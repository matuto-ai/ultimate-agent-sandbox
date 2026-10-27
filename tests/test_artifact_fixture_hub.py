"""Pure schema/policy/ledger tests; no fixture main or native transport runs."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from uas.artifact_protocol import canonical
from uas.kernel_origin import OriginDenied
from uas.ledger import LedgerError, RoomLedger

PATH = Path(__file__).resolve().parent / 'vm' / 'artifact_hub.py'
SPEC = importlib.util.spec_from_file_location('artifact_fixture_hub', PATH)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def metadata():
    return {'version': 1, 'challenge': 'a' * 64, 'supervisor_identity': [1, 2],
        'mapping_digest': 'b' * 64, 'profile_digest': 'c' * 64, 'room_id': 'alpha',
        'room_instance': 'd' * 32, 'project_id': 'project-alpha',
        'repository': 'example/project-alpha', 'run_id': 'artifact-run',
        'participant_id': 'builder', 'checkout': {'slot': 'primary', 'branch': 'refs/heads/main'},
        'scenarios': ['present', 'missing']}


class ArtifactFixtureHubTests(unittest.TestCase):
    def test_startup_accepts_only_fixed_bounded_shape(self):
        document = metadata()
        self.assertEqual(FIXTURE.configuration(canonical(document)), document)
        for change in ({'path': '/tmp/escape'}, {'argv': ['sh']}, {'version': True},
                       {'room_instance': 'bad'}, {'supervisor_identity': [True, 2]},
                       {'scenarios': ['present', 'present']}, {'scenarios': ['arbitrary']},
                       {'checkout': {'slot': 'primary', 'branch': 'HEAD'}},
                       {'repository': '../elsewhere'}):
            with self.subTest(change=change), self.assertRaises(OriginDenied):
                FIXTURE.configuration(canonical({**document, **change}))
        for raw in (b'', b'x' * 8193, b'{}', b'{"version":1,"version":1}', b'\xff'):
            with self.assertRaises(OriginDenied):
                FIXTURE.configuration(raw)

    def test_linked_checkout_requires_exact_recorded_slot_branch(self):
        document = metadata(); document['checkout'] = {'slot': 'f'*32, 'branch': 'refs/heads/uas-slot/'+'f'*32}
        self.assertEqual(FIXTURE.configuration(canonical(document)), document)
        document['checkout']['branch'] = 'refs/heads/uas-slot/'+'e'*32
        with self.assertRaises(OriginDenied):
            FIXTURE.configuration(canonical(document))

    def test_fixed_policy_has_no_caller_chosen_paths_or_commands(self):
        policy = FIXTURE.fixture_policy()
        self.assertEqual({gate['id'] for gate in policy['gates']}, {'artifact-'+s for s in FIXTURE.SCENARIOS})
        for gate in policy['gates']:
            self.assertEqual(gate['kind'], 'mechanical')
            self.assertEqual(gate['evaluator'], 'artifacts')
            self.assertEqual(gate['source'], 'supervisor-one-shot-helper')
            self.assertEqual(gate['scope'], 'exact-head-tree')
            self.assertEqual(gate['guarded_operations'], ['complete', 'submit-for-review'])
        present = next(g for g in policy['gates'] if g['id'] == 'artifact-present')
        self.assertEqual([item['path'] for item in present['config']['items']], ['README.md', 'docs'])
        missing = next(g for g in policy['gates'] if g['id'] == 'artifact-missing')
        self.assertEqual(missing['config']['items'][0]['path'], 'artifact-missing.txt')

    def test_fixture_seed_is_durable_explicit_and_never_native_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            with RoomLedger(Path(directory)/'room.db', 'alpha') as ledger:
                document = metadata(); origin = FIXTURE.fixture_origin('e'*32)
                FIXTURE.seed_fixture_run(ledger, document, origin)
                state = ledger.snapshot()['state']
                self.assertTrue(state['runs']['artifact-run']['qualification_fixture_seed'])
                self.assertEqual(state['runs']['artifact-run']['status'], 'ACTIVE')
                self.assertNotIn('run_admissions', state)
                event = ledger.replay(0)[0]
                self.assertEqual(event['kind'], 'qualification.fixture-run-seeded')
                self.assertFalse(event['payload']['native_run_admission_qualified'])
                data = json.loads(FIXTURE.report_document(ledger, document, []))
                self.assertFalse(data['production_enabled'])
                self.assertFalse(data['native_run_admission_qualified'])
                with self.assertRaises(LedgerError) as caught:
                    FIXTURE.seed_fixture_run(ledger, document, origin)
                self.assertEqual(caught.exception.code, 'QUALIFICATION_LEDGER_NOT_FRESH')

    def test_real_hub_arguments_and_explicit_same_operation_lookup_only(self):
        # Mock proves fixture invocation shape only; it is never used by main.
        class Hub:
            def __init__(self): self.calls = []
            def evaluate(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                if args[0] == 'artifact-missing': raise LedgerError('GATE_SOURCE_MISMATCH')
                return {'phase': 'TERMINAL', 'result': {'verdict': 'passed'}}
        hub = Hub(); document = metadata(); origin = FIXTURE.fixture_origin('e'*32)
        result = FIXTURE.run_evaluations(hub, document, origin)
        self.assertEqual(len(hub.calls), 3)
        self.assertEqual(hub.calls[0], hub.calls[1])
        self.assertEqual(hub.calls[0][0], ('artifact-present', 'artifact-run', 1, 'artifact-present'))
        self.assertEqual(hub.calls[0][1], {'origin': origin})
        self.assertEqual(result[1]['outcome'], 'request-error')
        self.assertNotIn('evaluation', result[1])
        self.assertEqual(result[1]['error'], 'GATE_SOURCE_MISMATCH')

    def test_fault_wrappers_keep_real_offer_type_and_record_only_injected_actions(self):
        # Deliberately inert stand-ins for unit coverage. main constructs the
        # real client and receives its kernel-bound GateOffer before wrapping.
        class Channel:
            def __init__(self): self.actions = []
            def shutdown(self, how): self.actions.append(('shutdown', how))
            def close(self): self.actions.append(('close',))
            def send(self, data): self.actions.append(('send', data)); return len(data)
        class Client:
            def __init__(self, offer): self.offer = offer; self.calls = []
            def start(self, *args): self.calls.append(args); return self.offer
        for scenario, fault in [('loss', 'close-actual-held-helper-channel'),
                                ('malformed', 'malformed-request-to-real-helper'),
                                ('resource', 'withhold-request-past-self-lifetime')]:
            with self.subTest(scenario=scenario):
                offer = object.__new__(FIXTURE.GateOffer)
                offer.channel = Channel()
                client = Client(offer); evidence = []; waits = []; times = iter((10, 26))
                FIXTURE.install_fixture_faults(client, evidence, monotonic=lambda: next(times), sleep=waits.append)
                scope = {'gate_id': 'artifact-' + scenario}
                self.assertIs(client.start(scope, {'target': 'typed'}, ['README.md']), offer)
                self.assertEqual(len(client.calls), 1)
                self.assertEqual(evidence[0]['fault'], fault)
                if scenario == 'loss': self.assertEqual(offer.channel.actions[-1], ('close',))
                if scenario == 'malformed':
                    self.assertEqual(offer.channel.actions, [('send', b'BAD1')])
                    self.assertFalse(evidence[0]['malformed_helper_output_claimed'])
                if scenario == 'resource':
                    self.assertEqual(waits, [16])
                    self.assertEqual(evidence[0]['elapsed_seconds'], 16)
                    self.assertEqual(evidence[0]['scope'], 'wall-lifetime-only-not-cpu-or-memory-exhaustion')

    def test_fault_wrapper_rejects_substitute_offer(self):
        class Client:
            def start(self, *_): return object()
        client = Client(); evidence = []
        FIXTURE.install_fixture_faults(client, evidence)
        with self.assertRaises(OriginDenied):
            client.start({'gate_id': 'artifact-loss'}, {}, [])
        self.assertEqual(evidence, [])

    def test_retry_difference_is_not_reported_as_success(self):
        class Hub:
            def __init__(self): self.calls = 0
            def evaluate(self, *_args, **_kwargs):
                self.calls += 1; return {'different': self.calls}
        document = metadata(); document['scenarios'] = ['present']
        result = FIXTURE.run_evaluations(Hub(), document, FIXTURE.fixture_origin('e'*32))
        self.assertEqual(result[0]['outcome'], 'request-error')
        self.assertEqual(result[0]['error'], 'QUALIFICATION_RETRY_CHANGED')


if __name__ == '__main__':
    unittest.main()
