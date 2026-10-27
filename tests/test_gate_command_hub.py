"""Pure real-Hub command adjudication with synthetic private-control facts.

The fake offers intentionally expose a generator like the real private client.
No native command, process confinement, executable digest or kernel sender is
qualified by these policy/lifecycle tests.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from test_gate_evaluation import FakeControl, FakeOffer, ORIGIN, Interrupted
from uas.artifact_protocol import profile_scope_digest
from uas.gate_evaluation import GateRoomBinding, PROVENANCE
from uas.gate_hub import GateHub, require_operation_gates
from uas.gate_policy import compile_policy
from uas.gate_repository import COMMAND_PROFILE_ID, command_correlation
from uas.ledger import Command, Event, LedgerError, RoomLedger, Transition


def config():
    return {'argv': ['/usr/bin/python3', '-B', 'verify.py'], 'cwd': '.',
        'timeout_seconds': 1, 'environment': {'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1'},
        'process_limit': 4, 'memory_bytes': 64 << 20, 'output_bytes': 1024,
        'executable_sha256': '1' * 64, 'executables': []}


class CommandOffer(FakeOffer):
    def document(self):
        value = {'source': 'supervisor-one-shot-helper', 'provenance': PROVENANCE,
            'profile': COMMAND_PROFILE_ID, 'profile_digest': 'd' * 64, 'binding_digest': 'e' * 64,
            'scope_digest': profile_scope_digest(COMMAND_PROFILE_ID, self.scope, self.target)}
        self.control.mutate_document(value)
        return value

    def records(self):
        self.control.effect('records')
        correlation = command_correlation(self.scope, self.target, self.paths)
        rows = [{'kind': 'header', 'correlation': correlation}]
        for name in ('stdout', 'stderr'):
            data = self.control.streams[name]; tail = data[-16384:]
            rows.append({'kind': 'stream', 'stream': name, 'bytes': len(data),
                'sha256': hashlib.sha256(data).hexdigest(), 'tail_bytes': len(tail),
                'truncated': len(data) > 16384})
            for offset in range(0, len(tail), 8192):
                rows.append({'kind': 'tail', 'stream': name, 'offset': offset,
                    'bytes_hex': tail[offset:offset + 8192].hex()})
        rows.append({'kind': 'exit', 'exit_code': 0, 'signal': 0, 'timed_out': False,
            'output_limited': False, 'duration_ms': 1, 'executable_sha256': self.paths['executable_sha256'],
            'whole_tree_exited': True, 'descendants_terminated': False, 'work_cleaned': True,
            **self.control.exit_fact})
        rows.append({'kind': 'final', 'correlation': correlation})
        self.control.mutate_records(rows)
        yield from rows

    def acknowledge_final(self, value):
        self.control.effect('ack')
        if not self.control.alive: raise LedgerError('GATE_HELPER_LOST')
        assert value == {'kind': 'final', 'correlation': command_correlation(self.scope, self.target, self.paths)}
        assert self.control.hub._row(self.scope['evaluation_id'])['phase'] == 'OBSERVED'
        self.acked = True


class CommandControl(FakeControl):
    profile = COMMAND_PROFILE_ID

    def __init__(self):
        super().__init__()
        self.streams = {'stdout': b'ok\n', 'stderr': b''}
        self.exit_fact = {}

    def start(self, scope, target, policy):
        self.effect('start')
        assert self.hub._row(scope['evaluation_id'])['phase'] == 'LAUNCH_RESERVED'
        self.offer = CommandOffer(self, scope, target, deepcopy(policy))
        return self.offer

    def prepare(self, scope, source):
        self.effect('prepare')
        row = self.hub._row(scope['evaluation_id'])
        assert row['phase'] == 'STARTED' and row['reservation']['scratch_bytes'] == 40 << 20
        self.target = {'target_id': scope['evaluation_id'][-32:], 'head_sha': source['head_sha'],
            'tree_sha': 'c' * 40, 'manifest_sha256': 'f' * 64, 'source_digest': source['source_digest'],
            'device': 1, 'inode': 100, 'entries': 2, 'expanded_bytes': 100,
            'work': {'device': 2, 'inode': 200, 'limit_bytes': 8 << 20}}
        return deepcopy(self.target)


class CommandGateHubTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'room.db'
        self.ledger = RoomLedger(self.path, 'alpha'); self.addCleanup(lambda: self.ledger.close())
        policy = json.loads(Path('tests/fixtures/two-rooms.json').read_text())['rooms'][0]['policies'][0]
        policy['gates'] = [{'id': 'command', 'kind': 'mechanical', 'evaluator': 'command', 'config': config()}]
        policy['protected_operations'] = {'complete': ['command'], 'submit-for-review': ['command']}
        self.run = {'run_id': 'run-one', 'generation': 1, 'status': 'ACTIVE',
            'project_id': 'project-alpha', 'repository': 'example/project-alpha',
            'participant_id': 'builder', 'actor_id': 'builder-actor',
            'checkout': {'slot': 'primary', 'branch': 'refs/heads/main'},
            'policy': compile_policy(policy, 'policy')}
        self.revision = 0; self.allowed = True
        self.seed(lambda state: state.update(runs={'run-one': deepcopy(self.run)}))
        self.control = CommandControl()
        self.construct()

    def construct(self):
        self.hub = GateHub(self.ledger, GateRoomBinding('alpha', 'room-instance',
            'project-alpha', 'example/project-alpha', 128 << 20), self.control,
            authorize=lambda *_: self.allowed, repository=self.control)
        self.control.hub = self.hub

    def seed(self, fn):
        self.revision += 1
        def decide(state, _):
            fn(state)
            return Transition(state, (Event('fixture.changed', {}),), {})
        self.ledger.apply(Command('seed-' + str(self.revision), 'fixture.changed', 'run-one', None, {}),
            ORIGIN, authorize=lambda *_: True, decide=decide)

    def evaluate(self, operation='command-one'):
        return self.hub.evaluate(operation, 'run-one', 1, 'command', origin=ORIGIN)

    def projection(self):
        return self.hub.projection('run-one', 1, 'command', origin=ORIGIN)

    def test_success_retains_exact_argv_raw_output_and_check_after_exit_cleanup(self):
        row = self.evaluate(); result = row['result']
        self.assertEqual('passed', result['verdict'])
        self.assertEqual('command-exit-zero', result['checks'][0]['note'])
        self.assertEqual(3, len(result['checks'][0]['evidence_refs']))
        stored = self.hub._row(row['evaluation_id'])
        self.assertEqual(config(), stored['config'])
        self.assertEqual(b'ok\n'.hex(), stored['observations']['stdout']['tail_hex'])
        self.assertEqual(0, stored['observations']['exit']['exit_code'])
        self.assertEqual('passed', self.projection()['state'])
        view = self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
        require_operation_gates(self.ledger.snapshot()['state'], view)
        self.assertEqual('ACTIVE', self.ledger.snapshot()['state']['runs']['run-one']['status'])
        self.assertEqual(['resolve', 'prepare', 'current', 'start', 'records', 'ack', 'exit', 'finish', 'current'], self.control.calls[:9])

    def test_nonzero_timeout_signal_output_limit_and_surviving_descendants_fail(self):
        cases = [({'exit_code': 2}, b'', 'command-nonzero-exit'),
            ({'exit_code': None, 'signal': 9, 'timed_out': True, 'duration_ms': 1000}, b'', 'command-timeout'),
            ({'exit_code': None, 'signal': 11}, b'', 'command-signal'),
            ({'output_limited': True}, b'x' * 1025, 'command-output-limit'),
            ({'descendants_terminated': True}, b'', 'command-descendants-survived')]
        for index, (fact, data, note) in enumerate(cases):
            with self.subTest(note=note):
                self.control.exit_fact = fact; self.control.streams['stdout'] = data
                result = self.evaluate('failed-' + str(index))['result']
                self.assertEqual('failed', result['verdict']); self.assertEqual(note, result['checks'][0]['note'])
                self.assertEqual('failed', self.projection()['state'])
                self.assertFalse(self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)['gates_satisfied'])

    def test_malformed_correlated_records_digest_and_tree_exit_are_errors(self):
        mutations = [lambda rows: rows[0].update(correlation='0' * 64),
            lambda rows: rows[1].update(sha256='0' * 64),
            lambda rows: rows[-2].update(executable_sha256='0' * 64),
            lambda rows: rows[-2].update(whole_tree_exited=False),
            lambda rows: rows[-2].update(work_cleaned=False),
            lambda rows: rows[-2].update(extra='verdict'),
            lambda rows: rows.pop(), lambda rows: rows.extend(deepcopy(rows))]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.control.mutate_records = mutate
                result = self.evaluate('malformed-' + str(index))['result']
                self.assertEqual('error', result['verdict']); self.assertFalse(result['checks'][0]['ok'])
                self.assertNotEqual('passed', self.projection()['state'])

    def test_helper_profile_and_binding_mismatch_never_reads_command_output(self):
        self.control.mutate_document = lambda value: value.update(profile='artifacts-v1-source')
        result = self.evaluate()['result']
        self.assertEqual(('error', 'GATE_HELPER_BINDING_MISMATCH'), (result['verdict'], result['reason']))
        self.assertNotIn('records', self.control.calls)

    def test_head_change_at_completion_keeps_historical_fact_but_stales_guard(self):
        self.control.at['finish'] = lambda: self.control.source.update(head_sha='b' * 40)
        result = self.evaluate()['result']
        self.assertEqual('passed', result['verdict'])
        self.assertEqual('stale', result['freshness_at_completion']['state'])
        self.assertEqual('stale', self.projection()['state'])
        self.assertFalse(self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)['gates_satisfied'])

    def test_target_mutation_after_command_is_error_not_pass(self):
        self.control.post_mutated = True
        result = self.evaluate()['result']
        self.assertEqual(('error', 'GATE_TARGET_CHANGED'), (result['verdict'], result['reason']))

    def test_helper_loss_and_unconfirmed_exit_never_pass(self):
        self.control.alive = False
        self.assertEqual('GATE_HELPER_LOST', self.evaluate('lost')['result']['reason'])
        self.control.alive = True; self.control.exit_confirmed = False; self.control.abort_cleanup = False
        result = self.evaluate('unconfirmed')['result']
        self.assertEqual('GATE_HELPER_EXIT_UNCONFIRMED', result['reason'])
        self.assertFalse(result['cleanup']['cleanup']); self.assertIsNotNone(result['cleanup']['quarantine_ref'])

    def test_cleanup_failure_quarantines_reservation_and_preserves_raw_evidence(self):
        self.control.cleanup = False
        row = self.evaluate(); result = row['result']
        self.assertEqual(('error', 'GATE_CLEANUP_FAILED'), (result['verdict'], result['reason']))
        stored = self.hub._row(row['evaluation_id'])
        self.assertGreater(stored['reservation']['scratch_bytes'], 0)
        self.assertEqual('GATE_TARGET_QUARANTINED', stored['operational']['attention'])
        self.assertEqual(0, stored['observations']['exit']['exit_code'])
        self.assertNotIn('abort', self.control.calls)

    def test_exact_retry_after_restart_never_relaunches_or_rereads_source(self):
        first = self.evaluate(); self.control.calls.clear()
        self.ledger.close(); self.ledger = RoomLedger(self.path, 'alpha'); self.construct()
        self.assertEqual(first, self.evaluate()); self.assertEqual([], self.control.calls)

    def test_interrupted_command_recovers_error_without_relaunch(self):
        self.control.at['records'] = lambda: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted): self.evaluate()
        self.assertEqual('in-flight', self.projection()['state'])
        self.control.calls.clear()
        row = self.hub.recover_interrupted(self.hub.evaluation_id('command-one'))
        self.assertEqual('error', row['result']['verdict'])
        self.assertNotIn('start', self.control.calls); self.assertNotIn('records', self.control.calls)
        self.control.calls.clear(); self.assertEqual(row, self.evaluate()); self.assertEqual([], self.control.calls)
