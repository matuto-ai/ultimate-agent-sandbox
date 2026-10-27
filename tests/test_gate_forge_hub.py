"""Pure connected GateHub/External Broker/audit provider fixtures, no native I/O.

The private client is synthetic. These checks do not qualify a process-bound
sender, live provider credentials, the helper or a Workstation boundary.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import threading
import unittest

from test_gate_evaluation import FakeControl, ORIGIN, Interrupted
from test_gate_forge import Fixture, TARGET, config, item, R, HEAD
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read_provider import BrokerReadProvider
from uas.gate_evaluation import GateRoomBinding
from uas.gate_forge import ExternalGateForgeBroker, gate_forge_origin
from uas.gate_hub import GateHub, require_operation_gates
from uas.gate_policy import compile_policy
from uas.github_read import GitHubProject
from uas.ledger import Command, Event, LedgerError, RoomLedger, Transition


class FixtureClient:
    def __init__(self, broker):
        self.broker, self.calls = broker, []
        self.before = self.after = None

    def observe(self, target, policy, operation, *, authorize):
        self.calls.append(operation)
        if self.before is not None: self.before()
        result = self.broker.execute({'id': operation, 'kind': 'gate-forge',
            'target': target, 'config': policy}, origin=gate_forge_origin('room-instance'),
            authorize=authorize)
        if self.after is not None: self.after(result)
        return result

    def observe_target(self, target, operation, *, authorize):
        self.calls.append(operation)
        if self.before is not None: self.before()
        result = self.broker.execute({'id': operation, 'kind': 'gate-target', 'target': target},
            origin=gate_forge_origin('room-instance'), authorize=authorize)
        if self.after is not None: self.after(result)
        return result


class ForgeGateHubTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.ledger_path = Path(self.tmp.name) / 'room.db'
        self.ledger = RoomLedger(self.ledger_path, 'alpha'); self.addCleanup(lambda: self.ledger.close())
        self.audit = ForgeAudit(Path(self.tmp.name) / 'audit.db', 'deployment'); self.addCleanup(self.audit.close)
        self.fixture = Fixture()
        self.control = FakeControl(); self.control.source.update(repository=R, head_sha=HEAD)
        self.binding = GateRoomBinding('alpha', 'room-instance', 'project-alpha', R, 128 << 20)
        provider = BrokerReadProvider(GitHubProject(R), self.fixture, None)
        broker = ExternalGateForgeBroker(ForgeBinding('alpha', 'project-alpha', R),
            'room-instance', self.audit, 'fixed-actor', lambda _: provider)
        self.client = FixtureClient(broker)
        self.policy = compile_policy({'id': 'default', 'version': 1,
            'gates': [{'id': 'ci', 'kind': 'mechanical', 'evaluator': 'forge-state', 'config': config()}],
            'protected_operations': {'submit-for-review': ['ci'], 'complete': ['ci']},
            'review_return_cap': 5, 'queue_timeout_seconds': 60, 'response_timeout_seconds': 60}, 'policy')
        self.run = {'run_id': 'run-one', 'generation': 1, 'status': 'ACTIVE',
            'project_id': 'project-alpha', 'repository': R, 'actor_id': 'builder-actor',
            'participant_id': 'builder', 'policy': self.policy,
            'checkout': {'slot': 'primary', 'branch': 'refs/heads/main'}}
        self.revision = 0
        self.seed(lambda state: state.update(runs={'run-one': deepcopy(self.run)}))
        self.authorized = lambda *_: True
        self.construct()
        bound = self.hub.bind_target('bind-target', 'run-one', 1, TARGET, origin=ORIGIN)
        self.assertEqual('BOUND', bound['status'])
        self.fixture.calls.clear(); self.client.calls.clear(); self.control.calls.clear()

    def construct(self):
        self.hub = GateHub(self.ledger, self.binding, self.control,
            authorize=lambda *args: self.authorized(*args), forge=self.client,
            authorize_target=lambda origin, _: origin == ORIGIN)
        self.control.hub = self.hub

    def seed(self, fn):
        self.revision += 1
        def decide(state, _):
            fn(state)
            return Transition(state, (Event('fixture.changed', {}),), {})
        self.ledger.apply(Command('seed-' + str(self.revision), 'fixture.changed', 'run-one', None, {}),
            ORIGIN, authorize=lambda *_: True, decide=decide)

    def evaluate(self, operation='evaluation', *, generation=1, origin=ORIGIN):
        return self.hub.evaluate(operation, 'run-one', generation, 'ci', origin=origin)

    def projection(self, *, generation=1, origin=ORIGIN):
        return self.hub.projection('run-one', generation, 'ci', origin=origin)

    def test_pass_records_exact_checks_after_audited_broker_and_refresh(self):
        observed = self.evaluate()
        result = observed['result']
        self.assertEqual('passed', result['verdict'])
        self.assertEqual(TARGET, result['target'])
        self.assertTrue(result['audit_reference'])
        self.assertTrue(result['dependencies']['dependency_digest'])
        self.assertTrue(all(row['ok'] for row in result['checks']))
        self.assertNotIn('start', self.control.calls)
        self.assertEqual('passed', self.projection()['state'])
        self.assertEqual(result, self.hub._row(observed['evaluation_id'])['result'])
        view = self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
        self.assertTrue(view['gates_satisfied'])
        require_operation_gates(self.ledger.snapshot()['state'], view)
        self.assertEqual('ACTIVE', self.ledger.snapshot()['state']['runs']['run-one']['status'])

    def test_exact_retry_and_restart_do_not_recontact_broker(self):
        first = self.evaluate()
        self.ledger.close(); self.ledger = RoomLedger(self.ledger_path, 'alpha'); self.construct()
        calls = len(self.fixture.calls), len(self.client.calls)
        self.assertEqual(first, self.evaluate())
        self.assertEqual(calls, (len(self.fixture.calls), len(self.client.calls)))
        self.seed(lambda state: state['runs']['run-one'].update(generation=2))
        self.assertEqual(first, self.evaluate())
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'): self.evaluate(generation=2)
        self.assertEqual(calls, (len(self.fixture.calls), len(self.client.calls)))

    def test_newer_pending_or_failed_attempt_blocks_previous_pass(self):
        self.evaluate()
        self.fixture.checks[HEAD][0].update(status='in_progress', conclusion=None)
        result = self.evaluate('pending')['result']
        self.assertEqual('failed', result['verdict'])
        calls = len(self.client.calls)
        self.assertEqual('failed', self.projection()['state'])
        self.assertEqual(calls, len(self.client.calls))
        self.assertFalse(self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)['gates_satisfied'])

    def test_provider_error_and_malformed_evidence_never_advance(self):
        self.fixture.before = lambda _: (_ for _ in ()).throw(RuntimeError('private credential text'))
        result = self.evaluate()['result']
        self.assertEqual('error', result['verdict'])
        self.assertEqual('error', self.projection()['state'])
        self.assertNotIn('private credential', str(result))
        self.fixture.before = None
        self.client.after = lambda result: result['observation'].update(verdict='passed')
        self.assertEqual('error', self.evaluate('malformed')['result']['verdict'])

    def test_new_inflight_blocks_old_pass_and_recovery_never_replays(self):
        self.evaluate()
        self.client.before = lambda: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted): self.evaluate('newer')
        self.assertEqual('in-flight', self.projection()['state'])
        calls = len(self.client.calls)
        with self.assertRaisesRegex(LedgerError, 'GATE_EVALUATION_IN_FLIGHT'): self.evaluate('another')
        evaluation = self.hub.evaluation_id('newer')
        result = self.hub.recover_interrupted(evaluation)['result']
        self.assertEqual(('error', 'GATE_INTERRUPTED_UNKNOWN'), (result['verdict'], result['reason']))
        self.assertEqual(calls, len(self.client.calls))
        self.assertEqual('error', self.projection()['state'])

    def test_source_generation_and_target_changes_after_observation_stale_history(self):
        changes = (
            lambda: self.control.source.update(head_sha='f'*40),
            lambda: self.seed(lambda s: s['runs']['run-one'].update(generation=2)),
            lambda: self.seed(lambda s: s['runs']['run-one']['gate_target'].update(base_sha='f'*40)),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.client.after = lambda _, change=change: change()
                result = self.evaluate('changed-' + str(index), generation=self.ledger.snapshot()['state']['runs']['run-one']['generation'])['result']
                self.assertEqual('stale', result['freshness_at_completion']['state'])
                self.assertEqual('stale', self.projection(generation=self.ledger.snapshot()['state']['runs']['run-one']['generation'])['state'])
                self.control.source['head_sha'] = HEAD
                self.seed(lambda s: s['runs']['run-one'].update(generation=1, gate_target=deepcopy(TARGET)))

    def test_refresh_interruption_is_durable_and_never_silently_replayed(self):
        row = self.evaluate()
        self.client.before = lambda: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted): self.projection()
        self.assertEqual('STARTED', self.hub._row(row['evaluation_id'])['refresh']['phase'])
        calls = len(self.client.calls)
        with self.assertRaisesRegex(LedgerError, 'GATE_FORGE_REFRESH_UNRESOLVED'): self.projection()
        self.assertEqual(calls, len(self.client.calls))
        self.hub.recover_interrupted(row['evaluation_id'])
        self.assertEqual(calls, len(self.client.calls))
        self.client.before = None
        self.assertEqual('passed', self.projection()['state'])
        self.assertEqual('passed', self.hub._row(row['evaluation_id'])['result']['verdict'])

    def test_refresh_uses_current_reader_authority_not_original_evaluator(self):
        self.evaluate()
        reader = replace(ORIGIN, actor_id='current-reader', authority_version='authority-v2')
        self.authorized = lambda origin, _: origin.actor_id == 'current-reader'
        self.assertEqual('passed', self.projection(origin=reader)['state'])
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'): self.projection()

    def test_refresh_unrelated_ci_preserves_dependency_while_required_change_blocks(self):
        self.evaluate()
        from test_github_surface import check
        self.fixture.checks[HEAD].append({**check(20), 'name': 'unrelated'})
        self.assertEqual('passed', self.projection()['state'])
        self.fixture.checks[HEAD][0].update(status='in_progress', conclusion=None)
        self.assertEqual('stale', self.projection()['state'])

    def test_refresh_rejects_missing_audit_reference_even_for_valid_observation(self):
        self.evaluate()
        self.client.after = lambda result: result.pop('audit_reference')
        self.assertEqual('stale', self.projection()['state'])

    def test_acceptance_rejects_changed_durable_target_after_passing_view(self):
        self.evaluate()
        view = self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
        self.seed(lambda state: state['runs']['run-one']['gate_target'].update(base_sha='f'*40))
        with self.assertRaises(LedgerError): require_operation_gates(self.ledger.snapshot()['state'], view)

    def test_authority_read_failure_is_immutable_error_not_lost_terminal(self):
        def revoke(_):
            self.authorized = lambda *_: (_ for _ in ()).throw(RuntimeError('authority unavailable'))
        self.client.after = revoke
        result = self.evaluate()['result']
        self.assertEqual('error', result['verdict'])
        self.assertEqual('GATE_AUTHORITY_REVOKED', result['reason'])

    def test_missing_trusted_target_does_not_contact_forge(self):
        self.seed(lambda state: state['runs']['run-one'].pop('gate_target'))
        with self.assertRaisesRegex(LedgerError, 'GATE_TARGET_UNBOUND'): self.evaluate()
        self.assertEqual([], self.client.calls)
        self.assertEqual([], self.fixture.calls)

    def test_missing_final_source_never_binds_target(self):
        prior = deepcopy(self.ledger.snapshot()['state']['runs']['run-one']['gate_target_binding'])
        self.client.after = lambda _: setattr(self.control, 'current', lambda _: None)
        result = self.hub.bind_target('missing-source-bind', 'run-one', 1, TARGET,
            origin=ORIGIN, expected_binding=prior['digest'])
        self.assertEqual('ERROR', result['status'])
        self.assertEqual(prior, self.ledger.snapshot()['state']['runs']['run-one']['gate_target_binding'])

    def test_missing_or_malformed_final_source_is_immutable_error(self):
        original = self.control.current
        for index, missing in enumerate((None, {}, {'head_sha': HEAD})):
            self.control.current = original
            self.client.after = lambda _, missing=missing: setattr(self.control, 'current', lambda _: missing)
            result = self.evaluate('missing-source-' + str(index))['result']
            self.assertEqual('error', result['verdict'])
            self.assertNotEqual('current', result['freshness_at_completion']['state'])

    def test_missing_refresh_source_cannot_authorize_protected_operation(self):
        self.assertEqual('passed', self.evaluate()['result']['verdict'])
        self.control.current = lambda _: None
        view = self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
        self.assertFalse(view['gates_satisfied'])
        self.assertNotEqual('passed', view['gates'][0]['state'])
        with self.assertRaises(LedgerError):require_operation_gates(self.ledger.snapshot()['state'], view)

    def test_real_ledger_transaction_consumes_fresh_guard_without_completing_run(self):
        # This is the narrow #74 transition-consumption contract, not its review
        # or merge workflow. The fixture owns and holds its external fence.
        fence = threading.RLock()
        self.authorized = lambda *_: fence._is_owned()
        with fence:
            self.assertEqual('passed', self.evaluate()['result']['verdict'])
            view = self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
            def decide(state, _):
                require_operation_gates(state, view)
                state['fixture_gate_consumed'] = {'evaluation_id': view['gates'][0]['evaluation_id']}
                return Transition(state, (Event('fixture.gate-consumed', {'run_id': 'run-one'}),), {})
            self.ledger.apply(Command('fixture-accept', 'fixture.gate-consumed', 'run-one', 1, {}),
                ORIGIN, authorize=self.authorized, decide=decide)
        state = self.ledger.snapshot()['state']
        self.assertIn('fixture_gate_consumed', state)
        self.assertEqual('ACTIVE', state['runs']['run-one']['status'])

    def test_real_acceptance_transaction_rolls_back_every_blocking_gate_state(self):
        fence = threading.RLock()
        self.authorized = lambda *_: fence._is_owned()
        def refuse(label):
            view = self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
            before = self.ledger.snapshot()
            def decide(state, _):
                require_operation_gates(state, view)
                state['fixture_illegal_advance'] = True
                return Transition(state, (Event('fixture.illegal', {}),), {})
            with self.assertRaises(LedgerError):
                self.ledger.apply(Command('deny-' + label, 'fixture.consume', 'run-one', 1, {}),
                    ORIGIN, authorize=self.authorized, decide=decide)
            self.assertEqual(before, self.ledger.snapshot())
            self.assertNotIn('fixture_illegal_advance', before['state'])
        with fence:
            refuse('missing')
            self.evaluate('passing')
            original = self.control.current; self.control.current = lambda _: None
            refuse('stale'); self.control.current = original
            self.fixture.checks[HEAD][0].update(status='completed', conclusion='failure')
            self.evaluate('failed'); refuse('failed')
            self.fixture.before = lambda _: (_ for _ in ()).throw(RuntimeError('unavailable'))
            self.evaluate('errored'); refuse('error'); self.fixture.before = None
            self.client.before = lambda: (_ for _ in ()).throw(Interrupted())
            with self.assertRaises(Interrupted):self.evaluate('pending')
            refuse('inflight')

    def test_target_bind_is_separate_authority_and_exact_retry_never_recontacts(self):
        calls = len(self.fixture.calls)
        existing = self.hub.bind_target('bind-target', 'run-one', 1, TARGET, origin=ORIGIN)
        self.assertEqual('BOUND', existing['status'])
        self.assertEqual(calls, len(self.fixture.calls))
        ordinary = replace(ORIGIN, actor_id='ordinary-evaluator')
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.hub.bind_target('participant-target', 'run-one', 1, TARGET, origin=ordinary)
        with self.assertRaisesRegex(LedgerError, 'GATE_TARGET_BINDING_CONFLICT'):
            self.hub.bind_target('blind-replace', 'run-one', 1, TARGET, origin=ORIGIN)
        self.assertEqual(calls, len(self.fixture.calls))

    def test_target_bind_unknown_outcome_recovery_does_not_recontact_or_replace(self):
        expected = self.ledger.snapshot()['state']['runs']['run-one']['gate_target_binding']['digest']
        self.client.before = lambda: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted):
            self.hub.bind_target('rebind', 'run-one', 1, TARGET, origin=ORIGIN, expected_binding=expected)
        calls = len(self.client.calls)
        self.assertEqual('PENDING', self.hub.bind_target('rebind', 'run-one', 1, TARGET,
            origin=ORIGIN, expected_binding=expected)['status'])
        recovered = self.hub.recover_target_binding('rebind')
        self.assertEqual(('ERROR', 'GATE_INTERRUPTED_UNKNOWN'), (recovered['status'], recovered['reason']))
        self.assertEqual(calls, len(self.client.calls))
        self.assertEqual(TARGET, self.ledger.snapshot()['state']['runs']['run-one']['gate_target'])


if __name__ == '__main__':
    unittest.main()
