"""Pure Hub/SQLite tests. Authority and revision readers are explicit fakes."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from uas.config import ConfigError, load
from uas.gate_policy import compile_policy
from uas.gate_hub import GateHub, require_operation_gates
from uas.gate_evaluation import GateRoomBinding
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from test_gate_evaluation import FakeControl, Interrupted

ORIGIN = Origin('reviewer', 'review-seat', 'review-session', 'epoch-1', ('review',))


def definition(kind='decision', scope='head', relationship='independent-reviewer'):
    return {'id': 'review', 'kind': kind, 'config': {'statement_id': 'review-complete',
        'scope': scope, 'eligible_actors': ['reviewer', 'other-reviewer'],
        'relationship': relationship, 'required_capability': 'review',
        'allow_self': False, 'continuing_authority': relationship == 'independent-reviewer'}}


class GateDecisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.ledger = RoomLedger(Path(self.temp.name) / 'room.db', 'alpha')
        self.addCleanup(self.ledger.close)
        self.policy = json.loads(Path('tests/fixtures/two-rooms.json').read_text())['rooms'][0]['policies'][0]
        self.policy['gates'] = [definition()]
        self.policy['protected_operations'] = {'submit-for-review': ['review'], 'complete': ['review']}
        self.run = {'run_id': 'run-one', 'generation': 1, 'status': 'ACTIVE',
            'project_id': 'project-alpha', 'repository': 'example/project-alpha',
            'participant_id': 'builder', 'actor_id': 'implementer',
            'checkout': {'slot': 'primary', 'branch': 'refs/heads/main'},
            'policy': compile_policy(self.policy, 'policy')}
        self.revision = 0; self.allowed = True
        self.seed(lambda state: state.update(runs={'run-one': deepcopy(self.run)}))
        self.control = FakeControl()
        self.authorities = {actor: {'actor_id': actor, 'kind': 'participant', 'active': True,
            'authority_epoch': 'epoch-1', 'capabilities': ['review'], 'contributors': ['implementer'],
            'contribution_version': 'contributions-1', 'history_status': 'read'}
            for actor in ('reviewer', 'other-reviewer')}
        self.identity_calls = []
        self.construct()

    def construct(self):
        self.hub = GateHub(self.ledger, GateRoomBinding('alpha', 'room-instance',
            'project-alpha', 'example/project-alpha', 128 << 20), self.control,
            authorize=lambda *_: self.allowed, identity=self.identity)
        self.control.hub = self.hub

    def identity(self, run, actor_id, head):
        self.identity_calls.append((actor_id, head))
        return deepcopy(self.authorities[actor_id])

    def seed(self, update):
        self.revision += 1
        def decide(state, _):
            update(state)
            return Transition(state, (Event('test.changed', {}),), {})
        self.ledger.apply(Command('seed-' + str(self.revision), 'test.change', 'run-one', None, {}),
                          ORIGIN, authorize=lambda *_: True, decide=decide)

    def configure(self, gate):
        self.policy['gates'] = [gate]
        compiled = compile_policy(self.policy, 'policy')
        self.seed(lambda state: state['runs']['run-one'].update(policy=compiled))

    def submit(self, operation='submit-one', action='approve', origin=ORIGIN):
        return self.hub.submit(operation, 'run-one', 1, {'gate_id': 'review',
            'statement_id': 'review-complete', 'action': action, 'note': 'Typed evidence only',
            'evidence_refs': ['review:123']}, origin=origin)

    def projection(self):
        return self.hub.projection('run-one', 1, 'review', origin=ORIGIN)

    def test_complete_kind_policy_compiles_without_executing(self):
        compiled = compile_policy(self.policy, 'policy')['gates'][0]
        self.assertEqual('authenticated-identity', compiled['source'])
        self.assertEqual('head', compiled['scope'])
        self.assertIn('eligibility', compiled['dependencies'])
        self.assertEqual(['complete', 'submit-for-review'], compiled['guarded_operations'])

    def test_unsafe_independence_or_implicit_self_policy_refused(self):
        for key, value in [('scope', 'run'), ('allow_self', True), ('continuing_authority', False),
                           ('required_capability', 'implement')]:
            policy = deepcopy(self.policy); policy['gates'][0]['config'][key] = value
            with self.subTest(key=key), self.assertRaises(ConfigError):
                compile_policy(policy, 'policy')

    def test_pass_is_decided_not_mechanically_verified(self):
        result = self.submit()['result']
        self.assertEqual('passed', result['verdict']); self.assertEqual('decided', result['provenance'])
        self.assertEqual('review-complete', result['checks'][0]['item'])
        self.assertEqual(['review:123'], result['checks'][0]['evidence_refs'])
        self.assertEqual('a' * 40, result['scope']['head_sha'])
        self.assertEqual('passed', self.projection()['state'])

    def test_contributor_identity_is_ineligible_across_sessions(self):
        self.authorities['reviewer']['contributors'] = ['implementer', 'reviewer']
        result = self.submit()['result']
        self.assertEqual('failed', result['verdict'])
        self.assertEqual('identity-ineligible', result['checks'][0]['note'])

    def test_missing_capability_and_epoch_are_failed_not_ignored(self):
        self.authorities['reviewer']['capabilities'] = []
        self.assertEqual('failed', self.submit()['result']['verdict'])
        self.authorities['reviewer']['capabilities'] = ['review']
        self.authorities['reviewer']['authority_epoch'] = 'epoch-2'
        self.assertEqual('failed', self.submit('submit-two')['result']['verdict'])

    def test_unverifiable_authority_produces_error(self):
        self.authorities['reviewer']['history_status'] = 'unavailable'
        result = self.submit()['result']
        self.assertEqual('error', result['verdict'])
        self.assertEqual('GATE_IDENTITY_UNVERIFIABLE', result['reason'])

    def test_withdrawal_supersedes_only_that_identity_without_rewriting_history(self):
        first = self.submit()['result']
        self.submit('withdraw-one', 'withdraw')
        self.assertEqual('failed', self.projection()['state'])
        self.assertEqual(first, self.hub._row(first['evaluation_id'])['result'])
        other = Origin('other-reviewer', 'other-seat', 'other-session', 'epoch-1', ('review',))
        self.submit('approve-other', origin=other)
        self.submit('reject-original', 'reject')
        self.assertEqual('passed', self.projection()['state'])

    def test_current_revocation_and_later_contribution_stale_approval(self):
        self.submit()
        self.authorities['reviewer']['active'] = False
        self.assertEqual('stale', self.projection()['state'])
        self.authorities['reviewer']['active'] = True
        self.authorities['reviewer']['contributors'] = ['implementer', 'reviewer']
        self.authorities['reviewer']['contribution_version'] = 'contributions-2'
        self.assertIn('eligibility', self.projection()['evaluations'][0]['changed_dependencies'])

    def test_head_change_stales_review_but_not_run_scoped_statement(self):
        self.submit()
        self.control.source['head_sha'] = 'b' * 40
        self.assertEqual('stale', self.projection()['state'])
        gate = definition('attestation', 'run', 'participant')
        self.configure(gate)
        self.submit('assert-plan', 'assert')
        self.control.source['head_sha'] = 'c' * 40
        self.authorities['reviewer']['active'] = False
        self.assertEqual('passed', self.projection()['state'])
        self.assertEqual('attested', self.projection()['provenance'])

    def test_generation_and_policy_change_stale_immutable_submission(self):
        result = self.submit()['result']
        self.seed(lambda state: state['runs']['run-one'].update(generation=2))
        projection = self.hub.projection('run-one', 2, 'review', origin=ORIGIN)
        self.assertEqual('stale', projection['state'])
        self.assertEqual(result, self.hub._row(result['evaluation_id'])['result'])

    def test_retry_returns_original_without_new_identity_or_revision_read(self):
        first = self.submit(); calls = len(self.identity_calls)
        self.control.source['head_sha'] = 'b' * 40
        self.assertEqual(first, self.submit())
        self.assertEqual(calls, len(self.identity_calls))
        self.allowed = False
        with self.assertRaises(LedgerError) as caught: self.submit()
        self.assertEqual('FORBIDDEN', caught.exception.code)

    def test_conflicting_operation_and_untyped_verdict_payload_refused(self):
        self.submit()
        with self.assertRaises(LedgerError) as caught: self.submit(action='withdraw')
        self.assertEqual('ID_CONFLICT', caught.exception.code)
        with self.assertRaises(LedgerError):
            self.hub.submit('forged', 'run-one', 1, {'gate_id': 'review', 'passed': True}, origin=ORIGIN)

    def test_protected_operation_missing_failed_stale_and_pass(self):
        def guard(): return self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
        self.assertFalse(guard()['gates_satisfied'])
        self.submit(action='reject'); self.assertFalse(guard()['gates_satisfied'])
        self.submit('approve', 'approve'); self.assertTrue(guard()['gates_satisfied'])
        self.control.source['head_sha'] = 'b' * 40
        self.assertFalse(guard()['gates_satisfied'])
        self.assertEqual('stale', guard()['blockers'][0]['state'])
        self.assertEqual('ACTIVE', self.ledger.snapshot()['state']['runs']['run-one']['status'])

    def test_protected_read_never_launches_evaluator(self):
        self.hub.operation_gates('run-one', 1, 'submit-for-review', origin=ORIGIN)
        self.assertNotIn('start', self.control.calls)
        with self.assertRaises(LedgerError):
            self.hub.operation_gates('run-one', 1, 'merge', origin=ORIGIN)

    def test_transaction_refuses_newer_withdrawal_after_positive_read(self):
        self.submit()
        view = self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
        self.assertEqual(view, require_operation_gates(self.ledger.snapshot()['state'], view))
        self.submit('withdraw-after-read', 'withdraw')
        with self.assertRaises(LedgerError) as caught:
            require_operation_gates(self.ledger.snapshot()['state'], view)
        self.assertEqual('GATE_OPERATION_STALE', caught.exception.code)

    def test_unrelated_contribution_change_preserves_eligible_review(self):
        self.submit()
        self.authorities['reviewer']['contributors'] = ['implementer', 'unrelated']
        self.authorities['reviewer']['contribution_version'] = 'contributions-2'
        self.assertEqual('passed', self.projection()['state'])

    def test_authority_loss_during_identity_read_never_passes(self):
        original = self.hub.identity
        def revoked(*args):
            result = original(*args); self.allowed = False; return result
        self.hub.identity = revoked
        result = self.submit()['result']
        self.assertEqual('error', result['verdict'])
        self.assertEqual('GATE_AUTHORITY_REVOKED', result['reason'])

    def test_head_change_during_identity_read_marks_historical_scope_stale(self):
        original = self.hub.identity
        def changed(*args):
            value = original(*args)
            self.control.source['head_sha'] = 'b' * 40
            return value
        self.hub.identity = changed
        result = self.submit()['result']
        self.assertEqual('a' * 40, result['scope']['head_sha'])
        self.assertEqual('stale', result['freshness_at_completion']['state'])
        self.assertTrue(result['freshness_at_completion']['changed_dependencies'])
        self.assertEqual('stale', self.projection()['state'])

    def test_head_change_during_projection_identity_read_never_returns_current_pass(self):
        self.submit()
        original = self.hub.identity
        def changed(*args):
            value = original(*args)
            self.control.source['head_sha'] = 'b' * 40
            return value
        self.hub.identity = changed
        self.assertEqual('stale', self.projection()['state'])

    def test_generation_change_during_projection_identity_read_fences_old_snapshot(self):
        self.submit()
        original = self.hub.identity
        def changed(*args):
            value = original(*args)
            self.seed(lambda state: state['runs']['run-one'].update(generation=2))
            return value
        self.hub.identity = changed
        self.assertEqual('stale', self.projection()['state'])

    def test_malformed_submission_reference_or_unicode_is_typed_refusal_before_ledger_effects(self):
        before = self.ledger.snapshot()
        malformed = ({'evidence_refs': [{}]}, {'evidence_refs': ['valid', 3]},
                     {'evidence_refs': [['nested']]}, {'note': '\ud800'})
        for index, extra in enumerate(malformed):
            payload = {'gate_id': 'review', 'statement_id': 'review-complete', 'action': 'approve',
                       'note': 'typed note', 'evidence_refs': ['review:123'], **extra}
            with self.subTest(index=index), self.assertRaisesRegex(LedgerError, 'INVALID_GATE_SUBMISSION'):
                self.hub.submit('invalid-' + str(index), 'run-one', 1, payload, origin=ORIGIN)
        self.assertEqual(before, self.ledger.snapshot())

    def test_interrupted_identity_evaluation_stays_inflight_and_recovers_without_replay(self):
        self.hub.identity = lambda *_: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted): self.submit()
        self.assertEqual('in-flight', self.projection()['state'])
        calls = len(self.identity_calls)
        recovered = self.hub.recover_interrupted(self.hub.evaluation_id('submit-one'))
        self.assertEqual('error', recovered['result']['verdict'])
        self.assertEqual('GATE_INTERRUPTED_UNKNOWN', recovered['result']['reason'])
        self.assertEqual(calls, len(self.identity_calls))
        self.assertEqual(recovered, self.submit())

    def test_newer_inflight_identity_blocks_another_identity_terminal_approval(self):
        first = self.submit()
        other = Origin('other-reviewer', 'other-seat', 'other-session', 'epoch-1', ('review',))
        self.hub.identity = lambda *_: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted): self.submit('other-inflight', origin=other)
        self.hub.identity = self.identity
        self.assertEqual('in-flight', self.projection()['state'])
        self.assertFalse(self.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)['gates_satisfied'])
        self.assertEqual(first, self.hub._view(self.hub._row(first['evaluation_id'])))
