"""Independent reset reducer tests with explicit supplied target/native fixtures.

The second ACTIVE Run and new Pi are controlled prerequisites, NOT evidence that
production admission/reset creates them. Real HumanSession, RoomLedger, context
reducers and recruitment/reset orchestrators run; native custody/launch is inert.
"""
from contextlib import ExitStack
from copy import copy, deepcopy
from dataclasses import replace
import time
import json
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas.claude_native_admission import NativeClaudeRoot
from uas.ledger import LedgerError, Origin
from uas.kernel_origin import OriginDenied
from uas.native_helper import NativeDescendantLease
from uas.native_host_forge import NativeHostForge
from uas.native_review_host import NativeReviewIdentity
from uas.native_reviewer_recruitment import NativeReviewerRecruitment
import test_native_reviewer_recruitment_adversarial as recruitment_fixture


class NativeReviewerResetAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.case = recruitment_fixture.RecruitmentAdversarialTests()
        self.case.setUp(); self.addCleanup(self.case.doCleanups)
        c = self.case
        self.previous = c.recruitment
        self.old_root = c.recruit()
        self.old_root.forge_service.binding.epoch = 1
        self.old_run = c.run_id
        old_scope = {'room_id': c.room['id'], 'participant_id': c.reviewer,
            'run_id': self.old_run, 'generation': 1, 'context_generation': 1}
        self.old_root.recipe = N(session_id='old-native-session', scope=deepcopy(old_scope))
        c.launcher.control = object()
        c.launcher.stack = ExitStack(); self.addCleanup(c.launcher.stack.close)
        c.launcher.budget = N(remaining=lambda limit: limit)
        self.target = 'provided-active-target'
        self.pi = copy(c.pi)
        self.pi.launch = N(incarnation='provided-pi', native_recipe=N(scope={
            'room_id': c.room['id'], 'participant_id': c.participant, 'run_id': self.target,
            'generation': 1, 'context_generation': 2}))
        self.pi.forge_service = copy(c.pi.forge_service)
        self.pi.forge_service.binding = N(operation_id='provided-pi')
        self.pi.forge_service.origin = replace(c.pi.forge_service.origin, incarnation_id='provided-pi')
        c.launcher.started[c.participant] = self.pi
        def supplied_target(state):
            old = state['runs'][self.old_run]
            target = deepcopy(old); target.update(run_id=self.target, status='ACTIVE', admission_operation='provided-active')
            old['status'] = 'CLOSED'
            state['runs'][self.target] = target
            old_admission = state['run_admissions'][self.old_run]
            target_admission = deepcopy(old_admission); target_admission['status'] = 'ACTIVE'
            old_admission['status'] = 'CLOSED'
            state['run_admissions'][self.target] = target_admission
            contexts = state['fixture_context']
            contexts['runs'][self.old_run].update(status='CLOSED', terminal_fact='COMPLETED')
            contexts['runs'][self.target] = {'status': 'OPEN', 'generation': 1, 'terminal_fact': None}
            contexts['participants'][c.participant].update(context_generation=2, bound_run={
                'run_id': self.target, 'generation': 1}, reserved_run=None, reset=None, status='READY')
            state['peer_traffic']['connections'][c.participant].update(
                incarnation_id='provided-pi', attachment_id='admit-provided-pi', context_generation=2, readiness='safe')
        c.seed(supplied_target)
        c.source['run_id'] = self.target
        self.owner = NativeReviewerRecruitment(c.admission, self.pi, self.previous.provenance,
                                               self.previous.resolver, self.previous.binding)
        self.attempts = []; self.admits = []; self.retired = False
        self.after_retire = lambda: None; self.mutate_proof = lambda root: None
        self.retire_error = None
        from uas.native_claude_retirement import NativeClaudeRetirement
        def initialize(retirement, root, *, lifecycle):
            self.assertIs(root, self.old_root); lifecycle.require(c.supervisor)
        def retire(retirement, *, timeout):
            self.attempts.append('retire')
            if self.retire_error is not None: raise self.retire_error
            self.retired = True
            self.after_retire()
        def exited(retirement, root):
            self.assertIs(root, self.old_root)
            if not self.retired: raise LedgerError('CONTROLLED_RETIREMENT_UNVERIFIED')
        # Patch methods on the genuine typed boundary, not the reset coordinator.
        patches = ExitStack(); self.addCleanup(patches.close)
        patches.enter_context(patch.object(NativeClaudeRetirement, '__init__', initialize))
        patches.enter_context(patch.object(NativeClaudeRetirement, 'retire', retire))
        patches.enter_context(patch.object(NativeClaudeRetirement, 'require_exited', exited))
        patches.enter_context(patch.object(NativeClaudeRetirement, 'close', lambda _: None))
        def launch(operation, run, generation):
            self.attempts.append('launch')
            self.owner._allowed()
            root = object.__new__(NativeClaudeRoot)
            scope = self.owner._reset.contexts.pending_scope(self.owner._reset.reset_id)
            root.recipe = N(scope=deepcopy(scope), session_id='new-native-session')
            root._prepared_initialization = {'deadline': time.monotonic() + 60, 'epoch': self.owner._reset.next_epoch}
            root._prepared_admit_started = False
            root._native_readiness_json = json.dumps({'scope': deepcopy(scope), 'native': {
                'session_id': 'new-native-session', 'source': 'fresh-home-explicit-session-native-idle-no-input'}})
            root.current = Mock()
            root.helper_lease = object.__new__(NativeDescendantLease)
            root.helper_lease.root = root
            root.helper_lease.state = 'released'
            root.helper_lease.current = Mock()
            root.helper_lease._lineage = N(current=Mock())
            root.review_host = root.forge_service = None
            self.owner.root = root
            self.mutate_proof(root)
            self.owner._reset.complete(root)  # Actual human-authorized canonical success reducer.
            committed = self.row()
            self.assertEqual((committed['context_generation'], committed['reset']['status']), (2, 'SUCCEEDED'))
            self.admits.append((run, generation, scope['context_generation']))
            ingress = object.__new__(NativeHostForge); ingress.client = c.owner_client
            ingress.origin = Origin(self.owner.selected['actor'], c.reviewer, 'new-reviewer',
                                    'new-reviewer-authority', ('forge-read', 'review'))
            ingress.binding = N(operation_id='new-reviewer', epoch=self.owner._reset.next_epoch); ingress._current = lambda: True
            c.hub.connect('admit-new-reviewer', c.reviewer, 'new-reviewer', object(), context_generation=2)
            root.forge_service = ingress
            root.review_host = N(identity=NativeReviewIdentity((self.pi.forge_service, ingress),
                c.ledger, self.owner.provenance, self.owner.resolver, self.owner.binding))
            return root
        self.owner._launch = launch

    def recruit(self, operation='reset-reviewer', session=None):
        return self.owner.recruit(operation, self.target, 1,
            session=self.case.session if session is None else session, reset_from=self.previous)

    def row(self):
        return self.case.ledger.snapshot()['state']['fixture_context']['participants'][self.case.reviewer]

    def assert_pending_without_admit(self):
        row = self.row()
        self.assertEqual(row['status'], 'RESETTING')
        self.assertEqual(row['context_generation'], 1)
        self.assertEqual(row['reset']['status'], 'REQUESTED')
        self.assertFalse(self.admits)

    def test_success_is_human_attributed_generation_changes_before_admit_and_retry_is_exact(self):
        root = self.recruit()
        self.assertEqual(self.admits, [(self.target, 1, 2)])
        self.assertEqual(self.row()['context_generation'], 2)
        self.assertEqual(self.row()['reset']['status'], 'SUCCEEDED')
        rows = self.case.ledger._connection().execute('SELECT * FROM operations').fetchall()
        # Persisted actual authenticated HumanSession, never a manufactured system origin.
        reset_rows = [json.loads(row['canonical']) for row in rows
                      if json.loads(row['canonical'])['command']['kind'].startswith('context.native-reset.')]
        self.assertEqual(len(reset_rows), 2)
        for row in reset_rows:
            self.assertEqual(row['origin'], self.case.human.canonical())
            self.assertEqual(row['command']['target'], self.target)
            self.assertEqual(row['command']['generation'], 1)
        root.current.assert_called()
        before = self.case.ledger.snapshot()
        self.assertIs(root, self.recruit())
        self.assertEqual(before, self.case.ledger.snapshot())
        self.assertEqual(self.attempts, ['retire', 'launch'])
        with self.assertRaisesRegex(LedgerError, 'OPERATION_CONFLICT'): self.recruit('different-op')

    def test_open_predecessor_denies_before_reset_or_retirement(self):
        self.case.seed(lambda state: state['runs'][self.old_run].update(status='ACTIVE'))
        before = self.case.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError, 'PRECEDING_RUN_OPEN'): self.recruit()
        self.assertEqual(before, self.case.ledger.snapshot()); self.assertFalse(self.attempts)

    def test_exhausted_or_invalid_epoch_refuses_before_reset(self):
        for epoch in (True, 0, 2**53 - 1):
            self.old_root.forge_service.binding.epoch = epoch
            before = self.case.ledger.snapshot()
            with self.assertRaisesRegex(LedgerError, 'EPOCH_EXHAUSTED'): self.recruit()
            self.assertEqual(before, self.case.ledger.snapshot())
            self.assertFalse(self.attempts)

    def test_old_attachment_lost_or_replaced_at_request_commit_denies(self):
        from uas.native_reviewer_reset import NativeReviewerReset
        original = NativeReviewerReset.request_locked
        for field, value in (('readiness', 'lost'), ('attachment_id', 'replaced')):
            with self.subTest(field=field):
                c = NativeReviewerResetAdversarialTests(); c.setUp(); self.addCleanup(c.doCleanups)
                before = deepcopy(c.row())
                def race(reset):
                    c.case.seed(lambda state: state['peer_traffic']['connections'][c.case.reviewer].update({field: value}))
                    return original(reset)
                with patch.object(NativeReviewerReset, 'request_locked', race):
                    with self.assertRaisesRegex(LedgerError, 'STALE_CONNECTION'): c.recruit()
                self.assertEqual(c.row(), before)
                self.assertFalse(c.attempts); self.assertFalse(c.admits)

    def test_helper_or_lineage_loss_after_prepare_keeps_generation(self):
        for field in ('current', '_lineage'):
            with self.subTest(field=field):
                c = NativeReviewerResetAdversarialTests(); c.setUp(); self.addCleanup(c.doCleanups)
                def lost(root):
                    current = Mock(side_effect=OriginDenied('controlled helper exited'))
                    if field == 'current': root.helper_lease.current = current
                    else: root.helper_lease._lineage.current = current
                c.mutate_proof = lost
                with self.assertRaises(OriginDenied): c.recruit()
                c.assert_pending_without_admit(); self.assertEqual(c.attempts, ['retire', 'launch'])

    def test_retirement_timeout_keeps_generation_and_resetting_without_new_launch(self):
        self.retire_error = TimeoutError('controlled owned-task timeout')
        with self.assertRaises(TimeoutError): self.recruit()
        self.assert_pending_without_admit(); self.assertEqual(self.attempts, ['retire'])
        self.assertFalse(self.owner._started)

    def test_target_source_and_human_changes_after_retirement_prevent_new_launch(self):
        for change in ('target', 'source', 'session'):
            with self.subTest(change=change):
                c = NativeReviewerResetAdversarialTests(); c.setUp(); self.addCleanup(c.doCleanups)
                if change == 'target':
                    c.after_retire = lambda: c.case.seed(lambda state: state['runs'][c.target].update(status='PAUSED'))
                elif change == 'source': c.after_retire = lambda: c.case.source.update(checkout='replaced')
                else: c.after_retire = lambda: setattr(c.case, 'connected', False)
                with self.assertRaises(LedgerError): c.recruit()
                c.assert_pending_without_admit(); self.assertEqual(c.attempts, ['retire'])

    def test_fresh_scope_session_idle_proof_and_original_deadline_required(self):
        def proof(root, field, value):
            document = root.native_readiness; document[field].update(value)
            root._native_readiness_json = json.dumps(document)
        mutations = {
            'old-session': lambda root: setattr(root.recipe, 'session_id', 'old-native-session'),
            'wrong-scope': lambda root: root.scope.update(context_generation=1),
            'wrong-proof-scope': lambda root: proof(root, 'scope', {'run_id': 'other'}),
            'wrong-proof-session': lambda root: proof(root, 'native', {'session_id': 'other'}),
            'not-fresh': lambda root: proof(root, 'native', {'source': 'resumed-history'}),
            'expired': lambda root: root._prepared_initialization.update(deadline=0),
            'old-epoch': lambda root: root._prepared_initialization.update(epoch=1),
            'already-admitted': lambda root: setattr(root, '_prepared_admit_started', True),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                c = NativeReviewerResetAdversarialTests(); c.setUp(); self.addCleanup(c.doCleanups)
                c.mutate_proof = mutation
                with self.assertRaisesRegex(LedgerError, 'FRESH_PROOF_REQUIRED'): c.recruit()
                c.assert_pending_without_admit(); self.assertEqual(c.attempts, ['retire', 'launch'])
                with self.assertRaisesRegex(LedgerError, 'RECONCILIATION_REQUIRED'): c.recruit()
                self.assertEqual(c.attempts, ['retire', 'launch'])

    def test_disconnected_or_wrong_human_session_denies_before_reset(self):
        before = self.case.ledger.snapshot()
        other = replace(self.case.session, human=replace(self.case.human, actor_id='other-human'))
        with self.assertRaises(LedgerError): self.recruit(session=other)
        self.case.connected = False
        with self.assertRaisesRegex(LedgerError, 'AUTHORIZATION_REVOKED'): self.recruit()
        self.assertEqual(before, self.case.ledger.snapshot()); self.assertFalse(self.attempts)
