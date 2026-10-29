"""Actual completed Run control reducers; only held-task effects controlled."""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch
from uas.ledger import LedgerError
from uas.kernel_origin import OriginDenied
from uas.native_pi_retirement import NativePiRetirement
from uas.native_claude_retirement import NativeClaudeRetirement
import test_native_reviewer_recruitment_adversarial as fixture

class CompletedRetirementTests(unittest.TestCase):
    seed=fixture.RecruitmentAdversarialTests.seed
    open=fixture.RecruitmentAdversarialTests.open
    recruit=fixture.RecruitmentAdversarialTests.recruit
    def setUp(self):
        fixture.RecruitmentAdversarialTests.setUp(self);self.root=self.recruit()
        self.launcher.exec_seat=N(participant_id=self.participant)
        self.launcher.stack=ExitStack();self.addCleanup(self.launcher.stack.close)
        self.launcher.budget=N(remaining=lambda cap:cap)
        state=self.ledger.snapshot()['state'];context=state['fixture_context']['participants'][self.reviewer]
        self.root.recipe=N(scope={'room_id':self.room['id'],'participant_id':self.reviewer,
            **(context['bound_run'] or context['reserved_run']),'context_generation':context['context_generation']})
        self.human=replace(self.human,capabilities=('human-open-run','human-control-run'))
        self.session=replace(self.session,human=self.human)
        self.completion={'merge_sha':'f'*40,'proof':'existing-authoritative-completion'}
        def complete(state):
            state['runs'][self.run_id].update(status='CLOSED',outcome='completed',completion=deepcopy(self.completion),control_revision=0,control_pending=None)
            state['fixture_context']['runs'][self.run_id]['status']='CLOSED'
        self.seed(complete)
        self.before=deepcopy(self.ledger.snapshot()['state']['runs'][self.run_id])
        self.captured=[];self.stopped=[];self.proven=set();self.after_capture=lambda:None;self.after_stop=lambda held:None
        self.fail=None;outer=self
        def capture(obj,held,*,lifecycle):
            lifecycle.require(outer.supervisor);obj.held=held;obj.attempted=False;obj.unknown=False
            outer.captured.append(held);outer.after_capture()
        def retire(obj,timeout=5):
            if not obj.attempted:
                obj.attempted=True;outer.stopped.append(obj.held);outer.after_stop(obj.held)
                if outer.fail is obj.held:obj.unknown=True;raise TimeoutError('unknown controlled task retirement')
                outer.proven.add(id(obj.held))
            return {'state':'unknown' if obj.unknown else 'exited'}
        def require(obj,held=None):
            if held is not obj.held or obj.unknown or id(obj.held) not in outer.proven:raise OriginDenied('unverified held task')
            return True
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        for cls in (NativePiRetirement,NativeClaudeRetirement):
            self.stack.enter_context(patch.object(cls,'__init__',capture));self.stack.enter_context(patch.object(cls,'retire',retire))
            self.stack.enter_context(patch.object(cls,'require_exited',require));self.stack.enter_context(patch.object(cls,'close',lambda obj:None))
    def retire(self,operation='retire',session=None):
        return self.admission.retire_completed(operation,self.run_id,1,0,session=self.session if session is None else session,reviewer=self.recruitment)
    def row(self):return self.ledger.snapshot()['state']['runs'][self.run_id]
    def unchanged_completion(self):
        for key in ('status','outcome','completion','review_stage','checkout','policy','generation'):
            self.assertEqual(self.before.get(key),self.row().get(key),key)
    def test_all_targets_and_exact_receipt_retry_preserve_completed_truth(self):
        result=self.retire();self.assertEqual({id(self.pi),id(self.root)},set(map(id,self.captured)))
        self.assertEqual({id(self.pi),id(self.root)},set(map(id,self.stopped)))
        self.assertEqual('VERIFIED',result['native_stop']['status']);self.assertEqual('RETAINED',result['checkout_release']['status'])
        self.unchanged_completion();counts=(len(self.captured),len(self.stopped));self.assertEqual(result,self.retire());self.assertEqual(counts,(len(self.captured),len(self.stopped)))
    def test_one_unknown_target_keeps_pending_and_cannot_replay_or_verify(self):
        self.fail=self.root
        with self.assertRaises(TimeoutError):self.retire()
        self.unchanged_completion();self.assertIsNotNone(self.row()['control_pending']);self.assertNotEqual('VERIFIED',self.row().get('native_stop',{}).get('status'))
        stopped=list(self.stopped);self.proven.add(id(self.root))
        with self.assertRaises(OriginDenied):self.retire()
        self.assertEqual(stopped,self.stopped);self.assertIsNotNone(self.row()['control_pending'])
    def test_human_disconnect_before_effect_refuses(self):
        self.connected=False
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.retire()
        self.assertFalse(self.captured);self.assertFalse(self.stopped);self.unchanged_completion()
    def test_revoked_human_after_capture_stops_no_target(self):
        self.after_capture=lambda:setattr(self,'connected',False)
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.retire()
        self.assertFalse(self.stopped);self.assertIsNotNone(self.row()['control_pending']);self.unchanged_completion()
    def test_changed_completion_after_first_effect_cannot_mark_verified(self):
        self.after_stop=lambda held:self.seed(lambda state:state['runs'][self.run_id]['completion'].update(merge_sha='e'*40))
        with self.assertRaises(LedgerError):self.retire()
        self.assertEqual(1,len(self.stopped))
        self.assertNotEqual('VERIFIED',self.row().get('native_stop',{}).get('status'));self.assertIsNotNone(self.row()['control_pending'])
    def test_replaced_target_attachment_after_capture_denies(self):
        self.after_capture=lambda:self.seed(lambda state:state['peer_traffic']['connections'][self.reviewer].update(attachment_id='replacement'))
        with self.assertRaisesRegex(LedgerError,'NATIVE_OWNERSHIP_CHANGED'):self.retire()
        self.assertFalse(self.stopped);self.unchanged_completion()
    def test_noncompleted_run_and_new_operation_do_not_reuse_receipt(self):
        self.seed(lambda state:state['runs'][self.run_id].update(status='ACTIVE'))
        with self.assertRaisesRegex(LedgerError,'COMPLETED_RETIREMENT_SCOPE_CHANGED'):self.retire()
        self.assertFalse(self.captured);self.assertFalse(self.stopped)

    def test_stop_capability_and_authenticated_session_required(self):
        session=replace(self.session,human=replace(self.human,capabilities=('human-open-run',)))
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.retire(session=session)
        with self.assertRaisesRegex(LedgerError,'MANAGER_AUTHENTICATION_REQUIRED'):
            self.admission.retire_completed('other',self.run_id,1,0,session=None,reviewer=self.recruitment)
        self.assertFalse(self.captured);self.assertFalse(self.stopped);self.unchanged_completion()

    def test_live_owner_replacement_cannot_be_accepted_from_old_identity(self):
        self.after_capture=lambda:setattr(self.recruitment,'root',object())
        with self.assertRaisesRegex(LedgerError,'NATIVE_OWNERSHIP_CHANGED'):self.retire()
        self.assertFalse(self.stopped);self.assertIsNotNone(self.row()['control_pending']);self.unchanged_completion()

    def test_missing_second_target_proof_never_finishes(self):
        self.after_stop=lambda held:self.proven.discard(id(self.pi)) if held is self.root else None
        with self.assertRaises(OriginDenied):self.retire()
        self.assertIsNotNone(self.row()['control_pending']);self.assertNotEqual('VERIFIED',self.row().get('native_stop',{}).get('status'))
        self.unchanged_completion()

    def test_changed_retry_revision_conflicts_instead_of_cached_success(self):
        self.retire();counts=(len(self.captured),len(self.stopped));before=self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):
            self.admission.retire_completed('retire',self.run_id,1,1,session=self.session,reviewer=self.recruitment)
        self.assertEqual(before,self.ledger.snapshot());self.assertEqual(counts,(len(self.captured),len(self.stopped)))

    def test_control_revision_change_after_first_stop_prevents_second(self):
        self.after_stop=lambda held:self.seed(lambda state:state['runs'][self.run_id].update(control_revision=999))
        with self.assertRaises(LedgerError):self.retire()
        self.assertEqual(1,len(self.stopped));self.assertIsNotNone(self.row()['control_pending'])
        self.assertNotEqual('VERIFIED',self.row().get('native_stop',{}).get('status'));self.unchanged_completion()
