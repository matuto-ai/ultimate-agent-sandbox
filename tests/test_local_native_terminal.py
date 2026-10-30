"""Canonical terminal reducer with retained native-effect doubles only."""
from dataclasses import replace
import unittest

import test_local_native_stop as fixture
from uas.local_native_stop import LocalNativeStopObservations
from uas.local_native_terminal import terminal_stopped_run, retirement_for, preceding_scope
from uas.ledger import LedgerError


class TerminalTests(fixture.LocalStopTests):
    # Inherited completed tests remain relevant; active cases explicitly activate.
    def activate(self):
        def active(state):
            state['runs'][self.run_id].update(status='ACTIVE',outcome=None,completion=None)
            state['fixture_context']['runs'][self.run_id].update(status='OPEN')
            state['run_admissions'][self.run_id]['status']='ACTIVE'
        self.seed(active)
        self.session=replace(self.session,authorized=lambda session,action:action=='terminal-stop')
        bundle=LocalNativeStopObservations(self.graph);bundle.retire();return bundle
    def terminal(self,bundle,**kw):
        return terminal_stopped_run(self.admission,bundle,kw.get('operation','terminal'),self.run_id,
            kw.get('generation',1),kw.get('revision',0),kw.get('reason','operator-stopped'),
            session=kw.get('session',self.session))
    def test_terminal_fences_without_claiming_completion_or_repeating_effects(self):
        bundle=self.activate();count=len(self.stopped)
        result=self.terminal(bundle);self.assertEqual(('CLOSED','stopped',2),
            (result['status'],result['outcome'],result['generation']))
        proof=retirement_for(self.admission,result['native_stop']);self.assertTrue(proof.require_terminal())
        self.assertEqual(2,preceding_scope(proof,self.participant)['generation'])
        self.assertEqual(1,proof.targets[0]['scope']['generation'])
        self.assertEqual('RETAINED',self.row()['checkout_release']['status'])
        self.assertEqual(result,self.terminal(bundle));self.assertEqual(count,len(self.stopped))
        self.assertIsNone(self.admission._session)
    def test_open_only_session_cannot_terminalize(self):
        bundle=self.activate();session=replace(self.session,authorized=lambda s,a:a=='open-run')
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.terminal(bundle,session=session)
        self.assertEqual('ACTIVE',self.row()['status']);self.assertFalse(getattr(self.admission,'_local_terminal_proofs',{}))
    def test_active_observations_cannot_be_adopted_as_completed(self):
        bundle=self.activate()
        with self.assertRaisesRegex(LedgerError,'SCOPE_CHANGED'):bundle.adopt_completed(self.admission,self.recruitment,'retire',self.run_id)
    def test_stale_revision_refuses_without_canonical_fence(self):
        bundle=self.activate()
        with self.assertRaisesRegex(LedgerError,'SCOPE_CHANGED'):self.terminal(bundle,revision=1)
        self.assertEqual('ACTIVE',self.row()['status'])
    def test_changed_attachment_or_unknown_does_not_terminalize(self):
        bundle=self.activate();bundle.unknown=True
        with self.assertRaises(LedgerError):self.terminal(bundle)
        self.assertEqual('ACTIVE',self.row()['status'])
    def test_missing_control_capability_refuses(self):
        bundle=self.activate();session=replace(self.session,human=replace(self.human,capabilities=('human-open-run',)))
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.terminal(bundle,session=session)
    def test_noncompleted_refused_before_any_capture(self):
        # Active capture is now allowed for root Stop, never completed adoption.
        bundle=self.activate()
        with self.assertRaises(LedgerError):self.adopt(bundle)
    def test_fenced_predecessor_can_reset_pi_with_fresh_proof(self):
        from copy import deepcopy
        from types import SimpleNamespace as N
        from uas.native_pi_reset import NativePiReset
        from uas.workstation_control import SupervisorAdmission
        bundle=self.activate();result=self.terminal(bundle)
        proof=retirement_for(self.admission,result['native_stop'])
        self.pi.forge_service.binding.epoch=1
        self.pi.launch.native_readiness={'native':{'session_id':'old-session','runtime_id':'old-runtime'}}
        self.session=replace(self.session,authorized=lambda s,a:True)
        with self.admission.human_scope(self.session):
            run,_=self.admission._prepare('next',2,self.participant,self.human)
            pending=self.ledger.snapshot()['state']['run_admissions'][run]
            reset=NativePiReset(self.admission,run,pending,proof)
            reset.request(lambda:True)
            scope=reset.contexts.pending_scope(reset.reset_id)
            self.assertEqual(2,reset.preceding['generation']);self.assertEqual(1,self.pi.launch.native_recipe.scope['generation'])
            fresh=object.__new__(SupervisorAdmission);fresh.seat=N(participant_id=self.participant);fresh._current=lambda:True
            fresh.launch=N(native_recipe=N(scope=scope,manifest_digest='manifest'),native_readiness={
                'scope':deepcopy(scope),'profile_digest':'manifest','native':{
                    'source':'native-empty-session-and-no-pending-messages','session_id':'fresh-session','runtime_id':'fresh-runtime'}})
            self.launcher.started[self.participant]=fresh
            reset.complete(fresh)
        self.assertTrue(proof.require_terminal())
        self.assertEqual('SUCCEEDED',self.ledger.snapshot()['state']['fixture_context']['participants'][self.participant]['reset']['status'])
    def test_late_canonical_change_cannot_be_rebaselined_by_retry(self):
        bundle=self.activate();self.terminal(bundle)
        self.seed(lambda state:state['runs'][self.run_id].update(outcome='completed'))
        with self.assertRaisesRegex(LedgerError,'UNVERIFIED'):self.terminal(bundle)

    def test_terminal_reviewer_reset_uses_fenced_scope_not_old_native_generation(self):
        from copy import copy,deepcopy
        from types import SimpleNamespace as N
        from uas.native_reviewer_recruitment import NativeReviewerRecruitment
        from uas.native_reviewer_reset import NativeReviewerReset
        bundle=self.activate();result=self.terminal(bundle)
        proof=retirement_for(self.admission,result['native_stop'])
        self.root.recipe.session_id='old-reviewer-session';self.root.forge_service.binding.epoch=1
        self.launcher.control=object()
        newpi=copy(self.pi);newpi.launch=N(incarnation='next-pi',native_recipe=N(scope={
            'room_id':self.room['id'],'participant_id':self.participant,'run_id':'next-run',
            'generation':1,'context_generation':2}))
        newpi.forge_service=copy(self.pi.forge_service)
        newpi.forge_service.origin=replace(self.pi.forge_service.origin,incarnation_id='next-pi')
        newpi.forge_service.binding=N(operation_id='next-pi')
        self.launcher.started[self.participant]=newpi
        def active(state):
            row=deepcopy(state['runs'][self.run_id]);row.update(run_id='next-run',generation=1,status='ACTIVE',
                outcome=None,completion=None,control_revision=0,control_pending=None,native_stop=None,
                admission_operation='next')
            state['runs']['next-run']=row
            state['fixture_context']['runs']['next-run']={'status':'OPEN','generation':1,'terminal_fact':None}
            state['fixture_context']['participants'][self.participant].update(bound_run={'run_id':'next-run','generation':1},
                reserved_run=None,context_generation=2,reset=None)
            state['peer_traffic']['connections'][self.participant].update(incarnation_id='next-pi',
                attachment_id='admit-next-pi',context_generation=2,readiness='safe')
        self.seed(active)
        newer=NativeReviewerRecruitment(self.admission,newpi,self.recruitment.provenance,
            self.recruitment.resolver,self.recruitment.binding)
        newer._pin={'run_id':'next-run','generation':1}
        with self.supervisor._locked() as capability:
            newer._capability=capability
            reset=NativeReviewerReset(newer,self.recruitment,'next-reviewer')
            reset.old_current(self.ledger.snapshot()['state'])
            self.assertIs(reset.completed,proof)
            self.assertEqual(2,reset.preceding['generation'])
            self.assertEqual(1,self.root.scope['generation'])
            self.assertEqual(2,reset.next_generation)
            self.assertIs(reset.retirement,proof.retirements[self.reviewer])
        newer._capability=None
    def test_bool_or_float_scope_is_rejected_before_any_terminal_intent(self):
        bundle=self.activate()
        for kwargs in ({'generation':True},{'generation':1.0},{'revision':False},{'revision':0.0}):
            with self.subTest(kwargs=kwargs),self.assertRaisesRegex(LedgerError,'SCOPE_CHANGED'):
                self.terminal(bundle,**kwargs)
        self.assertEqual('ACTIVE',self.row()['status'])
        self.assertFalse(getattr(self.admission,'_local_terminal_proofs',{}))
    def test_attachment_change_after_fence_cannot_verify_terminal(self):
        from unittest.mock import patch
        from uas.local_native_terminal import LocalNativeTerminalControl
        bundle=self.activate()
        original=LocalNativeTerminalControl._stop_owned
        def changed(control,pending,human,command):
            self.seed(lambda state:state['peer_traffic']['connections'][self.reviewer].update(attachment_id='replacement'))
            return original(control,pending,human,command)
        with patch.object(LocalNativeTerminalControl,'_stop_owned',changed):
            with self.assertRaisesRegex(LedgerError,'SCOPE_CHANGED'):self.terminal(bundle)
        self.assertEqual('PAUSED',self.row()['status'])
        self.assertIsNotNone(self.row()['control_pending'])
        self.assertNotEqual('VERIFIED',(self.row().get('native_stop') or {}).get('status'))
    def lost_terminal_return(self,bundle):
        from unittest.mock import patch
        from uas.run_control import RunControl
        original=RunControl.terminal_stop
        def committed_then_lost(control,*args,**kwargs):
            original(control,*args,**kwargs)
            raise OSError('controlled lost return after canonical commit')
        with patch.object(RunControl,'terminal_stop',committed_then_lost):
            with self.assertRaises(OSError):self.terminal(bundle)
        proof=self.admission._local_terminal_proofs['terminal']
        self.assertIsNone(proof.result)
        self.assertEqual('CLOSED',self.row()['status'])
        return proof

    def test_lost_return_after_commit_reconciles_only_original_pinned_state(self):
        bundle=self.activate();proof=self.lost_terminal_return(bundle)
        digest=proof.digest;count=len(self.stopped)
        result=self.terminal(bundle)
        self.assertEqual(proof.expected_result,result)
        self.assertEqual(digest,proof.digest);self.assertEqual(count,len(self.stopped))
        self.assertTrue(proof.require_terminal())

    def test_lost_return_cannot_adopt_changed_policy_checkout_or_completion(self):
        for field in ('policy','checkout','completion'):
            with self.subTest(field=field):
                case=TerminalTests();case.setUp();self.addCleanup(case.doCleanups)
                bundle=case.activate();proof=case.lost_terminal_return(bundle);digest=proof.digest
                def mutate(state):
                    row=state['runs'][case.run_id]
                    if field=='policy':row['policy']['version']='changed'
                    elif field=='checkout':row['checkout']['path']='/different-preserved-worktree'
                    else:row['completion']={'forged':'completion'}
                case.seed(mutate)
                with case.assertRaisesRegex(LedgerError,'UNVERIFIED'):case.terminal(bundle)
                case.assertIsNone(proof.result);case.assertEqual(digest,proof.digest)
                with case.assertRaisesRegex(LedgerError,'UNVERIFIED'):proof.require_terminal()

    def test_wrong_terminal_return_is_not_saved_even_if_commit_succeeded(self):
        from unittest.mock import patch
        from uas.run_control import RunControl
        bundle=self.activate();original=RunControl.terminal_stop
        def wrong(control,*args,**kwargs):
            result=original(control,*args,**kwargs)
            return {**result,'reason':'different'}
        with patch.object(RunControl,'terminal_stop',wrong):
            with self.assertRaisesRegex(LedgerError,'SCOPE_CHANGED'):self.terminal(bundle)
        proof=self.admission._local_terminal_proofs['terminal'];self.assertIsNone(proof.result)
        self.assertEqual(proof.expected_result,self.terminal(bundle))
    def test_lost_return_cannot_accept_replaced_target_attachment(self):
        bundle=self.activate();proof=self.lost_terminal_return(bundle)
        self.seed(lambda state:state['peer_traffic']['connections'][self.reviewer].update(attachment_id='replacement'))
        with self.assertRaisesRegex(LedgerError,'SCOPE_CHANGED'):self.terminal(bundle)
        self.assertIsNone(proof.result)
