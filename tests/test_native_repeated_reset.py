"""Generation-two predecessors through real reset reducers, inert task effects.

The earlier completion/next ACTIVE Run are controlled prerequisites, as in the
existing native reset suites. These tests do not claim end-to-end three Runs.
"""
from copy import deepcopy
from types import SimpleNamespace as N
import json
import time
import unittest

from uas.context import MAX_CONTEXT_GENERATION
from uas.ledger import LedgerError
from uas.native_pi_reset import NativePiReset
from uas.workstation_control import SupervisorAdmission
from uas.claude_native_admission import NativeClaudeRoot
from uas.native_helper import NativeDescendantLease
import test_native_completed_retirement as retirement_fixture
import test_native_reviewer_reset_adversarial as reviewer_fixture


class RepeatedNativeResetTests(unittest.TestCase):
    def pi_case(self, generation=2):
        c=retirement_fixture.CompletedRetirementTests();c.setUp();self.addCleanup(c.doCleanups)
        c.pi.launch.native_recipe.scope['context_generation']=generation
        c.root.recipe.scope['context_generation']=generation
        c.pi.forge_service.binding.epoch=generation
        c.pi.launch.native_readiness={'native':{'session_id':'prior-session','runtime_id':'prior-runtime'}}
        def previous(state):
            for participant in (c.participant,c.reviewer):
                state['fixture_context']['participants'][participant]['context_generation']=generation
                state['peer_traffic']['connections'][participant]['context_generation']=generation
        c.seed(previous);c.retire()
        retirement=c.admission._completed_retirements['retire']
        c.seed(lambda state:state['run_admissions'][c.run_id].update(status='CLOSED'))
        with c.admission.human_scope(c.session):
            run,_=c.admission._prepare('third-run',3,c.participant,c.human)
        pending=c.ledger.snapshot()['state']['run_admissions'][run]
        return c,retirement,run,pending

    def test_pi_third_run_uses_generation_three_and_exact_original_retirement(self):
        c,retirement,run,pending=self.pi_case()
        reset=NativePiReset(c.admission,run,pending,retirement)
        self.assertEqual((reset.expected_generation,reset.next_generation,reset.next_epoch),(2,3,3))
        with c.admission.human_scope(c.session):
            reset.request(lambda:c.connected and c.authorized)
            scope=reset.contexts.pending_scope(reset.reset_id)
            self.assertEqual(scope['context_generation'],3)
            handle=object.__new__(SupervisorAdmission);handle.seat=N(participant_id=c.participant)
            handle._current=lambda:True
            handle.launch=N(native_recipe=N(scope=scope,manifest_digest='manifest'),native_readiness={
                'scope':deepcopy(scope),'profile_digest':'manifest','native':{
                    'source':'native-empty-session-and-no-pending-messages',
                    'session_id':'third-session','runtime_id':'third-runtime'}})
            reset.complete(handle)
        row=c.ledger.snapshot()['state']['fixture_context']['participants'][c.participant]
        self.assertEqual((row['context_generation'],row['reset']['status']),(3,'SUCCEEDED'))
        self.assertEqual(row['reserved_run'],{'run_id':run,'generation':1})
        self.assertEqual(c.pi.launch.native_recipe.scope['context_generation'],2)
        self.assertIs(reset.retirement,retirement)
        self.assertIsNone(c.admission._session)

    def test_pi_reused_or_skipped_generation_and_wrong_predecessor_are_rejected(self):
        c,retirement,run,pending=self.pi_case()
        before=c.ledger.snapshot()
        for generation in (True,1,2,4,MAX_CONTEXT_GENERATION+1):
            with self.subTest(generation=generation),self.assertRaises(LedgerError):
                NativePiReset(c.admission,run,{**pending,'context_generation':generation},retirement)
        c.pi.launch.native_recipe.scope['run_id']='other-run'
        with self.assertRaisesRegex(LedgerError,'OWNER_REQUIRED'):
            NativePiReset(c.admission,run,pending,retirement)
        self.assertEqual(c.ledger.snapshot(),before)

    def test_pi_generation_exhaustion_fails_without_reset(self):
        c,retirement,run,pending=self.pi_case(MAX_CONTEXT_GENERATION-1)
        reset=NativePiReset(c.admission,run,pending,retirement)
        self.assertEqual(reset.next_generation,MAX_CONTEXT_GENERATION)
        c.pi.launch.native_recipe.scope['context_generation']=MAX_CONTEXT_GENERATION
        before=c.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'OWNER_REQUIRED'):
            NativePiReset(c.admission,run,pending,retirement)
        self.assertEqual(c.ledger.snapshot(),before)

    def reviewer_case(self):
        c=reviewer_fixture.NativeReviewerResetAdversarialTests();c.setUp();self.addCleanup(c.doCleanups)
        c.old_root.recipe.scope['context_generation']=2
        c.old_root.forge_service.binding.epoch=2
        c.pi.launch.native_recipe.scope['context_generation']=3
        def previous(state):
            state['fixture_context']['participants'][c.case.reviewer]['context_generation']=2
            state['peer_traffic']['connections'][c.case.reviewer]['context_generation']=2
            state['fixture_context']['participants'][c.case.participant]['context_generation']=3
            state['peer_traffic']['connections'][c.case.participant]['context_generation']=3
        c.case.seed(previous)
        return c

    def test_claude_third_run_keeps_retained_exit_and_new_home_session_proof(self):
        c=self.reviewer_case()
        def launch(operation,run,generation):
            c.owner._allowed()
            reset=c.owner._reset
            self.assertEqual((reset.expected_generation,reset.next_generation,reset.next_epoch),(2,3,3))
            scope=reset.contexts.pending_scope(reset.reset_id)
            root=object.__new__(NativeClaudeRoot)
            root.recipe=N(scope=deepcopy(scope),session_id='third-reviewer-session')
            root._prepared_initialization={'deadline':time.monotonic()+20,'epoch':3}
            root._prepared_admit_started=False
            root._native_readiness_json=json.dumps({'scope':scope,'native':{
                'session_id':'third-reviewer-session','source':'fresh-home-explicit-session-native-idle-no-input'}})
            root.current=lambda:True
            root.helper_lease=object.__new__(NativeDescendantLease);root.helper_lease.root=root
            root.helper_lease.state='released';root.helper_lease.current=lambda:True
            root.helper_lease._lineage=N(current=lambda:True)
            root.review_host=root.forge_service=None;c.owner.root=root
            reset.complete(root)
            return root
        c.owner._launch=launch
        c.recruit('reviewer-third-run')
        self.assertTrue(c.retired)
        self.assertEqual((c.row()['context_generation'],c.row()['reset']['status']),(3,'SUCCEEDED'))
        self.assertEqual(c.old_root.recipe.scope['context_generation'],2)
        self.assertIsNone(c.owner._session)

    def test_claude_exhaustion_refuses_before_retirement_or_reset(self):
        c=self.reviewer_case()
        c.old_root.recipe.scope['context_generation']=MAX_CONTEXT_GENERATION
        c.case.seed(lambda state:state['fixture_context']['participants'][c.case.reviewer].update(
            context_generation=MAX_CONTEXT_GENERATION))
        before=c.case.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'GENERATION_EXHAUSTED'):
            c.recruit('exhausted')
        self.assertEqual(c.case.ledger.snapshot(),before)
        self.assertFalse(c.attempts)
