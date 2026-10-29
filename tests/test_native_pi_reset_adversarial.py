"""Real canonical reset reducers/retained retirement; controlled native effects."""
from copy import deepcopy
from types import SimpleNamespace as N
import unittest
from uas.ledger import LedgerError
from uas.kernel_origin import OriginDenied
from uas.native_pi_reset import NativePiReset
from uas.workstation_control import SupervisorAdmission
import test_native_completed_retirement as fixture

class NativePiResetAdversarialTests(unittest.TestCase):
    seed=fixture.CompletedRetirementTests.seed
    open=fixture.CompletedRetirementTests.open
    recruit=fixture.CompletedRetirementTests.recruit
    retire=fixture.CompletedRetirementTests.retire
    row=fixture.CompletedRetirementTests.row
    def setUp(self):
        fixture.CompletedRetirementTests.setUp(self)
        self.pi.forge_service.binding.epoch=1
        self.pi.launch.native_readiness={'native':{'session_id':'old-session','runtime_id':'old-runtime'}}
        self.retire();self.retirement=self.admission._completed_retirements['retire']
        self.seed(lambda state:state['run_admissions'][self.run_id].update(status='CLOSED'))
        self.newrun=self.admission.run_id('next')
    def prepare(self):
        with self.admission.human_scope(self.session):
            run,_=self.admission._prepare('next',2,self.participant,self.human)
        self.assertEqual(self.newrun,run)
        pending=self.ledger.snapshot()['state']['run_admissions'][run]
        return NativePiReset(self.admission,run,pending,self.retirement)
    def request(self,reset):
        with self.admission.human_scope(self.session):reset.request(lambda:self.connected and self.authorized)
    def fresh(self,reset):
        scope={'room_id':self.room['id'],'participant_id':self.participant,'run_id':self.newrun,'generation':1,'context_generation':2}
        handle=object.__new__(SupervisorAdmission);handle.seat=N(participant_id=self.participant);handle._current=lambda:True
        handle.launch=N(native_recipe=N(scope=scope,manifest_digest='manifest'),native_readiness={
            'scope':scope,'profile_digest':'manifest','native':{'session_id':'new-session','runtime_id':'new-runtime',
                'source':'native-empty-session-and-no-pending-messages'}})
        return handle
    def complete(self,reset,handle):
        with self.admission.human_scope(self.session):reset.complete(handle)
    def context(self):return self.ledger.snapshot()['state']['fixture_context']['participants'][self.participant]
    def test_canonical_request_then_fresh_proof_advances_only_context(self):
        reset=self.prepare();old=deepcopy(self.pi.launch.native_recipe.scope);self.request(reset)
        self.assertEqual('RESETTING',self.context()['status']);self.assertEqual(1,self.context()['context_generation'])
        handle=self.fresh(reset);self.complete(reset,handle)
        self.assertEqual('SUCCEEDED',self.context()['reset']['status']);self.assertEqual(2,self.context()['context_generation'])
        self.assertEqual({'run_id':self.newrun,'generation':1},self.context()['reserved_run'])
        self.assertEqual(old,self.pi.launch.native_recipe.scope);self.assertEqual(2,reset.next_epoch)
        self.assertEqual('PREPARING',self.ledger.snapshot()['state']['run_admissions'][self.newrun]['status'])
    def test_old_session_runtime_scope_or_missing_empty_proof_refuse(self):
        for mutation in ('session','runtime','scope','source'):
            case=NativePiResetAdversarialTests();case.setUp();self.addCleanup(case.doCleanups)
            reset=case.prepare();case.request(reset);handle=case.fresh(reset)
            proof=handle.launch.native_readiness
            if mutation=='session':proof['native']['session_id']='old-session'
            elif mutation=='runtime':proof['native']['runtime_id']='old-runtime'
            elif mutation=='scope':proof['scope']={**proof['scope'],'context_generation':1}
            else:proof['native']['source']='unqualified'
            with self.assertRaisesRegex(LedgerError,'FRESH_PROOF_REQUIRED'):case.complete(reset,handle)
            self.assertEqual('REQUESTED',case.context()['reset']['status']);self.assertEqual(1,case.context()['context_generation'])
    def test_lost_retained_exit_or_changed_old_completion_denies_request(self):
        reset=self.prepare();self.proven.discard(id(self.pi))
        with self.assertRaises(OriginDenied):self.request(reset)
        self.assertIsNone(self.context()['reset'])
        self.proven.add(id(self.pi));self.seed(lambda state:state['runs'][self.run_id]['completion'].update(merge_sha='e'*40))
        with self.assertRaisesRegex(LedgerError,'RETIREMENT_UNVERIFIED'):self.request(reset)
        self.assertIsNone(self.context()['reset'])
    def test_late_authorization_loss_keeps_generation_one(self):
        reset=self.prepare();self.request(reset);handle=self.fresh(reset);self.connected=False
        with self.assertRaisesRegex(LedgerError,'ADMISSION_REVOKED'):self.complete(reset,handle)
        self.assertEqual(1,self.context()['context_generation'])
    def test_second_owned_handle_cannot_replace_uncertain_first(self):
        reset=self.prepare();self.request(reset);handle=self.fresh(reset)
        handle.launch.native_readiness['native']['source']='invalid'
        with self.assertRaises(LedgerError):self.complete(reset,handle)
        with self.assertRaisesRegex(LedgerError,'RECONCILIATION_REQUIRED'):self.complete(reset,self.fresh(reset))
        self.assertEqual(1,self.context()['context_generation'])
    def test_actual_advance_requests_reset_before_allocation_or_launch(self):
        events=[];allocate=self.admission.checkout_client.allocate
        def allocating(*args):
            events.append('allocate');self.assertEqual('REQUESTED',self.context()['reset']['status']);return allocate(*args)
        self.admission.checkout_client.allocate=allocating
        def launch(*args,**kwargs):
            events.append('launch');self.assertIs(type(kwargs['reset']),NativePiReset)
            self.assertEqual(['allocate','launch'],events)
            raise TimeoutError('controlled unknown native launch')
        self.launcher.launch=launch
        with self.assertRaises(TimeoutError):self.admission.open_human('next',2,self.participant,session=self.session)
        self.assertEqual(['allocate','launch'],events);self.assertEqual(1,self.context()['context_generation'])

    def launcher_effects(self,*,uncertain=False):
        from contextlib import ExitStack
        from unittest.mock import patch
        from uas.workstation_exec import ExecLaunch
        from uas.native_pi_recipe import NativePiRecipe
        self.launcher.attempted_runs=set();self.launcher.admissions=[]
        self.launcher.resources.update(pi_manifest_path='/controlled/public-manifest',peer_path='/controlled/peer')
        self.launcher.mounts=[];self.launcher.engine=object();self.launcher.endpoint=object();self.launcher.listener=object()
        self.launcher.admission_seat=N(participant_id=self.participant);self.launcher.control=object();self.launcher.hub_origin=object()
        self.launcher.controller='controller';self.launcher.control_lock=object()
        events=[];outer=self
        def recipe(*args,**kw):return N(scope=kw['scope'],checkout=kw['checkout'],manifest_digest='manifest')
        def init(launch,engine,seat,endpoint,journal,*,native_recipe,timeout):
            launch.native_recipe=native_recipe;launch._native_readiness=None
        def launch(held,listener,*,authorize):
            authorize();events.append('launch')
            if uncertain:raise TimeoutError('controlled native start uncertainty')
        def attach(held,**kw):
            events.append('fresh-proof');held._native_readiness={'scope':kw['scope'],'profile_digest':'manifest',
                'native':{'source':'native-empty-session-and-no-pending-messages','session_id':'new-session','runtime_id':'new-runtime'}}
        def admission(obj,launch,seat,control,**kw):obj.launch=launch;obj.seat=seat;obj._current=lambda:True
        def admit(obj,operation,*,epoch):
            events.append('admit');outer.assertEqual(2,outer.context()['context_generation'])
            outer.assertEqual('SUCCEEDED',outer.context()['reset']['status']);outer.assertEqual(2,epoch)
        stack=ExitStack();self.addCleanup(stack.close)
        for target,name,replacement in ((NativePiRecipe,'from_configuration',recipe),(ExecLaunch,'__init__',init),
                (ExecLaunch,'launch',launch),(ExecLaunch,'attach_native',attach),(ExecLaunch,'close',lambda obj:None),
                (SupervisorAdmission,'__init__',admission),(SupervisorAdmission,'revoke',lambda obj:None),
                (SupervisorAdmission,'attach_forge_service',lambda *args:None)):
            stack.enter_context(patch.object(target,name,replacement))
        stack.enter_context(patch('uas.native_session.admit_once',admit))
        return events

    def test_actual_launcher_fresh_generation_commits_before_admit(self):
        from uas.native_run_admission import NativeRunLauncher
        reset=self.prepare();self.request(reset);pending=self.ledger.snapshot()['state']['run_admissions'][self.newrun]
        events=self.launcher_effects()
        with self.admission.human_scope(self.session):
            handle=NativeRunLauncher.launch(self.launcher,self.newrun,pending,{'path':'/owned/checkout'},authorize=lambda:True,reset=reset)
        self.assertEqual(['launch','fresh-proof','admit'],events);self.assertIs(handle,self.launcher.started[self.participant])
        self.assertEqual(2,self.context()['context_generation'])

    def test_actual_launcher_unknown_start_cannot_be_repeated(self):
        from uas.native_run_admission import NativeRunLauncher
        reset=self.prepare();self.request(reset);pending=self.ledger.snapshot()['state']['run_admissions'][self.newrun]
        events=self.launcher_effects(uncertain=True)
        with self.admission.human_scope(self.session):
            with self.assertRaises(TimeoutError):NativeRunLauncher.launch(self.launcher,self.newrun,pending,{'path':'/owned/checkout'},authorize=lambda:True,reset=reset)
            with self.assertRaisesRegex(LedgerError,'RECONCILIATION_REQUIRED'):
                NativeRunLauncher.launch(self.launcher,self.newrun,pending,{'path':'/owned/checkout'},authorize=lambda:True,reset=reset)
        self.assertEqual(['launch'],events);self.assertIsNone(self.launcher.started[self.participant])
        self.assertIn(self.newrun,self.launcher.attempted_runs);self.assertEqual(1,self.context()['context_generation'])

    def test_missing_empty_or_nonstring_fresh_identity_cannot_count_as_changed(self):
        for key in ('session_id','runtime_id'):
            for value in ('<missing>',None,'',17,True,'bad/value'):
                case=NativePiResetAdversarialTests();case.setUp();self.addCleanup(case.doCleanups)
                reset=case.prepare();case.request(reset);handle=case.fresh(reset)
                if value == '<missing>':handle.launch.native_readiness['native'].pop(key)
                else:handle.launch.native_readiness['native'][key]=value
                with self.assertRaisesRegex(LedgerError,'FRESH_PROOF_REQUIRED'):case.complete(reset,handle)
                self.assertEqual(1,case.context()['context_generation'])
