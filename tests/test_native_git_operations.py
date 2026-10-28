"""Actual canonical Run/context checks; controlled native-resource/ProcView boundary."""
from dataclasses import asdict, replace
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas.kernel_origin import HeldOrigin, OriginDenied
from uas.ledger import LedgerError
from uas.git_service import GitBrokerClient
from uas.native_git_resources import NativeGitResources
from uas.native_git_operations import NativeGitOperations
from uas.workstation_exec import ExecSeat
import test_native_reviewer_recruitment_adversarial as fixture


class NativeGitOperationsTests(unittest.TestCase):
    seed=fixture.RecruitmentAdversarialTests.seed
    open=fixture.RecruitmentAdversarialTests.open
    recruit=fixture.RecruitmentAdversarialTests.recruit

    def setUp(self):
        fixture.RecruitmentAdversarialTests.setUp(self)
        self.root=self.recruit()
        self.source['slot_id']='primary'
        self.profile=N(room_id=self.room['id'],instance_id='instance',container_id='c'*64,
            repo='/owned/checkout',digest='a'*64)
        def checkout(slot,path):
            if slot!='primary' or path!=self.profile.repo:raise OriginDenied('later checkout projection unavailable')
        self.profile.require_checkout=checkout
        self.resources=object.__new__(NativeGitResources)
        self.resources.supervisor=self.supervisor;self.resources.plan=self.plan
        self.resources.profile=self.profile;self.resources.container_id='c'*64
        self.resources.require=Mock(return_value=True)
        self.resources.worker_host_uid=165530;self.resources.worker_host_gid=165532
        for field in ('request_listener','worker_listener','request_endpoint','worker_endpoint'):
            setattr(self.resources,field,Mock())
        self.resources.backend_fd=77;self.resources.backend_sha256='b'*64
        self.git_broker=object.__new__(GitBrokerClient);self.git_broker.binding=self.broker.binding
        self.git_broker.scope={**asdict(self.broker.binding),'room_instance':'instance'}
        self.git_broker.closed=False
        self.launcher.engine=object()
        for index,(ingress,actor,participant) in enumerate(zip(self.root.review_host.identity.ingresses,
                (self.actor,self.recruitment.selected['actor']),(self.participant,self.reviewer))):
            ingress.origin=replace(ingress.origin,capabilities=tuple(ingress.origin.capabilities)+('git-read',)+(('git-push',) if index==0 else ()))
            self.admission.actors[actor]['git_identity']={'name':actor,'email':actor+'@example.invalid'}
            process=object.__new__(HeldOrigin);process.credentials=(100+index,165532,165532)
            process.identity=(1,100+index);process.pidfd=70+index;process.revoked=False
            seat=ExecSeat(self.room['id'],'instance',participant,actor,'seat-a' if index==0 else 'seat-b','c'*64,165532,165532)
            if index==0:self.pi.launch.origin=process;self.pi.launch.seat=seat
            else:self.root.origin=process;self.root.seat=seat
        self.pi.launch.native_recipe.git_profile=self.profile
        self.root.recipe=N(git_profile=self.profile)
        self.observed=[]
        def task(view,pid,*,expected):
            self.observed.append((pid,expected))
            return N(namespace=((1,2),(3,4)),status={'NSpid':(pid,1)},close=Mock())
        self.fake_service=Mock();self.factory=Mock(return_value=self.fake_service)
        self.patches=[patch('uas.native_git_operations.ProcView',return_value=N(close=Mock())),
            patch('uas.native_git_operations._Task',side_effect=task),
            patch('uas.native_git_operations.GitSupervisor',self.factory)]
        for p in self.patches:p.start();self.addCleanup(p.stop)

    def create(self):
        return NativeGitOperations(self.admission,self.recruitment,self.resources,self.git_broker)

    def test_exact_original_roots_and_mapped_workers_feed_concrete_owner(self):
        op=self.create();args,kw=self.factory.call_args
        self.assertEqual(self.observed,[(100,(1,100)),(101,(1,101))])
        self.assertIs(args[7][0].process,self.pi.launch.origin)
        self.assertIs(args[7][1].process,self.root.origin)
        self.assertEqual([(x.host_uid,x.host_gid) for x in args[8]],[(165530,165532)]*2)
        self.assertIs(kw['native_resources'],self.resources)
        self.resources.request_listener.listen.assert_called_once_with(8)
        with op._fence():
            self.assertEqual(op._run_scope(self.pi.forge_service.origin,'primary'),{'run_id':self.run_id,'generation':1})
        op.serve_next(timeout=.5);self.fake_service.serve_next.assert_called_once_with(timeout=.5)
        op.close();op.close();self.fake_service.close.assert_called_once()

    def test_later_checkout_denied_before_listener_or_worker(self):
        self.source['slot_id']='later'
        with self.assertRaisesRegex(OriginDenied,'later checkout'):self.create()
        self.factory.assert_not_called();self.resources.request_listener.listen.assert_not_called()

    def test_pause_lost_and_actor_replacement_deny_without_mutation(self):
        for change in (lambda s:s['runs'][self.run_id].update(status='PAUSED'),
                lambda s:s['peer_traffic']['connections'][self.reviewer].update(readiness='lost'),
                lambda s:s['peer_traffic']['definition']['participants'][self.reviewer].update(actor_id='other')):
            case=NativeGitOperationsTests();case.setUp();self.addCleanup(case.doCleanups)
            op=case.create();case.seed(change);before=case.ledger.snapshot()
            with self.assertRaises((LedgerError,OriginDenied)):
                with op._fence():op._run_scope(case.pi.forge_service.origin,'primary')
            self.assertEqual(before,case.ledger.snapshot())

    def test_wrong_broker_instance_and_missing_identity_deny(self):
        self.git_broker.scope['room_instance']='other'
        with self.assertRaisesRegex(LedgerError,'OWNER_MISMATCH'):self.create()
        self.git_broker.scope['room_instance']='instance'
        self.admission.actors[self.actor].pop('git_identity')
        with self.assertRaises(LedgerError):self.create()
        self.resources.request_listener.listen.assert_not_called()

    def test_replaced_held_root_or_recipe_cannot_reuse_owner(self):
        op=self.create();self.root.origin=object()
        with self.assertRaisesRegex(OriginDenied,'owners replaced'):
            with op._fence():op._current()
        self.root.origin=op.processes[1];self.root.recipe.git_profile=object()
        with self.assertRaisesRegex(OriginDenied,'projection changed'):
            with op._fence():op._current()

    def test_no_scope_outside_fence_and_no_nested_lifecycle_lock(self):
        op=self.create()
        with self.assertRaisesRegex(LedgerError,'FENCE_REQUIRED'):op._current()
        with op._fence():
            with self.assertRaisesRegex(LedgerError,'NESTED_FENCE'):
                with op._fence():pass

    def test_successor_prerequisite_refuses_without_stopping_current_owners(self):
        op=self.create();before=self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'NATIVE_SUCCESSOR_GIT_VIEW_UNAVAILABLE'):op.require_successor()
        self.assertEqual(before,self.ledger.snapshot());self.assertFalse(op.closed)
        self.fake_service.close.assert_not_called()

    def test_missing_configured_git_capability_does_not_gain_authority(self):
        self.pi.forge_service.origin=replace(self.pi.forge_service.origin,capabilities=('forge-read','implement'))
        with self.assertRaisesRegex(LedgerError,'NATIVE_GIT_CAPABILITY_UNAVAILABLE'):self.create()
        self.resources.request_listener.listen.assert_not_called()

    def test_activation_failure_closes_owned_listener_and_child_authority(self):
        self.resources.request_listener.listen.side_effect=OSError('controlled activation failure')
        with self.assertRaises(OSError):self.create()
        self.fake_service.close.assert_called_once()
        self.resources.request_listener.close.assert_called_once()

    def test_final_owner_drift_keeps_listener_inactive_and_closes_children(self):
        def construct(*args,**kwargs):
            self.seed(lambda state:state['runs'][self.run_id].update(status='CLOSED'))
            return self.fake_service
        self.factory.side_effect=construct
        with self.assertRaisesRegex(LedgerError,'NATIVE_GIT_RUN_UNAVAILABLE'):self.create()
        self.resources.request_listener.listen.assert_not_called()
        self.fake_service.close.assert_called_once()
        self.resources.request_listener.close.assert_called_once()

    def test_scope_drift_cannot_be_silently_rebound(self):
        op=self.create();self.pi.launch.native_recipe.scope['generation']=2
        with self.assertRaisesRegex(OriginDenied,'projection changed'):
            with op._fence():op._current()

    def test_resource_owner_cannot_be_substituted_by_equal_metadata(self):
        self.resources.supervisor=object()
        with self.assertRaisesRegex(LedgerError,'OWNER_MISMATCH'):self.create()
        self.factory.assert_not_called()
        self.resources.request_listener.listen.assert_not_called()
