"""Actual native workflow/Gate/Room reducers; only raw provider/native seams controlled."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock

import test_native_review_host as native_fixture
import test_gate_forge as forge_fixture
import test_run_review as review_fixture
from uas.artifact_helper import GateSupervisorService
from uas.gate_forge import BrokerForgeState
from uas.gate_policy import compile_policy
from uas.forge_audit import ForgeAudit
from uas.manager_actions import HumanSession, run_version
from uas.github_read import GitHubProject, ProviderResponse
from uas.ledger import Command, Event, Transition, LedgerError
from uas.native_gate_control import NativeGateControl
from uas.native_gate_workflow import NativeGateWorkflow


class Interrupted(BaseException):pass


class NativeGateWorkflowTests(unittest.TestCase):
    def setUp(self):
        f=native_fixture.NativeReviewTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        f.source={'room_instance':'instance','project_id':'project','repository':'owner/repo',
            'run_id':'run','participant_id':'pi','slot_id':'primary','branch':'refs/heads/work',
            'head_sha':f.head,'source_digest':'d'*64}
        raw={'id':'default','version':1,'gates':[{'id':'ci','kind':'mechanical',
             'evaluator':'forge-state','config':forge_fixture.config()}],
             'protected_operations':{'submit-for-review':['ci'],'complete':['ci']},
             'review_return_cap':5,'queue_timeout_seconds':60,'response_timeout_seconds':60}
        self.target={**forge_fixture.TARGET,'repository':'owner/repo','head_sha':f.head}
        def seed(s):
            run=s['runs']['run'];run.update(policy=compile_policy(raw,'policy'),
                checkout={'slot':'primary','branch':'refs/heads/work'},control_revision=0)
            run.pop('gate_target',None);run.pop('gate_target_binding',None)
        f.seed(seed)
        self.service=GateSupervisorService(f.host.sources,N(),launch_factory=Mock(side_effect=AssertionError('helper launched')),listener=None)
        self.control=NativeGateControl(f.host,self.service)
        self.workflow=NativeGateWorkflow(f.host,self.control)
        self.calls=[];self.after_target=None;self.after_observe=None
        raw_provider=forge_fixture.Fixture()
        def provider(path):
            path=path.replace('owner/repo',forge_fixture.R).replace(f.head,forge_fixture.HEAD)
            reply=raw_provider(path)
            body=reply.body.decode().replace(forge_fixture.R,'owner/repo').replace(forge_fixture.HEAD,f.head)
            return ProviderResponse(reply.status,body.encode(),reply.headers)
        self.provider=BrokerForgeState(GitHubProject('owner/repo'),provider)
        def observe_target(target,operation,*,authorize):
            self.assertTrue(authorize());self.assertIsNone(f.host.identity.active.capability)
            self.calls.append(('target',operation));result={'audit_reference':operation,'observation':self.provider.observe_target(target)}
            if self.after_target:self.after_target()
            return result
        def observe(target,config,operation,*,authorize):
            self.assertTrue(authorize());self.assertIsNone(f.host.identity.active.capability)
            self.calls.append(('evaluate',operation));result={'audit_reference':operation,'observation':self.provider.observe(target,config)}
            if self.after_observe:self.after_observe()
            return result
        f.host.gates.forge=N(observe_target=observe_target,observe=observe)
        self.review=review_fixture.Broker();self.review.head=f.head
        base=self.review.observe
        def review(target,operation_id,*,authorize):
            result=base(target,operation_id,authorize=authorize)
            result['observation']['pull'].update(id=target['pull_id'],number=target['pull_number'])
            result['observation']['pull']['base']['sha']=target['base_sha']
            return result
        f.host.reviews.broker=N(observe=review)
        self.envelope={**f.envelope,'payload':{'target':deepcopy(self.target),'evidence':['test:gate']}}

    def submit(self,envelope=None):return self.f.host.submit(self.f.ingress,object(),envelope or self.envelope)
    def state(self):return self.f.ledger.snapshot()['state']

    def test_real_submission_binds_evaluates_then_caches_without_provider_replay(self):
        result=self.submit()
        self.assertEqual(result['stage'],'ATTENTION') # No reviewer fabricated by this fixture.
        row=next(iter(self.state()['gate_evaluations'].values()))
        self.assertEqual(row['result']['verdict'],'passed')
        self.assertEqual(self.state()['runs']['run']['gate_target'],self.target)
        before=deepcopy(self.calls);self.assertEqual(self.submit(),result);self.assertEqual(self.calls,before)
        self.service.launch_factory.assert_not_called()

    def test_invalid_payload_wrong_actor_and_main_id_conflict_precede_provider(self):
        invalid=deepcopy(self.envelope);invalid['payload']['unexpected']=True
        with self.assertRaisesRegex(LedgerError,'INVALID_REVIEW_COMMAND'):self.submit(invalid)
        self.f.seed(lambda s:s['runs']['run'].update(actor_id='not-builder'))
        with self.assertRaisesRegex(LedgerError,'REVIEW_IMPLEMENTER_REQUIRED'):self.submit()
        self.f.seed(lambda s:s['runs']['run'].update(actor_id='builder'))
        self.f.ledger.apply(Command(self.envelope['id'],'unrelated','run',1,{}),self.f.ingress.origin,
            authorize=lambda *_:True,decide=lambda state,_:Transition(state,(Event('unrelated',{}),),{}))
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):self.submit()
        self.assertEqual(self.calls,[])

    def test_interrupted_bind_does_not_recontact_and_changed_original_conflicts(self):
        self.after_target=lambda:(_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted):self.submit()
        calls=deepcopy(self.calls)
        changed=deepcopy(self.envelope);changed['payload']['evidence']=['test:different']
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):self.submit(changed)
        self.after_target=None
        with self.assertRaises(LedgerError):self.submit()
        self.assertEqual(calls,self.calls)
        self.assertEqual(next(iter(self.state()['gate_target_bindings'].values()))['phase'],'STARTED')

    def test_bound_then_interrupted_evaluation_reuses_original_cas_and_does_not_repeat(self):
        self.after_observe=lambda:(_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted):self.submit()
        calls=deepcopy(self.calls);self.after_observe=None
        with self.assertRaises(LedgerError):self.submit()
        self.assertEqual(self.calls,calls)
        self.assertEqual(next(iter(self.state()['gate_target_bindings'].values()))['result']['status'],'BOUND')
        self.assertIsNone(next(iter(self.state()['gate_evaluations'].values()))['result'])

    def test_late_source_swap_persists_error_not_pass(self):
        self.after_observe=lambda:self.f.source.update(source_digest='e'*64)
        with self.assertRaises(LedgerError):self.submit()
        row=next(iter(self.state()['gate_evaluations'].values()))
        self.assertEqual(row['result']['verdict'],'error')
        self.assertFalse(self.state().get('run_reviews',{}))
        self.assertIsNone(self.f.host.identity.active)

    def test_late_control_revision_change_persists_error_not_pass(self):
        self.after_observe=lambda:self.f.seed(lambda s:s['runs']['run'].update(control_revision=1))
        with self.assertRaises(LedgerError):self.submit()
        row=next(iter(self.state()['gate_evaluations'].values()))
        self.assertEqual(row['result']['verdict'],'error')
        self.assertFalse(self.state().get('run_reviews',{}))

    def test_late_native_lost_persists_error_not_pass(self):
        self.after_observe=lambda:self.f.seed(lambda s:s['peer_traffic']['connections']['pi'].update(readiness='lost'))
        with self.assertRaises(LedgerError):self.submit()
        row=next(iter(self.state()['gate_evaluations'].values()))
        self.assertEqual(row['result']['verdict'],'error')
        self.assertFalse(self.state().get('run_reviews',{}))

    def test_late_binding_source_change_records_error_and_never_evaluates(self):
        self.after_target=lambda:self.f.source.update(source_digest='e'*64)
        with self.assertRaises(LedgerError):self.submit()
        row=next(iter(self.state()['gate_target_bindings'].values()))
        self.assertEqual(row['result']['status'],'ERROR')
        self.assertEqual([kind for kind,_ in self.calls],['target'])
        self.assertNotIn('gate_target',self.state()['runs']['run'])
        calls=deepcopy(self.calls)
        with self.assertRaises(LedgerError):self.submit()
        self.assertEqual(self.calls,calls)

    def test_gate_child_id_conflict_is_denied_before_provider(self):
        import hashlib
        operation='native-gate-prepare-'+hashlib.sha256(self.envelope['id'].encode()).hexdigest()
        self.f.ledger.apply(Command(operation,'unrelated','run',1,{}),self.f.ingress.origin,
            authorize=lambda *_:True,decide=lambda state,_:Transition(state,(Event('unrelated',{}),),{}))
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):self.submit()
        self.assertEqual(self.calls,[])

    def instrument_lock_entries(self):
        f=self.f;counts={'lifecycle':0,'git':0}
        locked=f.supervisor._locked;history=f.git.history_fence
        @contextmanager
        def lifecycle(*args,**kwargs):
            self.assertFalse(f.ledger._connection().in_transaction,'lifecycle acquired under Room transaction')
            counts['lifecycle']+=1
            with locked(*args,**kwargs) as held:yield held
        @contextmanager
        def git(*args,**kwargs):
            self.assertFalse(f.ledger._connection().in_transaction,'Git acquired under Room transaction')
            counts['git']+=1
            with history(*args,**kwargs) as held:yield held
        f.supervisor._locked=lifecycle;f.git.history_fence=git
        return counts

    def test_failed_binding_fence_error_persists_without_lock_reentry_in_room(self):
        counts=self.instrument_lock_entries()
        self.after_target=lambda:self.f.source.update(source_digest='e'*64)
        with self.assertRaises(LedgerError):self.submit()
        row=next(iter(self.state()['gate_target_bindings'].values()))
        self.assertEqual(row['result']['status'],'ERROR')
        self.assertGreater(counts['lifecycle'],0);self.assertGreater(counts['git'],0)
        self.assertEqual([kind for kind,_ in self.calls],['target'])

    def test_failed_evaluation_fence_error_persists_without_lock_reentry_in_room(self):
        counts=self.instrument_lock_entries()
        self.after_observe=lambda:self.f.source.update(source_digest='e'*64)
        with self.assertRaises(LedgerError):self.submit()
        row=next(iter(self.state()['gate_evaluations'].values()))
        self.assertEqual(row['result']['verdict'],'error')
        self.assertGreater(counts['lifecycle'],0);self.assertGreater(counts['git'],0)
        self.assertFalse(self.state().get('run_reviews',{}))

    def after_gate_projection(self,mutate):
        original=self.f.host.reviews._operation_gates
        def gates(*args,**kwargs):
            result=original(*args,**kwargs);mutate();return result
        self.f.host.reviews._operation_gates=gates

    def test_post_refresh_control_revision_is_not_adopted_by_submission(self):
        self.after_gate_projection(lambda:self.f.seed(lambda s:s['runs']['run'].update(control_revision=9)))
        with self.assertRaisesRegex(LedgerError,'REVIEW_RUN_STALE'):self.submit()
        self.assertEqual(self.state()['runs']['run']['control_revision'],9)
        self.assertFalse(self.state().get('run_reviews',{}));self.assertEqual(self.review.calls,[])

    def test_post_refresh_run_pause_is_not_adopted_by_submission(self):
        self.after_gate_projection(lambda:self.f.seed(lambda s:s['runs']['run'].update(status='PAUSED')))
        with self.assertRaisesRegex(LedgerError,'REVIEW_RUN_STALE'):self.submit()
        self.assertEqual(self.state()['runs']['run']['status'],'PAUSED')
        self.assertFalse(self.state().get('run_reviews',{}));self.assertEqual(self.review.calls,[])

    def test_completion_review_replacement_after_refresh_is_not_adopted(self):
        self.submit();f=self.f
        audit=ForgeAudit(Path(f.tmp.name)/'manager-audit.db','deployment');self.addCleanup(audit.close)
        session=HumanSession('deployment','room','instance','manager',review_fixture.HUMAN,
            lambda *_:True,lambda:True)
        state=self.state();row=state['run_reviews']['run']['current']
        with audit.manager_action_guard('room','owner/repo') as guard:version=run_version(state,'run',guard)
        packet={'version':1,'operation_id':'override','action':'override-review','deployment_id':'deployment',
            'room_id':'room','instance_id':'instance','run_id':'run','generation':1,
            'object_id':row['submission_id'],'observed_version':version,'payload':{'reason':'human decision','rounds':None}}
        f.host.human_action(packet,session=session,audit=audit)
        self.review.merged=True;before=deepcopy(self.review.calls)
        self.after_gate_projection(lambda:f.seed(lambda s:s['run_reviews']['run']['current'].update(reason='concurrent-replacement')))
        with self.assertRaisesRegex(LedgerError,'REVIEW_COMPLETION_STALE'):
            f.host.observe_completion('completion','run',1,self.envelope['id'])
        self.assertEqual(self.review.calls,before)
        self.assertEqual(self.state()['runs']['run']['status'],'ACTIVE')
        self.assertNotIn('completion',self.state()['runs']['run'])

    def test_constructor_validation_keeps_other_host_default_deny(self):
        other=native_fixture.NativeReviewTests();other.setUp();self.addCleanup(other.doCleanups)
        original=other.host.gates.authorize_target
        with self.assertRaisesRegex(LedgerError,'EXACT_NATIVE_GATE_CONTROL_REQUIRED'):
            NativeGateWorkflow(other.host,self.control)
        self.assertIsNone(other.host.gate_workflow);self.assertIs(other.host.gates.authorize_target,original)
        self.assertFalse(original(other.ingress.origin,None))
