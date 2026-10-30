"""Complete-only Gate preparation through actual native host/canonical reducers.

Only raw provider/native boundaries are controlled; a real HumanSession override
supplies eligibility, never a manufactured independent review verdict.
"""
from copy import deepcopy
from pathlib import Path
import unittest

import test_native_gate_workflow as workflow_fixture
import test_gate_forge as forge_fixture
import test_run_review as review_fixture
from uas.forge_audit import ForgeAudit
from uas.gate_policy import compile_policy
from uas.ledger import Command, Event, LedgerError, Transition
from uas.manager_actions import HumanSession, run_version
from uas.native_review_host import NativeReviewAcceptance


class NativeGateCompletionTests(unittest.TestCase):
    def setUp(self):
        w=workflow_fixture.NativeGateWorkflowTests();w.setUp();self.addCleanup(w.doCleanups)
        self.w,self.f=w,w.f
        raw={'id':'default','version':1,'gates':[{'id':'ci','kind':'mechanical',
             'evaluator':'forge-state','config':forge_fixture.config()}, {'id':'submit-ci','kind':'mechanical','evaluator':'forge-state','config':forge_fixture.config()}],
             'protected_operations':{'submit-for-review':['submit-ci'],'complete':['ci']},
             'review_return_cap':5,'queue_timeout_seconds':60,'response_timeout_seconds':60}
        self.raw=deepcopy(raw)
        self.f.seed(lambda s:s['runs']['run'].update(policy=compile_policy(raw,'policy')))

    def state(self):return self.w.state()
    def rows(self):return {k:v for k,v in self.state().get('gate_evaluations',{}).items() if v['scope']['gate_id']=='ci'}
    def complete(self,operation='completion',submission=None):
        return self.f.host.observe_completion(operation,'run',1,submission or self.w.envelope['id'])
    def ready(self):
        result=self.w.submit();self.assertEqual(result['stage'],'ATTENTION')
        self.assertFalse(self.rows());self.assertEqual([k for k,_ in self.w.calls],['target','evaluate','evaluate'])
        audit=ForgeAudit(Path(self.f.tmp.name)/'completion-manager.db','deployment');self.addCleanup(audit.close)
        session=HumanSession('deployment','room','instance','manager',review_fixture.HUMAN,lambda *_:True,lambda:True)
        state=self.state();row=state['run_reviews']['run']['current']
        with audit.manager_action_guard('room','owner/repo') as guard:version=run_version(state,'run',guard)
        self.f.host.human_action({'version':1,'operation_id':'override','action':'override-review',
            'deployment_id':'deployment','room_id':'room','instance_id':'instance','run_id':'run','generation':1,
            'object_id':row['submission_id'],'observed_version':version,
            'payload':{'reason':'explicit human decision','rounds':None}},session=session,audit=audit)
        self.w.review.merged=True
        return result

    def test_complete_only_not_eager_and_real_completion_exact_retry_no_effects(self):
        self.ready();binding=deepcopy(self.state()['runs']['run']['gate_target_binding'])
        result=self.complete();self.assertEqual(result['stage'],'COMPLETED')
        self.assertEqual(self.state()['runs']['run']['outcome'],'completed')
        self.assertEqual(len(self.rows()),1);self.assertEqual(next(iter(self.rows().values()))['result']['verdict'],'passed')
        self.assertEqual(binding,self.state()['runs']['run']['gate_target_binding'])
        before=deepcopy((self.w.calls,self.w.review.calls))
        self.assertEqual(result,self.complete());self.assertEqual(before,(self.w.calls,self.w.review.calls))
        self.w.service.launch_factory.assert_not_called()

    def test_distinct_merge_polls_share_evaluation_not_target_binding(self):
        self.ready();self.w.review.merged=False
        self.assertEqual(self.complete('poll-one')['reason'],'AWAITING_HUMAN_MERGE')
        evaluations=deepcopy(self.rows());calls=len(self.w.calls);self.w.review.merged=True
        self.assertEqual(self.complete('poll-two')['stage'],'COMPLETED')
        self.assertEqual({k:{a:b for a,b in v.items() if a!='refresh'} for k,v in evaluations.items()},
                         {k:{a:b for a,b in v.items() if a!='refresh'} for k,v in self.rows().items()})
        self.assertEqual(len(self.w.calls)-calls,1) # Fresh projection observation, not evaluator replay.
        self.assertEqual([kind for kind,_ in self.w.calls].count('target'),1)

    def test_ineligible_submission_and_original_id_conflict_precede_evaluation(self):
        self.w.submit();before=deepcopy(self.w.calls)
        with self.assertRaisesRegex(LedgerError,'REVIEW_PASS_REQUIRED'):self.complete()
        self.assertFalse(self.rows());self.assertEqual(before,self.w.calls)
        self.f.ledger.apply(Command('conflict','unrelated','run',1,{}),review_fixture.HUMAN,
            authorize=lambda *_:True,decide=lambda state,_:Transition(state,(Event('test',{}),),{}))
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):self.complete('conflict')
        self.assertFalse(self.rows());self.assertEqual(before,self.w.calls)

    def test_wrong_submission_denied_before_evaluation(self):
        self.ready();before=deepcopy(self.w.calls)
        with self.assertRaisesRegex(LedgerError,'REVIEW_PASS_REQUIRED'):self.complete(submission='other')
        self.assertFalse(self.rows());self.assertEqual(before,self.w.calls)

    def assert_failed_evaluation(self,change):
        self.ready();self.w.instrument_lock_entries();before=deepcopy(self.w.review.calls)
        self.w.after_observe=change
        with self.assertRaises(LedgerError):self.complete()
        self.assertEqual(next(iter(self.rows().values()))['result']['verdict'],'error')
        self.assertEqual(self.state()['runs']['run']['status'],'ACTIVE')
        self.assertEqual(self.w.review.calls,before)
        self.assertIsNone(self.f.host.identity.active);self.assertIsNone(self.w.workflow.active)

    def test_late_review_row_change_persists_error_without_lock_reentry(self):
        self.assert_failed_evaluation(lambda:self.f.seed(lambda s:s['run_reviews']['run']['current'].update(reason='changed')))

    def test_late_source_swap_persists_error_without_lock_reentry(self):
        self.assert_failed_evaluation(lambda:self.f.source.update(source_digest='e'*64))

    def test_late_control_revision_persists_error_without_lock_reentry(self):
        self.assert_failed_evaluation(lambda:self.f.seed(lambda s:s['runs']['run'].update(control_revision=99)))

    def test_late_native_revoke_persists_error_without_lock_reentry(self):
        self.assert_failed_evaluation(lambda:self.f.seed(lambda s:s['peer_traffic']['connections']['pi'].update(readiness='lost')))

    def test_interrupted_evaluation_never_resends_for_same_or_new_poll(self):
        self.ready();self.w.after_observe=lambda:(_ for _ in ()).throw(workflow_fixture.Interrupted())
        with self.assertRaises(workflow_fixture.Interrupted):self.complete('poll-one')
        before=deepcopy((self.w.calls,self.w.review.calls,self.rows()));self.w.after_observe=None
        for operation in ('poll-one','poll-two'):
            with self.assertRaises(LedgerError):self.complete(operation)
            self.assertEqual(before,(self.w.calls,self.w.review.calls,self.rows()))
        self.assertIsNone(next(iter(self.rows().values()))['result'])

    def test_participant_cannot_spoof_private_completion_scope(self):
        self.ready();before=deepcopy(self.w.calls)
        packet={'id':'fake','kind':'observe-completion','run_id':'run','generation':1,
                'payload':{'submission_id':self.w.envelope['id']}}
        with self.assertRaises(LedgerError):self.w.submit(packet)
        scope=NativeReviewAcceptance(self.f.host,self.f.ingress,object(),self.w.envelope)
        with scope.operation(scope.admission_operation):
            with self.assertRaisesRegex(LedgerError,'NATIVE_GATE_COMPLETION_SCOPE_REQUIRED'):
                self.w.workflow.prepare_completion(Command('fake','review.observe-completion','run',1,
                    {'submission_id':self.w.envelope['id']}),self.f.ingress.origin)
        self.assertEqual(before,self.w.calls);self.assertFalse(self.rows())

    def test_wrong_merger_remains_attention_without_rewriting_gate_result(self):
        self.ready();self.w.review.who=999
        result=self.complete();self.assertEqual(result['stage'],'ATTENTION')
        self.assertEqual(result['reason'],'MERGE_IDENTITY_UNVERIFIABLE')
        self.assertEqual(self.state()['runs']['run']['status'],'ACTIVE')
        self.assertEqual(next(iter(self.rows().values()))['result']['verdict'],'passed')

    def test_preparation_return_review_drift_stops_before_projection_refresh(self):
        self.ready();original=self.f.host.prepare_completion;calls=[]
        def prepare(*args,**kwargs):
            result=original(*args,**kwargs)
            self.f.seed(lambda s:s['run_reviews']['run']['current'].update(reason='late replacement'))
            return result
        self.f.host.prepare_completion=prepare
        self.f.host.reviews._operation_gates=lambda *a,**k:calls.append('unexpected projection')
        with self.assertRaisesRegex(LedgerError,'REVIEW_COMPLETION_STALE'):self.complete()
        self.assertEqual(calls,[])

    def test_preparation_return_control_drift_stops_before_projection_refresh(self):
        self.ready();original=self.f.host.prepare_completion;calls=[]
        def prepare(*args,**kwargs):
            result=original(*args,**kwargs)
            self.f.seed(lambda s:s['runs']['run'].update(control_revision=100))
            return result
        self.f.host.prepare_completion=prepare
        self.f.host.reviews._operation_gates=lambda *a,**k:calls.append('unexpected projection')
        with self.assertRaisesRegex(LedgerError,'REVIEW_COMPLETION_STALE'):self.complete()
        self.assertEqual(calls,[])

    def test_non_override_reviewer_path_uses_actual_fact_without_lock_reentry(self):
        from dataclasses import replace
        from types import SimpleNamespace as N
        from unittest.mock import Mock
        import test_native_pi_host_forge as pi_fixture
        from uas.native_host_forge import NativePiHostForge
        from uas.native_review_host import NativeReviewHost
        from uas.native_gate_control import NativeGateControl
        from uas.native_gate_workflow import NativeGateWorkflow
        from uas.artifact_helper import GateSupervisorService
        from uas.peer import RequestCommand
        from uas.peer import Readiness, digest
        f=self.f;w=self.w
        helper=pi_fixture.NativePiForgeTests();self.addCleanup(helper.doCleanups)
        admission,client=helper.typed();client.supervisor=f.supervisor
        admission.seat=replace(admission.seat,actor_id='reviewer',participant_id='other',capabilities=('peer-traffic','review'))
        admission.launch.admission['operation_id']='e'*32
        second=NativePiHostForge(admission,client)
        connection=f.peer.connect('admit-'+second.binding.operation_id,'other',second.origin.incarnation_id,object())
        old=f.host;del f.ingress.review_host
        f.host=NativeReviewHost((f.ingress,second),f.ledger,f.git,old.identity.resolver,old.identity.binding,
            reviewers=[{'actor_id':'reviewer','participant_id':'other','github_user_id':8}],human_mergers=[7])
        w.service=GateSupervisorService(f.host.sources,N(),launch_factory=Mock(side_effect=AssertionError('helper launched')),listener=None)
        w.control=NativeGateControl(f.host,w.service);w.workflow=NativeGateWorkflow(f.host,w.control)
        f.host.gates.forge=old.gates.forge;f.host.reviews.broker=old.reviews.broker
        row=w.submit();self.assertEqual(row['stage'],'REVIEWING')
        f.peer.observe(connection,Readiness.SAFE)
        offer=f.peer.prepare_delivery(connection,traffic_id=row['request_id']);envelope=offer.envelope
        receipt={key:envelope[key] for key in ('delivery_id','participant_id','incarnation_id','context_generation')}
        receipt['digest']=digest(envelope);f.peer.confirm_delivery(connection,offer,receipt)
        f.peer.submit(connection,RequestCommand('accept-review','run',1,row['request_id'],'accept'))
        url='https://github.com/owner/repo/pull/'+str(w.target['pull_number'])+'#pullrequestreview-1'
        w.review.reviews=[{'id':1,'html_url':url,'pull_request_url':'https://api.github.com/repos/owner/repo/pulls/'+str(w.target['pull_number']),
            'user':{'id':8},'state':'APPROVED','submitted_at':'2026-10-27T21:00:01Z','commit_id':f.head}]
        result=f.host.submit(second,object(),{'id':'review-result','kind':'review-result','run_id':'run','generation':1,
            'payload':{'submission_id':w.envelope['id'],'verdict':'pass','review_reference':url,'lenses':['Standards','Specification','Runtime']}})
        self.assertEqual(result['stage'],'READY_FOR_HUMAN');self.assertFalse(result.get('override_id'))
        counts=w.instrument_lock_entries();w.review.merged=True
        self.assertEqual(self.complete()['stage'],'COMPLETED')
        self.assertGreater(counts['lifecycle'],0);self.assertGreater(counts['git'],0)

    def test_artifact_complete_service_scope_reaches_real_control_and_root_quota_binding_once(self):
        from types import SimpleNamespace as N
        from uas.native_checkout_handoff import gate_quota_binding
        from uas.review_broker import review_origin
        raw=deepcopy(self.raw)
        raw['gates'][0].update(evaluator='artifacts',config={'items':[{'path':'result.txt','type':'file','nonempty':True}]})
        self.f.seed(lambda s:s['runs']['run'].update(policy=compile_policy(raw,'policy')))
        self.ready();self.w.instrument_lock_entries();observed=[]
        def materialize(scope,source):
            active=self.f.host.identity.active
            self.assertTrue(active.host_poll);self.assertIsNone(active.ingress)
            self.assertIsNone(active.capability)
            self.assertEqual(active.origin,review_origin('instance'))
            self.assertEqual(scope['participant_id'],'pi')
            self.assertNotEqual(scope['participant_id'],active.origin.participant_id)
            state=self.state();row=state['gate_evaluations'][scope['evaluation_id']]
            self.assertEqual(row['phase'],'STARTED');self.assertIsNone(row['result'])
            self.assertEqual(row['origin'],active.origin.canonical())
            value=gate_quota_binding(self.f.ledger,state,self.f.host.identity.binding,scope['evaluation_id'])
            self.assertEqual(value['scope'],scope);self.assertEqual(value['source'],source)
            self.assertEqual(value['reservation_bytes'],32<<20)
            observed.append(deepcopy(value))
            raise workflow_fixture.Interrupted()
        # Actual NativeGateControl and GateSupervisorService run; only target
        # materialization is intercepted before any filesystem/helper effect.
        self.w.service.targets=N(prepare=materialize)
        with self.assertRaises(workflow_fixture.Interrupted):self.complete('artifact-poll')
        self.assertEqual(len(observed),1)
        frozen=deepcopy(self.rows())
        for operation in ('artifact-poll','artifact-poll-next'):
            with self.assertRaisesRegex(LedgerError,'NATIVE_GATE_EVALUATION_UNAVAILABLE'):self.complete(operation)
        self.assertEqual(self.rows(),frozen);self.assertEqual(len(observed),1)
        self.w.service.launch_factory.assert_not_called()
