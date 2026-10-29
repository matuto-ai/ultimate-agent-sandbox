"""Actual native owner/Gate/Room transactions with controlled provider seams only."""
from copy import deepcopy
from dataclasses import replace
import test_native_pi_host_forge as pi_fixture
from uas.native_host_forge import NativePiHostForge
from uas.native_review_host import NativeReviewHost, NativeReviewAcceptance
from pathlib import Path
import unittest
import test_native_review_host as fixture
import test_run_review as review_fixture
from uas.forge_audit import ForgeAudit
from uas.gate_policy import compile_policy
from uas.ledger import LedgerError
from uas.manager_actions import HumanSession, run_version


class NativeReviewAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.NativeReviewTests('test_real_reducer_and_gate_preparation_provider_outside_fences')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f
        policy={'id':'default','version':1,'gates':[{'id':'check','kind':'attestation',
            'config':{'statement_id':'checked','scope':'run','eligible_actors':['builder'],
                      'relationship':'implementer','required_capability':'implement','allow_self':True,
                      'continuing_authority':True}}],
            'protected_operations':{'submit-for-review':['check'],'complete':['check']},
            'review_return_cap':5,'queue_timeout_seconds':60,'response_timeout_seconds':60}
        self.target=deepcopy(review_fixture.TARGET);self.target['head_sha']=f.head
        f.seed(lambda s:s['runs']['run'].update(policy=compile_policy(policy,'policy'),
            gate_target=deepcopy(self.target),gate_target_binding={'fixture':'bound'}))
        scope=f.scope()
        with scope.operation(scope.admission_operation):
            f.host.gates.submit('gate-check','run',1,{'gate_id':'check','statement_id':'checked',
                'action':'assert','note':'checked','evidence_refs':['test:check']},origin=f.ingress.origin)
        self.broker=review_fixture.Broker();self.broker.head=f.head
        f.host.reviews.broker=self.broker
        self.envelope={**f.envelope,'payload':{'target':self.target,'evidence':['test:check']}}

    def submit(self):return self.f.host.submit(self.f.ingress,object(),self.envelope)

    def after_observation(self,mutate):
        observe=self.broker.observe
        def observing(*args,**kwargs):
            self.assertFalse(self.f.git._history_fenced)
            self.assertIsNone(self.f.host.identity.active.capability)
            result=observe(*args,**kwargs);mutate();return result
        self.broker.observe=observing

    def assert_no_review_attempt(self):
        self.assertFalse(self.f.ledger.snapshot()['state'].get('run_reviews',{}).get('run',{}).get('attempts'))
        self.assertEqual(len(self.broker.calls),1)
        self.assertIsNone(self.f.host.identity.active)

    def test_source_swap_after_provider_observation_cannot_commit(self):
        self.after_observation(lambda:self.f.source.update(checkout='replacement'))
        with self.assertRaisesRegex(LedgerError,'GATE_SOURCE_CHANGED'):self.submit()
        self.assert_no_review_attempt()

    def test_reviewer_contribution_after_provider_observation_invalidates_independence(self):
        f=self.f; helper=pi_fixture.NativePiForgeTests();self.addCleanup(helper.doCleanups)
        admission,client=helper.typed();client.supervisor=f.supervisor
        admission.seat=replace(admission.seat,actor_id='reviewer',participant_id='other',capabilities=('peer-traffic','review'))
        admission.launch.admission['operation_id']='e'*32
        second=NativePiHostForge(admission,client)
        f.peer.connect('admit-'+second.binding.operation_id,'other',second.origin.incarnation_id,object())
        del f.ingress.review_host
        old=f.host
        f.host=NativeReviewHost((f.ingress,second),f.ledger,f.git,old.identity.resolver,
            old.identity.binding,reviewers=[],human_mergers=[7])
        f.host.reviews.broker=self.broker
        f.source={'room_instance':'instance','project_id':'project','repository':'owner/repo',
                  'run_id':'run','participant_id':'pi','slot_id':'primary','branch':'refs/heads/work',
                  'head_sha':f.head,'source_digest':'d'*64}
        f.seed(lambda s:s['runs']['run']['checkout'].update(branch='refs/heads/work'))
        # Recompile from raw policy; the independent head attestation is supplied
        # by a distinct admitted Actor, initially absent from Git contributors.
        raw={'id':'default','version':1,'gates':[{'id':'check','kind':'attestation',
            'config':{'statement_id':'checked','scope':'head','eligible_actors':['reviewer'],
                'relationship':'independent-reviewer','required_capability':'review','allow_self':False,
                'continuing_authority':True}}],
            'protected_operations':{'submit-for-review':['check'],'complete':['check']},
            'review_return_cap':5,'queue_timeout_seconds':60,'response_timeout_seconds':60}
        f.seed(lambda s:(s['runs']['run'].update(policy=compile_policy(raw,'policy')),s.update(gate_evaluations={})))
        scope=NativeReviewAcceptance(f.host,second,object(),f.envelope)
        with scope.operation(scope.admission_operation):
            f.host.gates.submit('independent-check','run',1,{'gate_id':'check','statement_id':'checked',
                'action':'assert','note':'checked','evidence_refs':['test:independent']},origin=second.origin)
        def changed():
            f.git.record_mutation('late-contribution',{'run_id':'run','generation':1},
                second.origin,'add','b'*64,authorize=lambda:True)
        self.after_observation(changed)
        with self.assertRaisesRegex(LedgerError,'GATE_OPERATION_STALE'):self.submit()
        self.assert_no_review_attempt()

    def test_same_projection_digest_different_refresh_row_rejected_at_commit(self):
        def initial(s):
            row=next(iter(s['gate_evaluations'].values()))
            row['refresh']={'phase':'TERMINAL','operation_id':'first-refresh',
                'projection':{'dependency_digest':'same-semantic-digest'},'audit_reference':'first-observation'}
        self.f.seed(initial)
        def changed():
            state=self.f.ledger.snapshot()['state']
            row=next(iter(state['gate_evaluations'].values()));before=deepcopy(row)
            def mutate(s):
                target=s['gate_evaluations'][row['evaluation_id']]['refresh']
                target.update(operation_id='replacement-refresh',audit_reference='replacement-observation')
            self.f.seed(mutate)
            after=self.f.ledger.snapshot()['state']['gate_evaluations'][row['evaluation_id']]
            self.assertEqual(after['refresh']['projection'],before['refresh']['projection'])
            self.assertNotEqual(after['refresh']['operation_id'],before['refresh']['operation_id'])
        self.after_observation(changed)
        with self.assertRaisesRegex(LedgerError,'GATE_OPERATION_STALE'):self.submit()
        self.assert_no_review_attempt()

    def human(self):
        self.submit()
        self.audit=ForgeAudit(Path(self.f.tmp.name)/'human-audit.db','deployment');self.addCleanup(self.audit.close)
        self.connected=True;self.authorized=True
        session=HumanSession('deployment','room','instance','manager',review_fixture.HUMAN,
            lambda *_:self.authorized,lambda:self.connected)
        state=self.f.ledger.snapshot()['state'];row=state['run_reviews']['run']['current']
        with self.audit.manager_action_guard('room','owner/repo') as forge:
            version=run_version(state,'run',forge)
        packet={'version':1,'operation_id':'human-override','action':'override-review',
            'deployment_id':'deployment','room_id':'room','instance_id':'instance','run_id':'run','generation':1,
            'object_id':row['submission_id'],'observed_version':version,
            'payload':{'reason':'human decision','rounds':None}}
        return session,packet

    def test_actual_typed_human_session_executes_canonical_control_and_audit(self):
        session,packet=self.human()
        result=self.f.host.reviews.manager_action(packet,session=session,
            admission_operation='existing-manager-entry',audit=self.audit,
            repository='owner/repo',supervisor=self.f.supervisor)
        state=self.f.ledger.snapshot()['state'];audit=state['run_reviews']['run']['overrides'][-1]
        self.assertEqual(audit['manager']['human_origin'],review_fixture.HUMAN.canonical())
        self.assertEqual(audit['manager']['manager_id'],'manager')
        self.assertNotEqual(state['runs']['run']['status'],'CLOSED')
        self.assertIsNone(self.f.host.identity.active)
        self.assertIsInstance(result,dict)

    def test_typed_human_disconnect_denies_without_owner_write(self):
        session,packet=self.human();self.connected=False
        before=self.f.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
            self.f.host.human_action(packet,session=session,audit=self.audit)
        self.assertEqual(self.f.ledger.snapshot(),before)
        self.assertIsNone(self.f.host.identity.active)

    def test_typed_human_stale_version_denies_without_override(self):
        session,packet=self.human()
        self.f.seed(lambda s:s['runs']['run'].update(control_revision=9))
        with self.assertRaisesRegex(LedgerError,'MANAGER_STALE_ACTION'):
            self.f.host.human_action(packet,session=session,audit=self.audit)
        self.assertFalse(self.f.ledger.snapshot()['state']['run_reviews']['run']['overrides'])

    def test_host_completion_observes_human_merge_through_canonical_owner(self):
        session,packet=self.human()
        self.f.host.human_action(packet,session=session,audit=self.audit)
        self.broker.merged=True
        result=self.f.host.observe_completion('completion','run',1,self.envelope['id'])
        state=self.f.ledger.snapshot()['state']
        self.assertEqual(state['runs']['run']['status'],'CLOSED')
        self.assertEqual(state['run_reviews']['run']['current']['stage'],'COMPLETED')
        self.assertEqual(state['runs']['run']['completion']['merger_id'],7)
        self.assertTrue(all(call[0]=='observe' for call in self.broker.calls))
        self.assertIsNone(self.f.host.identity.active)
