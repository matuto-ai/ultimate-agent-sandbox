"""Guarded typed-host/actual SQLite tests; no native task, socket or provider I/O."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace as N
import tempfile
import unittest
from unittest.mock import patch

from uas.artifact_target import ArtifactSourceResolver
from uas.gate_evaluation import GateRoomBinding
from uas.gate_hub import _digest, _run_dependency_digest, _contribution_digest
from uas.git_provenance import GitProvenance, parse_commit
from uas.ledger import RoomLedger, Command, Event, Transition, LedgerError
from uas.lifecycle import Supervisor
from uas.native_host_forge import NativePiHostForge
from uas.native_review_host import NativeReviewHost, NativeReviewAcceptance
from uas.peer import FixturePeerHub, FixtureParticipant
import test_native_pi_host_forge as pi_fixture
from test_git_provenance import raw_commit


class NativeReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.ledger=RoomLedger(root/'room.db','room');self.addCleanup(self.ledger.close)
        self.git=GitProvenance(root/'git.db','room','project');self.addCleanup(self.git.close)
        raw=raw_commit();self.head=parse_commit(raw).oid
        self.git.anchor_source('owner/repo',self.head,raw,contributors=['builder'])
        self.supervisor=Supervisor(root/'control','room',object(),authorize=lambda *_:True,revoke=lambda *_:None)
        self.supervisor._read=lambda:{'phase':'running','desired':'running','instance_id':'instance','spec':{'project_id':'project'}}
        self.helper=pi_fixture.NativePiForgeTests();self.addCleanup(self.helper.doCleanups)
        admission,client=self.helper.typed();admission.seat=replace(admission.seat,capabilities=admission.seat.capabilities+('implement',));client.supervisor=self.supervisor;client.review_enabled=client.gate_enabled=True
        active=patch('uas.workstation_control.alive',return_value=True);active.start();self.addCleanup(active.stop)
        self.ingress=NativePiHostForge(admission,client)
        self.peer=FixturePeerHub(self.ledger)
        self.peer.configure('configure',(FixtureParticipant('pi','builder'),FixtureParticipant('other','reviewer')),'run')
        self.peer.connect('admit-'+self.ingress.binding.operation_id,'pi',self.ingress.origin.incarnation_id,object())
        self.n=0
        self.run={'run_id':'run','generation':1,'status':'ACTIVE','project_id':'project','repository':'owner/repo',
                  'actor_id':'builder','participant_id':'pi','checkout':{'slot':'primary'},'policy':{},
                  'gate_target':{'head_sha':self.head}}
        self.seed(lambda s:s.update(runs={'run':deepcopy(self.run)}))
        self.source={'run_id':'run','participant_id':'pi','room_instance':'instance','head_sha':self.head,
                     'source_digest':'d'*64,'checkout':'original'}
        resolver=object.__new__(ArtifactSourceResolver);resolver.supervisor=self.supervisor;resolver.repo=root
        resolver.resolve=lambda *args:deepcopy(self.source)
        def locked(cap,*args):cap.require(self.supervisor);return deepcopy(self.source)
        resolver.resolve_locked=locked
        self.host=NativeReviewHost((self.ingress,),self.ledger,self.git,resolver,
            GateRoomBinding('room','instance','project','owner/repo',128<<20),reviewers=[],human_mergers=[7])
        self.envelope={'id':'review','kind':'submit-for-review','run_id':'run','generation':1,'payload':{}}

    def seed(self,fn):
        self.n+=1
        def decide(state,_):fn(state);return Transition(state,(Event('seed',{}),),{})
        self.ledger.apply(Command('seed-'+str(self.n),'seed','run',1,{}),self.ingress.origin,
                          authorize=lambda *_:True,decide=decide)

    def scope(self):return NativeReviewAcceptance(self.host,self.ingress,object(),self.envelope)

    def test_exact_constructor_uses_same_ledger_and_canonical_projection_owners(self):
        self.assertIs(self.host.reviews.ledger,self.ledger)
        self.assertIs(self.host.gates.repository_hub.ledger,self.ledger)
        self.assertIs(self.host.gates.diff_hub.ledger,self.ledger)
        self.assertIs(self.ingress.review_host,self.host)
        with self.assertRaises(LedgerError):NativeReviewAcceptance(N(),self.ingress,None,self.envelope)

    def test_local_commit_order_and_source_change_rejection(self):
        scope=self.scope()
        with scope.operation(scope.admission_operation):
            self.assertFalse(getattr(self.git,'_history_fenced',False))
            with scope.commit():
                scope.capability.require(self.supervisor)
                self.assertTrue(self.git._history_fenced)
                scope.check_state(self.ledger.snapshot()['state'])
            self.source['head_sha']='f'*40
            with self.assertRaisesRegex(LedgerError,'GATE_SOURCE_CHANGED'):
                with scope.commit():self.fail('changed source accepted')
        self.assertEqual(scope.phase,'closed')
        with self.assertRaises(LedgerError):
            with scope.operation(scope.admission_operation):pass

    def test_full_worktree_binding_not_only_head(self):
        scope=self.scope()
        with scope.operation(scope.admission_operation):
            self.source['checkout']='replacement'
            with self.assertRaisesRegex(LedgerError,'GATE_SOURCE_CHANGED'):
                with scope.commit():pass

    def test_same_incarnation_replacement_attachment_and_actor_rejected(self):
        for mutation in ('attachment','actor','lost'):
            with self.subTest(mutation=mutation):
                original=deepcopy(self.ledger.snapshot()['state'])
                def change(s):
                    if mutation=='attachment':s['peer_traffic']['connections']['pi']['attachment_id']='other'
                    elif mutation=='actor':s['peer_traffic']['definition']['participants']['pi']['actor_id']='other'
                    else:s['peer_traffic']['connections']['pi']['readiness']='lost'
                self.seed(change)
                with self.assertRaises(LedgerError):
                    scope=self.scope()
                    with scope.operation(scope.admission_operation):pass
                self.seed(lambda s:s.update(deepcopy(original)))

    def test_fresh_git_contribution_visible_in_consuming_fence(self):
        scope=self.scope()
        with scope.operation(scope.admission_operation):
            initial=self.host.identity.read_identity(self.run,'builder',self.head,None)
            self.assertEqual(initial['contributors'],['builder'])
            self.git.record_mutation('mutation',{'run_id':'run','generation':1},self.ingress.origin,'add','b'*64,authorize=lambda:True)
            with scope.commit():
                scope.check_state(self.ledger.snapshot()['state'])
                fact=self.host.identity.read_identity(self.run,'builder',self.head,None)
                self.assertIn('builder',fact['contributors'])

    def test_exact_refresh_capture_rejects_same_digest_substitution(self):
        scope=self.scope()
        row={'evaluation_id':'evaluation','refresh':{'operation_id':'fresh-1','phase':'TERMINAL',
              'projection':{'dependency_digest':'same'},'audit_reference':'audit'}}
        with scope.operation(scope.admission_operation):
            scope.capture_refresh(row,'fresh-1');scope.finish_refresh('evaluation','fresh-1')
            before={'evaluation':{'evaluation_id':'evaluation'}}
            expected=scope.refreshed_rows(before)
            substituted=deepcopy(row);substituted['refresh']['operation_id']='fresh-2'
            self.assertEqual(expected['evaluation'],row)
            self.assertNotEqual(expected['evaluation'],substituted)
            row['refresh']['operation_id']='caller-mutated'
            self.assertEqual(expected['evaluation']['refresh']['operation_id'],'fresh-1')

    def test_apply_runs_callback_with_held_fences_and_no_reacquisition(self):
        scope=self.scope()
        with scope.operation(scope.admission_operation):
            def decide(state,_):
                self.assertTrue(self.git._history_fenced)
                scope.capability.require(self.supervisor)
                scope.check_state(state)
                return Transition(state,(Event('native.checked',{}),),{'done':True})
            result=self.host.reviews._apply(Command('accepted','native.accept','run',1,{}),self.ingress.origin,
                                            scope.authorize,decide)
            self.assertEqual(result,{'done':True})
            self.assertFalse(self.git._history_fenced)

    def test_human_claim_in_packet_never_authorizes_control(self):
        self.assertFalse(self.host.authorize_human(self.ingress.origin))
        with self.assertRaises(LedgerError):self.host.human_action({},session=N(),audit=N())

    def test_real_reducer_and_gate_preparation_provider_outside_fences(self):
        from uas.gate_policy import compile_policy
        from test_run_review import Broker, TARGET
        policy = {'id':'default','version':1,'gates':[{'id':'check','kind':'attestation',
            'config':{'statement_id':'checked','scope':'run','eligible_actors':['builder'],
                      'relationship':'implementer','required_capability':'implement','allow_self':True,
                      'continuing_authority':True}}],
            'protected_operations':{'submit-for-review':['check'],'complete':['check']},
            'review_return_cap':5,'queue_timeout_seconds':60,'response_timeout_seconds':60}
        target=deepcopy(TARGET);target['head_sha']=self.head
        self.seed(lambda s:s['runs']['run'].update(policy=compile_policy(policy,'policy'),
            gate_target=target,gate_target_binding={'fixture':'bound'}))
        scope=self.scope()
        with scope.operation(scope.admission_operation):
            self.host.gates.submit('gate-check','run',1,{'gate_id':'check','statement_id':'checked',
                'action':'assert','note':'checked','evidence_refs':['test:check']},origin=self.ingress.origin)
        with self.scope().operation(self.ingress.binding.operation_id):
            projected=self.host.gates.projection('run',1,'check',origin=self.ingress.origin)
            self.assertEqual(projected['state'],'passed',str(self.ledger.snapshot()['state']['gate_evaluations']))
        broker=Broker();broker.head=self.head
        observe=broker.observe
        def observed(*args,**kwargs):
            self.assertFalse(self.git._history_fenced)
            self.assertIsNone(self.host.identity.active.capability)
            return observe(*args,**kwargs)
        broker.observe=observed;self.host.reviews.broker=broker
        envelope={**self.envelope,'payload':{'target':target,'evidence':['test:check']}}
        result=self.host.submit(self.ingress,object(),envelope)
        self.assertEqual(result['stage'],'ATTENTION')  # no configured reviewer is invented
        self.assertEqual(result['reason'],'NO_ELIGIBLE_REVIEWER')
        self.assertEqual(len(broker.calls),1)
        self.assertEqual(self.host.submit(self.ingress,object(),envelope),result)
        self.assertEqual(len(broker.calls),1)

    def test_native_review_ingress_has_no_forge_id_reservation(self):
        import inspect
        source=inspect.getsource(NativePiHostForge.receive_once)
        review=source[source.index("if envelope.get('kind') in ('submit-for-review'"):source.index('else:',source.index("if envelope.get('kind') in ('submit-for-review'"))]
        self.assertIn('owner.submit(self,record,envelope)',review)
        self.assertNotIn('_reserve(',review)

class NativeCompletionTests(unittest.TestCase):
    def setUp(self):
        import test_native_review_host_adversarial as adversarial
        self.case=adversarial.NativeReviewAdversarialTests('test_host_completion_observes_human_merge_through_canonical_owner')
        self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.f=self.case.f

    def prepared(self):
        session,packet=self.case.human()
        self.f.host.human_action(packet,session=session,audit=self.case.audit)
        return session,packet

    def test_unmerged_and_wrong_merger_do_not_close(self):
        self.prepared()
        result=self.f.host.observe_completion('unmerged','run',1,self.case.envelope['id'])
        self.assertEqual(result['reason'],'AWAITING_HUMAN_MERGE')
        self.assertEqual(self.f.ledger.snapshot()['state']['runs']['run']['status'],'ACTIVE')
        self.case.broker.merged=True;self.case.broker.who=999
        result=self.f.host.observe_completion('wrong-merger','run',1,self.case.envelope['id'])
        self.assertEqual(result['reason'],'MERGE_IDENTITY_UNVERIFIABLE')
        self.assertEqual(self.f.ledger.snapshot()['state']['runs']['run']['status'],'ACTIVE')

    def test_host_poll_cannot_ignore_canonical_lost_even_after_override(self):
        self.prepared();self.case.broker.merged=True
        self.f.seed(lambda s:s['peer_traffic']['connections']['pi'].update(readiness='lost'))
        calls=len(self.case.broker.calls)
        with self.assertRaisesRegex(LedgerError,'STALE_CONNECTION'):
            self.f.host.observe_completion('after-lost','run',1,self.case.envelope['id'])
        self.assertEqual(len(self.case.broker.calls),calls)
        self.assertEqual(self.f.ledger.snapshot()['state']['runs']['run']['status'],'ACTIVE')

    def test_native_packet_cannot_request_completion_or_human_override(self):
        for kind in ('review.observe-completion','override-review'):
            with self.assertRaisesRegex(LedgerError,'INVALID_REVIEW_COMMAND'):
                self.f.host.submit(self.f.ingress,object(),{**self.case.envelope,'kind':kind})
        self.assertFalse(self.case.broker.calls)

    def test_owner_thread_checked_before_scope_or_duplicate(self):
        before=self.f.ledger.snapshot()
        with patch('uas.gate_evaluation.threading.get_ident',return_value=-1):
            with self.assertRaisesRegex(LedgerError,'GATE_OWNER_MISMATCH'):
                self.f.host.submit(self.f.ingress,object(),self.case.envelope)
            with self.assertRaisesRegex(LedgerError,'GATE_OWNER_MISMATCH'):
                self.f.host.observe_completion('wrong-thread','run',1,'review')
        self.assertIsNone(self.f.host.identity.active)
        self.assertEqual(self.f.ledger.snapshot(),before)

    def test_manager_eligibility_uses_typed_session_without_effect(self):
        session,packet=self.case.human();before=self.f.ledger.snapshot()
        self.f.host.reviews.manager_eligibility('override-review','run',session=session,
            admission_operation='manager',supervisor=self.f.supervisor)
        self.assertEqual(self.f.ledger.snapshot(),before)
        self.assertIsNone(self.f.host.identity.active)
