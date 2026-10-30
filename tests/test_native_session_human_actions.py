"""Driver to real Manager/RunReview reducers; only native/provider boundaries controlled."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch
import test_native_session_driver as driver_fixture
import test_native_gate_session_composition as composition_fixture
from uas.forge_audit import ForgeAudit
from uas.ledger import LedgerError
from uas.peer import Readiness
from uas.manager_actions import run_version
from uas.native_run_admission import NativeHumanRunRequest
from uas.native_session_driver import NativeSessionDriver, NativeHumanReviewInbox


class NativeSessionHumanActionsTests(unittest.TestCase):
    def setUp(self):
        f=driver_fixture.NativeSessionDriverTests();f.setUp();self.addCleanup(f.doCleanups);self.fixture=f
        self.c,self.review_host,self.budget=f.c,f.review_host,f.budget
        from uas.gate_policy import compile_policy
        from uas.git_provenance import parse_commit
        from uas.forge_audit import ForgeAudit
        from uas.manager_actions import run_version
        import test_run_review as review_fixture
        import test_git_provenance as git_fixture
        c=self.c;host=self.review_host
        c.pi.forge_service.origin=replace(c.pi.forge_service.origin,capabilities=c.pi.forge_service.origin.capabilities+('peer-traffic',))
        raw=git_fixture.raw_commit();head=parse_commit(raw).oid
        repository=c.room['project']['repository']
        c.recruitment.provenance.anchor_source(repository,head,raw,contributors=[c.actor])
        c.source['head_sha']=head
        target={**review_fixture.TARGET,'repository':repository,'head_sha':head}
        policy={'id':'default','version':1,'gates':[{'id':'check','kind':'attestation',
            'config':{'statement_id':'checked','scope':'run','eligible_actors':[c.actor],
                'relationship':'implementer','required_capability':'implement','allow_self':True,
                'continuing_authority':True}}],
            'protected_operations':{'submit-for-review':['check'],'complete':['check']},
            'review_return_cap':5,'queue_timeout_seconds':60,'response_timeout_seconds':60}
        c.seed(lambda state:state['runs'][c.run_id].update(policy=compile_policy(policy,'policy'),
            gate_target=deepcopy(target),gate_target_binding={'fixture':'bound'}))
        from uas.native_review_host import NativeReviewAcceptance
        envelope={'id':'submission','kind':'submit-for-review','run_id':c.run_id,'generation':1,
            'payload':{'target':target,'evidence':['test:check']}}
        scope=NativeReviewAcceptance(host,c.pi.forge_service,object(),envelope)
        with scope.operation(scope.admission_operation):
            host.gates.submit('gate-check',c.run_id,1,{'gate_id':'check','statement_id':'checked',
                'action':'assert','note':'checked','evidence_refs':['test:check']},origin=c.pi.forge_service.origin)
        broker=review_fixture.Broker();broker.head=head
        observe=broker.observe
        def provider(*args,**kwargs):
            result=observe(*args,**kwargs)
            result['observation']['pull']['base']['repo']['full_name']=repository
            return result
        broker.observe=provider;host.reviews.broker=broker
        from uas.peer import RequestCommand, digest
        connection=c.hub._connections[c.participant]
        request_id=c.ledger.snapshot()['state']['runs'][c.run_id]['implementation_request']
        c.hub.observe(connection,Readiness.SAFE)
        offer=c.hub.prepare_delivery(connection,traffic_id=request_id);offered=offer.envelope
        receipt={key:offered[key] for key in ('delivery_id','participant_id','incarnation_id','context_generation')}
        receipt['digest']=digest(offered)
        c.hub.confirm_delivery(connection,offer,receipt)
        c.hub.submit(connection,RequestCommand('accept-initial',c.run_id,1,request_id,'accept'))
        host.submit(c.pi.forge_service,object(),envelope)
        audit=ForgeAudit(Path(c.launcher.resources['supervisor_directory'])/'driver-audit.db',c.session.deployment_id)
        self.addCleanup(audit.close)
        state=c.ledger.snapshot()['state'];row=state['run_reviews'][c.run_id]['current']
        with audit.manager_action_guard(c.room['id'],repository) as forge:
            version=run_version(state,c.run_id,forge)
        packet={'version':1,'operation_id':'human-override','action':'override-review',
            'deployment_id':c.session.deployment_id,'room_id':c.room['id'],'instance_id':'instance',
            'run_id':c.run_id,'generation':1,'object_id':row['submission_id'],'observed_version':version,
            'payload':{'reason':'controlled human decision','rounds':None}}
        control_session=replace(c.session,human=replace(c.human,capabilities=c.human.capabilities+('human-control-run',)))
        host.human_action(packet,session=control_session,audit=audit)
        original_receipt=broker.comment_receipt
        def receipt(operation):
            value=original_receipt(operation)
            if value['comment_reference'] is not None:
                value['comment_reference']['url']=value['comment_reference']['url'].replace('owner/repo',repository)
            return value
        broker.comment_receipt=receipt
        self.audit,self.broker,self.session=audit,broker,control_session
        self.request=replace(self.fixture.request,session=control_session)
        self.inbox=NativeHumanReviewInbox(control_session,audit)
        self.driver=NativeSessionDriver(c.admission,c.recruitment,self.request,self.budget,human_actions=self.inbox)
        self.provider_calls=[]
        for name in ('observe','comment','reconcile_comment'):
            original=getattr(broker,name)
            def call(*args,_name=name,_original=original,**kwargs):
                self.assertIsNone(host.identity.active.capability)
                self.assertFalse(c.recruitment.provenance._history_fenced)
                self.assertFalse(c.ledger._connection().in_transaction)
                self.provider_calls.append((_name,args[2] if _name!='observe' else args[1]))
                return _original(*args,**kwargs)
            setattr(broker,name,call)
        broker.calls.clear()

    def packet(self,op='human-change',action='request-changes',object_id='submission'):
        c=self.c;state=c.ledger.snapshot()['state']
        with self.audit.manager_action_guard(c.room['id'],c.room['project']['repository']) as guard:
            version=run_version(state,c.run_id,guard)
        return {'version':1,'operation_id':op,'action':action,'deployment_id':self.session.deployment_id,
            'room_id':c.room['id'],'instance_id':'instance','run_id':c.run_id,'generation':1,
            'object_id':object_id,'observed_version':version,
            'payload':{'body':'Please revise the original candidate.'} if action=='request-changes' else {}}

    def comments(self):return self.c.ledger.snapshot()['state'].get('review_comments',{})

    def test_confirmed_human_request_is_actual_canonical_return_not_driver_fabrication(self):
        packet=self.packet();self.inbox.enqueue(packet)
        result=self.driver.run()
        row=self.comments()['human-change']
        self.assertEqual(row['status'],'confirmed',(result,self.provider_calls))
        self.assertEqual(row['human_origin'],self.session.human.canonical())
        self.assertEqual(row['manager']['manager_id'],self.session.manager_id)
        self.assertEqual([x[0] for x in self.provider_calls].count('comment'),1)
        self.assertEqual(self.inbox.enqueue(packet),'confirmed')
        self.assertNotIn('body',str(result['human_actions']))
        review=self.c.ledger.snapshot()['state']['run_reviews'][self.c.run_id]['current']
        self.assertEqual(review['stage'],'IMPLEMENTING')
        self.assertTrue(review['implementation_request'])

    def test_unknown_comment_blocks_all_automated_effects_and_identical_enqueue_does_not_repeat(self):
        self.broker.comment_status='unknown';packet=self.packet();self.inbox.enqueue(packet)
        self.fixture.readable=[s.helper.forge_channel for s in self.driver._services()]
        result=self.driver.run()
        self.assertEqual(self.comments()['human-change']['status'],'unknown')
        self.assertEqual(self.inbox.enqueue(packet),'unknown')
        self.assertEqual([x[0] for x in self.provider_calls].count('comment'),1)
        self.assertEqual(result['counts'],{'packets':0,'deliveries':0,'completion_reads':0})
        for service in self.driver._services():service.receive_once.assert_not_called()
        self.c.pi._delivery_exchange.assert_not_called()
        self.fixture.root.native_admission._delivery_exchange.assert_not_called()
        self.assertEqual(result['pending_human_comments'],['human-change'])

    def test_explicit_reconcile_uses_original_comment_without_second_post(self):
        self.broker.comment_status='unknown';self.inbox.enqueue(self.packet())
        queued=[]
        def later():
            if not queued and self.comments().get('human-change',{}).get('status')=='unknown':
                queued.append(True);self.broker.comment_status='confirmed'
                self.inbox.enqueue(self.packet('reconcile','reconcile-changes','human-change'))
        self.fixture.on_select=later
        result=self.driver.run()
        self.assertEqual(self.comments()['human-change']['status'],'confirmed',(result,self.provider_calls))
        self.assertEqual([x[0] for x in self.provider_calls].count('comment'),1)
        self.assertEqual([x[0] for x in self.provider_calls].count('reconcile_comment'),1)
        self.assertFalse(result['pending_human_comments'])
        self.assertEqual(next(value for name,value in self.provider_calls if name=='reconcile_comment'),'human-change')

    def test_stale_version_is_rejected_before_provider_and_does_not_repair_itself(self):
        self.inbox.enqueue(self.packet());self.c.seed(lambda s:s['runs'][self.c.run_id].update(control_revision=99))
        self.driver.next_completion=999
        self.driver.run()
        self.assertEqual(self.provider_calls,[]);self.assertFalse(self.comments())
        self.assertEqual(self.inbox.snapshot()[0]['status'],'rejected')
        self.assertEqual(self.inbox.snapshot()[0]['reason'],'MANAGER_STALE_ACTION')

    def test_disconnect_after_enqueue_cannot_grant_action(self):
        self.inbox.enqueue(self.packet());self.c.connected=False
        self.driver.run()
        self.assertEqual(self.provider_calls,[]);self.assertFalse(self.comments())

    def test_inbox_immutable_duplicate_conflict_and_lifetime_bound(self):
        packet=self.packet();self.inbox.enqueue(packet);packet['payload']['body']='changed outside inbox'
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):self.inbox.enqueue(packet)
        for i in range(1,8):self.inbox.enqueue(self.packet('op-'+str(i)))
        with self.assertRaisesRegex(LedgerError,'CAPACITY'):self.inbox.enqueue(self.packet('ninth'))
        self.assertEqual(len(self.inbox.snapshot()),8)

    def test_wrong_session_identity_not_accepted_even_equal_fields(self):
        inbox=NativeHumanReviewInbox(replace(self.session),self.audit)
        with self.assertRaisesRegex(LedgerError,'EXACT_NATIVE_HUMAN_ACTION_OWNER_REQUIRED'):
            NativeSessionDriver(self.c.admission,self.c.recruitment,self.request,self.budget,human_actions=inbox)

    def test_lost_post_response_retains_original_operation_and_never_reposts(self):
        original=self.broker.comment
        def lost(*args,**kwargs):
            original(*args,**kwargs)
            raise TimeoutError('controlled lost provider response')
        self.broker.comment=lost
        packet=self.packet();self.inbox.enqueue(packet)
        result=self.driver.run()
        self.assertEqual(result['outcome'],'unknown')
        self.assertEqual(self.comments()['human-change']['status'],'pending')
        self.assertEqual(self.inbox.enqueue(packet),'unknown')
        self.assertEqual([x[0] for x in self.provider_calls].count('comment'),1)
        self.assertEqual(result['counts'],{'packets':0,'deliveries':0,'completion_reads':0})

    def test_pending_comment_rejects_unrelated_new_write_without_resuming_effects(self):
        self.broker.comment_status='unknown';self.inbox.enqueue(self.packet())
        queued=[]
        def later():
            if not queued:
                queued.append(True);self.inbox.enqueue(self.packet('another-change'))
        self.fixture.on_select=later
        result=self.driver.run()
        self.assertEqual(set(self.comments()),{'human-change'})
        self.assertEqual(self.inbox.snapshot()[1]['reason'],'NATIVE_HUMAN_RECONCILIATION_REQUIRED')
        self.assertEqual([x[0] for x in self.provider_calls].count('comment'),1)
        self.assertEqual(result['counts'],{'packets':0,'deliveries':0,'completion_reads':0})

    def test_payload_bounds_do_not_spend_queue_capacity(self):
        for payload in ({'body':''},{'body':'x'*8193},{'body':True},{'body':'x','extra':True}):
            with self.subTest(payload_type=type(payload.get('body'))),self.assertRaises(LedgerError):
                self.inbox.enqueue({**self.packet(), 'payload':payload})
        with self.assertRaises(LedgerError):
            self.inbox.enqueue({**self.packet('reconcile','reconcile-changes','original'),'payload':{'body':'not allowed'}})
        self.assertEqual(self.inbox.snapshot(),[])

    def test_actual_session_run_passes_exact_authenticated_inbox_to_driver(self):
        import uas.native_session as session_module
        f=composition_fixture.NativeGateSessionCompositionTests();f.setUp();self.addCleanup(f.doCleanups)
        audit=ForgeAudit(Path(f.resources['supervisor_directory'])/'inbox-compose.db',f.request.session.deployment_id)
        self.addCleanup(audit.close)
        inbox=NativeHumanReviewInbox(f.request.session,audit)
        original_run=session_module.run;original_init=NativeSessionDriver.__init__;captured=[]
        def run(*args,**kwargs):return original_run(*args,**kwargs,human_actions=inbox)
        def init(driver,*args,**kwargs):
            original_init(driver,*args,**kwargs)
            self.assertIs(driver.human_actions,inbox)
            self.assertIs(driver.human_actions.session,driver.request.session)
            self.assertIs(driver.human_actions.audit,audit)
            captured.append(driver)
        with patch.object(session_module,'run',side_effect=run),patch.object(NativeSessionDriver,'__init__',init):
            result=f.execute()
        self.assertEqual(result['status'],'NATIVE_RUN_SESSION_FINISHED')
        self.assertEqual(len(captured),1)
        self.assertEqual(inbox.snapshot(),[])

    def test_multibyte_wire_limit_is_distinct_from_body_character_limit(self):
        valid={**self.packet('unicode-ok'),'payload':{'body':'Revisão aprovada? Não, ajustar primeiro. ✓'}}
        self.assertEqual(self.inbox.enqueue(valid),'queued')
        large={**self.packet('unicode-large'),'payload':{'body':'😀'*8192}}
        with self.assertRaises(LedgerError):self.inbox.enqueue(large)
        self.assertEqual(len(self.inbox.snapshot()),1)

    def test_authority_revoked_after_read_prevents_comment_post(self):
        original=self.broker.observe
        def observe(*args,**kwargs):
            result=original(*args,**kwargs);self.c.authorized=False;return result
        self.broker.observe=observe
        self.inbox.enqueue(self.packet());self.driver.run()
        self.assertFalse(self.comments())
        self.assertEqual([name for name,_ in self.provider_calls],['observe'])

    def test_source_changes_after_read_prevent_comment_post(self):
        original=self.broker.observe
        def observe(*args,**kwargs):
            result=original(*args,**kwargs);self.c.source['source_digest']='f'*64;return result
        self.broker.observe=observe
        self.inbox.enqueue(self.packet());self.driver.run()
        self.assertFalse(self.comments())
        self.assertNotIn('comment',[name for name,_ in self.provider_calls])
