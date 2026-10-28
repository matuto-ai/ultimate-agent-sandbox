"""Finite driver with actual canonical owners; native I/O/clock are controlled.

Seeded terminal facts are explicit inputs, not evidence of native Git/Gate work.
"""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas.claude_native_admission import NativeClaudeSupervisorAdmission
from uas.kernel_origin import OriginDenied
from uas.ledger import LedgerError
from uas.native_review_host import NativeReviewHost
from uas.native_run_admission import NativeHumanRunRequest
from uas.native_session import SessionBudget
from uas.native_session_driver import NativeSessionDriver
from uas.peer import Readiness
import test_native_reviewer_recruitment_adversarial as fixture


class NativeSessionDriverTests(unittest.TestCase):
    def setUp(self):
        c=fixture.RecruitmentAdversarialTests();c.setUp();self.addCleanup(c.doCleanups);self.c=c
        root=c.recruit();self.root=root
        c.launcher.exec_seat=N(participant_id=c.participant)
        self.now=0.;self.polls=[];self.on_select=lambda:None;self.readable=[]
        self.clock=patch('uas.native_session_driver.time.monotonic',side_effect=lambda:self.now)
        self.clock.start();self.addCleanup(self.clock.stop)
        self.budget=SessionBudget(120);c.launcher.budget=self.budget
        self.request=NativeHumanRunRequest('open',1,c.participant,c.session)
        root.recipe=N(scope={'room_id':c.room['id'],'participant_id':c.reviewer,'run_id':c.run_id,
            'generation':1,'context_generation':1},session_id='controlled-reviewer')
        root.incarnation='reviewer-incarnation'
        root.native_receiver=N(scope=root.recipe.scope,observe=lambda:Readiness.SAFE)
        reviewer=object.__new__(NativeClaudeSupervisorAdmission)
        reviewer.launch=root;reviewer.seat=N(participant_id=c.reviewer,room_id=c.room['id'])
        root.native_admission=reviewer
        for admission in (c.pi,reviewer):
            admission._authority=nullcontext();admission._delivery_lock=nullcontext()
            admission._delivery_pending=None;admission._current=Mock()
            admission._delivery_exchange=Mock(return_value={'status':'HELD'})
        c.recruitment.resolver.resolve=lambda *args:deepcopy(c.source)
        c.recruitment.resolver.repo=Path(c.launcher.resources['supervisor_directory'])
        c.owner_client.review_enabled=c.owner_client.gate_enabled=True
        self.review_host=NativeReviewHost((c.pi.forge_service,root.forge_service),c.ledger,
            c.recruitment.provenance,c.recruitment.resolver,c.recruitment.binding,
            reviewers=[],human_mergers=[7])
        root.review_host=self.review_host
        for service in (c.pi.forge_service,root.forge_service):
            service._current=Mock(return_value=True)
            service.helper=N(forge_channel=object());service.receive_once=Mock()
        self.driver=NativeSessionDriver(c.admission,c.recruitment,self.request,self.budget)
        def select(read,write,error,timeout):
            self.polls.append((tuple(read),timeout));self.now+=20
            self.on_select()
            return list(self.readable),[],[]
        self.select=patch('uas.native_session_driver.select.select',side_effect=select)
        self.select.start();self.addCleanup(self.select.stop)

    def close_run(self,outcome='completed'):
        self.c.seed(lambda state:state['runs'][self.c.run_id].update(status='CLOSED',outcome=outcome))

    def test_idle_keeps_polling_both_real_deliveries_until_original_budget(self):
        before=self.c.ledger.snapshot()
        result=self.driver.run()
        self.assertEqual((result['outcome'],result['reason']),('inconclusive','operation-deadline'))
        self.assertGreater(len(self.polls),1)
        self.assertEqual(self.c.pi._delivery_exchange.call_count,len(self.polls))
        self.assertEqual(self.root.native_admission._delivery_exchange.call_count,len(self.polls))
        self.assertEqual(self.c.ledger.snapshot(),before)
        self.assertEqual(result['counts'],{'packets':0,'deliveries':0,'completion_reads':0})
        self.assertFalse(result['authority_restored_from_journal'])
        with self.assertRaisesRegex(LedgerError,'ONE_SHOT'):self.driver.run()

    def test_ready_channels_service_both_exact_retained_ingresses(self):
        services=(self.c.pi.forge_service,self.root.forge_service)
        self.readable=[service.helper.forge_channel for service in services]
        services[1].receive_once.side_effect=self.close_run
        result=self.driver.run()
        self.assertEqual(result['outcome'],'completed');self.assertEqual(result['counts']['packets'],2)
        for service in services:service.receive_once.assert_called_once_with()
        self.assertEqual(len(self.polls),1)

    def test_packet_timeout_is_unknown_and_never_retried(self):
        service=self.c.pi.forge_service;self.readable=[service.helper.forge_channel]
        service.receive_once.side_effect=TimeoutError('uncertain response')
        result=self.driver.run()
        self.assertEqual(result['outcome'],'unknown');self.assertIn('reconcile',result['reason'])
        service.receive_once.assert_called_once_with()
        self.assertEqual(self.c.ledger.snapshot()['state']['runs'][self.c.run_id]['status'],'ACTIVE')

    def test_native_authority_loss_stops_without_replacing_owners(self):
        service=self.root.forge_service
        self.on_select=lambda:setattr(service,'_current',Mock(side_effect=OriginDenied('lost')))
        result=self.driver.run()
        self.assertEqual(result['reason'],'native-authority-lost-restoration-required')
        self.assertIs(self.c.launcher.started[self.c.participant],self.c.pi)
        self.assertEqual(len(self.c.starts),1)

    def test_disconnected_human_prevents_any_delivery_or_poll(self):
        self.c.connected=False
        result=self.driver.run()
        self.assertEqual(result['reason'],'NATIVE_SESSION_AUTHORIZATION_REVOKED')
        self.assertFalse(self.polls);self.c.pi._delivery_exchange.assert_not_called()

    def test_paused_and_noncompleted_closed_are_attention_not_success(self):
        self.c.seed(lambda state:state['runs'][self.c.run_id].update(status='PAUSED'))
        self.assertEqual(self.driver.run()['reason'],'canonical-run-not-active')
        self.close_run('stopped')
        second=NativeSessionDriver(self.c.admission,self.c.recruitment,self.request,self.budget)
        self.assertEqual(second.run()['reason'],'canonical-run-closed')
        self.assertFalse(self.polls)

    def test_existing_canonical_completion_returns_without_provider_or_delivery(self):
        self.close_run()
        result=self.driver.run()
        self.assertEqual(result['outcome'],'completed');self.assertFalse(self.polls)
        self.c.pi._delivery_exchange.assert_not_called()
        self.root.forge_service.receive_once.assert_not_called()

    def test_insufficient_budget_does_not_begin_native_operation(self):
        self.now=76
        result=self.driver.run()
        self.assertEqual(result['reason'],'operation-deadline');self.assertFalse(self.polls)
        self.c.pi._delivery_exchange.assert_not_called()

    def test_successor_requires_same_live_session_and_new_explicit_request(self):
        for changes in ({'session':replace(self.c.session,manager_id='other')},
                        {'participant_id':'different'},{'operation_id':'open'},{'issue_number':1}):
            value={'operation_id':'next','issue_number':2,'participant_id':self.c.participant,'session':self.c.session}
            value.update(changes)
            with self.assertRaisesRegex(LedgerError,'EXPLICIT_NATIVE_SUCCESSOR_REQUIRED'):
                NativeSessionDriver(self.c.admission,self.c.recruitment,self.request,self.budget,
                                    next_request=NativeHumanRunRequest(**value))

    def test_eligible_completion_observes_human_merge_with_real_host_and_reducers(self):
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
        broker.merged=True
        result=self.driver.run()
        self.assertEqual(result['outcome'],'completed')
        self.assertEqual(result['counts']['completion_reads'],1)
        state=c.ledger.snapshot()['state']
        self.assertEqual(state['runs'][c.run_id]['completion']['merger_id'],7)
        self.assertEqual(state['run_reviews'][c.run_id]['current']['stage'],'COMPLETED')
        self.assertTrue(all(call[0]=='observe' for call in broker.calls))

    def test_driver_confirms_real_outbox_receipt_without_reinjection(self):
        from uas.peer import digest
        c=self.c;connection=c.hub._connections[c.participant]
        request_id=c.ledger.snapshot()['state']['runs'][c.run_id]['implementation_request']
        held={};accepted=[]
        c.pi.seat.room_id=c.room['id']
        def exchange(kind,receipt=None):
            if kind=='POLL_DELIVERY':
                c.hub.observe(connection,Readiness.SAFE)
                offer=c.hub.prepare_delivery(connection,traffic_id=request_id)
                if offer is None:return {'status':'HELD'}
                held['offer']=offer
                return {'status':'OFFER','envelope':offer.envelope}
            return {'status':'CONFIRMED','receipt':c.hub.confirm_delivery(connection,held['offer'],receipt)}
        def accept(envelope):
            accepted.append(envelope['delivery_id'])
            receipt={key:envelope[key] for key in ('delivery_id','participant_id','incarnation_id','context_generation')}
            return {**receipt,'digest':digest(envelope)}
        c.pi._delivery_exchange=exchange;c.pi.launch.native_receiver.accept=accept
        result=self.driver.run()
        self.assertEqual(result['counts']['deliveries'],1);self.assertEqual(len(accepted),1)
        self.assertEqual(c.ledger.snapshot()['state']['peer_traffic']['traffic'][request_id]['status'],'DELIVERED')
        self.assertIsNone(c.pi._delivery_pending)

    def test_successor_retirement_refusal_keeps_original_owner_and_names_pending_run(self):
        self.close_run()
        request=NativeHumanRunRequest('next',2,self.c.participant,self.c.session)
        driver=NativeSessionDriver(self.c.admission,self.c.recruitment,self.request,self.budget,next_request=request)
        before=(len(self.c.launches),len(self.c.allocations))
        result=driver.run()
        self.assertEqual(result['outcome'],'attention')
        self.assertEqual(result['phase'],'predecessor-retirement')
        self.assertEqual(result['pending_successor'],{'run_id':self.c.admission.run_id('next'),'operation_id':'next'})
        self.assertIs(driver.request,self.request);self.assertIs(driver.recruitment,self.c.recruitment)
        self.assertEqual((len(self.c.launches),len(self.c.allocations)),before)
        self.assertEqual(self.c.ledger.snapshot()['state']['runs'][self.c.run_id]['outcome'],'completed')

    def test_canonical_completion_near_deadline_is_reported_without_effects(self):
        self.close_run();self.now=119.99
        before=self.c.ledger.snapshot()
        result=self.driver.run()
        self.assertEqual((result['outcome'],result['reason']),('completed','canonical-human-merge-observed'))
        self.assertEqual(self.c.ledger.snapshot(),before);self.assertFalse(self.polls)
        self.c.pi._delivery_exchange.assert_not_called()
        self.root.native_admission._delivery_exchange.assert_not_called()
        self.c.pi.forge_service.receive_once.assert_not_called()
        self.root.forge_service.receive_once.assert_not_called()

    def test_invalid_human_run_request_is_rejected_before_any_mutation(self):
        before=self.c.ledger.snapshot()
        for changes in ({'operation_id':''},{'operation_id':123},{'participant_id':''},
                        {'issue_number':True},{'issue_number':0},{'issue_number':10_000_000_000},
                        {'attempt_id':''}):
            with self.subTest(changes=changes):
                values={'operation_id':'next','issue_number':2,'participant_id':self.c.participant,
                        'session':self.c.session}
                values.update(changes)
                with self.assertRaises(LedgerError):NativeHumanRunRequest(**values)
        self.assertEqual(self.c.ledger.snapshot(),before);self.assertFalse(self.polls)
