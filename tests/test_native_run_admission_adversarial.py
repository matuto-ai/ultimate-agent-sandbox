"""Adversarial canonical native Run transactions with controlled native owners.

Real HumanSession, RoomLedger and reducers; no Git/native/socket/thread effects.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as N
import tempfile
import unittest

from uas.checkouts import CheckoutAllocator
from uas.forge import ForgeBinding
from uas.forge_read_service import ReadBrokerClient
from uas.ledger import RoomLedger, Origin, LedgerError, Command, Event, Transition
from uas.lifecycle import Supervisor
from uas.manager_actions import HumanSession
from uas.native_admission_broker import NativeAdmissionBroker
from uas.native_checkout_handoff import NativeCheckoutClient
from uas.native_host_forge import NativePiHostForge
from uas.native_run_admission import NativeRunAdmission, NativeRunLauncher, NativeHumanRunRequest
from uas.peer import FixturePeerHub, FixtureParticipant, Readiness
from uas.workstation_control import SupervisorAdmission
import test_native_qualification as configuration


class NativeRunAdversarialTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name)
        fixture=configuration.NativeQualificationTests();fixture.setUp()
        fixture.config['deployment']['actors'][0]['github_user_id']=7
        self.plan=fixture.plan();self.room=self.plan.room
        self.participant=self.plan.seats['pi']['participant'];self.actor=self.plan.seats['pi']['actor']
        self.ledger=RoomLedger(root/'room.db',self.room['id']);self.addCleanup(self.ledger.close)
        self.hub=FixturePeerHub(self.ledger)
        self.hub.configure('configure',tuple(FixtureParticipant(s['participant'],s['actor']) for s in self.room['seats']),'bootstrap')
        self.supervisor=Supervisor(root/'control',self.room['id'],object(),authorize=lambda *_:False,revoke=lambda *_:None)
        self.supervisor._read=lambda:{'phase':'running','desired':'running','instance_id':'instance','spec':{'project_id':self.room['project']['id']}}
        client=object.__new__(ReadBrokerClient);client.supervisor=self.supervisor;client.room_instance='instance'
        client.binding=ForgeBinding(self.room['id'],self.room['project']['id'],self.room['project']['repository'])
        client.closed=False;client._guards={}
        self.reads=[];self.after_read=lambda:None
        def perform(packet):
            self.reads.append(packet['envelope']['id'])
            guard=client._guards.pop(packet['request_id'])[1];guard()
            out={'status':'OK','completeness':'complete','issue':{'id':101,'number':1,'state':'open',
                'assignees':[{'id':7,'login':'actor'}]},'dependencies':[],'pages':1,
                'delivery_class':{'status':'known','value':'bounded','pages':1}}
            self.after_read()
            return {'admission':'not-evaluated','observation':out}
        client.perform=perform
        self.broker=NativeAdmissionBroker(self.ledger,client.binding,client)
        self.launcher=object.__new__(NativeRunLauncher)
        self.launcher.plan=self.plan;self.launcher.resources={'instance':'instance'}
        self.launcher.supervisor=self.supervisor;self.launcher.hub=self.hub
        self.launcher.forge_broker=self.broker;self.launcher.started={}
        self.launches=[];self.allocations=[];self.observations=[];self.dirty=False;self.serial=0
        def slot(run):return {'run':run,'participant':self.participant,'phase':'ready','reason':'ACTIVE',
            'observed_dirty':self.dirty,'observed_head':'a'*40,'base':'a'*40,'path':'/owned/checkout','slot':'primary'}
        checkout=object.__new__(NativeCheckoutClient)
        def allocate(run,op):self.allocations.append((run,op));return slot(run)
        def observe(run,op):self.observations.append((run,op));return slot(run)
        checkout.allocate=allocate;checkout.observe=observe
        allocator=object.__new__(CheckoutAllocator);allocator.supervisor=self.supervisor;allocator.room=self.room
        self.admission=NativeRunAdmission(self.launcher,allocator,checkout)
        self.connected=True;self.authorized=True
        self.human=Origin('human','human','session','v1',('human-open-run',))
        self.session=HumanSession(self.plan.config['deployment']['id'],self.room['id'],'instance','manager',self.human,
            lambda session,action:self.authorized,lambda:self.connected)
        def launch(run,pending,slot,*,authorize):
            if authorize() is not True:raise LedgerError('ADMISSION_REVOKED')
            self.launches.append(run)
            if self.participant in self.launcher.started:return self.launcher.started[self.participant]
            scope={'room_id':self.room['id'],'participant_id':self.participant,'run_id':run,'generation':1,'context_generation':1}
            handle=object.__new__(SupervisorAdmission)
            handle.seat=N(participant_id=self.participant,actor_id=self.actor)
            handle.launch=N(incarnation='incarnation',native_recipe=N(scope=scope),native_receiver=N(scope=scope,observe=lambda:Readiness.SAFE))
            ingress=object.__new__(NativePiHostForge);ingress.client=client;ingress.binding=N(operation_id='operation')
            ingress.origin=Origin(self.actor,self.participant,'incarnation','native-authority',('forge-read','implement'))
            ingress._current=lambda:True;handle.forge_service=ingress
            self.hub.connect('admit-operation',self.participant,'incarnation',object())
            def poll(kind):
                self.seed(lambda state:state['peer_traffic']['connections'][self.participant].update(readiness='safe'))
                return {'status':'HELD'}
            handle._delivery_exchange=poll
            self.launcher.started[self.participant]=handle
            return handle
        self.launcher.launch=launch
    def seed(self,change):
        self.serial+=1
        def decide(state,_):change(state);return Transition(state,(Event('test.seed',{}),),{})
        self.ledger.apply(Command('seed-'+str(self.serial),'seed','object',1,{}),self.human,authorize=lambda *_:True,decide=decide)
    def open(self,operation='open',attempt=None):
        return self.admission.open_human(operation,1,self.participant,session=self.session,attempt_id=attempt)
    def assert_unactivated(self):
        state=self.ledger.snapshot()['state']
        self.assertFalse(state.get('runs'));self.assertFalse(state['peer_traffic']['traffic'])
        self.assertTrue(all(not r['authorization_consumed'] for r in state.get('run_admissions',{}).values()))
    def test_exact_committed_retry_never_reallocates_relaunches_or_recontacts(self):
        first=self.open();counts=(len(self.allocations),len(self.launches),len(self.reads),len(self.observations))
        second=self.open();self.assertEqual(first,second)
        self.assertEqual(counts,(len(self.allocations),len(self.launches),len(self.reads),len(self.observations)))
        self.assertEqual(1,len(self.ledger.snapshot()['state']['peer_traffic']['traffic']))
    def test_missing_disconnected_or_wrong_scope_human_denies_before_effects(self):
        before=self.ledger.snapshot()
        with self.assertRaises(LedgerError):NativeHumanRunRequest('op',1,self.participant,{'authorized':True})
        with self.assertRaises(LedgerError):self.admission.open_human('open',1,self.participant,session=None)
        self.connected=False
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.open()
        self.connected=True
        with self.assertRaises(LedgerError):self.admission.open_human('open',1,self.participant,session=replace(self.session,instance_id='other'))
        self.assertEqual(before,self.ledger.snapshot());self.assertFalse(self.allocations+self.reads+self.launches)
    def test_actor_user_mapping_drift_after_reservation_denies_before_checkout(self):
        with self.admission.human_scope(self.session):self.admission._prepare('open',1,self.participant,self.human)
        self.admission.actors[self.actor]['github_user_id']=99
        with self.assertRaisesRegex(LedgerError,'ACTOR_BINDING_CHANGED'):self.open()
        self.assertFalse(self.allocations+self.reads+self.launches);self.assert_unactivated()
    def test_lost_attachment_after_provider_read_never_activates(self):
        self.after_read=lambda:self.seed(lambda state:state['peer_traffic']['connections'][self.participant].update(readiness='lost'))
        with self.assertRaisesRegex(LedgerError,'STALE_CONNECTION'):self.open()
        self.assertEqual(1,len(self.reads));self.assert_unactivated()
    def test_dirty_checkout_after_provider_read_is_reobserved_and_held(self):
        self.after_read=lambda:setattr(self,'dirty',True)
        with self.assertRaisesRegex(LedgerError,'CHECKOUT_NOT_READY'):self.open()
        self.assertEqual(1,len(self.allocations));self.assertEqual(1,len(self.observations));self.assert_unactivated()
    def test_human_disconnected_during_read_cannot_consume_authorization(self):
        self.after_read=lambda:setattr(self,'connected',False)
        with self.assertRaises(LedgerError):self.open()
        self.assert_unactivated();self.assertIsNone(self.admission._session)
    def test_already_connected_bootstrap_context_cannot_be_relabelled(self):
        self.hub.connect('bootstrap-attach',self.participant,'old-incarnation',object())
        before=self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'UNUSED_NATIVE_CONTEXT_REQUIRED'):self.open()
        self.assertEqual(before,self.ledger.snapshot());self.assertFalse(self.allocations+self.reads+self.launches)

    def test_human_disconnect_after_checkout_refuses_native_launch(self):
        allocate=self.admission.checkout_client.allocate
        def disconnected(run,operation):
            value=allocate(run,operation)
            self.connected=False
            return value
        self.admission.checkout_client.allocate=disconnected
        with self.assertRaisesRegex(LedgerError,'ADMISSION_REVOKED|FORBIDDEN'):
            self.open()
        self.assertEqual(1,len(self.allocations));self.assertFalse(self.launches+self.reads)
        self.assert_unactivated();self.assertIsNone(self.admission._session)
