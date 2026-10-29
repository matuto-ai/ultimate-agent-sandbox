"""Guardable pure transport/authority checks; no native/process/socket effects."""
from contextlib import contextmanager, nullcontext
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch
from uas import native_host_forge as m
from uas.workstation_admission import AdmissionSeat, AdmittedBinding, _canonical
from uas.kernel_origin import ReceiverIdentity, OriginDenied
from uas.ledger import LedgerError
from uas.workstation_peer import AdmittedPeerDispatcher


class Channel:
    def __init__(self): self.sent=[]; self.closed=False; self.timeout=None
    def send(self, raw): self.sent.append(raw); return len(raw)
    def close(self): self.closed=True
    def settimeout(self, value): self.timeout=value


class DirectForgeTests(unittest.TestCase):
    def make(self):
        obj=object.__new__(m.NativeHostForge);obj.closed=False
        seat=AdmissionSeat('room','instance','seat','actor','profile',('peer-traffic','forge-read','forge-write'),ReceiverIdentity(1000,1000,'hub','d'*64))
        obj.binding=AdmittedBinding(seat,'a'*32,'i'*32,2,'r'*64,'p'*64)
        self.stack=[];self.events=[]
        @contextmanager
        def lock():
            self.stack.append('lifecycle')
            try:yield
            finally:self.stack.pop()
        control=Channel()
        obj.admission=N(controller='c'*32,control=control,hub_origin=N(require=Mock()),_io=nullcontext(),_current=Mock(),control_lost=Mock())
        obj.helper=N(forge_channel=Channel(),operation_id='f'*32,origin=N(require=Mock()))
        obj.client=N(supervisor=N(_locked=lock,_read=lambda:{'phase':'running','instance_id':'instance','spec':{'project_id':'project'}}),closed=False,
            room_instance='instance',binding=N(project_id='project'))
        obj._binding=lambda:obj.binding
        obj.origin=obj._origin(obj.binding)
        def prepare(envelope, origin, *, authorize):
            self.assertEqual(self.stack,['lifecycle']);self.assertEqual(origin,obj.origin)
            obj.client.guard=authorize;self.events.append('prepare');return {'original':envelope}
        def perform(packet):
            self.assertEqual(self.stack,[]);self.events.append('perform')
            with lock():self.assertTrue(obj.client.guard())
            return {'mutation':{'status':'OK'}}
        obj.client.prepare=Mock(side_effect=prepare);obj.client.perform=Mock(side_effect=perform)
        return obj

    def exchange(self,obj,envelope=None,reserve_error=None):
        envelope=envelope or {'id':'write-id','kind':'forge-write','argv':['pr','comment','1','--body','unchanged']}
        record=N(data=json.dumps({'request_id':'1'*32,'envelope':envelope}).encode())
        def reserve(value):
            self.assertEqual(self.stack,[]);self.assertEqual(value,envelope)
            self.events.append('reserve')
            if reserve_error:raise reserve_error
            return hashlib.sha256(_canonical(value)).hexdigest()
        with patch.object(m,'receive',return_value=nullcontext(record)),patch.object(obj,'_reserve',side_effect=reserve):
            return obj.receive_once(),record

    def test_original_kernel_record_and_unlocked_provider(self):
        obj=self.make();result,record=self.exchange(obj)
        self.assertTrue(result['ok']);self.assertEqual(self.events,['reserve','prepare','perform'])
        self.assertGreaterEqual(obj.helper.origin.require.call_count,4)
        self.assertTrue(all(c.args==(record,) for c in obj.helper.origin.require.call_args_list))
        self.assertEqual(obj.client.prepare.call_args.args[0]['id'],'write-id')

    def test_origin_exactly_matches_existing_hub(self):
        obj=self.make();dispatcher=object.__new__(AdmittedPeerDispatcher)
        dispatcher.admissions=N(controller=obj.admission.controller)
        self.assertEqual(obj.origin,dispatcher._origin(obj.binding))

    def test_reservation_failure_never_contacts_broker(self):
        obj=self.make();result,_=self.exchange(obj,reserve_error=LedgerError('FORGE_UNAVAILABLE'))
        self.assertFalse(result['ok']);obj.client.prepare.assert_not_called();obj.client.perform.assert_not_called()

    def test_uncertain_reservation_fences_without_retry(self):
        obj=self.make();channel=obj.helper.forge_channel
        with self.assertRaises(TimeoutError):self.exchange(obj,reserve_error=TimeoutError('unknown'))
        self.assertTrue(obj.closed);self.assertTrue(channel.closed);obj.client.perform.assert_not_called()
        with self.assertRaises(OriginDenied):obj.receive_once()

    def test_wrong_original_sender_rejected_before_reserve(self):
        obj=self.make();obj.helper.origin.require.side_effect=OriginDenied('wrong task')
        with self.assertRaises(OriginDenied):self.exchange(obj)
        self.assertEqual(self.events,[]);obj.client.prepare.assert_not_called()

    def test_changed_epoch_or_controller_rejected(self):
        for change in ('epoch','controller'):
            obj=self.make()
            if change=='epoch':obj._binding=lambda:replace(obj.binding,epoch=3)
            else:obj.admission.controller='e'*32
            with self.assertRaises(OriginDenied):self.exchange(obj)
            obj.client.prepare.assert_not_called()

    def test_revoke_after_reservation_prevents_contact(self):
        for reason in ('root', 'host', 'epoch'):
            obj=self.make()
            envelope={'id':'stable','kind':'forge-read','argv':['pr','view','1']}
            record=N(data=_canonical({'request_id':'1'*32,'envelope':envelope}))
            def reserve(value):
                if reason=='epoch':obj._binding=lambda:replace(obj.binding,epoch=9)
                else:obj.admission._current.side_effect=OriginDenied(reason+' lost')
                return hashlib.sha256(_canonical(value)).hexdigest()
            with patch.object(m,'receive',return_value=nullcontext(record)),patch.object(obj,'_reserve',side_effect=reserve):
                with self.assertRaises(OriginDenied):obj.receive_once()
            obj.client.prepare.assert_not_called();obj.client.perform.assert_not_called()

    def test_preadmit_helper_cannot_construct_binding(self):
        obj=self.make()
        obj.helper.current=Mock()
        obj.helper.state='released';obj.helper._admission=obj.admission
        with self.assertRaises(OriginDenied):m.NativeHostForge._binding(obj)

    def test_late_revoke_blocks_disclosure(self):
        obj=self.make()
        def perform(packet):obj.client.closed=True;return {'mutation':{'status':'OK'}}
        obj.client.perform.side_effect=perform
        result,_=self.exchange(obj)
        self.assertFalse(result['ok']);self.assertEqual(result['error'],'ROOM_NOT_RUNNING')

    def test_lost_reply_fences_channel_without_replay(self):
        obj=self.make();channel=obj.helper.forge_channel;channel.send=lambda raw:0
        with self.assertRaises(OriginDenied):self.exchange(obj)
        obj.client.perform.assert_called_once();self.assertTrue(obj.closed);self.assertTrue(channel.closed)

    def test_nonforge_and_claimed_origin_never_prepare(self):
        for envelope in ({'id':'x','kind':'message'},{'id':'x','kind':'run-create'}):
            obj=self.make();result,_=self.exchange(obj,envelope)
            self.assertFalse(result['ok']);obj.client.prepare.assert_not_called()

    def test_reservation_reply_correlation_and_digest(self):
        for wrong in ('none','digest','actor','exchange'):
            obj=self.make();envelope={'id':'read-id','kind':'forge-read','argv':['pr','view','1']}
            def receive(channel):
                self.assertEqual(self.stack,[])
                packet=json.loads(channel.sent[-1]);self.assertNotIn('origin',packet)
                result={'status':'RESERVED','digest':packet['digest']}
                if wrong=='digest':result['digest']='0'*64
                if wrong=='actor':result['origin']={'actor_id':'forged'}
                reply={k:packet[k] for k in ('version','operation_id','controller','exchange_id')}
                reply.update(kind='REPLY',result=result)
                if wrong=='exchange':reply['exchange_id']='0'*32
                return nullcontext(N(data=_canonical(reply)))
            with patch.object(m,'receive',side_effect=receive):
                if wrong=='none':self.assertEqual(obj._reserve(envelope),hashlib.sha256(_canonical(envelope)).hexdigest())
                else:
                    with self.assertRaises(OriginDenied):obj._reserve(envelope)
                    obj.admission.control_lost.assert_called_once()

    def test_reservation_timeout_fences_shared_controller(self):
        obj=self.make()
        with patch.object(m,'receive',side_effect=TimeoutError('unknown')):
            with self.assertRaises(TimeoutError):obj._reserve({'id':'stable','kind':'forge-read','argv':['pr','view','1']})
        obj.admission.control_lost.assert_called_once()
        self.assertEqual(len(obj.admission.control.sent),1)

    def test_missing_typed_owner_is_not_a_generic_auth_callback(self):
        with self.assertRaises(OriginDenied):m.NativeHostForge(N(),N())

    def test_source_routes_gh_away_from_hub_and_keeps_credential_free_env(self):
        root=Path(__file__).resolve().parents[1]
        server=(root/'runtime/claude/mcp-server.mjs').read_text()
        self.assertIn("['gh','uas_review'].includes(r.params.name) ? forgeChannel : channel",server)
        self.assertIn('seqpacketChannel(4',server)
        connector=(root/'runtime/claude/mcp-connector.c').read_text()
        self.assertIn('close_range(5',connector)
        self.assertIn('char *env[]={"PATH=',connector)
        self.assertNotIn('environ',connector)

class HubReserveTests(unittest.TestCase):
    def test_only_canonical_local_reservation_under_fence(self):
        obj=object.__new__(AdmittedPeerDispatcher);obj.host_forge_binding=object()
        obj.hub=N(ledger=object(),_current=lambda conn:True);obj._connections={'root':object()}
        binding=N(operation_id='root');stack=[]
        @contextmanager
        def authorize(helper,record):
            self.assertEqual((helper,record),('helper',None));stack.append('admission')
            try:yield binding
            finally:stack.pop()
        def check(*args):self.assertEqual(stack,['admission']);return True
        obj.admissions=N(authorize_descendant=authorize,recheck_descendant=check)
        obj._origin=lambda binding:'trusted-origin'
        envelope={'id':'stable','kind':'forge-read','argv':['pr','view','1']};digest=hashlib.sha256(_canonical(envelope)).hexdigest()
        def reserve(ledger,forge,value,origin,guard):
            self.assertEqual(stack,['admission']);self.assertTrue(guard());self.assertEqual(origin,'trusted-origin')
        with patch('uas.forge_read_service.reserve_forge_operation',side_effect=reserve) as r:
            self.assertEqual(obj.reserve_host_forge('root','helper',envelope,digest),{'status':'RESERVED','digest':digest})
            r.assert_called_once()
            with self.assertRaises(LedgerError):obj.reserve_host_forge('other','helper',envelope,digest)
            self.assertEqual(r.call_count,1)

class SecondChannelTests(unittest.TestCase):
    def test_preactivation_queue_eof_or_missing_channel_denied(self):
        from uas.native_helper import NativeDescendantLease
        lease=object.__new__(NativeDescendantLease)
        for value in (b'queued-forge', b''):
            lease.forge_channel=N(recv=lambda *args:value)
            with self.assertRaises(OriginDenied):lease._empty_forge_channel()
        lease.forge_channel=None
        with self.assertRaises(OriginDenied):lease._empty_forge_channel()
        def empty(*args):raise BlockingIOError()
        lease.forge_channel=N(recv=empty)
        lease._empty_forge_channel()

    def test_same_task_only_and_single_binding(self):
        from uas import native_helper as helper
        from uas.kernel_origin import Record
        class Socket(Channel):
            family=helper.socket.AF_UNIX
            def getsockopt(self,*args):return helper.socket.SOCK_SEQPACKET
            def getpeername(self):return '/fixed'
        lease=object.__new__(helper.NativeDescendantLease)
        lease.state='released';lease.forge_channel=None;lease.current=Mock()
        lease.origin=N(require=Mock(side_effect=OriginDenied('different helper')))
        record=Record(helper.FORGE_HELLO,(123,1000,1000),-1)
        channel=Socket()
        with patch.object(helper.socket,'socket',Socket):
            with self.assertRaises(OriginDenied):lease.bind_forge(channel,record)
            self.assertIsNone(lease.forge_channel);self.assertFalse(channel.sent)
            lease.origin.require.side_effect=None
            lease.bind_forge(channel,record)
            self.assertEqual(channel.sent,[helper.FORGE_RELEASE])
            with self.assertRaises(OriginDenied):lease.bind_forge(Socket(),record)

class RealLedgerReserveTests(unittest.TestCase):
    def test_actual_canonical_namespace_exact_replay_and_revoke(self):
        import test_native_helper_owner as owner_fixture
        from uas.forge import ForgeBinding
        fixture=owner_fixture.CombinedSeamTests('test_actual_helper_dispatch_review_ledger_replay_and_revocation')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        admission=fixture.hub
        offer,binding=admission._active['a'*32]
        binding=replace(binding,seat=replace(binding.seat,capabilities=('peer-traffic','forge-read','forge-write')))
        admission._active['a'*32]=(offer,binding)
        dispatcher=fixture.dispatcher
        dispatcher.attach_host_forge_binding(ForgeBinding('room','project','owner/repository'))
        envelope={'id':'canonical-forge','kind':'forge-read','argv':['pr','view','1']}
        digest=hashlib.sha256(_canonical(envelope)).hexdigest()
        first=dispatcher.reserve_host_forge('a'*32,'f'*32,envelope,digest)
        snapshot=dispatcher.hub.ledger.snapshot()
        self.assertEqual(dispatcher.reserve_host_forge('a'*32,'f'*32,envelope,digest),first)
        self.assertEqual(dispatcher.hub.ledger.snapshot(),snapshot)
        changed={**envelope,'argv':['pr','view','2']}
        with self.assertRaises(LedgerError):dispatcher.reserve_host_forge('a'*32,'f'*32,changed,hashlib.sha256(_canonical(changed)).hexdigest())
        offer.origin.revoke()
        with self.assertRaises(OriginDenied):dispatcher.reserve_host_forge('a'*32,'f'*32,envelope,digest)
        self.assertEqual(dispatcher.hub.ledger.snapshot(),snapshot)
