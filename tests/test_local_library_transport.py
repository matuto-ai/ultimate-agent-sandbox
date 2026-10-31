"""Installed Library protocol guards plus real anonymous-channel proof when supported."""
import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas import library
from uas import local_library_transport as transport
from uas.kernel_origin import HeldOrigin, Record, OriginDenied, probe, enable
from uas.ledger import Origin

PROJECT={'id':'project','repository':'owner/project','roots':{'reference':'/owned/reference'}}
BINDING=library.project_binding(PROJECT,source_identity='source')
CAP=library.ENQUEUE_CAPABILITY
AUTHORITY={'participant_id':'participant','actor_id':'actor','authority_version':'seat-epoch',
           'capabilities':[CAP]}
SEATS={'participant':{'actor_id':'actor','profile_id':'profile','capabilities':[CAP]}}
RESULT=library.CaptureResult('REJECTED','request','EMPTY_BODY',False)


def scope():
    return library.participant_scope(Origin('actor','participant','incarnation','seat-epoch',(CAP,)),binding=BINDING)


class Wire:
    def __init__(self):self.packets=[];self.timeout=5
    def gettimeout(self):return self.timeout
    def settimeout(self,value):self.timeout=value
    def send(self,value):self.packets.append(value);return len(value)


class TransportGuards(unittest.TestCase):
    def decode(self,wire):
        peer=Mock(pidfd=1,revoked=False)
        def receive(_):return Record(wire.packets.pop(0),(1,1,1),-1)
        with patch.object(transport,'alive',return_value=True),patch.object(transport.select,'select',return_value=([wire],[],[])),patch.object(transport,'receive',side_effect=receive):
            result=transport.read(wire,peer)
        return result,peer

    def test_large_payload_frames_reassemble_authenticating_every_record(self):
        value={'body':'private-marker '*20000}
        wire=Wire();transport.send(wire,value);count=len(wire.packets)
        self.assertGreater(count,1);self.assertTrue(all(len(p)<65536 for p in wire.packets))
        result,peer=self.decode(wire)
        self.assertEqual(result,value);self.assertEqual(peer.require.call_count,count)
        self.assertEqual(wire.timeout,5)

    def test_framing_rejects_reorder_digest_size_and_duplicate_fields(self):
        for mutation in ('index','digest','size','extra'):
            with self.subTest(mutation=mutation):
                wire=Wire();transport.send(wire,{'body':'x'*100000})
                frame=json.loads(wire.packets[0])
                if mutation=='extra':frame['foreign']=True
                elif mutation=='digest':frame['digest']='0'*64
                elif mutation=='size':frame['size']=transport.MAX_MESSAGE+1
                else:frame['index']=1
                wire.packets[0]=json.dumps(frame).encode()
                with self.assertRaises(OriginDenied):self.decode(wire)

    def test_bound_refuses_before_sending(self):
        wire=Wire()
        with self.assertRaises(OriginDenied):transport.send(wire,{'body':'x'*transport.MAX_MESSAGE})
        self.assertEqual(wire.packets,[])

    def server(self):
        server=transport.RootServer.__new__(transport.RootServer)
        server.seats=SEATS;server.binding=BINDING
        return server

    def test_scope_constructed_from_fixed_seat_and_project_not_caller_binding(self):
        result=self.server()._scope(AUTHORITY)
        self.assertEqual(result.canonical(),scope().canonical())
        for field,value in [('actor_id','other'),('participant_id','other'),('capabilities',[CAP,'ungranted'])]:
            with self.subTest(field=field),self.assertRaises((OriginDenied,library.LibraryError)):
                self.server()._scope({**AUTHORITY,field:value})
        with self.assertRaises(OriginDenied):self.server()._scope({**AUTHORITY,'project_id':'other'})

    def test_capture_challenges_and_checks_after_result(self):
        channel=Mock();peer=Mock();current=Mock(return_value=True)
        client=transport.Client(channel,peer,BINDING)
        responses=[{'kind':'polled'},{'kind':'current','sequence':1},
                   {'kind':'result','sequence':1,'result':asdict(RESULT)}]
        with patch.object(transport,'read',side_effect=responses),patch.object(transport,'send') as send:
            self.assertEqual(client(scope=scope(),current=current,operation_id='op',request_id='request',value={},at='2026-10-31T00:00:00Z',run_id=None),RESULT)
        self.assertEqual(current.call_count,3)
        self.assertIn({'kind':'current','sequence':1,'active':True},[call.args[1] for call in send.call_args_list])

    def test_control_revocation_prevents_capture(self):
        client=transport.Client(Mock(),Mock(),BINDING,control_current=lambda:False)
        with patch.object(transport,'read',return_value={'kind':'polled'}),patch.object(transport,'send') as send:
            with self.assertRaises(OriginDenied):
                client(scope=scope(),current=lambda:True,operation_id='op',request_id='request',value={},at='2026-10-31T00:00:00Z',run_id=None)
        self.assertEqual(len(send.call_args_list),1) # poll only, no capture

    def test_no_report_ack_for_stale_receipt(self):
        server=self.server();server.report_worker=Mock();server.report_worker.send.side_effect=lambda raw:len(raw)
        server.report_worker.recv.return_value=b'recorded:old-request'
        with patch.object(transport.select,'select',return_value=([server.report_worker],[],[])),patch.object(transport.time,'monotonic',side_effect=[0,.01,.02,.2]):
            self.assertFalse(server.report({'room_id':'alpha'}))

    def test_uncertain_close_never_becomes_success_by_repetition(self):
        server=self.server();server.closed=threading.Event();server.channel=Mock()
        server.peer=Mock();server.reports=Mock();server.report_worker=Mock()
        server.thread=Mock(ident=123);server.thread.is_alive.return_value=True
        self.assertFalse(server.close());self.assertFalse(server.close())
        server.peer.close.assert_not_called()
        server.thread.is_alive.return_value=False
        self.assertTrue(server.close());server.peer.close.assert_called_once()

    def test_poll_checks_report_commit_before_ack(self):
        reports=Mock();reports.receive.return_value=True
        client=transport.Client(Mock(),Mock(),BINDING,reports=reports)
        with patch.object(transport,'read',side_effect=[{'kind':'report','report':{'room_id':'alpha'}},{'kind':'polled'}]),patch.object(transport,'send') as send:
            client.poll()
        reports.receive.assert_called_once_with({'room_id':'alpha'})
        self.assertIn({'kind':'report-result','accepted':True},[call.args[1] for call in send.call_args_list])


class NativeLibraryChannelTests(unittest.TestCase):
    def setUp(self):
        try:probe()
        except (OSError,RuntimeError) as error:self.skipTest('kernel channel unavailable: '+type(error).__name__)
        self.resources=[]

    def tearDown(self):
        for close in reversed(self.resources):close()

    def pair(self):
        pair=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        for channel in pair:enable(channel);channel.settimeout(5);self.resources.append(channel.close)
        return pair

    def origin(self):
        peer=HeldOrigin(Record(b'',(os.getpid(),os.getuid(),os.getgid()),os.pidfd_open(os.getpid())))
        self.resources.append(peer.close);return peer

    def test_actual_channel_large_capture_and_fresh_authority(self):
        root,host=self.pair();supervisor,hub=self.pair()
        endpoint=Mock();endpoint.contact.side_effect=lambda **kw: (self.assertTrue(kw['current']()),RESULT)[1]
        server=transport.RootServer(root,self.origin(),lambda:endpoint,BINDING,SEATS,current=lambda:True)
        relay=transport.Relay(supervisor,self.origin(),host,self.origin())
        server.start();relay.start();self.resources.extend([server.close,relay.close])
        client=transport.Client(hub,self.origin(),BINDING)
        result=client(scope=scope(),current=lambda:True,operation_id='op',request_id='request',value={'body':'x'*200000},at='2026-10-31T00:00:00Z',run_id=None)
        self.assertEqual(result,RESULT)
        self.assertEqual(len(endpoint.contact.call_args.kwargs['value']['body']),200000)
        self.assertIsNone(server.failure);self.assertIsNone(relay.failure)

    def test_kernel_rejects_another_sender_even_on_inherited_channel(self):
        import multiprocessing
        sender,receiver=self.pair();expected=self.origin()
        process=multiprocessing.get_context('fork').Process(target=lambda:transport.send(sender,{'forged':'sender'}))
        process.start()
        try:
            with self.assertRaises(OriginDenied):transport.read(receiver,expected)
        finally:
            process.join(1)
            if process.is_alive():process.kill();process.join(1)

    def test_actual_bootstrap_descriptor_authenticated_and_connected(self):
        sender,receiver=self.pair();left,right=self.pair()
        transport.handoff(sender,right)
        installed=transport.accept_handoff(receiver,self.origin());self.resources.append(installed.close)
        left.send(b'proof')
        from uas.kernel_origin import receive
        with receive(installed) as record:self.assertEqual(record.data,b'proof')

    def test_killed_report_sender_cannot_poison_later_report(self):
        import multiprocessing
        root,host=self.pair();supervisor,hub=self.pair()
        server=transport.RootServer(root,self.origin(),lambda:Mock(),BINDING,SEATS,current=lambda:True)
        relay=transport.Relay(supervisor,self.origin(),host,self.origin())
        server.start();relay.start();self.resources.extend([server.close,relay.close])
        reports=Mock();reports.receive.return_value=True
        client=transport.Client(hub,self.origin(),BINDING,reports=reports)
        context=multiprocessing.get_context('fork')
        first=context.Process(target=lambda:server.report({'room_id':'alpha','sequence':1}))
        first.start();time.sleep(.02);first.kill();first.join(1)
        client.poll() # Delayed receipt from killed sender must not ACK another report.
        result=[]
        second=threading.Thread(target=lambda:result.append(server.report({'room_id':'alpha','sequence':2})))
        second.start()
        for _ in range(5):
            client.poll()
            if not second.is_alive():break
            time.sleep(.01)
        second.join(1)
        self.assertEqual(result,[True]);self.assertEqual(reports.receive.call_count,2)
