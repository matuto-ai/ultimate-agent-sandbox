"""Installed Library protocol guards plus real anonymous-channel proof when supported."""
import array
import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import threading
import tempfile
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


class HandoffFailureTests(unittest.TestCase):
    def test_rejected_ancillary_closes_all_installed_descriptors_before_refusal(self):
        for mode in ('trunc','ctrunc','unknown-first','malformed-first','partial-rights','extra-rights','wrong-origin','wrong-tag'):
            with self.subTest(mode=mode):
                descriptors=[os.open('/dev/null',os.O_RDONLY) for _ in range(3 if mode=='extra-rights' else 2)]
                rights=descriptors[:-1];pidfd=descriptors[-1]
                ancillary=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',rights).tobytes()+
                            (b'x' if mode=='partial-rights' else b'')),
                           (socket.SOL_SOCKET,transport.SCM_PIDFD,array.array('i',[pidfd]).tobytes()),
                           (socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',1,2,3))]
                if mode=='unknown-first':ancillary.insert(0,(socket.SOL_SOCKET,999,b'unknown'))
                if mode=='malformed-first':ancillary.insert(0,(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,b'short'))
                flags={'trunc':socket.MSG_TRUNC,'ctrunc':socket.MSG_CTRUNC}.get(mode,0)
                channel=Mock();channel.recvmsg.return_value=(b'wrong' if mode=='wrong-tag' else b'LIBRARY-CHANNEL-1',ancillary,flags,None)
                origin=Mock()
                if mode=='wrong-origin':origin.require.side_effect=OriginDenied('wrong origin')
                try:
                    with self.assertRaises(OriginDenied):transport.accept_handoff(channel,origin)
                    for fd in descriptors:
                        with self.assertRaises(OSError):os.fstat(fd)
                    if mode!='wrong-origin':origin.require.assert_not_called()
                finally:
                    for fd in descriptors:
                        try:os.close(fd)
                        except OSError:pass

    def test_negative_pidfd_refusal_closes_only_actually_installed_fds(self):
        fd=os.open('/dev/null',os.O_RDONLY)
        control=Mock();control.recvmsg.return_value=(b'LIBRARY-CHANNEL-1',[
            (socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]).tobytes()),
            (socket.SOL_SOCKET,transport.SCM_PIDFD,array.array('i',[-13]).tobytes()),
            (socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',1,2,3))],0,None)
        with self.assertRaises(OriginDenied):transport.accept_handoff(control,Mock())
        with self.assertRaises(OSError):os.fstat(fd)

    def test_listener_and_wrong_type_are_closed_not_adopted(self):
        for listener,kind in ((True,socket.SOCK_SEQPACKET),(False,socket.SOCK_STREAM)):
            descriptors=[os.open('/dev/null',os.O_RDONLY) for _ in range(2)]
            channel=Mock();channel.recvmsg.return_value=(b'LIBRARY-CHANNEL-1',[
                (socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[descriptors[0]]).tobytes()),
                (socket.SOL_SOCKET,transport.SCM_PIDFD,array.array('i',[descriptors[1]]).tobytes()),
                (socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',1,2,3))],0,None)
            endpoint=Mock(family=socket.AF_UNIX,type=kind);endpoint.getsockopt.return_value=int(listener)
            endpoint.close.side_effect=lambda:os.close(descriptors[0])
            with patch.object(transport.socket,'socket',return_value=endpoint),self.assertRaises(OriginDenied):
                transport.accept_handoff(channel,Mock())
            for fd in descriptors:
                with self.assertRaises(OSError):os.fstat(fd)
            endpoint.getpeername.assert_not_called()

    def test_failed_offer_closes_both_created_endpoints(self):
        left,right=Mock(),Mock()
        with patch.object(transport.socket,'socketpair',return_value=(left,right)),patch.object(transport,'enable'),patch.object(transport,'handoff',side_effect=OriginDenied('refused')):
            with self.assertRaises(OriginDenied):transport.offer_handoff(Mock())
        left.close.assert_called_once();right.close.assert_called_once()


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
        sender,receiver=self.pair()
        left=transport.offer_handoff(sender);self.resources.append(left.close)
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

    def test_actual_report_channel_commits_canonical_ledger_and_rejects_foreign_scope(self):
        from uas.ledger import RoomLedger, LedgerError
        from uas.library_hub import DrainReports
        from uas.kernel_origin import alive
        report={'room_id':'alpha','project_identity':BINDING['project_identity'],
                'drain_id':'drain-1','sequence':1,'phase':'STARTED','attempt':1,
                'outcomes':[],'resulting_sha':None,'reason':None,'due':None}
        # Each refusal owns a fresh channel: a rejected trusted ingress is fatal,
        # not an ACK or a reason to reuse a possibly desynchronized stream.
        for changed in ({}, {'room_id':'beta'}, {'project_identity':'foreign-project'}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root,host=self.pair();supervisor,hub=self.pair()
                server=transport.RootServer(root,self.origin(),lambda:Mock(),BINDING,SEATS,current=lambda:True)
                relay=transport.Relay(supervisor,self.origin(),host,self.origin())
                server.start();relay.start();self.resources.extend([server.close,relay.close])
                peer=self.origin();path=Path(directory)/'room.db'
                result=[]
                with RoomLedger(path,'alpha') as ledger:
                    receiver=DrainReports(ledger,room_id='alpha',project_identity=BINDING['project_identity'],
                                          authenticate=lambda:not peer.revoked and alive(peer.pidfd))
                    client=transport.Client(hub,peer,BINDING,reports=receiver)
                    sender=threading.Thread(target=lambda:result.append(server.report({**report,**changed})))
                    sender.start()
                    # Wait for the atomic report packet, not an arbitrary sleep.
                    self.assertTrue(transport.select.select([server.reports],[],[],1)[0])
                    if changed:
                        with self.assertRaisesRegex(LedgerError,'INVALID_LIBRARY_BINDING'):client.poll()
                    else:
                        client.poll()
                        self.assertEqual([event['payload'] for event in ledger.replay(0,limit=10)], [report])
                    sender.join(1);self.assertFalse(sender.is_alive())
                    self.assertEqual(result,[not bool(changed)])
                # Reopen the actual canonical ledger: ACK means durable metadata,
                # while foreign Room/Project reports produced no ledger event.
                with RoomLedger(path,'alpha') as reopened:
                    events=reopened.replay(0,limit=10)
                    self.assertEqual([event['kind'] for event in events], [] if changed else ['library.drain.reported'])
                    if not changed:self.assertEqual(events[0]['payload'],report)
                self.assertTrue(relay.close());self.assertTrue(server.close())

    def test_reverse_handoff_is_authenticated_to_exact_owned_child(self):
        import multiprocessing
        sender,receiver=self.pair()
        def child():
            endpoint=transport.offer_handoff(sender)
            try:
                endpoint.send(b'child-created')
                endpoint.recv(16)
            finally:endpoint.close()
        process=multiprocessing.get_context('fork').Process(target=child);process.start()
        origin=HeldOrigin(Record(b'',(process.pid,os.getuid(),os.getgid()),os.pidfd_open(process.pid)))
        self.resources.append(origin.close)
        try:
            installed=transport.accept_handoff(receiver,origin);self.resources.append(installed.close)
            self.assertEqual(installed.recv(32),b'child-created')
            installed.send(b'ack');process.join(1)
            self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,0)
        finally:
            if process.is_alive():process.kill();process.join(1)
