"""Private control socketpairs; readiness is explicitly injected, not native proof."""
import array
import json
import os
import socket
import threading
import unittest
from unittest.mock import patch

import test_workstation_admission as admission_fixture
from uas.kernel_origin import HeldOrigin, OriginDenied, enable, receive
from uas.workstation_admission import _canonical
from uas.workstation_control import SupervisorAdmission


class ControlTests(unittest.TestCase):
    setUpClass = classmethod(admission_fixture.AdmissionTests.setUpClass.__func__)

    def setUp(self):
        admission_fixture.AdmissionTests.setUp(self)
        enable(self.sender)
        self.control.send(b'trusted-hub-startup')
        with receive(self.sender) as record:
            self.hub_origin = HeldOrigin(record)
        self.addCleanup(self.hub_origin.close)
        self.launch._native_readiness = {'digest': 'c'*64}  # Control fixture only.
        self.launch._save(first=True)
        self.client = SupervisorAdmission(self.launch, self.seat, self.sender,
            hub_origin=self.hub_origin, controller=self.hub.controller, control_lock=threading.Lock(), timeout=.2)

    def exchange(self, action, *, on_admitted=None):
        failures=[]
        def serve():
            try:self.hub.serve_once(self.control, on_admitted=on_admitted)
            except BaseException as error:failures.append(error)
        thread=threading.Thread(target=serve);thread.start()
        try:return action()
        finally:
            thread.join(2)
            self.assertFalse(thread.is_alive())
            if failures:raise failures[0]

    def test_admit_durable_intent_then_ack_closes_only_supervisor_peer_copy(self):
        send = self.sender.sendmsg
        def checked_send(*args,**kwargs):
            document=json.loads(self.launch.journal.read_text())
            self.assertEqual(document['admission']['state'],'intent')
            self.assertEqual(document['native_readiness']['digest'],'c'*64)
            return send(*args,**kwargs)
        # Socket methods are read-only; proxy retains real kernel transport.
        class Proxy:
            def sendmsg(_, *args, **kwargs):return checked_send(*args, **kwargs)
        with patch('uas.workstation_control.send_admit') as mocked:
            from uas.workstation_admission import send_admit
            mocked.side_effect=lambda control,**kw:send_admit(Proxy(),**kw)
            result=self.exchange(lambda:self.client.admit(self.operation,1))
        self.assertEqual(result['status'],'ADMITTED')
        self.assertEqual(self.launch.admission['state'],'admitted')
        self.assertIsNone(self.launch.channel)
        self.assertTrue(self.hub.status(self.operation)['installed'])
        self.runtime.send(b'queued-for-hub')
        with receive(self.hub.peer_channel(self.operation)) as record:
            with self.hub.authorize(self.operation,record):pass
        status=self.exchange(self.client.status)
        self.assertTrue(status['installed'])

    def test_lost_ack_is_unknown_then_status_reconciles_without_admit_resend(self):
        failures=[]
        def install_without_reply():
            try:self.hub.admit(self.control)
            except BaseException as error:failures.append(error)
        thread=threading.Thread(target=install_without_reply);thread.start()
        with self.assertRaises(TimeoutError):self.client.admit(self.operation,1)
        thread.join(2);self.assertFalse(failures)
        self.assertEqual(self.launch.admission['state'],'unknown')
        with self.assertRaises(OriginDenied):self.client.admit(self.operation,1)
        self.assertTrue(self.exchange(self.client.status)['installed'])
        self.assertEqual(self.launch.admission['state'],'admitted')
        self.assertEqual(self.hub.db.execute('SELECT count(*) FROM admissions').fetchone()[0],1)

    def test_revoke_fences_locally_and_hub_before_ack(self):
        self.exchange(lambda:self.client.admit(self.operation,1))
        result=self.exchange(self.client.revoke)
        self.assertFalse(result['installed'])
        self.assertTrue(self.launch.origin.revoked)
        self.assertEqual(self.launch.admission['state'],'revoked')
        with self.assertRaises(OriginDenied):self.client.status()

    def test_no_native_proof_no_send(self):
        self.launch._native_readiness=None
        with self.assertRaises(OriginDenied):self.client.admit(self.operation,1)
        self.assertIsNone(self.launch.admission)

    def test_presend_journal_failure_fences_without_hub_effect(self):
        with patch.object(self.launch,'_save',side_effect=OSError('durability failed')):
            with self.assertRaises(OSError):self.client.admit(self.operation,1)
        self.assertTrue(self.launch.origin.revoked)
        self.assertEqual(self.hub.status(self.operation)['state'],'absent')

    def test_status_rights_rejected_and_received_fd_closed(self):
        self.sender.sendmsg([_canonical({'version':1,'kind':'STATUS','exchange_id':'e'*32,'operation_id':self.operation,
            'controller':self.hub.controller})],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.origin.pidfd]))])
        before=len(os.listdir('/proc/self/fd'))
        with self.assertRaises(OriginDenied):self.hub.serve_once(self.control)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        self.assertTrue(self.hub._fenced)

    def test_wrong_controller_status_fences(self):
        self.sender.send(_canonical({'version':1,'kind':'STATUS','exchange_id':'e'*32,'operation_id':self.operation,'controller':'f'*32}))
        with self.assertRaises(OriginDenied):self.hub.serve_once(self.control)
        self.assertTrue(self.hub._fenced)

    def test_hub_reply_send_failure_fences_installed_authority(self):
        class BrokenReply:
            def recvmsg(_, *args):return self.control.recvmsg(*args)
            def send(_, data):raise OSError('reply lost')
        from uas.workstation_admission import send_admit
        send_admit(self.sender,launch=self.launch,seat=self.seat,operation_id=self.operation,epoch=1,readiness_digest='c'*64)
        with self.assertRaises(OSError):self.hub.serve_once(BrokenReply())
        self.assertFalse(self.hub.status(self.operation)['installed'])

    def test_admit_hook_attaches_existing_hub_before_ack_without_native_receiver(self):
        from uas.ledger import RoomLedger, LedgerError
        from uas.peer import FixturePeerHub, FixtureParticipant
        from uas.workstation_peer import AdmittedPeerDispatcher
        ledger=RoomLedger(self.launch.journal.parent/'room.db','alpha')
        self.addCleanup(ledger.close)
        hub=FixturePeerHub(ledger)
        hub.configure('configure',(FixtureParticipant('alice','actor-a'),
                                  FixtureParticipant('bob','actor-b')),'run-1')
        dispatcher=AdmittedPeerDispatcher(self.hub,hub)
        results,failures=[],[]
        def request():
            try:results.append(self.client.admit(self.operation,1))
            except BaseException as error:failures.append(error)
        thread=threading.Thread(target=request);thread.start()
        try:
            self.hub.serve_once(self.control,on_admitted=lambda operation:
                dispatcher.attach_current(operation,context_generation=1))
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive());self.assertFalse(failures)
        result=results[0]
        self.assertEqual(result['status'],'ADMITTED')
        connection=dispatcher._connections[self.operation]
        self.assertEqual(connection.incarnation_id,self.launch.incarnation)
        self.assertEqual(ledger.snapshot()['state']['peer_traffic']['connections']['alice']['incarnation_id'],self.launch.incarnation)
        with self.assertRaisesRegex(LedgerError,'SUPERVISOR_DELIVERY_UNAVAILABLE'):
            connection.receiver.accept({})

    def test_local_attachment_failure_fences_before_success_reply(self):
        from uas.workstation_admission import send_admit
        send_admit(self.sender,launch=self.launch,seat=self.seat,operation_id=self.operation,epoch=1,readiness_digest='c'*64)
        def fail(operation):raise OriginDenied('wrong local context')
        with self.assertRaisesRegex(OriginDenied,'wrong local context'):
            self.hub.serve_once(self.control,on_admitted=fail)
        self.assertFalse(self.hub.status(self.operation)['installed'])
        with self.assertRaises(TimeoutError):self.sender.recv(1024)

    def test_late_local_revoke_wins_over_queued_admit_ack(self):
        original=self.client._receive
        def revoke_before_receive(kind, exchange_id):
            with self.client._authority:
                self.client._fenced=True
                self.launch.revoke()
                self.client._save('revoking')
            return original(kind, exchange_id)
        with patch.object(self.client,'_receive',side_effect=revoke_before_receive):
            with self.assertRaises(OriginDenied):
                self.exchange(lambda:self.client.admit(self.operation,1))
        self.assertEqual(self.launch.admission['state'],'revoking')
        self.assertTrue(self.launch.origin.revoked)
        self.assertFalse(self.launch.admission.get('receipt'))

    def test_genuine_wrong_process_reply_never_confirms_admission(self):
        ready,release=os.pipe()
        child=os.fork()
        if child==0:
            os.close(release)
            self.control.send(_canonical({'version':1,'kind':'REPLY','operation_id':self.operation,
                'controller':self.hub.controller,'result':{}}))
            os.read(ready,1);os._exit(0)
        os.close(ready)
        try:
            with self.assertRaises(OriginDenied):self.client.admit(self.operation,1)
            self.assertEqual(self.launch.admission['state'],'unknown')
        finally:
            os.close(release);os.waitpid(child,0)

    def test_malformed_authenticated_receipt_fences_instead_of_confirming(self):
        class BadReceipt:
            def recvmsg(_, *args):return self.control.recvmsg(*args)
            def send(_, data):
                reply=json.loads(data)
                reply['result']['version']=True  # bool must not equal integer 1.
                self.control.send(_canonical(reply))
                return len(data)
        failures=[]
        def serve():
            try:self.hub.serve_once(BadReceipt())
            except BaseException as error:failures.append(error)
        thread=threading.Thread(target=serve);thread.start()
        try:
            with self.assertRaises(OriginDenied):self.client.admit(self.operation,1)
        finally:thread.join(2)
        self.assertFalse(failures)
        self.assertTrue(self.launch.origin.revoked)
        self.assertEqual(self.sender.fileno(),-1)
        # The hosting loop observes EOF and drops every transferred authority.
        with self.assertRaises(OriginDenied):self.hub.serve_once(self.control)
        self.assertFalse(self.hub.status(self.operation)['installed'])

    def test_control_loss_closes_transport_even_when_journal_fails(self):
        with patch.object(self.launch,'_save',side_effect=OSError('journal failed')):
            with self.assertRaises(OSError):self.client.control_lost()
        self.assertTrue(self.launch.origin.revoked)
        self.assertEqual(self.sender.fileno(),-1)

    def test_revocation_journal_failure_still_forces_hub_control_eof(self):
        self.exchange(lambda:self.client.admit(self.operation,1))
        with patch.object(self.launch,'_save',side_effect=OSError('journal failed')):
            with self.assertRaises(OSError):self.client.revoke()
        self.assertTrue(self.launch.origin.revoked)
        with self.assertRaises(OriginDenied):self.hub.serve_once(self.control)
        self.assertFalse(self.hub.status(self.operation)['installed'])

    def delayed_status_reply(self, change):
        self.exchange(lambda:self.client.admit(self.operation,1))
        with self.assertRaises(TimeoutError):self.client.status()
        captured=[]
        class Capture:
            def recvmsg(_, *args):return self.control.recvmsg(*args)
            def send(_, data):captured.append(data);return len(data)
        self.hub.serve_once(Capture())
        old=json.loads(captured[0])
        self.assertTrue(old['result']['installed'])
        change()
        self.control.send(captured[0])
        with self.assertRaisesRegex(OriginDenied,'unmatched private Hub reply'):
            self.client.status()
        self.assertEqual(self.launch.admission['state'],'unknown')
        self.assertTrue(self.launch.origin.revoked)
        self.assertEqual(self.sender.fileno(),-1)
        self.assertEqual(self.hub.db.execute('SELECT count(*) FROM admissions').fetchone()[0],1)
        self.assertFalse(self.hub.status(self.operation)['installed'])

    def test_delayed_previous_status_cannot_satisfy_new_status_after_revoke(self):
        self.delayed_status_reply(lambda:self.hub.revoke(self.operation))

    def test_delayed_previous_status_cannot_satisfy_new_status_after_control_loss(self):
        self.delayed_status_reply(self.hub.control_lost)
