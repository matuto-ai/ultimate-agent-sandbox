"""Supervisor delivery socketpairs with synthetic receiver, NOT native proof."""
from copy import deepcopy
import json
import select
import threading
import unittest

import test_workstation_control as fixture
from uas.kernel_origin import OriginDenied
from uas.ledger import LedgerError
from uas.peer import Readiness, digest, MAX_TEXT_BYTES


class SyntheticReceiver:
    def __init__(self, scope):
        self.scope=scope
        self.readiness=Readiness.SAFE
        self.accepted=[]
        self.before_accept=None

    def observe(self):return self.readiness

    def accept(self,envelope):
        if self.before_accept is not None:self.before_accept()
        self.accepted.append(deepcopy(envelope))
        return {'delivery_id':envelope['delivery_id'],'digest':digest(envelope),
                'participant_id':envelope['participant_id'],'incarnation_id':envelope['incarnation_id'],
                'context_generation':envelope['context_generation']}


class DeliveryClientTests(unittest.TestCase):
    setUpClass=classmethod(fixture.ControlTests.setUpClass.__func__)

    def setUp(self):
        fixture.ControlTests.setUp(self)
        fixture.ControlTests.exchange(self,lambda:self.client.admit(self.operation,1))
        self.native=SyntheticReceiver({'room_id':'alpha','participant_id':'alice',
            'run_id':'native-run','generation':1,'context_generation':1})
        self.launch.native_receiver=self.native
        self.envelope={**self.native.scope,'incarnation_id':self.launch.incarnation,
                       'id':'message-1','kind':'peer.message','delivery_id':'delivery-1','text':'native acceptance fixture'}
        self.calls=[]
        self.confirmed=[]

    def delivery(self,operation,kind,receipt=None):
        self.calls.append((operation,kind,deepcopy(receipt)))
        if kind=='POLL_DELIVERY':return {'status':'OFFER','envelope':deepcopy(self.envelope)}
        self.confirmed.append(deepcopy(receipt))
        return {'status':'CONFIRMED','receipt':{'room_id':'alpha',
            'operation_id':self.envelope['delivery_id']+':confirm','first_seq':7,'last_seq':7,'result':receipt}}

    def serve(self,action,*,packets=2,callback=None,send=None):
        failures=[]
        owner=self
        class Channel:
            def recvmsg(_, *args):return owner.control.recvmsg(*args)
            def send(_, data):return owner.control.send(data) if send is None else send(data)
        def worker():
            try:
                for _ in range(packets):
                    self.hub.serve_once(Channel(),on_delivery=callback or self.delivery)
            except BaseException as error:failures.append(error)
        thread=threading.Thread(target=worker);thread.start()
        try:return action()
        finally:
            thread.join(2)
            self.assertFalse(thread.is_alive())
            if failures:raise failures[0]

    def test_native_acceptance_holds_neither_authority_nor_shared_room_io_lock(self):
        def acceptance():
            checked=[]
            def other_owner():
                for lock in (self.client._authority,self.client._io):
                    acquired=lock.acquire(timeout=.1)
                    checked.append(acquired)
                    if acquired:lock.release()
            thread=threading.Thread(target=other_owner);thread.start();thread.join(1)
            self.assertFalse(thread.is_alive());self.assertEqual(checked,[True,True])
        self.native.before_accept=acceptance
        result=self.serve(self.client.deliver_one)
        self.assertEqual(result['status'],'CONFIRMED')
        self.assertEqual(len(self.native.accepted),1)
        self.assertIsNone(self.client._delivery_pending)
        self.assertEqual([call[1] for call in self.calls],['POLL_DELIVERY','CONFIRM_DELIVERY'])

    def test_busy_ambiguous_and_lost_readiness_never_poll_hub(self):
        for readiness in (Readiness.BUSY,Readiness.AMBIGUOUS,Readiness.LOST):
            self.native.readiness=readiness
            self.assertEqual(self.client.deliver_one(),{'status':'HELD'})
            self.assertFalse(select.select([self.control],[],[],0)[0])
        self.assertEqual(self.native.accepted,[])

    def test_hub_held_reply_has_no_native_effect(self):
        self.assertEqual(self.serve(self.client.deliver_one,packets=1,
            callback=lambda *a,**kw:{'status':'HELD'}),{'status':'HELD'})
        self.assertEqual(self.native.accepted,[])

    def test_scope_mismatch_fences_before_native_acceptance(self):
        self.envelope['run_id']='wrong-run'
        with self.assertRaises(OriginDenied):self.serve(self.client.deliver_one,packets=1)
        self.assertEqual(self.native.accepted,[])
        self.assertTrue(self.client._fenced)
        self.assertTrue(self.launch.origin.revoked)

    def test_lost_confirm_ack_retains_native_receipt_and_never_reaccepts(self):
        def drop_confirm(data):
            reply=json.loads(data)
            if reply['result'].get('status')=='CONFIRMED':return len(data)
            return self.control.send(data)
        with self.assertRaises(TimeoutError):self.serve(self.client.deliver_one,send=drop_confirm)
        pending=deepcopy(self.client._delivery_pending)
        self.assertIsNotNone(pending['receipt'])
        self.assertEqual(len(self.native.accepted),1)
        self.assertFalse(self.client._fenced)
        result=self.serve(self.client.deliver_one,packets=1)
        self.assertEqual(result['status'],'CONFIRMED')
        self.assertEqual(len(self.native.accepted),1)
        self.assertEqual(self.confirmed,[pending['receipt'],pending['receipt']])
        self.assertEqual([call[1] for call in self.calls],
                         ['POLL_DELIVERY','CONFIRM_DELIVERY','CONFIRM_DELIVERY'])
        self.assertIsNone(self.client._delivery_pending)

    def test_stale_exchange_reply_fences_without_native_acceptance(self):
        def stale(data):
            reply=json.loads(data);reply['exchange_id']='f'*32
            changed=json.dumps(reply).encode()
            self.control.send(changed)
            return len(data)
        with self.assertRaises(OriginDenied):
            self.serve(self.client.deliver_one,packets=1,send=stale)
        self.assertEqual(self.native.accepted,[])
        self.assertTrue(self.client._fenced)

    def test_late_revoke_after_native_acceptance_prevents_confirmation_send(self):
        self.native.before_accept=self.launch.origin.revoke
        with self.assertRaises(OriginDenied):self.serve(self.client.deliver_one,packets=1)
        self.assertEqual(len(self.native.accepted),1)
        self.assertEqual([call[1] for call in self.calls],['POLL_DELIVERY'])
        self.assertTrue(self.client._fenced)
        self.assertEqual(self.control.recv(8192),b'')  # EOF, not a late confirmation.

    def test_mismatched_ledger_receipt_fences(self):
        def callback(operation,kind,receipt=None):
            result=self.delivery(operation,kind,receipt)
            if kind=='CONFIRM_DELIVERY':result['receipt']['result']={**receipt,'digest':'forged'}
            return result
        with self.assertRaises(OriginDenied):self.serve(self.client.deliver_one,callback=callback)
        self.assertTrue(self.client._fenced)
        self.assertEqual(len(self.native.accepted),1)

    def test_valid_ledger_sequence_above_generation_bound_is_accepted(self):
        def callback(operation,kind,receipt=None):
            result=self.delivery(operation,kind,receipt)
            if kind=='CONFIRM_DELIVERY':
                result['receipt'].update(first_seq=2**53,last_seq=2**53)
            return result
        result=self.serve(self.client.deliver_one,callback=callback)
        self.assertEqual(result['status'],'CONFIRMED')
        self.assertFalse(self.client._fenced)

    def test_hub_ledger_refusal_is_not_a_new_acceptance_or_control_loss(self):
        def refused(operation,kind,receipt=None):
            if kind=='CONFIRM_DELIVERY':raise LedgerError('FORBIDDEN')
            return self.delivery(operation,kind,receipt)
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
            self.serve(self.client.deliver_one,callback=refused)
        self.assertFalse(self.client._fenced)
        self.assertIsNotNone(self.client._delivery_pending['receipt'])
        self.assertEqual(len(self.native.accepted),1)

    def test_maximum_ascii_and_multibyte_offer_reaches_native_receiver_then_later_offer(self):
        for index,text in enumerate(('a'*MAX_TEXT_BYTES,'é'*(MAX_TEXT_BYTES//2),
                                     '😀'*(MAX_TEXT_BYTES//4),'later message')):
            self.envelope.update(id='message-'+str(index),delivery_id='delivery-'+str(index),text=text)
            result=self.serve(self.client.deliver_one)
            self.assertEqual(result['status'],'CONFIRMED')
            self.assertEqual(self.native.accepted[-1]['text'],text)
            self.assertEqual(self.confirmed[-1]['digest'],digest(self.envelope))
        self.assertEqual(len(self.native.accepted),4)


if __name__=='__main__':unittest.main()
