"""Authenticated delivery-control socketpairs; no native or container evidence."""
import array
import json
import os
import socket
import threading
import unittest

import test_workstation_admission as fixture
from uas.kernel_origin import OriginDenied, enable, receive
from uas.ledger import LedgerError
from uas.workstation_admission import _canonical, _receive_offer, LIMIT, DELIVERY_REPLY_LIMIT


class DeliveryControlTests(unittest.TestCase):
    setUpClass = classmethod(fixture.AdmissionTests.setUpClass.__func__)
    setUp = fixture.AdmissionTests.setUp

    def command(self, kind='POLL_DELIVERY', **changes):
        value={'version':1,'kind':kind,'operation_id':self.operation,
               'controller':self.hub.controller,'exchange_id':'e'*32}
        if kind=='CONFIRM_DELIVERY':value['receipt']={'delivery_id':'delivery-fixture'}
        return {**value,**changes}

    def decode(self, value):
        self.sender.send(_canonical(value))
        return _receive_offer(self.control,self.supervisor,self.hub.seats,commands=True)

    def test_exact_poll_and_confirmation_decode(self):
        for kind in ('POLL_DELIVERY','CONFIRM_DELIVERY'):
            command=self.command(kind)
            self.assertEqual(self.decode(command),command)

    def test_extra_missing_and_invalid_receipt_shapes_denied(self):
        commands=[self.command(receipt={}), self.command(extra=True),
                  self.command('CONFIRM_DELIVERY',receipt=None),
                  self.command('CONFIRM_DELIVERY',receipt=[]),
                  self.command('CONFIRM_DELIVERY',version=True),
                  self.command('CONFIRM_DELIVERY',exchange_id='bad')]
        missing=self.command('CONFIRM_DELIVERY');del missing['receipt'];commands.append(missing)
        for command in commands:
            with self.subTest(command=command):
                before=len(os.listdir('/proc/self/fd'))
                with self.assertRaises(OriginDenied):self.decode(command)
                self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_receipt_nonfinite_canonical_expansion_and_oversize_denied(self):
        for receipt in ({'value':float('nan')},{'text':'é'*3000},{'text':'x'*DELIVERY_REPLY_LIMIT}):
            command=self.command('CONFIRM_DELIVERY',receipt=receipt)
            self.sender.send(json.dumps(command,ensure_ascii=False).encode())
            before=len(os.listdir('/proc/self/fd'))
            with self.assertRaises(OriginDenied):
                _receive_offer(self.control,self.supervisor,self.hub.seats,commands=True)
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_delivery_commands_never_accept_rights_and_close_every_received_fd(self):
        for kind in ('POLL_DELIVERY','CONFIRM_DELIVERY'):
            self.sender.sendmsg([_canonical(self.command(kind))],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                array.array('i',[self.origin.pidfd,self.peer.fileno(),self.runtime.fileno()]))])
            before=len(os.listdir('/proc/self/fd'))
            with self.assertRaises(OriginDenied):
                _receive_offer(self.control,self.supervisor,self.hub.seats,commands=True)
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
            os.fstat(self.origin.pidfd)  # Sender originals retain their ownership.

    def exchange(self, command, callback=None):
        enable(self.sender)
        self.sender.send(_canonical(command))
        result=self.hub.serve_once(self.control,on_delivery=callback)
        with receive(self.sender) as record:reply=json.loads(record.data)
        self.assertEqual(reply,{'version':1,'kind':'REPLY','operation_id':self.operation,
            'controller':self.hub.controller,'exchange_id':command['exchange_id'],'result':result})
        return result

    def test_callback_runs_after_controller_recheck_outside_admission_lock(self):
        calls=[]
        def callback(operation,kind,receipt=None):
            acquired=threading.Event()
            def other_owner():
                with self.hub._lock:acquired.set()
            thread=threading.Thread(target=other_owner);thread.start()
            thread.join(1)
            self.assertTrue(acquired.is_set(),'callback retained admission lock')
            self.assertFalse(thread.is_alive())
            calls.append((operation,kind,receipt))
            return {'outcome':'HELD'}
        self.assertEqual(self.exchange(self.command(),callback),{'outcome':'HELD'})
        self.assertEqual(calls,[(self.operation,'POLL_DELIVERY',None)])
        command=self.command('CONFIRM_DELIVERY',exchange_id='f'*32)
        self.exchange(command,callback)
        self.assertEqual(calls[-1],(self.operation,'CONFIRM_DELIVERY',command['receipt']))

    def test_ledger_failure_is_correlated_bounded_result_not_control_loss(self):
        def callback(*args,**kwargs):raise LedgerError('UNCONFIRMED_DELIVERY')
        self.assertEqual(self.exchange(self.command('CONFIRM_DELIVERY'),callback),
                         {'error':'UNCONFIRMED_DELIVERY'})
        self.assertFalse(self.hub._fenced)
        self.assertEqual(self.exchange(self.command()),{'error':'DELIVERY_UNAVAILABLE'})
        self.assertFalse(self.hub._fenced)

    def test_unbounded_application_error_is_sanitized_without_control_loss(self):
        def callback(*args,**kwargs):raise LedgerError('x'*LIMIT)
        self.assertEqual(self.exchange(self.command(),callback),{'error':'INVALID_DELIVERY_ERROR'})
        self.assertFalse(self.hub._fenced)

    def test_wrong_controller_never_calls_delivery_and_fences(self):
        calls=[]
        self.sender.send(_canonical(self.command(controller='f'*32)))
        with self.assertRaises(OriginDenied):
            self.hub.serve_once(self.control,on_delivery=lambda *a,**kw:calls.append(a))
        self.assertEqual(calls,[]);self.assertTrue(self.hub._fenced)

    def test_callback_authority_error_fences_rather_than_application_result(self):
        def callback(*args,**kwargs):raise OriginDenied('late revoke')
        self.sender.send(_canonical(self.command()))
        with self.assertRaises(OriginDenied):self.hub.serve_once(self.control,on_delivery=callback)
        self.assertTrue(self.hub._fenced)

    def test_oversized_callback_reply_is_never_sent(self):
        self.sender.send(_canonical(self.command()))
        with self.assertRaises(OriginDenied):
            self.hub.serve_once(self.control,on_delivery=lambda *a,**kw:{'text':'x'*DELIVERY_REPLY_LIMIT})
        self.assertTrue(self.hub._fenced)


if __name__=='__main__':unittest.main()
