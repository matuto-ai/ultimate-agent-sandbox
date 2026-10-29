"""One held Pi task retirement, controlled effects; never writer quiescence."""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace as N
import os
import select
import tempfile
import threading
import unittest
from unittest.mock import patch
from uas.native_pi_retirement import NativePiRetirement
from uas.native_pi_recipe import NativePiRecipe
from uas.native_host_forge import NativePiHostForge
from uas.workstation_control import SupervisorAdmission
from uas.workstation_exec import ExecLaunch
from uas.docker_exec_api import EngineStream
from uas.kernel_origin import HeldOrigin, OriginDenied
from uas.lifecycle import Supervisor

class Channel:
    def __init__(self,events):self.events=events;self.timeout=2;self.closed=False
    def gettimeout(self):return self.timeout
    def settimeout(self,value):self.timeout=value
    def close(self):self.closed=True;self.events.append('control-close')
    def shutdown(self,how):self.events.append('shutdown')

class NativePiRetirementTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.supervisor=Supervisor(Path(temp.name)/'control','room',object(),authorize=lambda *_:False,revoke=lambda *_:None)
        self.events=[];self.closed=[];self.exited=False
        self.root=object.__new__(ExecLaunch);self.root.native_recipe=object.__new__(NativePiRecipe)
        self.root.origin=object.__new__(HeldOrigin);self.root.origin.pidfd=1001;self.root.origin.identity=(1,1001);self.root.origin.revoked=False
        self.root.transport=object.__new__(EngineStream);self.root.transport.channel=Channel(self.events)
        self.root.admission={'operation_id':'operation','state':'admitted'}
        self.root.revoke=lambda:self.events.append('revoke') or self.root.origin.revoke()
        self.admission=object.__new__(SupervisorAdmission);self.admission.launch=self.root
        self.admission._authority=threading.RLock();self.admission._io=threading.Lock();self.admission._fenced=False
        self.admission.control=Channel(self.events);self.admission._current=lambda:True
        self.admission._save=lambda *a,**k:None;self.admission._send_command=lambda k:self.events.append('send') or 'exchange'
        self.admission._receive=lambda *a,**k:self.events.append('ack') or {'state':'revoked','installed':False}
        self.ingress=object.__new__(NativePiHostForge);self.ingress.admission=self.admission;self.ingress.helper=self.root
        self.ingress.client=N(supervisor=self.supervisor);self.ingress._current=lambda:True;self.admission.forge_service=self.ingress
        self.stack=ExitStack();self.addCleanup(self.stack.close);realclose=os.close
        self.stack.enter_context(patch('uas.native_pi_retirement.os.dup',return_value=2001))
        self.stack.enter_context(patch('uas.native_pi_retirement.os.set_inheritable'))
        self.stack.enter_context(patch('uas.native_pi_retirement.os.close',side_effect=lambda fd:self.closed.append(fd) if fd>=1000 else realclose(fd)))
        self.stack.enter_context(patch('uas.native_pi_retirement._identity',return_value=(1,1001)))
        case=self
        class Poll:
            def register(self,fd,flags):self.fd=fd
            def unregister(self,fd):pass
            def poll(self,timeout):return [(self.fd,select.POLLIN)] if case.exited else []
        self.stack.enter_context(patch('uas.native_pi_retirement.select.poll',Poll))
    def capture(self):
        with self.supervisor._locked() as scope:return NativePiRetirement(self.admission,lifecycle=scope)
    def test_ack_then_shutdown_then_exact_exit_preserves_control(self):
        owner=self.capture();self.exited=True
        self.assertEqual('exited',owner.retire(.2)['state']);self.assertTrue(owner.require_exited(self.admission))
        self.assertEqual(['revoke','send','ack','shutdown'],self.events);self.assertFalse(self.admission.control.closed)
        self.assertEqual(2,self.admission.control.timeout);self.assertFalse(self.closed)
        owner.close();self.assertEqual([2001],self.closed)
    def test_pending_reconciles_without_second_shutdown_or_revoke(self):
        owner=self.capture();self.assertEqual('pending',owner.retire(.2)['state']);events=list(self.events)
        with self.assertRaises(OriginDenied):owner.require_exited()
        self.exited=True;self.assertEqual('exited',owner.retire(.2)['state']);self.assertEqual(events,self.events)
    def test_unknown_revoke_never_upgrades_from_exit(self):
        owner=self.capture();self.admission._receive=lambda *a,**k:(_ for _ in ()).throw(TimeoutError())
        with self.assertRaises(TimeoutError):owner.retire(.2)
        self.exited=True;events=list(self.events);self.assertEqual('unknown',owner.observe()['state']);self.assertEqual(events,self.events)
        self.assertNotIn('shutdown',events);self.assertTrue(self.admission.control.closed)
    def test_contended_authority_fences_and_remains_unknown(self):
        owner=self.capture();calls=[]
        class Busy:
            def acquire(self,*,timeout):calls.append(timeout);return False
            def release(self):raise AssertionError('not acquired')
        self.admission._authority=Busy()
        with self.assertRaises(TimeoutError):owner.retire(.2)
        self.assertTrue(calls);self.assertTrue(self.admission.control.closed);self.assertFalse(owner.revoked)
    def test_partial_capture_closes_duplicate_without_owner_effect(self):
        with patch('uas.native_pi_retirement.os.set_inheritable',side_effect=OSError()):
            with self.assertRaises(OSError):self.capture()
        self.assertEqual([2001],self.closed);self.assertFalse(self.events)
    def test_changed_transport_or_duplicate_identity_denied(self):
        owner=self.capture();self.root.transport=object.__new__(EngineStream)
        with self.assertRaises(OriginDenied):owner.retire(.2)
        self.assertNotIn('shutdown',self.events)
        with patch('uas.native_pi_retirement._identity',return_value=(9,9)):
            with self.assertRaises(OriginDenied):owner.observe()
        self.exited=True
        with self.assertRaises(OriginDenied):owner.observe()
    def test_capture_and_wait_scope_exact_owner(self):
        with self.supervisor._locked() as scope:
            owner=NativePiRetirement(self.admission,lifecycle=scope)
            with self.assertRaises(OriginDenied):owner.retire(.2)
            self.ingress.admission=object()
            with self.assertRaises(OriginDenied):NativePiRetirement(self.admission,lifecycle=scope)
        with self.assertRaises(OriginDenied):owner.require_exited(object())
        owner.close()
        with self.assertRaises(OriginDenied):owner.observe()
    def test_shutdown_failure_attempted_once_not_exit_proof(self):
        owner=self.capture();calls=[]
        def fail(how):calls.append(how);raise OSError('uncertain shutdown')
        self.root.transport.channel.shutdown=fail
        with self.assertRaises(OSError):owner.retire(.2)
        self.assertEqual(1,len(calls));self.assertEqual('pending',owner.observe()['state'])
        self.exited=True;self.assertEqual('exited',owner.observe()['state']);self.assertEqual(1,len(calls))
