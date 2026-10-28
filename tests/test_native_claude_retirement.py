"""Finite retirement/lock/receipt tests; OS task/socket boundaries controlled."""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace as N
import os
import select
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from uas.claude_native_admission import NativeClaudeRoot, NativeClaudeHostLaunch, NativeClaudeSupervisorAdmission
from uas.docker_exec_api import EngineStream
from uas.kernel_origin import HeldOrigin, OriginDenied
from uas.lifecycle import Supervisor
from uas.native_helper import NativeDescendantLease
from uas.native_claude_retirement import NativeClaudeRetirement
from uas.workstation_control import _deadline_lock


class Channel:
    def __init__(self,events,name):self.events=events;self.name=name;self.timeout=2;self.closed=False
    def send(self,data):self.events.append(self.name+'-send');return len(data)
    def gettimeout(self):return self.timeout
    def settimeout(self,value):self.timeout=value
    def close(self):self.closed=True;self.events.append(self.name+'-close')
    def shutdown(self,how):self.events.append(self.name+'-shutdown')


class NativeClaudeRetirementTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.supervisor=Supervisor(Path(temp.name)/'control','room',object(),authorize=lambda *_:False,revoke=lambda *_:None)
        self.events=[];self.closed=[];self.exited=set();self.poll_calls=[]
        self.root=object.__new__(NativeClaudeRoot);self.host=object.__new__(NativeClaudeHostLaunch)
        def origin(fd):
            obj=object.__new__(HeldOrigin);obj.pidfd=fd;obj.identity=(1,fd);obj.revoked=False;return obj
        self.root.origin=origin(1002);self.root.host_origin=origin(1001)
        self.host.origin=self.root.host_origin;self.root.host_launch=self.host
        self.host.transport=object.__new__(EngineStream);self.host.transport.channel=Channel(self.events,'transport')
        self.root.state='active';self.root.current=lambda:True
        self.root.admission={'operation_id':'operation','state':'admitted'}
        def root_revoke():self.events.append('root-revoke');self.root.origin.revoke();self.root.state='revoked'
        self.root.revoke=root_revoke
        self.admission=object.__new__(NativeClaudeSupervisorAdmission)
        self.admission.launch=self.root;self.admission._authority=threading.RLock();self.admission._io=threading.Lock()
        self.admission.controller='c'*32;self.admission.control=Channel(self.events,'control');self.admission._fenced=False;self.admission._current=lambda:True
        self.admission._save=lambda *args,**kw:None
        self.admission._send_command=lambda kind:self.events.append('root-send') or 'exchange'
        self.admission._receive=lambda *args,**kw:self.events.append('root-ack') or {'state':'revoked','installed':False,'receipt':{}}
        self.root.native_admission=self.admission
        self.helper=object.__new__(NativeDescendantLease)
        self.helper.root=self.root;self.helper.origin=origin(1003);self.helper.current=lambda:True
        self.helper.state='admitted';self.helper._admission=self.admission;self.helper.operation_id='helper'
        self.helper._ready=lambda admission:True;self.helper._lineage=self.helper._authority=None
        self.helper.channel=self.helper.forge_channel=None
        def helper_ack(*args,**kw):self.events.append('helper-ack');return {'state':'revoked','helper_digest':'digest'}
        self.helper._receive=helper_ack
        self.root.helper_lease=self.helper
        self.root.forge_service=N(client=N(supervisor=self.supervisor))
        self.effects=ExitStack();self.addCleanup(self.effects.close)
        real_close=os.close
        self.effects.enter_context(patch('uas.native_claude_retirement.os.dup',side_effect=lambda fd:fd+1000))
        self.effects.enter_context(patch('uas.native_claude_retirement.os.set_inheritable'))
        self.effects.enter_context(patch('uas.native_claude_retirement.os.close',side_effect=lambda fd:self.closed.append(fd) if fd>=1000 else real_close(fd)))
        self.effects.enter_context(patch('uas.native_claude_retirement._identity',side_effect=lambda fd:(1,fd-1000)))
        outer=self
        class Poll:
            def __init__(self):self.fds=set()
            def register(self,fd,flags):self.fds.add(fd)
            def unregister(self,fd):self.fds.remove(fd)
            def poll(self,timeout):outer.poll_calls.append(timeout);return [(fd,select.POLLIN) for fd in self.fds & outer.exited]
        self.effects.enter_context(patch('uas.native_claude_retirement.select.poll',Poll))
    def capture(self):
        with self.supervisor._locked() as scope:return NativeClaudeRetirement(self.root,lifecycle=scope)
    def test_confirmed_helper_before_root_preserves_shared_controller(self):
        retirement=self.capture();self.exited={2001,2002,2003}
        result=retirement.retire(.5)
        self.assertEqual('exited',result['state']);self.assertTrue(retirement.require_exited(self.root))
        self.assertLess(self.events.index('helper-ack'),self.events.index('root-revoke'))
        self.assertLess(self.events.index('root-ack'),self.events.index('transport-shutdown'))
        self.assertFalse(self.admission.control.closed);self.assertIsNone(self.helper._admission)
        self.assertEqual(2,self.admission.control.timeout)
        self.assertNotIn(2001,self.closed);retirement.close();self.assertTrue({2001,2002,2003}<=set(self.closed))
    def test_one_live_task_preserves_custody_then_late_exit_without_resend(self):
        retirement=self.capture();self.exited={2001,2002}
        self.assertEqual('pending',retirement.retire(.5)['state']);before=list(self.events)
        with self.assertRaises(OriginDenied):retirement.require_exited()
        self.exited.add(2003);self.assertEqual('exited',retirement.retire(.1)['state'])
        self.assertEqual(before,self.events);self.assertFalse({2001,2002,2003}&set(self.closed))
    def test_unknown_helper_revoke_never_becomes_success_from_late_exits(self):
        retirement=self.capture()
        self.helper._receive=lambda *args,**kw:(_ for _ in ()).throw(TimeoutError('unknown'))
        with self.assertRaises(TimeoutError):retirement.retire(.5)
        self.assertTrue(self.admission.control.closed);before=list(self.events);self.exited={2001,2002,2003}
        self.assertEqual('unknown',retirement.observe(.1)['state']);self.assertEqual(before,self.events)
        with self.assertRaises(OriginDenied):retirement.require_exited()
        self.assertNotIn('transport-shutdown',self.events)
    def test_unknown_root_revoke_never_becomes_success(self):
        retirement=self.capture();self.admission._receive=lambda *args,**kw:(_ for _ in ()).throw(TimeoutError())
        with self.assertRaises(TimeoutError):retirement.retire(.5)
        self.exited={2001,2002,2003};self.assertEqual('unknown',retirement.observe()['state'])
        self.assertFalse(retirement.revoked);self.assertNotIn('transport-shutdown',self.events)
    def test_partial_duplicate_failure_closes_only_captured_fds(self):
        with patch('uas.native_claude_retirement.os.dup',side_effect=[2001,OSError('dup')]):
            with self.assertRaises(OSError):self.capture()
        self.assertEqual([2001],self.closed);self.assertFalse(self.events)
    def test_wrong_root_or_scope_cannot_capture_and_closed_proof_cannot_reuse(self):
        with self.supervisor._locked() as scope:
            self.helper.root=object()
            with self.assertRaises(OriginDenied):NativeClaudeRetirement(self.root,lifecycle=scope)
        self.helper.root=self.root
        with self.assertRaises(Exception):NativeClaudeRetirement(self.root,lifecycle=scope)
        retirement=self.capture();self.exited={2001,2002,2003};retirement.retire(.5)
        with self.assertRaises(OriginDenied):retirement.require_exited(object())
        retirement.close()
        with self.assertRaises(OriginDenied):retirement.require_exited()
    def test_retire_under_lifecycle_refuses_before_any_revocation(self):
        retirement=self.capture()
        with self.supervisor._locked():
            with self.assertRaisesRegex(OriginDenied,'released lifecycle'):retirement.retire(.5)
        self.assertFalse(self.events)
    def test_invalid_or_replaced_fd_never_counts_as_exit(self):
        retirement=self.capture()
        with patch('uas.native_claude_retirement._identity',return_value=(9,9)):
            with self.assertRaises(OriginDenied):retirement.observe()
        with self.assertRaises(OriginDenied):retirement.require_exited()
    def test_contended_io_or_authority_lock_uses_remaining_timeout_and_fences(self):
        for attribute in ('_io','_authority'):
            with self.subTest(attribute=attribute):
                case=NativeClaudeRetirementTests();case.setUp();self.addCleanup(case.doCleanups)
                retirement=case.capture();calls=[]
                class Busy:
                    def acquire(self,*,timeout):calls.append(timeout);return False
                    def release(self):raise AssertionError('not acquired')
                setattr(case.admission,attribute,Busy())
                with self.assertRaises(TimeoutError):retirement.retire(.5)
                self.assertTrue(calls);self.assertTrue(all(0<x<=.5 for x in calls))
                self.assertTrue(case.admission.control.closed);self.assertFalse(retirement.revoked)
    def test_deadline_lock_never_calls_unbounded_acquire(self):
        calls=[]
        class Lock:
            def acquire(self,*,timeout):calls.append(timeout);return True
            def release(self):calls.append('release')
        with _deadline_lock(Lock(),time.monotonic()+.2):pass
        self.assertEqual('release',calls[-1]);self.assertTrue(0<calls[0]<=.2)

    def test_receive_authority_contention_fences_without_waiting_again(self):
        import json
        from contextlib import contextmanager
        from uas.workstation_control import SupervisorAdmission
        self.admission.hub_origin=N(require=lambda record:None)
        class Busy:
            def acquire(self,*,timeout):return False
            def release(self):raise AssertionError('unacquired')
        self.admission._authority=Busy()
        @contextmanager
        def root_reply(channel):
            yield N(data=json.dumps({'version':1,'kind':'REPLY','operation_id':'operation',
                'controller':self.admission.controller,'exchange_id':'exchange',
                'result':{'receipt':None,'installed':False,'state':'revoked'}}).encode())
        with patch('uas.workstation_control.receive',root_reply):
            with self.assertRaises(TimeoutError):
                SupervisorAdmission._receive(self.admission,'REVOKE','exchange',deadline=time.monotonic()+.2)
        self.assertTrue(self.admission.control.closed);self.assertTrue(self.admission._fenced)

    def test_helper_receive_authority_contention_cleanup_is_bounded(self):
        import json
        from contextlib import contextmanager
        self.admission.hub_origin=N(require=lambda record:None);self.helper._digest='digest'
        class Busy:
            def acquire(self,*,timeout):return False
            def release(self):raise AssertionError('unacquired')
        self.admission._authority=Busy()
        @contextmanager
        def reply(channel):
            yield N(data=json.dumps({'version':1,'kind':'REPLY','operation_id':'helper',
                'controller':self.admission.controller,'exchange_id':'exchange',
                'result':{'state':'revoked','helper_digest':'digest'}}).encode())
        with patch('uas.native_helper.receive',reply):
            with self.assertRaises(TimeoutError):
                NativeDescendantLease._receive(self.helper,'exchange',revoking=True,deadline=time.monotonic()+.2)
        # A direct status timeout remains unknown; revoke owns the final fence.
        self.assertEqual('unknown',self.helper.state)
        with self.assertRaises(TimeoutError):self.helper.close(deadline=time.monotonic()+.2)
        self.assertTrue(self.admission.control.closed)

    def test_invalid_timeout_has_no_retirement_effect(self):
        retirement=self.capture()
        for timeout in (True,-1,31,float('inf'),float('nan'),0):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):retirement.retire(timeout)
        self.assertFalse(retirement.started);self.assertFalse(self.events)

    def test_confirmed_helper_ack_after_helper_exit_preserves_controller(self):
        import json
        from contextlib import contextmanager
        self.admission.hub_origin=N(require=lambda record:None)
        self.root.incarnation='incarnation';self.root.recipe=N(manifest_digest='manifest')
        self.root._native_readiness_json='{}'
        self.root.admission.update(controller=self.admission.controller,epoch=1)
        self.helper._root_identity=self.root.origin.identity
        self.helper._root_incarnation=self.root.incarnation
        self.helper._manifest_digest='manifest';self.helper._digest='digest'
        self.helper._document={'helper_identity':list(self.helper.origin.identity),
            'controller':self.admission.controller,'root_operation':'operation','root_epoch':1}
        del self.helper._ready;del self.helper._receive
        self.helper.current=lambda:(_ for _ in ()).throw(OriginDenied('helper exited'))
        self.helper.state='revoking'
        @contextmanager
        def reply(channel):
            yield N(data=json.dumps({'version':1,'kind':'REPLY','operation_id':'helper',
                'controller':self.admission.controller,'exchange_id':'exchange',
                'result':{'state':'revoked','helper_digest':'digest'}}).encode())
        with patch('uas.native_helper.receive',reply):
            result=self.helper._receive('exchange',revoking=True,deadline=time.monotonic()+.2)
        self.assertEqual('revoked',result['state']);self.assertFalse(self.admission.control.closed)
        # Ordinary status/admit readiness must still reject that exited helper.
        with self.assertRaises(OriginDenied):self.helper._ready(self.admission)
