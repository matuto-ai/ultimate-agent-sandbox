"""Pure real Broker/pump boundary ordering; all descriptors and events mocked."""
from contextlib import nullcontext
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.forge import ForgeBinding
from uas.kernel_origin import OriginDenied, Record
from uas.ledger import Origin
import uas.git_service as service
import uas.git_stream as stream


class EndScript(Exception):
    pass


class Channel:
    def __init__(self, incoming=()):
        self.incoming, self.sent, self.timeout = list(incoming), [], 35
    def fileno(self): return 600001
    def gettimeout(self): return self.timeout
    def settimeout(self, timeout): self.timeout = timeout
    def setblocking(self, value): self.timeout = None if value else 0
    def send(self, raw): self.sent.append(json.loads(raw)); return len(raw)


class Poll:
    def __init__(self, ticks): self.ticks = iter(ticks)
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def register(self, *args): pass
    def modify(self, *args): pass
    def unregister(self, *args): pass
    def select(self, _):
        return [(SimpleNamespace(data=label), mask) for label, mask in next(self.ticks)]


def receive(channel):
    if not channel.incoming: raise EndScript()
    return Record(json.dumps(channel.incoming.pop(0)).encode(), (123, 0, 0), -1)


class BrokerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.binding = ForgeBinding('room', 'project', 'owner/repo')
        self.origin = Origin('actor-a', 'seat-a', 'incarnation', 'epoch', ('git-read',))
        self.broker = object.__new__(service.ExternalGitBroker)
        self.broker.binding, self.broker.room_instance, self.broker.failed = self.binding, 'instance', False
        self.broker.audit = SimpleNamespace(failed=False,
            begin=Mock(return_value={'execute': True, 'record': {'id': 'a' * 64}}), finish=Mock())
        self.sessions = []
        self.broker.transport = SimpleNamespace(failed=False, open=Mock(side_effect=self.session), close=Mock())
        self.supervisor = SimpleNamespace(require=Mock(return_value=None), close=Mock(), revoked=False, pidfd=-1)
        self.stdout_before_exit = False
        self.pump_eof = False
        self.receipts = []

    def session(self, *args):
        pipes = [SimpleNamespace(fileno=lambda fd=fd: fd, close=Mock()) for fd in (600002,600003,600004)]
        value = SimpleNamespace(stdin=pipes[0], stdout=pipes[1], stderr=pipes[2],
            observe=Mock(side_effect=[None, object()] if self.stdout_before_exit else [object()]),
            finish=Mock(return_value=0), abort=Mock())
        self.sessions.append(value)
        return value

    def request(self, name):
        return {'kind':'GIT_OPEN', 'id':name, 'binding':self.broker.scope(),
                'origin':self.origin.canonical(),
                'argv':['git@github.com', "git-upload-pack 'owner/repo.git'"]}

    def run_boundary(self, frames):
        channel = Channel([{'kind':'GIT_HELLO','nonce':'a'*32,'binding':self.broker.scope()}, *frames])
        original_proxy = stream.proxy_ssh
        def pump(*args, **kwargs):
            events = [('stdout',1),('stderr',1)]
            if self.pump_eof: events.insert(0, ('channel',1))
            ticks = [events, []] if self.stdout_before_exit else [events]
            with patch.object(stream.selectors,'DefaultSelector',return_value=Poll(ticks)), \
                 patch.object(stream,'receive',side_effect=receive), \
                 patch.object(stream.os,'read',side_effect=[b'',b'']), \
                 patch.object(stream.os,'write',side_effect=AssertionError('unexpected native write')):
                receipt = original_proxy(*args, **kwargs)
            self.receipts.append(receipt)
            return receipt
        with patch.object(service,'enable',Mock()), patch.object(service,'receive',side_effect=receive), \
             patch.object(service,'HeldOrigin',return_value=self.supervisor), \
             patch.object(service,'alive',return_value=True), patch.object(stream,'proxy_ssh',side_effect=pump):
            try: service.serve(channel,self.broker,supervisor_uid=0,supervisor_gid=0)
            except EndScript: pass
        return channel

    def test_late_eof_after_success_never_becomes_next_requests_refusal(self):
        for stdout_first in (False,True):
            with self.subTest(stdout_before_exit=stdout_first):
                self.setUp(); self.stdout_before_exit=stdout_first
                channel=self.run_boundary([self.request('first'),{'kind':'eof'},
                                           self.request('second'),{'kind':'eof'}])
                self.assertEqual(['GIT_READY','ready','exit','ready','exit'],[f['kind'] for f in channel.sent])
                self.assertEqual(2,self.broker.audit.begin.call_count)
                self.assertEqual(2,self.broker.audit.finish.call_count)
                self.assertEqual(4,self.supervisor.require.call_count)
                self.assertTrue(all(r.status=='SUCCEEDED' and r.input_eof is False for r in self.receipts))
                for session in self.sessions:
                    session.finish.assert_called_once_with(timeout=0)
                    session.abort.assert_not_called()

    def test_new_open_without_late_eof_ends_previous_allowance(self):
        channel=self.run_boundary([self.request('first'),self.request('second'),{'kind':'eof'},
                                   self.request('third')])
        self.assertEqual(['GIT_READY','ready','exit','ready','exit','ready','exit'],[f['kind'] for f in channel.sent])
        self.assertEqual(4,self.supervisor.require.call_count)
        self.assertEqual(3,self.broker.audit.begin.call_count)

    def test_previously_consumed_or_duplicate_eof_and_non_eof_frames_refuse(self):
        bad=[{'kind':'eof'},{'kind':'eof','extra':1},{'kind':'data','data':'eA=='},{'kind':'cancel'}, {'kind':'shell'}]
        for value in bad:
            with self.subTest(frame=value):
                self.setUp()
                frames=[self.request('first'),{'kind':'eof'},value]
                with self.assertRaises(OriginDenied):self.run_boundary(frames)
                self.assertEqual(1,self.broker.audit.begin.call_count)
        self.setUp();self.pump_eof=True
        with self.assertRaises(OriginDenied):
            self.run_boundary([self.request('first'),{'kind':'eof'},{'kind':'eof'}])
        self.assertTrue(self.receipts[0].input_eof)

    def test_eof_before_any_stream_or_after_refusal_has_no_allowance(self):
        with self.assertRaises(OriginDenied):self.run_boundary([{'kind':'eof'}])
        self.broker.audit.begin.assert_not_called()
        self.setUp()
        self.broker.audit.begin.return_value={'execute':False,'record':{'result':None}}
        with self.assertRaises(OriginDenied):self.run_boundary([self.request('denied'),{'kind':'eof'}])
        self.broker.transport.open.assert_not_called()

    def test_late_eof_still_requires_current_bound_supervisor(self):
        self.supervisor.require.side_effect=[None,OriginDenied('revoked')]
        with self.assertRaises(OriginDenied):self.run_boundary([self.request('first'),{'kind':'eof'}])
        self.assertEqual(2,self.supervisor.require.call_count)
        self.assertEqual(1,self.broker.audit.finish.call_count)

    def test_next_relay_reads_its_actual_terminal_not_stale_refusal(self):
        client=object.__new__(service.GitBrokerClient)
        client.closed=False;client.binding=self.binding;client.scope=self.broker.scope()
        terminal={'kind':'exit','code':0,'status':'OK','repository':'owner/repo','advertised':[]}
        client.channel=Channel([{'kind':'ready'},terminal]);client.worker=SimpleNamespace(require=Mock())
        caller=Channel([{'kind':'stream-finished'}])
        authority=SimpleNamespace(current=Mock(return_value=True),require=Mock(),origin=self.origin)
        with patch.object(service,'receive',side_effect=receive), \
             patch.object(service.selectors,'DefaultSelector',return_value=Poll([[('broker',1)],[('caller',2)]])):
            result=client._relay(caller,authority,operation_id='second',
                argv=['git@github.com',"git-upload-pack 'owner/repo.git'"],lock=nullcontext)
        self.assertEqual(terminal,result)
        self.assertEqual(['ready','exit'],[f['kind'] for f in caller.sent])
        self.assertEqual(2,client.worker.require.call_count)
        authority.require.assert_called_once()
        self.assertEqual([],caller.incoming)
        self.assertGreaterEqual(authority.current.call_count,5)
