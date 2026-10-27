"""Pure Supervisor stream pump tests; all sockets, selectors and records inert."""
from contextlib import nullcontext
import json
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import Mock, patch

from uas.forge import ForgeBinding
from uas.git_service import GitBrokerClient
from uas.git_stream import GitStreamError, data_frame
from uas.kernel_origin import OriginDenied, Record
from uas.ledger import Origin
from test_git_stream import Poll


class Channel:
    def __init__(self):
        self.mode, self.sent, self.closed = 35, [], False
        self.send = Mock(side_effect=self._send)
    def gettimeout(self): return self.mode
    def settimeout(self, value): self.mode = value
    def setblocking(self, value): self.mode = None if value else 0
    def close(self): self.closed = True
    def _send(self, raw):
        if self.mode != 0: raise AssertionError('blocking relay send')
        self.sent.append(json.loads(raw)); return len(raw)


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.client = object.__new__(GitBrokerClient)
        self.client.channel, self.caller = Channel(), Channel()
        self.client.binding = ForgeBinding('room', 'project', 'org/repo')
        self.client.scope = {'room_id': 'room', 'project_id': 'project', 'repository': 'org/repo', 'host': 'github.com', 'room_instance': 'instance'}
        self.client.worker, self.client.closed = Mock(), False
        self.client._stream_lock = threading.Lock()
        self.authority = SimpleNamespace(origin=Origin('alice', 'seat-a', 'inc', 'epoch', ('git-read',)),
            current=Mock(return_value=True), require=Mock())
        self.terminal = {'kind': 'exit', 'code': 0, 'status': 'OK', 'repository': 'org/repo', 'advertised': []}
        self.locked = 0
        parent = self
        class Lock:
            def __enter__(self): parent.locked += 1
            def __exit__(self, *_): parent.locked -= 1
        self.lock = Lock
        for target in ('socket.socket', 'socket.socketpair', 'os.fork', 'os.pidfd_open', 'subprocess.Popen'):
            patch(target, side_effect=AssertionError('native effect forbidden')).start()
        self.addCleanup(patch.stopall)

    def run_relay(self, ticks, *, broker=None, caller=None):
        self.poll = Poll(ticks)
        incoming = {self.client.channel: iter(broker or [{'kind': 'ready'}, json.loads(data_frame(b'answer')), self.terminal]),
                    self.caller: iter(caller or [json.loads(data_frame(b'query')), {'kind': 'eof'}, {'kind': 'stream-finished'}])}
        self.incoming = incoming
        def recv(channel):
            value = next(incoming[channel])
            if isinstance(value, BaseException): raise value
            return Record(json.dumps(value).encode(), (1, 2, 2), -1)
        def select_(*args):
            self.assertEqual(self.locked, 0)
            self.assertLessEqual(args[3], .1)
            return (args[0], args[1], [])
        with patch('uas.git_service.receive', side_effect=recv), \
             patch('uas.git_service.selectors.DefaultSelector', return_value=self.poll), \
             patch('select.select', side_effect=select_):
            return self.client.relay(self.caller, self.authority, operation_id='op',
                argv=['git@github.com', "git-upload-pack 'org/repo.git'"], lock=self.lock)

    def test_bidirectional_partial_queues_and_terminal_after_delivery(self):
        terminal = self.run_relay([[('caller', 1)], [('broker', 3)], [('caller', 3)],
                                   [('broker', 2)], [('broker', 1)], [('caller', 2)]])
        self.assertEqual(terminal, self.terminal)
        self.assertEqual([value['kind'] for value in self.client.channel.sent], ['GIT_OPEN', 'data', 'eof'])
        self.assertEqual([value['kind'] for value in self.caller.sent], ['ready', 'data', 'exit'])
        self.assertEqual(self.caller.mode, 35)
        self.assertEqual(self.client.channel.mode, 35)
        self.assertEqual(self.authority.require.call_count, 3)
        self.assertGreaterEqual(self.authority.current.call_count, 8)
        self.assertTrue(all(value <= .1 for value in self.poll.timeouts))

    def test_backpressure_wait_outside_lifecycle_lock(self):
        original = self.caller._send
        blocked = [True]
        def send(raw):
            self.assertEqual(self.caller.mode, 0)
            if blocked[0]: blocked[0] = False; raise BlockingIOError()
            self.assertEqual(self.locked, 1)
            return original(raw)
        self.caller.send.side_effect = send
        self.run_relay([[('broker', 1)], [('caller', 2)]], broker=[{'kind': 'ready'}, self.terminal])
        self.assertFalse(self.client.closed)

    def test_revocation_discards_pending_output_and_closes_without_retry(self):
        def revoke():
            self.authority.current.side_effect = OriginDenied('revoked')
            return [('caller', 2)]
        with self.assertRaises(OriginDenied):
            self.run_relay([[('broker', 1)], revoke])
        self.assertEqual([frame['kind'] for frame in self.caller.sent], ['ready'])
        self.assertEqual(self.client.channel.sent[-1], {'kind': 'cancel'})
        self.assertTrue(self.client.closed)

    def test_invalid_broker_terminal_never_disclosed(self):
        with self.assertRaises(OriginDenied):
            self.run_relay([[('broker', 1)]], broker=[{'kind': 'ready'}, {**self.terminal, 'repository': 'evil/repo'}])
        self.assertEqual([frame['kind'] for frame in self.caller.sent], ['ready'])
        self.assertTrue(self.client.closed)

    def test_bootstrap_wait_rechecks_authority(self):
        with self.assertRaises(OriginDenied):
            self.authority.current.side_effect = [True, True, OriginDenied('revoked')]
            self.run_relay([], broker=[BlockingIOError(), {'kind': 'ready'}])
        self.assertEqual(self.caller.sent, [])

    def test_stream_lock_denies_concurrent_use_without_contact(self):
        self.client._stream_lock.acquire()
        try:
            with self.assertRaisesRegex(Exception, 'GIT_BROKER_BUSY'):
                self.run_relay([])
        finally: self.client._stream_lock.release()
        self.assertEqual(self.client.channel.sent, [])

    def test_crossed_input_drained_through_finish_before_return(self):
        marker = {'kind': 'stream-finished'}
        terminal = self.run_relay([[('broker', 1)], [('caller', 2)]],
            broker=[{'kind': 'ready'}, self.terminal],
            caller=[json.loads(data_frame(b'crossed')), {'kind': 'eof'}, marker, {'kind': 'result'}])
        self.assertEqual(terminal, self.terminal)
        self.assertEqual([x['kind'] for x in self.client.channel.sent], ['GIT_OPEN'])
        self.assertEqual(self.authority.require.call_count, 3)
        self.assertEqual(next(self.incoming[self.caller]), {'kind': 'result'})
        self.assertFalse(self.client.closed)

    def test_initial_refusal_requires_authenticated_finish(self):
        refusal = {'kind': 'refused', 'error': 'GIT_STREAM_ALREADY_CONSUMED', 'record': None}
        self.assertEqual(self.run_relay([], broker=[refusal],
            caller=[{'kind': 'stream-finished'}]), refusal)
        self.assertEqual(self.authority.require.call_count, 1)
        self.assertEqual(self.caller.sent, [refusal])

    def test_terminal_drain_failure_closes_without_retry(self):
        tails = [
            [{'kind': 'result'}],
            [{'kind': 'stream-finished', 'extra': True}],
            [{'kind': 'eof'}, {'kind': 'eof'}],
            [{'kind': 'eof'}, json.loads(data_frame(b'x'))],
            [OriginDenied('peer closed before finish')],
        ]
        for tail in tails:
            with self.subTest(tail=tail):
                self.setUp()
                with self.assertRaises((OriginDenied, GitStreamError)):
                    self.run_relay([[('broker', 1)], [('caller', 2)]],
                        broker=[{'kind': 'ready'}, self.terminal], caller=tail)
                self.assertTrue(self.client.closed)
                self.assertEqual(self.client.channel.sent[-1], {'kind': 'cancel'})

    def test_terminal_drain_checks_authority_after_terminal(self):
        self.authority.require.side_effect = OriginDenied('revoked caller')
        with self.assertRaises(OriginDenied):
            self.run_relay([[('broker', 1)], [('caller', 2)]],
                broker=[{'kind': 'ready'}, self.terminal], caller=[{'kind': 'stream-finished'}])
        self.assertTrue(self.client.closed)

    def test_terminal_drain_backpressure_waits_without_lock_and_checks_deadline(self):
        self.run_relay([[('broker', 1)], [('caller', 2)]],
            broker=[{'kind': 'ready'}, self.terminal],
            caller=[BlockingIOError(), {'kind': 'stream-finished'}])
        self.assertFalse(self.client.closed)

    def test_terminal_drain_input_bound(self):
        with patch('uas.git_stream.MAX_BYTES', 0), self.assertRaises(OriginDenied):
            self.run_relay([[('broker', 1)], [('caller', 2)]],
                broker=[{'kind': 'ready'}, self.terminal], caller=[json.loads(data_frame(b'x'))])
        self.assertTrue(self.client.closed)

    def test_terminal_drain_deadline_cannot_wait_forever(self):
        now = [0.0]
        original = self.caller._send
        def send(raw):
            result = original(raw)
            if json.loads(raw)['kind'] == 'exit': now[0] = 33.0
            return result
        self.caller.send.side_effect = send
        with patch('uas.git_service.time.monotonic', side_effect=lambda: now[0]), self.assertRaises(OriginDenied):
            self.run_relay([[('broker', 1)], [('caller', 2)]],
                broker=[{'kind': 'ready'}, self.terminal], caller=[{'kind': 'stream-finished'}])
        self.assertTrue(self.client.closed)

    def test_terminal_drain_preserves_preterminal_eof_and_byte_count(self):
        for tail in ({'kind': 'eof'}, json.loads(data_frame(b'x'))):
            with self.subTest(tail=tail):
                self.setUp()
                with self.assertRaises(OriginDenied):
                    self.run_relay([[('caller', 1)], [('broker', 1)], [('caller', 2)]],
                        broker=[{'kind': 'ready'}, self.terminal], caller=[{'kind': 'eof'}, tail])
                self.assertTrue(self.client.closed)
        self.setUp()
        with patch('uas.git_stream.MAX_BYTES', 1), self.assertRaises(OriginDenied):
            self.run_relay([[('caller', 1)], [('broker', 1)], [('caller', 2)]],
                broker=[{'kind': 'ready'}, self.terminal],
                caller=[json.loads(data_frame(b'x')), json.loads(data_frame(b'y'))])
