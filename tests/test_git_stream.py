"""Pure frame/state and mocked pump checks; no socket or child is created."""
import base64
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.git_stream import (GitStreamError, GitStreamState, MAX_BYTES, MAX_DATA,
                            data_frame, exit_frame, parse_frame, proxy_ssh)
from uas.kernel_origin import Record


class StreamStateTests(unittest.TestCase):
    def test_frames_have_exact_shapes_and_canonical_base64(self):
        data = b'\x00\xffgit\n'
        self.assertEqual(('data', data), parse_frame(data_frame(data)))
        self.assertEqual(('eof', None), parse_frame(b'{"kind":"eof"}'))
        self.assertEqual(('cancel', None), parse_frame(b'{"kind":"cancel"}'))
        self.assertEqual({'kind': 'exit', 'code': 0, 'status': 'SUCCEEDED'}, json.loads(exit_frame(0, 'SUCCEEDED')))
        self.assertEqual(MAX_DATA, len(parse_frame(data_frame(b'x' * MAX_DATA))[1]))

    def test_malformed_duplicate_oversized_and_noncanonical_frames_refuse(self):
        bad = [b'', b'[]', b'null', b'\xff', b'{"kind":"eof","extra":1}',
               b'{"kind":"eof","kind":"eof"}', b'{"kind":"data","data":1}',
               b'{"kind":"data","data":""}', b'{"kind":"data","data":"Zg"}',
               b'{"kind":"data","data":"Zh=="}', b'{"kind":"data","data":"Zg==\\n"}',
               b'{"kind":"data","data":"Zg=== "}', b'{"kind":"data","data":NaN}',
               b'{"kind":"data","data":"Zg==","actor":"chosen"}', exit_frame(0, 'SUCCEEDED'),
               json.dumps({'kind': 'data', 'data': base64.b64encode(b'x' * (MAX_DATA + 1)).decode()}).encode(),
               b' ' * 45001, None, 'not bytes']
        for raw in bad:
            with self.subTest(raw=repr(raw)[:100]), self.assertRaises(GitStreamError):
                parse_frame(raw)
        for value in (b'', b'x' * (MAX_DATA + 1), 'text'):
            with self.assertRaises(GitStreamError):
                data_frame(value)
        for code, status in ((-1, 'REMOTE_FAILED'), (256, 'REMOTE_FAILED'), (True, 'SUCCEEDED'), (0, 'secret')):
            with self.assertRaises(GitStreamError):
                exit_frame(code, status)

    def test_counters_hash_actual_forwarded_bytes_not_unreleased_queues(self):
        state = GitStreamState(limit=10)
        state.accept(data_frame(b'abcdef'))
        state.written(b'ab')
        state.written(b'c')
        state.read(b'uvwxyz')
        state.sent(b'uv')
        state.discard_stderr(b'secret')
        receipt = state.receipt()
        self.assertEqual((3, 2, 6), (receipt.input_bytes, receipt.output_bytes, receipt.stderr_bytes))
        self.assertEqual(hashlib.sha256(b'abc').hexdigest(), receipt.input_sha256)
        self.assertEqual(hashlib.sha256(b'uv').hexdigest(), receipt.output_sha256)
        self.assertNotIn('secret', repr(receipt.document()))

    def test_eof_is_exactly_once_and_cancel_remains_available_after_eof(self):
        state = GitStreamState()
        state.accept(b'{"kind":"eof"}')
        for raw in (b'{"kind":"eof"}', data_frame(b'x')):
            with self.assertRaises(GitStreamError) as caught:
                state.accept(raw)
            self.assertEqual('GIT_STREAM_AFTER_EOF', caught.exception.code)
        with self.assertRaises(GitStreamError) as caught:
            state.accept(b'{"kind":"cancel"}')
        self.assertEqual('GIT_STREAM_CANCELLED', caught.exception.code)

    def test_each_bound_and_impossible_accounting_refuse(self):
        for limit in (0, -1, True, MAX_BYTES + 1):
            with self.assertRaises(GitStreamError):
                GitStreamState(limit=limit)
        state = GitStreamState(limit=3)
        state.accept(data_frame(b'abc'))
        with self.assertRaises(GitStreamError):
            state.accept(data_frame(b'd'))
        with self.assertRaises(GitStreamError):
            state.written(b'abcd')
        state.read(b'abc')
        with self.assertRaises(GitStreamError):
            state.read(b'd')
        with self.assertRaises(GitStreamError):
            state.sent(b'abcd')
        state.discard_stderr(b'abc')
        with self.assertRaises(GitStreamError):
            state.discard_stderr(b'd')
        self.assertEqual(4, state.receipt().stderr_bytes)


class Pipe:
    def __init__(self, fd):
        self.fd, self.closed = fd, False
    def fileno(self):
        return self.fd
    def close(self):
        self.closed = True


class Channel:
    def __init__(self):
        self.sent = []
        self.send = Mock(side_effect=self._send)
    def fileno(self):
        return 600001
    def setblocking(self, value):
        self.blocking = value
    def _send(self, packet):
        self.sent.append(packet)
        return len(packet)


class Session:
    def __init__(self):
        self.stdin, self.stdout, self.stderr = Pipe(600002), Pipe(600003), Pipe(600004)
        self.observe = Mock(return_value=None)
        self.finish = Mock(return_value=0)
        self.abort = Mock()


class Poll:
    def __init__(self, ticks):
        self.ticks = iter(ticks)
        self.registered = {}
        self.timeouts = []
        self.history = []
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def register(self, fd, events, label):
        self.registered[fd] = (events, label)
    def modify(self, fd, events, label):
        self.register(fd, events, label)
    def unregister(self, fd):
        del self.registered[fd]
    def select(self, timeout):
        self.timeouts.append(timeout)
        self.history.append(dict(self.registered))
        tick = next(self.ticks)
        if callable(tick):
            tick = tick()
        result = []
        for label, mask in tick:
            found = [(fd, event) for fd, (event, tag) in self.registered.items() if tag == label]
            if not found or not found[0][1] & mask:
                raise AssertionError('scripted event was not registered: ' + label)
            result.append((SimpleNamespace(fd=found[0][0], data=label), mask))
        return result


class PumpTests(unittest.TestCase):
    def setUp(self):
        self.channel, self.session = Channel(), Session()
        self.current = Mock(return_value=True)
        self.require = Mock(return_value=None)

    def run_pump(self, ticks, packets=(), reads=(), writes=(), **kwargs):
        self.poll = Poll(ticks)
        records = [Record(packet, (123, 456, 456), -1) for packet in packets]
        with patch('uas.git_stream.selectors.DefaultSelector', return_value=self.poll), \
             patch('uas.git_stream.receive', side_effect=records) as receive, \
             patch('uas.git_stream.os.read', side_effect=reads) as read, \
             patch('uas.git_stream.os.write', side_effect=writes) as write:
            self.receive, self.read, self.write = receive, read, write
            return proxy_ssh(self.channel, self.session, self.require, self.current, **kwargs)

    def test_roundtrip_partial_write_eof_drain_exact_hashes_and_sanitized_stderr(self):
        # stdin closes only on the iteration after the queued input fully drains.
        def after_first_write():
            self.assertFalse(self.session.stdin.closed)
            return [('stdin', 2)]
        def eof_reads():
            self.assertTrue(self.session.stdin.closed)
            self.session.observe.return_value = SimpleNamespace(si_pid=999999)
            return [('stdout', 1), ('stderr', 1)]
        receipt = self.run_pump([
            [('channel', 1)], [('channel', 1), ('stdin', 2), ('stdout', 1), ('stderr', 1)],
            after_first_write, [('channel', 2)], eof_reads],
            packets=[data_frame(b'abcdef'), b'{"kind":"eof"}'],
            writes=[2, 4], reads=[b'result', b'secret diagnostic', b'', b''])
        self.assertEqual((6, 6, 17), (receipt.input_bytes, receipt.output_bytes, receipt.stderr_bytes))
        self.assertEqual(hashlib.sha256(b'abcdef').hexdigest(), receipt.input_sha256)
        self.assertEqual(hashlib.sha256(b'result').hexdigest(), receipt.output_sha256)
        self.assertEqual(('SUCCEEDED', 0), (receipt.status, receipt.exit_code))
        self.assertEqual(('data', b'result'), parse_frame(self.channel.sent[0]))
        self.assertEqual(1, len(self.channel.sent))  # Terminal belongs to post-audit service.
        self.assertNotIn(b'secret', b''.join(self.channel.sent))
        self.assertEqual(2, self.require.call_count)
        self.assertTrue(all(type(call.args[0]) is Record for call in self.require.call_args_list))
        self.session.finish.assert_called_once_with(timeout=0)
        self.session.abort.assert_not_called()
        self.assertTrue(all(timeout <= .1 for timeout in self.poll.timeouts))

    def test_revocation_before_read_or_output_disclosure_aborts_without_bytes(self):
        def revoke():
            self.current.return_value = False
            return [('stdout', 1)]
        with self.assertRaises(GitStreamError) as caught:
            self.run_pump([revoke], reads=[b'not disclosed'])
        self.assertEqual('GIT_STREAM_AUTHORITY_REVOKED', caught.exception.code)
        self.assertEqual(0, caught.exception.receipt.output_bytes)
        self.read.assert_not_called()
        self.session.abort.assert_called_once()
        self.assertFalse(self.channel.sent)

    def test_each_record_must_authenticate_before_packet_is_consumed(self):
        self.require.side_effect = RuntimeError('forged Actor secret')
        with self.assertRaises(GitStreamError) as caught:
            self.run_pump([[('channel', 1)]], packets=[data_frame(b'not written')])
        self.assertEqual('GIT_STREAM_AUTHORITY_REVOKED', caught.exception.code)
        self.assertEqual(0, caught.exception.receipt.input_bytes)
        self.assertNotIn('secret', str(caught.exception))
        self.write.assert_not_called()
        self.session.abort.assert_called_once()

    def test_cancel_duplicate_eof_and_input_limit_abort_without_forwarding(self):
        cases = [([b'{"kind":"cancel"}'], 'GIT_STREAM_CANCELLED', 10),
                 ([b'{"kind":"eof"}', b'{"kind":"eof"}'], 'GIT_STREAM_AFTER_EOF', 10),
                 ([data_frame(b'abcd')], 'GIT_STREAM_INPUT_LIMIT', 3)]
        for packets, code, limit in cases:
            self.setUp()
            with self.assertRaises(GitStreamError) as caught:
                self.run_pump([[('channel', 1)]] * len(packets), packets=packets, limit=limit)
            self.assertEqual(code, caught.exception.code)
            self.assertEqual(0, caught.exception.receipt.input_bytes)
            self.session.abort.assert_called_once()

    def test_blocking_io_retries_without_false_transfer_counts(self):
        attempts = [0]
        def send(packet):
            attempts[0] += 1
            if attempts[0] == 1:
                raise BlockingIOError()
            return self.channel._send(packet)
        self.channel.send.side_effect = send
        self.session.observe.return_value = SimpleNamespace(si_pid=999999)
        receipt = self.run_pump([[('stdout', 1)], [('stdout', 1)], [('channel', 2)],
            [('channel', 2), ('stdout', 1), ('stderr', 1)]],
            reads=[BlockingIOError(), b'ok', b'', b''])
        self.assertEqual(2, receipt.output_bytes)
        self.assertEqual(2, self.channel.send.call_count)

    def test_output_and_stderr_limits_abort_no_over_limit_disclosure(self):
        for label, code in (('stdout', 'GIT_STREAM_OUTPUT_LIMIT'), ('stderr', 'GIT_STREAM_STDERR_LIMIT')):
            self.setUp()
            with self.assertRaises(GitStreamError) as caught:
                self.run_pump([[(label, 1)]], reads=[b'abcd'], limit=3)
            self.assertEqual(code, caught.exception.code)
            self.assertEqual(0, caught.exception.receipt.output_bytes)
            self.assertFalse(self.channel.sent)

    def test_partial_seqpacket_send_is_not_counted_as_delivered(self):
        self.channel.send.side_effect = lambda packet: len(packet) - 1
        with self.assertRaises(GitStreamError) as caught:
            self.run_pump([[('stdout', 1)], [('channel', 2)]], reads=[b'bytes'])
        self.assertEqual('GIT_STREAM_DISCONNECTED', caught.exception.code)
        self.assertEqual(0, caught.exception.receipt.output_bytes)

    def test_ownership_or_cleanup_failure_is_never_retried_by_the_pump(self):
        self.session.observe.side_effect = RuntimeError('lost ownership')
        self.session.abort.side_effect = RuntimeError('already uncertain')
        with self.assertRaises(GitStreamError) as caught:
            self.run_pump([[]])
        self.assertEqual('GIT_STREAM_CLEANUP_UNKNOWN', caught.exception.code)
        self.session.observe.assert_called_once()
        self.session.abort.assert_called_once()

    def test_deadline_is_enforced_with_short_polling(self):
        with patch('uas.git_stream.time.monotonic', side_effect=[0, 0, 31]):
            with self.assertRaises(GitStreamError) as caught:
                self.run_pump([[]])
        self.assertEqual('GIT_STREAM_TIMEOUT', caught.exception.code)
        self.session.abort.assert_called_once()
        self.assertEqual([.1], self.poll.timeouts)

    def test_native_signal_exit_is_bounded_and_literal_remote_failure(self):
        self.session.observe.return_value = SimpleNamespace(si_pid=999999)
        self.session.finish.return_value = -9
        receipt = self.run_pump([[('stdout', 1), ('stderr', 1)]], reads=[b'', b''])
        self.assertEqual((137, 'REMOTE_FAILED'), (receipt.exit_code, receipt.status))
        self.assertFalse(self.channel.sent)

    def test_output_observer_runs_before_disclosure_and_receipt_has_no_terminal_frame(self):
        observed = []
        def observer(block):
            self.assertFalse(self.channel.sent)
            observed.append(block)
        self.session.observe.return_value = SimpleNamespace(si_pid=999999)
        receipt = self.run_pump([[('stdout', 1)], [('channel', 2), ('stdout', 1), ('stderr', 1)]],
            reads=[b'advertisement', b'', b''], observe_output=observer)
        self.assertEqual([b'advertisement'], observed)
        self.assertEqual(0, receipt.exit_code)
        self.assertEqual(['data'], [json.loads(packet)['kind'] for packet in self.channel.sent])

    def test_output_observer_failure_and_false_authorization_never_forward(self):
        with self.assertRaises(GitStreamError):
            self.run_pump([[('stdout', 1)]], reads=[b'unknown'],
                          observe_output=Mock(side_effect=ValueError('invalid advert')))
        self.assertFalse(self.channel.sent)
        self.setUp()
        self.require.return_value = False
        with self.assertRaises(GitStreamError) as caught:
            self.run_pump([[('channel', 1)]], packets=[data_frame(b'not authorized')])
        self.assertEqual('GIT_STREAM_AUTHORITY_REVOKED', caught.exception.code)
        self.write.assert_not_called()

    def test_invalid_configuration_aborts_already_open_session(self):
        for kwargs in ({'limit': 0}, {'timeout': 0}, {'observe_output': 'not callable'}):
            self.setUp()
            with self.assertRaises(GitStreamError):
                self.run_pump([], **kwargs)
            self.session.abort.assert_called_once()

    def test_zero_exit_with_unforwarded_input_is_not_success(self):
        self.session.observe.return_value = SimpleNamespace(si_pid=999999)
        with self.assertRaises(GitStreamError) as caught:
            self.run_pump([[('channel', 1), ('stdout', 1), ('stderr', 1)]],
                packets=[data_frame(b'unforwarded')], reads=[b'', b''])
        self.assertEqual('GIT_STREAM_INPUT_TRUNCATED', caught.exception.code)
        self.assertEqual(0, caught.exception.receipt.input_bytes)
        self.session.finish.assert_called_once()

    def test_input_backpressure_removes_reads_until_bounded_queue_drains(self):
        def full_queue():
            self.assertNotIn(self.channel.fileno(), self.poll.registered)
            return [('stdin', 2)]
        def drained():
            self.assertTrue(self.poll.registered[self.channel.fileno()][0] & 1)
            self.session.observe.return_value = SimpleNamespace(si_pid=999999)
            return [('channel', 1), ('stdout', 1), ('stderr', 1)]
        written = []
        def write(fd, data):
            written.append(bytes(data))
            return len(data)
        receipt = self.run_pump([[('channel', 1)], [('channel', 1)], full_queue, drained],
            packets=[data_frame(b'a' * MAX_DATA), data_frame(b'b' * MAX_DATA), b'{"kind":"eof"}'],
            writes=write, reads=[b'', b''])
        self.assertEqual(2 * MAX_DATA, receipt.input_bytes)
        self.assertEqual([b'a' * MAX_DATA + b'b' * MAX_DATA], written)

    def test_output_backpressure_stops_pipe_reads_before_unbounded_queueing(self):
        def full_queue():
            self.assertNotIn(self.session.stdout.fileno(), self.poll.registered)
            return [('channel', 2)]
        def draining():
            self.assertIn(self.session.stdout.fileno(), self.poll.registered)
            self.session.observe.return_value = SimpleNamespace(si_pid=999999)
            return [('channel', 2), ('stdout', 1), ('stderr', 1)]
        receipt = self.run_pump([[('stdout', 1)], [('stdout', 1)], full_queue, draining],
            reads=[b'a' * MAX_DATA, b'b' * MAX_DATA, b'', b''])
        self.assertEqual(2 * MAX_DATA, receipt.output_bytes)
        self.assertEqual(2, len(self.channel.sent))
        self.assertTrue(all(len(parse_frame(packet)[1]) == MAX_DATA for packet in self.channel.sent))


if __name__ == '__main__':
    unittest.main()
