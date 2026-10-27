"""Engine protocol/transport unit tests; no Docker daemon contact."""
import io
import json
import os
import socket
import struct
import unittest
from unittest.mock import patch

from uas.docker_exec_api import DockerExecAPI, EngineStream, NativeRpcIO, MAX_FRAME
from uas.pi_runtime import FixturePiRpcReceiver
from uas.workstation_exec import ExecUnavailable


class FakeSocket:
    def __init__(self, response):
        self.response = io.BytesIO(response)
        self.sent = b''
        self.closed = False
    def settimeout(self, *_):
        pass
    def connect(self, path):
        self.path = path
    def sendall(self, data):
        self.sent += data
    def recv(self, length):
        return self.response.read(length)
    def close(self):
        self.closed = True
    def shutdown(self, *_):
        pass


class DockerExecAPITests(unittest.TestCase):
    def test_upgrade_exact_exec_path_and_preserves_first_multiplex_bytes(self):
        header = (b'HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\n'
                  b'Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n')
        fake = FakeSocket(header + b'first-frame')
        api = DockerExecAPI('/not-contacted/docker.sock')
        with patch('uas.docker_exec_api.socket.socket', return_value=fake):
            stream = api.start('b'*64)
        self.assertIn(('/v1.48/exec/' + 'b'*64 + '/start').encode(), fake.sent)
        self.assertIn(b'"Detach":false,"Tty":false', fake.sent)
        self.assertEqual(fake.recv(11), b'first-frame')
        self.assertFalse(hasattr(stream, 'pid'))
        self.assertFalse(hasattr(stream, 'poll'))
        stream.close()

    def test_fixed_hub_attach_reuses_strict_multiplex_upgrade_not_init_pid(self):
        header = (b'HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\n'
                  b'Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n')
        fake = FakeSocket(header + b'first-frame')
        with patch('uas.docker_exec_api.socket.socket', return_value=fake):
            stream = DockerExecAPI('/not-contacted').attach_hub('c'*64)
        self.assertIn(('/containers/'+'c'*64+'/attach?stream=1&stdin=1&stdout=1&stderr=1').encode(),fake.sent)
        self.assertEqual(fake.recv(11),b'first-frame')
        self.assertFalse(hasattr(stream,'pid'));stream.close()

    def test_hub_start_requires_exact_204_and_never_retries_ambiguous_start(self):
        from unittest.mock import MagicMock
        for status,body in ((204,b''),(304,b''),(500,b''),(204,b'x')):
            connection=MagicMock()
            response=connection.getresponse.return_value
            response.status=status;response.read.return_value=body
            with patch('uas.docker_exec_api._UnixHTTP',return_value=connection) as factory:
                if status==204 and body==b'':
                    DockerExecAPI('/not-contacted').start_hub('c'*64)
                else:
                    with self.assertRaises(ExecUnavailable):DockerExecAPI('/not-contacted').start_hub('c'*64)
            self.assertEqual(factory.call_count,1)
            connection.request.assert_called_once()
            self.assertEqual(connection.request.call_args.args[1],'/v1.48/containers/'+'c'*64+'/start')
            connection.close.assert_called_once()

    def test_bad_or_ambiguous_upgrade_closes_without_retry(self):
        for header in (b'HTTP/1.1 500 Error\r\n\r\n', b'', b'X'*8193,
                       b'HTTP/1.1 101 UPGRADED\r\nUpgrade: tcp\r\nUpgrade: tcp\r\n\r\n'):
            fake = FakeSocket(header)
            with patch('uas.docker_exec_api.socket.socket', return_value=fake) as create:
                with self.assertRaises(ExecUnavailable):
                    DockerExecAPI('/not-contacted').start('b'*64)
            self.assertTrue(fake.closed)
            self.assertEqual(create.call_count, 1)

    def test_upgrade_requires_non_tty_multiplex_content_type(self):
        prefix = b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n'
        for fields in (b'', b'Content-Type: application/vnd.docker.raw-stream\r\n',
                       b'Content-Type: application/vnd.docker.multiplexed-stream\r\nContent-Length: 0\r\n',
                       b'Content-Type: application/vnd.docker.multiplexed-stream\r\nTransfer-Encoding: chunked\r\n'):
            fake = FakeSocket(prefix + fields + b'\r\n')
            with patch('uas.docker_exec_api.socket.socket', return_value=fake):
                with self.assertRaises(ExecUnavailable):
                    DockerExecAPI('/not-contacted').start('b'*64)
            self.assertTrue(fake.closed)

    def test_no_partial_or_caller_selected_id_paths(self):
        for value in ('short', '../other', 'b'*63, 'B'*64, None):
            with self.assertRaises(ExecUnavailable):
                DockerExecAPI('/not-contacted').inspect(value)

    def test_multiplex_io_is_not_task_liveness(self):
        left, right = socket.socketpair()
        transport = NativeRpcIO(left)
        try:
            right.sendall(struct.pack('>B3sI', 1, b'\0'*3, 4) + b'out\n')
            right.sendall(struct.pack('>B3sI', 2, b'\0'*3, 4) + b'err\n')
            self.assertEqual(transport.stdout.readline(5), b'out\n')
            self.assertEqual(transport.stderr.readline(5), b'err\n')
            transport.stdin.write(b'input\n')
            right.settimeout(2)
            self.assertEqual(right.recv(64), b'input\n')
            receiver = object.__new__(FixturePiRpcReceiver)
            receiver.process = transport
            receiver._task_alive = lambda: True
            transport.close()
            self.assertTrue(receiver._alive())  # closed I/O is not task exit
            receiver._task_alive = lambda: False
            self.assertFalse(receiver._alive())
        finally:
            transport.close(); left.close(); right.close()

    def test_oversized_or_wrong_stream_frame_is_terminal(self):
        for stream, length in ((0, 1), (3, 1), (1, MAX_FRAME+1)):
            left, right = socket.socketpair()
            transport = NativeRpcIO(left)
            try:
                right.sendall(struct.pack('>B3sI', stream, b'\0'*3, length))
                self.assertTrue(transport._stop.wait(2))
                self.assertIn('invalid/oversized', transport.error)
                self.assertEqual(transport.stdout.read(1), b'')
            finally:
                transport.close(); left.close(); right.close()

    def test_eof_mid_frame_fences_without_inventing_process_exit(self):
        left, right = socket.socketpair()
        transport = NativeRpcIO(left)
        try:
            right.sendall(struct.pack('>B3sI', 1, b'\0'*3, 20) + b'short')
            right.close()
            self.assertTrue(transport._stop.wait(2))
            self.assertIn('task state separate', transport.error)
        finally:
            transport.close(); left.close(); right.close()


class NativeRpcConstructorFailureTests(unittest.TestCase):
    def assert_setup_failure_clean(self, name, fail_at):
        import threading
        left, right = socket.socketpair()
        try:
            before = len(os.listdir('/proc/self/fd'))
            live_before = set(threading.enumerate())
            owner = threading.Thread if name == 'start' else os
            original = getattr(owner, name)
            calls = 0
            started = []
            def failing(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == fail_at:
                    raise OSError('injected constructor failure')
                result = original(*args, **kwargs)
                if name == 'start':
                    started.append(args[0])
                return result
            with patch.object(owner, name, failing):
                with self.assertRaisesRegex(OSError, 'injected constructor failure'):
                    NativeRpcIO(left)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            self.assertTrue(all(not thread.is_alive() for thread in started))
            self.assertEqual(set(threading.enumerate()), live_before)
            # The stream's caller still owns the passed Engine channel. It is
            # shut down/fenced, not confused with an acquired native task.
            self.assertGreaterEqual(left.fileno(), 0)
        finally:
            left.close(); right.close()

    def test_failed_rpc_attachment_fences_owned_engine_channel(self):
        left, right = socket.socketpair()
        transport = EngineStream(left)
        try:
            with patch('uas.docker_exec_api.os.pipe', side_effect=OSError('no pipes')):
                with self.assertRaises(OSError):
                    transport.rpc_io()
            self.assertTrue(transport.closed)
            self.assertEqual(left.fileno(), -1)
            with self.assertRaises(ExecUnavailable):
                transport.rpc_io()
        finally:
            transport.close(); right.close()

    def test_partial_pipe_allocation_is_closed(self):
        for fail_at in (1, 2, 3):
            with self.subTest(fail_at=fail_at):
                self.assert_setup_failure_clean('pipe', fail_at)

    def test_partial_fdopen_adoption_is_closed(self):
        for fail_at in (1, 2, 3):
            with self.subTest(fail_at=fail_at):
                self.assert_setup_failure_clean('fdopen', fail_at)

    def test_partial_nonblocking_setup_is_closed(self):
        for fail_at in (1, 2, 3):
            with self.subTest(fail_at=fail_at):
                self.assert_setup_failure_clean('set_blocking', fail_at)

    def test_thread_start_failure_joins_only_started_workers(self):
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                self.assert_setup_failure_clean('start', fail_at)
