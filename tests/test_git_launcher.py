"""Pure public RPC protocol with mocked endpoint/record/stdio operations."""
import ast
import base64
from contextlib import ExitStack, nullcontext
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.git_launcher import ENDPOINT, main
from uas.git_policy import GitPolicyError
from uas.kernel_origin import OriginDenied


def blob(name, raw):
    return [{'kind': 'blob', 'name': name, 'bytes': len(raw), 'count': 1, 'sha256': hashlib.sha256(raw).hexdigest()},
        {'kind': 'blob-part', 'name': name, 'index': 0, 'data': base64.b64encode(raw).decode()}]


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.channel = Mock()
        self.channel.__enter__ = Mock(return_value=self.channel)
        self.channel.__exit__ = Mock(return_value=False)
        self.socket = self.stack.enter_context(patch('uas.git_launcher.socket.socket', return_value=self.channel))
        self.enable = self.stack.enter_context(patch('uas.git_launcher.enable'))
        self.peer = Mock()
        self.stack.enter_context(patch('uas.git_launcher.EndpointPeer', return_value=self.peer))
        self.send = self.stack.enter_context(patch('uas.git_launcher.send'))
        self.receive = self.stack.enter_context(patch('uas.git_launcher.receive'))
        self.stack.enter_context(patch('uas.git_launcher.os.getcwd', return_value='/project'))
        self.stack.enter_context(patch('uas.git_launcher.uuid.uuid4', return_value=SimpleNamespace(hex='operation1')))
        self.output = []
        self.write = self.stack.enter_context(patch('uas.git_launcher.os.write', side_effect=lambda fd, raw: self.output.append((fd, raw[:3])) or min(3, len(raw))))
        for target in ('os.fork', 'os.pidfd_open', 'subprocess.Popen', 'os.execve'):
            self.stack.enter_context(patch(target, side_effect=AssertionError('public native effect forbidden')))

    def replies(self, values):
        self.receive.side_effect = [nullcontext(SimpleNamespace(data=json.dumps(value).encode(), pidfd=-1)) for value in values]

    def success(self, *, stdout=b'normal\x00output\n', stderr=b'warning\n', terminal=None):
        self.replies(blob('stdout', stdout) + blob('stderr', stderr) + [terminal or
            {'kind': 'exit', 'code': 0, 'status': 'OK', 'receipt': {'operation_id': 'operation1'}}])
        return stdout, stderr

    def test_public_request_has_no_actor_credential_result_or_executable_selection(self):
        stdout, stderr = self.success()
        with patch.dict(os.environ, {'GIT_SSH_COMMAND': 'evil', 'GH_TOKEN': 'not-forwarded', 'ACTOR_ID': 'forged'}):
            self.assertEqual(0, main(['status'], invoked_as='git'))
        self.assertEqual({'kind': 'git', 'id': 'operation1', 'invoked_as': 'git',
                          'argv': ['status'], 'cwd': '/project'}, self.send.call_args.args[1])
        self.channel.connect.assert_called_once_with(ENDPOINT)
        self.assertEqual(5, self.peer.require.call_count)
        self.assertEqual(stdout, b''.join(raw for fd, raw in self.output if fd == 1))
        self.assertEqual(stderr, b''.join(raw for fd, raw in self.output if fd == 2))
        self.peer.close.assert_called_once()

    def test_forged_actor_author_config_and_generic_commands_reject_before_connection(self):
        for argv in (['--actor', 'other', 'status'], ['-c', 'user.name=Forged', 'commit', '-m', 'x'],
                     ['commit', '--author=x', '-m', 'x'], ['am', 'mail.patch'], ['-u', 'status']):
            with self.assertRaises(GitPolicyError):
                main(argv, invoked_as='git')
        self.socket.assert_not_called()

    def test_refusal_and_bad_refusal_are_not_native_success(self):
        self.replies([{'kind': 'refused', 'error': 'FORBIDDEN', 'record': None}])
        self.assertEqual(128, main(['status'], invoked_as='git'))
        self.replies([{'kind': 'refused', 'error': 'FORBIDDEN', 'actor': 'forged'}])
        with self.assertRaises(OriginDenied):
            main(['status'], invoked_as='git')

    def test_every_frame_is_authenticated_and_nothing_prints_before_valid_terminal(self):
        self.success()
        self.peer.require.side_effect = [None, None, OriginDenied('different process')]
        with self.assertRaises(OriginDenied):
            main(['status'], invoked_as='git')
        self.write.assert_not_called()
        self.peer.close.assert_called_once()

    def test_bad_terminal_shape_boolean_code_and_payload_digest_fail_closed(self):
        for change in ({'code': True}, {'code': 256}, {'kind': 'success'}, {'extra': 'forbidden'}, {'status': None}):
            terminal = {'kind': 'exit', 'code': 0, 'status': 'OK', 'receipt': None} | change
            self.success(terminal=terminal)
            with self.subTest(change=change), self.assertRaises(OriginDenied):
                main(['status'], invoked_as='git')
        frames = blob('stdout', b'value')
        frames[0]['sha256'] = '0' * 64
        self.replies(frames)
        with self.assertRaises(OriginDenied):
            main(['status'], invoked_as='git')
        self.write.assert_not_called()

    def test_closed_stdio_is_failure_and_peer_always_disposed(self):
        self.success()
        self.write.return_value = 0
        self.write.side_effect = None
        with self.assertRaises(OriginDenied):
            main(['status'], invoked_as='git')
        self.peer.close.assert_called_once()

    def test_fixed_image_launcher_is_only_isolated_import_and_rpc_main(self):
        path = Path(__file__).resolve().parents[1] / 'runtime/git/launcher.py'
        raw = path.read_text()
        ast.parse(raw)
        self.assertTrue(raw.startswith('#!/usr/bin/python3 -I\n'))
        self.assertIn("sys.path.insert(0, '/opt/uas')", raw)
        self.assertIn('from uas.git_launcher import main', raw)
        for forbidden in ('subprocess', 'execve', 'GIT_SSH_COMMAND', 'SSH_AUTH_SOCK'):
            self.assertNotIn(forbidden, raw)


class SupervisorReplyTests(unittest.TestCase):
    """The caller cannot hold the Room lifecycle lock through blocked output."""
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.channel = Mock()
        self.locked = 0
        self.nonblocking = False
        self.channel.gettimeout.return_value = 40
        self.channel.setblocking.side_effect = lambda value: setattr(self, 'nonblocking', not value)
        self.channel.settimeout.side_effect = lambda value: setattr(self, 'nonblocking', value == 0)
        owner = self
        class Lock:
            def __enter__(self):
                owner.locked += 1
            def __exit__(self, *_):
                owner.locked -= 1
        self.lock = Lock
        self.revoked = False
        def current():
            self.assertEqual(1, self.locked)
            if self.revoked:
                raise OriginDenied('revoked')
            return True
        self.authority = SimpleNamespace(current=Mock(side_effect=current), close=Mock())
        def bind(record):
            self.assertEqual(1, self.locked)
            return self.authority
        self.child = SimpleNamespace(bind=Mock(side_effect=bind))
        self.request = {'kind': 'git', 'id': 'op1', 'invoked_as': 'git', 'argv': ['status'], 'cwd': '/project'}
        self.record = SimpleNamespace(data=json.dumps(self.request).encode())
        self.coordinator = SimpleNamespace(request=Mock(return_value={'code': 0, 'status': 'OK',
            'stdout': b'x' * 40000, 'stderr': b'warning', 'receipt': None}))
        self.frames = []
        self.revoke_after_frame = False
        self.backpressure = 0
        def send(channel, value):
            self.assertIs(channel, self.channel)
            if self.locked:
                self.assertTrue(self.nonblocking, 'blocking socket send held lifecycle lock')
            if self.backpressure:
                self.backpressure -= 1
                raise BlockingIOError()
            self.frames.append(value)
            if self.revoke_after_frame:
                self.revoked = True
        self.stack.enter_context(patch('uas.git_controller.enable'))
        self.stack.enter_context(patch('uas.git_controller.receive', return_value=nullcontext(self.record)))
        self.stack.enter_context(patch('uas.git_controller.send', side_effect=send))
        self.stack.enter_context(patch('uas.git_worker_native.send', side_effect=send))
        def writable(*args):
            self.assertEqual(0, self.locked, 'backpressure wait held lifecycle lock')
            self.assertLessEqual(args[3], .1)
            return ([], [self.channel], [])
        self.select = self.stack.enter_context(patch('uas.git_controller.select.select', side_effect=writable))

    def serve(self):
        from uas.git_controller import serve_one
        return serve_one(self.channel, self.coordinator, self.child, lifecycle_lock=self.lock)

    def test_reply_frames_are_authenticated_without_holding_lifecycle_lock_during_send(self):
        self.serve()
        self.coordinator.request.assert_called_once_with(self.request, self.authority)
        self.child.bind.assert_called_once_with(self.record)
        self.assertEqual('exit', self.frames[-1]['kind'])
        self.assertGreaterEqual(self.authority.current.call_count, len(self.frames))
        self.authority.close.assert_called_once()
        self.assertFalse(self.nonblocking)

    def test_revocation_between_frames_stops_output_and_never_sends_success_terminal(self):
        self.revoke_after_frame = True
        self.serve()
        self.assertEqual(['blob', 'refused'], [frame['kind'] for frame in self.frames])
        self.authority.close.assert_called_once()

    def test_direct_rpc_policy_error_is_a_typed_refusal_and_closes_authority(self):
        self.coordinator.request.side_effect = GitPolicyError('UNSUPPORTED_GIT_COMMAND')
        self.serve()
        self.assertEqual([{'kind': 'refused', 'error': 'UNSUPPORTED_GIT_COMMAND', 'record': None}], self.frames)
        self.authority.close.assert_called_once()

    def test_backpressure_wait_releases_lifecycle_lock_and_rechecks_authority(self):
        self.backpressure = 1
        self.serve()
        self.select.assert_called_once_with([], [self.channel], [], .1)
        self.assertEqual('exit', self.frames[-1]['kind'])
        self.assertGreater(self.authority.current.call_count, len(self.frames))
        self.assertFalse(self.nonblocking)

    def test_absolute_disclosure_deadline_refuses_and_restores_channel_mode(self):
        with patch('uas.git_controller.time.monotonic', side_effect=[0, 6]):
            self.serve()
        self.assertEqual(['refused'], [frame['kind'] for frame in self.frames])
        self.assertFalse(self.nonblocking)
        self.select.assert_not_called()


if __name__ == '__main__':
    unittest.main()
