"""Owned lifecycle faults, not native SDK or production authority evidence."""
import os
import select
import signal
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch

from uas.claude_runtime import (_dispose_sdk_process, _pidfd_alive,
                                ClaudeSignals, FixtureClaudeReceiver)


class ClaudeSDKCleanupTests(unittest.TestCase):
    def test_group_disposition_precedes_only_reap_even_for_exited_host(self):
        for observation in (None, object()):
            with self.subTest(exited=observation is not None):
                events = []
                process = Mock(pid=12345, returncode=None)
                process.wait.side_effect = lambda **kw: events.append('reap')
                def owned(kind, fd, flags):
                    self.assertEqual((kind, fd), (os.P_PIDFD, 111))
                    self.assertEqual(flags, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    events.append('ownership')
                    return observation
                with patch('uas.claude_runtime.os.waitid', side_effect=owned), \
                     patch('uas.claude_runtime.select.select', return_value=([111], [], [])), \
                     patch('uas.claude_runtime.signal.pidfd_send_signal') as send, \
                     patch('uas.claude_runtime.os.killpg', side_effect=lambda *a: events.append('group')):
                    _dispose_sdk_process(process, 111, 222)
                self.assertEqual(events, ['ownership', 'group', 'reap'])
                self.assertEqual([call.args for call in send.call_args_list],
                                 [(111, signal.SIGTERM, None, 0), (222, signal.SIGKILL, None, 0),
                                  (111, signal.SIGKILL, None, 0)])
                process.poll.assert_not_called()

    def test_external_reap_or_unverifiable_ownership_never_signals_numeric_group(self):
        for error in (ChildProcessError(), OSError('ownership unavailable')):
            with self.subTest(error=type(error).__name__):
                process = Mock(pid=12345, returncode=None)
                with patch('uas.claude_runtime.os.waitid', side_effect=error), \
                     patch('uas.claude_runtime.select.select', return_value=([111], [], [])), \
                     patch('uas.claude_runtime.signal.pidfd_send_signal') as send, \
                     patch('uas.claude_runtime.os.killpg') as group:
                    if isinstance(error, ChildProcessError):
                        _dispose_sdk_process(process, 111, 222)
                    else:
                        with self.assertRaisesRegex(OSError, 'ownership unavailable'):
                            _dispose_sdk_process(process, 111, 222)
                group.assert_not_called()
                send.assert_any_call(222, signal.SIGKILL, None, 0)
                process.wait.assert_called_once()

    def test_cleanup_failure_still_disposes_held_identities_and_reaps(self):
        process = Mock(pid=12345, returncode=None)
        with patch('uas.claude_runtime.os.waitid', return_value=None), \
             patch('uas.claude_runtime.select.select', return_value=([111], [], [])), \
             patch('uas.claude_runtime.signal.pidfd_send_signal') as send, \
             patch('uas.claude_runtime.os.killpg', side_effect=OSError('group fault')):
            with self.assertRaisesRegex(OSError, 'group fault'):
                _dispose_sdk_process(process, 111, 222)
        send.assert_any_call(222, signal.SIGKILL, None, 0)
        send.assert_any_call(111, signal.SIGKILL, None, 0)
        process.wait.assert_called_once()

    def test_close_releases_every_resource_and_is_idempotent_after_failure(self):
        receiver = FixtureClaudeReceiver.__new__(FixtureClaudeReceiver)
        receiver.close_lock = threading.RLock()
        receiver.condition = threading.Condition()
        receiver.signals = ClaudeSignals('session')
        receiver.closing = False
        receiver.process = process = Mock()
        receiver.reader = receiver.stderr = None
        receiver.host_pidfd, receiver.native_pidfd = 111, 222
        receiver.db = db = Mock()
        receiver.owner = owner = Mock()
        db.close.side_effect = OSError('database close fault')
        process.stdin.close.side_effect = OSError('stream fault')
        with patch('uas.claude_runtime._dispose_sdk_process', side_effect=OSError('dispose fault')) as dispose, \
             patch('uas.claude_runtime.os.close') as close_fd:
            with self.assertRaisesRegex(OSError, 'dispose fault'):
                receiver.close()
            receiver.close()
        dispose.assert_called_once()
        self.assertEqual([call.args for call in close_fd.call_args_list], [(222,), (111,)])
        for resource in (process.stdin, process.stdout, process.stderr, db, owner):
            resource.close.assert_called_once()
        self.assertIsNone(receiver.process)
        self.assertTrue(receiver.closing)

    def test_real_exited_unreaped_leader_keeps_group_owned_until_stopped_child_disposed(self):
        # Synthetic, network-free child; not a Claude invocation. Its only
        # descendant stops itself before the leader exits without reaping it.
        script = ('import os, signal, time\n'
                  'child = os.fork()\n'
                  'if child == 0:\n'
                  ' os.kill(os.getpid(), signal.SIGSTOP)\n'
                  ' time.sleep(30)\n'
                  'else:\n'
                  ' os.waitpid(child, os.WUNTRACED)\n'
                  ' print(child, flush=True)\n'
                  ' time.sleep(30)\n')
        process = subprocess.Popen([sys.executable, '-c', script], start_new_session=True,
                                   stdout=subprocess.PIPE, text=True)
        host_fd = os.pidfd_open(process.pid)
        native_fd = None
        try:
            self.assertTrue(select.select([process.stdout], [], [], 3)[0])
            native_fd = os.pidfd_open(int(process.stdout.readline()))
            signal.pidfd_send_signal(host_fd, signal.SIGTERM)
            self.assertTrue(select.select([host_fd], [], [], 3)[0])
            self.assertIsNone(process.returncode, 'leader has not been reaped')
            self.assertTrue(_pidfd_alive(native_fd), 'stopped child survived host exit')
            _dispose_sdk_process(process, host_fd, native_fd, grace=0)
            self.assertTrue(select.select([native_fd], [], [], 3)[0])
            self.assertIsNotNone(process.returncode)
        finally:
            _dispose_sdk_process(process, host_fd, native_fd, grace=0)
            process.stdout.close()
            for fd in (native_fd, host_fd):
                if fd is not None:
                    os.close(fd)
