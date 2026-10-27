"""Opt-in hosted process-group cleanup evidence; no import-time kernel probes.

Run only in the existing unprivileged Linux hosted job with either
UAS_REQUIRE_PARTICIPANT_PROCESS_TESTS=1 or UAS_FORGE_EXECUTOR_TEST=1.
The fixed, digest-pinned fake gh has no network or real account credentials.
"""
import hashlib
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from uas.github_executor import GhSurfaceTransport
from uas.github_read import ProviderFailure


ENABLED = (os.environ.get('UAS_REQUIRE_PARTICIPANT_PROCESS_TESTS') == '1'
           or os.environ.get('UAS_FORGE_EXECUTOR_TEST') == '1')


@unittest.skipUnless(ENABLED, 'hosted-only executable process cleanup gate')
class ExecutorProcessTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, 'linux', 'enabled gate requires Linux')
        self.assertNotEqual(os.getuid(), 0, 'fixture must execute under an unprivileged UID')
        self.assertTrue(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
                        'enabled gate requires held pidfd support')
        self.assertTrue(hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'),
                        'enabled gate requires non-reaping exit observation')
        self.temp = tempfile.TemporaryDirectory(prefix='uas-gh-process-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.child_fd = self.leader_fd = None
        self.worker = self.process = None
        self.calls = []
        self.addCleanup(self.cleanup_owned_processes)

    def cleanup_owned_processes(self):
        # Cleanup never rediscovers a PID or signals a numeric PID/group. These
        # handles were acquired while the exact fixture processes were alive.
        for fd in (self.child_fd, self.leader_fd):
            if fd is not None:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if self.worker is not None:
            self.worker.join(1)
        if self.process is not None and (self.worker is None or not self.worker.is_alive()):
            # Test assertions already checked cleanup ordering; reap a leader
            # only as failure containment after signaling its held identity.
            self.real_wait(timeout=1)
        for fd in (self.child_fd, self.leader_fd):
            if fd is not None:
                os.close(fd)

    def transport(self, *, close_stdout=False, child=True):
        # gh --include: LF status, then CRLF headers/blank line (not raw HTTP):
        # https://github.com/cli/cli/blob/v2.87.3/pkg/cmd/api/api.go#L420-L424 (also L540-L555).
        source = (f'#!{sys.executable}\n'
                  'import os, signal, time\n')
        if child:
            source += (
                'child = os.fork()\n'
                'if child == 0:\n'
                + (' os.close(1)\n' if close_stdout else '')
                + ' os.kill(os.getpid(), signal.SIGSTOP)\n'
                ' signal.pause()\n'
                ' os._exit(9)\n'
                'os.waitpid(child, os.WUNTRACED)\n'
                f'with open({str(self.root / "child.tmp")!r}, "w") as out:\n'
                ' out.write(str(child))\n'
                f'os.replace({str(self.root / "child.tmp")!r}, {str(self.root / "child.pid")!r})\n'
                f'while not os.path.exists({str(self.root / "release")!r}):\n'
                ' time.sleep(.001)\n'
                'os.write(1, b"HTTP/1.1 200 OK\\nContent-Type: application/json\\r\\n\\r\\n{}")\n'
                'os._exit(0)\n')
        else:
            source += 'signal.pause()\n'
        executable = self.root / 'gh-fixed-fixture'
        executable.write_text(source)
        executable.chmod(0o555)
        transport = GhSurfaceTransport(
            executable, hashlib.sha256(executable.read_bytes()).hexdigest(), 'fixture-actor',
            lambda actor, host: {'GH_TOKEN': 'ACCOUNT_FREE_FIXTURE_ONLY'}, timeout=.6)
        self.addCleanup(transport.close)
        return transport

    def spawn(self, *args, **kwargs):
        self.process = self.real_popen(*args, **kwargs)
        self.real_wait = self.process.wait
        self.leader_fd = os.pidfd_open(self.process.pid)

        def wait(*args, **kwargs):
            self.calls.append('reap')
            return self.real_wait(*args, **kwargs)

        self.process.wait = wait
        return self.process

    def kill_group(self, pgid, sig):
        self.assertEqual(pgid, self.process.pid)
        self.assertEqual(sig, signal.SIGKILL)
        self.assertIsNone(self.process.returncode, 'leader already reaped before group cleanup')
        # Unlike checking Popen.returncode alone, this also catches reaping via
        # a direct waitpid: the owned child must still be waitable here.
        observed = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if self.child_fd is not None:
            self.assertIsNotNone(observed, 'fixture leader must have exited before group cleanup')
            self.assertEqual(observed.si_pid, self.process.pid)
        self.calls.append('signal-owned-group')
        return self.real_killpg(pgid, sig)

    def assert_cleanup(self):
        self.assertIn('signal-owned-group', self.calls)
        self.assertIn('reap', self.calls)
        self.assertLess(self.calls.index('signal-owned-group'), self.calls.index('reap'))
        self.assertTrue(select.select([self.leader_fd], [], [], .1)[0], 'held leader has not exited')
        self.assertIsNotNone(self.process.returncode, 'leader was not reaped after group signal')
        if self.child_fd is not None:
            self.assertTrue(select.select([self.child_fd], [], [], .1)[0],
                            'held descendant survived executor cleanup')

    def descendant_case(self, *, close_stdout):
        transport = self.transport(close_stdout=close_stdout)
        self.real_popen, self.real_killpg = subprocess.Popen, os.killpg
        outcome = {}

        def execute():
            try:
                outcome['response'] = transport('repos/owner/project')
            except BaseException as error:
                outcome['error'] = error

        with patch('uas.github_executor.subprocess.Popen', side_effect=self.spawn), \
             patch('uas.github_executor.os.killpg', side_effect=self.kill_group):
            self.worker = threading.Thread(target=execute, daemon=True)
            self.worker.start()
            deadline = time.monotonic() + .5
            marker = self.root / 'child.pid'
            while not marker.exists() and self.worker.is_alive() and time.monotonic() < deadline:
                time.sleep(.001)
            self.assertTrue(marker.exists(), 'fake gh did not publish its stopped child identity')
            # The leader has not been released; it owns this stopped, unreaped
            # child. Pin that exact identity before allowing the leader to exit.
            self.child_fd = os.pidfd_open(int(marker.read_text()))
            self.assertFalse(select.select([self.child_fd], [], [], 0)[0])
            (self.root / 'release').touch()
            self.worker.join(.8)
            self.assertFalse(self.worker.is_alive(), 'executor exceeded its bounded timeout')
        self.assert_cleanup()
        if close_stdout:
            self.assertNotIn('error', outcome)
            self.assertEqual(200, outcome['response'].status)
            self.assertEqual(b'{}', outcome['response'].body)
        else:
            self.assertNotIn('response', outcome)
            self.assertIsInstance(outcome.get('error'), ProviderFailure)
            self.assertEqual('TIMEOUT', outcome['error'].code)

    def test_exited_leader_descendant_holding_stdout_is_killed_on_timeout(self):
        self.descendant_case(close_stdout=False)

    def test_normal_response_kills_descendant_even_after_it_closed_stdout(self):
        self.descendant_case(close_stdout=True)

    def test_selector_registration_failure_cleans_up_actual_spawned_leader(self):
        transport = self.transport(child=False)
        self.real_popen, self.real_killpg = subprocess.Popen, os.killpg

        class BrokenSelector:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def register(self, *_):
                raise RuntimeError('fixture selector registration failure')

        with patch('uas.github_executor.subprocess.Popen', side_effect=self.spawn), \
             patch('uas.github_executor.os.killpg', side_effect=self.kill_group), \
             patch('uas.github_executor.selectors.DefaultSelector', BrokenSelector):
            with self.assertRaisesRegex(RuntimeError, 'fixture selector registration failure'):
                transport('repos/owner/project')
        self.assert_cleanup()


if __name__ == '__main__':
    unittest.main()
