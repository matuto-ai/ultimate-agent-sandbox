import os
import signal
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch
from uas.local_host_process import run_fixed
from uas.local_host_profile import HostProfileError
from tests.test_local_host_observe import FakeProcess, FakeSelector


class ProcessCustodyTests(unittest.TestCase):
    def exercise(self, *, cancel=None, lost=False, reap_error=False):
        process = FakeProcess()
        handlers = {signal.SIGCHLD: signal.SIG_DFL,
                    signal.SIGINT: object(), signal.SIGTERM: object()}
        originals = dict(handlers)
        events = []
        def sethandler(sig, handler):
            handlers[sig] = handler
            if cancel == 'setup' and sig == signal.SIGTERM and callable(handler):
                handler(sig, None)
        def spawn(*args, **kwargs):
            events.append('spawn')
            if cancel == 'spawn': handlers[signal.SIGTERM](signal.SIGTERM, None)
            return process
        def observe(*args):
            events.append('observe')
            if lost: raise ChildProcessError()
            self.assertIsNone(process.returncode)
            self.assertTrue(args[-1] & os.WNOWAIT)
            if cancel == 'observe' and callable(handlers[signal.SIGTERM]): handlers[signal.SIGTERM](signal.SIGTERM, None)
            return SimpleNamespace(si_pid=process.pid, si_code=os.CLD_EXITED, si_status=0)
        def kill(*args):
            self.assertIsNone(process.returncode)
            events.append('kill')
        def reap(timeout):
            events.append('reap')
            process.returncode = 0
            if reap_error: raise KeyboardInterrupt()
            return 0
        with ExitStack() as stack:
            for name, replacement in [('signal.getsignal',lambda sig:handlers[sig]),
                ('signal.signal',sethandler),('subprocess.Popen',spawn),
                ('selectors.DefaultSelector',FakeSelector),('os.read',lambda *_:b''),
                ('os.waitid',observe),('os.killpg',kill)]:
                stack.enter_context(patch('uas.local_host_process.'+name, replacement))
            process.wait = reap
            try:
                return run_fixed(['/fixed/tool'])
            finally:
                self.assertEqual(handlers, originals)
                if 'spawn' in events:
                    self.assertTrue(process.stdout.closed and process.stderr.closed)
                if lost or cancel == 'setup':
                    self.assertNotIn('kill', events)
                    self.assertNotIn('reap', events)
                else:
                    self.assertEqual(events.count('kill'), 1)
                    self.assertEqual(events.count('reap'), 1)
                    self.assertLess(events.index('kill'), events.index('reap'))
                    self.assertEqual(events[-1], 'reap')
                if cancel == 'setup': self.assertNotIn('spawn',events)

    def test_success_fences_descendants_before_reap(self):
        self.assertEqual(self.exercise(), '')

    def test_cancellation_during_setup_spawn_or_observation(self):
        for cut in ('setup','spawn','observe'):
            with self.subTest(cut=cut), self.assertRaisesRegex(HostProfileError,'CANCELLED'):
                self.exercise(cancel=cut)

    def test_lost_ownership_never_signals_numeric_group(self):
        with self.assertRaisesRegex(HostProfileError,'OWNERSHIP_LOST'):
            self.exercise(lost=True)

    def test_reap_that_raises_never_signals_or_reaps_again(self):
        with self.assertRaises(KeyboardInterrupt): self.exercise(reap_error=True)
