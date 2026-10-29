"""Source-only orchestration tests; never launch Pi/Node or native processes."""
import importlib.util
import io
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pi_partition_runner', ROOT / 'tests/pi/parallel-tests.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
NAMES = ['test_pi_runtime.C.test_a', 'test_pi_forge.C.test_b', 'test_pi_assignment.C.test_c',
         'test_pi_future.C.test_new']


class PiPartitionRunnerTests(unittest.TestCase):
    def setUp(self):
        runner.CANCELLED = None

    def test_partition_exact_unique_union_and_future_default(self):
        self.assertEqual([NAMES[:3], NAMES[3:]], runner.partition(NAMES))
        for bad in ([], NAMES + NAMES[:1], NAMES[1:], NAMES + ['other.C.test']):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                runner.partition(bad)

    def test_wait_reports_failure_or_absolute_timeout_without_reaping(self):
        process = Mock(returncode=None)
        with patch.object(runner, 'observe', return_value=1), self.assertRaises(RuntimeError):
            runner.wait_workers([process], 10)
        with patch.object(runner, 'observe', return_value=None), \
             patch.object(runner.time, 'monotonic', return_value=11), self.assertRaises(TimeoutError):
            runner.wait_workers([process], 10)
        with patch.object(runner, 'observe', return_value=0):
            runner.wait_workers([process], 0)
        process.poll.assert_not_called()
        process.wait.assert_not_called()

    def test_cleanup_signals_before_reaping_and_rejects_lost_ownership(self):
        events = []
        first, second = Mock(pid=101, returncode=None), Mock(pid=102, returncode=None)
        for process in (first, second):
            process.wait.side_effect = lambda timeout, p=process: events.append(('wait', p.pid))
        with patch.object(runner.os, 'waitid', return_value=None), \
             patch.object(runner.time, 'sleep'), \
             patch.object(runner.os, 'killpg', side_effect=lambda pid, sig: events.append((sig,pid))):
            runner.cleanup([first, second])
        self.assertEqual([(signal.SIGTERM,101), (signal.SIGTERM,102),
                          (signal.SIGKILL,101), (signal.SIGKILL,102), ('wait',101), ('wait',102)], events)
        for process in (Mock(pid=103, returncode=0), Mock(pid=104, returncode=None)):
            with patch.object(runner.os, 'waitid', side_effect=ChildProcessError), \
                 patch.object(runner.time, 'sleep'), patch.object(runner.os, 'killpg') as kill:
                with self.assertRaisesRegex(RuntimeError, 'ownership lost'):
                    runner.cleanup([process])
                kill.assert_not_called()
                process.wait.assert_called_once()

    def test_observe_uses_wnowait_for_exact_unreaped_child(self):
        process = Mock(pid=123, returncode=None)
        status = Mock(si_pid=123, si_code=runner.os.CLD_EXITED, si_status=0)
        with patch.object(runner.os, 'waitid', return_value=status) as wait:
            self.assertEqual(0, runner.observe(process))
        wait.assert_called_once_with(runner.os.P_PID, 123,
            runner.os.WEXITED | runner.os.WNOHANG | runner.os.WNOWAIT)
        process.poll.assert_not_called()
        process.wait.assert_not_called()

    def test_worker_rejects_drift_before_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manifest.json'
            path.write_text(json.dumps(NAMES))
            loader = Mock(errors=[], loadTestsFromNames=lambda _: unittest.TestSuite())
            with patch.object(runner.unittest, 'TestLoader', return_value=loader), \
                 patch.object(runner.unittest, 'TextTestRunner') as run:
                with self.assertRaisesRegex(ValueError, 'differs'):
                    runner.worker(path)
                run.assert_not_called()

    def test_worker_cannot_pass_skipped_native_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manifest.json'
            path.write_text(json.dumps(NAMES))
            loader = Mock(errors=[])
            result = Mock(testsRun=len(NAMES), skipped=[('test', 'not installed')])
            result.wasSuccessful.return_value = True
            with patch.object(runner.unittest, 'TestLoader', return_value=loader), \
                 patch.object(runner, 'ids', return_value=iter(NAMES)), \
                 patch.object(runner.unittest, 'TextTestRunner') as text:
                text.return_value.run.return_value = result
                self.assertEqual(1, runner.worker(path))

    def exercise(self, *, launch_failure=False, wait_failure=False, cleanup_failure=False, cancel_during_spawn=False):
        processes, launch = [], []
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'joined.jsonl'
            evidence.write_text('serial-contract\n')
            def popen(argv, **kwargs):
                if launch_failure and processes:
                    raise OSError('second launch failed')
                process = Mock(pid=100 + len(processes))
                processes.append(process)
                launch.append((argv, kwargs))
                if cancel_during_spawn:
                    runner.interrupted(signal.SIGTERM, None)
                Path(kwargs['env']['UAS_PI_EVIDENCE']).write_text(str(process.pid) + '\n')
                return process
            cleanup = Mock(side_effect=RuntimeError('cleanup failure') if cleanup_failure else None)
            with patch.dict(runner.os.environ, {'UAS_PI_EVIDENCE': str(evidence)}), \
                 patch.object(runner, 'discover', return_value=NAMES), \
                 patch.object(runner.subprocess, 'Popen', side_effect=popen), \
                 patch.object(runner, 'wait_workers', side_effect=RuntimeError('suite failed') if wait_failure else None), \
                 patch.object(runner, 'cleanup', cleanup), patch.object(runner.signal, 'signal'), \
                 patch('sys.stdout', new=io.StringIO()), patch('sys.stderr', new=io.StringIO()):
                if launch_failure or wait_failure or cleanup_failure or cancel_during_spawn:
                    expected = 'interrupted' if cancel_during_spawn else 'second launch' if launch_failure else 'suite failed' if wait_failure else 'cleanup failure'
                    with self.assertRaisesRegex(Exception, expected):
                        runner.run()
                else:
                    self.assertEqual(0, runner.run())
            cleanup.assert_called_once_with(processes)
            if cancel_during_spawn:
                self.assertEqual(1, len(processes))
            self.assertEqual('serial-contract\n' + ''.join(str(p.pid)+'\n' for p in processes), evidence.read_text())
        for argv, kwargs in launch:
            self.assertTrue(kwargs['start_new_session'])
            self.assertEqual(ROOT, kwargs['cwd'])
            self.assertEqual(str(ROOT / 'tests/pi/parallel-tests.py'), argv[1])
        if len(launch) == 2:
            self.assertNotEqual(launch[0][1]['env']['TMPDIR'], launch[1][1]['env']['TMPDIR'])
            self.assertNotEqual(launch[0][1]['env']['UAS_PI_EVIDENCE'], launch[1][1]['env']['UAS_PI_EVIDENCE'])

    def test_signal_during_spawn_return_retains_child_before_cleanup(self):
        self.exercise(cancel_during_spawn=True)

    def test_two_workers_isolated_joined_evidence(self):
        self.exercise()

    def test_partial_launch_failure_cleans_first(self):
        self.exercise(launch_failure=True)

    def test_suite_failure_retains_partial_evidence_and_primary_error(self):
        self.exercise(wait_failure=True, cleanup_failure=True)

    def test_cleanup_failure_cannot_be_success(self):
        self.exercise(cleanup_failure=True)

    def test_shell_contracts_precede_partitions_no_timeout_change(self):
        text = (ROOT / 'tests/pi/run-tests.sh').read_text()
        self.assertLess(text.index('node tests/pi/auth-contract.mjs'), text.index('python3 tests/pi/parallel-tests.py'))
        self.assertLess(text.index('node tests/pi/resume-contract.mjs'), text.index('python3 tests/pi/parallel-tests.py'))
        self.assertEqual(125, runner.WORK_SECONDS)
