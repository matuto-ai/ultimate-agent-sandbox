"""Inert CLI/pipe/clock diagnostics tests; no real process, socket or SELinux."""
import ast
from pathlib import Path
import subprocess
import sys
from unittest import TestCase
from unittest.mock import Mock, patch

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
try:
    import room_service
finally:
    sys.path.pop(0)


class CLIDiagnosticsTests(TestCase):
    def exercise(self, fault=None, *, noisy=False):
        checks = {}
        clock = [0.0]
        calls = {'select': [], 'read': 0, 'wait': 0, 'killed': False}
        error = OSError('inert original ' + str(fault))
        stdout = Mock(); stdout.fileno.return_value = 21
        stderr = Mock(); stderr.fileno.return_value = 22
        process = Mock(pid=73, stdout=stdout, stderr=stderr, returncode=None)
        listener = Mock()
        channel = Mock(); channel.__enter__ = Mock(return_value=channel)
        channel.__exit__ = Mock(return_value=False)
        listener.accept.return_value = (channel, None)
        if fault == 'accept-call': listener.accept.side_effect = error
        payload = b'x' * 65536 if noisy else b'{"code":128}\n'
        chunks = {21: [payload, b''], 22: [b'inert stderr\n', b'']}
        if fault in ('flood', 'collect-flood'): chunks[21] = [b'x'] * 20 + [b'']
        def select(readers, _write, _error, timeout):
            calls['select'].append((listener in readers, timeout))
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 5)
            if listener in readers:
                if fault in ('accept-timeout', 'early-exit', 'kill', 'cleanup-wait'):
                    clock[0] += timeout
                    return [], [], []
                if fault == 'flood':
                    clock[0] += min(1, timeout)
                    return [stream for stream in readers if stream != listener], [], []
                clock[0] += .1
                return [listener], [], []
            if fault == 'collect-timeout' and not calls['killed']:
                clock[0] += timeout
                return [], [], []
            clock[0] += min(1, timeout) if fault == 'collect-flood' else .1
            return list(readers), [], []
        def read(fd, amount):
            self.assertEqual(65536, amount)
            calls['read'] += 1
            if fault == 'read' and calls['read'] == 1: raise error
            return chunks[fd].pop(0) if chunks[fd] else b''
        def wait(*, timeout):
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(timeout, 5)
            calls['wait'] += 1
            if fault == 'wait' and calls['wait'] == 1:
                raise subprocess.TimeoutExpired('inert', timeout)
            if fault == 'cleanup-wait': raise error
            process.returncode = 7 if fault == 'early-exit' else (-9 if calls['killed'] else 0)
            return process.returncode
        def poll():
            if fault == 'poll': raise error
            if fault == 'early-exit': process.returncode = 7
            return process.returncode
        def kill():
            self.assertIsNone(process.returncode, 'never signal a known reaped child')
            calls['killed'] = True
            if fault == 'kill': raise error
        process.wait.side_effect = wait
        process.poll.side_effect = poll
        process.kill.side_effect = kill
        if fault == 'close': stdout.close.side_effect = error
        serve = Mock(return_value=None)
        if fault == 'serve': serve.side_effect = error
        def setup(fd, blocking):
            self.assertFalse(blocking)
            if fault == 'pipe_setup' and fd == 22: raise error
        def launch(*args, **kwargs):
            self.assertEqual('launch', checks['stage'])
            self.assertEqual('in_progress', checks['status'])
            self.assertEqual(['docker', 'exec', 'a' * 64, '/usr/bin/python3', '-I',
                              '/opt/uas/uas/room_probe.py', 'denied-help'], args[0])
            self.assertEqual({'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}, kwargs)
            if fault == 'launch': raise error
            return process
        result = caught = None
        with patch.object(room_service.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(room_service.subprocess, 'Popen', side_effect=launch), \
             patch.object(room_service.select, 'select', side_effect=select), \
             patch.object(room_service.os, 'set_blocking', side_effect=setup), \
             patch.object(room_service.os, 'read', side_effect=read):
            try:
                result = room_service.observe_unrelated_cli(listener, 'a' * 64, serve, checks=checks)
            except BaseException as failure:
                caught = failure
        return checks, result, caught, error, process, serve, calls

    def test_complete_capture_is_not_itself_an_authority_refusal(self):
        checks, result, error, _, process, serve, _ = self.exercise()
        self.assertIsNone(error)
        self.assertEqual((None, b'{"code":128}\n', b'inert stderr\n'), result)
        self.assertEqual('collected', checks['status'])
        self.assertTrue(checks['connected'])
        self.assertNotIn('authority_refusal_proved', checks)
        self.assertEqual({'status': 'observed', 'returncode': 0}, checks['pre_cleanup_poll'])
        self.assertEqual(0, checks['returncode'])
        self.assertTrue(checks['cleanup']['reaped'])
        self.assertEqual([], checks['cleanup']['errors'])
        self.assertTrue(all(checks[name]['eof_observed'] for name in ('stdout', 'stderr')))
        process.kill.assert_not_called(); serve.assert_called_once()
        process.stdout.close.assert_called_once(); process.stderr.close.assert_called_once()

    def test_every_operation_failure_retains_first_error_and_owned_cleanup(self):
        for fault, stage in (('launch','launch'), ('pipe_setup','pipe_setup'),
                             ('accept-call','accept'), ('serve','serve'), ('read','collect')):
            with self.subTest(fault=fault):
                checks, result, caught, original, process, _, _ = self.exercise(fault)
                self.assertIs(original, caught)
                self.assertIsNone(result)
                self.assertEqual(('failed', stage), (checks['status'], checks['stage']))
                self.assertIn(stage, checks['stage_elapsed_seconds'])
                self.assertNotIn('authority_refusal_proved', checks)
                if fault != 'launch':
                    self.assertTrue(checks['cleanup']['kill_attempted'])
                    process.stdout.close.assert_called_once(); process.stderr.close.assert_called_once()
                if fault == 'pipe_setup': self.assertFalse(checks['stderr']['eof_observed'])
                if fault in ('accept-call', 'serve', 'read'):
                    self.assertEqual('{"code":128}\n', checks['stdout']['output'])
                    self.assertEqual(None, checks['pre_cleanup_poll']['returncode'])
                    self.assertEqual(-9, checks['returncode'])

    def test_no_connection_and_early_exit_never_count_as_refusal(self):
        for fault in ('accept-timeout', 'early-exit'):
            with self.subTest(fault=fault):
                checks, _, caught, _, process, serve, _ = self.exercise(fault)
                self.assertIsInstance(caught, TimeoutError)
                self.assertEqual('accept', checks['stage'])
                self.assertFalse(checks['connected'])
                serve.assert_not_called()
                self.assertEqual('{"code":128}\n', checks['stdout']['output'])
                self.assertNotIn('authority_refusal_proved', checks)
                if fault == 'early-exit':
                    self.assertEqual(7, checks['pre_cleanup_poll']['returncode'])
                    self.assertEqual(7, checks['returncode'])
                    process.kill.assert_not_called()

    def test_absolute_accept_deadline_is_not_reset_by_pipe_activity(self):
        checks, _, caught, _, _, serve, calls = self.exercise('flood')
        self.assertIsInstance(caught, TimeoutError)
        self.assertEqual('accept', checks['stage'])
        waits = [timeout for accepting, timeout in calls['select'] if accepting]
        self.assertEqual([5, 4, 3, 2, 1], waits)
        self.assertEqual(5, checks['cleanup']['started_elapsed_seconds'])
        serve.assert_not_called()

    def test_collection_timeout_or_wait_error_keeps_partial_output(self):
        for fault in ('collect-timeout', 'wait'):
            with self.subTest(fault=fault):
                checks, _, caught, _, _, _, _ = self.exercise(fault)
                self.assertIsInstance(caught, (TimeoutError, subprocess.TimeoutExpired))
                self.assertEqual('collect', checks['stage'])
                self.assertTrue(checks['connected'])
                self.assertEqual('{"code":128}\n', checks['stdout']['output'])
                self.assertTrue(checks['cleanup']['kill_attempted'])
                self.assertEqual(-9, checks['returncode'])

    def test_collection_and_cleanup_deadlines_are_not_reset_by_output(self):
        checks, _, caught, _, _, _, calls = self.exercise('collect-flood')
        self.assertIsInstance(caught, TimeoutError)
        self.assertEqual('collect', checks['stage'])
        waits = [round(timeout, 6) for accepting, timeout in calls['select'] if not accepting]
        self.assertEqual([5, 4, 3, 2, 1] * 2, waits)
        self.assertEqual(5.1, checks['cleanup']['started_elapsed_seconds'])
        self.assertEqual(10.1, checks['elapsed_seconds'])
        self.assertFalse(checks['stdout']['eof_observed'])
        self.assertIn('drain', [entry['operation'] for entry in checks['cleanup']['errors']])

    def test_cleanup_failure_never_masks_first_failure_or_becomes_pass(self):
        for fault, operation in (('kill', 'kill'), ('cleanup-wait', 'wait'),
                                 ('close', 'stdout_close'), ('poll', 'poll')):
            with self.subTest(fault=fault):
                checks, _, caught, _, process, _, _ = self.exercise(fault)
                if fault in ('kill', 'cleanup-wait'):
                    self.assertIsInstance(caught, TimeoutError)
                    self.assertEqual('accept', checks['stage'])
                else:
                    self.assertRegex(str(caught), 'cleanup incomplete')
                    self.assertEqual('cleanup', checks['stage'])
                    process.kill.assert_not_called()
                self.assertEqual('failed', checks['status'])
                self.assertIn(operation, [entry['operation'] for entry in checks['cleanup']['errors']])
                process.stderr.close.assert_called_once()

    def test_output_retention_is_bounded_while_all_bytes_are_counted(self):
        checks, result, caught, _, _, _, _ = self.exercise(noisy=True)
        self.assertIsNone(caught)
        self.assertEqual(4096, len(result[1]))
        self.assertEqual(65536, checks['stdout']['bytes'])
        self.assertTrue(checks['stdout']['truncated'])
        self.assertTrue(checks['stdout']['eof_observed'])
        self.assertLessEqual(len(checks['stdout']['output']), 4096)

    def test_caller_still_requires_actual_authority_refusal_and_no_worker(self):
        text = (VM/'room_service.py').read_text()
        source = ast.parse(text)
        prove = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                     and node.name == 'prove_service')
        code = ast.unparse(prove)
        self.assertLess(code.index("checks['unrelated_task'] = {}"), code.index('observe_unrelated_cli('))
        self.assertIn('lambda channel: serve_one(channel, service, authority, lifecycle_lock=supervisor._locked)', code)
        self.assertIn("observed['returncode'] == 0", code)
        self.assertIn("denied is None", code)
        self.assertIn("json.loads(stdout) == {'code': 128}", code)
        self.assertIn("effects['worker'] == 0", code)
        self.assertIn("not observed['stdout']['truncated']", code)
        self.assertIn("not observed['stderr']['truncated']", code)
        self.assertLess(code.index('same-UID unrelated task admitted'), code.index("observed['authority_refusal_proved'] = True"))
