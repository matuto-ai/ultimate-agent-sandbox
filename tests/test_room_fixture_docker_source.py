"""Pure source checks for the hosted-only endpoint Docker smoke."""
import ast
from contextlib import contextmanager
import io
import json
from pathlib import Path
import re
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

SOURCE = Path(__file__).with_name('test_room_fixture_docker.py')


class RoomEndpointDockerSourceTests(unittest.TestCase):
    def test_hosted_guards_precede_any_test_effect(self):
        tree = ast.parse(SOURCE.read_text())
        case = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                    and node.name == 'RoomEndpointDockerSmoke')
        method = next(node for node in case.body if isinstance(node, ast.FunctionDef)
                      and node.name.startswith('test_'))
        body = ast.unparse(method)
        boundary = body.index('with tempfile.TemporaryDirectory(')
        for guard in ("self.assertEqual('true', os.environ.get('GITHUB_ACTIONS'))",
                      "self.assertEqual('Linux', os.environ.get('RUNNER_OS'))", 'self.assertRegex(IMAGE,'):
            self.assertLess(body.index(guard), boundary)
        self.assertEqual(1, len([node for node in case.body if isinstance(node, ast.FunctionDef)
                                and node.name.startswith('test_')]))

    def test_fixture_keeps_exact_narrow_source_and_honest_evidence_scope(self):
        source = SOURCE.read_text()
        self.assertIn("for drift in (None, 'writable', 'source'):", source)
        self.assertIn("expected.removesuffix(',readonly')", source)
        self.assertIn("self.assertEqual(before_starts, backend.start_calls)", source)
        self.assertIn("self.assertEqual('created', actual['State']['Status'])", source)
        self.assertIn("self.assertEqual('EROFS', probe['project_write'])", source)
        self.assertIn("'scope': 'real mount/resource admission only; no Broker, SELinux or network qualification'", source)
        self.assertIn('self.assertLess(seconds, 20,', source)
        for forbidden in ('--privileged', 'system prune', 'os.chown', 'os.kill', 'NativeRpcIO'):
            self.assertNotIn(forbidden, source)
        self.assertEqual(1, source.count('subprocess.Popen('))
        self.assertIn("['docker', 'exec', container, '/fixture', '--probe', TARGET]", source)
        self.assertIn("DockerExecAPI('/var/run/docker.sock', timeout=remaining(deadline))", source)
        self.assertIn("'Cmd': ['/fixture']", source)
        self.assertIn("self.assertIsNone(backend._run(['inspect', '--type', 'container', container], missing_ok=True))", source)
        self.assertIn("not_tested=['Python import/readiness barrier', 'TCG latency', 'SELinux']", source)
        self.assertIn("if cleanup_receipt['errors'] and primary is None:", source)
        self.assertIn('EXEC_SECONDS = 10', source)


class FixedExecDiagnosticSourceTests(unittest.TestCase):
    """Only audited helper AST and inert mocks execute, never hosted test code."""
    def helpers(self):
        names = {'remaining', 'failure', 'exec_watchdog', 'observe_api_start', 'observe_cli_probe', 'observe_fixed_exec'}
        tree = ast.parse(SOURCE.read_text())
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual(names, {node.name for node in nodes})
        clock = [0.0]
        namespace = dict(time=SimpleNamespace(monotonic=lambda: clock[0]), re=re, json=json,
                         struct=struct, EXEC_SECONDS=10, OUTPUT_LIMIT=4096, STARTUP_LIMIT=256,
                         TARGET='/uas/endpoint-smoke', contextmanager=contextmanager,
                         signal=SimpleNamespace(ITIMER_REAL=0, SIGALRM=14, SIG_BLOCK=0,
                            getitimer=Mock(return_value=(0.0, 0.0)), pthread_sigmask=Mock(return_value=set()),
                            getsignal=Mock(return_value='prior-handler'), signal=Mock(), setitimer=Mock()))
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<audited-fixed-exec>', 'exec'), namespace)
        return namespace, clock

    def api_case(self, *, fault=None, raw=None, inspect=None, fragmented=False, slow=False,
                 pid_after_startup=False):
        namespace, clock = self.helpers()
        checks = {}
        error = OSError('inert API ' + str(fault))
        marker = b'fixture start=2 uid=65532\n'
        raw = struct.pack('>B3sI', 1, b'\0' * 3, len(marker)) + marker if raw is None else raw
        content = io.BytesIO(raw)
        channel = Mock()
        timeouts = []
        channel.settimeout.side_effect = lambda timeout: timeouts.append(timeout)
        def recv(length):
            if fault == 'recv': raise error
            clock[0] += min(timeouts[-1], 1 if slow else .01)
            return content.read(min(1, length) if fragmented else length)
        channel.recv.side_effect = recv
        stream = SimpleNamespace(channel=channel, close=Mock())
        if fault in ('close', 'recv+close'): stream.close.side_effect = error
        if fault == 'recv+close': channel.recv.side_effect = error
        api = Mock()
        observed = {'ID': 'e' * 64, 'ContainerID': 'c' * 64, 'Running': True, 'Pid': 321}
        if inspect: observed.update(inspect)
        def operation(name, result):
            def call(*_):
                clock[0] += .1
                if fault == name: raise error
                if name == 'inspect' and pid_after_startup and content.tell() < len(raw):
                    return {**result, 'Pid': 0}
                return result
            return call
        api.create.side_effect = operation('create', 'e' * 64)
        api.start.side_effect = operation('start', stream)
        api.inspect.side_effect = operation('inspect', observed)
        factory = Mock(return_value=api)
        namespace['DockerExecAPI'] = factory
        caught = None
        try: namespace['observe_api_start']('c' * 64, checks, 10)
        except BaseException as failure: caught = failure
        return checks, caught, error, api, stream, timeouts, clock

    def test_actual_path_contract_uses_exact_api_ids_and_fixed_non_tty_command(self):
        checks, caught, _, api, stream, _, _ = self.api_case(fragmented=True)
        self.assertIsNone(caught)
        self.assertEqual('observed', checks['status'])
        api.create.assert_called_once_with('c' * 64, {'AttachStdin': False, 'AttachStdout': True,
            'AttachStderr': True, 'Tty': False, 'Cmd': ['/fixture']})
        api.start.assert_called_once_with('e' * 64)
        api.inspect.assert_called_once_with('e' * 64)
        self.assertEqual('fixture start=2 uid=65532\n', checks['stdout'])
        self.assertEqual({'create', 'start', 'inspect', 'startup_bytes'}, set(checks['stages']))
        self.assertEqual(321, checks['inspect']['Pid'])
        self.assertTrue(checks['multiplex_hex'])
        self.assertNotIn('authority', checks)
        stream.close.assert_called_once_with()

    def test_api_failure_stages_retain_primary_and_close_only_acquired_stream(self):
        for fault in ('create', 'start', 'inspect', 'recv', 'recv+close'):
            with self.subTest(fault=fault):
                checks, caught, error, api, stream, _, _ = self.api_case(fault=fault)
                self.assertIs(error, caught)
                self.assertEqual('failed', checks['status'])
                self.assertEqual(int(fault not in ('create', 'start')), stream.close.call_count)
                self.assertEqual(1, api.create.call_count)
                if fault == 'recv+close': self.assertEqual(1, len(checks['cleanup_errors']))

    def test_api_cleanup_failure_prevents_success(self):
        checks, caught, _, _, _, _, _ = self.api_case(fault='close')
        self.assertIsInstance(caught, AssertionError)
        self.assertEqual('failed', checks['status'])
        self.assertEqual(1, len(checks['cleanup_errors']))

    def test_api_exact_inspect_id_container_running_and_integer_pid_are_required(self):
        for mutation in ({'ID': 'f' * 64}, {'ContainerID': 'd' * 64}, {'Running': 1},
                         {'Running': False}, {'Pid': True}, {'Pid': 0}, {'Pid': -1}, {'Pid': '321'}):
            with self.subTest(mutation=mutation):
                checks, caught, _, _, stream, _, _ = self.api_case(inspect=mutation)
                self.assertIsInstance(caught, AssertionError)
                self.assertEqual('inspect', checks['stage'])
                self.assertTrue(checks['multiplex_hex'])
                self.assertEqual('fixture start=2 uid=65532\n', checks['stdout'])
                stream.close.assert_called_once()

    def test_upgrade_ack_is_not_task_readiness_and_final_inspect_follows_startup_bytes(self):
        # Models hosted Docker28.0.4's observed Running=true/Pid=0 immediately
        # after upgrade. This is a mock sequence regression, not a daemon run.
        checks, caught, _, api, stream, _, _ = self.api_case(
            fragmented=True, pid_after_startup=True)
        self.assertIsNone(caught)
        self.assertEqual(['create', 'start', 'startup_bytes', 'inspect'], list(checks['stages']))
        self.assertEqual(321, checks['inspect']['Pid'])
        self.assertEqual('observed', checks['status'])
        self.assertEqual(1, api.create.call_count)
        api.start.assert_called_once_with('e' * 64)
        api.inspect.assert_called_once_with('e' * 64)
        stream.close.assert_called_once()

    def test_api_fragment_eof_invalid_header_oversize_and_wrong_marker_fail(self):
        frame = lambda kind, data: struct.pack('>B3sI', kind, b'\0' * 3, len(data)) + data
        for raw in (b'', b'\1\0', struct.pack('>B3sI', 1, b'\0' * 3, 99) + b'partial',
                    struct.pack('>B3sI', 1, b'\0' * 3, 257),
                    struct.pack('>B3sI', 1, b'bad', 1) + b'x', frame(0, b'x'),
                    frame(1, b'fixture start=2 uid=0\n'), frame(2, b'error\n'),
                    frame(1, b'x') * 17, frame(1, b'x' * 256) + frame(1, b'x')):
            with self.subTest(raw=raw[:16]):
                checks, caught, _, _, stream, _, _ = self.api_case(raw=raw)
                self.assertIsInstance(caught, AssertionError)
                self.assertLessEqual(len(checks['multiplex_hex']), 2048)
                self.assertLessEqual(len(checks['stdout']), 256)
                if len(raw) <= 8:
                    self.assertEqual(raw.hex(), checks['multiplex_hex'])
                stream.close.assert_called_once()

    def test_api_trickled_bytes_do_not_reset_absolute_three_second_deadline(self):
        checks, caught, _, _, _, timeouts, clock = self.api_case(fragmented=True, slow=True)
        self.assertIsInstance(caught, TimeoutError)
        self.assertAlmostEqual(3, clock[0])
        self.assertGreater(len(timeouts), 1)
        self.assertEqual(sorted(timeouts, reverse=True), timeouts)
        self.assertTrue(checks['multiplex_hex'])

    def cli_case(self, *, fault=None, flood=False, noisy=False):
        namespace, clock = self.helpers()
        checks = {}
        error = OSError('inert CLI ' + str(fault))
        output = b'x' * 65536 if noisy else b'{"uid":65532}\n'
        chunks = {21: [output, b''], 22: [b'']}
        stdout, stderr = Mock(), Mock()
        stdout.fileno.return_value = 21; stderr.fileno.return_value = 22
        process = Mock(pid=73, stdout=stdout, stderr=stderr, returncode=None)
        killed = [False]
        waits = []
        def launch(*args, **kwargs):
            self.assertEqual(['docker', 'exec', 'c' * 64, '/fixture', '--probe', '/uas/endpoint-smoke'], args[0])
            self.assertEqual(dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE), kwargs)
            if fault == 'popen': raise error
            return process
        def select(readers, _write, _error, timeout):
            waits.append(timeout)
            if fault == 'select': raise error
            stalled = fault in ('kill', 'cleanup_wait', 'collect_timeout') and not killed[0]
            clock[0] += min(timeout, 1 if flood or stalled else .05)
            return ([], [], []) if stalled else (list(readers), [], [])
        def read(fd, count):
            self.assertEqual(65536, count)
            if fault in ('read', 'read+poll'): raise error
            return b'x' if flood else chunks[fd].pop(0)
        def wait(*, timeout):
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(timeout, 5)
            if fault == 'cleanup_wait' or (fault == 'wait' and not killed[0]): raise error
            if fault == 'read+poll' and not killed[0]:
                raise subprocess.TimeoutExpired('inert unreaped child', timeout)
            process.returncode = -9 if killed[0] else (7 if fault == 'exit' else 0)
            return process.returncode
        def poll():
            if fault in ('poll', 'read+poll'): raise error
            return process.returncode
        def kill():
            self.assertIsNone(process.returncode)
            killed[0] = True
            if fault == 'kill': raise error
        def set_blocking(fd, value):
            self.assertFalse(value)
            if fault == 'pipe_setup': raise error
        process.wait.side_effect = wait; process.poll.side_effect = poll; process.kill.side_effect = kill
        if fault == 'close': stdout.close.side_effect = error
        namespace.update(subprocess=SimpleNamespace(Popen=launch, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE),
            select=SimpleNamespace(select=select), os=SimpleNamespace(read=read, set_blocking=set_blocking))
        result = caught = None
        try: result = namespace['observe_cli_probe']('c' * 64, checks, 10)
        except BaseException as failure: caught = failure
        return checks, result, caught, error, process, waits, clock

    def test_cli_fixed_probe_captures_both_streams_exit_and_precleanup_poll(self):
        checks, result, caught, _, process, _, _ = self.cli_case()
        self.assertIsNone(caught)
        self.assertEqual(b'{"uid":65532}\n', result)
        self.assertEqual({'popen', 'read', 'exit'}, set(checks['stages']))
        self.assertEqual({'status': 'observed', 'returncode': 0}, checks['pre_cleanup_poll'])
        self.assertTrue(all(checks[name]['eof'] for name in ('stdout', 'stderr')))
        self.assertTrue(checks['reaped']); self.assertEqual(0, checks['returncode'])
        process.kill.assert_not_called()

    def test_cli_failure_retains_primary_and_reaps_only_own_child(self):
        for fault in ('popen', 'pipe_setup', 'select', 'read', 'wait'):
            with self.subTest(fault=fault):
                checks, result, caught, error, process, _, _ = self.cli_case(fault=fault)
                self.assertIs(error, caught)
                self.assertIsNone(result)
                self.assertEqual('failed', checks['status'])
                self.assertEqual(int(fault != 'popen'), process.kill.call_count)
                if fault != 'popen':
                    self.assertTrue(checks['reaped'])
                    self.assertEqual(-9, checks['returncode'])
                    process.stdout.close.assert_called_once(); process.stderr.close.assert_called_once()

    def test_cli_output_flood_does_not_reset_five_second_deadline(self):
        checks, _, caught, _, process, waits, clock = self.cli_case(flood=True)
        self.assertIsInstance(caught, TimeoutError)
        self.assertEqual([5, 4, 3, 2, 1, 1], waits)
        self.assertEqual(6, clock[0])
        self.assertEqual(4, checks['stdout']['bytes'])
        self.assertTrue(checks['kill_attempted']); process.kill.assert_called_once()

    def test_cli_oversized_output_is_retained_bounded_and_never_passes(self):
        checks, _, caught, _, process, _, _ = self.cli_case(noisy=True)
        self.assertIsInstance(caught, AssertionError)
        self.assertEqual(65536, checks['stdout']['bytes'])
        self.assertEqual(4096, len(checks['stdout']['output']))
        process.kill.assert_not_called()

    def test_cli_cleanup_errors_fail_and_never_replace_primary(self):
        for fault in ('kill', 'cleanup_wait', 'poll', 'close'):
            with self.subTest(fault=fault):
                checks, _, caught, _, process, _, _ = self.cli_case(fault=fault)
                self.assertIsInstance(caught, TimeoutError if fault in ('kill', 'cleanup_wait') else AssertionError)
                self.assertEqual('failed', checks['status'])
                self.assertTrue(checks['cleanup_errors'])
                process.stderr.close.assert_called_once()

    def test_cli_primary_and_poll_failure_still_kills_and_reaps_own_live_child(self):
        checks, _, caught, original, process, _, _ = self.cli_case(fault='read+poll')
        self.assertIs(original, caught)
        self.assertEqual('failed', checks['pre_cleanup_poll']['status'])
        self.assertTrue(checks['kill_attempted']); self.assertTrue(checks['reaped'])
        self.assertEqual(-9, checks['returncode'])
        process.kill.assert_called_once()
        self.assertIn('poll', [error['operation'] for error in checks['cleanup_errors']])

    def test_cli_failed_collection_retains_postkill_output_and_eof(self):
        checks, _, caught, _, _, _, clock = self.cli_case(fault='collect_timeout')
        self.assertIsInstance(caught, TimeoutError)
        self.assertEqual([], checks['cleanup_errors'])
        self.assertEqual('{"uid":65532}\n', checks['stdout']['output'])
        self.assertTrue(all(checks[name]['eof'] for name in ('stdout', 'stderr')))
        self.assertEqual(-9, checks['returncode'])
        self.assertLess(clock[0], 6)

    def test_hard_watchdog_restores_handler_and_timer_on_success_or_expiry(self):
        for expire in (False, True):
            namespace, _ = self.helpers()
            signal = namespace['signal']; checks = {}
            caught = None
            try:
                with namespace['exec_watchdog'](checks, 10):
                    handler = signal.signal.call_args.args[1]
                    if expire: handler(14, None)
            except BaseException as error: caught = error
            self.assertEqual(expire, isinstance(caught, TimeoutError))
            self.assertEqual(expire, checks['watchdog']['fired'])
            self.assertEqual([], checks['watchdog']['cleanup_errors'])
            self.assertEqual([(0, 10), (0, 0.0, 0.0)], [call.args for call in signal.setitimer.call_args_list])
            self.assertEqual((14, 'prior-handler'), signal.signal.call_args.args)

    def test_watchdog_refuses_prearmed_or_blocked_timer_without_mutation(self):
        for conflict in ('armed', 'blocked'):
            namespace, _ = self.helpers()
            signal = namespace['signal']
            if conflict == 'armed': signal.getitimer.return_value = (7.0, 0.0)
            else: signal.pthread_sigmask.return_value = {14}
            with self.assertRaises(AssertionError):
                with namespace['exec_watchdog']({}, 10): self.fail('must not enter')
            signal.signal.assert_not_called(); signal.setitimer.assert_not_called()

    def test_watchdog_uses_remaining_budget_and_restores_handler_if_arming_fails(self):
        namespace, clock = self.helpers()
        signal = namespace['signal']
        signal.getsignal.side_effect = lambda *_: clock.__setitem__(0, 2) or 'prior-handler'
        error = OSError('inert timer arm failure')
        signal.setitimer.side_effect = [error, None]
        with self.assertRaises(OSError) as caught:
            with namespace['exec_watchdog']({}, 10): self.fail('must not enter')
        self.assertIs(error, caught.exception)
        self.assertEqual([(0, 8), (0, 0.0, 0.0)], [call.args for call in signal.setitimer.call_args_list])
        self.assertEqual((14, 'prior-handler'), signal.signal.call_args.args)

    def test_watchdog_interrupts_stalled_api_without_cli_or_success(self):
        namespace, clock = self.helpers()
        signal = namespace['signal']; checks = {}
        def blocked_api(*_):
            clock[0] = 10
            signal.signal.call_args.args[1](14, None)
        namespace['observe_api_start'] = Mock(side_effect=blocked_api)
        namespace['observe_cli_probe'] = Mock()
        with self.assertRaises(TimeoutError): namespace['observe_fixed_exec']('c' * 64, checks)
        namespace['observe_cli_probe'].assert_not_called()
        self.assertEqual('failed', checks['status'])
        self.assertTrue(checks['watchdog']['fired'])
        self.assertEqual((14, 'prior-handler'), signal.signal.call_args.args)

    def test_watchdog_cleanup_failure_fails_or_preserves_primary_and_attempts_both_restores(self):
        for primary in (None, OSError('inert body failure')):
            namespace, _ = self.helpers()
            signal = namespace['signal']; checks = {}
            signal.setitimer.side_effect = [None, OSError('inert timer cleanup')]
            caught = None
            try:
                with namespace['exec_watchdog'](checks, 10):
                    if primary: raise primary
            except BaseException as error: caught = error
            if primary: self.assertIs(primary, caught)
            else: self.assertIsInstance(caught, AssertionError)
            self.assertEqual((14, 'prior-handler'), signal.signal.call_args.args)
            self.assertEqual('restore_timer', checks['watchdog']['cleanup_errors'][0]['operation'])

    def test_cli_nonzero_exit_is_failure_not_probe_or_authority_success(self):
        checks, result, caught, _, process, _, _ = self.cli_case(fault='exit')
        self.assertIsInstance(caught, AssertionError)
        self.assertIsNone(result)
        self.assertEqual(7, checks['pre_cleanup_poll']['returncode'])
        process.kill.assert_not_called()

    def test_composition_shares_one_absolute_deadline_and_rejects_nonexact_container(self):
        namespace, clock = self.helpers()
        api = Mock(side_effect=lambda *_: clock.__setitem__(0, 3))
        cli = Mock(side_effect=lambda *_: clock.__setitem__(0, 10) or b'{}')
        namespace.update(observe_api_start=api, observe_cli_probe=cli)
        checks = {}
        with self.assertRaises(TimeoutError): namespace['observe_fixed_exec']('c' * 64, checks)
        self.assertEqual(10, api.call_args.args[-1]); self.assertEqual(10, cli.call_args.args[-1])
        self.assertEqual(10, checks['seconds'])
        self.assertIn('diagnostics only', checks['scope'])
        for container in ('short', '../other', 'C' * 64, None):
            with self.assertRaises(AssertionError): namespace['observe_fixed_exec'](container, {})
        self.assertEqual(1, api.call_count)
