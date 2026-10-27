"""Pure owner-hook tests: no native processes, sockets, procfs or Engine calls."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.peer import Readiness
from uas.pi_runtime import FixturePiRpcReceiver, NativeUnavailable
from uas.workstation_exec import ExecLaunch

SCOPE = {'room_id': 'alpha', 'participant_id': 'alice', 'run_id': 'run-1',
         'generation': 1, 'context_generation': 1}
STATE = {'api_baseline': '1.4.0', 'readiness': Readiness.SAFE.value,
         'runtime_id': 'runtime-1', 'session_id': 'session-1'}


class PiStartupDiagnosticTests(unittest.TestCase):
    def harness(self):
        stack = ExitStack(); self.addCleanup(stack.close)
        self.clock = 100.0
        stack.enter_context(patch('uas.pi_runtime.time.monotonic', side_effect=lambda: self.clock))
        database = Mock(); database.execute.return_value.fetchone.return_value = None
        self.database = database
        stack.enter_context(patch('uas.pi_runtime.sqlite3.connect', return_value=database))
        stack.enter_context(patch('uas.pi_runtime.os.set_blocking'))
        self.spawn = stack.enter_context(patch('uas.pi_runtime.subprocess.Popen', side_effect=AssertionError('no native execution')))
        self.thread = stack.enter_context(patch('uas.pi_runtime.threading.Thread'))
        self.thread.return_value.is_alive.return_value = False
        self.thread.return_value.ident = None
        self.printed = stack.enter_context(patch('builtins.print'))
        self.transport = SimpleNamespace(error=None, _stop=Mock())
        self.transport._stop.is_set.return_value = False
        for name in ('stdin', 'stdout', 'stderr'):
            stream = Mock(); stream.closed = False; stream.fileno.return_value = 11
            setattr(self.transport, name, stream)
        self.receiver = FixturePiRpcReceiver.__new__(FixturePiRpcReceiver)
        return stack

    def initialize(self, observer=None):
        self.receiver._initialize(transport=self.transport, task_alive=lambda: True,
            journal=Path('/not-opened'), runtime_version='1.4.0', scope=SCOPE,
            timeout=8, incarnation_id='owned-incarnation', startup_observer=observer)

    def failure(self, stage='state-rpc', observer=None, stderr=b'fixed fixture error\n'):
        original = NativeUnavailable('private exception text must not be echoed')
        def rpc(receiver, command, **fields):
            self.assertEqual(command, 'prompt')
            receiver._capture_startup_stderr(stderr)
            receiver.events.append({'secret_event': 'USER-CONTENT'})
            receiver._responses['secret-response'] = {'secret_response': 'USER-CONTENT'}
            self.clock = 108.0
            if stage == 'state-rpc': raise original
            return {'success': True}
        def wait(receiver, *args, **kwargs):
            if stage == 'state-notification': raise original
            return {'state': {**STATE, 'api_baseline': 'wrong'}}
        with patch.object(FixturePiRpcReceiver, 'rpc', autospec=True, side_effect=rpc) as call, \
                patch.object(FixturePiRpcReceiver, '_wait', autospec=True, side_effect=wait):
            with self.assertRaises(NativeUnavailable) as caught:
                self.initialize(observer)
        call.assert_called_once()
        if stage != 'validation': self.assertIs(caught.exception, original)
        return caught.exception

    def test_optional_hook_runs_before_close_and_has_original_exception(self):
        with self.harness():
            observed = []
            def observer(receiver, error):
                observed.append((receiver.startup_diagnostic(), error, receiver._closed))
                self.assertFalse(receiver._transport_fenced)
                self.database.close.assert_not_called()
            error = self.failure(observer=observer)
            value, observed_error, closed = observed[0]
            self.assertIs(error, observed_error); self.assertFalse(closed)
            self.assertEqual(value['stage'], 'state-rpc')
            self.assertEqual(value['elapsed_seconds'], 8.0)
            self.assertEqual(value['budget_seconds'], 8)
            self.assertTrue(value['held_task_alive']); self.assertFalse(value['reader_ended'])
            self.assertEqual(value['retained_event_count'], 1)
            self.assertEqual(value['buffered_response_count'], 1)
            self.assertNotIn('USER-CONTENT', json.dumps(value))
            self.assertNotIn('private exception', json.dumps(value))
            self.assertTrue(self.receiver._closed); self.assertTrue(self.receiver._transport_fenced)
            self.database.close.assert_called_once(); self.spawn.assert_not_called(); self.printed.assert_not_called()

    def test_phase_distinguishes_rpc_notification_and_validation(self):
        for stage in ('state-rpc', 'state-notification', 'validation'):
            with self.subTest(stage=stage), self.harness():
                values = []
                self.failure(stage=stage, observer=lambda receiver, error: values.append(receiver.startup_diagnostic()))
                self.assertEqual(values[0]['stage'], stage)
                self.assertFalse(values[0]['capture_active'])
                self.assertEqual(values[0]['budget_seconds'], 8)

    def test_observer_exception_cannot_replace_original_or_skip_cleanup(self):
        for failure in (RuntimeError('writer failure'), KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(failure=type(failure).__name__), self.harness():
                observer = Mock(side_effect=failure)
                original = self.failure(observer=observer)
                self.assertIs(observer.call_args.args[1], original)
                self.database.close.assert_called_once(); self.assertTrue(self.receiver._closed)
                self.spawn.assert_not_called(); self.printed.assert_not_called()

    def test_default_receiver_has_no_extra_capture_or_output_even_with_stderr(self):
        with self.harness():
            self.failure(observer=None, stderr=b'SECRET-STDERR')
            self.assertEqual(self.receiver.startup_diagnostic(include_stderr=True), {'version': 1, 'enabled': False})
            self.assertIsNone(self.receiver._startup_capture)
            self.printed.assert_not_called(); self.spawn.assert_not_called()

    def test_default_snapshot_omits_raw_stderr_and_all_event_command_contents(self):
        with self.harness():
            values = []
            self.failure(observer=lambda receiver, error: values.append(receiver.startup_diagnostic()),
                         stderr=b'SECRET-STDERR')
            value = values[0]; stderr = value['stderr']
            self.assertEqual(stderr['bytes'], len(b'SECRET-STDERR'))
            self.assertEqual(stderr['sha256'], hashlib.sha256(b'SECRET-STDERR').hexdigest())
            self.assertNotIn('head', stderr); self.assertNotIn('tail', stderr)
            self.assertNotIn('SECRET-STDERR', json.dumps(value)); self.assertNotIn('USER-CONTENT', json.dumps(value))

    def test_explicit_fixture_stderr_head_tail_count_hash_and_truncation(self):
        raw = b'first error\n' + b'x' * 6000 + b'last error\n'
        with self.harness():
            values = []
            self.failure(observer=lambda receiver, error: values.append(receiver.startup_diagnostic(include_stderr=True)), stderr=raw)
            value = values[0]['stderr']
            self.assertEqual(value['bytes'], len(raw))
            self.assertEqual(value['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(value['retained_bytes'], 2048); self.assertTrue(value['truncated'])
            self.assertTrue(value['head'].startswith('first error')); self.assertTrue(value['tail'].endswith('last error\n'))
            self.assertLessEqual(len(value['head'].encode()) + len(value['tail'].encode()), 2048)

    def test_small_stderr_not_duplicated_and_text_is_opt_in(self):
        for raw in (b'', b'abc', b'x' * 800, b'y' * 2048):
            with self.subTest(length=len(raw)), self.harness():
                values = []
                self.failure(observer=lambda receiver, error: values.append(receiver.startup_diagnostic(include_stderr=True)), stderr=raw)
                value = values[0]['stderr']
                self.assertEqual((value['head'] + value['tail']).encode(), raw)
                self.assertFalse(value['truncated']); self.assertEqual(value['retained_bytes'], len(raw))

    def test_invalid_utf8_and_controls_cannot_exceed_raw_text_budget(self):
        for raw in (b'\xff' * 9000, b'\x00' * 9000, ('界' * 3000).encode()):
            with self.subTest(raw=raw[:3]), self.harness():
                values = []
                self.failure(observer=lambda receiver, error: values.append(receiver.startup_diagnostic(include_stderr=True)), stderr=raw)
                value = values[0]['stderr']
                self.assertLessEqual(len(value['head'].encode()) + len(value['tail'].encode()), 2048)
                self.assertEqual(value['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertLess(len(json.dumps(values[0], ensure_ascii=True)), 15000)

    def test_failure_snapshot_freezes_stderr_before_observer_work(self):
        with self.harness():
            values = []
            def observer(receiver, error):
                receiver._capture_startup_stderr(b'AFTER-FAILURE')
                self.clock = 999
                values.append(receiver.startup_diagnostic(include_stderr=True))
            self.failure(observer=observer, stderr=b'BEFORE')
            self.assertEqual(values[0]['stderr']['bytes'], len(b'BEFORE'))
            self.assertNotIn('AFTER-FAILURE', json.dumps(values[0]))
            self.assertEqual(values[0]['elapsed_seconds'], 8.0)

    def test_success_stops_capture_without_invoking_observer_or_changing_readiness(self):
        with self.harness():
            observer = Mock()
            def native(receiver, command, payload):
                receiver._capture_startup_stderr(b'boot\n'); self.clock = 103
                return {'state': STATE}
            with patch.object(FixturePiRpcReceiver, '_native', autospec=True, side_effect=native) as native:
                self.initialize(observer)
            native.assert_called_once_with(self.receiver, 'state', {})
            self.receiver._capture_startup_stderr(b'LATER-PRIVATE-STDERR')
            value = self.receiver.startup_diagnostic(include_stderr=True)
            self.assertEqual(value['stage'], 'complete'); self.assertFalse(value['capture_active'])
            self.assertEqual(value['elapsed_seconds'], 3); self.assertEqual(value['stderr']['bytes'], 5)
            self.assertNotIn('LATER-PRIVATE-STDERR', json.dumps(value))
            self.assertIs(self.receiver.readiness, Readiness.SAFE)
            observer.assert_not_called(); self.database.close.assert_not_called(); self.printed.assert_not_called()

    def test_stderr_reader_captures_only_actual_stderr_bytes(self):
        with self.harness():
            original = NativeUnavailable('stop')
            values = []
            def native(receiver, *args):
                receiver.process.stderr.readline.side_effect = [b'first\n', b'second\n', b'']
                receiver._read_errors()
                raise original
            with patch.object(FixturePiRpcReceiver, '_native', autospec=True, side_effect=native):
                with self.assertRaises(NativeUnavailable) as caught:
                    self.initialize(lambda receiver, error: values.append(receiver.startup_diagnostic(include_stderr=True)))
            self.assertIs(caught.exception, original)
            self.assertEqual(values[0]['stderr']['sha256'], hashlib.sha256(b'first\nsecond\n').hexdigest())
            self.assertEqual(values[0]['retained_error_count'], 2)
            self.assertTrue(all(call.args == (4096,) for call in self.transport.stderr.readline.call_args_list))

    def test_unavailable_liveness_is_unknown_without_error_text(self):
        with self.harness():
            values = []
            def observer(receiver, error):
                with patch.object(receiver, '_alive', side_effect=PermissionError('SECRET')):
                    values.append(receiver.startup_diagnostic())
            self.failure(observer=observer)
            self.assertIsNone(values[0]['held_task_alive'])
            self.assertEqual(values[0]['liveness_error_type'], 'PermissionError')
            self.assertNotIn('SECRET', json.dumps(values[0]))

    def test_nonboolean_raw_option_rejected(self):
        with self.harness():
            self.failure()
            for value in (None, 0, 1, 'yes'):
                with self.assertRaises(ValueError): self.receiver.startup_diagnostic(include_stderr=value)

    def test_invalid_hook_rejected_before_process_or_reader_setup(self):
        with self.harness(), self.assertRaisesRegex(NativeUnavailable, 'observer must be callable'):
            self.initialize('not-a-hook')
        self.spawn.assert_not_called(); self.thread.assert_not_called()


class WorkstationStartupHookForwardingTests(unittest.TestCase):
    def test_invalid_workstation_hook_does_not_open_rpc_io(self):
        launch = ExecLaunch.__new__(ExecLaunch); launch.state = 'released'; launch.transport = Mock()
        with self.assertRaises(NativeUnavailable):
            FixturePiRpcReceiver.attach_workstation(launch, journal='not-opened', scope=SCOPE,
                                                   startup_observer='not-callable')
        launch.transport.rpc_io.assert_not_called()

    def test_owner_hook_is_forwarded_and_observed_before_revocation_and_transport_close(self):
        launch = ExecLaunch.__new__(ExecLaunch)
        launch.state = 'released'; launch.native_receiver = None; launch.exec_id = 'a' * 64
        launch.seat = SimpleNamespace(room_id='alpha', participant_id='alice')
        launch.origin = SimpleNamespace(revoked=False)
        events = []
        def revoke(): launch.origin.revoked = True; events.append('revoke')
        launch.origin.revoke = revoke
        launch._save = Mock(); launch.close_transport = Mock(side_effect=lambda: events.append('close'))
        original = NativeUnavailable('initialization failed')
        def observer(receiver, error):
            self.assertIs(error, original); self.assertEqual(launch.state, 'released')
            self.assertFalse(launch.origin.revoked); events.append('observe')
        def attach(owner, **kwargs):
            self.assertIs(owner, launch); self.assertEqual(kwargs['timeout'], 8)
            kwargs['startup_observer'](object(), original)
            raise original
        with patch.object(FixturePiRpcReceiver, 'attach_workstation', side_effect=attach) as attach:
            with self.assertRaises(NativeUnavailable) as caught:
                launch.attach_native(journal='not-opened', scope=SCOPE, profile_digest='d' * 64,
                                     startup_observer=observer)
        self.assertIs(caught.exception, original); attach.assert_called_once()
        self.assertEqual(events, ['observe', 'revoke', 'close'])
        self.assertEqual(launch.state, 'uncertain')


if __name__ == '__main__': unittest.main()
