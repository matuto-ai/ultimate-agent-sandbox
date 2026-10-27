"""Pure/mock opt-in cold state budget; no subprocess, socket, procfs or Engine I/O."""
import base64
from contextlib import ExitStack
import json
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.peer import Readiness
from uas.pi_runtime import FixturePiRpcReceiver, NativeUnavailable
from uas.workstation_exec import ExecLaunch

SCOPE = {'room_id': 'alpha', 'participant_id': 'alice', 'run_id': 'run-1',
         'generation': 1, 'context_generation': 1}
STATE = {'api_baseline': '1.4.0', 'readiness': Readiness.SAFE.value,
         'runtime_id': 'runtime-1', 'session_id': 'session-1', 'session_file': '/fixed/session'}


class PiInitialStateBudgetTests(unittest.TestCase):
    def harness(self, *, write_seconds=5, response_at=110, notification_at=120):
        stack = ExitStack(); self.addCleanup(stack.close)
        self.clock = 100.0; self.write_seconds = write_seconds
        self.response_at = response_at; self.notification_at = notification_at
        self.waits = []; self.writes = []; self.request = None
        self.on_wait = None; self.on_write = None; self.state = STATE
        condition = threading.Condition()
        self.wait_mock = stack.enter_context(patch.object(condition, 'wait', side_effect=self.wait))
        stack.enter_context(patch('uas.pi_runtime.time.monotonic', side_effect=lambda: self.clock))
        self.database = Mock(); self.database.execute.return_value.fetchone.return_value = None
        self.connect = stack.enter_context(patch('uas.pi_runtime.sqlite3.connect', return_value=self.database))
        self.blocking = stack.enter_context(patch('uas.pi_runtime.os.set_blocking'))
        self.spawn = stack.enter_context(patch('uas.pi_runtime.subprocess.Popen', side_effect=AssertionError('no subprocess')))
        self.thread = stack.enter_context(patch('uas.pi_runtime.threading.Thread'))
        self.thread.return_value.is_alive.return_value = False; self.thread.return_value.ident = None
        stack.enter_context(patch('uas.pi_runtime.threading.Condition', return_value=condition))
        self.printed = stack.enter_context(patch('builtins.print'))
        self.transport = SimpleNamespace(error=None, _stop=Mock())
        self.transport._stop.is_set.return_value = False
        for name in ('stdin', 'stdout', 'stderr'):
            stream = Mock(); stream.closed = False; stream.fileno.return_value = 11
            setattr(self.transport, name, stream)
        self.receiver = FixturePiRpcReceiver.__new__(FixturePiRpcReceiver)
        self.writer = stack.enter_context(patch('uas.pi_runtime.os.write', side_effect=self.write))
        original = FixturePiRpcReceiver._write
        self.write_deadlines = []
        def deadline_write(receiver, wire, deadline):
            self.write_deadlines.append(deadline)
            return original(receiver, wire, deadline)
        stack.enter_context(patch.object(FixturePiRpcReceiver, '_write', autospec=True, side_effect=deadline_write))
        return stack

    def write(self, fd, wire):
        self.assertEqual(fd, 11)
        value = json.loads(wire)
        self.writes.append(value); self.request = value
        if value['type'] == 'prompt':
            self.native_request = json.loads(base64.urlsafe_b64decode(value['message'].split(' ', 1)[1]))['request_id']
        self.clock += self.write_seconds
        if self.on_write is not None: self.on_write(value)
        return len(wire)

    def wait(self, remaining):
        self.waits.append(remaining)
        if self.on_wait is not None: return self.on_wait(remaining)
        if self.request['id'] in self.receiver._rpc_pending:
            self.clock = self.response_at
            self.receiver._responses[self.request['id']] = {'success': True}
        else:
            self.clock = self.notification_at
            self.receiver._notifications[self.native_request] = {'state': self.state}

    def initialize(self, budget=30, observer=None):
        self.receiver._initialize(transport=self.transport, task_alive=lambda: True,
            journal=Path('/not-opened'), runtime_version='1.4.0', scope=SCOPE,
            timeout=8, incarnation_id='owned-incarnation', startup_observer=observer,
            initial_state_timeout=budget)

    def test_one_absolute_budget_covers_write_rpc_and_notification(self):
        with self.harness(response_at=120, notification_at=129):
            self.initialize()
            self.assertEqual(self.write_deadlines, [130])
            self.assertEqual(self.waits, [25, 10])
            self.assertEqual(len(self.writes), 1)
            self.assertEqual(self.writes[0]['type'], 'prompt')
            self.assertNotIn('_deadline', self.writes[0])
            self.assertIs(self.receiver.readiness, Readiness.SAFE)
            self.assertEqual(self.receiver.timeout, 8)
            self.spawn.assert_not_called(); self.printed.assert_not_called()

    def test_deadline_starts_after_setup_immediately_before_initial_command(self):
        with self.harness(write_seconds=0, response_at=120, notification_at=125):
            self.database.commit.side_effect = lambda: setattr(self, 'clock', 115)
            self.initialize()
            self.assertEqual(self.write_deadlines, [145])
            self.assertEqual(self.waits, [30, 25])

    def test_default_keeps_original_eight_second_rpc_and_notification_budgets(self):
        with self.harness(write_seconds=2, response_at=104, notification_at=110):
            self.initialize(None)
            self.assertEqual(self.write_deadlines, [108])
            self.assertEqual(self.waits, [6, 8])
            self.assertEqual(self.receiver.timeout, 8)
            self.assertEqual(self.receiver.startup_diagnostic(), {'version': 1, 'enabled': False})
            self.printed.assert_not_called()

    def test_progress_does_not_renew_deadline_or_send_second_prompt(self):
        with self.harness(write_seconds=0):
            def progress(remaining):
                self.clock += 10
                self.receiver.events.append({'type': 'unrelated-progress'})
            self.on_wait = progress
            with self.assertRaisesRegex(NativeUnavailable, 'initial native state deadline exceeded'):
                self.initialize()
            self.assertEqual(self.waits, [30, 20, 10])
            self.assertEqual(self.clock, 130); self.assertEqual(len(self.writes), 1)
            self.assertTrue(self.receiver._closed); self.assertTrue(self.receiver._transport_fenced)
            self.assertIsNone(self.receiver._binding)

    def test_partial_write_progress_does_not_reset_absolute_deadline(self):
        with self.harness(write_seconds=0):
            def partial(fd, wire):
                self.clock += 10
                return 1
            self.writer.side_effect = partial
            with self.assertRaisesRegex(NativeUnavailable, 'native transport write deadline exceeded'):
                self.initialize()
            self.assertEqual(self.write_deadlines, [130])
            self.assertEqual(self.writer.call_count, 3)
            self.assertEqual(self.clock, 130); self.assertEqual(self.waits, [])
            self.assertTrue(self.receiver._transport_fenced)
            self.assertEqual(self.receiver._rpc_pending, set())
            self.assertEqual(self.receiver._native_pending, set())

    def test_buffered_late_rpc_response_cannot_bypass_expired_deadline(self):
        with self.harness(write_seconds=30):
            self.on_write = lambda value: self.receiver._responses.update({value['id']: {'success': True}})
            with self.assertRaisesRegex(NativeUnavailable, 'initial native state deadline exceeded'):
                self.initialize()
            self.assertEqual(self.waits, []); self.assertEqual(len(self.writes), 1)
            self.assertIsNone(self.receiver._binding)
            self.assertEqual(self.receiver._responses, {})
            self.assertEqual(self.receiver._native_pending, set())

    def test_response_arriving_at_deadline_is_rejected_without_notification_wait(self):
        with self.harness(write_seconds=5, response_at=130):
            with self.assertRaisesRegex(NativeUnavailable, 'initial native state deadline exceeded'):
                self.initialize()
            self.assertEqual(self.waits, [25]); self.assertEqual(len(self.writes), 1)
            self.assertEqual(self.receiver._responses, {}); self.assertIsNone(self.receiver._binding)

    def test_matching_notification_arriving_at_deadline_is_rejected(self):
        with self.harness(notification_at=130):
            with self.assertRaisesRegex(NativeUnavailable, 'initial native state deadline exceeded'):
                self.initialize()
            self.assertEqual(self.waits, [25, 20]); self.assertEqual(len(self.writes), 1)
            self.assertEqual(self.receiver._notifications, {}); self.assertIsNone(self.receiver._binding)
            self.assertEqual(self.receiver._native_pending, set())

    def test_buffered_notification_cannot_skip_absolute_expiry_check(self):
        with self.harness():
            original_stage = self.receiver._startup_stage
            def stage(name):
                original_stage(name)
                if name == 'state-notification':
                    self.receiver._notifications[self.native_request] = {'state': STATE}
                    self.clock = 130
            with patch.object(self.receiver, '_startup_stage', side_effect=stage):
                with self.assertRaisesRegex(NativeUnavailable, 'initial native state deadline exceeded'):
                    self.initialize()
            self.assertEqual(self.waits, [25]); self.assertIsNone(self.receiver._binding)

    def test_expired_validation_does_not_commit_binding_or_readiness(self):
        with self.harness(notification_at=129):
            owner = self
            class SlowState(dict):
                def get(self, key, default=None):
                    if key == 'readiness': owner.clock = 130
                    return super().get(key, default)
            self.state = SlowState(STATE)
            values = []
            with self.assertRaisesRegex(NativeUnavailable, 'initial native state deadline exceeded'):
                self.initialize(observer=lambda receiver, error: values.append(receiver.startup_diagnostic()))
            self.assertEqual(values[0]['stage'], 'validation')
            self.assertIsNone(self.receiver._binding)
            self.assertFalse(hasattr(self.receiver, 'initial_state'))
            self.assertFalse(hasattr(self.receiver, 'readiness'))
            self.assertTrue(self.receiver._transport_fenced)

    def test_late_data_cannot_reactivate_failed_receiver_or_reinject(self):
        with self.harness(notification_at=130):
            with self.assertRaises(NativeUnavailable): self.initialize()
            self.clock = 131
            self.receiver._responses[self.request['id']] = {'success': True}
            self.receiver._notifications[self.native_request] = {'state': STATE}
            self.assertIs(self.receiver.observe(), Readiness.AMBIGUOUS)
            self.assertEqual(len(self.writes), 1); self.assertIsNone(self.receiver._binding)

    def test_diagnostic_distinguishes_initial_and_ordinary_budgets(self):
        with self.harness(notification_at=130):
            values = []
            with self.assertRaises(NativeUnavailable):
                self.initialize(observer=lambda receiver, error: values.append(receiver.startup_diagnostic()))
            value = values[0]
            self.assertEqual(value['budget_seconds'], 30)
            self.assertEqual(value['initial_state_timeout_seconds'], 30)
            self.assertEqual(value['ordinary_timeout_seconds'], 8)
            self.assertEqual(value['initial_state_elapsed_seconds'], 30)
            self.assertEqual(value['stage'], 'state-notification')

    def test_ordinary_rpc_observe_and_fresh_context_do_not_inherit_cold_budget(self):
        with self.harness():
            self.initialize()
            # Subsequent actual protocol path still chooses self.timeout=8.
            self.clock = 140; self.write_seconds = 0; self.response_at = 141; self.notification_at = 142
            self.assertIs(self.receiver.observe(), Readiness.SAFE)
            self.assertEqual(self.write_deadlines[-1], 148)
            self.assertEqual(self.waits[-2:], [8, 8])
            self.clock = 150; self.response_at = 151
            self.receiver.rpc('ordinary-query')
            self.assertEqual(self.write_deadlines[-1], 158)
            self.assertEqual(self.waits[-1], 8)
            self.database.execute.return_value.fetchone.return_value = (0,)
            with patch.object(self.receiver, '_native', return_value={'state': STATE}) as native, \
                    patch.object(self.receiver, 'rpc', side_effect=[{'data': {
                        'sessionId': 'session-1', 'messageCount': 0, 'pendingMessageCount': 0,
                        'isStreaming': False, 'isCompacting': False}}, {'data': {'entries': []}}]) as rpc:
                self.receiver.prove_fresh_context()
            native.assert_called_once_with('state', {})
            self.assertEqual([call.kwargs for call in rpc.call_args_list], [{}, {}])
            self.assertEqual(self.receiver.timeout, 8)

    def test_invalid_options_fail_before_database_transport_or_native_setup(self):
        for value in (True, False, 0, -1, 30.1, float('inf'), float('-inf'), float('nan'), '30', object(), 10**500):
            with self.subTest(value=type(value).__name__), self.harness():
                with self.assertRaisesRegex(NativeUnavailable, 'initial state timeout'):
                    self.initialize(value)
                self.connect.assert_not_called(); self.blocking.assert_not_called()
                self.thread.assert_not_called(); self.writer.assert_not_called(); self.spawn.assert_not_called()

    def test_valid_numeric_boundary_and_fractional_budgets(self):
        for value in (30, 30.0, .5):
            with self.subTest(value=value), self.harness(write_seconds=0, response_at=100.1, notification_at=100.2):
                self.initialize(value)
                self.assertEqual(self.write_deadlines, [100 + value])


class InitialStateOwnerOptionTests(unittest.TestCase):
    def test_invalid_owner_option_rejected_before_rpc_io(self):
        for value in (True, 0, 31, float('inf'), float('nan'), '30'):
            launch = ExecLaunch.__new__(ExecLaunch); launch.state = 'released'; launch.transport = Mock()
            with self.subTest(value=type(value).__name__), self.assertRaises(NativeUnavailable):
                FixturePiRpcReceiver.attach_workstation(launch, journal='not-opened', scope=SCOPE,
                                                       initial_state_timeout=value)
            launch.transport.rpc_io.assert_not_called()

    def test_attach_workstation_forwards_bound_without_changing_ordinary_timeout(self):
        launch = ExecLaunch.__new__(ExecLaunch); launch.state = 'released'; launch.transport = Mock()
        launch.origin = SimpleNamespace(revoked=False, pidfd=42); launch.incarnation = 'owned-incarnation'
        with patch.object(FixturePiRpcReceiver, '_initialize', autospec=True) as initialize:
            receiver = FixturePiRpcReceiver.attach_workstation(launch, journal='not-opened', scope=SCOPE,
                                                              initial_state_timeout=30)
        self.assertIs(initialize.call_args.args[0], receiver)
        self.assertEqual(initialize.call_args.kwargs['timeout'], 8)
        self.assertEqual(initialize.call_args.kwargs['initial_state_timeout'], 30)
        launch.transport.rpc_io.assert_called_once()

    def test_exec_owner_forwards_initial_budget_and_failure_still_fences(self):
        launch = ExecLaunch.__new__(ExecLaunch); launch.state = 'released'; launch.native_receiver = None
        launch.exec_id = 'a' * 64; launch.seat = SimpleNamespace(room_id='alpha', participant_id='alice')
        launch.origin = Mock(); launch._save = Mock(); launch.close_transport = Mock()
        original = NativeUnavailable('initial state expired')
        with patch.object(FixturePiRpcReceiver, 'attach_workstation', side_effect=original) as attach:
            with self.assertRaises(NativeUnavailable) as caught:
                launch.attach_native(journal='not-opened', scope=SCOPE, profile_digest='d' * 64,
                                     initial_state_timeout=30)
        self.assertIs(caught.exception, original)
        self.assertEqual(attach.call_args.kwargs['timeout'], 8)
        self.assertEqual(attach.call_args.kwargs['initial_state_timeout'], 30)
        attach.assert_called_once(); launch.origin.revoke.assert_called_once(); launch.close_transport.assert_called_once()
        self.assertEqual(launch.state, 'uncertain')


if __name__ == '__main__': unittest.main()
