"""Synthetic fixed-host faults; not native SDK or permission-path evidence."""
from collections import deque
import io
from contextlib import nullcontext
import fcntl
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.claude_runtime import (BINARY_SHA256, ClaudeNotApplied, ClaudeSignals,
                               ClaudeUnavailable, FixtureClaudeReceiver)
from uas.peer import Readiness


class ClaudeSDKBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.native = FixtureClaudeReceiver.__new__(FixtureClaudeReceiver)
        self.native.timeout = .02
        self.native.condition = threading.Condition()
        self.native.command_lock = threading.Lock()
        self.native.signals = ClaudeSignals('session', safe_for=0)
        self.native.session_id = 'session'
        self.native.native_pid = 12345
        self.native.process = Mock()
        self.native.process.poll.return_value = None
        self.native.process.stdin.fileno.return_value = 42
        self.native.reply_id = self.native.reply = None
        self.native.event_revision = 3
        self.native.ended = False
        self.native.closing = False
        self.native._host_alive = Mock(return_value=True)
        self.native._terminate_host = Mock()

    def test_host_policy_fence_precedes_replayed_ack_even_if_python_parser_would_accept(self):
        message_id = '11111111-1111-4111-8111-111111111111'
        self.native.signals.begin(message_id, 'text')
        event = dict(type='user', session_id='session', uuid=message_id, isReplay=True,
                     parent_tool_use_id=None, message={'role': 'user', 'content': 'text'})
        self.native.events, self.native.errors = deque(maxlen=128), deque(maxlen=16)
        self.native.process.stdout = io.BytesIO((json.dumps(dict(type='native', event=event,
                                                               fence='prior-unknown-event')) + '\n').encode())
        self.native._read()
        self.assertTrue(self.native.signals.fenced)
        self.assertIsNone(self.native.signals.ack)

    def test_missing_ack_parent_and_no_pending_lifecycle_do_not_qualify(self):
        from uas.claude_runtime import _ack_matches
        message_id = '11111111-1111-4111-8111-111111111111'
        event = dict(type='user', session_id='session', uuid=message_id, isReplay=True,
                     message={'role': 'user', 'content': 'text'})
        self.assertFalse(_ack_matches(event, 'session', message_id, 'text'))
        event['parent_tool_use_id'] = None
        self.assertTrue(_ack_matches(event, 'session', message_id, 'text'))
        self.assertFalse(_ack_matches(event, 'session', ['invalid'], 'text'))
        self.native.signals.event(dict(type='command_lifecycle', state='completed',
                                      command_uuid=None, session_id='session'))
        self.assertTrue(self.native.signals.fenced)

    def test_zero_byte_failure_is_known_not_applied(self):
        with patch('uas.claude_runtime.os.write', side_effect=BrokenPipeError()):
            with self.assertRaises(ClaudeNotApplied):
                self.native._command('send')
        self.assertFalse(self.native.signals.fenced)
        self.assertIsNone(self.native.reply_id)

    def test_new_async_fence_stops_remaining_bytes(self):
        for partial in (False, True):
            for state in ('needs-input', 'unknown-signal'):
                with self.subTest(partial=partial, state=state):
                    self.setUp()
                    def write(fd, data):
                        self.native.signals.hold(state)
                        if partial:
                            return 1
                        raise BlockingIOError()
                    with patch('uas.claude_runtime.os.write', side_effect=write) as output, \
                         patch('uas.claude_runtime.select.select'):
                        with self.assertRaises(ClaudeUnavailable) as raised:
                            self.native._command('send')
                    self.assertEqual(isinstance(raised.exception, ClaudeNotApplied), not partial)
                    output.assert_called_once()
                    self.assertTrue(self.native.signals.fenced)
                    if partial:
                        self.native._terminate_host.assert_called()

    def test_lost_reply_after_complete_command_stays_unknown(self):
        with patch('uas.claude_runtime.os.write', side_effect=lambda fd, data: len(data)):
            with self.assertRaises(ClaudeUnavailable) as raised:
                self.native._command('send')
        self.assertNotIsInstance(raised.exception, ClaudeNotApplied)
        self.assertTrue(self.native.signals.fenced)
        self.native._terminate_host.assert_called()

    def test_locked_slot_does_not_write_or_claim_receipt(self):
        self.native.command_lock.acquire()
        try:
            with patch('uas.claude_runtime.os.write') as output:
                with self.assertRaises(ClaudeNotApplied):
                    self.native._command('send')
            output.assert_not_called()
        finally:
            self.native.command_lock.release()

    def test_frame_cap_rejects_before_any_byte(self):
        with patch('uas.claude_runtime.os.write') as output:
            with self.assertRaises(ClaudeNotApplied):
                self.native._command('send', content='x' * self.native.MAX_FRAME)
            output.assert_not_called()

    def test_safe_reply_requires_exact_identity_fresh_liveness_and_no_new_activity(self):
        safe = dict(state='safe', pid=12345, session_id='session',
                    liveness='fresh-public-mcpServerStatus', reason='native-listing-idle',
                    native_state=None, revision=0, _seen_revision=3)
        cases = [({}, Readiness.SAFE), ({'pid': 8}, Readiness.AMBIGUOUS),
                 ({'session_id': 'replacement'}, Readiness.AMBIGUOUS),
                 ({'liveness': None}, Readiness.AMBIGUOUS),
                 ({'reason': 'connected'}, Readiness.AMBIGUOUS),
                 ({'native_state': 'running'}, Readiness.AMBIGUOUS),
                 ({'revision': True}, Readiness.AMBIGUOUS),
                 ({'_seen_revision': 2}, Readiness.AMBIGUOUS)]
        for change, expected in cases:
            with self.subTest(change=change), patch.object(self.native, '_kernel', return_value='S'), \
                 patch.object(self.native, '_command', return_value={**safe, **change}):
                self.assertIs(self.native._probe(), expected)
        with patch.object(self.native, '_kernel', return_value='T'), \
             patch.object(self.native, '_command', return_value=safe):
            self.assertIs(self.native._probe(), Readiness.AMBIGUOUS)

    def test_idle_reply_cannot_clear_local_pending_attention_or_unknown_intent(self):
        with patch.object(self.native, '_unknown', return_value=True), patch.object(self.native, '_probe') as probe:
            self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
            probe.assert_not_called()
        self.native.signals.hold('needs-input')
        with patch.object(self.native, '_unknown', return_value=False), patch.object(self.native, '_probe') as probe:
            self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
            probe.assert_not_called()

    def test_release_is_not_ack_and_not_applied_releases_only_own_slot(self):
        with patch.object(self.native, '_command', return_value={'released': True}):
            self.native._write('message', 'text', peer=True)
        self.assertIsNone(self.native.signals.ack)
        self.assertEqual(self.native.signals.pending, ('message', 'text'))
        self.setUp()
        with patch.object(self.native, '_command', return_value={'not_applied': True, 'state': 'busy'}):
            with self.assertRaises(ClaudeNotApplied):
                self.native._write('message', 'text', peer=True)
        self.assertIsNone(self.native.signals.pending)
        self.assertIsNone(self.native.signals.ack)

    def test_no_synthetic_control_turn_exists(self):
        self.assertFalse(hasattr(self.native, 'refresh'))
        with patch.object(self.native, '_command') as command:
            with self.assertRaises(ClaudeNotApplied):
                self.native._write('message', 'hidden bootstrap')
            command.assert_not_called()

    def test_failed_database_spawn_or_thread_start_releases_journal_and_owned_resources(self):
        for failure in ('database', 'spawn', 'pidfd', 'blocking', 'thread', 'ready'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as root:
                root = Path(root)
                binary = root / 'synthetic-binary'
                binary.write_bytes(b'not executed')
                child = Mock()
                child.pid = 12345
                child.returncode = None
                child.poll.return_value = None
                child.wait.return_value = 0
                kwargs = dict(sdk_install=root, node=root / 'not-executed', cwd=root, home=root,
                              gateway_url='http://127.0.0.1:1234', fixture_key='fixture-only-test',
                              journal=root / 'intent.db', scope={'room_id': 'alpha',
                              'participant_id': 'claude', 'run_id': 'run-1', 'generation': 1,
                              'context_generation': 1})
                target = {'database': 'uas.claude_runtime.sqlite3.connect',
                          'spawn': 'uas.claude_runtime.subprocess.Popen',
                          'pidfd': 'uas.claude_runtime.os.pidfd_open',
                          'blocking': 'uas.claude_runtime.os.set_blocking',
                          'ready': 'uas.claude_runtime.FixtureClaudeReceiver._wait',
                          'thread': 'uas.claude_runtime.threading.Thread.start'}[failure]
                with patch('uas.claude_runtime.require_loopback_namespace'), \
                     patch('uas.claude_runtime.hashlib.file_digest', return_value=SimpleNamespace(hexdigest=lambda: BINARY_SHA256)), \
                     patch('uas.claude_runtime.os.set_blocking'), patch('uas.claude_runtime.os.killpg'), \
                     patch('uas.claude_runtime.os.pidfd_open', return_value=111), \
                     patch('uas.claude_runtime.signal.pidfd_send_signal') as send_signal, \
                     patch('uas.claude_runtime.select.select', return_value=([], [], [])), \
                     patch('uas.claude_runtime.os.waitid', return_value=None), \
                     patch('uas.claude_runtime.os.close'):
                    if failure in ('pidfd', 'blocking', 'thread', 'ready'):
                        with patch('uas.claude_runtime.subprocess.Popen', return_value=child), \
                             (nullcontext() if failure == 'thread' else patch('uas.claude_runtime.threading.Thread')), \
                             patch(target, side_effect=RuntimeError('fault')):
                            with self.assertRaisesRegex(RuntimeError, 'fault'):
                                FixtureClaudeReceiver(binary, **kwargs)
                        import signal
                        if failure == 'pidfd':
                            send_signal.assert_not_called()
                        else:
                            send_signal.assert_any_call(111, signal.SIGTERM, None, 0)
                        child.wait.assert_called_once()
                        child.stdin.close.assert_called_once()
                        child.stdout.close.assert_called_once()
                        child.stderr.close.assert_called_once()
                    else:
                        with patch(target, side_effect=RuntimeError('fault')):
                            with self.assertRaisesRegex(RuntimeError, 'fault'):
                                FixtureClaudeReceiver(binary, **kwargs)
                with open(str(root / 'intent.db') + '.owner', 'a+b') as owner:
                    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
