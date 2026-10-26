"""Source signal tests are synthetic; native tests require official CLI + CI netns."""
import json
import os
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from uas.claude_runtime import ClaudeSignals, ClaudeUnavailable, FixtureClaudeReceiver, VERSION, require_loopback_namespace
from uas.ledger import LedgerError, RoomLedger
from uas.peer import FixtureParticipant, FixturePeerHub, Readiness, WorkRequest


class ClaudeSignalTests(unittest.TestCase):
    def setUp(self):
        self.signals = ClaudeSignals('session')

    def emit(self, **fields):
        self.signals.event({'session_id': 'session', **fields})

    def initialized(self):
        self.emit(type='system', subtype='init', claude_code_version=VERSION, tools=[], mcp_servers=[])

    def ack(self):
        self.emit(type='user', uuid='message', isReplay=True, parent_tool_use_id=None,
                  message={'role': 'user', 'content': 'text'})

    def result(self, **fields):
        self.emit(**dict(type='result', user_message_uuid='message', subtype='success', is_error=False,
                         permission_denials=[], queued_turn_count=0, terminal_reason='completed', stop_reason='end_turn', **fields))

    def test_init_and_silence_are_not_safe(self):
        self.initialized()
        self.assertIs(self.signals.readiness(), Readiness.AMBIGUOUS)

    def test_only_correlated_ack_then_terminal_success_yields_inferred_idle(self):
        self.signals.begin('message', 'text')
        self.initialized()
        self.ack()
        self.assertIs(self.signals.readiness(), Readiness.BUSY)
        self.result()
        self.assertIs(self.signals.readiness(), Readiness.SAFE)
        self.signals.safe_at -= 3
        self.assertIs(self.signals.readiness(), Readiness.AMBIGUOUS)

    def test_wrong_uuid_content_session_or_replay_never_acknowledges(self):
        for override in ({'uuid': 'other'}, {'session_id': 'other'}, {'isReplay': False},
                         {'message': {'role': 'user', 'content': 'different'}}):
            with self.subTest(override=override):
                self.setUp()
                self.signals.begin('message', 'text')
                event = {'type': 'user', 'session_id': 'session', 'uuid': 'message', 'isReplay': True,
                         'message': {'role': 'user', 'content': 'text'}, 'parent_tool_use_id': None, **override}
                self.signals.event(event)
                self.assertIsNone(self.signals.ack)
                self.assertTrue(self.signals.fenced)

    def test_result_without_ack_and_unexpected_tools_hold(self):
        self.signals.begin('message', 'text')
        self.initialized()
        self.result()
        self.assertTrue(self.signals.fenced)
        self.setUp()
        self.emit(type='system', subtype='init', claude_code_version=VERSION, tools=['Bash'], mcp_servers=[])
        self.assertTrue(self.signals.fenced)

    def test_needs_input_unknown_loss_and_unresponsive_stay_held_after_late_result(self):
        for state in ('needs-input', 'unknown', 'transport-loss', 'unresponsive-inferred', 'replacement'):
            with self.subTest(state=state):
                self.setUp()
                self.signals.begin('message', 'text')
                self.initialized()
                self.ack()
                self.signals.hold(state)
                self.result()
                self.assertIs(self.signals.readiness(), Readiness.AMBIGUOUS)
                with self.assertRaises(ClaudeUnavailable):
                    self.signals.begin('another', 'text')

    def test_permission_control_and_unknown_event_fail_closed(self):
        for event in ({'type': 'control_request'}, {'type': 'system', 'subtype': 'permission_denied'},
                      {'type': 'new-undocumented-event'}):
            self.setUp()
            self.emit(**event)
            self.assertTrue(self.signals.fenced)

    def test_loopback_guard_rejects_extra_interface_or_ipv6_route(self):
        with patch('socket.if_nameindex', return_value=[(1, 'lo'), (2, 'eth0')]):
            with self.assertRaises(ClaudeUnavailable):
                require_loopback_namespace()
        with patch('socket.if_nameindex', return_value=[(1, 'lo')]), patch('pathlib.Path.read_text', side_effect=['header\n', ':: :: eth0\n']):
            with self.assertRaises(ClaudeUnavailable):
                require_loopback_namespace()


INSTALL = os.environ.get('UAS_CLAUDE_INSTALL')


@unittest.skipUnless(INSTALL, 'Official Claude native suite runs in its mandatory loopback-only CI job')
class ClaudeNativeTests(unittest.TestCase):
    def setUp(self):
        from claude.probe import Gateway, Handler
        require_loopback_namespace()
        self.temp = tempfile.TemporaryDirectory(prefix='uas-claude-native-')
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.gateway = Gateway(('127.0.0.1', 0), Handler)
        self.gateway.key = 'fixture-only-local-key'
        self.gateway.requests = []
        self.thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.thread.start()
        self.binary = Path(INSTALL) / 'node_modules/@anthropic-ai/claude-code-linux-x64/claude'
        self.scope = {'room_id': 'alpha', 'participant_id': 'claude', 'run_id': 'run-1', 'generation': 1, 'context_generation': 1}
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('sender', 'actor-a'), FixtureParticipant('claude', 'actor-c')), 'run-1')
        self.sender = self.hub.connect('sender', 'sender', 'sender-inc', object())
        self.native = None
        self.start()

    def start(self, *, resume=False):
        self.native = FixtureClaudeReceiver(self.binary, cwd=self.root, home=self.home,
                         gateway_url=f'http://127.0.0.1:{self.gateway.server_port}', fixture_key=self.gateway.key,
                         journal=self.root / 'intent.db', scope=self.scope, resume=resume)
        self.connection = self.hub.connect('attach-' + self.native.incarnation_id, 'claude', self.native.incarnation_id, self.native)
        self.assertEqual(self.hub.deliver(self.connection)['outcome'], 'HELD', 'connect/resume is not readiness')
        self.native.wait_safe()

    def tearDown(self):
        if self.native:
            print(json.dumps({'case': self.id(), **self.native.evidence()}, sort_keys=True))
            self.native.close()
        self.gateway.shutdown()
        self.gateway.server_close()
        self.thread.join(timeout=3)
        self.ledger.close()
        self.temp.cleanup()

    def submit(self, id='work-1', text='Inspect fixture only.'):
        self.hub.submit(self.sender, WorkRequest(id, 'run-1', 1, 'claude', text))

    def deliver(self):
        self.hub.observe(self.connection, self.native.observe())
        return self.hub.deliver(self.connection, limit=1)

    def request(self, id='work-1'):
        return self.hub.snapshot()['state']['peer_traffic']['traffic'][id]

    def test_long_lived_ack_starts_clock_but_working_holds_next_message(self):
        self.gateway.delay = .8
        self.submit()
        self.submit('work-2')
        self.assertIsNone(self.request()['response_started_at'])
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertIsNotNone(self.request()['response_started_at'])
        self.assertEqual(self.request()['status'], 'DELIVERED', 'runtime input acceptance is not work acceptance')
        self.assertIs(self.native.observe(), Readiness.BUSY)
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertIsNone(self.request('work-2')['response_started_at'])
        self.native.wait_safe()
        self.assertIsNone(self.native.process.poll())
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.native.wait_safe()
        self.assertIsNone(self.native.process.poll(), 'stdin stays open over multiple genuine turns')

    def test_lost_hub_return_and_actual_same_session_resume_do_not_reinject(self):
        self.submit(text='UNIQUE-PEER-HISTORY-NONCE')
        original = self.native.accept
        def lose_return(envelope):
            original(envelope)
            raise LedgerError('LOST_HUB_RETURN')
        self.native.accept = lose_return
        with self.assertRaisesRegex(LedgerError, 'LOST_HUB_RETURN'):
            self.deliver()
        self.assertIsNone(self.request()['response_started_at'])
        self.native.wait_safe()
        old = self.connection
        session = self.native.session_id
        self.native.close()
        self.native = None
        self.start(resume=True)
        self.assertEqual(self.native.session_id, session)
        self.assertNotEqual(old.incarnation_id, self.connection.incarnation_id)
        self.assertEqual(self.hub.deliver(old)['outcome'], 'HELD')
        before = len(self.gateway.requests)
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(len(self.gateway.requests), before)
        # Native CLI sent its restored conversation to the local fixture.
        history = self.gateway.requests[-1]['request']['messages']
        self.assertEqual(json.dumps(history).count('UNIQUE-PEER-HISTORY-NONCE'), 1)

    def test_expired_signal_and_exit_do_not_deliver(self):
        self.native.signals.safe_at -= 3  # Synthetic freshness expiry, not native hung proof.
        self.submit()
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.native.refresh()
        self.native.wait_safe()
        self.native.process.terminate()
        self.native.process.wait(timeout=3)
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertIsNone(self.request()['response_started_at'])

    def test_actual_stopped_process_missing_ack_never_reinjects_after_resume(self):
        self.submit(text='x' * 16000)
        # Stop only this disposable owned process; bound the real pipe write.
        os.kill(self.native.process.pid, signal.SIGSTOP)
        import fcntl
        fcntl.fcntl(self.native.process.stdin.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        self.native.timeout = .25
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
                self.deliver()
            self.assertLess(time.monotonic() - started, 2)
            self.assertIsNone(self.request()['response_started_at'])
            self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        finally:
            self.native.process.kill()
            self.native.process.wait(timeout=3)
        self.native.close()
        self.native = None
        self.start(resume=True)
        before = len(self.gateway.requests)
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertEqual(len(self.gateway.requests), before)

    def test_unsupported_cross_run_reset_and_stale_incarnation_are_rejected(self):
        self.submit()
        self.native.incarnation_id = 'changed-for-negative-source-test'
        with self.assertRaisesRegex(LedgerError, 'NATIVE_SCOPE_MISMATCH'):
            self.deliver()
        self.native.close()
        self.native = None
        self.scope['run_id'] = 'different-run'
        with self.assertRaisesRegex(ClaudeUnavailable, 'reset/remap unsupported'):
            self.start(resume=True)
