"""SDK receiver + durable Hub tests; native cases run only in isolated Claude CI.

Injected Python failures are source fault tests, not native attention evidence.
Actual native cases use the fixed tool-less SDK host and no-upstream gateway.
"""
import json
import fcntl
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
import uuid

from uas import claude_runtime
from uas.claude_runtime import ClaudeNotApplied, ClaudeUnavailable, require_loopback_namespace
from uas.ledger import LedgerError, RoomLedger
from uas.peer import FixtureParticipant, FixturePeerHub, Readiness, WorkRequest


SCOPE = {'room_id': 'alpha', 'participant_id': 'claude', 'run_id': 'run-1',
         'generation': 1, 'context_generation': 1}
INSTALL = os.environ.get('UAS_CLAUDE_INSTALL')
SDK_INSTALL = os.environ.get('UAS_CLAUDE_SDK_INSTALL')
NODE = os.environ.get('UAS_CLAUDE_NODE')


class ClaudeSDKJournalSourceTests(unittest.TestCase):
    """No SDK, native process, provider, or network is used by these cases."""
    def setUp(self):
        self.receiver = claude_runtime.FixtureClaudeReceiver.__new__(claude_runtime.FixtureClaudeReceiver)
        self.receiver.scope = dict(SCOPE)
        self.receiver.session_id = str(uuid.uuid4())
        self.receiver.incarnation_id = 'source-incarnation'
        self.receiver.db = sqlite3.connect(':memory:')
        self.addCleanup(self.receiver.db.close)
        self.receiver.db.execute('CREATE TABLE handoffs (logical_digest TEXT PRIMARY KEY, '
                                 'logical TEXT, message_id TEXT, receipt TEXT, retryable INTEGER DEFAULT 0)')
        self.receiver.observe = lambda: Readiness.AMBIGUOUS if self.receiver.db.execute(
            'SELECT 1 FROM handoffs WHERE receipt IS NULL AND retryable != 1').fetchone() else Readiness.SAFE
        self.receiver._write = Mock(side_effect=ClaudeNotApplied('injected before any host input'))
        self.envelope = {**SCOPE, 'incarnation_id': self.receiver.incarnation_id,
                         'delivery_id': 'source-delivery', 'id': 'source-work',
                         'kind': 'peer.work-request', 'text': 'synthetic source policy test'}

    def test_committed_zero_byte_classification_preserves_uuid_for_one_retry(self):
        with self.assertRaisesRegex(LedgerError, 'NATIVE_NOT_APPLIED'):
            self.receiver.accept(self.envelope)
        message_id, receipt, retryable = self.receiver.db.execute(
            'SELECT message_id,receipt,retryable FROM handoffs').fetchone()
        self.assertIsNone(receipt)
        self.assertEqual(retryable, 1)
        original_content = self.receiver._write.call_args.args[1]
        self.receiver._write = Mock()
        self.receiver._wait_ack = Mock(return_value={
            'type': 'user', 'uuid': message_id, 'session_id': self.receiver.session_id,
            'isReplay': True, 'parent_tool_use_id': None,
            'message': {'role': 'user', 'content': original_content}})
        self.receiver.accept(self.envelope)
        self.receiver._write.assert_called_once_with(message_id, original_content, peer=True)
        saved_id, saved_receipt, retryable = self.receiver.db.execute(
            'SELECT message_id,receipt,retryable FROM handoffs').fetchone()
        self.assertEqual(saved_id, message_id)
        self.assertEqual(json.loads(saved_receipt)['uuid'], message_id)
        self.assertEqual(retryable, 0)
        self.receiver.accept(self.envelope)
        self.receiver._write.assert_called_once()

    def test_failed_no_effect_classification_leaves_unknown_and_prevents_retry(self):
        self.receiver.db.execute("CREATE TRIGGER fail_classification BEFORE UPDATE ON handoffs "
            "WHEN NEW.retryable=1 BEGIN SELECT RAISE(ABORT, 'source classification failure'); END")
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.receiver.accept(self.envelope)
        receipt, retryable = self.receiver.db.execute('SELECT receipt,retryable FROM handoffs').fetchone()
        self.assertIsNone(receipt)
        self.assertEqual(retryable, 0)
        self.receiver.db.execute('DROP TRIGGER fail_classification')
        with self.assertRaisesRegex(LedgerError, 'NATIVE_NOT_SAFE'):
            self.receiver.accept(self.envelope)
        self.receiver._write.assert_called_once()


@unittest.skipUnless(INSTALL and SDK_INSTALL and NODE,
                     'Actual SDK receiver requires pinned packages and mandatory loopback-only Claude CI')
class ClaudeSDKReceiverNativeTests(unittest.TestCase):
    def setUp(self):
        from claude.probe import Gateway, Handler

        class ObservedHandler(Handler):
            def parse_request(self):
                parsed = super().parse_request()
                if parsed:
                    self.server.all_requests.append({'method': self.command, 'path': self.path})
                return parsed

        require_loopback_namespace()
        self.temp = tempfile.TemporaryDirectory(prefix='uas-claude-sdk-receiver-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.scope = dict(SCOPE)
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('sender', 'actor-a'),
                                        FixtureParticipant('claude', 'actor-c')), 'run-1')
        self.sender = self.hub.connect('sender', 'sender', 'sender-inc', object())
        self.gateway = Gateway(('127.0.0.1', 0), ObservedHandler)
        self.gateway.key = 'fixture-only-' + uuid.uuid4().hex
        self.gateway.requests = []
        self.gateway.all_requests = []
        self.gateway.release = threading.Event()
        self.gateway.release.set()
        self.gateway.entered = threading.Event()
        self.thread = threading.Thread(target=lambda: self.gateway.serve_forever(poll_interval=.05), daemon=True)
        self.thread.start()
        self.addCleanup(self.close_gateway)
        self.native = None
        self.addCleanup(self.close_native)
        self.binary = Path(INSTALL) / 'node_modules/@anthropic-ai/claude-code-linux-x64/claude'
        self.started = time.monotonic()
        self.start()

    def kwargs(self, *, resume=False):
        return dict(cwd=self.root, home=self.home,
                    gateway_url=f'http://127.0.0.1:{self.gateway.server_port}', fixture_key=self.gateway.key,
                    journal=self.root / 'intent.db', scope=self.scope, resume=resume,
                    sdk_install=SDK_INSTALL, node=NODE, timeout=5)

    def start(self, *, resume=False, wait=True):
        self.native = claude_runtime.FixtureClaudeReceiver(self.binary, **self.kwargs(resume=resume))
        self.assertNotEqual(self.native.process.pid, self.native.native_pid,
                            'the SDK host PID is not native Participant authority')
        self.assertFalse(hasattr(self.native, 'refresh'), 'no synthetic model bootstrap or refresh API')
        self.connection = self.hub.connect('attach-' + self.native.incarnation_id,
                                          'claude', self.native.incarnation_id, self.native)
        self.assertEqual(self.hub.deliver(self.connection)['outcome'], 'HELD',
                         'attachment alone is never readiness')
        if wait:
            self.native.wait_safe()

    def close_native(self):
        self.gateway.release.set()
        if self.native is not None:
            native, self.native = self.native, None
            native.close()

    def close_gateway(self):
        self.gateway.release.set()
        self.gateway.shutdown()
        self.gateway.server_close()
        self.thread.join(timeout=2)

    def tearDown(self):
        if self.native is not None:
            print(json.dumps({'case': self.id(), 'elapsed_seconds': round(time.monotonic() - self.started, 3),
                'gateway_requests': len(self.gateway.requests), 'all_gateway_requests': self.gateway.all_requests,
                **self.native.evidence()}, sort_keys=True))

    def submit(self, id='work-1', text='Inspect fixture only.'):
        self.hub.submit(self.sender, WorkRequest(id, 'run-1', 1, 'claude', text))

    def deliver(self):
        self.hub.observe(self.connection, self.native.observe())
        return self.hub.deliver(self.connection, limit=1)

    def request(self, id='work-1'):
        return self.hub.snapshot()['state']['peer_traffic']['traffic'][id]

    def wait_result(self, message_id):
        deadline = time.monotonic() + 5
        while True:
            # Copy the bounded deque; the native reader may append concurrently.
            events = list(self.native.events.copy())
            result = next((e for e in events if e.get('type') == 'result'
                           and e.get('user_message_uuid') == message_id), None)
            if result is not None:
                self.assertEqual(result['session_id'], self.native.session_id)
                self.assertFalse(result['is_error'])
                return result
            self.assertLess(time.monotonic(), deadline, 'missing correlated native terminal event')
            time.sleep(.01)

    def test_no_input_and_later_idle_polling_then_busy_peer_clock_at_native_ack(self):
        self.assertIs(self.native.observe(), Readiness.SAFE)
        self.assertEqual(self.gateway.all_requests, [])
        time.sleep(2.1)
        self.native.wait_safe()
        self.assertIs(self.native.observe(), Readiness.SAFE)
        self.assertEqual(self.gateway.all_requests, [], 'polling must not create a bootstrap/model request')
        self.submit(text='FIRST-ACTUAL-PEER')
        self.submit('work-2', 'SECOND-ACTUAL-PEER')
        self.gateway.release.clear()
        self.gateway.entered.clear()
        original_wait = self.native._wait_ack
        def inspect_held_turn(message_id, content):
            self.assertTrue(self.gateway.entered.wait(timeout=3))
            self.assertIs(self.native._probe(), Readiness.BUSY)
            self.assertIs(self.native.observe(), Readiness.AMBIGUOUS,
                          'in-flight intent has no durable receipt yet')
            self.assertIsNone(self.request()['response_started_at'])
            self.assertIsNone(self.request('work-2')['response_started_at'])
            self.assertFalse(any(e.get('type') == 'result' and e.get('user_message_uuid') == message_id
                                 for e in self.native.events.copy()))
            self.assertEqual(len(self.gateway.requests), 1)
            # Blocking all provider bytes can also delay native replay ACK.
            # Never require ACK to precede a model response or completion.
            self.gateway.release.set()
            return original_wait(message_id, content)
        try:
            with patch.object(self.native, '_wait_ack', side_effect=inspect_held_turn):
                self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
            message_id, receipt = self.native.db.execute('SELECT message_id,receipt FROM handoffs').fetchone()
            self.assertEqual(json.loads(receipt)['uuid'], message_id)
            self.assertIsNotNone(self.request()['response_started_at'], 'Hub clock begins only after persisted exact native ACK')
            self.assertEqual(self.request()['status'], 'DELIVERED', 'input acceptance is not work acceptance')
            self.assertIsNone(self.request('work-2')['response_started_at'])
        finally:
            self.gateway.release.set()
        self.native.wait_safe()
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.native.wait_safe()
        self.assertEqual(len(self.gateway.requests), 2)
        self.assertTrue(self.native._host_alive(), 'one long-lived SDK host spans genuine peer turns')

    def test_lost_hub_return_resume_reconciles_once_then_real_peer_proves_history_and_fencing(self):
        self.submit(text='SDK-RECEIVER-HISTORY-NONCE')
        original = self.native.accept
        captured = []

        def lose_return(envelope):
            captured.append(dict(envelope))
            original(envelope)
            raise LedgerError('LOST_HUB_RETURN')

        with patch.object(self.native, 'accept', side_effect=lose_return):
            with self.assertRaisesRegex(LedgerError, 'LOST_HUB_RETURN'):
                self.deliver()
        self.assertIsNone(self.request()['response_started_at'])
        self.native.wait_safe()
        old_connection, session = self.connection, self.native.session_id
        self.close_native()
        self.start(resume=True)
        self.assertEqual(self.native.session_id, session)
        self.assertNotEqual(old_connection.incarnation_id, self.connection.incarnation_id)
        self.assertEqual(self.hub.deliver(old_connection)['outcome'], 'HELD')
        with self.assertRaisesRegex(LedgerError, 'NATIVE_SCOPE_MISMATCH'):
            self.native.accept(captured[0])
        before = len(self.gateway.all_requests)
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(len(self.gateway.all_requests), before, 'durable ACK reconciliation must not reinject')
        self.assertIsNotNone(self.request()['response_started_at'])
        self.submit('work-2', 'ACTUAL-NEXT-PEER-TURN')
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.native.wait_safe()
        history = json.dumps(self.gateway.requests[-1]['request']['messages'])
        self.assertEqual(history.count('SDK-RECEIVER-HISTORY-NONCE'), 1)
        self.assertEqual(history.count('ACTUAL-NEXT-PEER-TURN'), 1)
        self.assertEqual(len(self.gateway.requests), 2)
        self.close_native()
        self.scope['run_id'] = 'different-run'
        with self.assertRaisesRegex(ClaudeUnavailable, 'reset/remap unsupported'):
            self.start(resume=True)

    def test_native_ack_receipt_commit_failure_remains_unknown_across_resume(self):
        self.submit(text='SDK-RECEIVER-UNKNOWN-ACK')
        self.native.db.execute("CREATE TRIGGER fail_receipt BEFORE UPDATE ON handoffs "
            "WHEN NEW.receipt IS NOT NULL BEGIN SELECT RAISE(ABORT, 'fixture receipt failure'); END")
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        message_id, receipt = self.native.db.execute('SELECT message_id,receipt FROM handoffs').fetchone()
        self.assertIsNone(receipt)
        self.wait_result(message_id)
        self.assertEqual(sum(e.get('type') == 'user' and e.get('uuid') == message_id
                             for e in self.native.events.copy()), 1)
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        self.assertIsNone(self.request()['response_started_at'])
        self.native.db.execute('DROP TRIGGER fail_receipt')
        self.native.db.commit()
        session = self.native.session_id
        self.close_native()
        self.start(resume=True, wait=False)
        self.assertEqual(self.native.session_id, session)
        before = len(self.gateway.all_requests)
        self.native.wait_safe()  # Fresh native liveness/idle cannot settle durable responsibility.
        self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.submit('work-2', 'CANNOT-ROUTE-AROUND-UNKNOWN')
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertIsNone(self.request('work-2')['response_started_at'])
        self.assertEqual(len(self.gateway.all_requests), before)
        self.assertEqual(len(self.gateway.requests), 1)
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)

    def test_stopped_owned_native_control_fences_without_http_or_hub_delivery(self):
        self.submit()
        self.assertIs(self.native.observe(), Readiness.SAFE)
        os.kill(self.native.native_pid, signal.SIGSTOP)
        deadline = time.monotonic() + 1
        while '\nState:\tT' not in Path(f'/proc/{self.native.native_pid}/status').read_text():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.01)
        started = time.monotonic()
        readiness = self.native.observe()
        self.assertIn(readiness, (Readiness.AMBIGUOUS, Readiness.LOST))
        self.assertLess(time.monotonic() - started, 3)
        self.hub.observe(self.connection, readiness)
        self.assertEqual(self.hub.deliver(self.connection)['outcome'], 'HELD')
        self.assertEqual(self.hub.deliver(self.connection)['outcome'], 'HELD', 'no retry through stale safe evidence')
        self.assertIsNone(self.request()['response_started_at'])
        self.assertEqual(self.gateway.all_requests, [])
        self.assertEqual(self.native.db.execute('SELECT count(*) FROM handoffs').fetchone()[0], 0)

    def test_zero_byte_failure_then_non_model_poll_retries_same_uuid_with_one_native_ack(self):
        self.submit(text='SDK-ZERO-BYTE-RETRY-NONCE')
        with patch.object(self.native, '_write', side_effect=ClaudeNotApplied('injected zero host bytes')) as write:
            with self.assertRaisesRegex(LedgerError, 'NATIVE_NOT_APPLIED'):
                self.deliver()
            write.assert_called_once()
        message_id, receipt, retryable = self.native.db.execute(
            'SELECT message_id,receipt,retryable FROM handoffs').fetchone()
        self.assertIsNone(receipt)
        self.assertEqual(retryable, 1)
        self.assertEqual(self.gateway.all_requests, [])
        self.assertIsNone(self.request()['response_started_at'])
        self.native.wait_safe()
        self.assertEqual(self.gateway.all_requests, [], 'fresh readiness is a non-model control round trip')
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.native.wait_safe()
        after_id, receipt, retryable = self.native.db.execute(
            'SELECT message_id,receipt,retryable FROM handoffs').fetchone()
        self.assertEqual(after_id, message_id)
        self.assertEqual(json.loads(receipt)['uuid'], message_id)
        self.assertEqual(retryable, 0)
        self.assertEqual(sum(e.get('type') == 'user' and e.get('uuid') == message_id
                             for e in self.native.events.copy()), 1)
        self.assertEqual(len(self.gateway.requests), 1)
        self.assertEqual(json.dumps(self.gateway.requests[0]['request']['messages']).count('SDK-ZERO-BYTE-RETRY-NONCE'), 1)
        self.assertIsNotNone(self.request()['response_started_at'])
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertEqual(len(self.gateway.requests), 1)

    def test_failed_zero_byte_classification_stays_unknown_without_any_native_input(self):
        self.submit()
        self.native.db.execute("CREATE TRIGGER fail_classification BEFORE UPDATE ON handoffs "
            "WHEN NEW.retryable=1 BEGIN SELECT RAISE(ABORT, 'fixture classification failure'); END")
        with patch.object(self.native, '_write', side_effect=ClaudeNotApplied('injected zero host bytes')):
            with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
                self.deliver()
        self.native.db.execute('DROP TRIGGER fail_classification')
        self.native.db.commit()
        self.native.wait_safe()
        self.assertEqual(self.native.evidence()['retryable_intents'], 0)
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertIsNone(self.request()['response_started_at'])
        self.assertEqual(self.gateway.all_requests, [])

    def test_partial_owned_host_frame_remains_unknown_after_real_same_session_resume(self):
        self.submit(text='SDK-PARTIAL-HOST-PRIOR-HISTORY')
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.native.wait_safe()
        self.assertEqual(len(self.gateway.requests), 1)
        self.submit('work-2', 'SECOND-UNCONFIRMED-' + 'x' * 16000)
        original = self.native._write
        real_write = os.write
        host_fd = self.native.process.stdin.fileno()
        partial_writes = []
        stopped = False

        def track_actual_write(fd, data):
            count = real_write(fd, data)
            if stopped and fd == host_fd:
                partial_writes.append(count)
            return count

        def stop_owned_host_then_write(message_id, content, **kwargs):
            nonlocal stopped
            self.assertTrue(kwargs.get('peer'))
            self.assertGreater(len(content.encode()), 4096)
            # Stop only the disposable SDK host, not an unrelated process or
            # the native CLI. A partial wrapper frame is not a native receipt.
            os.kill(self.native.process.pid, signal.SIGSTOP)
            deadline = time.monotonic() + 1
            while '\nState:\tT' not in Path(f'/proc/{self.native.process.pid}/status').read_text():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            fcntl.fcntl(host_fd, fcntl.F_SETPIPE_SZ, 4096)
            stopped = True
            self.native.timeout = .2
            return original(message_id, content, **kwargs)

        before = len(self.gateway.all_requests)
        with patch.object(self.native, '_write', side_effect=stop_owned_host_then_write), \
             patch('uas.claude_runtime.os.write', side_effect=track_actual_write):
            with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
                self.deliver()
        self.assertGreater(sum(partial_writes), 0, 'actual owned-host pipe received a partial frame')
        self.assertLessEqual(sum(partial_writes), 4096)
        message_id, receipt, retryable = self.native.db.execute(
            'SELECT message_id,receipt,retryable FROM handoffs WHERE receipt IS NULL').fetchone()
        self.assertIsNone(receipt)
        self.assertEqual(retryable, 0)
        self.assertFalse(any(e.get('type') == 'user' and e.get('uuid') == message_id
                             for e in self.native.events.copy()))
        self.assertIsNone(self.request('work-2')['response_started_at'])
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        self.assertEqual(len(self.gateway.all_requests), before)
        session = self.native.session_id
        self.close_native()  # Receiver's bounded cleanup kills only its own stopped process group.
        self.start(resume=True, wait=False)
        self.assertEqual(self.native.session_id, session)
        self.native.wait_safe()
        self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        self.assertIsNone(self.request('work-2')['response_started_at'])
        self.assertEqual(len(self.gateway.all_requests), before, 'unknown host handoff must never reinject')
