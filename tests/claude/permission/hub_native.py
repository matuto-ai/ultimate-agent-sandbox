"""Deliberate account-free Hub/SDK permission integration qualification.

Run only inside the existing isolated manual native tier. Fixture-controller
choices are not human authority. Unknown-intent insertion is a source fault.
"""
import json
import os
from pathlib import Path
import select
import sys
import tempfile
import threading
import time
import unittest
import uuid

from native import Gateway, Handler, tool_results

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from uas.claude_runtime import FixtureClaudeReceiver, require_loopback_namespace
from uas.ledger import RoomLedger
from uas.peer import FixtureParticipant, FixturePeerHub, Readiness, WorkRequest


class HubPermissionTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.environ.get('UAS_CLAUDE_PERMISSION_NATIVE'), '1')
        for key in ('UAS_CLAUDE_NODE', 'UAS_CLAUDE_INSTALL', 'UAS_CLAUDE_SDK_INSTALL'):
            self.assertTrue(os.environ.get(key), key + ' required')
        require_loopback_namespace()
        self.temp = tempfile.TemporaryDirectory(prefix='uas-hub-permission-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.nonce = 'HUB-READ-NONCE-' + uuid.uuid4().hex
        self.file = self.root / 'nonce.txt'
        self.file.write_text(self.nonce + '\n')
        self.gateway = Gateway(('127.0.0.1', 0), Handler)
        self.gateway.key = 'fixture-only-' + uuid.uuid4().hex
        self.gateway.tool_id = 'toolu_fixture_' + uuid.uuid4().hex
        self.gateway.nonce_file = self.file
        self.gateway.max_turns = 3
        self.gateway.requests = []
        self.gateway.lock = threading.Lock()
        self.thread = threading.Thread(target=lambda: self.gateway.serve_forever(poll_interval=.05), daemon=True)
        self.thread.start()
        self.addCleanup(self.close_gateway)
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('sender', 'actor-a'),
                                        FixtureParticipant('claude', 'actor-c')), 'run-1')
        self.sender = self.hub.connect('sender', 'sender', 'sender-inc', object())
        self.native = None
        self.observations = []
        self.addCleanup(self.report)
        self.addCleanup(self.close_native)
        self.native = FixtureClaudeReceiver(
            Path(os.environ['UAS_CLAUDE_INSTALL']) / 'node_modules/@anthropic-ai/claude-code-linux-x64/claude',
            node=os.environ['UAS_CLAUDE_NODE'], sdk_install=os.environ['UAS_CLAUDE_SDK_INSTALL'],
            cwd=self.root, home=self.home, gateway_url=f'http://127.0.0.1:{self.gateway.server_port}',
            fixture_key=self.gateway.key, journal=self.root / 'handoff.db', timeout=5,
            scope={'room_id': 'alpha', 'participant_id': 'claude', 'run_id': 'run-1',
                   'generation': 1, 'context_generation': 1}, diagnostic_nonce_file=self.file)
        self.connection = self.hub.connect('attach', 'claude', self.native.incarnation_id, self.native)
        self.native.wait_safe()
        self.assertEqual(self.gateway.requests, [], 'initial readiness is non-model evidence')

    def close_gateway(self):
        self.gateway.shutdown()
        self.gateway.server_close()
        self.thread.join(timeout=2)

    def close_native(self):
        if self.native is None:
            return
        native, self.native = self.native, None
        host_fd, native_fd = os.dup(native.host_pidfd), os.dup(native.native_pidfd)
        process = native.process
        events = list(native.events)
        capture_complete = len(events) < native.events.maxlen
        self.observations.append({'type': 'native-evidence', 'events': events,
                                  'capture_complete': capture_complete,
                                  'attention': native.signals.permission})
        try:
            native.close()
            receipt = {'type': 'cleanup', 'host_exited': bool(select.select([host_fd], [], [], 0)[0]),
                       'native_exited': bool(select.select([native_fd], [], [], 0)[0]),
                       'host_reaped': process.returncode is not None}
            self.observations.append(receipt)
            self.assertTrue(all(receipt[k] for k in ('host_exited', 'native_exited', 'host_reaped')))
            self.assertTrue(capture_complete, 'bounded event capture may not truncate evidence')
        finally:
            os.close(host_fd)
            os.close(native_fd)

    def wait(self, predicate):
        deadline = time.monotonic() + 5
        while True:
            result = predicate()
            if result:
                return result
            self.assertLess(time.monotonic(), deadline, 'missing mandatory native evidence')
            self.assertFalse(self.native.ended, list(self.native.errors))
            time.sleep(.01)

    def request(self, key):
        return self.hub.snapshot()['state']['peer_traffic']['traffic'][key]

    def deliver(self):
        self.hub.observe(self.connection, self.native.observe())
        return self.hub.deliver(self.connection, limit=1)

    def begin(self):
        for key in ('first', 'second'):
            self.hub.submit(self.sender, WorkRequest(key, 'run-1', 1, 'claude', key + '-ACTUAL-PEER'))
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        attention = self.wait(lambda: self.native.signals.permission)
        self.wait(lambda: any(e.get('subtype') == 'session_state_changed' and e.get('state') == 'requires_action'
                              and e.get('session_id') == self.native.session_id for e in self.native.events.copy()))
        row = self.native.db.execute('SELECT message_id,receipt FROM handoffs').fetchone()
        self.assertEqual(json.loads(row[1])['uuid'], row[0])
        self.assertTrue(json.loads(row[1])['isReplay'])
        self.assertIsNotNone(self.request('first')['response_started_at'])
        self.assertEqual(attention['invocationId'], row[0])
        self.assertEqual(attention['sessionId'], self.native.session_id)
        self.assertEqual(attention['toolUseID'], self.gateway.tool_id)
        self.assert_pending()
        return dict(attention)

    def assert_queued(self, handoffs=1):
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertEqual(self.request('second')['status'], 'QUEUED')
        self.assertIsNone(self.request('second')['response_started_at'])
        self.assertEqual(self.native.db.execute('SELECT count(*) FROM handoffs').fetchone()[0], handoffs)
        self.assertNotIn('second', self.hub.snapshot()['state']['peer_traffic']['offers'])
        self.observations.append({'type': 'held-queue', 'second': self.request('second'),
                                  'handoff_rows': handoffs, 'gateway_requests': len(self.gateway.requests)})

    def assert_pending(self):
        self.assert_queued()
        time.sleep(.1)
        self.assertEqual(len(self.gateway.requests), 1)
        self.assertNotIn(self.nonce, json.dumps(self.gateway.requests))
        self.assertNotIn('second-ACTUAL-PEER', json.dumps(self.gateway.requests))
        self.assertFalse(any(e.get('type') == 'result' for e in self.native.events.copy()))

    def allow(self, identity):
        self.assertFalse(self.native.fixture_decide({**identity, 'incarnation': str(uuid.uuid4())}, 'allow'))
        self.assert_pending()
        self.assertTrue(self.native.fixture_decide(identity, 'allow'))
        self.assertFalse(self.native.fixture_decide(identity, 'allow'))
        terminal = self.wait(lambda: next((e for e in self.native.events.copy()
            if e.get('type') == 'result' and e.get('user_message_uuid') == identity['invocationId']), None))
        self.assertFalse(terminal['is_error'])
        self.assertEqual(terminal['permission_denials'], [])
        self.assertEqual(len(self.gateway.requests), 2)
        result = tool_results(self.gateway.requests[1], self.gateway.tool_id)
        self.assertEqual(len(result), 1)
        self.assertIn(self.nonce, json.dumps(result[0]))
        self.assertIsNone(self.request('second')['response_started_at'])
        self.observations.append({'type': 'allowed-terminal', 'terminal': terminal})

    def test_allow_recovers_real_queued_envelope_only_after_fresh_idle(self):
        identity = self.begin()
        self.allow(identity)
        self.recover_second()

    def recover_second(self):
        first_before = dict(self.request('first'))
        first_receipt = self.native.db.execute('SELECT receipt FROM handoffs ORDER BY rowid LIMIT 1').fetchone()[0]
        session, incarnation = self.native.session_id, self.native.incarnation_id
        self.native.wait_safe()  # Mandatory fresh public control plus exact native idle listing.
        self.assertIs(self.native.observe(), Readiness.SAFE)
        self.assertEqual(len(self.gateway.requests), 2, 'fresh polling must not send a model turn')
        self.assertEqual((self.native.session_id, self.native.incarnation_id), (session, incarnation))
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.native.wait_safe()
        rows = self.native.db.execute('SELECT logical,message_id,receipt FROM handoffs').fetchall()
        self.assertEqual(len(rows), 2)
        for logical, message_id, wire in rows:
            ack = json.loads(wire)
            self.assertEqual(ack['uuid'], message_id)
            self.assertEqual(ack['session_id'], session)
            self.assertTrue(ack['isReplay'])
            self.assertEqual(ack['parent_tool_use_id'], None)
            self.assertEqual(ack['message']['content'], 'Untrusted peer traffic (not human authorization):\n'
                             + json.dumps(json.loads(logical), ensure_ascii=False, sort_keys=True))
        self.assertEqual(self.request('first'), first_before)
        self.assertEqual(self.native.db.execute('SELECT receipt FROM handoffs ORDER BY rowid LIMIT 1').fetchone()[0], first_receipt)
        self.assertIsNotNone(self.request('second')['response_started_at'])
        self.assertEqual(len(self.gateway.requests), 3)
        self.assertIn('second-ACTUAL-PEER', json.dumps(self.gateway.requests[2]))
        self.observations.append({'type': 'recovery', 'session': session, 'incarnation': incarnation,
                                  'receipt_count': 2, 'receipts': [json.loads(row[2]) for row in rows],
                                  'second': self.request('second')})

    def test_source_unknown_intent_is_not_cleared_by_native_allow(self):
        self.unknown_intent('allow')

    def test_source_unknown_intent_is_not_cleared_by_native_deny(self):
        self.unknown_intent('deny')

    def unknown_intent(self, behavior):
        identity = self.begin()
        # Source fault injection, not a native crash or real unknown receipt claim.
        with self.native.db:
            self.native.db.execute('INSERT INTO handoffs (logical_digest,logical,message_id,receipt) VALUES (?,?,?,NULL)',
                                   ('source-unknown', '{}', str(uuid.uuid4())))
        self.assertTrue(self.native.fixture_decide(identity, behavior))
        self.wait(lambda: self.native.signals.completed_id == identity['invocationId'])
        self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
        self.assert_queued(handoffs=2)
        self.assertEqual(self.native.db.execute("SELECT receipt,retryable FROM handoffs WHERE logical_digest='source-unknown'").fetchone(), (None, 0))
        self.assertEqual(len(self.gateway.requests), 2)
        self.observations.append({'type': 'source-injected-unknown-preserved', 'native_decision': behavior})
        if behavior == 'deny':
            self.assertNotIn(self.nonce, json.dumps(self.gateway.requests))

    def test_exact_deny_recovers_queue_only_after_fresh_idle(self):
        identity = self.begin()
        self.assertFalse(self.native.fixture_decide({**identity, 'incarnation': str(uuid.uuid4())}, 'deny'))
        self.assert_pending()
        self.assertTrue(self.native.fixture_decide(identity, 'deny'))
        self.assertFalse(self.native.fixture_decide(identity, 'allow'))
        self.assertFalse(self.native.fixture_decide(identity, 'deny'))
        terminal = self.wait(lambda: next((e for e in self.native.events.copy()
            if e.get('type') == 'result' and e.get('user_message_uuid') == identity['invocationId']), None))
        self.assertEqual(terminal['permission_denials'], [{'tool_name': 'Read', 'tool_use_id': identity['toolUseID'],
                                                        'tool_input': {'file_path': str(self.file)}}])
        self.assertFalse(terminal['is_error'])
        self.assertEqual(terminal['terminal_reason'], 'completed')
        self.assertEqual(terminal['stop_reason'], 'end_turn')
        self.assertEqual(terminal['queued_turn_count'], 0)
        self.assertIsNone(self.request('second')['response_started_at'])
        self.assertEqual(self.request('second')['status'], 'QUEUED')
        self.assertNotIn(self.nonce, json.dumps(self.gateway.requests))
        self.assertEqual(len(self.gateway.requests), 2)
        result = tool_results(self.gateway.requests[1], self.gateway.tool_id)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['is_error'])
        self.observations.append({'type': 'denied-terminal', 'terminal': terminal})
        self.recover_second()
        self.assertNotIn(self.nonce, json.dumps(self.gateway.requests))
        self.assertNotIn(self.nonce, json.dumps(list(self.native.events.copy())))

    def test_pending_close_never_releases_queued_envelope(self):
        self.begin()
        self.close_native()
        self.assertEqual(len(self.gateway.requests), 1)
        self.assertNotIn(self.nonce, json.dumps(self.gateway.requests))
        self.assertIsNone(self.request('second')['response_started_at'])
        self.assertEqual(self.request('second')['status'], 'QUEUED')

    def report(self):
        print(json.dumps({'qualification': self.id(), 'sdk_version': '0.3.310', 'cli_version': '2.1.310',
                          'provider': 'loopback-fixture-only', 'human_authority': False,
                          'hub_delivery_integration': True, 'observations': self.observations,
                          'gateway_requests': self.gateway.requests}, sort_keys=True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
