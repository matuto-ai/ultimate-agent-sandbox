"""Pure receiver authority/fresh-proof policy; no native process or kernel access."""
import json
import io
from collections import deque
import threading
import sqlite3
import unittest
from unittest.mock import Mock, patch

from uas.claude_runtime import ClaudeUnavailable, ClaudeSignals, FixtureClaudeReceiver
from uas.ledger import LedgerError
from uas.peer import Readiness


class ClaudeAuthoritySourceTests(unittest.TestCase):
    def receiver(self):
        receiver = FixtureClaudeReceiver.__new__(FixtureClaudeReceiver)
        receiver.resumed = False
        receiver.authorize = None
        receiver.scope = {'room_id': 'alpha', 'participant_id': 'claude', 'run_id': 'run-b',
                          'generation': 2, 'context_generation': 7}
        receiver.incarnation_id = 'supervisor-incarnation'
        receiver.session_id = '11111111-1111-4111-8111-111111111111'
        receiver.db = sqlite3.connect(':memory:')
        self.addCleanup(receiver.db.close)
        receiver.db.execute('CREATE TABLE handoffs (logical_digest TEXT PRIMARY KEY, logical TEXT, '
                            'message_id TEXT, receipt TEXT, retryable INTEGER DEFAULT 0)')
        receiver._probe = Mock(return_value=Readiness.SAFE)
        return receiver

    def test_revoked_badge_cannot_observe_safe_or_touch_a_journal(self):
        receiver = self.receiver()
        receiver.authorize = Mock(side_effect=LedgerError('AUTHORITY_REVOKED'))
        self.assertIs(receiver.observe(), Readiness.LOST)
        with self.assertRaisesRegex(ClaudeUnavailable, 'Supervisor authority'):
            receiver.accept({})
        receiver._probe.assert_not_called()
        self.assertEqual(0, receiver.db.execute('SELECT count(*) FROM handoffs').fetchone()[0])

    def test_late_revocation_keeps_native_receipt_but_cannot_return_hub_acceptance(self):
        receiver = self.receiver()
        receiver.authorize = Mock(side_effect=[True, LedgerError('AUTHORITY_REVOKED')])
        receiver.observe = Mock(return_value=Readiness.SAFE)
        receiver._write = Mock()
        receiver._wait_ack = lambda message_id, content: {
            'type': 'user', 'uuid': message_id, 'session_id': receiver.session_id,
            'isReplay': True, 'parent_tool_use_id': None, 'message': {'role': 'user', 'content': content}}
        envelope = {**receiver.scope, 'incarnation_id': receiver.incarnation_id,
                    'delivery_id': 'delivery', 'id': 'work', 'kind': 'peer.work-request', 'text': 'source-only'}
        with self.assertRaisesRegex(ClaudeUnavailable, 'Supervisor authority'):
            receiver.accept(envelope)
        row = receiver.db.execute('SELECT receipt FROM handoffs').fetchone()
        self.assertEqual('user', json.loads(row[0])['type'])
        receiver._write.assert_called_once()

    def test_fresh_proof_rejects_resume_prior_session_intents_and_missing_idle(self):
        receiver = self.receiver()
        proof = receiver.prove_fresh_context(preceding_session='old-session')
        self.assertEqual(receiver.session_id, proof['session_id'])
        receiver.resumed = True
        with self.assertRaises(ClaudeUnavailable):
            receiver.prove_fresh_context()
        receiver.resumed = False
        with self.assertRaises(ClaudeUnavailable):
            receiver.prove_fresh_context(preceding_session=receiver.session_id)
        receiver._probe.return_value = Readiness.AMBIGUOUS
        with self.assertRaises(ClaudeUnavailable):
            receiver.prove_fresh_context()
        receiver._probe.return_value = Readiness.SAFE
        receiver.db.execute("INSERT INTO handoffs VALUES('id','{}','uuid',NULL,0)")
        with self.assertRaises(ClaudeUnavailable):
            receiver.prove_fresh_context()

    def test_deferred_initialization_preserves_error_for_controller_owned_cleanup(self):
        receiver = FixtureClaudeReceiver.__new__(FixtureClaudeReceiver)
        failure = ClaudeUnavailable('fixed startup failure')
        receiver._wait = Mock(side_effect=failure)
        receiver._startup_failed = Mock()
        with self.assertRaises(ClaudeUnavailable) as caught:
            receiver.wait_ready()
        self.assertIs(failure, caught.exception)
        receiver._startup_failed.assert_not_called()
        self.assertIs(failure, receiver.startup_error)

    def test_early_native_identity_is_cleanup_ownership_never_readiness(self):
        receiver = FixtureClaudeReceiver.__new__(FixtureClaudeReceiver)
        receiver.process = Mock(pid=101)
        receiver.process.stdout = io.BytesIO((json.dumps({'type': 'native-spawned',
            'host_pid': 101, 'native_pid': 202, 'native_start': '123',
            'session_id': 'session'}) + '\n').encode())
        receiver.condition = threading.Condition()
        receiver.signals = ClaudeSignals('session')
        receiver.session_id = 'session'
        receiver.ready = receiver.closing = receiver.ended = False
        receiver.native_pid = receiver.native_pidfd = receiver.native_start = None
        receiver.errors = deque()
        receiver._terminate_host = Mock()
        with patch('uas.claude_runtime._sdk_native_pidfd', return_value=303) as bind:
            receiver._read()
        bind.assert_called_once_with(202, 101, '123')
        self.assertEqual((202, 303, '123'), (receiver.native_pid, receiver.native_pidfd, receiver.native_start))
        self.assertFalse(receiver.ready)
        self.assertTrue(receiver.ended)
        self.assertEqual([], list(receiver.errors))
