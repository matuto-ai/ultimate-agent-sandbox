"""Pi receiver journal generation CAS only; no process, native session or RPC."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from uas.pi_runtime import FixturePiRpcReceiver, NativeUnavailable
from uas.ledger import LedgerError


class RunGenerationBindingTests(unittest.TestCase):
    def test_controller_checkpoint_and_journal_retry_preserve_reset_lineage_and_session(self):
        from uas.participant import FixtureParticipantController
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / 'sessions'
            sessions.mkdir()
            old = {**self.old, 'context_generation': 2}
            new = {**old, 'generation': 2}
            self.receiver.scope = old
            self.db.execute('UPDATE binding SET scope=?', (json.dumps(old),))
            self.db.commit()
            proof = {'runtime_id': 'same-runtime', 'session_id': 'same-session',
                     'session_file': str(sessions / 'same-session.jsonl'),
                     'source': 'native-empty-session-and-no-pending-messages'}
            self.receiver.initial_state = deepcopy(proof)
            controller = FixtureParticipantController.__new__(FixtureParticipantController)
            controller.path = root / 'participants.json'
            controller.instance = 'room-instance'
            controller.supervisor = SimpleNamespace(_sync_directory=lambda _path: None)
            controller._authority = lambda *_: True  # explicit synthetic ownership
            recipe = SimpleNamespace(scope=old, directory=root, session_directory=sessions)
            handle = SimpleNamespace(badge=SimpleNamespace(participant_id='builder'),
                process=SimpleNamespace(pid=1), connection=SimpleNamespace(receiver=self.receiver), pi_recipe=recipe)
            controller._save_pi_checkpoint('builder', recipe, 'original-native-reset', proof)
            save = controller._save_pi_checkpoint
            def save_then_lose(*args):
                save(*args)
                raise OSError('synthetic lost checkpoint acknowledgement')
            with patch.object(controller, '_save_pi_checkpoint', save_then_lose), self.assertRaises(OSError):
                controller._advance_pi_generation_locked(handle, old, new, authorize=lambda: True)
            self.assertEqual(new, self.binding())
            controller._advance_pi_generation_locked(handle, old, new, authorize=lambda: True)
            saved = json.loads(controller._pi_checkpoint_path('builder').read_text())
            self.assertEqual(new, saved['scope'])
            self.assertEqual('original-native-reset', saved['reset_id'])
            self.assertEqual(proof, saved['native'])
            self.assertEqual(new, handle.pi_recipe.scope)
            controller._pi_checkpoint_path('builder').unlink()
            with self.assertRaises(LedgerError) as caught:
                controller._advance_pi_generation_locked(handle, new, {**new, 'generation': 3}, authorize=lambda: True)
            self.assertEqual('NATIVE_CONTEXT_RESTORE_UNVERIFIED', caught.exception.code)
            self.assertEqual(new, self.binding())

    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE binding (singleton INTEGER PRIMARY KEY, scope TEXT NOT NULL)')
        self.db.execute('CREATE TABLE handoffs (id TEXT PRIMARY KEY, envelope TEXT NOT NULL)')
        self.old = {'room_id': 'alpha', 'participant_id': 'builder', 'run_id': 'run-test',
                    'generation': 1, 'context_generation': 1}
        self.new = {**self.old, 'generation': 2}
        self.db.execute('INSERT INTO binding VALUES (1, ?)', (json.dumps(self.old),))
        self.db.execute('INSERT INTO handoffs VALUES (?, ?)', ('old-intent', json.dumps(self.old)))
        self.db.commit()
        self.receiver = FixturePiRpcReceiver.__new__(FixturePiRpcReceiver)
        self.receiver._closed = False
        self.receiver._scope_lock = threading.RLock()
        self.receiver.scope = deepcopy(self.old)
        self.receiver.db = self.db
        self.receiver.incarnation_id = 'synthetic-incarnation'

    def advance(self, old=None, new=None, authorize=lambda: True):
        return self.receiver.advance_run_generation(self.old if old is None else old,
            self.new if new is None else new, authorize=authorize)

    def binding(self):
        return json.loads(self.db.execute('SELECT scope FROM binding WHERE singleton=1').fetchone()[0])

    def test_exact_same_context_advance_and_retry_preserve_old_handoffs(self):
        before = self.db.execute('SELECT * FROM handoffs').fetchall()
        self.assertEqual(self.new, self.advance())
        self.assertEqual(self.new, self.binding())
        self.assertEqual(self.new, self.receiver.scope)
        self.assertEqual(self.new, self.advance())
        self.assertEqual(before, self.db.execute('SELECT * FROM handoffs').fetchall())
        self.assertEqual(1, self.receiver.scope['context_generation'])

    def test_wrong_scope_generation_types_or_authority_cannot_change_journal(self):
        for target in ({**self.new, 'run_id': 'other-run'}, {**self.new, 'room_id': 'beta'},
                       {**self.new, 'participant_id': 'reviewer'},
                       {**self.new, 'context_generation': 2},
                       {**self.new, 'context_generation': True},
                       {**self.new, 'generation': True}, {**self.new, 'generation': 3},
                       {**self.new, 'generation': 2.0}, {**self.new, 'extra': 'not-scope'}):
            with self.subTest(target=target), self.assertRaises(NativeUnavailable):
                self.advance(new=target)
        with self.assertRaises(NativeUnavailable):
            self.advance(authorize=lambda: False)
        with self.assertRaises(NativeUnavailable):
            self.advance(old={**self.old, 'generation': 0}, new=self.old)
        self.assertEqual(self.old, self.binding())
        self.assertEqual(self.old, self.receiver.scope)
        malformed = {**self.old, 'context_generation': True}
        self.db.execute('UPDATE binding SET scope=?', (json.dumps(malformed),))
        self.db.commit()
        with self.assertRaises(NativeUnavailable):
            self.advance()
        self.assertIs(True, self.binding()['context_generation'])

    def test_prepared_old_generation_offer_cannot_reach_native_after_fence(self):
        envelope = {**self.old, 'incarnation_id': self.receiver.incarnation_id,
                    'delivery_id': 'old-delivery', 'text': 'old generation'}
        def no_native(*_args):
            raise AssertionError('stale offer must not observe or invoke native runtime')
        self.receiver.observe = no_native
        self.receiver._native = no_native
        self.advance()
        with self.assertRaises(LedgerError) as caught:
            self.receiver.accept(envelope)
        self.assertEqual('NATIVE_SCOPE_MISMATCH', caught.exception.code)
        self.assertEqual([('old-intent', json.dumps(self.old))],
                         self.db.execute('SELECT * FROM handoffs').fetchall())

    def test_authority_is_rechecked_inside_transaction_and_rollback_is_exact(self):
        calls = []
        def authorize():
            calls.append('authorize')
            return len(calls) == 1
        with self.assertRaises(NativeUnavailable):
            self.advance(authorize=authorize)
        self.assertEqual(2, len(calls))
        self.assertEqual(self.old, self.binding())
        self.assertFalse(self.db.in_transaction)
        self.receiver._closed = True
        with self.assertRaises(NativeUnavailable):
            self.advance()
        self.assertEqual(self.old, self.binding())

    def test_lost_commit_ack_reconciles_exact_journal_without_reinjecting(self):
        database = self.db
        class LostAck:
            def execute(self, *args): return database.execute(*args)
            def rollback(self): return database.rollback()
            def commit(self):
                database.commit()
                raise sqlite3.OperationalError('synthetic lost acknowledgement')
        self.receiver.db = LostAck()
        with self.assertRaises(sqlite3.OperationalError):
            self.advance()
        self.assertEqual(self.new, self.binding())
        self.assertEqual(self.old, self.receiver.scope)
        self.receiver.db = self.db
        self.assertEqual(self.new, self.advance())
        self.assertEqual([('old-intent', json.dumps(self.old))],
                         self.db.execute('SELECT * FROM handoffs').fetchall())

