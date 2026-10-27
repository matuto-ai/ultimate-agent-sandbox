"""Pure SQLite regressions for the external read Room-operation reservation.

No Broker process, listener, credential, provider or executable is started here.
The Room owns operation identity; external ForgeAudit owns read observations.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.forge import ForgeBinding
from uas.forge_read_service import reserve_read_operation
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition, _json


class ReadReservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'room.db'
        self.ledger = RoomLedger(self.path, 'room')
        self.addCleanup(lambda: self.ledger.close())
        self.binding = ForgeBinding('room', 'project', 'owner/repo')
        self.origin = Origin('actor', 'participant', 'incarnation', 'epoch', ('forge-read',))
        self.envelope = {'id': 'operation', 'kind': 'forge-read',
                         'argv': ['repo', 'read-file', 'PRIVATE_ARGV_SOURCE.md']}
        self.allowed = True
        self.authorizations = []

    def authorize(self):
        self.authorizations.append(self.ledger._connection().in_transaction)
        return self.allowed

    def reserve(self, *, envelope=None, origin=None, binding=None, authorize=None):
        return reserve_read_operation(
            self.ledger, binding or self.binding,
            self.envelope if envelope is None else envelope,
            self.origin if origin is None else origin,
            self.authorize if authorize is None else authorize)

    def assert_code(self, code, callback):
        with self.assertRaises(LedgerError) as raised:
            callback()
        self.assertEqual(code, raised.exception.code)

    def persisted_operation(self):
        row = self.ledger._connection().execute(
            'SELECT canonical, receipt FROM operations WHERE id=?',
            (self.envelope['id'],)).fetchone()
        return json.loads(row['canonical']), json.loads(row['receipt'])

    def assert_empty(self):
        self.assertEqual({'room_id': 'room', 'room_seq': 0, 'state': {}}, self.ledger.snapshot())
        self.assertEqual([], self.ledger.replay(0))
        self.assertEqual(0, self.ledger._connection().execute('SELECT count(*) FROM operations').fetchone()[0])

    def test_exact_command_and_metadata_only_event(self):
        receipt = self.reserve()
        payload = {'request_digest': hashlib.sha256(_json(self.envelope).encode()).hexdigest(),
                   'host': 'github.com', 'repository': 'owner/repo'}
        stored, stored_receipt = self.persisted_operation()
        self.assertEqual({'room_id': 'room',
            'command': Command('operation', 'forge-read-external', 'project', None, payload).canonical(),
            'origin': self.origin.canonical()}, stored)
        self.assertEqual(receipt, stored_receipt)
        self.assertEqual('operation', receipt['operation_id'])
        self.assertEqual(1, receipt['first_seq'])
        self.assertEqual(1, receipt['last_seq'])
        events = self.ledger.replay(0)
        self.assertEqual(1, len(events))
        self.assertEqual('forge-read-reserved', events[0]['kind'])
        self.assertEqual(payload, events[0]['payload'])
        self.assertEqual('project', events[0]['target'])
        self.assertIsNone(events[0]['generation'])
        self.assertEqual(self.origin.canonical(), events[0]['origin'])
        self.assertEqual({}, self.ledger.snapshot()['state'])

    def test_exact_retry_does_not_append_and_returns_unchanged_receipt(self):
        first = self.reserve()
        # Object insertion order is not an operation-identity change.
        reordered = {'argv': list(self.envelope['argv']), 'kind': 'forge-read', 'id': 'operation'}
        second = self.reserve(envelope=reordered)
        self.assertEqual(first, second)
        self.assertEqual(1, self.ledger.snapshot()['room_seq'])
        self.assertEqual(1, len(self.ledger.replay(0)))

    def test_reservation_survives_reopen_without_rewriting_receipt(self):
        first = self.reserve()
        self.ledger.close()
        self.ledger = RoomLedger(self.path, 'room')
        self.assertEqual(first, self.reserve())
        self.assertEqual(1, self.ledger.snapshot()['room_seq'])

    def test_authorization_is_fresh_even_for_an_exact_retry(self):
        first = self.reserve()
        previous_calls = len(self.authorizations)
        self.allowed = False
        self.assert_code('FORBIDDEN', self.reserve)
        self.assertGreater(len(self.authorizations), previous_calls)
        self.allowed = True
        self.assertEqual(first, self.reserve())
        self.assertEqual(1, self.ledger.snapshot()['room_seq'])

    def test_authorization_is_rechecked_inside_the_write_transaction(self):
        def revoke_under_lock():
            # A pre-lock allow decision must not survive lock acquisition.
            return not self.ledger._connection().in_transaction
        self.assert_code('FORBIDDEN', lambda: self.reserve(authorize=revoke_under_lock))
        self.assert_empty()

    def test_only_literal_true_authorizes(self):
        for decision in (False, None, 1, 'yes'):
            with self.subTest(decision=decision):
                self.assert_code('FORBIDDEN', lambda: self.reserve(authorize=lambda: decision))
                self.assert_empty()

    def test_forge_read_capability_required_despite_fresh_authorization(self):
        for capabilities in ((), ('forge-write',), ('peer-send',)):
            with self.subTest(capabilities=capabilities):
                self.assert_code('FORBIDDEN', lambda: self.reserve(
                    origin=replace(self.origin, capabilities=capabilities)))
                self.assert_empty()

    def test_same_id_changed_argv_conflicts_without_extra_event(self):
        first = self.reserve()
        changed = {**self.envelope, 'argv': ['repo', 'read-file', 'DIFFERENT_PRIVATE_PATH.md']}
        self.assert_code('ID_CONFLICT', lambda: self.reserve(envelope=changed))
        self.assertEqual(first, self.reserve())
        self.assertEqual(1, len(self.ledger.replay(0)))

    def test_same_id_changed_origin_conflicts_for_each_authenticated_field(self):
        self.reserve()
        changes = ({'actor_id': 'other-actor'}, {'participant_id': 'other-peer'},
                   {'incarnation_id': 'other-incarnation'}, {'authority_version': 'other-epoch'},
                   {'capabilities': ('forge-read', 'peer-send')})
        for change in changes:
            with self.subTest(change=change):
                self.assert_code('ID_CONFLICT', lambda: self.reserve(origin=replace(self.origin, **change)))
        self.assertEqual(1, len(self.ledger.replay(0)))

    def test_capability_order_is_canonical_not_a_new_identity(self):
        first = self.reserve(origin=replace(self.origin, capabilities=('forge-read', 'peer-send')))
        second = self.reserve(origin=replace(self.origin, capabilities=('peer-send', 'forge-read')))
        self.assertEqual(first, second)
        self.assertEqual(1, self.ledger.snapshot()['room_seq'])

    def test_same_id_shared_with_legacy_read_write_or_peer_conflicts(self):
        for kind in ('forge-read', 'forge-write', 'peer-send'):
            with self.subTest(kind=kind):
                command = Command('prior-' + kind, kind, 'project', None, {'request_digest': 'a' * 64})
                before = self.ledger.apply(command, self.origin, authorize=lambda *_: True,
                    decide=lambda state, _: Transition(state, (Event('prior-reservation', {'kind': kind}),),
                                                       {'status': 'RESERVED'}))
                envelope = {**self.envelope, 'id': command.id}
                self.assert_code('ID_CONFLICT', lambda: self.reserve(envelope=envelope))
                self.assertEqual(before['last_seq'], self.ledger.snapshot()['room_seq'])
        self.assertEqual(3, len(self.ledger.replay(0)))

    def test_new_id_reserves_independently_without_replacing_other_state(self):
        state = {'existing_projection': {'generation': 3}}
        self.ledger.apply(Command('existing', 'context', 'project', None, {}), self.origin,
            authorize=lambda *_: True,
            decide=lambda _, __: Transition(state, (Event('context', {'generation': 3}),), {'ok': True}))
        first = self.reserve()
        second = self.reserve(envelope={**self.envelope, 'id': 'second'})
        self.assertEqual(2, first['first_seq'])
        self.assertEqual(3, second['first_seq'])
        self.assertEqual(state, self.ledger.snapshot()['state'])

    def test_exact_envelope_only_and_no_body_or_result_injection(self):
        malformed = [None, [], {},
                     {'id': 'operation', 'kind': 'forge-read'},
                     {**self.envelope, 'kind': 'forge-write'},
                     {**self.envelope, 'origin': self.origin.canonical()},
                     {**self.envelope, 'observation': {'body': 'PRIVATE_RESPONSE_BODY'}},
                     {**self.envelope, 'result': {'token': 'PRIVATE_RESPONSE_TOKEN'}}]
        for envelope in malformed:
            with self.subTest(envelope=envelope):
                # Call directly: None must not mean the helper method's default.
                self.assert_code('INVALID_FORGE_ENVELOPE', lambda: reserve_read_operation(
                    self.ledger, self.binding, envelope, self.origin, self.authorize))
                self.assert_empty()

    def test_raw_argv_and_content_never_enter_room_storage(self):
        self.reserve()
        database_text = '\n'.join(self.ledger._connection().iterdump())
        self.assertNotIn('PRIVATE_ARGV_SOURCE', database_text)
        self.assertNotIn('read-file', database_text)
        self.assertNotIn('"argv"', database_text)
        self.assertNotIn('"observation"', database_text)
        self.assertNotIn('"body"', database_text)
        for path in self.path.parent.glob('room.db*'):
            with self.subTest(path=path.name):
                self.assertNotIn(b'PRIVATE_ARGV_SOURCE', path.read_bytes())
                self.assertNotIn(b'PRIVATE_RESPONSE_BODY', path.read_bytes())

    def test_commit_storage_failure_is_audit_unavailable_and_retry_recovers(self):
        with patch.object(self.ledger, '_commit', side_effect=sqlite3.OperationalError('PRIVATE_STORAGE_DETAIL')):
            self.assert_code('AUDIT_UNAVAILABLE', self.reserve)
        self.assert_empty()
        receipt = self.reserve()
        self.assertEqual(1, receipt['first_seq'])
        self.assertNotIn('PRIVATE_STORAGE_DETAIL', '\n'.join(self.ledger._connection().iterdump()))

    def test_closed_store_is_audit_unavailable_not_success(self):
        self.ledger.close()
        self.assert_code('AUDIT_UNAVAILABLE', lambda: self.reserve(authorize=lambda: True))


if __name__ == '__main__':
    unittest.main()
