"""Pure Deployment read-audit durability and exact-scope tests; no providers/processes."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from uas.forge_audit import ForgeAudit, _V1_SCHEMA
from uas.ledger import LedgerError


def metadata(**changes):
    return {'room_id': 'alpha', 'room_instance': 'instance-a', 'project_id': 'project-a',
        'actor_id': 'actor-a', 'participant_id': 'alice', 'incarnation_id': 'incarnation-a',
        'authority_version': 'epoch-1', 'provider_host': 'github.com',
        'requested_repository': 'owner/repo', 'effective_repository': 'owner/repo',
        'route': 'pr-view', 'request_digest': 'a' * 64, 'origin_digest': 'b' * 64, **changes}


def result(**changes):
    return {'status': 'OK', 'completeness': 'complete', 'contact': 'read',
        'output_bytes': 127, 'dropped_bytes': 0, 'observation_digest': 'c' * 64, **changes}


def interrupted():
    return result(status='INTERRUPTED_OBSERVATION', completeness='unknown',
                  contact='unknown', output_bytes=0, dropped_bytes=None, observation_digest=None)


class ForgeReadAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'forge.db'
        self.audit = ForgeAudit(self.path, 'deployment-a')
        self.addCleanup(self.audit.close)

    def error(self, code, function):
        with self.assertRaises(LedgerError) as raised:
            function()
        self.assertEqual(code, raised.exception.code)

    def test_durable_exact_retry_start_terminal_and_detached_values(self):
        supplied = metadata()
        first = self.audit.begin_read('read-1', supplied)
        self.assertTrue(first['started'])
        supplied['actor_id'] = 'modified-after-call'
        first['record']['metadata']['actor_id'] = 'modified-result'
        self.assertEqual('actor-a', self.audit.read_record('read-1')['metadata']['actor_id'])
        repeated = self.audit.begin_read('read-1', metadata())
        self.assertFalse(repeated['started'])
        self.assertIsNone(repeated['record']['result'])
        terminal = self.audit.finish_read('read-1', result())
        self.assertEqual(terminal, self.audit.finish_read('read-1', result()))
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertEqual(terminal, reopened.read_record('read-1'))
            self.assertFalse(reopened.begin_read('read-1', metadata())['started'])
            self.assertEqual([], reopened.pending_reads('alpha'))

    def test_every_scope_and_full_origin_digest_bound_to_operation(self):
        self.audit.begin_read('read-1', metadata())
        for field, value in metadata().items():
            changed = ('d' * 64 if field.endswith('_digest') else
                       'other/repo' if field.endswith('_repository') else
                       'issue-view' if field == 'route' else 'another')
            if field == 'provider_host':
                self.error('INVALID_FORGE_AUDIT', lambda: self.audit.begin_read('read-1', metadata(**{field: changed})))
                continue
            self.error('ID_CONFLICT', lambda field=field, changed=changed:
                       self.audit.begin_read('read-1', metadata(**{field: changed})))
        self.assertIsNone(self.audit.read_record('read-1')['result'])

    def test_results_are_immutable_and_need_start(self):
        self.error('FORGE_AUDIT_NOT_FOUND', lambda: self.audit.finish_read('missing', result()))
        self.audit.begin_read('read-1', metadata())
        self.audit.finish_read('read-1', result())
        self.error('ID_CONFLICT', lambda: self.audit.finish_read('read-1', result(output_bytes=128)))
        self.error('ID_CONFLICT', lambda: self.audit.finish_read('read-1', interrupted()))

    def test_pending_read_never_grants_recontact_and_requires_owner_fencing_to_recover(self):
        contacts = []
        for _ in range(2):
            admitted = self.audit.begin_read('read-1', metadata())
            if admitted['started']:
                contacts.append('provider contacted once')
        self.assertEqual(1, len(contacts))
        self.audit.close()  # Explicitly stopped owner, not a live-inflight timeout inference.
        with ForgeAudit(self.path, 'deployment-a') as owner:
            old = owner.begin_read('read-1', metadata())
            self.assertFalse(old['started'])
            self.assertIsNone(old['record']['result'])
            recovered = owner.finish_read('read-1', interrupted())
            self.assertEqual('INTERRUPTED_OBSERVATION', recovered['result']['status'])
            self.assertFalse(owner.begin_read('read-1', metadata())['started'])
            self.assertTrue(owner.begin_read('explicit-fresh-read', metadata())['started'])
        self.assertEqual(1, len(contacts))

    def test_scoped_bounded_pending_inventory_and_exact_retry_at_capacity(self):
        for number in range(256):
            self.audit.begin_read('a-' + str(number), metadata())
        self.audit.begin_read('b-1', metadata(room_id='beta'))
        self.error('FORGE_RECOVERY_CAPACITY', lambda: self.audit.begin_read('overflow', metadata()))
        self.assertFalse(self.audit.begin_read('a-0', metadata())['started'])
        self.assertEqual(256, len(self.audit.pending_reads('alpha')))
        self.assertEqual(['b-1'], [r['operation_id'] for r in self.audit.pending_reads('beta')])
        self.assertEqual([], self.audit.pending_reads('missing'))
        self.audit.finish_read('a-0', interrupted())
        self.assertTrue(self.audit.begin_read('next', metadata())['started'])

    def test_precontact_commit_failure_fences_owner_without_provider_contact(self):
        contacts = []
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError('SECRET')):
            self.error('AUDIT_UNAVAILABLE', lambda: self.audit.begin_read('read-1', metadata()))
        self.assertIsNone(self.audit.read_record('read-1'))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.begin_read('read-2', metadata()))
        self.assertEqual([], contacts)
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertTrue(reopened.begin_read('read-1', metadata())['started'])

    def test_terminal_commit_failure_keeps_pending_and_fences_new_reads(self):
        self.audit.begin_read('read-1', metadata())
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError('SECRET')):
            self.error('AUDIT_UNAVAILABLE', lambda: self.audit.finish_read('read-1', result()))
        self.assertIsNone(self.audit.read_record('read-1')['result'])
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.begin_read('new', metadata()))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.finish_read('read-1', result()))
        self.audit.close()
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertFalse(reopened.begin_read('read-1', metadata())['started'])
            self.assertEqual('INTERRUPTED_OBSERVATION', reopened.finish_read('read-1', interrupted())['result']['status'])

    def test_lost_start_commit_acknowledgement_never_grants_recontact(self):
        commit = self.audit._commit
        def lost():
            commit()
            raise sqlite3.OperationalError('SECRET')
        with patch.object(self.audit, '_commit', side_effect=lost):
            self.error('AUDIT_UNAVAILABLE', lambda: self.audit.begin_read('read-1', metadata()))
        self.assertIsNotNone(self.audit.read_record('read-1'))
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertFalse(reopened.begin_read('read-1', metadata())['started'])

    def test_lost_terminal_acknowledgement_recovers_original_terminal(self):
        self.audit.begin_read('read-1', metadata())
        commit = self.audit._commit
        def lost():
            commit()
            raise sqlite3.OperationalError('SECRET')
        with patch.object(self.audit, '_commit', side_effect=lost):
            self.error('AUDIT_UNAVAILABLE', lambda: self.audit.finish_read('read-1', result()))
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertFalse(reopened.begin_read('read-1', metadata())['started'])
            self.assertEqual(result(), reopened.read_record('read-1')['result'])
            self.assertEqual(result(), reopened.finish_read('read-1', result())['result'])

    def test_two_connections_race_only_one_grants_contact(self):
        barrier = threading.Barrier(2)
        def attempt(_):
            with ForgeAudit(self.path, 'deployment-a') as store:
                barrier.wait()
                return store.begin_read('shared', metadata())['started']
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual([True, False], list(pool.map(attempt, range(2))))

    def test_no_read_id_can_be_reused_for_assignment_or_its_reconciliation(self):
        write = {'room_id': 'alpha', 'project_id': 'project-a', 'repository': 'owner/repo',
            'actor_id': 'actor-a', 'participant_id': 'alice', 'incarnation_id': 'incarnation-a',
            'authority_version': 'epoch-1', 'issue_number': 66, 'github_user_id': 41,
            'request_digest': 'a' * 64}
        self.audit.begin_read('read-1', metadata())
        self.error('ID_CONFLICT', lambda: self.audit.begin('read-1', write))
        self.audit.begin('write-1', write)
        self.error('ID_CONFLICT', lambda: self.audit.begin_read('write-1', metadata()))
        self.error('ID_CONFLICT', lambda: self.audit.begin_reconciliation('write-1', 'read-1'))
        self.audit.begin_reconciliation('write-1', 'reconcile-1')
        self.error('ID_CONFLICT', lambda: self.audit.begin_read('reconcile-1', metadata()))

    def test_metadata_and_result_reject_content_secret_redirect_and_unknown_fields(self):
        for field in ('body', 'diff', 'logs', 'argv', 'token', 'signed_url', 'credential', 'headers'):
            self.error('INVALID_FORGE_AUDIT', lambda field=field:
                       self.audit.begin_read('bad', {**metadata(), field: 'SECRET'}))
        self.audit.begin_read('read-1', metadata())
        for field in ('body', 'diff', 'logs', 'argv', 'token', 'signed_url'):
            self.error('INVALID_FORGE_AUDIT', lambda field=field:
                       self.audit.finish_read('read-1', {**result(), field: 'SECRET'}))
        self.assertNotIn('SECRET', json.dumps(self.audit.read_record('read-1')))
        self.assertNotIn(b'SECRET', self.path.read_bytes())

    def test_schema_validates_bounds_exact_types_and_unknown_vs_complete(self):
        for change in ({'provider_host': 'attacker.invalid'}, {'route': 'pr-view\nSECRET'},
                       {'requested_repository': 'owner/../other'}, {'effective_repository': 'owner/..'},
                       {'origin_digest': 'bad'}, {'request_digest': True}, {'room_id': 'a\nSECRET'}):
            with self.subTest(change=change):
                with self.assertRaises(LedgerError):
                    self.audit.begin_read('bad', metadata(**change))
        self.audit.begin_read('read-1', metadata())
        for change in ({'status': 'secret'}, {'status': []}, {'completeness': True},
                       {'contact': []}, {'output_bytes': True}, {'output_bytes': 1048577},
                       {'dropped_bytes': -1}, {'dropped_bytes': True}, {'dropped_bytes': None},
                       {'observation_digest': None}, {'observation_digest': 'bad'},
                       {'completeness': 'unknown'}, {'contact': 'none'}, {'contact': 'unknown'}):
            with self.subTest(change=change):
                self.error('INVALID_FORGE_AUDIT', lambda: self.audit.finish_read('read-1', result(**change)))
        self.audit.finish_read('read-1', result(output_bytes=1048576, dropped_bytes=1999999))

    def test_incomplete_results_never_claim_exact_dropped_counts(self):
        self.audit.begin_read('read-1', metadata())
        incomplete = result(status='OUTPUT_LIMIT', completeness='incomplete', dropped_bytes=None)
        self.error('INVALID_FORGE_AUDIT', lambda: self.audit.finish_read('read-1', {**incomplete, 'dropped_bytes': 1}))
        self.assertEqual(incomplete, self.audit.finish_read('read-1', incomplete)['result'])
        self.audit.begin_read('read-2', metadata())
        self.error('INVALID_FORGE_AUDIT', lambda: self.audit.finish_read('read-2', {**interrupted(), 'output_bytes': 1}))

    def test_generated_help_is_no_contact_only_and_bound_to_help_route(self):
        help_result = result(status='HELP', contact='none')
        self.audit.begin_read('wrong', metadata())
        self.error('INVALID_FORGE_AUDIT', lambda: self.audit.finish_read('wrong', help_result))
        self.audit.begin_read('help', metadata(route='help'))
        self.assertEqual(help_result, self.audit.finish_read('help', help_result)['result'])

    def test_corrupt_read_metadata_cannot_be_returned_or_authorize_retry(self):
        self.audit.begin_read('read-1', metadata())
        self.audit._db.execute("UPDATE read_starts SET metadata=? WHERE id='read-1'", (json.dumps({'body': 'SECRET'}),))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.read_record('read-1'))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.begin_read('read-1', metadata()))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.begin_read('new', metadata()))

    def test_duplicate_or_noncanonical_stored_json_is_corruption(self):
        self.audit.begin_read('read-1', metadata())
        raw = self.audit._db.execute("SELECT metadata FROM read_starts WHERE id='read-1'").fetchone()[0]
        duplicate = raw[:-1] + ',\"actor_id\":\"actor-a\"}'
        self.audit._db.execute("UPDATE read_starts SET metadata=? WHERE id='read-1'", (duplicate,))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.read_record('read-1'))

    def legacy(self, path, *, version=1, deployment='deployment-a'):
        db = sqlite3.connect(path)
        for statement in _V1_SCHEMA.values():
            db.execute(statement)
        db.execute('CREATE INDEX scope_idx ON starts(scope)')
        db.execute('INSERT INTO deployment VALUES(1, ?, ?)', (version, deployment))
        db.commit()
        return db

    def test_v1_migration_preserves_exact_assignment_rows_and_upgrades_once(self):
        path = Path(self.temp.name) / 'legacy.db'
        with self.legacy(path) as db:
            old = metadata()
            db.execute('INSERT INTO starts VALUES(?,?,?,?)', ('old', 'scope', json.dumps(old), '2026-10-27T00:00:00+00:00'))
        with ForgeAudit(path, 'deployment-a') as migrated:
            self.assertEqual(4, migrated._db.execute('SELECT version FROM deployment').fetchone()[0])
            self.assertEqual(old, migrated.get('old')['metadata'])
            self.assertTrue(migrated.begin_read('new', metadata())['started'])
        with ForgeAudit(path, 'deployment-a') as reopened:
            self.assertEqual(old, reopened.get('old')['metadata'])
            self.assertFalse(reopened.begin_read('new', metadata())['started'])

    def test_wrong_deployment_never_migrates_and_unknown_version_refused(self):
        path = Path(self.temp.name) / 'legacy.db'
        self.legacy(path).close()
        self.error('DEPLOYMENT_MISMATCH', lambda: ForgeAudit(path, 'other'))
        with sqlite3.connect(path) as db:
            self.assertEqual(1, db.execute('SELECT version FROM deployment').fetchone()[0])
            self.assertFalse(db.execute("SELECT name FROM sqlite_master WHERE name='read_starts'").fetchall())
            db.execute('UPDATE deployment SET version=77')
        self.error('DEPLOYMENT_MISMATCH', lambda: ForgeAudit(path, 'deployment-a'))

    def test_foreign_or_malformed_familiar_store_never_adopted(self):
        for mode in ('extra-table', 'wrong-schema', 'unexpected-trigger'):
            path = Path(self.temp.name) / (mode + '.db')
            with self.legacy(path) as db:
                if mode == 'extra-table':
                    db.execute('CREATE TABLE project_content (body TEXT)')
                elif mode == 'wrong-schema':
                    db.execute('DROP TABLE observations')
                    db.execute('CREATE TABLE observations (secret TEXT)')
                else:
                    db.execute('CREATE TRIGGER surprising AFTER INSERT ON starts BEGIN DELETE FROM starts; END')
            self.error('INVALID_STORE', lambda: ForgeAudit(path, 'deployment-a'))
            with sqlite3.connect(path) as db:
                self.assertEqual(1, db.execute('SELECT version FROM deployment').fetchone()[0])
                self.assertFalse(db.execute("SELECT name FROM sqlite_master WHERE name='read_starts'").fetchall())


if __name__ == '__main__':
    unittest.main()
