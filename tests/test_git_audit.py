import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.forge_audit import ForgeAudit, _V1_SCHEMA, _READ_SCHEMA, _MUTATION_SCHEMA, _RECONCILIATION_SCHEMA
from uas.git_audit import GitAudit, GIT_SCHEMA, metadata, terminal
from uas.ledger import LedgerError


class GitAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'audit.db'
        self.owner = ForgeAudit(self.path, 'deployment'); self.addCleanup(self.owner.close)
        self.audit = GitAudit(self.owner)
        self.meta = {'room_id': 'room', 'room_instance': 'instance', 'project_id': 'project',
            'actor_id': 'alice', 'participant_id': 'seat-a', 'incarnation_id': 'incarnation',
            'authority_version': 'epoch-1', 'origin_digest': 'a' * 64,
            'host': 'github.com', 'repository': 'owner/repo', 'service': 'git-receive-pack',
            'request_digest': 'b' * 64}
        self.result = {'status': 'OK', 'contact': 'write-possible', 'input_bytes': 20,
                       'output_bytes': 5, 'output_sha256': hashlib.sha256(b'hello').hexdigest()}

    def begin(self, operation='one', **changes):
        return self.audit.begin(operation, {**self.meta, **changes})

    def test_same_deployment_store_and_exact_retry_never_grants_reexecution(self):
        first = self.begin(); self.assertTrue(first['execute'])
        self.assertFalse(self.begin()['execute'])
        done = self.audit.finish(first['record']['id'], self.result)
        self.assertEqual(done['result'], self.result)
        self.assertEqual(self.audit.finish(first['record']['id'], self.result), done)
        self.assertEqual(self.begin()['record'], done)
        self.assertFalse(self.begin()['execute'])
        self.assertEqual(self.owner._db.execute('SELECT version FROM deployment').fetchone()[0], 5)
        self.assertEqual(self.owner._db.execute('SELECT count(*) FROM git_starts').fetchone()[0], 1)

    def test_changed_actor_origin_route_or_request_conflicts(self):
        self.begin()
        for changes in ({'actor_id': 'bob'}, {'origin_digest': 'c' * 64},
                        {'repository': 'other/repo'}, {'request_digest': 'd' * 64},
                        {'service': 'git-upload-pack'}):
            with self.subTest(changes=changes), self.assertRaises(LedgerError) as raised:
                self.begin(**changes)
            self.assertEqual(raised.exception.code, 'ID_CONFLICT')

    def test_room_instance_scopes_operation_id(self):
        self.begin()
        self.assertTrue(self.begin(room_instance='next')['execute'])
        self.assertTrue(self.begin(room_id='other')['execute'])

    def test_start_failure_makes_no_permission_and_fences(self):
        with patch.object(self.owner, '_commit', side_effect=sqlite3.OperationalError('disk')):
            with self.assertRaises(LedgerError): self.begin()
        self.assertTrue(self.audit.failed)
        with self.assertRaises(LedgerError): self.begin()
        self.assertEqual(self.owner._db.execute('SELECT count(*) FROM git_starts').fetchone()[0], 0)

    def test_terminal_failure_remains_pending_and_never_becomes_success(self):
        key = self.begin()['record']['id']
        with patch.object(self.owner, '_commit', side_effect=sqlite3.OperationalError('disk')):
            with self.assertRaises(LedgerError): self.audit.finish(key, self.result)
        self.assertTrue(self.audit.failed)
        self.assertEqual(self.owner._db.execute('SELECT count(*) FROM git_terminals').fetchone()[0], 0)

    def test_fenced_recovery_is_unknown_write_not_replay(self):
        key = self.begin()['record']['id']
        read = self.begin('read', service='git-upload-pack')['record']['id']
        self.begin('other', room_instance='other')
        for value in (False, None, 1, 'true'):
            with self.assertRaises(LedgerError): self.audit.recover('room', 'instance', fenced=value)
        records = self.audit.recover('room', 'instance', fenced=True)
        self.assertEqual(len(records), 2)
        self.assertEqual(self.audit.get(key)['result']['status'], 'UNKNOWN_OUTCOME')
        self.assertEqual(self.audit.get(read)['result']['status'], 'INTERRUPTED')
        self.assertFalse(self.begin()['execute'])
        self.assertEqual(self.audit.recover('room', 'instance', fenced=True), [])

    def test_metadata_and_results_do_not_accept_content_or_secret_fields(self):
        for value in ({**self.meta, 'key': 'secret'}, {**self.meta, 'argv': ['ssh']},
                      {**self.meta, 'host': 'evil.example'}, {**self.meta, 'repository': '../x'},
                      {**self.meta, 'service': 'sh'}, {**self.meta, 'origin_digest': 'short'}):
            with self.subTest(value=value), self.assertRaises(LedgerError): metadata(value)
        for value in ({**self.result, 'body': 'secret'}, {**self.result, 'input_bytes': True},
                      {**self.result, 'input_bytes': 2**30}, {**self.result, 'status': 'SUCCESS'},
                      {**self.result, 'output_sha256': None}, {**self.result, 'contact': 'none'}):
            with self.subTest(value=value), self.assertRaises(LedgerError): terminal(value)

    def test_service_contact_and_terminal_immutability(self):
        key = self.begin(service='git-upload-pack')['record']['id']
        with self.assertRaises(LedgerError): self.audit.finish(key, self.result)
        result = {**self.result, 'contact': 'read'}
        self.audit.finish(key, result)
        with self.assertRaises(LedgerError): self.audit.finish(key, {**result, 'status': 'FAILED'})

    def test_corrupt_canonical_record_fences_owner(self):
        key = self.begin()['record']['id']
        self.owner._db.execute('UPDATE git_starts SET metadata=? WHERE id=?', (json.dumps(self.meta), key))
        with self.assertRaises(LedgerError): self.audit.get(key)
        self.assertTrue(self.audit.failed)

    def test_pending_capacity_refuses_before_permission(self):
        for i in range(16): self.begin('op-' + str(i))
        with self.assertRaises(LedgerError) as raised: self.begin('over')
        self.assertEqual(raised.exception.code, 'GIT_AUDIT_CAPACITY')

    def test_v4_migration_preserves_prior_schema_and_unknown_version_refuses(self):
        self.owner.close()
        db = sqlite3.connect(self.path)
        for name in reversed(tuple(GIT_SCHEMA)): db.execute('DROP TABLE ' + name)
        db.execute('UPDATE deployment SET version=4'); db.commit(); db.close()
        self.owner = ForgeAudit(self.path, 'deployment'); self.addCleanup(self.owner.close)
        actual = {row[0] for row in self.owner._db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(actual, set(_V1_SCHEMA) | set(_READ_SCHEMA) | set(_MUTATION_SCHEMA) | set(_RECONCILIATION_SCHEMA) | set(GIT_SCHEMA))
        self.owner._db.execute('UPDATE deployment SET version=999'); self.owner.close()
        with self.assertRaises(LedgerError): ForgeAudit(self.path, 'deployment')


if __name__ == '__main__': unittest.main()
