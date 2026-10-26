"""Deployment assignment audit durability without credentials or provider effects."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from uas.forge_audit import ForgeAudit
from uas.ledger import LedgerError


class ForgeAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'forge.db'
        self.audit = ForgeAudit(self.path, 'deployment-a')
        self.addCleanup(self.audit.close)
        self.metadata = {'room_id': 'alpha', 'project_id': 'project-a', 'repository': 'owner/repo',
            'actor_id': 'actor-a', 'participant_id': 'alice', 'incarnation_id': 'inc-1',
            'authority_version': 'epoch-1', 'issue_number': 66, 'github_user_id': 41,
            'request_digest': 'a' * 64}

    @staticmethod
    def result(status='ASSIGNED', *, issue_id=166, ids=None, contact='write-possible'):
        return {'status': status, 'issue_id': issue_id,
            'observed_assignee_ids': [41] if ids is None else ids,
            'confirmed_fields': ['add-assignee'] if status == 'ASSIGNED' else [],
            'contact': contact,
            'attribution': 'confirmed-response' if status == 'ASSIGNED' else 'unknown'}

    @staticmethod
    def observation(status='MATCHED', *, issue_id=166, ids=None):
        return {'status': status, 'issue_id': issue_id,
            'observed_assignee_ids': [41] if ids is None else ids,
            'confirmed_fields': [], 'contact': 'read', 'attribution': 'observed-only'}

    def start(self):
        return self.audit.begin('op', self.metadata)

    def prepared(self):
        self.start()
        return self.audit.prepared('op', 166)

    def reconcile(self, operation_id, reconciliation_id, observation):
        self.audit.begin_reconciliation(operation_id, reconciliation_id)
        return self.audit.reconcile(operation_id, reconciliation_id, observation)

    def test_durable_exact_retry_and_result(self):
        start = self.start()
        self.assertTrue(start['started'])
        self.assertIsNone(start['record']['issue_id'])
        self.assertEqual(start['record'], self.start()['record'])
        self.assertFalse(self.start()['started'])
        self.prepared()
        final = self.audit.finish('op', self.result())
        self.assertEqual(final, self.audit.finish('op', self.result()))
        with ForgeAudit(self.path, 'deployment-a') as other:
            self.assertEqual(final, other.get('op'))
            self.assertFalse(other.begin('op', self.metadata)['started'])
            self.assertEqual('ASSIGNED', other.get('op')['result']['status'])

    def test_pending_new_id_cross_room_same_actor_blocked(self):
        self.start()
        for changes in ({}, {'room_id': 'beta'}, {'incarnation_id': 'new'}, {'repository': 'OWNER/Repo'}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
                    self.audit.begin('other', {**self.metadata, **changes})
        self.assertIsNone(self.audit.get('other'))
        self.assertTrue(self.audit.begin('other-issue', {**self.metadata, 'issue_number': 67})['started'])
        self.assertTrue(self.audit.begin('other-actor', {**self.metadata, 'actor_id': 'actor-b'})['started'])

    def test_pending_reconciliation_does_not_release_inflight_reservation(self):
        self.prepared()
        self.reconcile('op', 'read-1', self.observation())
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
            self.audit.begin('other', self.metadata)

    def test_unknown_definitive_read_allows_only_new_explicit_operation(self):
        self.prepared()
        self.audit.finish('op', self.result('UNKNOWN_OUTCOME', ids=[]))
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
            self.audit.begin('other', self.metadata)
        self.reconcile('op', 'read-unknown', self.observation('UNKNOWN', issue_id=None, ids=[]))
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
            self.audit.begin('other', self.metadata)
        reconciled = self.reconcile('op', 'read-absent', self.observation('ABSENT', ids=[]))
        self.assertEqual('UNKNOWN_OUTCOME', reconciled['result']['status'])
        self.assertFalse(self.start()['started'])
        self.assertTrue(self.audit.begin('other', self.metadata)['started'])

    def test_reconciliation_is_observed_not_causal(self):
        self.prepared()
        self.audit.finish('op', self.result('UNKNOWN_OUTCOME', ids=[]))
        record = self.reconcile('op', 'read', self.observation())
        self.assertEqual('UNKNOWN_OUTCOME', record['result']['status'])
        self.assertEqual([], record['reconciliations'][0]['observation']['confirmed_fields'])
        self.assertEqual('observed-only', record['reconciliations'][0]['observation']['attribution'])
        self.assertEqual(record, self.reconcile('op', 'read', self.observation()))

    def test_immutable_request_issue_result_and_reconciliation(self):
        self.prepared()
        for call in (lambda: self.audit.begin('op', {**self.metadata, 'actor_id': 'other'}),
                     lambda: self.audit.prepared('op', 167)):
            with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
                call()
        self.audit.finish('op', self.result())
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
            self.audit.finish('op', self.result('UNKNOWN_OUTCOME'))
        self.reconcile('op', 'read', self.observation())
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
            self.reconcile('op', 'read', self.observation('ABSENT', ids=[]))

    def test_unprepared_write_and_wrong_issue_rejected(self):
        self.start()
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
            self.audit.finish('op', self.result())
        self.audit.prepared('op', 166)
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
            self.audit.finish('op', self.result(issue_id=167))
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
            self.reconcile('op', 'read', self.observation(issue_id=167))

    def test_sanitized_schema_rejects_raw_extra_fields(self):
        for name in ('argv', 'body', 'credentials', 'path'):
            with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
                self.audit.begin('bad-' + name, {**self.metadata, name: 'SECRET'})
        self.prepared()
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
            self.audit.finish('op', {**self.result(), 'body': 'SECRET'})
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
            self.reconcile('op', 'read', {**self.observation(), 'argv': ['SECRET']})
        self.assertNotIn('SECRET', json.dumps(self.audit.get('op')))

    def test_schema_rejects_inconsistent_or_unbounded_values(self):
        self.prepared()
        for update in ({'issue_number': True}, {'github_user_id': 0}, {'request_digest': 'raw secret'},
                       {'repository': 'owner/../repo'}, {'room_id': 'a\nsecret'}):
            with self.assertRaises(LedgerError):
                self.audit.begin('bad', {**self.metadata, **update})
        for update in ({'status': 'ASSIGNED', 'confirmed_fields': []},
                       {'contact': True}, {'status': []}, {'attribution': {}}, {'observed_assignee_ids': [True]},
                       {'observed_assignee_ids': [41, 41]}, {'issue_id': True}):
            with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
                self.audit.finish('op', {**self.result(), **update})
        for update in ({'status': 'ABSENT'}, {'attribution': 'confirmed-response'},
                       {'confirmed_fields': ['add-assignee']}):
            with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
                self.reconcile('op', 'bad', {**self.observation(), **update})

    def test_precontact_commit_failure_leaves_no_start(self):
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError('secret')):
            with self.assertRaisesRegex(LedgerError, '^AUDIT_UNAVAILABLE$'):
                self.start()
        self.assertIsNone(self.audit.get('op'))

    def test_prepared_failure_leaves_start_unprepared(self):
        self.start()
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError()):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.audit.prepared('op', 166)
        self.assertIsNone(self.audit.get('op')['issue_id'])

    def test_terminal_failure_preserves_pending_for_read_reconciliation(self):
        self.prepared()
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError()):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.audit.finish('op', self.result())
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertIsNone(reopened.get('op')['result'])
            self.assertFalse(reopened.begin('op', self.metadata)['started'])
            with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
                reopened.begin('other', self.metadata)

    def test_lost_commit_acknowledgement_recovers_original_start(self):
        commit = self.audit._commit
        def lost():
            commit()
            raise sqlite3.OperationalError()
        with patch.object(self.audit, '_commit', side_effect=lost):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.start()
        self.assertFalse(self.start()['started'])

    def test_two_connections_race_only_one_start(self):
        barrier = threading.Barrier(2)
        def attempt(operation):
            with ForgeAudit(self.path, 'deployment-a') as store:
                barrier.wait()
                try:
                    return store.begin(operation, self.metadata)['started']
                except LedgerError as error:
                    return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, ('one', 'two')))
        self.assertCountEqual([True, 'FORGE_RECONCILIATION_REQUIRED'], outcomes)

    def test_process_crash_after_prepared_keeps_no_replay_intent(self):
        code = """
import json, os, sys
from uas.forge_audit import ForgeAudit
store = ForgeAudit(sys.argv[1], 'deployment-a')
store.begin('crashed', json.loads(sys.argv[2]))
store.prepared('crashed', 166)
os._exit(17)
"""
        process = subprocess.run([sys.executable, '-c', code, str(self.path), json.dumps(self.metadata)],
                                 capture_output=True, timeout=5)
        self.assertEqual(17, process.returncode, process.stderr)
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            record = reopened.get('crashed')
            self.assertEqual(166, record['issue_id'])
            self.assertIsNone(record['result'])
            self.assertFalse(reopened.begin('crashed', self.metadata)['started'])
            with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
                reopened.begin('new-id', self.metadata)

    def test_nonmutation_terminal_binds_observed_identity(self):
        self.start()
        outcome = self.result('ALREADY_ASSIGNED', contact='read')
        outcome['attribution'] = 'observed-only'
        record = self.audit.finish('op', outcome)
        self.assertEqual(166, record['issue_id'])
        self.reconcile('op', 'unknown', self.observation('UNKNOWN', ids=[]))
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
            self.reconcile('op', 'wrong', self.observation(issue_id=167))

    def test_reconciliation_limit_preserves_original_exact_retries(self):
        self.prepared()
        for i in range(32):
            self.reconcile('op', 'read-' + str(i), self.observation())
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_CAPACITY'):
            self.reconcile('op', 'read-32', self.observation())
        self.reconcile('op', 'read-0', self.observation())
        self.assertEqual(32, len(self.audit.get('op')['reconciliations']))

    def test_reconciliation_requires_committed_start(self):
        self.prepared()
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_NOT_STARTED'):
            self.audit.reconcile('op', 'unstarted', self.observation())
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError()):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.audit.begin_reconciliation('op', 'failed')
        self.assertEqual([], self.audit.get('op')['reconciliations'])
        start = self.audit.begin_reconciliation('op', 'read')
        self.assertTrue(start['started'])
        self.assertIsNone(start['record']['reconciliations'][0]['observation'])
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            retry = reopened.begin_reconciliation('op', 'read')
            self.assertFalse(retry['started'])
            self.assertEqual(start['record'], retry['record'])
        result = self.audit.reconcile('op', 'read', self.observation())
        self.assertEqual(result, self.audit.begin_reconciliation('op', 'read')['record'])

    def test_reconciliation_ids_bound_before_provider_read_and_pending_counts(self):
        self.prepared()
        self.audit.begin('other', {**self.metadata, 'issue_number': 67})
        self.audit.begin_reconciliation('op', 'shared-read')
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
            self.audit.begin_reconciliation('other', 'shared-read')
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
            self.audit.reconcile('other', 'shared-read', self.observation())
        for i in range(31):
            self.audit.begin_reconciliation('op', 'pending-' + str(i))
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_CAPACITY'):
            self.audit.begin_reconciliation('op', 'over-limit')
        self.assertFalse(self.audit.begin_reconciliation('op', 'shared-read')['started'])
        self.audit.reconcile('op', 'shared-read', self.observation())

    def test_pending_read_never_unlocks_unknown_write(self):
        self.prepared()
        self.audit.finish('op', self.result('UNKNOWN_OUTCOME', ids=[]))
        self.reconcile('op', 'matched', self.observation())
        self.audit.begin_reconciliation('op', 'new-pending-read')
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
            self.audit.begin('other', self.metadata)

    def test_scoped_pending_and_prewrite_fenced_terminal(self):
        self.start()
        self.audit.begin('other-room', {**self.metadata, 'room_id': 'beta', 'issue_number': 67})
        self.assertEqual(['op'], [r['operation_id'] for r in self.audit.pending('alpha')])
        self.assertEqual(['other-room'], [r['operation_id'] for r in self.audit.pending('beta')])
        self.assertEqual([], self.audit.pending('missing'))
        stopped = self.result('NOT_EXECUTED', issue_id=None, ids=[], contact='none')
        self.audit.finish('op', stopped)
        self.assertEqual([], self.audit.pending('alpha'))
        self.assertTrue(self.audit.begin('explicit-new', self.metadata)['started'])
        self.audit.prepared('explicit-new', 166)
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
            self.audit.finish('explicit-new', stopped)

    def test_deployment_binding_and_closed_fail(self):
        with self.assertRaisesRegex(LedgerError, 'DEPLOYMENT_MISMATCH'):
            ForgeAudit(self.path, 'different')
        self.audit.close()
        with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
            self.start()

    def test_success_terminal_requires_exact_metadata_assignee_and_issue_identity(self):
        self.prepared()
        for status in ('ASSIGNED', 'ALREADY_ASSIGNED'):
            valid = self.result(status, contact='write-possible' if status == 'ASSIGNED' else 'read')
            if status == 'ALREADY_ASSIGNED':
                valid['attribution'] = 'observed-only'
            for update in ({'observed_assignee_ids': []}, {'observed_assignee_ids': [99]},
                           {'observed_assignee_ids': [41, 99]}, {'issue_id': None}, {'issue_id': 167}):
                with self.subTest(status=status, update=update):
                    with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
                        self.audit.finish('op', {**valid, **update})
                    self.assertIsNone(self.audit.get('op')['result'])
        self.assertEqual('ASSIGNED', self.audit.finish('op', self.result())['result']['status'])

    def test_already_assigned_is_observed_only_with_exact_target_without_prepared(self):
        self.start()
        valid = {**self.result('ALREADY_ASSIGNED', contact='read'), 'attribution': 'observed-only'}
        for update in ({'issue_id': None}, {'observed_assignee_ids': []}, {'observed_assignee_ids': [99]},
                       {'attribution': 'confirmed-response'}, {'attribution': 'unknown'},
                       {'contact': 'none'}, {'confirmed_fields': ['add-assignee']}):
            with self.subTest(update=update):
                with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_AUDIT'):
                    self.audit.finish('op', {**valid, **update})
                self.assertIsNone(self.audit.get('op')['result'])
        record = self.audit.finish('op', valid)
        self.assertEqual('observed-only', record['result']['attribution'])
        self.assertEqual([], record['result']['confirmed_fields'])
