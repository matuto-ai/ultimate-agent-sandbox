"""Pure connected Broker/provider/audit evidence; no native or network calls."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_mutations import ExternalMutationBroker
from uas.github_mutations import GitHubMutationProvider
from uas.github_read import GitHubProject
from uas.ledger import LedgerError, Origin
from test_github_mutations import MemoryGitHub


class MutationBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'deployment.db'
        self.audit = ForgeAudit(self.path, 'deployment-a')
        self.addCleanup(lambda: self.audit.close())
        self.binding = ForgeBinding('alpha', 'project-a', 'owner/repo')
        self.fixture = MemoryGitHub()
        self.provider = GitHubMutationProvider(GitHubProject('owner/repo'), self.fixture)
        self.origin = Origin('actor-a', 'alice', 'incarnation-a', 'epoch-1', ('forge-write',))
        self.broker = self.make_broker()

    def make_broker(self):
        return ExternalMutationBroker(self.binding, 'room-instance-a', self.audit,
                                      {'actor-a': 41}, lambda actor: self.provider, work_labels=('bug', 'docs'))

    @staticmethod
    def envelope(argv, operation='op', **extra):
        return {'id': operation, 'kind': 'forge-write', 'argv': argv, **extra}

    def execute(self, argv, operation='op', *, origin=None, authorize=lambda: True, **extra):
        return self.broker.execute(self.envelope(argv, operation, **extra),
                                   origin=self.origin if origin is None else origin, authorize=authorize)

    def reopen(self):
        self.audit.close()
        self.audit = ForgeAudit(self.path, 'deployment-a')
        self.broker = self.make_broker()

    def error(self, expected, call):
        with self.assertRaises(LedgerError) as caught: call()
        self.assertEqual(expected, caught.exception.code)

    def fail_commit(self, nth):
        original = self.audit._commit
        count = 0
        def failing():
            nonlocal count
            count += 1
            if count == nth: raise sqlite3.OperationalError('simulated commit loss')
            original()
        return patch.object(self.audit, '_commit', side_effect=failing)

    def test_deadline_after_prepare_is_definite_no_contact_not_unknown(self):
        with patch('uas.github_mutations.time.monotonic',side_effect=[0,0,0,0,0,31]):
            receipt=self.execute(['issue','close','1'])
        self.assertEqual('PROVIDER_FAILURE',receipt['mutation']['status'])
        self.assertEqual('TIMEOUT_BEFORE_CONTACT',receipt['mutation']['error_code'])
        self.assertEqual('read',receipt['mutation']['contact'])
        self.assertEqual([],self.fixture.effects)
        record=self.audit.get_mutation(receipt['audit_reference'])
        self.assertEqual('TIMEOUT_BEFORE_CONTACT',record['steps'][0]['error_code'])
        self.assertEqual('OK',self.execute(['issue','close','1'],'different')['mutation']['status'])

    def test_authority_revoked_after_prepare_before_transport_has_definite_receipt(self):
        for fail_step in (0,1):
            if fail_step:
                self.audit.close()
                self.setUp()
            allowed=True;original=self.audit.mutation_prepared
            def checkpoint(operation,step,target):
                nonlocal allowed
                record=original(operation,step,target)
                if step==fail_step:allowed=False
                return record
            with patch.object(self.audit,'mutation_prepared',side_effect=checkpoint):
                with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
                    self.execute(['issue','edit','1','--title','first','--body','second'],authorize=lambda:allowed)
            row=self.audit._db.execute('SELECT result FROM mutation_terminals').fetchone()
            terminal=json.loads(row[0])
            self.assertEqual('PARTIAL_MUTATION' if fail_step else 'PROVIDER_FAILURE',terminal['status'])
            self.assertEqual('write-possible' if fail_step else 'read',terminal['contact'])
            self.assertEqual('AUTHORITY_REVOKED_BEFORE_CONTACT',terminal['error_code'])
            self.assertEqual(fail_step,len(self.fixture.effects))

    def test_revocation_between_confirmed_steps_is_known_partial_not_unknown(self):
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
            self.execute(['issue','edit','1','--title','first','--body','second'],
                authorize=lambda:len(self.fixture.effects)<1)
        rows=self.audit._db.execute('SELECT result FROM mutation_terminals').fetchall()
        self.assertEqual(1,len(rows))
        terminal=json.loads(rows[0][0])
        self.assertEqual('PARTIAL_MUTATION',terminal['status'])
        self.assertEqual(['title'],terminal['confirmed_fields'])
        self.assertEqual(1,len(self.fixture.effects))

    def test_recovery_does_not_terminalize_another_room_instance(self):
        with self.fail_commit(2):
            self.error('AUDIT_UNAVAILABLE',lambda:self.execute(['issue','close','1']))
        self.reopen()
        prior=self.audit.pending_mutations('alpha')[0]
        other=ExternalMutationBroker(self.binding,'other-instance',self.audit,{'actor-a':41},lambda _:self.provider)
        called=[]
        other.recover(lambda metadata:called.append(metadata) or True)
        self.assertEqual([],called)
        self.assertIsNone(self.audit.get_mutation(prior['operation_id'])['result'])
        self.error('FORGE_RECONCILIATION_REQUIRED',lambda:other.execute(
            self.envelope(['issue','close','1'],'new'),origin=self.origin,authorize=lambda:True))

    def test_representative_native_commands_cross_same_durable_broker(self):
        commands = [
            ['issue', 'create', '--title', 'New issue', '--body', 'Text'],
            ['issue', 'edit', '1', '--title', 'Updated'],
            ['issue', 'comment', '1', '--body', 'Comment'],
            ['issue', 'edit', '1', '--add-label', 'bug', '--remove-label', 'docs'],
            ['issue', 'dependency', 'add', '1', '--blocked-by', '2'],
            ['pr', 'create', '--title', 'New PR', '--body', 'Text', '--base', 'main', '--head', 'topic'],
            ['pr', 'reply', '3', '--comment-id', '501', '--body', 'Reply'],
            ['pr', 'review', '3', '--approve', '--commit', 'a' * 40],
        ]
        for index, argv in enumerate(commands):
            with self.subTest(command=argv[:2]):
                receipt = self.execute(argv, operation='op-' + str(index))
                self.assertEqual(('OK', 0), (receipt['mutation']['status'], receipt['exit_code']))
                record = self.audit.get_mutation(receipt['audit_reference'])
                self.assertEqual(receipt['mutation'], record['result'])
                self.assertTrue(record['started_at'])
                self.assertTrue(record['finished_at'])
                self.assertTrue(record['steps'])
        self.assertEqual([], self.audit.pending_mutations('alpha'))

    def test_success_warning_is_exit_zero_with_exact_retry_and_restart_no_replay(self):
        argv = ['issue', 'edit', '1', '--add-assignee', '@me,@me', '--repo', 'OWNER/REPO']
        first = self.execute(argv)
        self.assertEqual(0, first['exit_code'])
        self.assertEqual(2, len(first['warnings']))
        contact = deepcopy(self.fixture.calls)
        self.assertEqual(first, self.execute(argv))
        self.assertEqual(contact, self.fixture.calls)
        self.reopen()
        self.assertEqual(first, self.execute(argv))
        self.assertEqual(contact, self.fixture.calls)
        self.error('OPERATION_CONFLICT', lambda: self.execute(['issue', 'edit', '1', '--title', 'different']))

    def test_denied_route_returns_safe_token_correction_and_audit_no_provider(self):
        receipt = self.execute(['issue', 'comment', '1', '--body-file', '/tmp/secret-never-store'])
        self.assertEqual(('DENIED', 1), (receipt['mutation']['status'], receipt['exit_code']))
        self.assertEqual('BODY_FILE_DENIED', receipt['diagnostic']['code'])
        self.assertEqual('--body-file', receipt['diagnostic']['token'])
        self.assertEqual([], self.fixture.calls)
        record = self.audit.get_mutation(receipt['audit_reference'])
        self.assertEqual('denied', record['metadata']['route'])
        self.assertEqual('DENIED', record['result']['status'])
        self.assertNotIn('secret-never-store', json.dumps(record))

    def test_audit_contains_metadata_not_raw_body_argv_or_temp_path(self):
        secret = 'private-body-contents-not-for-canonical-audit'
        receipt = self.execute(['issue', 'comment', '1', '--body-file', '-'], body=secret)
        record = self.audit.get_mutation(receipt['audit_reference'])
        serialized = json.dumps(record)
        self.assertNotIn(secret, serialized)
        self.assertNotIn('--body-file', serialized)
        self.assertNotIn(str(self.path), serialized)
        self.assertEqual(64, len(record['metadata']['request_digest']))
        self.assertEqual(['comment'], record['result']['confirmed_fields'])

    def test_fresh_capability_and_actor_required_even_on_exact_retry(self):
        argv = ['issue', 'close', '1']
        self.execute(argv)
        count = len(self.fixture.calls)
        for origin in [Origin('actor-a', 'alice', 'incarnation-a', 'epoch-1', ('forge-read',)),
                       Origin('unknown', 'alice', 'incarnation-a', 'epoch-1', ('forge-write',))]:
            self.error('FORBIDDEN', lambda origin=origin: self.execute(argv, origin=origin))
        self.error('FORBIDDEN', lambda: self.execute(argv, authorize=lambda: False))
        self.assertEqual(count, len(self.fixture.calls))

    def test_start_audit_failure_is_precontact_and_latches_owner(self):
        with self.fail_commit(1):
            self.error('AUDIT_UNAVAILABLE', lambda: self.execute(['issue', 'close', '1']))
        self.assertTrue(self.broker.failed)
        self.assertEqual([], self.fixture.calls)
        self.error('AUDIT_UNAVAILABLE', lambda: self.execute(['issue', 'close', '1']))

    def test_checkpoint_audit_failure_never_reaches_write_and_recovery_does_not_replay(self):
        with self.fail_commit(2):
            self.error('AUDIT_UNAVAILABLE', lambda: self.execute(['issue', 'close', '1']))
        self.assertEqual([], self.fixture.effects)
        self.assertTrue(self.fixture.calls)
        self.reopen()
        count = len(self.fixture.calls)
        self.broker.recover(lambda _: True)
        receipt = self.execute(['issue', 'close', '1'])
        self.assertEqual('NOT_EXECUTED', receipt['mutation']['status'])
        self.assertEqual(count, len(self.fixture.calls))

    def test_confirmation_audit_failure_returns_unknown_and_blocks_further_contact(self):
        with self.fail_commit(3):
            receipt = self.execute(['issue', 'edit', '1', '--title', 'Applied'])
        self.assertEqual(('UNKNOWN_OUTCOME', 'AUDIT_UNAVAILABLE'),
                         (receipt['mutation']['status'], receipt['mutation']['error_code']))
        self.assertEqual([], receipt['mutation']['confirmed_fields'])
        self.assertEqual('Applied', self.fixture.issues[1]['title'])
        self.assertTrue(self.broker.failed)
        count = len(self.fixture.calls)
        self.error('AUDIT_UNAVAILABLE', lambda: self.execute(['issue', 'close', '1'], operation='new'))
        self.reopen()
        self.broker.recover(lambda _: True)
        retried = self.execute(['issue', 'edit', '1', '--title', 'Applied'])
        self.assertEqual('UNKNOWN_OUTCOME', retried['mutation']['status'])
        self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.execute(['issue', 'close', '1'], operation='new'))
        self.assertEqual(count, len(self.fixture.calls))

    def test_terminal_audit_failure_cannot_disclose_success_and_preserves_confirmed_fields(self):
        with self.fail_commit(4):
            receipt = self.execute(['issue', 'edit', '1', '--title', 'Applied'])
        self.assertEqual('UNKNOWN_OUTCOME', receipt['mutation']['status'])
        self.assertEqual(['title'], receipt['mutation']['confirmed_fields'])
        self.assertEqual(1, receipt['exit_code'])
        pending = self.audit.get_mutation(receipt['audit_reference'])
        self.assertIsNone(pending['result'])
        self.assertEqual(['title'], pending['steps'][0]['fields'])
        count = len(self.fixture.calls)
        self.reopen()
        self.broker.recover(lambda _: True)
        retried = self.execute(['issue', 'edit', '1', '--title', 'Applied'])
        self.assertEqual('UNKNOWN_OUTCOME', retried['mutation']['status'])
        self.assertEqual(['title'], retried['mutation']['confirmed_fields'])
        self.assertEqual(count, len(self.fixture.calls))

    def test_partial_and_unknown_keep_honest_durable_field_receipts(self):
        self.fixture.before = lambda method, path, body: (MemoryGitHub.response({}, 403)
            if method == 'PATCH' and 'body' in body else None)
        argv = ['issue', 'edit', '1', '--title', 'Applied', '--body', 'Rejected']
        receipt = self.execute(argv)
        self.assertEqual('PARTIAL_MUTATION', receipt['mutation']['status'])
        self.assertEqual(['title'], receipt['mutation']['confirmed_fields'])
        self.assertEqual(receipt['mutation'], self.audit.get_mutation(receipt['audit_reference'])['result'])
        count = len(self.fixture.calls)
        self.assertEqual(receipt, self.execute(argv))
        self.assertEqual(count, len(self.fixture.calls))
        self.fixture.before = None
        def lost(method, path, body, response):
            if method == 'POST': raise OSError('lost after provider effect')
        self.fixture.after = lost
        unknown = self.execute(['issue', 'comment', '1', '--body', 'Comment'], operation='lost')
        self.assertEqual('UNKNOWN_OUTCOME', unknown['mutation']['status'])
        self.assertEqual([], unknown['mutation']['confirmed_fields'])
        count = len(self.fixture.calls)
        self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.execute(['issue', 'close', '1'], operation='after-lost'))
        self.assertEqual(count, len(self.fixture.calls))

    def test_late_revocation_blocks_success_disclosure_but_keeps_terminal_evidence(self):
        allowed = True
        def revoke(method, path, body, response):
            nonlocal allowed
            if method == 'PATCH': allowed = False
        self.fixture.after = revoke
        self.error('FORBIDDEN', lambda: self.execute(['issue', 'edit', '1', '--title', 'Applied'], authorize=lambda: allowed))
        self.assertEqual('Applied', self.fixture.issues[1]['title'])
        self.assertEqual([], self.audit.pending_mutations('alpha'))

    def test_partial_multi_label_receipt_identifies_executed_normalized_item(self):
        self.fixture.before = lambda method, path, body: (MemoryGitHub.response({}, 403)
            if method == 'POST' and path.endswith('/labels') and body == {'labels': ['docs']} else None)
        receipt = self.execute(['issue', 'edit', '1', '--add-label', 'bug,docs'])
        self.assertEqual('PARTIAL_MUTATION', receipt['mutation']['status'])
        self.assertEqual(['add-label'], receipt['mutation']['confirmed_fields'])
        self.assertEqual('add-label', receipt['mutation']['failed_field'])
        self.assertEqual([{'step': 0, 'fields': ['add-label'],
                           'object': {'kind': 'issue', 'id': 101, 'number': 1}, 'item_index': 0}],
                         receipt['executed_steps'])
        self.assertEqual(1, len(self.fixture.effects))
        count = len(self.fixture.calls)
        self.reopen()
        self.assertEqual(receipt, self.execute(['issue', 'edit', '1', '--add-label', 'bug,docs']))
        self.assertEqual(count, len(self.fixture.calls))

    def test_recover_definite_rejection_keeps_partial_not_unknown_without_replay(self):
        self.fixture.before = lambda method, path, body: (MemoryGitHub.response({}, 403)
            if method == 'PATCH' and 'body' in body else None)
        argv = ['issue', 'edit', '1', '--title', 'Applied', '--body', 'Rejected']
        with self.fail_commit(6):
            receipt = self.execute(argv)
        self.assertEqual('UNKNOWN_OUTCOME', receipt['mutation']['status'])
        count = len(self.fixture.calls)
        self.reopen()
        self.broker.recover(lambda _: True)
        recovered = self.execute(argv)
        self.assertEqual('PARTIAL_MUTATION', recovered['mutation']['status'])
        self.assertEqual(['title'], recovered['mutation']['confirmed_fields'])
        self.assertEqual('PROVIDER_ERROR', recovered['mutation']['error_code'])
        self.assertEqual(count, len(self.fixture.calls))


if __name__ == '__main__':
    unittest.main()
