"""Connected pure Broker/provider/Deployment audit recovery, no external effects."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from test_github_reconciliation import RecoverableGitHub
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit, _RECONCILIATION_SCHEMA
from uas.forge_mutations import ExternalMutationBroker, digest
from uas.github_mutations import GitHubMutationProvider
from uas.github_read import GitHubProject
from uas.ledger import LedgerError, Origin


class ForgeReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'deployment.db'
        self.audit = ForgeAudit(self.path, 'deployment-a')
        self.addCleanup(lambda: self.audit.close())
        self.binding = ForgeBinding('alpha', 'project-a', 'owner/repo')
        self.fixture = RecoverableGitHub()
        self.provider = GitHubMutationProvider(GitHubProject('owner/repo'), self.fixture)
        self.origin = Origin('actor-a', 'alice', 'incarnation-a', 'epoch-1', ('forge-read', 'forge-write'))
        self.broker = self.make_broker()

    def make_broker(self, *, instance='room-instance-a', binding=None, actors=None):
        return ExternalMutationBroker(binding or self.binding, instance, self.audit,
            actors or {'actor-a': 41}, lambda actor: self.provider, work_labels=('bug', 'docs'))

    def reopen(self, *, instance='room-instance-a'):
        self.audit.close(); self.audit = ForgeAudit(self.path, 'deployment-a')
        self.broker = self.make_broker(instance=instance)

    def error(self, code, call):
        with self.assertRaises(LedgerError) as caught: call()
        self.assertEqual(code, caught.exception.code)

    def uncertain(self, argv=None):
        original = {'id': 'write-a', 'kind': 'forge-write',
                    'argv': argv or ['issue', 'comment', '1', '--body', 'Private recovery body']}
        def lose(method, path, body, response):
            if method != 'GET': raise TimeoutError('lost after actual effect')
        self.fixture.after = lose
        receipt = self.broker.execute(original, origin=self.origin, authorize=lambda: True)
        self.fixture.after = None
        self.assertEqual('UNKNOWN_OUTCOME', receipt['mutation']['status'])
        envelope = {'id': 'read-a', 'kind': 'forge-reconcile', 'audit_reference': receipt['audit_reference'],
                    'mutation': original}
        return envelope, receipt

    def reconcile(self, envelope, *, origin=None, authorize=lambda: True, broker=None):
        start, effects = len(self.fixture.calls), len(self.fixture.effects)
        result = (broker or self.broker).reconcile(envelope, origin=origin or self.origin, authorize=authorize)
        self.assertEqual(effects, len(self.fixture.effects))
        self.assertTrue(all(call[0] == 'GET' for call in self.fixture.calls[start:]))
        return result

    def test_lost_create_comment_review_and_partial_edit_recover_without_duplicate(self):
        cases = [['issue', 'create', '--title', 'Created', '--body', 'Private recovery body'],
                 ['issue', 'comment', '1', '--body', 'Private recovery body'],
                 ['pr', 'review', '3', '--approve', '--commit', 'a' * 40],
                 ['issue', 'edit', '1', '--title', 'New title', '--body', 'New body']]
        for argv in cases:
            with self.subTest(argv=argv):
                if self.fixture.effects:
                    self.audit.close(); self.setUp()
                envelope, original = self.uncertain(argv)
                calls = len(self.fixture.calls)
                self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.broker.execute(
                    {'id': 'another-write', 'kind': 'forge-write', 'argv': ['issue', 'close', '1']},
                    origin=self.origin, authorize=lambda: True))
                self.assertEqual(calls, len(self.fixture.calls))
                self.reopen()
                observed = self.reconcile(envelope)
                if 'edit' in argv:
                    self.assertEqual('PARTIAL', observed['reconciliation']['status'])
                    self.assertEqual(['MATCHED', 'CONFLICT'], [f['status'] for f in observed['reconciliation']['fields']])
                else: self.assertEqual('MATCHED', observed['reconciliation']['status'])
                self.assertEqual(original['mutation'], observed['mutation'])
                self.assertEqual(1, len(self.fixture.effects))
                count = len(self.fixture.calls)
                self.assertEqual(observed, self.reconcile(envelope))
                self.assertEqual(count, len(self.fixture.calls))
                self.reopen()
                self.assertEqual(observed, self.reconcile(envelope))
                self.assertEqual(count, len(self.fixture.calls))
                # The original operation keeps its immutable UNKNOWN receipt;
                # reconciliation does not turn observed-only into confirmation.
                self.assertEqual(original, self.broker.execute(envelope['mutation'], origin=self.origin, authorize=lambda: True))
                self.assertEqual(count, len(self.fixture.calls))

    def test_current_same_actor_epoch_can_reconcile_old_terminal_but_not_steal_attempt_id(self):
        envelope, _ = self.uncertain()
        old_result = self.reconcile(envelope)
        newer = Origin('actor-a', 'alice-replacement', 'incarnation-b', 'epoch-2', self.origin.capabilities)
        calls = len(self.fixture.calls)
        self.error('ID_CONFLICT', lambda: self.reconcile(envelope, origin=newer))
        self.assertEqual(calls, len(self.fixture.calls))
        new_envelope = {**envelope, 'id': 'read-b'}
        newer_result = self.reconcile(new_envelope, origin=newer)
        self.assertEqual('MATCHED', newer_result['reconciliation']['status'])
        self.assertNotEqual(old_result['reconciliation_reference'], newer_result['reconciliation_reference'])
        self.reopen(instance='room-instance-b')
        self.assertEqual('MATCHED', self.reconcile({**envelope, 'id': 'new-instance-read'}, origin=newer)['reconciliation']['status'])

    def test_changed_actor_project_request_or_capability_denied_before_provider(self):
        envelope, _ = self.uncertain()
        before = len(self.fixture.calls)
        other = Origin('actor-b', 'other', 'other-incarnation', 'epoch-1', self.origin.capabilities)
        broker = self.make_broker(actors={'actor-a': 41, 'actor-b': 88})
        self.error('FORBIDDEN', lambda: self.reconcile(envelope, origin=other, broker=broker))
        for caps in (('forge-read',), ('forge-write',), ()):
            unauthorized = Origin('actor-a', 'alice', 'incarnation-a', 'epoch-1', caps)
            self.error('FORBIDDEN', lambda: self.reconcile(envelope, origin=unauthorized))
        changed = deepcopy(envelope); changed['mutation']['argv'][-1] = 'Changed intent'
        self.error('OPERATION_CONFLICT', lambda: self.reconcile(changed))
        changed = deepcopy(envelope); changed['mutation']['id'] = 'another-write'
        self.error('OPERATION_CONFLICT', lambda: self.reconcile(changed))
        other_project = self.make_broker(binding=ForgeBinding('alpha', 'project-b', 'owner/repo'))
        self.error('FORBIDDEN', lambda: self.reconcile(envelope, broker=other_project))
        self.assertEqual(before, len(self.fixture.calls))

    def test_unfinished_write_requires_fenced_owner_recovery_not_reconciliation_adoption(self):
        envelope, _ = self.uncertain()
        # Simulate crash before terminal commit, leaving the exact durable
        # prepared checkpoint and its possible provider effect intact.
        self.audit._db.execute('DELETE FROM mutation_terminals')
        before = len(self.fixture.calls)
        self.error('FORGE_OPERATION_PENDING', lambda: self.reconcile(envelope))
        self.assertEqual(before, len(self.fixture.calls))
        self.broker.recover(lambda _: False)
        self.error('FORGE_OPERATION_PENDING', lambda: self.reconcile(envelope))
        self.broker.recover(lambda _: True)
        self.assertEqual(before, len(self.fixture.calls))
        self.assertEqual('MATCHED', self.reconcile(envelope)['reconciliation']['status'])

    def test_interrupted_reconciliation_exact_id_never_recontacts_and_new_id_can_observe(self):
        envelope, _ = self.uncertain()
        with patch('uas.github_reconciliation.GitHubReconciliationProvider.reconcile', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.reconcile(envelope)
        self.reopen()
        before = len(self.fixture.calls)
        result = self.reconcile(envelope)
        self.assertEqual('UNKNOWN', result['reconciliation']['status'])
        self.assertEqual('INTERRUPTED_OBSERVATION', result['reconciliation']['error_code'])
        self.assertEqual(before, len(self.fixture.calls))
        self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.broker.execute(
            {'id': 'new-write', 'kind': 'forge-write', 'argv': ['issue', 'close', '1']}, origin=self.origin, authorize=lambda: True))
        self.assertEqual('MATCHED', self.reconcile({**envelope, 'id': 'fresh-observation'})['reconciliation']['status'])

    def test_unknown_read_failure_and_repeated_attempts_do_not_unfence_mutations(self):
        envelope, _ = self.uncertain()
        self.fixture.before = lambda method, path, body: self.fixture.response({}, 403)
        first = self.reconcile(envelope)
        self.assertEqual('UNKNOWN', first['reconciliation']['status'])
        before = len(self.fixture.calls)
        self.assertEqual(first, self.reconcile(envelope))
        self.assertEqual(before, len(self.fixture.calls))
        self.assertEqual('UNKNOWN', self.reconcile({**envelope, 'id': 'fresh-unknown'})['reconciliation']['status'])
        self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.broker.execute(
            {'id': 'new-write', 'kind': 'forge-write', 'argv': ['issue', 'close', '1']}, origin=self.origin, authorize=lambda: True))
        self.assertEqual(1, len(self.fixture.effects))

    def test_reconciliation_start_commit_failure_has_no_provider_contact_and_stops_owner(self):
        envelope, _ = self.uncertain(); before = len(self.fixture.calls)
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError('commit failed')):
            self.error('AUDIT_UNAVAILABLE', lambda: self.reconcile(envelope))
        self.assertEqual(before, len(self.fixture.calls))
        self.assertTrue(self.broker.failed)
        self.error('AUDIT_UNAVAILABLE', lambda: self.reconcile({**envelope, 'id': 'new'}))
        self.reopen()
        self.assertEqual('MATCHED', self.reconcile(envelope)['reconciliation']['status'])

    def test_observation_commit_failure_never_returns_success_and_exact_retry_does_not_recontact(self):
        envelope, _ = self.uncertain(); commit = self.audit._commit; calls = []
        def fail_second():
            calls.append(1)
            if len(calls) == 2: raise sqlite3.OperationalError('terminal commit failed')
            commit()
        with patch.object(self.audit, '_commit', side_effect=fail_second):
            self.error('AUDIT_UNAVAILABLE', lambda: self.reconcile(envelope))
        self.assertTrue(self.broker.failed)
        self.reopen(); before = len(self.fixture.calls)
        self.assertEqual('UNKNOWN', self.reconcile(envelope)['reconciliation']['status'])
        self.assertEqual(before, len(self.fixture.calls))
        self.assertEqual('MATCHED', self.reconcile({**envelope, 'id': 'fresh'})['reconciliation']['status'])
        self.assertEqual(1, len(self.fixture.effects))

    def test_lost_observation_commit_ack_reopens_to_exact_durable_result_without_reads(self):
        envelope, _ = self.uncertain(); commit = self.audit._commit; calls = []
        def lose_second_ack():
            calls.append(1); commit()
            if len(calls) == 2: raise sqlite3.OperationalError('ack lost')
        with patch.object(self.audit, '_commit', side_effect=lose_second_ack):
            self.error('AUDIT_UNAVAILABLE', lambda: self.reconcile(envelope))
        self.reopen(); before = len(self.fixture.calls)
        self.assertEqual('MATCHED', self.reconcile(envelope)['reconciliation']['status'])
        self.assertEqual(before, len(self.fixture.calls))

    def test_late_authority_loss_records_unknown_and_does_not_disclose_observation(self):
        envelope, _ = self.uncertain(); count = []
        def guard():
            count.append(1)
            return len(count) < 5
        self.error('FORBIDDEN', lambda: self.reconcile(envelope, authorize=guard))
        observations = self.audit.get_mutation(envelope['audit_reference'])['reconciliations']
        self.assertEqual('UNKNOWN', observations[-1]['observation']['status'])
        self.assertEqual('AUTHORITY_REVOKED', observations[-1]['observation']['error_code'])

    def test_v3_to_v5_preserves_all_existing_prepared_terminal_bytes_and_marks_legacy_unknown(self):
        envelope, _ = self.uncertain()
        key = envelope['audit_reference']
        self.audit.close()
        from uas.git_audit import GIT_SCHEMA
        with sqlite3.connect(self.path) as db:
            for table in reversed(GIT_SCHEMA): db.execute('DROP TABLE ' + table)
            for table in reversed(_RECONCILIATION_SCHEMA): db.execute('DROP TABLE ' + table)
            db.execute('UPDATE deployment SET version=3')
            before = {table: db.execute('SELECT * FROM ' + table).fetchall() for table in
                      ('mutation_starts', 'mutation_prepared', 'mutation_confirmed', 'mutation_rejected', 'mutation_terminals')}
        self.reopen()
        self.assertEqual(5, self.audit._db.execute('SELECT version FROM deployment').fetchone()[0])
        for table, rows in before.items():
            self.assertEqual(rows, [tuple(row) for row in self.audit._db.execute('SELECT * FROM ' + table)])
        self.assertIsNone(self.audit.get_mutation(key)['steps'][0]['intent'])
        result = self.reconcile(envelope)
        self.assertEqual('UNKNOWN', result['reconciliation']['status'])
        self.assertEqual('LEGACY_MARKER_UNAVAILABLE', result['reconciliation']['error_code'])

    def test_corrupt_stored_intent_or_observation_fails_closed_without_provider(self):
        for table, column in (('mutation_intents', 'intent'), ('mutation_observations', 'observation')):
            with self.subTest(table=table):
                if self.fixture.effects:
                    self.audit.close(); self.setUp()
                envelope, _ = self.uncertain()
                if table == 'mutation_observations': self.reconcile(envelope)
                self.audit._db.execute('UPDATE ' + table + ' SET ' + column + "='{}'")
                before = len(self.fixture.calls)
                self.error('AUDIT_UNAVAILABLE', lambda: self.reconcile({**envelope, 'id': 'fresh'}))
                self.assertEqual(before, len(self.fixture.calls))

    def test_corrupt_known_observation_cannot_bypass_new_write_fence(self):
        envelope,_=self.uncertain();self.reconcile(envelope)
        self.audit._db.execute('UPDATE mutation_observations SET observation=?', ('{"status":"MATCHED"}',))
        before=len(self.fixture.calls)
        self.error('AUDIT_UNAVAILABLE',lambda:self.broker.execute(
            {'id':'new-after-corrupt','kind':'forge-write','argv':['issue','close','1']},
            origin=self.origin,authorize=lambda:True))
        self.assertEqual(before,len(self.fixture.calls))
        self.assertEqual(1,self.audit._db.execute('SELECT count(*) FROM mutation_starts').fetchone()[0])

    def test_resolved_history_is_validated_across_recovery_pages(self):
        envelope,_=self.uncertain();self.reconcile(envelope)
        db=self.audit._db;old=envelope['audit_reference']
        old_recon=db.execute('SELECT reconciliation_id FROM mutation_reconciliation_starts').fetchone()[0]
        for index in range(256):
            key='historical-'+str(index);recon='historical-read-'+str(index)
            db.execute('INSERT INTO mutation_starts SELECT ?,room_id,repository,metadata,timestamp FROM mutation_starts WHERE id=?',(key,old))
            db.execute('INSERT INTO mutation_prepared SELECT ?,step,target,timestamp FROM mutation_prepared WHERE id=?',(key,old))
            db.execute('INSERT INTO mutation_intents SELECT ?,step,intent FROM mutation_intents WHERE id=?',(key,old))
            db.execute('INSERT INTO mutation_terminals SELECT ?,result,timestamp FROM mutation_terminals WHERE id=?',(key,old))
            db.execute('INSERT INTO mutation_reconciliation_starts(id,reconciliation_id,metadata,timestamp) SELECT ?,?,metadata,timestamp FROM mutation_reconciliation_starts WHERE reconciliation_id=?',(key,recon,old_recon))
            db.execute('INSERT INTO mutation_observations SELECT ?,observation,timestamp FROM mutation_observations WHERE reconciliation_id=?',(recon,old_recon))
        receipt=self.broker.execute({'id':'after-page','kind':'forge-write','argv':['issue','close','1']},
            origin=self.origin,authorize=lambda:True)
        self.assertEqual('OK',receipt['mutation']['status'])
        db.execute('UPDATE mutation_observations SET observation=? WHERE reconciliation_id=?',
            ('{"status":"MATCHED"}','historical-read-255'))
        before=len(self.fixture.calls)
        self.error('AUDIT_UNAVAILABLE',lambda:self.broker.execute(
            {'id':'after-page-corrupt','kind':'forge-write','argv':['issue','reopen','1']},
            origin=self.origin,authorize=lambda:True))
        self.assertEqual(before,len(self.fixture.calls))

    def test_canonical_audit_retains_no_raw_body_argv_provider_prose_or_markers(self):
        envelope, _ = self.uncertain(); self.reconcile(envelope)
        dump = '\n'.join(self.audit._db.iterdump())
        for private in ('Private recovery body', '<!-- uas:mutation:', 'lost after actual effect', '--body'):
            self.assertNotIn(private, dump)
        row = self.audit.get_mutation(envelope['audit_reference'])
        self.assertEqual(digest(envelope['mutation']), row['metadata']['request_digest'])
        self.assertEqual('observed-only', row['reconciliations'][0]['observation']['attribution'])


if __name__ == '__main__': unittest.main()
