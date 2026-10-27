"""Pure SQLite mutation audit evidence; no subprocesses, sockets or providers."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.forge_audit import ForgeAudit, _V1_SCHEMA, _READ_SCHEMA, _json
from uas.ledger import LedgerError


def metadata(**changes):
    return {'room_id': 'alpha', 'room_instance': 'instance-a', 'project_id': 'project-a',
        'repository': 'owner/repo', 'actor_id': 'actor-a', 'participant_id': 'alice',
        'incarnation_id': 'incarnation-a', 'authority_version': 'epoch-1', 'github_user_id': 41,
        'provider_host': 'github.com', 'route': 'issue-edit', 'request_digest': 'a' * 64,
        'origin_digest': 'b' * 64, **changes}


def result(**changes):
    return {'status': 'OK', 'confirmed_fields': ['title'],
        'objects': [{'kind': 'issue', 'id': 166, 'number': 66}],
        'contact': 'write-possible', 'failed_field': None, 'error_code': None, **changes}


def none_result(**changes):
    return result(status='NOT_EXECUTED', confirmed_fields=[], objects=[], contact='none', **changes)


ISSUE = {'kind': 'issue', 'id': 166, 'number': 66}
REPO = {'kind': 'repository', 'id': 12}


class MutationAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'audit.db'
        self.audit = ForgeAudit(self.path, 'deployment-a')
        self.addCleanup(self.audit.close)

    def error(self, code, call):
        with self.assertRaises(LedgerError) as raised:
            call()
        self.assertEqual(code, raised.exception.code)

    def start(self, operation='op', **changes):
        return self.audit.begin_mutation(operation, metadata(**changes))

    def prepare(self, operation='op', step=0, target=ISSUE):
        return self.audit.mutation_prepared(operation, step, target)

    def confirm(self, operation='op', step=0, fields=None, obj=ISSUE):
        return self.audit.mutation_confirmed(operation, step, ['title'] if fields is None else fields, obj)

    def completed(self):
        self.start(); self.prepare(); self.confirm()
        return self.audit.finish_mutation('op', result())

    def test_exact_retry_durable_detached_start_step_and_terminal(self):
        supplied = metadata()
        first = self.audit.begin_mutation('op', supplied)
        supplied['actor_id'] = 'changed'
        first['record']['metadata']['actor_id'] = 'changed'
        self.assertEqual('actor-a', self.audit.get_mutation('op')['metadata']['actor_id'])
        self.assertFalse(self.start()['started'])
        prepared = self.prepare()
        self.assertEqual(prepared, self.prepare())
        confirmed = self.confirm()
        self.assertEqual(confirmed, self.confirm())
        final = self.audit.finish_mutation('op', result())
        self.assertEqual(final, self.audit.finish_mutation('op', result()))
        self.audit.close()
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertEqual(final, reopened.get_mutation('op'))
            self.assertFalse(reopened.begin_mutation('op', metadata())['started'])
            self.assertEqual([], reopened.pending_mutations('alpha'))
            self.assertTrue(reopened.begin_mutation('fresh', metadata())['started'])

    def test_every_metadata_value_bound_and_operation_conflict(self):
        self.start()
        for field in metadata():
            value = ('c' * 64 if field.endswith('_digest') else 42 if field == 'github_user_id'
                     else 'another/repo' if field == 'repository' else 'pr-edit' if field == 'route'
                     else 'another')
            if field == 'provider_host':
                self.error('INVALID_FORGE_AUDIT', lambda: self.start(**{field: value}))
            else:
                self.error('OPERATION_CONFLICT', lambda field=field, value=value: self.start(**{field: value}))
        self.assertFalse(self.start()['started'])

    def test_cross_actor_incarnation_and_repository_case_cannot_bypass_fence(self):
        self.start()
        for changes in ({}, {'actor_id': 'other'}, {'participant_id': 'other'},
                        {'room_instance': 'new'}, {'authority_version': 'new'},
                        {'incarnation_id': 'new'}, {'repository': 'OWNER/REPO'}):
            self.error('FORGE_RECONCILIATION_REQUIRED', lambda changes=changes: self.start('new', **changes))
        self.assertIsNone(self.audit.get_mutation('new'))
        self.assertTrue(self.start('separate-room', room_id='beta')['started'])

    def test_pending_unprepared_can_only_recover_not_execute_and_exact_retry_stays_old(self):
        self.start()
        self.audit.close()
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertFalse(reopened.begin_mutation('op', metadata())['started'])
            old = reopened.finish_mutation('op', none_result(error_code='INTERRUPTED_MUTATION'))
            self.assertEqual('NOT_EXECUTED', old['result']['status'])
            self.assertFalse(reopened.begin_mutation('op', metadata())['started'])
            self.assertTrue(reopened.begin_mutation('new', metadata())['started'])

    def test_prepared_interruption_is_unknown_and_never_replayed_or_cleared(self):
        self.start(); self.prepare()
        self.error('INVALID_FORGE_AUDIT', lambda: self.audit.finish_mutation('op', none_result()))
        unknown = result(status='UNKNOWN_OUTCOME', confirmed_fields=[], objects=[], error_code='INTERRUPTED_MUTATION')
        self.audit.finish_mutation('op', unknown)
        self.assertFalse(self.start()['started'])
        self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.start('new'))
        with ForgeAudit(self.path, 'deployment-a') as reopened:
            self.assertEqual(unknown, reopened.get_mutation('op')['result'])
            self.error('FORGE_RECONCILIATION_REQUIRED', lambda: reopened.begin_mutation('new', metadata()))

    def test_multistep_partial_retains_exact_confirmed_fields_and_objects(self):
        self.start(route='issue-create'); self.prepare(target=REPO)
        self.confirm(fields=['create', 'title', 'body'])
        self.prepare(step=1); self.confirm(step=1, fields=['add-label'])
        self.prepare(step=2)
        partial = result(status='PARTIAL_MUTATION', confirmed_fields=['create', 'title', 'body', 'add-label'],
                         failed_field='add-assignee', error_code='TIMEOUT')
        terminal = self.audit.finish_mutation('op', partial)
        self.assertEqual(partial, terminal['result'])
        self.assertIsNone(terminal['steps'][2]['fields'])
        self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.start('new'))
        self.error('OPERATION_CONFLICT', lambda: self.audit.finish_mutation('op', {**partial, 'status': 'UNKNOWN_OUTCOME'}))

    def test_definite_rejected_step_releases_fence_without_fabricating_fields(self):
        self.start(); self.prepare(); self.confirm()
        self.prepare(step=1)
        rejected = self.audit.mutation_rejected('op', 1, 'PROVIDER_ERROR')
        self.assertEqual(rejected, self.audit.mutation_rejected('op', 1, 'PROVIDER_ERROR'))
        self.error('OPERATION_CONFLICT', lambda: self.audit.mutation_rejected('op', 1, 'FORBIDDEN'))
        self.error('OPERATION_CONFLICT', lambda: self.confirm(step=1, fields=['body']))
        self.error('INVALID_FORGE_AUDIT', lambda: self.prepare(step=2))
        partial = result(status='PARTIAL_MUTATION', failed_field='body', error_code='PROVIDER_ERROR')
        self.audit.finish_mutation('op', partial)
        self.assertTrue(self.start('fresh')['started'])
        self.assertFalse(self.start()['started'])

    def test_first_step_rejection_is_provider_failure_and_requires_matching_error(self):
        self.start(); self.prepare()
        for code in ('TIMEOUT', 'OUTPUT_LIMIT', 'INVALID_RESPONSE', 'AUDIT_UNAVAILABLE'):
            self.error('INVALID_FORGE_AUDIT', lambda code=code: self.audit.mutation_rejected('op', 0, code))
        self.audit.mutation_rejected('op', 0, 'FORBIDDEN')
        rejected = result(status='PROVIDER_FAILURE', confirmed_fields=[], objects=[], error_code='FORBIDDEN')
        self.error('INVALID_FORGE_AUDIT', lambda: self.audit.finish_mutation('op', {**rejected, 'error_code': 'TIMEOUT'}))
        self.audit.finish_mutation('op', rejected)
        self.assertTrue(self.start('fresh')['started'])

    def test_steps_require_start_contiguous_prepared_then_confirmed(self):
        for call in (lambda: self.prepare(), lambda: self.confirm(),
                     lambda: self.audit.mutation_rejected('op', 0, 'FORBIDDEN'),
                     lambda: self.audit.finish_mutation('op', none_result())):
            self.error('FORGE_AUDIT_NOT_FOUND', call)
        self.start()
        self.error('INVALID_FORGE_AUDIT', lambda: self.confirm())
        self.error('INVALID_FORGE_AUDIT', lambda: self.prepare(step=1))
        self.prepare()
        self.error('INVALID_FORGE_AUDIT', lambda: self.prepare(step=1))
        self.error('OPERATION_CONFLICT', lambda: self.prepare(target={**ISSUE, 'id': 167}))
        self.error('INVALID_FORGE_AUDIT', lambda: self.confirm(obj={**ISSUE, 'id': 167}))
        self.confirm()
        self.error('OPERATION_CONFLICT', lambda: self.confirm(fields=['body']))
        self.error('OPERATION_CONFLICT', lambda: self.audit.mutation_rejected('op', 0, 'FORBIDDEN'))
        self.audit.finish_mutation('op', result())
        self.error('FORGE_AUDIT_TERMINAL', lambda: self.prepare(step=1))

    def test_dependency_checkpoint_binds_both_immutable_issue_identities(self):
        self.start(route='dependency-add')
        related = {**ISSUE, 'related_id': 167, 'related_number': 67}
        self.error('INVALID_FORGE_AUDIT', lambda: self.prepare())
        for changes in ({'related_id': 166}, {'related_number': 66}, {'related_id': True},
                        {'related_number': 0}, {'kind': 'pull'}):
            self.error('INVALID_FORGE_AUDIT', lambda changes=changes:
                       self.prepare(target={**related, **changes}))
        self.prepare(target=related)
        self.confirm(fields=['dependency'])
        final = self.audit.finish_mutation('op', result(confirmed_fields=['dependency']))
        self.assertEqual(related, final['steps'][0]['target'])
        self.assertEqual([ISSUE], final['result']['objects'])
        self.start('ordinary')
        self.error('INVALID_FORGE_AUDIT', lambda: self.prepare('ordinary', target=related))

    def test_step_bound_and_aggregate_deduplication(self):
        self.start()
        for step in range(32):
            self.prepare(step=step)
            self.confirm(step=step)
        self.error('INVALID_FORGE_AUDIT', lambda: self.prepare(step=32))
        final = self.audit.finish_mutation('op', result())
        self.assertEqual(32, len(final['steps']))
        self.assertEqual(['title'], final['result']['confirmed_fields'])
        self.assertEqual([ISSUE], final['result']['objects'])

    def test_success_cannot_claim_unconfirmed_fields_objects_or_contact(self):
        self.start(); self.prepare()
        self.error('INVALID_FORGE_AUDIT', lambda: self.audit.finish_mutation('op', result()))
        self.confirm()
        for changes in ({'confirmed_fields': ['body']}, {'objects': []},
                        {'objects': [{**ISSUE, 'id': 167}]}, {'contact': 'none'},
                        {'failed_field': 'body'}, {'error_code': 'PROVIDER_ERROR'}):
            self.error('INVALID_FORGE_AUDIT', lambda changes=changes:
                       self.audit.finish_mutation('op', result(**changes)))
        self.audit.finish_mutation('op', result())

    def test_precontact_prepared_confirmation_rejection_and_terminal_commit_failure_latch(self):
        for phase in ('start', 'prepared', 'confirmed', 'rejected', 'terminal'):
            with self.subTest(phase=phase):
                path = Path(self.temp.name) / (phase + '.db')
                with ForgeAudit(path, 'deployment-a') as audit:
                    if phase != 'start': audit.begin_mutation('op', metadata())
                    if phase in {'confirmed', 'rejected', 'terminal'}: audit.mutation_prepared('op', 0, ISSUE)
                    if phase == 'terminal': audit.mutation_confirmed('op', 0, ['title'], ISSUE)
                    call = {'start': lambda: audit.begin_mutation('op', metadata()),
                            'prepared': lambda: audit.mutation_prepared('op', 0, ISSUE),
                            'confirmed': lambda: audit.mutation_confirmed('op', 0, ['title'], ISSUE),
                            'rejected': lambda: audit.mutation_rejected('op', 0, 'FORBIDDEN'),
                            'terminal': lambda: audit.finish_mutation('op', result())}[phase]
                    with patch.object(audit, '_commit', side_effect=sqlite3.OperationalError('SECRET')):
                        self.error('AUDIT_UNAVAILABLE', call)
                    record = audit.get_mutation('op')
                    if phase == 'start': self.assertIsNone(record)
                    else: self.assertIsNone(record['result'])
                    self.error('AUDIT_UNAVAILABLE', lambda: audit.begin_mutation('fresh', metadata()))
                    self.assertNotIn('SECRET', json.dumps(record))

    def test_lost_start_and_terminal_acknowledgement_never_grants_replay(self):
        for phase in ('start', 'terminal'):
            path = Path(self.temp.name) / ('lost-' + phase + '.db')
            with ForgeAudit(path, 'deployment-a') as audit:
                if phase == 'terminal':
                    audit.begin_mutation('op', metadata()); audit.mutation_prepared('op', 0, ISSUE)
                    audit.mutation_confirmed('op', 0, ['title'], ISSUE)
                commit = audit._commit
                def lost():
                    commit()
                    raise sqlite3.OperationalError('SECRET')
                with patch.object(audit, '_commit', side_effect=lost):
                    self.error('AUDIT_UNAVAILABLE', lambda: audit.begin_mutation('op', metadata())
                               if phase == 'start' else audit.finish_mutation('op', result()))
                self.error('AUDIT_UNAVAILABLE', lambda: audit.begin_mutation('fresh', metadata()))
            with ForgeAudit(path, 'deployment-a') as reopened:
                prior = reopened.begin_mutation('op', metadata())
                self.assertFalse(prior['started'])
                self.assertEqual(None if phase == 'start' else result(), prior['record']['result'])

    def test_rejects_raw_content_unknown_enums_and_unbounded_typed_values(self):
        for field in ('body', 'argv', 'token', 'credential', 'temporary_path', 'attachment'):
            self.error('INVALID_FORGE_AUDIT', lambda field=field:
                       self.audit.begin_mutation('bad', {**metadata(), field: 'SECRET'}))
        for changes in ({'github_user_id': True}, {'provider_host': 'example.com'},
                        {'route': 'SECRET'}, {'origin_digest': 'SECRET'}, {'repository': 'owner/..'}):
            self.error('INVALID_FORGE_AUDIT', lambda changes=changes: self.start('bad', **changes))
        self.start(); self.prepare()
        for step in (-1, 32, True, '0'):
            self.error('INVALID_FORGE_AUDIT', lambda step=step: self.prepare(step=step))
        for obj in ({**ISSUE, 'body': 'SECRET'}, {**ISSUE, 'id': True}, {**ISSUE, 'kind': 'SECRET'},
                    {**ISSUE, 'number': 0}, {'kind': 'repository', 'id': 1, 'number': 1}):
            self.error('INVALID_FORGE_AUDIT', lambda obj=obj: self.confirm(obj=obj))
        for fields in ([], ['SECRET'], ['title', 'title'], 'title', [True]):
            self.error('INVALID_FORGE_AUDIT', lambda fields=fields: self.confirm(fields=fields))
        self.confirm()
        for changes in ({'body': 'SECRET'}, {'status': 'SECRET'}, {'status': []}, {'contact': []},
                        {'failed_field': 'SECRET'}, {'error_code': 'SECRET'}, {'objects': [ISSUE, ISSUE]}):
            self.error('INVALID_FORGE_AUDIT', lambda changes=changes:
                       self.audit.finish_mutation('op', {**result(), **changes}))
        self.assertNotIn('SECRET', json.dumps(self.audit.get_mutation('op')))

    def test_denied_route_records_no_contact_and_cannot_prepare(self):
        self.start(route='denied')
        self.error('INVALID_FORGE_AUDIT', lambda: self.prepare())
        self.error('INVALID_FORGE_AUDIT', lambda: self.audit.finish_mutation('op', none_result()))
        denied = {**none_result(), 'status': 'DENIED', 'error_code': 'UNSUPPORTED_ROUTE'}
        self.audit.finish_mutation('op', denied)
        self.assertTrue(self.start('valid')['started'])

    def test_creation_comment_reply_and_review_receipts_keep_only_object_ids(self):
        cases = (
            ('issue-create', REPO, ISSUE, ['create', 'title', 'body']),
            ('pr-create', REPO, {'kind': 'pull', 'id': 900, 'number': 9}, ['create', 'title', 'body', 'head', 'base', 'draft']),
            ('issue-comment', ISSUE, {'kind': 'comment', 'id': 700}, ['comment']),
            ('pr-comment', {'kind': 'pull', 'id': 900, 'number': 9}, {'kind': 'comment', 'id': 701}, ['comment']),
            ('pr-reply', {'kind': 'comment', 'id': 701}, {'kind': 'comment', 'id': 702}, ['reply']),
            ('pr-review', {'kind': 'pull', 'id': 900, 'number': 9}, {'kind': 'review', 'id': 801}, ['review']),
        )
        for index, (route, target, obj, fields) in enumerate(cases):
            operation = 'op-' + str(index)
            self.start(operation, route=route)
            self.prepare(operation, target=target)
            self.confirm(operation, fields=fields, obj=obj)
            final = self.audit.finish_mutation(operation, result(confirmed_fields=fields, objects=[obj]))
            self.assertEqual([obj], final['result']['objects'])
            self.assertEqual(fields, final['result']['confirmed_fields'])

    def test_pending_capacity_is_bounded_without_discarding_exact_retry(self):
        for index in range(256):
            self.start('op-' + str(index), repository='owner/repo-' + str(index))
        self.error('FORGE_RECOVERY_CAPACITY', lambda: self.start('overflow', repository='owner/another'))
        self.assertFalse(self.start('op-0', repository='owner/repo-0')['started'])
        self.assertEqual(256, len(self.audit.pending_mutations('alpha')))
        self.audit.finish_mutation('op-0', none_result())
        self.assertTrue(self.start('fresh', repository='owner/another')['started'])

    def test_audit_failure_fences_read_and_legacy_write_admission_too(self):
        from test_forge_read_audit import metadata as read_metadata
        assignment = {key: value for key, value in metadata().items() if key in {
            'room_id', 'project_id', 'repository', 'actor_id', 'participant_id', 'incarnation_id',
            'authority_version', 'github_user_id', 'request_digest'}}
        assignment['issue_number'] = 66
        self.start(); self.prepare(); self.confirm()
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError()):
            self.error('AUDIT_UNAVAILABLE', lambda: self.audit.finish_mutation('op', result()))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.begin_read('read', read_metadata()))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.begin('legacy', assignment))
        self.assertIsNone(self.audit.get_mutation('op')['result'])

    def test_pending_inventory_scoped_and_no_terminal_recovery_replay(self):
        self.start(); self.start('beta', room_id='beta')
        self.assertEqual(['op'], [r['operation_id'] for r in self.audit.pending_mutations('alpha')])
        self.assertEqual(['beta'], [r['operation_id'] for r in self.audit.pending_mutations('beta')])
        self.assertEqual([], self.audit.pending_mutations('missing'))
        self.audit.finish_mutation('op', none_result())
        self.assertEqual([], self.audit.pending_mutations('alpha'))

    def test_corrupt_stored_metadata_checkpoints_and_terminal_fail_closed(self):
        for table, field, payload in (
                ('mutation_starts', 'metadata', '{"body":"SECRET"}'),
                ('mutation_prepared', 'target', '{"kind":"issue","id":166,"body":"SECRET"}'),
                ('mutation_confirmed', 'fields', '["SECRET"]'),
                ('mutation_terminals', 'result', '{"status":"OK","body":"SECRET"}')):
            with self.subTest(table=table):
                path = Path(self.temp.name) / (table + '.db')
                with ForgeAudit(path, 'deployment-a') as audit:
                    audit.begin_mutation('op', metadata()); audit.mutation_prepared('op', 0, ISSUE)
                    audit.mutation_confirmed('op', 0, ['title'], ISSUE); audit.finish_mutation('op', result())
                    audit._db.execute('UPDATE ' + table + ' SET ' + field + '=? WHERE id=?', (payload, 'op'))
                    self.error('AUDIT_UNAVAILABLE', lambda: audit.get_mutation('op'))
                    self.error('AUDIT_UNAVAILABLE', lambda: audit.begin_mutation('fresh', metadata()))

    def test_noncanonical_or_duplicate_metadata_is_corruption(self):
        self.start()
        raw = self.audit._db.execute("SELECT metadata FROM mutation_starts WHERE id='op'").fetchone()[0]
        self.audit._db.execute("UPDATE mutation_starts SET metadata=? WHERE id='op'",
                               (raw[:-1] + ',"actor_id":"actor-a"}',))
        self.error('AUDIT_UNAVAILABLE', lambda: self.audit.get_mutation('op'))

    def test_same_database_connections_only_first_grants_start(self):
        first = self.start()
        with ForgeAudit(self.path, 'deployment-a') as other:
            second = other.begin_mutation('op', metadata())
            self.assertEqual((True, False), (first['started'], second['started']))
            self.error('FORGE_RECONCILIATION_REQUIRED', lambda: other.begin_mutation('new', metadata()))

    def test_legacy_v1_v2_migration_preserves_rows_and_wrong_deployment_never_migrates(self):
        for version in (1, 2):
            path = Path(self.temp.name) / ('legacy-' + str(version) + '.db')
            with sqlite3.connect(path) as db:
                for statement in _V1_SCHEMA.values(): db.execute(statement)
                db.execute('CREATE INDEX scope_idx ON starts(scope)')
                if version == 2:
                    for statement in _READ_SCHEMA.values(): db.execute(statement)
                db.execute('INSERT INTO deployment VALUES(1,?,?)', (version, 'deployment-a'))
                raw = _json({'historical': 'unchanged'})
                db.execute('INSERT INTO starts VALUES(?,?,?,?)', ('legacy', 'scope', raw, '2026-10-27T00:00:00+00:00'))
            self.error('DEPLOYMENT_MISMATCH', lambda: ForgeAudit(path, 'different'))
            with sqlite3.connect(path) as db:
                self.assertEqual(version, db.execute('SELECT version FROM deployment').fetchone()[0])
            with ForgeAudit(path, 'deployment-a') as migrated:
                self.assertEqual(3, migrated._db.execute('SELECT version FROM deployment').fetchone()[0])
                self.assertEqual(raw, migrated._db.execute("SELECT metadata FROM starts WHERE id='legacy'").fetchone()[0])
                self.assertTrue(migrated.begin_mutation('new', metadata())['started'])
            with ForgeAudit(path, 'deployment-a') as reopened:
                self.assertFalse(reopened.begin_mutation('new', metadata())['started'])

    def test_legacy_assignment_uncertainty_and_generic_uncertainty_share_fence(self):
        assignment = {key: value for key, value in metadata().items() if key in {
            'room_id', 'project_id', 'repository', 'actor_id', 'participant_id', 'incarnation_id',
            'authority_version', 'github_user_id', 'request_digest'}}
        assignment['issue_number'] = 66
        self.audit.begin('legacy', assignment)
        self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.start())
        self.audit.finish('legacy', {'status': 'NOT_EXECUTED', 'issue_id': None,
            'observed_assignee_ids': [], 'confirmed_fields': [], 'contact': 'none', 'attribution': 'unknown'})
        self.start()
        self.error('FORGE_RECONCILIATION_REQUIRED', lambda: self.audit.begin('another-legacy', assignment))

    def test_generic_ids_never_alias_legacy_read_or_reconciliation_ids(self):
        from test_forge_read_audit import metadata as read_metadata
        assignment = {key: value for key, value in metadata().items() if key in {
            'room_id', 'project_id', 'repository', 'actor_id', 'participant_id', 'incarnation_id',
            'authority_version', 'github_user_id', 'request_digest'}}
        assignment['issue_number'] = 66
        self.start()
        self.error('ID_CONFLICT', lambda: self.audit.begin_read('op', read_metadata()))
        self.error('ID_CONFLICT', lambda: self.audit.begin('op', assignment))
        self.audit.begin_read('read', read_metadata())
        self.error('OPERATION_CONFLICT', lambda: self.audit.begin_mutation('read', metadata()))
        self.audit.finish_mutation('op', none_result())
        self.audit.begin('assignment', assignment)
        self.error('OPERATION_CONFLICT', lambda: self.audit.begin_mutation('assignment', metadata()))
        self.audit.begin_reconciliation('assignment', 'reconciliation')
        self.error('OPERATION_CONFLICT', lambda: self.audit.begin_mutation('reconciliation', metadata()))
        self.error('ID_CONFLICT', lambda: self.audit.begin_reconciliation('assignment', 'op'))


if __name__ == '__main__':
    unittest.main()
