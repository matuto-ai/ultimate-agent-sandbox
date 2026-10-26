"""One controlled GitHub effect across Broker and Deployment audit; no accounts."""
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.forge import ForgeBinding, ReadOnlyForgeBroker
from uas.forge_assignment import AssignmentBroker
from uas.forge_audit import ForgeAudit
from uas.github_assignment import GitHubAssignmentProvider
from uas.github_read import GitHubProject, ProviderResponse, parse_assignment_route
from uas.ledger import LedgerError, Origin, RoomLedger


class AssignmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.audit = ForgeAudit(self.root / 'deployment.db', 'deployment')
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.addCleanup(self.ledger.close)
        self.addCleanup(self.audit.close)
        self.binding = ForgeBinding('alpha', 'project', 'owner/repo')
        self.origin = Origin('actor', 'builder', 'inc1', 'epoch1', ('forge-write', 'forge-read'))
        self.ids, self.calls, self.user_id = [], [], 41
        self.number, self.issue_id, self.state = 7, 107, 'open'
        self.lost, self.ignore, self.authorized, self.conflict = False, False, True, False
        self.provider = GitHubAssignmentProvider(GitHubProject('owner/repo'), self.transport)
        self.service = AssignmentBroker(self.binding, self.audit, {'actor': 41}, lambda _: self.provider)
        self.broker = ReadOnlyForgeBroker(self.ledger, self.binding, lambda _: None, assignments=self.service)

    def issue(self):
        base = 'https://api.github.com/repos/owner/repo'
        return {'id': self.issue_id, 'number': self.number, 'state': self.state,
            'repository_url': base, 'url': base + '/issues/' + str(self.number),
            'assignees': [{'id': i, 'login': 'actor-' + str(i)} for i in self.ids],
            'body': 'SECRET_RESPONSE_BODY'}

    def transport(self, method, path, body):
        self.calls.append((method, path, body))
        # Every provider contact observes a committed sanitized start.
        rows = self.audit._db.execute('SELECT count(*) FROM starts').fetchone()[0]
        self.assertGreater(rows, 0)
        if path == 'user':
            value = {'id': self.user_id, 'login': 'actor-41'}
        else:
            if method == 'POST':
                self.assertEqual(body, {'assignees': ['actor-41']})
                self.assertEqual(self.audit.get(self.service._key('write'))['issue_id'], 107)
                if not self.ignore:
                    self.ids = [41, 99] if self.conflict else [41]
                if self.lost:
                    raise TimeoutError('SECRET_TOKEN')
            value = self.issue()
        return ProviderResponse(201 if method == 'POST' else 200, json.dumps(value).encode(), {})

    def envelope(self, operation='write', argv=None):
        return {'id': operation, 'kind': 'forge-write',
            'argv': argv or ['issue', 'edit', '7', '--add-assignee', '@me']}

    def submit(self, envelope=None, origin=None):
        return self.broker.submit(envelope or self.envelope(), origin=origin or self.origin,
                                  authorize=lambda: self.authorized)

    def reconcile(self, rid='reconcile'):
        return self.service.reconcile('write', rid, origin=self.origin, authorize=lambda: self.authorized)

    def test_exact_success_receipt_sanitization_and_no_replay(self):
        first = self.submit()
        self.assertEqual('ASSIGNED', first['assignment']['status'])
        self.assertEqual(['add-assignee'], first['assignment']['confirmed_fields'])
        self.assertEqual(first, self.submit())
        self.assertEqual(1, sum(c[0] == 'POST' for c in self.calls))
        self.audit.close()
        self.audit = ForgeAudit(self.root / 'deployment.db', 'deployment')
        self.addCleanup(self.audit.close)
        self.service.audit = self.audit
        self.assertEqual(first, self.submit())
        text = json.dumps(self.audit.get(self.service._key('write')))
        for secret in ['SECRET', 'argv', 'body', 'GH_TOKEN']:
            self.assertNotIn(secret, text)

    def test_lost_response_reconciliation_proves_current_state_not_causation(self):
        self.lost = True
        first = self.submit()
        self.assertEqual('UNKNOWN_OUTCOME', first['assignment']['status'])
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
            self.submit(self.envelope('new-id'))
        self.assertEqual(first, self.submit())
        result = self.reconcile()
        self.assertEqual('MATCHED', result['assignment']['status'])
        self.assertEqual('observed-only', result['assignment']['attribution'])
        self.assertEqual([], result['assignment']['confirmed_fields'])
        calls = len(self.calls)
        self.assertEqual(result, self.reconcile())
        self.assertEqual(calls, len(self.calls))
        self.assertEqual(first, self.submit())
        self.assertEqual(1, sum(c[0] == 'POST' for c in self.calls))

    def test_absence_conflict_and_unknown_do_not_replay(self):
        self.lost = True
        self.submit()
        for ids, expected in (([], 'ABSENT'), ([99], 'CONFLICT')):
            self.ids = ids
            self.assertEqual(expected, self.reconcile(expected)['assignment']['status'])
        with patch.object(self.provider, 'transport', side_effect=TimeoutError()):
            self.assertEqual('UNKNOWN', self.reconcile('unknown')['assignment']['status'])
        self.assertEqual(1, sum(c[0] == 'POST' for c in self.calls))

    def test_assignment_conflict_and_wrong_actor_never_write(self):
        self.ids = [99]
        self.assertEqual('ASSIGNMENT_CONFLICT', self.submit()['assignment']['status'])
        self.user_id = 52
        self.assertEqual('ACTOR_MISMATCH', self.submit(self.envelope('wrong-account'))['assignment']['status'])
        self.assertFalse(any(c[0] == 'POST' for c in self.calls))

    def test_concurrent_external_assignment_is_preserved_and_unknown(self):
        self.conflict = True
        self.assertEqual('UNKNOWN_OUTCOME', self.submit()['assignment']['status'])
        self.assertEqual([41, 99], self.ids)
        self.assertEqual('CONFLICT', self.reconcile()['assignment']['status'])

    def test_http_success_silently_ignored_assignment_not_success(self):
        self.ignore = True
        self.assertEqual('UNKNOWN_OUTCOME', self.submit()['assignment']['status'])
        self.assertEqual('ABSENT', self.reconcile()['assignment']['status'])

    def test_capability_project_and_arbitrary_routes_fail_before_contact(self):
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.submit(origin=replace(self.origin, capabilities=('forge-read',)))
        for argv in (['issue','edit','7','--add-assignee','other'],
                     ['issue','edit','7','--add-assignee','@me','--repo','other/repo'],
                     ['api','user'], ['issue','edit','7','--remove-assignee','@me']):
            with self.assertRaises(LedgerError):
                self.submit(self.envelope(argv=argv))
        self.assertEqual([], self.calls)

    def test_audit_failure_before_contact_and_before_post(self):
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError()):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.submit()
        self.assertEqual([], self.calls)
        self.service.failed = False  # New broker would be explicitly constructed.
        original = self.audit._commit
        count = 0
        def fail_prepared():
            nonlocal count
            count += 1
            if count == 2:
                raise sqlite3.OperationalError()
            original()
        with patch.object(self.audit, '_commit', side_effect=fail_prepared):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.submit()
        self.assertFalse(any(c[0] == 'POST' for c in self.calls))

    def test_terminal_audit_failure_fences_and_reopen_reconciles_without_post(self):
        original = self.audit._commit
        count = 0
        def fail_terminal():
            nonlocal count
            count += 1
            if count == 3:
                raise sqlite3.OperationalError()
            original()
        with patch.object(self.audit, '_commit', side_effect=fail_terminal):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.submit()
        with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
            self.submit()
        self.audit.close()
        self.audit = ForgeAudit(self.root / 'deployment.db', 'deployment')
        self.addCleanup(self.audit.close)
        self.service = AssignmentBroker(self.binding, self.audit, {'actor': 41}, lambda _: self.provider)
        self.broker.assignments = self.service
        self.assertEqual('UNKNOWN_OUTCOME', self.submit()['assignment']['status'])
        self.assertEqual('MATCHED', self.reconcile()['assignment']['status'])
        self.assertEqual(1, sum(c[0] == 'POST' for c in self.calls))

    def test_revocation_between_preflight_and_post_has_no_write(self):
        original = self.transport
        def revoke(method, path, body):
            result = original(method, path, body)
            if path.endswith('/issues/7'):
                self.authorized = False
            return result
        self.provider.transport = revoke
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.submit()
        self.assertFalse(any(c[0] == 'POST' for c in self.calls))

    def test_reconciliation_binds_exact_issue_id(self):
        self.lost = True
        self.submit()
        self.issue_id = 999
        self.assertEqual('UNKNOWN', self.reconcile()['assignment']['status'])

    def test_room_operation_id_cannot_change_read_into_write(self):
        self.broker.submit({'id': 'write', 'kind': 'forge-read', 'argv': ['issue', 'view', '7']},
                           origin=self.origin, authorize=lambda: True)
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
            self.submit()
        self.assertEqual([], self.calls)

    def test_preassigned_self_records_observation_without_mutation(self):
        self.ids = [41]
        result = self.submit()
        self.assertEqual('ALREADY_ASSIGNED', result['assignment']['status'])
        self.assertEqual('observed-only', result['assignment']['attribution'])
        self.assertEqual([], result['assignment']['confirmed_fields'])
        self.assertFalse(any(c[0] == 'POST' for c in self.calls))
        self.assertEqual('MATCHED', self.reconcile()['assignment']['status'])

    def test_invalid_provider_object_and_output_fail_before_write(self):
        original = self.transport
        for mode in ('pr', 'wrong-number', 'oversize'):
            def invalid(method, path, body):
                response = original(method, path, body)
                if path == 'user':
                    return response
                if mode == 'oversize':
                    return ProviderResponse(200, b'x' * 1_048_577, {})
                value = json.loads(response.body)
                if mode == 'pr':
                    value['pull_request'] = {}
                else:
                    value['number'] = 8
                return ProviderResponse(200, json.dumps(value).encode(), {})
            self.provider.transport = invalid
            self.assertEqual('PROVIDER_FAILURE', self.submit(self.envelope(mode))['assignment']['status'])
        self.assertFalse(any(c[0] == 'POST' for c in self.calls))

    def test_reconciliation_start_failure_and_interrupted_retry_make_no_get(self):
        self.lost = True
        self.submit()
        before = len(self.calls)
        with patch.object(self.audit, '_commit', side_effect=sqlite3.OperationalError()):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.reconcile('failed-start')
        self.assertEqual(before, len(self.calls))
        self.service = AssignmentBroker(self.binding, self.audit, {'actor': 41}, lambda _: self.provider)
        self.broker.assignments = self.service
        self.audit.begin_reconciliation(self.service._key('write'), 'interrupted-read')
        result = self.reconcile('interrupted-read')
        self.assertEqual('UNKNOWN', result['assignment']['status'])
        self.assertEqual(before, len(self.calls))
        self.assertEqual('MATCHED', self.reconcile('new-explicit-read')['assignment']['status'])

    def test_fenced_recovery_before_post_releases_only_for_new_explicit_operation(self):
        self.broker.prepare(self.envelope(), origin=self.origin, authorize=lambda: True)
        self.service.recover_pending(lambda _: False)
        self.assertIsNone(self.audit.get(self.service._key('write'))['result'])
        self.service.recover_pending(lambda old: old.incarnation_id == self.origin.incarnation_id)
        self.assertEqual('NOT_EXECUTED', self.submit()['assignment']['status'])
        self.assertEqual([], self.calls)
        # New operation is an explicit caller decision, never an automatic retry.
        begun = self.broker.prepare(self.envelope('explicit-new-write'), origin=self.origin, authorize=lambda: True)
        self.assertTrue(begun['started'])
        self.assertEqual([], self.calls)

    def test_fenced_recovery_after_prepared_remains_unknown_and_blocks_new_write(self):
        intent = self.broker.prepare(self.envelope(), origin=self.origin, authorize=lambda: True)
        self.audit.prepared(intent['key'], 107)
        self.service.recover_pending(lambda _: True)
        self.assertEqual('UNKNOWN_OUTCOME', self.submit()['assignment']['status'])
        with self.assertRaisesRegex(LedgerError, 'FORGE_RECONCILIATION_REQUIRED'):
            self.submit(self.envelope('unsafe-retry'))
        self.assertEqual([], self.calls)
        self.assertEqual('ABSENT', self.reconcile()['assignment']['status'])
        self.assertFalse(any(c[0] == 'POST' for c in self.calls))

    def test_unsupported_route_denial_is_sanitized_and_durable(self):
        with self.assertRaises(LedgerError):
            self.submit(self.envelope(argv=['issue','edit','7','--add-assignee','secret-other']))
        events = self.ledger.replay(0)
        self.assertEqual('forge-record-denied', events[-1]['kind'])
        self.assertEqual('UNSUPPORTED_ROUTE', events[-1]['payload']['code'])
        self.assertNotIn('secret-other', json.dumps(events))

    def test_prewrite_authority_loss_abandon_is_not_executed_not_permanent_unknown(self):
        intent = self.broker.prepare(self.envelope(), origin=self.origin, authorize=lambda: True)
        self.broker.abandon(intent, 'AUTHORITY_REVOKED')
        self.assertEqual('NOT_EXECUTED', self.audit.get(intent['key'])['result']['status'])
        self.assertTrue(self.broker.prepare(self.envelope('new-explicit'), origin=self.origin,
                                           authorize=lambda: True)['started'])
        self.assertEqual([], self.calls)
