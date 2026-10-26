"""Durable connected Broker decisions; no live account or canonical Run claims."""
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.forge import ForgeBinding, ReadOnlyForgeBroker
from uas.github_read import GitHubProject, GitHubReadProvider, ProviderResponse
from uas.ledger import LedgerError, Origin, RoomLedger


class ForgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'ledger.db'
        self.ledger = RoomLedger(self.path, 'alpha')
        self.addCleanup(self.ledger.close)
        self.binding = ForgeBinding('alpha', 'project-alpha', 'owner/repo')
        self.origin = Origin('actor-a', 'alice', 'inc-1', 'epoch-1', ('forge-read',))
        self.calls = []
        self.actors = []
        self.response = self.issue()
        self.broker = self.new_broker()

    def issue(self, number=66):
        return {'id': 100 + number, 'number': number, 'state': 'open',
                'repository_url': 'https://api.github.com/repos/owner/repo',
                'url': f'https://api.github.com/repos/owner/repo/issues/{number}',
                'assignees': [{'id': 9, 'login': 'worker'}], 'body': 'SECRET_RAW_BODY'}

    def transport(self, path):
        self.calls.append(path)
        value = self.response if '/dependencies/' not in path else []
        return ProviderResponse(200, json.dumps(value).encode(), {})

    def new_broker(self):
        def select(actor):
            self.actors.append(actor)
            return GitHubReadProvider(GitHubProject('owner/repo'), self.transport)
        return ReadOnlyForgeBroker(self.ledger, self.binding, select)

    def envelope(self, id='read', argv=None):
        return {'id': id, 'kind': 'forge-read', 'argv': argv or ['issue', 'view', '66']}

    def submit(self, envelope=None, broker=None, origin=None, authorize=lambda: True):
        return (broker or self.broker).submit(envelope or self.envelope(),
            origin=origin or self.origin, authorize=authorize)

    def test_durable_sanitized_exact_retry_and_no_admission(self):
        first = self.submit()
        self.assertEqual('complete', first['observation']['completeness'])
        self.assertEqual('not-evaluated', first['admission'])
        self.assertEqual(['actor-a'], self.actors)
        self.assertEqual(first, self.submit())
        self.assertEqual(2, len(self.calls))
        self.ledger.close()
        self.ledger = RoomLedger(self.path, 'alpha')
        self.addCleanup(self.ledger.close)
        self.broker = self.new_broker()
        self.assertEqual(first, self.submit())
        self.assertEqual(2, len(self.calls))
        text = json.dumps(self.ledger.replay(0)) + json.dumps(self.ledger.snapshot())
        self.assertNotIn('SECRET_RAW_BODY', text)
        self.assertNotIn('argv', text)
        self.assertEqual(2, len(self.ledger.replay(0)))

    def test_invalid_routes_are_durably_denied_without_provider_contact(self):
        for n, argv in enumerate((['api', 'repos/owner/repo'], ['issue', 'edit', '66'],
                ['issue', 'view', '../../secret'], ['issue', 'view', '66', '--repo', 'other/repo'],
                ['issue', 'view', '66', '--hostname', 'evil.invalid'], ['auth', 'token'])):
            with self.subTest(argv=argv):
                result = self.submit(self.envelope(str(n), argv))
                self.assertEqual('unknown', result['observation']['completeness'])
        self.assertFalse(self.calls)
        self.assertNotIn('secret', json.dumps(self.ledger.replay(0)))
        self.assertEqual(12, len(self.ledger.replay(0)))

    def test_authority_and_room_rejected_before_contact(self):
        for origin, authorize in ((self.origin, lambda: False),
                                  (replace(self.origin, capabilities=()), lambda: True)):
            with self.assertRaises(LedgerError):
                self.submit(origin=origin, authorize=authorize)
        with self.assertRaises(LedgerError):
            ReadOnlyForgeBroker(self.ledger, replace(self.binding, room_id='beta'), lambda _: None)
        self.assertFalse(self.calls)
        self.assertEqual(0, self.ledger.snapshot()['room_seq'])

    def test_exact_retry_needs_fresh_authority_and_conflicting_id_fails(self):
        self.submit()
        for envelope, origin, auth in ((self.envelope(argv=['issue', 'view', '67']), self.origin, lambda: True),
                (self.envelope(), replace(self.origin, actor_id='actor-b'), lambda: True),
                (self.envelope(), self.origin, lambda: False)):
            with self.assertRaises(LedgerError):
                self.submit(envelope, origin=origin, authorize=auth)
        self.assertEqual(2, len(self.calls))

    def test_precontact_store_failure_fences_no_contact(self):
        with patch.object(self.ledger, '_commit', side_effect=sqlite3.OperationalError()):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.submit()
        with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
            self.submit(self.envelope('other'))
        self.assertFalse(self.calls)
        self.assertEqual(0, self.ledger.snapshot()['room_seq'])

    def test_terminal_store_failure_reopen_is_unknown_no_blind_retry(self):
        commit = self.ledger._commit
        count = 0
        def fail_terminal():
            nonlocal count
            count += 1
            if count == 2:
                raise sqlite3.OperationalError()
            return commit()
        with patch.object(self.ledger, '_commit', side_effect=fail_terminal):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.submit()
        self.assertEqual(2, len(self.calls))
        self.assertEqual(1, len(self.ledger.replay(0)))
        with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
            self.submit()
        self.ledger.close()
        self.ledger = RoomLedger(self.path, 'alpha')
        self.addCleanup(self.ledger.close)
        self.broker = self.new_broker()
        recovered = self.submit()
        self.assertEqual('INTERRUPTED_OBSERVATION', recovered['observation']['status'])
        self.assertEqual('unknown', recovered['observation']['completeness'])
        self.assertEqual(recovered, self.submit())
        self.assertEqual(2, len(self.calls))

    def test_lost_ack_after_committed_terminal_recovers_original(self):
        commit = self.ledger._commit
        count = 0
        def lost_ack():
            nonlocal count
            count += 1
            commit()
            if count == 2:
                raise sqlite3.OperationalError()
        with patch.object(self.ledger, '_commit', side_effect=lost_ack):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.submit()
        self.broker = self.new_broker()
        self.assertEqual('complete', self.submit()['observation']['completeness'])
        self.assertEqual(2, len(self.calls))

    def test_provider_exception_and_unsanitized_result_never_escape(self):
        for n, failure in enumerate(('exception', 'raw')):
            class BadProvider:
                project = GitHubProject('owner/repo')
                def read_issue(inner, number):
                    if failure == 'exception':
                        raise RuntimeError('SECRET_TOKEN')
                    return {'raw': 'SECRET_TOKEN'}
            broker = ReadOnlyForgeBroker(self.ledger, self.binding, lambda _: BadProvider())
            result = self.submit(self.envelope(str(n)), broker=broker)
            self.assertEqual('unknown', result['observation']['completeness'])
        self.assertNotIn('SECRET_TOKEN', json.dumps(self.ledger.replay(0)))

    def test_sanitized_wrong_issue_cannot_masquerade_as_requested_target(self):
        class WrongIssue:
            project = GitHubProject('owner/repo')
            def read_issue(inner, number):
                return {'status': 'OK', 'completeness': 'complete', 'pages': 1,
                        'issue': {'id': 167, 'number': 67, 'state': 'open', 'assignees': []},
                        'dependencies': []}
        broker = ReadOnlyForgeBroker(self.ledger, self.binding, lambda _: WrongIssue())
        result = self.submit(broker=broker)
        self.assertEqual('unknown', result['observation']['completeness'])
        self.assertEqual('PROVIDER_FAILURE', result['observation']['status'])

    def test_late_authority_loss_releases_only_own_reservation_without_recontact(self):
        first = self.broker.prepare(self.envelope('first'), origin=self.origin, authorize=lambda: True)
        second = self.broker.prepare(self.envelope('second'), origin=self.origin, authorize=lambda: True)
        outcome = self.broker.perform(first)
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.broker.complete(first, outcome, authorize=lambda: False)
        self.broker.abandon(first, 'AUTHORITY_REVOKED')
        pending = self.ledger.snapshot()['state']['forge_pending']
        self.assertEqual({second['key']}, set(pending))
        self.assertEqual(2, len(self.calls))
        terminal = self.ledger.operation_receipt('forge-terminal-' + first['key'], self.origin,
                                                 authorize=lambda: True)
        self.assertEqual('AUTHORITY_LOST', terminal['result']['observation']['status'])
        self.broker.abandon(first, 'ROOM_NOT_RUNNING')
        self.assertEqual(2, len(self.calls))
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.submit(self.envelope('first'), authorize=lambda: False)
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_INTENT'):
            self.broker.abandon({**first, 'key': second['key']}, 'AUTHORITY_REVOKED')
        self.assertIsNone(self.broker.abandon(second, 'AUTHORITY_REVOKED'))
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])

    def test_abandon_reconciles_committed_terminal_after_lost_ack_without_downgrade(self):
        intent = self.broker.prepare(self.envelope(), origin=self.origin, authorize=lambda: True)
        outcome = self.broker.perform(intent)
        commit = self.ledger._commit
        def lost_ack():
            commit()
            raise sqlite3.OperationalError()
        with patch.object(self.ledger, '_commit', side_effect=lost_ack):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.broker.complete(intent, outcome, authorize=lambda: True)
        before = self.ledger.snapshot()
        self.broker.abandon(intent, 'AUTHORITY_REVOKED')
        self.assertEqual(before, self.ledger.snapshot())
        receipt = self.ledger.operation_receipt('forge-terminal-' + intent['key'], self.origin,
                                                authorize=lambda: True)
        self.assertEqual('complete', receipt['result']['observation']['completeness'])
        self.assertEqual(2, len(self.calls))
        self.assertFalse(any(e['kind'] == 'forge-read-abandoned' for e in self.ledger.replay(0)))
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_ABANDONMENT'):
            self.new_broker().abandon(intent, 'AUTHORITY_REVOKED')
        forged = {**intent, 'origin': replace(self.origin, actor_id='actor-b')}
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
            self.broker.abandon(forged, 'AUTHORITY_REVOKED')

    def test_help_and_generic_unauthenticated_denial_audit(self):
        result = self.submit(self.envelope(argv=['--help']))
        self.assertEqual('HELP', result['observation']['status'])
        self.assertIn('gh issue view', result['observation']['help'])
        self.broker.denied('WRONG_PROCESS')
        event = self.ledger.replay(0)[-1]
        self.assertEqual({'code': 'WRONG_PROCESS'}, event['payload'])
        self.assertEqual('forge-audit', event['origin']['actor_id'])
        self.assertFalse(self.calls)
