"""Existing broker/process read seam; PR facts never grant workflow authority."""
from copy import deepcopy
from dataclasses import replace
import json
import sqlite3
import unittest
from unittest.mock import patch

import test_forge as broker_harness
import test_participant as process_harness
from test_github_pr import pull, review, response
from uas.forge import ForgeBinding, ReadOnlyForgeBroker
from uas.github_read import GitHubProject, GitHubReadProvider, ProviderResponse
from uas.ledger import LedgerError, RoomLedger


class PullBrokerTests(unittest.TestCase):
    issue = broker_harness.ForgeTests.issue
    new_broker = broker_harness.ForgeTests.new_broker
    submit = broker_harness.ForgeTests.submit

    def setUp(self):
        broker_harness.ForgeTests.setUp(self)
        self.pull = pull(number=66, repository='owner/repo')
        self.reviews = [review(number=66, repository='owner/repo')]

    def envelope(self, id='read', argv=None):
        return {'id': id, 'kind': 'forge-read', 'argv': argv or ['pr', 'view', '66']}

    def transport(self, path):
        self.calls.append(path)
        return response(self.reviews if '/reviews?' in path else self.pull)

    def test_sanitized_durable_exact_retry_no_run_review_or_gate_transition(self):
        result = self.submit()
        self.assertEqual('OK', result['observation']['status'])
        self.assertEqual('not-evaluated', result['admission'])
        self.assertEqual(self.pull['head']['sha'], result['observation']['pull']['head']['sha'])
        self.assertEqual(self.pull['merge_commit_sha'], result['observation']['pull']['merge_commit_sha'])
        self.assertEqual(['actor-a'], self.actors)
        self.assertEqual(3, len(self.calls))
        self.assertEqual(result, self.submit())
        self.assertEqual(3, len(self.calls))
        self.ledger.close()
        self.ledger = RoomLedger(self.path, 'alpha')
        self.addCleanup(self.ledger.close)
        self.broker = self.new_broker()
        self.assertEqual(result, self.submit())
        state = self.ledger.snapshot()['state']
        self.assertEqual({'forge_pending': {}}, state)
        text = json.dumps(self.ledger.replay(0))
        for field in ('body', 'title', 'email', 'SECRET', 'argv'):
            self.assertNotIn(field, text)
        for field in ('verdict', 'eligible', 'review_round', 'gate'):
            self.assertNotIn(field, result['observation'])

    def test_rejected_identity_routes_and_no_read_capability_never_contact(self):
        for argv in (['pr', 'view', '66', '--repo', 'other/repo'], ['pr', 'merge', '66'],
                     ['pr', 'review', '66', '--approve'], ['pr', 'view', '66', '--hostname', 'evil.invalid']):
            result = self.submit(self.envelope(str(len(self.ledger.replay(0))), argv))
            self.assertEqual('unknown', result['observation']['completeness'])
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.submit(origin=replace(self.origin, capabilities=('forge-write',)))
        self.assertEqual([], self.calls)

    def test_internal_issue_admission_cannot_repurpose_pr_route(self):
        intent = self.broker.prepare(self.envelope(), origin=self.origin, authorize=lambda: True, admission=True)
        result = self.broker.complete(intent, self.broker.perform(intent), authorize=lambda: True)
        self.assertEqual('UNSUPPORTED_ROUTE', result['observation']['status'])
        self.assertEqual([], self.calls)

    def test_broker_rejects_provider_extra_fields_and_wrong_bound_number(self):
        provider = GitHubReadProvider(GitHubProject('owner/repo'), self.transport)
        valid = provider.read_pull(66)
        for changed in ({**valid, 'verdict': 'pass'},
                        {**valid, 'pull': {**valid['pull'], 'number': 67}},
                        {**valid, 'reviews': [{**valid['reviews'][0], 'body': 'SECRET'}]}):
            with patch.object(provider, 'read_pull', return_value=changed):
                self.broker.provider_for_actor = lambda _: provider
                result = self.submit(self.envelope('bad-' + str(len(self.ledger.replay(0)))))
                self.assertEqual('PROVIDER_FAILURE', result['observation']['status'])
        self.assertNotIn('SECRET', json.dumps(self.ledger.replay(0)))

    def test_audit_failure_precontact_and_postread_remain_fail_closed(self):
        with patch.object(self.ledger, '_commit', side_effect=sqlite3.OperationalError()):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.submit()
        self.assertEqual([], self.calls)
        self.broker = self.new_broker()
        original, count = self.ledger._commit, 0
        def fail_terminal():
            nonlocal count
            count += 1
            if count == 2:
                raise sqlite3.OperationalError()
            original()
        with patch.object(self.ledger, '_commit', side_effect=fail_terminal):
            with self.assertRaisesRegex(LedgerError, 'AUDIT_UNAVAILABLE'):
                self.submit()
        self.assertEqual(3, len(self.calls))
        self.ledger.close()
        self.ledger = RoomLedger(self.path, 'alpha')
        self.addCleanup(self.ledger.close)
        self.broker = self.new_broker()
        self.assertEqual('INTERRUPTED_OBSERVATION', self.submit()['observation']['status'])
        self.assertEqual(3, len(self.calls))

    def test_late_authority_loss_never_publishes_pr_facts(self):
        intent = self.broker.prepare(self.envelope(), origin=self.origin, authorize=lambda: True)
        observation = self.broker.perform(intent)
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.broker.complete(intent, observation, authorize=lambda: False)
        self.broker.abandon(intent, 'AUTHORITY_REVOKED')
        self.assertEqual('AUTHORITY_LOST', self.submit()['observation']['status'])
        self.assertNotIn('pullrequestreview', json.dumps(self.ledger.replay(0)))


@unittest.skipUnless(process_harness.SUPPORTED, 'requires existing process/socketpair fixture')
class PullProcessTests(unittest.TestCase):
    setUp = process_harness.ParticipantTests.setUp
    reopen_supervisor = process_harness.ParticipantTests.reopen_supervisor
    seat = process_harness.ParticipantTests.seat
    launch = process_harness.ParticipantTests.launch
    line = process_harness.ParticipantTests.line
    send = process_harness.ParticipantTests.send

    def test_kernel_bound_process_can_observe_pr_without_workflow_authority(self):
        calls = []
        def transport(path):
            calls.append(path)
            return response([review(repository='owner/repo')] if '/reviews?' in path
                            else pull(repository='owner/repo'))
        broker = ReadOnlyForgeBroker(self.ledger, ForgeBinding('alpha', 'fixture', 'owner/repo'),
            lambda _: GitHubReadProvider(GitHubProject('owner/repo'), transport))
        self.controller.bind_forge(broker)
        handle = self.launch(seat=self.seat(capabilities=('peer-traffic', 'forge-read')))
        envelope = {'id': 'native-pr', 'kind': 'forge-read', 'argv': ['pr', 'view', '42']}
        _, first = self.send(handle, envelope)
        self.assertTrue(first['ok'])
        self.assertEqual('complete', first['receipt']['observation']['completeness'])
        self.assertEqual('not-evaluated', first['receipt']['admission'])
        _, retried = self.send(handle, envelope)
        self.assertEqual(first, retried)
        self.assertEqual(3, len(calls))
        events = [e for e in self.ledger.replay(0) if e['kind'] == 'forge-read-observed']
        self.assertEqual(handle.badge.origin().canonical(), events[0]['origin'])
        self.assertNotIn('runs', self.ledger.snapshot()['state'])
