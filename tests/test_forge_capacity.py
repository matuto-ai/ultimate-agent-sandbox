"""Shared Room projection capacity and exact-origin read receipt regressions.

Synthetic peer/context evidence only; actual Pi saturation is tested separately.
"""
from dataclasses import replace
import json
import unittest

import test_context as context_fixture
from uas.context import FixtureRun, FixtureRunTerminal, MAX_CONTEXT_GENERATION, MAX_RUNS
from uas.forge import ForgeBinding, ReadOnlyForgeBroker
from uas.github_read import GitHubProject, GitHubReadProvider, ProviderResponse
from uas.ledger import LedgerError, Origin, _json
from uas.peer import RequestCommand, WorkRequest


class ForgeCapacityTests(unittest.TestCase):
    # Reuse only fixture setup/helpers, never inherit and rerun unrelated tests.
    connect = context_fixture.ContextTests.connect
    tearDown = context_fixture.ContextTests.tearDown
    ready = context_fixture.ContextTests.ready
    row = context_fixture.ContextTests.row

    def setUp(self):
        context_fixture.ContextTests.setUp(self)
        self.calls = []
        self.origin = Origin('actor-alice', 'alice', 'alice-1', 'epoch-1', ('forge-read',))
        def transport(path):
            self.calls.append(path)
            value = [] if '/dependencies/' in path else {
                'id': 1066, 'number': 66, 'state': 'open', 'assignees': [],
                'url': 'https://api.github.com/repos/owner/repo/issues/66',
                'repository_url': 'https://api.github.com/repos/owner/repo'}
            return ProviderResponse(200, json.dumps(value).encode(), {})
        self.broker = ReadOnlyForgeBroker(self.ledger, ForgeBinding('room', 'project', 'owner/repo'),
            lambda actor: GitHubReadProvider(GitHubProject('owner/repo'), transport))

    def prepare(self, operation):
        return self.broker.prepare({'id': operation, 'kind': 'forge-read', 'argv': ['issue', 'view', '66']},
                                   origin=self.origin, authorize=lambda: True)

    def complete(self, intent):
        return self.broker.complete(intent, self.broker.perform(intent), authorize=lambda: True)

    def saturate_requests(self, prefix='bulk'):
        admitted = []
        for n in range(100):
            before = self.ledger.snapshot()
            operation = f'{prefix}-{n}'
            try:
                self.hub.submit(self.a, WorkRequest(operation, 'run-a', 1, 'bob', 'x' * 16_384))
                admitted.append(operation)
            except LedgerError as error:
                self.assertEqual(error.code, 'QUEUE_CAPACITY_EXHAUSTED')
                self.assertEqual(before, self.ledger.snapshot())
                break
        else:
            self.fail('peer admission did not enforce shared capacity')
        self.assertGreater(len(admitted), 1)
        return admitted

    def test_pending_reads_reserve_before_contact_and_bound_concurrency(self):
        intents = [self.prepare(f'read-{n}') for n in range(8)]
        self.assertEqual([], self.calls)
        pending = self.ledger.snapshot()['state']['forge_pending']
        self.assertEqual(8, len(pending))
        self.assertTrue(all(len(row['reserved']) == 65_536 for row in pending.values()))
        before = self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError, 'FORGE_CAPACITY'):
            self.prepare('overflow')
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.calls)
        admitted = self.saturate_requests()
        for intent in intents:
            self.assertEqual('complete', self.complete(intent)['observation']['completeness'])
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])
        self.assertEqual(16, len(self.calls))
        self.assertTrue(all(self.ledger.snapshot()['state']['peer_traffic']['traffic'][key]['status'] == 'QUEUED'
                            for key in admitted))
        self.hub._reserve_capacity(self.ledger.snapshot()['state'])

    def test_completed_reads_do_not_accumulate_projection_results(self):
        initial = None
        first, first_intent = None, None
        for n in range(100):
            intent = self.prepare(f'sequential-{n}')
            result = self.complete(intent)
            state = self.ledger.snapshot()['state']
            if initial is None:
                initial, first, first_intent = state, result, intent
            self.assertEqual(initial, state)
            self.assertNotIn('"observation":', _json(state))
            self.assertEqual({}, state['forge_pending'])
        self.assertEqual(200, len(self.calls))
        self.assertEqual(first, self.complete(self.prepare('sequential-0')))
        self.assertEqual(200, len(self.calls))
        receipt = self.ledger.operation_receipt('forge-terminal-' + first_intent['key'], self.origin,
                                                authorize=lambda: True)
        self.assertEqual(first, receipt['result'])

    def test_exhausted_peer_context_reserve_rejects_read_before_contact(self):
        self.saturate_requests()
        before = self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError, 'QUEUE_CAPACITY_EXHAUSTED'):
            self.prepare('no-budget')
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.calls)
        # This was a rejected start, not an interrupted read admitted to audit.
        self.assertIsNone(self.ledger.operation_receipt('no-budget', self.origin, authorize=lambda: True))

    def test_pending_read_preserves_work_request_terminal_and_context_reset_capacity(self):
        self.hub.submit(self.c, WorkRequest('next-work', 'run-b', 1, 'bob', 'Next fixture context'))
        intent = self.prepare('pending-through-reset')
        admitted = self.saturate_requests()
        # Exhaust all remaining context Run slots with maximal tokens/generation.
        for n in range(MAX_RUNS - 3):
            self.hub.contexts.open_run(f'wide-{n}', FixtureRun(f'r{n:03d}' + 'x' * 252, MAX_CONTEXT_GENERATION))
        self.ready()
        for key in admitted:
            self.hub.submit(self.b, RequestCommand('block-' + key, 'run-a', 1, key, 'block', '\n' * 8_192))
        for n, key in enumerate(admitted):
            if n % 2:
                self.hub.cancel('cancel-' + key, key, 'x' * 16_384)
            else:
                self.hub.submit(self.b, RequestCommand('accept-' + key, 'run-a', 1, key, 'accept'))
                self.hub.submit(self.b, RequestCommand('complete-' + key, 'run-a', 1, key, 'complete'))
        self.hub.contexts.close_run('close-a', 'run-a', FixtureRunTerminal.COMPLETED)
        self.hub.contexts.request_reset('reset-bob', 'bob', 1, FixtureRun('run-b'))
        self.hub.contexts.fail_reset('reset-bob', 1, 'x' * 256)
        self.hub.contexts.succeed_reset('reset-bob', 1, authorize=lambda: True)
        self.b = self.connect('bob', 2, 'x' * 256)
        self.ready()
        self.hub.submit(self.b, RequestCommand('accept-next', 'run-b', 1, 'next-work', 'accept'))
        self.hub.submit(self.b, RequestCommand('complete-next', 'run-b', 1, 'next-work', 'complete'))
        self.assertEqual(2, self.row()['context_generation'])
        self.assertEqual([], self.calls)
        self.assertEqual('complete', self.complete(intent)['observation']['completeness'])
        state = self.ledger.snapshot()['state']
        self.assertEqual({}, state['forge_pending'])
        self.assertTrue(all(row['status'] in {'COMPLETED', 'CANCELLED'}
                            for row in state['peer_traffic']['traffic'].values()))
        self.hub._reserve_capacity(state)

    def test_operation_receipt_requires_exact_origin_and_fresh_authority(self):
        intent = self.prepare('private-receipt')
        expected = self.complete(intent)
        operation = 'forge-terminal-' + intent['key']
        for origin in (replace(self.origin, actor_id='actor-bob'),
                       replace(self.origin, incarnation_id='new-incarnation'),
                       replace(self.origin, capabilities=())):
            with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
                self.ledger.operation_receipt(operation, origin, authorize=lambda: True)
        for operation_id in (operation, 'absent'):
            with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
                self.ledger.operation_receipt(operation_id, self.origin, authorize=lambda: False)
        self.assertEqual(expected, self.ledger.operation_receipt(operation, self.origin,
                                                               authorize=lambda: True)['result'])
