"""Hosted only: actual Pi, Git, kernel-authenticated fixture requester and stop.

Provider responses are bounded account-free fixtures, not live GitHub proof.
The ordinary pi-native workflow runs these with the existing three-minute cap.
"""
from copy import deepcopy
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import select
import unittest

import test_pi_run_admission as harness
from uas.fixture_peer import FixtureReceiver
from uas.ledger import LedgerError
from uas.participant import FixtureSeat
from uas.peer import WorkRequest
from uas.pi_fixture import FixturePiRecipe
from uas.run_admission import RunAdmission


@unittest.skipUnless(harness.INSTALL, 'requires hosted locked official Pi fixture')
class RunManagementTests(unittest.TestCase):
    git = harness.RunAdmissionTests.git
    reopen_supervisor = harness.RunAdmissionTests.reopen_supervisor
    reopen = harness.RunAdmissionTests.reopen
    issue = harness.RunAdmissionTests.issue
    error = harness.RunAdmissionTests.error
    capture_evidence = harness.RunAdmissionTests.capture_evidence

    def transport(self, path):
        if path.endswith('/issues/3'):
            from uas.github_read import ProviderResponse
            self.calls.append(path)
            return ProviderResponse(200, json.dumps(self.issue(3)).encode(), {})
        return harness.RunAdmissionTests.transport(self, path)

    def setUp(self):
        harness.RunAdmissionTests.setUp(self)
        self.config['rooms'][0]['profiles'][1]['capabilities'].append('can-open-requested-run')
        self.human = replace(self.human, capabilities=('human-open-run', 'human-control-run'))
        self.admission = RunAdmission(self.controller, self.broker, self.allocator,
            io.StringIO(json.dumps(self.config)), seats={'builder': self.seat}, install=harness.INSTALL,
            runtime_root=self.root / 'native', authorize_human=lambda *_: self.authorized)
        self.controller.bind_runs(self.admission)

    def line(self, handle):
        self.assertTrue(select.select([handle.process.stdout], [], [], 5)[0], 'fixture output timeout')
        return json.loads(handle.process.stdout.readline())

    def requester(self):
        receiver = FixtureReceiver(self.root / 'requester.db', 'alpha', 'reviewer', 'outbound-only')
        self.addCleanup(receiver.close)
        configured = self.config['rooms'][0]['seats'][1]
        seat = FixtureSeat('reviewer', 'bob', configured['profile'],
                          ('peer-traffic', 'can-open-requested-run'))
        handle = self.controller.launch(seat, receiver)
        self.assertTrue(self.line(handle)['ready'])
        return handle

    def send(self, handle, operation, kind, payload, mode=None):
        message = {'id': operation, 'kind': kind, 'payload': payload}
        handle.process.stdin.write(json.dumps({'message': message, **({'mode': mode} if mode else {})}) + '\n')
        handle.process.stdin.flush()
        sent = self.line(handle)
        result = self.controller.receive(handle)
        self.assertEqual(result, self.line(handle))
        return sent, result

    def open_human(self, operation='human-open', number=1):
        return self.admission.open(operation, number, 'builder', human=self.human)

    def test_authenticated_request_consumption_wrong_process_and_no_capacity(self):
        requester = self.requester()
        self.admission.issue_request('grant', 1, 'reviewer', 'builder', human=self.human)
        payload = {'request_id': 'grant', 'attempt_id': None}
        sent, refused = self.send(requester, 'participant-open', 'run-open-requested', payload, mode='fork')
        self.assertNotEqual(requester.process.pid, sent['pid'])
        self.assertEqual('WRONG_PROCESS', refused['error'])
        self.assertEqual('UNUSED', self.ledger.snapshot()['state']['run_requests']['grant']['status'])
        _, opened = self.send(requester, 'participant-open', 'run-open-requested', payload)
        self.assertTrue(opened['ok'], opened)
        row = opened['receipt']
        self.assertEqual('ACTIVE', row['status'])
        self.assertEqual('grant', row['run_request'])
        self.assertEqual(opened, self.send(requester, 'participant-open', 'run-open-requested', payload)[1])
        self.assertEqual('CONFIRMED', self.hub.deliver(self.controller.handles['builder'].connection)['outcome'])
        self.admission.issue_request('second-grant', 3, 'reviewer', 'builder', human=self.human)
        refused = self.send(requester, 'second-open', 'run-open-requested',
                            {'request_id': 'second-grant', 'attempt_id': None})[1]
        self.assertEqual('RUN_CAPACITY_OR_DUPLICATE', refused['error'])
        self.assertEqual('UNUSED', self.ledger.snapshot()['state']['run_requests']['second-grant']['status'])
        self.assertEqual(1, len(self.hub._state()['traffic']))

    def test_authenticated_proposal_needs_exact_approval(self):
        requester = self.requester()
        result = self.send(requester, 'proposal', 'run-propose', {'issue_number': 1, 'participant_id': 'builder'})[1]
        self.assertTrue(result['ok'], result)
        proposal = result['receipt']
        self.assertNotIn('runs', self.ledger.snapshot()['state'])
        self.error('EXACT_PROPOSAL_REQUIRED', lambda: self.admission.approve_proposal(
            'approve-wrong', 'proposal', '0' * 64, human=self.human))
        self.admission.approve_proposal('approved', 'proposal', proposal['digest'], human=self.human)
        result = self.send(requester, 'approved-open', 'run-open-requested',
                           {'request_id': 'approved', 'attempt_id': None})[1]
        self.assertTrue(result['ok'], result)
        self.assertEqual('CONSUMED', self.ledger.snapshot()['state']['run_requests']['approved']['status'])

    def test_policy_migration_native_context_preserved_force_and_terminal_stop(self):
        row = self.open_human()
        handle = self.controller.handles['builder']
        native = handle.connection.receiver
        self.hub.deliver(handle.connection)
        session = native.initial_state['session_id']
        policy = deepcopy(self.admission.room['policies'][0])
        policy['version'] += 1
        self.admission.room['policies'][0] = policy
        migrated = self.admission.migrate_policy('migrate', row['run_id'], 1, 0,
            policy['id'], policy['version'], 'new-evidence-policy', human=self.human)
        self.assertEqual(('PAUSED', 2), (migrated['status'], migrated['generation']))
        self.assertEqual(session, native.initial_state['session_id'])
        self.assertEqual(1, native.scope['context_generation'])
        self.assertEqual(2, native.scope['generation'])
        self.error('STALE_GENERATION', lambda: self.hub.submit(handle.connection,
            WorkRequest('stale-request', row['run_id'], 1, 'reviewer', 'stale policy')))
        self.admission.resume('resume-migrated', row['run_id'], 2, 1, 'continue', human=self.human)
        self.assertEqual('CONFIRMED', self.hub.deliver(handle.connection)['outcome'])
        (self.repo / 'human-dirty.txt').write_text('retain this work\n')
        stopped = self.admission.force_stop('force', row['run_id'], 2, 2, 'human-stop', human=self.human)
        self.assertEqual(('PAUSED', 3), (stopped['status'], stopped['generation']))
        self.assertIsNotNone(handle.process.poll())
        self.error('NATIVE_RESTORE_REQUIRED', lambda: self.admission.resume(
            'bad-resume', row['run_id'], 3, 3, 'cannot-revive', human=self.human))
        recipe = FixturePiRecipe(harness.INSTALL, self.root / 'native' / row['run_id'],
            scope=self.hub.contexts.scope('builder'), checkout=row['checkout']['path'])
        restored = self.controller.restore_pi(self.seat, recipe)
        self.assertEqual(session, restored.connection.receiver.initial_state['session_id'])
        self.assertEqual(self.repo, Path('/proc', str(restored.process.pid), 'cwd').resolve())
        self.admission.resume('resume-stopped', row['run_id'], 3, 3, 'explicit-restore', human=self.human)
        self.assertEqual('CONFIRMED', self.hub.deliver(restored.connection)['outcome'])
        closed = self.admission.terminal_stop('terminal', row['run_id'], 3, 4, 'ended-early', human=self.human)
        self.assertEqual(('CLOSED', 'stopped', 'ended-early'), (closed['status'], closed['outcome'], closed['reason']))
        self.assertEqual('retain this work\n', (self.repo / 'human-dirty.txt').read_text())
        self.error('PRIMARY_NOT_RECONCILED', lambda: self.open_human('dirty-retarget', 3))
        pending = self.ledger.snapshot()['state']['run_admissions'][self.admission.run_id('dirty-retarget')]
        self.assertFalse(pending['authorization_consumed'])
        self.assertEqual('PRIMARY_NOT_RECONCILED', pending['attention'])
        self.assertEqual('retain this work\n', (self.repo / 'human-dirty.txt').read_text())

    def test_closed_run_retarget_requires_native_reset_and_retains_closed_history(self):
        row = self.open_human()
        first = self.controller.handles['builder']
        self.hub.deliver(first.connection)
        old_session = first.connection.receiver.initial_state['session_id']
        self.admission.terminal_stop('end-first', row['run_id'], 1, 0, 'different-work', human=self.human)
        next_run = self.open_human('new-exact-item', 3)
        second = self.controller.handles['builder']
        self.assertNotEqual(first.badge.incarnation_id, second.badge.incarnation_id)
        self.assertNotEqual(old_session, second.connection.receiver.initial_state['session_id'])
        self.assertEqual(2, next_run['context_generation'])
        self.assertEqual('CLOSED', self.ledger.snapshot()['state']['runs'][row['run_id']]['status'])
        self.assertEqual('CONFIRMED', self.hub.deliver(second.connection)['outcome'])
        session = second.connection.receiver.initial_state['session_id']
        policy = deepcopy(self.admission.room['policies'][0])
        policy['version'] += 1
        self.admission.room['policies'][0] = policy
        self.admission.migrate_policy('later-context-policy', next_run['run_id'], 1, 0,
            policy['id'], policy['version'], 'retain-context', human=self.human)
        self.admission.force_stop('later-context-stop', next_run['run_id'], 2, 1, 'stop', human=self.human)
        recipe = FixturePiRecipe(harness.INSTALL, self.root / 'native' / next_run['run_id'],
            scope=self.hub.contexts.scope('builder'), checkout=next_run['checkout']['path'])
        restored = self.controller.restore_pi(self.seat, recipe)
        self.assertEqual(session, restored.connection.receiver.initial_state['session_id'])
        self.assertEqual(2, restored.connection.context_generation)
        self.assertEqual(self.repo, Path('/proc', str(restored.process.pid), 'cwd').resolve())
        self.admission.resume('later-context-resume', next_run['run_id'], 3, 2, 'continue', human=self.human)
        self.assertEqual('CONFIRMED', self.hub.deliver(restored.connection)['outcome'])
        self.admission.appoint_coordinator('human-appoint', next_run['run_id'], 3, 3, 'builder',
                                           human=self.human, ttl_seconds=30, request_budget=1)
        self.controller.revoke('builder')
        current = self.ledger.snapshot()['state']['runs'][next_run['run_id']]
        self.assertEqual(('ACTIVE', None, 'COORDINATOR_LOST'),
                         (current['status'], current['coordinator'], current['coordinator_attention']))
