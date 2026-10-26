"""Actual official Pi, process-owned socketpair, audit and canonical admission.

Only controlled account-free provider responses; never live GitHub mutations.
"""
from dataclasses import replace
import io
import json
import os
import unittest

import test_pi_forge as forge_harness
import test_pi_run_admission as admission_harness
from uas.forge_assignment import AssignmentBroker
from uas.forge_audit import ForgeAudit
from uas.github_assignment import GitHubAssignmentProvider
from uas.github_read import GitHubProject, ProviderResponse
from uas.run_admission import RunAdmission

INSTALL = os.environ.get('UAS_PI_INSTALL')


@unittest.skipUnless(INSTALL, 'Set UAS_PI_INSTALL for actual Pi assignment integration')
class PiAssignmentTests(unittest.TestCase):
    recipe = forge_harness.PiForgeTests.recipe
    start = forge_harness.PiForgeTests.start
    tearDown = forge_harness.PiForgeTests.tearDown
    receive = forge_harness.PiForgeTests.receive
    idle = forge_harness.PiForgeTests.idle
    issue = forge_harness.PiForgeTests.issue
    transport = forge_harness.PiForgeTests.transport
    select_provider = forge_harness.PiForgeTests.select_provider
    invoke = forge_harness.PiForgeTests.invoke

    def setUp(self):
        forge_harness.PiForgeTests.setUp(self)
        self.seat = replace(self.seat, capabilities=('peer-traffic', 'forge-read', 'forge-write'))
        self.assignment_ids, self.write_calls = [], []
        self.audit = ForgeAudit(self.root / 'deployment-forge.db', 'deployment')
        self.addCleanup(self.audit.close)
        self.assignment_provider = GitHubAssignmentProvider(GitHubProject('owner/repo'), self.write_transport)
        self.broker.assignments = AssignmentBroker(self.broker.binding, self.audit, {'actor-p': 41},
                                                   lambda _: self.assignment_provider)

    def write_transport(self, method, path, body):
        self.write_calls.append((method, path))
        if path == 'user':
            value = {'id': 41, 'login': 'actor-p'}
        else:
            if method == 'POST':
                self.assignment_ids = [41]
            value = self.issue(66)
            value['assignees'] = [{'id': i, 'login': 'actor-p'} for i in self.assignment_ids]
        return ProviderResponse(201 if method == 'POST' else 200, json.dumps(value).encode(), {})

    def test_actual_pi_native_self_assignment_has_exact_process_audit_and_no_replay(self):
        handle = self.start()
        args = ['issue', 'edit', '66', '--add-assignee', '@me']
        first = self.invoke('assign-native', args)
        self.assertTrue(first['ok'])
        self.assertEqual('ASSIGNED', first['receipt']['assignment']['status'])
        self.assertEqual(first['receipt'], self.invoke('assign-native', args)['receipt'])
        self.assertEqual(1, sum(method == 'POST' for method, _ in self.write_calls))
        record = self.audit.get(first['receipt']['audit_reference'])
        self.assertEqual(handle.badge.origin().incarnation_id, record['metadata']['incarnation_id'])
        self.assertEqual('actor-p', record['metadata']['actor_id'])
        self.assertEqual(1066, record['issue_id'])
        self.assertTrue(any(e.get('type') == 'tool_execution_start' and e.get('toolName') == 'gh'
                            for e in self.native.event_snapshot()))

    def test_native_read_capability_does_not_authorize_assignment(self):
        self.seat = replace(self.seat, capabilities=('peer-traffic', 'forge-read'))
        self.start()
        result = self.invoke('forbidden-assignment', ['issue', 'edit', '66', '--add-assignee', '@me'])
        self.assertFalse(result['ok'])
        self.assertEqual('FORBIDDEN', result['error'])
        self.assertEqual([], self.write_calls)


@unittest.skipUnless(INSTALL, 'Set UAS_PI_INSTALL for actual assignment admission')
class AssignmentAdmissionTests(unittest.TestCase):
    git = admission_harness.RunAdmissionTests.git
    reopen_supervisor = admission_harness.RunAdmissionTests.reopen_supervisor
    reopen = admission_harness.RunAdmissionTests.reopen
    issue = admission_harness.RunAdmissionTests.issue
    transport = admission_harness.RunAdmissionTests.transport
    capture_evidence = admission_harness.RunAdmissionTests.capture_evidence
    open = admission_harness.RunAdmissionTests.open
    error = admission_harness.RunAdmissionTests.error

    def setUp(self):
        admission_harness.RunAdmissionTests.setUp(self)
        self.assignment = []
        self.seat = replace(self.seat, capabilities=self.seat.capabilities + ('forge-write',))
        self.audit = ForgeAudit(self.root / 'deployment-forge.db', self.config['deployment']['id'])
        self.addCleanup(self.audit.close)
        self.lost, self.conflict, self.post_calls = False, False, 0
        self.assignment_provider = GitHubAssignmentProvider(GitHubProject('example/alpha'), self.write_transport)
        self.broker.assignments = AssignmentBroker(self.broker.binding, self.audit, {'alice': 41},
                                                   lambda _: self.assignment_provider)
        self.admission = RunAdmission(self.controller, self.broker, self.allocator,
            io.StringIO(json.dumps(self.config)), seats={'builder': self.seat}, install=INSTALL,
            runtime_root=self.root / 'native', authorize_human=lambda *_: self.authorized)

    def write_transport(self, method, path, body):
        if path == 'user':
            value = {'id': 41, 'login': 'actor-41'}
        else:
            if method == 'POST':
                self.post_calls += 1
                self.assignment = [41, 99] if self.conflict else [41]
                if self.lost:
                    raise TimeoutError()
            value = self.issue(1)
        return ProviderResponse(201 if method == 'POST' else 200, json.dumps(value).encode(), {})

    def test_unassigned_issue_becomes_one_canonical_run_and_delivered_request(self):
        row = self.open()
        self.assertEqual('ACTIVE', row['status'])
        self.assertEqual([41], self.assignment)
        self.assertEqual(1, self.post_calls)
        handle = self.controller.handles['builder']
        self.assertEqual('CONFIRMED', self.hub.deliver(handle.connection)['outcome'])
        self.assertEqual(row, self.open())
        self.assertEqual(1, self.post_calls)
        self.assertEqual(1, len(self.hub._state()['traffic']))

    def test_lost_reply_holds_then_explicit_read_reconciliation_admits_without_post(self):
        self.lost = True
        self.error('ASSIGNMENT_UNKNOWN', self.open)
        self.assertEqual({}, self.ledger.snapshot()['state']['runs'])
        self.error('ASSIGNMENT_UNKNOWN', self.open)
        row = self.open(attempt='explicit-human-refresh')
        self.assertEqual('ACTIVE', row['status'])
        self.assertEqual(1, self.post_calls)
        audit = self.audit.get(self.broker.assignments._key('admit-assignment-' + row['run_id']))
        self.assertEqual('UNKNOWN_OUTCOME', audit['result']['status'])
        self.assertEqual('MATCHED', audit['reconciliations'][0]['observation']['status'])
        self.assertEqual('observed-only', audit['reconciliations'][0]['observation']['attribution'])

    def test_external_conflict_holds_without_overwriting_or_consuming_human_authority(self):
        self.conflict = True
        self.error('ASSIGNMENT_UNKNOWN', self.open)
        self.error('ASSIGNMENT_CONFLICT', lambda: self.open(attempt='explicit-conflict-read'))
        state = self.ledger.snapshot()['state']
        self.assertEqual({}, state['runs'])
        self.assertEqual([41, 99], self.assignment)
        self.assertEqual(1, self.post_calls)
        self.assertFalse(next(iter(state['run_admissions'].values()))['authorization_consumed'])
