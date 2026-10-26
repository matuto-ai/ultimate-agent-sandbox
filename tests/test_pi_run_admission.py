"""Real official Pi + actual Git + bounded account-free GitHub admission facts."""
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from copy import deepcopy

import test_checkouts as checkout_harness
from uas.forge import ForgeBinding, ReadOnlyForgeBroker
from uas.github_read import GitHubProject, GitHubReadProvider, ProviderResponse
from uas.ledger import LedgerError, Origin, RoomLedger
from uas.participant import FixtureCredentials, FixtureSeat
from uas.peer import FixtureParticipant, FixturePeerHub
from uas.run_admission import RunAdmission
from uas.context import FixtureRunTerminal

INSTALL = os.environ.get('UAS_PI_INSTALL')


@unittest.skipUnless(INSTALL, 'Set UAS_PI_INSTALL for actual canonical admission integration')
class RunAdmissionTests(unittest.TestCase):
    git = checkout_harness.CheckoutTests.git
    reopen_supervisor = checkout_harness.CheckoutTests.reopen_supervisor
    reopen = checkout_harness.CheckoutTests.reopen

    def setUp(self):
        checkout_harness.CheckoutTests.setUp(self)
        self.config['deployment']['actors'][0]['github_user_id'] = 41
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('builder', 'alice'),
            FixtureParticipant('reviewer', 'bob'), FixtureParticipant('other', 'other-actor')), 'bootstrap')
        self.controller = self.supervisor.participants(self.hub, FixtureCredentials())
        self.calls = []
        self.assignment, self.dependency, self.labels = [41], 'closed', ['delivery:bounded']
        self.fail_read = False
        self.provider = GitHubReadProvider(GitHubProject('example/alpha'), self.transport)
        self.broker = ReadOnlyForgeBroker(self.ledger, ForgeBinding('alpha', 'alpha', 'example/alpha'),
                                         lambda _: self.provider)
        self.controller.bind_forge(self.broker)
        self.seat = FixtureSeat('builder', 'alice', 'worker', ('peer-traffic', 'forge-read', 'implement'), runtime='pi-fixture')
        self.authorized = True
        self.human = Origin('operator', 'human', 'manager-session', 'human-v1', ('human-open-run',))
        self.admission = RunAdmission(self.controller, self.broker, self.allocator,
            io.StringIO(json.dumps(self.config)), seats={'builder': self.seat}, install=INSTALL,
            runtime_root=self.root / 'native', authorize_human=lambda *_: self.authorized)
        self.addCleanup(self.ledger.close)
        self.addCleanup(self.controller.close)
        self.addCleanup(self.capture_evidence)

    def capture_evidence(self):
        destination = os.environ.get('UAS_PI_EVIDENCE')
        handle = self.controller.handles.get('builder')
        if not destination or handle is None or handle.connection is None:
            return
        native = handle.connection.receiver
        if native._closed:
            return
        state = self.ledger.snapshot()['state']
        row = {'case': self.id(), **native.evidence(),
               'authority': 'trusted-human-source-seam-and-supervisor-owned-real-pi',
               'forge': 'controlled-account-free-responses', 'git': 'actual-local-owned-checkout',
               'runs': [{'run_id': r['run_id'], 'status': r['status'], 'issue_id': r['issue_id'],
                         'context_generation': r['context_generation'],
                         'authorization_consumed': r['authorization_consumed']}
                        for r in state.get('runs', {}).values()],
               'pending_admissions': sum(r['status'] == 'PREPARING' for r in state.get('run_admissions', {}).values()),
               'implementation_requests': len(state['peer_traffic']['traffic'])}
        with open(destination, 'a') as output:
            output.write(json.dumps(row, sort_keys=True) + '\n')

    def issue(self, n, state='open'):
        base = 'https://api.github.com/repos/example/alpha'
        return {'id': 1000+n, 'number': n, 'state': state,
                'repository_url': base, 'url': base+'/issues/'+str(n),
                'assignees': [{'id': n, 'login': 'actor-'+str(n)} for n in self.assignment]}

    def transport(self, path):
        self.calls.append(path)
        if self.fail_read:
            return ProviderResponse(403, b'{}', {})
        if '/dependencies/' in path:
            value = [self.issue(2, self.dependency)]
        elif '/labels?' in path:
            value = [{'id': i+1, 'name': name} for i, name in enumerate(self.labels)]
        else:
            value = self.issue(1)
        return ProviderResponse(200, json.dumps(value).encode(), {})

    def open(self, op='human-open', attempt=None):
        return self.admission.open(op, 1, 'builder', human=self.human, attempt_id=attempt)

    def error(self, code, action):
        with self.assertRaises(LedgerError) as raised:
            action()
        self.assertEqual(code, raised.exception.code)

    def test_actual_pi_git_human_admission_delivery_retry_and_fixture_close_denial(self):
        row = self.open()
        self.assertEqual('ACTIVE', row['status'])
        self.assertTrue(row['authorization_consumed'])
        self.assertEqual('bounded', row['delivery_class'])
        self.assertEqual('unavailable-no-write-support', row['projection'])
        self.assertEqual(str(self.repo), row['checkout']['path'])
        handle = self.controller.handles['builder']
        self.assertEqual(self.repo, Path('/proc', str(handle.process.pid), 'cwd').resolve())
        self.assertEqual('CONFIRMED', self.hub.deliver(handle.connection)['outcome'])
        traffic = self.hub._state()['traffic'][row['implementation_request']]
        self.assertEqual('DELIVERED', traffic['status'])
        self.assertIsNotNone(traffic['response_started_at'])
        before = len(self.calls)
        self.assertEqual(row, self.open())
        self.assertEqual(before, len(self.calls))
        changed = deepcopy(self.config)
        changed['deployment']['actors'][0]['github_user_id'] = 99
        changed['rooms'][0]['policies'][0]['version'] += 1
        reconstructed = RunAdmission(self.controller, self.broker, self.allocator,
            io.StringIO(json.dumps(changed)), seats={'builder': self.seat}, install=INSTALL,
            runtime_root=self.root / 'native', authorize_human=lambda *_: self.authorized)
        self.assertEqual(row, reconstructed.open('human-open', 1, 'builder', human=self.human))
        self.assertEqual(before, len(self.calls))
        self.error('CANONICAL_RUN_AUTHORITY_REQUIRED', lambda: self.hub.contexts.close_run(
            'not-proof', row['run_id'], FixtureRunTerminal.COMPLETED))
        self.assertEqual('ACTIVE', self.ledger.snapshot()['state']['runs'][row['run_id']]['status'])
        self.assertEqual(1, len(self.hub._state()['traffic']))
        self.authorized = False
        self.error('FORBIDDEN', self.open)

    def test_assignment_conflict_holds_and_explicit_retry_refreshes_without_consuming_authorization(self):
        self.assignment = [99]
        self.error('ASSIGNMENT_CONFLICT', self.open)
        state = self.ledger.snapshot()['state']
        self.assertEqual({}, state['runs'])
        self.assertEqual({}, state['peer_traffic']['traffic'])
        pending = next(iter(state['run_admissions'].values()))
        self.assertFalse(pending['authorization_consumed'])
        self.assignment = [41]
        calls = len(self.calls)
        self.error('ASSIGNMENT_CONFLICT', self.open)
        self.assertEqual(calls, len(self.calls))
        row = self.open(attempt='human-refresh')
        self.assertGreater(len(self.calls), calls)
        self.assertEqual('ACTIVE', row['status'])
        self.assertEqual(1, len(self.allocator.status()))

    def test_git_success_before_return_recovers_same_owned_slot_no_duplicate(self):
        allocate = self.allocator.allocate
        def interrupted(*args):
            allocate(*args)
            raise LedgerError('STORAGE_ERROR')
        with patch.object(self.allocator, 'allocate', interrupted):
            self.error('STORAGE_ERROR', self.open)
        self.assertEqual(1, len(self.allocator.status()))
        self.assertEqual({}, self.ledger.snapshot()['state']['runs'])
        self.assertFalse(next(iter(self.ledger.snapshot()['state']['run_admissions'].values()))['authorization_consumed'])
        self.assertEqual('ACTIVE', self.open()['status'])
        self.assertEqual(1, len(self.allocator.status()))

    def test_unknown_missing_class_and_dependency_hold_with_durable_attention(self):
        attempts = [('FORGE_FACTS_UNKNOWN', 'fail_read', True),
                    ('DELIVERY_CLASS_UNKNOWN', 'labels', []),
                    ('ASSIGNMENT_REQUIRED_NO_WRITE_SUPPORT', 'assignment', []),
                    ('DEPENDENCY_BLOCKED', 'dependency', 'open')]
        for code, field, value in attempts:
            original = getattr(self, field)
            setattr(self, field, value)
            self.error(code, lambda: self.open(attempt='check-' + field))
            state = self.ledger.snapshot()['state']
            pending = next(iter(state['run_admissions'].values()))
            self.assertEqual(code, pending['attention'])
            self.assertFalse(pending['authorization_consumed'])
            self.assertEqual({}, state['runs'])
            self.assertEqual({}, state['peer_traffic']['traffic'])
            setattr(self, field, original)
        self.assertEqual('ACTIVE', self.open(attempt='fresh-eligible')['status'])

    def test_native_exit_before_admission_relaunches_only_owned_pending_scope(self):
        self.assignment = [99]
        self.error('ASSIGNMENT_CONFLICT', self.open)
        old = self.controller.handles['builder']
        old.process.kill(); old.process.wait(timeout=3)
        self.assignment = [41]
        row = self.open(attempt='after-exit')
        new = self.controller.handles['builder']
        self.assertNotEqual(old.badge.incarnation_id, new.badge.incarnation_id)
        self.assertEqual(1, row['context_generation'])
        self.assertEqual('ACTIVE', row['status'])

    def test_activation_ack_loss_recovers_committed_run_without_another_read_or_request(self):
        commit = self.ledger._commit
        lost = [False]
        def commit_then_lose():
            active = self.ledger.snapshot()['state'].get('runs', {})
            commit()
            if active and not lost[0]:
                lost[0] = True
                raise LedgerError('STORAGE_ERROR')
        with patch.object(self.ledger, '_commit', commit_then_lose):
            recovered = self.open()
        self.assertEqual('ACTIVE', recovered['status'])
        self.assertTrue(lost[0])
        before = len(self.calls)
        row = self.open()
        self.assertEqual('ACTIVE', row['status'])
        self.assertEqual(before, len(self.calls))
        self.assertEqual(1, len(self.hub._state()['traffic']))
        self.assertEqual(1, len(self.ledger.snapshot()['state']['runs']))

    def test_late_process_revocation_abandons_read_and_exact_attempt_never_recontacts(self):
        transport = self.provider.transport
        revoked = [False]
        def revoke_after_contact(path):
            response = transport(path)
            if not revoked[0]:
                revoked[0] = True
                self.controller.revoke('builder')
            return response
        self.provider.transport = revoke_after_contact
        self.error('AUTHORITY_REVOKED', self.open)
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])
        calls = len(self.calls)
        self.error('AUTHORITY_REVOKED', self.open)
        self.assertEqual(calls, len(self.calls))
        self.provider.transport = transport
        self.assertEqual('ACTIVE', self.open(attempt='after-revocation')['status'])

    def test_successful_read_before_interruption_is_not_reused_as_fresh_activation(self):
        slot = self.admission._slot
        count = [0]
        def interrupt_after_read(*args):
            count[0] += 1
            if count[0] == 2:
                raise LedgerError('STORAGE_ERROR')
            return slot(*args)
        with patch.object(self.admission, '_slot', interrupt_after_read):
            self.error('STORAGE_ERROR', self.open)
        calls = len(self.calls)
        self.error('FORGE_FACTS_EXPIRED', self.open)
        self.assertEqual(calls, len(self.calls))
        self.assertEqual({}, self.ledger.snapshot()['state']['runs'])
        self.assertEqual('ACTIVE', self.open(attempt='fresh-after-interruption')['status'])

    def test_reserved_admission_survives_full_peer_and_context_capacity_during_provider_io(self):
        from uas.context import FixtureRun, MAX_RUNS, MAX_CONTEXT_GENERATION
        from uas.peer import WorkRequest
        run, _ = self.admission._prepare('human-open', 1, 'builder', self.human)
        sender = self.hub.connect('background-sender', 'reviewer', 'background-incarnation', object())
        for index in range(MAX_RUNS - 2):
            self.hub.contexts.open_run('wide-context-' + str(index),
                FixtureRun('r' + str(index) + 'x' * 250, MAX_CONTEXT_GENERATION))
        def saturate(prefix):
            admitted = []
            for index in range(100):
                try:
                    name = prefix + str(index)
                    self.hub.submit(sender, WorkRequest(name, 'bootstrap', 1, 'other', 'x' * 16384))
                    admitted.append(name)
                except LedgerError as error:
                    self.assertEqual('QUEUE_CAPACITY_EXHAUSTED', error.code)
                    break
            else:
                self.fail('unbounded peer capacity')
            return admitted
        retained = saturate('before-read-')
        self.assertGreater(len(retained), 1)
        full_reservation = len(self.admission._pending(run)['reservation'])
        transport = self.provider.transport
        transferred = []
        def during_read(path):
            pending = self.admission._pending(run)
            transferred.append(len(pending['reservation']) < full_reservation)
            # Even a small additional item must reserve the later refund; no
            # transient Broker-transfer padding is free for peer admissions.
            for index in range(100):
                try:
                    self.hub.submit(sender, WorkRequest('during-read-' + str(len(self.calls)) + '-' + str(index),
                        'bootstrap', 1, 'other', 'x'))
                except LedgerError as error:
                    self.assertEqual('QUEUE_CAPACITY_EXHAUSTED', error.code)
                    break
            return transport(path)
        self.provider.transport = during_read
        self.assignment = [99]
        self.error('ASSIGNMENT_CONFLICT', self.open)
        self.assertEqual(full_reservation, len(self.admission._pending(run)['reservation']))
        from uas.ledger import Command
        self.admission._attention(run, self.human, 'x' * 256,
            Command('max-attention', 'run.admission-attempt-result', run, 1, {}))
        self.assertEqual('x' * 256, self.admission._pending(run)['attention'])
        self.assignment = [41]
        row = self.open(attempt='after-saturated-conflict')
        self.assertTrue(all(transferred))
        self.assertEqual('ACTIVE', row['status'])
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])
        self.assertTrue(set(retained) <= set(self.hub._state()['traffic']))
        self.assertEqual('CONFIRMED', self.hub.deliver(self.controller.handles['builder'].connection)['outcome'])
        self.assertEqual('DELIVERED', self.hub._state()['traffic'][row['implementation_request']]['status'])
        self.hub._reserve_capacity(self.ledger.snapshot()['state'])

    def test_capacity_and_duplicate_refusal_precedes_git_and_preserves_human_authorization(self):
        self.admission._prepare('reserve-one', 1, 'builder', self.human)
        with patch.object(self.allocator, 'allocate', side_effect=AssertionError('no Git')):
            self.error('RUN_CAPACITY_OR_DUPLICATE', lambda: self.open('other-open'))
        self.assertEqual([], self.allocator.status())
        self.assertEqual({}, self.hub._state()['traffic'])
        self.assertFalse(next(iter(self.ledger.snapshot()['state']['run_admissions'].values()))['authorization_consumed'])
