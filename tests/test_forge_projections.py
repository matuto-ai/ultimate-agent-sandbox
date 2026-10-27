"""Pure disk/transaction/provider-seam proof; no native processes or live accounts."""
from copy import deepcopy
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.forge import ForgeBinding
from uas.forge_projections import (ProjectionOutbox, enqueue_run_projection,
    OWNED_LABELS, RESERVED_BYTES, validate_intent, validate_observation)
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition, _json

ORIGIN = Origin('hub-actor', 'hub', 'supervisor-one', 'epoch-one', ('forge-project',))
BINDING = ForgeBinding('room', 'project', 'owner/repo')


class Crash(BaseException):
    pass


class Provider:
    def __init__(self):
        self.labels = {'delivery:critical', 'wayfinder:task'}
        self.assignees = [41]
        self.calls = []
        self.mode = None
        self.before_observe = self.before_repair = None

    def observe(self, intent, operation_id, *, authorize):
        if authorize() is not True: raise LedgerError('FORBIDDEN')
        self.calls.append(('observe', operation_id, deepcopy(intent)))
        if self.before_observe: self.before_observe()
        if self.mode == 'read-crash': raise Crash()
        if self.mode == 'read-exception': raise OSError('private provider detail')
        unknown = self.mode == 'read-unknown'
        return {'status': 'UNKNOWN' if unknown else 'OK',
            'completeness': 'unknown' if unknown else 'complete',
            'repository': intent['repository'], 'issue_id': intent['issue_id'],
            'issue_number': intent['issue_number'],
            'labels': [] if unknown else sorted(self.labels & OWNED_LABELS),
            'assignee_ids': [] if unknown else list(self.assignees),
            'audit_reference': operation_id, 'error_code': 'FORBIDDEN' if unknown else None}

    def repair(self, intent, operation_id, observed, *, authorize):
        if self.before_repair: self.before_repair()
        if authorize() is not True: raise LedgerError('FORBIDDEN')
        self.calls.append(('repair', operation_id, deepcopy(intent)))
        extra = sorted((self.labels & OWNED_LABELS) - set(intent['labels']))
        missing = sorted(set(intent['labels']) - self.labels)
        fields = []
        if self.mode == 'rejected':
            return {'audit_reference': operation_id, 'mutation': {
                'status': 'PROVIDER_FAILURE', 'confirmed_fields': [], 'objects': [],
                'contact': 'read', 'failed_field': 'add-label', 'error_code': 'FORBIDDEN'}}
        for label in extra:
            self.labels.remove(label)
            fields.append('remove-label')
        for label in missing:
            self.labels.add(label)
            fields.append('add-label')
            if self.mode == 'partial': break
        if self.mode == 'write-crash': raise Crash()
        if self.mode == 'lost': raise OSError('lost response after provider contact')
        status = 'PARTIAL_MUTATION' if self.mode == 'partial' else 'OK'
        return {'audit_reference': operation_id, 'mutation': {
            'status': status, 'confirmed_fields': sorted(set(fields)),
            'objects': [{'kind': 'issue', 'id': intent['issue_id'], 'number': intent['issue_number']}],
            'contact': 'write-possible', 'failed_field': 'add-label' if status != 'OK' else None,
            'error_code': 'FORBIDDEN' if status != 'OK' else None}}


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'room.db'
        self.ledger = RoomLedger(self.path, 'room')
        self.addCleanup(self.ledger.close)
        self.provider = Provider()
        self.outbox = ProjectionOutbox(self.ledger, BINDING, self.provider)
        self.authorized = True
        self.seed()

    def seed(self, run='run-a', number=7):
        def decide(state, _):
            state.setdefault('runs', {})[run] = {
                'run_id': run, 'generation': 1, 'status': 'ACTIVE', 'outcome': None,
                'control_revision': 0, 'project_id': 'project', 'repository': 'owner/repo',
                'issue_id': 1000 + number, 'issue_number': number, 'github_user_id': 41,
                'policy': {'version': 1}}
            event = enqueue_run_projection(state, 'room', run)
            return Transition(state, (Event('run.activated', {'run_id': run}), event), {})
        self.ledger.apply(Command('seed-' + run, 'fixture.seed', run, None, {}), ORIGIN,
            authorize=lambda *_: True, decide=decide)

    def change(self, status, op='change', run='run-a'):
        def decide(state, _):
            state['runs'][run]['status'] = status
            event = enqueue_run_projection(state, 'room', run)
            return Transition(state, (Event('run.changed', {'status': status}),) + ((event,) if event else ()), {})
        return self.ledger.apply(Command(op, 'fixture.change', run, None, {'status': status}),
            ORIGIN, authorize=lambda *_: True, decide=decide)

    def advance(self, op='sync', run='run-a', origin=ORIGIN):
        return self.outbox.advance(op, run, origin=origin, authorize=lambda: self.authorized)

    def view(self, run='run-a'):
        return self.outbox.projection(run, origin=ORIGIN, authorize=lambda: self.authorized)

    def error(self, code, fn):
        with self.assertRaises(LedgerError) as caught: fn()
        self.assertEqual(code, caught.exception.code)

    def test_atomic_enqueue_drift_repair_exact_retry_work_labels_and_replay(self):
        self.assertEqual('pending', self.view()['state'])
        run = deepcopy(self.ledger.snapshot()['state']['runs']['run-a'])
        self.assertEqual([], self.provider.calls)
        result = self.advance()
        self.assertEqual('repaired', result['state'])
        self.assertEqual({'lifecycle:active', 'run:active', 'delivery:critical', 'wayfinder:task'}, self.provider.labels)
        self.assertEqual(result, self.advance())
        self.assertEqual(2, len(self.provider.calls))
        self.assertEqual(['forge.projection-enqueued', 'forge.projection-started',
            'forge.projection-drifted', 'forge.projection-observed'], [e['kind'] for e in
                self.ledger.replay(0) if e['kind'].startswith('forge.projection')])
        current = self.ledger.snapshot()['state']['runs']['run-a']
        self.assertEqual(run | {'projection': 'repaired'}, current)
        # External label edits are drift, not new Hub truth.
        self.provider.labels.remove('run:active'); self.provider.labels.add('run:closed')
        self.provider.labels.add('delivery:bounded')
        self.advance('repair-drift')
        self.assertIn('delivery:bounded', self.provider.labels)
        self.assertNotIn('run:closed', self.provider.labels)
        self.assertEqual('ACTIVE', current['status'])

    def test_lost_provider_response_reconciles_before_any_new_mutation(self):
        self.provider.mode = 'lost'
        result = self.advance()
        self.assertEqual('unknown', result['state'])
        self.assertIsNotNone(result['unresolved_operation'])
        self.assertEqual(result, self.advance())
        self.assertEqual(2, len(self.provider.calls))
        self.provider.mode = None
        result = self.advance('fresh-observation')
        self.assertEqual('repaired', result['state'])
        self.assertEqual('observed-only', result['attribution'])
        self.assertIsNone(result['unresolved_operation'])
        self.assertEqual(['observe', 'repair', 'observe'], [r[0] for r in self.provider.calls])
        self.assertIsNotNone(self.provider.calls[-1][2]['reconcile_operation'])

    def test_partial_needs_fresh_read_and_repairs_only_missing_labels(self):
        self.provider.mode = 'partial'
        result = self.advance()
        self.assertEqual('partial', result['state'])
        self.assertEqual(['lifecycle:active'], sorted(self.provider.labels & OWNED_LABELS))
        self.assertEqual(['add-label'], result['last_result']['receipt']['mutation']['confirmed_fields'])
        self.provider.mode = None
        self.assertEqual('repaired', self.advance('after-partial')['state'])
        self.assertEqual(['observe', 'repair', 'observe', 'repair'], [r[0] for r in self.provider.calls])

    def test_read_failure_is_not_absence_and_provider_failure_does_not_change_run(self):
        for mode in ('read-unknown', 'read-exception'):
            self.provider.mode = mode
            result = self.advance(mode)
            self.assertEqual('unknown', result['state'])
            self.assertNotIn('private provider detail', _json(result))
            self.assertFalse(any(call[0] == 'repair' for call in self.provider.calls))
        self.provider.mode = 'rejected'
        self.assertEqual('failed', self.advance('rejected')['state'])
        self.assertEqual('ACTIVE', self.ledger.snapshot()['state']['runs']['run-a']['status'])

    def test_assignment_conflict_is_visible_and_never_overwritten(self):
        self.provider.assignees = [41, 55]
        result = self.advance()
        self.assertEqual('failed', result['state'])
        self.assertEqual('ASSIGNMENT_CONFLICT', result['reason'])
        self.assertEqual([41, 55], result['observed']['assignee_ids'])
        self.assertEqual(['observe'], [r[0] for r in self.provider.calls])
        self.assertEqual({'delivery:critical', 'wayfinder:task'}, self.provider.labels)

    def test_interrupted_read_and_send_require_positive_owner_fence(self):
        for mode in ('read-crash', 'write-crash'):
            with self.subTest(mode=mode):
                self.provider.mode = mode
                with self.assertRaises(Crash): self.advance(mode)
                self.assertEqual('unknown', self.advance(mode)['state'])
                self.error('PROJECTION_IN_FLIGHT', lambda: self.advance(mode + '-blocked'))
                before = self.ledger.snapshot()
                self.error('PROJECTION_OWNER_NOT_FENCED', lambda: self.outbox.recover(
                    mode + '-recover', 'run-a', origin=ORIGIN, authorize=lambda: True, fenced=lambda _: False))
                self.assertEqual(before, self.ledger.snapshot())
                recovered = self.outbox.recover(mode + '-recover', 'run-a', origin=ORIGIN,
                    authorize=lambda: True, fenced=lambda _: True)
                self.assertEqual('unknown', recovered['state'])
                self.provider.mode = None
                self.assertEqual('repaired', self.advance(mode + '-reconcile')['state'])
                # Force a different desired label set for the second iteration.
                if mode == 'read-crash': self.change('PAUSED')
        self.assertEqual(2, sum(call[0] == 'repair' for call in self.provider.calls))

    def test_commit_before_send_loss_recovers_without_provider_contact(self):
        original = self.ledger._commit
        def committed_then_lost():
            original(); raise LedgerError('STORAGE_ERROR')
        with patch.object(self.ledger, '_commit', committed_then_lost):
            self.error('STORAGE_ERROR', self.advance)
        self.assertEqual([], self.provider.calls)
        self.assertEqual('unknown', self.advance()['state'])
        self.ledger.close()
        self.ledger = RoomLedger(self.path, 'room'); self.addCleanup(self.ledger.close)
        self.outbox = ProjectionOutbox(self.ledger, BINDING, self.provider)
        self.outbox.recover('recovered', 'run-a', origin=ORIGIN, authorize=lambda: True, fenced=lambda _: True)
        self.assertEqual('repaired', self.advance('resume')['state'])

    def test_precommit_failure_is_atomic_and_no_provider_contact(self):
        before = self.ledger.snapshot()
        with patch.object(self.ledger, '_commit', side_effect=sqlite3.OperationalError('disk unavailable')):
            self.error('STORAGE_ERROR', self.advance)
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.provider.calls)
        self.assertEqual('repaired', self.advance()['state'])

    def test_source_change_during_observe_or_before_write_fences_stale_intent(self):
        self.provider.before_observe = lambda: self.change('PAUSED')
        result = self.advance()
        self.assertEqual('pending', result['state'])
        self.assertEqual(['observe'], [r[0] for r in self.provider.calls])
        self.provider.before_observe = None
        self.assertEqual('repaired', self.advance('new-version')['state'])
        self.assertEqual({'lifecycle:attention', 'run:paused'}, self.provider.labels & OWNED_LABELS)
        self.change('ACTIVE', 'resume')
        self.provider.before_repair = lambda: self.change('PAUSED', 'pause-again')
        self.assertEqual('pending', self.advance('revoked-before-repair')['state'])
        self.assertEqual('PAUSED', self.ledger.snapshot()['state']['runs']['run-a']['status'])

    def test_repeated_sync_constant_projection_budget_and_historical_exact_receipts(self):
        result = self.advance()
        first_size = len(_json(self.ledger.snapshot()['state']['forge_projections']['run-a']).encode())
        for index in range(30): self.advance('observe-' + str(index))
        final = self.ledger.snapshot()['state']['forge_projections']['run-a']
        self.assertEqual(first_size, len(_json(final).encode()))
        self.assertLess(first_size, RESERVED_BYTES + 100)
        self.assertEqual(result, self.advance())
        self.assertEqual(1, sum(c[0] == 'repair' for c in self.provider.calls))

    def test_authority_exact_origin_and_cross_run_operation_conflicts(self):
        self.error('FORBIDDEN', lambda: self.advance(origin=replace(ORIGIN, capabilities=('forge-write',))))
        self.authorized = False
        self.error('FORBIDDEN', self.advance)
        self.authorized = True
        self.advance()
        self.error('ID_CONFLICT', lambda: self.advance(origin=replace(ORIGIN, actor_id='other')))
        self.seed('run-b', 8)
        self.error('ID_CONFLICT', lambda: self.advance(run='run-b'))
        self.assertEqual(2, len(self.provider.calls))

    def test_closed_source_projection_removes_lifecycle_only_without_creating_completion(self):
        self.advance()
        self.change('CLOSED')
        result = self.advance('closed')
        self.assertEqual('repaired', result['state'])
        self.assertEqual({'run:closed', 'delivery:critical', 'wayfinder:task'}, self.provider.labels)
        # A trusted fixture supplied CLOSED. Projecting it did not author a
        # completed outcome, forge merge evidence, or create a new Run.
        run = self.ledger.snapshot()['state']['runs']['run-a']
        self.assertIsNone(run['outcome'])
        self.assertEqual(1, len(self.ledger.snapshot()['state']['runs']))

    def test_duplicate_reservation_race_contacts_only_from_transaction_creator(self):
        original = self.advance()
        before = deepcopy(self.provider.calls)
        # Simulate a stale pre-lock duplicate lookup; the ledger transaction is
        # still definitive and must not execute the provider from its old receipt.
        with patch.object(self.ledger, 'exact_receipt', return_value=None):
            self.assertEqual(original, self.advance())
        self.assertEqual(before, self.provider.calls)

    def test_terminal_commit_failure_after_success_requires_readside_recovery(self):
        commit = self.ledger._commit
        count = 0
        def fail_terminal():
            nonlocal count
            count += 1
            if count == 3: raise sqlite3.OperationalError('disk failure')
            commit()
        with patch.object(self.ledger, '_commit', fail_terminal):
            self.error('STORAGE_ERROR', self.advance)
        self.assertEqual('unknown', self.advance()['state'])
        self.outbox.recover('recover-terminal', 'run-a', origin=ORIGIN,
            authorize=lambda: True, fenced=lambda _: True)
        self.assertEqual('repaired', self.advance('reconcile-terminal')['state'])
        self.assertEqual(['observe', 'repair', 'observe'], [r[0] for r in self.provider.calls])

    def test_newer_intent_keeps_unresolved_send_and_reconciles_before_repair(self):
        self.provider.mode = 'lost'
        first = self.advance()
        self.change('PAUSED')
        self.assertEqual(first['unresolved_operation'], self.view()['unresolved_operation'])
        self.provider.mode = None
        self.assertEqual('repaired', self.advance('sync-paused')['state'])
        self.assertEqual(first['unresolved_operation'], self.provider.calls[2][2]['reconcile_operation'])
        self.assertEqual({'lifecycle:attention', 'run:paused'}, self.provider.labels & OWNED_LABELS)
        self.assertEqual('PAUSED', self.ledger.snapshot()['state']['runs']['run-a']['status'])

    def test_invalid_observation_and_wrong_mutation_target_never_claim_success(self):
        original = self.provider.observe
        def changed(*args, **kwargs):
            result = original(*args, **kwargs); result['issue_id'] += 1; return result
        self.provider.observe = changed
        self.assertEqual('unknown', self.advance()['state'])
        self.assertFalse(any(c[0] == 'repair' for c in self.provider.calls))
        self.provider.observe = original
        repair = self.provider.repair
        def wrong(*args, **kwargs):
            result = repair(*args, **kwargs); result['mutation']['objects'][0]['id'] += 1; return result
        self.provider.repair = wrong
        result = self.advance('wrong-receipt')
        self.assertEqual('unknown', result['state'])
        self.assertIsNotNone(result['unresolved_operation'])


class CanonicalProjectionHookTests(unittest.TestCase):
    def setUp(self):
        from uas.peer import FixtureParticipant, FixturePeerHub
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = RoomLedger(self.root / 'room.db', 'room')
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('alice', 'actor-a'),
            FixtureParticipant('bob', 'actor-b')), 'run-a')
        def seed(state, _):
            state['runs'] = {'run-a': {'run_id': 'run-a', 'generation': 1,
                'status': 'ACTIVE', 'outcome': None, 'control_revision': 0,
                'project_id': 'project', 'repository': 'owner/repo',
                'issue_id': 1007, 'issue_number': 7, 'github_user_id': 41}}
            event = enqueue_run_projection(state, 'room', 'run-a')
            return Transition(state, (event,), {})
        self.ledger.apply(Command('seed', 'fixture.seed', 'run-a', None, {}), ORIGIN,
            authorize=lambda *_: True, decide=seed)

    def row(self):
        return self.ledger.snapshot()['state']['forge_projections']['run-a']

    def test_shared_peer_capacity_preserves_existing_projection_completion_and_controls(self):
        from uas.fixture_peer import FixtureReceiver
        from uas.peer import WorkRequest
        from uas.run_admission import RunAdmission
        receiver = FixtureReceiver(self.root / 'alice.db', 'room', 'alice', 'alice-1')
        self.addCleanup(receiver.close)
        alice = self.hub.connect('attach-alice', 'alice', 'alice-1', receiver)
        count = 0
        for index in range(100):
            try:
                self.hub.submit(alice, WorkRequest('bulk-' + str(index), 'run-a', 1, 'bob', 'x' * 16384))
                count += 1
            except LedgerError as error:
                self.assertEqual('QUEUE_CAPACITY_EXHAUSTED', error.code)
                break
        else: self.fail('expected bounded shared capacity')
        self.assertGreater(count, 0)
        admission = RunAdmission.__new__(RunAdmission)
        admission.supervisor = SimpleNamespace(_locked=nullcontext)
        admission.ledger = self.ledger; admission.authorize_human = lambda *_: True
        human = replace(ORIGIN, capabilities=('human-control-run',))
        admission.pause('pause', 'run-a', 1, 0, 'hold', human=human)
        outbox = ProjectionOutbox(self.ledger, BINDING, Provider())
        self.assertEqual('repaired', outbox.advance('sync', 'run-a', origin=ORIGIN,
            authorize=lambda: True)['state'])
        admission.resume('resume', 'run-a', 1, 1, 'continue', human=human)
        self.assertEqual('repaired', outbox.advance('sync-resume', 'run-a', origin=ORIGIN,
            authorize=lambda: True)['state'])
        state = self.ledger.snapshot()['state']
        self.hub._reserve_capacity(state)
        self.assertTrue(all(r['status'] == 'QUEUED' for r in state['peer_traffic']['traffic'].values()))

    def test_actual_pause_resume_owner_enqueues_in_same_transaction_and_retry_is_noop(self):
        from uas.run_admission import RunAdmission
        admission = RunAdmission.__new__(RunAdmission)
        admission.supervisor = SimpleNamespace(_locked=nullcontext)
        admission.ledger = self.ledger
        admission.authorize_human = lambda *_: True
        human = replace(ORIGIN, capabilities=('human-control-run',))
        result = admission.pause('pause', 'run-a', 1, 0, 'human-hold', human=human)
        self.assertEqual(['lifecycle:attention', 'run:paused'], self.row()['desired']['labels'])
        sequence = self.ledger.snapshot()['room_seq']
        self.assertEqual(result, admission.pause('pause', 'run-a', 1, 0, 'human-hold', human=human))
        self.assertEqual(sequence, self.ledger.snapshot()['room_seq'])
        events = self.ledger.replay(sequence - 2)
        self.assertEqual(['run.paused', 'forge.projection-enqueued'], [e['kind'] for e in events])
        admission.resume('resume', 'run-a', 1, 1, 'continue', human=human)
        self.assertEqual(['lifecycle:active', 'run:active'], self.row()['desired']['labels'])
        before = self.ledger.snapshot()
        with patch.object(self.ledger, '_commit', side_effect=sqlite3.OperationalError('disk')):
            with self.assertRaisesRegex(LedgerError, 'STORAGE_ERROR'):
                admission.pause('rolled-back', 'run-a', 1, 2, 'hold', human=human)
        self.assertEqual(before, self.ledger.snapshot())

    def test_real_peer_block_unblock_cancel_change_only_derived_projection(self):
        from uas.fixture_peer import FixtureReceiver
        from uas.peer import WorkRequest, RequestCommand, Readiness
        connections = []
        for name in ('alice', 'bob'):
            receiver = FixtureReceiver(self.root / (name + '.db'), 'room', name, name + '-1')
            self.addCleanup(receiver.close)
            connections.append(self.hub.connect('attach-' + name, name, name + '-1', receiver))
        alice, bob = connections
        self.hub.submit(alice, WorkRequest('work', 'run-a', 1, 'bob', 'Inspect this work'))
        self.hub.observe(bob, Readiness.SAFE)
        self.hub.deliver(bob)
        self.hub.submit(bob, RequestCommand('block', 'run-a', 1, 'work', 'block', 'dependency'))
        self.assertEqual(['lifecycle:blocked', 'run:active'], self.row()['desired']['labels'])
        self.hub.submit(bob, RequestCommand('accept', 'run-a', 1, 'work', 'accept', None))
        self.assertEqual(['lifecycle:active', 'run:active'], self.row()['desired']['labels'])
        self.hub.submit(bob, RequestCommand('block-again', 'run-a', 1, 'work', 'block', 'dependency'))
        self.hub.cancel('cancel', 'work', 'human cancellation')
        self.assertEqual(['lifecycle:active', 'run:active'], self.row()['desired']['labels'])
        self.assertEqual('ACTIVE', self.ledger.snapshot()['state']['runs']['run-a']['status'])
        self.assertEqual(5, self.row()['desired']['version'])


if __name__ == '__main__': unittest.main()
