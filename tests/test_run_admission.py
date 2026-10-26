"""Non-native admission refusals and competing durable reservations.

Actual Git fixtures exist, but every refusal is before allocator mutation or Pi
launch. Native integration lives separately in test_pi_run_admission.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from dataclasses import replace
import io
import json
import threading
import unittest
from unittest.mock import patch

import test_pi_run_admission as harness
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.run_admission import RunAdmission


class RunAdmissionRefusalTests(unittest.TestCase):
    setUp = harness.RunAdmissionTests.setUp
    capture_evidence = harness.RunAdmissionTests.capture_evidence
    git = harness.RunAdmissionTests.git
    reopen_supervisor = harness.RunAdmissionTests.reopen_supervisor
    reopen = harness.RunAdmissionTests.reopen
    issue = harness.RunAdmissionTests.issue
    transport = harness.RunAdmissionTests.transport
    open = harness.RunAdmissionTests.open
    error = harness.RunAdmissionTests.error

    def construct(self, config=None, seat=None):
        return RunAdmission(self.controller, self.broker, self.allocator,
            io.StringIO(json.dumps(config or self.config)), seats={'builder': seat or self.seat},
            install=None, runtime_root=self.root / 'native',
            authorize_human=lambda *_: self.authorized)

    def test_incomplete_gate_policy_refused_before_any_provider_git_or_native_effect(self):
        from uas.config import ConfigError
        config = deepcopy(self.config)
        del config['rooms'][0]['policies'][0]['gates'][0]['evaluator']
        before = self.ledger.snapshot()
        with patch.object(self.allocator, 'allocate', side_effect=AssertionError('no Git mutation')):
            with patch.object(self.controller, 'launch_pi', side_effect=AssertionError('no native launch')):
                with self.assertRaises(ConfigError) as caught:
                    self.construct(config=config)
        self.assertTrue(caught.exception.field.endswith('.evaluator'))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.calls)
        self.assertEqual([], self.allocator.status())
        self.assertEqual({}, self.controller.handles)

    def test_compiled_policy_snapshot_is_stable_across_exact_retry_and_config_change(self):
        first = self.admission._prepare('policy-snapshot', 1, 'builder', self.human)
        before = self.ledger.snapshot()
        row = next(iter(before['state']['run_admissions'].values()))
        gate = row['policy']['gates'][0]
        self.assertEqual('exact-head-tree', gate['scope'])
        self.assertEqual('dependency-changes', gate['freshness'])
        self.assertEqual(['complete', 'submit-for-review'], gate['guarded_operations'])
        changed = deepcopy(self.config)
        policy = changed['rooms'][0]['policies'][0]
        policy['version'] += 1
        policy['gates'][0]['config']['items'][0]['path'] = 'different.txt'
        admission = self.construct(config=changed)
        self.assertEqual(first, admission._prepare('policy-snapshot', 1, 'builder', self.human))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.calls)
        self.assertEqual([], self.allocator.status())

    def test_assignment_audit_requires_configured_deployment_before_any_effect(self):
        from uas.forge_assignment import AssignmentBroker
        from uas.forge_audit import ForgeAudit
        before = self.ledger.snapshot()
        def no_provider(_):
            raise AssertionError('no provider selection')
        with ForgeAudit(self.root / 'wrong-deployment.db', 'wrong-deployment') as audit:
            self.broker.assignments = AssignmentBroker(self.broker.binding, audit, {'alice': 41}, no_provider)
            with patch.object(self.allocator, 'allocate', side_effect=AssertionError('no Git mutation')):
                with patch.object(self.controller, 'launch_pi', side_effect=AssertionError('no native launch')):
                    self.error('ADMISSION_BINDING_MISMATCH', self.construct)
            self.assertEqual([], audit.pending('alpha'))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.calls)
        self.assertEqual({}, self.controller.handles)
        self.assertEqual([], self.allocator.status())
        # Standalone broker fixtures choose their own trusted Deployment store;
        # canonical admission additionally binds it to installation configuration.
        with ForgeAudit(self.root / 'right-deployment.db', self.config['deployment']['id']) as audit:
            self.broker.assignments = AssignmentBroker(self.broker.binding, audit, {'alice': 41}, no_provider)
            self.construct()
            self.assertEqual([], audit.pending('alpha'))
        self.assertEqual(before, self.ledger.snapshot())

    def test_refused_human_authority_preserves_state_and_never_calls_git_or_pi(self):
        before = self.ledger.snapshot()
        with patch.object(self.allocator, 'allocate', side_effect=AssertionError('no Git mutation')):
            with patch.object(self.controller, 'launch_pi', side_effect=AssertionError('no native launch')):
                self.authorized = False
                self.error('FORBIDDEN', self.open)
                self.authorized = True
                origin = Origin('operator', 'human', 'manager-session', 'human-v1', ())
                self.error('FORBIDDEN', lambda: self.admission.open('no-capability', 1, 'builder', human=origin))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.calls)

    def test_exact_issue_only_no_selectors_batch_or_unknown_participant(self):
        before = self.ledger.snapshot()
        for number in (True, 0, -1, 10_000_000_000, '1', '*', 'label:ready', [1], None):
            with self.subTest(number=number):
                self.error('INVALID_RUN_REQUEST', lambda: self.admission.open('bad-number', number, 'builder', human=self.human))
        self.error('INVALID_RUN_REQUEST', lambda: self.admission.open('bad-participant', 1, 'outsider', human=self.human))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.allocator.status())
        self.assertEqual([], self.calls)

    def test_operation_conflict_and_exact_retry_precede_capacity_checks(self):
        result = self.admission._prepare('reserved', 1, 'builder', self.human)
        before = self.ledger.snapshot()
        self.assertEqual(result, self.admission._prepare('reserved', 1, 'builder', self.human))
        self.assertEqual(before, self.ledger.snapshot())
        self.error('ID_CONFLICT', lambda: self.admission._prepare('reserved', 2, 'builder', self.human))
        self.error('RUN_CAPACITY_OR_DUPLICATE', lambda: self.admission._prepare('another', 1, 'builder', self.human))
        self.error('RUN_CAPACITY_OR_DUPLICATE', lambda: self.admission._prepare('retarget', 2, 'builder', self.human))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.allocator.status())
        row = next(iter(before['state']['run_admissions'].values()))
        self.assertFalse(row['authorization_consumed'])
        self.assertEqual({}, before['state']['runs'])
        self.assertEqual({}, self.hub._state()['traffic'])

    def test_configured_profile_and_implementation_capability_are_required(self):
        for seat in (replace(self.seat, profile_id='not-configured'),
                     replace(self.seat, capabilities=('peer-traffic', 'forge-read')),
                     replace(self.seat, capabilities=self.seat.capabilities + ('undeclared',))):
            self.error('ADMISSION_BINDING_MISMATCH', lambda: self.construct(seat=seat))
        config = deepcopy(self.config)
        profile = next(p for p in config['rooms'][0]['profiles'] if p['id'] == self.seat.profile_id)
        profile['capabilities'].remove('implement')
        self.error('ADMISSION_BINDING_MISMATCH', lambda: self.construct(config=config))
        self.assertEqual([], self.allocator.status())

    def test_unknown_github_mapping_does_not_consume_authority_or_allocate(self):
        config = deepcopy(self.config)
        del config['deployment']['actors'][0]['github_user_id']
        admission = self.construct(config=config)
        before = self.ledger.snapshot()
        self.error('GITHUB_ACTOR_ID_UNKNOWN', lambda: admission.open('unknown-id', 1, 'builder', human=self.human))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.allocator.status())

    def test_valid_but_oversize_policy_is_refused_before_reservation_or_git(self):
        config = deepcopy(self.config)
        policy = config['rooms'][0]['policies'][0]
        template = deepcopy(policy['gates'][0])
        policy['gates'] = [dict(deepcopy(template), id='gate-' + str(i) + '-' + 'x' * 50) for i in range(300)]
        policy['protected_operations'] = {op: [gate['id'] for gate in policy['gates']]
                                           for op in ('submit-for-review', 'complete')}
        admission = self.construct(config=config)  # Config itself remains valid.
        before = self.ledger.snapshot()
        with patch.object(self.allocator, 'allocate', side_effect=AssertionError('no Git')):
            self.error('INVALID_PAYLOAD', lambda: admission.open('large-policy', 1, 'builder', human=self.human))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.calls)

    def test_joint_room_projection_capacity_refusal_has_no_partial_admission(self):
        def fill(state, command):
            state['other_owner'] = 'x' * 900_000
            return Transition(state, (Event('fixture.capacity-filled', {}),), {})
        self.ledger.apply(Command('fill', 'fixture.capacity', 'alpha', None, {}), self.human,
                          authorize=lambda *_: True, decide=fill)
        before = self.ledger.snapshot()
        with patch.object(self.allocator, 'allocate', side_effect=AssertionError('no Git')):
            self.error('QUEUE_CAPACITY_EXHAUSTED', self.open)
        self.assertEqual(before, self.ledger.snapshot())
        self.assertNotIn('run_admissions', before['state'])
        self.assertEqual({}, before['state']['peer_traffic']['traffic'])
        self.assertEqual([], self.allocator.status())

    def test_context_table_bound_is_preserved_before_git_effects(self):
        from uas.context import FixtureRun
        for index in range(63):
            self.hub.contexts.open_run('fixture-open-' + str(index), FixtureRun('fixture-' + str(index)))
        before = self.ledger.snapshot()
        self.assertEqual(64, len(before['state']['fixture_context']['runs']))
        with patch.object(self.allocator, 'allocate', side_effect=AssertionError('no Git')):
            self.error('RUN_CONTEXT_CAPACITY', self.open)
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual([], self.allocator.status())

    def test_funded_read_restart_abandonment_refunds_exact_admission_budget(self):
        run, _ = self.admission._prepare('funded', 1, 'builder', self.human)
        origin = Origin('alice', 'builder', 'synthetic-process', 'fixture-authority', ('forge-read',))
        before = len(self.admission._pending(run)['reservation'])
        intent = self.broker.prepare({'id': 'funded-read', 'kind': 'forge-read',
            'argv': ['issue', 'view', '1']}, origin=origin, authorize=lambda: True,
            admission=True, admission_reservation=run)
        row = self.ledger.snapshot()['state']['forge_pending'][intent['key']]
        charge = row['admission_funding']['released_bytes']
        self.assertEqual(before - charge, len(self.admission._pending(run)['reservation']))
        self.assertEqual([], self.calls)
        self.broker.recover_pending(lambda _: True)
        self.assertEqual(before, len(self.admission._pending(run)['reservation']))
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])
        self.assertEqual([], self.calls)
        # Exact recovery cannot refund twice or repeat provider contact.
        snapshot = self.ledger.snapshot()
        self.broker.recover_pending(lambda _: True)
        self.assertEqual(snapshot, self.ledger.snapshot())
        self.hub._reserve_capacity(snapshot['state'])

    def test_reconstructed_pending_binding_drift_is_held_before_external_effects(self):
        self.admission._prepare('reserved-binding', 1, 'builder', self.human)
        changed_mapping = deepcopy(self.config)
        changed_mapping['deployment']['actors'][0]['github_user_id'] = 99
        changed_capability = replace(self.seat, capabilities=self.seat.capabilities + ('git-read',))
        changed_profile = deepcopy(self.config)
        changed_profile['rooms'][0]['profiles'][0]['capabilities'].remove('git-push')
        variants = [self.construct(config=changed_mapping),
                    self.construct(seat=changed_capability), self.construct(config=changed_profile)]
        with patch.object(self.allocator, 'allocate', side_effect=AssertionError('no Git')):
            with patch.object(self.controller, 'launch_pi', side_effect=AssertionError('no native launch')):
                for index, admission in enumerate(variants):
                    self.error('ACTOR_BINDING_CHANGED', lambda: admission.open('reserved-binding', 1,
                        'builder', human=self.human, attempt_id='binding-refresh-' + str(index)))
        self.assertEqual([], self.calls)
        self.assertEqual([], self.allocator.status())
        state = self.ledger.snapshot()['state']
        self.assertFalse(next(iter(state['run_admissions'].values()))['authorization_consumed'])
        self.assertEqual({}, state['runs'])
        self.assertEqual({}, state['peer_traffic']['traffic'])

    def test_concurrent_durable_reservations_have_exactly_one_winner(self):
        barrier = threading.Barrier(2)
        def reserve(operation):
            # Each caller owns a SQLite connection. Supervisor's existing lock
            # and RoomLedger transaction arbitrate, not an in-memory test mutex.
            with RoomLedger(self.root / 'room.db', 'alpha') as ledger:
                admission = copy(self.admission)
                admission.ledger = ledger
                barrier.wait(timeout=5)
                try:
                    admission._prepare(operation, 1, 'builder', self.human)
                    return 'reserved'
                except LedgerError as error:
                    return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, ['race-a', 'race-b']))
        self.assertCountEqual(['reserved', 'RUN_CAPACITY_OR_DUPLICATE'], results)
        state = self.ledger.snapshot()['state']
        self.assertEqual(1, len(state['run_admissions']))
        self.assertFalse(next(iter(state['run_admissions'].values()))['authorization_consumed'])
        self.assertEqual({}, state['runs'])
        self.assertEqual({}, state['peer_traffic']['traffic'])
        self.assertEqual([], self.allocator.status())
