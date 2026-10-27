"""Auditable pure lifecycle cases; native seams are explicit synthetic effects.

These tests never start Git, a Runtime, sockets, processes, Docker, or a kernel
fixture. Hosted fixture integration supplies those separate kinds of evidence.
"""
from copy import deepcopy
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from run_control_support import RunControlCase
from uas.context import MAX_CONTEXT_GENERATION
from uas.ledger import LedgerError


class RunLifecycleControlTests(RunControlCase):
    def test_resume_rejects_restored_owner_in_wrong_checkout_before_request(self):
        self.seed_run(status='PAUSED', native_stop={'status': 'VERIFIED', 'restored': False})
        handle = SimpleNamespace(process=SimpleNamespace(pid=999999),
            connection=SimpleNamespace(receiver=SimpleNamespace(scope=self.hub.contexts.scope('builder'))))
        self.controller.handles['builder'] = handle
        self.controller._alive = lambda _handle: True
        self.admission._authority = lambda _handle: True
        before = self.ledger.snapshot()
        def observed_path(*args):
            return Path('/synthetic-wrong-checkout') if args[0] == '/proc' else Path(*args)
        with patch('uas.run_admission.Path', observed_path):
            self.error('NATIVE_CHECKOUT_MISMATCH', lambda: self.admission.resume(
                'resume-wrong-cwd', 'run-test', 1, 0, 'resume', human=self.human))
        self.assertEqual(before, self.ledger.snapshot())

    def test_stop_rechecks_human_authority_inside_owned_revoke_lock(self):
        from uas.participant import FixtureParticipantController
        self.seed_run()
        self.controller_document['seats']['builder'] = {'incarnation_id': 'owned-child', 'pid': None}
        self.controller.handles['builder'] = SimpleNamespace(badge=SimpleNamespace(incarnation_id='owned-child'))
        def revoke(participant, **kwargs):
            self.authorized = False  # revoked after outer check, before effect lock
            return FixtureParticipantController.revoke(self.controller, participant, **kwargs)
        self.controller.revoke = revoke
        self.error('FORBIDDEN', self.stop)
        row = self.state()['runs']['run-test']
        self.assertEqual('PAUSED', row['status'])
        self.assertIsNotNone(row['control_pending'])
        self.assertNotIn('native_stop', row)

    def test_checkout_release_rechecks_exact_pending_authority_inside_allocator_lock(self):
        from uas.checkouts import CheckoutAllocator
        row = self.seed_run()
        self.admission._stop_owned = lambda *_: None
        self.allocator.status = lambda: [deepcopy(row['checkout'])]
        allocator = CheckoutAllocator.__new__(CheckoutAllocator)
        allocator._locked = lambda _action: nullcontext({'slots': {}})
        def release(run, participant, *, authorize):
            self.authorized = False  # stop succeeded, but release is no longer authorized
            return allocator.release(run, participant, authorize=authorize)
        self.allocator.release = release
        self.error('FORBIDDEN', lambda: self.admission.terminal_stop(
            'terminal', 'run-test', 1, 0, 'cancel', human=self.human))
        row = self.state()['runs']['run-test']
        self.assertEqual('PAUSED', row['status'])
        self.assertIsNotNone(row['control_pending'])
        self.assertNotIn('checkout_release', row)

    def prepare_migration(self):
        row = self.seed_run()
        self.admission.room = deepcopy(self.room)
        self.admission.room['policies'][0]['version'] += 1
        self.effects = []
        def synthetic_rebind(pending, human, command):
            state = self.state()
            current = state['runs']['run-test']
            self.assertEqual('PAUSED', current['status'])
            self.assertEqual(2, current['generation'])
            self.assertEqual(pending, current['control_pending'])
            self.assertEqual(1, state['fixture_context']['participants']['builder']['context_generation'])
            self.effects.append(('rebind', command.id))
        self.admission._rebind_generation = synthetic_rebind
        self.admission._verify_control_effect = lambda *_: None  # same synthetic native observation
        return row

    def migrate(self, operation='migrate', generation=1, revision=0):
        policy = self.admission.room['policies'][0]
        return self.admission.migrate_policy(operation, 'run-test', generation, revision,
            policy['id'], policy['version'], 'new-policy', human=self.human)

    def stop(self, operation='stop', generation=1, revision=0, terminal=False):
        method = self.admission.terminal_stop if terminal else self.admission.force_stop
        return method(operation, 'run-test', generation, revision, 'human-stopped', human=self.human)

    def test_policy_migration_fences_generation_preserves_context_and_exact_retry(self):
        original = self.prepare_migration()
        result = self.migrate()
        state = self.state()
        row = state['runs']['run-test']
        self.assertEqual(2, result['generation'])
        self.assertEqual(1, result['control_revision'])
        self.assertEqual('PAUSED', row['status'])
        self.assertEqual(2, row['policy']['version'])
        self.assertEqual(original['checkout'], row['checkout'])
        request = state['peer_traffic']['traffic'][row['implementation_request']]
        self.assertEqual(2, request['generation'])
        self.assertEqual('QUEUED', request['status'])
        self.assertIn('"version":2', request['text'])
        self.assertIsNone(row['control_pending'])
        self.assertEqual({'run_id': 'run-test', 'generation': 2},
            state['fixture_context']['participants']['builder']['bound_run'])
        self.assertEqual(1, row['context_generation'])
        self.assertEqual([('rebind', 'migrate')], self.effects)
        self.assertEqual(result, self.migrate())
        self.assertEqual([('rebind', 'migrate')], self.effects)
        self.assertEqual(state, self.state())
        self.error('STALE_RUN_GENERATION', lambda: self.admission.resume(
            'stale', 'run-test', 1, 1, 'resume', human=self.human))

    def test_failed_rebind_is_durable_paused_and_recovers_same_intent(self):
        self.prepare_migration()
        rebind = self.admission._rebind_generation
        self.admission._rebind_generation = lambda *_: (_ for _ in ()).throw(LedgerError('NATIVE_NOT_SAFE'))
        self.error('NATIVE_NOT_SAFE', self.migrate)
        row = self.state()['runs']['run-test']
        self.assertEqual(2, row['generation'])
        self.assertIsNotNone(row['control_pending'])
        self.error('RUN_CONTROL_PENDING', lambda: self.admission.resume(
            'blocked-resume', 'run-test', 2, 1, 'resume', human=self.human))
        self.admission._rebind_generation = rebind
        self.migrate()
        self.assertEqual(2, self.state()['runs']['run-test']['generation'])
        self.assertEqual(1, len(self.effects))

    def test_force_stop_cancels_stale_requests_but_preserves_unknown_delivery_evidence(self):
        self.seed_run()
        offer = {'outcome': 'UNCONFIRMED', 'delivery_id': 'delivery-old'}
        def traffic(state):
            state['peer_traffic']['traffic']['old-request'] = {
                'id': 'old-request', 'kind': 'peer.work-request', 'run_id': 'run-test',
                'generation': 1, 'sender': 'run-hub', 'actor_id': 'operator',
                'recipients': ['builder'], 'deliveries': {}, 'status': 'QUEUED',
                'text': 'implement', 'parent_id': None, 'correlation_id': 'old-request',
                'submitted_at': '2026-10-27T00:00:00+00:00', 'submitted_seq': 2,
                'response_started_at': None, 'reason': None, 'attention': None}
            state['peer_traffic']['offers']['old-request'] = {'builder': deepcopy(offer)}
        self.seed(traffic)
        effects = []
        def synthetic_stop(pending, _human, _command):
            state = self.state()
            self.assertEqual('CANCELLED', state['peer_traffic']['traffic']['old-request']['status'])
            self.assertEqual(2, state['runs']['run-test']['generation'])
            effects.append(deepcopy(pending))
        self.admission._stop_owned = synthetic_stop
        result = self.stop()
        self.assertEqual('PAUSED', result['status'])
        self.assertEqual('VERIFIED', result['native_stop']['status'])
        self.assertEqual(offer, self.state()['peer_traffic']['offers']['old-request']['builder'])
        self.assertEqual(1, len(effects))
        self.assertEqual(result, self.stop())
        self.assertEqual(1, len(effects))

    def test_terminal_stop_records_reason_successor_and_preserves_dirty_owned_checkout(self):
        row = self.seed_run()
        self.admission._stop_owned = lambda *_: None  # synthetic verified-stop observation
        self.allocator.status = lambda: [deepcopy(row['checkout'])]
        release_calls = []
        def release(run, participant, *, authorize=None):
            self.assertTrue(authorize())
            self.assertEqual('PAUSED', self.state()['runs'][run]['status'])
            release_calls.append((run, participant))
            return {**row['checkout'], 'reason': 'DIRTY_OR_UNTRACKED_OR_IGNORED', 'disposition': 'retained'}
        self.allocator.release = release
        result = self.admission.terminal_stop('terminal', 'run-test', 1, 0, 'changed-priority',
            human=self.human, successor_run='run-successor')
        current = self.state()['runs']['run-test']
        self.assertEqual('CLOSED', result['status'])
        self.assertEqual('stopped', result['outcome'])
        self.assertEqual('changed-priority', current['stop_reason'])
        self.assertEqual('run-successor', current['successor_run'])
        self.assertEqual('retained', current['checkout_release']['disposition'])
        self.assertEqual(row['checkout'], current['checkout'])
        self.assertEqual('CLOSED', self.state()['fixture_context']['runs']['run-test']['status'])
        self.assertEqual('CLOSED', self.state()['run_admissions']['run-test']['status'])
        self.assertEqual([('run-test', 'builder')], release_calls)
        self.error('INVALID_RUN_TRANSITION', lambda: self.admission.resume(
            'resume-closed', 'run-test', 2, 1, 'resume', human=self.human))

    def test_stop_failure_holds_and_new_exact_human_stop_can_supersede_uncertainty(self):
        self.prepare_migration()
        self.admission._rebind_generation = lambda *_: (_ for _ in ()).throw(LedgerError('NATIVE_NOT_SAFE'))
        self.error('NATIVE_NOT_SAFE', self.migrate)
        self.admission._stop_owned = lambda *_: (_ for _ in ()).throw(LedgerError('NATIVE_STOP_UNVERIFIED'))
        self.error('NATIVE_STOP_UNVERIFIED', lambda: self.stop('force', 2, 1))
        current = self.state()['runs']['run-test']
        self.assertEqual(3, current['generation'])
        self.assertEqual('force', current['control_pending']['operation_id'])
        self.assertNotIn('native_stop', current)
        self.error('RUN_CONTROL_CONFLICT', self.migrate)
        self.admission._stop_owned = lambda *_: None
        result = self.stop('force', 2, 1)
        self.assertEqual(3, result['generation'])
        self.assertEqual('VERIFIED', result['native_stop']['status'])

    def test_authority_stale_revision_exhaustion_and_unknown_policy_have_no_effect(self):
        self.prepare_migration()
        before = self.state()
        self.authorized = False
        self.error('FORBIDDEN', self.migrate)
        self.authorized = True
        self.error('STALE_RUN_CONTROL', lambda: self.migrate('wrong-revision', revision=2))
        self.error('UNKNOWN_RUN_POLICY', lambda: self.admission.migrate_policy(
            'unknown-policy', 'run-test', 1, 0, 'unknown', 2, 'new-policy', human=self.human))
        self.error('FORBIDDEN', lambda: self.admission.force_stop('peer-stop', 'run-test', 1, 0,
            'peer-cannot-stop', human=replace(self.human, capabilities=('can-open-requested-run',))))
        self.assertEqual(before, self.state())
        self.assertEqual([], self.effects)
        self.seed(lambda state: state['runs']['run-test'].update(generation=MAX_CONTEXT_GENERATION))
        self.error('RUN_GENERATION_EXHAUSTED', lambda: self.migrate('exhausted', MAX_CONTEXT_GENERATION))

    def test_lost_terminal_ack_reconciles_without_second_native_stop(self):
        self.seed_run()
        effects = []
        self.admission._stop_owned = lambda *_: effects.append('stop')
        commit = self.ledger._commit
        calls = []
        def commit_then_lose_final():
            commit()
            calls.append('commit')
            if len(calls) == 2:
                raise LedgerError('STORAGE_ERROR')
        with patch.object(self.ledger, '_commit', commit_then_lose_final):
            self.error('STORAGE_ERROR', self.stop)
        self.assertEqual(['stop'], effects)
        self.assertEqual('VERIFIED', self.state()['runs']['run-test']['native_stop']['status'])
        self.stop()
        self.assertEqual(['stop'], effects)

    def test_withdraw_fences_before_stop_and_retains_context_until_native_reset(self):
        run, _command = self.admission._prepare('pending-open', 1, 'builder', self.human)
        effects = []
        def synthetic_stop(_pending, _human, _command):
            self.assertEqual('WITHDRAWING', self.state()['run_admissions'][run]['status'])
            effects.append('stop')
        self.admission._stop_owned = synthetic_stop
        result = self.admission.withdraw('withdraw', run, 'different-work', human=self.human)
        state = self.state()
        self.assertEqual('CLOSED', result['status'])
        self.assertFalse(result['authorization_consumed'])
        self.assertEqual({'run_id': run, 'generation': 1},
            state['fixture_context']['participants']['builder']['reserved_run'])
        self.assertEqual('CLOSED', state['fixture_context']['runs'][run]['status'])
        self.assertEqual(result, self.admission.withdraw('withdraw', run, 'different-work', human=self.human))
        self.assertEqual(['stop'], effects)

    def test_pending_forge_read_blocks_withdraw_completion_without_abandoning_it(self):
        run, _command = self.admission._prepare('pending-open', 1, 'builder', self.human)
        # Minimal bounded pure funding record; valid owned read shape is covered
        # by the Broker tests. This transition only checks presence and ownership.
        self.seed(lambda state: state['forge_pending'].update(read={'admission_funding': {
            'run_id': run, 'released_bytes': 65536}}))
        self.admission._stop_owned = lambda *_: self.fail('pending read must settle first')
        self.error('ADMISSION_EFFECT_PENDING', lambda: self.admission.withdraw(
            'withdraw', run, 'cancel-intake', human=self.human))
        self.assertEqual('WITHDRAWING', self.state()['run_admissions'][run]['status'])
        self.assertIn('read', self.state()['forge_pending'])

    def test_owned_stop_invokes_exact_incarnation_and_rejects_replacement_after_effect(self):
        self.seed_run()
        self.controller_document['seats']['builder'] = {'incarnation_id': 'owned-child', 'pid': None}
        handle = SimpleNamespace(badge=SimpleNamespace(incarnation_id='owned-child'),
            protocol='pi', process=SimpleNamespace(poll=lambda: 0))
        self.controller.handles['builder'] = handle
        self.controller._alive = lambda candidate: False
        effects = []
        def revoke(participant, *, expected_incarnation, authorize):
            self.assertTrue(authorize())
            effects.append((participant, expected_incarnation))
            # Explicit synthetic owner replacement races stop acknowledgement.
            self.controller_document['seats']['builder']['incarnation_id'] = 'replacement'
        self.controller.revoke = revoke
        self.error('NATIVE_OWNERSHIP_CHANGED', self.stop)
        row = self.state()['runs']['run-test']
        self.assertIsNotNone(row['control_pending'])
        self.assertNotIn('native_stop', row)
        self.assertEqual([('builder', 'owned-child')], effects)
        self.controller_document['seats']['builder']['incarnation_id'] = 'owned-child'
        self.controller.revoke = lambda participant, **scope: effects.append((participant, scope['expected_incarnation']))
        self.stop()
        self.assertEqual('VERIFIED', self.state()['runs']['run-test']['native_stop']['status'])

    def test_unknown_retired_owner_blocks_without_pid_adoption_or_checkout_release(self):
        self.seed_run()
        self.controller_document['retired_pids'] = [12345]
        observed = []
        def observed_absence(pid):
            observed.append(pid)
            return False
        self.admission._absent_pid = observed_absence  # explicit synthetic absence observation
        self.error('RETIRED_PROCESSES_UNVERIFIED', lambda: self.stop(terminal=True))
        row = self.state()['runs']['run-test']
        self.assertEqual('PAUSED', row['status'])
        self.assertEqual([12345], observed)
        self.assertNotIn('checkout_release', row)

    def test_capacity_model_retains_historical_withdrawal_after_context_retarget(self):
        from uas.run_control import reserve_run_control_capacity
        run, _ = self.admission._prepare('pending-open', 1, 'builder', self.human)
        self.admission._stop_owned = lambda *_: None
        self.admission.withdraw('withdraw', run, 'cancel-intake', human=self.human)
        state = self.state()
        state['fixture_context']['participants']['builder']['reserved_run'] = {'run_id': 'later', 'generation': 1}
        reserve_run_control_capacity(state)
        self.assertEqual(['builder'], [target['participant_id']
            for target in state['run_admissions'][run]['withdrawal']['targets']])

    def test_withdraw_retarget_before_reset_preserves_preceding_scope(self):
        row = self.seed_run(status='CLOSED', native_stop={'status': 'VERIFIED', 'generation': 1})
        preceding = {'run_id': row['run_id'], 'generation': 1}
        def pending(state):
            state['run_admissions'][row['run_id']]['status'] = 'CLOSED'
            state['fixture_context']['runs'][row['run_id']]['status'] = 'CLOSED'
            state['fixture_context']['runs']['new-run'] = {'status': 'OPEN', 'generation': 1, 'terminal_fact': None}
            state['run_admissions']['new-run'] = {'status': 'PREPARING', 'participant_id': 'builder',
                'issue_number': 2, 'preceding_run': preceding, 'authorization_consumed': False,
                'reservation': 'x' * 131072}
        self.seed(pending)
        self.admission._stop_owned = lambda *_: None
        self.admission.withdraw('withdraw-new', 'new-run', 'new-plan', human=self.human)
        context = self.state()['fixture_context']['participants']['builder']
        self.assertEqual(preceding, context['bound_run'])
        self.assertEqual(1, context['context_generation'])
        self.assertEqual('CLOSED', self.state()['fixture_context']['runs']['new-run']['status'])

    def test_withdraw_failed_retarget_reset_preserves_unknown_reset_and_context_generation(self):
        row = self.seed_run()
        reset = {'id': 'reset-new', 'status': 'FAILED', 'target_run': {'run_id': 'new-run', 'generation': 1},
                 'expected_context_generation': 1, 'next_context_generation': 2}
        def pending(state):
            state['fixture_context']['participants']['builder'].update(status='UNAVAILABLE', reset=deepcopy(reset))
            state['fixture_context']['runs']['new-run'] = {'status': 'OPEN', 'generation': 1, 'terminal_fact': None}
            state['run_admissions']['new-run'] = {'status': 'PREPARING', 'participant_id': 'builder',
                'issue_number': 2, 'preceding_run': {'run_id': row['run_id'], 'generation': 1},
                'authorization_consumed': False, 'reservation': 'x' * 131072}
        self.seed(pending)
        self.admission._stop_owned = lambda *_: None
        self.admission.withdraw('withdraw-new', 'new-run', 'new-plan', human=self.human)
        context = self.state()['fixture_context']['participants']['builder']
        self.assertEqual(reset, context['reset'])
        self.assertEqual('UNAVAILABLE', context['status'])
        self.assertEqual(1, context['context_generation'])
        self.assertEqual({'run_id': row['run_id'], 'generation': 1}, context['bound_run'])

    def test_unknown_assignment_requires_existing_read_reconciliation_before_withdrawal(self):
        run, _ = self.admission._prepare('pending-open', 1, 'builder', self.human)
        record = {'result': {'status': 'UNKNOWN_OUTCOME'}, 'reconciliations': []}
        self.broker.assignments = SimpleNamespace(audit=SimpleNamespace(get=lambda _: deepcopy(record)), _key=lambda x: x)
        effects = []
        self.admission._stop_owned = lambda *_: effects.append('stop')
        self.error('ADMISSION_ASSIGNMENT_PENDING', lambda: self.admission.withdraw(
            'withdraw', run, 'cancel-intake', human=self.human))
        self.assertEqual([], effects)
        self.assertEqual('WITHDRAWING', self.state()['run_admissions'][run]['status'])
        record['reconciliations'].append({'observation': {'status': 'MATCHED'}})
        result = self.admission.withdraw('withdraw', run, 'cancel-intake', human=self.human)
        self.assertEqual('CLOSED', result['status'])
        self.assertEqual(['stop'], effects)
        self.assertEqual('UNKNOWN_OUTCOME', record['result']['status'])  # immutable causal evidence

    def test_migration_capacity_failure_rolls_back_fence_policy_and_new_request(self):
        self.prepare_migration()
        self.seed(lambda state: state.update(other_owner='x' * 900_000))
        before = self.state()
        self.error('QUEUE_CAPACITY_EXHAUSTED', self.migrate)
        self.assertEqual(before, self.state())
        self.assertEqual([], self.effects)
