"""Hub policy/lifecycle proof over a mocked private Supervisor control client.

No kernel sender, target isolation, static helper, Docker, native Runtime, or
production qualification is inferred from these deliberately synthetic facts.
"""
from copy import deepcopy
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest

from uas.artifact_protocol import PROFILE_ID, expected_header, path_digest, scope_digest
from uas.config import load
from uas.gate_policy import compile_policy
from uas.gate_evaluation import ArtifactGateHub, GateRoomBinding, SCRATCH_BYTES, PROVENANCE
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition, _json


ORIGIN = Origin('operator', 'human', 'control-session', 'authority-v1', ())


class Interrupted(BaseException):
    pass


class FakeOffer:
    """Mock trusted GATE_BIND: not a Participant/relay evidence interface."""
    def __init__(self, control, scope, target, paths):
        self.control, self.scope, self.target, self.paths = control, scope, target, paths
        self.acked, self.exited = False, False
        self.closed = False

    def document(self):
        result = {'source': 'supervisor-one-shot-helper', 'provenance': PROVENANCE,
            'profile': PROFILE_ID, 'profile_digest': 'd' * 64, 'binding_digest': 'e' * 64,
            'scope_digest': scope_digest(self.scope, self.target)}
        self.control.mutate_document(result)
        return result

    def records(self):
        self.control.effect('records')
        records = [expected_header(self.scope, self.target, self.paths)]
        for i, path in enumerate(self.paths):
            fact = {'kind': 'item', 'index': i, 'path_digest': path_digest(path),
                'observed_type': 'file', 'length': 10, 'nonempty': False, 'error': 0}
            fact.update(self.control.facts.get(path, {}))
            records.append(fact)
        records.append(expected_header(self.scope, self.target, self.paths, kind='final'))
        self.control.mutate_records(records)
        yield from records

    def acknowledge_final(self, record):
        self.control.effect('ack')
        if not self.control.alive:
            raise LedgerError('GATE_HELPER_LOST')
        assert record == expected_header(self.scope, self.target, self.paths, kind='final')
        assert self.control.hub._row(self.scope['evaluation_id'])['phase'] == 'OBSERVED'
        self.acked = True

    def confirm_exit(self):
        self.control.effect('exit')
        assert self.acked
        self.exited = self.control.exit_confirmed
        return self.exited

    def close(self):
        self.closed = True


class FakeControl:
    def __init__(self):
        self.hub = None
        self.calls = []
        self.source = {'room_instance': 'room-instance', 'project_id': 'project-alpha',
            'repository': 'example/project-alpha', 'run_id': 'run-one', 'participant_id': 'builder',
            'slot_id': 'primary', 'branch': 'refs/heads/main', 'head_sha': 'a' * 40,
            'source_digest': 'b' * 64}
        self.target = None
        self.facts = {}
        self.mutate_records = lambda _: None
        self.mutate_document = lambda _: None
        self.at = {}
        self.cleanup = True
        self.alive = True
        self.exit_confirmed = True
        self.post_mutated = False
        self.abort_cleanup = True
        self.offer = None

    def effect(self, name):
        self.calls.append(name)
        if name in self.at:
            self.at[name]()

    def resolve(self, run_id, participant_id, room_instance):
        self.effect('resolve')
        assert (run_id, participant_id, room_instance) == ('run-one', 'builder', 'room-instance')
        return deepcopy(self.source)

    def current(self, source):
        self.effect('current')
        return deepcopy(self.source)

    def prepare(self, scope, source):
        self.effect('prepare')
        row = self.hub._row(scope['evaluation_id'])
        assert row['phase'] == 'STARTED' and row['reservation']['scratch_bytes'] == SCRATCH_BYTES
        self.target = {'target_id': scope['evaluation_id'][-32:], 'head_sha': source['head_sha'], 'tree_sha': 'c' * 40,
            'manifest_sha256': 'f' * 64, 'source_digest': source['source_digest'],
            'device': 1, 'inode': 100, 'entries': 2, 'expanded_bytes': 100}
        return deepcopy(self.target)

    def start(self, scope, target, paths):
        self.effect('start')
        assert self.hub._row(scope['evaluation_id'])['phase'] == 'LAUNCH_RESERVED'
        self.offer = FakeOffer(self, scope, target, paths)
        return self.offer

    def finish(self, target, offer):
        self.effect('finish')
        assert offer is self.offer and offer.exited and offer.acked
        post = deepcopy(target)
        if self.post_mutated:
            post['manifest_sha256'] = '0' * 64
        return {'post_target': post, 'cleanup': self.cleanup,
                'launch_state': 'exited', 'exit_confirmed': True,
                'quarantine_ref': None if self.cleanup else 'quarantine-one'}

    def abort(self, evaluation_id, target=None, offer=None):
        self.effect('abort')
        state = 'never-launched' if self.offer is None else 'exited' if self.exit_confirmed else 'unknown'
        return {'cleanup': self.abort_cleanup, 'post_target': None,
                'launch_state': state, 'exit_confirmed': state == 'exited',
                'quarantine_ref': None if self.abort_cleanup else 'quarantine-one'}


class GateEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'room.db'
        self.ledger = RoomLedger(self.path, 'alpha')
        self.addCleanup(lambda: self.ledger.close())
        config = load(io.StringIO(Path('tests/fixtures/two-rooms.json').read_text()))
        self.policy = config['rooms'][0]['policies'][0]
        self.gate = self.policy['gates'][0]['id']
        self.run = {'run_id': 'run-one', 'generation': 1, 'status': 'ACTIVE',
            'project_id': 'project-alpha', 'repository': 'example/project-alpha',
            'participant_id': 'builder', 'policy': deepcopy(self.policy),
            'checkout': {'slot': 'primary', 'branch': 'refs/heads/main'}}
        self.revision = 0
        self.allowed = True
        self.seed(lambda s: s.update(runs={'run-one': deepcopy(self.run)}))
        self.control = FakeControl()
        self.binding = GateRoomBinding('alpha', 'room-instance', 'project-alpha',
                                       'example/project-alpha', 128 << 20)
        self.construct()

    def construct(self):
        self.hub = ArtifactGateHub(self.ledger, self.binding, self.control,
                                   authorize=lambda *_: self.allowed)
        self.control.hub = self.hub

    def seed(self, change):
        self.revision += 1
        def update(state, _):
            change(state)
            return Transition(state, (Event('test.changed', {}),), {})
        self.ledger.apply(Command('seed-' + str(self.revision), 'test.change', 'run-one', None, {}),
                          ORIGIN, authorize=lambda *_: True, decide=update)

    def evaluate(self, op='evaluate-one', generation=1, gate=None, origin=ORIGIN):
        return self.hub.evaluate(op, 'run-one', generation, gate or self.gate, origin=origin)

    def projection(self, generation=1):
        return self.hub.projection('run-one', generation, self.gate, origin=ORIGIN)

    def error(self, code, fn):
        with self.assertRaises(LedgerError) as caught:
            fn()
        self.assertEqual(code, caught.exception.code)

    def test_pass_records_hub_checks_target_and_provenance_after_exit_cleanup(self):
        result = self.evaluate()['result']
        self.assertEqual('passed', result['verdict'])
        self.assertEqual(PROVENANCE, result['provenance'])
        self.assertEqual([True], [c['ok'] for c in result['checks']])
        self.assertTrue(result['checks'][0]['evidence_refs'])
        self.assertEqual(self.control.target, result['target'])
        self.assertEqual(['resolve', 'prepare', 'current', 'start', 'records', 'ack', 'exit', 'finish', 'current'],
                         self.control.calls)
        events = self.ledger.replay(0)
        self.assertEqual(['gate.started', 'gate.target-bound', 'gate.launch-reserved', 'gate.source-bound',
                          'gate.observed', 'gate.completed'], [e['kind'] for e in events[1:]])
        self.assertEqual(events[1]['room_seq'], result['started']['sequence'])
        self.assertEqual(events[-1]['room_seq'], result['completed']['sequence'])
        self.assertEqual(0, self.hub._row(result['evaluation_id'])['reservation']['scratch_bytes'])
        self.assertEqual('passed', self.projection()['state'])
        self.assertEqual('ACTIVE', self.ledger.snapshot()['state']['runs']['run-one']['status'])
        self.assertTrue(self.control.offer.closed)

    def test_only_operation_run_generation_gate_are_public_arguments(self):
        for field in ('path', 'head_sha', 'argv', 'policy', 'evaluator', 'verdict', 'target'):
            with self.subTest(field=field), self.assertRaises(TypeError):
                self.hub.evaluate('op', 'run-one', 1, self.gate, origin=ORIGIN, **{field: 'chosen'})
        self.assertEqual([], self.control.calls)

    def test_refused_authority_precedes_lookup_and_resolver(self):
        self.allowed = False
        self.error('FORBIDDEN', self.evaluate)
        self.assertEqual([], self.control.calls)
        self.assertNotIn('gate_evaluations', self.ledger.snapshot()['state'])

    def test_retry_and_conflict_precede_staleness_and_resolver(self):
        original = self.evaluate()
        before = self.ledger.snapshot()
        self.seed(lambda s: s['runs']['run-one'].update(generation=2))
        self.control.calls.clear()
        self.assertEqual(original, self.evaluate())
        self.error('ID_CONFLICT', lambda: self.evaluate(generation=2))
        self.error('ID_CONFLICT', lambda: self.evaluate(gate='other'))
        self.error('ID_CONFLICT', lambda: self.evaluate(origin=replace(ORIGIN, actor_id='other')))
        self.assertEqual([], self.control.calls)
        self.allowed = False
        self.error('FORBIDDEN', self.evaluate)
        self.assertEqual(before['room_seq'] + 1, self.ledger.snapshot()['room_seq'])

    def test_reopen_exact_retry_preserves_attempt_and_has_no_external_effect(self):
        first = self.evaluate()
        self.ledger.close()
        self.ledger = RoomLedger(self.path, 'alpha')
        self.construct()
        self.control.calls.clear()
        self.assertEqual(first, self.evaluate())
        self.assertEqual([], self.control.calls)

    def test_cross_run_id_reuse_conflicts_before_any_resolution(self):
        self.evaluate()
        self.control.calls.clear()
        self.error('ID_CONFLICT', lambda: self.hub.evaluate('evaluate-one', 'another-run', 1,
                                                          self.gate, origin=ORIGIN))
        self.assertEqual([], self.control.calls)

    def test_replacement_room_instance_retry_returns_old_attempt_not_new_authority(self):
        first = self.evaluate()
        self.binding = replace(self.binding, room_instance='replacement-instance')
        self.construct()
        self.control.calls.clear()
        self.assertEqual(first, self.evaluate())
        self.assertEqual([], self.control.calls)
        self.assertEqual('stale', self.projection()['state'])
        self.assertEqual('room-instance', first['scope']['room_instance'])

    def test_changed_authority_epoch_cannot_reuse_operation_in_new_instance(self):
        self.evaluate()
        self.construct()
        self.control.calls.clear()
        self.error('ID_CONFLICT', lambda: self.evaluate(origin=replace(ORIGIN, authority_version='v2')))
        self.assertEqual([], self.control.calls)

    def test_missing_wrong_type_and_empty_required_are_failed_not_error(self):
        for fact in ({'observed_type': 'missing', 'length': 0},
                     {'observed_type': 'directory', 'length': 0}, {'length': 0}):
            with self.subTest(fact=fact):
                self.control.facts['README.md'] = fact
                result = self.evaluate('failed-' + str(self.revision))['result']
                self.assertEqual('failed', result['verdict'])
                self.assertFalse(result['checks'][0]['ok'])
                self.revision += 1

    def test_empty_file_allowed_only_when_compiled_policy_says_so(self):
        self.seed(lambda s: s['runs']['run-one']['policy']['gates'][0]['config']['items'][0].update(nonempty=False))
        self.control.facts['README.md'] = {'length': 0}
        self.assertEqual('passed', self.evaluate()['result']['verdict'])

    def test_directory_nonempty_is_raw_fact_not_helper_verdict(self):
        self.seed(lambda s: s['runs']['run-one']['policy']['gates'][0]['config']['items'][0].update(type='directory'))
        self.control.facts['README.md'] = {'observed_type': 'directory', 'length': 0, 'nonempty': True}
        self.assertEqual('passed', self.evaluate()['result']['verdict'])
        self.control.facts['README.md']['nonempty'] = False
        self.assertEqual('failed', self.evaluate('empty-directory')['result']['verdict'])

    def test_typed_read_error_is_error_not_missing_or_failed(self):
        self.control.facts['README.md'] = {'observed_type': 'error', 'length': 0, 'error': 40}
        result = self.evaluate()['result']
        self.assertEqual('error', result['verdict'])
        self.assertEqual('artifact-read-error-40', result['checks'][0]['note'])

    def test_malformed_claims_order_missing_extra_and_correlation_fail_before_ack(self):
        mutations = [lambda r: r[1].update(ok=True), lambda r: r[1].update(verdict='passed'),
            lambda r: r[1].update(index=1), lambda r: r[1].update(index=True),
            lambda r: r[1].update(path_digest='0' * 64), lambda r: r.pop(1),
            lambda r: r.insert(1, deepcopy(r[1])), lambda r: r.append(deepcopy(r[-1])),
            lambda r: r[0].update(scope_digest='0' * 64), lambda r: r[-1].update(inode=101),
            lambda r: r[0].update(count=True), lambda r: r[1].update(observed_type='symlink'),
            lambda r: r[1].update(length=True), lambda r: r[1].update(length=-1),
            lambda r: r[1].update(length=1 << 30), lambda r: r[1].update(error=5)]
        # Separate durable stores keep this adversarial matrix independent of
        # the intentionally bounded retained evaluation projection.
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.control.mutate_records = mutate
                self.control.calls.clear()
                result = self.evaluate('bad-' + str(self.revision))['result']
                self.assertEqual('error', result['verdict'])
                self.assertNotIn('ack', self.control.calls)
                self.assertNotIn('finish', self.control.calls)
                self.revision += 1

    def test_maximum_canonical_items_have_one_check_each_with_reserved_growth(self):
        policy = json.loads(Path('tests/fixtures/two-rooms.json').read_text())['rooms'][0]['policies'][0]
        policy['gates'][0]['config']['items'] = [
            {'path': 'artifact-' + str(i).zfill(3), 'type': 'file', 'nonempty': True}
            for i in reversed(range(128))]
        compiled = compile_policy(policy, 'policy')
        self.seed(lambda s: s['runs']['run-one'].update(policy=compiled))
        result = self.evaluate()['result']
        self.assertEqual('passed', result['verdict'])
        self.assertEqual(128, len(result['checks']))
        self.assertEqual(list(range(128)), [c['item']['index'] for c in result['checks']])

    def test_different_gates_can_hold_independent_bounded_attempts(self):
        policy = json.loads(Path('tests/fixtures/two-rooms.json').read_text())['rooms'][0]['policies'][0]
        other = deepcopy(policy['gates'][0]); other['id'] = 'other-artifacts'
        policy['gates'].append(other)
        for ids in policy['protected_operations'].values():
            ids.append(other['id'])
        compiled = compile_policy(policy, 'policy')
        self.seed(lambda s: s['runs']['run-one'].update(policy=compiled))
        self.control.at['prepare'] = lambda: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted):
            self.evaluate()
        del self.control.at['prepare']
        self.assertEqual('passed', self.evaluate('different-gate', gate=other['id'])['result']['verdict'])
        self.assertEqual('in-flight', self.projection()['state'])

    def test_history_capacity_never_evicts_or_rewrites_original_attempts(self):
        self.control.mutate_records = lambda r: r.pop(1)
        first = self.evaluate('evaluation-0')
        for i in range(1, 16):
            self.evaluate('evaluation-' + str(i))
        self.control.calls.clear()
        self.error('GATE_HISTORY_CAPACITY', lambda: self.evaluate('evaluation-16'))
        self.assertEqual(['resolve'], self.control.calls)
        self.assertEqual(first, self.evaluate('evaluation-0'))

    def test_helper_source_binding_cannot_be_a_participant_or_wrong_scope(self):
        self.control.mutate_document = lambda d: d.update(source='participant')
        result = self.evaluate()['result']
        self.assertEqual('GATE_HELPER_BINDING_MISMATCH', result['reason'])
        self.assertNotIn('records', self.control.calls)

    def test_helper_loss_after_final_before_ack_is_error(self):
        self.control.alive = False
        result = self.evaluate()['result']
        self.assertEqual('error', result['verdict'])
        self.assertEqual('GATE_HELPER_LOST', result['reason'])
        self.assertNotIn('finish', self.control.calls)
        self.assertTrue(self.control.offer.closed)

    def test_eof_or_final_without_actual_exit_cannot_finalize_pass_or_cleanup(self):
        self.control.exit_confirmed = False
        self.control.abort_cleanup = False
        row = self.evaluate()
        self.assertEqual('GATE_HELPER_EXIT_UNCONFIRMED', row['result']['reason'])
        self.assertEqual('GATE_TARGET_QUARANTINED', row['operational']['attention'])
        self.assertEqual(SCRATCH_BYTES, self.hub._row(row['evaluation_id'])['reservation']['scratch_bytes'])
        self.assertNotIn('finish', self.control.calls)

    def test_cleanup_claim_without_exit_or_never_launch_proof_keeps_reservation(self):
        self.control.exit_confirmed = False
        self.control.abort_cleanup = True  # Deliberately contradictory trusted-boundary mock.
        row = self.evaluate()
        self.assertEqual('error', row['result']['verdict'])
        self.assertFalse(row['operational']['cleanup'])
        self.assertEqual('unknown', row['result']['cleanup']['launch_state'])
        self.assertEqual(SCRATCH_BYTES, self.hub._row(row['evaluation_id'])['reservation']['scratch_bytes'])

    def test_post_target_mutation_is_error(self):
        self.control.post_mutated = True
        self.assertEqual('GATE_TARGET_CHANGED', self.evaluate()['result']['reason'])

    def test_failed_cleanup_never_commits_pass_and_recovery_preserves_immutable_error(self):
        self.control.cleanup = self.control.abort_cleanup = False
        row = self.evaluate()
        immutable = deepcopy(row['result'])
        self.assertEqual('error', immutable['verdict'])
        self.assertEqual('GATE_CLEANUP_FAILED', immutable['reason'])
        self.assertEqual(SCRATCH_BYTES, self.hub._row(row['evaluation_id'])['reservation']['scratch_bytes'])
        self.control.abort_cleanup = True
        recovered = self.hub.reconcile_cleanup(row['evaluation_id'])
        self.assertEqual(immutable, recovered['result'])
        self.assertTrue(recovered['operational']['cleanup'])
        self.assertEqual(0, self.hub._row(row['evaluation_id'])['reservation']['scratch_bytes'])

    def test_failed_cleanup_is_not_silently_retried_by_error_handler(self):
        self.control.cleanup = False
        self.control.abort_cleanup = True
        row = self.evaluate()
        self.assertEqual('GATE_CLEANUP_FAILED', row['result']['reason'])
        self.assertFalse(row['operational']['cleanup'])
        self.assertNotIn('abort', self.control.calls)

    def test_head_change_after_measurement_preserves_historical_pass_but_stales_current(self):
        self.control.at['finish'] = lambda: self.control.source.update(head_sha='2' * 40)
        result = self.evaluate()['result']
        self.assertEqual('passed', result['verdict'])
        self.assertEqual('a' * 40, result['source']['head_sha'])
        self.assertEqual('stale', result['freshness_at_completion']['state'])
        projection = self.projection()
        self.assertEqual('stale', projection['state'])
        self.assertIn('head_sha', projection['changed_dependencies'])
        self.assertEqual(result, self.evaluate()['result'])

    def test_head_change_before_launch_blocks_helper(self):
        self.control.at['prepare'] = lambda: self.control.source.update(head_sha='2' * 40)
        result = self.evaluate()['result']
        self.assertEqual('GATE_SOURCE_CHANGED_BEFORE_LAUNCH', result['reason'])
        self.assertNotIn('start', self.control.calls)

    def test_current_run_changes_during_prepare_fence_launch_transaction(self):
        mutations = (
            ('generation', lambda r: r.update(generation=2), 'STALE_RUN_GENERATION'),
            ('pause', lambda r: r.update(status='PAUSED'), 'RUN_NOT_ACTIVE'),
            ('policy', lambda r: r['policy'].update(version=2), 'GATE_DEPENDENCY_CHANGED'),
            ('config', lambda r: r['policy']['gates'][0]['config']['items'][0].update(nonempty=False),
             'GATE_DEPENDENCY_CHANGED'),
            ('branch', lambda r: r['checkout'].update(branch='refs/heads/replaced'), 'GATE_SOURCE_MISMATCH'),
            ('slot', lambda r: r['checkout'].update(slot='replacement'), 'GATE_SOURCE_MISMATCH'),
            ('path', lambda r: r['checkout'].update(path='/different-owned-slot'), 'GATE_SOURCE_MISMATCH'),
            ('identity', lambda r: r['checkout'].update(identity={'directory': [9, 9]}), 'GATE_SOURCE_MISMATCH'),
        )
        for label, mutate, reason in mutations:
            with self.subTest(change=label):
                self.seed(lambda s: s['runs'].update({'run-one': deepcopy(self.run)}))
                self.control.calls.clear()
                self.control.at['prepare'] = lambda: self.seed(lambda s: mutate(s['runs']['run-one']))
                row = self.evaluate('change-before-launch-' + label)
                self.assertEqual(reason, row['result']['reason'])
                self.assertEqual('error', row['result']['verdict'])
                self.assertNotIn('start', self.control.calls)
                self.assertTrue(row['operational']['cleanup'])
                self.assertNotIn('gate.launch-reserved', [e['kind'] for e in self.ledger.replay(0)
                    if e['target'] == row['evaluation_id']])

    def test_launch_reauthorization_is_inside_the_reservation_transaction(self):
        checked = []
        def authorize(*_):
            rows = self.ledger.snapshot()['state'].get('gate_evaluations', {})
            if rows and next(iter(rows.values()))['phase'] == 'TARGET_BOUND':
                checked.append(self.ledger._db.in_transaction)
                return False
            return True
        self.hub.authorize = authorize
        row = self.evaluate()
        self.assertEqual([True, True], checked)  # Launch fence, then terminal authorization.
        self.assertEqual('GATE_AUTHORITY_REVOKED', row['result']['reason'])
        self.assertNotIn('start', self.control.calls)

    def test_unchanged_head_does_not_hide_changed_source_ownership(self):
        result = self.evaluate()['result']
        self.control.source['source_digest'] = '3' * 64
        projection = self.projection()
        self.assertEqual('stale', projection['state'])
        self.assertIn('source_digest', projection['changed_dependencies'])
        self.assertEqual(result, self.evaluate()['result'])

    def test_authority_is_rechecked_before_final_acceptance(self):
        self.control.at['finish'] = lambda: setattr(self, 'allowed', False)
        result = self.evaluate()['result']
        self.assertEqual('GATE_AUTHORITY_REVOKED', result['reason'])
        self.assertEqual('error', result['verdict'])

    def test_authority_failure_during_terminal_check_still_records_error(self):
        def revoke():
            self.hub.authorize = lambda *_: (_ for _ in ()).throw(LedgerError('AUTHORITY_REVOKED'))
        self.control.at['finish'] = revoke
        result = self.evaluate()['result']
        self.assertEqual('GATE_AUTHORITY_REVOKED', result['reason'])
        self.assertEqual('error', result['verdict'])

    def test_run_policy_and_generation_changes_stale_historical_facts(self):
        self.control.at['finish'] = lambda: self.seed(lambda s: s['runs']['run-one'].update(generation=2))
        result = self.evaluate()['result']
        self.assertEqual('passed', result['verdict'])
        self.assertEqual('stale', result['freshness_at_completion']['state'])
        self.assertEqual('stale', self.projection(2)['state'])

    def test_current_checkout_changes_at_finish_stale_historical_pass(self):
        for field, value, dependency in (('branch', 'refs/heads/replaced', 'branch'),
                                          ('slot', 'replacement', 'slot_id'),
                                          ('path', '/different-owned-slot', 'checkout-binding'),
                                          ('identity', {'directory': [9, 9]}, 'checkout-binding')):
            with self.subTest(field=field):
                self.seed(lambda s: s['runs']['run-one'].update(checkout=deepcopy(self.run['checkout'])))
                self.control.at['finish'] = lambda: self.seed(
                    lambda s: s['runs']['run-one']['checkout'].update({field: value}))
                row = self.evaluate('changed-checkout-' + field)
                result = row['result']
                self.assertEqual('passed', result['verdict'])
                self.assertEqual('stale', result['freshness_at_completion']['state'])
                self.assertIn(dependency, result['freshness_at_completion']['changed_dependencies'])
                self.assertEqual('stale', self.projection()['state'])
                self.assertEqual(row, self.evaluate('changed-checkout-' + field))

    def test_mutable_checkout_observations_are_not_revision_dependencies(self):
        self.control.at['prepare'] = lambda: self.seed(lambda s: s['runs']['run-one']['checkout'].update(
            observed_dirty=True, observed_head='9' * 40, reason='DIRTY_OR_UNTRACKED_OR_IGNORED'))
        result = self.evaluate()['result']
        self.assertEqual('passed', result['verdict'])
        self.assertEqual('current', result['freshness_at_completion']['state'])
        self.assertEqual('passed', self.projection()['state'])

    def test_latest_failed_rerun_supersedes_pass_without_fallback(self):
        first = self.evaluate()['result']
        self.control.facts['README.md'] = {'length': 0}
        second = self.evaluate('rerun')['result']
        self.assertEqual('passed', first['verdict'])
        self.assertEqual('failed', second['verdict'])
        self.assertEqual(second['evaluation_id'], self.projection()['evaluation_id'])
        self.assertEqual('failed', self.projection()['state'])

    def test_missing_projection_does_not_launch_implicitly(self):
        self.assertEqual('missing', self.projection()['state'])
        self.assertEqual([], self.control.calls)

    def test_inflight_retry_waits_and_new_id_does_not_relaunch(self):
        self.control.at['prepare'] = lambda: (_ for _ in ()).throw(Interrupted())
        with self.assertRaises(Interrupted):
            self.evaluate()
        self.control.calls.clear()
        self.assertEqual('STARTED', self.evaluate()['phase'])
        self.assertEqual([], self.control.calls)
        self.assertEqual('in-flight', self.projection()['state'])
        self.error('GATE_EVALUATION_IN_FLIGHT', lambda: self.evaluate('other-operation'))
        self.assertEqual(['resolve'], self.control.calls)

    def test_interrupted_launch_reopen_is_error_unknown_never_automatic_retry(self):
        self.control.at['start'] = lambda: (_ for _ in ()).throw(Interrupted())
        self.control.abort_cleanup = False
        with self.assertRaises(Interrupted):
            self.evaluate()
        self.ledger.close()
        self.ledger = RoomLedger(self.path, 'alpha')
        self.construct()
        self.control.calls.clear()
        row = self.evaluate()
        self.assertEqual('LAUNCH_RESERVED', row['phase'])
        self.assertEqual([], self.control.calls)
        recovered = self.hub.recover_interrupted(row['evaluation_id'])
        self.assertEqual('GATE_INTERRUPTED_UNKNOWN', recovered['result']['reason'])
        self.assertEqual(['abort'], self.control.calls)
        self.assertEqual(SCRATCH_BYTES, self.hub._row(row['evaluation_id'])['reservation']['scratch_bytes'])
        self.assertEqual(recovered, self.evaluate())

    def test_quarantined_targets_keep_capacity_until_verified_removal(self):
        self.binding = replace(self.binding, disk_bytes=SCRATCH_BYTES)
        self.construct()
        self.control.cleanup = self.control.abort_cleanup = False
        row = self.evaluate()
        self.control.calls.clear()
        self.error('GATE_RESOURCE_CAPACITY', lambda: self.evaluate('another'))
        self.assertEqual(['resolve'], self.control.calls)
        self.control.abort_cleanup = True
        self.hub.reconcile_cleanup(row['evaluation_id'])
        self.control.cleanup = True
        self.assertEqual('passed', self.evaluate('after-cleanup')['result']['verdict'])

    def test_undersized_room_refuses_before_target_or_launch_effects(self):
        self.binding = replace(self.binding, disk_bytes=SCRATCH_BYTES - 1)
        self.construct()
        self.error('GATE_RESOURCE_CAPACITY', self.evaluate)
        self.assertEqual(['resolve'], self.control.calls)
        self.assertNotIn('gate_evaluations', self.ledger.snapshot()['state'])

    def test_projection_reservation_refusal_precedes_any_target_effect(self):
        self.seed(lambda s: s.update(other_owner='x' * 900000))
        self.error('INVALID_JSON', self.evaluate)
        self.assertEqual(['resolve'], self.control.calls)
        self.assertNotIn('gate_evaluations', self.ledger.snapshot()['state'])

    def test_corrupt_or_unsupported_snapshot_fails_before_resolver(self):
        self.seed(lambda s: s['runs']['run-one']['policy']['gates'][0].update(evaluator='command'))
        self.error('INVALID_GATE_POLICY', self.evaluate)
        self.assertEqual([], self.control.calls)

    def test_changed_resolved_slot_or_repository_cannot_select_target(self):
        self.control.source['slot_id'] = 'other'
        self.error('GATE_SOURCE_MISMATCH', self.evaluate)
        self.assertNotIn('prepare', self.control.calls)

    def test_failed_storage_start_never_performs_target_effect(self):
        original = self.ledger._commit
        self.ledger._commit = lambda: (_ for _ in ()).throw(LedgerError('STORAGE_ERROR'))
        try:
            self.error('STORAGE_ERROR', self.evaluate)
        finally:
            self.ledger._commit = original
        self.assertEqual(['resolve'], self.control.calls)
        self.assertNotIn('gate_evaluations', self.ledger.snapshot()['state'])

    def test_uncertain_committed_start_does_not_replay_effects_on_retry(self):
        original = self.ledger._commit
        def uncertain():
            original()
            raise LedgerError('STORAGE_ERROR')
        self.ledger._commit = uncertain
        try:
            self.error('STORAGE_ERROR', self.evaluate)
        finally:
            self.ledger._commit = original
        self.control.calls.clear()
        self.assertEqual('STARTED', self.evaluate()['phase'])
        self.assertEqual([], self.control.calls)

    def test_storage_failure_after_prepare_cleans_once_then_records_error(self):
        original = self.ledger._commit
        failed = False
        def fail_bound_once():
            nonlocal failed
            row = next(iter(self.ledger.snapshot()['state'].get('gate_evaluations', {}).values()), {})
            if not failed and row.get('phase') == 'TARGET_BOUND':
                failed = True
                raise LedgerError('STORAGE_ERROR')
            original()
        self.ledger._commit = fail_bound_once
        try:
            row = self.evaluate()
        finally:
            self.ledger._commit = original
        self.assertEqual('STORAGE_ERROR', row['result']['reason'])
        self.assertEqual(['resolve', 'prepare', 'abort'], self.control.calls)
        self.assertEqual('error', row['result']['verdict'])

    def test_other_owner_cannot_consume_reserved_completion_capacity(self):
        def fill_free_space():
            def fill(state):
                free = 1048576 - len(_json(state).encode()) - 4096
                state['other_owner'] = 'x' * free
            self.seed(fill)
        self.control.at['prepare'] = fill_free_space
        self.assertEqual('passed', self.evaluate()['result']['verdict'])
        self.assertLess(len(_json(self.ledger.snapshot()['state']).encode()), 1048576)

    def test_terminal_storage_failure_reopens_without_relaunch_or_fabricated_pass(self):
        original = self.ledger._commit
        failed = False
        def fail_terminal_once():
            nonlocal failed
            row = next(iter(self.ledger.snapshot()['state'].get('gate_evaluations', {}).values()), {})
            if not failed and row.get('phase') == 'TERMINAL':
                failed = True
                raise LedgerError('STORAGE_ERROR')
            original()
        self.ledger._commit = fail_terminal_once
        try:
            self.error('STORAGE_ERROR', self.evaluate)
        finally:
            self.ledger._commit = original
        self.control.calls.clear()
        row = self.evaluate()
        self.assertIsNone(row['result'])
        self.assertEqual([], self.control.calls)
        self.assertEqual('error', self.hub.recover_interrupted(row['evaluation_id'])['result']['verdict'])
        self.assertEqual(['abort'], self.control.calls)


if __name__ == '__main__':
    unittest.main()
