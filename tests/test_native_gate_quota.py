"""Real canonical Gate/SQLite reservation; quota kernel query is controlled only."""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_gate_evaluation as fixture
from uas.lifecycle import LifecycleError
from uas.ledger import LedgerError
from uas.native_checkout_handoff import (RootCheckoutHandoff, NativeCheckoutClient,
    gate_quota_binding, request_value, MAX_REQUESTS)
from uas.native_qualification_backend import NativeQualificationBackend


class GateQuotaTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.GateEvaluationTests()
        self.case.setUp(); self.addCleanup(self.case.doCleanups)
        self.case.control.at['prepare'] = lambda: (_ for _ in ()).throw(fixture.Interrupted())
        with self.assertRaises(fixture.Interrupted): self.case.evaluate()
        self.evaluation = self.case.hub.evaluation_id('evaluate-one')
        self.request = {'version': 1, 'kind': 'GATE_QUOTA', 'evaluation_id': self.evaluation}
        self.binding = self.case.binding
        self.depth = 0
        self.backend = object.__new__(NativeQualificationBackend)
        self.observation = {'used_bytes': 4096, 'hard_bytes': self.binding.disk_bytes, 'scratch_identity': [9, 17]}
        self.backend.observe_gate_quota = Mock(side_effect=self.observe)
        self.lifecycle = {'phase': 'running', 'instance_id': self.binding.room_instance,
            'spec': {'config_digest': 'sha256:config'}}
        self.owner = object.__new__(RootCheckoutHandoff)
        self.owner.owner = SimpleNamespace(_locked=self.locked, _read=lambda: deepcopy(self.lifecycle), backend=self.backend)
        self.owner.plan = SimpleNamespace(config_digest='config', room={'id': self.binding.room_id,
            'project': {'id': self.binding.project_id, 'repository': self.binding.repository},
            'resources': {'disk_bytes': self.binding.disk_bytes}})
        self.owner.resources = SimpleNamespace(data={'instance': self.binding.room_instance, 'hub_ledger_path': str(self.case.path)})
        self.owner.ledger_identity = None; self.owner.deadline = 100
        self.owner._held = Mock()
        self.clock = patch('uas.native_checkout_handoff.time.monotonic', return_value=1)
        self.clock.start(); self.addCleanup(self.clock.stop)
        self.mutate = lambda: None

    @contextmanager
    def locked(self, **kwargs):
        self.depth += 1
        try: yield
        finally: self.depth -= 1

    def observe(self, state, *, deadline):
        self.assertEqual(deadline, self.owner.deadline)
        self.assertEqual(self.depth, 0)
        self.assertEqual(state, self.lifecycle)
        self.mutate()
        return deepcopy(self.observation)

    def project(self, state=None):
        return gate_quota_binding(self.case.ledger,
            self.case.ledger.snapshot()['state'] if state is None else state,
            self.binding, self.evaluation)

    def test_exact_readonly_request_no_caller_authority(self):
        self.assertEqual(request_value(self.request), self.request)
        for key in ('path', 'project', 'limit', 'actor', 'scope', 'run_id'):
            with self.assertRaises(LifecycleError): request_value({**self.request, key: 'claim'})
        with self.assertRaises(LifecycleError): request_value({**self.request, 'version': True})
        self.assertEqual(MAX_REQUESTS, 8)

    def test_actual_started_reservation_and_quarantined_capacity_are_returned(self):
        def add(state):
            other = deepcopy(state['gate_evaluations'][self.evaluation])
            other.update(evaluation_id='quarantined', phase='COMPLETED', result={'error': True})
            other['reservation']['scratch_bytes'] = 64 << 20
            state['gate_evaluations']['quarantined'] = other
        self.case.seed(add)
        before = self.case.ledger.snapshot()
        value = self.owner.operation(self.request)
        self.assertEqual(value['reservation_bytes'], 32 << 20)
        self.assertEqual(value['total_reserved_bytes'], 96 << 20)
        self.assertEqual(len(value['outstanding']), 2)
        self.assertEqual(value['source']['head_sha'], 'a' * 40)
        self.assertEqual(value['scratch_identity'], [9, 17])
        self.assertEqual(self.case.ledger.snapshot(), before)
        self.assertEqual(self.owner.operation(self.request), value)
        self.assertEqual(self.backend.observe_gate_quota.call_count, 2)

    def test_stale_policy_checkout_scope_or_wrong_phase_refuse_before_observation(self):
        edits = [lambda s: s['runs']['run-one'].update(status='CLOSED'),
            lambda s: s['runs']['run-one']['checkout'].update(branch='changed'),
            lambda s: s['runs']['run-one']['policy'].update(version=99),
            lambda s: s['gate_evaluations'][self.evaluation].update(phase='TARGET_BOUND'),
            lambda s: s['gate_evaluations'][self.evaluation].update(target={}),
            lambda s: s['gate_evaluations'][self.evaluation].update(evaluator='command'),
            lambda s: s['gate_evaluations'][self.evaluation]['reservation'].update(scratch_bytes=True)]
        original = self.case.ledger.snapshot()['state']
        for edit in edits:
            state = deepcopy(original); edit(state)
            with self.subTest(edit=edit), self.assertRaises((LedgerError, LifecycleError)):
                self.project(state)
        self.backend.observe_gate_quota.assert_not_called()

    def test_reservation_replacement_same_total_during_query_is_denied(self):
        def mutate():
            def change(state):
                old = deepcopy(state['gate_evaluations'][self.evaluation])
                old.update(evaluation_id='other', result={}, phase='COMPLETED')
                state['gate_evaluations']['other'] = old
            self.case.seed(change)
        # Seed another reservation then exchange its identity, preserving amount.
        mutate()
        def replace():
            def change(state):
                row = state['gate_evaluations'].pop('other'); row['evaluation_id'] = 'replacement'
                state['gate_evaluations']['replacement'] = row
            self.case.seed(change)
        self.mutate = replace
        with self.assertRaisesRegex(LifecycleError, 'GATE_QUOTA_RESERVATION_CHANGED'):
            self.owner.operation(self.request)

    def test_full_current_row_or_room_change_during_query_denied(self):
        for kind in ('source', 'origin', 'room'):
            with self.subTest(kind=kind):
                self.set_mutator(kind)
                with self.assertRaises((LedgerError, LifecycleError)):
                    self.owner.operation(self.request)
                # Restore independent canonical fixture for remaining cases.
                if kind != 'room':
                    self.case.seed(lambda s: s['gate_evaluations'][self.evaluation].update(
                        source=deepcopy(self.case.control.source), origin=fixture.ORIGIN.canonical()))
    def set_mutator(self, kind):
        if kind == 'room': self.mutate = lambda: self.lifecycle.update(instance_id='replacement')
        else:
            def mutate():
                def change(state):
                    row = state['gate_evaluations'][self.evaluation]
                    if kind == 'source': row['source']['head_sha'] = 'b' * 40
                    else: row['origin']['actor_id'] = 'replacement'
                self.case.seed(change)
            self.mutate = mutate

    def test_malformed_observation_and_changed_scratch_refuse(self):
        self.owner.operation(self.request)
        self.observation['scratch_identity'] = [9, 18]
        with self.assertRaisesRegex(LifecycleError, 'GATE_QUOTA_SCRATCH_CHANGED'): self.owner.operation(self.request)
        self.observation['used_bytes'] = True
        with self.assertRaisesRegex(LifecycleError, 'GATE_QUOTA_OBSERVATION_INVALID'): self.owner.operation(self.request)

    def test_repeated_evaluation_cannot_adopt_replaced_source(self):
        self.owner.operation(self.request)
        self.case.seed(lambda s: s['gate_evaluations'][self.evaluation]['source'].update(head_sha='b' * 40))
        with self.assertRaisesRegex(LifecycleError, 'GATE_QUOTA_RESERVATION_CHANGED'):
            self.owner.operation(self.request)
        self.assertEqual(self.backend.observe_gate_quota.call_count, 1)

    def test_client_uses_exact_existing_channel_operation(self):
        client = object.__new__(NativeCheckoutClient); client._call = Mock(return_value={'snapshot': True})
        self.assertEqual(client.observe_gate_quota(self.evaluation), {'snapshot': True})
        client._call.assert_called_once_with('GATE_QUOTA', evaluation_id=self.evaluation)
