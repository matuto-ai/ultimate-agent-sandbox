"""Pure composition contract tests: no socket, native process, DB or provider.

Canonical objects below are deliberately uninitialized controlled doubles; they
prove delegation/guards only, never real admission or lifecycle acceptance.
"""
from copy import deepcopy
from types import SimpleNamespace as NS
from unittest import TestCase
from unittest.mock import patch

from uas.ledger import LedgerError
from uas.lifecycle_scenario import LifecycleScenario, preflight
from uas.run_review import RunReview
from uas.workstation_control import SupervisorAdmission
from uas.workstation_peer import AdmittedPeerDispatcher


class LifecycleScenarioTests(TestCase):
    def setUp(self):
        self.snapshot = {'room_id': 'alpha', 'room_seq': 7, 'state': {'runs': {
            'run': {'generation': 1, 'project_id': 'project', 'repository': 'owner/repo', 'status': 'ACTIVE'}},
            'review_comments': {'comment': {'run_id': 'run', 'generation': 1, 'status': 'unknown'}}}}
        self.owner = object.__new__(RunReview)
        self.dispatcher = object.__new__(AdmittedPeerDispatcher)
        self.ledger = NS(room_id='alpha', snapshot=lambda: deepcopy(self.snapshot))
        self.owner.ledger = self.ledger
        self.owner.identity = NS(dispatcher=self.dispatcher)
        self.owner.gates = NS(ledger=self.ledger, identity=self.owner.identity,
            binding=NS(room_id='alpha', project_id='project', repository='owner/repo'))
        self.dispatcher.hub = NS(ledger=self.ledger)
        self.dispatcher.reviews = self.owner
        self.seat = NS(room_id='alpha', participant_id='pi')
        self.channel = NS(gettimeout=lambda: 1)
        self.dispatcher.admissions = NS(seats={'pi': self.seat}, peer_channel=lambda _: self.channel,
            controller='host', binding=lambda _: NS(seat=self.seat, incarnation='inc'))
        self.authority = {'human': object(), 'authorize': lambda: False, 'admission_operation': 'admit'}
        self.scenario = LifecycleScenario(self.owner, self.dispatcher, 'run', 1, max_steps=4)

    def test_rejects_mixed_owners_and_invalid_bounds(self):
        self.owner.gates.ledger = object()
        with self.assertRaisesRegex(LedgerError, 'OWNER_MISMATCH'):
            LifecycleScenario(self.owner, self.dispatcher, 'run', 1)
        self.owner.gates.ledger = self.ledger
        for bound in (0, 129, True, 1.5):
            with self.assertRaisesRegex(LedgerError, 'INVALID_BOUND'):
                LifecycleScenario(self.owner, self.dispatcher, 'run', 1, max_steps=bound)

    def test_native_receive_delegates_without_constructing_origin(self):
        with patch.object(AdmittedPeerDispatcher, 'receive', return_value={'ok': True}) as receive:
            self.assertEqual(self.scenario.receive_room_once('admit'), {'ok': True})
            receive.assert_called_once_with('admit')

    def test_room_pump_does_not_relabel_sibling_run_or_require_selected_generation(self):
        self.snapshot['state']['runs']['run']['generation'] = 2
        receipt = {'ok': True, 'receipt': {'run_id': 'sibling', 'generation': 7}}
        with patch.object(AdmittedPeerDispatcher, 'receive', return_value=receipt) as receive:
            self.assertEqual(self.scenario.receive_room_once('admit'), receipt)
            receive.assert_called_once_with('admit')
        with self.assertRaisesRegex(LedgerError, 'SCOPE_CHANGED'):
            self.scenario.report()

    def test_unbounded_channel_rejected_without_read_or_mutation(self):
        with patch.object(AdmittedPeerDispatcher, 'receive') as receive:
            for timeout in (None, 0, 6):
                self.channel.gettimeout = lambda: timeout
                with self.assertRaisesRegex(LedgerError, 'UNBOUNDED_CHANNEL'):
                    self.scenario.receive_room_once('admit')
            receive.assert_not_called()
            self.assertEqual(self.scenario.remaining, 1)

    def test_delivery_uses_supervisor_never_marks_safe_itself(self):
        controller = object.__new__(SupervisorAdmission)
        controller.seat = self.seat
        controller.controller = 'host'
        controller.launch = NS(incarnation='inc', admission={'state': 'admitted', 'operation_id': 'admit'})
        with patch.object(SupervisorAdmission, 'deliver_one', return_value={'status': 'HELD'}) as deliver:
            self.assertEqual(self.scenario.deliver_seat_once(controller), {'status': 'HELD'})
            deliver.assert_called_once_with()
            controller.seat = NS(room_id='beta', participant_id='pi')
            with self.assertRaisesRegex(LedgerError, 'DELIVERY_OWNER_MISMATCH'):
                self.scenario.deliver_seat_once(controller)
            self.assertEqual(deliver.call_count, 1)

    def test_unknown_write_reconciliation_preserves_identity_and_authority(self):
        payload = {'submission_id': 'submit', 'body': 'request', 'target': {'head_sha': 'a'*40}}
        with patch.object(RunReview, 'request_changes', return_value={'status': 'unknown'}) as request, \
             patch.object(RunReview, 'reconcile_changes', return_value={'status': 'confirmed'}) as reconcile:
            self.assertEqual(self.scenario.request_changes('comment', payload, **self.authority)['status'], 'unknown')
            request.assert_called_once_with('comment', 'run', 1, payload, **self.authority)
            self.assertEqual(self.scenario.reconcile_changes('comment', 'read1', **self.authority)['status'], 'confirmed')
            reconcile.assert_called_once_with('comment', reconciliation_id='read1', **self.authority)
            self.assertEqual(request.call_count, 1)

    def test_unknown_scope_never_reconciles_sibling_operation(self):
        self.snapshot['state']['review_comments']['comment']['run_id'] = 'other'
        with patch.object(RunReview, 'reconcile_changes') as reconcile:
            with self.assertRaisesRegex(LedgerError, 'OPERATION_SCOPE_MISMATCH'):
                self.scenario.reconcile_changes('comment', 'read1', **self.authority)
            reconcile.assert_not_called()

    def test_timeout_not_automatically_retried_and_counts_toward_bound(self):
        self.scenario.remaining = 1
        with patch.object(RunReview, 'request_changes', side_effect=TimeoutError) as request:
            with self.assertRaises(TimeoutError):
                self.scenario.request_changes('comment', {}, **self.authority)
            with self.assertRaisesRegex(LedgerError, 'STEP_LIMIT'):
                self.scenario.request_changes('different-id', {}, **self.authority)
            self.assertEqual(request.call_count, 1)

    def test_scope_reset_fails_before_owner_call(self):
        self.snapshot['state']['runs']['run']['generation'] = 2
        with patch.object(RunReview, 'complete') as complete:
            with self.assertRaisesRegex(LedgerError, 'SCOPE_CHANGED'):
                self.scenario.observe_completion('finish', 'submit', **self.authority)
            complete.assert_not_called()

    def test_completion_only_observes_no_merge_or_authority_substitution(self):
        with patch.object(RunReview, 'complete', return_value={'stage': 'COMPLETED'}) as complete:
            self.scenario.observe_completion('finish', 'submit', observation_id='read1', **self.authority)
            complete.assert_called_once_with('finish', 'run', 1, 'submit', origin=self.authority['human'],
                authorize=self.authority['authorize'], admission_operation='admit', observation_id='read1')

    def test_report_uses_single_cut_redacts_content_and_never_claims_real(self):
        self.snapshot['state']['runs']['run']['status'] = 'CLOSED'
        self.snapshot['state']['run_reviews'] = {'run': {'returns': 1, 'current': {
            'stage': 'COMPLETED', 'evidence': ['secret'], 'target': {'head_sha': 'a'*40, 'base_sha': 'b'*40},
            'completion': {'candidate_sha': 'a'*40, 'integration_sha': 'c'*40, 'merger_id': 7},
            'reviewer': {'actor_id': 'reviewer', 'credentials': 'secret'}}}}
        self.snapshot['state']['peer_traffic'] = {'traffic': {'req': {'run_id': 'run', 'generation': 1,
            'kind': 'peer.work-request', 'id': 'req', 'status': 'COMPLETED', 'text': 'secret'}}}
        result = self.scenario.report()
        self.assertNotIn('secret', str(result))
        self.assertEqual(result['completion']['candidate_sha'], 'a'*40)
        self.assertEqual(result['completion']['integration_sha'], 'c'*40)
        self.assertEqual(result['run_status'], 'CLOSED')
        self.assertFalse(result['real_lifecycle_qualified'])
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['missing'], preflight()['missing'])
        self.assertEqual(result['remaining_steps'], 4)
