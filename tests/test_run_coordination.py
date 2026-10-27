"""Pure bounded coordination rules; synthetic handles are not process proof."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from run_control_support import RunControlCase
from uas.ledger import LedgerError
from uas.peer import Readiness, RequestCommand, WorkRequest
from uas.run_coordination import current_coordinator


class RunCoordinationTests(RunControlCase):
    def test_replacement_connection_immediately_loses_appointment_without_reconcile(self):
        self.seed_connected()
        self.appoint()
        self.request('reviewer', 'ordinary-first')
        self.request('builder', 'old-priority')
        connection = self.hub.connect('replacement', 'builder', 'new-builder-incarnation', SimpleNamespace())
        self.connections['builder'] = connection
        self.hub.observe(connection, Readiness.SAFE)
        self.request('builder', 'replacement-request')
        row = self.state()['runs']['run-test']
        self.assertIsNone(row['coordinator'])
        self.assertEqual('COORDINATOR_LOST', row['coordinator_attention'])
        self.assertEqual(['ordinary-first', 'old-priority', 'replacement-request'],
                         [item['id'] for item in self.hub._pending(self.connections['observer'])])

    def seed_connected(self):
        self.seed_run()
        def scopes(state):
            for participant in ('builder', 'reviewer'):
                state['fixture_context']['participants'][participant].update(
                    bound_run={'run_id': 'run-test', 'generation': 1}, reserved_run=None)
            state['peer_traffic']['definition']['participants']['observer'] = {
                'actor_id': 'observer-actor', 'work_slots': 1}
            state['peer_traffic']['cursors']['observer'] = 0
            state['fixture_context']['participants']['observer'] = {
                'context_generation': 1, 'status': 'READY',
                'bound_run': {'run_id': 'run-test', 'generation': 1},
                'reserved_run': None, 'reset': None}
        self.seed(scopes)
        self.connections = {}
        for participant, actor in [('builder', 'alice'), ('reviewer', 'bob'), ('observer', 'observer-actor')]:
            connection = self.hub.connect('connect-' + participant, participant,
                                         'incarnation-' + participant, SimpleNamespace())
            self.connections[participant] = connection
            self.hub.observe(connection, Readiness.SAFE)
            self.controller.handles[participant] = SimpleNamespace(connection=connection,
                badge=SimpleNamespace(actor_id=actor, participant_id=participant,
                                      incarnation_id='incarnation-' + participant))
        self.owned_authorized = True
        def authority(handle):
            if not self.owned_authorized or self.controller.handles.get(handle.badge.participant_id) is not handle:
                raise LedgerError('AUTHORITY_REVOKED')
            return True
        self.admission._authority = authority

    def appoint(self, operation='appoint', revision=0, participant='builder', **kwargs):
        return self.admission.appoint_coordinator(operation, 'run-test', 1, revision,
                                                  participant, human=self.human, **kwargs)

    def request(self, sender, operation):
        return self.hub.submit(self.connections[sender],
            WorkRequest(operation, 'run-test', 1, 'observer', 'bounded peer work'))

    def test_human_only_exact_revision_bounded_appointment_replace_remove_and_retry(self):
        self.seed_connected()
        with patch('uas.run_coordination.time.time', return_value=1000):
            appointed = self.appoint(ttl_seconds=30, request_budget=2)
        coordinator = appointed['coordinator']
        self.assertEqual(('builder', 'incarnation-builder', 1030, 2, 0),
            tuple(coordinator[k] for k in ('participant_id', 'incarnation_id', 'expires_at',
                                          'request_budget', 'requests_used')))
        before = self.ledger.snapshot()
        self.error('FORBIDDEN', lambda: self.admission.appoint_coordinator(
            'participant-cannot-appoint', 'run-test', 1, 1, 'reviewer', human=self.origin))
        self.error('STALE_RUN_CONTROL', lambda: self.appoint(operation='stale', participant='reviewer'))
        self.assertEqual(appointed, self.appoint(ttl_seconds=30, request_budget=2))
        self.assertEqual(before, self.ledger.snapshot())
        replacement = self.appoint(operation='replace', revision=1, participant='reviewer')
        self.assertEqual('reviewer', replacement['coordinator']['participant_id'])
        removed = self.appoint(operation='remove', revision=2, participant=None)
        self.assertIsNone(removed['coordinator'])
        self.assertEqual(3, removed['control_revision'])
        self.assertEqual('ACTIVE', self.state()['runs']['run-test']['status'])
        self.assertEqual(1, self.state()['runs']['run-test']['generation'])

    def test_invalid_bounds_or_unavailable_owned_participant_never_appoint(self):
        self.seed_connected()
        before = self.ledger.snapshot()
        for value in (True, 0, -1, 3601, 1.5, '1'):
            self.error('INVALID_COORDINATOR_BOUND', lambda: self.appoint(ttl_seconds=value))
        for value in (True, 0, -1, 17, 1.5, '1'):
            self.error('INVALID_COORDINATOR_BOUND', lambda: self.appoint(request_budget=value))
        self.error('COORDINATOR_UNAVAILABLE', lambda: self.appoint(participant='foreign'))
        self.owned_authorized = False
        self.error('AUTHORITY_REVOKED', self.appoint)
        self.owned_authorized = True
        handle = self.controller.handles.pop('builder')
        self.error('COORDINATOR_UNAVAILABLE', self.appoint)
        self.controller.handles['builder'] = handle
        self.assertEqual(before, self.ledger.snapshot())

    def test_nomination_is_data_only_and_cannot_self_appoint_or_change_capabilities(self):
        self.seed_connected()
        profiles = deepcopy(self.room['profiles'])
        result = self.admission.nominate_coordinator('nominate', 'run-test', 1, 'reviewer',
            origin=self.origin, authorize=self.authorize_participant)
        self.assertEqual('HUMAN_APPROVAL_REQUIRED', result['status'])
        run = self.state()['runs']['run-test']
        self.assertEqual('reviewer', run['coordinator_nomination'])
        self.assertIsNone(run.get('coordinator'))
        self.assertEqual(profiles, self.room['profiles'])
        before = self.ledger.snapshot()
        self.error('STALE_RUN_GENERATION', lambda: self.admission.nominate_coordinator(
            'stale', 'run-test', 2, 'reviewer', origin=self.origin, authorize=self.authorize_participant))
        self.error('FORBIDDEN', lambda: self.admission.nominate_coordinator(
            'wrong-actor', 'run-test', 1, 'reviewer', origin=replace(self.origin, actor_id='alice'),
            authorize=self.authorize_participant))
        self.error('COORDINATOR_UNAVAILABLE', lambda: self.admission.nominate_coordinator(
            'outsider', 'run-test', 1, 'foreign', origin=self.origin, authorize=self.authorize_participant))
        self.assertEqual(before, self.ledger.snapshot())

    def test_loss_and_expiry_return_to_peer_attention_without_freezing_run(self):
        self.seed_connected()
        self.appoint()
        self.hub.observe(self.connections['builder'], Readiness.LOST)
        row = self.state()['runs']['run-test']
        self.assertEqual(('ACTIVE', None, 'COORDINATOR_LOST'),
                         (row['status'], row['coordinator'], row['coordinator_attention']))
        self.assertEqual(2, row['control_revision'])
        with patch('uas.run_coordination.time.time', return_value=1000):
            self.appoint(operation='appoint-reviewer', revision=2, participant='reviewer', ttl_seconds=1)
        with patch('uas.run_coordination.time.time', return_value=1002):
            result = self.admission.reconcile_coordinator('expired', 'run-test')
        self.assertEqual(('peer', 'COORDINATOR_BOUND_EXPIRED'), (result['mode'], result['attention']))
        self.assertEqual('ACTIVE', self.state()['runs']['run-test']['status'])
        self.assertIsNone(self.state()['runs']['run-test']['coordinator'])

    def test_replaced_or_revoked_incarnation_cannot_keep_coordination(self):
        self.seed_connected()
        self.appoint()
        handle = self.controller.handles['builder']
        self.controller.handles['builder'] = SimpleNamespace(
            badge=SimpleNamespace(incarnation_id='replacement'))
        result = self.admission.reconcile_coordinator('lost-owner', 'run-test')
        self.assertEqual(('peer', 'COORDINATOR_LOST'), (result['mode'], result['attention']))
        self.controller.handles['builder'] = handle
        revision = self.state()['runs']['run-test']['control_revision']
        self.appoint(operation='appoint-again', revision=revision)
        self.owned_authorized = False
        result = self.admission.reconcile_coordinator('revoked-owner', 'run-test')
        self.assertEqual(('peer', 'COORDINATOR_LOST'), (result['mode'], result['attention']))
        self.assertEqual('ACTIVE', self.state()['runs']['run-test']['status'])

    def test_request_priority_is_bounded_and_never_forces_acceptance(self):
        self.seed_connected()
        self.request('reviewer', 'ordinary-first')
        self.appoint(request_budget=1)
        self.request('builder', 'coordinator-second')
        self.request('reviewer', 'ordinary-third')
        self.request('builder', 'over-budget-fourth')
        pending = self.hub._pending(self.connections['observer'])
        self.assertEqual(['coordinator-second', 'ordinary-first', 'ordinary-third', 'over-budget-fourth'],
                         [item['id'] for item in pending])
        self.assertTrue(all(item['status'] == 'QUEUED' for item in pending))
        self.assertEqual(1, self.state()['runs']['run-test']['coordinator']['requests_used'])
        self.error('INVALID_TRANSITION', lambda: self.hub.submit(self.connections['observer'],
            RequestCommand('cannot-force', 'run-test', 1, 'coordinator-second', 'accept')))
        before = self.ledger.snapshot()
        self.error('FORBIDDEN', lambda: self.admission.force_stop('not-human', 'run-test', 1, 1,
            'coordinator-wants-stop', human=replace(self.origin, participant_id='builder', actor_id='alice')))
        self.assertEqual(before, self.ledger.snapshot())

