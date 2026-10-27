"""Run Request/proposal rules at the pure ledger seam, not native identity proof."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from run_control_support import RunControlCase
from uas.ledger import LedgerError, _json
from uas.peer import Readiness


class RunRequestTests(RunControlCase):
    def test_replaced_implementer_cannot_publish_stale_native_checkpoint_proof(self):
        self.request()
        with self.synthetic_activation() as run:
            handle = self.controller.handles['builder']
            def prove_then_replace():
                self.controller.handles['builder'] = SimpleNamespace()
                return {'fixture': 'old-owned-proof'}
            handle.connection.receiver.prove_fresh_context = prove_then_replace
            def current_owner(candidate):
                if self.controller.handles.get('builder') is not candidate:
                    raise LedgerError('AUTHORITY_REVOKED')
                return True
            with patch.object(self.admission, '_authority', current_owner):
                self.error('AUTHORITY_REVOKED', self.open_requested)
        self.assertEqual('UNUSED', self.state()['run_requests']['request']['status'])
        self.assertEqual({}, self.state()['runs'])
        self.assertEqual({}, self.state()['peer_traffic']['traffic'])

    def test_new_exact_target_reserves_native_reset_without_relabelling_closed_context(self):
        self.seed_run(status='CLOSED', native_stop={'status': 'VERIFIED'})
        self.seed(lambda state: (state['run_admissions']['run-test'].update(status='CLOSED'),
            state['fixture_context']['runs']['run-test'].update(status='CLOSED')))
        old = deepcopy(self.state()['fixture_context']['participants']['builder'])
        run, _ = self.admission._prepare('new-target', 3, 'builder', self.human)
        pending = self.state()['run_admissions'][run]
        self.assertEqual({'run_id': 'run-test', 'generation': 1}, pending['preceding_run'])
        self.assertEqual(2, pending['context_generation'])
        self.assertEqual(old, self.state()['fixture_context']['participants']['builder'])
        self.assertEqual({}, self.state()['peer_traffic']['traffic'])

    def test_unverified_preceding_stop_cannot_retarget_or_consume_authority(self):
        self.seed_run(status='CLOSED')
        self.seed(lambda state: state['run_admissions']['run-test'].update(status='CLOSED'))
        before = self.ledger.snapshot()
        self.error('NATIVE_STOP_UNVERIFIED', lambda: self.admission._prepare(
            'unsafe-retarget', 3, 'builder', self.human))
        self.assertEqual(before, self.ledger.snapshot())

    def test_malformed_participant_targets_are_bounded_refusals(self):
        before = self.ledger.snapshot()
        for value in ([], {}, True, None, 1):
            self.error('INVALID_RUN_REQUEST', lambda: self.admission.submit(
                {'id': 'bad-target', 'kind': 'run-propose',
                 'payload': {'issue_number': 1, 'participant_id': value}},
                origin=self.origin, authorize=self.authorize_participant))
            self.error('INVALID_RUN_REQUEST', lambda: self.admission._prepare(
                'bad-direct', 1, value, self.human))
        self.assertEqual(before, self.ledger.snapshot())

    def request(self, operation='request', **changes):
        values = {'issue_number': 1, 'requester_id': 'reviewer', 'participant_id': 'builder'}
        values.update(changes)
        return self.admission.issue_request(operation, **values, human=self.human)

    def propose(self, operation='proposal', **changes):
        values = {'issue_number': 1, 'participant_id': 'builder', 'origin': self.origin,
                  'authorize': self.authorize_participant}
        values.update(changes)
        return self.admission.propose(operation, **values)

    def open_requested(self, operation='open-request', request_id='request', **changes):
        values = {'origin': self.origin, 'authorize': self.authorize_participant}
        values.update(changes)
        return self.admission.open_requested(operation, request_id, **values)

    def prepare(self, operation='open-request', request_id='request'):
        row = self.state()['run_requests'][request_id]
        run = self.admission.run_id(operation)
        return self.admission._prepare(operation, row['issue_number'], row['participant_id'],
            self.origin, request_id=request_id,
            authorize=lambda *_: self.admission._request_authority(
                request_id, run, self.origin, self.authorize_participant))

    @contextmanager
    def synthetic_activation(self, operation='open-request', request_id='request', *, read_hook=None):
        """Explicit synthetic external seams; real admission/activation transaction.

        No actual process, Git checkout or provider exists. These substitutions
        test durable state/atomicity only; hosted fixtures own runtime evidence.
        """
        run, _ = self.prepare(operation, request_id)
        scope = self.hub.contexts.scope('builder')
        native = SimpleNamespace(scope=scope, observe=lambda: Readiness.SAFE,
                                 prove_fresh_context=lambda: {'fixture': 'synthetic'})
        connection = self.hub.connect('synthetic-connect-' + operation, 'builder',
                                      'synthetic-implementer', native)
        handle = SimpleNamespace(connection=connection, process=SimpleNamespace(pid=999_999))
        self.controller.handles['builder'] = handle
        self.controller._alive = lambda _handle: True
        slot = {'run': run, 'participant': 'builder', 'slot': 'primary',
                'path': str(self.root / 'synthetic-checkout'), 'phase': 'ready', 'reason': 'ACTIVE',
                'base': 'a' * 40, 'observed_head': 'a' * 40, 'observed_dirty': False}
        def observed_slot(_run, participant, *, authorize=None):
            self.assertEqual((run, 'builder'), (_run, participant))
            if authorize is not None:
                self.assertTrue(authorize())
            return deepcopy(slot)
        def observed_read(_run, number, _handle, attempt):
            self.assertEqual((run, 1, handle), (_run, number, _handle))
            if read_hook is not None:
                read_hook()
            return {'operation_id': 'synthetic-forge-' + attempt, 'observation': {
                'status': 'OK', 'completeness': 'complete',
                'issue': {'number': 1, 'id': 1001, 'state': 'open', 'assignees': [{'id': 41}]},
                'dependencies': [{'state': 'closed'}],
                'delivery_class': {'status': 'known', 'value': 'bounded'}}}, True
        def observed_path(*args):
            # The /proc comparison is an explicitly substituted observation,
            # never a read or process probe on this local executor.
            return Path(slot['path']) if args and args[0] == '/proc' else Path(*args)
        with patch.object(self.admission, '_slot', observed_slot), \
             patch.object(self.admission, '_fresh_read', observed_read), \
             patch.object(self.admission, '_authority', lambda _handle: True), \
             patch('uas.run_admission.Path', observed_path):
            yield run

    def test_human_request_is_exact_durable_unused_and_idempotent(self):
        row = self.request()
        self.assertEqual(('alpha', 'example/alpha', 1, 'reviewer', 'builder'),
            tuple(row[k] for k in ('project_id', 'repository', 'issue_number', 'requester_id', 'participant_id')))
        self.assertEqual('UNUSED', row['status'])
        self.assertIsNone(row['reserved_run'])
        self.assertIsNone(row['consumed_run'])
        self.assertEqual(self.human.canonical(), row['human_origin'])
        before = self.ledger.snapshot()
        self.assertEqual(row, self.request())
        self.error('ID_CONFLICT', lambda: self.request(issue_number=2))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertNotIn('runs', self.state())
        self.assertEqual({}, self.state()['peer_traffic']['traffic'])
        self.authorized = False
        self.error('FORBIDDEN', self.request)

    def test_request_requires_exact_selectors_capable_requester_and_human_authority(self):
        before = self.ledger.snapshot()
        for value in (True, 0, -1, '1', '*', 'label:ready', [1], None, 10_000_000_000):
            self.error('INVALID_RUN_REQUEST', lambda: self.request(issue_number=value))
        self.error('INVALID_RUN_REQUEST', lambda: self.request(participant_id='foreign'))
        for requester in ('builder', 'foreign'):
            self.error('RUN_REQUEST_CAPABILITY_REQUIRED', lambda: self.request(requester_id=requester))
        self.error('FORBIDDEN', lambda: self.admission.issue_request('not-human', 1, 'reviewer',
            'builder', human=self.origin))
        self.assertEqual(before, self.ledger.snapshot())

    def test_proposal_is_data_until_exact_human_approval(self):
        proposal = self.propose()
        content = {key: proposal[key] for key in ('project_id', 'repository', 'issue_number',
                   'participant_id', 'requester_id', 'proposal_id', 'origin')}
        self.assertEqual(hashlib.sha256(_json(content).encode()).hexdigest(), proposal['digest'])
        self.assertEqual('PROPOSED', proposal['status'])
        self.assertNotIn('run_requests', self.state())
        before = self.ledger.snapshot()
        self.assertEqual(proposal, self.propose())
        self.error('EXACT_PROPOSAL_REQUIRED', lambda: self.admission.approve_proposal(
            'approve', 'proposal', '0' * 64, human=self.human))
        self.error('EXACT_PROPOSAL_REQUIRED', lambda: self.admission.approve_proposal(
            'approve', 'unknown-proposal', proposal['digest'], human=self.human))
        self.error('FORBIDDEN', lambda: self.admission.approve_proposal(
            'approve', 'proposal', proposal['digest'], human=self.origin))
        self.assertEqual(before, self.ledger.snapshot())
        grant = self.admission.approve_proposal('approve', 'proposal', proposal['digest'], human=self.human)
        self.assertEqual(('proposal', proposal['digest'], 'UNUSED'),
                         (grant['proposal_id'], grant['proposal_digest'], grant['status']))
        self.assertEqual('APPROVED', self.state()['run_proposals']['proposal']['status'])
        self.assertEqual(grant, self.admission.approve_proposal(
            'approve', 'proposal', proposal['digest'], human=self.human))
        self.error('PROPOSAL_ALREADY_APPROVED', lambda: self.admission.approve_proposal(
            'second-approval', 'proposal', proposal['digest'], human=self.human))
        self.assertEqual(1, len(self.state()['run_requests']))
        self.assertNotIn('runs', self.state())

    def test_proposal_fresh_process_authority_and_current_room_identity_are_required(self):
        before = self.ledger.snapshot()
        self.participant_authorized = False
        self.error('FORBIDDEN', self.propose)
        self.participant_authorized = True
        for origin in (replace(self.origin, actor_id='alice'),
                       replace(self.origin, participant_id='foreign'),
                       replace(self.origin, capabilities=('can-open-requested-run',)), None, {}):
            self.error('FORBIDDEN', lambda: self.propose(origin=origin))
        self.assertEqual(before, self.ledger.snapshot())
        proposal = self.propose()
        self.participant_authorized = False
        self.error('FORBIDDEN', self.propose)
        self.assertEqual(proposal, self.state()['run_proposals']['proposal'])

    def test_envelope_has_no_selector_scheduler_batch_human_or_policy_authority(self):
        before = self.ledger.snapshot()
        base = {'id': 'envelope', 'kind': 'run-propose',
                'payload': {'issue_number': 1, 'participant_id': 'builder'}}
        variants = [dict(base, origin=self.human.canonical()), dict(base, project_id='beta'),
            dict(base, kind='run-open'), dict(base, kind='run-schedule'),
            dict(base, kind='run-poll'), dict(base, kind='run-batch'),
            dict(base, payload={**base['payload'], 'policy': {'version': 999}}),
            dict(base, payload={**base['payload'], 'human': True}),
            dict(base, payload={**base['payload'], 'repository': 'example/beta'})]
        for envelope in variants:
            self.error('INVALID_RUN_ENVELOPE', lambda: self.admission.submit(
                envelope, origin=self.origin, authorize=self.authorize_participant))
        self.assertEqual(before, self.ledger.snapshot())

    def test_requested_open_requires_grant_requester_and_both_capability_sources(self):
        self.request()
        before = self.ledger.snapshot()
        self.error('FORBIDDEN_RUN_REQUEST', lambda: self.open_requested(request_id='missing'))
        self.participant_authorized = False
        self.error('FORBIDDEN_RUN_REQUEST', self.open_requested)
        self.participant_authorized = True
        for origin in (replace(self.origin, capabilities=('peer-traffic',)),
                       replace(self.origin, actor_id='alice'), self.human):
            self.error('FORBIDDEN_RUN_REQUEST', lambda: self.open_requested(origin=origin))
        next(p for p in self.room['profiles'] if p['id'] == 'reviewer')['capabilities'].remove('can-open-requested-run')
        self.error('FORBIDDEN_RUN_REQUEST', self.open_requested)
        self.assertEqual(before, self.ledger.snapshot())

    def test_cross_project_or_repository_grant_and_proposal_cannot_activate(self):
        self.request()
        proposal = self.propose()
        before = self.ledger.snapshot()
        self.room['project']['id'] = 'beta'
        self.error('FORBIDDEN_RUN_REQUEST', self.open_requested)
        self.error('PROJECT_MISMATCH', lambda: self.admission.approve_proposal(
            'approve', 'proposal', proposal['digest'], human=self.human))
        self.room['project']['id'] = 'alpha'
        self.broker.binding.repository = 'example/beta'
        self.error('FORBIDDEN_RUN_REQUEST', self.open_requested)
        self.error('PROJECT_MISMATCH', lambda: self.admission.approve_proposal(
            'approve', 'proposal', proposal['digest'], human=self.human))
        self.assertEqual(before, self.ledger.snapshot())

    def test_reservation_is_not_consumption_and_competing_operation_cannot_reuse_request(self):
        self.request()
        run, command = self.prepare()
        self.assertEqual('run.participant-open', command.kind)
        row = self.state()['run_requests']['request']
        self.assertEqual(('UNUSED', run, None), (row['status'], row['reserved_run'], row['consumed_run']))
        self.assertFalse(self.state()['run_admissions'][run]['authorization_consumed'])
        before = self.ledger.snapshot()
        self.assertEqual((run, command), self.prepare())
        self.error('FORBIDDEN_RUN_REQUEST', lambda: self.open_requested(operation='other-open'))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual({}, self.state()['peer_traffic']['traffic'])

    def test_capacity_failure_consumes_no_request_reserves_nothing_and_queues_no_retry(self):
        self.request()
        def fill(state):
            state['run_admissions'] = {'full-' + str(i): {'status': 'CLOSED'} for i in range(8)}
        self.seed(fill)
        before = self.ledger.snapshot()
        self.error('RUN_CAPACITY', self.open_requested)
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual('UNUSED', self.state()['run_requests']['request']['status'])
        self.assertIsNone(self.state()['run_requests']['request']['reserved_run'])
        self.assertEqual({}, self.state()['peer_traffic']['traffic'])

    def test_revocation_fences_pending_request_and_never_becomes_automatic_retry(self):
        self.request()
        run, _ = self.prepare()
        revoked = self.admission.revoke_request('revoke', 'request', 'human-withdrew', human=self.human)
        self.assertEqual(('REVOKED', run, None),
                         (revoked['status'], revoked['reserved_run'], revoked['consumed_run']))
        before = self.ledger.snapshot()
        self.assertEqual(revoked, self.admission.revoke_request(
            'revoke', 'request', 'human-withdrew', human=self.human))
        self.error('FORBIDDEN_RUN_REQUEST', self.open_requested)
        self.error('FORBIDDEN', self.prepare)
        self.error('RUN_REQUEST_NOT_UNUSED', lambda: self.admission.revoke_request(
            'another-revoke', 'request', 'human-withdrew', human=self.human))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual('PREPARING', self.state()['run_admissions'][run]['status'])
        self.assertEqual({}, self.state()['peer_traffic']['traffic'])

    def test_activation_consumes_one_request_and_refreshes_policy_atomically(self):
        self.request()
        with self.synthetic_activation() as run:
            self.room['policies'][0]['version'] = 2
            row = self.open_requested()
            self.assertEqual(('ACTIVE', run, 'request', 2),
                (row['status'], row['run_id'], row['run_request'], row['policy']['version']))
            grant = self.state()['run_requests']['request']
            self.assertEqual(('CONSUMED', run), (grant['status'], grant['consumed_run']))
            before = self.ledger.snapshot()
            self.assertEqual(row, self.open_requested())
            self.error('FORBIDDEN_RUN_REQUEST', lambda: self.open_requested(operation='another-open'))
            self.assertEqual(before, self.ledger.snapshot())
            self.assertEqual(1, len(self.state()['peer_traffic']['traffic']))
            self.assertIn('"version":2', next(iter(self.state()['peer_traffic']['traffic'].values()))['text'])
            self.error('RUN_REQUEST_NOT_UNUSED', lambda: self.admission.revoke_request(
                'too-late', 'request', 'stop', human=self.human))

    def test_activation_commit_failure_rolls_back_consumption_and_exact_retry_recovers(self):
        self.request()
        with self.synthetic_activation() as run:
            apply = self.admission._apply
            def fail_terminal(command, origin, decide, **kwargs):
                if command.kind == 'run.admission-attempt-result':
                    with patch.object(self.ledger, '_commit', side_effect=LedgerError('STORAGE_ERROR')):
                        return apply(command, origin, decide, **kwargs)
                return apply(command, origin, decide, **kwargs)
            with patch.object(self.admission, '_apply', fail_terminal):
                self.error('STORAGE_ERROR', self.open_requested)
            state = self.state()
            self.assertEqual('UNUSED', state['run_requests']['request']['status'])
            self.assertIsNone(state['run_requests']['request']['consumed_run'])
            self.assertFalse(state['run_admissions'][run]['authorization_consumed'])
            self.assertEqual({}, state['runs'])
            self.assertEqual({}, state['peer_traffic']['traffic'])
            row = self.open_requested()
            self.assertEqual('ACTIVE', row['status'])
            self.assertEqual('CONSUMED', self.state()['run_requests']['request']['status'])
            self.assertEqual(1, len(self.state()['peer_traffic']['traffic']))

    def test_revocation_during_fresh_read_cannot_commit_or_inject_work(self):
        self.request()
        def revoke():
            self.admission.revoke_request('revoke-mid-read', 'request', 'human-withdrew', human=self.human)
        with self.synthetic_activation(read_hook=revoke) as run:
            self.error('FORBIDDEN', self.open_requested)
            state = self.state()
            self.assertEqual('REVOKED', state['run_requests']['request']['status'])
            self.assertFalse(state['run_admissions'][run]['authorization_consumed'])
            self.assertEqual({}, state['runs'])
            self.assertEqual({}, state['peer_traffic']['traffic'])

    def test_grant_capacity_failure_does_not_mark_proposal_approved(self):
        for index in range(32):
            self.request('request-' + str(index))
        proposal = self.propose()
        before = self.ledger.snapshot()
        self.error('RUN_REQUEST_CAPACITY', lambda: self.request('one-too-many'))
        self.error('RUN_REQUEST_CAPACITY', lambda: self.admission.approve_proposal(
            'approve-no-capacity', 'proposal', proposal['digest'], human=self.human))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual('PROPOSED', self.state()['run_proposals']['proposal']['status'])
        self.assertTrue(all(row['status'] == 'UNUSED' for row in self.state()['run_requests'].values()))

    def test_proposal_capacity_is_bounded_without_any_run_or_automatic_intake(self):
        for index in range(32):
            self.propose('proposal-' + str(index))
        before = self.ledger.snapshot()
        self.error('RUN_PROPOSAL_CAPACITY', lambda: self.propose('one-too-many'))
        self.assertEqual(before, self.ledger.snapshot())
        self.assertNotIn('run_requests', self.state())
        self.assertNotIn('runs', self.state())
        self.assertEqual({}, self.state()['peer_traffic']['traffic'])

    def test_approval_lost_ack_recovers_one_grant_and_preserves_human_identity(self):
        proposal = self.propose()
        commit = self.ledger._commit
        def commit_then_lose():
            commit()
            raise LedgerError('STORAGE_ERROR')
        def approve(human=None):
            return self.admission.approve_proposal('approve', 'proposal', proposal['digest'],
                                                  human=human or self.human)
        with patch.object(self.ledger, '_commit', commit_then_lose):
            self.error('STORAGE_ERROR', approve)
        self.assertEqual('APPROVED', self.state()['run_proposals']['proposal']['status'])
        before = self.ledger.snapshot()
        row = approve()
        self.assertEqual('approve', row['request_id'])
        self.assertEqual(1, len(self.state()['run_requests']))
        self.error('ID_CONFLICT', lambda: approve(replace(self.human, actor_id='other-human')))
        self.assertEqual(before, self.ledger.snapshot())

