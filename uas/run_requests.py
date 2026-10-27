"""Exact authenticated human Run grants; Participant proposals are only data.

The controller supplies the process Origin and fresh authority callback. Neither
an envelope nor a stored proposal may supply a human identity or authorization.
"""
from copy import deepcopy
import hashlib

from .ledger import Command, Event, LedgerError, Origin, Transition, _json, _token
from .peer import FixturePeerHub


class RunRequests:
    def _participant_authorized(self, origin, authorize, capability=None):
        if type(origin) is not Origin or not callable(authorize) or authorize() is not True:
            return False
        seat = next((s for s in self.room['seats'] if s['participant'] == origin.participant_id), None)
        profile = next((p for p in self.room['profiles'] if seat and p['id'] == seat['profile']), None)
        return (seat is not None and profile is not None and seat['actor'] == origin.actor_id
                and 'peer-traffic' in origin.capabilities
                and (capability is None or capability in origin.capabilities
                     and capability in profile['capabilities']))

    def _exact_target(self, number, participant):
        if (type(number) is not int or not 1 <= number <= 9_999_999_999
                or type(participant) is not str or participant not in self.seats):
            raise LedgerError('INVALID_RUN_REQUEST')
        return {'project_id': self.room['project']['id'], 'repository': self.broker.binding.repository,
                'issue_number': number, 'participant_id': participant}

    def issue_request(self, operation_id, issue_number, requester_id, participant_id, *, human):
        payload = {**self._exact_target(issue_number, participant_id), 'requester_id': _token(requester_id)}
        command = Command(operation_id, 'run.human-request', payload['project_id'], None, payload)
        def decide(state, _):
            return self._grant(state, command, human)
        return self._apply(command, human, decide)['result']

    def _grant(self, state, command, human, proposal=None):
        payload = command.payload
        requester = next((s for s in self.room['seats'] if s['participant'] == payload['requester_id']), None)
        profile = next((p for p in self.room['profiles'] if requester and p['id'] == requester['profile']), None)
        if profile is None or 'can-open-requested-run' not in profile['capabilities']:
            raise LedgerError('RUN_REQUEST_CAPABILITY_REQUIRED')
        rows = state.setdefault('run_requests', {})
        if len(rows) >= 32:
            raise LedgerError('RUN_REQUEST_CAPACITY')
        row = {**deepcopy(payload), 'request_id': command.id, 'status': 'UNUSED',
               'reserved_run': None, 'consumed_run': None, 'reason': None,
               'human_origin': human.canonical(), 'human_operation': command.id,
               'proposal_id': None if proposal is None else proposal['proposal_id'],
               'proposal_digest': None if proposal is None else proposal['digest']}
        rows[command.id] = row
        if proposal is not None:
            proposal.update(status='APPROVED', request_id=command.id)
        FixturePeerHub._reserve_capacity(state)
        return Transition(state, (Event('run.request-authorized', row),), deepcopy(row))

    def propose(self, operation_id, issue_number, participant_id, *, origin, authorize):
        if type(origin) is not Origin:
            raise LedgerError('FORBIDDEN')
        payload = {**self._exact_target(issue_number, participant_id), 'requester_id': origin.participant_id}
        command = Command(operation_id, 'run.participant-propose', payload['project_id'], None, payload)
        def decide(state, _):
            proposals = state.setdefault('run_proposals', {})
            if len(proposals) >= 32:
                raise LedgerError('RUN_PROPOSAL_CAPACITY')
            content = {**payload, 'proposal_id': operation_id, 'origin': origin.canonical()}
            row = {**content, 'digest': hashlib.sha256(_json(content).encode()).hexdigest(),
                   'status': 'PROPOSED', 'request_id': None}
            proposals[operation_id] = row
            FixturePeerHub._reserve_capacity(state)
            return Transition(state, (Event('run.proposed', row),), deepcopy(row))
        with self.supervisor._locked():
            return self.ledger.apply(command, origin,
                authorize=lambda *_: self._participant_authorized(origin, authorize), decide=decide)['result']

    def approve_proposal(self, operation_id, proposal_id, digest, *, human):
        _token(proposal_id)
        _token(digest)
        command = Command(operation_id, 'run.human-approve-proposal', self.room['project']['id'], None,
                          {'proposal_id': proposal_id, 'digest': digest})
        def decide(state, _):
            proposal = state.get('run_proposals', {}).get(proposal_id)
            if proposal is None or proposal['digest'] != digest:
                raise LedgerError('EXACT_PROPOSAL_REQUIRED')
            if proposal['status'] != 'PROPOSED':
                raise LedgerError('PROPOSAL_ALREADY_APPROVED')
            target = self._exact_target(proposal['issue_number'], proposal['participant_id'])
            if any(proposal[key] != value for key, value in target.items()):
                raise LedgerError('PROJECT_MISMATCH')
            grant = Command(operation_id, command.kind, command.target, None,
                            {**target, 'requester_id': proposal['requester_id']})
            return self._grant(state, grant, human, proposal)
        return self._apply(command, human, decide)['result']

    def revoke_request(self, operation_id, request_id, reason, *, human):
        command = Command(operation_id, 'run.human-revoke-request', _token(request_id), None,
                          {'reason': _token(reason)})
        def decide(state, _):
            row = state.get('run_requests', {}).get(request_id)
            if row is None:
                raise LedgerError('UNKNOWN_RUN_REQUEST')
            if row['status'] != 'UNUSED':
                raise LedgerError('RUN_REQUEST_NOT_UNUSED')
            row.update(status='REVOKED', reason=reason)
            FixturePeerHub._reserve_capacity(state)
            return Transition(state, (Event('run.request-revoked', deepcopy(row)),), deepcopy(row))
        return self._apply(command, human, decide)['result']

    def _request_authority(self, request_id, run, origin, authorize, state=None):
        if not self._participant_authorized(origin, authorize, 'can-open-requested-run'):
            return False
        state = self.ledger.snapshot()['state'] if state is None else state
        row = state.get('run_requests', {}).get(request_id)
        return (row is not None and row['requester_id'] == origin.participant_id
                and row['project_id'] == self.room['project']['id']
                and row['repository'] == self.broker.binding.repository
                and row['reserved_run'] in (None, run)
                and (row['status'] == 'UNUSED'
                     or row['status'] == 'CONSUMED' and row['consumed_run'] == run))

    def open_requested(self, operation_id, request_id, *, origin, authorize, attempt_id=None):
        _token(request_id)
        run = self.run_id(operation_id)
        with self.supervisor._locked():
            if not self._request_authority(request_id, run, origin, authorize):
                raise LedgerError('FORBIDDEN_RUN_REQUEST')
            row = self.ledger.snapshot()['state']['run_requests'][request_id]
        return self._open(operation_id, row['issue_number'], row['participant_id'], origin,
            request_id=request_id, attempt_id=attempt_id,
            authorize=lambda *_: self._request_authority(request_id, run, origin, authorize))

    def submit(self, envelope, *, origin, authorize):
        """Strict controller dispatch. No arbitrary origin, policy, selectors or batch."""
        if type(envelope) is not dict or set(envelope) != {'id', 'kind', 'payload'} or type(envelope['payload']) is not dict:
            raise LedgerError('INVALID_RUN_ENVELOPE')
        p = envelope['payload']
        if envelope['kind'] == 'run-propose' and set(p) == {'issue_number', 'participant_id'}:
            return self.propose(envelope['id'], **p, origin=origin, authorize=authorize)
        if envelope['kind'] == 'run-open-requested' and set(p) == {'request_id', 'attempt_id'}:
            return self.open_requested(envelope['id'], **p, origin=origin, authorize=authorize)
        if envelope['kind'] == 'run-coordinator-nominate' and set(p) == {'run_id', 'generation', 'participant_id'}:
            return self.nominate_coordinator(envelope['id'], **p, origin=origin, authorize=authorize)
        raise LedgerError('INVALID_RUN_ENVELOPE')
