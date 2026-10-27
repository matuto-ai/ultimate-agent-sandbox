"""Human-appointed, expiring peer coordination; never a privilege elevation."""
from copy import deepcopy
import time

from .context import MAX_CONTEXT_GENERATION
from .ledger import Command, Event, LedgerError, Origin, Transition, _token
from .peer import FixturePeerHub


def current_coordinator(run, now=None):
    value = run.get('coordinator')
    return (value if value and run['status'] != 'CLOSED'
            and value['generation'] == run['generation']
            and value['expires_at'] > (time.time() if now is None else now) else None)


class RunCoordination:
    def appoint_coordinator(self, operation_id, run_id, generation, revision, participant_id,
                            *, human, ttl_seconds=300, request_budget=8):
        if participant_id is not None:
            _token(participant_id)
        if (type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600
                or type(request_budget) is not int or not 1 <= request_budget <= 16):
            raise LedgerError('INVALID_COORDINATOR_BOUND')
        command = Command(operation_id, 'run.human-coordinator', _token(run_id), generation,
            {'expected_revision': revision, 'participant_id': participant_id,
             'ttl_seconds': ttl_seconds, 'request_budget': request_budget})
        with self.supervisor._locked():
            def decide(state, _):
                row = self._run_revision(state, run_id, generation, revision)
                if participant_id is not None:
                    configured = next((s for s in self.room['seats'] if s['participant'] == participant_id), None)
                    context = state['fixture_context']['participants'].get(participant_id)
                    handle = self.controller.handles.get(participant_id)
                    if (configured is None or context is None or handle is None
                            or context['status'] != 'READY'
                            or (context['bound_run'] or context['reserved_run']) != {'run_id': run_id, 'generation': generation}
                            or handle.badge.actor_id != configured['actor']):
                        raise LedgerError('COORDINATOR_UNAVAILABLE')
                    self._authority(handle)
                    row['coordinator'] = {'participant_id': participant_id,
                        'incarnation_id': handle.badge.incarnation_id, 'generation': generation,
                        'expires_at': int(time.time()) + ttl_seconds, 'request_budget': request_budget,
                        'requests_used': 0, 'appointment': operation_id}
                else:
                    row['coordinator'] = None
                row.update(control_revision=revision + 1, coordinator_attention=None)
                FixturePeerHub._reserve_capacity(state)
                result = {'run_id': run_id, 'generation': generation,
                          'control_revision': revision + 1, 'coordinator': deepcopy(row['coordinator'])}
                return Transition(state, (Event('run.coordinator-appointed', result),), result)
            return self._apply(command, human, decide)['result']

    def reconcile_coordinator(self, operation_id, run_id):
        """Trusted owner observation, never a Participant-selectable command.

        Expiry/loss returns to ordinary peer mode. It does not pause the Run or
        cancel Requests; already accepted work retains its ordinary lifecycle.
        """
        origin = Origin('run-hub', 'run-hub', 'run-owner', 'run-owner-v1', ('run-owner',))
        command = Command(operation_id, 'run.coordinator-reconcile', _token(run_id), None, {})
        with self.supervisor._locked():
            self.controller._room()
            def decide(state, _):
                row = state.get('runs', {}).get(run_id)
                if row is None:
                    raise LedgerError('UNKNOWN_RUN')
                coordinator = row.get('coordinator')
                reason = None
                if coordinator:
                    handle = self.controller.handles.get(coordinator['participant_id'])
                    if current_coordinator(row) is None:
                        reason = 'COORDINATOR_BOUND_EXPIRED'
                    elif handle is None or handle.badge.incarnation_id != coordinator['incarnation_id']:
                        reason = 'COORDINATOR_LOST'
                    else:
                        try:
                            self._authority(handle)
                        except LedgerError:
                            reason = 'COORDINATOR_LOST'
                if reason:
                    row.update(coordinator=None, coordinator_attention=reason)
                    row['control_revision'] = min(MAX_CONTEXT_GENERATION, row.get('control_revision', 0) + 1)
                FixturePeerHub._reserve_capacity(state)
                result = {'run_id': run_id, 'mode': 'peer' if row.get('coordinator') is None else 'coordinator',
                          'attention': row.get('coordinator_attention')}
                return Transition(state, (Event('run.coordinator-reconciled', result),), result)
            return self.ledger.apply(command, origin, authorize=lambda *_: True, decide=decide)['result']

    def nominate_coordinator(self, operation_id, run_id, generation, participant_id, *, origin, authorize):
        """A suggestion only, including handoff; never appoints the nominee."""
        command = Command(operation_id, 'run.coordinator-nominate', _token(run_id), generation,
                          {'participant_id': _token(participant_id)})
        with self.supervisor._locked():
            def decide(state, _):
                row = state.get('runs', {}).get(run_id)
                if not row or row['status'] == 'CLOSED' or row['generation'] != generation:
                    raise LedgerError('STALE_RUN_GENERATION')
                context = state['fixture_context']['participants'].get(origin.participant_id)
                if (not context or (context['bound_run'] or context['reserved_run']) !=
                        {'run_id': run_id, 'generation': generation}):
                    raise LedgerError('FORBIDDEN')
                if not any(s['participant'] == participant_id for s in self.room['seats']):
                    raise LedgerError('COORDINATOR_UNAVAILABLE')
                # Bounded latest observation; history remains in the ledger.
                row['coordinator_nomination'] = participant_id
                FixturePeerHub._reserve_capacity(state)
                result = {'run_id': run_id, 'nominee': participant_id, 'status': 'HUMAN_APPROVAL_REQUIRED'}
                return Transition(state, (Event('run.coordinator-nominated', result),), result)
            return self.ledger.apply(command, origin,
                authorize=lambda *_: self._participant_authorized(origin, authorize), decide=decide)['result']
