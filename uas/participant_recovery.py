"""Participant-owner failed-restoration attention and human replacement intent.

Selection is not a process launch, context reset, work reassignment or review
appointment. Those existing owners must consume/revalidate the exact intent;
the old Participant/Actor history and current Work Requests remain unchanged.
"""
from contextlib import nullcontext
from copy import deepcopy
import hashlib

from .ledger import Command, Event, LedgerError, Origin, Transition, _json, _token


def _digest(value): return hashlib.sha256(_json(value).encode()).hexdigest()


class ParticipantRecovery:
    """Mixin on the actual lifecycle owner, using its existing Room ledger."""
    def _record_restore_failure(self, participant, code):
        # Called only by the native restore wrappers after an actual failure.
        # Caller-supplied Manager text cannot enter this observation seam.
        with self.supervisor._locked():
            room = self._room()
            self.supervisor._allowed('participant-restore', room)
            document = self._read(); record = document['seats'].get(participant)
            if not record or record['status'] in {'active', 'starting', 'closed'}: return
            state = self.hub.ledger.snapshot()['state']
            context = state.get('fixture_context', {}).get('participants', {}).get(participant)
            scope = (context or {}).get('bound_run') or (context or {}).get('reserved_run')
            run = state.get('runs', {}).get((scope or {}).get('run_id'))
            if not run or run['status'] == 'CLOSED' or run['generation'] != scope['generation']: return
            row = {'participant_id': participant, 'actor_id': record['seat']['actor_id'],
                'instance_id': self.instance, 'controller_id': self.controller_id,
                'incarnation_id': record['incarnation_id'], 'epoch': record['epoch'],
                'run_id': scope['run_id'], 'generation': scope['generation'],
                'context_generation': context['context_generation'], 'reason': code,
                'selection': None}
            operation = 'restore-attention-' + _digest(row)
            origin = Origin('participant-supervisor', 'participant-supervisor', self.controller_id,
                            'participant-recovery-v1', ('participant-recovery',))
            def decide(current, _):
                fresh = current.get('fixture_context', {}).get('participants', {}).get(participant)
                fresh_run = current.get('runs', {}).get(row['run_id'])
                if (fresh != context or not fresh_run or fresh_run['status'] == 'CLOSED'
                        or fresh_run['generation'] != row['generation']):
                    raise LedgerError('REPLACEMENT_ATTENTION_STALE')
                current.setdefault('participant_recoveries', {})[participant] = deepcopy(row)
                return Transition(current, (Event('participant.restore-failed', deepcopy(row)),), deepcopy(row))
            self.hub.ledger.apply(Command(operation, 'participant.restore-failed', participant,
                scope['generation'], row), origin, authorize=lambda *_: not self.store_failed, decide=decide)

    def _replacement_view(self, state, document, participant, *, forge, reviews=None):
        row = state.get('participant_recoveries', {}).get(participant)
        record = document['seats'].get(participant)
        if (not row or not record or row['instance_id'] != self.instance
                or row['controller_id'] != self.controller_id
                or row['incarnation_id'] != record['incarnation_id'] or row['epoch'] != record['epoch']
                or record['status'] in {'active', 'starting', 'closed'}):
            raise LedgerError('REPLACEMENT_ATTENTION_STALE')
        run = state.get('runs', {}).get(row['run_id'])
        if not run or run['generation'] != row['generation'] or run['status'] == 'CLOSED':
            raise LedgerError('REPLACEMENT_ATTENTION_STALE')
        contexts = state.get('fixture_context', {}).get('participants', {})
        failed_context = contexts.get(participant)
        scope = {'run_id': row['run_id'], 'generation': row['generation']}
        if (not failed_context or failed_context['context_generation'] != row['context_generation']
                or (failed_context.get('bound_run') or failed_context.get('reserved_run')) != scope):
            raise LedgerError('REPLACEMENT_ATTENTION_STALE')
        required = set(record['seat']['capabilities']) & {'implement', 'review', 'peer-traffic'}
        review = state.get('run_reviews', {}).get(row['run_id'], {}).get('current')
        is_reviewer = review and (review.get('reviewer') or {}).get('participant_id') == participant
        candidates = []
        for name, candidate in sorted(document['seats'].items()):
            context = contexts.get(name)
            if (name == participant or candidate['status'] in {'starting', 'closed', 'disabled'}
                    or candidate.get('cleanup_pending') or candidate['epoch'] >= 2**53 - 1
                    or not required <= set(candidate['seat']['capabilities'])
                    or self.credentials.missing(candidate['seat']) or not context
                    or context['status'] != 'READY'
                    or context.get('reset') and context['reset']['status'] != 'SUCCEEDED'
                    or (context.get('bound_run') or context.get('reserved_run')) not in (None, scope)):
                continue
            if is_reviewer:
                if reviews is None: continue
                try:
                    admitted = reviews.identity.dispatcher.reviewer_authority(name, row['run_id'], row['generation'])
                    if admitted.actor_id != candidate['seat']['actor_id']: continue
                    reviews._fact(run, candidate['seat']['actor_id'], admitted.authority_version)
                except (LedgerError, RuntimeError): continue
            candidates.append({'participant_id': name, 'actor_id': candidate['seat']['actor_id'],
                'incarnation_id': candidate['incarnation_id'], 'epoch': candidate['epoch'],
                'context_generation': context['context_generation']})
        version = _digest({'attention': row, 'record': record, 'context': failed_context,
            'candidates': candidates, 'controller': self.controller_id, 'run': run,
            'review': review, 'source_revision': document.get('observation_revision'), 'forge': forge})
        return {'participant_id': participant, 'run_id': row['run_id'], 'generation': row['generation'],
                'observed_version': version, 'candidates': candidates,
                'selection': deepcopy(row['selection']), 'reason': row['reason'],
                'forge_uncertain': forge['blocked'], 'eligible': not forge['blocked'] and row['selection'] is None and bool(candidates)}

    def replacement_view(self, participant, *, audit, repository, reviews=None, admission_operation=None):
        context = reviews._fence(admission_operation) if reviews is not None else nullcontext()
        with context, self.supervisor._locked():
            self.supervisor._allowed('participant-replacement-observe', self._room())
            with audit.manager_action_guard(self.supervisor.room_id, repository) as forge:
                return self._replacement_view(self.hub.ledger.snapshot()['state'], self._read(), participant, reviews=reviews, forge=forge)

    def manager_replacement(self, value, *, session, audit, repository, reviews=None, admission_operation=None):
        from .manager_actions import request, uncertain_forge
        value = request(value, session)
        if (value['action'] != 'select-replacement' or session.room_id != self.supervisor.room_id
                or session.instance_id != self.instance or set(value['payload']) != {'participant_id'}):
            raise LedgerError('INVALID_MANAGER_ACTION')
        selected = _token(value['payload']['participant_id'])
        command = Command(value['operation_id'], 'participant.select-replacement', value['object_id'],
            value['generation'], {'run_id': value['run_id'], 'selected_participant': selected,
                'observed_version': value['observed_version'], 'manager': {**session.metadata(),
                    'request_digest': _digest(value)}})
        context = reviews._fence(admission_operation) if reviews is not None else nullcontext()
        with context, self.supervisor._locked():
            def authorize(*_):
                if not session.allowed('select-replacement') or self.store_failed: return False
                self.supervisor._allowed('participant-select-replacement', self._room())
                return True
            if self.hub.ledger.exact_receipt(command, session.human, authorize=authorize) is not None:
                raise LedgerError('MANAGER_DUPLICATE_ACTION')
            def decide(state, _):
                view = self._replacement_view(state, self._read(), value['object_id'], reviews=reviews, forge=forge)
                if (view['observed_version'] != value['observed_version'] or view['run_id'] != value['run_id']
                        or view['generation'] != value['generation']):
                    raise LedgerError('MANAGER_STALE_ACTION')
                if uncertain_forge(state, value['run_id'], forge=forge): raise LedgerError('MANAGER_FORGE_RECONCILIATION_REQUIRED')
                candidate = next((c for c in view['candidates'] if c['participant_id'] == selected), None)
                if candidate is None or view['selection'] is not None: raise LedgerError('REPLACEMENT_INELIGIBLE')
                intent = {'operation_id': value['operation_id'], 'status': 'selected-not-launched',
                    'candidate': candidate, 'human_origin': session.human.canonical(), 'manager': session.metadata()}
                state['participant_recoveries'][value['object_id']]['selection'] = intent
                return Transition(state, (Event('participant.replacement-selected', deepcopy(intent)),), intent)
            with audit.manager_action_guard(self.supervisor.room_id, repository) as forge:
                return self.hub.ledger.apply(command, session.human, authorize=authorize, decide=decide)['result']
