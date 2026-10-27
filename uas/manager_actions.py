"""Finite Manager requests to actual Room owners, never browser authority.

The hosting authentication layer supplies HumanSession; JSON cannot construct
one or choose identity/capabilities. The host must revalidate it on every owner
transaction and provider call. This module adds no login or credential grant.
"""
from copy import deepcopy
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
import hashlib
import re

from .ledger import Command, LedgerError, Origin, _json, _token


RUN_ACTIONS = frozenset({'pause', 'resume'})
REVIEW_ACTIONS = frozenset({'request-changes', 'add-rounds', 'waive-cap', 'override-review', 'reconcile-changes'})
ACTIONS = RUN_ACTIONS | REVIEW_ACTIONS | {'select-replacement', 'start', 'stop', 'open-github', 'reconcile-changes'}
_HASH = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class HumanSession:
    """Trusted authenticated context, never deserialized from a request.

    human is the unchanged Origin authenticated by the host. manager_id is
    independent accountability metadata, not a replacement Actor Identity.
    connected/authorized are fresh host checks, not JSON booleans.
    """
    deployment_id: str
    room_id: str
    instance_id: str
    manager_id: str
    human: Origin
    authorized: object
    connected: object

    def __post_init__(self):
        for value in (self.deployment_id, self.room_id, self.instance_id, self.manager_id): _token(value)
        if type(self.human) is not Origin or not callable(self.authorized) or not callable(self.connected):
            raise LedgerError('MANAGER_AUTHENTICATION_REQUIRED')
        self.human.canonical()

    def allowed(self, action):
        return (self.connected() is True and self.authorized(self, action) is True)

    def metadata(self):
        return {'deployment_id': self.deployment_id, 'room_id': self.room_id,
                'instance_id': self.instance_id, 'manager_id': self.manager_id,
                'human_origin': self.human.canonical()}


def request(value, session):
    if (type(session) is not HumanSession or type(value) is not dict
            or set(value) != {'version', 'operation_id', 'action', 'deployment_id', 'room_id',
                             'instance_id', 'run_id', 'generation', 'object_id', 'observed_version', 'payload'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['action']) is not str or value['action'] not in ACTIONS
            or type(value['payload']) is not dict):
        raise LedgerError('INVALID_MANAGER_ACTION')
    _json(value)
    for field in ('operation_id', 'deployment_id', 'room_id', 'instance_id', 'object_id'): _token(value[field])
    if any(value[key] != getattr(session, key) for key in ('deployment_id', 'room_id', 'instance_id')):
        raise LedgerError('MANAGER_SCOPE_MISMATCH')
    if value['action'] in {'start', 'stop'}:
        if value['run_id'] is not None or value['generation'] is not None:
            raise LedgerError('INVALID_MANAGER_ACTION')
    else:
        _token(value['run_id'])
        if type(value['generation']) is not int or not 1 <= value['generation'] < 2**63:
            raise LedgerError('INVALID_MANAGER_ACTION')
    if type(value['observed_version']) is not str or not _HASH.fullmatch(value['observed_version']):
        raise LedgerError('INVALID_MANAGER_ACTION')
    return deepcopy(value)


def run_version(state, run_id, forge):
    """Exact semantic owner version; unrelated stream cursor is not authority."""
    run = state.get('runs', {}).get(run_id)
    if run is None: raise LedgerError('UNKNOWN_RUN')
    return hashlib.sha256(_json({'run': run,
        'review': state.get('run_reviews', {}).get(run_id), 'forge': forge,
        'comments': {key: row for key, row in state.get('review_comments', {}).items() if row.get('run_id') == run_id},
        'projection': state.get('forge_projections', {}).get(run_id)}).encode()).hexdigest()


def uncertain_forge(state, run_id, *, forge=None, except_operation=None):
    if forge is not None and forge['blocked']: return True
    comments = state.get('review_comments', {})
    if any(key != except_operation and row.get('run_id') == run_id and row.get('status') in
           {'pending', 'unknown', 'confirmed-awaiting-target'} for key, row in comments.items()):
        return True
    projection = state.get('forge_projections', {}).get(run_id, {})
    return (projection.get('state') in {'unknown', 'partial'}
            or projection.get('unresolved') is not None)


def current_run(state, run_id, forge):
    """Small response projection; never returns bodies, raw owner rows or errors."""
    run = state.get('runs', {}).get(run_id)
    if run is None: return None
    review = state.get('run_reviews', {}).get(run_id, {}).get('current')
    return {'run_id': run_id, 'generation': run['generation'], 'status': run['status'],
            'observed_version': run_version(state, run_id, forge),
            'control_revision': run.get('control_revision', 0),
            'review_stage': None if review is None else review['stage'],
            'submission_id': None if review is None else review['submission_id'],
            'forge_uncertain': uncertain_forge(state, run_id, forge=forge),
            'forge_outcome': deepcopy(forge)}


class OwnerFence:
    """Used *inside* the actual owner, including its write transaction.

    It excludes this operation's own pending comment but no other uncertainty.
    A lost Manager response never grants another write or bypasses revocation.
    """
    def __init__(self, ledger, session, value, actions, *, audit, repository, supervisor):
        self.ledger, self.session = ledger, session
        self.audit, self.repository, self.supervisor = audit, repository, supervisor
        self._forge = None
        self.value = request(value, session)
        if ledger.room_id != session.room_id or self.value['action'] not in actions:
            raise LedgerError('MANAGER_SCOPE_MISMATCH')

    def authorize(self):
        if not self.session.allowed(self.value['action']): return False
        self.live()
        return True

    def live(self):
        state = self.supervisor._read()
        if state is None or state['instance_id'] != self.session.instance_id:
            raise LedgerError('ROOM_REPLACED')
        if state['phase'] != 'running' or state['desired'] != 'running':
            raise LedgerError('ROOM_NOT_RUNNING')

    @contextmanager
    def guard(self, *, lifecycle_locked=False):
        # Lock order: existing identity/target fence, lifecycle, audit, Hub.
        # Never acquire Broker/provider locks or send while this guard is held.
        with (nullcontext() if lifecycle_locked else self.supervisor._locked()):
            self.live()
            with self.audit.manager_action_guard(self.ledger.room_id, self.repository) as forge:
                self._forge = forge
                try: yield
                finally: self._forge = None

    def check(self, state, *, uncertainty=True):
        value = self.value
        if not self.authorize(): raise LedgerError('FORBIDDEN')
        run = state.get('runs', {}).get(value['run_id'])
        forge = self._forge or self.audit.manager_action_state(self.ledger.room_id, self.repository)
        if (run is None or run['generation'] != value['generation']
                or run_version(state, value['run_id'], forge) != value['observed_version']):
            raise LedgerError('MANAGER_STALE_ACTION')
        if uncertainty and uncertain_forge(state, value['run_id'], forge=forge, except_operation=value['operation_id']):
            raise LedgerError('MANAGER_FORGE_RECONCILIATION_REQUIRED')
        return run

    def metadata(self):
        return {**self.session.metadata(), 'object_id': self.value['object_id'],
                'observed_version': self.value['observed_version'], 'action': self.value['action'],
                'request_digest': hashlib.sha256(_json(self.value).encode()).hexdigest()}

    def command(self, command):
        return Command(command.id, command.kind, command.target, command.generation,
                       {**command.payload, '_manager': self.metadata()})

    def before(self, command):
        """Duplicate is a no-op response, not a second owner invocation."""
        receipt = self.ledger.exact_receipt(command, self.session.human,
                                           authorize=lambda *_: self.authorize())
        if receipt is not None: raise LedgerError('MANAGER_DUPLICATE_ACTION')
        return self.check(self.ledger.snapshot()['state'], uncertainty=self.value['action'] != 'reconcile-changes')


class ManagerHubActions:
    """Fixed dispatch to real Hub owners. No arbitrary method/URL/command route."""
    def __init__(self, admission, reviews, *, deployment_id, instance_id, admission_operation, audit, participants=None):
        from .run_admission import RunAdmission
        from .run_review import RunReview
        from .forge_audit import ForgeAudit
        from .lifecycle import Supervisor
        if (type(admission) is not RunAdmission or type(reviews) is not RunReview
                or admission.ledger is not reviews.ledger or type(audit) is not ForgeAudit
                or audit.deployment_id != deployment_id or type(admission.supervisor) is not Supervisor):
            raise LedgerError('MANAGER_OWNER_REQUIRED')
        self.admission, self.reviews, self.ledger = admission, reviews, reviews.ledger
        self.deployment_id, self.instance_id = _token(deployment_id), _token(instance_id)
        self.admission_operation = _token(admission_operation)
        self.audit, self.repository = audit, admission.broker.binding.repository
        if participants is not None:
            from .participant import FixtureParticipantController
            if (type(participants) is not FixtureParticipantController or participants.hub.ledger is not self.ledger
                    or participants.instance != self.instance_id or admission.controller is not participants):
                raise LedgerError('MANAGER_OWNER_REQUIRED')
        self.participants = participants
        self.lifecycle = admission.supervisor

    def forge_state(self):
        try: return self.audit.manager_action_state(self.ledger.room_id, self.repository)
        except LedgerError:
            return {'version': hashlib.sha256(b'AUDIT_UNAVAILABLE').hexdigest(), 'blocked': True,
                    'partial': False, 'reason': 'AUDIT_UNAVAILABLE'}

    def current(self, run_id):
        try: return current_run(self.ledger.snapshot()['state'], run_id, self.forge_state())
        except LedgerError: return None

    def replacement_view(self, participant, *, session):
        if (type(session) is not HumanSession or session.deployment_id != self.deployment_id
                or session.room_id != self.ledger.room_id or session.instance_id != self.instance_id
                or not session.allowed('select-replacement')):
            raise LedgerError('FORBIDDEN')
        if self.participants is None: raise LedgerError('MANAGER_ACTION_UNAVAILABLE')
        return self.participants.replacement_view(participant, reviews=self.reviews,
            admission_operation=self.admission_operation, audit=self.audit, repository=self.repository)

    def lifecycle_view(self, *, session):
        if (type(session) is not HumanSession or session.room_id != self.ledger.room_id
                or session.instance_id != self.instance_id or session.deployment_id != self.deployment_id):
            raise LedgerError('MANAGER_SCOPE_MISMATCH')
        return self.lifecycle.manager_view(session=session, deployment_id=self.deployment_id)

    def view(self, run_id, *, session):
        if (type(session) is not HumanSession or session.deployment_id != self.deployment_id
                or session.room_id != self.ledger.room_id or session.instance_id != self.instance_id):
            raise LedgerError('MANAGER_SCOPE_MISMATCH')
        state = self.ledger.snapshot()['state']; current = current_run(state, run_id, self.forge_state())
        if current is None: return {'current': None, 'actions': []}
        run = state['runs'][run_id]
        row = state.get('run_reviews', {}).get(run_id, {}).get('current')
        actions = []
        for action in sorted(RUN_ACTIONS | REVIEW_ACTIONS | {'open-github'}):
            object_id = run_id if action in RUN_ACTIONS else row['submission_id'] if row else run_id
            reason = None
            if not session.allowed(action): reason = 'HUMAN_AUTHORITY_UNAVAILABLE'
            elif run.get('control_pending'): reason = 'RUN_CONTROL_PENDING'
            elif run['status'] == 'CLOSED' and action != 'open-github': reason = 'RUN_CLOSED'
            elif current['forge_uncertain'] and action not in {'reconcile-changes', 'open-github'}:
                reason = 'MANAGER_FORGE_RECONCILIATION_REQUIRED'
            elif action == 'pause' and run['status'] != 'ACTIVE': reason = 'INELIGIBLE_STATE'
            elif action == 'resume' and (run['status'] != 'PAUSED' or
                    run.get('native_stop') and not run['native_stop'].get('restored', False)):
                reason = 'INELIGIBLE_STATE'
            elif action == 'request-changes' and (not row or row['stage'] != 'READY_FOR_HUMAN'):
                reason = 'INELIGIBLE_STATE'
            elif action in {'add-rounds', 'waive-cap', 'override-review'} and (
                    not row or row['stage'] not in {'ATTENTION', 'READY_FOR_HUMAN'}):
                reason = 'INELIGIBLE_STATE'
            elif action == 'reconcile-changes':
                # One explicit original operation, never an automatic retry.
                pending = [key for key, item in state.get('review_comments', {}).items()
                    if item['run_id'] == run_id and item['generation'] == run['generation']
                    and item['status'] in {'pending', 'unknown', 'confirmed-awaiting-target'}]
                if len(pending) != 1: reason = 'RECONCILIATION_TARGET_REQUIRED'
                else: object_id = pending[0]
            elif action == 'open-github' and not run.get('gate_target'): reason = 'SOURCE_LINK_UNAVAILABLE'
            if reason is None:
                try:
                    if action in RUN_ACTIONS:
                        self.admission.manager_eligibility(action, run_id, session=session)
                    elif action in REVIEW_ACTIONS:
                        self.reviews.manager_eligibility(action, run_id, session=session,
                            admission_operation=self.admission_operation, supervisor=self.lifecycle)
                    else:
                        with self.lifecycle._locked():
                            self.admission.manager_live(session)
                except LedgerError as error: reason = error.code
                except Exception: reason = 'OWNER_AUTHORITY_UNAVAILABLE'
            actions.append({'action': action, 'object_id': object_id, 'eligible': reason is None, 'reason': reason})
        return {'current': current, 'actions': actions}

    def inspect(self, value, *, session):
        """Read the exact original operation; never retry it or call a provider."""
        from .manager_lifecycle import current as lifecycle_current, inspect_result
        value = request(value, session)
        if (session.deployment_id != self.deployment_id or session.room_id != self.ledger.room_id
                or session.instance_id != self.instance_id): raise LedgerError('MANAGER_SCOPE_MISMATCH')
        action = value['action']
        if action in {'open-github', 'reconcile-changes'}: raise LedgerError('INVALID_MANAGER_ACTION')
        digest = hashlib.sha256(_json(value).encode()).hexdigest()
        with self.lifecycle._locked():
            def authorize(origin, command):
                state = self.lifecycle._read()
                if (not state or state['instance_id'] != session.instance_id
                        or not session.allowed('observe') or not session.allowed(action)): return False
                if action in RUN_ACTIONS:
                    probe = command or Command(value['operation_id'], 'run.human-'+action,
                        value['run_id'], value['generation'], {})
                    return self.admission._human(origin, probe)
                if action in REVIEW_ACTIONS:
                    return self.reviews._human(origin, lambda: session.allowed(action))
                if action == 'select-replacement':
                    if self.participants is None: return False
                    self.lifecycle._allowed('participant-replacement-observe', state)
                    return not self.participants.store_failed
                self.lifecycle._allowed(action, state)
                return True
            def matches(command):
                if action in {'start', 'stop'}:
                    return (command.kind == 'room.manager-'+action and
                        command.payload == {'request': value, 'principal': session.metadata()})
                kinds = {'pause':'run.human-pause', 'resume':'run.human-resume',
                    'request-changes':'review.human-changes', 'add-rounds':'review.human-control',
                    'waive-cap':'review.human-control', 'override-review':'review.human-control',
                    'select-replacement':'participant.select-replacement'}
                if command.kind != kinds[action]: return False
                metadata = command.payload.get('_manager') if action != 'select-replacement' else command.payload.get('manager')
                return (type(metadata) is dict and metadata.get('request_digest') == digest
                        and metadata.get('human_origin') == session.human.canonical())
            receipt = self.ledger.matched_receipt(value['operation_id'], session.human,
                authorize=authorize, matches=matches)
            outcome = 'unknown'
            if receipt is not None:
                if action in {'start','stop'}:
                    outcome = inspect_result(self.lifecycle, value, session)
                elif action == 'request-changes':
                    item = self.ledger.snapshot()['state'].get('review_comments', {}).get(value['operation_id'])
                    if item and item.get('status') == 'confirmed': outcome = 'confirmed'
                    elif item and item.get('status') == 'stale': outcome = 'partial'
                else: outcome = 'confirmed'
            if not authorize(session.human, None): raise LedgerError('FORBIDDEN')
            return {'operation_id': value['operation_id'], 'outcome': outcome,
                'reason': None if outcome == 'confirmed' else 'OWNER_OUTCOME_UNCONFIRMED',
                'current': (lifecycle_current(self.lifecycle._read())
                    if action in {'start','stop'} else self.current(value['run_id'])),
                'receipt': {'operation_id': value['operation_id'], 'status': outcome,
                            'source': 'exact-owner-receipt', 'read_only': True}}

    def execute(self, value, *, session):
        if (type(session) is not HumanSession or session.deployment_id != self.deployment_id or session.instance_id != self.instance_id
                or session.room_id != self.ledger.room_id):
            raise LedgerError('MANAGER_SCOPE_MISMATCH')
        raw = value
        try:
            value = request(value, session)
        except LedgerError as error:
            # An invalid browser packet still gets only this authorized Room's
            # current bounded view, never attacker-selected cross-Room state.
            run_id = raw.get('run_id') if type(raw) is dict else None
            current = (self.current(run_id)
                if type(run_id) is str and session.allowed('observe') else None)
            return {'operation_id': None, 'outcome': 'denied', 'reason': error.code, 'current': current}
        try:
            if value['action'] in {'start', 'stop'}:
                if self.lifecycle is None: raise LedgerError('MANAGER_ACTION_UNAVAILABLE')
                return self.lifecycle.manager_action(value, session=session, deployment_id=self.deployment_id, ledger=self.ledger)
            elif value['action'] in RUN_ACTIONS:
                result = self.admission.manager_action(value, session=session, audit=self.audit)
            elif value['action'] in REVIEW_ACTIONS:
                result = self.reviews.manager_action(value, session=session,
                    admission_operation=self.admission_operation, audit=self.audit,
                    repository=self.repository, supervisor=self.lifecycle)
            elif value['action'] == 'select-replacement':
                if self.participants is None: raise LedgerError('MANAGER_ACTION_UNAVAILABLE')
                result = self.participants.manager_replacement(value, session=session,
                    reviews=self.reviews, admission_operation=self.admission_operation,
                    audit=self.audit, repository=self.repository)
                return {'operation_id': value['operation_id'], 'outcome': 'selected', 'reason': None,
                    'selection': {'status': result['status'], 'participant_id': result['candidate']['participant_id']},
                    'current': self.current(value['run_id'])}
            elif value['action'] == 'open-github':
                from .gate_forge import validate_forge_target
                fence = OwnerFence(self.ledger, session, value, {'open-github'}, audit=self.audit,
                    repository=self.repository, supervisor=self.lifecycle)
                with fence.guard():
                    run = deepcopy(fence.check(self.ledger.snapshot()['state'], uncertainty=False))
                target = validate_forge_target(run.get('gate_target'))
                row = self.ledger.snapshot()['state'].get('run_reviews', {}).get(value['run_id'], {}).get('current')
                if (value['payload'] or value['object_id'] != (row['submission_id'] if row else value['run_id'])
                        or target['repository'] != self.admission.broker.binding.repository):
                    raise LedgerError('MANAGER_TARGET_MISMATCH')
                return {'operation_id': value['operation_id'], 'outcome': 'link', 'reason': None,
                    'url': f"https://github.com/{target['repository']}/pull/{target['pull_number']}",
                    'current': self.current(value['run_id'])}
            else:
                raise LedgerError('MANAGER_ACTION_UNAVAILABLE')
            status = result.get('status')
            outcome = ('unknown' if status in {'pending', 'unknown', 'confirmed-awaiting-target'} else
                       'denied' if status == 'error' else 'partial' if status == 'stale' else 'confirmed')
            code = ('OWNER_NOT_EXECUTED' if status == 'error' else
                    'TARGET_CHANGED_AFTER_WRITE' if status == 'stale' else None)
        except LedgerError as error:
            outcome = ('unknown' if error.code == 'STORAGE_ERROR' or
                error.code not in {'MANAGER_DUPLICATE_ACTION', 'ID_CONFLICT'} and
                uncertain_forge(self.ledger.snapshot()['state'], value['run_id']) and
                value['action'] == 'request-changes' and
                value['operation_id'] in self.ledger.snapshot()['state'].get('review_comments', {})
                else 'denied')
            code = error.code
        except Exception:
            # A missing response is not proof of no effect. Never echo native
            # exception text, retry the write or claim Manager acknowledged it.
            outcome, code = 'unknown', 'OWNER_OUTCOME_UNCONFIRMED'
        response = {'operation_id': value['operation_id'], 'outcome': outcome, 'reason': code,
                'current': self.current(value['run_id'])}
        if value['action'] in {'request-changes', 'reconcile-changes'}:
            key = value['object_id'] if value['action'] == 'reconcile-changes' else value['operation_id']
            item = self.ledger.snapshot()['state'].get('review_comments', {}).get(key)
            if item is not None and item.get('run_id') == value['run_id']:
                receipt = item['receipt']
                response['receipt'] = {'operation_id': key, 'status': item['status'],
                    'observation_audit': item['observation_audit'], 'provider': None if receipt is None else
                    {'status': receipt['status'], 'audit_reference': receipt['audit_reference'],
                     'comment_reference': deepcopy(receipt['comment_reference']) if receipt['status'] == 'confirmed' else None}}
        return response
