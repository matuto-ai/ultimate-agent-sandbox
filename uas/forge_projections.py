"""Hub-owned label outbox over the one Room ledger.

Run/Request state is authoritative. The outbox stores derived intent and effect
observations, never a second workflow state. Provider methods are trusted Broker
calls, not Participant-selected URLs, credentials, or arbitrary label edits.
"""
from copy import deepcopy
import hashlib

from .forge import ForgeBinding
from .forge_audit import _mutation_result
from .github_read import GitHubProject, _positive
from .ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition, _json, _token


# Exact names are a specification detail in decision #50. These product labels
# deliberately do not reuse this repository's contributor agent:* workflow.
LIFECYCLE_LABELS = frozenset({'lifecycle:active', 'lifecycle:blocked',
                            'lifecycle:attention', 'lifecycle:review'})
RUN_LABELS = frozenset({'run:active', 'run:paused', 'run:closed'})
OWNED_LABELS = LIFECYCLE_LABELS | RUN_LABELS
PROJECTION_STATES = frozenset({'pending', 'drifted', 'repaired', 'partial', 'unknown', 'failed'})
RESERVED_BYTES = 12288
MAX_PROJECTIONS = 32
_INTENT_KEYS = {'room_id', 'project_id', 'repository', 'run_id', 'generation',
                'issue_number', 'issue_id', 'github_user_id', 'labels', 'version',
                'reconcile_operation'}
_OBSERVATION_KEYS = {'status', 'completeness', 'repository', 'issue_id',
                     'issue_number', 'labels', 'assignee_ids', 'audit_reference', 'error_code'}


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _capacity(state):
    if 'peer_traffic' in state:
        from .peer import FixturePeerHub
        FixturePeerHub._reserve_capacity(state)
    else:
        _json(state)


def _reserve(row):
    row.pop('reserved', None)
    size = len(_json(row).encode())
    if size > RESERVED_BYTES:
        raise LedgerError('PROJECTION_CAPACITY')
    # Keep the same occupied budget as outcomes and audit references grow.
    row['reserved'] = 'x' * (RESERVED_BYTES - size)


def _intent(state, room_id, run_id):
    run = state.get('runs', {}).get(run_id)
    if type(run) is not dict:
        raise LedgerError('UNKNOWN_RUN')
    for field in ('run_id', 'project_id'):
        _token(run.get(field))
    if (run['run_id'] != run_id or run.get('status') not in {'ACTIVE', 'PAUSED', 'CLOSED'}
            or any(not _positive(run.get(key)) for key in
                   ('generation', 'issue_number', 'issue_id', 'github_user_id'))
            or run['issue_number'] > 9_999_999_999):
        raise LedgerError('INVALID_PROJECTION_SOURCE')
    GitHubProject(run.get('repository'))
    status = run['status']
    # Read only existing canonical facts. No label or native review result can
    # create a ready-for-human-review fact (that workflow belongs to #74).
    blocked = any(r.get('kind') == 'peer.work-request' and r.get('run_id') == run_id
                  and r.get('generation') == run['generation'] and r.get('status') == 'BLOCKED'
                  for r in state.get('peer_traffic', {}).get('traffic', {}).values())
    lifecycle = ('lifecycle:attention' if status == 'PAUSED' else
                 'lifecycle:attention' if run.get('review_stage') == 'ATTENTION' else
                 'lifecycle:review' if run.get('review_stage') in {'REVIEWING', 'READY_FOR_HUMAN'} else
                 'lifecycle:blocked' if blocked else 'lifecycle:active')
    labels = ['run:' + status.lower()]
    if status != 'CLOSED': labels.append(lifecycle)
    return {'room_id': _token(room_id), 'run_id': run_id, 'project_id': run['project_id'],
            'repository': run['repository'], 'generation': run['generation'],
            'issue_number': run['issue_number'], 'issue_id': run['issue_id'],
            'github_user_id': run['github_user_id'], 'labels': sorted(labels)}


def enqueue_run_projection(state, room_id, run_id):
    """Called *inside* the canonical owner's Run/Request transition transaction.

    Pending or uncertain attempts survive newer desired intent. A source update
    is not permission to discard an in-flight write or its reconciliation fence.
    The returned event belongs in that same transition's immutable event tuple.
    """
    desired = _intent(state, room_id, run_id)
    rows = state.setdefault('forge_projections', {})
    old = rows.get(run_id)
    if old is not None and {k: old['desired'][k] for k in desired} == desired:
        return None
    if old is None and len(rows) >= MAX_PROJECTIONS:
        raise LedgerError('PROJECTION_CAPACITY')
    version = 1 if old is None else old['desired']['version'] + 1
    if version > 2**63 - 1:
        raise LedgerError('PROJECTION_VERSION_EXHAUSTED')
    desired.update(version=version, reconcile_operation=None)
    row = old if old is not None else {
        'active': None, 'unresolved': None, 'observed': None, 'last_result': None,
        'audit_reference': None, 'attribution': 'none', 'reason': 'NOT_OBSERVED'}
    row.update(desired=desired, state='pending')
    rows[run_id] = row
    state['runs'][run_id]['projection'] = 'pending'
    _reserve(row)
    return Event('forge.projection-enqueued', {'run_id': run_id, 'version': version,
        'labels': desired['labels'], 'generation': desired['generation']})


def validate_intent(value):
    if type(value) is not dict or set(value) != _INTENT_KEYS:
        raise LedgerError('INVALID_PROJECTION_INTENT')
    for field in ('room_id', 'project_id', 'run_id'):
        _token(value[field])
    GitHubProject(value['repository'])
    if (any(not _positive(value[k]) for k in
            ('generation', 'issue_number', 'issue_id', 'github_user_id', 'version'))
            or value['issue_number'] > 9_999_999_999
            or type(value['labels']) is not list or not 1 <= len(value['labels']) <= 2
            or any(type(label) is not str for label in value['labels'])
            or value['labels'] != sorted(set(value['labels']))
            or any(label not in OWNED_LABELS for label in value['labels'])
            or value['labels'] not in (['lifecycle:active', 'run:active'],
                ['lifecycle:blocked', 'run:active'], ['lifecycle:review', 'run:active'],
                ['lifecycle:attention', 'run:active'], ['lifecycle:attention', 'run:paused'], ['run:closed'])):
        raise LedgerError('INVALID_PROJECTION_INTENT')
    if value['reconcile_operation'] is not None: _token(value['reconcile_operation'])
    return deepcopy(value)


def validate_observation(value, intent):
    if (type(value) is not dict or set(value) != _OBSERVATION_KEYS
            or type(value['status']) is not str
            or value['status'] not in {'OK', 'UNKNOWN', 'CONFLICT'}
            or type(value['completeness']) is not str
            or value['completeness'] not in {'complete', 'unknown'}
            or any(value[key] != intent[key] for key in ('repository', 'issue_id', 'issue_number'))
            or type(value['labels']) is not list
            or any(type(label) is not str for label in value['labels'])
            or value['labels'] != sorted(set(value['labels']))
            or any(label not in OWNED_LABELS for label in value['labels'])
            or type(value['assignee_ids']) is not list or len(value['assignee_ids']) > 100
            or any(not _positive(v) for v in value['assignee_ids'])
            or value['assignee_ids'] != sorted(set(value['assignee_ids']))):
        raise LedgerError('INVALID_PROJECTION_OBSERVATION')
    _token(value['audit_reference'])
    if value['error_code'] is not None: _token(value['error_code'])
    if ((value['status'] == 'UNKNOWN') != (value['completeness'] == 'unknown')
            or (value['status'] == 'UNKNOWN' and (value['labels'] or value['assignee_ids']))
            or (value['status'] == 'OK' and value['error_code'] is not None)):
        raise LedgerError('INVALID_PROJECTION_OBSERVATION')
    return deepcopy(value)


class ProjectionOutbox:
    """One bounded explicit synchronization attempt; no polling/backlog scheduler.

    A trusted Supervisor supplies authority and the external Broker provider.
    Every exact retry is read-only locally, even if the original acknowledgement
    was lost. Interrupted attempts need an independently proven fenced owner.
    """
    def __init__(self, ledger, binding, provider):
        if (type(ledger) is not RoomLedger or type(binding) is not ForgeBinding
                or binding.room_id != ledger.room_id
                or not callable(getattr(provider, 'observe', None))
                or not callable(getattr(provider, 'repair', None))):
            raise LedgerError('INVALID_PROJECTION_OWNER')
        GitHubProject(binding.repository, binding.host)
        self.ledger, self.binding, self.provider = ledger, binding, provider

    @staticmethod
    def _authorized(origin, authorize):
        return (type(origin) is Origin and 'forge-project' in origin.capabilities
                and authorize() is True)

    def _command(self, operation_id, run_id, kind, payload):
        return Command(_token(operation_id), 'forge.projection-' + kind, _token(run_id), None, payload)

    def _apply(self, command, origin, authorize, decide):
        return self.ledger.apply(command, origin,
            authorize=lambda *_: self._authorized(origin, authorize), decide=decide)

    @staticmethod
    def _view(row):
        return deepcopy({k: row[k] for k in ('state', 'desired', 'observed',
            'audit_reference', 'attribution', 'reason', 'last_result')}) | {
                'pending_operation': None if row['active'] is None else row['active']['operation_id'],
                'unresolved_operation': row['unresolved']}

    def projection(self, run_id, *, origin, authorize):
        if not self._authorized(origin, authorize): raise LedgerError('FORBIDDEN')
        row = self.ledger.snapshot()['state'].get('forge_projections', {}).get(_token(run_id))
        if row is None: raise LedgerError('UNKNOWN_PROJECTION')
        return self._view(row)

    def _terminal(self, operation_id, run_id, origin, authorize):
        return self.ledger.operation_receipt('projection-terminal-' + _digest(
            [self.binding.room_id, run_id, operation_id]), origin,
            authorize=lambda: self._authorized(origin, authorize))

    def _guard(self, run_id, operation_id, version, origin, authorize):
        if not self._authorized(origin, authorize): return False
        state = self.ledger.snapshot()['state']
        row = state.get('forge_projections', {}).get(run_id)
        if (row is None or row['active'] is None
                or row['active']['operation_id'] != operation_id
                or row['desired']['version'] != version): return False
        actual = _intent(state, self.binding.room_id, run_id)
        return actual == {k: row['desired'][k] for k in actual}

    def advance(self, operation_id, run_id, *, origin, authorize):
        command = self._command(operation_id, run_id, 'advance', {})
        previous = self.ledger.exact_receipt(command, origin,
            authorize=lambda *_: self._authorized(origin, authorize))
        if previous is not None:
            terminal = self._terminal(operation_id, run_id, origin, authorize)
            return (terminal['result'] if terminal is not None else {
                'state': 'unknown', 'reason': 'IN_FLIGHT_OR_INTERRUPTED',
                'operation_id': operation_id, 'provider_contact': 'not-repeated'})
        key = _digest([self.binding.room_id, run_id, operation_id])
        started = False
        def reserve(state, _):
            nonlocal started
            enqueued = enqueue_run_projection(state, self.binding.room_id, run_id)
            row = state['forge_projections'][run_id]
            if row['active'] is not None: raise LedgerError('PROJECTION_IN_FLIGHT')
            intent = deepcopy(row['desired'])
            intent['reconcile_operation'] = row['unresolved']
            validate_intent(intent)
            if (intent['project_id'] != self.binding.project_id
                    or intent['repository'] != self.binding.repository
                    or intent['room_id'] != self.binding.room_id):
                raise LedgerError('PROJECT_MISMATCH')
            row['active'] = {'operation_id': operation_id, 'intent': intent, 'phase': 'reading',
                'write_operation': 'projection-write-' + key, 'origin': origin.canonical()}
            row['state'] = 'pending'; row['reason'] = 'READ_PENDING'
            state['runs'][run_id]['projection'] = row['state']
            _reserve(row); _capacity(state)
            started = True
            events = (Event('forge.projection-started', {
                'run_id': run_id, 'version': intent['version'], 'operation_id': operation_id}),)
            return Transition(state, ((enqueued,) if enqueued else ()) + events, {'intent': intent})
        # Exact ledger retry is the arbitration point after competing reads.
        begun = self._apply(command, origin, authorize, reserve)
        intent = begun['result']['intent']
        # A concurrent same-ID caller may have won after exact_receipt above.
        # decide runs only for the creator, so duplicate calls never contact.
        if not started:
            terminal = self._terminal(operation_id, run_id, origin, authorize)
            return (terminal['result'] if terminal is not None else {
                'state': 'unknown', 'reason': 'IN_FLIGHT_OR_INTERRUPTED',
                'operation_id': operation_id, 'provider_contact': 'not-repeated'})
        return self._perform(operation_id, run_id, key, intent, origin, authorize)

    def _perform(self, operation_id, run_id, key, intent, origin, authorize):
        guard = lambda: self._guard(run_id, operation_id, intent['version'], origin, authorize)
        observed = None
        try:
            if not guard():
                return self._finish(operation_id, run_id, key, origin, authorize,
                    'pending', 'SOURCE_CHANGED', None, None, 'none', False)
            observed = validate_observation(self.provider.observe(intent,
                'projection-read-' + key, authorize=guard), intent)
        except Exception as error:
            # No fabricated provider observation is persisted on transport or
            # validation failure. The Hub records only its own failed attempt.
            reason = error.code if isinstance(error, LedgerError) and error.code in {
                'AUDIT_UNAVAILABLE', 'FORBIDDEN', 'BROKER_UNAVAILABLE'} else 'OBSERVATION_UNAVAILABLE'
            return self._finish(operation_id, run_id, key, origin, authorize,
                'unknown', reason, None, None, 'none', False)
        if observed['status'] == 'UNKNOWN':
            return self._finish(operation_id, run_id, key, origin, authorize,
                'unknown', observed['error_code'] or 'OBSERVATION_UNAVAILABLE', observed,
                None, 'observed-only', False)
        if (observed['status'] == 'CONFLICT' or
                observed['assignee_ids'] != [intent['github_user_id']]):
            return self._finish(operation_id, run_id, key, origin, authorize,
                'failed', 'ASSIGNMENT_CONFLICT', observed, None, 'observed-only', False)
        if observed['labels'] == intent['labels']:
            return self._finish(operation_id, run_id, key, origin, authorize,
                'repaired', 'MATCHED', observed, None, 'observed-only', False)

        def before(state, _):
            row = state['forge_projections'][run_id]
            if (row['active'] is None or row['active']['operation_id'] != operation_id
                    or row['desired']['version'] != intent['version']):
                raise LedgerError('STALE_PROJECTION')
            row.update(state='drifted', reason='LABEL_DRIFT', observed=observed,
                audit_reference=observed['audit_reference'], attribution='observed-only')
            row['active']['phase'] = 'writing'
            # This stable operation is retained even if no response reaches us.
            row['unresolved'] = 'projection-write-' + key
            state['runs'][run_id]['projection'] = row['state']
            _reserve(row); _capacity(state)
            return Transition(state, (Event('forge.projection-drifted', {
                'run_id': run_id, 'version': intent['version'], 'observation': observed}),), {})
        try:
            self._apply(self._command('projection-send-' + key, run_id, 'send',
                {'operation_id': operation_id}), origin, authorize, before)
        except LedgerError as error:
            if error.code == 'STALE_PROJECTION':
                return self._finish(operation_id, run_id, key, origin, authorize,
                    'pending', 'SOURCE_CHANGED', observed, None, 'observed-only', False)
            raise
        mutation = None
        try:
            result = self.provider.repair(intent, 'projection-write-' + key, observed, authorize=guard)
            if type(result) is not dict or set(result) != {'audit_reference', 'mutation'}:
                raise LedgerError('INVALID_PROJECTION_RECEIPT')
            _token(result['audit_reference'])
            mutation = _mutation_result(result['mutation'])
            if (set(mutation['confirmed_fields']) - {'add-label', 'remove-label'}
                    or any(obj != {'kind': 'issue', 'id': intent['issue_id'],
                        'number': intent['issue_number']} for obj in mutation['objects'])):
                raise LedgerError('INVALID_PROJECTION_RECEIPT')
            result = {'audit_reference': result['audit_reference'], 'mutation': mutation}
        except Exception:
            return self._finish(operation_id, run_id, key, origin, authorize,
                'unknown', 'MUTATION_UNAVAILABLE', observed, None, 'none', True)
        status = mutation['status']
        state = {'OK': 'repaired', 'PARTIAL_MUTATION': 'partial', 'UNKNOWN_OUTCOME': 'unknown',
                 'NOT_EXECUTED': 'failed', 'PROVIDER_FAILURE': 'failed', 'DENIED': 'failed'}[status]
        return self._finish(operation_id, run_id, key, origin, authorize, state,
            status, observed, result, 'confirmed-response' if status == 'OK' else
                'partial-response' if mutation['confirmed_fields'] else 'none',
            status in {'UNKNOWN_OUTCOME', 'PARTIAL_MUTATION'})

    def _finish(self, operation_id, run_id, key, origin, authorize, status, reason,
                observed, receipt, attribution, uncertain):
        def finish(state, _):
            row = state['forge_projections'][run_id]
            active = row['active']
            if active is None or active['operation_id'] != operation_id:
                raise LedgerError('STALE_PROJECTION')
            current = row['desired']['version'] == active['intent']['version']
            if observed is not None: row['observed'] = observed
            if receipt is not None: row['audit_reference'] = receipt['audit_reference']
            elif observed is not None: row['audit_reference'] = observed['audit_reference']
            # Successful read reconciles a prior fenced send; unknown reads do
            # not clear it. A newly uncertain send always replaces that fence.
            if uncertain: row['unresolved'] = active['write_operation']
            elif observed is not None and observed['completeness'] == 'complete': row['unresolved'] = None
            row.update(active=None, state=status if current else 'pending',
                reason=reason if current else 'SOURCE_CHANGED', attribution=attribution,
                last_result={'operation_id': operation_id, 'state': status, 'reason': reason,
                    'version': active['intent']['version'], 'receipt': receipt})
            state['runs'][run_id]['projection'] = row['state']
            _reserve(row); _capacity(state)
            result = self._view(row)
            return Transition(state, (Event('forge.projection-observed', {
                'run_id': run_id, 'result': result}),), result)
        return self._apply(self._command('projection-terminal-' + key, run_id,
            'terminal', {'operation_id': operation_id, 'state': status, 'reason': reason,
                'observed': observed, 'receipt': receipt, 'uncertain': uncertain}),
            origin, authorize, finish)['result']

    def recover(self, operation_id, run_id, *, origin, authorize, fenced):
        """Trusted replacement only: require positive proof old owner is stopped.

        Never guess from age/PID or a disconnected Manager. An audit-aware
        Supervisor owns this proof; the next advance performs read reconciliation.
        """
        if not callable(fenced): raise LedgerError('FORBIDDEN')
        command = self._command(operation_id, run_id, 'recover', {})
        def recover(state, _):
            row = state.get('forge_projections', {}).get(run_id)
            if row is None: raise LedgerError('UNKNOWN_PROJECTION')
            attempt = row['active']
            if attempt is None: raise LedgerError('NO_PENDING_PROJECTION')
            if fenced(deepcopy(attempt)) is not True:
                raise LedgerError('PROJECTION_OWNER_NOT_FENCED')
            if attempt['phase'] == 'writing': row['unresolved'] = attempt['write_operation']
            row.update(active=None, state='unknown', reason='INTERRUPTED_PROJECTION',
                attribution='none', last_result={'operation_id': attempt['operation_id'],
                    'state': 'unknown', 'reason': 'INTERRUPTED_PROJECTION',
                    'version': attempt['intent']['version'], 'receipt': None})
            state['runs'][run_id]['projection'] = row['state']
            _reserve(row); _capacity(state)
            result = self._view(row)
            return Transition(state, (Event('forge.projection-recovered', {
                'run_id': run_id, 'operation_id': attempt['operation_id'], 'result': result}),), result)
        return self._apply(command, origin, authorize, recover)['result']
