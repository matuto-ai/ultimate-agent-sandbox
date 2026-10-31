"""T31 private authenticated host -> Hub -> Library service attachment.

Trusted installation wiring supplies both authenticators and fixed scope. This
is deliberately not a generic command, listener, UI, draft store or Run gate.
Only request digests and finite receipt projections enter the Room ledger.
Inspection content is returned once to the current authenticated caller; neither
this attachment nor reconnect/replay caches it. Python memory is not zeroized.
"""
import hashlib
import json
import re

from . import library
from .library_controls import Controls, MAX_REQUEST, MAX_RESPONSE, canonical, decode
from .ledger import Command, Event, LedgerError, RoomLedger, Transition
from .manager_actions import HumanSession

_WRITES = frozenset(('drain', 'retry', 'defer', 'requeue', 'reject', 'adjudicate', 'resume'))
_OBSERVABLE = frozenset(('inspect', 'drain', 'retry', 'defer', 'requeue', 'resume'))
_ACTIONS = _WRITES | {'observe', 'inspect'}
_ERRORS = frozenset(('FORBIDDEN', 'ID_CONFLICT', 'STALE_INSPECTION', 'STALE_CONTROL_STATE',
    'CONTROL_BUSY', 'CONTROL_OUTCOME_UNKNOWN', 'INVALID_CONTROL_REQUEST',
    'CONTROL_REQUEST_LIMIT', 'PROJECT_UNAVAILABLE', 'SERVICE_NOT_AVAILABLE',
    'PROJECT_BLOCKED', 'PROJECT_ARCHIVED', 'DRAIN_DISPOSED', 'DRAIN_NOT_BLOCKED',
    'DRAIN_NOT_DISPOSED', 'PROJECT_NOT_BLOCKED', 'PROJECT_NOT_DISPOSED',
    'PROJECT_ARCHIVING', 'SCHEDULER_BUSY', 'SCHEDULER_RECOVERY_REQUIRED',
    'NO_ELIGIBLE_PARKED_WORK', 'ATTENTION_UNAVAILABLE',
    'ATTENTION_UNKNOWN', 'ATTENTION_ALREADY_SNOOZED', 'ATTENTION_NOT_PRESENT',
    'PENDING_ITEM_UNAVAILABLE', 'INSPECTION_CONTEXT_LIMIT', 'INSPECTION_RESPONSE_LIMIT',
    'INVALID_TEXT', 'RECORD_UNCERTAIN', 'TARGET_NOT_QUALIFIED', 'MODEL_NOT_QUALIFIED'))
_RECEIPT_REASONS = _ERRORS | {'ATTENTION_SNOOZED', 'OPERATOR_REQUESTED',
    'OPERATOR_RETRY', 'OPERATOR_RESUME', 'SCHEDULE_RECORDED'}
_NO_EFFECT_ERRORS = frozenset(('STALE_INSPECTION', 'STALE_CONTROL_STATE', 'CONTROL_BUSY',
    'PROJECT_BLOCKED', 'PROJECT_ARCHIVED', 'PROJECT_ARCHIVING', 'PROJECT_NOT_BLOCKED',
    'PROJECT_NOT_DISPOSED', 'DRAIN_DISPOSED', 'NO_ELIGIBLE_PARKED_WORK',
    'ATTENTION_UNAVAILABLE', 'ATTENTION_UNKNOWN', 'ATTENTION_ALREADY_SNOOZED',
    'ATTENTION_NOT_PRESENT', 'PENDING_ITEM_UNAVAILABLE'))


def _receipt_query(request):
    if (type(request) is not dict or set(request) !=
            {'version', 'action', 'project_id', 'for_action'}
            or type(request['version']) is not int or request['version'] != 1
            or request['action'] != 'receipt' or request['for_action'] not in _WRITES):
        _fail('INVALID_CONTROL_REQUEST')
    library._identifier(request['project_id'], 'project_id')
    return request


def _fail(code):
    raise LedgerError(code)


def envelope(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST + 1024:
        _fail('CONTROL_REQUEST_LIMIT')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: _fail('INVALID_CONTROL_REQUEST')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: _fail('INVALID_CONTROL_REQUEST'))
    except (ValueError, UnicodeError, RecursionError):
        _fail('INVALID_CONTROL_REQUEST')
    if (type(value) is not dict or set(value) != {'version', 'operation_id', 'mode', 'request'}
            or type(value['version']) is not int or value['version'] != 1
            or value['mode'] not in ('execute', 'reconcile')):
        _fail('INVALID_CONTROL_REQUEST')
    library._token(value['operation_id'], 'operation_id')
    if type(value['request']) is dict and value['request'].get('action') == 'receipt':
        if value['mode'] != 'reconcile': _fail('INVALID_CONTROL_REQUEST')
        return value, _receipt_query(value['request'])
    request = decode(canonical(value['request']))
    if request['action'] not in _ACTIONS or (request['action'] == 'observe'
            and request['for_action'] not in _OBSERVABLE):
        _fail('INVALID_CONTROL_REQUEST')
    return value, request


class LibraryServiceContact:
    """Authenticated service boundary, with independently resolved Project grants."""
    def __init__(self, controls, authenticate):
        if type(controls) is not Controls or not callable(authenticate):
            _fail('INVALID_LIBRARY_BINDING')
        self.controls, self.authenticate = controls, authenticate

    def __call__(self, request, session, *, reconcile, current, project_identity):
        principal = self.authenticate(session)
        if (type(principal) is not library.LocalHuman
                or principal.human_id != session.manager_id
                or principal.actor_id != session.human.actor_id):
            _fail('FORBIDDEN')
        # Every service publication/read fence also observes current host session.
        fenced = library.LocalHuman(principal.human_id, principal.actor_id,
            principal.authority_version,
            lambda _, project, action: project == project_identity and current() and principal.allowed(project, action),
            lambda: current() and principal.connected() is True)
        if request['action'] == 'receipt':
            result = self.controls.receipt(request['project_id'], request['for_action'],
                request['service_operation_id'], fenced)
        else:
            raw = canonical(request)
            method = self.controls.reconcile if reconcile else self.controls.handle
            # Hold the scheduling fence across the operation and a refusal read.
            # Publisher reserves stable operation identity BEFORE any Git push;
            # scheduling/defer record + effect share one SQLite transaction.
            # Once publication is possible, disposition/requeue mark _failed.
            # Thus only an unfailed owner, absent identity and fresh authority
            # can prove this specific finite refusal had no effect.
            with self.controls.service.scheduler._lock:
                try:
                    result = method(raw, fenced)
                except library.LibraryError as error:
                    if (reconcile or request['action'] not in _WRITES
                            or error.code not in _NO_EFFECT_ERRORS
                            or self.controls.service.scheduler._failed):
                        raise
                    entry = self.controls._entry(request['project_id'])
                    scope = self.controls._scope(fenced, entry, request['action'])
                    identity = 'human-control-' + library._digest(
                        [scope.project_identity, request['request_id']])
                    with self.controls.service.scheduler._records() as records:
                        prior = records.record(identity, project_identity=scope.project_identity)
                    if prior is not None: raise
                    if not current() or not fenced.allowed(project_identity, 'library-' + request['action']):
                        _fail('FORBIDDEN')
                    result = {'outcome': 'REFUSED', 'reason': error.code}
        kind = request.get('for_action', request['action'])
        if not fenced.allowed(project_identity, 'library-' + kind): _fail('FORBIDDEN')
        return result


class ManagerLibraryHub:
    def __init__(self, ledger, *, deployment_id, room_id, instance_id,
                 project_id, project_identity, contact):
        if type(ledger) is not RoomLedger or ledger.room_id != room_id or not callable(contact):
            _fail('INVALID_LIBRARY_BINDING')
        for value in (deployment_id, room_id, instance_id, project_id): library._token(value, 'binding')
        self.ledger, self.contact = ledger, contact
        self.scope = (deployment_id, room_id, instance_id)
        if type(project_identity) is not str or not project_identity.startswith('github.com/'):
            _fail('INVALID_LIBRARY_BINDING')
        library._token(project_identity[len('github.com/'):], 'project_identity')
        self.project_id, self.project_identity = project_id, project_identity

    def handle(self, raw, session):
        value, request = envelope(raw)
        kind = request.get('for_action', request['action'])
        def current():
            return (type(session) is HumanSession
                and (session.deployment_id, session.room_id, session.instance_id) == self.scope
                and session.allowed('library-' + kind))
        if not current(): _fail('FORBIDDEN')
        if request['project_id'] != self.project_id: _fail('FORBIDDEN')
        if request['action'] == 'receipt':
            return self._reconcile_receipt(value, request, session, current)
        metadata = {'request_sha256': hashlib.sha256(canonical(request)).hexdigest(),
                    'project_identity': self.project_identity, 'session': session.metadata()}
        if 'request_id' in request:
            metadata['service_operation_id'] = 'human-control-' + library._digest(
                [self.project_identity, request['request_id']])
        command = Command(value['operation_id'], 'library.private', self.project_id, None, metadata)
        fresh = False
        def reserve(state, _):
            nonlocal fresh
            fresh = True
            return Transition(state, (Event('library.private.reserved', metadata),), metadata)
        if value['mode'] == 'reconcile':
            if self.ledger.exact_receipt(command, session.human, authorize=lambda *_: current()) is None:
                _fail('CONTROL_OUTCOME_UNKNOWN')
        else:
            self.ledger.apply(command, session.human, authorize=lambda *_: current(), decide=reserve)
        write = request['action'] in _WRITES
        # A reconnect/receipt lookup can never replay or reopen private bodies.
        if value['mode'] == 'reconcile' and not write:
            return {'outcome': 'FRESH_OPEN_REQUIRED'}
        result = self.contact(request, session, reconcile=write and not fresh, current=current,
                              project_identity=self.project_identity)
        if not current(): _fail('FORBIDDEN')
        if len(canonical(result)) > MAX_RESPONSE: _fail('CONTROL_RESPONSE_LIMIT')
        if not write:
            if (type(result) is not dict or result.get('project_id') != self.project_id
                    or ('queue_id' in request and result.get('queue_id') != request['queue_id'])):
                _fail('INVALID_LIBRARY_RESULT')
            if request['action'] == 'inspect' and (result.get('request_id') != request['request_id']
                    or result.get('media_type') != 'text/plain' or result.get('recursive') is not False
                    or result.get('remote_resources') is not False):
                _fail('INVALID_LIBRARY_RESULT')
            response = {'outcome': 'OBSERVED', 'result': result}
            if len(canonical(response)) > MAX_RESPONSE: _fail('CONTROL_RESPONSE_LIMIT')
            return response
        if (type(result) is dict and set(result) == {'outcome', 'reason'}
                and result['outcome'] == 'REFUSED' and result['reason'] in _NO_EFFECT_ERRORS):
            # Not a durable service receipt. If this response is lost, the old
            # reservation stays unknown; it can never authorize another write.
            return result
        return self._write_result(result, value['operation_id'], request, metadata,
                                  session, current)

    def _write_result(self, result, operation_id, request, metadata, session, current):
        receipt = library.admit_receipt(result)
        if (any(receipt[key] != request[key] for key in ('request_id', 'settings_id') if key in request)
                or receipt['kind'] != request.get('for_action', request['action'])
                or ('queue_id' in request and receipt['queue_id'] not in (None, request['queue_id']))
                or ('drain_id' in request and receipt['drain_id'] != request['drain_id'])):
            _fail('INVALID_LIBRARY_RESULT')
        publication = receipt['publication']
        sha = publication['commit_sha'] if publication else None
        if sha is not None and (type(sha) is not str or not re.fullmatch(r'[0-9a-f]{40}(?:[0-9a-f]{24})?', sha)):
            _fail('INVALID_LIBRARY_RESULT')
        safe = {'outcome': receipt['outcome'], 'service_operation_id': receipt['operation_id'],
                'commit_sha': sha, 'kind': receipt['kind'], 'drain_id': receipt['drain_id'],
                'reason': receipt['reason'] if receipt['reason'] in _RECEIPT_REASONS else None,
                'acknowledgement': receipt['acknowledgement']}
        if safe['service_operation_id'] != metadata['service_operation_id']:
            _fail('INVALID_LIBRARY_RESULT')
        if not current(): _fail('FORBIDDEN')
        result_id = 'library-private-result-' + library._digest([operation_id, safe])
        self.ledger.apply(Command(result_id, 'library.private.result', self.project_id, None,
            {'command_id': operation_id, **safe}), session.human,
            authorize=lambda *_: current(),
            decide=lambda state, _: Transition(state, (Event('library.private.result', safe),), safe))
        return safe

    def _reconcile_receipt(self, value, request, session, current):
        # Browser retains only an opaque operation identity and action. The
        # original request body is neither needed nor recovered from a cache.
        # matched_receipt enforces exact original Origin, session and Project.
        found = {}
        def matches(command):
            if (command.kind != 'library.private' or command.target != self.project_id
                    or command.payload.get('project_identity') != self.project_identity
                    or command.payload.get('session') != session.metadata()
                    or 'service_operation_id' not in command.payload):
                return False
            found.update(command.payload)
            return True
        prior = self.ledger.matched_receipt(value['operation_id'], session.human,
            authorize=lambda *_: current(), matches=matches)
        if prior is None: _fail('CONTROL_OUTCOME_UNKNOWN')
        result = self.contact({**request, 'service_operation_id': found['service_operation_id']},
            session, reconcile=True, current=current, project_identity=self.project_identity)
        if not current(): _fail('FORBIDDEN')
        if len(canonical(result)) > MAX_RESPONSE: _fail('CONTROL_RESPONSE_LIMIT')
        return self._write_result(result, value['operation_id'], request, found, session, current)


class FieldNotesLibraryHost:
    """Attach to authenticated Manager host; context is never supplied by JSON."""
    def __init__(self, hub, authenticate):
        if type(hub) is not ManagerLibraryHub or not callable(authenticate):
            _fail('INVALID_LIBRARY_BINDING')
        self.hub, self.authenticate = hub, authenticate

    def handle(self, raw, context):
        try:
            return self.hub.handle(raw, self.authenticate(context))
        except Exception as error:
            code = getattr(error, 'code', None)
            # Unknown network/driver/decoder diagnostics may contain body text.
            return {'outcome': 'UNCONFIRMED', 'reason': code if code in _ERRORS else 'LIBRARY_UNAVAILABLE'}
