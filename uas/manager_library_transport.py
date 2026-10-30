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

_ACTIONS = frozenset(('observe', 'inspect', 'reject', 'adjudicate'))
_ERRORS = frozenset(('FORBIDDEN', 'ID_CONFLICT', 'STALE_INSPECTION', 'STALE_CONTROL_STATE',
    'CONTROL_BUSY', 'CONTROL_OUTCOME_UNKNOWN', 'INVALID_CONTROL_REQUEST',
    'CONTROL_REQUEST_LIMIT', 'PROJECT_UNAVAILABLE', 'SERVICE_NOT_AVAILABLE'))


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
    request = decode(canonical(value['request']))
    if request['action'] not in _ACTIONS or (request['action'] == 'observe'
            and request['for_action'] != 'inspect'):
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
        raw = canonical(request)
        method = self.controls.reconcile if reconcile else self.controls.handle
        result = method(raw, fenced)
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
        write = request['action'] in ('reject', 'adjudicate')
        # A reconnect/receipt lookup can never replay or reopen private bodies.
        if value['mode'] == 'reconcile' and not write:
            return {'outcome': 'FRESH_OPEN_REQUIRED'}
        result = self.contact(request, session, reconcile=write and not fresh, current=current,
                              project_identity=self.project_identity)
        if not current(): _fail('FORBIDDEN')
        if len(canonical(result)) > MAX_RESPONSE: _fail('CONTROL_RESPONSE_LIMIT')
        if not write:
            if (type(result) is not dict or result.get('project_id') != self.project_id
                    or result.get('queue_id') != request['queue_id']):
                _fail('INVALID_LIBRARY_RESULT')
            if request['action'] == 'inspect' and (result.get('request_id') != request['request_id']
                    or result.get('media_type') != 'text/plain' or result.get('recursive') is not False
                    or result.get('remote_resources') is not False):
                _fail('INVALID_LIBRARY_RESULT')
            response = {'outcome': 'OBSERVED', 'result': result}
            if len(canonical(response)) > MAX_RESPONSE: _fail('CONTROL_RESPONSE_LIMIT')
            return response
        receipt = library.admit_receipt(result)
        if (any(receipt[key] != request[key] for key in ('request_id', 'settings_id'))
                or receipt['kind'] != request['action']
                or receipt['queue_id'] not in (None, request['queue_id'])
                or receipt['drain_id'] != request['drain_id']):
            _fail('INVALID_LIBRARY_RESULT')
        publication = receipt['publication']
        sha = publication['commit_sha'] if publication else None
        if sha is not None and (type(sha) is not str or not re.fullmatch(r'[0-9a-f]{40}(?:[0-9a-f]{24})?', sha)):
            _fail('INVALID_LIBRARY_RESULT')
        safe = {'outcome': receipt['outcome'], 'service_operation_id': receipt['operation_id'],
                'commit_sha': sha}
        if safe['service_operation_id'] != metadata['service_operation_id']:
            _fail('INVALID_LIBRARY_RESULT')
        result_id = 'library-private-result-' + library._digest([value['operation_id'], safe])
        self.ledger.apply(Command(result_id, 'library.private.result', self.project_id, None,
            {'command_id': value['operation_id'], **safe}), session.human,
            authorize=lambda *_: current(),
            decide=lambda state, _: Transition(state, (Event('library.private.result', safe),), safe))
        return safe


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
