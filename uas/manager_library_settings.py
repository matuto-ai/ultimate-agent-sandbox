"""Installation-only Field Notes settings attachment; no Project content route.

Trusted wiring supplies two independent authenticators. The Room Hub retains
request digests only; the durable SettingsOwner owns configuration and receipts.
A reserved operation is never sent to the owner as a second write.
"""
import json
from . import library, library_settings
from .ledger import Command, Event, LedgerError, RoomLedger, Transition
from .manager_actions import HumanSession


def fail(code): raise LedgerError(code)
def canonical(value): return library_settings.canonical(value).encode()


def envelope(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= library_settings.MAX_REQUEST + 1024:
        fail('SETTINGS_REQUEST_LIMIT')
    try:
        value = json.loads(raw, object_pairs_hook=library._unique_pairs,
                           parse_constant=lambda _: fail('INVALID_SETTINGS_REQUEST'))
    except (ValueError, UnicodeError, RecursionError): fail('INVALID_SETTINGS_REQUEST')
    if (type(value) is not dict or set(value) != {'version','operation_id','mode','request'}
            or type(value['version']) is not int or value['version'] != 1
            or value['mode'] not in ('execute','reconcile')): fail('INVALID_SETTINGS_REQUEST')
    library._token(value['operation_id'], 'operation_id')
    request = library_settings.decode(canonical(value['request']))
    if value['mode'] == 'reconcile' and request['action'] != 'settings-update':
        fail('INVALID_SETTINGS_REQUEST')
    return value, request


class LibrarySettingsContact:
    def __init__(self, owner, authenticate):
        if type(owner) is not library_settings.SettingsOwner or not callable(authenticate):
            fail('INVALID_SETTINGS_BINDING')
        self.owner, self.authenticate = owner, authenticate

    def __call__(self, request, session, *, reconcile, current):
        principal = self.authenticate(session)
        if (type(principal) is not library.LocalHuman
                or principal.human_id != session.manager_id
                or principal.actor_id != session.human.actor_id): fail('FORBIDDEN')
        fenced = library.LocalHuman(principal.human_id, principal.actor_id, principal.authority_version,
            lambda _, project, action: project is None and action == library.SETTINGS_CAPABILITY
                and current() and principal.allowed(None, action),
            lambda: current() and principal.connected() is True)
        method = self.owner.reconcile if reconcile else self.owner.handle
        result = method(canonical(request), fenced)
        library.local_settings_scope(fenced)
        return result


class ManagerLibrarySettingsHub:
    def __init__(self, ledger, *, deployment_id, room_id, instance_id, contact):
        if type(ledger) is not RoomLedger or ledger.room_id != room_id or not callable(contact):
            fail('INVALID_SETTINGS_BINDING')
        for value in (deployment_id, room_id, instance_id): library._token(value, 'binding')
        self.ledger, self.contact = ledger, contact
        self.scope = (deployment_id, room_id, instance_id)

    def handle(self, raw, session):
        value, request = envelope(raw)
        def current():
            return (type(session) is HumanSession
                and (session.deployment_id, session.room_id, session.instance_id) == self.scope
                and session.allowed(library.SETTINGS_CAPABILITY))
        if not current() or request['deployment'] != self.scope[0]: fail('FORBIDDEN')
        metadata = {'request_sha256':library._digest(request), 'session':session.metadata()}
        command = Command(value['operation_id'], 'library.settings', self.scope[0], None, metadata)
        fresh = False
        def reserve(state, _):
            nonlocal fresh
            fresh = True
            return Transition(state, (Event('library.settings.reserved', metadata),), metadata)
        if value['mode'] == 'reconcile':
            if self.ledger.exact_receipt(command, session.human, authorize=lambda *_:current()) is None:
                fail('SETTINGS_OUTCOME_UNKNOWN')
        else:
            self.ledger.apply(command, session.human, authorize=lambda *_:current(), decide=reserve)
        write = request['action'] == 'settings-update'
        result = self.contact(request, session, reconcile=write and not fresh, current=current)
        if not current(): fail('FORBIDDEN')
        if type(result) is not dict or result.get('deployment') != self.scope[0]:
            fail('INVALID_SETTINGS_RESULT')
        if write and (result.get('request_id') != request['request_id']
                or result.get('outcome') not in ('CONFIGURED','REJECTED')): fail('INVALID_SETTINGS_RESULT')
        if len(canonical(result)) > library_settings.MAX_REQUEST: fail('SETTINGS_RESPONSE_LIMIT')
        return {'outcome':'RECEIPT' if write else 'OBSERVED', 'result':result}


class FieldNotesLibrarySettingsHost:
    def __init__(self, hub, authenticate):
        if type(hub) is not ManagerLibrarySettingsHub or not callable(authenticate):
            fail('INVALID_SETTINGS_BINDING')
        self.hub, self.authenticate = hub, authenticate

    def handle(self, raw, context):
        try: return self.hub.handle(raw, self.authenticate(context))
        except Exception as error:
            code = getattr(error, 'code', None)
            safe = {'FORBIDDEN','ID_CONFLICT','SETTINGS_OUTCOME_UNKNOWN','STALE_SETTINGS_AUTHORITY',
                    'INVALID_SETTINGS_REQUEST','SETTINGS_REQUEST_LIMIT','WRONG_SETTINGS_SCOPE'}
            return {'outcome':'UNCONFIRMED', 'reason':code if code in safe else 'SETTINGS_UNAVAILABLE'}
