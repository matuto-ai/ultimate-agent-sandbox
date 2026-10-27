"""Supervisor-owned fenced Start/Stop for an existing persistent Room only.

No spec, mount, image, arguments, Destroy or Engine operation comes from a
Manager request. Current Supervisor policy and authenticated human are checked
under the lifecycle lock, even before duplicate receipt disclosure.
"""
import hashlib
import json
import sqlite3

from .ledger import Command, Event, LedgerError, RoomLedger, Transition, _json
from .lifecycle import LifecycleError
from .manager_actions import HumanSession, request


def current(state):
    if state is None: return None
    value = {key: state.get(key) for key in ('room_id', 'instance_id', 'observation_revision', 'phase', 'desired', 'authority')}
    value['observed_version'] = hashlib.sha256(_json(value).encode()).hexdigest()
    return value


def _eligible(supervisor, state, action, session):
    if not state or state['instance_id'] != session.instance_id or state['desired'] == 'destroyed':
        raise LedgerError('MANAGER_SCOPE_MISMATCH')
    if not session.allowed(action): raise LedgerError('FORBIDDEN')
    supervisor._allowed(action, state)
    phases = {'stopped', 'start_failed'} if action == 'start' else {'running', 'start_failed', 'stop_failed'}
    if state['phase'] not in phases: raise LedgerError('MANAGER_ACTION_INELIGIBLE')
    if action == 'start':
        control = supervisor._control_plane
        if control is None or control.require_ready_locked() is not True:
            raise LedgerError('CONTROL_PLANE_NOT_READY')


def view(supervisor, *, session, deployment_id):
    if (type(session) is not HumanSession or session.deployment_id != deployment_id
            or session.room_id != supervisor.room_id): raise LedgerError('MANAGER_SCOPE_MISMATCH')
    with supervisor._locked():
        state = supervisor._read(); actions = []
        for action in ('start', 'stop'):
            reason = None
            try: _eligible(supervisor, state, action, session)
            except (LifecycleError, LedgerError) as error: reason = error.code
            actions.append({'action': action, 'object_id': None if state is None else state['instance_id'],
                            'eligible': reason is None, 'reason': reason})
        return {'current': current(state), 'actions': actions}


def execute(supervisor, value, *, session, deployment_id, ledger):
    """Called by Supervisor.manager_action; not a JSON-selected service adapter."""
    if (type(session) is not HumanSession or session.deployment_id != deployment_id
            or session.room_id != supervisor.room_id or type(ledger) is not RoomLedger
            or ledger.room_id != supervisor.room_id):
        raise LedgerError('MANAGER_SCOPE_MISMATCH')
    value = request(value, session)
    if value['action'] not in {'start', 'stop'} or value['payload']:
        raise LedgerError('INVALID_MANAGER_ACTION')
    with supervisor._locked():
        state = supervisor._read()
        def response(outcome, reason=None):
            return {'operation_id': value['operation_id'], 'outcome': outcome, 'reason': reason,
                    'current': current(supervisor._read())}
        if (state is None or state['instance_id'] != session.instance_id
                or value['object_id'] != state['instance_id'] or state['desired'] == 'destroyed'):
            return response('denied', 'MANAGER_SCOPE_MISMATCH')
        if not session.allowed(value['action']): return response('denied', 'FORBIDDEN')
        try:
            supervisor._allowed(value['action'], state)
            path = supervisor._owned_directory(state) / 'manager-actions.db'
            if path.is_symlink(): raise LifecycleError('MANAGER_ACTION_STORE_INVALID')
        except LifecycleError as error:
            return response('denied', error.code)
        canonical = _json({'request': value, 'principal': session.metadata()})
        command = Command(value['operation_id'], 'room.manager-' + value['action'], state['instance_id'],
                          None, {'request': value, 'principal': session.metadata()})
        def authorized(*_):
            supervisor._allowed(value['action'], supervisor._read())
            return session.allowed(value['action'])
        database = None; intent = False
        try:
            if path.exists():
                database = sqlite3.connect(path, isolation_level=None)
                database.execute('PRAGMA synchronous=FULL')
                previous = database.execute('SELECT request,result FROM actions WHERE operation=?', (value['operation_id'],)).fetchone()
                if previous is not None:
                    if previous[0] != canonical: return response('denied', 'ID_CONFLICT')
                    # Unknown intent and old receipts never restart a Room
                    # stopped by a later action. Reconcile through owner state.
                    return response('denied' if previous[1] is not None else 'unknown',
                                    'MANAGER_DUPLICATE_ACTION' if previous[1] is not None else 'OWNER_OUTCOME_UNCONFIRMED')
            if (state.get('observation_revision') is None
                    or current(state)['observed_version'] != value['observed_version']):
                return response('denied', 'MANAGER_STALE_ACTION')
            _eligible(supervisor, state, value['action'], session)
            # The actual Hub owns the Room-wide operation namespace. Reserve
            # only after eligibility checks, before a separate lifecycle effect.
            previous = ledger.exact_receipt(command, session.human, authorize=authorized)
            if previous is not None: return response('unknown', 'OWNER_OUTCOME_UNCONFIRMED')
            def reserve(hub_state, _):
                return Transition(hub_state, (Event('room.manager-intent', {'operation_id': value['operation_id'],
                    'action': value['action'], 'instance_id': state['instance_id']}),), {'status': 'pending'})
            ledger.apply(command, session.human, authorize=authorized, decide=reserve)
            intent = True
            if database is None:
                database = sqlite3.connect(path, isolation_level=None)
                database.execute('PRAGMA synchronous=FULL')
                database.execute('CREATE TABLE actions (operation TEXT PRIMARY KEY, request TEXT NOT NULL, result TEXT)')
            database.execute('INSERT INTO actions VALUES (?,?,NULL)', (value['operation_id'], canonical))
            state['manager_action'] = {'operation_id': value['operation_id'],
                'request_digest': hashlib.sha256(canonical.encode()).hexdigest()}
            state.update(desired='running' if value['action'] == 'start' else 'stopped',
                         phase='starting' if value['action'] == 'start' else 'stopping')
            supervisor._save(state)  # Exact durable intent before existing owner effects.
            if value['action'] == 'start': supervisor._converge_running(state)
            else: supervisor._converge_stopped(state)
            final = supervisor._read()
            expected = 'running' if value['action'] == 'start' else 'stopped'
            result = response('confirmed' if final['phase'] == expected else 'unknown',
                              None if final['phase'] == expected else 'LIFECYCLE_RECONCILIATION_REQUIRED')
            database.execute('UPDATE actions SET result=? WHERE operation=?', (_json(result), value['operation_id']))
            return result
        except (LifecycleError, LedgerError) as error:
            return response('unknown' if intent else 'denied', 'OWNER_OUTCOME_UNCONFIRMED' if intent else error.code)
        except (sqlite3.Error, OSError):
            return response('unknown', 'OWNER_OUTCOME_UNCONFIRMED')
        finally:
            if database is not None: database.close()


def inspect_result(supervisor, value, session):
    """Read under caller-held lifecycle lock; absence/intent is not no-effect."""
    state = supervisor._read()
    path = supervisor._owned_directory(state) / 'manager-actions.db'
    if path.is_symlink() or not path.is_file(): return 'unknown'
    connection = None
    try:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
        row = connection.execute('SELECT request,result FROM actions WHERE operation=?',
                                 (value['operation_id'],)).fetchone()
        if row is None: return 'unknown'
        if row[0] != _json({'request': value, 'principal': session.metadata()}): raise LedgerError('ID_CONFLICT')
        if row[1] is None: return 'unknown'
        return 'confirmed' if json.loads(row[1]).get('outcome') == 'confirmed' else 'unknown'
    except (sqlite3.Error, ValueError, OSError):
        return 'unknown'
    finally:
        if connection is not None: connection.close()
