"""Authenticated host attachment for Field Notes' fixed action client.

This is an opt-in host call boundary, not a listener or login implementation.
The operator constructs one attachment per Room with actual owners. The host's
existing authenticated request context resolves a fresh HumanSession each call;
no browser value selects a principal, owner, credential, endpoint or Room.
"""
import json

from .ledger import LedgerError, _json, _token
from .manager_actions import HumanSession, ManagerHubActions
from .manager_action_protocol import ManagerActionProtocol, MAX_ACTION_BYTES, _pairs


class FieldNotesActionHost:
    def __init__(self, owner, authenticate):
        if type(owner) is not ManagerHubActions or not callable(authenticate):
            raise LedgerError('MANAGER_OWNER_REQUIRED')
        self.owner, self.authenticate = owner, authenticate
        self.protocol = ManagerActionProtocol(owner)

    def handle(self, body, *, context):
        """Host routes a bounded message to this preselected attachment.

        Field Notes adapters map view(runId), lifecycle(), replacement(id),
        execute(packet), inspect(originalPacket) to the five envelopes below. `context` is the server's
        authenticated request context, NEVER a field from this JSON envelope.
        Default Field Notes remains read-only without this explicit attachment.
        """
        unavailable = {'status': 'unavailable', 'reason': 'MANAGER_AUTHENTICATION_REQUIRED',
                       'current': None, 'actions': []}
        try:
            session = self.authenticate(context)
            if (type(session) is not HumanSession or not session.allowed('observe')
                    or session.deployment_id != self.owner.deployment_id
                    or session.room_id != self.owner.ledger.room_id
                    or session.instance_id != self.owner.instance_id):
                return unavailable
        except Exception:
            return unavailable
        value = None
        try:
            if type(body) is not bytes or not 0 < len(body) <= MAX_ACTION_BYTES:
                raise LedgerError('INVALID_MANAGER_ACTION')
            value = json.loads(body.decode('utf-8'), object_pairs_hook=_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            _json(value)
            if type(value) is not dict or type(value.get('kind')) is not str:
                raise LedgerError('INVALID_MANAGER_ACTION')
            kind = value['kind']
            if kind in {'execute','inspect'} and set(value) == {'kind', 'request'}:
                result = (self.protocol.handle(_json(value['request']).encode(), session=session)
                    if kind == 'execute' else self.owner.inspect(value['request'], session=session))
                if not session.allowed('observe'):
                    # Revocation is not rollback. Suppress owner data and any
                    # receipt; an already-attempted effect stays unconfirmed.
                    return {'operation_id': result.get('operation_id'),
                            'outcome': 'denied' if result.get('outcome') == 'denied' else 'unknown',
                            'reason': 'MANAGER_AUTHENTICATION_REQUIRED', 'current': None}
                return result
            if kind == 'run' and set(value) == {'kind', 'run_id'}:
                result = self.owner.view(_token(value['run_id']), session=session)
            elif kind == 'lifecycle' and set(value) == {'kind'}:
                result = self.owner.lifecycle_view(session=session)
            elif kind == 'replacement' and set(value) == {'kind', 'participant_id'}:
                result = {'replacement': self.owner.replacement_view(
                    _token(value['participant_id']), session=session), 'current': None, 'actions': []}
            else:
                raise LedgerError('INVALID_MANAGER_ACTION')
            # Recheck before disclosing a view if authentication changed during
            # an owner read. Execution itself rechecks inside consuming owners.
            if not session.allowed('observe'): return unavailable
            return {'status': 'available', 'scope': {
                'deployment_id': session.deployment_id, 'room_id': session.room_id,
                'instance_id': session.instance_id}, **result}
        except (LedgerError, ValueError, UnicodeError, RecursionError) as error:
            return {**unavailable, 'reason': error.code if isinstance(error, LedgerError)
                    else 'INVALID_MANAGER_ACTION'}
        except Exception:
            if type(value) is dict and value.get('kind') == 'execute':
                return {'operation_id': None, 'outcome': 'unknown',
                        'reason': 'OWNER_OUTCOME_UNCONFIRMED', 'current': None}
            return {**unavailable, 'reason': 'OWNER_STATE_UNAVAILABLE'}
