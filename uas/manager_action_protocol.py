"""Bounded browser/Manager-to-Hub command boundary on authenticated host calls.

The caller supplies a host-authenticated HumanSession, not JSON credentials.
The existing deployment transport/host owns TLS, sessions and scheduling; this
module opens no listener, installs no login and grants no new authority.
"""
import json

from .ledger import LedgerError, _json
from .manager_actions import HumanSession, ManagerHubActions

MAX_ACTION_BYTES = 16384


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise LedgerError('INVALID_MANAGER_ACTION')
        result[key] = value
    return result


class ManagerActionProtocol:
    """Exact fixed route into actual owners; UI prose/eligibility is irrelevant."""
    def __init__(self, owner):
        if type(owner) is not ManagerHubActions: raise LedgerError('MANAGER_OWNER_REQUIRED')
        self.owner = owner

    def handle(self, body, *, session):
        if type(session) is not HumanSession: raise LedgerError('MANAGER_AUTHENTICATION_REQUIRED')
        if type(body) is not bytes or not 0 < len(body) <= MAX_ACTION_BYTES:
            return {'operation_id': None, 'outcome': 'denied', 'reason': 'INVALID_MANAGER_ACTION', 'current': None}
        try:
            value = json.loads(body.decode('utf-8'), object_pairs_hook=_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            _json(value)
        except (ValueError, UnicodeError, RecursionError, LedgerError):
            return {'operation_id': None, 'outcome': 'denied', 'reason': 'INVALID_MANAGER_ACTION', 'current': None}
        return self.owner.execute(value, session=session)
