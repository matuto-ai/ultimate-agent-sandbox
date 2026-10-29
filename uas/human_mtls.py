"""Request-scoped human mTLS authentication; no listener, account or action host.

Trusted operator grants are distinct from Room-stream and Room-Start bindings.
A received JSON frame supplies action data only; it never supplies authority.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import re
import ssl
import threading

from .ledger import LedgerError, Origin, _json, _token
from .manager_actions import HumanSession
from .manager_action_protocol import MAX_ACTION_BYTES
from .manager_transport import receive_frame


PATH = '/uas/human-action/v1'
ACTIONS = frozenset({'observe', 'open-run', 'authorize-run-request',
                     'request-changes', 'reconcile-changes'})
_FRAME_ACTIONS = {
    'observe': frozenset({'observe'}),
    'authorize-run-request': frozenset({'authorize-run-request'}),
    'open-run': frozenset({'open-run', 'authorize-run-request'}),
    'request-changes': frozenset({'request-changes', 'observe'}),
    'reconcile-changes': frozenset({'reconcile-changes', 'observe'}),
}
_AUTHORITY_FIELDS = frozenset({'principal', 'origin', 'callback', 'human', 'human_origin', 'actor_id',
    'incarnation_id', 'authority_version', 'capabilities', 'authorized', 'connected',
    'session', 'grant', 'actions'})
_CORRELATION_FIELDS = frozenset({'deployment_id', 'room_id', 'instance_id', 'manager_id'})


def _fingerprint(value):
    if type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise LedgerError('INVALID_HUMAN_CERTIFICATE_BINDING')
    return value


@dataclass(frozen=True)
class HumanActionGrant:
    deployment_id: str
    room_id: str
    instance_id: str
    manager_id: str
    human: Origin
    actions: tuple[str, ...] = ()

    def __post_init__(self):
        for value in (self.deployment_id, self.room_id, self.instance_id, self.manager_id):
            if type(value) is not str:
                raise LedgerError('INVALID_HUMAN_ACTION_GRANT')
            _token(value)
        if (type(self.human) is not Origin or type(self.actions) is not tuple
                or any(type(action) is not str or action not in ACTIONS for action in self.actions)
                or len(set(self.actions)) != len(self.actions)):
            raise LedgerError('INVALID_HUMAN_ACTION_GRANT')
        self.human.canonical()


def _peer(channel):
    """Authenticate already-established server-side TLS, not connection liveness."""
    try:
        if (type(channel) is not ssl.SSLSocket or channel.server_side is not True
                or channel.fileno() < 0 or channel.context.verify_mode != ssl.CERT_REQUIRED
                or channel.context.minimum_version < ssl.TLSVersion.TLSv1_3
                or channel.version() != 'TLSv1.3'):
            raise LedgerError('HUMAN_MUTUAL_TLS_REQUIRED')
        certificate = channel.getpeercert(binary_form=True)
        if type(certificate) is not bytes or not certificate:
            raise LedgerError('HUMAN_CLIENT_CERTIFICATE_REQUIRED')
        return hashlib.sha256(certificate).hexdigest()
    except LedgerError:
        raise
    except Exception:
        raise LedgerError('HUMAN_MUTUAL_TLS_REQUIRED') from None


class HumanActionBindings:
    """Explicit trusted registry; changing even an equal grant rotates authority."""
    def __init__(self, bindings=None):
        if bindings is None:
            bindings = {}
        if type(bindings) is not dict:
            raise LedgerError('HUMAN_ACTION_BINDINGS_REQUIRED')
        self._bindings = {}
        self._generation = 0
        self._owner_thread = threading.get_ident()
        for fingerprint, grant in bindings.items():
            self.bind(fingerprint, grant)

    def _owner(self):
        if threading.get_ident() != self._owner_thread:
            raise LedgerError('HUMAN_AUTHENTICATION_OWNER_REQUIRED')

    def _advance(self):
        self._owner()
        if self._generation >= 2**63 - 1:
            raise LedgerError('HUMAN_GRANT_GENERATION_EXHAUSTED')
        self._generation += 1
        return self._generation

    def bind(self, fingerprint, grant):
        self._owner()
        _fingerprint(fingerprint)
        if type(grant) is not HumanActionGrant:
            raise LedgerError('INVALID_HUMAN_ACTION_GRANT')
        self._bindings[fingerprint] = (grant, self._advance())

    def revoke(self, fingerprint):
        self._owner()
        _fingerprint(fingerprint)
        # Removal alone invalidates old sessions; never discard generation state.
        self._bindings.pop(fingerprint, None)

    def accept(self, channel):
        self._owner()
        return HumanActionConnection(self, channel)


def _frame(value, grant):
    if (type(value) is not dict or set(value) != {'version', 'action', 'payload'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['action']) is not str or value['action'] not in ACTIONS
            or type(value['payload']) is not dict):
        raise LedgerError('INVALID_HUMAN_ACTION_FRAME')
    if len(_json(value).encode('utf-8')) > MAX_ACTION_BYTES:
        raise LedgerError('HUMAN_ACTION_FRAME_LIMIT')
    def data_only(item):
        if type(item) is dict:
            if _AUTHORITY_FIELDS.intersection(item):
                raise LedgerError('JSON_HUMAN_AUTHORITY_DENIED')
            # Existing exact Manager packets retain their scope correlation
            # fields verbatim. Matching values do not select or grant authority.
            if any(type(item[key]) is not str or item[key] != getattr(grant, key)
                   for key in _CORRELATION_FIELDS.intersection(item)):
                raise LedgerError('HUMAN_ACTION_SCOPE_MISMATCH')
            for child in item.values():
                data_only(child)
        elif type(item) is list:
            for child in item:
                data_only(child)
    data_only(value['payload'])
    return value


class HumanActionConnection:
    """Borrowed TLS channel. Only a received frame creates a usable HumanSession."""
    def __init__(self, bindings, channel):
        if type(bindings) is not HumanActionBindings:
            raise LedgerError('HUMAN_ACTION_BINDINGS_REQUIRED')
        bindings._owner()
        fingerprint = _peer(channel)
        bound = bindings._bindings.get(fingerprint)
        if bound is None:
            raise LedgerError('UNREGISTERED_HUMAN_CERTIFICATE')
        self._bindings, self._channel, self._fingerprint = bindings, channel, fingerprint
        self._grant, self._generation = bound
        self._closed, self._active = False, None
        self._owner_thread = threading.get_ident()

    def _owner(self):
        if threading.get_ident() != self._owner_thread:
            raise LedgerError('HUMAN_AUTHENTICATION_OWNER_REQUIRED')
        self._bindings._owner()

    def _current(self):
        self._owner()
        bound = self._bindings._bindings.get(self._fingerprint)
        if (self._closed or bound is None or bound[0] is not self._grant
                or bound[1] != self._generation or _peer(self._channel) != self._fingerprint):
            raise LedgerError('HUMAN_AUTHENTICATION_REVOKED')

    def close(self):
        """Invalidate authentication only; the host still owns its TLS socket."""
        self._owner()
        self._closed, self._active = True, None

    def _connected(self, token):
        if threading.get_ident() != self._owner_thread or self._active is not token:
            return False
        try:
            self._current()
            return True
        except Exception:
            if threading.get_ident() == self._owner_thread:
                self.close()
            return False

    @contextmanager
    def request(self, value):
        """Process one already received frame on this authenticated TLS connection.

        The trusted HTTP host may route a bounded request before entering here.
        JSON still supplies no authority: the original peer, live binding and
        exact grant are rechecked before and after frame validation.

        Owner/provider calls must finish within this scope and keep using the
        canonical HumanSession checks. Remote EOF can only be known when I/O
        observes it; certificate getters never assert remote peer liveness.
        """
        self._owner()
        if self._active is not None:
            self.close()
            raise LedgerError('HUMAN_FRAME_ALREADY_ACTIVE')
        try:
            self._current()
            value = _frame(value, self._grant)
            self._current()
            grant, action = self._grant, value['action']
            permitted = _FRAME_ACTIONS[action]
            if not permitted.issubset(grant.actions):
                raise LedgerError('HUMAN_ACTION_DENIED')
            token = object()
            self._active = token
            session = HumanSession(grant.deployment_id, grant.room_id, grant.instance_id,
                grant.manager_id, grant.human,
                authorized=lambda current, selected: current is session and type(selected) is str
                    and selected in permitted and selected in grant.actions and self._connected(token),
                connected=lambda: self._connected(token))
            yield value, session
        except BaseException:
            self.close()
            raise
        finally:
            # Deny-only cleanup is unconditional, even if a caller illegally
            # exits this context on another thread. A saved session cannot live on.
            self._active = None
            if threading.get_ident() != self._owner_thread:
                self._closed = True
                raise LedgerError('HUMAN_AUTHENTICATION_OWNER_REQUIRED')

    @contextmanager
    def receive(self):
        """Receive one fixed-protocol frame and retain the same request fences."""
        self._owner()
        if self._active is not None:
            self.close()
            raise LedgerError('HUMAN_FRAME_ALREADY_ACTIVE')
        try:
            self._current()
            value = receive_frame(self._channel, path=PATH)
            with self.request(value) as admitted:
                yield admitted
        except BaseException:
            self.close()
            raise
