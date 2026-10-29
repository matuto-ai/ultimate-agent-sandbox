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



@dataclass(frozen=True, init=False)
class AdmittedRunGrant:
    """Revocation handle for one explicit Open, not human command authority.

    Only the original authenticated frame can mint this in-memory handle. It
    retains neither the request session nor its TLS connection. The native Run
    owner must separately bind the committed admission, Run generation, policy,
    Actor and exact live process owners before doing any work. This handle alone
    cannot open a Run, authenticate a command, or reconstruct authority on restart.
    """
    _bindings: object
    _fingerprint: str
    _grant: HumanActionGrant
    _generation: int
    operation_id: str
    issue_number: int

    def __init__(self, *args, **kwargs):
        raise LedgerError('AUTHENTICATED_RUN_FRAME_REQUIRED')

    @property
    def deployment_id(self): return self._grant.deployment_id
    @property
    def room_id(self): return self._grant.room_id
    @property
    def instance_id(self): return self._grant.instance_id
    @property
    def manager_id(self): return self._grant.manager_id
    @property
    def human(self): return self._grant.human

    def require_current(self):
        if type(self) is not AdmittedRunGrant or type(self._bindings) is not HumanActionBindings:
            raise LedgerError('ADMITTED_RUN_GRANT_REQUIRED')
        self._bindings._owner()
        bound = self._bindings._bindings.get(self._fingerprint)
        if (bound is None or bound[0] is not self._grant or bound[1] != self._generation
                or not {'open-run', 'authorize-run-request'}.issubset(self._grant.actions)
                or 'human-open-run' not in self._grant.human.capabilities):
            raise LedgerError('ADMITTED_RUN_GRANT_REVOKED')
        return True

    def __reduce_ex__(self, protocol):
        raise TypeError('Admitted Run grants are not serializable')

    def __copy__(self): return self
    def __deepcopy__(self, memo): return self


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
        self._active_session, self._active_open = None, None
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
        self._active_session, self._active_open = None, None

    def run_admission_lease(self, session, operation_id, issue_number):
        """Mint only for this original explicit Open and its live session.

        These arguments are compared with a snapshot made before yielding the
        frame, so a handler cannot change the received payload into another grant.
        No transport, callback or HumanSession is retained by the result.
        """
        self._current()
        if (type(session) is not HumanSession or session is not self._active_session
                or self._active is None or self._active_open is None
                or type(operation_id) is not str or type(issue_number) is not int
                or not 1 <= issue_number <= 9_999_999_999
                or self._active_open != (operation_id, issue_number)
                or not session.allowed('open-run') or not session.allowed('authorize-run-request')
                or 'human-open-run' not in session.human.capabilities):
            raise LedgerError('AUTHENTICATED_RUN_FRAME_REQUIRED')
        _token(operation_id)
        result = object.__new__(AdmittedRunGrant)
        for name, value in (('_bindings', self._bindings), ('_fingerprint', self._fingerprint),
                ('_grant', self._grant), ('_generation', self._generation),
                ('operation_id', operation_id), ('issue_number', issue_number)):
            object.__setattr__(result, name, value)
        result.require_current()
        return result

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
            self._active_session = session
            self._active_open = ((value['payload'].get('operation_id'), value['payload'].get('issue_number'))
                                 if action == 'open-run' else None)
            yield value, session
        except BaseException:
            self.close()
            raise
        finally:
            # Deny-only cleanup is unconditional, even if a caller illegally
            # exits this context on another thread. A saved session cannot live on.
            self._active = None
            self._active_session, self._active_open = None, None
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
