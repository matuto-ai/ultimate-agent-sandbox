"""Native human-action audit fencing over the original private Broker channel.

No audit database is copied, opened by the native host, or made less private.
The Broker retains its real SQLite writer fence while the host consumes one
short local transaction. Acquisition/release happen outside all owner locks.
This is not a provider route, credential grant, or persisted authority lease.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import re
import select
import socket
import threading
import time
import uuid

from .kernel_origin import HeldOrigin, OriginDenied, _identity, alive, receive
from .ledger import LedgerError, Origin, _json, _token
from .lifecycle import _unique_object


KIND = 'NATIVE_MANAGER_AUDIT'
ACTIONS = frozenset({'request-changes', 'reconcile-changes'})
AUDIT_ACTIONS = ACTIONS | {'observe'}
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_REQUEST = re.compile(r'[0-9a-f]{32}\Z')


def _state(value):
    if (type(value) is not dict or set(value) != {'version', 'blocked', 'partial', 'reason'}
            or type(value['version']) is not str or not _SHA.fullmatch(value['version'])
            or type(value['blocked']) is not bool or type(value['partial']) is not bool
            or value['reason'] not in (None, 'AUDIT_UNAVAILABLE', 'FORGE_RECONCILIATION_REQUIRED')
            or value['blocked'] != (value['reason'] is not None)):
        raise LedgerError('NATIVE_AUDIT_STATE_INVALID')
    return deepcopy(value)


def _scope(packet, broker):
    fields = {'kind', 'request_id', 'deployment_id', 'room_id', 'room_instance', 'repository',
              'operation_id', 'action', 'request_digest', 'origin'}
    if (type(packet) is not dict or set(packet) != fields or packet['kind'] != KIND
            or type(packet['request_id']) is not str or not _REQUEST.fullmatch(packet['request_id'])
            or packet['deployment_id'] != broker.audit.deployment_id
            or packet['room_id'] != broker.binding.room_id
            or packet['room_instance'] != broker.room_instance
            or packet['repository'] != broker.binding.repository
            or packet['action'] not in AUDIT_ACTIONS
            or type(packet['request_digest']) is not str or not _SHA.fullmatch(packet['request_digest'])):
        raise LedgerError('NATIVE_AUDIT_SCOPE_INVALID')
    _token(packet['operation_id'])
    origin = packet['origin']
    if (type(origin) is not dict or set(origin) != {'actor_id', 'participant_id', 'incarnation_id',
                                                  'authority_version', 'capabilities'}
            or type(origin['capabilities']) is not list):
        raise LedgerError('NATIVE_AUDIT_ORIGIN_REQUIRED')
    human = Origin(**{**origin, 'capabilities': tuple(origin['capabilities'])})
    required = 'human-open-run' if packet['action'] == 'observe' else 'human-control-run'
    if human.canonical() != origin or required not in human.capabilities:
        raise LedgerError('NATIVE_AUDIT_ORIGIN_REQUIRED')
    return hashlib.sha256(_json(packet).encode()).hexdigest()


def _holder_exited(holder):
    """Unknown descriptor state must never release a live holder's audit fence."""
    try:
        if type(holder) is not HeldOrigin or _identity(holder.pidfd) != holder.identity:
            return False
        poll = select.poll(); poll.register(holder.pidfd, select.POLLIN)
        events = poll.poll(0)
        return (len(events) == 1 and events[0][0] == holder.pidfd
                and events[0][1] in (select.POLLIN, select.POLLIN | select.POLLHUP)
                and _identity(holder.pidfd) == holder.identity)
    except BaseException:
        return False


def _wait_holder_exit(holder):
    # No timeout releases authority. The fixed outer qualification owner owns
    # the host deadline and termination; a live/unknown holder stays fenced.
    while True:
        try:
            if _holder_exited(holder): return
            time.sleep(.05)
        except BaseException:
            continue


def serve_audit_fence(channel, broker, holder, packet):
    """Called only after the existing server verified this Supervisor record.

    Never call ordinary audit-writing denial paths while the transaction is
    held. A poisoned exchange waits for exact retained holder exit, rather than
    rolling back on timeout/EOF and allowing another mutation to race the Hub.
    """
    from .forge_read import ExternalReadBroker
    from .forge_audit import ForgeAudit
    from .forge_read_service import send_result
    if (type(broker) is not ExternalReadBroker or type(broker.audit) is not ForgeAudit
            or type(holder) is not HeldOrigin or broker.failed):
        raise LedgerError('NATIVE_AUDIT_OWNER_REQUIRED')
    digest = _scope(packet, broker)
    request_id = packet['request_id']
    released = False
    guard = broker.audit.manager_action_guard(broker.binding.room_id, broker.binding.repository)
    state = guard.__enter__()
    try:
        poisoned = False
        try:
            send_result(channel, request_id, {'kind': KIND + '_HELD', 'request_id': request_id,
                'scope_digest': digest, 'state': _state(state)})
        except BaseException:
            poisoned = True
        while not _holder_exited(holder):
            if poisoned:
                _wait_holder_exit(holder)
                break
            try:
                channel.settimeout(1)
                with receive(channel) as record:
                    holder.require(record)
                    answer = json.loads(record.data, object_pairs_hook=_unique_object)
                if answer != {'kind': KIND + '_RELEASE', 'request_id': request_id, 'scope_digest': digest}:
                    raise OriginDenied('unexpected audit fence record')
                released = True
                break
            except socket.timeout:
                continue
            except BaseException:
                poisoned = True
    finally:
        if not released and not _holder_exited(holder):
            _wait_holder_exit(holder)
        guard.__exit__(None, None, None)
    if not released:
        broker.failed = True
        raise OriginDenied('audit fence holder exited without release')
    # The database fence is released before acknowledgement, never before the
    # exact original holder's release. Lost acknowledgement poisons the client.
    send_result(channel, request_id, {'kind': KIND + '_RELEASED', 'request_id': request_id,
                                    'scope_digest': digest})


class NativeBrokerAudit:
    """Typed original Broker owner, bound to one genuine HumanSession."""
    def __init__(self, client, session):
        from .forge_read_service import ReadBrokerClient
        from .manager_actions import HumanSession
        if (type(client) is not ReadBrokerClient or type(session) is not HumanSession
                or not getattr(client, 'manager_audit_enabled', False)
                or type(client.worker) is not HeldOrigin
                or client.binding.room_id != session.room_id or client.room_instance != session.instance_id):
            raise LedgerError('NATIVE_AUDIT_OWNER_REQUIRED')
        self.client, self.session = client, session
        self.deployment_id = session.deployment_id
        self.worker = client.worker
        self.worker_pidfd, self.worker_identity = self.worker.pidfd, self.worker.identity
        self.binding, self.instance = client.binding, client.room_instance
        self.owner_thread = threading.get_ident()
        self.failed = False

    def observation(self):
        """One read-only view cut over the original audit and local Hub snapshot.

        This fixed operation creates no provider request or Manager mutation.
        Its scope is constructed by the retained host, never a browser selector.
        """
        return NativeAuditOperation(self, {'version': 1, 'action': 'observe',
            'operation_id': 'native-human-observation', 'deployment_id': self.deployment_id,
            'room_id': self.binding.room_id, 'instance_id': self.instance,
            'repository': self.binding.repository})

    def bind(self, value, session):
        from .manager_actions import request
        value = request(value, session)
        if session is not self.session or value['action'] not in ACTIONS:
            raise LedgerError('NATIVE_AUDIT_SCOPE_INVALID')
        return NativeAuditOperation(self, value)


class NativeAuditOperation:
    """Invocation-only fence; cached state is usable only while Broker-held."""
    def __init__(self, owner, value):
        if type(owner) is not NativeBrokerAudit:
            raise LedgerError('NATIVE_AUDIT_OWNER_REQUIRED')
        self.owner, self.value = owner, deepcopy(value)
        self.digest = hashlib.sha256(_json(self.value).encode()).hexdigest()
        self.deployment_id = owner.deployment_id
        self.held = None

    def require_current(self):
        owner = self.owner; client = owner.client; session = owner.session
        # A cached HELD reply is not continuing authority after the original
        # Broker dies, is revoked, or loses its retained process-object identity.
        # This bounded kernel observation performs no channel/provider I/O.
        try:
            worker = owner.worker
            worker_current = (type(worker) is HeldOrigin and not worker.revoked
                and worker.pidfd == owner.worker_pidfd and worker.pidfd >= 0
                and worker.identity == owner.worker_identity
                and _identity(worker.pidfd) == owner.worker_identity
                and alive(worker.pidfd)
                and _identity(worker.pidfd) == owner.worker_identity
                and not worker.revoked and worker.pidfd == owner.worker_pidfd)
        except BaseException:
            worker_current = False
        if (not worker_current or owner.failed or client.closed or client.worker is not owner.worker
                or threading.get_ident() != owner.owner_thread
                or client.binding != owner.binding or client.room_instance != owner.instance
                or hashlib.sha256(_json(self.value).encode()).hexdigest() != self.digest
                or not session.allowed('observe') or not session.allowed(self.value['action'])):
            raise LedgerError('NATIVE_AUDIT_UNAVAILABLE')

    def _poison(self):
        self.owner.failed = True
        # Keep the exact worker handle for ordinary owner cleanup; closing the
        # channel cannot certify retirement of the Broker's retained audit guard.
        self.owner.client.closed = True
        try: self.owner.client.channel.close()
        except BaseException: pass

    @contextmanager
    def prepare_manager_guard(self):
        from .forge_read_service import send_result, receive_result
        self.require_current()
        client = self.owner.client
        if self.held is not None or not client.lock.acquire(blocking=False):
            raise LedgerError('NATIVE_AUDIT_BUSY')
        client._manager_audit_active = self
        try:
            self.require_current()
            packet = {'kind': KIND, 'request_id': uuid.uuid4().hex,
                'deployment_id': self.deployment_id, 'room_id': client.binding.room_id,
                'room_instance': client.room_instance, 'repository': client.binding.repository,
                'operation_id': self.value['operation_id'], 'action': self.value['action'],
                'request_digest': hashlib.sha256(_json(self.value).encode()).hexdigest(),
                'origin': self.owner.session.human.canonical()}
            digest = hashlib.sha256(_json(packet).encode()).hexdigest()
            try:
                send_result(client.channel, packet['request_id'], packet, request=True)
                reply = receive_result(client.channel, self.owner.worker, packet['request_id'])
                if (type(reply) is not dict or set(reply) != {'kind', 'request_id', 'scope_digest', 'state'}
                        or {k:reply[k] for k in ('kind', 'request_id', 'scope_digest')} != {
                            'kind': KIND + '_HELD', 'request_id': packet['request_id'], 'scope_digest': digest}):
                    raise LedgerError('NATIVE_AUDIT_STATE_INVALID')
                self.held = _state(reply['state'])
            except BaseException:
                self._poison()
                raise
            try:
                self.require_current()
                yield
            finally:
                # Caller exits all lifecycle/Git/Hub locks before this release.
                release = {'kind': KIND + '_RELEASE', 'request_id': packet['request_id'], 'scope_digest': digest}
                try:
                    raw = _json(release).encode()
                    if client.channel.send(raw) != len(raw): raise OriginDenied('partial audit release')
                    reply = receive_result(client.channel, self.owner.worker, packet['request_id'])
                    if reply != {'kind': KIND + '_RELEASED', 'request_id': packet['request_id'], 'scope_digest': digest}:
                        raise OriginDenied('audit release unconfirmed')
                except BaseException:
                    self._poison()
                    raise LedgerError('NATIVE_AUDIT_RELEASE_UNKNOWN') from None
        finally:
            self.held = None
            client._manager_audit_active = None
            client.lock.release()

    @contextmanager
    def manager_action_guard(self, room_id, repository):
        self._scope(room_id, repository)
        self.require_current()
        if self.held is None: raise LedgerError('NATIVE_AUDIT_NOT_PREPARED')
        yield deepcopy(self.held)  # Pure local check while original Broker holds SQLite.

    def _scope(self, room_id, repository):
        if room_id != self.owner.client.binding.room_id or repository != self.owner.client.binding.repository:
            raise LedgerError('NATIVE_AUDIT_SCOPE_INVALID')

    def manager_action_state(self, room_id, repository):
        self._scope(room_id, repository)
        if self.held is not None:
            self.require_current()
            return deepcopy(self.held)
        with self.prepare_manager_guard():
            return deepcopy(self.held)
