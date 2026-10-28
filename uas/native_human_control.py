"""Retained native human transport checkpoint; not a launcher or Run owner.

The final host supplies an established TLS socket and trusted exact bindings.
One explicit thread owns transport; the creating thread alone consumes commands
and uses the retained session. Callbacks perform no transport or owner I/O.
"""
from copy import deepcopy
from dataclasses import dataclass
import math
import re
import threading
import time

from .human_mtls import HumanActionBindings, HumanActionGrant, PATH, _peer, _frame, _FRAME_ACTIONS
from .ledger import LedgerError, _token
from .manager_actions import HumanSession, request
from .manager_transport import receive_frame, send_frame


MAX_ACTIONS = 8
MAX_FRESHNESS = 5.0
_STATUSES = frozenset({'queued', 'attempted', 'pending', 'confirmed', 'unknown',
    'rejected', 'error', 'stale', 'confirmed-awaiting-target'})
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_STAGES = frozenset({'REVIEWING', 'READY_FOR_HUMAN', 'ATTENTION', 'IMPLEMENTING',
                     'SUPERSEDED', 'COMPLETED'})


@dataclass(frozen=True)
class NativeHumanOpen:
    """Action data only; the future trusted plan selects the Participant."""
    operation_id: str
    issue_number: int

    def __post_init__(self):
        if (type(self.operation_id) is not str or type(self.issue_number) is not int
                or not 1 <= self.issue_number <= 9_999_999_999):
            raise LedgerError('INVALID_NATIVE_HUMAN_OPEN')
        _token(self.operation_id)


def _capable(grant, action):
    capability = ('human-open-run' if action in {'open-run', 'authorize-run-request'}
                  else 'human-control-run' if action in {'request-changes', 'reconcile-changes'} else None)
    return action in grant.actions and (capability is None or capability in grant.human.capabilities)


def _view(value):
    if value is None:
        return None
    if (type(value) is not dict or set(value) != {'run_id', 'generation', 'status', 'observed_version',
                                                'review_stage', 'submission_id', 'forge_uncertain'}
            or type(value['run_id']) is not str or type(value['generation']) is not int
            or not 1 <= value['generation'] < 2**63
            or type(value['status']) is not str or value['status'] not in {'OPEN', 'ACTIVE', 'PAUSED', 'CLOSED'}
            or type(value['observed_version']) is not str or not _SHA.fullmatch(value['observed_version'])
            or value['review_stage'] is not None and (type(value['review_stage']) is not str or value['review_stage'] not in _STAGES)
            or value['submission_id'] is not None and type(value['submission_id']) is not str
            or type(value['forge_uncertain']) is not bool):
        raise LedgerError('INVALID_NATIVE_HUMAN_VIEW')
    _token(value['run_id'])
    if value['submission_id'] is not None:
        _token(value['submission_id'])
    return deepcopy(value)


class NativeHumanControl:
    """One connection, one initial request, eight lifetime control operations.

    Registry mutation stays on its original creating thread. Main callbacks
    compare exact grant/generation on every use. The worker never invokes a
    registry method, callback, Broker, inbox or owner; queued data is not authority.
    """
    def __init__(self, bindings, channel, *, instance_id, deadline, freshness=MAX_FRESHNESS,
                 clock=time.monotonic):
        if type(bindings) is not HumanActionBindings:
            raise LedgerError('HUMAN_ACTION_BINDINGS_REQUIRED')
        bindings._owner()
        fingerprint = _peer(channel)
        bound = bindings._bindings.get(fingerprint)
        if bound is None or type(bound[0]) is not HumanActionGrant:
            raise LedgerError('UNREGISTERED_HUMAN_CERTIFICATE')
        grant, generation = bound
        if not callable(clock):
            raise LedgerError('INVALID_NATIVE_HUMAN_CLOCK')
        self._clock = clock  # Trusted time-only test seam; never wire-configurable.
        now = clock()
        if (type(now) not in (int, float) or not math.isfinite(now)
                or type(instance_id) is not str or instance_id != grant.instance_id
                or type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= now
                or type(freshness) not in (int, float) or not math.isfinite(freshness)
                or not 0 < freshness <= MAX_FRESHNESS):
            raise LedgerError('INVALID_NATIVE_HUMAN_LIFETIME')
        self._bindings, self._channel, self._fingerprint = bindings, channel, fingerprint
        self._grant, self._generation = grant, generation
        self._instance, self._deadline, self._freshness = instance_id, deadline, freshness
        self._owner_thread = threading.get_ident()
        self._lock = threading.Lock()
        self._thread, self._worker_thread = None, None
        self._started, self._closed, self._reason = False, False, None
        self._expires = min(deadline, now + freshness)
        self._first, self._first_taken, self._observe_requested = None, False, False
        self._transport_closed = False
        self._items, self._queue, self._current_view = {}, [], None
        session = HumanSession(grant.deployment_id, grant.room_id, grant.instance_id,
            grant.manager_id, grant.human,
            authorized=lambda current, action: current is session and type(action) is str
                and action in _FRAME_ACTIONS and all(_capable(grant, selected)
                    for selected in _FRAME_ACTIONS[action]) and self._connected(),
            connected=self._connected)
        self._session = session

    @property
    def session(self):
        return self._session

    def _owner(self):
        if threading.get_ident() != self._owner_thread:
            raise LedgerError('NATIVE_HUMAN_OWNER_REQUIRED')
        self._bindings._owner()

    def _end_locked(self, reason):
        self._closed = True
        if self._reason is None:
            self._reason = reason

    def _live_locked(self, now=None):
        now = self._clock() if now is None else now
        if type(now) not in (int, float) or not math.isfinite(now) or now >= min(self._expires, self._deadline):
            self._end_locked('NATIVE_HUMAN_EXPIRED')
        return self._started and not self._closed

    def _main_live_locked(self):
        bound = self._bindings._bindings.get(self._fingerprint)
        if (bound is None or bound[0] is not self._grant or bound[1] != self._generation
                or self._grant.instance_id != self._instance):
            self._end_locked('NATIVE_HUMAN_REVOKED')
        return self._live_locked()

    def _connected(self):
        # Wrong-thread checks fail closed without mutating owner state.
        if threading.get_ident() != self._owner_thread:
            return False
        with self._lock:
            return self._main_live_locked() and self._first is not None

    def _require_locked(self):
        if not self._main_live_locked():
            raise LedgerError('NATIVE_HUMAN_AUTHENTICATION_LOST')

    def start(self):
        """Explicit production effect; after success only the worker uses TLS."""
        self._owner()
        with self._lock:
            if self._started or self._closed:
                raise LedgerError('NATIVE_HUMAN_START_ONCE')
            self._started = True
            self._require_locked()
        try:
            self._thread = threading.Thread(target=self._pump, name='uas-native-human', daemon=False)
            self._thread.start()
        except BaseException:
            with self._lock:
                self._end_locked('NATIVE_HUMAN_START_FAILED')
            if self._thread is None or self._thread.ident is None:
                self._close_transport()
            raise

    def first_request(self):
        """Main-thread once-only handoff; None only while awaiting receipt."""
        self._owner()
        with self._lock:
            self._require_locked()
            if self._first_taken:
                raise LedgerError('NATIVE_HUMAN_OPEN_ALREADY_TAKEN')
            if self._first is None:
                return None
            self._first_taken = True
            return self._first

    def take_observation_request(self):
        """Consume a coalesced request to compute a fresh view on the main owner."""
        self._owner()
        with self._lock:
            self._require_locked()
            requested, self._observe_requested = self._observe_requested, False
            return requested

    def drain_commands(self):
        """Main-thread data handoff, not execution, durable delivery or retry."""
        self._owner()
        with self._lock:
            self._require_locked()
            result = tuple(deepcopy(self._items[key]['request']) for key in self._queue)
            self._queue.clear()
            return result

    def publish(self, view, statuses=()):
        """Publish only this small projection; no bodies, errors or Origin data."""
        self._owner()
        current = _view(view)
        if type(statuses) is not tuple or len(statuses) > MAX_ACTIONS:
            raise LedgerError('INVALID_NATIVE_HUMAN_STATUS')
        updates = {}
        for item in statuses:
            if (type(item) is not dict or set(item) != {'operation_id', 'status'}
                    or type(item['operation_id']) is not str or type(item['status']) is not str
                    or item['status'] not in _STATUSES or item['operation_id'] in updates):
                raise LedgerError('INVALID_NATIVE_HUMAN_STATUS')
            updates[item['operation_id']] = item['status']
        with self._lock:
            self._require_locked()
            if current is not None and (self._first is None or not _capable(self._grant, 'observe')):
                raise LedgerError('HUMAN_ACTION_DENIED')
            if any(key not in self._items for key in updates):
                raise LedgerError('INVALID_NATIVE_HUMAN_STATUS')
            self._current_view = current
            for key, status in updates.items():
                self._items[key]['status'] = status

    def close(self):
        """Deny immediately; TLS owner closes its socket, never another thread."""
        self._owner()
        with self._lock:
            self._end_locked('NATIVE_HUMAN_CLOSED')
            worker = self._thread
        if worker is None or worker.ident is None:
            self._close_transport()
        else:
            worker.join(timeout=MAX_FRESHNESS + .25)
            if worker.is_alive():
                raise LedgerError('NATIVE_HUMAN_PUMP_STOP_PENDING')

    def _close_transport(self):
        if not self._transport_closed:
            self._transport_closed = True
            self._channel.close()

    def _accept(self, value):
        if threading.get_ident() != self._worker_thread:
            raise LedgerError('NATIVE_HUMAN_TRANSPORT_OWNER_REQUIRED')
        value = _frame(value, self._grant)
        action, payload = value['action'], value['payload']
        if action == 'authorize-run-request' or not all(
                _capable(self._grant, selected) for selected in _FRAME_ACTIONS[action]):
            raise LedgerError('HUMAN_ACTION_DENIED')
        opened = command = None
        if action == 'open-run':
            if set(payload) != {'operation_id', 'issue_number'}:
                raise LedgerError('INVALID_NATIVE_HUMAN_OPEN')
            opened = NativeHumanOpen(**payload)
        elif action == 'observe':
            if payload:
                raise LedgerError('INVALID_NATIVE_HUMAN_OBSERVE')
        else:
            command = request(payload, self.session)
            if command['action'] != action:
                raise LedgerError('NATIVE_HUMAN_ACTION_MISMATCH')
            body = command['payload']
            if (action == 'request-changes' and (set(body) != {'body'}
                    or type(body['body']) is not str or not 1 <= len(body['body']) <= 8192)
                    or action == 'reconcile-changes' and body):
                raise LedgerError('INVALID_MANAGER_ACTION')
        with self._lock:
            # Never let a frame arriving after a gap revive a stopped lease.
            now = self._clock()
            if not self._live_locked(now):
                raise LedgerError('NATIVE_HUMAN_AUTHENTICATION_LOST')
            if self._first is None:
                if opened is None:
                    raise LedgerError('NATIVE_HUMAN_OPEN_FIRST')
                self._first = opened
            elif opened is not None and opened != self._first:
                raise LedgerError('NATIVE_HUMAN_SECOND_RUN_DENIED')
            if command is not None:
                key = command['operation_id']
                if key == self._first.operation_id:
                    raise LedgerError('ID_CONFLICT')
                previous = self._items.get(key)
                if previous is not None and previous['request'] != command:
                    raise LedgerError('ID_CONFLICT')
                if previous is None:
                    if len(self._items) >= MAX_ACTIONS:
                        raise LedgerError('NATIVE_HUMAN_ACTION_CAPACITY')
                    self._items[key] = {'request': command, 'status': 'queued'}
                    self._queue.append(key)
            if action == 'observe':
                self._observe_requested = True
            self._expires = min(self._deadline, now + self._freshness)
            return {'version': 1, 'receipt': 'observed' if action == 'observe' else 'queued',
                'view_kind': 'last-published-not-live', 'current': deepcopy(self._current_view), 'actions': [
                    {'operation_id': key, 'status': item['status']} for key, item in self._items.items()]}

    def _pump(self):
        self._worker_thread = threading.get_ident()
        try:
            if self._worker_thread == self._owner_thread:
                raise LedgerError('NATIVE_HUMAN_TRANSPORT_OWNER_REQUIRED')
            while True:
                with self._lock:
                    if not self._live_locked():
                        return
                value = receive_frame(self._channel, path=PATH)
                if _peer(self._channel) != self._fingerprint:
                    raise LedgerError('HUMAN_AUTHENTICATION_REVOKED')
                response = self._accept(value)
                with self._lock:
                    if not self._live_locked():
                        return
                send_frame(self._channel, response, response=True, path=PATH)
        except BaseException:
            with self._lock:
                self._end_locked('NATIVE_HUMAN_TRANSPORT_FAILED')
        finally:
            with self._lock:
                self._end_locked('NATIVE_HUMAN_PUMP_STOPPED')
            self._close_transport()
