"""Finite root-owned checkout handoff for the fixed qualification host only.

Not a root command service: two exact operations, one configured implementer,
canonical PREPARING reservation, and the existing CheckoutAllocator. No caller
paths, Actor identities, commands, permission changes or lifecycle mutations.
"""
from copy import deepcopy
from io import StringIO
import hashlib
import json
import math
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import time

from .checkouts import CheckoutAllocator
from .kernel_origin import _identity, alive, enable, receive
from .ledger import RoomLedger, LedgerError, _token
from .lifecycle import Supervisor, LifecycleError
from .native_image_package import canonical
from .workstation_admission import _unique

MAX_REQUEST = 1024
MAX_REPLY = 20000
MAX_REQUESTS = 8
HOST_UID = 165533


def require(value, code):
    if not value:
        raise LifecycleError(code)


def remaining(deadline):
    require(type(deadline) in (int, float) and math.isfinite(deadline), 'INVALID_DEADLINE')
    value = deadline - time.monotonic()
    require(value > 0, 'CHECKOUT_HANDOFF_DEADLINE')
    return value


def request_value(value):
    require(type(value) is dict and set(value) == {'version', 'kind', 'run_id', 'operation_id'}
            and type(value['version']) is int and value['version'] == 1
            and value['kind'] in ('ALLOCATE', 'OBSERVE'), 'CHECKOUT_REQUEST_INVALID')
    _token(value['operation_id']); _token(value['run_id'])
    require(value['run_id'] == 'run-' + hashlib.sha256(value['operation_id'].encode()).hexdigest(),
            'CHECKOUT_OPERATION_MISMATCH')
    return value


def reservation(state, request, room, actors, *, initial):
    """Pure projection of canonical reservation, not a supplied authority claim."""
    run = request['run_id']
    seats = [s for s in room['seats'] if s['runtime'] == 'pi']
    require(len(seats) == 1, 'CHECKOUT_IMPLEMENTER_UNAVAILABLE')
    seat = seats[0]
    profile = next(p for p in room['profiles'] if p['id'] == seat['profile'])
    row = state.get('run_admissions', {}).get(run)
    require(type(row) is dict and row.get('status') == 'PREPARING'
            and row.get('admission_operation') == request['operation_id']
            and row.get('participant_id') == seat['participant']
            and row.get('actor_id') == seat['actor']
            and row.get('github_user_id') == actors[seat['actor']].get('github_user_id')
            and type(row.get('context_generation')) is int
            and row.get('authorization_consumed') is False
            and type(row.get('admission_origin')) is dict
            and type(row.get('human_origin')) is dict
            and type(row.get('human_operation')) is str,
            'CHECKOUT_RESERVATION_CHANGED')
    binding = row.get('seat_binding', {})
    configured = {k: seat[k] for k in ('id', 'participant', 'actor', 'profile', 'runtime', 'arguments', 'provider')}
    expected_seat = {'participant_id': seat['participant'], 'actor_id': seat['actor'],
        'profile_id': seat['profile'], 'capabilities': sorted(set(profile['capabilities']) | {'peer-traffic'}),
        'runtime': 'pi-native', 'configured_selection': seat}
    require(binding.get('seat') == expected_seat and binding.get('configured_seat') == configured
            and binding.get('configured_capabilities') == list(profile['capabilities'])
            and 'implement' in profile['capabilities'], 'CHECKOUT_SEAT_CHANGED')
    peer = state.get('peer_traffic', {}).get('definition', {}).get('participants', {}).get(seat['participant'])
    require(type(peer) is dict and peer.get('actor_id') == seat['actor'], 'CHECKOUT_SEAT_CHANGED')
    context = state.get('fixture_context', {}).get('participants', {}).get(seat['participant'])
    target = {'run_id': run, 'generation': 1}
    predecessor = row.get('preceding_run')
    successor_pin = None
    if predecessor is None:
        require(row['context_generation'] == 1 and type(context) is dict
                and context.get('context_generation') == 1
                and context.get('status') == 'READY' and context.get('reset') is None
                and ((context.get('reserved_run') == target and context.get('bound_run') is None)
                     or (not initial and context.get('bound_run') == target and context.get('reserved_run') is None)),
                'CHECKOUT_CONTEXT_CHANGED')
    else:
        # Qualification supports exactly the first reuse, never arbitrary generations.
        require(row['context_generation'] == 2 and type(predecessor) is dict
                and set(predecessor) == {'run_id', 'generation'}
                and type(predecessor['run_id']) is str and predecessor['run_id'] != run
                and type(predecessor['generation']) is int and predecessor['generation'] >= 1,
                'CHECKOUT_PREDECESSOR_CHANGED')
        old = state.get('runs', {}).get(predecessor['run_id'])
        old_context = state.get('fixture_context', {}).get('runs', {}).get(predecessor['run_id'])
        require(type(old) is dict and old.get('status') == 'CLOSED'
                and old.get('participant_id') == seat['participant'] and old.get('actor_id') == seat['actor']
                and type(old.get('native_stop')) is dict and old['native_stop'].get('status') == 'VERIFIED'
                and old['native_stop'].get('generation') == old.get('generation')
                and old.get('generation') == predecessor['generation']
                and type(old_context) is dict and old_context.get('status') == 'CLOSED'
                and old_context.get('generation') == predecessor['generation'],
                'CHECKOUT_PREDECESSOR_CHANGED')
        reset = context.get('reset') if type(context) is dict else None
        reset_id = 'native-pi-reset-' + hashlib.sha256(request['operation_id'].encode()).hexdigest()
        immutable = {'id': reset_id, 'participant_id': seat['participant'],
                     'expected_context_generation': 1, 'next_context_generation': 2,
                     'preceding_run': predecessor, 'target_run': target, 'reason_code': None}
        require(type(reset) is dict and all(reset.get(k) == v for k, v in immutable.items()),
                'CHECKOUT_RESET_CHANGED')
        requested = (reset.get('status') == 'REQUESTED' and context.get('status') == 'RESETTING'
            and context.get('context_generation') == 1
            and ((context.get('bound_run') == predecessor and context.get('reserved_run') is None)
                 or (context.get('reserved_run') == predecessor and context.get('bound_run') is None)))
        succeeded = (not initial and reset.get('status') == 'SUCCEEDED' and context.get('status') == 'READY'
            and context.get('context_generation') == 2
            and ((context.get('bound_run') == target and context.get('reserved_run') is None)
                 or (context.get('reserved_run') == target and context.get('bound_run') is None)))
        require(requested or succeeded, 'CHECKOUT_CONTEXT_CHANGED')
        successor_pin = {'reset': deepcopy(immutable), 'predecessor_stop': deepcopy(old['native_stop']),
                         'predecessor_generation': old.get('generation')}
    context_run = state.get('fixture_context', {}).get('runs', {}).get(run)
    require(context_run == {'generation': 1, 'status': 'OPEN', 'terminal_fact': None}
            and run not in state.get('runs', {}), 'CHECKOUT_RESERVATION_CHANGED')
    # Attention is a diagnosis, not a new authorization; every other admission
    # field is pinned across the finite handoff, including origins and policy.
    pinned = deepcopy(row); pinned.pop('attention', None)
    if successor_pin is not None: pinned['_successor_pin'] = successor_pin
    return seat['participant'], pinned


def ready_slot(slot, run, participant):
    require(type(slot) is dict and slot.get('run') == run and slot.get('participant') == participant
            and slot.get('active') is True and slot.get('phase') == 'ready'
            and slot.get('reason') == 'ACTIVE' and slot.get('observed_dirty') is False
            and slot.get('observed_head') == slot.get('base')
            and len(canonical(slot)) <= 16384, 'CHECKOUT_NOT_READY')
    return slot


class NativeCheckoutClient:
    """Trusted child endpoint. An uncertain transfer fences the stream."""
    def __init__(self, channel, *, deadline):
        require(type(channel) is socket.socket and channel.family == socket.AF_UNIX
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET,
                'CHECKOUT_CHANNEL_REQUIRED')
        remaining(deadline)
        self.channel, self.deadline, self.closed = channel, deadline, False

    def close(self):
        self.closed = True
        self.channel.close()

    def _call(self, kind, run, operation_id):
        require(not self.closed, 'CHECKOUT_CHANNEL_FENCED')
        request = request_value({'version': 1, 'kind': kind, 'run_id': run, 'operation_id': operation_id})
        try:
            self.channel.settimeout(remaining(self.deadline))
            raw = canonical(request)
            require(len(raw) <= MAX_REQUEST and self.channel.send(raw) == len(raw), 'CHECKOUT_TRANSFER_UNKNOWN')
            self.channel.settimeout(remaining(self.deadline))
            raw, ancillary, flags, _ = self.channel.recvmsg(MAX_REPLY, 0)
            require(raw and not flags and not ancillary, 'CHECKOUT_REPLY_INVALID')
            reply = json.loads(raw, object_pairs_hook=_unique)
            require(type(reply) is dict and all(reply.get(k) == v for k, v in request.items()),
                    'CHECKOUT_REPLY_MISMATCH')
            if reply.get('status') == 'ERROR':
                require(set(reply) == set(request) | {'status', 'error'}
                        and type(reply['error']) is str and len(reply['error']) <= 96,
                        'CHECKOUT_REPLY_INVALID')
                raise LifecycleError(reply['error'])
            require(set(reply) == set(request) | {'status', 'slot'} and reply['status'] == 'OK',
                    'CHECKOUT_REPLY_INVALID')
            return reply['slot']
        except BaseException:
            self.close()
            raise

    def allocate(self, run, operation_id):
        return self._call('ALLOCATE', run, operation_id)

    def observe(self, run, operation_id):
        return self._call('OBSERVE', run, operation_id)


class RootCheckoutHandoff:
    """Fixed owner retains actual Popen child identity, not sender PID lookup."""
    def __init__(self, plan, resources, child, channel, *, deadline):
        from .native_qualification import QualificationPlan
        from .native_qualification_backend import LaunchResources
        require(type(plan) is QualificationPlan and type(resources) is LaunchResources
                and type(resources._supervisor) is Supervisor
                and type(child) is subprocess.Popen and resources._child is child,
                'CHECKOUT_ROOT_OWNER_REQUIRED')
        remaining(deadline)
        self.plan, self.resources, self.child, self.channel = plan, resources, child, channel
        self.owner, self.deadline = resources._supervisor, deadline
        self.allocator = CheckoutAllocator(self.owner, StringIO(plan.config_text), deadline=deadline,
            manifest_reader_gid=HOST_UID, git_identity=(165532, 165532))
        self.actors = {a['id']: a for a in plan.config['deployment']['actors']}
        self.pin = None
        self.pins = {}
        self.attempted = set()
        self.count = 0
        self.ledger_identity = None
        self.pidfd = os.pidfd_open(child.pid, 0)  # Exact retained Popen, never payload PID.
        try:
            self.identity = _identity(self.pidfd)
            self._held()
        except BaseException:
            os.close(self.pidfd)
            raise

    def close(self):
        if self.pidfd >= 0:
            fd, self.pidfd = self.pidfd, -1
            os.close(fd)

    def _held(self):
        remaining(self.deadline)
        require(self.child.poll() is None and self.pidfd >= 0 and alive(self.pidfd)
                and _identity(self.pidfd) == self.identity, 'CHECKOUT_HOST_EXITED')

    def _snapshot(self):
        path = Path(self.resources.data['hub_ledger_path'])
        info = path.lstat()
        require(path.resolve() == path and stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1, 'CHECKOUT_ROOM_STORE_CHANGED')
        identity = (info.st_dev, info.st_ino)
        if self.ledger_identity is None: self.ledger_identity = identity
        require(identity == self.ledger_identity, 'CHECKOUT_ROOM_STORE_CHANGED')
        with RoomLedger.open_reader(path, self.plan.room['id']) as ledger:
            ledger._connection().execute('PRAGMA busy_timeout=' + str(max(1, int(min(5, remaining(self.deadline)) * 1000))))
            state = ledger.snapshot()['state']
        after = path.lstat()
        require((after.st_dev, after.st_ino) == identity, 'CHECKOUT_ROOM_STORE_CHANGED')
        return state

    def _authorized(self, request, *, initial):
        self._held()
        lifecycle = self.owner._read()
        require(lifecycle is not None and lifecycle['phase'] == 'running'
                and lifecycle['instance_id'] == self.resources.data['instance']
                and lifecycle['spec']['config_digest'] == 'sha256:' + self.plan.config_digest,
                'CHECKOUT_ROOM_CHANGED')
        participant, pinned = reservation(self._snapshot(), request, self.plan.room, self.actors, initial=initial)
        if not hasattr(self, 'pins'): self.pins = {}
        run = request['run_id']
        pin = (run, participant, pinned)
        if run not in self.pins:
            require(len(self.pins) < 2, 'CHECKOUT_RUN_LIMIT')
            if self.pins:
                preceding = pinned.get('preceding_run')
                require(preceding is not None and preceding['run_id'] in self.pins
                        and self.pins[preceding['run_id']][2].get('context_generation') == 1,
                        'CHECKOUT_PREDECESSOR_CHANGED')
            self.pins[run] = pin
        require(self.pins[run] == pin, 'CHECKOUT_RESERVATION_CHANGED')
        self.pin = pin
        return True

    def operation(self, request):
        request_value(request)
        initial = request['kind'] == 'ALLOCATE'
        with self.owner._locked(deadline=self.deadline):
            self._authorized(request, initial=initial)
        run, participant, pinned = self.pin
        preceding = pinned.get('preceding_run')
        retained = (preceding['run_id'], participant) if preceding else None
        if initial:
            require(run not in self.attempted, 'CHECKOUT_ALLOCATION_RECONCILE_ONLY')
            self.attempted.add(run)  # Even failure may have written durable intent.
            options = {'retained_predecessor': retained} if retained is not None else {}
            slot = self.allocator.allocate(run, participant,
                authorize=lambda: self._authorized(request, initial=True), **options)
        else:
            # Read only: never call allocate/reconcile or recover creating state.
            with self.allocator._locked('status') as state:
                self._authorized(request, initial=False)
                if retained is not None:
                    self.allocator._retained_predecessor(state, run, participant, retained)
                found = [(key, value) for key, value in state['slots'].items() if value['run'] == run]
                require(len(found) == 1 and found[0][1]['participant'] == participant,
                        'CHECKOUT_BINDING_CONFLICT')
                slot = self.allocator._observe(state, found[0][0])
        remaining(self.deadline)
        return ready_slot(slot, run, participant)

    def serve_one(self):
        self._held()
        self.count += 1
        require(self.count <= MAX_REQUESTS, 'CHECKOUT_REQUEST_LIMIT')
        self.channel.settimeout(remaining(self.deadline))
        with receive(self.channel) as record:
            require(record.credentials == (self.child.pid, HOST_UID, HOST_UID)
                    and alive(record.pidfd) and _identity(record.pidfd) == self.identity
                    and len(record.data) <= MAX_REQUEST, 'CHECKOUT_HOST_MISMATCH')
            request = request_value(json.loads(record.data, object_pairs_hook=_unique))
        try:
            slot = self.operation(request)
            reply = {**request, 'status': 'OK', 'slot': slot}
        except (LifecycleError, LedgerError) as error:
            reply = {**request, 'status': 'ERROR', 'error': error.code}
        raw = canonical(reply)
        require(len(raw) <= MAX_REPLY, 'CHECKOUT_REPLY_LIMIT')
        self.channel.settimeout(remaining(self.deadline))
        require(self.channel.send(raw) == len(raw), 'CHECKOUT_REPLY_UNKNOWN')


def collect_child(child, handoff, *, deadline):
    """Bound stdout and service only this channel until the exact child exits."""
    output = bytearray()
    stdout_open = channel_open = True
    while child.poll() is None or stdout_open:
        watched = ([child.stdout] if stdout_open else [])
        if child.poll() is None and channel_open: watched.append(handoff.channel)
        if not watched:
            child.wait(timeout=remaining(deadline))
            break
        ready, _, _ = select.select(watched, [], [], remaining(deadline))
        require(ready, 'CHECKOUT_HANDOFF_DEADLINE')
        for stream in ready:
            if stream is handoff.channel:
                if not stream.recv(1, socket.MSG_PEEK):
                    channel_open = False
                else:
                    handoff.serve_one()
            else:
                block = os.read(child.stdout.fileno(), min(4096, 16385 - len(output)))
                if not block: stdout_open = False
                output.extend(block)
                require(len(output) <= 16384, 'NATIVE_PAIR_STARTUP_FAILED')
    return bytes(output)
