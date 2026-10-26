"""Source-only single ADMIT seam; no Engine access or namespace qualification.

Only a trusted Supervisor may send this private-control packet. Participant
records use kernel_origin.receive(), whose rejection of SCM_RIGHTS is unchanged.
No stored receipt can recreate live descriptor authority after controller loss.
"""
import array
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import struct
import threading
from types import MappingProxyType
import uuid

from .kernel_origin import (HeldOrigin, OriginDenied, OriginUnavailable, ReceiverIdentity, Record,
                            SCM_PIDFD, _identity, alive, enable)

LIMIT = 8192
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
OPERATION = re.compile(r'[0-9a-f]{32}\Z')


def _token(value):
    return type(value) is str and TOKEN.fullmatch(value)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OriginDenied('duplicate admission field')
        result[key] = value
    return result


@dataclass(frozen=True)
class AdmissionSeat:
    """Immutable local trusted configuration, NOT constructed from peer input."""
    room_id: str
    room_instance: str
    participant_id: str
    actor_id: str
    profile_id: str
    capabilities: tuple
    receiver: ReceiverIdentity

    def __post_init__(self):
        if (not all(_token(v) for v in (self.room_id, self.room_instance,
                self.participant_id, self.actor_id, self.profile_id))
                or type(self.capabilities) is not tuple or len(self.capabilities) > 32
                or not all(_token(v) for v in self.capabilities)
                or len(set(self.capabilities)) != len(self.capabilities)
                or type(self.receiver) is not ReceiverIdentity):
            raise OriginDenied('invalid trusted admission seat')

    def document(self):
        return json.loads(_canonical(asdict(self)))


@dataclass(frozen=True)
class AdmittedBinding:
    seat: AdmissionSeat
    operation_id: str
    incarnation: str
    epoch: int
    readiness_digest: str


@dataclass
class _Offer:
    document: dict
    channel: socket.socket
    origin: HeldOrigin

    def close(self):
        try:
            self.origin.close()
        finally:
            self.channel.close()


def send_admit(control, *, launch, seat, operation_id, epoch, readiness_digest):
    """Supervisor-only. Never returns the launch object to the receiving Hub.

    Caller serializes against revocation and journals this operation before
    sending. After possible send, outcome is unknown until ACK/status; no retry.
    """
    from .workstation_exec import ExecLaunch
    if (type(launch) is not ExecLaunch or launch.state != 'active'
            or type(seat) is not AdmissionSeat or launch.origin.revoked
            or not alive(launch.origin.pidfd)
            or any(getattr(launch.seat, key) != getattr(seat, key)
                   for key in ('room_id', 'room_instance', 'participant_id', 'actor_id'))):
        raise OriginDenied('active exact Supervisor launch required')
    launch.endpoint.require()
    document = {'version': 1, 'kind': 'ADMIT', 'operation_id': operation_id,
                'seat': seat.document(), 'incarnation': launch.incarnation,
                'epoch': epoch, 'readiness_digest': readiness_digest,
                'origin_identity': list(launch.origin.identity)}
    _validate_document(document, seat)
    packet = _canonical(document)
    if len(packet) > LIMIT:
        raise OriginDenied('oversized admission')
    sent = control.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                            array.array('i', [launch.channel.fileno(), launch.origin.pidfd]))])
    if sent != len(packet):
        raise OriginDenied('partial ADMIT; outcome unknown, reconcile operation')


def _validate_document(document, seat):
    if (type(document) is not dict or set(document) != {
            'version', 'kind', 'operation_id', 'seat', 'incarnation', 'epoch',
            'readiness_digest', 'origin_identity'}
            or type(document['version']) is not int or document['version'] != 1
            or document['kind'] != 'ADMIT'
            or type(document['operation_id']) is not str
            or not OPERATION.fullmatch(document['operation_id'])
            or type(document['incarnation']) is not str
            or not OPERATION.fullmatch(document['incarnation'])
            or type(document['epoch']) is not int or not 0 < document['epoch'] < 2**53
            or type(document['readiness_digest']) is not str
            or not DIGEST.fullmatch(document['readiness_digest'])
            or _canonical(document['seat']) != _canonical(seat.document())
            or type(document['origin_identity']) is not list
            or len(document['origin_identity']) != 2
            or any(type(v) is not int or v < 0 for v in document['origin_identity'])):
        raise OriginDenied('admission does not match trusted configuration')


def _receive_offer(control, supervisor, seats):
    data, ancillary, flags, _ = control.recvmsg(LIMIT,
        socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4) + socket.CMSG_SPACE(253*4),
        socket.MSG_CMSG_CLOEXEC)
    installed, credentials, pidfds, rights = [], [], [], []
    channel = origin = result = None
    invalid = not data or bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
    try:
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind in (SCM_PIDFD, socket.SCM_RIGHTS):
                fds = array.array('i'); fds.frombytes(raw[:len(raw) - len(raw) % 4])
                installed.extend(fd for fd in fds if fd >= 0)
                if len(raw) % 4 or any(fd < 0 for fd in fds):
                    invalid = True
                (pidfds if kind == SCM_PIDFD else rights).extend(fds)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(raw) == 12:
                credentials.append(struct.unpack('3i', raw))
            else:
                invalid = True
        if invalid or len(credentials) != 1 or len(pidfds) != 1 or len(rights) != 2:
            raise OriginDenied('invalid ADMIT ancillary')
        if any(os.get_inheritable(fd) for fd in installed):
            raise OriginDenied('inheritable ADMIT descriptor')
        # Authenticate actual sender before accepting its asserted metadata.
        supervisor.require(Record(data, credentials[0], pidfds[0]))
        document = json.loads(data.decode('utf-8'), object_pairs_hook=_unique)
        participant = document.get('seat', {}).get('participant_id') if type(document) is dict and type(document.get('seat')) is dict else None
        seat = seats.get(participant) if type(participant) is str else None
        if seat is None:
            raise OriginDenied('unknown admission seat')
        _validate_document(document, seat)
        if list(_identity(rights[1])) != document['origin_identity']:
            raise OriginDenied('substituted runtime process object')
        channel = socket.socket(fileno=rights[0]); installed.remove(rights[0])
        if (channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise OriginDenied('connected peer seqpacket required')
        channel.getpeername()  # Unconnected endpoint cannot be installed.
        enable(channel)
        # Only the trusted local config supplies receiver translation. PID0 is
        # diagnostic, not looked up or considered proof of any task identity.
        record = Record(b'', (0, seat.receiver.uid, seat.receiver.gid), rights[1])
        origin = HeldOrigin(record, receiver=seat.receiver)
        installed.remove(rights[1])
        result = _Offer(document, channel, origin)
        channel = origin = None
        return result
    except (ValueError, UnicodeError, TypeError, OSError, OriginUnavailable) as error:
        raise OriginDenied('invalid ADMIT record or descriptors') from error
    finally:
        cleanup_error = None
        # Every installed descriptor has one owner and one close attempt. A
        # failed close may already have released it; never retry that fd number.
        while installed:
            fd = installed.pop()
            try:
                os.close(fd)
            except BaseException as error:
                cleanup_error = cleanup_error or error
        for resource in (origin, channel):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            # A finally failure cancels the pending return. The assembled offer
            # has not reached its caller, so it must not strand its two FDs.
            try:
                if result is not None:
                    result.close()
            finally:
                raise cleanup_error


class HubAdmission:
    """Trusted Hub-side library, not an exposed service or production launcher.

    Caller owns the authenticated control loop and endpoint/SELinux preflight.
    The DB contains receipts, never descriptors or reconstructable authority.
    """
    def __init__(self, journal, *, seats, supervisor, endpoint):
        if type(supervisor) is not HeldOrigin or supervisor.revoked or not alive(supervisor.pidfd):
            raise OriginDenied('held trusted Supervisor required')
        configured = tuple(seats)
        if (not configured or any(type(seat) is not AdmissionSeat for seat in configured)
                or len({(s.room_id, s.room_instance, s.receiver.context) for s in configured}) != 1
                or len({s.participant_id for s in configured}) != len(configured)):
            raise OriginDenied('one exact Room receiver configuration required')
        self.seats = MappingProxyType({s.participant_id: s for s in configured})
        self.supervisor = supervisor  # caller retains ownership
        self.endpoint = endpoint  # trusted Hub-local lease, never from ADMIT
        self.endpoint.require()
        self.controller = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._authorization = threading.local()
        self._active = {}
        self._fenced = False
        self._closed = False
        path = Path(journal)
        parent = path.parent.lstat()
        if (not path.is_absolute() or path.parent.resolve() != path.parent
                or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700
                or (path.exists() and (path.is_symlink() or not path.is_file()))):
            raise OriginDenied('private Hub journal required')
        self.db = None
        self._lease = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
            os.chmod(path, 0o600)
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS scope (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL)')
            scope = _canonical({'room_id': configured[0].room_id,
                'room_instance': configured[0].room_instance,
                'actors': sorted((seat.participant_id, seat.actor_id) for seat in configured)}).decode()
            self.db.execute('INSERT OR IGNORE INTO scope VALUES (1,?)', (scope,))
            if self.db.execute('SELECT binding FROM scope WHERE id=1').fetchone()[0] != scope:
                raise OriginDenied('Hub journal scope or immutable Actor changed')
            self.db.execute('CREATE TABLE IF NOT EXISTS admissions '
                '(operation TEXT PRIMARY KEY, digest TEXT NOT NULL, participant TEXT NOT NULL, '
                'epoch INTEGER NOT NULL, controller TEXT NOT NULL, receipt TEXT NOT NULL, state TEXT NOT NULL)')
            self.db.execute("UPDATE admissions SET state='fenced' WHERE state='active'")
            # No restore loop: prior controller receipts are historical only.
        except BaseException:
            try:
                if self.db is not None:
                    self.db.close()
            finally:
                lease, self._lease = self._lease, -1
                os.close(lease)
            raise

    def _install(self, operation, offer, binding):
        self._active[operation] = (offer, binding)

    def admit(self, control):
        # Never hold the authority/ledger lock over a blocking transport read.
        # Revoke and control-loss must be able to fence a stalled receiver.
        controller, supervisor = self.controller, self.supervisor
        try:
            offer = _receive_offer(control, supervisor, self.seats)
        except BaseException:
            self.control_lost()
            raise
        installed = False
        try:
            with self._lock:
                if (self._closed or self._fenced or controller != self.controller
                        or supervisor is not self.supervisor or supervisor.revoked
                        or not alive(supervisor.pidfd)):
                    raise OriginDenied('Hub control is fenced or changed')
                self.endpoint.require()
                doc = offer.document
                operation, participant = doc['operation_id'], doc['seat']['participant_id']
                if not alive(offer.origin.pidfd):
                    raise OriginDenied('runtime exited before admission')
                digest = hashlib.sha256(_canonical(doc)).hexdigest()
                if self.db.execute('SELECT 1 FROM admissions WHERE operation=?', (operation,)).fetchone():
                    raise OriginDenied('operation already observed; use read-only status')
                if any(active.origin.identity == offer.origin.identity
                       for active, _ in self._active.values()):
                    raise OriginDenied('kernel task already bound to an active seat')
                previous = self.db.execute('SELECT MAX(epoch) FROM admissions WHERE participant=?', (participant,)).fetchone()[0]
                if previous is not None and doc['epoch'] <= previous:
                    raise OriginDenied('stale admission epoch')
                if any(binding.seat.participant_id == participant for _, binding in self._active.values()):
                    raise OriginDenied('existing seat must be fenced before replacement')
                binding = AdmittedBinding(self.seats[participant], operation, doc['incarnation'],
                                          doc['epoch'], doc['readiness_digest'])
                receipt = {'version': 1, 'operation_id': operation, 'epoch': binding.epoch,
                           'controller': self.controller, 'admission_digest': digest}
                self.db.execute('BEGIN IMMEDIATE')
                try:
                    self.db.execute('INSERT INTO admissions VALUES (?,?,?,?,?,?,?)',
                        (operation, digest, participant, binding.epoch, self.controller,
                         _canonical(receipt).decode(), 'active'))
                    self.db.execute('COMMIT')
                except BaseException:
                    if self.db.in_transaction:
                        self.db.execute('ROLLBACK')
                    raise
                # Commit/install/dispatch share the same lock. Any failure after
                # commit fences the controller, so durable receipt != authority.
                try:
                    self._install(operation, offer, binding)
                except BaseException:
                    self.control_lost()
                    raise
                installed = True
                return {**receipt, 'status': 'ADMITTED'}
        finally:
            if not installed:
                offer.close()

    def status(self, operation):
        """Read-only reconciliation for the trusted control loop; never relaunch."""
        with self._lock:
            row = self.db.execute('SELECT receipt,state FROM admissions WHERE operation=?', (operation,)).fetchone()
            active = self._active.get(operation)
            installed = (not self._fenced and active is not None
                         and not active[0].origin.revoked and alive(active[0].origin.pidfd)
                         and not self.supervisor.revoked and alive(self.supervisor.pidfd))
            return {'receipt': None if row is None else json.loads(row[0]), 'installed': installed,
                    'state': 'absent' if row is None else row[1]}

    def _check_current(self, operation, record=None):
        """Pure authority observation; caller already holds the admission lock."""
        active = self._active.get(operation)
        if (self._closed or self._fenced or active is None or self.supervisor.revoked
                or not alive(self.supervisor.pidfd)):
            raise OriginDenied('inactive admission')
        offer, binding = active
        self.endpoint.require()
        if offer.origin.revoked or not alive(offer.origin.pidfd):
            raise OriginDenied('runtime task unavailable')
        if record is not None:
            offer.origin.require(record)
        return offer, binding

    def peer_channel(self, operation):
        """Borrow for receive outside the lock; channel alone grants no authority."""
        with self._lock:
            return self._check_current(operation)[0].channel

    def binding(self, operation):
        """Trusted local attachment metadata, never Participant-selected identity."""
        with self._lock:
            return self._check_current(operation)[1]

    def recheck(self, operation, record):
        """Pure transaction-time check, with NO lock acquisition or store write.

        It is usable only inside this thread's already-held authorize context,
        preserving admission -> RoomLedger lock order even inside apply().
        """
        if not getattr(self._authorization, 'depth', 0):
            raise OriginDenied('authority lock must precede ledger transaction')
        self._check_current(operation, record)
        return True

    @contextmanager
    def authorize(self, operation, record):
        """Hold through the consuming Hub ledger transaction, serializing revoke."""
        with self._lock:
            if self.supervisor.revoked or not alive(self.supervisor.pidfd):
                self.control_lost()
            try:
                _, binding = self._check_current(operation, record)
            except OSError:
                self.control_lost()
                raise
            self._authorization.depth = getattr(self._authorization, 'depth', 0) + 1
            try:
                yield binding
            finally:
                self._authorization.depth -= 1

    def revoke(self, operation):
        with self._lock:
            active = self._active.pop(operation, None)
            if active is not None:
                active[0].origin.revoke()
                try:
                    self.db.execute("UPDATE admissions SET state='revoked' WHERE operation=?", (operation,))
                except BaseException:
                    self._fenced = True
                    raise
                finally:
                    active[0].close()

    def control_lost(self):
        with self._lock:
            self._fenced = True
            error = None
            for operation in tuple(self._active):
                try:
                    self.revoke(operation)
                except BaseException as failure:
                    error = failure
            if error is not None:
                raise error

    def close(self):
        with self._lock:
            if not self._closed:
                try:
                    self.control_lost()
                finally:
                    self._closed = True
                    try:
                        self.db.close()
                    finally:
                        # Clear ownership before close: a failing close is not
                        # permission to retry a possibly recycled descriptor.
                        lease, self._lease = self._lease, -1
                        if lease >= 0:
                            os.close(lease)
