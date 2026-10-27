"""Supervisor-owned native Git child attribution, not ambient socket authority.

Every admission starts with SCM_PIDFD.  Bounded /proc lookups corroborate the
current live parent links to an already admitted Participant; numeric PIDs never
create an Actor.  The receiver must see the whole lineage in its pinned procfs
view.  Nested/foreign PID or user namespaces, reparenting and ambiguity refuse.
"""
from dataclasses import dataclass
import os
import re
import stat
import time

from .kernel_origin import HeldOrigin, OriginDenied, Record, _identity, alive
from .ledger import Origin

MAX_DEPTH = 32
MAX_SECONDS = .050
MAX_STATUS = 16384
_FIELDS = ('Pid', 'Tgid', 'PPid', 'Uid', 'Gid', 'NSpid', 'NStgid')


def parse_status(raw):
    """Inert parser; no caller strings enter a path or diagnostic."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_STATUS:
        raise OriginDenied('invalid bounded process status')
    try:
        fields = {}
        for line in raw.decode('ascii').splitlines():
            name, separator, value = line.partition(':')
            if name not in _FIELDS:
                continue
            if not separator or name in fields:
                raise ValueError()
            parts = value.split()
            if not parts or any(not re.fullmatch(r'[0-9]{1,10}', item) for item in parts):
                raise ValueError()
            numbers = tuple(int(item) for item in parts)
            if any(item >= 2**31 for item in numbers):
                raise ValueError()
            fields[name] = numbers
        if set(fields) != set(_FIELDS):
            raise ValueError()
        if any(len(fields[name]) != 1 for name in ('Pid', 'Tgid', 'PPid')):
            raise ValueError()
        if any(len(fields[name]) != 4 for name in ('Uid', 'Gid')):
            raise ValueError()
        if (fields['Pid'] != fields['Tgid'] or fields['Pid'][0] <= 0
                or not 1 <= len(fields['NSpid']) <= 32
                or fields['NSpid'] != fields['NStgid']
                or fields['NSpid'][0] != fields['Pid'][0]
                or any(value <= 0 for value in fields['NSpid'])):
            raise ValueError()
        return fields
    except (ValueError, UnicodeError):
        raise OriginDenied('inconsistent process status') from None


def _read_at(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        data = os.read(fd, MAX_STATUS + 1)
        if len(data) > MAX_STATUS or os.read(fd, 1):
            raise OriginDenied('oversized process status')
        return data
    finally:
        os.close(fd)


class ProcView:
    """Hold the receiver's actual procfs root; never accept an input path."""
    def __init__(self):
        import ctypes
        self.receiver_directory = -1
        self.fd = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fs = (ctypes.c_long * 32)()
            if ctypes.CDLL(None, use_errno=True).fstatfs(self.fd, ctypes.byref(fs)) or fs[0] != 0x9fa0:
                raise OriginDenied('receiver procfs unavailable')
            # `self` is procfs's kernel-resolved current process, not the
            # unproved numeric /proc/getpid lookup. In an ancestor proc mount,
            # identical-looking numeric PIDs can otherwise describe strangers.
            if os.readlink('self', dir_fd=self.fd) != str(os.getpid()):
                raise OriginDenied('receiver procfs self mapping differs')
            own = os.open('self', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=self.fd)
            try:
                observed = parse_status(_read_at(own, 'status'))
                if observed['Pid'] != (os.getpid(),) or observed['NSpid'] != (os.getpid(),):
                    raise OriginDenied('receiver procfs PID mapping differs')
                descriptor = os.pidfd_open(os.getpid())
                try:
                    if not alive(descriptor):
                        raise OriginDenied('receiver process unavailable')
                    self.receiver_identity = _identity(descriptor)
                finally:
                    os.close(descriptor)
                self.receiver_namespace = self.namespaces(own)
                # NSpid starts in the proc mount's PID namespace and lists
                # descendants down to this task's active namespace. For the
                # actual receiver's own view it MUST contain one element;
                # numeric equality alone can accidentally hold in an ancestor
                # view and is not proof of the correct PID mapping.
                self.receiver_directory, own = own, -1
            finally:
                if own >= 0: os.close(own)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def namespaces(directory):
        values = []
        for name in ('ns/pid', 'ns/user'):
            # These are kernel procfs namespace magic links, not caller paths.
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
            try:
                node = os.fstat(fd)
                if not stat.S_ISREG(node.st_mode) or node.st_ino <= 0:
                    raise OriginDenied('process namespace unavailable')
                values.append((node.st_dev, node.st_ino))
            finally:
                os.close(fd)
        return tuple(values)

    def close(self):
        if self.receiver_directory >= 0:
            fd, self.receiver_directory = self.receiver_directory, -1
            os.close(fd)
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            os.close(fd)

    def require(self):
        if self.fd < 0 or self.receiver_directory < 0:
            raise OriginDenied('pinned receiver procfs mapping changed')
        status = parse_status(_read_at(self.receiver_directory, 'status'))
        if (os.readlink('self', dir_fd=self.fd) != str(os.getpid())
                or status['Pid'] != (os.getpid(),) or status['NSpid'] != (os.getpid(),)
                or self.namespaces(self.receiver_directory) != self.receiver_namespace):
            raise OriginDenied('pinned receiver procfs mapping changed')


class _Task:
    """One corroborated link.  The initial link must match SCM_PIDFD."""
    def __init__(self, view, pid, *, expected=None):
        self.view, self.pid = view, pid
        self.pidfd = self.directory = -1
        if type(pid) is not int or not 0 < pid < 2**31:
            raise OriginDenied('unmapped process in receiver namespace')
        try:
            self.pidfd = os.pidfd_open(pid)
            self.identity = _identity(self.pidfd)
            if expected is not None and self.identity != expected:
                raise OriginDenied('numeric PID no longer denotes received process')
            self.directory = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=view.fd)
            self.status, self.namespace = self.observe()
        except BaseException:
            self.close()
            raise

    def observe(self):
        self.view.require()
        if not alive(self.pidfd):
            raise OriginDenied('lineage task exited')
        # A numeric lookup is only an identity cross-check against the held
        # task.  It is never a fallback for an absent SCM_PIDFD.
        current = os.pidfd_open(self.pid)
        try:
            if _identity(current) != self.identity or not alive(current):
                raise OriginDenied('lineage PID replaced')
            result = parse_status(_read_at(self.directory, 'status'))
            namespace = self.view.namespaces(self.directory)
            if result['Pid'] != (self.pid,) or not alive(self.pidfd):
                raise OriginDenied('lineage task changed during observation')
            return result, namespace
        finally:
            os.close(current)

    def check(self):
        status, namespace = self.observe()
        if status != self.status or namespace != self.namespace:
            raise OriginDenied('lineage reparented or namespace/credentials changed')

    def close(self):
        for name in ('directory', 'pidfd'):
            fd = getattr(self, name)
            if fd >= 0:
                setattr(self, name, -1)
                os.close(fd)


@dataclass(frozen=True)
class GitSeat:
    """Constructed only from the Supervisor's current admitted Runtime."""
    origin: Origin
    process: HeldOrigin
    current: object
    namespace: tuple
    pid_depth: int

    def __post_init__(self):
        if (type(self.origin) is not Origin or type(self.process) is not HeldOrigin
                or not callable(self.current) or type(self.namespace) is not tuple
                or len(self.namespace) != 2 or any(type(pair) is not tuple or len(pair) != 2
                    or any(type(value) is not int or value <= 0 for value in pair) for pair in self.namespace)
                or type(self.pid_depth) is not int or not 1 <= self.pid_depth <= 32):
            raise OriginDenied('trusted current Git seat required')


class GitProcessBinding:
    def __init__(self, tasks, seat, credentials):
        self.tasks, self.seat, self.credentials = tasks, seat, credentials
        self.closed = False

    @property
    def origin(self):
        return self.seat.origin

    def current(self, *, deadline=None):
        """Caller serializes this final check with Room/seat revocation."""
        now = time.monotonic()
        deadline = now + MAX_SECONDS if deadline is None else min(deadline, now + MAX_SECONDS)
        if now >= deadline:
            raise OriginDenied('lineage observation deadline exceeded')
        if self.closed or self.seat.current() is not True:
            raise OriginDenied('native Git authority revoked')
        root = self.seat.process
        if root.revoked or not alive(root.pidfd) or _identity(root.pidfd) != self.tasks[-1].identity:
            raise OriginDenied('Participant exited or replaced')
        # Revalidate root down to caller.  A dead parent cannot be replaced by
        # a reused number while retaining its original child's real-parent link.
        for task in reversed(self.tasks):
            if time.monotonic() >= deadline:
                raise OriginDenied('lineage observation deadline exceeded')
            task.check()
            if time.monotonic() >= deadline:
                raise OriginDenied('lineage observation deadline exceeded')
        if self.seat.current() is not True:
            raise OriginDenied('native Git authority revoked')
        if time.monotonic() >= deadline:
            raise OriginDenied('lineage observation deadline exceeded')
        return True

    def require(self, record):
        if (type(record) is not Record or record.pidfd < 0
                or record.credentials != self.credentials
                or _identity(record.pidfd) != self.tasks[0].identity
                or not alive(record.pidfd)):
            raise OriginDenied('Git record is not the admitted task')
        return self.current()

    def close(self):
        self.closed = True
        while self.tasks:
            self.tasks.pop().close()


class GitChildAuthority:
    """Fresh bounded lineage per new request; no positive ancestry cache."""
    def __init__(self, seats):
        if (type(seats) not in (tuple, list) or not 1 <= len(seats) <= 32
                or any(type(seat) is not GitSeat for seat in seats)):
            raise OriginDenied('bounded trusted Git seats required')
        self.seats = {seat.process.identity: seat for seat in seats}
        if len(self.seats) != len(seats):
            raise OriginDenied('duplicate Git process authority')
        self.view = ProcView()

    def bind(self, record):
        deadline = time.monotonic() + MAX_SECONDS
        if (type(record) is not Record or record.pidfd < 0
                or type(record.credentials) is not tuple or len(record.credentials) != 3
                or any(type(v) is not int or v <= 0 for v in record.credentials)
                or not alive(record.pidfd)):
            raise OriginDenied('live mapped kernel process origin required')
        allowed = {seat.process.credentials[1:] for seat in self.seats.values()}
        if record.credentials[1:] not in allowed:
            raise OriginDenied('unexpected Git process credentials')
        tasks, seen = [], set()
        pid, expected = record.credentials[0], _identity(record.pidfd)
        try:
            for _ in range(MAX_DEPTH):
                if time.monotonic() >= deadline:
                    raise OriginDenied('lineage admission deadline exceeded')
                task = _Task(self.view, pid, expected=expected)
                tasks.append(task)
                if time.monotonic() >= deadline:
                    raise OriginDenied('lineage admission deadline exceeded')
                if task.identity in seen:
                    raise OriginDenied('cyclic or replaced process lineage')
                seen.add(task.identity)
                uid, gid = record.credentials[1:]
                if (task.status['Uid'] != (uid,) * 4 or task.status['Gid'] != (gid,) * 4
                        or task.namespace != tasks[0].namespace
                        or len(task.status['NSpid']) != len(tasks[0].status['NSpid'])):
                    raise OriginDenied('foreign credential or namespace lineage')
                seat = self.seats.get(task.identity)
                if seat is not None:
                    if (seat.process.credentials[1:] != (uid, gid)
                            or task.namespace != seat.namespace
                            or len(task.status['NSpid']) != seat.pid_depth):
                        raise OriginDenied('root receiver mapping differs')
                    result = GitProcessBinding(tasks, seat, record.credentials)
                    result.current(deadline=deadline)
                    tasks = []
                    return result
                pid, expected = task.status['PPid'][0], None
                if pid <= 0:
                    break
            raise OriginDenied('no current Participant within bounded lineage')
        except (OSError, ValueError):
            raise OriginDenied('native Git lineage unavailable') from None
        finally:
            while tasks:
                tasks.pop().close()

    def close(self):
        self.view.close()
