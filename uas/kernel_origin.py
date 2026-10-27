"""Linux x86-64 per-record process objects for the Workstation transport.

This is a transport primitive, not Actor admission. Only a trusted launch gate
may attach one of these objects to a seat. Numeric PID/UID and SO_PEERCRED do not
supply that binding. Unsupported kernels fail closed; no pidfd_open(sender_pid)
fallback is used. Received descriptors belong to Record until explicitly moved.
"""
import array
import ctypes
from dataclasses import dataclass
import os
import platform
import select
import socket
import struct

SO_PASSPIDFD = 76
SCM_PIDFD = 4
PIDFS_MAGIC = 0x50494446
MAX_PACKET = 65536
_UCRED = struct.Struct('3i')
_INT = struct.Struct('i')


class OriginUnavailable(RuntimeError):
    pass


class OriginDenied(RuntimeError):
    pass


def _identity(fd):
    # pidfs (Linux 6.9+) supplies a stable per-struct-pid inode on 64-bit.
    # Old anonymous pidfds share an inode and MUST NOT pass this check.
    if platform.machine() != 'x86_64' or struct.calcsize('P') != 8:
        raise OriginUnavailable('qualified pidfs ABI unavailable')
    info = (ctypes.c_long * 32)()  # aligned, larger than Linux x86-64 statfs
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fstatfs(ctypes.c_int(fd), ctypes.byref(info)) != 0 or info[0] != PIDFS_MAGIC:
        raise OriginUnavailable('pidfs process identity unavailable')
    value = os.fstat(fd)
    return value.st_dev, value.st_ino


def alive(fd):
    if type(fd) is not int or fd < 0:
        return False
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    return not poller.poll(0)


@dataclass
class Record:
    data: bytes
    credentials: tuple
    pidfd: int

    def close(self):
        if self.pidfd >= 0:
            fd, self.pidfd = self.pidfd, -1
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@dataclass(frozen=True)
class ReceiverIdentity:
    """Trusted, preflight-verified UID/GID translation in one receiver context.

    Neither field comes from a Participant. context and mapping_digest bind the
    Supervisor's namespace/mapping observation to this particular Hub launch.
    This value does not itself prove that a namespace was inspected.
    """
    uid: int
    gid: int
    context: str
    mapping_digest: str
    overflow_uid: int = 65534
    overflow_gid: int = 65534

    def __post_init__(self):
        import re
        if (any(type(value) is not int or not 0 < value < 2**31
                for value in (self.uid, self.gid, self.overflow_uid, self.overflow_gid))
                or self.uid == self.overflow_uid or self.gid == self.overflow_gid
                or type(self.context) is not str
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', self.context)
                or type(self.mapping_digest) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', self.mapping_digest)):
            raise OriginDenied('invalid trusted receiver namespace binding')


class HeldOrigin:
    """Owned process object; caller also checks seat epoch, Room and endpoint."""
    def __init__(self, record, *, receiver=None):
        if receiver is not None and type(receiver) is not ReceiverIdentity:
            raise OriginDenied('invalid receiver namespace binding')
        self._receiver = receiver
        if type(record) is not Record or record.pidfd < 0:
            raise OriginDenied('missing kernel origin')
        self.identity = _identity(record.pidfd)
        if not alive(record.pidfd):
            raise OriginDenied('origin exited')
        self.credentials = record.credentials
        self.pidfd, record.pidfd = record.pidfd, -1
        self.revoked = False

    @property
    def receiver(self):
        return self._receiver

    def require(self, record):
        # In a sibling PID namespace SCM_CREDENTIALS.pid can be zero. It is
        # never looked up. pidfs object identity still authenticates the task;
        # the separately pinned receiver UID/GID translation remains mandatory.
        credentials_match = (record.credentials == self.credentials if self.receiver is None
            else record.credentials[1:] == (self.receiver.uid, self.receiver.gid))
        if (self.revoked or not alive(self.pidfd) or not alive(record.pidfd)
                or not credentials_match
                or _identity(record.pidfd) != self.identity):
            raise OriginDenied('record is not the live bound task')

    def revoke(self):
        # Fence before attempting any stop, close or external side effect.
        self.revoked = True

    def close(self):
        self.revoke()
        if self.pidfd >= 0:
            fd, self.pidfd = self.pidfd, -1
            os.close(fd)


def enable(channel):
    if (channel.family != socket.AF_UNIX
            or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
        raise OriginUnavailable('Unix seqpacket required')
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.setsockopt(socket.SOL_SOCKET, SO_PASSPIDFD, 1)
        if (channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1
                or channel.getsockopt(socket.SOL_SOCKET, SO_PASSPIDFD) != 1):
            raise OriginUnavailable('mandatory kernel ancillary options unavailable')
    except OSError as error:
        raise OriginUnavailable('SO_PASSPIDFD unavailable') from error


def receive(channel):
    # Include maximum rights space so malicious passed descriptors are received
    # and closed. If control truncates, the kernel closes uninstalled excess FDs.
    data, ancillary, flags, _ = channel.recvmsg(MAX_PACKET,
        socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(_INT.size)
        + socket.CMSG_SPACE(253 * _INT.size), socket.MSG_CMSG_CLOEXEC)
    installed, credentials, pidfds = [], [], []
    invalid = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)) or not data
    try:
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, SCM_PIDFD):
                descriptors = array.array('i')
                descriptors.frombytes(raw[:len(raw) - len(raw) % _INT.size])
                installed.extend(fd for fd in descriptors if fd >= 0)
                if kind == SCM_PIDFD and len(raw) == _INT.size:
                    pidfds.extend(descriptors)
                else:
                    invalid = True
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(raw) == _UCRED.size:
                credentials.append(_UCRED.unpack(raw))
            else:
                invalid = True
        if invalid or len(credentials) != 1 or len(pidfds) != 1 or pidfds[0] < 0:
            raise OriginDenied('malformed, truncated or unauthenticated record')
        fd = pidfds[0]
        if os.get_inheritable(fd):
            raise OriginDenied('inheritable kernel descriptor')
        _identity(fd)
        result = Record(data, credentials[0], fd)
        installed.remove(fd)
        return result
    finally:
        for fd in installed:
            os.close(fd)


def probe():
    """Actual kernel capability probe, not a version-number assumption."""
    own = other = left = right = None
    try:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        enable(left)
        own = os.pidfd_open(os.getpid())
        parent = os.getppid()
        if parent <= 0:
            raise OriginUnavailable('known parent unavailable; qualified Hub init required')
        other = os.pidfd_open(parent)
        if _identity(own) == _identity(other):
            raise OriginUnavailable('non-unique pidfd identity')
        right.send(b'kernel-origin-probe')
        with receive(left) as record:
            if (record.data != b'kernel-origin-probe'
                    or record.credentials != (os.getpid(), os.getuid(), os.getgid())
                    or _identity(record.pidfd) != _identity(own) or not alive(record.pidfd)):
                raise OriginUnavailable('kernel-origin probe mismatch')
        return {'kernel': platform.release(), 'machine': platform.machine(),
                'passpidfd': True, 'pidfs': True}
    except (OSError, AttributeError, OriginDenied) as error:
        raise OriginUnavailable('kernel-origin support unavailable') from error
    finally:
        for channel in (left, right):
            if channel is not None:
                channel.close()
        for fd in (own, other):
            if fd is not None:
                os.close(fd)
