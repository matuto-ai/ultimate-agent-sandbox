"""One fixed credential-free native Git worker in the existing Workstation.

This is not a shell executor. The ordinary public launcher is untrusted RPC;
only this Supervisor-launched, distinct-UID worker supplies command evidence.
Container/image/mount admission stays with the existing Supervisor. In
particular, this module never repairs Project permissions or creates mounts.
"""
import array
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import time
import select

from .git_policy import GitIdentity, parse_git
from .git_service import decode, send
from .kernel_origin import HeldOrigin, OriginDenied, Record, SCM_PIDFD, _identity, alive, enable, receive
from .ledger import LedgerError, Origin, _json
from .workstation_exec import ExecLaunch, ExecUnavailable

WORKER = '/opt/uas/bin/git-worker-connector'
WORKER_UID = 65530
WORKER_GID = 65532
_STATUS = {'CapEff': '0000000000000000', 'CapBnd': '0000000000000000', 'NoNewPrivs': '1', 'Seccomp': '2'}


class GitExecLaunch(ExecLaunch):
    """The same journal/challenge/kernel/Engine binding as native Runtime exec.

    The distinct UID is fixed, never selected by a Participant. An already
    admitted Workstation must expose the exact Project checkout with suitable
    existing access and the immutable Git runtime view; absence fails closed.
    """
    def _create_spec(self):
        return {'AttachStdin': True, 'AttachStdout': True, 'AttachStderr': True,
                'Tty': False, 'Privileged': False, 'User': '65530:65532',
                'WorkingDir': '/uas/workspace', 'Cmd': [WORKER, self.seat.slot], 'Env': []}

    def attach_worker(self):
        if self.state != 'released': raise ExecUnavailable('Git worker not freshly released')
        try:
            with receive(self.channel) as record:
                self.origin.require(record)
                value = decode(record.data)
            if (any(type(value.get(key)) is not int for key in ('version', 'uid', 'gid'))
                    or value != {'kind': 'GIT_WORKER_READY', 'version': 1, 'uid': WORKER_UID,
                         'gid': WORKER_GID, 'kernel_status': _STATUS}):
                raise ExecUnavailable('fixed Git worker boundary differs')
            self.activate(lambda launch: launch is self)
            return TrustedGitWorker(self)
        except BaseException:
            self.origin.revoke()
            self.state = 'uncertain'
            self._save()
            raise


class TrustedGitWorker:
    def __init__(self, launch):
        if type(launch) is not GitExecLaunch or launch.state != 'active':
            raise OriginDenied('exact active Supervisor Git worker required')
        self.launch = launch
        self.used = False

    @property
    def channel(self): return self.launch.channel

    def require(self, record):
        self.launch.require_record(record, room_id=self.launch.seat.room_id,
                                   participant_id=self.launch.seat.participant_id)

    def configure(self, document, backend_fd):
        if self.used: raise LedgerError('GIT_WORKER_ALREADY_CONSUMED')
        self.used = True  # Never replay after send uncertainty.
        packet = _json(document).encode()
        if len(packet) > 65536: raise LedgerError('INVALID_GIT_REQUEST')
        self.launch.endpoint.require()
        if self.channel.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                              array.array('i', [backend_fd]))]) != len(packet):
            raise OriginDenied('Git worker configuration send uncertain')

    def receive(self):
        with receive(self.channel) as record:
            self.require(record)
            return decode(record.data)

    def reply(self, value):
        self.launch.endpoint.require()
        send(self.channel, value)

    def finish(self, operation_id, *, timeout=2):
        """A live authenticated cleanup acknowledgement, then held-task exit.

        Closing ExecLaunch is not this proof; no numeric PID kill/reap/adoption
        occurs here. Engine remains the worker's process owner.
        """
        if type(timeout) not in (int, float) or not 0 < timeout <= 2:
            raise OriginDenied('invalid Git cleanup deadline')
        deadline = time.monotonic() + timeout
        previous = self.channel.gettimeout()
        held = -1
        try:
            origin = self.launch.origin
            expected_identity = origin.identity
            if origin.revoked or type(origin.pidfd) is not int or origin.pidfd < 0:
                raise OriginDenied('Git worker process ownership absent')
            held = os.dup(origin.pidfd)
            # Independent descriptor ownership prevents concurrent launch.close
            # or descriptor reuse from turning closed-fd state into exit proof.
            if _identity(held) != expected_identity or not alive(held):
                raise OriginDenied('Git worker process ownership changed')
            self.channel.settimeout(timeout)
            expected = {'kind': 'GIT_WORKER_QUIESCENT', 'version': 1, 'operation_id': operation_id}
            value = self.receive()
            if type(value.get('version')) is not int or value != expected or time.monotonic() >= deadline:
                raise OriginDenied('Git worker quiescence not verified')
            self.reply({'kind': 'GIT_WORKER_EXIT_ACK', 'version': 1, 'operation_id': operation_id})
            while alive(held):
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise OriginDenied('Git worker exit not observed')
                select.select([held], [], [], min(.05, remaining))
            if time.monotonic() >= deadline:
                raise OriginDenied('Git worker cleanup deadline exceeded')
            return {'worker_identity': list(expected_identity), 'quiescent': True, 'exited': True}
        finally:
            try: self.channel.settimeout(previous)
            finally:
                if held >= 0:
                    descriptor, held = held, -1
                    os.close(descriptor)


def receive_configuration(channel, peer):
    """Worker-only initial message: one sealed backend, no host directory fds.

    Project directories MUST be opened inside the existing Workstation mount
    namespace. Passing a host directory FD would expose its host mount ancestry.
    """
    data, ancillary, flags, _ = channel.recvmsg(65536,
        socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4) + socket.CMSG_SPACE(253 * 4), socket.MSG_CMSG_CLOEXEC)
    installed, credentials, pidfds, rights = [], [], [], []
    invalid = not data or bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
    try:
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, SCM_PIDFD):
                fds = array.array('i'); fds.frombytes(raw[:len(raw) - len(raw) % 4])
                installed.extend(fd for fd in fds if fd >= 0)
                if len(raw) % 4 or any(fd < 0 for fd in fds): invalid = True
                (pidfds if kind == SCM_PIDFD else rights).extend(fds)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(raw) == 12:
                credentials.append(struct.unpack('3i', raw))
            else: invalid = True
        if (invalid or len(credentials) != 1 or len(pidfds) != 1 or len(rights) != 1
                or any(os.get_inheritable(fd) for fd in installed)):
            raise OriginDenied('invalid private Git worker configuration')
        record = Record(data, credentials[0], pidfds[0])
        supervisor = peer.hold(record)
        installed.remove(pidfds[0]); installed.remove(rights[0])
        try:
            return decode(data), rights[0], supervisor
        except BaseException:
            try: supervisor.close()
            finally: os.close(rights[0])
            raise
    finally:
        cleanup_error = None
        while installed:
            try: os.close(installed.pop())
            except OSError as error: cleanup_error = error
        if cleanup_error is not None: raise cleanup_error


def worker_ready(channel):
    from .workstation_probe import process_status
    if os.getuid() != WORKER_UID or os.getgid() != WORKER_GID or process_status() != _STATUS:
        raise OriginDenied('fixed isolated Git worker required')
    send(channel, {'kind': 'GIT_WORKER_READY', 'version': 1, 'uid': WORKER_UID,
                   'gid': WORKER_GID, 'kernel_status': _STATUS})


def open_inside(path, *, directory):
    """Open only canonical configured paths inside this Workstation namespace."""
    if (type(path) is not str or not path.startswith('/') or str(Path(path)) != path
            or path.startswith('//') or '..' in Path(path).parts or '\x00' in path):
        raise OriginDenied('canonical Git runtime path required')
    parent = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    result = -1
    try:
        for component in Path(path).parts[1:-1]:
            next_fd = os.open(component, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            previous, parent = parent, next_fd
            os.close(previous)
        result = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                         | (os.O_DIRECTORY if directory else 0), dir_fd=parent)
    finally:
        previous, parent = parent, -1
        try: os.close(previous)
        except BaseException:
            if result >= 0:
                descriptor, result = result, -1
                os.close(descriptor)
            raise
    return result


def main():
    """Fixed connector's FD3, not caller-provided paths or configuration."""
    from .git_endpoint import EndpointPeer
    from .git_worker_native import worker_main
    with socket.socket(fileno=3) as channel:
        enable(channel); channel.settimeout(40)
        peer = EndpointPeer(channel)
        supervisor = None
        try:
            worker_ready(channel)
            document, backend, supervisor = receive_configuration(channel, peer)
            result = worker_main(channel, document, backend, supervisor)
            operation = document['operation_id']
            # worker_main returns only after owned native cleanup and all local
            # resource disposal. Stay alive until Supervisor authenticates this.
            send(channel, {'kind': 'GIT_WORKER_QUIESCENT', 'version': 1, 'operation_id': operation})
            with receive(channel) as record:
                supervisor.require(record)
                value = decode(record.data)
                if type(value.get('version')) is not int or value != {'kind': 'GIT_WORKER_EXIT_ACK', 'version': 1, 'operation_id': operation}:
                    raise OriginDenied('Git worker exit acknowledgement absent')
            return result
        finally:
            try: peer.close()
            finally:
                if supervisor is not None: supervisor.close()
