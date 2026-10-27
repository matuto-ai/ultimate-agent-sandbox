"""Concrete callable Git assembly for an already admitted Supervisor Room.

This does not admit a Workstation, provision credentials, install mounts, or
start a listener. Its caller owns those existing resources and their lifecycle.
The public request can select arguments only, never an Actor, Engine recipe,
backend, checkout projection, endpoint, or provenance store.
This first assembly deliberately supports identity-mapped worker UID/GID only;
user-namespace translations require separate admission and are not inferred.
The admitted worktree ancestry must be non-renamable by Participant/worker,
with mount administration denied; RuntimeView checks the mount root, not the
complete readonly-rootfs/disjoint-writable-mount admission contract.
"""
import os
from pathlib import Path
import socket
import stat
import uuid

from .git_controller import GitCoordinator, serve_one
from .git_process import GitChildAuthority, GitSeat
from .git_worker import GitExecLaunch
from .kernel_origin import OriginDenied, enable
from .workstation_exec import EndpointLease, ExecSeat


class GitSupervisor:
    def __init__(self, binding, room_instance, identities, checkouts, provenance, broker,
                 engine, seats, worker_seats, *, request_listener, worker_listener,
                 request_endpoint, worker_endpoint, journal_dir, backend_fd,
                 backend_sha256, lifecycle_lock, run_scope):
        if (type(seats) is not tuple or not seats or len(seats) > 32
                or any(type(seat) is not GitSeat for seat in seats)
                or type(worker_seats) is not tuple or len(worker_seats) != len(seats)
                or any(type(seat) is not ExecSeat for seat in worker_seats)
                or not callable(lifecycle_lock)):
            raise OriginDenied('exact admitted Git seats required')
        self.lifecycle_lock = lifecycle_lock
        self.journal_dir = Path(journal_dir)
        node = self.journal_dir.lstat()
        if (not self.journal_dir.is_absolute() or self.journal_dir.resolve() != self.journal_dir
                or not stat.S_ISDIR(node.st_mode) or node.st_uid != os.getuid()
                or stat.S_IMODE(node.st_mode) != 0o700):
            raise OriginDenied('existing private Git launch journal required')
        self.journal_identity = (node.st_dev, node.st_ino)
        self.request_listener, self.worker_listener = request_listener, worker_listener
        self.request_endpoint, self.worker_endpoint = request_endpoint, worker_endpoint
        for listener, endpoint in ((request_listener, request_endpoint), (worker_listener, worker_endpoint)):
            if (type(listener) is not socket.socket or type(endpoint) is not EndpointLease
                    or listener.family != socket.AF_UNIX or listener.type != socket.SOCK_SEQPACKET
                    or listener.getsockname() != str(endpoint.path)):
                raise OriginDenied('exact prebound Git endpoint required')
            endpoint.require()
            enable(listener)
        self.engine, self.closed = engine, False
        self.seats = {}
        for admitted, worker in zip(seats, worker_seats):
            origin = admitted.origin
            if (worker.room_id != binding.room_id or worker.room_instance != room_instance
                    or worker.actor_id != origin.actor_id or worker.participant_id != origin.participant_id
                    or worker.host_uid != 65530 or worker.host_gid != 65532
                    or origin.participant_id in self.seats):
                raise OriginDenied('fixed mapped Git worker seat differs')
            self.seats[origin.participant_id] = (admitted, worker)
        self.children = GitChildAuthority(seats)
        try:
            self.coordinator = GitCoordinator(binding, room_instance, identities, checkouts,
                provenance, broker, self._worker, backend_fd=backend_fd,
                backend_sha256=backend_sha256, lifecycle_lock=lifecycle_lock, run_scope=run_scope)
        except BaseException:
            self.children.close()
            raise

    def _worker(self, origin):
        # Invoked under the caller's Room lifecycle lock after durable reserve.
        if self.closed: raise OriginDenied('Git Supervisor closed')
        pair = self.seats.get(origin.participant_id)
        if pair is None or pair[0].origin != origin or pair[0].current() is not True:
            raise OriginDenied('Git worker origin is not current admitted seat')
        node = self.journal_dir.lstat()
        if ((node.st_dev, node.st_ino) != self.journal_identity
                or not stat.S_ISDIR(node.st_mode) or node.st_uid != os.getuid()
                or stat.S_IMODE(node.st_mode) != 0o700
                or self.journal_dir.resolve() != self.journal_dir):
            raise OriginDenied('Git launch journal directory replaced')
        self.worker_endpoint.require()
        launch = GitExecLaunch(self.engine, pair[1], self.worker_endpoint,
                               self.journal_dir / (uuid.uuid4().hex + '.json'))
        try:
            launch.launch(self.worker_listener)
            return launch.attach_worker()
        except BaseException:
            launch.close()
            raise

    def serve_next(self, *, timeout=5):
        """One bounded accepted request; caller schedules/serializes admission."""
        if self.closed: raise OriginDenied('Git Supervisor closed')
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise OriginDenied('bounded Git request acceptance required')
        self.request_endpoint.require()
        previous = self.request_listener.gettimeout()
        try:
            self.request_listener.settimeout(timeout)
            channel, _ = self.request_listener.accept()
        finally:
            self.request_listener.settimeout(previous)
        with channel:
            self.request_endpoint.require()
            return serve_one(channel, self.coordinator, self.children, lifecycle_lock=self.lifecycle_lock)

    def close(self):
        if not self.closed:
            self.closed = True
            self.children.close()
