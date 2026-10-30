"""Local operator transport for the persistent installation owner.

A private Unix socket authenticates the installation's OS owner; it is not a
Room/Participant endpoint or a replacement for human Manager mTLS. Requests
select only fixed actions and configured Rooms, never commands or credentials.
"""
import json
import fcntl
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import stat
import struct

from .local_installation import Installation, LocalInstallationError, document, canonical, require

MAX_REQUEST = 8192
MAX_RESPONSE = 1024 * 1024


class LocalController:
    def __init__(self, installation, native_factory, *, services, host_lock_fd=None, manager=None,
                 library=None):
        require(type(installation) is Installation, 'INSTALLATION_OWNER_REQUIRED')
        if library is not None:
            from .library_deployment import DeploymentLibrary
            require(type(library) is DeploymentLibrary, 'LOCAL_LIBRARY_DEPLOYMENT_REQUIRED')
        self.installation = installation
        self.value, self.config, selected = installation.open()
        self.rooms = {r['id'] for r in self.config['rooms']}
        self.services = services
        self.host_lock_fd = host_lock_fd
        self.manager = manager
        self.library = library
        self._ledgers = {}
        self.native = None
        if selected['native'] is not None:
            self.native = native_factory(self.config, selected['native'],
                Path(self.config['deployment']['state_root']),
                authorize=self.authorize, revoke=self.revoke,
                runtimeplans={room:installation.runtime_plan_for for room in self.value.get('runtime',{})})

    def authorize(self, action, room_id, instance):
        return os.geteuid() == 0 and room_id in self.rooms and action in {'start', 'stop', 'checkout.allocate', 'checkout.status', 'checkout.release', 'checkout.reserve'}

    def revoke(self, instance, scope):
        # Actual service owner decides; never infer revocation from a PID or a flag.
        return self.services.revoke(instance, scope) is True

    def handle(self, raw):
        from .local_services import LocalServices
        if type(self.services) is LocalServices:
            with self.services.operation_lock:
                return self._handle(raw)
        return self._handle(raw)

    def ledger(self, room):
        """The running Room's canonical ledger; no guessed instance or path."""
        from .ledger import RoomLedger
        if self.native is None:
            raise LocalInstallationError('LIBRARY_LEDGER_UNAVAILABLE')
        path = self._ledgers.get(room)
        if path is None:
            owner, backend, state = self.native.resources(room)
            path = backend.layout(state)['hub'] / 'room.db'
            self._ledgers[room] = path
        return RoomLedger(path, room)

    def _handle(self, raw):
        require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST, 'REQUEST_SIZE')
        request = document(raw)
        require(set(request) == {'action', 'room_id'} and request['action'] in {'start','status','stop'}
                and type(request['room_id']) is str and request['room_id'] in self.rooms,
                'LOCAL_REQUEST_REFUSED')
        action, room = request['action'], request['room_id']
        # Never silently reread changed selections into an already-running host.
        current, _, _ = self.installation.open()
        require(current == self.value, 'INSTALLATION_CHANGED_RESTART_REQUIRED')
        if self.native is None:
            return {'room_id':room, 'state':'not-configured', 'missing':['native-installation'],
                    'runtime':'not-started', 'isolation':'not-verified'}
        if action == 'start':
            if self.host_lock_fd is not None:
                self.native.prepare_start(room, owner_lock_fd=self.host_lock_fd)
            # A Room whose projection this request bound must not keep it when
            # the Room itself fails to start; a projection the host published at
            # startup is left to the lease, which removes no content.
            bound = False
            if self.library is not None and not self.library.bound(room):
                self.library.start_room(room)
                bound = True
            try:
                result = self.native.start(room)
                owner, backend, state = self.native.resources(room)
                self._ledgers.pop(room, None)  # a restarted Room owns a new ledger path
                service = self.services.ensure(room, owner, backend, state)
            except BaseException:
                if bound:
                    self.library.stop_room(room)
                raise
            manager = ({'status':'owned-by-runtime-child'} if service.get('manager_owner') in {'runtime','unknown'} else
                       self.manager.ensure(room, owner, backend, state) if self.manager else {'status':'not-configured'})
            return {**result, 'services': service, 'manager':manager}
        if action == 'stop':
            result = self.native.stop(room)
            # Room Stop releases only this projection; canonical data and the
            # Library singleton keep running.
            if self.library is not None:
                self.library.stop_room(room)
            self._ledgers.pop(room, None)
            return result
        return {**self.native.status(room), 'services': self.services.status(room),
                'manager':self.manager.status() if self.manager else {'status':'not-configured'}}


def peer_owner(channel, owner):
    raw = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    _, uid, _ = struct.unpack('3i', raw)
    require(uid == owner, 'LOCAL_OPERATOR_REQUIRED')


@contextmanager
def host_lock(installation):
    """Exclusive owner retained by every helper, independent of request locks."""
    installation._safe_root()
    fd = os.open(installation.root/'host.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    try:
        node = os.fstat(fd)
        require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1
                and node.st_uid == os.geteuid() and not node.st_mode & 0o077, 'LOCAL_HOST_LOCK_UNSAFE')
        try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise LocalInstallationError('LOCAL_HOST_ALREADY_ACTIVE') from None
        yield fd
    finally:
        os.close(fd)


def serve(installation, controller, *, stopped, owner_lock_fd=None):
    """Foreground service; installation owner supplies the process lifecycle.

    A stale endpoint is recovered only under its exclusive installation lock. On interruption, cleanup
    removes only the socket inode this invocation actually created.
    """
    installation._safe_root()
    endpoint = installation.root/'operator.sock'
    require(len(os.fsencode(endpoint)) <= 107, 'LOCAL_SOCKET_PATH_TOO_LONG')
    if os.path.lexists(endpoint):
        require(owner_lock_fd is not None, 'LOCAL_HOST_ALREADY_PRESENT_OR_UNCERTAIN')
        lock = os.fstat(owner_lock_fd)
        expected = (installation.root/'host.lock').lstat()
        require((lock.st_dev,lock.st_ino)==(expected.st_dev,expected.st_ino)
                and stat.S_ISREG(lock.st_mode) and lock.st_uid==os.geteuid()
                and not lock.st_mode&0o077 and lock.st_nlink==1, 'LOCAL_HOST_LOCK_UNSAFE')
        try: fcntl.flock(owner_lock_fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise LocalInstallationError('LOCAL_HOST_ALREADY_ACTIVE') from None
        node = endpoint.lstat()
        require(stat.S_ISSOCK(node.st_mode) and node.st_uid==os.geteuid(), 'LOCAL_SOCKET_OWNER')
        # No prior helper can hold this installation's lock now. Do not adopt
        # any Room/container state here; canonical recovery remains separate.
        endpoint.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owned = None
    try:
        listener.bind(str(endpoint))
        node = endpoint.lstat(); owned = (node.st_dev,node.st_ino)
        # Root directory mode0700 protects endpoint; no global umask change.
        require(stat.S_ISSOCK(node.st_mode) and node.st_uid == os.geteuid(), 'LOCAL_SOCKET_OWNER')
        listener.listen(8);listener.settimeout(.25)
        while not stopped():
            try: channel,_ = listener.accept()
            except socket.timeout: continue
            with channel:
                channel.settimeout(5)
                try:
                    peer_owner(channel, os.geteuid())
                    raw = channel.recv(MAX_REQUEST+1)
                    response = controller.handle(raw)
                    encoded = canonical({'outcome':'observed','result':response})
                except Exception as error:
                    encoded = canonical({'outcome':'unknown', 'error':getattr(error,'code','LOCAL_OPERATION_FAILED')})
                if len(encoded) > MAX_RESPONSE:
                    encoded = canonical({'outcome':'unknown','error':'LOCAL_RESPONSE_LIMIT'})
                try: channel.sendall(encoded)
                except OSError:
                    # The effect may already be committed. A disconnected
                    # caller cannot terminate ownership of this or other Rooms;
                    # its next explicit status request reconciles the outcome.
                    pass
    finally:
        listener.close()
        if owned is not None:
            try:
                node = endpoint.lstat()
                if (node.st_dev,node.st_ino) == owned and stat.S_ISSOCK(node.st_mode): endpoint.unlink()
            except FileNotFoundError: pass


def request(installation, action, room_id):
    installation._safe_root()
    endpoint = installation.root/'operator.sock'
    node = endpoint.lstat()
    require(stat.S_ISSOCK(node.st_mode) and node.st_uid == os.geteuid(), 'LOCAL_SOCKET_OWNER')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(180)
        channel.connect(str(endpoint))
        peer_owner(channel, os.geteuid())
        channel.sendall(canonical({'action':action,'room_id':room_id}))
        raw = channel.recv(MAX_RESPONSE+1)
        require(0 < len(raw) <= MAX_RESPONSE, 'LOCAL_RESPONSE_LIMIT')
        return document(raw)
