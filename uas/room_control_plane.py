"""Persistent Room control-plane ownership, outside the Workstation.

Owns already-started *real* Hub/Forge/Git services. It never accepts a client PID,
launch recipe, callback revoker, or an inferred service identity. The trusted
launcher supplies SCM_PIDFD-authenticated service handles and exact endpoint
leases. Stop retains these processes; Destroy durably fences them before any
Workstation cleanup. This module does not grant production launch admission.
"""
from dataclasses import dataclass
import json
import hashlib
from copy import deepcopy, copy
import os
from pathlib import Path
import select
import signal
import socket
import stat
import uuid

from .kernel_origin import HeldOrigin, Record, OriginDenied, _identity, alive
from .lifecycle import LifecycleError, Supervisor, _canonical, _unique_object
from .workstation_exec import EndpointLease, ExecUnavailable

SERVICES = frozenset({'hub', 'forge', 'git'})


@dataclass(frozen=True)
class ServiceLease:
    name: str
    origin: HeldOrigin
    channel: socket.socket
    endpoints: tuple[EndpointLease, ...] = ()

    def document(self):
        if (self.name not in SERVICES or type(self.origin) is not HeldOrigin
                or type(self.channel) is not socket.socket
                or self.channel.family != socket.AF_UNIX
                or self.channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                or type(self.endpoints) is not tuple or len(self.endpoints) > 8
                or any(type(endpoint) is not EndpointLease for endpoint in self.endpoints)):
            raise LifecycleError('CONTROL_PLANE_BINDING_INVALID')
        if self.origin.revoked or not alive(self.origin.pidfd):
            raise LifecycleError('CONTROL_PLANE_SERVICE_NOT_CURRENT')
        if self.origin.credentials[1] <= 0 or self.origin.credentials[2] <= 0:
            raise LifecycleError('CONTROL_PLANE_PRIVILEGED_SERVICE')
        if _identity(self.origin.pidfd) != self.origin.identity:
            raise LifecycleError('CONTROL_PLANE_SERVICE_REPLACED')
        endpoints = []
        for endpoint in self.endpoints:
            endpoint.require()
            endpoints.append({'path': str(endpoint.path), 'owner': endpoint.owner,
                              'group': endpoint.group, 'identity': list(endpoint.expected)})
        return {'identity': list(self.origin.identity), 'uid': self.origin.credentials[1],
                'gid': self.origin.credentials[2], 'endpoints': endpoints, 'exited': False, 'revoked': False}


class RoomControlPlane:
    """One Supervisor-owned, lifecycle-locked service set for one Room instance.

    A reopened owner must reauthenticate the same held kernel tasks. Missing
    handles are unknown, not proof of exit; they block cleanup. No PID scan or
    numeric-PID restoration exists. The launcher must retain/recover its exact
    authenticated channels, or supply independently verified service absence.
    """
    def __init__(self, supervisor):
        if type(supervisor) is not Supervisor:
            raise LifecycleError('CONTROL_PLANE_OWNER_INVALID')
        if supervisor._control_plane is not None:
            raise LifecycleError('CONTROL_PLANE_OWNER_EXISTS')
        self.supervisor = supervisor
        self.services = {}
        self._clients = {}
        self._manager_worker = None
        self.leftovers = []
        with supervisor._locked():
            state = supervisor._read()
            if state is None or state['phase'] == 'destroyed':
                raise LifecycleError('ROOM_ABSENT')
            self.instance = state['instance_id']
            self.directory = supervisor._owned_directory(state)
            self.path = self.directory / 'control-plane.json'
            node = self.directory.lstat()
            marker = self.directory / 'owner.json'
            if (self.directory.is_symlink() or not stat.S_ISDIR(node.st_mode)
                    or node.st_uid != os.getuid() or node.st_mode & 0o022
                    or marker.is_symlink() or not marker.is_file()
                    or json.loads(marker.read_text()) != {'room_id':supervisor.room_id,'instance_id':self.instance}):
                raise LifecycleError('OWNERSHIP_CONFLICT')
            self.document = self._read()
            self._saved = deepcopy(self.document)
            if self.document is None:
                if state.get('control_plane_required'):
                    raise LifecycleError('CONTROL_PLANE_STORE_MISSING')
                self.document = {'version': 1, 'room_id': supervisor.room_id,
                    'instance_id': self.instance, 'stream_id': uuid.uuid4().hex,
                    'phase': 'registering', 'services': {}}
                self._save()
            if not state.get('control_plane_required'):
                state['control_plane_required'] = True
                supervisor._save(state)  # Requirement is durable before any service attaches.
        supervisor._control_plane = self

    def _read(self):
        try:
            if not os.path.lexists(self.path):
                return None
            node = self.path.lstat()
            if (not stat.S_ISREG(node.st_mode) or stat.S_IMODE(node.st_mode) != 0o600
                    or node.st_uid != os.getuid() or node.st_size > 65536):
                raise ValueError()
            value = json.loads(self.path.read_text(), object_pairs_hook=_unique_object)
            if (type(value) is not dict or not {'version','room_id','instance_id','stream_id','phase','services'} <= value.keys()
                    or value.keys() - {'version','room_id','instance_id','stream_id','phase','services','manager'}
                    or type(value['version']) is not int or value['version'] != 1
                    or value['room_id'] != self.supervisor.room_id or value['instance_id'] != self.instance
                    or type(value['stream_id']) is not str or len(value['stream_id']) != 32
                    or any(c not in '0123456789abcdef' for c in value['stream_id'])
                    or value['phase'] not in {'registering','ready','revoking','revoked'}
                    or type(value['services']) is not dict or value['services'].keys() - SERVICES):
                raise ValueError()
            for service in value['services'].values():
                if (type(service) is not dict or set(service) != {'identity','uid','gid','endpoints','exited','revoked'}
                        or type(service['identity']) is not list or len(service['identity']) != 2
                        or any(type(n) is not int or n < 0 for n in service['identity'])
                        or any(type(service[k]) is not int or service[k] <= 0 for k in ('uid','gid'))
                        or type(service['exited']) is not bool or type(service['revoked']) is not bool or type(service['endpoints']) is not list
                        or len(service['endpoints']) > 8):
                    raise ValueError()
                for endpoint in service['endpoints']:
                    if (type(endpoint) is not dict or set(endpoint) != {'path','owner','group','identity'}
                            or type(endpoint['path']) is not str or len(endpoint['path']) > 4096
                            or not Path(endpoint['path']).is_absolute()
                            or self.directory not in Path(endpoint['path']).parents
                            or any(type(endpoint[k]) is not int or endpoint[k] < 0 for k in ('owner','group'))
                            or type(endpoint['identity']) is not list or len(endpoint['identity']) != 4
                            or any(type(n) is not int or n < 0 for n in endpoint['identity'])):
                        raise ValueError()
            if value['phase'] in {'ready','revoked'} and set(value['services']) != SERVICES:
                raise ValueError()
            if value['phase'] == 'revoked' and not all(s['revoked'] for s in value['services'].values()):
                raise ValueError()
            if 'manager' in value:
                from .manager_stream import RoomIdentity
                manager = value['manager']
                if (type(manager) is not dict or set(manager) != {'worker_id','identity','terminated'}
                        or type(manager['worker_id']) is not str or len(manager['worker_id']) != 32
                        or any(c not in '0123456789abcdef' for c in manager['worker_id'])
                        or type(manager['identity']) is not dict
                        or set(manager['identity']) != {'deployment_id','room_id','stream_id'}
                        or RoomIdentity(**manager['identity']).document() != manager['identity']
                        or manager['identity']['room_id'] != self.supervisor.room_id
                        or manager['identity']['stream_id'] != value['stream_id']
                        or type(manager['terminated']) is not bool
                        or (value['phase'] == 'revoked' and not manager['terminated'])):
                    raise ValueError()
            if value['phase'] == 'ready' and any(s['exited'] or s['revoked'] for s in value['services'].values()):
                raise ValueError()
            if value['services'].keys() == SERVICES:
                if any(value['services'][name]['uid'] == value['services']['hub']['uid'] for name in ('git','forge')):
                    raise ValueError()
            if any(s['revoked'] and not s['exited'] for s in value['services'].values()):
                raise ValueError()
            return value
        except (ValueError, OSError, KeyError, TypeError):
            raise LifecycleError('CONTROL_PLANE_STORE_INVALID') from None

    def _assert_current(self):
        if self._read() != self._saved:
            raise LifecycleError('CONTROL_PLANE_OWNER_STALE')

    def _save(self):
        self._assert_current()
        path = self.directory / ('.control-plane-' + uuid.uuid4().hex)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w') as output:
                output.write(_canonical(self.document)); output.flush(); os.fsync(output.fileno())
            os.replace(path, self.path)
            self.supervisor._sync_directory(self.directory)
            self._saved = deepcopy(self.document)
        finally:
            path.unlink(missing_ok=True)

    def attach(self, service):
        """Attach before exposing service authority, using exact startup proof."""
        if type(service) is not ServiceLease:
            raise LifecycleError('CONTROL_PLANE_BINDING_INVALID')
        with self.supervisor._locked():
            state = self.supervisor._read()
            if (state['instance_id'] != self.instance or state['desired'] == 'destroyed'
                    or self.document['phase'] in {'revoking','revoked'}):
                raise LifecycleError('CONTROL_PLANE_FENCED')
            document = service.document()
            previous = self.document['services'].get(service.name)
            if previous is not None and previous != document:
                raise LifecycleError('CONTROL_PLANE_OWNERSHIP_CONFLICT')
            if service.name in self.services and self.services[service.name] is not service:
                raise LifecycleError('CONTROL_PLANE_OWNER_EXISTS')
            # Endpoint deletion is only ever within the exact Room instance.
            for endpoint in service.endpoints:
                if self.directory not in endpoint.path.parents:
                    raise LifecycleError('CONTROL_PLANE_ENDPOINT_OUTSIDE_ROOM')
            candidate = deepcopy(self.document)
            candidate['services'][service.name] = document
            if candidate['services'].keys() == SERVICES:
                hub = candidate['services']['hub']
                if any(candidate['services'][name]['uid'] == hub['uid'] for name in ('forge','git')):
                    raise LifecycleError('CONTROL_PLANE_SERVICE_SEPARATION')
                candidate['phase'] = 'ready'
            self.document = candidate
            # Cleanup owns its own held kernel object. A client losing a reply
            # may close its handle without discarding lifecycle exit proof.
            record = Record(b'', service.origin.credentials, os.dup(service.origin.pidfd))
            with record:
                held = HeldOrigin(record, receiver=service.origin.receiver)
            owned = ServiceLease(service.name, held, service.channel, service.endpoints)
            try:
                self._save()
            except BaseException:
                held.close()
                raise
            self.services[service.name] = owned

    def attach_hub(self, admission, *, endpoints):
        """Use the actual native Hub startup/client binding, never a PID."""
        from .room_hub import RoomHubClient
        if type(admission) is RoomHubClient:
            if admission.scope != {'room_id': self.supervisor.room_id, 'instance_id': self.instance} or admission.closed:
                raise LifecycleError('CONTROL_PLANE_HUB_BINDING_INVALID')
            return self.attach(ServiceLease('hub', admission.worker, admission.channel, endpoints))
        from .workstation_control import SupervisorAdmission
        if (type(admission) is not SupervisorAdmission
                or admission.seat.room_id != self.supervisor.room_id
                or admission.seat.room_instance != self.instance):
            raise LifecycleError('CONTROL_PLANE_HUB_BINDING_INVALID')
        self.attach(ServiceLease('hub', admission.hub_origin, admission.control, endpoints))

    def attach_forge(self, client, *, endpoints=()):
        from .forge_read_service import ReadBrokerClient
        if (type(client) is not ReadBrokerClient or client.supervisor is not self.supervisor
                or client.room_instance != self.instance or client.closed):
            raise LifecycleError('CONTROL_PLANE_FORGE_BINDING_INVALID')
        self.attach(ServiceLease('forge', client.worker, client.channel, endpoints))
        self._clients['forge'] = client

    def attach_git(self, client, *, endpoints):
        from .git_service import GitBrokerClient
        if (type(client) is not GitBrokerClient or client.closed
                or client.scope['room_id'] != self.supervisor.room_id
                or client.scope['room_instance'] != self.instance):
            raise LifecycleError('CONTROL_PLANE_GIT_BINDING_INVALID')
        self.attach(ServiceLease('git', client.worker, client.channel, endpoints))
        self._clients['git'] = client

    def attach_manager_worker(self, worker):
        """Start the actual #75 exporter on its own readonly source thread."""
        from .manager_host import RoomManagerWorker
        if type(worker) is not RoomManagerWorker:
            raise LifecycleError('CONTROL_PLANE_EXPORTER_INVALID')
        status = worker.status()
        identity = worker.identity.document()
        if (identity['room_id'] != self.supervisor.room_id
                or identity['stream_id'] != self.document['stream_id'] or status['phase'] != 'new'):
            raise LifecycleError('CONTROL_PLANE_EXPORTER_INVALID')
        with self.supervisor._locked():
            state = self.supervisor._read()
            self._assert_current()
            if state['desired'] == 'destroyed' or 'manager' in self.document:
                raise LifecycleError('CONTROL_PLANE_EXPORTER_EXISTS_OR_FENCED')
            self.require_ready_locked()
            self.document['manager'] = {'worker_id':status['worker_id'],'identity':identity,'terminated':False}
            self._save()  # Exact ownership precedes thread creation/network I/O.
            self._manager_worker = worker
        worker.start()  # Never construct readers or wait under the lifecycle lock.
        return worker.status()

    def recover_manager_worker(self, worker):
        from .manager_host import RoomManagerWorker
        if type(worker) is not RoomManagerWorker:
            raise LifecycleError('CONTROL_PLANE_EXPORTER_INVALID')
        with self.supervisor._locked():
            self._assert_current()
            expected = self.document.get('manager')
            status = worker.status()
            if (expected is None or expected['worker_id'] != status['worker_id']
                    or expected['identity'] != status['identity'] or status['phase'] == 'new'
                    or (expected['terminated'] and not status['terminated'])):
                raise LifecycleError('CONTROL_PLANE_EXPORTER_RECOVERY_UNVERIFIED')
            self._manager_worker = worker

    def _stop_exporter_locked(self):
        expected = self.document.get('manager')
        if expected is None or expected['terminated']:
            return True
        name = self.instance + ':manager:' + expected['worker_id']
        worker = self._manager_worker
        if worker is None:
            self.leftovers.append({'kind':'authority','name':name,'reason':'MANAGER_EXPORTER_OWNER_UNKNOWN'})
            return False
        worker.request_stop()  # Nonblocking; source capture may need our lock.
        if not worker.status()['terminated']:
            self.leftovers.append({'kind':'authority','name':name,'reason':'MANAGER_EXPORTER_STOP_PENDING'})
            return False
        expected['terminated'] = True
        self._save()
        return True

    def require_ready_locked(self):
        self._assert_current()
        if self.document['phase'] != 'ready' or self.services.keys() != SERVICES:
            raise LifecycleError('CONTROL_PLANE_NOT_READY')
        try:
            for name, lease in self.services.items():
                if lease.document() != self.document['services'][name]:
                    raise LifecycleError('CONTROL_PLANE_OWNERSHIP_CONFLICT')
        except (OriginDenied, ExecUnavailable, OSError) as error:
            raise LifecycleError('CONTROL_PLANE_NOT_READY') from error
        return True

    def status(self):
        with self.supervisor._locked():
            self._assert_current()
            result = {'room_id': self.supervisor.room_id, 'instance_id': self.instance,
                      'stream_id': self.document['stream_id'], 'phase': self.document['phase'], 'services': {}}
            for name, stored in self.document['services'].items():
                lease = self.services.get(name)
                known = lease is not None and lease.origin.pidfd >= 0
                result['services'][name] = {'revoked': stored['revoked'],
                    'running': alive(lease.origin.pidfd) if known else None}
            return result

    def recover(self, service, *, client=None):
        """Reattach a launcher-retained exact process handle during cleanup.

        Does not restore authority or adopt a PID. This permits recovery of an
        interrupted owner while its trusted launcher still holds kernel objects.
        """
        if type(service) is not ServiceLease or type(service.origin) is not HeldOrigin:
            raise LifecycleError('CONTROL_PLANE_BINDING_INVALID')
        if service.name in {'forge','git'}:
            from .forge_read_service import ReadBrokerClient
            from .git_service import GitBrokerClient
            expected = ReadBrokerClient if service.name == 'forge' else GitBrokerClient
            if (type(client) is not expected or client.channel is not service.channel
                    or client.worker.identity != service.origin.identity
                    or client.binding.room_id != self.supervisor.room_id
                    or (client.room_instance if service.name == 'forge' else client.scope['room_instance']) != self.instance):
                raise LifecycleError('CONTROL_PLANE_RECOVERY_CLIENT_INVALID')
        elif client is not None:
            raise LifecycleError('CONTROL_PLANE_RECOVERY_CLIENT_INVALID')
        with self.supervisor._locked():
            state = self.supervisor._read()
            self._assert_current()
            stored = self.document['services'].get(service.name)
            if (state['instance_id'] != self.instance or self.document['phase'] != 'revoking'
                    or stored is None or stored['revoked']
                    or list(_identity(service.origin.pidfd)) != stored['identity']
                    or service.origin.credentials[1:] != (stored['uid'], stored['gid'])):
                raise LifecycleError('CONTROL_PLANE_RECOVERY_UNVERIFIED')
            held = copy(service.origin)
            held.pidfd = os.dup(service.origin.pidfd)
            held.revoked = True
            self.services[service.name] = ServiceLease(service.name, held, service.channel, service.endpoints)
            if client is not None:
                self._clients[service.name] = client

    def _remove_endpoint(self, endpoint):
        path = Path(endpoint['path'])
        if self.directory not in path.parents or path.parent.resolve() != path.parent:
            raise OriginDenied('endpoint escaped owned Room')
        directory = path.parent.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or stat.S_IMODE(directory.st_mode) != 0o710
                or (directory.st_uid, directory.st_gid) != (endpoint['owner'], endpoint['group'])
                or [directory.st_dev, directory.st_ino] != endpoint['identity'][:2]):
            raise OriginDenied('endpoint parent ownership changed')
        if not os.path.lexists(path):
            return
        node = path.lstat()
        if (not stat.S_ISSOCK(node.st_mode) or stat.S_IMODE(node.st_mode) != 0o620
                or (node.st_uid, node.st_gid) != (endpoint['owner'], endpoint['group'])
                or [node.st_dev, node.st_ino] != endpoint['identity'][2:]):
            raise OriginDenied('endpoint ownership changed')
        path.unlink()
        self.supervisor._sync_directory(path.parent)
        if os.path.lexists(path):
            raise OriginDenied('endpoint removal unverified')

    def revoke_locked(self, state, scope):
        if state['instance_id'] != self.instance:
            return False
        if scope == 'participants':
            # Participant controller fences seats; persistent services stay alive.
            return self.require_ready_locked()
        if self.document['phase'] == 'revoked' and state['authority'] == 'all-revoked':
            return True  # Instance data may already be gone; finish tombstone.
        self.leftovers = []
        self.document['phase'] = 'revoking'; self._save()
        complete = self.document['services'].keys() == SERVICES
        if not self._stop_exporter_locked():
            complete = False
        for name, stored in self.document['services'].items():
            if stored['revoked']:
                continue
            lease = self.services.get(name)
            operation_lock = None
            if not stored['exited'] and name in {'forge','git'}:
                client = self._clients.get(name)
                if client is None:
                    complete = False
                    self.leftovers.append({'kind':'authority','name':self.instance + ':' + name,
                                           'reason':'SERVICE_OPERATION_UNKNOWN'})
                    continue
                operation_lock = client.lock if name == 'forge' else client._stream_lock
                if not operation_lock.acquire(blocking=False):
                    complete = False
                    self.leftovers.append({'kind':'authority','name':self.instance + ':' + name,
                                           'reason':'SERVICE_OPERATION_ACTIVE'})
                    continue
            try:
                if not stored['exited']:
                    if lease is None:
                        raise OriginDenied('service process state unknown')
                    origin = lease.origin
                    if origin.pidfd < 0 or list(_identity(origin.pidfd)) != stored['identity']:
                        raise OriginDenied('service identity unavailable')
                    origin.revoke()  # Local issuance fences before any external effect.
                    lease.channel.close()
                    if alive(origin.pidfd):
                        # A failed client may still have accepted provider work.
                        # Wait for its own bounded shutdown; never kill/certify
                        # the Broker while that outcome remains uncertain.
                        if name == 'hub' or not self._clients[name].closed:
                            try:
                                signal.pidfd_send_signal(origin.pidfd, signal.SIGTERM)
                            except ProcessLookupError:
                                pass  # Still verify the held kernel task has exited.
                        ready, _, _ = select.select([origin.pidfd], [], [], 1)
                        if not ready or alive(origin.pidfd):
                            raise OriginDenied('service exit unverified')
                    # Preserve exit proof BEFORE endpoint removal. A crash after
                    # this point can retry exact endpoint cleanup without a PID.
                    stored['exited'] = True
                    self._save()
                    origin.close()  # Durable exit proof replaces this kernel handle.
                endpoints_complete = True
                for endpoint in stored['endpoints']:
                    try:
                        self._remove_endpoint(endpoint)
                    except (OSError, ValueError, OriginDenied, ExecUnavailable):
                        complete = endpoints_complete = False
                        path = endpoint['path']
                        exact_name = path if len(path) <= 256 else 'endpoint-sha256:' + hashlib.sha256(path.encode()).hexdigest()
                        self.leftovers.append({'kind':'authority','name':exact_name,'reason':'ENDPOINT_CLEANUP_UNVERIFIED'})
                if not endpoints_complete:
                    continue
                stored['revoked'] = True
                self._save()
            except (OSError, ValueError, OriginDenied, ExecUnavailable):
                complete = False
                self.leftovers.append({'kind':'authority', 'name':self.instance + ':' + name,
                    'reason':'ENDPOINT_CLEANUP_UNVERIFIED' if stored['exited'] else 'SERVICE_EXIT_UNVERIFIED'})
            finally:
                if operation_lock is not None:
                    operation_lock.release()
        if not self.document['services'].keys() == SERVICES:
            self.leftovers.extend({'kind':'authority','name':self.instance + ':' + name,
                                   'reason':'SERVICE_OWNERSHIP_UNREGISTERED'}
                                  for name in sorted(SERVICES-self.document['services'].keys()))
        if complete:
            self.document['phase'] = 'revoked'; self._save()
        return complete
