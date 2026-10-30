"""T40 trusted Deployment composition of the external Library service.

The Deployment owns one Library singleton for its whole host lifetime, not one
per Room: the canonical target, its host-local working clone, credential
references, the model runner, qualification evidence, Room reference mounts and
backup remain external operator configuration. This owner only validates and
wires those values. It provisions no service, credential, mount or network
route, and adds no host/LAN or proxy exemption.

Room Stop/Destroy is unbinding the Project projection, never deleting canonical
content or ending the service; a later bind republishes the current coherent
generation. Configuration is validated before any clone work, and the existing
library lease refuses a second instance at that same point.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
import os
import stat
import threading
import time

from . import library, library_controls
from .ledger import RoomLedger
from .library_attempts import Attempts
from .library_enqueue import EnqueueEndpoint
from .library_git import LibraryGit
from .library_hub import DrainReports, LibraryHub
from .library_projection import ProjectProjection
from .library_service import Project, Service


def fail(code):
    raise library.LibraryError(code, 'deployment')


def _directory(path, code):
    try:
        node = path.lstat()
    except OSError:
        fail(code)
    if (not path.is_absolute() or path.resolve() != path or not stat.S_ISDIR(node.st_mode)
            or node.st_uid != os.geteuid() or node.st_mode & 0o022):
        fail(code)
    return path


@dataclass(frozen=True)
class _Room:
    room: str
    project: dict
    source_identity: str
    binding: dict
    scope: library.LibraryScope
    runner: object
    context: object


@dataclass
class _Bound:
    item: _Room
    projection: ProjectProjection


class DeploymentLibrary:
    """One Deployment's Library composition; trusted host construction only.

    ``settings`` is the external authority document (canonical target/branch,
    credential/model references, limits). ``credentials`` maps those references
    to Git transport environments; service code never reads a secret value.
    ``rooms`` maps each approved Room to its configured Project plus immutable
    source identity. ``scope_for``, ``runner_for``, ``ledger_for`` and
    ``qualification`` are trusted external owners (live authority, model
    dispatch, the Room Hub store, and target qualification evidence).
    ``ledger_for`` must open its own connection in the calling process: report
    ingress runs inside the existing bounded report worker.
    ``operator`` enables the independent host-local human path when supplied.
    """

    def __init__(self, state_root, *, deployment_id, settings, credentials, rooms,
                 scope_for, runner_for, ledger_for, authenticate, qualification=None,
                 operator=None, egress_approvals=(), audit=None, publisher_factory=LibraryGit,
                 now=lambda: datetime.now(timezone.utc)):
        library._token(deployment_id, 'deployment_id')
        if type(credentials) is not dict or type(rooms) is not dict:
            fail('DEPLOYMENT_DEPENDENCY_REQUIRED')
        for name, value in (('scope_for', scope_for), ('runner_for', runner_for),
                            ('ledger_for', ledger_for), ('authenticate', authenticate),
                            ('qualification', qualification), ('operator', operator)):
            if value is not None and not callable(value):
                fail('DEPLOYMENT_AUTHENTICATION_REQUIRED' if name == 'authenticate'
                     else 'DEPLOYMENT_DEPENDENCY_REQUIRED')
        if not callable(publisher_factory) or not callable(now):
            fail('DEPLOYMENT_DEPENDENCY_REQUIRED')
        self.deployment_id = deployment_id
        self.state_root = Path(state_root)
        # Trusted host may hand over the admitted value or the external document.
        self.settings = (library.admit_settings_value(settings)
                         if type(settings) is dict and 'settings_id' in settings
                         else library.admit_settings(StringIO(json.dumps(settings)),
                                                     egress_approvals=egress_approvals))
        self.credentials, self.rooms_inventory = credentials, rooms
        self.scope_for, self.runner_for, self.ledger_for = scope_for, runner_for, ledger_for
        self.authenticate, self.qualification, self.operator = authenticate, qualification, operator
        self.audit, self.publisher_factory, self.now = audit, publisher_factory, now
        self.failure = None
        self._started = False
        self._lock = threading.RLock()
        self._stopping = threading.Event()
        self._rooms, self._bound, self._hubs = {}, {}, {}

    # --- admission: no clone or other external effect ----------------------

    def _state(self):
        root = self.state_root
        if not library._absolute(str(root)):
            fail('INVALID_DEPLOYMENT_STATE')
        _directory(root if os.path.lexists(root) else root.parent, 'INVALID_DEPLOYMENT_STATE')
        return root / 'library'

    def _credential(self):
        reference = self.settings['repository']['credential_ref']
        environment = self.credentials.get(reference)
        if type(environment) is not dict:
            fail('CREDENTIAL_REFERENCE_UNAVAILABLE')
        return dict(environment)

    def _qualify(self):
        if self.qualification is None or self.qualification(self.settings) is not True:
            fail('TARGET_NOT_QUALIFIED')

    def _inventory(self):
        if not 1 <= len(self.rooms_inventory) <= 256:
            fail('INVALID_DEPLOYMENT_ROOMS')
        state = self._state()
        inventory, identities, projects, references = [], set(), set(), []
        for room, entry in sorted(self.rooms_inventory.items()):
            library._identifier(room, 'room_id')
            if type(entry) is not dict or set(entry) != {'project', 'source_identity'}:
                fail('INVALID_DEPLOYMENT_ROOMS')
            binding = library.project_binding(entry['project'], source_identity=entry['source_identity'])
            if (binding['project_identity'] in identities
                    or binding['project_id'] in projects):
                fail('CONFLICTING_PROJECT')
            identities.add(binding['project_identity'])
            projects.add(binding['project_id'])
            reference = Path(binding['reference_root']).parent
            _directory(reference, 'UNSAFE_REFERENCE_ROOT')
            if state == reference or state in reference.parents or reference in state.parents:
                fail('INVALID_DEPLOYMENT_STATE')
            for other in references:
                if (other == reference or other in reference.parents or reference in other.parents):
                    fail('CONFLICTING_PROJECT')
            references.append(reference)
            scope = self.scope_for(binding)
            if (type(scope) is not library.LibraryScope
                    or scope.canonical() != dict(
                        scope.canonical(), **{key: binding[key] for key in
                        ('project_id', 'project_identity', 'project_path', 'reference_root')})):
                fail('INVALID_PROJECT_BINDING')
            runner, context = self._runner(scope)
            inventory.append(_Room(room, dict(entry['project']), entry['source_identity'],
                                   binding, scope, runner, context))
        return inventory

    def _runner(self, scope):
        value = self.runner_for(scope)
        runner, context = ((value.runner, value.context) if type(value) is Project
                           else value if type(value) is tuple and len(value) == 2 else (None, None))
        if type(runner) is not Attempts or not callable(context):
            fail('SCHEDULER_DEPENDENCY_REQUIRED')
        current, settings = runner.assembler._scope(), runner.assembler._settings()
        if (type(current) is not library.LibraryScope or current.canonical() != scope.canonical()
                or settings['repository']['target'] != self.settings['repository']['target']
                or settings['repository']['branch'] != self.settings['repository']['branch']):
            fail('SCHEDULER_TARGET_MISMATCH')
        return runner, context

    # --- lifetime ----------------------------------------------------------

    def start(self):
        with self._lock:
            if self._started:
                fail('DEPLOYMENT_ALREADY_STARTED')
            self._stopping.clear()
            self.failure = None
            service_root = self._state()
            environment = self._credential()
            self._qualify()
            self._publisher = self.publisher_factory(
                service_root, records_path=service_root / 'records.db',
                deployment_id=self.deployment_id, target=self.settings['repository']['target'],
                branch=self.settings['repository']['branch'], environment=environment,
                audit=self.audit)
            inventory = self._inventory()
            self._rooms = {item.room: item for item in inventory}
            self._service = Service(self._publisher, lambda _publisher: list(self._projects()),
                                    transport=self._transport, room_for=self._room_for, now=self.now)
            try:
                # Service startup takes the lease before any clone work; a second
                # instance is refused there, not after registration or projection.
                self._service.startup()
                for item in inventory:
                    self._bind(item)
                if self.operator is not None:
                    self._serve_operator(service_root)
            except BaseException:
                self._abandon()
                raise
            self._started = True
            self._thread = threading.Thread(target=self._run, name='library-service', daemon=True)
            self._thread.start()
            return self

    def _projects(self):
        return tuple(Project(item.scope, item.runner, item.context) for item in self._rooms.values())

    def _room_for(self, scope):
        for item in self._rooms.values():
            if item.scope.project_identity == scope.project_identity:
                return item.room
        fail('INVALID_PROJECT_BINDING')

    def _run(self):
        while not self._stopping.is_set():
            try:
                self._service.tick()
            except library.LibraryError as error:
                if error.code == 'SERVICE_BUSY':
                    self._stopping.wait(0.05)
                    continue
                self.failure = error.code
                self._stopping.set()
                return
            except BaseException:
                self.failure = 'DEPLOYMENT_SERVICE_FAILED'
                self._stopping.set()
                return
            self._stopping.wait(0.1)

    def _abandon(self):
        self._stopping.set()
        for bound in list(self._bound.values()):
            bound.projection.close()
        self._bound.clear()
        operator = getattr(self, '_operator_thread', None)
        if operator is not None:
            operator.join(timeout=2)
        try:
            self._service.shutdown()
        finally:
            self._publisher.close()

    def _serve_operator(self, service_root):
        root = service_root / 'operator'
        try:
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
        except FileExistsError:
            pass
        _directory(root, 'LOCAL_CONTROL_ROOT_UNSAFE')
        endpoint = root / 'library-operator.sock'
        if os.path.lexists(endpoint):
            # The service lease above already excludes a live sibling owner.
            node = endpoint.lstat()
            if stat.S_ISSOCK(node.st_mode) and node.st_uid == os.geteuid():
                endpoint.unlink()
        controls = library_controls.Controls(self._service)
        self._operator_thread = threading.Thread(
            target=library_controls.serve, name='library-operator', daemon=True,
            args=(root, controls), kwargs={'authenticate': self.operator,
                                          'stopped': self._stopping.is_set})
        self._operator_thread.start()
        deadline = time.monotonic() + 5
        while not endpoint.exists():
            if not self._operator_thread.is_alive() or time.monotonic() >= deadline:
                fail('LOCAL_CONTROL_UNAVAILABLE')
            time.sleep(0.02)

    # --- Room binding ------------------------------------------------------

    def _bind(self, item):
        if item.room in self._bound:
            fail('ROOM_ALREADY_BOUND')
        projection = ProjectProjection(
            self._publisher, item.scope, self.settings,
            current_scope=lambda binding=item.binding: self._fresh(binding),
            clock=lambda: self.now().isoformat())
        try:
            projection.start()
        except BaseException:
            projection.close()
            raise
        self._bound[item.room] = _Bound(item, projection)

    def _fresh(self, binding):
        scope = self.scope_for(binding)
        if type(scope) is not library.LibraryScope:
            fail('INVALID_PROJECT_BINDING')
        return scope

    def start_room(self, room):
        """Bind one approved Room; the singleton and other Rooms keep running."""
        with self._lock:
            self._require()
            item = self._rooms.get(room)
            if item is None:
                fail('INVALID_PROJECT_BINDING')
            self._bind(item)
        return self.wait_idle(room)

    def stop_room(self, room):
        """Room Stop/Destroy: release its projection, never canonical data."""
        with self._lock:
            self._require()
            bound = self._bound.pop(room, None)
            self._hubs.pop(room, None)
            if bound is None:
                return False
            bound.projection.close()
            return True

    def wait_idle(self, room, timeout=5):
        bound = self._bound.get(room)
        if bound is None:
            fail('ROOM_NOT_BOUND')
        return bound.projection.wait_idle(timeout)

    def read(self, room):
        """One coherent pinned public generation for a bound Room."""
        bound = self._bound.get(room)
        if bound is None:
            fail('ROOM_NOT_BOUND')
        return bound.projection.read()

    def _require(self):
        if not self._started:
            fail('DEPLOYMENT_NOT_STARTED')

    # --- authenticated endpoints ------------------------------------------

    def hub(self, room, clock=None):
        """The Room's one authenticated enqueue endpoint; payloads bind no Room/Project."""
        with self._lock:
            self._require()
            bound = self._bound.get(room)
            if bound is None:
                fail('ROOM_NOT_BOUND')
            if room in self._hubs:
                fail('ROOM_HUB_ALREADY_ATTACHED')
            endpoint = EnqueueEndpoint(self._publisher, settings=lambda: self.settings,
                                       projection=bound.projection)
            ledger = self.ledger_for(room)
            hub = LibraryHub(ledger, room_id=room, project=bound.item.project,
                             source_identity=bound.item.source_identity, contact=endpoint.contact,
                             clock=clock or (lambda: self.now().isoformat()))
            self._hubs[room] = hub
            return hub

    def _transport(self, report):
        """Authenticated service-to-Room ingress; a Room without a Hub stays replayable."""
        room = report.get('room_id') if type(report) is dict else None
        item = self._rooms.get(room)
        if item is None:
            return False
        ledger = self.ledger_for(room)
        if type(ledger) is not RoomLedger or ledger.room_id != room:
            return False
        try:
            return DrainReports(ledger, room_id=room, project_identity=item.scope.project_identity,
                                authenticate=self.authenticate).receive(report) is True
        except Exception:
            return False
        finally:
            ledger.close()

    # --- observation and shutdown -----------------------------------------

    @property
    def publisher(self):
        return self._publisher

    @property
    def service(self):
        return self._service

    @property
    def rooms(self):
        return tuple(sorted(self._rooms))

    @property
    def running(self):
        return self._started and not self._stopping.is_set() and self.failure is None

    def stop(self):
        """Bounded graceful stop; a live attempt beyond its bound keeps the lease."""
        with self._lock:
            self._require()
            self._stopping.set()
            thread = getattr(self, '_thread', None)
        if thread is not None:
            thread.join(timeout=10)
        for room in list(self._bound):
            self.stop_room(room)
        operator = getattr(self, '_operator_thread', None)
        if operator is not None:
            operator.join(timeout=5)
        self._service.shutdown()
        with self._lock:
            self._started = False
        return True
