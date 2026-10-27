"""Linux same-namespace Participant authority fixture, not a Workstation launcher.

The trusted supervisor owns both this object and its private control store. Each
record uses kernel SCM_CREDENTIALS plus a held pidfd, never a transferable bearer
badge, claimed PID, UID alone, or connection-time SO_PEERCRED. No Forge/provider
credential is loaded; FixtureCredentials contains synthetic references only.
"""
from dataclasses import asdict, dataclass
import array
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import uuid

from .ledger import LedgerError, Origin, _json, _token
from .forge_wire import request_json, MAX_REQUEST
from .lifecycle import _canonical, _unique_object
from .peer import Readiness

MAX_PACKET = 65_536
MAX_SEATS = 32
MAX_EPOCH = 2**53 - 1
_UCRED = struct.Struct("3i")


@dataclass(frozen=True)
class FixtureSeat:
    participant_id: str
    actor_id: str
    profile_id: str
    capabilities: tuple[str, ...]
    provider_host: str = "forge.fixture.invalid"
    required_credentials: tuple[str, ...] = ()
    runtime: str = "fixture"
    arguments: tuple[str, ...] = ()

    def document(self):
        for value in (self.participant_id, self.actor_id, self.profile_id):
            _token(value)
        if self.runtime not in {"fixture", "pi-fixture"} or self.provider_host != "forge.fixture.invalid":
            raise LedgerError("FIXTURE_ONLY")
        for values in (self.capabilities, self.required_credentials, self.arguments):
            if type(values) is not tuple or len(values) > 32:
                raise LedgerError("INVALID_SEAT")
            for value in values:
                _token(value)
        if len(set(self.capabilities)) != len(self.capabilities):
            raise LedgerError("INVALID_SEAT")
        if set(self.required_credentials) - {"git", "forge"}:
            raise LedgerError("INVALID_SEAT")
        return json.loads(_json({**asdict(self), "capabilities": list(self.capabilities),
                                "required_credentials": list(self.required_credentials),
                                "arguments": list(self.arguments)}))


class FixtureCredentials:
    """Exact (Actor, provider-host, kind) -> synthetic reference; no fallback.

    Availability is fixture input, not a real credential validation assertion.
    No secret values, environment lookup, account contact, or provider API exists.
    """
    def __init__(self, bindings=(), available=()):
        self._bindings = {}
        self._available = set()
        for actor, host, kind, reference in bindings:
            _token(actor)
            if host != "forge.fixture.invalid" or kind not in {"git", "forge"}:
                raise LedgerError("FIXTURE_ONLY")
            self._reference(reference)
            key = (actor, host, kind)
            if key in self._bindings:
                raise LedgerError("DUPLICATE_CREDENTIAL_BINDING")
            self._bindings[key] = reference
        for reference in available:
            self.set_available(reference, True)

    @staticmethod
    def _reference(reference):
        _token(reference)
        if not reference.startswith("fixture-"):
            raise LedgerError("FIXTURE_ONLY")

    def set_available(self, reference, available):
        self._reference(reference)
        if type(available) is not bool or reference not in self._bindings.values():
            raise LedgerError("UNKNOWN_CREDENTIAL_REFERENCE")
        (self._available.add if available else self._available.discard)(reference)

    def missing(self, seat):
        return [kind for kind in seat["required_credentials"]
                if self._bindings.get((seat["actor_id"], seat["provider_host"], kind)) not in self._available]


@dataclass(frozen=True)
class Badge:
    room_id: str
    room_instance: str
    controller_id: str
    actor_id: str
    participant_id: str
    profile_id: str
    capabilities: tuple[str, ...]
    incarnation_id: str
    epoch: int

    def origin(self):
        # Bind the complete effective security context in ledger idempotency.
        import hashlib
        version = "seat-" + hashlib.sha256(_canonical(asdict(self)).encode()).hexdigest()
        return Origin(self.actor_id, self.participant_id, self.incarnation_id, version, self.capabilities)


@dataclass(eq=False)
class ProcessHandle:
    """Trusted supervisor handle; never accepted from an untrusted request."""
    badge: Badge
    process: subprocess.Popen
    channel: socket.socket
    pidfd: int
    connection: object
    runtime_directory: Path
    protocol: str = "fixture"
    managed_receiver: object = None


class FixtureParticipantController:
    def __init__(self, supervisor, hub, credentials):
        if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
            raise LedgerError("PROCESS_BINDING_UNAVAILABLE")
        if type(credentials) is not FixtureCredentials or hub.ledger.room_id != supervisor.room_id:
            raise LedgerError("ROOM_MISMATCH")
        # SCM_CREDENTIALS PID forgery requires privilege. This fixture launches
        # only an ordinary same-UID child, never a root/capability-bearing one.
        try:
            status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
            if os.getuid() == 0 or os.geteuid() != os.getuid() or int(status["CapEff"].strip(), 16):
                raise LedgerError("UNPRIVILEGED_FIXTURE_REQUIRED")
        except (OSError, ValueError, KeyError) as error:
            raise LedgerError("PROCESS_BINDING_UNAVAILABLE") from error
        self.supervisor, self.hub, self.credentials = supervisor, hub, credentials
        self.forge_broker = None
        self.read_service = None
        self.handles = {}
        self.fenced = set()
        self.store_failed = False
        self.controller_id = uuid.uuid4().hex
        with supervisor._locked():
            state = supervisor._read()
            supervisor._allowed("participant-controller", state)
            if not state or state["phase"] != "running":
                raise LedgerError("ROOM_NOT_RUNNING")
            self.instance = state["instance_id"]
            self.project_id = state["spec"]["project_id"]
            self.path = supervisor._owned_directory(state) / "participants.json"
            document = self._read(require_owner=False)
            if document is None:
                document = {"version": 1, "room_id": supervisor.room_id, "instance_id": self.instance,
                            "controller_id": self.controller_id, "seats": {}, "retired_pids": []}
            else:
                # Never reconstruct authority from persisted PID/UID. A new
                # owner fences every prior process, even if one is still alive.
                for seat in document["seats"].values():
                    if seat["pid"] is not None:
                        document["retired_pids"].append(seat["pid"])
                        seat["pid"] = None
                    if seat["status"] != "closed":
                        seat.update(status="revoked", epoch=min(MAX_EPOCH, seat["epoch"] + 1), reason="controller-replaced")
                document["retired_pids"] = sorted(set(document["retired_pids"]))
                if len(document["retired_pids"]) > MAX_SEATS:
                    raise LedgerError("RETIRED_PROCESSES_UNVERIFIED")
                document["controller_id"] = self.controller_id
            self._save(document)

    def _read(self, *, require_owner=True):
        if not self.path.exists():
            if require_owner:
                raise LedgerError("AUTHORITY_STORE_UNAVAILABLE")
            return None
        try:
            if self.path.is_symlink() or self.path.stat().st_size > 1_048_576:
                raise ValueError()
            document = json.loads(self.path.read_text(), object_pairs_hook=_unique_object)
            if (set(document) != {"version", "room_id", "instance_id", "controller_id", "seats", "retired_pids"}
                    or type(document["version"]) is not int or document["version"] != 1
                    or document["room_id"] != self.supervisor.room_id or document["instance_id"] != self.instance
                    or type(document["seats"]) is not dict or len(document["seats"]) > MAX_SEATS):
                raise ValueError()
            _token(document["controller_id"])
            if (type(document["retired_pids"]) is not list or len(document["retired_pids"]) > MAX_SEATS
                    or any(type(pid) is not int or pid < 1 for pid in document["retired_pids"])):
                raise ValueError()
            for participant, record in document["seats"].items():
                if set(record) != {"seat", "epoch", "incarnation_id", "status", "reason", "pid"}:
                    raise ValueError()
                seat = record["seat"]
                normalized = FixtureSeat(**{**seat, **{key: tuple(seat[key]) for key in
                                                     ("capabilities", "required_credentials", "arguments")}}).document()
                if normalized != seat or participant != seat["participant_id"]:
                    raise ValueError()
                if (type(record["epoch"]) is not int or not 1 <= record["epoch"] <= MAX_EPOCH
                        or record["status"] not in {"starting", "active", "revoked", "closed", "disabled", "exited"}):
                    raise ValueError()
                if record["pid"] is not None and (type(record["pid"]) is not int or record["pid"] < 1):
                    raise ValueError()
                _token(record["incarnation_id"])
                _token(record["reason"])
        except (OSError, ValueError, TypeError, KeyError, LedgerError, RecursionError) as error:
            raise LedgerError("INVALID_AUTHORITY_STORE") from error
        if require_owner and document["controller_id"] != self.controller_id:
            raise LedgerError("CONTROLLER_REPLACED")
        return document

    def _save(self, document):
        encoded = _canonical(document)
        if len(encoded.encode()) > 1_048_576:
            raise LedgerError("AUTHORITY_CAPACITY")
        temporary = self.path.with_name(".participants-" + uuid.uuid4().hex)
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            self.supervisor._sync_directory(self.path.parent)
        except OSError:
            # An uncertain manifest write is never renewed authority. Only an
            # explicit controller reconstruction can leave this failed state.
            self.store_failed = True
            raise
        finally:
            temporary.unlink(missing_ok=True)

    def _room(self, *, running=True):
        state = self.supervisor._read()
        if not state or state["instance_id"] != self.instance:
            raise LedgerError("ROOM_REPLACED")
        if running and (state["phase"] != "running" or state["desired"] != "running"):
            raise LedgerError("ROOM_NOT_RUNNING")
        return state

    def launch(self, seat, receiver):
        """Explicit start/restart of the fixed synthetic Runtime, never shell/argv execution."""
        if type(seat) is not FixtureSeat:
            raise LedgerError("INVALID_SEAT")
        definition = seat.document()
        if seat.runtime != "fixture":
            raise LedgerError("FIXTURE_ONLY")
        if self.store_failed:
            raise LedgerError("AUTHORITY_STORE_UNAVAILABLE")
        with self.supervisor._locked():
            state = self._room()
            self.supervisor._allowed("participant-start", state)
            document = self._read()
            previous = document["seats"].get(seat.participant_id)
            if previous and previous["seat"] != definition:
                raise LedgerError("SEAT_BINDING_CONFLICT")
            if previous and previous["status"] == "closed":
                raise LedgerError("PARTICIPANT_CLOSED")
            if previous and previous["epoch"] == MAX_EPOCH:
                raise LedgerError("AUTHORITY_EPOCH_EXHAUSTED")
            old = self.handles.get(seat.participant_id)
            if previous and previous["status"] == "active" and old and self._alive(old):
                raise LedgerError("ALREADY_RUNNING")
            if not previous and len(document["seats"]) >= MAX_SEATS:
                raise LedgerError("AUTHORITY_CAPACITY")
            scope = self.hub._state()["definition"]["participants"].get(seat.participant_id)
            if not scope or scope["actor_id"] != seat.actor_id:
                raise LedgerError("PEER_BINDING_CONFLICT")
            incarnation = "process-" + uuid.uuid4().hex
            epoch = previous["epoch"] + 1 if previous else 1
            record = {"seat": definition, "epoch": epoch, "incarnation_id": incarnation,
                      "status": "starting", "reason": "explicit-start", "pid": None}
            document["seats"][seat.participant_id] = record
            if self.credentials.missing(definition):
                record.update(status="disabled", reason="missing-credential")
            self._save(document)  # Fence old authority BEFORE any process effect.
            if old:
                self._dispose(old)
                self.handles.pop(seat.participant_id, None)
            if record["status"] == "disabled":
                raise LedgerError("MISSING_ACTOR_CREDENTIAL")
            hub_socket = child_socket = process = None
            pidfd = None
            runtime_directory = None
            try:
                hub_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                hub_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                hub_socket.settimeout(2)
                worker = Path(__file__).with_name("fixture_participant.py")
                runtime_directory = Path(tempfile.mkdtemp(prefix="uas-participant-runtime-"))
                process = subprocess.Popen([sys.executable, "-I", str(worker), str(child_socket.fileno()),
                                            *seat.arguments], pass_fds=(child_socket.fileno(),),
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                           cwd=runtime_directory, env={"LANG": "C.UTF-8"}, text=True, bufsize=1)
                # Unreaped child PID cannot be reused between spawn and pidfd_open.
                pidfd = os.pidfd_open(process.pid, 0)
                connection = self.hub.connect("attach-" + uuid.uuid4().hex, seat.participant_id,
                                              incarnation, receiver)
                badge = Badge(self.supervisor.room_id, self.instance, self.controller_id, seat.actor_id,
                              seat.participant_id, seat.profile_id, seat.capabilities, incarnation, epoch)
                handle = ProcessHandle(badge, process, hub_socket, pidfd, connection, runtime_directory)
                self.handles[seat.participant_id] = handle
                record.update(status="active", reason="launched", pid=process.pid)
                self._save(document)
                return handle
            except BaseException:
                self.fenced.add(incarnation)
                # Even failure of the compensating store write cannot bypass
                # cleanup or leave a live, authorized partially launched child.
                try:
                    record.update(status="revoked", reason="launch-failed", epoch=min(MAX_EPOCH, epoch + 1))
                    self._save(document)
                finally:
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=3)
                        process.stdin.close()
                        process.stdout.close()
                    if pidfd is not None:
                        os.close(pidfd)
                    if hub_socket is not None:
                        hub_socket.close()
                    self.handles.pop(seat.participant_id, None)
                    if runtime_directory is not None:
                        runtime_directory.rmdir()
                raise
            finally:
                if child_socket is not None:
                    child_socket.close()

    def launch_pi(self, seat, recipe):
        from .pi_fixture import FixturePiRecipe
        if type(recipe) is not FixturePiRecipe or type(seat) is not FixtureSeat:
            raise LedgerError('INVALID_SEAT')
        if self.hub.contexts.scope(seat.participant_id)['context_generation'] > 1:
            return self.restore_pi(seat, recipe)
        return self._launch_pi(seat, recipe)

    def _launch_pi(self, seat, recipe, *, reset=None, restoring=None):
        """Explicit fixed Pi fixture recipe, not a generic spawn/adopt API.

        The controller owns the sole child/pidfd/socket. Native attachment may
        wait on RPC, so it runs outside the lifecycle lock. Pending authority
        is never usable; Stop/revoke/replacement may cancel that handshake.
        """
        from .pi_fixture import FixturePiRecipe
        if type(seat) is not FixtureSeat or type(recipe) is not FixturePiRecipe:
            raise LedgerError("INVALID_SEAT")
        definition = seat.document()
        if seat.runtime != "pi-fixture" or seat.arguments:
            raise LedgerError("FIXTURE_ONLY")
        if self.store_failed:
            raise LedgerError("AUTHORITY_STORE_UNAVAILABLE")
        handle = None
        receiver = None
        hub_socket = child_socket = process = None
        pidfd = None
        runtime_directory = None
        incarnation = None
        try:
            with self.supervisor._locked():
                state = self._room()
                self.supervisor._allowed("participant-start", state)
                document = self._read()
                previous = document["seats"].get(seat.participant_id)
                if previous and previous["seat"] != definition:
                    raise LedgerError("SEAT_BINDING_CONFLICT")
                if previous and previous["status"] == "closed":
                    raise LedgerError("PARTICIPANT_CLOSED")
                if previous and previous["epoch"] == MAX_EPOCH:
                    raise LedgerError("AUTHORITY_EPOCH_EXHAUSTED")
                old = self.handles.get(seat.participant_id)
                if previous and previous["status"] == "active" and old and self._alive(old):
                    raise LedgerError("ALREADY_RUNNING")
                if not previous and len(document["seats"]) >= MAX_SEATS:
                    raise LedgerError("AUTHORITY_CAPACITY")
                scope = self.hub._state()["definition"]["participants"].get(seat.participant_id)
                if not scope or scope["actor_id"] != seat.actor_id:
                    raise LedgerError("PEER_BINDING_CONFLICT")
                expected_scope = (self.hub.contexts.pending_scope(reset['id']) if reset is not None
                                  else self.hub.contexts.scope(seat.participant_id))
                if recipe.scope != expected_scope:
                    raise LedgerError("PEER_BINDING_CONFLICT")
                if reset is None and not self.hub.contexts.permits(seat.participant_id,
                        expected_scope['context_generation'], expected_scope['run_id'], expected_scope['generation']):
                    raise LedgerError('CONTEXT_UNAVAILABLE')
                incarnation = "process-" + uuid.uuid4().hex
                epoch = previous["epoch"] + 1 if previous else 1
                record = {"seat": definition, "epoch": epoch, "incarnation_id": incarnation,
                          "status": "starting", "reason": "explicit-start", "pid": None}
                document["seats"][seat.participant_id] = record
                if self.credentials.missing(definition):
                    record.update(status="disabled", reason="missing-credential")
                self._save(document)
                if old:
                    self._dispose(old)
                    self.handles.pop(seat.participant_id, None)
                if record["status"] == "disabled":
                    raise LedgerError("MISSING_ACTOR_CREDENTIAL")
                badge = Badge(self.supervisor.room_id, self.instance, self.controller_id, seat.actor_id,
                              seat.participant_id, seat.profile_id, seat.capabilities, incarnation, epoch)
                hub_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                hub_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                hub_socket.settimeout(2)
                child_socket.setblocking(False)
                runtime_directory = Path(tempfile.mkdtemp(prefix="uas-participant-runtime-"))
                process = recipe.spawn(child_socket, runtime_directory)
                # Only the exact direct child is eligible; no native PID claim
                # or adoption by UID is accepted during receiver attachment.
                if not isinstance(process, subprocess.Popen):
                    raise LedgerError("INVALID_NATIVE_PROCESS")
                pidfd = os.pidfd_open(process.pid, 0)
                handle = ProcessHandle(badge, process, hub_socket, pidfd, None, runtime_directory, "pi")
                self.handles[seat.participant_id] = handle
                record["pid"] = process.pid
                self._save(document)  # Pending process identity before unlocking.
                child_socket.close()
                child_socket = None

            receiver = recipe.attach(process, badge)  # Native RPC, never under lock.
            if (getattr(receiver, "process", None) is not process
                    or getattr(receiver, "incarnation_id", None) != badge.incarnation_id
                    or getattr(receiver, "scope", None) != expected_scope):
                raise LedgerError("INVALID_NATIVE_RECEIVER")
            native_proof = receiver.prove_fresh_context(preceding_session=reset['preceding_session']) if reset else None
            if restoring is not None:
                if restoring['fresh']:
                    native_proof = receiver.prove_fresh_context(preceding_session=restoring['native']['session_id'])
                elif receiver.initial_state['session_id'] != restoring['native']['session_id']:
                    raise LedgerError('NATIVE_SESSION_MISMATCH')
            with self.supervisor._locked():
                state = self._room()
                self.supervisor._allowed("participant-start", state)
                document = self._read()
                current = document["seats"].get(seat.participant_id)
                if (self.store_failed or self.handles.get(seat.participant_id) is not handle
                        or incarnation in self.fenced or not current
                        or current["status"] != "starting" or current["epoch"] != epoch
                        or current["incarnation_id"] != incarnation or current["seat"] != definition):
                    raise LedgerError("AUTHORITY_REVOKED")
                if not self._alive(handle):
                    raise LedgerError("PROCESS_EXITED")
                if self.credentials.missing(definition):
                    self._fence(document, seat.participant_id, "disabled", "missing-credential")
                    raise LedgerError("MISSING_ACTOR_CREDENTIAL")
                handle.managed_receiver = receiver
                if restoring is not None and restoring['fresh']:
                    self._save_pi_checkpoint(seat.participant_id, recipe, restoring['reset_id'], native_proof)
                if reset is not None:
                    self._save_pi_checkpoint(seat.participant_id, recipe, reset['id'], native_proof)
                    self.hub.contexts.succeed_reset(reset['id'], reset['expected_generation'],
                        authorize=lambda: self._pending_pi_authority(handle, definition))
                handle.connection = self.hub.connect("attach-" + uuid.uuid4().hex, seat.participant_id,
                                                     incarnation, receiver,
                                                     context_generation=expected_scope['context_generation'])
                current.update(status="active", reason="launched")
                self._save(document)
                return handle
        except BaseException:
            if incarnation is not None:
                self.fenced.add(incarnation)
                # Never overwrite a concurrent close, replacement, new owner,
                # or destroyed Room. Cleanup remains independent of this write.
                try:
                    with self.supervisor._locked():
                        document = self._read()
                        current = document["seats"].get(seat.participant_id)
                        if (current and current["incarnation_id"] == incarnation
                                and current["status"] in {"starting", "active"}):
                            self._fence(document, seat.participant_id, "revoked", "launch-failed")
                except (LedgerError, OSError):
                    pass
            try:
                if handle is not None:
                    with self.supervisor._locked():
                        handle.managed_receiver = receiver
                        self._dispose(handle)
                elif process is not None and isinstance(process, subprocess.Popen):
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=3)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
            finally:
                with self.supervisor._locked():
                    if self.handles.get(seat.participant_id) is handle:
                        self.handles.pop(seat.participant_id, None)
                if handle is None:
                    if pidfd is not None:
                        os.close(pidfd)
                    if hub_socket is not None:
                        hub_socket.close()
                    if runtime_directory is not None:
                        self._remove_empty_runtime_directory(runtime_directory)
            raise
        finally:
            if child_socket is not None:
                child_socket.close()

    def _pending_pi_authority(self, handle, definition):
        """Pure transaction-time guard: no native RPC or nested ledger write."""
        self._room()
        current = self._read()['seats'].get(handle.badge.participant_id)
        if (self.store_failed or self.handles.get(handle.badge.participant_id) is not handle
                or handle.badge.incarnation_id in self.fenced or not current
                or current['status'] != 'starting' or current['epoch'] != handle.badge.epoch
                or current['incarnation_id'] != handle.badge.incarnation_id
                or current['seat'] != definition or self.credentials.missing(definition)
                or not self._alive(handle)):
            raise LedgerError('AUTHORITY_REVOKED')
        return True

    def _pi_checkpoint_path(self, participant):
        return self.path.with_name('pi-context-' + hashlib.sha256(participant.encode()).hexdigest() + '.json')

    def _save_pi_checkpoint(self, participant, recipe, reset_id, proof):
        """Private native handles never enter Hub state or process authority."""
        session = Path(proof['session_file']).resolve()
        if not session.is_relative_to(recipe.session_directory):
            raise LedgerError('NATIVE_SESSION_PATH_MISMATCH')
        path = self._pi_checkpoint_path(participant)
        value = {'version': 1, 'room_instance': self.instance, 'participant': participant,
                 'reset_id': reset_id, 'scope': recipe.scope, 'directory': str(recipe.directory),
                 'native': proof}
        encoded = _canonical(value)
        if len(encoded.encode()) > 8192:
            raise LedgerError('NATIVE_CHECKPOINT_CAPACITY')
        temporary = path.with_name('.pi-context-' + uuid.uuid4().hex)
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            self.supervisor._sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def restore_pi(self, seat, recipe):
        """Restore only this ledger-approved context, never an older generation.

        A reset may succeed before Pi first creates its session file. Fresh
        restart within that same unbound generation is safe only if the retained
        native intent journal proves zero handoffs. Unknown intents still hold.
        """
        from .pi_fixture import FixturePiRecipe
        if type(seat) is not FixtureSeat or type(recipe) is not FixturePiRecipe:
            raise LedgerError('INVALID_SEAT')
        with self.supervisor._locked():
            self.supervisor._allowed('participant-restore', self._room())
            scope = self.hub.contexts.scope(seat.participant_id)
            path = self._pi_checkpoint_path(seat.participant_id)
            try:
                if path.is_symlink() or path.stat().st_size > 8192:
                    raise ValueError()
                saved = json.loads(path.read_text(), object_pairs_hook=_unique_object)
                if (set(saved) != {'version', 'room_instance', 'participant', 'reset_id', 'scope', 'directory', 'native'}
                        or type(saved['version']) is not int or saved['version'] != 1 or saved['room_instance'] != self.instance
                        or saved['participant'] != seat.participant_id or _canonical(saved['scope']) != _canonical(scope)
                        or recipe.scope != scope or saved['directory'] != str(recipe.directory)
                        or self.hub.contexts.reset_status(saved['reset_id'])['status'] != 'SUCCEEDED'):
                    raise ValueError()
                native = saved['native']
                if (type(native) is not dict or set(native) != {'runtime_id', 'session_id', 'session_file', 'source'}
                        or any(type(value) is not str or not value for value in native.values())
                        or native['source'] != 'native-empty-session-and-no-pending-messages'):
                    raise ValueError()
                session = Path(native['session_file']).resolve()
                if not session.is_relative_to(recipe.session_directory):
                    raise ValueError()
                if recipe.session is not None and recipe.session != str(session):
                    raise ValueError()
                fresh = not session.exists()
                if fresh:
                    if self.hub.contexts._row(seat.participant_id)['bound_run'] is not None:
                        raise ValueError()
                    database = sqlite3.connect(recipe.journal.as_uri() + '?mode=ro', uri=True)
                    try:
                        binding = database.execute('SELECT scope FROM binding WHERE singleton=1').fetchone()
                        if not binding or json.loads(binding[0]) != scope or database.execute('SELECT count(*) FROM handoffs').fetchone()[0]:
                            raise ValueError()
                    finally:
                        database.close()
            except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
                raise LedgerError('NATIVE_CONTEXT_RESTORE_UNVERIFIED') from error
        selected = FixturePiRecipe(recipe.install, recipe.directory, scope=scope,
                                   session=None if fresh else str(session), timeout=recipe.timeout)
        return self._launch_pi(seat, selected, restoring={**saved, 'fresh': fresh})

    def reset_pi(self, operation_id, seat, recipe, *, expected_context_generation, target_run):
        """Trusted fixture reset of one seat, never participant-claimed completion.

        Request fencing is durable before process effects. Failed/unknown reset
        leaves both Runs undeliverable to this seat. Exact completed retry does
        not repeat native reset or advance the generation twice.
        """
        from .pi_fixture import FixturePiRecipe
        if type(seat) is not FixtureSeat or type(recipe) is not FixturePiRecipe or recipe.session is not None:
            raise LedgerError('INVALID_RESET_RECIPE')
        definition = seat.document()
        if seat.runtime != 'pi-fixture' or seat.arguments:
            raise LedgerError('INVALID_RESET_RECIPE')
        with self.supervisor._locked():
            self.supervisor._allowed('participant-reset', self._room())
            previous = self._read()['seats'].get(seat.participant_id)
            if previous and previous['seat'] != definition:
                raise LedgerError('SEAT_BINDING_CONFLICT')
            self.hub.contexts.request_reset(operation_id, seat.participant_id,
                                            expected_context_generation, target_run)
            status = self.hub.contexts.reset_status(operation_id)
            if status['status'] == 'SUCCEEDED':
                current = self.handles.get(seat.participant_id)
                if (current is not None and self._alive(current) and current.connection is not None
                        and self.hub._current(current.connection)
                        and current.connection.context_generation == expected_context_generation + 1):
                    self._authority(current, (current.process.pid, os.getuid(), os.getgid()))
                    return current
                raise LedgerError('RESET_SUCCEEDED_RESTORE_REQUIRED')
        try:
            expected = self.hub.contexts.pending_scope(operation_id)
            if recipe.scope != expected:
                raise LedgerError('PEER_BINDING_CONFLICT')
            with self.supervisor._locked():
                old = self.handles.get(seat.participant_id)
                preceding_session = (old.managed_receiver.initial_state['session_id']
                                     if old is not None and old.managed_receiver is not None else None)
                if old is not None:
                    document = self._read()
                    self._fence(document, seat.participant_id, 'revoked', 'context-reset')
                    self._dispose(old)
                    if self._alive(old) or old.process.poll() is None:
                        raise LedgerError('NATIVE_STOP_UNVERIFIED')
                # A reconstructed controller never adopts or kills an old PID.
                # Any still-live retired process conservatively blocks reset.
                for pid in self._read()['retired_pids']:
                    try:
                        descriptor = os.pidfd_open(pid, 0)
                    except ProcessLookupError:
                        continue
                    try:
                        if not select.select([descriptor], [], [], 0)[0]:
                            raise LedgerError('RETIRED_PROCESSES_UNVERIFIED')
                    finally:
                        os.close(descriptor)
            return self._launch_pi(seat, recipe, reset={'id': operation_id,
                'expected_generation': expected_context_generation, 'preceding_session': preceding_session})
        except BaseException:
            # Read after an uncertain success commit BEFORE any compensating
            # transition. A succeeded reset is never downgraded or reopened.
            try:
                status = self.hub.contexts.reset_status(operation_id)
                if status['status'] != 'SUCCEEDED':
                    self.hub.contexts.fail_reset(operation_id, expected_context_generation, 'NATIVE_RESET_FAILED')
            except (LedgerError, OSError, sqlite3.Error):
                pass
            raise

    @staticmethod
    def _alive(handle):
        return handle.pidfd >= 0 and not select.select([handle.pidfd], [], [], 0)[0]

    def _authority(self, handle, credentials):
        if self.store_failed:
            raise LedgerError("AUTHORITY_STORE_UNAVAILABLE")
        state = self._room()
        if (state['spec']['project_id'] != self.project_id
                or (self.forge_broker is not None and self.forge_broker.binding.project_id != self.project_id)):
            raise LedgerError('PROJECT_MISMATCH')
        document = self._read()
        badge = handle.badge
        record = document["seats"].get(badge.participant_id)
        if (self.handles.get(badge.participant_id) is not handle or not record
                or badge.incarnation_id in self.fenced
                or record["status"] != "active" or record["epoch"] != badge.epoch
                or record["incarnation_id"] != badge.incarnation_id):
            raise LedgerError("AUTHORITY_REVOKED")
        if not self._alive(handle):
            raise LedgerError("PROCESS_EXITED")
        if self.credentials.missing(record["seat"]):
            raise LedgerError("MISSING_ACTOR_CREDENTIAL")
        # sender PID is for this exact record. A duplicated/passed socket does
        # not duplicate its sender's kernel credentials; a live pidfd prevents
        # PID recycling from making a different process match the original.
        if credentials != (handle.process.pid, os.getuid(), os.getgid()):
            raise LedgerError("WRONG_PROCESS")
        return True

    @staticmethod
    def _record(channel):
        data, ancillary, flags, _ = channel.recvmsg(MAX_PACKET, socket.CMSG_SPACE(_UCRED.size), socket.MSG_CMSG_CLOEXEC)
        credentials = []
        invalid = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                # recvmsg installed descriptors even though the record is denied.
                descriptors = array.array("i")
                descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
                for descriptor in descriptors:
                    os.close(descriptor)
                invalid = True
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == _UCRED.size:
                credentials.append(_UCRED.unpack(value))
            else:
                invalid = True
        if invalid or len(credentials) != 1 or not data:
            raise LedgerError("INVALID_PROCESS_RECORD")
        return data, credentials[0]

    @staticmethod
    def _decode_packet(data):
        try:
            message = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
            write = type(message) is dict and type(message.get('envelope')) is dict and message['envelope'].get('kind') in {'forge-write','forge-reconcile'}
            (request_json if write else _json)(message)  # Typed, bounded, finite JSON.
        except (ValueError, UnicodeError, RecursionError) as error:
            raise LedgerError("INVALID_PROCESS_RECORD") from error
        return message

    def _forge_packet(self, handle, data, credentials):
        """Pi-only write-body assembly; authenticate every kernel record."""
        # Ordinary protocols keep their original single admission check under
        # the dispatch lock; they never enter the Pi chunk decoder.
        if handle.protocol != 'pi':
            return data, credentials
        import base64
        import time
        with self.supervisor._locked():
            self._authority(handle,credentials)
            first = self._decode_packet(data)
        if not (type(first) is dict and set(first)=={'request_id','index','count','sha256','data'}):
            return data,credentials
        raw=bytearray();scope=None;deadline=time.monotonic()+5
        for index in range(28):
            if index:
                remaining=deadline-time.monotonic()
                if remaining<=0 or not select.select([handle.channel],[],[],remaining)[0]:
                    raise LedgerError('INVALID_NATIVE_FRAME')
                data,credentials=self._record(handle.channel)
                with self.supervisor._locked():
                    self._authority(handle,credentials)
                    frame=self._decode_packet(data)
            else: frame=first
            if (type(frame) is not dict or set(frame)!={'request_id','index','count','sha256','data'}
                    or type(frame['request_id']) is not str or not re.fullmatch('[0-9a-f]{32}',frame['request_id'])
                    or type(frame['index']) is not int or frame['index']!=index
                    or type(frame['count']) is not int or not 1<=frame['count']<=28
                    or type(frame['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',frame['sha256'])
                    or type(frame['data']) is not str): raise LedgerError('INVALID_NATIVE_FRAME')
            current=(frame['request_id'],frame['count'],frame['sha256'])
            if scope is not None and scope!=current: raise LedgerError('INVALID_NATIVE_FRAME')
            scope=current
            try: chunk=base64.b64decode(frame['data'],validate=True)
            except ValueError: raise LedgerError('INVALID_NATIVE_FRAME') from None
            if len(chunk)>40000 or (index+1<frame['count'] and len(chunk)!=40000): raise LedgerError('INVALID_NATIVE_FRAME')
            raw.extend(chunk)
            if len(raw)>MAX_REQUEST: raise LedgerError('INVALID_NATIVE_FRAME')
            if index+1==frame['count']:
                if hashlib.sha256(raw).hexdigest()!=frame['sha256']: raise LedgerError('INVALID_NATIVE_FRAME')
                packet=self._decode_packet(bytes(raw))
                if (type(packet) is not dict or packet.get('request_id')!=frame['request_id']
                        or type(packet.get('envelope')) is not dict
                        or packet['envelope'].get('kind') not in {'forge-write','forge-reconcile'}): raise LedgerError('INVALID_NATIVE_FRAME')
                return bytes(raw),credentials
        raise LedgerError('INVALID_NATIVE_FRAME')

    @staticmethod
    def _packet(channel):
        # Parser-only test seam. Public receive authenticates before decoding.
        data, credentials = FixtureParticipantController._record(channel)
        return FixtureParticipantController._decode_packet(data), credentials

    def bind_forge(self, broker):
        """Supervisor-owned immutable Room/Project binding, never client input.

        Same-UID fixture seam only; production external Broker isolation and
        Deployment-wide audit remain unqualified.
        """
        from .forge import ReadOnlyForgeBroker
        if (type(broker) is not ReadOnlyForgeBroker or broker.ledger is not self.hub.ledger
                or broker.binding.room_id != self.supervisor.room_id):
            raise LedgerError('ROOM_MISMATCH')
        with self.supervisor._locked():
            state = self._room()
            if broker.binding.project_id != self.project_id or state['spec']['project_id'] != self.project_id:
                raise LedgerError('PROJECT_MISMATCH')
            if self.forge_broker is not None:
                raise LedgerError('FORGE_ALREADY_BOUND')
            records = self._read()['seats']
            def fenced(origin):
                record = records.get(origin.participant_id)
                return (record is None or record['status'] != 'active'
                        or record['incarnation_id'] != origin.incarnation_id)
            # New controller construction already fences old manifest authority.
            # Reconcile bounded old intents before making the endpoint available.
            broker.recover_pending(fenced)
            self.forge_broker = broker

    def bind_read_service(self, service):
        """Attach only a Supervisor-owned external Broker, never a payload client."""
        from .forge_read_service import ReadBrokerClient
        if type(service) is not ReadBrokerClient or service.supervisor is not self.supervisor:
            raise LedgerError('INVALID_READ_BROKER')
        with self.supervisor._locked():
            state = self._room()
            if (service.binding.room_id != self.supervisor.room_id
                    or service.binding.project_id != self.project_id
                    or service.room_instance != state['instance_id']):
                raise LedgerError('PROJECT_MISMATCH')
            if self.read_service is not None:
                raise LedgerError('FORGE_ALREADY_BOUND')
            self.read_service = service

    def _external_forge(self, message):
        # Negotiated with the authenticated external owner at bootstrap, never
        # caller-selected. Read-only #66 configurations retain legacy writes.
        return (type(message) is dict and self.read_service is not None
            and (message.get('kind')=='forge-read' or (message.get('kind') in {'forge-write','forge-reconcile'}
                and self.read_service.write_enabled is True)))

    def receive(self, handle):
        """Consume one kernel-authenticated record and dispatch to #65/#60.

        Waiting for input is outside the lifecycle lock. Authentication and the
        ledger transactions share that lock with revocation/Stop/Destroy. Forge
        provider I/O runs outside it; terminal publication rechecks authority.
        Replies can be lost; exact authorized retry retains ledger idempotency.
        """
        request_id = None
        forge_intent = None
        read_intent = None
        try:
            data, credentials = self._record(handle.channel)
            data, credentials = self._forge_packet(handle,data,credentials)
            with self.supervisor._locked():
                self._authority(handle, credentials)
                message = self._decode_packet(data)
                if handle.protocol == "pi":
                    if (type(message) is dict and type(message.get("request_id")) is str
                            and re.fullmatch(r"[0-9a-f]{32}", message["request_id"])):
                        request_id = message["request_id"]
                    if (request_id is None or set(message) != {"request_id", "envelope"}
                            or type(message["envelope"]) is not dict):
                        raise LedgerError("INVALID_NATIVE_FRAME")
                    message = message["envelope"]
                if self._external_forge(message):
                    from .forge_read_service import reserve_forge_operation
                    reserve_forge_operation(self.hub.ledger,self.read_service.binding,message,
                        handle.badge.origin(),lambda:self._authority(handle,credentials))
                    read_intent = self.read_service.prepare(message, handle.badge.origin(),
                        authorize=lambda: self._authority(handle, credentials))
                elif type(message) is dict and message.get('kind') in {'forge-read', 'forge-write'}:
                    if self.forge_broker is None:
                        raise LedgerError('FORGE_UNAVAILABLE')
                    forge_intent = self.forge_broker.prepare(message, origin=handle.badge.origin(),
                        authorize=lambda: self._authority(handle, credentials))
                else:
                    receipt = self.hub.submit(handle.connection, message, origin=handle.badge.origin(),
                                              authorize=lambda: self._authority(handle, credentials))
            if read_intent is not None:
                receipt = self.read_service.perform(read_intent)
                with self.supervisor._locked():
                    self._authority(handle, credentials)
            if forge_intent is not None:
                # Network/subprocess I/O must not hold Stop/revoke hostage.
                outcome = self.forge_broker.perform(forge_intent)
                with self.supervisor._locked():
                    receipt = self.forge_broker.complete(forge_intent, outcome,
                        authorize=lambda: self._authority(handle, credentials))
            result = {"ok": True, "receipt": receipt}
        except LedgerError as error:
            code = error.code
            # authorize() remains pure, including checks after SQLite BEGIN.
            # Every transaction and dispatch lock has unwound before fencing;
            # this also covers first/mid-chunk and late provider authority loss.
            if code in {"PROCESS_EXITED", "MISSING_ACTOR_CREDENTIAL"}:
                with self.supervisor._locked():
                    document = self._read()
                    record = document['seats'].get(handle.badge.participant_id)
                    # A replacement may have won the lock after the failing
                    # check; never overwrite a replacement or a stronger
                    # close/revoke decision for the same incarnation.
                    if (record is not None and self.handles.get(handle.badge.participant_id) is handle
                            and record['incarnation_id'] == handle.badge.incarnation_id
                            and record['status'] == 'active' and record['epoch'] == handle.badge.epoch):
                        self._fence(document, handle.badge.participant_id,
                                    "exited" if code == "PROCESS_EXITED" else "disabled",
                                    "process-exited" if code == "PROCESS_EXITED" else "missing-credential")
            if self.read_service is not None:
                try:
                    self.read_service.denied(code)
                except (LedgerError, OSError):
                    code = 'AUDIT_UNAVAILABLE'
            if self.forge_broker is not None:
                try:
                    if forge_intent is not None and code in {
                            'AUTHORITY_REVOKED', 'PROCESS_EXITED', 'MISSING_ACTOR_CREDENTIAL',
                            'ROOM_NOT_RUNNING', 'ROOM_REPLACED', 'CONTROLLER_REPLACED'}:
                        with self.supervisor._locked():
                            self.forge_broker.abandon(forge_intent, code)
                    self.forge_broker.denied(code)
                except LedgerError as audit_error:
                    code = audit_error.code
            result = {"ok": False, "error": code}
        if handle.protocol == "pi":
            result = {"request_id": request_id, **result}
        try:
            encoded = _json(result).encode()
            if len(encoded) <= MAX_PACKET:
                handle.channel.send(encoded)
            elif handle.protocol == 'pi' and read_intent is not None:
                from .forge_read_service import send_result
                send_result(handle.channel, request_id, result)
            else:
                raise LedgerError('OUTPUT_LIMIT')
        except OSError as error:
            if error.errno not in {errno.EPIPE, errno.ECONNRESET, errno.EBADF}:
                raise
            # Lifecycle may dispose the channel during a pending provider read.
            # Durable receipt, not delivery, is the success boundary.
        return result

    def _fence(self, document, participant, status, reason):
        record = document["seats"][participant]
        self.fenced.add(record["incarnation_id"])
        record.update(status=status, reason=reason, epoch=min(MAX_EPOCH, record["epoch"] + 1))
        self._save(document)
        handle = self.handles.get(participant)
        if handle is not None and handle.connection is not None and self.hub._current(handle.connection):
            self.hub.observe(handle.connection, Readiness.LOST)

    def revoke(self, participant, *, close=False):
        with self.supervisor._locked():
            state = self._room(running=False)
            self.supervisor._allowed("participant-close" if close else "participant-revoke", state)
            document = self._read()
            if participant not in document["seats"]:
                raise LedgerError("UNKNOWN_PARTICIPANT")
            try:
                if document["seats"][participant]["status"] != "closed":
                    self._fence(document, participant, "closed" if close else "revoked", "explicit-revocation")
            finally:
                handle = self.handles.get(participant)
                if handle is not None:
                    self._dispose(handle)

    def set_credential_available(self, reference, available):
        """Trusted fixture observation; serialize credential revocation with dispatch.

        Repair updates only availability. It never starts a process or advances
        a revoked seat back to active; an explicit launch is required.
        """
        with self.supervisor._locked():
            state = self._room(running=False)
            self.supervisor._allowed("participant-credential-observation", state)
            self.credentials.set_available(reference, available)
            document = self._read()
            for participant, record in document["seats"].items():
                if record["status"] in {"starting", "active"} and self.credentials.missing(record["seat"]):
                    try:
                        self._fence(document, participant, "disabled", "missing-credential")
                    finally:
                        handle = self.handles.get(participant)
                        if handle is not None:
                            self._dispose(handle)

    def _revoke_all_locked(self, state):
        try:
            if state["instance_id"] != self.instance:
                return False
            document = self._read()
            for participant, record in document["seats"].items():
                if record["status"] not in {"closed", "revoked"}:
                    self._fence(document, participant, "revoked", "room-stopped")
            for handle in self.handles.values():
                self._dispose(handle)
            # A new controller does not own old pidfds. It may prove absence,
            # never adopt/kill by a persisted PID. A reused live PID conservatively
            # blocks Stop/Destroy rather than granting authority or being killed.
            remaining = []
            for pid in document["retired_pids"]:
                try:
                    fd = os.pidfd_open(pid, 0)
                except ProcessLookupError:
                    continue
                try:
                    if not select.select([fd], [], [], 0)[0]:
                        remaining.append(pid)
                finally:
                    os.close(fd)
            document["retired_pids"] = remaining
            self._save(document)
            return not remaining and all(not self._alive(handle) for handle in self.handles.values())
        except (LedgerError, OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _remove_empty_runtime_directory(directory):
        try:
            directory.rmdir()
        except FileNotFoundError:
            pass
        except OSError as error:
            if error.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                raise
            # Native state/unexpected files are retained, never recursively
            # removed. Pi's explicit persistent recipe directory is not ours.

    @staticmethod
    def _dispose(handle):
        if handle.process.poll() is None:
            handle.process.terminate()
            try:
                handle.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                handle.process.kill()
                handle.process.wait(timeout=2)
        receiver_error = None
        try:
            if handle.managed_receiver is not None:
                try:
                    handle.managed_receiver.close()
                    handle.managed_receiver = None
                except Exception as error:
                    receiver_error = error
        finally:
            handle.channel.close()
            if handle.pidfd >= 0:
                os.close(handle.pidfd)
                handle.pidfd = -1
            for stream in (handle.process.stdin, handle.process.stdout, handle.process.stderr):
                if stream is not None:
                    stream.close()
            FixtureParticipantController._remove_empty_runtime_directory(handle.runtime_directory)
        if receiver_error is not None:
            raise LedgerError("NATIVE_RECEIVER_CLOSE_FAILED") from receiver_error

    def snapshot(self):
        with self.supervisor._locked():
            self._room(running=False)
            return self._read()

    def close(self):
        """Fixture harness cleanup. Never adopt/kill arbitrary persisted PIDs."""
        with self.supervisor._locked():
            try:
                self._revoke_all_locked(self._room(running=False))
            finally:
                for handle in self.handles.values():
                    self._dispose(handle)
