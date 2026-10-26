"""Linux same-namespace Participant authority fixture, not a Workstation launcher.

The trusted supervisor owns both this object and its private control store. Each
record uses kernel SCM_CREDENTIALS plus a held pidfd, never a transferable bearer
badge, claimed PID, UID alone, or connection-time SO_PEERCRED. No Forge/provider
credential is loaded; FixtureCredentials contains synthetic references only.
"""
from dataclasses import asdict, dataclass
import array
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import uuid

from .ledger import LedgerError, Origin, _json, _token
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
        if self.runtime != "fixture" or self.provider_host != "forge.fixture.invalid":
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

    @staticmethod
    def _alive(handle):
        return handle.pidfd >= 0 and not select.select([handle.pidfd], [], [], 0)[0]

    def _authority(self, handle, credentials):
        if self.store_failed:
            raise LedgerError("AUTHORITY_STORE_UNAVAILABLE")
        self._room()
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
    def _packet(channel):
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
        try:
            message = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
            _json(message)  # rejects excessive nesting, nonfinite numbers, etc.
        except (ValueError, UnicodeError, RecursionError) as error:
            raise LedgerError("INVALID_PROCESS_RECORD") from error
        return message, credentials[0]

    def receive(self, handle):
        """Consume one kernel-authenticated record and dispatch to #65/#60.

        Waiting for input is outside the lifecycle lock. Authentication and the
        complete ledger transaction share that lock with revocation/Stop/Destroy.
        Replies can be lost; exact authorized retry retains ledger idempotency.
        """
        try:
            message, credentials = self._packet(handle.channel)
            with self.supervisor._locked():
                try:
                    self._authority(handle, credentials)
                    receipt = self.hub.submit(handle.connection, message, origin=handle.badge.origin(),
                                              authorize=lambda: self._authority(handle, credentials))
                except LedgerError as error:
                    # authorize() is pure: it can detect an exit/credential
                    # race after SQLite BEGIN but cannot nest another write.
                    # apply() has rolled back before this lifecycle mutation.
                    if error.code in {"PROCESS_EXITED", "MISSING_ACTOR_CREDENTIAL"}:
                        document = self._read()
                        self._fence(document, handle.badge.participant_id,
                                    "exited" if error.code == "PROCESS_EXITED" else "disabled",
                                    "process-exited" if error.code == "PROCESS_EXITED" else "missing-credential")
                    raise
            result = {"ok": True, "receipt": receipt}
        except LedgerError as error:
            result = {"ok": False, "error": error.code}
        try:
            handle.channel.send(_json(result).encode())
        except (BrokenPipeError, ConnectionResetError):
            pass  # Durable receipt, not delivery, is the success boundary.
        return result

    def _fence(self, document, participant, status, reason):
        record = document["seats"][participant]
        self.fenced.add(record["incarnation_id"])
        record.update(status=status, reason=reason, epoch=min(MAX_EPOCH, record["epoch"] + 1))
        self._save(document)
        handle = self.handles.get(participant)
        if handle is not None and self.hub._current(handle.connection):
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
                if record["status"] == "active" and self.credentials.missing(record["seat"]):
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
    def _dispose(handle):
        if handle.process.poll() is None:
            handle.process.terminate()
            try:
                handle.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                handle.process.kill()
                handle.process.wait(timeout=2)
        handle.channel.close()
        if handle.pidfd >= 0:
            os.close(handle.pidfd)
            handle.pidfd = -1
        handle.process.stdin.close()
        handle.process.stdout.close()
        if handle.runtime_directory.exists():
            handle.runtime_directory.rmdir()  # Never recursively delete data.

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
