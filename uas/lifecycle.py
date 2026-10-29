"""Supervisor-owned fixture lifecycle, separate from Hub/domain execution.

No production Workstation can be activated by this module. The Docker backend is
explicitly fixture-only; #62 supplies the later production launch qualifier.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import json
import math
import time
import os
from pathlib import Path
import re
import shutil
import threading
import uuid

from .manager_owner import REVISION_FIELDS, advance_revision, lifecycle_observations, validate_revision


class LifecycleError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class BackendUnknown(Exception):
    """Effect/observation uncertain. Inspect exact resources before any retry."""


class OwnershipConflict(Exception):
    """A named resource exists but its ownership cannot be verified."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest field")
        result[key] = value
    return result


def _now():
    return datetime.now(timezone.utc).isoformat()


def _path(path):
    try:
        path = Path(path)
        if not path.is_absolute() or path == Path("/") or ".." in path.parts or path.resolve() != path:
            raise LifecycleError("INVALID_PATH")
        return path
    except (TypeError, ValueError, OSError) as error:
        raise LifecycleError("INVALID_PATH") from error


def _overlap(a, b):
    return a == b or a in b.parents or b in a.parents


@dataclass(frozen=True)
class FixtureSpec:
    """Validated fixture selection, not a production launch-policy approval."""
    room_id: str
    project_id: str
    project_paths: tuple[str, ...]
    image_id: str
    config_digest: str
    profile_digest: str

    def document(self):
        for value in (self.room_id, self.project_id):
            if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value):
                raise LifecycleError("INVALID_SPEC")
        for value in (self.image_id, self.config_digest, self.profile_digest):
            if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                raise LifecycleError("INVALID_SPEC")
        if type(self.project_paths) is not tuple or not 1 <= len(self.project_paths) <= 16:
            raise LifecycleError("INVALID_SPEC")
        # The fixture's Docker --mount grammar cannot represent commas or
        # control characters. Reject before intent persistence/resource effects.
        if any(type(path) is not str or "," in path or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in path)
               for path in self.project_paths):
            raise LifecycleError("INVALID_SPEC")
        paths = [str(_path(path)) for path in self.project_paths]
        if len(paths) != len(set(paths)):
            raise LifecycleError("INVALID_SPEC")
        return {**asdict(self), "project_paths": sorted(paths)}


class _HeldLifecycleScope:
    """Transient proof of one exact Supervisor lock scope; never serialized."""
    __slots__ = ('_supervisor',)

    def __init__(self, supervisor):
        self._supervisor = supervisor

    def require(self, supervisor):
        if type(supervisor) is not Supervisor or supervisor is not self._supervisor:
            raise LifecycleError('LIFECYCLE_LOCK_REQUIRED')
        Supervisor._require_lifecycle_scope(supervisor, self)


class Supervisor:
    """Serialize one Room's intent/effects; preserve owned/unowned distinction.

    backend: inspect/create/admit/start/stop/remove exact fixture resources.
    admit re-observes the actual boundary before Start/resume/reconciliation;
    ownership alone never authorizes execution. Stop/Destroy do not need admission.
    authorize(action, room_id, instance_id): current trusted human authorization.
    revoke(instance_id, scope): idempotently revoke and VERIFY authority; must
    return literal True. Scope is 'participants' on Stop, 'all' on Destroy.
    Neither callback may be selected or replaced by untrusted client payload.
    """

    def __init__(self, control_root, room_id, backend, *, authorize, revoke):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", room_id):
            raise LifecycleError("INVALID_SPEC")
        self.root = _path(control_root)
        self.room_id, self.backend = room_id, backend
        self.authorize, self.revoke = authorize, revoke
        self.directory = self.root / room_id
        self._manifest = self.directory / "lifecycle.json"
        self._participant_controller = None
        self._control_plane = None
        self._lifecycle_scopes = {}

    @contextmanager
    def _locked(self, *, deadline=None):
        # The enclosing control store is trusted host state, not a Workstation
        # mount. This is not a substitute for #62 filesystem/process isolation.
        if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise LifecycleError('INVALID_DEADLINE')
        if self.directory.resolve() != self.directory:
            raise LifecycleError("INVALID_PATH")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(self.directory / "lifecycle.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        scope = None
        try:
            if deadline is None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            else:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LifecycleError('LIFECYCLE_DEADLINE')
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        time.sleep(min(0.02, remaining))
                if time.monotonic() >= deadline:
                    raise LifecycleError('LIFECYCLE_DEADLINE')
            scope = _HeldLifecycleScope(self)
            self._lifecycle_scopes[scope] = (os.getpid(), threading.get_ident(), descriptor)
            yield scope
        finally:
            if scope is not None:
                self._lifecycle_scopes.pop(scope, None)
            os.close(descriptor)

    def _require_lifecycle_scope(self, scope):
        if type(self) is not Supervisor or type(scope) is not _HeldLifecycleScope:
            raise LifecycleError('LIFECYCLE_LOCK_REQUIRED')
        held = self._lifecycle_scopes.get(scope)
        if (held is None or scope._supervisor is not self
                or held[:2] != (os.getpid(), threading.get_ident())):
            raise LifecycleError('LIFECYCLE_LOCK_REQUIRED')

    def _read(self):
        if not self._manifest.exists():
            return None
        if self._manifest.is_symlink():
            raise LifecycleError("INVALID_STORE")
        try:
            if self._manifest.stat().st_size > 1_048_576:
                raise ValueError("oversized manifest")
            document = json.loads(self._manifest.read_text(), object_pairs_hook=_unique_object)
            required = {"version", "room_id", "instance_id", "spec", "phase", "desired",
                        "created_at", "pending_spec", "authority"}
            optional = {"leftovers", "destroy_requested_at", "destroyed_at", "remote_start", "control_plane_required", "manager_action"} | REVISION_FIELDS
            if type(document) is not dict or not required <= document.keys() or document.keys() - required - optional:
                raise ValueError("manifest fields")
            validate_revision(document)
            if "manager_action" in document:
                marker = document["manager_action"]
                if (type(marker) is not dict or set(marker) != {"operation_id", "request_digest"}
                        or type(marker["operation_id"]) is not str
                        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", marker["operation_id"])
                        or type(marker["request_digest"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", marker["request_digest"])):
                    raise ValueError("Manager action marker")
            if "control_plane_required" in document and document["control_plane_required"] is not True:
                raise ValueError("control plane requirement")
            if "remote_start" in document:
                marker = document["remote_start"]
                if (type(marker) is not dict or set(marker) != {"operation_id", "human_id", "request_digest"}
                        or any(type(marker[k]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", marker[k]) for k in ("operation_id", "human_id"))
                        or type(marker["request_digest"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", marker["request_digest"])):
                    raise ValueError("remote Start marker")
            if type(document["version"]) is not int or document["version"] != 1 or document["room_id"] != self.room_id:
                raise ValueError("manifest version/room")
            if type(document["instance_id"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", document["instance_id"]):
                raise ValueError("instance identity")
            phases = {"creating": "running", "starting": "running", "running": "running", "start_failed": "running",
                      "stopping": "stopped", "stopped": "stopped", "stop_failed": "stopped",
                      "destroying": "destroyed", "destroy_failed": "destroyed", "destroyed": "destroyed"}
            if type(document["phase"]) is not str or document["phase"] not in phases or document["desired"] != phases[document["phase"]]:
                raise ValueError("phase/intent")
            if document["authority"] not in ("not-issued", "participants-revoked", "all-revoked"):
                raise ValueError("authority")
            spec = self._stored_spec(document["spec"])
            if spec["room_id"] != self.room_id:
                raise ValueError("spec room")
            self._verify_projects(spec)
            pending = document["pending_spec"]
            if pending is not None:
                pending = self._stored_spec(pending)
                if any(pending[key] != spec[key] for key in ("room_id", "project_id", "project_paths")):
                    raise ValueError("pending binding")
            for key in ("created_at", "destroy_requested_at", "destroyed_at"):
                if key in document:
                    value = document[key]
                    if type(value) is not str or len(value) > 64 or datetime.fromisoformat(value).tzinfo is None:
                        raise ValueError("timestamp")
            if document["desired"] == "destroyed" and "destroy_requested_at" not in document:
                raise ValueError("missing destroy intent")
            if document["desired"] != "destroyed" and any(key in document for key in ("destroy_requested_at", "destroyed_at")):
                raise ValueError("unexpected destroy history")
            if document["phase"] == "destroyed" and ("destroyed_at" not in document or document["authority"] != "all-revoked"):
                raise ValueError("incomplete terminal state")
            leftovers = document.get("leftovers", [])
            if type(leftovers) is not list or len(leftovers) > 32:
                raise ValueError("leftovers")
            for item in leftovers:
                if type(item) is not dict or set(item) != {"kind", "name", "reason"}:
                    raise ValueError("leftover fields")
                if item["kind"] not in ("container", "volume", "control-state", "authority", "reconciliation", "tombstone"):
                    raise ValueError("leftover kind")
                for value in item.values():
                    if type(value) is not str or not 1 <= len(value) <= 256 or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
                        raise ValueError("leftover value")
            return document
        except (ValueError, KeyError, TypeError, RecursionError, LifecycleError) as error:
            raise LifecycleError("INVALID_STORE") from error

    @staticmethod
    def _stored_spec(document):
        keys = {"room_id", "project_id", "project_paths", "image_id", "config_digest", "profile_digest"}
        if type(document) is not dict or set(document) != keys or type(document["project_paths"]) is not list:
            raise ValueError("stored spec fields")
        normalized = FixtureSpec(**{**document, "project_paths": tuple(document["project_paths"])}).document()
        if normalized != document:
            raise ValueError("noncanonical stored spec")
        return normalized

    def _sync_directory(self, path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _save(self, state):
        try:
            advance_revision(state)
        except ValueError as error:
            raise LifecycleError('INVALID_STORE') from error
        temporary = self.directory / (".lifecycle-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "w") as output:
                output.write(_canonical(state))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self._manifest)
            self._sync_directory(self.directory)
        finally:
            temporary.unlink(missing_ok=True)

    def _allowed(self, action, state):
        if self.authorize(action, self.room_id, state["instance_id"] if state else None) is not True:
            raise LifecycleError("FORBIDDEN")

    def _verify_projects(self, spec):
        for path in spec["project_paths"]:
            project = _path(path)
            if _overlap(project, self.root):
                raise LifecycleError("CONTROL_PROJECT_OVERLAP")

    def _owned_directory(self, state):
        directory = self.directory / "instances" / state["instance_id"]
        if directory.resolve() != directory:
            raise LifecycleError("OWNERSHIP_CONFLICT")
        return directory

    def _ensure_owned_directory(self, state):
        directory = self._owned_directory(state)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = directory / "owner.json"
        expected = {"room_id": self.room_id, "instance_id": state["instance_id"]}
        if marker.exists():
            if marker.is_symlink() or json.loads(marker.read_text()) != expected:
                raise LifecycleError("OWNERSHIP_CONFLICT")
        else:
            # Never adopt an existing nonempty directory as disposable state.
            if any(directory.iterdir()):
                raise LifecycleError("OWNERSHIP_CONFLICT")
            with marker.open("x") as output:
                output.write(_canonical(expected))
                output.flush()
                os.fsync(output.fileno())
            self._sync_directory(directory)
        (directory / "data").mkdir(exist_ok=True, mode=0o700)

    def _observe(self, state):
        observed, leftovers = {}, []
        for kind in ("container", "volume"):
            name = self.backend.name(state, kind)
            try:
                observed[kind] = self.backend.inspect(state, kind)
            except (BackendUnknown, OwnershipConflict) as error:
                observed[kind] = {"unknown": True}
                leftovers.append({"kind": kind, "name": name,
                                  "reason": "OWNERSHIP_CONFLICT" if isinstance(error, OwnershipConflict) else "OBSERVATION_UNKNOWN"})
        return observed, leftovers

    def _result(self, state):
        observed, unknown = self._observe(state)
        leftovers = {(item["kind"], item["name"]): item for item in unknown}
        leftovers.update({(item["kind"], item["name"]): item for item in state.get("leftovers", [])})
        if state["desired"] == "destroyed" and state["phase"] != "destroyed":
            for kind, resource in observed.items():
                if resource is not None:
                    name = self.backend.name(state, kind)
                    leftovers.setdefault((kind, name), {"kind": kind, "name": name, "reason": "STILL_PRESENT"})
            if os.path.lexists(self.directory / "instances" / state["instance_id"]):
                leftovers.setdefault(("control-state", state["instance_id"]),
                                     {"kind": "control-state", "name": state["instance_id"], "reason": "RETAINED_UNTIL_RESOURCE_CLEANUP"})
        return {"room_id": self.room_id, "instance_id": state["instance_id"],
                "phase": state["phase"], "desired": state["desired"], "observed": observed,
                "pending_spec": state.get("pending_spec"), "leftovers": list(leftovers.values()),
                "fixture_only": True, "production_launch": "unqualified",
                "authority": state.get("authority", "unknown"),
                "error": {"destroy_failed": "DESTROY_FAILED", "start_failed": "START_FAILED",
                          "stop_failed": "STOP_FAILED"}.get(state["phase"])}

    def checkouts(self, source, *, writer_quiescent=None, writer_guard=None):
        """Host Git allocation under this Room's lifecycle/authorization lock.

        This does not mount a checkout or qualify a production Workstation.
        """
        from .checkouts import CheckoutAllocator
        return CheckoutAllocator(self, source, writer_quiescent=writer_quiescent, writer_guard=writer_guard)

    def status(self):
        with self._locked():
            state = self._read()
            return self._result(state) if state else {"room_id": self.room_id, "phase": "absent", "fixture_only": True}

    def manager_observations(self):
        """Passive persisted facts; never inspect Docker or infer process health."""
        with self._locked():
            return lifecycle_observations(self._read())

    def participants(self, hub, credentials):
        """Launch the synthetic process fixture, never a production Runtime.

        Uses this Room's lifecycle lock and current human authorization. Only
        one controller is attached to a Supervisor; reconstructing a Supervisor
        and controller fences previous authority instead of adopting old PIDs.
        """
        if self._participant_controller is not None:
            raise LifecycleError("PARTICIPANT_CONTROLLER_EXISTS")
        from .participant import FixtureParticipantController
        controller = FixtureParticipantController(self, hub, credentials)
        self._participant_controller = controller
        return controller

    def start(self, spec: FixtureSpec):
        requested = spec.document()
        if requested["room_id"] != self.room_id:
            raise LifecycleError("ROOM_MISMATCH")
        self._verify_projects(requested)
        with self._locked():
            state = self._read()
            self._allowed("start", state)
            if state and state["phase"] in {"destroying", "destroy_failed"}:
                raise LifecycleError("DESTROY_INCOMPLETE")
            if state and state["phase"] != "destroyed":
                if any(state["spec"][key] != requested[key] for key in ("project_id", "project_paths")):
                    raise LifecycleError("PROJECT_BINDING_CONFLICT")
                state["pending_spec"] = requested if requested != state["spec"] else None
                state["phase"] = "starting"
            else:
                self._control_plane = None
                state = {"version": 1, "room_id": self.room_id, "instance_id": uuid.uuid4().hex,
                         "spec": requested, "phase": "creating", "created_at": _now(),
                         "pending_spec": None, "authority": "not-issued"}
            state["desired"] = "running"
            self._save(state)  # Commit identity and intent BEFORE any resource effect.
            return self._converge_running(state)

    def _converge_running(self, state):
        self._ensure_owned_directory(state)
        try:
            control_store = self._owned_directory(state) / "control-plane.json"
            if state.get("control_plane_required") or control_store.exists() or control_store.is_symlink():
                if self._control_plane is None or self._control_plane.instance != state["instance_id"]:
                    raise LifecycleError("CONTROL_PLANE_NOT_READY")
                self._control_plane.require_ready_locked()
            for kind in ("volume", "container"):
                resource = self.backend.inspect(state, kind)
                if resource is None:
                    try:
                        self.backend.create(state, kind)
                    except BackendUnknown:
                        pass  # A missing response is not permission to create again.
                    resource = self.backend.inspect(state, kind)
                    if resource is None:
                        raise BackendUnknown()
                if kind == "container":
                    if resource["image_id"] != state["spec"]["image_id"]:
                        raise LifecycleError("MANAGED_IMAGE_DRIFT")
                    self.backend.admit(state)
                    if not resource["running"]:
                        try:
                            self.backend.start(state)
                        except BackendUnknown:
                            pass
                        resource = self.backend.inspect(state, kind)
                        if resource is None or not resource.get("running"):
                            raise BackendUnknown()
                        self.backend.admit(state)
            state["phase"], state["leftovers"] = "running", []
        except (BackendUnknown, OwnershipConflict, LifecycleError) as error:
            state["phase"] = "start_failed"
            state["leftovers"] = [{"kind": "reconciliation", "name": state["instance_id"],
                                   "reason": error.code if isinstance(error, LifecycleError) else type(error).__name__}]
        self._save(state)
        return self._result(state)

    def stop(self):
        with self._locked():
            state = self._read()
            if state is None:
                raise LifecycleError("ROOM_ABSENT")
            self._allowed("stop", state)
            if state["phase"] in {"destroying", "destroy_failed", "destroyed"}:
                raise LifecycleError("DESTROY_INCOMPLETE")
            state["desired"], state["phase"] = "stopped", "stopping"
            self._save(state)
            return self._converge_stopped(state)

    def manager_action(self, value, *, session, deployment_id, ledger):
        from .manager_lifecycle import execute
        return execute(self, value, session=session, deployment_id=deployment_id, ledger=ledger)

    def manager_view(self, *, session, deployment_id):
        from .manager_lifecycle import view
        return view(self, session=session, deployment_id=deployment_id)

    def _revoked(self, state, scope):
        try:
            if scope == "all" and state.get("control_plane_required") and state["desired"] == "destroyed" and state["authority"] == "all-revoked" and not self._owned_directory(state).exists():
                return True  # Durable revocation proof survives removed instance data.
            if self._participant_controller is not None:
                if not self._participant_controller._revoke_all_locked(state):
                    return False
            elif (self._owned_directory(state) / "participants.json").exists():
                # A reconstructed supervisor must reconnect the actual
                # controller; a legacy/vacuous callback cannot vouch for seats.
                return False
            control_store = self._owned_directory(state) / "control-plane.json"
            if self._control_plane is not None:
                if not self._control_plane.revoke_locked(state, scope):
                    return False
            elif state.get("control_plane_required") or control_store.exists() or control_store.is_symlink():
                # Persisted nonempty services cannot be certified by a callback.
                return False
            return self.revoke(state["instance_id"], scope) is True
        except (BackendUnknown, LifecycleError):
            return False

    def _converge_stopped(self, state):
        if not self._revoked(state, "participants"):
            state["phase"] = "stop_failed"
            state["leftovers"] = [{"kind": "authority", "name": state["instance_id"], "reason": "REVOCATION_UNVERIFIED"}]
        else:
            state["authority"] = "participants-revoked"
            try:
                resource = self.backend.inspect(state, "container")
                if resource is not None and resource["running"]:
                    try:
                        self.backend.stop(state)
                    except BackendUnknown:
                        pass
                resource = self.backend.inspect(state, "container")
                if resource is not None and resource["running"]:
                    raise BackendUnknown()
                state["phase"], state["leftovers"] = "stopped", []
            except (BackendUnknown, OwnershipConflict) as error:
                state["phase"] = "stop_failed"
                state["leftovers"] = [{"kind": "container", "name": self.backend.name(state, "container"), "reason": type(error).__name__}]
        self._save(state)
        return self._result(state)

    def destroy(self):
        with self._locked():
            state = self._read()
            if state is None:
                raise LifecycleError("ROOM_ABSENT")
            self._allowed("destroy", state)
            if state["phase"] == "destroyed":
                return self._result(state)
            state["desired"], state["phase"] = "destroyed", "destroying"
            state.setdefault("destroy_requested_at", _now())
            self._save(state)
            return self._converge_destroyed(state)

    def _converge_destroyed(self, state):
        # Mandatory verified revocation comes before any stop/remove operation.
        if not self._revoked(state, "all"):
            state["phase"] = "destroy_failed"
            state["leftovers"] = (self._control_plane.leftovers if self._control_plane is not None and self._control_plane.leftovers else
                                  [{"kind": "authority", "name": state["instance_id"], "reason": "REVOCATION_UNVERIFIED"}])
            self._save(state)
            return self._result(state)
        state["authority"] = "all-revoked"
        self._save(state)
        leftovers = []
        for kind in ("container", "volume"):
            name = self.backend.name(state, kind)
            try:
                resource = self.backend.inspect(state, kind)
                if resource is not None:
                    if kind == "container" and resource["running"]:
                        try:
                            self.backend.stop(state)
                        except BackendUnknown:
                            pass
                        resource = self.backend.inspect(state, kind)
                        if resource is not None and resource["running"]:
                            raise BackendUnknown()
                    try:
                        self.backend.remove(state, kind)
                    except BackendUnknown:
                        pass
                if self.backend.inspect(state, kind) is not None:
                    leftovers.append({"kind": kind, "name": name, "reason": "STILL_PRESENT"})
            except (BackendUnknown, OwnershipConflict) as error:
                leftovers.append({"kind": kind, "name": name, "reason": type(error).__name__})
        if not leftovers:
            try:
                directory = self._owned_directory(state)
                if directory.exists():
                    marker = directory / "owner.json"
                    if marker.is_symlink() or json.loads(marker.read_text()) != {"room_id": self.room_id, "instance_id": state["instance_id"]}:
                        raise LifecycleError("OWNERSHIP_CONFLICT")
                    shutil.rmtree(directory)  # Exact marked control-plane instance, never Project roots.
                    self._sync_directory(directory.parent)
            except (OSError, ValueError, LifecycleError) as error:
                leftovers.append({"kind": "control-state", "name": state["instance_id"], "reason": type(error).__name__})
        state["leftovers"] = leftovers
        if leftovers:
            state["phase"] = "destroy_failed"
        else:
            state.setdefault("destroyed_at", _now())
            self._save(state)
            try:
                self._tombstone(state)
                state["phase"] = "destroyed"
            except (OSError, LifecycleError) as error:
                state["phase"] = "destroy_failed"
                state["leftovers"] = [{"kind": "tombstone", "name": state["instance_id"],
                                       "reason": error.code if isinstance(error, LifecycleError) else "STORAGE_ERROR"}]
        self._save(state)
        return self._result(state)

    def _tombstone(self, state):
        directory = self.directory / "tombstones"
        if directory.resolve() != directory:
            raise LifecycleError("INVALID_PATH")
        directory.mkdir(exist_ok=True, mode=0o700)
        document = {key: state[key] for key in ("room_id", "instance_id", "created_at", "destroy_requested_at", "destroyed_at")}
        document["project_id"] = state["spec"]["project_id"]
        document["authority"] = "all-revoked"
        path = directory / (state["instance_id"] + ".json")
        content = _canonical(document)
        temporary = directory / (".tombstone-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        try:
            with os.fdopen(descriptor, "w") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, path)  # Atomic no-overwrite publication.
            except FileExistsError:
                if path.is_symlink() or path.read_text() != content:
                    raise LifecycleError("TOMBSTONE_CONFLICT")
            self._sync_directory(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def reconcile(self):
        with self._locked():
            state = self._read()
            if state is None:
                raise LifecycleError("ROOM_ABSENT")
            # Intent was already human-authorized before persistence. Reconcile
            # only that intent, not new work or a client-supplied replacement.
            if state["phase"] == "destroyed":
                return self._result(state)
            return {"running": self._converge_running, "stopped": self._converge_stopped,
                    "destroyed": self._converge_destroyed}[state["desired"]](state)
