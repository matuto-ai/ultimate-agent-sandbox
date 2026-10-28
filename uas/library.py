"""Per-Project Library contracts and fail-closed settings admission.

This module defines the typed contract seam only. It opens no clone, loads no
credential, calls no model, publishes no projection and provisions no service,
so every refusal here has no Library, Git, network or external effect.

Trusted Hub/Service code derives Project, Actor and human scope from already
authenticated authority. Caller payloads carry no scope: reserved authority
fields are rejected instead of interpreted, and persistence/audit metadata is
safe metadata or content-free digests. Consumers still recheck current
authority on every attempt; a stored scope is not fresh authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import posixpath
import re

from .ledger import Origin
from .manager_actions import HumanSession


CONTRACT_VERSION = 1
SETTINGS_VERSION = 1
MAX_SETTINGS_BYTES = 65536
MAX_AUDIT_BYTES = 4096
MAX_PROPOSAL_OPERATIONS = 64
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,200}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")

ENQUEUE_CAPABILITY = "library-enqueue"
SETTINGS_CAPABILITY = "library-settings"
SUBJECTS = ("participant", "human", "operator")
CAPTURE_TYPES = ("context", "decision", "research")
OUTCOMES = {
    "DURABLY_QUEUED", "REJECTED", "NOT_DURABLE", "COMMITTED",
    "REFUSED", "BUSY", "STALE", "UNKNOWN",
}
OBSERVATION_STATES = {"healthy", "stale", "disconnected", "unknown", "blocked"}
HUMAN_KINDS = {
    "register", "import-preview", "import-confirm", "inspect", "drain", "retry",
    "defer", "requeue", "reject", "adjudicate", "resume", "scan", "repair",
    "archive", "restore",
}
DRAIN_KINDS = {"retry", "defer", "requeue", "reject", "adjudicate", "resume"}
ITEM_KINDS = {"reject", "adjudicate"}
FENCED_KINDS = {
    "import-confirm", "drain", "retry", "defer", "requeue", "reject",
    "adjudicate", "resume", "archive", "restore",
}
# Only these operations reach a model, so only they need hosted-egress approval.
MODEL_KINDS = {"drain", "archive"}
PROPOSAL_OPERATIONS = {"create", "update", "park"}
CONCEPT_DIRECTORIES = ("context", "decisions", "research")

# Fixed crash-protection maxima. They are constants, not settings: an operator
# cannot raise them and admission refuses any value above them.
MAXIMA = {
    "title_chars": 512,
    "body_bytes": 262144,
    "sources": 64,
    "payload_bytes": 524288,
    "batch_drafts": 64,
    "batch_bytes": 2097152,
    "attempt_seconds": 3600,
    "coalesce_seconds": 3600,
    "warning_seconds": 2592000,
    "inspection_bytes": 262144,
    "document_bytes": 1048576,
    "scan_documents": 4096,
    "projection_bytes": 1048576,
}
# Published starting values. Admission never substitutes them for a missing
# setting; a deployment supplies every one of them explicitly.
INITIAL_LIMITS = {
    "title_chars": 200,
    "body_bytes": 16384,
    "sources": 16,
    "payload_bytes": 32768,
    "batch_drafts": 8,
    "batch_bytes": 65536,
    "attempt_seconds": 120,
    "coalesce_seconds": 10,
    "warning_seconds": 86400,
    "inspection_bytes": 16384,
    "document_bytes": 65536,
    "scan_documents": 256,
    "projection_bytes": 65536,
}
# Caller-supplied authority or service-owned identity. Rejected at any depth.
RESERVED_KEYS = frozenset({
    "project", "project_id", "project_identity", "reference_root", "snapshot_path",
    "root", "actor", "actor_id", "participant_id", "human", "human_id", "subject",
    "scope", "origin", "authority", "authority_version", "capabilities",
    "installation", "installation_id", "settings", "settings_id",
    "outcome", "receipt", "provenance", "submitted_by", "published_sha",
    "verified", "generated", "status",
})
# A capture payload never supplies its own operation, queue or drain identity.
CAPTURE_IDENTITY_KEYS = ("operation_id", "request_id", "queue_id", "drain_id")
CONTENT_KEYS = frozenset({
    "body", "text", "prompt", "output", "transcript", "content", "title",
    "secret", "password", "credential", "token",
})


class LibraryError(ValueError):
    """Stable code plus safe field path; never echoes input values or secrets."""

    def __init__(self, code: str, field: str = "$"):
        self.code, self.field = code, field
        super().__init__(f"{code}: {field}")


def _fail(code, field="$"):
    raise LibraryError(code, field)


def _canonical(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("INVALID_CONTRACT")
    return encoded


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _size(value):
    return len(_canonical(value).encode("utf-8"))


def _text(value, field, limit=2048, multiline=False):
    if (type(value) is not str or not value or len(value) > limit
            or any((ord(c) < 32 or 127 <= ord(c) < 160) and not (multiline and c in "\n\t") for c in value)):
        _fail("INVALID_TEXT", field)
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail("INVALID_TEXT", field)
    return value


def _token(value, field, limit=128):
    if type(value) is not str or len(value) > limit or not TOKEN.fullmatch(value):
        _fail("INVALID_IDENTIFIER", field)
    return value


def _identifier(value, field):
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        _fail("INVALID_IDENTIFIER", field)
    return value


def _digest_value(value, field):
    if type(value) is not str or not DIGEST.fullmatch(value):
        _fail("INVALID_DIGEST", field)
    return value


def _commit(value, field, allow_none=False):
    if value is None and allow_none:
        return None
    if type(value) is not str or not COMMIT.fullmatch(value):
        _fail("INVALID_COMMIT", field)
    return value


def _integer(value, field, minimum=1, maximum=2**53 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("INVALID_INTEGER", field)
    return value


def _timestamp(value, field):
    if type(value) is not str or len(value) > 40:
        _fail("INVALID_TIMESTAMP", field)
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() is None:
            raise ValueError()
    except ValueError:
        _fail("INVALID_TIMESTAMP", field)
    return value


def _object(value, field, required, optional=()):
    if type(value) is not dict:
        _fail("INVALID_CONTRACT", field)
    for key in value:
        if key not in (*required, *optional):
            _fail("UNKNOWN_FIELD", f"{field}.{key}")
    for key in required:
        if key not in value:
            _fail("MISSING_FIELD", f"{field}.{key}")
    return value


def _array(value, field, limit, nonempty=False):
    if type(value) is not list or len(value) > limit or (nonempty and not value):
        _fail("INVALID_CONTRACT", field)
    return value


def _reject_reserved(value, field="$", depth=0, extra=()):
    """Caller payloads never carry scope, service identities or generated state."""
    if depth > 16:
        _fail("INVALID_CONTRACT", field)
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not TOKEN.fullmatch(key):
                _fail("INVALID_CONTRACT", field)
            if key in RESERVED_KEYS or key in extra:
                _fail("CALLER_AUTHORITY", f"{field}.{key}")
            _reject_reserved(item, f"{field}.{key}", depth + 1, extra)
    elif type(value) is list:
        for index, item in enumerate(value):
            _reject_reserved(item, f"{field}[{index}]", depth + 1, extra)
    elif not (value is None or type(value) in (bool, int, float, str)):
        _fail("INVALID_CONTRACT", field)


# --- Settings admission ----------------------------------------------------

def _git_target(value):
    """Canonical Git target distinct from service-owned writable directories."""
    _text(value, "repository.target", 512)
    if value.startswith("git+"):
        value = value[4:]
    if not value.startswith(("https://", "ssh://")):
        _fail("UNSAFE_TARGET", "repository.target")
    scheme, _, rest = value.partition("://")
    authority, slash, path = rest.partition("/")
    if not slash or not path or path.endswith("/") or ".." in path.split("/"):
        _fail("UNSAFE_TARGET", "repository.target")
    if any(c in value for c in "?#"):
        _fail("UNSAFE_TARGET", "repository.target")
    user, _, host = authority.rpartition("@")
    if scheme == "ssh" and not user:
        _fail("UNSAFE_TARGET", "repository.target")
    if scheme == "https" and (user or "@" in authority):
        _fail("UNSAFE_TARGET", "repository.target")
    host, colon, port = host.partition(":")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host) or ".." in host:
        _fail("UNSAFE_TARGET", "repository.target")
    if colon and (not port.isdigit() or not 1 <= int(port) <= 65535):
        _fail("UNSAFE_TARGET", "repository.target")
    return value


def _branch(value):
    if (type(value) is not str or not BRANCH.fullmatch(value) or value.startswith(("-", "/", "."))
            or value.endswith(("/", ".", ".lock")) or ".." in value or "//" in value):
        _fail("UNSAFE_BRANCH", "repository.branch")
    return value


def _egress(value):
    _object(value, "egress", ("project_id", "model_profile_ref", "approval_ref"))
    return {"project_id": _identifier(value["project_id"], "egress.project_id"),
            "model_profile_ref": _token(value["model_profile_ref"], "egress.model_profile_ref"),
            "approval_ref": _token(value["approval_ref"], "egress.approval_ref")}


def admit_settings(source, *, egress_approvals=()):
    """Validate one complete active settings document; no defaults, no effects.

    Repository target/branch/credential/qualification, the selected model
    profile and its qualification, and per-Project hosted-egress approvals are
    distinct inputs. Reference IDs are not proof of qualification: nothing here
    authenticates, provisions or authorizes the referenced service or provider.
    """
    raw = source.read(MAX_SETTINGS_BYTES + 1) if hasattr(source, "read") else None
    if type(raw) is not str:
        _fail("INVALID_SETTINGS")
    try:
        if len(raw.encode("utf-8")) > MAX_SETTINGS_BYTES:
            _fail("SETTINGS_TOO_LARGE")
    except UnicodeError:
        _fail("INVALID_SETTINGS")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except LibraryError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        _fail("INVALID_SETTINGS")
    _object(document, "$", ("version", "repository", "model", "limits"))
    if type(document["version"]) is not int or document["version"] != SETTINGS_VERSION:
        _fail("UNSUPPORTED_SETTINGS_VERSION", "$.version")

    repository = _object(document["repository"], "repository",
                         ("target", "branch", "credential_ref", "qualification_ref"))
    model = _object(document["model"], "model",
                    ("profile_ref", "placement", "qualification_ref"))
    if model["placement"] not in ("local", "hosted"):
        _fail("UNSAFE_SETTING", "model.placement")
    limits = _object(document["limits"], "limits", tuple(MAXIMA))
    admitted = {key: _integer(limits[key], "limits." + key, maximum=MAXIMA[key])
                for key in MAXIMA}
    if admitted["batch_bytes"] < admitted["body_bytes"]:
        _fail("CONFLICTING_SETTING", "limits.batch_bytes")
    if admitted["payload_bytes"] < admitted["body_bytes"]:
        _fail("CONFLICTING_SETTING", "limits.payload_bytes")

    normalized = {
        "version": SETTINGS_VERSION,
        "repository": {
            "target": _git_target(repository["target"]),
            "branch": _branch(repository["branch"]),
            "credential_ref": _token(repository["credential_ref"], "repository.credential_ref"),
            "qualification_ref": _token(repository["qualification_ref"], "repository.qualification_ref"),
        },
        "model": {
            "profile_ref": _token(model["profile_ref"], "model.profile_ref"),
            "placement": model["placement"],
            "qualification_ref": _token(model["qualification_ref"], "model.qualification_ref"),
        },
        "limits": admitted,
    }
    egress = {}
    for index, item in enumerate(egress_approvals):
        approval = _egress(item)
        if approval["model_profile_ref"] != normalized["model"]["profile_ref"]:
            _fail("CONFLICTING_EGRESS", f"egress_approvals[{index}]")
        previous = egress.get(approval["project_id"])
        if previous is not None and previous != approval:
            _fail("CONFLICTING_EGRESS", f"egress_approvals[{index}]")
        egress[approval["project_id"]] = approval
    normalized["egress"] = [egress[key] for key in sorted(egress)]
    normalized["settings_id"] = _digest({key: normalized[key]
                                         for key in ("version", "repository", "model", "limits")})
    return normalized


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail("DUPLICATE_FIELD", f"$.{key}")
        result[key] = value
    return result


def egress_approval(settings, project_id):
    """Project-authorized hosted-egress approval, never implied by settings."""
    _identifier(project_id, "project_id")
    for approval in settings["egress"]:
        if approval["project_id"] == project_id:
            return dict(approval)
    _fail("EGRESS_NOT_AUTHORIZED", "project_id")


# --- Trusted scope ---------------------------------------------------------

@dataclass(frozen=True)
class LibraryScope:
    """Authority-derived scope. Construct only through a trusted constructor."""
    subject: str
    actor_id: str
    authority_version: str
    capabilities: tuple
    project_id: str | None = None
    project_identity: str | None = None
    reference_root: str | None = None
    participant_id: str | None = None
    human_id: str | None = None

    def __post_init__(self):
        if self.subject not in SUBJECTS:
            _fail("INVALID_SCOPE", "subject")
        _token(self.actor_id, "actor_id")
        _token(self.authority_version, "authority_version")
        if type(self.capabilities) is not tuple or not self.capabilities:
            _fail("INVALID_SCOPE", "capabilities")
        for capability in self.capabilities:
            _token(capability, "capabilities")
        if self.subject == "operator":
            if self.project_id is not None or self.project_identity is not None:
                _fail("INVALID_SCOPE", "project_id")
            if SETTINGS_CAPABILITY not in self.capabilities:
                _fail("FORBIDDEN", "capabilities")
        else:
            _identifier(self.project_id, "project_id")
            _token(self.project_identity, "project_identity")
            if self.reference_root is None or not _absolute(self.reference_root):
                _fail("INVALID_SCOPE", "reference_root")
        if self.subject == "participant" and self.participant_id is None:
            _fail("INVALID_SCOPE", "participant_id")
        if self.subject == "human" and self.human_id is None:
            _fail("INVALID_SCOPE", "human_id")

    def canonical(self):
        return {"subject": self.subject, "actor_id": self.actor_id,
                "authority_version": self.authority_version,
                "capabilities": list(self.capabilities),
                "project_id": self.project_id, "project_identity": self.project_identity,
                "reference_root": self.reference_root,
                "participant_id": self.participant_id, "human_id": self.human_id}


def _absolute(value):
    return (type(value) is str and value.startswith("/") and value != "/"
            and ".." not in value.split("/") and posixpath.normpath(value) == value)


def project_binding(project):
    """Derive the Library binding from the trusted configured Room Project."""
    if type(project) is not dict:
        _fail("INVALID_BINDING", "project")
    project_id = _identifier(project.get("id"), "project.id")
    repository = project.get("repository")
    if type(repository) is not str or not REPOSITORY.fullmatch(repository):
        _fail("INVALID_BINDING", "project.repository")
    roots = project.get("roots")
    if type(roots) is not dict or not _absolute(roots.get("reference")):
        _fail("INVALID_BINDING", "project.roots.reference")
    reference = roots["reference"].rstrip("/") or "/"
    if reference == "/":
        _fail("INVALID_BINDING", "project.roots.reference")
    return {"project_id": project_id,
            "project_identity": "github.com/" + repository,
            "reference_root": reference + "/library",
            "snapshot_path": reference + "/library.snapshot.json"}


def participant_scope(origin, *, binding):
    if type(origin) is not Origin:
        _fail("LIBRARY_AUTHENTICATION_REQUIRED", "origin")
    if ENQUEUE_CAPABILITY not in origin.capabilities:
        _fail("FORBIDDEN", "capabilities")
    return LibraryScope(subject="participant", actor_id=origin.actor_id,
                        authority_version=origin.authority_version,
                        capabilities=tuple(origin.capabilities),
                        project_id=binding["project_id"],
                        project_identity=binding["project_identity"],
                        reference_root=binding["reference_root"],
                        participant_id=origin.participant_id)


def human_scope(session, *, binding, kind):
    """One exact human action, freshly allowed by the Manager authority seam."""
    if type(session) is not HumanSession:
        _fail("LIBRARY_AUTHENTICATION_REQUIRED", "session")
    if kind not in HUMAN_KINDS:
        _fail("UNKNOWN_OPERATION", "kind")
    action = "library-" + kind
    if session.allowed(action) is not True:
        _fail("FORBIDDEN", "session")
    return LibraryScope(subject="human", actor_id=session.human.actor_id,
                        authority_version=session.human.authority_version,
                        capabilities=(action,),
                        project_id=binding["project_id"],
                        project_identity=binding["project_identity"],
                        reference_root=binding["reference_root"],
                        human_id=session.manager_id)


def installation_scope(origin):
    """Shared-settings authority: installation scope, no Project content."""
    if type(origin) is not Origin:
        _fail("LIBRARY_AUTHENTICATION_REQUIRED", "origin")
    if SETTINGS_CAPABILITY not in origin.capabilities:
        _fail("FORBIDDEN", "capabilities")
    return LibraryScope(subject="operator", actor_id=origin.actor_id,
                        authority_version=origin.authority_version,
                        capabilities=(SETTINGS_CAPABILITY,))


# --- Operation contract ----------------------------------------------------

@dataclass(frozen=True)
class Operation:
    """One typed attempt; the payload is transient content, never audit data."""
    kind: str
    operation_id: str
    request_id: str
    at: str
    payload: dict
    scope: LibraryScope
    settings_id: str
    provenance: dict
    queue_id: str | None = None

    def digest(self):
        return _digest(self.payload)

    def canonical(self):
        return {"version": CONTRACT_VERSION, "kind": self.kind,
                "operation_id": self.operation_id, "request_id": self.request_id,
                "queue_id": self.queue_id, "settings_id": self.settings_id,
                "at": self.at, "payload_digest": self.digest(),
                "scope": self.scope.canonical(), "provenance": self.provenance}

    def audit_metadata(self):
        """Safe, content-free record for ledger/audit/replay surfaces."""
        return audit_metadata({
            "operation_id": self.operation_id, "kind": self.kind,
            "request_id": self.request_id, "queue_id": self.queue_id,
            "settings_id": self.settings_id, "payload_sha256": self.digest(),
            "payload_bytes": _size(self.payload), "subject": self.scope.subject,
            "actor_id": self.scope.actor_id,
            "project_id": self.scope.project_id, "at": self.at,
        })


def _operation(kind, scope, settings, operation_id, request_id, payload, at, queue_id=None,
               provenance=None):
    _token(kind, "kind")
    _token(operation_id, "operation_id")
    _token(request_id, "request_id")
    _timestamp(at, "at")
    _digest_value(settings["settings_id"], "settings_id")
    _reject_reserved(payload)
    if _size(payload) > settings["limits"]["payload_bytes"]:
        _fail("PAYLOAD_TOO_LARGE", "payload")
    provenance = provenance or {
        "actor_id": scope.actor_id, "participant_id": scope.participant_id,
        "subject": scope.subject, "at": at, "request_id": request_id,
        "payload_sha256": _digest(payload)}
    return Operation(kind=kind, operation_id=operation_id, request_id=request_id,
                     at=at, payload=payload, scope=scope,
                     settings_id=settings["settings_id"], provenance=provenance,
                     queue_id=queue_id)


def _hosted(settings):
    return settings["model"]["placement"] == "hosted"


def _require_scope(scope, subject, capability):
    if type(scope) is not LibraryScope or scope.subject != subject:
        _fail("FORBIDDEN", "scope")
    if capability not in scope.capabilities:
        _fail("FORBIDDEN", "capabilities")


def _capture_payload(value, limits):
    _reject_reserved(value, "capture", extra=CAPTURE_IDENTITY_KEYS)
    _object(value, "capture", ("type", "title", "body"), ("sources", "hints"))
    if value["type"] not in CAPTURE_TYPES:
        _fail("UNSAFE_CAPTURE_TYPE", "capture.type")
    title = _text(value["title"], "capture.title", limits["title_chars"])
    body = _text(value["body"], "capture.body", 2**31 - 1, multiline=True)
    if len(body.encode("utf-8")) > limits["body_bytes"]:
        _fail("CAPTURE_TOO_LARGE", "capture.body")
    sources = []
    for index, item in enumerate(_array(value.get("sources", []), "capture.sources",
                                        limits["sources"])):
        field = f"capture.sources[{index}]"
        _object(item, field, ("resource",), ("title",))
        sources.append({"resource": _text(item["resource"], field + ".resource")})
        if "title" in item:
            sources[-1]["title"] = _text(item["title"], field + ".title", limits["title_chars"])
    if value["type"] == "research" and not sources:
        _fail("SOURCE_REQUIRED", "capture.sources")
    hints = []
    for index, item in enumerate(_array(value.get("hints", []), "capture.hints", 8)):
        hints.append(_text(item, f"capture.hints[{index}]", 256))
    return {"type": value["type"], "title": title, "body": body,
            "sources": sources, "hints": hints}


def capture(scope, settings, *, operation_id, request_id, value, at):
    """One Participant enqueue attempt. Scope comes from the trusted badge only."""
    _require_scope(scope, "participant", ENQUEUE_CAPABILITY)
    payload = _capture_payload(value, settings["limits"])
    queue_id = _digest({"version": CONTRACT_VERSION, "kind": "enqueue",
                        "request_id": request_id, "payload": payload})
    return _operation("enqueue", scope, settings, operation_id, request_id,
                      payload, at, queue_id=queue_id)


def action(scope, settings, *, kind, operation_id, request_id, payload, at):
    """One human request through the shared typed Manager seam."""
    if kind not in HUMAN_KINDS:
        _fail("UNKNOWN_OPERATION", "kind")
    _require_scope(scope, "human", "library-" + kind)
    if _hosted(settings) and kind in MODEL_KINDS:
        egress_approval(settings, scope.project_id)
    if type(payload) is not dict:
        _fail("INVALID_CONTRACT", "payload")
    _reject_reserved(payload)
    if kind in FENCED_KINDS:
        _digest_value(payload.get("observed_version"), "payload.observed_version")
    if kind in DRAIN_KINDS:
        _token(payload.get("drain_id"), "payload.drain_id")
    if kind in ITEM_KINDS:
        _token(payload.get("queue_id"), "payload.queue_id")
    return _operation(kind, scope, settings, operation_id, request_id, payload, at)


def settings_change(scope, settings, *, operation_id, request_id, document, at,
                    egress_approvals=()):
    """Installation-settings authority only; egress stays a separate approval."""
    _require_scope(scope, "operator", SETTINGS_CAPABILITY)
    if not hasattr(document, "read"):
        _fail("INVALID_SETTINGS")
    candidate = admit_settings(document, egress_approvals=egress_approvals)
    if candidate["settings_id"] == settings["settings_id"]:
        _fail("UNCHANGED_SETTINGS")
    payload = {"next_settings_id": candidate["settings_id"],
               "repository": candidate["repository"], "model": candidate["model"],
               "limits": candidate["limits"]}
    return _operation("settings-update", scope, settings, operation_id, request_id,
                      payload, at)


def retry(scope, settings, previous, *, operation_id, at):
    """New Hub Command ID, same librarian request and payload, fresh authority.

    The original submission provenance is immutable; this attempt records the
    actually authorizing actor and the configuration identity it starts under.
    """
    if type(previous) is not Operation or previous.kind != "enqueue":
        _fail("INVALID_OPERATION", "previous")
    _require_scope(scope, "participant", ENQUEUE_CAPABILITY)
    if previous.scope.project_id != scope.project_id:
        _fail("FORBIDDEN", "scope.project_id")
    if operation_id == previous.operation_id:
        _fail("ID_CONFLICT", "operation_id")
    payload = _capture_payload(previous.payload, settings["limits"])
    if _digest(payload) != previous.digest():
        _fail("INVALID_OPERATION", "payload")
    if _digest({"version": CONTRACT_VERSION, "kind": "enqueue",
                "request_id": previous.request_id, "payload": payload}) != previous.queue_id:
        _fail("INVALID_OPERATION", "queue_id")
    return _operation("enqueue", scope, settings, operation_id, previous.request_id,
                      payload, at, queue_id=previous.queue_id,
                      provenance=previous.provenance)


def identity(previous, operation):
    """Two-level idempotency: exact duplicate keeps the first result."""
    if type(previous) is not Operation or type(operation) is not Operation:
        _fail("INVALID_OPERATION")
    if previous.kind != operation.kind:
        _fail("INVALID_OPERATION", "kind")
    same_id = previous.operation_id == operation.operation_id
    same_payload = previous.digest() == operation.digest()
    if same_id:
        if previous.canonical() != operation.canonical():
            _fail("ID_CONFLICT", "operation_id")
        return "DUPLICATE"
    if previous.request_id == operation.request_id and not same_payload:
        _fail("ID_CONFLICT", "request_id")
    if previous.queue_id is not None and previous.queue_id != operation.queue_id:
        _fail("ID_CONFLICT", "queue_id")
    return "RETRY"


# --- Outcome and receipt contract -----------------------------------------

def queue_path(project_identity, queue_id):
    """Bundle-relative draft path derived from validated identity, no traversal."""
    if (type(project_identity) is not str or not project_identity
            or any(part in ("", ".", "..") for part in project_identity.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in project_identity)):
        _fail("INVALID_PROJECT_IDENTITY", "project_identity")
    return "projects/" + project_identity + "/pending/" + _digest_value(queue_id, "queue_id") + ".md"


def receipt(operation, outcome, *, at, publication=None, projection=None,
            reason=None, retryable=None):
    """Build the typed result for one operation; no content or secret fields.

    ``drain_id`` is a reference read from the validated payload, never a claim.
    The returned value is re-admitted so a builder cannot emit what a receiver
    would refuse.
    """
    if type(operation) is not Operation:
        _fail("INVALID_OPERATION")
    if retryable is None:
        retryable = False
    if outcome == "NOT_DURABLE":
        retryable = True
    return admit_receipt({
        "version": CONTRACT_VERSION, "operation_id": operation.operation_id,
        "kind": operation.kind, "request_id": operation.request_id,
        "queue_id": operation.queue_id,
        "drain_id": operation.payload.get("drain_id"),
        "settings_id": operation.settings_id, "outcome": outcome, "at": at,
        "publication": publication, "projection": projection,
        "reason": reason, "retryable": retryable})


def admit_receipt(value):
    """Validate a received receipt; a claim is not publication or visibility."""
    _object(value, "$", ("version", "operation_id", "kind", "request_id", "queue_id",
                         "drain_id", "settings_id", "outcome", "at", "publication",
                         "projection", "reason", "retryable"))
    if type(value["version"]) is not int or value["version"] != CONTRACT_VERSION:
        _fail("UNSUPPORTED_CONTRACT_VERSION", "$.version")
    _token(value["kind"], "kind")
    _token(value["operation_id"], "operation_id")
    _token(value["request_id"], "request_id")
    if value["queue_id"] is not None:
        _digest_value(value["queue_id"], "queue_id")
    if value["drain_id"] is not None:
        _token(value["drain_id"], "drain_id")
    _digest_value(value["settings_id"], "settings_id")
    outcome = value["outcome"]
    if outcome not in OUTCOMES:
        _fail("UNKNOWN_OUTCOME", "outcome")
    _timestamp(value["at"], "at")
    if type(value["retryable"]) is not bool:
        _fail("INVALID_OUTCOME", "retryable")
    if (outcome == "NOT_DURABLE") != value["retryable"]:
        _fail("INVALID_OUTCOME", "retryable")
    if outcome in ("DURABLY_QUEUED", "COMMITTED"):
        if value["reason"] is not None:
            _token(value["reason"], "reason")
    else:
        _token(value["reason"], "reason")
    durable = outcome in ("DURABLY_QUEUED", "COMMITTED")
    publication = value["publication"]
    if durable:
        if type(publication) is not dict:
            _fail("PUBLICATION_REQUIRED", "publication")
        _object(publication, "publication", ("commit_sha", "path"))
        _commit(publication["commit_sha"], "publication.commit_sha")
        _text(publication["path"], "publication.path", 4096)
        if outcome == "DURABLY_QUEUED" and value["queue_id"] is not None:
            if not publication["path"].endswith("/pending/" + value["queue_id"] + ".md"):
                _fail("INVALID_PUBLICATION", "publication.path")
    elif publication is not None:
        _fail("INVALID_OUTCOME", "publication")
    if value["projection"] is not None:
        projection = value["projection"]
        if type(projection) is not dict:
            _fail("INVALID_PROJECTION", "projection")
        _object(projection, "projection", ("commit_sha", "visible"))
        _commit(projection["commit_sha"], "projection.commit_sha", allow_none=True)
        if type(projection["visible"]) is not bool:
            _fail("INVALID_PROJECTION", "projection.visible")
        if projection["visible"] and not durable:
            _fail("INVALID_PROJECTION", "projection.commit_sha")
        if (projection["visible"]
                and projection["commit_sha"] != publication["commit_sha"]):
            _fail("INVALID_PROJECTION", "projection.commit_sha")
    if _size(value) > MAX_AUDIT_BYTES * 8:
        _fail("RECEIPT_TOO_LARGE")
    return value


# --- Projection snapshot contract -----------------------------------------

def snapshot(value):
    """The supervisor-published manifest; null commit means no first publication."""
    _object(value, "snapshot", ("version", "project_id", "project_identity",
                                "commit_sha", "published_at"))
    if type(value["version"]) is not int or value["version"] != CONTRACT_VERSION:
        _fail("UNSUPPORTED_CONTRACT_VERSION", "snapshot.version")
    project_id = _identifier(value["project_id"], "snapshot.project_id")
    identity = _token(value["project_identity"], "snapshot.project_identity", 256)
    if any(part in ("", ".", "..") for part in identity.split("/")):
        _fail("INVALID_PROJECT_IDENTITY", "snapshot.project_identity")
    commit_sha = _commit(value["commit_sha"], "snapshot.commit_sha", allow_none=True)
    published_at = value["published_at"]
    if commit_sha is None:
        if published_at is not None:
            _fail("INCOHERENT_SNAPSHOT", "snapshot.published_at")
    else:
        _timestamp(published_at, "snapshot.published_at")
    return {"version": CONTRACT_VERSION, "project_id": project_id,
            "project_identity": identity, "commit_sha": commit_sha,
            "published_at": published_at}


def projection(snapshot_value, *, bundle_present, bundle_commit_sha=None):
    """One coherent published pair; a failed refresh never fabricates a bundle."""
    manifest = snapshot(snapshot_value)
    if type(bundle_present) is not bool:
        _fail("INVALID_PROJECTION", "bundle_present")
    if manifest["commit_sha"] is None:
        if bundle_present:
            _fail("INCOHERENT_PROJECTION", "bundle_present")
    else:
        if not bundle_present:
            _fail("INCOHERENT_PROJECTION", "bundle_present")
        if _commit(bundle_commit_sha, "bundle_commit_sha") != manifest["commit_sha"]:
            _fail("INCOHERENT_PROJECTION", "bundle_commit_sha")
    return {"project_id": manifest["project_id"],
            "commit_sha": manifest["commit_sha"],
            "published_at": manifest["published_at"],
            "visible": bundle_present}


# --- Model proposal contract ----------------------------------------------

def admit_proposal(value, *, drain_id, queue_ids, limits):
    """Strict proposal manifest: typed content only, never a Git diff or patch."""
    _token(drain_id, "drain_id")
    if type(queue_ids) not in (list, tuple) or not queue_ids:
        _fail("INVALID_CONTRACT", "queue_ids")
    batch = []
    for index, queue_id in enumerate(queue_ids):
        batch.append(_digest_value(queue_id, f"queue_ids[{index}]"))
    if len(set(batch)) != len(batch):
        _fail("INVALID_CONTRACT", "queue_ids")
    _object(value, "proposal", ("version", "drain_id", "attempt", "operations"))
    if type(value["version"]) is not int or value["version"] != CONTRACT_VERSION:
        _fail("UNSUPPORTED_CONTRACT_VERSION", "proposal.version")
    if _token(value["drain_id"], "proposal.drain_id") != drain_id:
        _fail("PROPOSAL_BATCH_MISMATCH", "proposal.drain_id")
    attempt = _integer(value["attempt"], "proposal.attempt")
    operations = _array(value["operations"], "proposal.operations",
                        MAX_PROPOSAL_OPERATIONS, nonempty=True)
    normalized, parked = [], set()
    for index, item in enumerate(operations):
        field = f"proposal.operations[{index}]"
        if type(item) is not dict or "op" not in item:
            _fail("INVALID_CONTRACT", field)
        op = item["op"]
        if op not in PROPOSAL_OPERATIONS:
            _fail("UNSAFE_PROPOSAL_OPERATION", field + ".op")
        if op == "park":
            _object(item, field, ("op", "queue_id", "reason"))
            queue_id = _digest_value(item["queue_id"], field + ".queue_id")
            if queue_id not in batch:
                _fail("PROPOSAL_BATCH_MISMATCH", field + ".queue_id")
            if queue_id in parked:
                _fail("PROPOSAL_BATCH_MISMATCH", field + ".queue_id")
            parked.add(queue_id)
            normalized.append({"op": "park", "queue_id": queue_id,
                               "reason": _token(item["reason"], field + ".reason")})
            continue
        _object(item, field, ("op", "path", "type", "title", "body"), ("sources",))
        path = _concept_path(item["path"], field + ".path")
        if item["type"] not in CAPTURE_TYPES:
            _fail("UNSAFE_CAPTURE_TYPE", field + ".type")
        title = _text(item["title"], field + ".title", limits["title_chars"])
        body = _text(item["body"], field + ".body", 2**31 - 1, multiline=True)
        if len(body.encode("utf-8")) > limits["body_bytes"]:
            _fail("CAPTURE_TOO_LARGE", field + ".body")
        sources = []
        for source_index, source in enumerate(_array(item.get("sources", []),
                                                     field + ".sources", limits["sources"])):
            source_field = f"{field}.sources[{source_index}]"
            _object(source, source_field, ("resource",), ("title",))
            sources.append({"resource": _text(source["resource"], source_field + ".resource")})
            if "title" in source:
                sources[-1]["title"] = _text(source["title"], source_field + ".title",
                                             limits["title_chars"])
        normalized.append({"op": op, "path": path, "type": item["type"],
                           "title": title, "body": body, "sources": sources})
    return {"version": CONTRACT_VERSION, "drain_id": drain_id, "attempt": attempt,
            "operations": normalized}


def _concept_path(value, field):
    if type(value) is not str or "\\" in value or value.startswith("/") or value.endswith("/"):
        _fail("UNSAFE_PROPOSAL_PATH", field)
    parts = value.split("/")
    if len(parts) != 2 or parts[0] not in CONCEPT_DIRECTORIES:
        _fail("UNSAFE_PROPOSAL_PATH", field)
    name = parts[1]
    if not name.endswith(".md") or name == "index.md":
        _fail("UNSAFE_PROPOSAL_PATH", field)
    if not SLUG.fullmatch(name[:-3]):
        _fail("UNSAFE_PROPOSAL_PATH", field)
    if posixpath.normpath(value) != value:
        _fail("UNSAFE_PROPOSAL_PATH", field)
    return value


# --- Observation and safe metadata ---------------------------------------

def observation(value):
    """Literal, source-tagged, timestamped fact; never an inferred clean state."""
    _object(value, "observation", ("version", "owner", "subject", "state", "observed_at"),
            ("reason",))
    if type(value["version"]) is not int or value["version"] != CONTRACT_VERSION:
        _fail("UNSUPPORTED_CONTRACT_VERSION", "observation.version")
    if value["state"] not in OBSERVATION_STATES:
        _fail("INVALID_OBSERVATION", "observation.state")
    record = {"version": CONTRACT_VERSION,
              "owner": _token(value["owner"], "observation.owner"),
              "subject": _token(value["subject"], "observation.subject"),
              "state": value["state"],
              "observed_at": _timestamp(value["observed_at"], "observation.observed_at"),
              "reason": None if value.get("reason") is None
              else _token(value["reason"], "observation.reason")}
    return record


def audit_metadata(value):
    """Bounded trusted metadata record; transient content and secrets are refused."""
    _reject_content(value)
    if _size(value) > MAX_AUDIT_BYTES:
        _fail("AUDIT_TOO_LARGE")
    return value


def _reject_content(value, field="$", depth=0):
    if depth > 8:
        _fail("INVALID_CONTRACT", field)
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not TOKEN.fullmatch(key):
                _fail("INVALID_CONTRACT", field)
            if key in CONTENT_KEYS:
                _fail("CONTENT_NOT_ALLOWED", f"{field}.{key}")
            _reject_content(item, f"{field}.{key}", depth + 1)
    elif type(value) is list:
        for index, item in enumerate(value):
            _reject_content(item, f"{field}[{index}]", depth + 1)
    elif not (value is None or type(value) in (bool, int, float, str)):
        _fail("INVALID_CONTRACT", field)
