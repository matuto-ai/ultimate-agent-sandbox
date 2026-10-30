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

from dataclasses import dataclass, field
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

ENQUEUE_CAPABILITY = "library:enqueue"
SETTINGS_CAPABILITY = "library-settings"
SUBJECTS = ("participant", "human", "operator")
CAPTURE_TYPES = ("context", "decision", "research")
OUTCOMES = {
    "DURABLY_QUEUED", "REJECTED", "NOT_DURABLE", "COMMITTED",
    "CONFIGURED", "ACKNOWLEDGED", "REFUSED", "BUSY", "STALE", "UNKNOWN",
}
CONTENT_OUTCOMES = ("DURABLY_QUEUED", "COMMITTED")
OBSERVATION_STATES = {"healthy", "stale", "disconnected", "unknown", "blocked"}
FILTER_MODES = ("observe", "block")
INITIAL_FILTERS = {"high_confidence": "block", "heuristic": "observe"}
# Fixed typed payload per human operation: (required, optional) fields. Nothing
# else reaches the service, so a caller cannot assert a commit, outcome or path.
HUMAN_PAYLOADS = {
    "register": ((), ()),
    "relocate": ((), ()),
    "import-preview": (("source_commit", "paths"), ("types",)),
    "import-confirm": (("preview_id", "source_commit", "paths", "observed_version"), ("types",)),
    "inspect": (("queue_id", "observed_version"), ("drain_id",)),
    "drain": (("observed_version",), ()),
    "retry": (("drain_id", "observed_version"), ()),
    "defer": (("drain_id", "observed_version"), ()),
    "requeue": (("drain_id", "observed_version"), ()),
    "resume": (("drain_id", "observed_version"), ("queue_ids",)),
    "reject": (("drain_id", "queue_id", "reason", "observed_version"), ()),
    "adjudicate": (("drain_id", "queue_id", "conclusion", "rationale",
                    "observed_version"), ()),
    "scan": (("observed_version",), ()),
    "repair": (("observed_version",), ()),
    "archive": (("observed_version",), ()),
    "restore": (("observed_version",), ()),
}
HUMAN_KINDS = set(HUMAN_PAYLOADS)
# Only these operations reach a model, so only they need hosted-egress approval.
MODEL_KINDS = {"drain", "retry", "archive"}
PROPOSAL_OPERATIONS = {"create", "update", "deprecate", "park"}
CONCEPT_DIRECTORIES = ("context", "decisions", "research")

# Fixed crash-protection maxima. They are constants, not settings: an operator
# cannot raise them and admission refuses any value above them.
MAXIMA = {
    "request_files": 512,
    "request_bytes": 2097152,
    "request_tokens": 524288,
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
    "result_count": 64,
}
# Published starting values. Admission never substitutes them for a missing
# setting; a deployment supplies every one of them explicitly.
INITIAL_LIMITS = {
    "request_files": 64,
    "request_bytes": 131072,
    "request_tokens": 32768,
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
    "result_count": 8,
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
    """Stable code plus safe field path; never echoes input values or secrets.

    ``evidence`` carries optional rule/location/hash facts about the refusal
    (for example a credential rule name, its document line and a digest of the
    matched bytes) so a record can correlate refusals without the secret.
    """

    def __init__(self, code: str, field: str = "$", evidence=None):
        self.code, self.field = code, field
        self.evidence = evidence
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
        if len(value) > 4096:
            _fail("INVALID_CONTRACT", field)
        for key, item in value.items():
            if type(key) is not str or not TOKEN.fullmatch(key):
                _fail("INVALID_CONTRACT", field)
            if key in RESERVED_KEYS or key in extra:
                _fail("CALLER_AUTHORITY", f"{field}.{key}")
            _reject_reserved(item, f"{field}.{key}", depth + 1, extra)
    elif type(value) is list:
        if len(value) > 4096:
            _fail("INVALID_CONTRACT", field)
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
    if scheme == "ssh" and (not user or ":" in user
                            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user)):
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
    if (type(value) is not str or not BRANCH.fullmatch(value)
            or value.startswith(("-", "/")) or value.endswith(("/", "."))
            or ".." in value or "//" in value):
        _fail("UNSAFE_BRANCH", "repository.branch")
    for part in value.split("/"):
        if not part or part.startswith(".") or part.endswith(".lock"):
            _fail("UNSAFE_BRANCH", "repository.branch")
    return value


def _egress(value):
    _object(value, "egress", ("project_id", "model_profile_ref", "approval_ref"))
    return {"project_id": _identifier(value["project_id"], "egress.project_id"),
            "model_profile_ref": _token(value["model_profile_ref"], "egress.model_profile_ref"),
            "approval_ref": _token(value["approval_ref"], "egress.approval_ref")}


CORE_SETTINGS = ("version", "repository", "model", "filters", "limits")


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
    normalized = _settings_core(document)
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
    normalized["settings_id"] = _settings_id(normalized)
    return normalized


def _settings_id(normalized):
    return _digest({key: normalized[key] for key in CORE_SETTINGS})


def _settings_core(document):
    """Validate and normalize the five shared settings namespaces."""
    _object(document, "$", CORE_SETTINGS)
    if type(document["version"]) is not int or document["version"] != SETTINGS_VERSION:
        _fail("UNSUPPORTED_SETTINGS_VERSION", "$.version")

    repository = _object(document["repository"], "repository",
                         ("target", "branch", "credential_ref", "qualification_ref"))
    model = _object(document["model"], "model",
                    ("profile_ref", "placement", "qualification_ref"))
    if model["placement"] not in ("local", "hosted"):
        _fail("UNSAFE_SETTING", "model.placement")
    filters = _object(document["filters"], "filters", tuple(INITIAL_FILTERS))
    for name in INITIAL_FILTERS:
        if filters[name] not in FILTER_MODES:
            _fail("UNSAFE_SETTING", "filters." + name)
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
        "filters": {name: filters[name] for name in INITIAL_FILTERS},
        "limits": admitted,
    }
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


@dataclass(frozen=True)
class CaptureResult:
    outcome: str
    request_id: str | None
    reason: str | None
    retryable: bool
    queue_id: str | None = None
    path: str | None = None  # bundle-relative; never a caller-selected path
    published_sha: str | None = None
    projection_sha: str | None = None
    visible: bool = False



# --- Trusted scope ---------------------------------------------------------

_SCOPE_SEAL = object()


class LibraryScope:
    """Authority-derived scope; only the constructors below can mint one.

    A scope is immutable and never deserialized: it is built from an already
    authenticated Origin, Manager HumanSession or installation-authority Origin.
    """
    __slots__ = ("subject", "actor_id", "authority_version", "capabilities",
                 "project_id", "project_identity", "project_path",
                 "reference_root", "participant_id", "human_id")

    def __init__(self, *, seal, subject, actor_id, authority_version, capabilities,
                 project_id=None, project_identity=None, project_path=None,
                 reference_root=None, participant_id=None, human_id=None):
        if seal is not _SCOPE_SEAL:
            _fail("INVALID_SCOPE", "seal")
        for name, value in (("subject", subject), ("actor_id", actor_id),
                            ("authority_version", authority_version)):
            object.__setattr__(self, name, value)
        if type(capabilities) is not tuple or not capabilities:
            _fail("INVALID_SCOPE", "capabilities")
        for capability in capabilities:
            _token(capability, "capabilities")
        object.__setattr__(self, "capabilities", capabilities)
        for name, value in (("project_id", project_id),
                            ("project_identity", project_identity),
                            ("project_path", project_path),
                            ("reference_root", reference_root),
                            ("participant_id", participant_id),
                            ("human_id", human_id)):
            object.__setattr__(self, name, value)
        if self.subject not in SUBJECTS:
            _fail("INVALID_SCOPE", "subject")
        _token(self.actor_id, "actor_id")
        _token(self.authority_version, "authority_version")
        if self.subject == "operator":
            if (self.project_id is not None or self.project_identity is not None
                    or self.project_path is not None):
                _fail("INVALID_SCOPE", "project_id")
            if SETTINGS_CAPABILITY not in self.capabilities:
                _fail("FORBIDDEN", "capabilities")
        else:
            _identifier(self.project_id, "project_id")
            _token(self.project_identity, "project_identity")
            path = _token(self.project_path, "project_path", 256)
            if any(part in ("", ".", "..") for part in path.split("/")):
                _fail("INVALID_SCOPE", "project_path")
            if self.reference_root is None or not _absolute(self.reference_root):
                _fail("INVALID_SCOPE", "reference_root")
        if self.subject == "participant" and self.participant_id is None:
            _fail("INVALID_SCOPE", "participant_id")
        if self.subject == "human" and self.human_id is None:
            _fail("INVALID_SCOPE", "human_id")

    def __setattr__(self, name, value):
        raise AttributeError("LibraryScope is immutable")

    def __repr__(self):
        return "LibraryScope(%s, %s)" % (self.subject, self.actor_id)

    def canonical(self):
        return {"subject": self.subject, "actor_id": self.actor_id,
                "authority_version": self.authority_version,
                "capabilities": list(self.capabilities),
                "project_id": self.project_id, "project_identity": self.project_identity,
                "project_path": self.project_path,
                "reference_root": self.reference_root,
                "participant_id": self.participant_id, "human_id": self.human_id}


def _absolute(value):
    return (type(value) is str and value.startswith("/") and value != "/"
            and ".." not in value.split("/") and posixpath.normpath(value) == value)


def project_binding(project, *, source_identity):
    """Derive the Library binding from the trusted configured Room Project.

    Registration identity is the source Forge host plus the immutable source
    repository identity, so a rename or transfer keeps project identity, queue
    identity and deduplication stable. Current ``repository`` coordinates only
    establish the human-readable bundle path. The main product is GitHub-first,
    so the source host is fixed; Library hosting stays independent of it.
    """
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
    identity = _token(source_identity, "source_identity", 128)
    return {"project_id": project_id,
            "project_identity": "github.com/" + identity,
            "project_path": "github.com/" + repository,
            "reference_root": reference + "/library",
            "snapshot_path": reference + "/library.snapshot.json"}


def participant_scope(origin, *, binding):
    if type(origin) is not Origin:
        _fail("LIBRARY_AUTHENTICATION_REQUIRED", "origin")
    if ENQUEUE_CAPABILITY not in origin.capabilities:
        _fail("FORBIDDEN", "capabilities")
    return LibraryScope(seal=_SCOPE_SEAL, subject="participant", actor_id=origin.actor_id,
                        authority_version=origin.authority_version,
                        capabilities=tuple(origin.capabilities),
                        project_id=binding["project_id"],
                        project_identity=binding["project_identity"],
                        project_path=binding["project_path"],
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
    return LibraryScope(seal=_SCOPE_SEAL, subject="human", actor_id=session.human.actor_id,
                        authority_version=session.human.authority_version,
                        capabilities=(action,),
                        project_id=binding["project_id"],
                        project_identity=binding["project_identity"],
                        project_path=binding["project_path"],
                        reference_root=binding["reference_root"],
                        human_id=session.manager_id)


def installation_scope(origin):
    """Shared-settings authority: installation scope, no Project content."""
    if type(origin) is not Origin:
        _fail("LIBRARY_AUTHENTICATION_REQUIRED", "origin")
    if SETTINGS_CAPABILITY not in origin.capabilities:
        _fail("FORBIDDEN", "capabilities")
    return LibraryScope(seal=_SCOPE_SEAL, subject="operator", actor_id=origin.actor_id,
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
    drain_id: str | None = None
    manifest: dict | None = None

    def digest(self):
        return _digest(self.payload)

    def canonical(self):
        # Mutable bundle coordinates are excluded: a rename must not change
        # deduplication identity for the same immutable Project identity.
        scope = self.scope.canonical()
        scope.pop("project_path", None)
        result = {"version": CONTRACT_VERSION, "kind": self.kind,
                "operation_id": self.operation_id, "request_id": self.request_id,
                "queue_id": self.queue_id, "drain_id": self.drain_id,
                "settings_id": self.settings_id,
                "at": self.at, "payload_digest": self.digest(),
                "scope": scope, "provenance": self.provenance}
        if self.manifest is not None:
            result["manifest"] = operation_manifest(self.kind, self.manifest)
        return result

    def audit_metadata(self):
        """Safe, content-free record for ledger/audit/replay surfaces."""
        return audit_metadata({
            "operation_id": self.operation_id, "kind": self.kind,
            "request_id": self.request_id, "queue_id": self.queue_id,
            "settings_id": self.settings_id, "payload_sha256": self.digest(),
            "payload_bytes": _size(self.payload), "subject": self.scope.subject,
            "actor_id": self.scope.actor_id,
            "project_id": self.scope.project_id,
            "project_path": self.scope.project_path, "at": self.at,
        })


def _operation(kind, scope, settings, operation_id, request_id, payload, at, queue_id=None,
               drain_id=None, provenance=None):
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
                     queue_id=queue_id, drain_id=drain_id)


def admit_settings_value(settings):
    """Revalidate an already admitted settings value at a consumer's start."""
    return _settings(settings)


def _settings(settings):
    """Revalidate an admitted settings value and its identity at operation start.

    Values are re-admitted, not merely key-checked, and the recomputed digest
    must equal the operation-start identity the caller passes on. Egress
    approvals are rechecked against the currently selected model profile so a
    later profile change cannot reuse an approval for a different one.
    """
    if type(settings) is not dict:
        _fail("INVALID_SETTINGS", "settings")
    core = _settings_core({key: settings.get(key) for key in CORE_SETTINGS})
    _digest_value(settings.get("settings_id"), "settings.settings_id")
    if _settings_id(core) != settings["settings_id"]:
        _fail("CONFIGURATION_MISMATCH", "settings.settings_id")
    if type(settings.get("egress")) is not list:
        _fail("INVALID_SETTINGS", "settings.egress")
    egress = {}
    for item in settings["egress"]:
        approval = _egress(item)
        if approval["model_profile_ref"] != core["model"]["profile_ref"]:
            _fail("CONFLICTING_EGRESS", "settings.egress")
        previous = egress.get(approval["project_id"])
        if previous is not None and previous != approval:
            _fail("CONFLICTING_EGRESS", "settings.egress")
        egress[approval["project_id"]] = approval
    return settings


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
        _object(item, field, ("resource",), ("title", "range", "sha256"))
        sources.append({"resource": _text(item["resource"], field + ".resource")})
        if "title" in item:
            sources[-1]["title"] = _text(item["title"], field + ".title", limits["title_chars"])
        if ("range" in item) != ("sha256" in item):
            _fail("INCOMPLETE_EXCERPT", field)
        if "range" in item:
            span = _text(item["range"], field + ".range", 24)
            if not re.fullmatch(r"[1-9][0-9]*-[1-9][0-9]*", span):
                _fail("INVALID_EXCERPT_RANGE", field)
            first, last = map(int, span.split("-"))
            if not first <= last <= 2**31-1 or last-first+1 > 200:
                _fail("INVALID_EXCERPT_RANGE", field)
            _digest_value(item["sha256"], field + ".sha256")
            sources[-1].update(range=span, sha256=item["sha256"])
    if value["type"] == "research" and not sources:
        _fail("SOURCE_REQUIRED", "capture.sources")
    hints = []
    for index, item in enumerate(_array(value.get("hints", []), "capture.hints", 8)):
        hints.append(_text(item, f"capture.hints[{index}]", 256))
    return {"type": value["type"], "title": title, "body": body,
            "sources": sources, "hints": hints}


def capture(scope, settings, *, operation_id, request_id, value, at, run_id=None):
    """One Participant enqueue attempt. Scope comes from the trusted badge only."""
    _settings(settings)
    _require_scope(scope, "participant", ENQUEUE_CAPABILITY)
    payload = _capture_payload(value, settings["limits"])
    queue_id = _digest({"version": CONTRACT_VERSION, "kind": "enqueue",
                        "project_identity": scope.project_identity,
                        "request_id": request_id, "payload": payload})
    operation = _operation("enqueue", scope, settings, operation_id, request_id,
                           payload, at, queue_id=queue_id)
    if run_id is not None:
        operation.provenance["run_id"] = _token(run_id, "run_id")
    return operation


def _human_payload(kind, payload, limits):
    required, optional = HUMAN_PAYLOADS[kind]
    _object(payload, "payload", required, optional)
    if "observed_version" in payload:
        _digest_value(payload["observed_version"], "payload.observed_version")
    if "source_commit" in payload:
        _commit(payload["source_commit"], "payload.source_commit")
    if "preview_id" in payload:
        _token(payload["preview_id"], "payload.preview_id")
    if "drain_id" in payload:
        _token(payload["drain_id"], "payload.drain_id")
    if "queue_id" in payload:
        _digest_value(payload["queue_id"], "payload.queue_id")
    if "reason" in payload:
        _token(payload["reason"], "payload.reason")
    for key in ("conclusion", "rationale"):
        if key in payload:
            text = _text(payload[key], "payload." + key, 2**31 - 1, multiline=True)
            if len(text.encode("utf-8")) > limits["body_bytes"]:
                _fail("PAYLOAD_TOO_LARGE", "payload." + key)
    if "paths" in payload:
        for index, path in enumerate(_array(payload["paths"], "payload.paths",
                                            limits["scan_documents"], nonempty=True)):
            field = f"payload.paths[{index}]"
            if (type(path) is not str or not path or path.startswith("/") or "\\" in path
                    or ".." in path.split("/") or posixpath.normpath(path) != path
                    or any(ord(c) < 32 or ord(c) == 127 for c in path)):
                _fail("UNSAFE_PATH", field)
    if "types" in payload:
        types = _array(payload["types"], "payload.types", limits["scan_documents"], nonempty=True)
        if len(types) != len(payload["paths"]) or any(item not in CAPTURE_TYPES for item in types):
            _fail("INVALID_IMPORT_TYPES", "payload.types")
    if "queue_ids" in payload:
        for index, queue_id in enumerate(_array(payload["queue_ids"], "payload.queue_ids",
                                                limits["batch_drafts"], nonempty=True)):
            _digest_value(queue_id, f"payload.queue_ids[{index}]")
    return payload


def action(scope, settings, *, kind, operation_id, request_id, payload, at):
    """One human request through the shared typed Manager seam."""
    _settings(settings)
    if kind not in HUMAN_KINDS:
        _fail("UNKNOWN_OPERATION", "kind")
    _require_scope(scope, "human", "library-" + kind)
    if _hosted(settings) and kind in MODEL_KINDS:
        egress_approval(settings, scope.project_id)
    if type(payload) is not dict:
        _fail("INVALID_CONTRACT", "payload")
    _reject_reserved(payload)
    _human_payload(kind, payload, settings["limits"])
    return _operation(kind, scope, settings, operation_id, request_id, payload, at,
                      drain_id=payload.get("drain_id"))


def settings_change(scope, settings, *, operation_id, request_id, document, at,
                    egress_approvals=()):
    """Installation-settings authority only; egress stays a separate approval."""
    _settings(settings)
    _require_scope(scope, "operator", SETTINGS_CAPABILITY)
    if not hasattr(document, "read"):
        _fail("INVALID_SETTINGS")
    candidate = admit_settings(document, egress_approvals=egress_approvals)
    if candidate["settings_id"] == settings["settings_id"]:
        _fail("UNCHANGED_SETTINGS")
    payload = {"next_settings_id": candidate["settings_id"],
               "repository": candidate["repository"], "model": candidate["model"],
               "filters": candidate["filters"], "limits": candidate["limits"]}
    return _operation("settings-update", scope, settings, operation_id, request_id,
                      payload, at)


def retry(scope, settings, previous, *, operation_id, at):
    """New Hub Command ID, same librarian request and payload, fresh authority.

    The original submission provenance is immutable; this attempt records the
    actually authorizing actor and the configuration identity it starts under.
    """
    _settings(settings)
    if type(previous) is not Operation or previous.kind != "enqueue":
        _fail("INVALID_OPERATION", "previous")
    _require_scope(scope, "participant", ENQUEUE_CAPABILITY)
    if (previous.scope.project_id != scope.project_id
            or previous.scope.project_identity != scope.project_identity):
        _fail("FORBIDDEN", "scope.project_id")
    if operation_id == previous.operation_id:
        _fail("ID_CONFLICT", "operation_id")
    payload = _capture_payload(previous.payload, settings["limits"])
    if _digest(payload) != previous.digest():
        _fail("INVALID_OPERATION", "payload")
    if _digest({"version": CONTRACT_VERSION, "kind": "enqueue",
                "project_identity": previous.scope.project_identity,
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
    if previous.scope.project_identity != operation.scope.project_identity:
        _fail("INVALID_OPERATION", "scope")
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

def queue_path(project_path, queue_id):
    """Bundle-relative draft path from current coordinates, no traversal."""
    if (type(project_path) is not str or not project_path
            or any(part in ("", ".", "..") for part in project_path.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in project_path)):
        _fail("INVALID_PROJECT_IDENTITY", "project_path")
    return "projects/" + project_path + "/pending/" + _digest_value(queue_id, "queue_id") + ".md"


def receipt(operation, outcome, *, at, publication=None, projection=None,
            configuration=None, acknowledgement=None, reason=None, retryable=None, evidence=None):
    """Build the typed result for one operation; no content or secret fields.

    Success evidence is outcome-specific: content publication for
    ``DURABLY_QUEUED``/``COMMITTED``, a durable configuration version for
    ``CONFIGURED``, and an operational acknowledgement for ``ACKNOWLEDGED``.
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
    value = {
        "version": CONTRACT_VERSION, "operation_id": operation.operation_id,
        "kind": operation.kind, "request_id": operation.request_id,
        "queue_id": operation.queue_id, "drain_id": operation.drain_id,
        "settings_id": operation.settings_id, "outcome": outcome, "at": at,
        "publication": publication, "projection": projection,
        "configuration": configuration, "acknowledgement": acknowledgement,
        "reason": reason, "retryable": retryable}
    if evidence is not None:
        value["evidence"] = list(evidence)
    return admit_receipt(value)


def admit_receipt(value):
    """Validate a received receipt; a claim is not publication or visibility."""
    _object(value, "$", ("version", "operation_id", "kind", "request_id", "queue_id",
                         "drain_id", "settings_id", "outcome", "at", "publication",
                         "projection", "configuration", "acknowledgement",
                         "reason", "retryable"), ("evidence",))
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
    if outcome in ("NOT_DURABLE", "REJECTED", "REFUSED", "BUSY", "STALE", "UNKNOWN"):
        _token(value["reason"], "reason")
    elif value["reason"] is not None:
        _token(value["reason"], "reason")
    durable = outcome in CONTENT_OUTCOMES
    publication = value["publication"]
    configuration = value["configuration"]
    acknowledgement = value["acknowledgement"]
    if durable:
        if type(publication) is not dict:
            _fail("PUBLICATION_REQUIRED", "publication")
        _object(publication, "publication", ("commit_sha", "path"))
        _commit(publication["commit_sha"], "publication.commit_sha")
        _text(publication["path"], "publication.path", 4096)
        if outcome == "DURABLY_QUEUED" and value["queue_id"] is not None:
            if not publication["path"].endswith("/pending/" + value["queue_id"] + ".md"):
                _fail("INVALID_PUBLICATION", "publication.path")
        if configuration is not None or acknowledgement is not None:
            _fail("INVALID_OUTCOME", "configuration")
    elif outcome == "CONFIGURED":
        if publication is not None:
            _fail("INVALID_OUTCOME", "publication")
        if type(configuration) is not dict:
            _fail("CONFIGURATION_REQUIRED", "configuration")
        _object(configuration, "configuration", ("settings_id", "version"))
        _digest_value(configuration["settings_id"], "configuration.settings_id")
        _integer(configuration["version"], "configuration.version")
        if acknowledgement is not None:
            _fail("INVALID_OUTCOME", "acknowledgement")
    elif outcome == "ACKNOWLEDGED":
        if publication is not None or configuration is not None:
            _fail("INVALID_OUTCOME", "publication")
        _token(acknowledgement, "acknowledgement")
    elif publication is not None or configuration is not None or acknowledgement is not None:
        _fail("INVALID_OUTCOME", "publication")
    if value["projection"] is None:
        if outcome == "DURABLY_QUEUED":
            _fail("PROJECTION_REQUIRED", "projection")
    else:
        if not durable:
            _fail("INVALID_PROJECTION", "projection.commit_sha")
        projection = value["projection"]
        if type(projection) is not dict:
            _fail("INVALID_PROJECTION", "projection")
        _object(projection, "projection", ("commit_sha", "visible"))
        _commit(projection["commit_sha"], "projection.commit_sha", allow_none=True)
        if type(projection["visible"]) is not bool:
            _fail("INVALID_PROJECTION", "projection.visible")
        if projection["visible"] and projection["commit_sha"] is None:
            _fail("INVALID_PROJECTION", "projection.commit_sha")
    if "evidence" in value:
        for index, fact in enumerate(_array(value["evidence"], "evidence", 64)):
            field = "evidence[%d]" % index
            _object(fact, field, ("rule", "path", "line", "sha256"))
            _token(fact["rule"], field + ".rule")
            _text(fact["path"], field + ".path", 1024)
            _integer(fact["line"], field + ".line", maximum=2**31-1)
            _digest_value(fact["sha256"], field + ".sha256")
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
        if op == "deprecate":
            _object(item, field, ("op", "path", "reason"))
            normalized.append({"op": "deprecate",
                               "path": _concept_path(item["path"], field + ".path"),
                               "reason": _token(item["reason"], field + ".reason")})
            continue
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
        if len(value) > 4096:
            _fail("INVALID_CONTRACT", field)
        for key, item in value.items():
            if type(key) is not str or not TOKEN.fullmatch(key):
                _fail("INVALID_CONTRACT", field)
            if key in CONTENT_KEYS:
                _fail("CONTENT_NOT_ALLOWED", f"{field}.{key}")
            _reject_content(item, f"{field}.{key}", depth + 1)
    elif type(value) is list:
        if len(value) > 4096:
            _fail("INVALID_CONTRACT", field)
        for index, item in enumerate(value):
            _reject_content(item, f"{field}[{index}]", depth + 1)
    elif not (value is None or type(value) in (bool, int, float, str)):
        _fail("INVALID_CONTRACT", field)


def synthesis_manifest(value):
    """Strict metadata-only durable T19 input identity, never model bytes."""
    _object(value, 'manifest', ('attempt', 'input_sha', 'selected', 'accepted', 'indexes',
        'request_sha256', 'request_bytes', 'request_files', 'request_tokens', 'inputs',
        'batch_drafts', 'batch_bytes', 'attempt_seconds'))
    _integer(value['attempt'], 'attempt')
    _commit(value['input_sha'], 'input_sha')
    for key in ('request_bytes', 'request_files', 'request_tokens', 'batch_drafts', 'batch_bytes', 'attempt_seconds'):
        _integer(value[key], key, maximum=MAXIMA.get(key, 2097152))
    _digest_value(value['request_sha256'], 'request_sha256')
    for q in _array(value['selected'], 'selected', 64): _digest_value(q, 'selected')
    if not value['selected'] or len(set(value['selected'])) != len(value['selected']): _fail('INVALID_BATCH')
    for ref in _array(value['accepted'], 'accepted', 512):
        if type(ref) is not str or not ref.startswith('concept-') or not DIGEST.fullmatch(ref[8:]): _fail('INVALID_CONCEPT_REFERENCE')
    for ref in _array(value['indexes'], 'indexes', 4):
        if ref not in ('index.md','context/index.md','decisions/index.md','research/index.md'): _fail('INVALID_REQUEST_SELECTION')
    for item in _array(value['inputs'], 'inputs', 1024):
        _object(item, 'inputs', ('name_sha256', 'bytes_sha256'))
        for v in item.values(): _digest_value(v, 'inputs')
    _reject_content(value)
    if _size(value) > 262144: _fail("ATTEMPT_MANIFEST_TOO_LARGE")
    return json.loads(_canonical(value))


def batch_manifest(value):
    """Recoverable fixed batch identity before assembly or contact."""
    _object(value, 'manifest', ('selected',))
    for queue in _array(value['selected'], 'selected', 64): _digest_value(queue, 'selected')
    if not value['selected'] or len(set(value['selected'])) != len(value['selected']): _fail('INVALID_BATCH')
    return json.loads(_canonical(value))


def operation_manifest(kind, value):
    if kind == 'library-observation':
        from .manager_projection import (library_observation as observation, library_ObservationError as ObservationError)
        try: return observation(value)
        except ObservationError: _fail('INVALID_LIBRARY_OBSERVATION')
    if kind == 'synthesis-batch': return batch_manifest(value)
    if kind == 'scheduler-state': return scheduler_manifest(value)
    if kind == 'source-park': return source_manifest(value)
    if kind == 'synthesis-attempt': return synthesis_manifest(value)
    _fail('INVALID_RECORD', 'manifest')


def scheduler_manifest(value):
    """Bounded durable scheduling metadata, never draft or model content."""
    _object(value, 'schedule', ('sequence', 'served', 'state', 'due', 'drain_id',
        'selected', 'attempt', 'failures', 'model_failures', 'wake', 'reason'), ('transition',))
    for key in ('sequence', 'served', 'attempt', 'failures', 'model_failures'):
        if type(value[key]) is not int or not 0 <= value[key] <= 2**53 - 1: _fail('INVALID_SCHEDULE', key)
    if value['state'] not in ('IDLE','READY','ACTIVE','BACKOFF','BLOCKED','DISPOSED'): _fail('INVALID_SCHEDULE')
    if type(value['wake']) is not bool: _fail('INVALID_SCHEDULE')
    if value['due'] is not None: _timestamp(value['due'], 'due')
    if value['drain_id'] is not None: _token(value['drain_id'], 'drain_id')
    if value['reason'] is not None: _token(value['reason'], 'reason')
    for queue in _array(value['selected'], 'selected', 64): _digest_value(queue, 'selected')
    if len(value['selected']) != len(set(value['selected'])): _fail('INVALID_SCHEDULE')
    if bool(value['selected']) != bool(value['drain_id']): _fail('INVALID_SCHEDULE')
    _reject_content(value)
    if _size({k:v for k,v in value.items() if k != 'transition'}) > 8192: _fail('INVALID_SCHEDULE')
    if 'transition' in value:
        transition = drain_transition(value['transition'])
        if transition['sequence'] != value['sequence']: _fail('INVALID_SCHEDULE')
    return json.loads(_canonical(value))


def drain_transition(value):
    """Closed, bounded metadata-only T21 report. Never document or model bytes."""
    _object(value, 'transition', ('drain_id', 'sequence', 'phase', 'attempt',
        'outcomes', 'resulting_sha', 'reason', 'due'))
    _token(value['drain_id'], 'drain_id')
    for name in ('sequence', 'attempt'):
        if type(value[name]) is not int or not 0 <= value[name] <= 2**53-1: _fail('INVALID_TRANSITION')
    if value['sequence']==0 or (value['attempt']==0 and value['phase']!='BLOCKED'): _fail('INVALID_TRANSITION')
    if value['phase'] not in ('STARTED','RETRY_SCHEDULED','COMMITTED','BLOCKED','OPERATOR_DISPOSED'):
        _fail('INVALID_TRANSITION')
    if value['reason'] is not None: _token(value['reason'], 'reason')
    if value['due'] is not None: _timestamp(value['due'], 'due')
    if value['resulting_sha'] is not None: _commit(value['resulting_sha'], 'resulting_sha')
    if (value['phase'] == 'COMMITTED') != (value['resulting_sha'] is not None): _fail('INVALID_TRANSITION')
    if (value['phase'] == 'RETRY_SCHEDULED') != (value['due'] is not None): _fail('INVALID_TRANSITION')
    seen = set()
    for item in _array(value['outcomes'], 'outcomes', 64):
        _object(item, 'outcome', ('queue_id', 'kind'), ('targets','reason'))
        queue = _digest_value(item['queue_id'], 'queue_id')
        if queue in seen: _fail('INVALID_TRANSITION')
        seen.add(queue)
        if item['kind'] in ('integrated', 'merged'):
            if set(item) != {'queue_id','kind','targets'}: _fail('INVALID_TRANSITION')
            for path in _array(item['targets'], 'targets', 64):
                if (type(path) is not str or len(path)>1024 or '..' in path.split('/')
                        or not path.startswith(('context/','decisions/','research/'))): _fail('INVALID_TRANSITION')
        elif item['kind'] in ('parked','rejected','adjudicated'):
            if set(item) != {'queue_id','kind','reason'}: _fail('INVALID_TRANSITION')
            _token(item['reason'], 'reason')
        else: _fail('INVALID_TRANSITION')
    if value['phase'] not in ('COMMITTED','OPERATOR_DISPOSED') and value['outcomes']: _fail('INVALID_TRANSITION')
    if value['phase'] != 'OPERATOR_DISPOSED' and any(x['kind'] in ('rejected','adjudicated') for x in value['outcomes']):
        _fail('INVALID_TRANSITION')
    _reject_content(value)
    if _size(value)>262144: _fail('INVALID_TRANSITION')
    return json.loads(_canonical(value))


def source_manifest(value):
    _object(value,'source_manifest',('basis','selected','accepted','indexes','attempt'))
    _commit(value['basis'],'basis'); _integer(value['attempt'],'attempt')
    for queue in _array(value['selected'],'selected',64): _digest_value(queue,'queue_id')
    for ref in _array(value['accepted'],'accepted',64): _token(ref,'reference')
    for name in _array(value['indexes'],'indexes',4):
        if name not in ('index.md','context/index.md','decisions/index.md','research/index.md'): _fail('INVALID_RECORD')
    if _size(value)>32768: _fail('INVALID_RECORD')
    return json.loads(_canonical(value))
