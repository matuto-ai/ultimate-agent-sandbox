"""Versioned configuration admission, not runtime activation or secret loading.

The JSON adapter is deliberately replaceable. load() validates the entire input
before returning one normalized value; it performs no writes or network calls.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import stat
from typing import TextIO
from urllib.parse import urlsplit

MAX_BYTES = 1024 * 1024
ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")
IMAGE_PATH = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\Z")
CAPABILITIES = {
    "implement": "hub", "review": "hub", "can-open-requested-run": "hub",
    "forge-read": "broker", "forge-write": "broker", "git-read": "broker", "git-push": "broker",
}
CONTROLS = ("non_root", "outer_confinement", "process_binding", "private_endpoints", "no_host_runtime_socket")
NETWORK_CONTROLS = ("block_host", "block_private", "block_metadata", "block_other_rooms")


class ConfigError(ValueError):
    """A stable field path and bounded explanation, without input values/secrets."""
    def __init__(self, field: str, reason: str):
        self.field, self.reason = field, reason
        super().__init__(f"{field}: {reason}")


class _Pairs(list):
    pass


def _decode(value, field="$", depth=0):
    if depth > 32:
        raise ConfigError("$", "configuration nesting exceeds 32 levels")
    if isinstance(value, _Pairs):
        result = {}
        for key, item in value:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key):
                raise ConfigError(field, "invalid field name")
            child = f"{field}.{key}"
            if key in result:
                raise ConfigError(child, "duplicate field")
            result[key] = _decode(item, child, depth + 1)
        return result
    if isinstance(value, list):
        return [_decode(item, f"{field}[{i}]", depth + 1) for i, item in enumerate(value)]
    return value


def _object(value, field, required, optional=()):
    if not isinstance(value, dict):
        raise ConfigError(field, "expected object")
    for key in value:
        if key not in (*required, *optional):
            raise ConfigError(f"{field}.{key}", "unknown field")
    for key in required:
        if key not in value:
            raise ConfigError(f"{field}.{key}", "required field")
    return value


def _text(value, field, limit=4096, multiline=False):
    if not isinstance(value, str) or not value or len(value) > limit or any((ord(c) < 32 or 127 <= ord(c) < 160) and not (multiline and c in "\n\t") for c in value):
        raise ConfigError(field, "expected nonempty bounded text without control characters")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ConfigError(field, "expected valid Unicode text") from None
    return value


def _id(value, field):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ConfigError(field, "expected lowercase identifier (1–64 characters)")
    return value


def _integer(value, field, minimum=1, maximum=2**53 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ConfigError(field, "expected integer within supported positive bounds")
    return value


def _version(value, field):
    if type(value) is not int or value != 1:
        raise ConfigError(field, "unsupported schema version; expected 1")


def _array(value, field, nonempty=True):
    if not isinstance(value, list) or (nonempty and not value) or len(value) > 1024:
        raise ConfigError(field, "expected bounded array" + (" with at least one entry" if nonempty else ""))
    return value


def _strings(value, field, allowed=None, nonempty=False):
    seen = set()
    for i, item in enumerate(_array(value, field, nonempty)):
        p = f"{field}[{i}]"
        _text(item, p)
        if allowed is not None and item not in allowed:
            raise ConfigError(p, "unsupported value")
        if item in seen:
            raise ConfigError(p, "duplicate value")
        seen.add(item)
    return sorted(seen)


def _named(value, field):
    result = {}
    for i, item in enumerate(_array(value, field)):
        p = f"{field}[{i}]"
        if not isinstance(item, dict) or "id" not in item:
            raise ConfigError(p + ".id", "required identifier")
        name = _id(item["id"], p + ".id")
        if name in result:
            raise ConfigError(p + ".id", "duplicate identifier")
        result[name] = (item, p)
    return result


def _reference(value, field, registry):
    _id(value, field)
    if value not in registry:
        raise ConfigError(field, "unresolved reference")
    return value


def _url(value, field):
    _text(value, field)
    try:
        url = urlsplit(value)
        host = url.hostname
        port = url.port
        if url.scheme != "https" or not host or url.username or url.password or url.query or url.fragment:
            raise ValueError()
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")) or "." not in host:
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not re.search(r"[a-zA-Z]", host) or not re.fullmatch(r"[a-zA-Z0-9.-]+", host) or any(not part or part.startswith("-") or part.endswith("-") for part in host.split(".")):
                raise ValueError()
        else:
            if not address.is_global:
                raise ValueError()
    except ValueError:
        raise ConfigError(field, "expected credential-free public HTTPS URL; local routing is deferred") from None
    return value


def _image(value, field):
    """A bounded distribution-style name (optional tag) pinned to a digest.

    Registry DNS names/IPv4 and ports are supported; bracketed IPv6 registries
    are not part of the initial input surface. This never resolves or pulls.
    """
    _text(value, field, 340)
    name, separator, digest = value.partition("@")
    if not separator or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or len(name) > 255:
        raise ConfigError(field, "expected image pinned by SHA-256 digest")
    parts = name.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry = parts.pop(0)
        host, colon, port = registry.partition(":")
        if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", host):
            raise ConfigError(field, "invalid image registry host")
        if colon and (not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535):
            raise ConfigError(field, "invalid image registry port")
    if not parts:
        raise ConfigError(field, "missing image repository")
    last, colon, tag = parts[-1].partition(":")
    if colon and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        raise ConfigError(field, "invalid image tag")
    parts[-1] = last
    if not all(IMAGE_PATH.fullmatch(part) for part in parts):
        raise ConfigError(field, "invalid image repository path")


def _path(value, field):
    _text(value, field)
    if not value.startswith("/") or value == "/" or ".." in value.split("/") or os.path.normpath(value) != value:
        raise ConfigError(field, "expected canonical absolute non-root path without traversal")
    if any(value == p or value.startswith(p + "/") for p in ("/proc", "/sys", "/dev", "/etc", "/boot", "/usr", "/bin", "/sbin", "/run")):
        raise ConfigError(field, "reserved host path")
    if os.path.realpath(value) != value:
        raise ConfigError(field, "symlink or noncanonical ancestor")
    current = ""
    for component in value.split("/")[1:]:
        current += "/" + component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            break  # Later components also do not exist; launch revalidates.
        except OSError:
            raise ConfigError(field, "cannot inspect path ancestry") from None
        if not stat.S_ISDIR(mode):
            raise ConfigError(field, "expected directory ancestry without symlinks")
    return value


def _overlaps(a, b):
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def load(source: TextIO, *, available_credentials=()) -> dict:
    """Validate and normalize v1 JSON. Inventory contains reference IDs, never secrets.

    Inventory is an external observation, not proof of provider authentication.
    Default empty inventory leaves affected seats unavailable, not invalid.
    Paths are inspected read-only; launch must revalidate race-sensitive facts.
    """
    raw = source.read(MAX_BYTES + 1)
    try:
        size = len(raw.encode("utf-8"))
    except UnicodeError:
        raise ConfigError("$", "configuration must be UTF-8") from None
    if size > MAX_BYTES:
        raise ConfigError("$", "configuration exceeds 1 MiB")
    try:
        document = json.loads(raw, object_pairs_hook=_Pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        config = _decode(document)
    except ConfigError:
        raise
    except (ValueError, RecursionError):
        raise ConfigError("$", "invalid JSON or excessive nesting") from None
    return _normalize(config, available_credentials)


def _normalize(config, available_credentials):
    _object(config, "$", ("version", "deployment", "rooms"))
    _version(config["version"], "$.version")
    d = _object(config["deployment"], "$.deployment", ("id", "state_root", "manager", "credentials", "actors", "images", "providers", "audit"))
    did = _id(d["id"], "$.deployment.id")
    state = _path(d["state_root"], "$.deployment.state_root")
    creds = _named(d["credentials"], "$.deployment.credentials")
    for c, p in creds.values():
        _object(c, p, ("id", "kind"))
        if c["kind"] not in ("git", "forge", "manager-client", "manager-trust"):
            raise ConfigError(p + ".kind", "unsupported credential kind")
    available = set()
    for i, name in enumerate(available_credentials):
        available.add(_reference(name, f"$available_credentials[{i}]", creds))

    def credential(name, field, kind):
        _reference(name, field, creds)
        if creds[name][0]["kind"] != kind:
            raise ConfigError(field, "credential kind mismatch")

    manager = _object(d["manager"], "$.deployment.manager", ("url", "client_credential_ref", "server_trust_ref"))
    _url(manager["url"], "$.deployment.manager.url")
    credential(manager["client_credential_ref"], "$.deployment.manager.client_credential_ref", "manager-client")
    credential(manager["server_trust_ref"], "$.deployment.manager.server_trust_ref", "manager-trust")
    actors = _named(d["actors"], "$.deployment.actors")
    for a, p in actors.values():
        _object(a, p, ("id",), ("git_credential_ref", "forge_credential_ref", "github_user_id", "git_identity"))
        # Operator-declared immutable assignment mapping, not proof of credential
        # identity, native account access, or authority to admit a Run.
        if "github_user_id" in a:
            _integer(a["github_user_id"], p + ".github_user_id", maximum=2**63 - 1)
        # Optional for backwards-compatible admission. Native Git mutations
        # require this trusted canonical identity at their operation seam;
        # credential presence alone never invents a name or email.
        if "git_identity" in a:
            from .git_policy import GitIdentity, GitPolicyError
            identity = _object(a["git_identity"], p + ".git_identity", ("name", "email"))
            for field, limit in (("name", 256), ("email", 254)):
                value = _text(identity[field], p + ".git_identity." + field, limit)
                try:
                    # One identity contract for offline config and launcher;
                    # probe each field separately for an exact sanitized error.
                    GitIdentity(a['id'], value if field == 'name' else 'Validation',
                                value if field == 'email' else 'validation@example.invalid')
                except GitPolicyError:
                    raise ConfigError(p + ".git_identity." + field, "expected canonical Git identity text") from None
        for kind in ("git", "forge"):
            key = kind + "_credential_ref"
            if key in a:
                credential(a[key], p + "." + key, kind)
    images = _named(d["images"], "$.deployment.images")
    for image, p in images.values():
        _object(image, p, ("id", "reference"))
        _image(image["reference"], p + ".reference")
    providers = _named(d["providers"], "$.deployment.providers")
    for provider, p in providers.values():
        _object(provider, p, ("id", "runtime"), ("model", "endpoint"))
        if provider["runtime"] not in ("pi", "claude"):
            raise ConfigError(p + ".runtime", "unsupported Runtime")
        if "model" in provider:
            _text(provider["model"], p + ".model", 256)
        if "endpoint" in provider:
            _url(provider["endpoint"], p + ".endpoint")
    audit = _object(d["audit"], "$.deployment.audit", ("retention_days", "max_bytes"))
    _integer(audit["retention_days"], "$.deployment.audit.retention_days")
    _integer(audit["max_bytes"], "$.deployment.audit.max_bytes")

    rooms = _named(config["rooms"], "$.rooms")
    paths, projects, repositories, networks = [], set(), set(), set()
    room_states = []
    for room, p in rooms.values():
        _object(room, p, ("version", "id", "project", "state_root", "image", "network", "boundary", "resources", "profiles", "policies", "default_policy", "seats"), ("ambient",))
        _version(room["version"], p + ".version")
        root = _path(room["state_root"], p + ".state_root")
        if not root.startswith(state + "/") or any(_overlaps(root, other) for other in room_states):
            raise ConfigError(p + ".state_root", "expected disjoint Room-owned directory inside Deployment state")
        room_states.append(root)
        _reference(room["image"], p + ".image", images)
        project = _object(room["project"], p + ".project", ("id", "repository", "roots"))
        project_id = _id(project["id"], p + ".project.id")
        if project_id in projects:
            raise ConfigError(p + ".project.id", "Project already bound to another Room")
        projects.add(project_id)
        repository = project["repository"]
        if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository) or any(x in (".", "..") for x in repository.split("/")):
            raise ConfigError(p + ".project.repository", "expected GitHub owner/repository")
        if repository.casefold() in repositories:
            raise ConfigError(p + ".project.repository", "writable repository already bound to another Room")
        repositories.add(repository.casefold())
        roots = _object(project["roots"], p + ".project.roots", ("repo", "workspace", "reference", "checkouts"))
        for name, value in roots.items():
            field = p + ".project.roots." + name
            _path(value, field)
            if _overlaps(value, state):
                raise ConfigError(field, "Project path overlaps Deployment control state")
            for previous, previous_name, previous_room in paths:
                if _overlaps(value, previous) and not (name == previous_name == "reference" and previous_room != room["id"]):
                    raise ConfigError(field, "Project paths overlap writable or same-Room data")
            paths.append((value, name, room["id"]))
        net = _object(room["network"], p + ".network", ("id", *NETWORK_CONTROLS))
        network = _id(net["id"], p + ".network.id")
        if network in networks:
            raise ConfigError(p + ".network.id", "network already owned by another Room")
        networks.add(network)
        for key in NETWORK_CONTROLS:
            if net[key] is not True:
                raise ConfigError(p + ".network." + key, "required Room deny control must be true")
        boundary = _object(room["boundary"], p + ".boundary", CONTROLS)
        for key in CONTROLS:
            if boundary[key] is not True:
                raise ConfigError(p + ".boundary." + key, "required Room boundary control must be true")
        limits = _object(room["resources"], p + ".resources", ("cpu", "memory_bytes", "disk_bytes", "pids", "log_bytes"))
        cpu = limits["cpu"]
        if type(cpu) not in (int, float) or not 0 < cpu <= 1024 or not math.isfinite(cpu):
            raise ConfigError(p + ".resources.cpu", "expected finite positive CPU limit at most 1024")
        for key in ("memory_bytes", "disk_bytes", "pids", "log_bytes"):
            _integer(limits[key], p + ".resources." + key)
        if limits["log_bytes"] > limits["disk_bytes"]:
            raise ConfigError(p + ".resources.log_bytes", "log limit exceeds Room disk limit")
        ambient = _object(room.get("ambient", {}), p + ".ambient", (), ("browser", "nested_containers"))
        for key in ("browser", "nested_containers"):
            if ambient.get(key, False) is not False:
                raise ConfigError(p + ".ambient." + key, "enabled ambient variants require later boundary qualification")
            ambient[key] = False
        room["ambient"] = ambient
        profiles = _named(room["profiles"], p + ".profiles")
        for profile, pp in profiles.values():
            _object(profile, pp, ("id", "instructions", "tools", "capabilities"))
            _text(profile["instructions"], pp + ".instructions", 16384, multiline=True)
            profile["tools"] = _strings(profile["tools"], pp + ".tools")
            profile["capabilities"] = _strings(profile["capabilities"], pp + ".capabilities", CAPABILITIES)
        policies = _named(room["policies"], p + ".policies")
        from .gate_policy import compile_policy
        for policy, pp in policies.values():
            compiled = compile_policy(policy, pp)
            policy.clear()
            policy.update(compiled)
        _reference(room["default_policy"], p + ".default_policy", policies)
        seats = _named(room["seats"], p + ".seats")
        participants = set()
        for seat, sp in seats.values():
            _object(seat, sp, ("id", "participant", "runtime", "arguments", "actor", "profile", "provider"))
            participant = _id(seat["participant"], sp + ".participant")
            if participant in participants:
                raise ConfigError(sp + ".participant", "Participant already bound to another seat in this Room")
            participants.add(participant)
            if seat["runtime"] not in ("pi", "claude"):
                raise ConfigError(sp + ".runtime", "unsupported Runtime")
            # argv is data; never execute, shell-expand, or infer authority from it.
            for i, arg in enumerate(_array(seat["arguments"], sp + ".arguments", False)):
                _text(arg, f"{sp}.arguments[{i}]")
            actor = actors[_reference(seat["actor"], sp + ".actor", actors)][0]
            _reference(seat["profile"], sp + ".profile", profiles)
            provider = providers[_reference(seat["provider"], sp + ".provider", providers)][0]
            if seat["runtime"] != provider["runtime"]:
                raise ConfigError(sp + ".provider", "provider Runtime does not match seat")
            missing = [kind for kind in ("git", "forge") if actor.get(kind + "_credential_ref") not in available]
            seat["resolved"] = {"deployment_id": did, "room_id": room["id"], "credential_status": "unavailable" if missing else "available", "missing_actor_credentials": missing, "provider_configuration": "valid", "inference_health": "unknown", "activation": "not-evaluated"}
        room["resolved"] = {"deployment_id": did, "project_id": project_id, "activation": "not-evaluated", "boundary": "declared-not-verified"}
        for key, registry in (("profiles", profiles), ("policies", policies), ("seats", seats)):
            room[key] = [registry[k][0] for k in sorted(registry)]
    for key, registry in (("credentials", creds), ("actors", actors), ("images", images), ("providers", providers)):
        d[key] = [registry[k][0] for k in sorted(registry)]
    config["rooms"] = [rooms[k][0] for k in sorted(rooms)]
    config["capability_enforcement"] = dict(CAPABILITIES)
    return config
