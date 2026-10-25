"""Read-only launch preflight. Observations are not production authorization.

The production launcher is intentionally unavailable until all #62 controls have
real qualification. This module never starts containers or changes host policy.
"""
from datetime import datetime, timezone
import errno
import os
from pathlib import PurePosixPath
import socket
import stat
import struct

from .config import ConfigError, load


def _fact(control, status, source, *, reason=None, observation=None):
    result = {"control": control, "status": status, "source": source}
    if reason is not None:
        result["reason"] = reason
    if observation is not None:
        result["observation"] = observation
    return result


def _parts(path):
    if type(path) is not str or len(path) > 4096 or not path.startswith("/") or path == "/":
        raise ValueError("noncanonical absolute path")
    parts = path.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts) or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path):
        raise ValueError("noncanonical absolute path")
    return parts


def _metadata(info):
    kind = "directory" if stat.S_ISDIR(info.st_mode) else "socket" if stat.S_ISSOCK(info.st_mode) else "other"
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "gid": info.st_gid, "mode": format(stat.S_IMODE(info.st_mode), "04o"), "kind": kind}


def _stat_no_follow(path):
    """Walk real directory descriptors; reject symlinks at every component.

    This captures one path observation, not a mount lease or race-free later
    activation. The future launcher must revalidate the actual opened objects.
    """
    parts = _parts(path)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise NotImplementedError()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink")
        return info
    finally:
        os.close(descriptor)


def observe_path(path, *, control, expected_kind="directory"):
    """Read metadata only; never create/chmod/chown a path or read its content."""
    source = "host.filesystem.openat-no-follow"
    try:
        metadata = _metadata(_stat_no_follow(path))
        if metadata["kind"] != expected_kind:
            return _fact(control, "failed", source, reason="WRONG_FILE_TYPE", observation=metadata)
        return _fact(control, "observed", source, observation=metadata)
    except (ValueError, TypeError):
        return _fact(control, "failed", source, reason="UNSAFE_PATH")
    except NotImplementedError:
        return _fact(control, "unknown", source, reason="NO_NOFOLLOW_SUPPORT")
    except OSError as error:
        if error.errno == errno.ENOENT:
            reason = "MISSING_PATH"
        elif error.errno in (errno.ELOOP, errno.ENOTDIR):
            reason = "UNSAFE_PATH"
        elif error.errno in (errno.EACCES, errno.EPERM):
            reason = "UNREADABLE_PATH"
        else:
            reason = "OBSERVATION_UNAVAILABLE"
        return _fact(control, "failed" if reason in ("MISSING_PATH", "UNSAFE_PATH") else "unknown", source, reason=reason)


def observe_unix_peer(connection):
    """Read kernel peer credentials from a connected Unix stream descriptor.

    Intended for a future trusted accept/transport boundary. PID/UID/GID alone
    are NOT a Participant binding, capability, or proof against PID reuse.
    """
    control, source = "unix_peer_credentials", "kernel.SO_PEERCRED"
    if type(connection) is not socket.socket or connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM:
        return _fact(control, "failed", source, reason="NOT_UNIX_STREAM")
    if not hasattr(socket, "SO_PEERCRED"):
        return _fact(control, "unknown", source, reason="KERNEL_PEER_UNAVAILABLE")
    try:
        connection.getpeername()  # An unconnected socket is not peer evidence.
        pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if pid <= 0 or uid < 0 or gid < 0:
            return _fact(control, "unknown", source, reason="KERNEL_PEER_UNAVAILABLE")
        return _fact(control, "observed", source, observation={"pid": pid, "uid": uid, "gid": gid})
    except (OSError, struct.error):
        return _fact(control, "unknown", source, reason="NO_CONNECTED_PEER")


def probe_unix_peer_support():
    """Ephemeral local socketpair only: never connect to a configured service."""
    # Use both managed descriptors; no path, listener, network, or payload.
    try:
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with first, second:
            result = observe_unix_peer(first)
            result["control"], result["source"] = "kernel_peer_support", "kernel.socketpair-probe"
            result["scope"] = "local-probe-only-not-broker-authentication"
            return result
    except (AttributeError, OSError):
        return _fact("kernel_peer_support", "unknown", "kernel.socketpair-probe", reason="KERNEL_PEER_UNAVAILABLE")


def observe_broker_endpoint(path, *, room_state_root, expected_uid, expected_gid):
    """Inspect the narrow socket and its control-store parents, without connect.

    Expected identities come from trusted supervisor policy, not request claims.
    The initial conservative metadata policy allows a 0600/0660 socket and
    0700/0750 directories. It does not qualify SELinux or live endpoint authority.
    """
    source = "host.filesystem.openat-no-follow"
    if type(expected_uid) is not int or type(expected_gid) is not int or expected_uid <= 0 or expected_gid <= 0:
        return [_fact("broker_endpoint", "failed", source, reason="NONROOT_ENDPOINT_IDENTITY_REQUIRED")]
    try:
        _parts(path); _parts(room_state_root)
        if not path.startswith(room_state_root + "/"):
            raise ValueError("endpoint outside Room control store")
    except (ValueError, TypeError):
        return [_fact("broker_endpoint", "failed", source, reason="ENDPOINT_OUTSIDE_ROOM_STORE")]
    endpoint = observe_path(path, control="broker_endpoint", expected_kind="socket")
    if endpoint["status"] == "observed":
        metadata = endpoint["observation"]
        if metadata["uid"] != expected_uid or metadata["gid"] != expected_gid:
            endpoint.update(status="failed", reason="ENDPOINT_OWNER_MISMATCH")
        elif metadata["mode"] not in ("0600", "0660"):
            endpoint.update(status="failed", reason="ENDPOINT_MODE_UNSAFE")
    results = [endpoint]
    parent = PurePosixPath(path).parent
    anchor = PurePosixPath(room_state_root)
    while True:
        observed = observe_path(str(parent), control="broker_parent:" + ("." if parent == anchor else str(parent.relative_to(anchor))))
        if observed["status"] == "observed":
            metadata = observed["observation"]
            if metadata["uid"] not in {os.geteuid(), expected_uid}:
                observed.update(status="failed", reason="ENDPOINT_PARENT_OWNER_MISMATCH")
            elif metadata["mode"] not in ("0700", "0750") or (metadata["mode"] == "0750" and metadata["gid"] != expected_gid):
                observed.update(status="failed", reason="ENDPOINT_PARENT_MODE_UNSAFE")
        results.append(observed)
        if parent == anchor:
            break
        parent = parent.parent
    return results


def check_launch(source, room_id, *, broker_socket=None, broker_uid=None, broker_gid=None):
    """Load the existing versioned schema and report real read-only observations.

    No caller-supplied evidence flags, Docker options, or qualification override
    are accepted. Even a fully positive implemented preflight cannot start a
    production Workstation: the remaining controls have no qualified observer.
    """
    config = load(source)
    room = next((item for item in config["rooms"] if item["id"] == room_id), None)
    if room is None:
        raise ConfigError("$.rooms", "requested Room does not exist")
    roots = room["project"]["roots"]
    checks = [observe_path(path, control="project." + name) for name, path in sorted(roots.items())]
    checks.append(observe_path(room["state_root"], control="room.control_store"))
    checks.append(probe_unix_peer_support())
    if broker_socket is None:
        checks.append(_fact("broker_endpoint", "unknown", "supervisor.selection", reason="ENDPOINT_NOT_SELECTED"))
    else:
        checks.extend(observe_broker_endpoint(broker_socket, room_state_root=room["state_root"],
                                             expected_uid=broker_uid, expected_gid=broker_gid))
    for control in ("runtime_state_mount", "container_nonroot_identity", "outer_confinement",
                    "public_egress_and_deny_routes", "running_resource_bounds", "broker_process_binding", "selinux_transport"):
        checks.append(_fact(control, "unknown", "not-implemented", reason="QUALIFICATION_REQUIRED"))
    image = next(item["reference"] for item in config["deployment"]["images"] if item["id"] == room["image"])
    return {"version": 1, "deployment_id": config["deployment"]["id"], "room_id": room_id,
            "observed_at": datetime.now(timezone.utc).isoformat(), "admission": "blocked",
            "launch_allowed": False, "production_launcher": "disabled",
            "checks": checks,
            "desired_plan": {"status": "declaration-only-not-launchable", "image": image,
                "mounts": [{"role": name, "source": roots[name], "destination": roots[name],
                            "read_only": name == "reference"} for name in ("repo", "workspace", "reference")],
                "checkout_slots": "not-allocated-or-mounted", "network": room["network"],
                "resources": room["resources"], "ambient": room["ambient"],
                "non_root": "required", "outer_confinement": "required",
                "privileged": False, "host_namespaces": False, "host_devices": [], "host_runtime_socket": False},
            "limits": ["metadata is a point-in-time observation, not a launch lease",
                       "kernel peer credentials are not Participant/process-incarnation authority",
                       "network, quota, confinement and endpoint qualification remain required"]}
