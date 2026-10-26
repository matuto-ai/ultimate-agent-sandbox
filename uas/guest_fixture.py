"""Actual network/quota enforcement for the no-NIC disposable VM fixture only.

Not a production launcher or policy framework. The same Supervisor owns Docker
lifecycle. Only alpha/beta synthetic storage is supported. The boot marker is an
accidental-use guard, not an authentication mechanism or a host authorization.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

from .docker_fixture import DockerFixtureBackend
from .lifecycle import BackendUnknown, LifecycleError, OwnershipConflict

STORAGE = Path("/mnt/uas-boundary")
CONTROL = Path("/var/lib/uas-boundary")
ROOMS = {"alpha": (101, "10.89.1.0/24", "10.89.1.1", "s0:c101,c102"),
         "beta": (102, "10.89.2.0/24", "10.89.2.1", "s0:c103,c104")}
BLOCK_KIB = 8192
INODES = 128
USERNS_BASE = 100000
WORKSTATION_HOST_UID = USERNS_BASE + 65532
DENIED_V4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
             "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
             "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
             "224.0.0.0/4", "240.0.0.0/4")


def command(*args, input=None):
    try:
        result = subprocess.run(args, input=input, text=True, capture_output=True,
                                timeout=30, check=False,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BackendUnknown() from error
    if result.returncode or len(result.stdout) > 262144:
        raise BackendUnknown("guest command failed: " + args[0] + ": " + result.stderr[-1024:])
    return result.stdout


def guard(nonce, *, require_selinux=True):
    try:
        valid = (os.geteuid() == 0 and re.fullmatch(r"[0-9a-f]{32}", nonce)
                 and Path("/run/uas-vm-fixture").read_text().strip() == nonce)
    except OSError:
        valid = False
    if not valid:
        raise LifecycleError("DISPOSABLE_GUEST_REQUIRED")
    if require_selinux and (command("getenforce").strip() != "Enforcing" or Path("/sys/fs/selinux/enforce").read_text().strip() != "1"):
        raise LifecycleError("GUEST_SELINUX_REQUIRED")


def identity(path):
    path = Path(path)
    if path.resolve() != path or not path.is_dir():
        raise OwnershipConflict()
    info = path.stat()
    return [info.st_dev, info.st_ino]


def publish(path, value):
    """Private, fsynced immutable record with process-crash reconciliation."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(".pending")
    if path.is_symlink() or temporary.is_symlink():
        raise OwnershipConflict()
    if path.exists():
        if path.is_symlink() or path.read_text() != encoded:
            raise OwnershipConflict()
        if temporary.exists():
            if temporary.is_symlink() or temporary.stat().st_ino != path.stat().st_ino:
                raise OwnershipConflict()
            temporary.unlink()
        return
    if temporary.exists():
        if temporary.is_symlink() or temporary.read_text() != encoded:
            raise OwnershipConflict()
    else:
        with temporary.open("x") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink()
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def project_attributes(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        value = bytearray(28)
        fcntl.ioctl(descriptor, 0x801C581F, value, True)  # Linux FS_IOC_FSGETXATTR
        flags, _, _, project, _, _ = struct.unpack("=5I8s", value)
        return project, bool(flags & 0x200)  # FS_XFLAG_PROJINHERIT
    finally:
        os.close(descriptor)


def prepare_storage(nonce):
    """Provision only fresh fixture trees on the harness's disposable XFS disk.

    Project roots intentionally survive Supervisor Destroy. The harness removes
    the entire *VM*, not arbitrary files or mounts on an operator's machine.
    """
    guard(nonce)
    if command("stat", "-f", "-c", "%T", str(STORAGE)).strip() != "xfs":
        raise LifecycleError("GUEST_XFS_REQUIRED")
    CONTROL.mkdir(mode=0o700, exist_ok=True)
    for room, (project, _, _, level) in ROOMS.items():
        root = STORAGE / room
        if root.exists():
            raise OwnershipConflict()  # No adoption or automatic root replacement.
        root.mkdir(mode=0o755)
        paths = {}
        for name in ("repository", "workspace", "checkouts", "references", "runtime"):
            path = root / name
            path.mkdir(mode=0o755)
            if name != "runtime":
                os.chown(path, WORKSTATION_HOST_UID, WORKSTATION_HOST_UID)
            paths[name] = identity(path)
        command("xfs_quota", "-x", "-c", f"project -s -p {root} {project}", str(STORAGE))
        command("xfs_quota", "-x", "-c", f"limit -p bhard={BLOCK_KIB}k ihard={INODES} {project}", str(STORAGE))
        command("chcon", "-R", "-t", "container_file_t", "-l", level, str(root))
        publish(CONTROL / (room + ".json"), {"nonce": nonce, "room": room,
                "root": identity(root), "paths": paths, "project": project})


def network_names(state):
    instance = state["instance_id"]
    if not re.fullmatch(r"[0-9a-f]{32}", instance):
        raise OwnershipConflict()
    return "uas-guest-" + instance, "uas" + instance[:12], "uas_" + instance


def firewall_document(state, nonce):
    """Policy is outside the container; input denies even public host addresses.

    IPv6 is explicitly denied, not silently left as a bypass. This IPv4 fixture
    proves packet classification, not actual external Internet connectivity.
    """
    _, bridge, table = network_names(state)
    owner = "uas:" + nonce + ":" + state["instance_id"]
    objects = [{"table": {"family": "inet", "name": table, "comment": owner}}]
    for name in ("input", "forward"):
        objects.append({"chain": {"family": "inet", "table": table, "name": name,
                                  "type": "filter", "hook": name, "prio": -100, "policy": "accept"}})
    source = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": bridge}}
    def rule(chain, extra):
        objects.append({"rule": {"family": "inet", "table": table, "chain": chain,
                                 "expr": [source, *extra, {"counter": None}, {"drop": None}], "comment": owner}})
    rule("input", [])
    rule("forward", [{"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}}])
    prefixes = [{"prefix": {"addr": value.split("/")[0], "len": int(value.split("/")[1])}} for value in DENIED_V4]
    rule("forward", [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                                  "right": {"set": prefixes}}}])
    return {"nftables": [{"add": value} for value in objects]}


def canonical_firewall(document):
    """Ignore only runtime handles/counters; keep every enforcing expression."""
    result = []
    for item in document["nftables"]:
        if "metainfo" in item:
            continue
        item = json.loads(json.dumps(item.get("add", item)))
        for name, value in item.items():
            value.pop("handle", None)
            if name == "rule":
                for expression in value["expr"]:
                    if "counter" in expression:
                        expression["counter"] = None
        result.append(item)
    # nft emits table, all chains, then rules; generated form follows this order.
    return result


class GuestBoundaryBackend(DockerFixtureBackend):
    """Fixed alpha/beta fixture enforcement, no caller-supplied flags/evidence."""
    def __init__(self, nonce, room):
        super().__init__(timeout=30)
        if room not in ROOMS:
            raise LifecycleError("GUEST_ROOM_REQUIRED")
        self.nonce, self.room = nonce, room
        self.project, self.subnet, self.gateway, self.level = ROOMS[room]
        self.root = STORAGE / room

    def _storage(self, *, require_selinux=True):
        guard(self.nonce, require_selinux=require_selinux)
        try:
            path = CONTROL / (self.room + ".json")
            if path.is_symlink() or path.stat().st_size > 4096:
                raise OwnershipConflict()
            manifest = json.loads(path.read_text())
            if (manifest["nonce"] != self.nonce or manifest["room"] != self.room
                    or manifest["project"] != self.project or manifest["root"] != identity(self.root)):
                raise OwnershipConflict()
            for name, expected in manifest["paths"].items():
                if name not in {"repository", "workspace", "checkouts", "references", "runtime"}:
                    raise OwnershipConflict()
                if identity(self.root / name) != expected:
                    raise OwnershipConflict()
            if set(manifest["paths"]) != {"repository", "workspace", "checkouts", "references", "runtime"}:
                raise OwnershipConflict()
        except (OSError, KeyError, ValueError, TypeError) as error:
            raise OwnershipConflict() from error
        return manifest

    def _quota(self):
        self._storage()
        state = command("xfs_quota", "-x", "-c", "state -p", str(STORAGE))
        if "Accounting: ON" not in state or "Enforcement: ON" not in state:
            raise LifecycleError("GUEST_QUOTA_DISABLED")
        for flag, limit in (("b", BLOCK_KIB), ("i", INODES)):
            report = command("xfs_quota", "-x", "-c", f"report -p -{flag} -n -N", str(STORAGE))
            rows = [line.split() for line in report.splitlines() if line.split() and line.split()[0] == "#" + str(self.project)]
            if len(rows) != 1 or len(rows[0]) < 4 or rows[0][3] != str(limit):
                raise LifecycleError("GUEST_QUOTA_DRIFT")
        for path in (self.root, *(self.root / name for name in ("repository", "workspace", "checkouts", "references", "runtime"))):
            if project_attributes(path) != (self.project, True):
                raise LifecycleError("GUEST_PROJECT_QUOTA_DRIFT")

    def _project_paths(self, state):
        self._storage()
        expected = {str(self.root / name) for name in ("repository", "workspace", "checkouts", "references")}
        if state["room_id"] != self.room or set(state["spec"]["project_paths"]) != expected:
            raise OwnershipConflict()
        super()._project_paths(state)

    def _runtime_path(self, state):
        network_names(state)  # Validate instance before filesystem use.
        return self.root / "runtime" / state["instance_id"]

    def _runtime_marker(self, state):
        return CONTROL / (state["instance_id"] + ".runtime.json")

    def _runtime_intent(self, state):
        return CONTROL / (state["instance_id"] + ".intent.json")

    def _runtime_artifacts(self, state):
        marker, intent = self._runtime_marker(state), self._runtime_intent(state)
        return (self._runtime_path(state), marker, intent,
                marker.with_suffix(".pending"), intent.with_suffix(".pending"))

    def _intent_value(self, state):
        return {"nonce": self.nonce, "room": self.room, "instance": state["instance_id"],
                "parent": identity(self.root / "runtime"), "path": str(self._runtime_path(state))}

    def _runtime(self, state, *, create=False):
        self._storage()
        path, marker, intent = self._runtime_path(state), self._runtime_marker(state), self._runtime_intent(state)
        if any(item.is_symlink() for item in self._runtime_artifacts(state)):
            raise OwnershipConflict()  # Includes dangling links; never absence.
        expected_intent = self._intent_value(state)
        if create:
            if self._inspect_object(state, "volume") is None:
                raise BackendUnknown("runtime mutation requires its volume cleanup anchor")
            if not intent.exists() and path.exists():
                raise OwnershipConflict()
            publish(intent, expected_intent)  # Durable ownership intent BEFORE mkdir.
        try:
            if intent.is_symlink() or json.loads(intent.read_text()) != expected_intent:
                raise OwnershipConflict()
            if not marker.exists():
                if not create:
                    raise OwnershipConflict()
                if not path.exists():
                    path.mkdir(mode=0o755)
                # Only a matching pre-start intent in a root-owned parent can
                # recover this empty mkdir window. A workload cannot yet run.
                if path.resolve() != path or not path.is_dir() or any(path.iterdir()):
                    raise OwnershipConflict()
                if path.stat().st_uid not in (0, WORKSTATION_HOST_UID):
                    raise OwnershipConflict()
                os.chown(path, WORKSTATION_HOST_UID, WORKSTATION_HOST_UID)
                command("chcon", "-t", "container_file_t", "-l", self.level, str(path))
                publish(marker, {**expected_intent, "identity": identity(path)})
            if marker.is_symlink() or json.loads(marker.read_text()) != {**expected_intent, "identity": identity(path)}:
                raise OwnershipConflict()
        except (OSError, ValueError) as error:
            raise OwnershipConflict() from error
        return path

    def _remove_runtime(self, state):
        self._storage(require_selinux=False)
        path, marker, intent = self._runtime_path(state), self._runtime_marker(state), self._runtime_intent(state)
        if any(item.is_symlink() for item in self._runtime_artifacts(state)):
            raise OwnershipConflict()
        expected = self._intent_value(state)
        if intent.exists():
            if intent.is_symlink() or json.loads(intent.read_text()) != expected:
                raise OwnershipConflict()
        elif path.exists() or marker.exists():
            raise OwnershipConflict()
        if path.exists():
            if marker.exists():
                if marker.is_symlink() or json.loads(marker.read_text()) != {**expected, "identity": identity(path)}:
                    raise OwnershipConflict()
            elif path.resolve() != path or not path.is_dir() or any(path.iterdir()):
                raise OwnershipConflict()  # Incomplete mkdir may only be empty.
            shutil.rmtree(path)  # Exact marked instance path, never Project roots.
        for record in (marker, intent):
            if record.exists():
                value = json.loads(record.read_text())
                if record.is_symlink() or any(value.get(key) != item for key, item in expected.items()):
                    raise OwnershipConflict()
                record.unlink()
            pending = record.with_suffix(".pending")
            if pending.exists():
                value = json.loads(pending.read_text())
                if pending.is_symlink() or any(value.get(key) != item for key, item in expected.items()):
                    raise OwnershipConflict()
                pending.unlink()

    def inspect(self, state, kind):
        resource = super().inspect(state, kind)
        if kind == "volume" and resource is None:
            # An externally lost cleanup anchor must not turn owned policy or
            # network leftovers into a falsely successful Destroy receipt.
            if (self._network(state, policy=False) is not None or self._firewall(state) is not None
                    or any(os.path.lexists(item) for item in self._runtime_artifacts(state))):
                raise BackendUnknown("guest cleanup anchor missing with owned leftovers")
        return resource

    def _network_name(self, state):
        return network_names(state)[0]

    def _security_options(self, state):
        return ["no-new-privileges=true", "label=level:" + self.level]

    def _volume_options(self, state):
        return {"type": "none", "device": str(self._runtime_path(state)), "o": "bind"}

    def _project_writable(self, state, path):
        return path != str(self.root / "references")

    def _network(self, state, *, policy=True):
        try:
            return self._network_object(state, policy=policy)
        except (KeyError, ValueError, TypeError, AttributeError, IndexError) as error:
            raise BackendUnknown() from error

    def _network_object(self, state, *, policy=True):
        name, bridge, _ = network_names(state)
        names = self._run(["network", "ls", "--filter", "name=^" + name + "$", "--format", "{{.Name}}"])
        if not names.strip():
            return None
        if names.splitlines() != [name]:
            raise OwnershipConflict()
        values = json.loads(self._run(["network", "inspect", name]))
        if len(values) != 1:
            raise BackendUnknown()
        value = values[0]
        labels = self._labels(state, "volume")
        labels[self.LABEL + ".kind"] = "network"
        if value["Name"] != name or any(value.get("Labels", {}).get(k) != v for k, v in labels.items()):
            raise OwnershipConflict()
        expected_options = {"com.docker.network.bridge.name": bridge,
                            "com.docker.network.bridge.enable_ip_masquerade": "false"}
        if policy and (value["Driver"] != "bridge" or value["Internal"] is not False or value["EnableIPv6"] is not False
                or value["Options"] != expected_options
                or value["IPAM"]["Config"] != [{"Subnet": self.subnet, "Gateway": self.gateway}]):
            raise LifecycleError("GUEST_NETWORK_DRIFT")
        return value

    def _firewall(self, state):
        table = network_names(state)[2]
        tables = json.loads(command("nft", "-j", "list", "tables"))["nftables"]
        found = [entry["table"] for entry in tables if "table" in entry
                 and entry["table"]["family"] == "inet" and entry["table"]["name"] == table]
        if not found:
            return None
        if len(found) != 1:
            raise OwnershipConflict()
        observed = json.loads(command("nft", "-j", "list", "table", "inet", table))
        expected_owner = "uas:" + self.nonce + ":" + state["instance_id"]
        owners = [entry["table"].get("comment") for entry in observed["nftables"] if "table" in entry]
        if owners != [expected_owner]:
            raise OwnershipConflict()
        return observed

    def _ensure_network(self, state):
        # The volume is the durable cleanup anchor: install nothing before it.
        if self._inspect_object(state, "volume") is None:
            raise BackendUnknown()
        name, bridge, _ = network_names(state)
        if self._network(state) is None:
            labels = self._labels(state, "volume")
            labels[self.LABEL + ".kind"] = "network"
            self._run(["network", "create", "--driver", "bridge", "--subnet", self.subnet,
                       "--gateway", self.gateway, "--opt", "com.docker.network.bridge.name=" + bridge,
                       "--opt", "com.docker.network.bridge.enable_ip_masquerade=false",
                       *[item for key, value in labels.items() for item in ("--label", key + "=" + value)], name])
        if self._network(state) is None:
            raise BackendUnknown()
        expected = firewall_document(state, self.nonce)
        if self._firewall(state) is None:
            command("nft", "-j", "-f", "-", input=json.dumps(expected))
        if canonical_firewall(self._firewall(state)) != canonical_firewall(expected):
            raise LifecycleError("GUEST_FIREWALL_DRIFT")

    def create(self, state, kind):
        guard(self.nonce)
        self._quota()
        self._project_paths(state)
        if kind == "volume":
            # Docker's local bind volume stores options before mounting the
            # device at container start. Thus the anchor precedes mkdir effects.
            super().create(state, kind)
            self._runtime(state, create=True)
        else:
            self._runtime(state, create=True)  # Reconcile interrupted pre-start mkdir/marker.
            self._ensure_network(state)  # BEFORE Docker create/start of workload.
            super().create(state, kind)

    def _user_namespace(self, state, resource):
        try:
            self._verify_user_namespace(state, resource)
        except (OSError, KeyError, ValueError, TypeError) as error:
            raise BackendUnknown() from error

    def _verify_user_namespace(self, state, resource):
        expected = ["0", str(USERNS_BASE), "65536"]
        for name in ("subuid", "subgid"):
            records = [line for line in Path("/etc/" + name).read_text().splitlines() if line.startswith("uas-remap:")]
            if records != ["uas-remap:" + str(USERNS_BASE) + ":65536"]:
                raise LifecycleError("GUEST_USERNS_MAPPING_DRIFT")
        root = self._run(["info", "--format", "{{.DockerRootDir}}"]).strip()
        if root != "/var/lib/docker/100000.100000":
            raise LifecycleError("GUEST_USERNS_MAPPING_DRIFT")
        for path in [self._runtime_path(state), *(Path(path) for path in state["spec"]["project_paths"])]:
            info = path.stat()
            if info.st_uid != WORKSTATION_HOST_UID or info.st_gid != WORKSTATION_HOST_UID:
                raise LifecycleError("GUEST_MOUNT_OWNER_DRIFT")
        if resource["State"]["Running"] is True:
            pid = resource["State"].get("Pid")
            if type(pid) is not int or pid <= 0:
                raise BackendUnknown()
            for name in ("uid_map", "gid_map"):
                if Path(f"/proc/{pid}/{name}").read_text().split() != expected:
                    raise LifecycleError("GUEST_USERNS_MAPPING_DRIFT")

    def admit(self, state):
        guard(self.nonce)
        self._quota()
        self._runtime(state)
        if self._network(state) is None or self._firewall(state) is None:
            raise LifecycleError("GUEST_NETWORK_MISSING")
        if canonical_firewall(self._firewall(state)) != canonical_firewall(firewall_document(state, self.nonce)):
            raise LifecycleError("GUEST_FIREWALL_DRIFT")
        options = json.loads(self._run(["info", "--format", "{{json .SecurityOptions}}"]))
        if "name=selinux" not in options or "name=userns" not in options:
            raise LifecycleError("GUEST_DOCKER_SELINUX_USERNS_REQUIRED")
        resource = super().admit(state)
        self._user_namespace(state, resource)
        if (resource["ProcessLabel"] != "system_u:system_r:container_t:" + self.level
                or resource["MountLabel"] != "system_u:object_r:container_file_t:" + self.level):
            raise LifecycleError("GUEST_CONTAINER_LABEL_REQUIRED")
        return resource

    def remove(self, state, kind):
        # Cleanup checks ownership, not admission: stopped drifted workloads
        # remain removable. Never repair a running or uncertain firewall here.
        guard(self.nonce, require_selinux=False)
        if kind == "volume":
            self._storage(require_selinux=False)
            if self.inspect(state, "container") is not None:
                raise BackendUnknown()
            network = self._network(state, policy=False)
            if network is not None:
                self._run(["network", "rm", network["Id"]])
            if self._firewall(state) is not None:
                command("nft", "delete", "table", "inet", network_names(state)[2])
            # The anchor remains until exact runtime directory and metadata
            # cleanup completes. Interrupted cleanup retries from owned intent.
            try:
                self._remove_runtime(state)
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                raise BackendUnknown() from error
        super().remove(state, kind)
