"""Exact-resource Docker backend for disposable lifecycle fixtures only.

It cannot launch Participants or supply #62 production isolation qualification.
All subprocess arguments are owned argv entries; no shell and no host pruning.
"""
import json
import subprocess

from .launch import observe_path
from .lifecycle import BackendUnknown, LifecycleError, OwnershipConflict


class DockerFixtureBackend:
    LABEL = "im.puglab.uas.fixture"

    def __init__(self, *, executable="docker", timeout=20):
        self.executable, self.timeout = executable, timeout

    def _run(self, arguments, *, missing_ok=False):
        try:
            process = subprocess.run([self.executable, *arguments], capture_output=True,
                                     text=True, timeout=self.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BackendUnknown() from error
        if process.returncode:
            # A daemon/permission/transport error is not evidence of absence.
            if missing_ok and process.returncode == 1 and len(arguments) == 4 and arguments[:2] == ["inspect", "--type"]:
                kind, name = arguments[2:]
                if kind in {"container", "volume"}:
                    absent = {f"Error: No such {kind}: {name}",
                              f"Error response from daemon: No such {kind}: {name}",
                              f"Error: No such object: {name}"}
                    if kind == "volume":
                        # Docker 28's volume OpErr is `get NAME: no such volume`.
                        # Match the complete response and exact requested name,
                        # never a substring in an unrelated daemon/auth error.
                        absent.add(f"Error response from daemon: get {name}: no such volume")
                    if process.stderr.strip().casefold() in {message.casefold() for message in absent}:
                        return None
            raise BackendUnknown()
        return process.stdout

    def name(self, state, kind):
        if kind not in {"container", "volume"}:
            raise ValueError("unknown fixture resource")
        return "uas-fixture-" + state["instance_id"] + ("-state" if kind == "volume" else "")

    def _labels(self, state, kind):
        return {self.LABEL: "true", self.LABEL + ".room": state["room_id"],
                self.LABEL + ".instance": state["instance_id"], self.LABEL + ".kind": kind,
                self.LABEL + ".config": state["spec"]["config_digest"],
                self.LABEL + ".profile": state["spec"]["profile_digest"]}

    def _inspect_object(self, state, kind):
        name = self.name(state, kind)
        output = self._run(["inspect", "--type", kind, name], missing_ok=True)
        if output is None:
            return None
        try:
            objects = json.loads(output)
            if type(objects) is not list or len(objects) != 1 or type(objects[0]) is not dict:
                raise BackendUnknown()
            resource = objects[0]
            labels = (resource["Config"].get("Labels") if kind == "container" else resource.get("Labels")) or {}
            if any(labels.get(key) != value for key, value in self._labels(state, kind).items()):
                raise OwnershipConflict()
            # A similarly labelled resource returned for another name is not ours.
            if resource["Name"].lstrip("/") != name:
                raise OwnershipConflict()
            return resource
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise BackendUnknown() from error

    def inspect(self, state, kind):
        # Ownership observation remains available for status and safe cleanup
        # even when execution admission fails. Never hide rejected resources.
        resource = self._inspect_object(state, kind)
        if resource is None:
            return None
        name = self.name(state, kind)
        try:
            if kind == "container":
                if type(resource["State"]["Running"]) is not bool:
                    raise BackendUnknown()
                return {"id": resource["Id"], "name": name, "running": resource["State"]["Running"],
                        "image_id": resource["Image"], "labels": resource["Config"].get("Labels") or {}}
            return {"id": name, "name": name, "labels": resource.get("Labels") or {}}
        except (KeyError, TypeError) as error:
            raise BackendUnknown() from error

    @staticmethod
    def _require(value, control):
        if not value:
            raise LifecycleError("FIXTURE_BOUNDARY_" + control)

    # Fixed backend policy seams. The default remains the conservative
    # network-none/read-only fixture; callers cannot supply policy overrides.
    def _network_name(self, state):
        return "none"

    def _security_options(self, state):
        return ["no-new-privileges=true"]

    def _volume_options(self, state):
        return {}

    def _project_writable(self, state, path):
        return False

    def _resource_limits(self, state):
        return {"Memory": 64 * 1024 * 1024, "MemorySwap": 64 * 1024 * 1024,
                "NanoCpus": 500_000_000, "PidsLimit": 32}

    def _log_config(self, state):
        return {"Type": "local", "Config": {
            "max-size": "1m", "max-file": "1", "compress": "false"}}

    def _endpoint_mounts(self, state):
        # Only a trusted fixed backend may supply these. Its admission must
        # retain/revalidate actual endpoint objects before returning this plan.
        return ()

    def _project_paths(self, state):
        for path in state["spec"]["project_paths"]:
            result = observe_path(path, control="fixture.project")
            self._require(result["status"] == "observed", "PROJECT_PATH")

    def admit(self, state):
        """Inspect real owned resources before execution, never caller evidence.

        This gates only the conservative network-none fixture. It is NOT a
        production qualification, a mount lease, or continuous drift watchdog.
        The Docker daemon and fixture image are trusted test infrastructure.
        """
        self._project_paths(state)
        try:
            security = json.loads(self._run(["info", "--format", "{{json .SecurityOptions}}"]))
            self._require(type(security) is list and "name=seccomp,profile=builtin" in security,
                          "DAEMON_SECCOMP")
        except (TypeError, ValueError) as error:
            raise BackendUnknown() from error
        return self._admit_resources(state)

    def _admit_resources(self, state):
        # Private body: public admission always observes paths and daemon policy.
        volume = self._inspect_object(state, "volume")
        resource = self._inspect_object(state, "container")
        if volume is None or resource is None:
            raise BackendUnknown()
        required = self._require
        try:
            required(volume["Driver"] == "local" and volume["Scope"] == "local"
                     and (volume.get("Options") or {}) == self._volume_options(state), "STATE_VOLUME")
            config, host = resource["Config"], resource["HostConfig"]
            required(resource["Image"] == state["spec"]["image_id"], "IMAGE")
            required(config["User"] == "65532:65532", "USER")
            required(host["ReadonlyRootfs"] is True and host["Privileged"] is False, "ROOTFS")
            required(host["CapDrop"] == ["ALL"] and host["CapAdd"] in (None, []), "CAPABILITIES")
            required([value.replace("no-new-privileges=true", "no-new-privileges") for value in host["SecurityOpt"]]
                     == [value.replace("no-new-privileges=true", "no-new-privileges") for value in self._security_options(state)],
                     "SECURITY_OPTIONS")
            required(host["NetworkMode"] == self._network_name(state)
                     and set(resource["NetworkSettings"]["Networks"]) == {self._network_name(state)}, "NETWORK")
            required(host["PidMode"] == "" and host["IpcMode"] == "private" and host["UTSMode"] == ""
                     and host["UsernsMode"] == "" and host["CgroupnsMode"] == "private", "NAMESPACES")
            required(all(host[key] in (None, []) for key in ("Devices", "DeviceRequests", "DeviceCgroupRules")), "DEVICES")
            required(host["PublishAllPorts"] is False and host["PortBindings"] in (None, {}), "PORTS")
            required(host["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0}, "RESTART_POLICY")
            required(all(type(host[key]) is int and host[key] == value
                         for key, value in self._resource_limits(state).items()), "RESOURCE_LIMITS")
            required(host["LogConfig"] == self._log_config(state), "LOG_LIMITS")
            required({"/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"}
                     <= set(host["MaskedPaths"]), "MASKED_PATHS")
            required({"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}
                     <= set(host["ReadonlyPaths"]), "READONLY_PATHS")
            mounts = resource["Mounts"]
            endpoints = dict(self._endpoint_mounts(state))
            required(type(mounts) is list and len(mounts) == len(state["spec"]["project_paths"]) + len(endpoints) + 1, "MOUNTS")
            destinations = set()
            for mount in mounts:
                destination = mount["Destination"]
                required(destination not in destinations, "MOUNTS")
                destinations.add(destination)
                if destination == "/state":
                    required(mount["Type"] == "volume" and mount["Name"] == self.name(state, "volume")
                             and mount["Driver"] == "local" and mount["RW"] is True, "STATE_MOUNT")
                elif destination in endpoints:
                    required(mount["Type"] == "bind" and mount["Source"] == endpoints[destination]
                             and mount["RW"] is False and mount["Propagation"] == "rprivate", "ENDPOINT_MOUNT")
                else:
                    required(destination in state["spec"]["project_paths"] and mount["Type"] == "bind"
                             and mount["Source"] == destination and mount["RW"] is self._project_writable(state, destination)
                             and mount["Propagation"] == "rprivate", "PROJECT_MOUNT")
            required(destinations == {"/state", *state["spec"]["project_paths"], *endpoints}, "MOUNTS")
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            # Missing/malformed daemon data never becomes an accepted default.
            raise BackendUnknown() from error
        return resource

    def create(self, state, kind):
        # Reconcile an uncertain prior create before attempting another effect.
        if self.inspect(state, kind) is not None:
            return
        labels = [value for key, item in self._labels(state, kind).items() for value in ("--label", key + "=" + item)]
        if kind == "volume":
            options = [value for key, item in self._volume_options(state).items() for value in ("--opt", key + "=" + item)]
            self._run(["volume", "create", *labels, *options, self.name(state, kind)])
            return
        self._project_paths(state)
        mounts = ["--mount", "type=volume,source=" + self.name(state, "volume") + ",target=/state"]
        for path in state["spec"]["project_paths"]:
            # Fixture paths use the same absolute host/container path, read-only.
            # Production repository read-write policy is a separate #62 launch.
            if any(character in path for character in (",", "\n", "\r")):
                raise ValueError("unsupported fixture mount path")
            mode = "" if self._project_writable(state, path) else ",readonly"
            mounts += ["--mount", f"type=bind,source={path},target={path}" + mode]
        for destination, source in self._endpoint_mounts(state):
            mounts += ["--mount", f"type=bind,source={source},target={destination},readonly"]
        limits, logging = self._resource_limits(state), self._log_config(state)
        cpu = str(limits["NanoCpus"] // 1_000_000_000) + "." + str(limits["NanoCpus"] % 1_000_000_000).zfill(9)
        self._run(["create", "--name", self.name(state, kind), *labels,
                   "--user", "65532:65532", "--read-only", "--network", self._network_name(state),
                   "--ipc", "private", "--cgroupns", "private",
                   "--cap-drop", "ALL",
                   *[value for option in self._security_options(state) for value in ("--security-opt", option)],
                   "--memory", str(limits["Memory"]), "--memory-swap", str(limits["MemorySwap"]),
                   "--cpus", cpu, "--pids-limit", str(limits["PidsLimit"]),
                   "--log-driver", logging["Type"],
                   *[value for key, item in logging["Config"].items() for value in ("--log-opt", key + "=" + item)],
                   *mounts, state["spec"]["image_id"]])

    def start(self, state):
        # Repeat actual admission immediately before the effect. Direct backend
        # callers cannot bypass it, and a name replacement cannot redirect start.
        resource = self.admit(state)
        if resource["State"]["Running"] is False:
            self._run(["start", resource["Id"]])
        elif resource["State"]["Running"] is not True:
            raise BackendUnknown()

    def stop(self, state):
        resource = self.inspect(state, "container")
        if resource is not None and resource["running"]:
            self._run(["stop", "--time", "3", resource["id"]])

    def remove(self, state, kind):
        # Re-verify immediately before an exact-ID destructive call.
        resource = self.inspect(state, kind)
        if resource is None:
            return
        if kind == "container":
            if resource["running"]:
                raise BackendUnknown()
            self._run(["rm", resource["id"]])
        else:
            self._run(["volume", "rm", resource["id"]])
