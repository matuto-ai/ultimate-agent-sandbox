"""Exact-resource Docker backend for disposable lifecycle fixtures only.

It cannot launch Participants or supply #62 production isolation qualification.
All subprocess arguments are owned argv entries; no shell and no host pruning.
"""
import json
import subprocess

from .lifecycle import BackendUnknown, OwnershipConflict


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
            if missing_ok and any(message in process.stderr.lower() for message in (
                "no such container:", "no such volume:", "no such object:"
            )):
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

    def inspect(self, state, kind):
        name = self.name(state, kind)
        output = self._run(["inspect", "--type", kind, name], missing_ok=True)
        if output is None:
            return None
        try:
            objects = json.loads(output)
            if len(objects) != 1:
                raise BackendUnknown()
            resource = objects[0]
            labels = (resource["Config"].get("Labels") if kind == "container" else resource.get("Labels")) or {}
            if any(labels.get(key) != value for key, value in self._labels(state, kind).items()):
                raise OwnershipConflict()
            # A similarly labelled resource returned for another name is not ours.
            if resource["Name"].lstrip("/") != name:
                raise OwnershipConflict()
            if kind == "container":
                return {"id": resource["Id"], "name": name, "running": resource["State"]["Running"],
                        "image_id": resource["Image"], "labels": labels}
            return {"id": name, "name": name, "labels": labels}
        except (KeyError, TypeError, ValueError) as error:
            raise BackendUnknown() from error

    def create(self, state, kind):
        # Reconcile an uncertain prior create before attempting another effect.
        if self.inspect(state, kind) is not None:
            return
        labels = [value for key, item in self._labels(state, kind).items() for value in ("--label", key + "=" + item)]
        if kind == "volume":
            self._run(["volume", "create", *labels, self.name(state, kind)])
            return
        mounts = ["--mount", "type=volume,source=" + self.name(state, "volume") + ",target=/state"]
        for path in state["spec"]["project_paths"]:
            # Fixture paths use the same absolute host/container path, read-only.
            # Production repository read-write policy is a separate #62 launch.
            if any(character in path for character in (",", "\n", "\r")):
                raise ValueError("unsupported fixture mount path")
            mounts += ["--mount", f"type=bind,source={path},target={path},readonly"]
        self._run(["create", "--name", self.name(state, kind), *labels,
                   "--user", "65532:65532", "--read-only", "--network", "none",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
                   "--memory", "64m", "--cpus", "0.5", "--pids-limit", "32",
                   "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
                   *mounts, state["spec"]["image_id"]])

    def start(self, state):
        resource = self.inspect(state, "container")
        if resource is None:
            raise BackendUnknown()
        if not resource["running"]:
            self._run(["start", resource["id"]])

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
