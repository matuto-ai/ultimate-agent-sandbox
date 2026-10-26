"""Docker command/observation contract tests; these are not container evidence."""
import json
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from uas.docker_fixture import DockerFixtureBackend
from uas.lifecycle import BackendUnknown, LifecycleError, OwnershipConflict


class DockerFixtureContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir()
        self.backend = DockerFixtureBackend()
        self.state = {"instance_id": "a" * 32, "room_id": "alpha", "spec": {
            "image_id": "sha256:" + "b" * 64, "config_digest": "sha256:" + "c" * 64,
            "profile_digest": "sha256:" + "d" * 64, "project_paths": [str(self.project)]}}

    def object(self, *, running=False):
        return {"Id": "exact-container-id", "Name": "/" + self.backend.name(self.state, "container"),
                "Config": {"Labels": self.backend._labels(self.state, "container")},
                "Image": self.state["spec"]["image_id"], "State": {"Running": running}}

    def admitted_object(self, *, running=False):
        resource = self.object(running=running)
        resource["Config"]["User"] = "65532:65532"
        resource["HostConfig"] = {
            "ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"], "CapAdd": None,
            "SecurityOpt": ["no-new-privileges=true"], "NetworkMode": "none",
            "PidMode": "", "IpcMode": "private", "UTSMode": "", "UsernsMode": "", "CgroupnsMode": "private",
            "Devices": [], "DeviceRequests": None, "DeviceCgroupRules": None,
            "PublishAllPorts": False, "PortBindings": {}, "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "Memory": 67108864, "MemorySwap": 67108864, "NanoCpus": 500000000, "PidsLimit": 32,
            "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}},
            "MaskedPaths": ["/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"],
            "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]}
        resource["NetworkSettings"] = {"Networks": {"none": {}}}
        resource["Mounts"] = [
            {"Type": "volume", "Name": self.backend.name(self.state, "volume"), "Destination": "/state", "Driver": "local", "RW": True},
            {"Type": "bind", "Source": str(self.project), "Destination": str(self.project), "RW": False, "Propagation": "rprivate"}]
        return resource

    def volume_object(self):
        return {"Name": self.backend.name(self.state, "volume"), "Labels": self.backend._labels(self.state, "volume"),
                "Driver": "local", "Scope": "local", "Options": None}

    def observed_run(self, resource, volume=None):
        volume = self.volume_object() if volume is None else volume
        def run(arguments, **_):
            if arguments[0] == "info":
                return '["name=seccomp,profile=builtin"]'
            if arguments[:3] == ["inspect", "--type", "volume"]:
                return json.dumps([volume])
            if arguments[:3] == ["inspect", "--type", "container"]:
                return json.dumps([resource])
            return ""
        return run

    def test_admission_precedes_exact_id_start_and_running_recheck_is_read_only(self):
        with patch.object(self.backend, "_run", side_effect=self.observed_run(self.admitted_object())) as run:
            self.backend.start(self.state)
        self.assertEqual(["start", "exact-container-id"], run.call_args.args[0])
        self.assertTrue(all(call.args[0][0] in {"inspect", "info"} for call in run.call_args_list[:-1]))
        with patch.object(self.backend, "_run", side_effect=self.observed_run(self.admitted_object(running=True))) as run:
            self.backend.start(self.state)
        self.assertTrue(all(call.args[0][0] in {"inspect", "info"} for call in run.call_args_list))

    def test_boundary_drift_rejects_start_without_mutation_but_preserves_cleanup(self):
        mutations = [
            ("USER", lambda r: r["Config"].update(User="0:0")),
            ("ROOTFS", lambda r: r["HostConfig"].update(ReadonlyRootfs=False)),
            ("ROOTFS", lambda r: r["HostConfig"].update(Privileged=True)),
            ("CAPABILITIES", lambda r: r["HostConfig"].update(CapAdd=["SYS_ADMIN"])),
            ("SECURITY_OPTIONS", lambda r: r["HostConfig"].update(SecurityOpt=["seccomp=unconfined"])),
            ("SECURITY_OPTIONS", lambda r: r["HostConfig"].update(SecurityOpt=["label=disable"])),
            ("NETWORK", lambda r: r["HostConfig"].update(NetworkMode="host")),
            ("NETWORK", lambda r: r["NetworkSettings"]["Networks"].update(bridge={})),
            ("NAMESPACES", lambda r: r["HostConfig"].update(PidMode="host")),
            ("NAMESPACES", lambda r: r["HostConfig"].update(IpcMode="host")),
            ("NAMESPACES", lambda r: r["HostConfig"].update(UsernsMode="host")),
            ("DEVICES", lambda r: r["HostConfig"].update(Devices=[{"PathOnHost": "/dev/kvm"}])),
            ("PORTS", lambda r: r["HostConfig"].update(PublishAllPorts=True)),
            ("RESTART_POLICY", lambda r: r["HostConfig"].update(RestartPolicy={"Name": "always", "MaximumRetryCount": 0})),
            ("RESOURCE_LIMITS", lambda r: r["HostConfig"].update(Memory=0)),
            ("RESOURCE_LIMITS", lambda r: r["HostConfig"].update(PidsLimit=-1)),
            ("RESOURCE_LIMITS", lambda r: r["HostConfig"].update(NanoCpus=0)),
            ("LOG_LIMITS", lambda r: r["HostConfig"]["LogConfig"]["Config"].update({"max-file": "2"})),
            ("MASKED_PATHS", lambda r: r["HostConfig"].update(MaskedPaths=[])),
            ("READONLY_PATHS", lambda r: r["HostConfig"].update(ReadonlyPaths=[])),
            ("PROJECT_MOUNT", lambda r: r["Mounts"][1].update(RW=True)),
            ("PROJECT_MOUNT", lambda r: r["Mounts"][1].update(Source="/var/run/docker.sock")),
            ("PROJECT_MOUNT", lambda r: r["Mounts"][1].update(Propagation="rshared")),
            ("STATE_MOUNT", lambda r: r["Mounts"][0].update(Name="other-room-state")),
            ("MOUNTS", lambda r: r["Mounts"].append(dict(r["Mounts"][1]))),
        ]
        for control, mutate in mutations:
            resource = self.admitted_object(); mutate(resource)
            with self.subTest(control=control), patch.object(self.backend, "_run", side_effect=self.observed_run(resource)) as run:
                with self.assertRaises(LifecycleError) as raised:
                    self.backend.start(self.state)
                self.assertEqual("FIXTURE_BOUNDARY_" + control, raised.exception.code)
                self.assertTrue(all(call.args[0][0] in {"inspect", "info"} for call in run.call_args_list))
                self.assertIsNotNone(self.backend.inspect(self.state, "container"))
                self.backend.remove(self.state, "container")
                self.assertEqual(["rm", "exact-container-id"], run.call_args.args[0])

    def test_missing_metadata_volume_redirection_daemon_failure_and_path_swap_fail_closed(self):
        resource = self.admitted_object(); del resource["HostConfig"]["PidsLimit"]
        with patch.object(self.backend, "_run", side_effect=self.observed_run(resource)):
            with self.assertRaises(BackendUnknown): self.backend.start(self.state)
        volume = self.volume_object(); volume["Options"] = {"type": "none", "device": "/", "o": "bind"}
        with patch.object(self.backend, "_run", side_effect=self.observed_run(self.admitted_object(), volume)):
            with self.assertRaises(LifecycleError) as raised: self.backend.start(self.state)
            self.assertEqual("FIXTURE_BOUNDARY_STATE_VOLUME", raised.exception.code)
        with patch.object(self.backend, "_run", return_value="[]") as run:
            with self.assertRaises(LifecycleError) as raised: self.backend.start(self.state)
            self.assertEqual("FIXTURE_BOUNDARY_DAEMON_SECCOMP", raised.exception.code)
            self.assertEqual(1, run.call_count)
        self.project.rmdir(); self.project.symlink_to(self.temp.name, target_is_directory=True)
        with patch.object(self.backend, "_run") as run:
            with self.assertRaises(LifecycleError): self.backend.start(self.state)
            run.assert_not_called()

    def test_only_explicit_not_found_means_absence(self):
        name = self.backend.name(self.state, "container")
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "Error: No such object: " + name)):
            self.assertIsNone(self.backend.inspect(self.state, "container"))
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "Cannot connect to Docker daemon")):
            with self.assertRaises(BackendUnknown):
                self.backend.inspect(self.state, "container")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 1)):
            with self.assertRaises(BackendUnknown):
                self.backend.inspect(self.state, "container")

    def test_required_ownership_and_name_verified_unowned_settings_preserved(self):
        resource = self.object()
        resource["Config"]["Labels"]["user-setting"] = "keep"
        with patch.object(self.backend, "_run", return_value=json.dumps([resource])):
            self.assertEqual("keep", self.backend.inspect(self.state, "container")["labels"]["user-setting"])
        resource["Config"]["Labels"][self.backend.LABEL + ".instance"] = "other"
        with patch.object(self.backend, "_run", return_value=json.dumps([resource])):
            with self.assertRaises(OwnershipConflict):
                self.backend.inspect(self.state, "container")
        resource = self.object(); resource["Name"] = "/unowned"
        with patch.object(self.backend, "_run", return_value=json.dumps([resource])):
            with self.assertRaises(OwnershipConflict):
                self.backend.inspect(self.state, "container")

    def test_fixture_create_is_nonroot_bounded_and_has_no_network_or_runtime_socket(self):
        with patch.object(self.backend, "inspect", return_value=None), patch.object(self.backend, "_run") as run:
            self.backend.create(self.state, "container")
        arguments = run.call_args.args[0]
        self.assertEqual("65532:65532", arguments[arguments.index("--user") + 1])
        self.assertEqual("none", arguments[arguments.index("--network") + 1])
        self.assertIn("--read-only", arguments)
        self.assertIn("--memory", arguments)
        self.assertIn("--pids-limit", arguments)
        self.assertIn("--cpus", arguments)
        self.assertNotIn("--privileged", arguments)
        log_options = [arguments[index + 1] for index, value in enumerate(arguments) if value == "--log-opt"]
        self.assertEqual(["max-size=1m", "max-file=1", "compress=false"], log_options)
        self.assertFalse(any("docker.sock" in value for value in arguments))
        self.assertEqual(self.state["spec"]["image_id"], arguments[-1])

    def test_remove_uses_verified_exact_id_and_refuses_running_container(self):
        with patch.object(self.backend, "_run", side_effect=[json.dumps([self.object()]), ""]) as run:
            self.backend.remove(self.state, "container")
            self.assertEqual(["rm", "exact-container-id"], run.call_args.args[0])
        with patch.object(self.backend, "_run", return_value=json.dumps([self.object(running=True)])) as run:
            with self.assertRaises(BackendUnknown):
                self.backend.remove(self.state, "container")
            self.assertEqual(1, run.call_count)

    def test_subprocess_uses_argv_no_shell_and_bounded_timeout(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run:
            self.assertEqual("ok", self.backend._run(["version"]))
            self.assertEqual(["docker", "version"], run.call_args.args[0])
            self.assertNotIn("shell", run.call_args.kwargs)
            self.assertEqual(20, run.call_args.kwargs["timeout"])

    def test_docker28_volume_absence_is_exact_not_generic_command_failure(self):
        name = self.backend.name(self.state, "volume")
        missing = f"Error response from daemon: get {name}: no such volume"
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "[]\n", missing + "\n")):
            self.assertIsNone(self.backend.inspect(self.state, "volume"))
        for code, message in ((2, missing), (1, missing.replace(name, "different-volume")),
                              (1, "permission denied: " + missing), (1, missing + "; daemon unavailable"),
                              (1, "Cannot connect to the Docker daemon"), (1, "no such volume")):
            with self.subTest(code=code, message=message), patch("subprocess.run", return_value=subprocess.CompletedProcess([], code, "", message)):
                with self.assertRaises(BackendUnknown):
                    self.backend.inspect(self.state, "volume")
