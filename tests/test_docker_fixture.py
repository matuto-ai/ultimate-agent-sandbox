"""Docker command/observation contract tests; these are not container evidence."""
import json
import subprocess
import unittest
from unittest.mock import patch

from uas.docker_fixture import DockerFixtureBackend
from uas.lifecycle import BackendUnknown, OwnershipConflict


class DockerFixtureContractTests(unittest.TestCase):
    def setUp(self):
        self.backend = DockerFixtureBackend()
        self.state = {"instance_id": "a" * 32, "room_id": "alpha", "spec": {
            "image_id": "sha256:" + "b" * 64, "config_digest": "sha256:" + "c" * 64,
            "profile_digest": "sha256:" + "d" * 64, "project_paths": ["/tmp/fixture-project"]}}

    def object(self, *, running=False):
        return {"Id": "exact-container-id", "Name": "/" + self.backend.name(self.state, "container"),
                "Config": {"Labels": self.backend._labels(self.state, "container")},
                "Image": self.state["spec"]["image_id"], "State": {"Running": running}}

    def test_only_explicit_not_found_means_absence(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "Error: No such object: name")):
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
