"""Real filesystem and kernel-peer observations, never production qualification."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from uas.config import ConfigError, load
from uas.launch import check_launch, observe_broker_endpoint, observe_path, observe_unix_peer, probe_unix_peer_support

FIXTURE = Path(__file__).parent / "fixtures/two-rooms.json"


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads(FIXTURE.read_text())
        self.config["rooms"] = self.config["rooms"][:1]
        self.config["deployment"]["state_root"] = str(self.root / "control")
        self.room = self.config["rooms"][0]
        self.room["state_root"] = str(self.root / "control/alpha")
        self.state = Path(self.room["state_root"])
        self.state.mkdir(parents=True, mode=0o700)
        for name in self.room["project"]["roots"]:
            path = self.root / "project" / name
            path.mkdir(parents=True)
            self.room["project"]["roots"][name] = str(path)
        self.endpoint_directory = self.state / "endpoints"
        self.endpoint_directory.mkdir(mode=0o700)
        self.endpoint = self.endpoint_directory / "broker.sock"

    def require_unix_socket(self):
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.close()
        except OSError as error:
            if os.environ.get("UAS_REQUIRE_UNIX_PEER_TESTS") == "1":
                raise AssertionError("required actual Unix-peer capability unavailable") from error
            self.skipTest("local sandbox denies Unix sockets; dedicated CI requires actual kernel proof")

    def endpoint_listener(self):
        self.require_unix_socket()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.endpoint))
        self.listener.listen()
        self.listener.setblocking(False)
        os.chmod(self.endpoint, 0o660)
        self.addCleanup(self.listener.close)

    def check(self, **kwargs):
        return check_launch(io.StringIO(json.dumps(self.config)), "alpha", **kwargs)

    def endpoint_check(self, **kwargs):
        return observe_broker_endpoint(str(self.endpoint), room_state_root=str(self.state),
                                       expected_uid=kwargs.get("uid", os.getuid()),
                                       expected_gid=kwargs.get("gid", os.getgid()))

    def test_positive_observations_compile_plan_but_cannot_enable_production(self):
        self.endpoint_listener()
        report = self.check(broker_socket=str(self.endpoint), broker_uid=os.getuid(), broker_gid=os.getgid())
        implemented = [check for check in report["checks"] if check["source"] != "not-implemented"]
        self.assertTrue(all(check["status"] == "observed" for check in implemented), implemented)
        plan = report["desired_plan"]
        self.assertEqual([False, False, True], [mount["read_only"] for mount in plan["mounts"]])
        self.assertTrue(all(mount["source"] == mount["destination"] for mount in plan["mounts"]))
        self.assertEqual("not-allocated-or-mounted", plan["checkout_slots"])
        self.assertEqual(self.room["resources"], plan["resources"])
        self.assertFalse(plan["privileged"])
        self.assertFalse(plan["host_namespaces"])
        self.assertEqual([], plan["host_devices"])
        self.assertFalse(report["launch_allowed"])
        self.assertEqual("blocked", report["admission"])
        self.assertEqual("disabled", report["production_launcher"])
        unknown = {item["control"] for item in report["checks"] if item["status"] == "unknown"}
        self.assertIn("public_egress_and_deny_routes", unknown)
        self.assertIn("selinux_transport", unknown)
        self.assertIn("running_resource_bounds", unknown)
        with self.assertRaises(BlockingIOError):
            self.listener.accept()  # Inspection did not connect/send to endpoint.

    def test_actual_metadata_matches_opened_directory_identity(self):
        result = observe_path(str(self.state), control="state")
        info = self.state.stat()
        self.assertEqual("observed", result["status"])
        self.assertEqual(info.st_ino, result["observation"]["inode"])
        self.assertEqual(info.st_dev, result["observation"]["device"])
        self.assertEqual(os.getuid(), result["observation"]["uid"])

    def test_missing_wrong_type_traversal_and_symlink_paths_fail(self):
        regular = self.root / "ordinary-file"; regular.write_text("not read by observer")
        link = self.root / "link"; link.symlink_to(self.state, target_is_directory=True)
        final = self.state / "symlink"; final.symlink_to(regular)
        for path, reason in ((str(self.root / "missing"), "MISSING_PATH"),
                             (str(regular), "WRONG_FILE_TYPE"),
                             (str(self.root) + "/../escape", "UNSAFE_PATH"),
                             (str(link), "UNSAFE_PATH"), (str(link / "endpoints"), "UNSAFE_PATH"),
                             (str(final), "UNSAFE_PATH")):
            with self.subTest(path=path):
                self.assertEqual(reason, observe_path(path, control="test").get("reason"))

    def test_endpoint_requires_socket_exact_nonroot_owner_and_narrow_modes(self):
        self.endpoint_listener()
        self.assertTrue(all(item["status"] == "observed" for item in self.endpoint_check()))
        self.assertEqual("ENDPOINT_OWNER_MISMATCH", self.endpoint_check(uid=os.getuid() + 1)[0]["reason"])
        self.assertEqual("NONROOT_ENDPOINT_IDENTITY_REQUIRED", self.endpoint_check(uid=0)[0]["reason"])
        for mode in (0o666, 0o777, 0o640):
            os.chmod(self.endpoint, mode)
            self.assertEqual("ENDPOINT_MODE_UNSAFE", self.endpoint_check()[0]["reason"])
        os.chmod(self.endpoint, 0o660)
        for mode in (0o777, 0o755, 0o770):
            os.chmod(self.endpoint_directory, mode)
            self.assertIn("ENDPOINT_PARENT_MODE_UNSAFE", [item.get("reason") for item in self.endpoint_check()])
        outside = observe_broker_endpoint("/run/docker.sock", room_state_root=str(self.state),
                                          expected_uid=os.getuid(), expected_gid=os.getgid())
        self.assertEqual("ENDPOINT_OUTSIDE_ROOM_STORE", outside[0]["reason"])

    def test_endpoint_regular_file_or_missing_is_not_a_valid_socket(self):
        other = self.endpoint_directory / "not-socket"; other.write_text("not read")
        result = observe_broker_endpoint(str(other), room_state_root=str(self.state),
                                         expected_uid=os.getuid(), expected_gid=os.getgid())
        self.assertEqual("WRONG_FILE_TYPE", result[0]["reason"])
        other.unlink()
        result = observe_broker_endpoint(str(other), room_state_root=str(self.state),
                                         expected_uid=os.getuid(), expected_gid=os.getgid())
        self.assertEqual("MISSING_PATH", result[0]["reason"])

    def test_revalidation_catches_path_swapped_after_configuration_load(self):
        repo = Path(self.room["project"]["roots"]["repo"])
        def loaded_then_swapped(source):
            result = load(source)
            repo.rename(repo.with_name("old-repo"))
            repo.symlink_to(repo.with_name("workspace"), target_is_directory=True)
            return result
        with patch("uas.launch.load", side_effect=loaded_then_swapped):
            report = self.check()
        observed = next(item for item in report["checks"] if item["control"] == "project.repo")
        self.assertEqual("UNSAFE_PATH", observed["reason"])
        self.assertFalse(report["launch_allowed"])

    def test_preflight_performs_no_writes_subprocess_or_external_connect(self):
        original_open = os.open
        def read_only_open(path, flags, *args, **kwargs):
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            return original_open(path, flags, *args, **kwargs)
        with patch("os.open", side_effect=read_only_open), patch("os.chmod", side_effect=AssertionError("write")), \
                patch("subprocess.run", side_effect=AssertionError("execution")), \
                patch.object(socket.socket, "connect", side_effect=AssertionError("external connect")):
            report = self.check()
        self.assertFalse(report["launch_allowed"])

    def test_caller_evidence_and_unsafe_launch_overrides_are_not_schema(self):
        for key, value in (("launch_allowed", True), ("observed_controls", {"network": True}),
                           ("privileged", True), ("host_namespaces", True),
                           ("devices", ["/dev/kvm"]), ("mounts", ["/run/docker.sock"])):
            document = deepcopy(self.config)
            document["rooms"][0][key] = value
            with self.subTest(key=key), patch("uas.launch.observe_path", side_effect=AssertionError("invalid config observed")):
                with self.assertRaises(ConfigError):
                    check_launch(io.StringIO(json.dumps(document)), "alpha")
        for key in self.room["boundary"]:
            document = deepcopy(self.config); document["rooms"][0]["boundary"][key] = False
            with self.subTest(control=key), self.assertRaises(ConfigError):
                check_launch(io.StringIO(json.dumps(document)), "alpha")
        with self.assertRaises(ConfigError):
            check_launch(io.StringIO(json.dumps(self.config)), "missing-room")

    def test_kernel_probe_is_literal_support_not_broker_or_participant_authority(self):
        result = probe_unix_peer_support()
        if result["status"] != "observed" and os.environ.get("UAS_REQUIRE_UNIX_PEER_TESTS") != "1":
            self.skipTest("local kernel socketpair observation unavailable; CI requires it")
        self.assertEqual("observed", result["status"])
        self.assertEqual(os.getpid(), result["observation"]["pid"])
        self.assertEqual(os.getuid(), result["observation"]["uid"])
        self.assertEqual("local-probe-only-not-broker-authentication", result["scope"])
        self.assertEqual("NOT_UNIX_STREAM", observe_unix_peer({"uid": os.getuid(), "pid": os.getpid()})["reason"])

    def test_unconnected_or_nonstream_descriptor_is_not_peer_evidence(self):
        self.require_unix_socket()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unconnected:
            self.assertEqual("unknown", observe_unix_peer(unconnected)["status"])
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as datagram:
            self.assertEqual("NOT_UNIX_STREAM", observe_unix_peer(datagram)["reason"])

    def test_kernel_peer_identifies_real_other_process_without_client_claims(self):
        self.require_unix_socket()
        path = self.root / "peer.sock"
        program = '''import socket,sys
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
 server.bind(sys.argv[1]); server.listen(); print("ready",flush=True)
 connection,_=server.accept()
 with connection: connection.recv(1)
'''
        process = subprocess.Popen([sys.executable, "-c", program, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], "peer fixture did not become ready")
            self.assertEqual("ready", process.stdout.readline().strip())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(path))
                result = observe_unix_peer(client)
                self.assertEqual("observed", result["status"])
                self.assertEqual(process.pid, result["observation"]["pid"])
                self.assertEqual(os.getuid(), result["observation"]["uid"])
                self.assertEqual(os.getgid(), result["observation"]["gid"])
            self.assertEqual(0, process.wait(timeout=5))
        finally:
            if process.poll() is None:
                process.terminate(); process.wait(timeout=5)
            process.stdout.close(); process.stderr.close()

    def test_cli_is_observable_but_returns_blocked_exit_not_successful_launch(self):
        path = self.root / "config.json"; path.write_text(json.dumps(self.config))
        result = subprocess.run([sys.executable, "-m", "uas", "check-launch", str(path), "--room", "alpha"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(3, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual("alpha", report["room_id"])
        self.assertEqual("blocked", report["admission"])
        self.assertFalse(report["launch_allowed"])
        self.assertEqual("", result.stderr)

    def test_positive_filesystem_plan_is_not_inferred_host_enforcement(self):
        report = self.check()
        paths = [item for item in report["checks"] if item["control"].startswith("project.")]
        self.assertEqual(4, len(paths))
        self.assertTrue(all(item["status"] == "observed" for item in paths))
        self.assertEqual("declaration-only-not-launchable", report["desired_plan"]["status"])
        self.assertEqual([False, False, True], [mount["read_only"] for mount in report["desired_plan"]["mounts"]])
        self.assertFalse(report["launch_allowed"])
        self.assertEqual("ENDPOINT_NOT_SELECTED", next(item for item in report["checks"] if item["control"] == "broker_endpoint")["reason"])

    def test_unavailable_peer_probe_stays_unknown_not_success(self):
        with patch("socket.socketpair", side_effect=PermissionError("fixture denial")):
            result = probe_unix_peer_support()
        self.assertEqual("unknown", result["status"])
        self.assertEqual("KERNEL_PEER_UNAVAILABLE", result["reason"])
