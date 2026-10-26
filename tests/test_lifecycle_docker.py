"""Actual Docker integration; required dedicated CI job, explicit local skip."""
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from uas.docker_fixture import DockerFixtureBackend
from uas.lifecycle import BackendUnknown, FixtureSpec, LifecycleError, Supervisor

IMAGE = os.environ.get("UAS_DOCKER_FIXTURE_IMAGE")
WORKER = Path(__file__).parent / "fixtures/lifecycle_worker.py"


class FaultBackend(DockerFixtureBackend):
    lose_create_response = False
    fail_volume_remove = False
    create_drift = None

    def _run(self, arguments, **kwargs):
        if arguments[0] == "create" and self.create_drift:
            arguments = list(arguments)
            if self.create_drift == "pids":
                arguments[arguments.index("--pids-limit") + 1] = "16"
            elif self.create_drift == "mount":
                arguments = [item.removesuffix(",readonly") if item.startswith("type=bind,") else item for item in arguments]
            else:
                raise AssertionError("unknown synthetic drift")
        return super()._run(arguments, **kwargs)

    def create(self, state, kind):
        super().create(state, kind)
        if self.lose_create_response:
            raise BackendUnknown()

    def remove(self, state, kind):
        if kind == "volume" and self.fail_volume_remove:
            raise BackendUnknown()
        super().remove(state, kind)


@unittest.skipUnless(IMAGE, "actual Docker fixture runs in its dedicated CI job; not local runtime proof")
class DockerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="uas-lifecycle-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.project.chmod(0o777)  # Probe must fail EROFS, not discretionary EACCES.
        self.sentinel = self.project / "user-owned.txt"
        self.sentinel.write_text("never delete Project data")
        self.backend = FaultBackend()
        self.spec = FixtureSpec("alpha", "fixture", (str(self.project),), IMAGE,
                                "sha256:" + "b" * 64, "sha256:" + "c" * 64)
        self.revocations = []
        self.supervisor = self.reopen()
        self.addCleanup(self.cleanup_room)

    def reopen(self):
        def revoke(instance, scope):
            self.revocations.append((instance, scope))
            return True  # No capabilities are issued in this fixture.
        return Supervisor(self.root / "control", "alpha", self.backend,
                          authorize=lambda *_: True, revoke=revoke)

    def cleanup_room(self):
        self.backend.fail_volume_remove = False
        if self.supervisor.status()["phase"] != "absent":
            result = self.supervisor.destroy()
            self.assertEqual("destroyed", result["phase"], result)

    def wait_started(self, container, count):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            output = self.backend._run(["logs", container])
            if f"fixture start={count} uid=65532" in output:
                return
            time.sleep(0.05)
        self.fail("fixture did not report persistent startup count")

    def assert_running(self, result):
        if result["phase"] != "running":
            container = result["observed"].get("container")
            if container and "id" in container:
                # Read only this already ownership-verified disposable fixture.
                state = json.loads(self.backend._run(["inspect", "--type", "container", container["id"]]))[0]["State"]
                diagnostic = {key: state.get(key) for key in ("Status", "Error", "ExitCode", "OOMKilled")}
                print("Fixture startup state:", json.dumps(diagnostic)[:4096], flush=True)
                logs = subprocess.run(["docker", "logs", "--tail", "30", container["id"]],
                                      capture_output=True, text=True, timeout=20)
                print("Fixture startup logs:", logs.stdout[-4096:], logs.stderr[-4096:], flush=True)
        self.assertEqual("running", result["phase"], result)

    def assert_kernel_boundary(self, container):
        # Real fixture process, not caller flags or a forged inspect object.
        probe = json.loads(self.backend._run(["exec", container, "/fixture", "--probe", str(self.project)]))
        print("Fixture kernel boundary:", json.dumps(probe, sort_keys=True), flush=True)
        self.assertEqual([], probe["errors"])
        self.assertEqual((65532, 65532), (probe["uid"], probe["gid"]))
        self.assertEqual("0" * 16, probe["process"]["CapEff"])
        self.assertEqual("0" * 16, probe["process"]["CapBnd"])
        self.assertEqual("1", probe["process"]["NoNewPrivs"])
        self.assertEqual("2", probe["process"]["Seccomp"])
        self.assertEqual("67108864", probe["cgroup"]["memory.max"])
        self.assertEqual("32", probe["cgroup"]["pids.max"])
        quota, period = map(int, probe["cgroup"]["cpu.max"].split())
        self.assertEqual(period, quota * 2)
        self.assertEqual(["lo"], probe["interfaces"])
        self.assertEqual("ENETUNREACH", probe["network_connect"])
        self.assertEqual("EROFS", probe["root_write"])
        self.assertEqual("EROFS", probe["project_write"])

    def test_real_lifecycle_persistence_drift_partial_destroy_and_recreation(self):
        # Deliberately unowned sibling volume must survive all supervisor actions.
        unrelated = "uas-unowned-test-" + uuid.uuid4().hex
        self.backend._run(["volume", "create", "--label", "uas.integration-test=" + unrelated, unrelated])
        def cleanup_unrelated():
            resource = json.loads(self.backend._run(["volume", "inspect", unrelated]))[0]
            self.assertEqual(unrelated, resource["Labels"]["uas.integration-test"])
            self.backend._run(["volume", "rm", unrelated])
        self.addCleanup(cleanup_unrelated)
        self.backend.lose_create_response = True
        first = self.supervisor.start(self.spec)
        self.assert_running(first)
        container = first["observed"]["container"]["id"]
        self.wait_started(container, 1)
        self.assert_kernel_boundary(container)
        actual = json.loads(self.backend._run(["inspect", "--type", "container", container]))[0]
        self.assertEqual("65532:65532", actual["Config"]["User"])
        self.assertEqual("none", actual["HostConfig"]["NetworkMode"])
        self.assertTrue(actual["HostConfig"]["ReadonlyRootfs"])
        self.assertFalse(actual["HostConfig"]["Privileged"])
        self.assertEqual(64 * 1024 * 1024, actual["HostConfig"]["Memory"])
        self.assertEqual(500_000_000, actual["HostConfig"]["NanoCpus"])
        self.assertEqual(32, actual["HostConfig"]["PidsLimit"])
        self.assertEqual({"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}},
                         actual["HostConfig"]["LogConfig"])
        self.assertFalse(any("docker.sock" in mount["Destination"] for mount in actual["Mounts"]))
        self.assertEqual(container, self.supervisor.start(self.spec)["observed"]["container"]["id"])
        instance = first["instance_id"]
        data = self.root / "control/alpha/instances" / instance / "data"
        (data / "hub-state-fixture").write_text("retained across Stop")
        self.assertEqual("stopped", self.supervisor.stop()["phase"])
        self.assertEqual("retained across Stop", (data / "hub-state-fixture").read_text())
        self.supervisor = self.reopen()
        self.assertEqual("stopped", self.supervisor.status()["phase"])
        resumed = self.supervisor.start(self.spec)
        self.assertEqual(instance, resumed["instance_id"])
        self.assertEqual(container, resumed["observed"]["container"]["id"])
        self.wait_started(container, 2)
        self.assert_kernel_boundary(container)
        changed = replace(self.spec, config_digest="sha256:" + "d" * 64,
                          profile_digest="sha256:" + "e" * 64)
        staged = self.supervisor.start(changed)
        self.assertEqual(changed.document(), staged["pending_spec"])
        self.assertEqual(container, staged["observed"]["container"]["id"])
        self.backend.fail_volume_remove = True
        failed = self.supervisor.destroy()
        self.assertEqual("destroy_failed", failed["phase"])
        self.assertEqual(["volume", "control-state"], [item["kind"] for item in failed["leftovers"]])
        self.assertIsNone(failed["observed"]["container"])
        self.assertTrue(data.exists())
        with self.assertRaises(LifecycleError) as raised:
            self.supervisor.start(self.spec)
        self.assertEqual("DESTROY_INCOMPLETE", raised.exception.code)
        self.backend.fail_volume_remove = False
        self.assertEqual("destroyed", self.reopen().reconcile()["phase"])
        tombstone = self.root / "control/alpha/tombstones" / (instance + ".json")
        self.assertTrue(tombstone.is_file())
        self.assertFalse(data.parent.exists())
        self.assertEqual("never delete Project data", self.sentinel.read_text())
        self.assertIsNotNone(self.backend._run(["volume", "inspect", unrelated]))
        recreated = self.supervisor.start(self.spec)
        self.assert_running(recreated)
        self.assertNotEqual(instance, recreated["instance_id"])
        self.assertNotEqual(container, recreated["observed"]["container"]["id"])
        self.assertTrue(tombstone.is_file())
        self.assertTrue(any(scope == "all" for _, scope in self.revocations))

    def test_actual_created_boundary_drift_never_starts_and_remains_destroyable(self):
        # Deliberately alter only this disposable synthetic fixture. The mount
        # case contains no real Project data; neither rejected container starts.
        for drift, reason in (("pids", "RESOURCE_LIMITS"), ("mount", "PROJECT_MOUNT")):
            with self.subTest(drift=drift):
                self.backend.create_drift = drift
                failed = self.supervisor.start(self.spec)
                self.assertEqual("start_failed", failed["phase"], failed)
                self.assertEqual("FIXTURE_BOUNDARY_" + reason, failed["leftovers"][0]["reason"])
                container = failed["observed"]["container"]["id"]
                actual = json.loads(self.backend._run(["inspect", "--type", "container", container]))[0]
                self.assertEqual("created", actual["State"]["Status"])
                self.assertFalse(actual["State"]["Running"])
                self.assertEqual("", self.backend._run(["logs", container]))
                again = self.reopen().reconcile()
                self.assertEqual("start_failed", again["phase"])
                self.assertEqual(container, again["observed"]["container"]["id"])
                self.assertEqual("destroyed", self.reopen().destroy()["phase"])
                self.assertEqual("never delete Project data", self.sentinel.read_text())
        self.backend.create_drift = None
        self.assert_running(self.supervisor.start(self.spec))

    def test_actual_resume_and_running_drift_fail_closed_without_silent_repair(self):
        first = self.supervisor.start(self.spec)
        self.assert_running(first)
        container = first["observed"]["container"]["id"]
        self.wait_started(container, 1)
        self.assertEqual("stopped", self.supervisor.stop()["phase"])
        # Tighten, never exhaust, the test container's process cap.
        self.backend._run(["update", "--pids-limit", "16", container])
        failed = self.reopen().start(self.spec)
        self.assertEqual("start_failed", failed["phase"])
        self.assertFalse(failed["observed"]["container"]["running"])
        actual = json.loads(self.backend._run(["inspect", "--type", "container", container]))[0]
        self.assertEqual(16, actual["HostConfig"]["PidsLimit"])
        self.assertNotIn("fixture start=2", self.backend._run(["logs", container]))
        # Explicit test-operator repair, not a supervisor rewrite of drift.
        self.backend._run(["update", "--pids-limit", "32", container])
        self.assert_running(self.reopen().reconcile())
        self.wait_started(container, 2)
        self.assert_kernel_boundary(container)
        self.backend._run(["update", "--pids-limit", "16", container])
        failed = self.reopen().reconcile()
        self.assertEqual("start_failed", failed["phase"])
        self.assertTrue(failed["observed"]["container"]["running"])
        self.assertEqual("stopped", self.reopen().stop()["phase"])
        self.assertEqual("destroyed", self.reopen().destroy()["phase"])

    def test_sigkill_after_actual_container_removal_reconciles_remaining_volume(self):
        first = self.supervisor.start(self.spec)
        self.assert_running(first)
        self.wait_started(first["observed"]["container"]["id"], 1)
        killed = subprocess.run([sys.executable, str(WORKER), str(self.root / "control")],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(-signal.SIGKILL, killed.returncode, killed.stderr)
        interrupted = self.reopen().status()
        self.assertEqual("destroying", interrupted["phase"])
        self.assertIsNone(interrupted["observed"]["container"])
        self.assertIsNotNone(interrupted["observed"]["volume"])
        self.assertEqual("destroyed", self.reopen().reconcile()["phase"])
        self.assertEqual("never delete Project data", self.sentinel.read_text())
