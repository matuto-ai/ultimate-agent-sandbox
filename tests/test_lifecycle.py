from dataclasses import replace
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from lifecycle_support import FileFixtureBackend
from uas.lifecycle import FixtureSpec, LifecycleError, Supervisor


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.sentinel = self.project / "human-data"
        self.sentinel.write_text("retain this")
        self.backend = FileFixtureBackend(self.root / "resources")
        self.spec = FixtureSpec("alpha", "project", (str(self.project),), "sha256:" + "a" * 64,
                                "sha256:" + "b" * 64, "sha256:" + "c" * 64)
        self.authorized = True
        self.supervisor = self.reopen()

    def reopen(self):
        return Supervisor(self.root / "control", "alpha", self.backend,
                          authorize=lambda *_: self.authorized, revoke=self.backend.revoke)

    def manifest(self):
        return json.loads((self.root / "control/alpha/lifecycle.json").read_text())

    def error(self, code, function):
        with self.assertRaises(LifecycleError) as raised:
            function()
        self.assertEqual(code, raised.exception.code)

    def test_create_repeated_start_stop_resume_and_reopen_keep_identity(self):
        first = self.supervisor.start(self.spec)
        self.assertEqual("running", first["phase"])
        self.assertEqual("unqualified", first["production_launch"])
        self.assertEqual(first["instance_id"], self.supervisor.start(self.spec)["instance_id"])
        self.assertEqual("stopped", self.supervisor.stop()["phase"])
        self.assertEqual("stopped", self.reopen().status()["phase"])
        resumed = self.reopen().start(self.spec)
        self.assertEqual(first["instance_id"], resumed["instance_id"])
        self.assertEqual(1, self.backend.calls.count("create-container"))
        self.assertEqual(1, self.backend.calls.count("create-volume"))
        self.assertEqual("preserved", resumed["observed"]["container"]["unowned_setting"])
        self.assertEqual("retain this", self.sentinel.read_text())

    def test_destroy_revokes_first_preserves_project_and_immutable_tombstone(self):
        first = self.supervisor.start(self.spec)
        data = self.root / "control/alpha/instances" / first["instance_id"] / "data"
        (data / "hub-state").write_text("fixture")
        self.backend.calls.clear()
        destroyed = self.supervisor.destroy()
        self.assertEqual("destroyed", destroyed["phase"])
        self.assertEqual("revoke-all", self.backend.calls[0])
        self.assertFalse(data.parent.exists())
        tombstone = self.root / "control/alpha/tombstones" / (first["instance_id"] + ".json")
        original = tombstone.read_bytes()
        self.assertEqual(0o400, tombstone.stat().st_mode & 0o777)
        self.assertEqual("destroyed", self.supervisor.destroy()["phase"])
        self.assertEqual(original, tombstone.read_bytes())
        recreated = self.supervisor.start(self.spec)
        self.assertNotEqual(first["instance_id"], recreated["instance_id"])
        self.assertEqual(original, tombstone.read_bytes())
        self.assertEqual("retain this", self.sentinel.read_text())

    def test_partial_destroy_exact_leftovers_blocks_recreate_then_targeted_retry(self):
        self.supervisor.start(self.spec)
        self.backend.fail_before.add("remove-volume")
        failed = self.supervisor.destroy()
        self.assertEqual("destroy_failed", failed["phase"])
        self.assertEqual("DESTROY_FAILED", failed["error"])
        self.assertEqual(["volume", "control-state"], [item["kind"] for item in failed["leftovers"]])
        self.assertIsNone(failed["observed"]["container"])
        self.assertIsNotNone(failed["observed"]["volume"])
        self.error("DESTROY_INCOMPLETE", lambda: self.supervisor.start(self.spec))
        self.backend.fail_before.clear()
        self.backend.calls.clear()
        self.assertEqual("destroyed", self.reopen().reconcile()["phase"])
        self.assertNotIn("remove-container", self.backend.calls)
        self.assertIn("remove-volume", self.backend.calls)
        self.assertEqual("retain this", self.sentinel.read_text())

    def test_lost_create_start_stop_remove_responses_reconcile_without_duplicate(self):
        self.backend.fail_after.update({"create-container", "create-volume", "start", "stop", "remove-container", "remove-volume"})
        self.assertEqual("running", self.supervisor.start(self.spec)["phase"])
        self.assertEqual("running", self.supervisor.reconcile()["phase"])
        self.assertEqual(1, self.backend.calls.count("create-container"))
        self.assertEqual("stopped", self.supervisor.stop()["phase"])
        self.assertEqual("destroyed", self.supervisor.destroy()["phase"])
        self.assertEqual(1, self.backend.calls.count("remove-container"))
        self.assertEqual(1, self.backend.calls.count("remove-volume"))

    def test_missing_create_effect_is_not_blindly_repeated_in_same_attempt(self):
        self.backend.fail_before.add("create-container")
        failed = self.supervisor.start(self.spec)
        self.assertEqual("start_failed", failed["phase"])
        self.assertEqual(1, self.backend.calls.count("create-container"))
        self.backend.fail_before.clear()
        resumed = self.reopen().reconcile()
        self.assertEqual("running", resumed["phase"])
        self.assertEqual(failed["instance_id"], resumed["instance_id"])
        self.assertEqual(1, self.backend.calls.count("create-volume"))

    def test_unknown_observation_prevents_effects(self):
        from uas.lifecycle import BackendUnknown
        with patch.object(self.backend, "inspect", side_effect=BackendUnknown):
            result = self.supervisor.start(self.spec)
        self.assertEqual("start_failed", result["phase"])
        self.assertEqual([], self.backend.calls)

    def test_boundary_admission_rejection_before_first_start_resume_and_running_reconcile(self):
        with patch.object(self.backend, "admit", side_effect=LifecycleError("FIXTURE_BOUNDARY_RESOURCE_LIMITS")):
            failed = self.supervisor.start(self.spec)
        self.assertEqual("start_failed", failed["phase"])
        self.assertFalse(failed["observed"]["container"]["running"])
        self.assertNotIn("start", self.backend.calls)
        self.assertEqual("FIXTURE_BOUNDARY_RESOURCE_LIMITS", failed["leftovers"][0]["reason"])
        self.assertEqual("running", self.reopen().reconcile()["phase"])
        self.assertEqual("stopped", self.supervisor.stop()["phase"])
        self.backend.calls.clear()
        with patch.object(self.backend, "admit", side_effect=LifecycleError("FIXTURE_BOUNDARY_PROJECT_MOUNT")):
            self.assertEqual("start_failed", self.reopen().start(self.spec)["phase"])
            self.assertNotIn("start", self.backend.calls)
        self.assertEqual("running", self.reopen().reconcile()["phase"])
        with patch.object(self.backend, "admit", side_effect=LifecycleError("FIXTURE_BOUNDARY_PROJECT_MOUNT")):
            failed = self.reopen().reconcile()
            self.assertEqual("start_failed", failed["phase"])
            self.assertTrue(failed["observed"]["container"]["running"])
            self.assertEqual("stopped", self.reopen().stop()["phase"])
            self.assertEqual("destroyed", self.reopen().destroy()["phase"])

    def test_admission_observation_failure_never_becomes_success_even_if_running(self):
        self.supervisor.start(self.spec)
        self.backend.fail_before.add("admit")
        failed = self.reopen().reconcile()
        self.assertEqual("start_failed", failed["phase"])
        self.assertTrue(failed["observed"]["container"]["running"])
        self.backend.fail_before.clear()
        self.assertEqual("running", self.reopen().reconcile()["phase"])

    def test_human_authorization_required_for_actions_not_payload_claim(self):
        self.authorized = False
        self.error("FORBIDDEN", lambda: self.supervisor.start(self.spec))
        self.assertEqual([], self.backend.calls)
        self.authorized = True
        self.supervisor.start(self.spec)
        self.authorized = False
        self.error("FORBIDDEN", self.supervisor.stop)
        self.error("FORBIDDEN", self.supervisor.destroy)
        self.assertEqual("running", self.supervisor.status()["phase"])

    def test_revocation_failure_blocks_stop_and_all_destroy_effects(self):
        self.supervisor.start(self.spec)
        self.backend.revoke_verified = False
        self.backend.calls.clear()
        self.assertEqual("stop_failed", self.supervisor.stop()["phase"])
        self.assertEqual(["revoke-participants"], self.backend.calls)
        self.backend.calls.clear()
        result = self.supervisor.destroy()
        self.assertEqual("destroy_failed", result["phase"])
        self.assertEqual(["revoke-all"], self.backend.calls)
        self.assertEqual("authority", result["leftovers"][0]["kind"])

    def test_project_rebinding_and_control_overlap_fail_before_effects(self):
        self.supervisor.start(self.spec)
        self.error("PROJECT_BINDING_CONFLICT", lambda: self.supervisor.start(replace(self.spec, project_id="other")))
        self.error("CONTROL_PROJECT_OVERLAP", lambda: self.supervisor.start(replace(self.spec, project_paths=(str(self.root / "control"),))))
        self.assertEqual(1, self.backend.calls.count("create-container"))
        self.assertEqual("retain this", self.sentinel.read_text())

    def test_pending_image_config_profile_update_does_not_change_loaded_resource(self):
        first = self.supervisor.start(self.spec)
        updated = replace(self.spec, image_id="sha256:" + "d" * 64,
                          config_digest="sha256:" + "e" * 64, profile_digest="sha256:" + "f" * 64)
        result = self.supervisor.start(updated)
        self.assertEqual(updated.document(), result["pending_spec"])
        self.assertEqual(first["observed"]["container"]["image_id"], result["observed"]["container"]["image_id"])
        self.supervisor.stop()
        self.assertEqual(updated.document(), self.supervisor.start(updated)["pending_spec"])
        self.assertEqual(1, self.backend.calls.count("create-container"))

    def test_unowned_named_resource_never_removed(self):
        self.supervisor.start(self.spec)
        state = self.manifest()
        path = self.backend.path(state, "container")
        resource = json.loads(path.read_text()); resource["owner"] = "somebody-else"
        path.write_text(json.dumps(resource))
        self.backend.calls.clear()
        result = self.supervisor.destroy()
        self.assertEqual("destroy_failed", result["phase"])
        self.assertNotIn("remove-container", self.backend.calls)
        self.assertTrue(path.exists())

    def test_control_symlink_escape_never_deletes_target(self):
        first = self.supervisor.start(self.spec)
        directory = self.root / "control/alpha/instances" / first["instance_id"]
        # The marked directory itself is not replaced; a nested unowned symlink
        # is unlinked rather than traversed by exact-directory rmtree.
        (directory / "data/link").symlink_to(self.project, target_is_directory=True)
        self.assertEqual("destroyed", self.supervisor.destroy()["phase"])
        self.assertEqual("retain this", self.sentinel.read_text())

    def test_unowned_control_marker_prevents_control_state_deletion(self):
        first = self.supervisor.start(self.spec)
        directory = self.root / "control/alpha/instances" / first["instance_id"]
        (directory / "owner.json").write_text('{"room_id":"other","instance_id":"other"}')
        result = self.supervisor.destroy()
        self.assertEqual("destroy_failed", result["phase"])
        self.assertEqual("control-state", result["leftovers"][0]["kind"])
        self.assertTrue(directory.exists())

    def test_interruption_after_remove_is_recovered_from_disk_intent(self):
        self.supervisor.start(self.spec)
        original = self.backend.remove
        def interrupted(state, kind):
            original(state, kind)
            if kind == "container":
                raise KeyboardInterrupt()
        with patch.object(self.backend, "remove", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.supervisor.destroy()
        self.assertEqual("destroying", self.manifest()["phase"])
        self.assertEqual("destroyed", self.reopen().reconcile()["phase"])
        self.assertEqual("retain this", self.sentinel.read_text())

    def test_tombstone_storage_failure_is_reported_and_targeted_retry_converges(self):
        self.supervisor.start(self.spec)
        with patch.object(self.supervisor, "_tombstone", side_effect=OSError("fixture failure")):
            result = self.supervisor.destroy()
        self.assertEqual("DESTROY_FAILED", result["error"])
        self.assertEqual("tombstone", result["leftovers"][0]["kind"])
        self.error("DESTROY_INCOMPLETE", lambda: self.supervisor.start(self.spec))
        self.backend.calls.clear()
        self.assertEqual("destroyed", self.reopen().reconcile()["phase"])
        self.assertEqual(["revoke-all"], self.backend.calls)

    def test_tombstone_directory_symlink_does_not_write_into_project(self):
        self.supervisor.start(self.spec)
        (self.root / "control/alpha/tombstones").symlink_to(self.project, target_is_directory=True)
        result = self.supervisor.destroy()
        self.assertEqual("DESTROY_FAILED", result["error"])
        self.assertEqual([self.sentinel], list(self.project.iterdir()))

    def test_concurrent_starts_serialize_to_one_canonical_resource_set(self):
        barrier = threading.Barrier(3)
        results, failures = [], []
        def start():
            try:
                supervisor = self.reopen()
                barrier.wait(timeout=5)
                results.append(supervisor.start(self.spec))
            except BaseException as error:
                failures.append(error)
        threads = [threading.Thread(target=start) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual([], failures)
        self.assertEqual(1, len({result["instance_id"] for result in results}))
        self.assertEqual(1, self.backend.calls.count("create-container"))
        self.assertEqual(1, self.backend.calls.count("create-volume"))

    def test_intent_write_failure_prevents_effects_and_post_effect_failure_reconciles(self):
        with patch.object(self.supervisor, "_save", side_effect=OSError("fixture disk error")):
            with self.assertRaises(OSError):
                self.supervisor.start(self.spec)
        self.assertEqual([], self.backend.calls)
        save = self.supervisor._save
        calls = 0
        def fail_second(state):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("fixture terminal write error")
            save(state)
        with patch.object(self.supervisor, "_save", side_effect=fail_second):
            with self.assertRaises(OSError):
                self.supervisor.start(self.spec)
        self.assertEqual("creating", self.manifest()["phase"])
        self.assertEqual("running", self.reopen().reconcile()["phase"])
        self.assertEqual(1, self.backend.calls.count("create-container"))

    def test_existing_conflicting_tombstone_is_never_overwritten(self):
        started = self.supervisor.start(self.spec)
        directory = self.root / "control/alpha/tombstones"
        directory.mkdir()
        tombstone = directory / (started["instance_id"] + ".json")
        tombstone.write_text("unowned content")
        result = self.supervisor.destroy()
        self.assertEqual("DESTROY_FAILED", result["error"])
        self.assertEqual("TOMBSTONE_CONFLICT", result["leftovers"][0]["reason"])
        self.assertEqual("unowned content", tombstone.read_text())

    def test_malformed_stored_state_rejected_before_any_backend_observation_or_effect(self):
        self.supervisor.start(self.spec)
        valid = self.manifest()
        corruptions = []
        for field, value in (("version", True), ("phase", "unknown"), ("phase", []),
                             ("desired", "unknown"), ("desired", "stopped"), ("authority", []),
                             ("created_at", "not-a-time"), ("created_at", "2026-01-01"),
                             ("pending_spec", []), ("leftovers", [{}]), ("leftovers", [{}] * 33),
                             ("spec", []), ("instance_id", "../other"), ("extra", "unknown")):
            document = deepcopy(valid); document[field] = value; corruptions.append(document)
        for field in ("spec", "desired", "created_at", "pending_spec"):
            document = deepcopy(valid); del document[field]; corruptions.append(document)
        for field, value in (("image_id", "unreviewed:latest"), ("project_paths", "not-a-list"),
                             ("project_paths", ["/tmp/unsupported,mount"]), ("project_id", "../bad")):
            document = deepcopy(valid); document["spec"][field] = value; corruptions.append(document)
        document = deepcopy(valid); document["pending_spec"] = {**document["spec"], "project_id": "other"}; corruptions.append(document)
        document = deepcopy(valid); document["leftovers"] = [{"kind": "volume", "name": "x", "reason": "x" * 257}]; corruptions.append(document)
        for document in corruptions:
            with self.subTest(document=document):
                self.supervisor._manifest.write_text(json.dumps(document))
                with patch.object(self.backend, "inspect", side_effect=AssertionError("invalid restore reached backend")) as inspect:
                    for action in (self.supervisor.status, self.supervisor.reconcile, self.supervisor.destroy,
                                   self.supervisor.stop, lambda: self.supervisor.start(self.spec)):
                        self.error("INVALID_STORE", action)
                    inspect.assert_not_called()
        self.supervisor._manifest.write_text(json.dumps(valid))

    def test_fixture_mount_grammar_rejected_before_manifest_or_resources(self):
        for suffix in ("comma,path", "line\npath", "return\rpath"):
            with self.subTest(suffix=suffix):
                invalid = replace(self.spec, project_paths=(str(self.root / suffix),))
                self.error("INVALID_SPEC", lambda: self.supervisor.start(invalid))
                self.assertEqual([], self.backend.calls)
                self.assertFalse(self.supervisor._manifest.exists())
