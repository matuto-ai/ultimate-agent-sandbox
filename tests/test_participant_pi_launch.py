"""Controller race/failure seams with real synthetic children, NOT Pi evidence.

Actual official Pi execution is covered separately by test_pi_runtime.py. Here
only the fixed recipe's spawn/attach methods are replaced to inject exact faults.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from lifecycle_support import FileFixtureBackend
from test_participant import SUPPORTED
from uas.ledger import LedgerError, RoomLedger
from uas.lifecycle import FixtureSpec, Supervisor
from uas.participant import FixtureCredentials, FixtureSeat
from uas.peer import FixtureParticipant, FixturePeerHub
from uas.pi_fixture import FixturePiRecipe


class AttachedReceiver:
    def __init__(self, process, badge, scope):
        self.process, self.incarnation_id, self.scope = process, badge.incarnation_id, scope
        self.closed = False
        self.close_error = False

    def close(self):
        if self.process.poll() is None:
            raise AssertionError("controller must terminate before receiver close")
        self.closed = True
        if self.close_error:
            raise RuntimeError("synthetic receiver close failure")


@unittest.skipUnless(SUPPORTED, "requires actual Linux process credential/pidfd primitives")
class PiControllerSeamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="uas-pi-controller-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        project = self.root / "project"
        project.mkdir()
        self.backend = FileFixtureBackend(self.root / "backend")
        self.supervisor = self.reopen()
        self.spec = FixtureSpec("alpha", "fixture", (str(project),), *["sha256:" + c * 64 for c in "abc"])
        self.supervisor.start(self.spec)
        self.ledger = RoomLedger(self.root / "room.db", "alpha")
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure("configure", (FixtureParticipant("alice", "actor-a"), FixtureParticipant("bob", "actor-b")), "run-1")
        self.credentials = FixtureCredentials((("actor-a", "forge.fixture.invalid", "forge", "fixture-a"),), ("fixture-a",))
        self.controller = self.supervisor.participants(self.hub, self.credentials)
        self.addCleanup(self.controller.close)
        self.seat = FixtureSeat("alice", "actor-a", "peer-profile", ("peer-traffic",),
                                required_credentials=("forge",), runtime="pi-fixture")
        # Exact class remains enforced by production launch_pi. Constructor and
        # official package validation are outside these controller fault seams.
        self.recipe = object.__new__(FixturePiRecipe)
        self.recipe.scope = {"room_id": "alpha", "participant_id": "alice", "run_id": "run-1",
                             "generation": 1, "context_generation": 1}
        self.created = []
        self.receivers = []
        self.after_attach = lambda *_: None
        self.spawn_patch = patch.object(FixturePiRecipe, "spawn", self.spawn)
        self.attach_patch = patch.object(FixturePiRecipe, "attach", self.attach)
        self.spawn_patch.start()
        self.attach_patch.start()
        self.addCleanup(self.spawn_patch.stop)
        self.addCleanup(self.attach_patch.stop)

    def reopen(self):
        return Supervisor(self.root / "control", "alpha", self.backend,
                          authorize=lambda *_: True, revoke=self.backend.revoke)

    def spawn(self, child_socket, runtime_directory):
        record = self.controller._read()["seats"]["alice"]
        self.assertEqual("starting", record["status"])
        self.assertIsNone(record["pid"])
        child_socket.setblocking(True)  # The synthetic worker is not Node.
        process = subprocess.Popen([sys.executable, "-I", str(Path(__file__).parents[1] / "uas/fixture_participant.py"),
                                    str(child_socket.fileno())], pass_fds=(child_socket.fileno(),),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=runtime_directory, env={"LANG": "C.UTF-8"}, bufsize=0)
        self.created.append((process, runtime_directory))
        return process

    def attach(self, process, badge):
        record = self.controller.snapshot()["seats"]["alice"]
        self.assertEqual(("starting", process.pid, badge.epoch, badge.incarnation_id),
                         (record["status"], record["pid"], record["epoch"], record["incarnation_id"]))
        self.assertTrue(select.select([process.stdout], [], [], 3)[0])
        self.assertTrue(json.loads(process.stdout.readline())["ready"])
        receiver = AttachedReceiver(process, badge, dict(self.recipe.scope))
        self.receivers.append(receiver)
        self.after_attach(process, badge, receiver)
        return receiver

    def launch(self):
        return self.controller.launch_pi(self.seat, self.recipe)

    def assert_code(self, code, function):
        with self.assertRaises(LedgerError) as raised:
            function()
        self.assertEqual(code, raised.exception.code)

    def frame(self, request_id=None):
        return {"request_id": request_id or uuid.uuid4().hex,
                "envelope": {"id": "message-1", "run_id": "run-1", "generation": 1, "kind": "message",
                             "payload": {"recipient": "bob", "text": "Fixture", "parent_id": None}}}

    def exchange(self, handle, frame, mode=None):
        command = {"message": frame}
        if mode:
            command["mode"] = mode
        handle.process.stdin.write((json.dumps(command) + "\n").encode())
        handle.process.stdin.flush()
        self.assertTrue(select.select([handle.process.stdout], [], [], 3)[0])
        sent = json.loads(handle.process.stdout.readline())
        result = self.controller.receive(handle)
        self.assertTrue(select.select([handle.process.stdout], [], [], 3)[0])
        self.assertEqual(result, json.loads(handle.process.stdout.readline()))
        return sent, result

    def assert_disposed(self, process, directory):
        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdin.closed and process.stdout.closed and process.stderr.closed)
        self.assertFalse(directory.exists())

    def test_native_frame_binding_and_managed_receiver_cleanup(self):
        handle = self.launch()
        self.assertIs(handle.process, handle.managed_receiver.process)
        self.assertEqual("active", self.controller.snapshot()["seats"]["alice"]["status"])
        frame = self.frame()
        sent, result = self.exchange(handle, frame)
        self.assertEqual(handle.process.pid, sent["pid"])
        self.assertEqual(frame["request_id"], result["request_id"])
        self.assertTrue(result["ok"])
        self.controller.revoke("alice")
        self.assertTrue(self.receivers[0].closed)
        self.assert_disposed(*self.created[0])

    def test_process_identity_precedes_native_correlation_and_frame_validation(self):
        handle = self.launch()
        before = self.ledger.snapshot()
        frame = self.frame()
        sent, result = self.exchange(handle, frame, "handoff")
        self.assertNotEqual(handle.process.pid, sent["pid"])
        self.assertEqual({"request_id": None, "ok": False, "error": "WRONG_PROCESS"}, result)
        for invalid in (frame["envelope"], {**frame, "extra": True}, {**frame, "request_id": "a" * 33},
                        {**frame, "request_id": frame["request_id"].upper()}, {**frame, "envelope": []}):
            self.assertEqual("INVALID_NATIVE_FRAME", self.exchange(handle, invalid)[1]["error"])
        self.assertEqual(before, self.ledger.snapshot())
        self.assertTrue(self.exchange(handle, frame)[1]["ok"])

    def test_stop_during_native_handshake_wins_without_deadlock(self):
        self.after_attach = lambda *_: self.assertEqual("stopped", self.supervisor.stop()["phase"])
        self.assert_code("ROOM_NOT_RUNNING", self.launch)
        self.assertEqual({}, self.controller.handles)
        self.assertTrue(self.receivers[0].closed)
        self.assert_disposed(*self.created[0])
        self.assertEqual({}, self.hub._state()["connections"])

    def test_concurrent_stop_finishes_before_late_handshake_returns(self):
        attaching, stopped = threading.Event(), threading.Event()
        outcomes = []
        def stop_thread():
            if not attaching.wait(3):
                outcomes.append("handshake-not-entered")
                stopped.set()
                return
            try:
                outcomes.append(self.supervisor.stop()["phase"])
            except BaseException as error:
                outcomes.append(error)
            finally:
                stopped.set()
        thread = threading.Thread(target=stop_thread, daemon=True)
        thread.start()
        def late_handshake(*_):
            attaching.set()
            self.assertTrue(stopped.wait(3), "Stop blocked behind native attachment")
        self.after_attach = late_handshake
        try:
            self.assert_code("ROOM_NOT_RUNNING", self.launch)
        finally:
            thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(["stopped"], outcomes)
        self.assertTrue(self.receivers[0].closed)
        self.assert_disposed(*self.created[0])
        self.assertEqual({}, self.hub._state()["connections"])

    def test_revoke_and_close_during_handshake_win(self):
        self.after_attach = lambda *_: self.controller.revoke("alice", close=True)
        self.assert_code("AUTHORITY_REVOKED", self.launch)
        self.assertEqual("closed", self.controller.snapshot()["seats"]["alice"]["status"])
        self.assertTrue(self.receivers[0].closed)
        self.assert_disposed(*self.created[0])

    def test_replacement_during_handshake_does_not_kill_or_overwrite_new_process(self):
        replacements = []
        def replace_pending(*_):
            self.after_attach = lambda *_: None
            replacements.append(self.launch())
        self.after_attach = replace_pending
        self.assert_code("AUTHORITY_REVOKED", self.launch)
        replacement = replacements[0]
        self.assertIs(self.controller.handles["alice"], replacement)
        self.assertEqual("active", self.controller.snapshot()["seats"]["alice"]["status"])
        self.assert_disposed(*self.created[0])
        self.assertIsNone(replacement.process.poll())
        self.assertTrue(self.exchange(replacement, self.frame())[1]["ok"])

    def test_controller_replacement_during_handshake_wins(self):
        controllers = []
        def replace_controller(*_):
            controllers.append(self.reopen().participants(self.hub, self.credentials))
        self.after_attach = replace_controller
        self.assert_code("CONTROLLER_REPLACED", self.launch)
        self.addCleanup(controllers[0].close)
        self.assertEqual("revoked", controllers[0].snapshot()["seats"]["alice"]["status"])
        self.assert_disposed(*self.created[0])

    def test_credential_revocation_during_handshake_disables_pending_seat(self):
        self.after_attach = lambda *_: self.controller.set_credential_available("fixture-a", False)
        self.assert_code("AUTHORITY_REVOKED", self.launch)
        self.assertEqual("disabled", self.controller.snapshot()["seats"]["alice"]["status"])
        self.assert_disposed(*self.created[0])

    def test_failure_publishing_active_and_cleanup_write_never_leak_process(self):
        original_replace = os.replace
        def fail_active(source, target):
            if Path(target) == self.controller.path:
                record = json.loads(Path(source).read_text())["seats"].get("alice")
                if record and record["reason"] in {"launched", "launch-failed"}:
                    raise OSError("synthetic active/compensating persistence failure")
            return original_replace(source, target)
        with patch("uas.participant.os.replace", side_effect=fail_active):
            with self.assertRaises(OSError):
                self.launch()
        self.assertTrue(self.controller.store_failed)
        self.assertEqual({}, self.controller.handles)
        self.assertTrue(self.receivers[0].closed)
        self.assert_disposed(*self.created[0])

    def test_attach_failure_and_receiver_close_failure_still_cleanup_owned_resources(self):
        def fail_attach(*_):
            raise RuntimeError("synthetic attachment failure")
        self.after_attach = fail_attach
        with self.assertRaises(RuntimeError):
            self.launch()
        self.assert_disposed(*self.created[0])
        self.after_attach = lambda *_: None
        handle = self.launch()
        receiver = handle.managed_receiver
        receiver.close_error = True
        self.assert_code("NATIVE_RECEIVER_CLOSE_FAILED", lambda: self.controller.revoke("alice"))
        self.assert_disposed(*self.created[1])
        receiver.close_error = False
        self.controller.close()

    def test_only_exact_fixed_recipe_empty_arguments_and_matching_scope_allowed(self):
        self.assert_code("INVALID_SEAT", lambda: self.controller.launch_pi(self.seat, object()))
        self.assert_code("FIXTURE_ONLY", lambda: self.controller.launch_pi(replace(self.seat, arguments=("injected",)), self.recipe))
        self.assert_code("FIXTURE_ONLY", lambda: self.controller.launch(self.seat, None))
        self.recipe.scope["run_id"] = "wrong-run"
        self.assert_code("PEER_BINDING_CONFLICT", self.launch)
        self.assertEqual([], self.created)

    def test_nonempty_runtime_directory_is_retained_not_recursively_deleted(self):
        handle = self.launch()
        retained = handle.runtime_directory / "retain.txt"
        retained.write_text("do not delete")
        self.addCleanup(handle.runtime_directory.rmdir)
        self.addCleanup(retained.unlink)
        self.controller.revoke("alice")
        self.assertTrue(retained.exists())
        self.assertIsNotNone(handle.process.poll())


if __name__ == "__main__":
    unittest.main()
