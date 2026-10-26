"""Real Linux processes, per-record credentials, held pidfds and actual ledger.

No Docker, native agent, account, or #62 production-boundary qualification.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lifecycle_support import FileFixtureBackend
from uas.fixture_peer import FixtureReceiver
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.lifecycle import FixtureSpec, Supervisor
from uas.participant import FixtureCredentials, FixtureSeat, FixtureParticipantController, MAX_PACKET, MAX_EPOCH
from uas.peer import FixtureParticipant, FixturePeerHub


def supported():
    try:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        a.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        b.send(b"probe")
        _, ancillary, _, _ = a.recvmsg(10, socket.CMSG_SPACE(12))
        a.close()
        b.close()
        fd = os.pidfd_open(os.getpid())
        os.close(fd)
        return len(ancillary) == 1
    except (AttributeError, OSError):
        return False


SUPPORTED = supported()
if os.environ.get("UAS_REQUIRE_PARTICIPANT_PROCESS_TESTS") == "1" and not SUPPORTED:
    raise RuntimeError("Required actual Linux Participant process tests are unavailable")


@unittest.skipUnless(SUPPORTED, "requires actual Linux SOCK_SEQPACKET/SCM_CREDENTIALS and pidfd; not runtime evidence")
class ParticipantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="uas-participant-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.backend = FileFixtureBackend(self.root / "resources")
        self.spec = FixtureSpec("alpha", "fixture", (str(self.project),), *["sha256:" + c * 64 for c in "abc"])
        self.supervisor = self.reopen_supervisor()
        self.assertEqual("running", self.supervisor.start(self.spec)["phase"])
        self.ledger = RoomLedger(self.root / "room.db", "alpha")
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure("configure", (FixtureParticipant("alice", "actor-a"),
                           FixtureParticipant("bob", "actor-b"), FixtureParticipant("sibling", "actor-a")), "run-1")
        self.credentials = FixtureCredentials((("actor-a", "forge.fixture.invalid", "forge", "fixture-a"),
                                               ("actor-b", "forge.fixture.invalid", "forge", "fixture-b")),
                                              ("fixture-a", "fixture-b"))
        self.controller = self.supervisor.participants(self.hub, self.credentials)
        self.addCleanup(self.controller.close)
        self.counter = 0
        self.receivers = []
        self.addCleanup(lambda: [receiver.close() for receiver in self.receivers])

    def reopen_supervisor(self):
        return Supervisor(self.root / "control", "alpha", self.backend,
                          authorize=lambda *_: True, revoke=self.backend.revoke)

    def seat(self, participant="alice", *, capabilities=("peer-traffic",), required=("forge",)):
        return FixtureSeat(participant, "actor-b" if participant == "bob" else "actor-a", "peer-profile",
                           capabilities, required_credentials=required, arguments=("fixture-model-a",))

    def launch(self, participant="alice", *, seat=None, controller=None):
        self.counter += 1
        # Recipient inbox is still #65's disk fixture, not native Runtime delivery.
        receiver = FixtureReceiver(self.root / f"receiver-{self.counter}.db", "alpha", participant,
                                   "unused-inbound-fixture")
        self.receivers.append(receiver)
        handle = (controller or self.controller).launch(seat or self.seat(participant), receiver)
        ready = self.line(handle)
        self.assertEqual({"ready": True, "pid": handle.process.pid, "uid": os.getuid()}, ready)
        return handle

    def line(self, handle):
        self.assertTrue(select.select([handle.process.stdout], [], [], 5)[0], "fixture output timed out")
        line = handle.process.stdout.readline()
        self.assertTrue(line, "fixture exited unexpectedly")
        return json.loads(line)

    def message(self, identifier="message-1", recipient="bob"):
        return {"id": identifier, "run_id": "run-1", "generation": 1, "kind": "message",
                "payload": {"recipient": recipient, "text": "Synthetic peer traffic", "parent_id": None}}

    def send(self, handle, message=None, *, mode=None, controller=None, **options):
        command = {"message": message or self.message(), **options}
        if mode:
            command["mode"] = mode
        handle.process.stdin.write(json.dumps(command) + "\n")
        handle.process.stdin.flush()
        sent = self.line(handle)
        self.assertTrue(sent["sent"])
        result = (controller or self.controller).receive(handle)
        self.assertEqual(result, self.line(handle))
        return sent, result

    def assert_code(self, code, call):
        with self.assertRaises(LedgerError) as raised:
            call()
        self.assertEqual(code, raised.exception.code)

    def test_actual_launch_immutable_badge_and_ledger_peer_attribution(self):
        a, b = self.launch(), self.launch("bob")
        badge = a.badge
        self.assertEqual(("alpha", self.supervisor.status()["instance_id"], "actor-a", "alice", "peer-profile", 1),
                         (badge.room_id, badge.room_instance, badge.actor_id, badge.participant_id, badge.profile_id, badge.epoch))
        self.assertEqual(("peer-traffic",), badge.capabilities)
        sent, result = self.send(a)
        self.assertEqual(a.process.pid, sent["pid"])
        self.assertTrue(result["ok"])
        self.assertEqual(result, self.send(a)[1])  # exact authenticated retry
        event = next(event for event in self.ledger.replay(0) if event["operation_id"] == "message-1")
        self.assertEqual(badge.origin().canonical(), event["origin"])
        self.assertEqual("actor-a", self.hub._state()["traffic"]["message-1"]["actor_id"])
        self.assertTrue(self.send(b, self.message("reply", "alice"))[1]["ok"])
        self.assert_code("ALREADY_RUNNING", lambda: self.controller.launch(self.seat(), None))
        for changed in (replace(self.seat(), actor_id="actor-b"), replace(self.seat(), profile_id="other"),
                        replace(self.seat(), arguments=("fixture-model-b",))):
            self.assert_code("SEAT_BINDING_CONFLICT", lambda changed=changed: self.controller.launch(changed, None))

    def test_same_uid_inherited_and_scm_rights_handoff_are_not_authority(self):
        a = self.launch()
        before = self.ledger.snapshot()
        for mode in ("fork", "handoff"):
            sent, result = self.send(a, self.message(mode), mode=mode)
            self.assertEqual(os.getuid(), sent["uid"])
            self.assertNotEqual(a.process.pid, sent["pid"])
            self.assertEqual({"ok": False, "error": "WRONG_PROCESS"}, result)
            self.assertEqual(before, self.ledger.snapshot())
        self.assertTrue(self.send(a)[1]["ok"])  # attack did not poison the seat

    def test_same_uid_wrong_process_on_valid_socket_cannot_impersonate(self):
        a = self.launch()
        before = self.ledger.snapshot()
        # A supervisor/test process with the same UID and a copy of the actual
        # child endpoint still cannot become that Participant.
        a.process.stdin.write(json.dumps({"mode": "handoff", "message": self.message("wrong")}) + "\n")
        a.process.stdin.flush()
        sent = self.line(a)
        self.assertNotEqual(a.process.pid, sent["pid"])
        result = self.controller.receive(a)
        self.assertEqual("WRONG_PROCESS", result["error"])
        self.assertEqual(result, self.line(a))
        self.assertEqual(before, self.ledger.snapshot())

    def test_user_identity_badge_capability_and_model_fields_never_pick_origin(self):
        a = self.launch()
        before = self.ledger.snapshot()
        for field in ("actor_id", "participant_id", "room_id", "capabilities", "badge", "epoch", "pid", "uid", "model"):
            message = {**self.message(field), field: "actor-b"}
            self.assertEqual("INVALID_ENVELOPE", self.send(a, message)[1]["error"])
            message = self.message("payload-" + field)
            message["payload"][field] = "actor-b"
            self.assertEqual("INVALID_PAYLOAD", self.send(a, message)[1]["error"])
        self.assertEqual(before, self.ledger.snapshot())
        self.assertTrue(self.send(a)[1]["ok"])

    def test_caps_are_derived_from_profile_not_traffic_or_shared_uid(self):
        a = self.launch(seat=self.seat(capabilities=()))
        before = self.ledger.snapshot()
        self.assertEqual("FORBIDDEN", self.send(a)[1]["error"])
        self.assertEqual(before, self.ledger.snapshot())
        b = self.launch("bob")
        self.assertTrue(self.send(b, self.message("allowed", "alice"))[1]["ok"])

    def test_packet_bounds_duplicate_keys_utf8_depth_and_ancillary_fail_closed(self):
        a = self.launch()
        before = self.ledger.snapshot()
        cases = ({"hex": "fffe"}, {"size": MAX_PACKET + 1}, {"raw": '{"id":"a","id":"b"}'},
                 {"raw": '[' * 100 + '0' + ']' * 100}, {"raw": '{"amount":NaN}'}, {"mode": "rights"})
        for case in cases:
            self.assertFalse(self.send(a, **case)[1]["ok"])
            self.assertEqual(before, self.ledger.snapshot())
        # Bad ancillary shapes are impossible to manufacture through Linux's
        # validated sendmsg API; unit-test the parser's fail-closed branches.
        class Record:
            def __init__(self, ancillary, flags=0):
                self.ancillary, self.flags = ancillary, flags
            def recvmsg(self, *_):
                return b'{}', self.ancillary, self.flags, None
        valid = (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("3i", a.process.pid, os.getuid(), os.getgid()))
        for ancillary, flags in (([], 0), ([valid, valid], 0), ([(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, b'x')], 0),
                                 ([valid], socket.MSG_CTRUNC), ([valid], socket.MSG_TRUNC), ([(0, 0, b'x')], 0)):
            self.assert_code("INVALID_PROCESS_RECORD", lambda: FixtureParticipantController._packet(Record(ancillary, flags)))
        self.assertTrue(self.send(a)[1]["ok"])

    def test_exit_pidfd_revocation_replacement_and_sibling_continuity(self):
        a, b = self.launch(), self.launch("bob")
        self.assertTrue(self.send(a)[1]["ok"])
        old_badge = a.badge
        old_socket_inode = os.fstat(a.channel.fileno()).st_ino
        a.process.stdin.write('{"mode":"exit"}\n')
        a.process.stdin.flush()
        a.process.wait(timeout=3)
        self.assertFalse(self.controller._alive(a))
        with self.supervisor._locked():
            self.assert_code("PROCESS_EXITED", lambda: self.controller._authority(a, (a.process.pid, os.getuid(), os.getgid())))
        self.assertTrue(self.send(b, self.message("sibling-after-exit", "alice"))[1]["ok"])
        replacement = self.launch()
        self.assertNotEqual(old_badge.incarnation_id, replacement.badge.incarnation_id)
        self.assertGreater(replacement.badge.epoch, old_badge.epoch)
        self.assertNotEqual(old_socket_inode, os.fstat(replacement.channel.fileno()).st_ino)
        self.assertEqual(-1, a.channel.fileno())
        # Old operation receipt is security-context-bound, not a bearer badge.
        self.assertEqual("ID_CONFLICT", self.send(replacement)[1]["error"])
        self.assertTrue(self.send(replacement, self.message("new-process"))[1]["ok"])
        with self.supervisor._locked():
            self.assert_code("AUTHORITY_REVOKED", lambda: self.controller._authority(a, (replacement.process.pid, os.getuid(), os.getgid())))
        self.controller.revoke("alice")
        self.assertIsNotNone(replacement.process.poll())
        self.assertTrue(self.send(b, self.message("sibling-after-revoke", "alice"))[1]["ok"])
        self.controller.revoke("alice", close=True)
        self.assert_code("PARTICIPANT_CLOSED", lambda: self.controller.launch(self.seat(), None))

    def test_credential_loss_is_exact_no_fallback_and_repair_requires_explicit_restart(self):
        a, b = self.launch(), self.launch("bob")
        sibling = self.launch("sibling", seat=self.seat("sibling", required=()))
        self.credentials.set_available("fixture-a", False)
        self.assertEqual("MISSING_ACTOR_CREDENTIAL", self.send(a)[1]["error"])
        self.assertEqual("disabled", self.controller.snapshot()["seats"]["alice"]["status"])
        self.assertTrue(self.send(b, self.message("b-still-valid", "alice"))[1]["ok"])
        self.assertTrue(self.send(sibling, self.message("same-actor-no-credential"))[1]["ok"])
        self.credentials.set_available("fixture-a", True)
        self.assertEqual("AUTHORITY_REVOKED", self.send(a)[1]["error"])
        repaired = self.launch()
        self.assertTrue(self.send(repaired, self.message("repaired"))[1]["ok"])
        self.assertEqual("running", self.supervisor.status()["phase"])
        self.credentials.set_available("fixture-a", False)
        self.controller.revoke("alice")
        self.assert_code("MISSING_ACTOR_CREDENTIAL", lambda: self.controller.launch(self.seat(), None))
        table = FixtureCredentials((("actor-b", "forge.fixture.invalid", "forge", "fixture-b"),), ("fixture-b",))
        self.assertEqual(["forge"], table.missing(self.seat().document()))
        self.assertEqual(["forge"], self.credentials.missing({**self.seat().document(), "provider_host": "other.fixture.invalid"}))

    def test_serialized_credential_observation_stops_only_affected_seats(self):
        a, b = self.launch(), self.launch("bob")
        sibling = self.launch("sibling", seat=self.seat("sibling", required=()))
        self.controller.set_credential_available("fixture-a", False)
        self.assertIsNotNone(a.process.poll())
        self.assertIsNone(b.process.poll())
        self.assertIsNone(sibling.process.poll())
        self.assertEqual("disabled", self.controller.snapshot()["seats"]["alice"]["status"])
        self.controller.set_credential_available("fixture-a", True)
        self.assertEqual("disabled", self.controller.snapshot()["seats"]["alice"]["status"])
        repaired = self.launch()
        self.assertTrue(self.send(repaired)[1]["ok"])
        self.assertTrue(self.send(b, self.message("unaffected", "alice"))[1]["ok"])

    def test_new_controller_fences_still_live_old_process_and_preserves_actor_history(self):
        a = self.launch()
        self.send(a)
        # Existing durable actor contribution data belongs to the ledger; fresh
        # controller/model/context has no clearing or reattribution operation.
        origin = Origin("fixture", "fixture", "fixture", "fixture", ())
        self.ledger.apply(Command("contribution", "fixture.contribution", "run-1", 1, {}), origin,
                          authorize=lambda *_: True,
                          decide=lambda state, _: Transition({**state, "actor_contributions": {"actor-a": ["patch-1"]}},
                                                             (Event("fixture.contribution", {}),), {}))
        reopened = self.reopen_supervisor()
        controller = reopened.participants(self.hub, self.credentials)
        self.addCleanup(controller.close)
        self.assertTrue(self.controller._alive(a))
        self.assertEqual("CONTROLLER_REPLACED", self.send(a)[1]["error"])
        replacement = self.launch(controller=controller)
        self.assertTrue(self.send(replacement, self.message("fresh"), controller=controller)[1]["ok"])
        self.assertEqual({"actor-a": ["patch-1"]}, self.ledger.snapshot()["state"]["actor_contributions"])
        self.assertEqual("actor-a", self.hub._state()["traffic"]["message-1"]["actor_id"])

    def test_stop_destroy_verify_nonempty_revocation_before_backend_effect(self):
        a, b = self.launch(), self.launch("bob")
        original_stop = self.backend.stop
        def stop(state):
            self.assertIsNotNone(a.process.poll())
            self.assertIsNotNone(b.process.poll())
            self.assertTrue(all(record["status"] == "revoked" for record in self.controller._read()["seats"].values()))
            return original_stop(state)
        self.backend.stop = stop
        self.assertEqual("stopped", self.supervisor.stop()["phase"])
        self.assert_code("ROOM_NOT_RUNNING", lambda: self.controller.launch(self.seat(), None))
        self.assertEqual("running", self.supervisor.start(self.spec)["phase"])
        fresh = self.launch()
        self.assertTrue(self.send(fresh, self.message("after-stop"))[1]["ok"])
        original_remove = self.backend.remove
        def remove(state, kind):
            self.assertIsNotNone(fresh.process.poll())
            return original_remove(state, kind)
        self.backend.remove = remove
        self.assertEqual("destroyed", self.supervisor.destroy()["phase"])

    def test_reopened_supervisor_cannot_use_vacuous_revocation_callback(self):
        a = self.launch()
        reopened = self.reopen_supervisor()
        result = reopened.stop()
        self.assertEqual("stop_failed", result["phase"])
        self.assertNotIn("stop", self.backend.calls)
        # Explicitly reconstruct controller (after restoring fixture Room) to
        # fence authority. Never infer nonempty authority from a trusted bool.
        self.assertEqual("running", reopened.start(self.spec)["phase"])
        controller = reopened.participants(self.hub, self.credentials)
        self.addCleanup(controller.close)
        self.assertEqual("CONTROLLER_REPLACED", self.send(a)[1]["error"])

    def test_launch_store_failure_always_kills_process_even_if_cleanup_write_fails(self):
        created = []
        original_popen = __import__("subprocess").Popen
        original_replace = os.replace
        def popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            created.append(process)
            return process
        calls = 0
        def replace_file(source, target):
            nonlocal calls
            calls += 1
            if calls > 1:  # intent durable; active and compensating writes fail
                raise OSError("synthetic full store")
            original_replace(source, target)
        with patch("uas.participant.subprocess.Popen", side_effect=popen), patch("uas.participant.os.replace", side_effect=replace_file):
            with self.assertRaises(OSError):
                self.controller.launch(self.seat(), None)
        self.assertEqual(1, len(created))
        self.assertIsNotNone(created[0].poll())
        self.assertTrue(created[0].stdin.closed)
        self.assertTrue(created[0].stdout.closed)
        self.assertEqual({}, self.controller.handles)
        self.assertNotEqual("active", self.controller.snapshot()["seats"]["alice"]["status"])
        self.assertTrue(self.controller.store_failed)
        self.assert_code("AUTHORITY_STORE_UNAVAILABLE", lambda: self.controller.launch(self.seat(), None))
        reopened = self.reopen_supervisor()
        controller = reopened.participants(self.hub, self.credentials)
        self.addCleanup(controller.close)
        repaired = self.launch(controller=controller)
        self.assertTrue(self.send(repaired, controller=controller)[1]["ok"])

    def test_fresh_credential_race_fences_after_ledger_rollback_not_nested_write(self):
        a = self.launch()
        original_authority = self.controller._authority
        calls = 0
        def authority(handle, credentials):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.assertTrue(self.ledger._db.in_transaction)
                self.credentials.set_available("fixture-a", False)
            return original_authority(handle, credentials)
        with patch.object(self.controller, "_authority", side_effect=authority):
            self.assertEqual("MISSING_ACTOR_CREDENTIAL", self.send(a)[1]["error"])
        self.assertEqual(2, calls)
        self.assertFalse(self.ledger._db.in_transaction)
        self.assertEqual({}, self.hub._state()["traffic"])
        self.assertEqual("disabled", self.controller.snapshot()["seats"]["alice"]["status"])

    def test_fresh_exit_race_fences_after_ledger_rollback(self):
        a = self.launch()
        a.process.stdin.write(json.dumps({"message": self.message()}) + "\n")
        a.process.stdin.flush()
        self.line(a)
        original_authority = self.controller._authority
        calls = 0
        def authority(handle, credentials):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.assertTrue(self.ledger._db.in_transaction)
                a.process.terminate()
                a.process.wait(timeout=3)
            return original_authority(handle, credentials)
        with patch.object(self.controller, "_authority", side_effect=authority):
            self.assertEqual("PROCESS_EXITED", self.controller.receive(a)["error"])
        self.assertFalse(self.ledger._db.in_transaction)
        self.assertEqual({}, self.hub._state()["traffic"])
        self.assertEqual("exited", self.controller.snapshot()["seats"]["alice"]["status"])

    def test_retired_live_process_blocks_stop_until_verified_absent(self):
        a = self.launch()
        reopened = self.reopen_supervisor()
        controller = reopened.participants(self.hub, self.credentials)
        self.addCleanup(controller.close)
        self.assertEqual([a.process.pid], controller.snapshot()["retired_pids"])
        self.assertEqual("stop_failed", reopened.stop()["phase"])
        self.assertNotIn("stop", self.backend.calls)
        self.controller.close()  # only original owner has the held pidfd/child
        self.assertEqual("stopped", reopened.stop()["phase"])
        self.assertEqual([], controller.snapshot()["retired_pids"])

    def test_actual_supervisor_sigkill_fences_recovery_and_fixture_child_exits(self):
        root = self.root / "crash"
        worker = Path(__file__).parent / "fixtures/participant_controller_worker.py"
        process = subprocess.Popen([sys.executable, str(worker), str(root)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stderr.close)
        self.assertTrue(select.select([process.stdout], [], [], 5)[0])
        binding = json.loads(process.stdout.readline())
        pidfd = os.pidfd_open(binding["pid"])
        self.addCleanup(os.close, pidfd)
        process.kill()
        process.wait(timeout=3)
        self.assertTrue(select.select([pidfd], [], [], 5)[0], "fixed Runtime must exit when supervisor stdio disappears")
        backend = FileFixtureBackend.__new__(FileFixtureBackend)
        backend.__dict__.update(root=root / "resources", calls=[], fail_before=set(), fail_after=set(), revoke_verified=True)
        supervisor = Supervisor(root / "control", "alpha", backend, authorize=lambda *_: True, revoke=backend.revoke)
        ledger = RoomLedger(root / "room.db", "alpha")
        self.addCleanup(ledger.close)
        hub = FixturePeerHub(ledger)
        controller = supervisor.participants(hub, FixtureCredentials())
        self.addCleanup(controller.close)
        self.assertEqual("revoked", controller.snapshot()["seats"]["alice"]["status"])
        handle = controller.launch(FixtureSeat("alice", "actor-a", "peer-profile", ("peer-traffic",)), None)
        self.line(handle)
        self.assertNotEqual(binding["incarnation"], handle.badge.incarnation_id)
        self.assertGreater(handle.badge.epoch, binding["epoch"])
        self.assertTrue(self.send(handle, controller=controller)[1]["ok"])
        self.assertEqual("stopped", supervisor.stop()["phase"])

    def test_epoch_exhaustion_revokes_without_persisting_invalid_store(self):
        a = self.launch()
        document = self.controller.snapshot()
        document["seats"]["alice"]["epoch"] = MAX_EPOCH
        self.controller._save(document)
        self.controller.revoke("alice")
        self.assertIsNotNone(a.process.poll())
        record = self.controller.snapshot()["seats"]["alice"]
        self.assertEqual(("revoked", MAX_EPOCH), (record["status"], record["epoch"]))
        with patch("uas.participant.subprocess.Popen") as popen:
            self.assert_code("AUTHORITY_EPOCH_EXHAUSTED", lambda: self.controller.launch(self.seat(), None))
            popen.assert_not_called()
        reopened = self.reopen_supervisor()
        controller = reopened.participants(self.hub, self.credentials)
        self.addCleanup(controller.close)
        self.assertEqual(MAX_EPOCH, controller.snapshot()["seats"]["alice"]["epoch"])
        self.assertEqual("stopped", reopened.stop()["phase"])

    def test_rejected_scm_rights_records_do_not_leak_descriptors(self):
        a = self.launch()
        count = len(os.listdir("/proc/self/fd"))
        for _ in range(20):
            self.assertEqual("INVALID_PROCESS_RECORD", self.send(a, mode="rights")[1]["error"])
        self.assertEqual(count, len(os.listdir("/proc/self/fd")))
        descriptor = os.dup(a.channel.fileno())
        class Record:
            def recvmsg(self, *_):
                return b'{}', [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", descriptor))], 0, None
        self.assert_code("INVALID_PROCESS_RECORD", lambda: FixtureParticipantController._packet(Record()))
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertEqual(count, len(os.listdir("/proc/self/fd")))

    def test_revocation_store_failure_still_terminates_and_fences_process(self):
        a = self.launch()
        with patch("uas.participant.os.replace", side_effect=OSError("synthetic store unavailable")):
            with self.assertRaises(OSError):
                self.controller.revoke("alice")
        self.assertIsNotNone(a.process.poll())
        self.assertEqual(-1, a.channel.fileno())
        self.assertTrue(self.controller.store_failed)
        with self.supervisor._locked():
            self.assert_code("AUTHORITY_STORE_UNAVAILABLE", lambda: self.controller._authority(a, (a.process.pid, os.getuid(), os.getgid())))
        self.assertEqual("stopped", self.supervisor.stop()["phase"])

    def test_store_failure_and_corruption_deny_without_domain_mutation(self):
        a = self.launch()
        before = self.ledger.snapshot()
        original = self.controller.path.read_text()
        self.controller.path.write_text('{"version": 1}')
        self.assertEqual("INVALID_AUTHORITY_STORE", self.send(a)[1]["error"])
        self.assertEqual(before, self.ledger.snapshot())
        self.controller.path.write_text(original)
        original_save = self.controller._save
        def failure(_):
            raise OSError("synthetic storage failure")
        self.controller._save = failure
        try:
            with self.assertRaises(OSError):
                self.controller.revoke("alice")
        finally:
            self.controller._save = original_save
        # Failed revocation has not been reported as verified; successful retry
        # fences before terminating, and Room remains independent of siblings.
        self.controller.revoke("alice")
        self.assertEqual("revoked", self.controller.snapshot()["seats"]["alice"]["status"])


if __name__ == "__main__":
    unittest.main()
