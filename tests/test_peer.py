import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

from uas.fixture_peer import FixtureReceiver
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.peer import FixtureParticipant, FixturePeerHub, Message, Readiness, RequestCommand, WorkRequest


class PeerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ledger = RoomLedger(self.root / "room.db", "alpha")
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure("configure", (FixtureParticipant("alice", "actor-a"),
                           FixtureParticipant("bob", "actor-b"), FixtureParticipant("carol", "actor-c")), "run-1")
        self.receivers = []
        self.a = self.connect("alice")
        self.b = self.connect("bob")
        self.c = self.connect("carol")

    def tearDown(self):
        self.ledger.close()
        for receiver in self.receivers:
            receiver.close()
        self.temp.cleanup()

    def connect(self, participant, incarnation=1, *, hub=None, attachment=None):
        hub = hub or self.hub
        name = f"{participant}-{incarnation}"
        filename = f"{participant}.db" if incarnation == 1 else f"{name}.db"
        receiver = FixtureReceiver(self.root / filename, "alpha", participant, name)
        self.receivers.append(receiver)
        return hub.connect(attachment or "attach-" + name, participant, name, receiver)

    def request(self, id="request-1", recipient="bob"):
        return self.hub.submit(self.a, WorkRequest(id, "run-1", 1, recipient, "Please inspect the fixture"))

    def command(self, action, request_id="request-1", connection=None, id=None, reason=None):
        return self.hub.submit(connection or self.b, RequestCommand(
            id or f"{request_id}-{action}", "run-1", 1, request_id, action, reason))

    def state(self):
        return self.hub.snapshot()["state"]["peer_traffic"]

    def ready(self, connection=None):
        self.hub.observe(connection or self.b, Readiness.SAFE)
        return self.hub.deliver(connection or self.b)

    def assert_code(self, code, call):
        with self.assertRaises(LedgerError) as raised:
            call()
        self.assertEqual(code, raised.exception.code)

    def test_integrated_request_reply_broadcast_and_one_room_ledger(self):
        # The domain shares the existing application-ledger boundary; unrelated
        # Room-owned materialized state and event sequence survive unchanged.
        origin = Origin("fixture", "fixture", "fixture", "v1", ())
        self.ledger.apply(Command("other", "other.record", "other", None, {}), origin,
                          authorize=lambda *_: True,
                          decide=lambda state, _: Transition({**state, "other": {"kept": 42}},
                                                             (Event("other.recorded", {}),), {}))
        self.request()
        self.assertEqual("QUEUED", self.state()["traffic"]["request-1"]["status"])
        self.assertEqual("CONFIRMED", self.ready()["outcome"])
        self.command("accept")
        reply = Message("reply-1", "run-1", 1, None, "Inspection finished", "request-1")
        self.hub.submit(self.b, reply)
        self.command("complete")
        self.hub.submit(self.a, Message("broadcast", "run-1", 1, "*", "Shared information"))
        self.ready(self.a)
        self.ready(self.b)
        self.ready(self.c)
        domain = self.state()
        self.assertEqual("COMPLETED", domain["traffic"]["request-1"]["status"])
        self.assertEqual(["alice"], domain["traffic"]["reply-1"]["recipients"])
        self.assertEqual("request-1", domain["traffic"]["reply-1"]["correlation_id"])
        self.assertEqual(["bob", "carol"], domain["traffic"]["broadcast"]["recipients"])
        self.assertNotIn("status", domain["traffic"]["broadcast"])
        self.assertNotIn("response_started_at", domain["traffic"]["broadcast"])
        self.assertEqual({"kept": 42}, self.hub.snapshot()["state"]["other"])
        events = self.ledger.replay(0, limit=1000)
        self.assertEqual(list(range(1, len(events) + 1)), [event["room_seq"] for event in events])
        submitted = next(event for event in events if event["operation_id"] == "request-1")
        self.assertEqual("actor-a", submitted["origin"]["actor_id"])
        self.assertEqual(submitted["room_seq"], domain["traffic"]["request-1"]["submitted_seq"])

    def test_safe_points_hold_and_response_clock_requires_receiver_confirmation(self):
        self.request()
        initial = copy.deepcopy(self.state()["traffic"]["request-1"])
        for readiness in (Readiness.AMBIGUOUS, Readiness.BUSY, Readiness.COMPACTING):
            self.hub.observe(self.b, readiness)
            self.assertEqual("HELD", self.hub.deliver(self.b)["outcome"])
            self.assertEqual(initial, self.state()["traffic"]["request-1"])
        self.hub.observe(self.b, Readiness.SAFE)
        accept = self.b.receiver.accept
        def inspect(envelope):
            before = self.state()["traffic"]["request-1"]
            self.assertEqual("QUEUED", before["status"])
            self.assertIsNone(before["response_started_at"])
            self.assertEqual("UNCONFIRMED", self.state()["offers"]["request-1"]["bob"]["outcome"])
            return accept(envelope)
        self.b.receiver.accept = inspect
        self.hub.deliver(self.b)
        delivered = self.state()["traffic"]["request-1"]
        self.assertEqual("DELIVERED", delivered["status"])
        self.assertGreaterEqual(delivered["response_started_at"], initial["submitted_at"])
        self.assertEqual(initial["submitted_at"], delivered["submitted_at"])

    def test_client_authority_and_metadata_are_rejected(self):
        data = {"id": "forged", "run_id": "run-1", "generation": 1, "kind": "work-request",
                "payload": {"recipient": "bob", "text": "Test"}}
        before = self.hub.snapshot()
        for field in ("actor_id", "status", "timestamp", "room_seq", "capabilities", "repository", "room_id"):
            self.assert_code("INVALID_ENVELOPE", lambda field=field: self.hub.submit(self.a, {**data, field: "forged"}))
            payload = {**data["payload"], field: "forged"}
            self.assert_code("INVALID_PAYLOAD", lambda payload=payload: self.hub.submit(self.a, {**data, "payload": payload}))
        forged = replace(self.a, participant_id="bob")
        self.assert_code("STALE_CONNECTION", lambda: self.hub.submit(forged, self.hub.parse(data)))
        self.assertEqual(before, self.hub.snapshot())
        self.hub.submit(self.a, data)
        self.assertEqual("actor-a", self.state()["traffic"]["forged"]["actor_id"])

    def test_retry_conflict_and_stale_generation_use_application_ledger(self):
        first = self.request()
        before = self.hub.snapshot()
        self.assertEqual(first, self.request())
        self.assertEqual(before, self.hub.snapshot())
        self.assert_code("ID_CONFLICT", lambda: self.hub.submit(self.a, WorkRequest("request-1", "run-1", 0, "bob", "Changed")))
        self.assert_code("STALE_GENERATION", lambda: self.hub.submit(self.a, WorkRequest("new", "run-1", 0, "bob", "Changed")))
        self.assert_code("ID_CONFLICT", lambda: self.hub.submit(self.c, WorkRequest("request-1", "run-1", 1, "bob", "Please inspect the fixture")))
        self.assertEqual(before, self.hub.snapshot())

    def test_parent_authorization_and_correlation(self):
        self.request()
        reply = Message("reply", "run-1", 1, None, "Hello", "request-1")
        self.assert_code("PARENT_NOT_DELIVERED", lambda: self.hub.submit(self.b, reply))
        self.assert_code("FORBIDDEN_PARENT", lambda: self.hub.submit(self.c, reply))
        self.ready()
        self.assert_code("REPLY_TARGET_DERIVED", lambda: self.hub.submit(self.b, replace(reply, recipient="carol")))
        self.hub.submit(self.b, reply)
        self.assertEqual("request-1", self.state()["traffic"]["reply"]["correlation_id"])
        self.assert_code("FORBIDDEN_REQUEST", lambda: self.command("accept", connection=self.c))

    def test_capacity_released_by_defer_block_complete_and_decline(self):
        self.request()
        self.request("request-2")
        self.ready()
        self.command("accept")
        self.assert_code("CAPACITY_EXHAUSTED", lambda: self.command("accept", "request-2"))
        self.command("defer", reason="Wait for peer")
        self.command("accept", "request-2")
        self.command("block", "request-2", reason="Need fixture input")
        self.assertEqual("BLOCKED", self.state()["traffic"]["request-2"]["attention"])
        self.command("accept", id="reaccept-1")
        self.command("complete")
        self.command("accept", "request-2", id="reaccept-2")
        self.command("defer", "request-2", reason="Try later")
        self.command("decline", "request-2", reason="Unavailable")
        self.assertEqual("DECLINED", self.state()["traffic"]["request-2"]["status"])
        self.assert_code("INVALID_TRANSITION", lambda: self.command("accept", "request-2", id="too-late"))
        self.assert_code("INVALID_TRANSITION", lambda: self.hub.cancel("cancel-complete", "request-1", "late"))

    def test_all_direct_response_branches_and_terminal_validation(self):
        for action in ("decline", "defer", "block"):
            id = "direct-" + action
            self.request(id)
            self.ready()
            self.command(action, id, reason="Fixture reason")
            self.assertEqual({"decline": "DECLINED", "defer": "DEFERRED", "block": "BLOCKED"}[action], self.state()["traffic"][id]["status"])
        self.command("decline", "direct-block", reason="Cannot proceed")
        self.request("queued")
        self.assert_code("INVALID_TRANSITION", lambda: self.command("complete", "queued"))
        self.assert_code("INVALID_TRANSITION", lambda: self.command("accept", "queued"))
        self.ready()
        self.assert_code("INVALID_PAYLOAD", lambda: self.command("block", "queued"))
        self.assert_code("UNKNOWN_COMMAND", lambda: self.command("force-stop", "queued"))
        self.assert_code("UNKNOWN_COMMAND", lambda: self.command("cancel", "queued", reason="Not authorized"))

    def test_fixture_cancellation_from_each_nonterminal_state(self):
        for status in ("QUEUED", "DELIVERED", "ACCEPTED", "DEFERRED", "BLOCKED"):
            id = "cancel-" + status
            self.request(id)
            if status != "QUEUED":
                self.ready()
            if status in ("ACCEPTED", "DEFERRED", "BLOCKED"):
                self.command({"ACCEPTED": "accept", "DEFERRED": "defer", "BLOCKED": "block"}[status], id,
                             reason=None if status == "ACCEPTED" else "Fixture hold")
            receipt = self.hub.cancel("control-" + id, id, "Fixture operator cancelled")
            self.assertEqual("CANCELLED", receipt["result"]["status"])
            self.assertEqual(receipt, self.hub.cancel("control-" + id, id, "Fixture operator cancelled"))
        self.assertEqual("HELD", self.hub.deliver(self.b)["outcome"])

    def test_process_loss_retains_active_capacity_and_restoration_redelivers(self):
        self.request()
        self.request("request-2")
        self.ready()
        self.command("accept")
        first_time = self.state()["traffic"]["request-1"]["response_started_at"]
        self.hub.observe(self.b, Readiness.LOST)
        self.assertEqual("ACCEPTED", self.state()["traffic"]["request-1"]["status"])
        self.assertEqual("HELD", self.hub.deliver(self.b)["outcome"])
        self.assert_code("STALE_CONNECTION", lambda: self.command("complete"))
        old = self.b
        self.b = self.connect("bob", 2)
        self.assert_code("DELIVERY_REQUIRED", lambda: self.command("complete"))
        self.assertEqual("HELD", self.hub.deliver(self.b)["outcome"])
        self.ready()
        self.assertEqual(2, len(self.b.receiver.inbox()))
        self.assertEqual(first_time, self.state()["traffic"]["request-1"]["response_started_at"])
        self.assert_code("CAPACITY_EXHAUSTED", lambda: self.command("accept", "request-2"))
        self.command("complete")
        self.command("accept", "request-2")
        self.assert_code("STALE_CONNECTION", lambda: self.hub.submit(old, Message("old", "run-1", 1, "alice", "old")))

    def test_replacement_fences_same_incarnation_old_attachment(self):
        old = self.b
        self.b = self.connect("bob", attachment="reattach-bob")
        self.assertEqual("HELD", self.hub.deliver(old)["outcome"])
        self.assert_code("STALE_CONNECTION", lambda: self.hub.observe(old, Readiness.SAFE))
        self.assert_code("CONTEXT_MISMATCH", lambda: self.hub.connect("bad-context", "bob", "bob-2", self.b.receiver, context_generation=2))

    def test_retired_incarnation_cannot_replay_old_confirmation_as_current(self):
        self.request()
        self.ready()
        self.command("accept")
        previous = self.b
        self.b = self.connect("bob", 2)
        self.ready()
        before = self.hub.snapshot()
        self.assert_code("INCARNATION_RETIRED", lambda: self.hub.connect(
            "retired-attach", "bob", "bob-1", previous.receiver))
        self.assertEqual(before, self.hub.snapshot())
        self.command("complete")

    def test_receiver_rejects_changed_envelope_or_binding_even_after_reopen(self):
        self.request()
        self.ready()
        envelope = self.b.receiver.inbox()[0]
        receipt = self.b.receiver.accept(envelope)
        self.assertEqual(receipt, self.b.receiver.accept(envelope))
        self.assert_code("ID_CONFLICT", lambda: self.b.receiver.accept({**envelope, "text": "different"}))
        for field, value in (("participant_id", "carol"), ("incarnation_id", "bob-2"), ("context_generation", 2), ("room_id", "beta")):
            self.assert_code("RECEIVER_BINDING_CONFLICT", lambda field=field, value=value: self.b.receiver.accept({**envelope, field: value}))
        self.assert_code("RECEIVER_BINDING_CONFLICT", lambda: FixtureReceiver(self.root / "bob.db", "alpha", "bob", "bob-2"))
        reopened = FixtureReceiver(self.root / "bob.db", "alpha", "bob", "bob-1")
        self.receivers.append(reopened)
        self.assertEqual(receipt, reopened.accept(envelope))
        self.assertEqual(1, len(reopened.inbox()))

    def test_ambiguity_after_receiver_commit_fences_confirmation_not_effect(self):
        self.request()
        self.hub.observe(self.b, Readiness.SAFE)
        accept = self.b.receiver.accept
        def lose_readiness(envelope):
            receipt = accept(envelope)
            self.hub.observe(self.b, Readiness.AMBIGUOUS)
            return receipt
        self.b.receiver.accept = lose_readiness
        self.assert_code("FORBIDDEN", lambda: self.hub.deliver(self.b))
        self.assertEqual(1, len(self.b.receiver.inbox()))
        self.assertIsNone(self.state()["traffic"]["request-1"]["response_started_at"])
        self.assertEqual("UNCONFIRMED", self.state()["offers"]["request-1"]["bob"]["outcome"])
        self.b.receiver.accept = accept
        self.ready()
        self.assertEqual(1, len(self.b.receiver.inbox()))
        self.assertEqual("DELIVERED", self.state()["traffic"]["request-1"]["status"])

    def test_mismatched_receipt_and_receiver_error_remain_unconfirmed(self):
        self.request()
        accept = self.b.receiver.accept
        self.b.receiver.accept = lambda envelope: {**accept(envelope), "incarnation_id": "wrong"}
        self.assert_code("UNCONFIRMED_DELIVERY", lambda: self.ready())
        self.assertIsNone(self.state()["traffic"]["request-1"]["response_started_at"])
        def unavailable(envelope):
            raise OSError("fixture receiver unavailable")
        self.b.receiver.accept = unavailable
        with self.assertRaises(OSError):
            self.hub.deliver(self.b)
        self.assertEqual("QUEUED", self.state()["traffic"]["request-1"]["status"])
        self.b.receiver.accept = accept
        self.hub.deliver(self.b)
        self.assertEqual(1, len(self.b.receiver.inbox()))

    def test_receipt_types_and_exact_shape_cannot_forge_confirmation(self):
        self.request()
        accept = self.b.receiver.accept
        self.hub.observe(self.b, Readiness.SAFE)
        mutations = (
            lambda receipt: {**receipt, "context_generation": True},
            lambda receipt: {**receipt, "context_generation": 1.0},
            lambda receipt: {**receipt, "extra": "field"},
            lambda receipt: {key: value for key, value in receipt.items() if key != "digest"},
            lambda receipt: [receipt],
            lambda receipt: None,
        )
        for mutation in mutations:
            self.b.receiver.accept = lambda envelope, mutation=mutation: mutation(accept(envelope))
            self.assert_code("UNCONFIRMED_DELIVERY", lambda: self.hub.deliver(self.b))
            self.assertIsNone(self.state()["traffic"]["request-1"]["response_started_at"])
            self.assertEqual("QUEUED", self.state()["traffic"]["request-1"]["status"])
        self.b.receiver.accept = accept
        self.hub.deliver(self.b)
        self.assertEqual(1, len(self.b.receiver.inbox()))

    def test_cancel_after_offer_cannot_regress_or_confirm(self):
        self.request()
        accept = self.b.receiver.accept
        def cancel(envelope):
            receipt = accept(envelope)
            self.hub.cancel("cancel-race", "request-1", "cancel during offer")
            return receipt
        self.b.receiver.accept = cancel
        self.assert_code("DELIVERY_FENCED", lambda: self.ready())
        self.assertEqual("CANCELLED", self.state()["traffic"]["request-1"]["status"])
        self.assertIsNone(self.state()["traffic"]["request-1"]["response_started_at"])
        self.assertEqual("HELD", self.hub.deliver(self.b)["outcome"])

    def test_hub_reopen_requires_fresh_safe_point_and_durable_cursor(self):
        self.request()
        self.ready()
        cursor = self.state()["cursors"]["bob"]
        self.request("request-2")
        self.ledger.close()
        self.ledger = RoomLedger(self.root / "room.db", "alpha")
        self.hub = FixturePeerHub(self.ledger)
        self.assertEqual("HELD", self.hub.deliver(self.b)["outcome"])
        self.b = self.connect("bob", attachment="restart-bob")
        self.assertEqual(cursor, self.state()["cursors"]["bob"])
        self.assertEqual("HELD", self.hub.deliver(self.b)["outcome"])
        self.ready()
        self.assertEqual(["request-1", "request-2"], [item["id"] for item in self.b.receiver.inbox()])
        self.assertGreater(self.state()["cursors"]["bob"], cursor)

    def test_configured_multi_slot_capacity_and_json_command(self):
        with RoomLedger(self.root / "two-slots.db", "slots") as ledger:
            hub = FixturePeerHub(ledger)
            hub.configure("config", (FixtureParticipant("alice", "a"), FixtureParticipant("bob", "b", 2)), "run-1")
            alice = FixtureReceiver(self.root / "slots-a.db", "slots", "alice", "a-1")
            bob = FixtureReceiver(self.root / "slots-b.db", "slots", "bob", "b-1")
            self.receivers.extend((alice, bob))
            a = hub.connect("attach-a", "alice", "a-1", alice)
            b = hub.connect("attach-b", "bob", "b-1", bob)
            for index in range(3):
                hub.submit(a, WorkRequest(f"request-{index}", "run-1", 1, "bob", "Fixture"))
            hub.observe(b, Readiness.SAFE)
            hub.deliver(b)
            def accept(index):
                return hub.submit(b, {"id": f"accept-{index}", "run_id": "run-1", "generation": 1,
                                      "kind": "command", "payload": {"request_id": f"request-{index}",
                                      "action": "accept", "reason": None}})
            accept(0)
            accept(1)
            self.assert_code("CAPACITY_EXHAUSTED", lambda: accept(2))
            hub.submit(b, RequestCommand("done", "run-1", 1, "request-0", "complete"))
            accept(2)

    def test_admission_reserves_delivery_capacity_for_broadcast_and_restart(self):
        text = "x" * 16_384
        admitted = []
        for index in range(100):
            before = self.hub.snapshot()
            try:
                id = f"bounded-{index}"
                self.hub.submit(self.a, Message(id, "run-1", 1, "*", text))
                admitted.append(id)
            except LedgerError as error:
                self.assertEqual("QUEUE_CAPACITY_EXHAUSTED", error.code)
                self.assertEqual(before, self.hub.snapshot())
                break
        else:
            self.fail("Room admission must reserve lifecycle capacity")
        self.assertGreater(len(admitted), 1)
        self.ledger.close()
        self.ledger = RoomLedger(self.root / "room.db", "alpha")
        self.hub = FixturePeerHub(self.ledger)
        self.b = self.connect("bob", attachment="bounded-restart-bob")
        self.c = self.connect("carol", attachment="bounded-restart-carol")
        for connection in (self.b, self.c):
            self.ready(connection)
            self.assertEqual(admitted, [item["id"] for item in connection.receiver.inbox()])
        for item in self.state()["traffic"].values():
            self.assertEqual({"bob", "carol"}, set(item["deliveries"]))
        before = self.hub.snapshot()
        self.ledger.close()
        self.ledger = RoomLedger(self.root / "room.db", "alpha")
        self.assertEqual(before, self.ledger.snapshot())

    def test_admission_reserves_request_completion_and_cancellation_capacity(self):
        admitted = []
        for index in range(100):
            before = self.hub.snapshot()
            try:
                id = f"request-bounded-{index}"
                self.hub.submit(self.a, WorkRequest(id, "run-1", 1, "bob", "x" * 16_384))
                admitted.append(id)
            except LedgerError as error:
                self.assertEqual("QUEUE_CAPACITY_EXHAUSTED", error.code)
                self.assertEqual(before, self.hub.snapshot())
                break
        else:
            self.fail("request budget should be bounded")
        self.assertGreater(len(admitted), 1)
        # An unknown receiver effect at saturation must not consume the budget
        # needed to present retained responsibility to a replacement process.
        accept = self.b.receiver.accept
        self.b.receiver.accept = lambda envelope: (accept(envelope), None)[1]
        self.assert_code("UNCONFIRMED_DELIVERY", lambda: self.ready())
        self.assertEqual(1, len(self.b.receiver.inbox()))
        self.assertIsNone(self.state()["traffic"][admitted[0]]["response_started_at"])
        # Replacement uses maximum allowed incarnation and attachment IDs.
        receiver = FixtureReceiver(self.root / "wide.db", "alpha", "bob", "x" * 256)
        self.receivers.append(receiver)
        self.b = self.hub.connect("y" * 256, "bob", "x" * 256, receiver)
        self.ready()
        self.assertEqual(admitted, [item["id"] for item in receiver.inbox()])
        self.assertEqual(1, self.state()["offers"][admitted[0]]["bob"]["superseded_unconfirmed"]["count"])
        # Hold maximum encoded reasons on every accepted request at once.
        for id in admitted:
            self.command("block", id, reason="\n" * 8_192)
        for index, id in enumerate(admitted):
            if index % 2:
                self.hub.cancel("cancel-" + id, id, "x" * 16_384)
            else:
                self.command("accept", id)
                self.command("complete", id)
        self.assertTrue(all(item["status"] in {"COMPLETED", "CANCELLED"}
                            for item in self.state()["traffic"].values()))
        before = self.hub.snapshot()
        self.ledger.close()
        self.ledger = RoomLedger(self.root / "room.db", "alpha")
        self.assertEqual(before, self.ledger.snapshot())

    def test_payload_limit_accounts_for_json_escaping_and_utf8(self):
        for index, (text, extra) in enumerate((("\n" * 8_192, "\n"), ("😀" * 4_096, "😀"))):
            self.hub.submit(self.a, Message(f"max-text-{index}", "run-1", 1, "bob", text))
            before = self.hub.snapshot()
            self.assert_code("INVALID_PAYLOAD", lambda: self.hub.submit(
                self.a, Message(f"oversize-text-{index}", "run-1", 1, "bob", text + extra)))
            self.assertEqual(before, self.hub.snapshot())

    def test_replaced_unknown_offer_remains_explicit_in_projection_and_ledger(self):
        self.request()
        accept = self.b.receiver.accept
        self.b.receiver.accept = lambda envelope: (accept(envelope), None)[1]
        self.assert_code("UNCONFIRMED_DELIVERY", lambda: self.ready())
        previous = copy.deepcopy(self.state()["offers"]["request-1"]["bob"])
        self.b = self.connect("bob", 2)
        self.ready()
        current = self.state()["offers"]["request-1"]["bob"]
        self.assertEqual("CONFIRMED", current["outcome"])
        self.assertEqual({"count": 1, "first_seq": previous["offer_seq"], "last_seq": previous["offer_seq"]},
                         current["superseded_unconfirmed"])
        historical = self.ledger.replay(previous["offer_seq"] - 1, limit=1)[0]
        self.assertEqual("UNCONFIRMED", historical["payload"]["outcome"])
        self.assertEqual(previous["delivery_id"], historical["payload"]["delivery_id"])
        latest = self.ledger.replay(current["offer_seq"] - 1, limit=1)[0]
        self.assertEqual(previous["delivery_id"], latest["payload"]["supersedes_unconfirmed"])

    @unittest.skipUnless(os.name == "posix", "requires actual SIGKILL and POSIX subprocess pipes")
    def test_real_process_crashes_at_receiver_and_hub_commit_boundaries(self):
        # Each subcase is a separate on-disk Room; use the real public Hub path.
        for phase in ("hub-after-offer", "receiver-before-commit", "receiver-after-commit", "hub-before-confirm", "hub-after-confirm"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with RoomLedger(root / "room.db", "alpha") as ledger:
                    hub = FixturePeerHub(ledger)
                    hub.configure("config", (FixtureParticipant("alice", "a"), FixtureParticipant("bob", "b")), "run-1")
                    receiver = FixtureReceiver(root / "alice.db", "alpha", "alice", "alice-1")
                    a = hub.connect("attach-a", "alice", "alice-1", receiver)
                    hub.submit(a, WorkRequest("request", "run-1", 1, "bob", "Crash fixture"))
                    receiver.close()
                worker = Path(__file__).parent / "fixtures" / "peer_worker.py"
                process = subprocess.Popen([sys.executable, str(worker), str(root), phase], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    readable, _, _ = select.select([process.stdout], [], [], 15)
                    self.assertTrue(readable, "crash worker did not reach checkpoint")
                    self.assertEqual("CRASH_POINT", process.stdout.readline().strip())
                    process.kill()
                    process.wait(timeout=10)
                    self.assertLess(process.returncode, 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=10)
                    process.stdout.close()
                    process.stderr.close()
                with RoomLedger(root / "room.db", "alpha") as ledger:
                    hub = FixturePeerHub(ledger)
                    record = hub.snapshot()["state"]["peer_traffic"]["traffic"]["request"]
                    self.assertEqual("DELIVERED" if phase == "hub-after-confirm" else "QUEUED", record["status"])
                    self.assertEqual(phase == "hub-after-confirm", record["response_started_at"] is not None)
                    receiver = FixtureReceiver(root / "bob.db", "alpha", "bob", "bob-1")
                    before_count = 0 if phase in ("hub-after-offer", "receiver-before-commit") else 1
                    self.assertEqual(before_count, len(receiver.inbox()))
                    b = hub.connect("recovered-attach", "bob", "bob-1", receiver)
                    self.assertEqual("HELD", hub.deliver(b)["outcome"])
                    hub.observe(b, Readiness.SAFE)
                    hub.deliver(b)
                    self.assertEqual(1, len(receiver.inbox()))
                    self.assertEqual("DELIVERED", hub.snapshot()["state"]["peer_traffic"]["traffic"]["request"]["status"])
                    hub.deliver(b)
                    self.assertEqual(1, len(receiver.inbox()))
                    receiver.close()


if __name__ == "__main__":
    unittest.main()
