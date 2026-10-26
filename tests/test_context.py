"""Typed fixture context facts and shared-budget regressions (not native proof)."""
from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest

from uas.context import FixtureRun, FixtureRunTerminal, MAX_CONTEXT_GENERATION, MAX_RUNS
from uas.fixture_peer import FixtureReceiver
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition, _json
from uas.peer import FixtureParticipant, FixturePeerHub, Message, Readiness, RequestCommand, WorkRequest


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ledger = RoomLedger(self.root / "room.db", "room")
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure("configure", tuple(FixtureParticipant(name, "actor-" + name)
                           for name in ("alice", "bob", "carol", "dave", "erin")), "run-a",
                           initial_runs={"carol": FixtureRun("run-b"), "dave": FixtureRun("run-c"),
                                         "erin": FixtureRun("run-c")})
        self.receivers = []
        self.a = self.connect("alice")
        self.b = self.connect("bob")
        self.c = self.connect("carol")
        self.d = self.connect("dave")
        self.e = self.connect("erin")

    def tearDown(self):
        self.ledger.close()
        for receiver in self.receivers:
            receiver.close()
        self.temp.cleanup()

    def connect(self, participant, generation=1, incarnation=None):
        incarnation = incarnation or f"{participant}-{generation}"
        receiver = FixtureReceiver(self.root / (hashlib.sha256(incarnation.encode()).hexdigest() + ".db"), "room", participant, incarnation, generation)
        self.receivers.append(receiver)
        return self.hub.connect(incarnation if len(incarnation) > 240 else "attach-" + incarnation,
                                participant, incarnation, receiver, context_generation=generation)

    def row(self, participant="bob"):
        return self.hub.snapshot()["state"]["fixture_context"]["participants"][participant]

    def assert_code(self, code, call):
        with self.assertRaises(LedgerError) as raised:
            call()
        self.assertEqual(code, raised.exception.code)

    def ready(self, connection=None):
        self.hub.observe(connection or self.b, Readiness.SAFE)
        return self.hub.deliver(connection or self.b)

    def close_a(self):
        return self.hub.contexts.close_run("close-a", "run-a", FixtureRunTerminal.COMPLETED)

    def request_reset(self, reset_id="reset-bob"):
        return self.hub.contexts.request_reset(reset_id, "bob", 1, FixtureRun("run-b"))

    def succeed(self, reset_id="reset-bob"):
        # This is only a trusted synthetic proof seam. Actual native proof is
        # separately exercised by the Supervisor/Pi integration tests.
        return self.hub.contexts.succeed_reset(reset_id, 1, authorize=lambda: True)

    def mutate(self, id, mutate):
        def decide(state, _):
            mutate(state)
            return Transition(state, (Event("test.mutated", {}),), {})
        return self.ledger.apply(Command(id, "test.mutate", "room", None, {}),
                                 Origin("test", "test", "test", "v1", ()),
                                 authorize=lambda *_: True, decide=decide)

    def test_first_offer_reservation_and_only_confirmed_delivery_binds(self):
        self.assertIsNone(self.row()["bound_run"])
        self.assertEqual({"run_id": "run-a", "generation": 1}, self.row()["reserved_run"])
        self.hub.submit(self.a, WorkRequest("work-a", "run-a", 1, "bob", "Fixture"))
        accept = self.b.receiver.accept
        def uncertain(envelope):
            self.assertIsNone(self.row()["bound_run"])
            self.assertEqual("run-a", self.row()["reserved_run"]["run_id"])
            accept(envelope)
            return None
        self.b.receiver.accept = uncertain
        self.assert_code("UNCONFIRMED_DELIVERY", self.ready)
        self.assertIsNone(self.row()["bound_run"])
        self.assertEqual("run-a", self.row()["reserved_run"]["run_id"])
        self.b.receiver.accept = accept
        self.hub.deliver(self.b)
        self.assertEqual({"run_id": "run-a", "generation": 1}, self.row()["bound_run"])
        self.assertIsNone(self.row()["reserved_run"])
        self.assertEqual(1, len(self.b.receiver.inbox()))

    def test_close_requires_typed_fact_and_every_request_terminal(self):
        self.assert_code("INVALID_TERMINAL_FACT", lambda: self.hub.contexts.close_run("bad", "run-a", True))
        self.hub.submit(self.a, WorkRequest("work-a", "run-a", 1, "bob", "Fixture"))
        self.assert_code("RUN_HAS_LIVE_REQUESTS", self.close_a)
        self.ready()
        for index, (action, reason) in enumerate(((None, None), ("accept", None), ("defer", "wait"),
                                                ("accept", None), ("block", "blocked"))):
            if action:
                self.hub.submit(self.b, RequestCommand(action + str(index), "run-a", 1, "work-a", action, reason))
            self.assert_code("RUN_HAS_LIVE_REQUESTS", self.close_a)
        self.hub.cancel("cancel-a", "work-a", "fixture closed")
        receipt = self.close_a()
        self.assertEqual(receipt, self.close_a())
        self.assert_code("STALE_GENERATION", lambda: self.hub.submit(self.a, Message("late", "run-a", 1, "bob", "late")))

    def test_reset_fences_immediately_success_once_sibling_unaffected(self):
        self.hub.submit(self.a, Message("old-message", "run-a", 1, "bob", "Old history"))
        self.hub.submit(self.c, WorkRequest("new-work", "run-b", 1, "bob", "New work"))
        self.close_a()
        requested = self.request_reset()
        self.assertEqual(requested, self.request_reset())
        self.assertEqual("RESETTING", self.row()["status"])
        self.assertFalse(self.hub._current(self.b))
        self.assertEqual("HELD", self.hub.deliver(self.b)["outcome"])
        self.assert_code("STALE_CONNECTION", lambda: self.hub.submit(self.b, Message("forged", "run-b", 1, "carol", "no")))
        self.assert_code("CONTEXT_MISMATCH", lambda: self.hub.connect("early", "bob", "new-bob", self.b.receiver, context_generation=2))
        self.assert_code("CONTEXT_UNAVAILABLE", lambda: self.hub.contexts.scope("bob"))
        self.assertEqual({"room_id": "room", "participant_id": "bob", "run_id": "run-b", "generation": 1,
                          "context_generation": 2}, self.hub.contexts.pending_scope("reset-bob"))
        # Independent Run C's authority and delivery are not rebound roomwide.
        self.hub.submit(self.d, Message("sibling", "run-c", 1, "erin", "Still live"))
        self.assertEqual("CONFIRMED", self.ready(self.e)["outcome"])
        sibling = deepcopy(self.row("erin"))
        succeeded = self.succeed()
        self.assertEqual(succeeded, self.succeed())
        self.assertEqual(2, self.row()["context_generation"])
        self.assertIsNone(self.row()["bound_run"])
        self.assertEqual("run-b", self.row()["reserved_run"]["run_id"])
        self.assert_code("CONTEXT_MISMATCH", lambda: self.hub.connect("old-context", "bob", "old-bob", self.b.receiver))
        self.assert_code("INCARNATION_RETIRED", lambda: self.hub.connect(
            "old-process-new-context", "bob", self.b.incarnation_id, self.b.receiver, context_generation=2))
        self.b = self.connect("bob", 2)
        self.assertEqual("CONFIRMED", self.ready()["outcome"])
        self.assertEqual(["new-work"], [item["id"] for item in self.b.receiver.inbox()])
        self.assertEqual("run-b", self.row()["bound_run"]["run_id"])
        self.assertEqual(sibling, self.row("erin"))
        self.assertIn("old-message", self.hub.snapshot()["state"]["peer_traffic"]["traffic"])
        events = [event["kind"] for event in self.ledger.replay(0, limit=1000)]
        self.assertEqual(1, events.count("context.reset.requested"))
        self.assertEqual(1, events.count("context.reset.succeeded"))

    def test_failure_retries_keep_old_closed_and_new_unavailable(self):
        self.close_a()
        self.request_reset()
        before = self.hub.snapshot()
        self.assert_code("FORBIDDEN", lambda: self.hub.contexts.succeed_reset("reset-bob", 1, authorize=lambda: False))
        self.assertEqual(before, self.hub.snapshot())
        first = self.hub.contexts.fail_reset("reset-bob", 1, "NATIVE_TIMEOUT", attempt_id="attempt-1")
        self.assertEqual(first, self.hub.contexts.fail_reset("reset-bob", 1, "NATIVE_TIMEOUT", attempt_id="attempt-1"))
        self.assert_code("ID_CONFLICT", lambda: self.hub.contexts.fail_reset("reset-bob", 1, "OTHER", attempt_id="attempt-1"))
        self.hub.contexts.fail_reset("reset-bob", 1, "NATIVE_EXIT", attempt_id="attempt-2")
        self.assertEqual("UNAVAILABLE", self.row()["status"])
        self.assertEqual(1, self.row()["context_generation"])
        self.assertEqual("CLOSED", self.hub.snapshot()["state"]["fixture_context"]["runs"]["run-a"]["status"])
        self.assertEqual("run-b", self.hub.contexts.pending_scope("reset-bob")["run_id"])
        self.assert_code("CONTEXT_UNAVAILABLE", lambda: self.hub.contexts.scope("bob"))
        self.succeed()
        self.assertEqual(2, self.row()["context_generation"])
        before = self.hub.snapshot()
        self.assert_code("STALE_RESET", lambda: self.hub.contexts.fail_reset("reset-bob", 1, "LATE", attempt_id="late"))
        self.assertEqual(before, self.hub.snapshot())

    def test_reopen_retains_pending_reset_and_exact_retry(self):
        self.close_a()
        requested = self.request_reset()
        self.hub.contexts.fail_reset("reset-bob", 1, "NATIVE_EXIT")
        self.ledger.close()
        self.ledger = RoomLedger(self.root / "room.db", "room")
        self.hub = FixturePeerHub(self.ledger)
        self.assertEqual(requested, self.request_reset())
        self.assertEqual("FAILED", self.hub.contexts.reset_status("reset-bob")["status"])
        self.assertFalse(self.hub._current(self.b))
        self.succeed()
        self.assertEqual(2, self.hub.contexts.scope("bob")["context_generation"])

    def test_reset_rejects_open_old_closed_target_stale_and_exhausted_generation(self):
        self.assert_code("PRECEDING_RUN_OPEN", self.request_reset)
        self.close_a()
        self.assert_code("CONTEXT_MISMATCH", lambda: self.hub.contexts.request_reset("stale", "bob", 2, FixtureRun("run-b")))
        self.assert_code("CONTEXT_MISMATCH", lambda: self.hub.contexts.request_reset("bool", "bob", True, FixtureRun("run-b")))
        self.assert_code("TARGET_RUN_UNAVAILABLE", lambda: self.hub.contexts.request_reset("missing", "bob", 1, FixtureRun("missing")))
        self.assert_code("INVALID_SCOPE", lambda: self.hub.contexts.request_reset("untyped", "bob", 1, {"run_id": "run-b"}))
        self.mutate("exhaust", lambda state: state["fixture_context"]["participants"]["bob"].update(context_generation=MAX_CONTEXT_GENERATION))
        before = self.hub.snapshot()
        self.assert_code("CONTEXT_GENERATION_EXHAUSTED", lambda: self.hub.contexts.request_reset(
            "exhausted", "bob", MAX_CONTEXT_GENERATION, FixtureRun("run-b")))
        self.assertEqual(before, self.hub.snapshot())

    def test_target_closing_during_native_reset_cannot_publish_success(self):
        self.close_a()
        self.request_reset()
        self.hub.contexts.close_run("close-b", "run-b", FixtureRunTerminal.CANCELLED)
        self.assert_code("TARGET_RUN_UNAVAILABLE", self.succeed)
        self.hub.contexts.fail_reset("reset-bob", 1, "TARGET_CLOSED")
        self.assertEqual("UNAVAILABLE", self.row()["status"])
        self.assertEqual(1, self.row()["context_generation"])

    def test_late_native_receipt_after_run_close_and_reset_is_fenced(self):
        self.hub.submit(self.a, Message("old-message", "run-a", 1, "bob", "Old"))
        accept = self.b.receiver.accept
        def race(envelope):
            receipt = accept(envelope)
            self.close_a()
            self.request_reset()
            return receipt
        self.b.receiver.accept = race
        self.assert_code("FORBIDDEN", self.ready)
        self.assertIsNone(self.row()["bound_run"])
        self.assertEqual("run-a", self.row()["reserved_run"]["run_id"])
        self.assertEqual("UNCONFIRMED", self.hub.snapshot()["state"]["peer_traffic"]["offers"]["old-message"]["bob"]["outcome"])

    def test_previous_context_parent_and_request_cannot_be_reused(self):
        self.hub.submit(self.a, WorkRequest("old-work", "run-a", 1, "bob", "Old"))
        self.ready()
        self.hub.cancel("cancel", "old-work", "Closed")
        self.close_a()
        self.request_reset()
        self.succeed()
        self.b = self.connect("bob", 2)
        self.assert_code("FORBIDDEN_PARENT", lambda: self.hub.submit(self.b, Message("reply", "run-b", 1, None, "No", "old-work")))
        self.assert_code("UNKNOWN_REQUEST", lambda: self.hub.submit(self.b, RequestCommand("complete", "run-b", 1, "old-work", "complete")))
        self.assert_code("STALE_GENERATION", lambda: self.hub.submit(self.b, Message("old-run", "run-a", 1, "alice", "No")))

    def test_closed_run_ids_never_reopen_even_after_bounded_row_pruning(self):
        self.hub.contexts.open_run("open-extra", FixtureRun("extra"))
        self.hub.contexts.close_run("close-extra", "extra", FixtureRunTerminal.COMPLETED)
        self.assertNotIn("extra", self.hub.snapshot()["state"]["fixture_context"]["runs"])
        before = self.hub.snapshot()
        self.assert_code("RUN_CLOSED", lambda: self.hub.contexts.open_run("reopen-extra", FixtureRun("extra", 2)))
        self.assertEqual(before, self.hub.snapshot())
        # Historical facts are on disk; repeated closed rows do not accumulate.
        for index in range(66):
            run = "closed-" + str(index)
            self.hub.contexts.open_run("open-" + run, FixtureRun(run))
            self.hub.contexts.close_run("close-" + run, run, FixtureRunTerminal.CANCELLED)
        self.assertEqual(3, len(self.hub.snapshot()["state"]["fixture_context"]["runs"]))

    def test_open_run_limit_and_generation_validation_are_atomic(self):
        for index in range(MAX_RUNS - 3):
            self.hub.contexts.open_run("open-" + str(index), FixtureRun("open-" + str(index)))
        before = self.hub.snapshot()
        self.assert_code("RUN_CAPACITY_EXHAUSTED", lambda: self.hub.contexts.open_run("overflow", FixtureRun("overflow")))
        self.assert_code("INVALID_SCOPE", lambda: self.hub.contexts.open_run("bad-gen", FixtureRun("bad-gen", MAX_CONTEXT_GENERATION + 1)))
        self.assertEqual(before, self.hub.snapshot())

    def test_old_reset_status_remains_history_not_authority(self):
        self.close_a()
        self.request_reset()
        self.succeed()
        self.hub.contexts.close_run("close-b", "run-b", FixtureRunTerminal.COMPLETED)
        self.hub.contexts.request_reset("reset-2", "bob", 2, FixtureRun("run-c"))
        before = self.hub.snapshot()
        self.assertEqual("SUCCEEDED", self.hub.contexts.reset_status("reset-bob")["status"])
        self.assert_code("STALE_RESET", lambda: self.hub.contexts.pending_scope("reset-bob"))
        self.assert_code("FORBIDDEN", self.succeed)
        self.assertEqual(before, self.hub.snapshot())
        self.hub.contexts.succeed_reset("reset-2", 2, authorize=lambda: True)
        self.assertEqual(3, self.row()["context_generation"])

    def test_shared_reserve_survives_saturation_close_reset_restart_and_completion(self):
        # Admit the next Run's work before saturating the shared projection.
        self.hub.submit(self.c, WorkRequest("new-work", "run-b", 1, "bob", "New"))
        admitted = []
        for index in range(100):
            before = self.hub.snapshot()
            try:
                id = "bulk-" + str(index)
                self.hub.submit(self.a, WorkRequest(id, "run-a", 1, "bob", "x" * 16384))
                admitted.append(id)
            except LedgerError as error:
                self.assertEqual("QUEUE_CAPACITY_EXHAUSTED", error.code)
                self.assertEqual(before, self.hub.snapshot())
                break
        else:
            self.fail("admission must saturate")
        self.assertGreater(len(admitted), 1)
        # Peer admission reserved all 64 maximal Run rows before QUEUED, not
        # only the three rows present at admission.
        for index in range(MAX_RUNS - 3):
            self.hub.contexts.open_run("wide-open-" + str(index),
                                      FixtureRun(f"r{index:03d}" + "x" * 252, MAX_CONTEXT_GENERATION))
        for id in admitted:
            self.hub.cancel("cancel-" + id, id, "x" * 16384)
        self.close_a()
        self.request_reset()
        self.hub.contexts.fail_reset("reset-bob", 1, "x" * 256)
        self.ledger.close()
        self.ledger = RoomLedger(self.root / "room.db", "room")
        self.hub = FixturePeerHub(self.ledger)
        self.succeed()
        self.b = self.connect("bob", 2, "x" * 256)
        self.ready()
        self.hub.submit(self.b, RequestCommand("accept-new", "run-b", 1, "new-work", "accept"))
        self.hub.submit(self.b, RequestCommand("complete-new", "run-b", 1, "new-work", "complete"))
        self.assertEqual("COMPLETED", self.hub.snapshot()["state"]["peer_traffic"]["traffic"]["new-work"]["status"])
        self.assertEqual(2, self.row()["context_generation"])
        self.hub._reserve_capacity(self.hub.snapshot()["state"])

    def test_reset_storage_failure_before_commit_has_no_fence_or_generation_change(self):
        self.close_a()
        before = self.hub.snapshot()
        commit = self.ledger._commit
        def failed_commit():
            raise OSError("fixture commit unavailable")
        self.ledger._commit = failed_commit
        try:
            with self.assertRaises(OSError):
                self.request_reset()
        finally:
            self.ledger._commit = commit
        self.assertEqual(before, self.hub.snapshot())
        self.assertTrue(self.hub._current(self.b))
        self.request_reset()
        self.assertFalse(self.hub._current(self.b))

    def test_uncertain_success_commit_reconciles_without_generation_readvance(self):
        self.close_a()
        self.request_reset()
        commit = self.ledger._commit
        def lost_ack():
            commit()
            raise OSError("fixture lost success acknowledgement")
        self.ledger._commit = lost_ack
        try:
            with self.assertRaises(OSError):
                self.succeed()
        finally:
            self.ledger._commit = commit
        self.assertEqual("SUCCEEDED", self.hub.contexts.reset_status("reset-bob")["status"])
        self.assertEqual(2, self.row()["context_generation"])
        before = self.hub.snapshot()
        self.succeed()
        self.assertEqual(before, self.hub.snapshot())
        self.assert_code("STALE_RESET", lambda: self.hub.contexts.fail_reset("reset-bob", 1, "UNKNOWN"))
        self.assertEqual(before, self.hub.snapshot())

    def test_legacy_enablement_preserves_already_confirmed_binding(self):
        self.hub.submit(self.a, Message("old-message", "run-a", 1, "bob", "Legacy"))
        self.ready()
        self.mutate("legacy", lambda state: state.pop("fixture_context"))
        self.hub.contexts.enable("enable")
        self.assertEqual({"run_id": "run-a", "generation": 1}, self.row()["bound_run"])
        self.assertIsNone(self.row()["reserved_run"])

    def test_legacy_enablement_cannot_consume_reserved_peer_lifecycle_space(self):
        # Legacy state can exist without the new domain. Its explicit upgrade
        # must fail atomically if a different trusted writer consumed headroom.
        def fill(state):
            state.pop("fixture_context")
            state["other"] = "x" * 980000
        self.mutate("legacy-full", fill)
        self.assertLess(len(_json(self.hub.snapshot()["state"]).encode()), 1048576)
        before = self.hub.snapshot()
        self.assert_code("QUEUE_CAPACITY_EXHAUSTED", lambda: self.hub.contexts.enable("enable-context"))
        self.assertEqual(before, self.hub.snapshot())
        self.mutate("free-headroom", lambda state: state.pop("other"))
        self.hub.contexts.enable("enable-context")
        self.assertEqual(1, self.hub.contexts.scope("bob")["context_generation"])


if __name__ == "__main__":
    unittest.main()
