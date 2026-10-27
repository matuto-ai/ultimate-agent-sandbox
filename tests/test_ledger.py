"""Application persistence proof, including real process death and disk reopen."""
from dataclasses import replace
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from ledger_support import ORIGIN, authorized, command, increment
from uas.ledger import Event, LedgerError, RoomLedger, Transition

WORKER = Path(__file__).parent / "fixtures" / "ledger_worker.py"


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "room.sqlite3"
        self.ledger = RoomLedger(self.path, "alpha")
        self.addCleanup(self.ledger.close)

    def apply(self, operation=None, origin=ORIGIN, **kwargs):
        return self.ledger.apply(operation or command(), origin,
                                 authorize=kwargs.pop("authorize", authorized),
                                 decide=kwargs.pop("decide", increment), **kwargs)

    def error(self, code, call):
        with self.assertRaises(LedgerError) as raised:
            call()
        self.assertEqual(code, raised.exception.code)

    def worker(self, mode, *args):
        return subprocess.run([sys.executable, str(WORKER), str(self.path), mode, *args],
                              capture_output=True, text=True, timeout=15)

    def test_append_snapshot_and_ordered_bounded_replay(self):
        snapshot = self.ledger.snapshot()
        self.assertEqual({"room_id": "alpha", "room_seq": 0, "state": {}}, snapshot)
        for index in range(5):
            result = self.apply(command(f"op-{index}", generation=index))
            self.assertEqual(index + 1, result["first_seq"])
            self.assertEqual(index + 1, result["last_seq"])
        self.assertEqual({"value": 5, "generation": 5}, self.ledger.snapshot()["state"])
        events, cursor = [], snapshot["room_seq"]
        while batch := self.ledger.replay(cursor, limit=2):
            events.extend(batch)
            cursor = batch[-1]["room_seq"]
        self.assertEqual([1, 2, 3, 4, 5], [event["room_seq"] for event in events])
        self.assertEqual(events, self.ledger.replay(0))
        self.assertEqual([3, 4], [e["room_seq"] for e in self.ledger.replay(2, through_seq=4)])
        self.assertEqual([], self.ledger.replay(5))
        self.assertEqual("alice", events[0]["origin"]["actor_id"])
        self.assertEqual("counter", events[0]["target"])
        self.assertTrue(events[0]["timestamp"].endswith("+00:00"))

    def test_exact_retry_is_original_result_before_stale_generation_check(self):
        result = self.apply()
        self.apply(command("later", generation=1))
        self.assertEqual(result, self.apply(decide=lambda *_: self.fail("retry ran domain handler")))
        self.assertEqual(2, self.ledger.snapshot()["room_seq"])
        self.error("STALE_GENERATION", lambda: self.apply(command("new-id")))
        self.assertEqual(2, len(self.ledger.replay(0)))

    def test_exact_read_authorizes_and_compares_without_reserving_or_domain_effects(self):
        before = self.ledger.snapshot()
        self.assertIsNone(self.ledger.exact_receipt(command(), ORIGIN, authorize=authorized))
        self.assertEqual(before, self.ledger.snapshot())
        receipt = self.apply()
        self.apply(command('later', generation=1))
        self.assertEqual(receipt, self.ledger.exact_receipt(command(), ORIGIN, authorize=authorized))
        self.error('ID_CONFLICT', lambda: self.ledger.exact_receipt(
            command(generation=2), ORIGIN, authorize=authorized))
        self.error('FORBIDDEN', lambda: self.ledger.exact_receipt(
            command(), ORIGIN, authorize=lambda *_: False))
        self.error('FORBIDDEN', lambda: self.ledger.exact_receipt(
            command('unseen'), ORIGIN, authorize=lambda *_: 1))
        self.assertEqual(2, self.ledger.snapshot()['room_seq'])

    def test_exact_read_detaches_authorizer_payload_and_returned_receipt(self):
        receipt = self.apply()
        def mutating_authorizer(origin, operation):
            operation.payload['amount'] = 900
            return True
        found = self.ledger.exact_receipt(command(), ORIGIN, authorize=mutating_authorizer)
        self.assertEqual(receipt, found)
        found['result']['value'] = 999
        self.assertEqual(receipt, self.ledger.exact_receipt(command(), ORIGIN, authorize=authorized))

    def test_restart_public_interface_preserves_result_state_and_events(self):
        result = self.apply()
        snapshot, events = self.ledger.snapshot(), self.ledger.replay(0)
        self.ledger.close()
        restarted = self.worker("snapshot")
        self.assertEqual(0, restarted.returncode, restarted.stderr)
        self.assertEqual({"snapshot": snapshot, "events": events}, json.loads(restarted.stdout))
        retried = self.worker("apply")
        self.assertEqual(0, retried.returncode, retried.stderr)
        self.assertEqual(result, json.loads(retried.stdout))
        conflict = self.worker("apply", "op-1", "2")
        self.assertEqual(0, conflict.returncode, conflict.stderr)
        self.assertEqual({"error": "ID_CONFLICT"}, json.loads(conflict.stdout))

    def test_conflict_binds_kind_target_generation_typed_payload_and_origin(self):
        result = self.apply()
        variants = [replace(command(), kind="other"), replace(command(), target="other"),
                    replace(command(), generation=1), command(amount=2), command(amount=True),
                    command(amount=1.0), replace(command(), payload={"amount": "1"})]
        origins = [replace(ORIGIN, actor_id="bob"), replace(ORIGIN, participant_id="reviewer"),
                   replace(ORIGIN, incarnation_id="process-2"), replace(ORIGIN, authority_version="policy-v2"),
                   replace(ORIGIN, capabilities=("counter-write", "review"))]
        for operation in variants:
            with self.subTest(operation=operation):
                self.error("ID_CONFLICT", lambda: self.apply(operation))
        for origin in origins:
            with self.subTest(origin=origin):
                self.error("ID_CONFLICT", lambda: self.apply(origin=origin, authorize=lambda *_: True))
        self.assertEqual(result, self.apply())
        self.assertEqual(1, self.ledger.snapshot()["room_seq"])

    def test_every_retry_requires_current_authorization(self):
        self.apply()
        self.error("FORBIDDEN", lambda: self.apply(authorize=lambda *_: False))
        self.error("FORBIDDEN", lambda: self.apply(authorize=lambda *_: 1))
        self.error("FORBIDDEN", lambda: self.apply(origin=replace(ORIGIN, actor_id="bob")))
        self.assertEqual(1, len(self.ledger.replay(0)))

    def test_revocation_while_waiting_for_lock_blocks_commit_and_retry_disclosure(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "room.sqlite3"
                with RoomLedger(path, "alpha") as setup:
                    if duplicate:
                        setup.apply(command(), ORIGIN, authorize=authorized, decide=increment)
                ready, start, waiting, locked, release = [threading.Event() for _ in range(5)]
                outcomes, failures = [], []
                def waiter():
                    try:
                        with RoomLedger(path, "alpha") as client:
                            client._db.set_trace_callback(lambda sql: waiting.set() if sql == "BEGIN IMMEDIATE" else None)
                            ready.set()
                            if not start.wait(5):
                                raise AssertionError("waiter was not started")
                            def authorize_current(origin, operation):
                                return not client.snapshot()["state"].get("revoked", False)
                            try:
                                outcomes.append(client.apply(command(), ORIGIN, authorize=authorize_current, decide=increment))
                            except LedgerError as error:
                                outcomes.append(error.code)
                    except BaseException as error:
                        failures.append(error)
                def revoke():
                    try:
                        with RoomLedger(path, "alpha") as writer:
                            def revoke_policy(state, operation):
                                locked.set()
                                if not release.wait(5):
                                    raise AssertionError("revoker was not released")
                                return Transition({**state, "revoked": True}, (Event("policy.revoked", {}),), {})
                            writer.apply(replace(command(), id="revoke", kind="policy.revoke"), ORIGIN,
                                         authorize=lambda *_: True, decide=revoke_policy)
                    except BaseException as error:
                        failures.append(error)
                client_thread = threading.Thread(target=waiter)
                writer_thread = threading.Thread(target=revoke)
                client_thread.start()
                try:
                    self.assertTrue(ready.wait(5))
                    writer_thread.start()
                    self.assertTrue(locked.wait(5))
                    start.set()
                    self.assertTrue(waiting.wait(5))
                finally:
                    start.set()
                    release.set()
                    client_thread.join(timeout=10)
                    if writer_thread.ident is not None:
                        writer_thread.join(timeout=10)
                self.assertFalse(client_thread.is_alive())
                self.assertFalse(writer_thread.is_alive())
                self.assertEqual([], failures)
                self.assertEqual(["FORBIDDEN"], outcomes)
                with RoomLedger(path, "alpha") as reopened:
                    self.assertEqual(2 if duplicate else 1, reopened.snapshot()["room_seq"])
                    self.assertTrue(reopened.snapshot()["state"]["revoked"])

    def test_canonical_object_and_capability_order_not_python_equality(self):
        origin = replace(ORIGIN, capabilities=("counter-write", "review"))
        operation = replace(command(), payload={"a": {"x": 1, "y": 2}, "b": [1, True]})
        def decide(state, operation):
            return Transition(state, (Event("noted", operation.payload),), {"ok": True})
        result = self.apply(operation, origin, decide=decide)
        reordered = replace(operation, payload={"b": [1, True], "a": {"y": 2, "x": 1}})
        self.assertEqual(result, self.apply(reordered, replace(origin, capabilities=tuple(reversed(origin.capabilities))), decide=decide))
        self.error("ID_CONFLICT", lambda: self.apply(replace(operation, payload={"a": {"x": True, "y": 2}, "b": [1, True]}), origin, decide=decide))

    def test_multiple_events_state_result_and_sequence_commit_together(self):
        def decide(state, operation):
            return Transition({"ready": True}, (Event("one", {}), Event("two", {})), {"ok": True})
        receipt = self.apply(decide=decide)
        self.assertEqual((1, 2), (receipt["first_seq"], receipt["last_seq"]))
        self.assertEqual(2, self.ledger.snapshot()["room_seq"])
        self.assertEqual([1, 2], [e["room_seq"] for e in self.ledger.replay(0)])

    def test_invalid_late_event_rolls_back_prior_event_and_state(self):
        def decide(state, operation):
            return Transition({"should": "rollback"}, (Event("valid", {}), Event("bad space", {})), {})
        self.error("INVALID_COMMAND", lambda: self.apply(decide=decide))
        self.assertEqual([], self.ledger.replay(0))
        self.assertEqual({}, self.ledger.snapshot()["state"])
        self.assertEqual(1, self.apply()["first_seq"])

    def test_handler_failure_and_invalid_transition_leave_no_operation(self):
        def fail(state, operation):
            state["modified"] = True
            raise LedgerError("REJECTED")
        self.error("REJECTED", lambda: self.apply(decide=fail))
        for invalid in (None, Transition({}, (), {}), Transition([], (Event("x", {}),), {}),
                        Transition({}, (Event("x", []),), {}), Transition({}, (Event("x", {}),), [])):
            self.error("INVALID_TRANSITION", lambda: self.apply(decide=lambda *_: invalid))
        self.assertEqual({"room_id": "alpha", "room_seq": 0, "state": {}}, self.ledger.snapshot())
        self.assertEqual(1, self.apply()["last_seq"])

    def test_detached_input_output_and_snapshot(self):
        operation = command()
        def mutate(state, cmd):
            cmd.payload["amount"] = 900
            return increment(state, command(amount=1))
        result = self.apply(operation, decide=mutate)
        result["result"]["value"] = 100
        snapshot = self.ledger.snapshot()
        snapshot["state"]["value"] = 100
        self.assertEqual({"amount": 1}, operation.payload)
        self.assertEqual(1, self.apply()["result"]["value"])
        self.assertEqual(1, self.ledger.snapshot()["state"]["value"])

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "requires process kill")
    def test_kill_before_commit_exposes_none_then_retry_commits_once(self):
        self.ledger.close()
        killed = self.worker("before")
        self.assertEqual(-signal.SIGKILL, killed.returncode, killed.stderr)
        self.assertEqual("", killed.stdout)
        with RoomLedger(self.path, "alpha") as reopened:
            self.assertEqual(0, reopened.snapshot()["room_seq"])
            self.assertEqual({}, reopened.snapshot()["state"])
            self.assertEqual([], reopened.replay(0))
            result = reopened.apply(command(), ORIGIN, authorize=authorized, decide=increment)
            self.assertEqual(1, result["last_seq"])

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "requires process kill")
    def test_kill_after_event_before_result_and_state_rolls_back_all(self):
        self.ledger.close()
        killed = self.worker("partial")
        self.assertEqual(-signal.SIGKILL, killed.returncode, killed.stderr)
        self.assertEqual("", killed.stdout)
        with RoomLedger(self.path, "alpha") as reopened:
            self.assertEqual({"room_id": "alpha", "room_seq": 0, "state": {}}, reopened.snapshot())
            self.assertEqual([], reopened.replay(0))
            self.assertEqual(1, reopened.apply(command(), ORIGIN, authorize=authorized, decide=increment)["last_seq"])

    @unittest.skipUnless(hasattr(signal, "SIGKILL"), "requires process kill")
    def test_kill_after_commit_before_ack_exposes_all_and_returns_original(self):
        self.ledger.close()
        killed = self.worker("after")
        self.assertEqual(-signal.SIGKILL, killed.returncode, killed.stderr)
        self.assertEqual("", killed.stdout)
        with RoomLedger(self.path, "alpha") as reopened:
            self.assertEqual({"value": 1, "generation": 1}, reopened.snapshot()["state"])
            self.assertEqual(1, reopened.snapshot()["room_seq"])
            self.assertEqual(1, len(reopened.replay(0)))
            receipt = reopened.apply(command(), ORIGIN, authorize=authorized,
                                     decide=lambda *_: self.fail("committed result missing"))
            self.assertEqual({"value": 1}, receipt["result"])
            self.assertEqual(1, receipt["last_seq"])

    def test_real_sqlite_full_rolls_back_and_recovers(self):
        # Limit this disposable SQLite database, not the host disk. This is a real
        # SQLITE_FULL from SQLite's pager, not a mocked failure or host power-loss.
        pages = self.ledger._db.execute("PRAGMA page_count").fetchone()[0]
        self.ledger._db.execute(f"PRAGMA max_page_count={pages}")
        def large(state, operation):
            return Transition({"data": "x" * 100_000}, (Event("large", {}),), {})
        with self.assertRaises(LedgerError) as failed:
            self.apply(decide=large)
        self.assertEqual("STORAGE_ERROR", failed.exception.code)
        self.assertEqual(sqlite3.SQLITE_FULL, failed.exception.__cause__.sqlite_errorcode)
        self.assertEqual(0, self.ledger.snapshot()["room_seq"])
        self.assertEqual([], self.ledger.replay(0))
        self.ledger.close()
        with RoomLedger(self.path, "alpha") as reopened:
            self.assertEqual({}, reopened.snapshot()["state"])
            self.assertEqual(1, reopened.apply(command(), ORIGIN, authorize=authorized, decide=increment)["last_seq"])

    def test_concurrent_exact_duplicates_from_independent_processes(self):
        processes = [subprocess.Popen([sys.executable, str(WORKER), str(self.path), "apply"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(6)]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(0, process.returncode, stderr)
            results.append(json.loads(stdout))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(1, self.ledger.snapshot()["room_seq"])
        self.assertEqual(1, len(self.ledger.replay(0)))

    def test_concurrent_conflicts_commit_only_one_result(self):
        processes = [subprocess.Popen([sys.executable, str(WORKER), str(self.path), "apply", "same-id", str(amount)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for amount in (1, 2)]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(0, process.returncode, stderr)
            results.append(json.loads(stdout))
        self.assertEqual(1, sum(result == {"error": "ID_CONFLICT"} for result in results))
        self.assertEqual(1, self.ledger.snapshot()["room_seq"])
        committed = next(result for result in results if "result" in result)
        self.assertEqual(committed["result"]["value"], self.ledger.snapshot()["state"]["value"])

    def test_concurrent_snapshots_have_one_consistent_cut(self):
        errors = []
        started, done = threading.Event(), threading.Event()
        def write():
            try:
                with RoomLedger(self.path, "alpha") as writer:
                    started.set()
                    for index in range(100):
                        writer.apply(command(f"op-{index}", generation=index), ORIGIN, authorize=authorized, decide=increment)
            except BaseException as error:
                errors.append(error)
            finally:
                done.set()
        thread = threading.Thread(target=write)
        thread.start()
        self.assertTrue(started.wait(5))
        observations = 0
        deadline = time.monotonic() + 10
        while not done.is_set() and time.monotonic() < deadline:
            snapshot = self.ledger.snapshot()
            self.assertEqual(snapshot["room_seq"], snapshot["state"].get("value", 0))
            self.assertEqual(snapshot["room_seq"], snapshot["state"].get("generation", 0))
            observations += 1
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "writer did not finish")
        self.assertEqual([], errors)
        self.assertGreater(observations, 0)
        self.assertEqual(100, self.ledger.snapshot()["room_seq"])

    def test_room_binding_unknown_schema_and_closed_handle_fail_closed(self):
        self.error("ROOM_MISMATCH", lambda: RoomLedger(self.path, "beta"))
        self.ledger.close()
        self.error("CLOSED", self.ledger.snapshot)
        self.error("CLOSED", lambda: self.ledger.replay(0))
        self.error("CLOSED", self.apply)
        with sqlite3.connect(self.path) as database:
            database.execute("UPDATE room SET version=99")
        self.error("UNSUPPORTED_STORE_VERSION", lambda: RoomLedger(self.path, "alpha"))
        unrelated = Path(self.temp.name) / "unrelated.sqlite3"
        with sqlite3.connect(unrelated) as database:
            database.execute("CREATE TABLE unrelated (x)")
        self.error("INVALID_STORE", lambda: RoomLedger(unrelated, "alpha"))
        self.error("INVALID_STORE", lambda: RoomLedger(":memory:", "alpha"))

    def test_invalid_envelopes_payload_json_origins_and_cursors(self):
        for operation in (replace(command(), id=""), replace(command(), kind="bad space"),
                          replace(command(), generation=True), replace(command(), generation=-1),
                          replace(command(), payload=[])):
            self.error("INVALID_COMMAND", lambda: self.apply(operation))
        for value in (float("nan"), float("inf"), {1: "bad"}, (1, 2), "\ud800", 2**80, "x" * 1_048_577):
            self.error("INVALID_JSON", lambda: self.apply(replace(command(), payload={"value": value})))
        cycle = {}; cycle["self"] = cycle
        self.error("INVALID_JSON", lambda: self.apply(replace(command(), payload=cycle)))
        self.error("INVALID_COMMAND", lambda: self.apply(origin=replace(ORIGIN, capabilities=("x", "x"))))
        for cursor in (-1, True, "0", 2**64):
            self.error("INVALID_CURSOR", lambda: self.ledger.replay(cursor))
        for limit in (0, 1001, True):
            self.error("INVALID_CURSOR", lambda: self.ledger.replay(0, limit=limit))
        self.error("INVALID_CURSOR", lambda: self.ledger.replay(2, through_seq=1))
        self.assertEqual(0, self.ledger.snapshot()["room_seq"])


if __name__ == "__main__":
    unittest.main()
