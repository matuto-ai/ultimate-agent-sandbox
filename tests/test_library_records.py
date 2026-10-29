"""Library operational record seam: durable metadata-only receipts and attempts."""
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from library_support import (AT, ORIGIN, OTHER, binding, capture, document, operation, session,
                             settings, value)
from uas import library
from uas.ledger import Origin
from uas.library import LibraryError
from uas.library_records import LibraryRecords, MAX_PENDING

WORKER = Path(__file__).parent / "fixtures" / "library_record_worker.py"
TITLE_MARKER = "PRIVATE_TITLE_MARKER_5f1c"
BODY_MARKER = "PRIVATE_BODY_MARKER_8b27"
CONTENT = value(title="Pick SQLite " + TITLE_MARKER, body="Body " + BODY_MARKER + ".\n")
DIGEST = "a" * 64


def durable(operation, projection_commit="b" * 40, visible=False):
    """DURABLY_QUEUED evidence: exact published draft path plus projection state."""
    return library.receipt(operation, "DURABLY_QUEUED", at=AT,
                           publication={"commit_sha": "c" * 40,
                                        "path": library.queue_path(
                                            operation.scope.project_path, operation.queue_id)},
                           projection={"commit_sha": projection_commit, "visible": visible})


def human_reject(operation_id="reject-1"):
    return library.action(library.human_scope(session(("library-reject",)), binding=binding(),
                                              kind="reject"),
                          settings(), kind="reject", operation_id=operation_id,
                          request_id="human-request-1",
                          payload={"drain_id": "drain-1", "queue_id": DIGEST,
                                   "reason": "RULE_REFUSED", "observed_version": DIGEST},
                          at=AT)


def bodies(text):
    """Distinct marker strings anywhere in a serialized surface."""
    return sorted({match for match in (TITLE_MARKER, BODY_MARKER) if match in text})


class RecordCommitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "library-records.sqlite3"
        self.records = LibraryRecords(self.path, "deployment-1")
        self.addCleanup(self.records.close)

    def reopen(self):
        self.records.close()
        self.records = LibraryRecords(self.path, "deployment-1")
        self.addCleanup(self.records.close)
        return self.records

    def test_intent_and_terminal_survive_reopen(self):
        attempt = capture(payload=CONTENT)
        started = self.records.begin(attempt)
        self.assertEqual("PENDING", started["state"])
        record = started["record"]
        identity = attempt.scope.canonical()
        self.assertEqual(attempt.operation_id, record["operation_id"])
        self.assertEqual("enqueue", record["kind"])
        self.assertEqual(attempt.request_id, record["request_id"])
        self.assertEqual(attempt.queue_id, record["queue_id"])
        self.assertEqual(attempt.settings_id, record["settings_id"])
        self.assertEqual(attempt.digest(), record["payload_sha256"])
        self.assertGreater(record["payload_bytes"], 0)
        self.assertEqual(identity["project_id"], record["project_id"])
        self.assertEqual(identity["project_identity"], record["project_identity"])
        self.assertEqual(identity["project_path"], record["project_path"])
        self.assertEqual("participant", record["origin"]["subject"])
        self.assertEqual(ORIGIN.actor_id, record["origin"]["actor_id"])
        self.assertEqual(ORIGIN.authority_version, record["origin"]["authority_version"])
        self.assertIsNone(record["receipt"])
        self.assertIsNone(record["finished_at"])
        self.assertRegex(record["started_at"], r"\+00:00\Z")
        self.assertEqual([record], self.records.pending())

        reopened = self.reopen()
        self.assertEqual(record, reopened.record(attempt.operation_id,
                                                 project_identity=identity["project_identity"]))
        self.assertEqual([record], reopened.pending())

        finished = reopened.finish(attempt, durable(attempt))
        self.assertEqual("RECORDED", finished["state"])
        self.assertEqual("DURABLY_QUEUED", finished["receipt"]["outcome"])
        self.assertEqual("c" * 40, finished["receipt"]["publication"]["commit_sha"])
        self.assertEqual([], reopened.pending())

        again = self.reopen()
        self.assertEqual(finished, again.record(attempt.operation_id,
                                                project_identity=identity["project_identity"]))
        submission = again.submission(identity["project_identity"], attempt.request_id)
        self.assertEqual([finished], submission["attempts"])

    def test_recorded_outcome_is_never_rewritten(self):
        attempt = capture()
        self.records.begin(attempt)
        recorded = self.records.finish(attempt, durable(attempt))
        with self.assertRaises(LibraryError) as refused:
            self.records.finish(attempt, library.receipt(attempt, "REJECTED", at=AT,
                                                         reason="RULE_REFUSED"))
        self.assertEqual("ID_CONFLICT", refused.exception.code)
        with self.assertRaises(LibraryError) as drift:
            self.records.finish(attempt, durable(attempt, projection_commit="d" * 40, visible=True))
        self.assertEqual("ID_CONFLICT", drift.exception.code)
        self.assertEqual(recorded, self.reopen().record(
            attempt.operation_id, project_identity=attempt.scope.project_identity))

    def test_exact_retries_stay_stable(self):
        attempt = capture()
        first = self.records.begin(attempt)
        second = self.reopen().begin(attempt)
        self.assertEqual(first, second)
        self.assertEqual(1, len(self.records.submission(attempt.scope.project_identity,
                                                       attempt.request_id)["attempts"]))
        terminal = self.records.finish(attempt, durable(attempt))
        self.assertEqual(terminal, self.reopen().finish(attempt, durable(attempt)))
        self.assertEqual(1, len(self.records.submission(attempt.scope.project_identity,
                                                       attempt.request_id)["attempts"]))

    def test_conflicting_identity_and_digest_reuse_is_refused(self):
        attempt = capture()
        self.records.begin(attempt)
        recorded = self.records.finish(attempt, durable(attempt))
        conflicting = capture(payload=value(title="Different", body="Different body\n"))
        for reuse in (replace(conflicting, operation_id=attempt.operation_id),
                      conflicting):
            with self.assertRaises(LibraryError) as refused:
                self.records.begin(reuse)
            self.assertEqual("ID_CONFLICT", refused.exception.code)
        submission = self.records.submission(attempt.scope.project_identity, attempt.request_id)
        self.assertEqual(attempt.digest(), submission["origin"]["payload_sha256"])
        self.assertEqual([recorded], submission["attempts"])

    def test_submission_cannot_claim_another_actors_origin(self):
        attempt = capture()
        forged = replace(attempt, provenance={**attempt.provenance, "actor_id": OTHER.actor_id})
        with self.assertRaises(LibraryError) as refused:
            self.records.begin(forged)
        self.assertEqual("CALLER_AUTHORITY", refused.exception.code)
        self.assertIsNone(self.records.record(attempt.operation_id,
                                              project_identity=attempt.scope.project_identity))

    def test_forged_submission_time_is_a_typed_refusal(self):
        attempt = capture()
        for at in ("", "garbage", "2026-10-28T22:00:00"):
            with self.subTest(at=at):
                forged = replace(attempt, provenance={**attempt.provenance, "at": at})
                with self.assertRaises(LibraryError) as refused:
                    self.records.begin(forged)
                self.assertEqual("INVALID_RECORD", refused.exception.code)
        self.assertEqual([], self.records.pending())
        self.assertEqual("PENDING", self.records.begin(attempt)["state"])

    def test_unrecorded_terminal_needs_a_durable_intent(self):
        attempt = capture()
        with self.assertRaises(LibraryError) as missing:
            self.records.finish(attempt, durable(attempt))
        self.assertEqual("RECORD_NOT_FOUND", missing.exception.code)

    def test_terminal_must_describe_the_stored_attempt(self):
        attempt = capture()
        self.records.begin(attempt)
        for receipt in (durable(replace(attempt, operation_id="other-command")),
                        durable(replace(attempt, settings_id="e" * 64)),
                        library.receipt(attempt, "CONFIGURED", at=AT,
                                        configuration={"settings_id": DIGEST, "version": 1}),
                        {"version": 1, "outcome": "DURABLY_QUEUED", "body": "leak"}):
            with self.subTest(receipt=str(receipt)[:40]):
                with self.assertRaises(LibraryError) as refused:
                    self.records.finish(attempt, receipt)
                self.assertIn(refused.exception.code, {"INVALID_RECEIPT", "INVALID_CONTRACT",
                                                        "RECORD_INVALID", "UNKNOWN_FIELD"})
        self.assertEqual("PENDING", self.records.record(
            attempt.operation_id, project_identity=attempt.scope.project_identity)["state"])


class ScopeIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "library-records.sqlite3"
        self.records = LibraryRecords(self.path, "deployment-1")
        self.addCleanup(self.records.close)

    def test_drain_history_serves_report_replay_without_claiming_delivery(self):
        attempt = human_reject()
        self.records.begin(attempt)
        identity = attempt.scope.project_identity
        pending = self.records.drain(attempt.drain_id, project_identity=identity)
        self.assertEqual([attempt.operation_id], [item["operation_id"] for item in pending])
        self.assertEqual(["PENDING"], [item["state"] for item in pending])
        terminal = self.records.finish(attempt, library.receipt(
            attempt, "COMMITTED", at=AT,
            publication={"commit_sha": "f" * 40, "path": "projects/x/pending/b.md"}))
        self.assertEqual(terminal, self.records.drain(attempt.drain_id,
                                                      project_identity=identity)[0])
        self.assertEqual([], self.records.drain(
            attempt.drain_id, project_identity=binding("beta", "acme/beta", "1002")
            ["project_identity"]))
        self.assertEqual([], self.records.drain("drain-unknown", project_identity=identity))

    def test_two_projects_and_origins_stay_separate(self):
        alpha = capture(payload=CONTENT)
        beta = capture(origin=OTHER, target=binding("beta", "acme/beta", "1002"),
                       operation_id="op-beta", request_id="request-beta",
                       payload=value(title="beta " + TITLE_MARKER, body="beta " + BODY_MARKER))
        for attempt in (alpha, beta):
            self.records.begin(attempt)
            self.records.finish(attempt, durable(attempt))
        alpha_id, beta_id = alpha.scope.project_identity, beta.scope.project_identity
        self.assertNotEqual(alpha_id, beta_id)
        self.assertNotEqual(alpha.queue_id, beta.queue_id)
        for attempt, own, foreign in ((alpha, alpha_id, beta_id), (beta, beta_id, alpha_id)):
            self.assertIsNotNone(self.records.record(attempt.operation_id, project_identity=own))
            self.assertIsNone(self.records.record(attempt.operation_id, project_identity=foreign))
            self.assertIsNone(self.records.submission(foreign, attempt.request_id))
            self.assertEqual(attempt.digest(),
                             self.records.submission(own, attempt.request_id)["attempts"][0]
                             ["payload_sha256"])
        self.assertEqual([], [item for item in self.records.pending() if item["state"] != "PENDING"])
        self.assertEqual([], self.records.pending(project_identity=beta_id))
    def test_submission_provenance_is_immutable_while_attempts_record_actual_actor(self):
        original = capture()
        retry = library.retry(library.participant_scope(OTHER, binding=binding()), settings(),
                              original, operation_id="op-2", at="2026-10-28T23:00:00+00:00")
        for attempt in (original, retry):
            self.records.begin(attempt)
        recorded = [self.records.finish(attempt, durable(attempt)) for attempt in (original, retry)]
        self.assertEqual(original.queue_id, retry.queue_id)
        submission = self.records.submission(original.scope.project_identity, original.request_id)
        self.assertEqual(ORIGIN.actor_id, submission["origin"]["actor_id"])
        self.assertEqual(AT, submission["origin"]["at"])
        self.assertEqual(original.digest(), submission["origin"]["payload_sha256"])
        self.assertEqual([original.operation_id, retry.operation_id],
                         [item["operation_id"] for item in submission["attempts"]])
        self.assertEqual([ORIGIN.actor_id, OTHER.actor_id],
                         [item["origin"]["actor_id"] for item in submission["attempts"]])
        self.assertEqual(["DURABLY_QUEUED"] * 2, [item["receipt"]["outcome"] for item in recorded])
        self.assertEqual([ORIGIN.participant_id, OTHER.participant_id],
                         [item["origin"]["participant_id"] for item in submission["attempts"]])


class InstallationScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.records = LibraryRecords(Path(self.temp.name) / "records.sqlite3", "deployment-1")
        self.addCleanup(self.records.close)

    def test_installation_settings_record_holds_no_project_scope(self):
        operator = library.installation_scope(Origin("operator-a", "operator-a", "inc-op",
                                                     "epoch-op", ("library-settings",)))
        changed = document()
        changed["limits"]["result_count"] = 4
        attempt = library.settings_change(operator, settings(), operation_id="settings-1",
                                          request_id="settings-request-1",
                                          document=io.StringIO(json.dumps(changed)), at=AT)
        self.assertEqual("PENDING", self.records.begin(attempt)["state"])
        self.assertEqual([attempt.operation_id], [
            item["operation_id"] for item in self.records.pending()])
        self.assertIsNone(self.records.submission(None, attempt.request_id))
        self.assertEqual([], self.records.pending(project_identity=binding()["project_identity"]))
        terminal = self.records.finish(attempt, library.receipt(
            attempt, "CONFIGURED", at=AT,
            configuration={"settings_id": attempt.payload["next_settings_id"], "version": 2}))
        self.assertEqual(terminal, self.records.record(attempt.operation_id,
                                                       project_identity=None))
        self.assertIsNone(terminal["project_id"])
        self.assertIsNone(terminal["project_identity"])
        self.assertEqual("operator", terminal["origin"]["subject"])
        self.assertEqual([], self.records.pending())
        self.assertIsNone(self.records.record(attempt.operation_id,
                                              project_identity=binding()["project_identity"]))


class UncertaintyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "library-records.sqlite3"
        self.records = LibraryRecords(self.path, "deployment-1")
        self.addCleanup(self.records.close)

    def reopen(self):
        self.records.close()
        self.records = LibraryRecords(self.path, "deployment-1")
        self.addCleanup(self.records.close)
        return self.records

    def test_pending_intent_never_claims_publication(self):
        attempt = capture()
        record = self.records.begin(attempt)["record"]
        self.assertEqual("PENDING", record["state"])
        self.assertIsNone(record["receipt"])
        self.assertNotIn("publication", record)
        pending = self.reopen().pending(project_identity=attempt.scope.project_identity)
        self.assertEqual([attempt.operation_id], [item["operation_id"] for item in pending])
        self.assertEqual([None], [item["receipt"] for item in pending])

    def test_transient_lock_failure_leaves_the_instance_usable(self):
        attempt = capture()
        other = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(other.close)
        other.execute("BEGIN IMMEDIATE")
        self.records._db.execute("PRAGMA busy_timeout=0")
        with self.assertRaises(LibraryError) as busy:
            self.records.begin(attempt)
        self.assertEqual("RECORD_UNAVAILABLE", busy.exception.code)
        self.assertEqual([], self.records.pending())
        other.rollback()
        self.assertEqual("PENDING", self.records.begin(attempt)["state"])

    def test_corrupted_submission_is_a_typed_refusal(self):
        attempt = capture()
        self.records.begin(attempt)
        for value in ('{"broken', '{"actor_id":"actor-z"}'):
            with self.subTest(value=value):
                self.records._db.execute("UPDATE submissions SET origin=?", (value,))
                with self.assertRaises(LibraryError) as corrupt:
                    self.records.submission(attempt.scope.project_identity, attempt.request_id)
                self.assertEqual("RECORD_INVALID", corrupt.exception.code)
        self.assertEqual("PENDING", self.records.record(
            attempt.operation_id, project_identity=attempt.scope.project_identity)["state"])

    def test_uncertain_commit_reconciles_by_repeating_the_identity(self):
        attempt = capture()
        commit = self.records._commit

        def lost_acknowledgement():
            commit()
            raise LibraryError("RECORD_UNCERTAIN")

        self.records._commit = lost_acknowledgement
        with self.assertRaises(LibraryError) as uncertain:
            self.records.begin(attempt)
        self.assertEqual("RECORD_UNCERTAIN", uncertain.exception.code)
        reopened = self.reopen()
        stored = reopened.record(attempt.operation_id,
                                 project_identity=attempt.scope.project_identity)
        self.assertEqual("PENDING", stored["state"])
        self.assertEqual(stored, reopened.begin(attempt)["record"])
        self.assertEqual(1, len(reopened.submission(attempt.scope.project_identity,
                                                    attempt.request_id)["attempts"]))
        self.assertEqual("RECORDED", reopened.finish(attempt, durable(attempt))["state"])
        self.assertEqual(1, len(self.records.submission(attempt.scope.project_identity,
                                                        attempt.request_id)["attempts"]))

    def test_uncommitted_storage_failure_creates_no_record(self):
        attempt = capture()

        def failed_commit():
            raise sqlite3.OperationalError("disk I/O error")

        self.records._commit = failed_commit
        with self.assertRaises(LibraryError) as failed:
            self.records.begin(attempt)
        self.assertEqual("RECORD_UNCERTAIN", failed.exception.code)
        self.assertIsInstance(failed.exception.__cause__, sqlite3.Error)
        reopened = self.reopen()
        self.assertIsNone(reopened.record(attempt.operation_id,
                                          project_identity=attempt.scope.project_identity))
        self.assertIsNone(reopened.submission(attempt.scope.project_identity, attempt.request_id))
        self.assertEqual("PENDING", reopened.begin(attempt)["state"])

    def test_real_full_storage_fails_safely_without_erasing_evidence(self):
        recorded = capture()
        self.records.begin(recorded)
        terminal = self.records.finish(recorded, durable(recorded))
        pages = self.records._db.execute("PRAGMA page_count").fetchone()[0]
        self.records._db.execute(f"PRAGMA max_page_count={pages}")
        code, cause = None, None
        for index in range(4096):
            try:
                self.records.begin(capture(operation_id=f"fill-{index}",
                                           request_id=f"fill-request-{index}",
                                           payload=value(title="fill", body="x" * 16000)))
            except LibraryError as error:
                code, cause = error.code, error.__cause__
                break
        self.assertEqual("RECORD_UNCERTAIN", code)
        self.assertEqual(sqlite3.SQLITE_FULL, cause.sqlite_errorcode)
        reopened = self.reopen()
        self.assertEqual(terminal, reopened.record(recorded.operation_id,
                                                   project_identity=recorded.scope.project_identity))
        fresh = capture(operation_id="after-full", request_id="after-full-request")
        self.assertEqual("PENDING", reopened.begin(fresh)["state"])

    def test_unavailable_storage_is_not_a_recording_claim(self):
        with self.assertRaises(LibraryError) as missing:
            LibraryRecords(Path(self.temp.name) / "absent" / "records.sqlite3", "deployment-1")
        self.assertEqual("RECORD_UNAVAILABLE", missing.exception.code)
        directory = Path(self.temp.name) / "locked"
        directory.mkdir()
        locked = LibraryRecords(directory / "records.sqlite3", "deployment-1")
        attempt = capture()
        locked.begin(attempt)
        terminal = locked.finish(attempt, durable(attempt))
        locked.close()
        os.chmod(directory, 0o500)
        self.addCleanup(os.chmod, directory, 0o700)
        with self.assertRaises(LibraryError) as denied:
            LibraryRecords(directory / "records.sqlite3", "deployment-1")
        self.assertEqual("RECORD_UNAVAILABLE", denied.exception.code)
        os.chmod(directory, 0o700)
        with LibraryRecords(directory / "records.sqlite3", "deployment-1") as reopened:
            self.assertEqual(terminal, reopened.record(
                attempt.operation_id, project_identity=attempt.scope.project_identity))

    def test_pending_capacity_refuses_new_intents_without_erasing_evidence(self):
        for index in range(MAX_PENDING):
            self.records.begin(capture(operation_id=f"op-{index}",
                                       request_id=f"request-{index}"))
        self.assertEqual(MAX_PENDING, len(self.records.pending()))
        with self.assertRaises(LibraryError) as full:
            self.records.begin(capture(operation_id="overflow", request_id="overflow-request"))
        self.assertEqual("RECORD_CAPACITY", full.exception.code)
        self.assertEqual(MAX_PENDING, len(self.reopen().pending()))
        first = self.records.pending()[0]
        first_operation = capture(operation_id=first["operation_id"],
                                  request_id=first["request_id"])
        self.records.finish(first_operation, durable(first_operation))
        self.assertEqual("PENDING", self.records.begin(
            capture(operation_id="overflow", request_id="overflow-request"))["state"])


class ContentIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "library-records.sqlite3"
        self.records = LibraryRecords(self.path, "deployment-1")
        self.addCleanup(self.records.close)

    def test_no_content_reaches_the_store_or_any_surface(self):
        attempt = capture(payload=CONTENT)
        self.records.begin(attempt)
        terminal = self.records.finish(attempt, durable(attempt))
        adjudication = library.action(
            library.human_scope(session(("library-adjudicate",)), binding=binding(),
                                kind="adjudicate"), settings(), kind="adjudicate",
            operation_id="adjudicate-1", request_id="adjudicate-request-1",
            payload={"drain_id": "drain-1", "queue_id": DIGEST,
                     "conclusion": "Accepted " + TITLE_MARKER, "rationale": BODY_MARKER,
                     "observed_version": DIGEST}, at=AT)
        self.records.begin(adjudication)
        self.records.finish(adjudication, library.receipt(
            adjudication, "COMMITTED", at=AT,
            publication={"commit_sha": "e" * 40, "path": "projects/x/decisions/a.md"}))
        surfaces = [
            terminal,
            self.records.record(attempt.operation_id,
                                project_identity=attempt.scope.project_identity),
            self.records.submission(attempt.scope.project_identity, attempt.request_id),
            self.records.pending(),
            self.records.record(adjudication.operation_id,
                                project_identity=adjudication.scope.project_identity),
        ]
        for surface in surfaces:
            self.assertEqual([], bodies(json.dumps(surface, sort_keys=True)))
        errors = []
        with self.assertRaises(LibraryError) as refused:
            self.records.begin(capture(payload=value(title="Other " + TITLE_MARKER,
                                                     body="Other " + BODY_MARKER + "\n")))
        errors.append(refused.exception)
        with self.assertRaises(LibraryError) as rewritten:
            self.records.finish(attempt, library.receipt(attempt, "REJECTED", at=AT,
                                                         reason="RULE_REFUSED"))
        errors.append(rewritten.exception)
        for error in errors:
            self.assertEqual([], bodies(repr(error) + str(error)))
        self.assertEqual(["ID_CONFLICT", "ID_CONFLICT"], [error.code for error in errors])
        self.records.close()
        stored = b"".join(path.read_bytes() for path in sorted(self.path.parent.glob("*.sqlite3*")))
        self.assertGreater(len(stored), 0)
        self.assertEqual([], bodies(stored.decode("utf-8", "replace")))


class ConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "library-records.sqlite3"
        LibraryRecords(self.path, "deployment-1").close()

    def run_workers(self, operations):
        results, barrier = [], threading.Barrier(len(operations))

        def worker(item):
            barrier.wait()
            with LibraryRecords(self.path, "deployment-1") as records:
                try:
                    results.append(("record", records.begin(item)["record"]))
                except LibraryError as error:
                    results.append(("error", error.code))

        threads = [threading.Thread(target=worker, args=(item,)) for item in operations]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        self.assertFalse([thread for thread in threads if thread.is_alive()])
        return results

    def test_concurrent_exact_duplicates_record_one_attempt(self):
        attempt = capture()
        results = self.run_workers([attempt] * 6)
        self.assertEqual(["record"] * 6, [kind for kind, _ in results])
        self.assertEqual(1, len({json.dumps(item, sort_keys=True) for _, item in results}))
        with LibraryRecords(self.path, "deployment-1") as records:
            self.assertEqual(1, len(records.submission(attempt.scope.project_identity,
                                                       attempt.request_id)["attempts"]))

    def test_concurrent_conflicting_reuse_records_one_identity(self):
        original = capture()
        conflicting = replace(capture(payload=value(title="Rival", body="Rival body\n")),
                              operation_id=original.operation_id)
        results = self.run_workers([original, conflicting, original, conflicting])
        outcomes = sorted(kind for kind, _ in results)
        self.assertEqual(["error", "error", "record", "record"], outcomes)
        self.assertEqual(["ID_CONFLICT", "ID_CONFLICT"],
                         sorted(value for kind, value in results if kind == "error"))
        with LibraryRecords(self.path, "deployment-1") as records:
            stored = records.record(original.operation_id,
                                    project_identity=original.scope.project_identity)
            self.assertIn(stored["payload_sha256"],
                          {original.digest(), conflicting.digest()})
            self.assertEqual(1, len(records.submission(original.scope.project_identity,
                                                       original.request_id)["attempts"]))


class RestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "library-records.sqlite3"
        LibraryRecords(self.path, "deployment-1").close()

    def worker(self, mode):
        return subprocess.run([sys.executable, str(WORKER), str(self.path), mode],
                              capture_output=True, text=True, timeout=60)

    def test_process_death_after_intent_leaves_a_recoverable_record(self):
        killed = self.worker("after")
        self.assertEqual(-signal.SIGKILL, killed.returncode, killed.stderr)
        self.assertEqual({"state": "PENDING"}, json.loads(killed.stdout))
        attempt = operation()
        with LibraryRecords(self.path, "deployment-1") as records:
            pending = records.pending(project_identity=attempt.scope.project_identity)
            self.assertEqual([attempt.operation_id], [item["operation_id"] for item in pending])
            self.assertEqual("PENDING", pending[0]["state"])
            recovered = records.finish(attempt, durable(attempt))
            self.assertEqual("RECORDED", recovered["state"])
            self.assertEqual([], records.pending())
        with LibraryRecords(self.path, "deployment-1") as records:
            self.assertEqual(recovered, records.record(
                attempt.operation_id, project_identity=attempt.scope.project_identity))
            self.assertEqual(1, len(records.submission(attempt.scope.project_identity,
                                                       attempt.request_id)["attempts"]))

    def test_process_death_during_intent_commit_records_nothing(self):
        killed = self.worker("during")
        self.assertEqual(-signal.SIGKILL, killed.returncode, killed.stderr)
        attempt = operation()
        with LibraryRecords(self.path, "deployment-1") as records:
            self.assertIsNone(records.record(attempt.operation_id,
                                             project_identity=attempt.scope.project_identity))
            self.assertEqual([], records.pending())
            self.assertEqual("PENDING", records.begin(attempt)["state"])
            self.assertEqual([attempt.operation_id], [
                item["operation_id"] for item in records.pending(
                    project_identity=attempt.scope.project_identity)])


class SignatureTests(unittest.TestCase):
    def test_store_schema_and_deployment_identity_are_exact(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "records.sqlite3"
            LibraryRecords(path, "deployment-1").close()
            with self.assertRaises(LibraryError) as mismatch:
                LibraryRecords(path, "deployment-2")
            self.assertEqual("DEPLOYMENT_MISMATCH", mismatch.exception.code)
            with LibraryRecords(path, "deployment-1") as records:
                self.assertEqual([], records.pending())
            with self.assertRaises(LibraryError) as memory:
                LibraryRecords(":memory:", "deployment-1")
            self.assertEqual("INVALID_STORE", memory.exception.code)


if __name__ == "__main__":
    unittest.main()
