"""Per-Project Library operational records; metadata only, no Library content.

Canonical Git owns Library content. This external store owns the safe
operational evidence the specification requires: bounded operation identity,
Project and authenticated origin, canonical payload digest/size, operation-start
configuration identity, each attempt's actual actor/time/Command, and safe
outcome/revision references. Titles, bodies, prompts, model output, matched
secrets and human conclusions never enter it.

One intent commits before an operation acts; one terminal receipt commits
before the Service acknowledges it. An intent without a terminal is explicitly
pending: it records that no outcome was durably captured, so it can never be
read as canonical publication success or absence. Later Git reconciliation,
scheduler recovery and report replay consume these records. Recovery and deduplication identity never expires. Configured retention compacts
settled detail into durable tombstones; required evidence is capacity-fenced.

Attempt equality follows the supplied ``Operation.canonical()`` contract, so
an exact retry reconciles while a reused Command ID or a changed request in the
same Project or installation scope is refused for every operation kind.
"""
from datetime import datetime, timezone, timedelta
from .library import receipt as library_receipt
from contextlib import contextmanager
import fcntl
import os
import time
import stat
from . import library_deadline
import json
from pathlib import Path
import re
import sqlite3

from .library import LibraryError, LibraryScope, Operation, admit_receipt, audit_metadata, synthesis_manifest, batch_manifest, operation_manifest, _digest as value_digest


RECORD_VERSION = 1
MAX_PENDING = 256
MAX_ATTEMPTS = 256
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT_KEYS = ("record_version", "kind", "operation_id", "request_id", "queue_id",
                 "drain_id", "settings_id", "at", "payload_sha256", "payload_bytes",
                 "scope", "provenance", "project_path")
# Mutable bundle coordinates stay descriptive; the supplied Operation.canonical
# contract excludes them so a rename does not break exact-retry reconciliation.
_COORDINATES = ("project_path",)

# An outcome a Producer cannot reach for this kind is refused, so a record
# cannot claim a publication its operation does not make.
_KIND_OUTCOMES = {
    "enqueue": {"DURABLY_QUEUED", "REJECTED", "NOT_DURABLE"},
    "settings-update": {"CONFIGURED", "REJECTED", "NOT_DURABLE"},
}

_SCHEMA = {
    "deployment": "CREATE TABLE deployment (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, id TEXT NOT NULL)",
    "submissions": "CREATE TABLE submissions (scope_key TEXT NOT NULL, request_id TEXT NOT NULL, identity TEXT NOT NULL, origin TEXT NOT NULL, submitted_at TEXT NOT NULL, PRIMARY KEY(scope_key, request_id))",
    "attempts": "CREATE TABLE attempts (operation_id TEXT PRIMARY KEY, project_identity TEXT, request_id TEXT NOT NULL, queue_id TEXT, drain_id TEXT, identity TEXT NOT NULL, started_at TEXT NOT NULL, receipt TEXT, finished_at TEXT)",
}
_OLD_SCHEMA = dict(_SCHEMA)
_SCHEMA["retention"] = "CREATE TABLE retention (singleton INTEGER PRIMARY KEY CHECK(singleton=1), retention_days INTEGER NOT NULL, max_bytes INTEGER NOT NULL)"
_INDEXES = {
    "attempt_request_idx": "CREATE INDEX attempt_request_idx ON attempts(project_identity, request_id)",
    "attempt_queue_idx": "CREATE INDEX attempt_queue_idx ON attempts(queue_id)",
    "attempt_drain_idx": "CREATE INDEX attempt_drain_idx ON attempts(drain_id)",
    "attempt_pending_idx": "CREATE INDEX attempt_pending_idx ON attempts(receipt, started_at)",
}
_SUBMISSION_ORIGIN = {"actor_id", "participant_id", "subject", "at", "request_id",
                      "payload_sha256"}
_SUBMISSION_IDENTITY = {"record_version", "kind", "queue_id", "payload_sha256"}


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise LibraryError("INVALID_RECORD") from error


def _safe(value, field):
    """Bounded trusted metadata; content keys and non-token keys are refused."""
    try:
        audit_metadata(value)
    except LibraryError as error:
        raise LibraryError("INVALID_RECORD", field) from error
    return value


def _token(value, field):
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise LibraryError("INVALID_RECORD", field)
    return value


def _timestamp(value):
    if type(value) is not str or len(value) > 64:
        raise LibraryError("INVALID_RECORD", "timestamp")
    try:
        if datetime.fromisoformat(value).tzinfo is None:
            raise ValueError()
    except ValueError as error:
        raise LibraryError("INVALID_RECORD", "timestamp") from error
    return value


def _digest(value, field):
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise LibraryError("INVALID_RECORD", field)
    return value


def _now():
    return datetime.now(timezone.utc).isoformat()


def _origin(scope):
    """The authenticated origin that actually authorized this attempt."""
    origin = {"subject": scope.subject, "actor_id": scope.actor_id,
              "authority_version": scope.authority_version,
              "capabilities": sorted(scope.capabilities),
              "participant_id": scope.participant_id, "human_id": scope.human_id}
    for key in ("subject", "actor_id", "authority_version"):
        _token(origin[key], key)
    for capability in origin["capabilities"]:
        _token(capability, "capabilities")
    for key in ("participant_id", "human_id"):
        if origin[key] is not None:
            _token(origin[key], key)
    return _safe(origin, "origin")


def _submission_origin(operation):
    """Immutable first-submission provenance supplied by the contract seam."""
    origin = dict(operation.provenance)
    if set(origin) not in (_SUBMISSION_ORIGIN, _SUBMISSION_ORIGIN | {"run_id"}):
        raise LibraryError("INVALID_RECORD", "provenance")
    for key in ("actor_id", "participant_id", "subject", "request_id"):
        if origin[key] is not None or key != "participant_id":
            _token(origin[key], "provenance." + key)
    if "run_id" in origin:
        _token(origin["run_id"], "provenance.run_id")
    _timestamp(origin["at"])
    _digest(origin["payload_sha256"], "provenance.payload_sha256")
    if origin["request_id"] != operation.request_id:
        raise LibraryError("INVALID_RECORD", "provenance.request_id")
    if origin["payload_sha256"] != operation.digest():
        raise LibraryError("INVALID_RECORD", "provenance.payload_sha256")
    return _safe(origin, "provenance")


def _scope_key(scope):
    """One Project or the installation scope; never a caller path."""
    return scope.project_identity or ""


def _identity(operation):
    """One attempt's bounded identity; payload content stays outside it.

    The equality value is the supplied ``Operation.canonical()`` contract: the
    attempt time, payload digest, authenticated scope and immutable submission
    provenance decide identity, while mutable bundle coordinates are recorded
    descriptively so a repository rename does not change it.
    """
    payload = _canonical(operation.payload)
    try:
        size = len(payload.encode("utf-8"))
    except UnicodeError as error:
        raise LibraryError("INVALID_RECORD", "payload") from error
    scope = operation.scope.canonical()
    project_path = scope.pop("project_path")
    identity = {
        "record_version": RECORD_VERSION, "kind": operation.kind,
        "operation_id": operation.operation_id, "request_id": operation.request_id,
        "queue_id": operation.queue_id, "drain_id": operation.drain_id,
        "settings_id": operation.settings_id, "at": operation.at,
        "payload_sha256": operation.digest(), "payload_bytes": size,
        "scope": scope, "provenance": _submission_origin(operation),
        "project_path": project_path,
    }
    for key in ("kind", "operation_id", "request_id", "settings_id"):
        _token(identity[key], key)
    if identity["queue_id"] is not None:
        _digest(identity["queue_id"], "queue_id")
    if identity["drain_id"] is not None:
        _token(identity["drain_id"], "drain_id")
    if project_path is not None:
        _token(project_path, "project_path")
    _timestamp(identity["at"])
    if (identity["kind"] == "enqueue") != (identity["queue_id"] is not None):
        raise LibraryError("INVALID_RECORD", "queue_id")
    _origin(operation.scope)  # validate the authenticated origin fields
    _safe(identity, "identity")
    if operation.manifest is not None:
        if operation.kind not in ("synthesis-attempt", "synthesis-batch", "scheduler-state", "source-park", "library-observation"):
            raise LibraryError("INVALID_RECORD", "manifest")
        identity["manifest"] = operation_manifest(operation.kind, operation.manifest)
        expected = identity["manifest"] if operation.kind in ("synthesis-batch", "source-park") else {"manifest_sha256": value_digest(identity["manifest"])}
        if operation.payload != expected: raise LibraryError("INVALID_RECORD", "manifest")
    return identity


def _submission(identity):
    """Request-level deduplication identity: kind, queue and canonical digest."""
    return {"record_version": RECORD_VERSION, "kind": identity["kind"],
            "queue_id": identity["queue_id"],
            "payload_sha256": identity["payload_sha256"]}


class LibraryRecords:
    """One Deployment's metadata-only Library operation journal.

    ``begin`` returns only after its intent is durable, and ``finish`` only
    after the terminal receipt is durable. A storage failure during a write
    raises ``RECORD_UNCERTAIN``: the commit state is unknown until a fresh
    instance reopens the store and reads the same identity. Repeating that
    identity then returns the committed record instead of a second operation.
    """

    def __init__(self, path, deployment_id):
        self.deployment_id = _token(deployment_id, "deployment_id")
        self._db = None
        self._failed = False
        self.path = Path(path)
        try:
            path = Path(path)
            if str(path) == ":memory:":
                raise LibraryError("INVALID_STORE")
            self._db = sqlite3.connect(path, timeout=library_deadline.remaining(5), isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA synchronous=FULL")
            if self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise LibraryError("INVALID_STORE")
            self._db.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in self._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                for statement in _SCHEMA.values():
                    self._db.execute(statement)
                for statement in _INDEXES.values():
                    self._db.execute(statement)
                self._db.execute("INSERT INTO deployment VALUES(1, ?, ?)",
                                 (RECORD_VERSION, self.deployment_id))
            # Exact legacy schema only; reject unrelated databases before migration.
            objects = {r["name"]: r["sql"] for r in self._db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if objects == _OLD_SCHEMA:
                self._db.execute(_SCHEMA["retention"])
            self._schema()
            self._db.commit()
        except (sqlite3.Error, OSError) as error:
            self.close()
            raise LibraryError("RECORD_UNAVAILABLE") from error
        except BaseException:
            self.close()
            raise

    def _schema(self):
        # Refuse an arbitrary database with merely familiar table names.
        objects = self._db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        tables = {row["name"]: row["sql"] for row in objects if row["type"] == "table"}
        indexes = {row["name"]: row["sql"] for row in objects if row["type"] == "index"}
        if (tables != _SCHEMA or indexes != _INDEXES
                or any(row["type"] not in {"table", "index"} for row in objects)
                or self._db.execute("PRAGMA foreign_key_check").fetchone() is not None):
            raise LibraryError("INVALID_STORE")
        row = self._db.execute("SELECT version,id FROM deployment WHERE singleton=1").fetchone()
        if row is None or row["version"] != RECORD_VERSION:
            raise LibraryError("UNSUPPORTED_STORE_VERSION")
        if row["id"] != self.deployment_id:
            raise LibraryError("DEPLOYMENT_MISMATCH")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None

    def _connection(self):
        if self._failed:
            raise LibraryError("RECORD_UNCERTAIN")
        if self._db is None:
            raise LibraryError("RECORD_UNAVAILABLE")
        return self._db

    def _commit(self):
        # Narrow storage boundary; tests replace this to model a lost commit.
        self._connection().commit()

    @contextmanager
    def _writer(self):
        # Bound lock waits, scanning and SQLite maintenance by the current
        # operation deadline, with a finite storage-local ceiling as well.
        fd = None
        db = self._connection()
        with library_deadline.bounded(5):
            def progress():
                try: library_deadline.remaining(5)
                except LibraryError: return 1
                return 0
            try:
                fd = os.open(str(self.path) + ".writer", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                node = os.fstat(fd)
                if (not stat.S_ISREG(node.st_mode) or node.st_nlink != 1
                        or node.st_uid != os.geteuid() or node.st_mode & 0o077):
                    raise LibraryError("INVALID_STORE", "writer")
                while True:
                    library_deadline.remaining(5)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        time.sleep(0.01)
                db.execute('PRAGMA busy_timeout=' + str(max(1,int(library_deadline.remaining(5)*1000))))
                db.set_progress_handler(progress, 1000)
                yield
            except OSError as error:
                raise LibraryError("RECORD_UNAVAILABLE", "writer") from error
            except sqlite3.Error as error:
                self._failed = True
                try: db.rollback()
                except sqlite3.Error: pass
                raise LibraryError("RECORD_UNCERTAIN", "maintenance") from error
            finally:
                db.set_progress_handler(None, 0)
                if fd is not None: os.close(fd)

    def _policy(self, db):
        row = db.execute("SELECT retention_days,max_bytes FROM retention WHERE singleton=1").fetchone()
        return dict(row) if row else None

    def _page_limit(self, policy):
        # Reserve main + VACUUM temporary copy + full WAL frames (24-byte
        # headers), shm and header/locking overhead together.
        page = self._connection().execute("PRAGMA page_size").fetchone()[0]
        return max(0, (policy["max_bytes"] - 32768 - 4096) // (3 * page + 24))

    def _write(self, work):
        with self._writer():
            return self._write_locked(work)

    def _write_locked(self, work, *, enforce=True, reclaim=True):
        db = self._connection()
        policy = self._policy(db) if enforce else None
        if policy:
            checkpoint = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint[0] or checkpoint[1] != checkpoint[2]:
                raise LibraryError("RECORD_CAPACITY", "checkpoint")
            limit = self._page_limit(policy)
            used = db.execute("PRAGMA page_count").fetchone()[0] - db.execute("PRAGMA freelist_count").fetchone()[0]
            if limit < used: raise LibraryError("RECORD_CAPACITY", "required_state")
            db.execute("PRAGMA max_page_count=" + str(max(1, limit)))
        try:
            db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            # Nothing was attempted, so this instance stays usable.
            raise LibraryError("RECORD_UNAVAILABLE") from error
        try:
            result = work(db)
            if policy:
                self._compact_work(db, policy, datetime.now(timezone.utc))
                if db.execute("PRAGMA page_count").fetchone()[0] > self._page_limit(policy):
                    raise LibraryError("RECORD_CAPACITY", "required_state")
            self._commit()
            return result
        except sqlite3.Error as error:
            if policy and getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                db.rollback()
                # SQLITE_FULL rolls back before any acknowledgement. Compact only
                # settled detail once, then retry this metadata-only transaction.
                if policy and reclaim:
                    expired = self._write_locked(lambda connection: self._compact_work(
                        connection, policy, datetime.now(timezone.utc), pressure=True), enforce=False)
                    if expired:
                        self._vacuum(db)
                        return self._write_locked(work, reclaim=False)
                raise LibraryError("RECORD_CAPACITY", "required_state") from error
            self._failed = True
            try:
                db.rollback()
            except sqlite3.Error:
                pass
            raise LibraryError("RECORD_UNCERTAIN") from error
        except BaseException:
            db.rollback()
            raise

    def _read(self, work):
        db = self._connection()
        try:
            db.execute("BEGIN")
            result = work(db)
            db.rollback()
            return result
        except sqlite3.Error as error:
            db.rollback()
            raise LibraryError("RECORD_UNAVAILABLE") from error
        except BaseException:
            db.rollback()
            raise

    # --- reads -----------------------------------------------------------

    def _attempt(self, db, operation_id):
        row = db.execute("SELECT identity,started_at,receipt,finished_at FROM attempts "
                         "WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return None
        try:
            identity = json.loads(row["identity"])
            receipt = None if row["receipt"] is None else admit_receipt(json.loads(row["receipt"]))
            if (type(identity) is not dict or row["identity"] != _canonical(identity)
                    or identity.get("operation_id") != operation_id
                    or ("_expired" not in identity and _canonical(_identity_like(identity)) != row["identity"])):
                raise ValueError()
            if receipt is not None and (row["receipt"] != _canonical(receipt)
                                        or receipt["operation_id"] != operation_id):
                raise ValueError()
            if "_expired" in identity:
                self._tombstone(identity, receipt)
            _timestamp(row["started_at"])
            if row["finished_at"] is not None:
                _timestamp(row["finished_at"])
            if (receipt is None) != (row["finished_at"] is None):
                raise ValueError()
        except LibraryError as error:
            raise LibraryError("RECORD_INVALID") from error
        except (ValueError, TypeError, KeyError, RecursionError) as error:
            raise LibraryError("RECORD_INVALID") from error
        return {**identity, "record_version": RECORD_VERSION,
                "started_at": row["started_at"], "receipt": receipt,
                "finished_at": row["finished_at"],
                "state": "DETAIL_EXPIRED" if "_expired" in identity else "PENDING" if receipt is None else "RECORDED"}

    def record(self, operation_id, *, project_identity):
        """Exact Project-fenced read; nothing is disclosed across scopes."""
        _token(operation_id, "operation_id")
        if project_identity is not None:
            _token(project_identity, "project_identity")
        value = self._read(lambda db: self._attempt(db, operation_id))
        if value is None or value["scope"]["project_identity"] != project_identity:
            return None
        return value

    def submission(self, project_identity, request_id):
        """Immutable original submission plus its attempts, oldest first.

        Every operation kind is fenced by its Project or installation scope and
        request identity. Bounded: history past this owner's read limit needs
        operator action.
        """
        if project_identity is not None:
            _token(project_identity, "project_identity")
        _token(request_id, "request_id")
        scope_key = project_identity or ""

        def read(db):
            row = db.execute("SELECT identity,origin,submitted_at FROM submissions "
                             "WHERE scope_key=? AND request_id=?",
                             (scope_key, request_id)).fetchone()
            if row is None:
                return None
            try:
                origin, identity = json.loads(row["origin"]), json.loads(row["identity"])
                _timestamp(row["submitted_at"])
                if (row["origin"] != _canonical(origin)
                        or row["identity"] != _canonical(identity)
                        or set(origin) not in (_SUBMISSION_ORIGIN, _SUBMISSION_ORIGIN | {"run_id"})
                        or origin.get("request_id") != request_id
                        or set(identity) != _SUBMISSION_IDENTITY
                        or identity.get("payload_sha256") != origin.get("payload_sha256")):
                    raise ValueError()
            except LibraryError as error:
                raise LibraryError("RECORD_INVALID") from error
            except (ValueError, TypeError, KeyError, RecursionError) as error:
                raise LibraryError("RECORD_INVALID") from error
            attempts = db.execute("SELECT operation_id FROM attempts WHERE project_identity IS ? "
                                  "AND request_id=? ORDER BY started_at,operation_id LIMIT ?",
                                  (project_identity or None, request_id,
                                   MAX_ATTEMPTS + 1)).fetchall()
            if len(attempts) > MAX_ATTEMPTS:
                raise LibraryError("RECORD_CAPACITY")
            records = [self._attempt(db, item["operation_id"]) for item in attempts]
            return {"project_identity": project_identity, "request_id": request_id,
                    "origin": origin, "submitted_at": row["submitted_at"],
                    "attempts": records}

        return self._read(read)

    def drain(self, drain_id, *, project_identity=None):
        """Recorded attempts of one drain, in attempt-start order, for report replay.

        Bounded: history past this owner's read limit needs operator action.
        """
        _token(drain_id, "drain_id")
        if project_identity is not None:
            _token(project_identity, "project_identity")

        def read(db):
            statement = ("SELECT operation_id FROM attempts WHERE drain_id=?"
                         + (" AND project_identity IS ?" if project_identity is not None else "")
                         + " ORDER BY started_at,operation_id LIMIT ?")
            arguments = ((drain_id, project_identity) if project_identity is not None
                         else (drain_id,)) + (MAX_ATTEMPTS + 1,)
            rows = db.execute(statement, arguments).fetchall()
            if len(rows) > MAX_ATTEMPTS:
                raise LibraryError("RECORD_CAPACITY")
            return [self._attempt(db, row["operation_id"]) for row in rows]

        return self._read(read)

    def latest_schedule(self, project_identity):
        """Latest persisted transition, including a durable intent with lost receipt."""
        _token(project_identity, 'project_identity')
        def read(db):
            rows = db.execute("SELECT operation_id FROM attempts WHERE project_identity=? "
                "AND operation_id LIKE ? ORDER BY rowid DESC LIMIT 1", (project_identity, 'scheduler-' + value_digest(project_identity) + '-%')).fetchall()
            return self._attempt(db, rows[0]['operation_id']) if rows else None
        return self._read(read)

    def iter_drain(self, drain_id, *, project_identity):
        """Bounded pages without an arbitrary lifetime retry count ceiling."""
        _token(drain_id, 'drain_id'); _token(project_identity, 'project_identity')
        cursor = 0
        while True:
            def read(db):
                rows = db.execute("SELECT rowid,operation_id FROM attempts WHERE drain_id=? "
                    "AND project_identity=? AND rowid>? ORDER BY rowid LIMIT 64",
                    (drain_id, project_identity, cursor)).fetchall()
                return [(row['rowid'], self._attempt(db, row['operation_id'])) for row in rows]
            rows = self._read(read)
            if not rows: return
            for cursor, record in rows: yield record

    def iter_schedules(self, project_identity, *, after_sequence=0):
        """All durable transition sources in bounded pages, including lost ACKs."""
        _token(project_identity, 'project_identity')
        if type(after_sequence) is not int or after_sequence < 0: raise LibraryError('INVALID_RECORD')
        cursor = 0
        prefix = 'scheduler-' + value_digest(project_identity) + '-'
        while True:
            def read(db):
                rows = db.execute("SELECT rowid,operation_id FROM attempts WHERE project_identity=? "
                    "AND operation_id LIKE ? AND CAST(substr(operation_id,?) AS INTEGER)>? AND rowid>? ORDER BY rowid LIMIT 64",
                    (project_identity, prefix+'%', len(prefix)+1, after_sequence, cursor)).fetchall()
                return [(row['rowid'], self._attempt(db, row['operation_id'])) for row in rows]
            rows = self._read(read)
            if not rows: return
            for cursor, record in rows:
                if record["state"] != "DETAIL_EXPIRED": yield record

    def latest_observation(self, project_identity):
        _token(project_identity, 'project_identity')
        def read(db):
            row = db.execute("SELECT operation_id FROM attempts WHERE project_identity=? AND json_extract(identity, '$.kind')='library-observation' ORDER BY rowid DESC LIMIT 1",
                (project_identity,)).fetchone()
            return self._attempt(db, row['operation_id']) if row else None
        return self._read(read)

    def project_history(self, project_identity, *, limit):
        """Bounded owner metadata snapshot; truncation must remain explicit."""
        _token(project_identity, 'project_identity')
        if type(limit) is not int or not 1 <= limit <= 10000: raise LibraryError('INVALID_RECORD')
        def read(db):
            rows = db.execute("SELECT operation_id FROM attempts WHERE project_identity=? ORDER BY rowid DESC LIMIT ?",
                (project_identity, limit + 1)).fetchall()
            records = [self._attempt(db, row['operation_id']) for row in rows[:limit]]
            return records, len(rows) <= limit and not any(r["state"] == "DETAIL_EXPIRED" for r in records)
        return self._read(read)

    def iter_pending(self):
        """Startup inventory in bounded pages; outages do not impose a lifetime cap."""
        cursor = 0
        while True:
            def read(db):
                rows = db.execute("SELECT rowid,operation_id FROM attempts WHERE receipt IS NULL "
                    "AND rowid>? ORDER BY rowid LIMIT 64", (cursor,)).fetchall()
                return [(row['rowid'],self._attempt(db,row['operation_id'])) for row in rows]
            rows = self._read(read)
            if not rows: return
            for cursor, record in rows: yield record

    def pending(self, *, project_identity=None):
        """Bounded restart inventory: records whose terminal was never captured."""
        if project_identity is not None:
            _token(project_identity, "project_identity")

        def read(db):
            statement = ("SELECT operation_id FROM attempts WHERE receipt IS NULL"
                         + (" AND project_identity IS ?" if project_identity is not None else "")
                         + " ORDER BY started_at,operation_id LIMIT ?")
            arguments = ((project_identity,) if project_identity is not None else ()) + (MAX_PENDING + 1,)
            rows = db.execute(statement, arguments).fetchall()
            if len(rows) > MAX_PENDING:
                raise LibraryError("RECORD_CAPACITY")
            return [self._attempt(db, row["operation_id"]) for row in rows]

        return self._read(read)

    @staticmethod
    def _matches(prior, equality):
        if "_expired" in prior:
            return prior["_expired"]["identity_sha256"] == value_digest(json.loads(equality))
        return _canonical(_equality(_identity_like(prior))) == equality

    @staticmethod
    def _tombstone(identity, receipt):
        if set(identity) != set(_ATTEMPT_KEYS) | {"_expired"} or receipt is None:
            raise LibraryError("RECORD_INVALID")
        proof = identity["_expired"]
        if type(proof) is not dict or set(proof) != {"identity_sha256", "receipt_sha256"}:
            raise LibraryError("RECORD_INVALID")
        for value in proof.values(): _digest(value, "tombstone")
        if receipt.get("detail_expired") is not True: raise LibraryError("RECORD_INVALID")
        # Retain the original scoped identity/digest and outcome references.
        _safe({key: value for key, value in identity.items() if key != "_expired"}, "tombstone")
        _safe(proof, "tombstone")

    def configure_retention(self, audit):
        """Trusted Deployment audit config; persisted for every future handle.

        No defaults, independent retention policy, or caller payload authority.
        A too-small cap remains installed and safely blocks future writes.
        """
        if (type(audit) is not dict or set(audit) != {"retention_days", "max_bytes"}
                or any(type(v) is not int or not 1 <= v <= 2**53-1 for v in audit.values())):
            raise LibraryError("INVALID_RETENTION")
        with self._writer():
            self._write_locked(lambda db: db.execute("INSERT OR REPLACE INTO retention VALUES(1,?,?)",
                (audit["retention_days"], audit["max_bytes"])), enforce=False)
        return self.compact()

    def _protected(self, db):
        rows = db.execute("SELECT operation_id FROM attempts ORDER BY rowid").fetchall()
        records = []
        for row in rows:
            library_deadline.remaining(5)
            records.append(self._attempt(db, row[0]))
        protected = {r['operation_id'] for r in records if r['receipt'] is None
                     or r['receipt']['outcome'] in ('NOT_DURABLE','UNKNOWN')}
        latest = {}; active_drains = set()
        by_id = {r['operation_id']:r for r in records}
        for r in records:
            if r['state'] != 'DETAIL_EXPIRED' and r['kind'] in ('scheduler-state','library-observation'):
                latest[(r['scope']['project_identity'],r['kind'])] = r
        for r in latest.values():
            protected.add(r['operation_id'])
            if r['kind']=='scheduler-state' and r['manifest']['drain_id']:
                active_drains.add((r['scope']['project_identity'],r['manifest']['drain_id']))
        for r in records:
            if r['operation_id'] in protected and r['drain_id']:
                active_drains.add((r['scope']['project_identity'],r['drain_id']))
            transition = r.get('manifest',{}).get('transition')
            if r['kind']=='scheduler-state' and transition:
                ack = 'report-' + value_digest([r['scope']['project_identity'],transition['drain_id'],transition['sequence']])
                if ack not in by_id or by_id[ack]['receipt'] is None:
                    protected.add(r['operation_id'])
                    active_drains.add((r['scope']['project_identity'],transition['drain_id']))
        for r in records:
            if (r['scope']['project_identity'],r['drain_id']) in active_drains:
                protected.add(r['operation_id'])
        return records, protected

    def _compact_work(self, db, policy, now, *, pressure=False):
        records, protected = self._protected(db)
        cutoff = now - timedelta(days=min(policy['retention_days'], 365000))
        count = 0
        for record in records:
            library_deadline.remaining(5)
            if record['operation_id'] in protected or record['state']=='DETAIL_EXPIRED': continue
            if not pressure and datetime.fromisoformat(record['finished_at']) > cutoff: continue
            identity = _identity_like(record)
            proof = {'identity_sha256':value_digest(_equality(identity)),
                     'receipt_sha256':value_digest(record['receipt'])}
            identity.pop('manifest',None); identity['_expired']=proof
            receipt = dict(record['receipt']); receipt.pop('evidence',None)
            receipt['detail_expired'] = True
            if receipt['projection'] is not None: receipt['projection']={'commit_sha':None,'visible':False}
            admit_receipt(receipt)
            db.execute("UPDATE attempts SET identity=?,receipt=? WHERE operation_id=?",
                (_canonical(identity),_canonical(receipt),record['operation_id']))
            count += 1
        return count

    @staticmethod
    def _vacuum(db):
        if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:
            raise LibraryError('RECORD_CAPACITY', 'checkpoint')
        db.execute('VACUUM')
        if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:
            raise LibraryError('RECORD_CAPACITY', 'checkpoint')

    def compact(self, *, now=None):
        """Only settled operational detail. Atomic tombstones, then physical reclaim.

        Active reader/checkpoint or insufficient required-state capacity is a safe
        failure, never permission to delete dedupe/recovery data or Git history.
        """
        now = datetime.now(timezone.utc) if now is None else now
        if not isinstance(now,datetime) or now.tzinfo is None: raise LibraryError('INVALID_RETENTION')
        with self._writer():
            db=self._connection();policy=self._policy(db)
            if policy is None: raise LibraryError('RETENTION_NOT_CONFIGURED')
            count=self._write_locked(lambda connection:self._compact_work(connection,policy,now),enforce=False)
            if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:
                raise LibraryError('RECORD_CAPACITY','checkpoint')
            # VACUUM is crash-atomic SQLite maintenance; no second body store.
            self._vacuum(db)
            limit=self._page_limit(policy)
            if db.execute('PRAGMA page_count').fetchone()[0] > limit:
                count+=self._write_locked(lambda connection:self._compact_work(connection,policy,now,pressure=True),enforce=False)
                self._vacuum(db)
            if db.execute('PRAGMA page_count').fetchone()[0] > limit:
                raise LibraryError('RECORD_CAPACITY','required_state')
            return {'expired':count,'max_bytes':policy['max_bytes'],'details':'operational_only'}

    # --- writes ----------------------------------------------------------

    def begin(self, operation, *, exclusive=False):
        return self._write(self._begin_work(operation, exclusive=exclusive))

    def _begin_work(self, operation, *, exclusive=False):
        """Durably record one attempt intent; no acknowledgement before commit.

        An exact repeat returns the committed record unchanged. Reusing a
        Command ID for a different attempt, or a request ID for a different
        kind/digest, is refused for every operation kind instead of overwriting
        a receipt or admitting a changed request.
        """
        if type(operation) is not Operation or type(operation.scope) is not LibraryScope:
            raise LibraryError("INVALID_OPERATION", "operation")
        identity = _identity(operation)
        canonical = _canonical(identity)
        equality = _canonical(_equality(identity))
        submission = _canonical(_submission(identity))
        origin = identity["provenance"]
        scope = identity["scope"]

        def work(db):
            prior = self._attempt(db, operation.operation_id)
            if prior is not None:
                if not self._matches(prior, equality):
                    raise LibraryError("ID_CONFLICT", "operation_id")
                if exclusive:
                    raise LibraryError("ATTEMPT_ALREADY_RESERVED", "operation_id")
                return {"state": prior["state"], "record": prior}
            row = db.execute("SELECT identity FROM submissions WHERE scope_key=? "
                             "AND request_id=?",
                             (_scope_key(operation.scope), identity["request_id"])).fetchone()
            if row is not None:
                if row["identity"] != submission:
                    raise LibraryError("ID_CONFLICT", "request_id")
                expired = db.execute("SELECT operation_id FROM attempts WHERE project_identity IS ? AND request_id=? AND json_type(identity, '$._expired') IS NOT NULL LIMIT 1", (scope["project_identity"], identity["request_id"])).fetchone()
                if expired: raise LibraryError("DETAIL_EXPIRED", "request_id")
            else:
                # Only a retry may carry another actor's submission origin.
                if any(origin[key] != scope[key] for key in
                       ("actor_id", "participant_id", "subject")):
                    raise LibraryError("CALLER_AUTHORITY", "provenance.actor_id")
                db.execute("INSERT INTO submissions VALUES(?,?,?,?,?)",
                           (_scope_key(operation.scope), identity["request_id"],
                            submission, _canonical(origin), _now()))
            self._capacity(db)
            db.execute("INSERT INTO attempts(operation_id,project_identity,request_id,"
                       "queue_id,drain_id,identity,started_at) VALUES(?,?,?,?,?,?,?)",
                       (operation.operation_id, scope["project_identity"],
                        identity["request_id"], identity["queue_id"], identity["drain_id"],
                        canonical, _now()))
            return {"state": "PENDING", "record": self._attempt(db, operation.operation_id)}

        return work

    def _capacity(self, db):
        pending = db.execute("SELECT count(*) FROM attempts WHERE receipt IS NULL").fetchone()[0]
        if pending >= MAX_PENDING:
            raise LibraryError("RECORD_CAPACITY")

    def finish(self, operation, receipt):
        return self._write(self._finish_work(operation, receipt))

    def _finish_work(self, operation, receipt):
        """Durably record the terminal receipt before any acknowledgement.

        The receipt must describe this stored attempt. An exact repeat returns
        the committed record; a different value is a conflict, never a rewrite.
        """
        if type(operation) is not Operation or type(operation.scope) is not LibraryScope:
            raise LibraryError("INVALID_OPERATION", "operation")
        canonical_identity = _canonical(_equality(_identity(operation)))
        try:
            admitted = admit_receipt(dict(receipt))
        except LibraryError as error:
            raise LibraryError("INVALID_RECEIPT", "$") from error
        except (TypeError, ValueError) as error:
            raise LibraryError("INVALID_RECEIPT", "$") from error
        if (admitted["operation_id"] != operation.operation_id
                or admitted["kind"] != operation.kind
                or admitted["request_id"] != operation.request_id
                or admitted["queue_id"] != operation.queue_id
                or admitted["drain_id"] != operation.drain_id
                or admitted["settings_id"] != operation.settings_id):
            raise LibraryError("INVALID_RECEIPT", "identity")
        allowed = _KIND_OUTCOMES.get(operation.kind, {"COMMITTED", "ACKNOWLEDGED",
                                                      "REJECTED", "REFUSED", "BUSY",
                                                      "STALE", "UNKNOWN", "NOT_DURABLE"})
        if admitted["outcome"] not in allowed:
            raise LibraryError("INVALID_RECEIPT", "outcome")
        value = _canonical(admitted)

        def work(db):
            prior = self._attempt(db, operation.operation_id)
            if prior is None:
                raise LibraryError("RECORD_NOT_FOUND")
            if not self._matches(prior, canonical_identity):
                raise LibraryError("ID_CONFLICT", "operation_id")
            if prior["receipt"] is not None:
                if (prior.get("_expired", {}).get("receipt_sha256") != value_digest(admitted) if "_expired" in prior else _canonical(prior["receipt"]) != value):
                    raise LibraryError("ID_CONFLICT", "receipt")
                return prior
            db.execute("UPDATE attempts SET receipt=?,finished_at=? WHERE operation_id=?",
                       (value, _now(), operation.operation_id))
            return self._attempt(db, operation.operation_id)

        return work

    def inspection_identity(self, operation):
        """Atomically reserve only a read's identity; never its content/response.

        Exact retries compare even compacted identity, but callers must freshly
        authorize and read. The acknowledgement is not an inspection replay.
        """
        if operation.kind != 'inspect' or operation.scope.subject != 'human':
            raise LibraryError('INVALID_OPERATION')
        receipt = library_receipt(
            operation, 'ACKNOWLEDGED', at=operation.at,
            acknowledgement=operation.digest())
        begin = self._begin_work(operation)
        finish = self._finish_work(operation, receipt)
        def work(db):
            prior = begin(db)['record']
            if prior['receipt'] is not None: return
            finish(db)
        self._write(work)

    def schedule_control(self, operation, receipt, schedule, schedule_receipt):
        """One durable transaction for a human acknowledgement and schedule intent.

        No external action occurs inside it. A lost commit response is uncertain;
        a fresh Project-fenced receipt read reconciles the whole transition.
        """
        if (operation.kind not in ('drain','retry','resume') or operation.scope.subject != 'human'
                or schedule.kind != 'scheduler-state'
                or operation.scope.project_identity != schedule.scope.project_identity
                or receipt['outcome'] != 'ACKNOWLEDGED'
                or receipt['acknowledgement'] != value_digest(schedule.manifest)):
            raise LibraryError('INVALID_OPERATION')
        begin = self._begin_work(operation)
        begin_schedule = self._begin_work(schedule, exclusive=True)
        finish_schedule = self._finish_work(schedule, schedule_receipt)
        finish = self._finish_work(operation, receipt)
        def work(db):
            prior = begin(db)['record']
            if prior['receipt'] is not None:
                # Caller reconciles before choosing a new sequence; never repeat.
                raise LibraryError('CONTROL_ALREADY_RECORDED')
            begin_schedule(db); finish_schedule(db)
            return finish(db)
        return self._write(work)


def _identity_like(value):
    """Rebuild the stored identity from a record for tamper checking."""
    result = {key: value[key] for key in _ATTEMPT_KEYS}
    if "manifest" in value:
        if value["kind"] not in ("synthesis-attempt", "synthesis-batch", "scheduler-state", "source-park", "library-observation"): raise LibraryError("INVALID_RECORD")
        result["manifest"] = operation_manifest(value["kind"], value["manifest"])
        expected = result["manifest"] if value["kind"] in ("synthesis-batch", "source-park") else {"manifest_sha256": value_digest(result["manifest"])}
        if value["payload_sha256"] != value_digest(expected): raise LibraryError("INVALID_RECORD", "manifest")
    return result


def _equality(value):
    """The part of a stored identity that decides exact-retry equality."""
    return {key: item for key, item in value.items() if key not in _COORDINATES}
