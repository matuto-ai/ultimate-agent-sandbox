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
scheduler recovery and report replay consume these records. Recovery and
deduplication state is never pruned here; receipt-detail expiry belongs to a
later slice.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3

from .library import LibraryError, Operation, admit_receipt, audit_metadata


RECORD_VERSION = 1
MAX_PENDING = 256
MAX_ATTEMPTS = 256
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_KEYS = ("record_version", "kind", "operation_id", "request_id", "queue_id",
                  "drain_id", "settings_id", "project_id", "project_identity",
                  "project_path", "payload_sha256", "payload_bytes", "origin")

# An outcome a Producer cannot reach for this kind is refused, so a record
# cannot claim a publication its operation does not make.
_KIND_OUTCOMES = {
    "enqueue": {"DURABLY_QUEUED", "REJECTED", "NOT_DURABLE"},
    "settings-update": {"CONFIGURED", "REJECTED", "NOT_DURABLE"},
}

_SCHEMA = {
    "deployment": "CREATE TABLE deployment (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, id TEXT NOT NULL)",
    "submissions": "CREATE TABLE submissions (project_identity TEXT, request_id TEXT NOT NULL, identity TEXT NOT NULL, origin TEXT NOT NULL, submitted_at TEXT NOT NULL, PRIMARY KEY(project_identity, request_id))",
    "attempts": "CREATE TABLE attempts (operation_id TEXT PRIMARY KEY, project_identity TEXT, request_id TEXT NOT NULL, queue_id TEXT, drain_id TEXT, identity TEXT NOT NULL, started_at TEXT NOT NULL, receipt TEXT, finished_at TEXT)",
}
_INDEXES = {
    "attempt_request_idx": "CREATE INDEX attempt_request_idx ON attempts(project_identity, request_id)",
    "attempt_queue_idx": "CREATE INDEX attempt_queue_idx ON attempts(queue_id)",
    "attempt_drain_idx": "CREATE INDEX attempt_drain_idx ON attempts(drain_id)",
    "attempt_pending_idx": "CREATE INDEX attempt_pending_idx ON attempts(receipt, started_at)",
}
_SUBMISSION_ORIGIN = {"actor_id", "participant_id", "subject", "at", "request_id",
                      "payload_sha256"}


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
    if set(origin) != _SUBMISSION_ORIGIN:
        raise LibraryError("INVALID_RECORD", "provenance")
    for key in ("actor_id", "participant_id", "subject", "request_id"):
        _token(origin[key], "provenance." + key)
    _timestamp(origin["at"])
    _digest(origin["payload_sha256"], "provenance.payload_sha256")
    if origin["request_id"] != operation.request_id:
        raise LibraryError("INVALID_RECORD", "provenance.request_id")
    if origin["payload_sha256"] != operation.digest():
        raise LibraryError("INVALID_RECORD", "provenance.payload_sha256")
    return _safe(origin, "provenance")


def _identity(operation):
    """Bounded immutable identity of one attempt; the payload itself is excluded."""
    payload = _canonical(operation.payload)
    try:
        size = len(payload.encode("utf-8"))
    except UnicodeError as error:
        raise LibraryError("INVALID_RECORD", "payload") from error
    identity = {
        "record_version": RECORD_VERSION, "kind": operation.kind,
        "operation_id": operation.operation_id, "request_id": operation.request_id,
        "queue_id": operation.queue_id, "drain_id": operation.drain_id,
        "settings_id": operation.settings_id,
        "project_id": operation.scope.project_id,
        "project_identity": operation.scope.project_identity,
        "project_path": operation.scope.project_path,
        "payload_sha256": operation.digest(), "payload_bytes": size,
        "origin": _origin(operation.scope),
    }
    for key in ("kind", "operation_id", "request_id", "settings_id"):
        _token(identity[key], key)
    for key in ("queue_id",):
        if identity[key] is not None:
            _digest(identity[key], key)
    for key in ("project_id", "project_identity"):
        if identity[key] is not None:
            _token(identity[key], key)
    for key, stored in (("project_path", operation.scope.project_path),
                        ("drain_id", operation.drain_id)):
        if stored is not None:
            _token(stored, key)
    if (identity["kind"] == "enqueue") != (identity["queue_id"] is not None):
        raise LibraryError("INVALID_RECORD", "queue_id")
    return _safe(identity, "identity")


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
        try:
            path = Path(path)
            if str(path) == ":memory:":
                raise LibraryError("INVALID_STORE")
            self._db = sqlite3.connect(path, timeout=5, isolation_level=None)
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

    def _write(self, work):
        db = self._connection()
        try:
            db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            # Nothing was attempted, so this instance stays usable.
            raise LibraryError("RECORD_UNAVAILABLE") from error
        try:
            result = work(db)
            self._commit()
            return result
        except sqlite3.Error as error:
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
                    or _canonical(_identity_like(identity)) != row["identity"]):
                raise ValueError()
            if receipt is not None and (row["receipt"] != _canonical(receipt)
                                        or receipt["operation_id"] != operation_id):
                raise ValueError()
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
                "state": "PENDING" if receipt is None else "RECORDED"}

    def record(self, operation_id, *, project_identity):
        """Exact Project-fenced read; nothing is disclosed across scopes."""
        _token(operation_id, "operation_id")
        if project_identity is not None:
            _token(project_identity, "project_identity")
        value = self._read(lambda db: self._attempt(db, operation_id))
        if value is None or value["project_identity"] != project_identity:
            return None
        return value

    def submission(self, project_identity, request_id):
        """Immutable original submission plus its attempts, oldest first.

        Bounded: history past this owner's read limit needs operator action.
        """
        if project_identity is not None:
            _token(project_identity, "project_identity")
        _token(request_id, "request_id")

        def read(db):
            row = db.execute("SELECT identity,origin,submitted_at FROM submissions "
                             "WHERE project_identity IS ? AND request_id=?",
                             (project_identity, request_id)).fetchone()
            if row is None:
                return None
            try:
                origin, identity = json.loads(row["origin"]), json.loads(row["identity"])
                _timestamp(row["submitted_at"])
                if (row["origin"] != _canonical(origin)
                        or row["identity"] != _canonical(identity)
                        or set(origin) != _SUBMISSION_ORIGIN
                        or origin.get("request_id") != request_id
                        or identity.get("request_id") != request_id
                        or identity.get("payload_sha256") != origin.get("payload_sha256")):
                    raise ValueError()
            except LibraryError as error:
                raise LibraryError("RECORD_INVALID") from error
            except (ValueError, TypeError, KeyError, RecursionError) as error:
                raise LibraryError("RECORD_INVALID") from error
            attempts = db.execute("SELECT operation_id FROM attempts WHERE project_identity IS ? "
                                  "AND request_id=? ORDER BY started_at,operation_id LIMIT ?",
                                  (project_identity, request_id, MAX_ATTEMPTS + 1)).fetchall()
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

    # --- writes ----------------------------------------------------------

    def begin(self, operation):
        """Durably record one attempt intent; no acknowledgement before commit.

        An exact repeat returns the committed record unchanged. Conflicting
        identity or digest reuse is refused instead of overwriting a receipt.
        """
        if type(operation) is not Operation:
            raise LibraryError("INVALID_OPERATION", "operation")
        identity = _identity(operation)
        canonical = _canonical(identity)
        origin = _submission_origin(operation) if operation.kind == "enqueue" else None

        def work(db):
            prior = self._attempt(db, operation.operation_id)
            if prior is not None:
                if _canonical(_identity_like(prior)) != canonical:
                    raise LibraryError("ID_CONFLICT", "operation_id")
                return {"state": prior["state"], "record": prior}
            if origin is not None:
                row = db.execute("SELECT identity FROM submissions WHERE "
                                 "project_identity IS ? AND request_id=?",
                                 (identity["project_identity"], identity["request_id"])).fetchone()
                if row is not None:
                    stored = json.loads(row["identity"])
                    if (stored.get("payload_sha256") != identity["payload_sha256"]
                            or stored.get("queue_id") != identity["queue_id"]
                            or stored.get("kind") != identity["kind"]):
                        raise LibraryError("ID_CONFLICT", "request_id")
                else:
                    # Only a retry may carry another actor's submission origin.
                    if any(origin[key] != identity["origin"][key] for key in
                           ("actor_id", "participant_id", "subject")):
                        raise LibraryError("CALLER_AUTHORITY", "provenance.actor_id")
                    db.execute("INSERT INTO submissions VALUES(?,?,?,?,?)",
                               (identity["project_identity"], identity["request_id"],
                                canonical, _canonical(origin), _now()))
            self._capacity(db)
            db.execute("INSERT INTO attempts(operation_id,project_identity,request_id,"
                       "queue_id,drain_id,identity,started_at) VALUES(?,?,?,?,?,?,?)",
                       (operation.operation_id, identity["project_identity"],
                        identity["request_id"], identity["queue_id"], identity["drain_id"],
                        canonical, _now()))
            return {"state": "PENDING", "record": self._attempt(db, operation.operation_id)}

        return self._write(work)

    def _capacity(self, db):
        pending = db.execute("SELECT count(*) FROM attempts WHERE receipt IS NULL").fetchone()[0]
        if pending >= MAX_PENDING:
            raise LibraryError("RECORD_CAPACITY")

    def finish(self, operation, receipt):
        """Durably record the terminal receipt before any acknowledgement.

        The receipt must describe this stored attempt. An exact repeat returns
        the committed record; a different value is a conflict, never a rewrite.
        """
        if type(operation) is not Operation:
            raise LibraryError("INVALID_OPERATION", "operation")
        canonical_identity = _canonical(_identity(operation))
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
            if _canonical(_identity_like(prior)) != canonical_identity:
                raise LibraryError("ID_CONFLICT", "operation_id")
            if prior["receipt"] is not None:
                if _canonical(prior["receipt"]) != value:
                    raise LibraryError("ID_CONFLICT", "receipt")
                return prior
            db.execute("UPDATE attempts SET receipt=?,finished_at=? WHERE operation_id=?",
                       (value, _now(), operation.operation_id))
            return self._attempt(db, operation.operation_id)

        return self._write(work)


def _identity_like(value):
    """Rebuild the stored identity from a record for tamper checking."""
    return {key: value[key] for key in _IDENTITY_KEYS}
