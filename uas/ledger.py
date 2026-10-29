"""One Room's application ledger; no transport, agent runtime, or external effects.

Only trusted Hub code constructs Origin and supplies authorize/decide callbacks.
A connection belongs to one thread. Separate connections serialize via SQLite.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import sqlite3
from typing import Callable


MAX_JSON_BYTES = 1_048_576
MAX_EVENTS = 256
MAX_SEQUENCE = 2**63 - 1
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")


class LedgerError(Exception):
    """Stable, non-secret failure code. Storage errors require reconciliation."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _token(value):
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise LedgerError("INVALID_COMMAND")
    return value


def _json(value):
    """Canonical typed JSON: object order is irrelevant; bool/int/float differ."""
    def check(item, depth=0):
        if depth > 32:
            raise LedgerError("INVALID_JSON")
        if item is None or type(item) is bool:
            return
        if type(item) is int and abs(item) <= MAX_SEQUENCE:
            return
        if type(item) is float and math.isfinite(item):
            return
        if type(item) is str:
            if len(item) > MAX_JSON_BYTES:
                raise LedgerError("INVALID_JSON")
            return
        if type(item) is list and len(item) <= 4096:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict and len(item) <= 4096:
            for key, child in item.items():
                if type(key) is not str:
                    raise LedgerError("INVALID_JSON")
                check(key, depth + 1)
                check(child, depth + 1)
            return
        raise LedgerError("INVALID_JSON")

    check(value)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
            raise LedgerError("INVALID_JSON")
    except (ValueError, UnicodeError, RecursionError) as error:
        raise LedgerError("INVALID_JSON") from error
    return encoded


@dataclass(frozen=True)
class Origin:
    """Authenticated identity/context, supplied by the Hub, never by payload.

    authority_version identifies the effective security context. authorize is
    still called on every retry: persisted identity is not fresh authorization.
    """
    actor_id: str
    participant_id: str
    incarnation_id: str
    authority_version: str
    capabilities: tuple[str, ...]

    def canonical(self):
        fields = {key: _token(getattr(self, key)) for key in (
            "actor_id", "participant_id", "incarnation_id", "authority_version"
        )}
        if type(self.capabilities) is not tuple or len(self.capabilities) > 256:
            raise LedgerError("INVALID_COMMAND")
        capabilities = [_token(value) for value in self.capabilities]
        if len(set(capabilities)) != len(capabilities):
            raise LedgerError("INVALID_COMMAND")
        return {**fields, "capabilities": sorted(capabilities)}


@dataclass(frozen=True)
class Command:
    id: str
    kind: str
    target: str
    generation: int | None
    payload: dict

    def canonical(self):
        if self.generation is not None and (
            type(self.generation) is not int or not 0 <= self.generation <= MAX_SEQUENCE
        ):
            raise LedgerError("INVALID_COMMAND")
        if type(self.payload) is not dict:
            raise LedgerError("INVALID_COMMAND")
        return {"id": _token(self.id), "kind": _token(self.kind),
                "target": _token(self.target), "generation": self.generation, "payload": self.payload}


@dataclass(frozen=True)
class Event:
    kind: str
    payload: dict


@dataclass(frozen=True)
class Transition:
    """Pure domain decision. No network, filesystem, or other external effects."""
    state: dict
    events: tuple[Event, ...]
    result: dict


class RoomLedger:
    """Persistent public append/snapshot/replay interface for trusted Hub code.

    Path must be in the configured Room's control-plane store, not a Workstation
    mount. This module does not implement that mount/process security boundary.
    """

    def __init__(self, path: str | Path, room_id: str):
        self.room_id = _token(room_id)
        self._db = None
        try:
            # No URI interpretation, parent creation, or in-memory durability claim.
            path = Path(path)
            if str(path) == ":memory:":
                raise LedgerError("INVALID_STORE")
            self._db = sqlite3.connect(path, timeout=5, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA synchronous=FULL")
            if self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise LedgerError("INVALID_STORE")
            self._db.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in self._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )}
            if not tables:
                self._db.execute("CREATE TABLE room (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, room_id TEXT NOT NULL, seq INTEGER NOT NULL, state TEXT NOT NULL)")
                self._db.execute("CREATE TABLE operations (id TEXT PRIMARY KEY, canonical TEXT NOT NULL, receipt TEXT NOT NULL)")
                self._db.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES operations(id) DEFERRABLE INITIALLY DEFERRED, event TEXT NOT NULL)")
                self._db.execute("INSERT INTO room VALUES (1, 1, ?, 0, '{}')", (self.room_id,))
            elif tables != {"room", "operations", "events"}:
                raise LedgerError("INVALID_STORE")
            row = self._db.execute("SELECT version, room_id FROM room WHERE singleton=1").fetchone()
            if row is None or row["version"] != 1:
                raise LedgerError("UNSUPPORTED_STORE_VERSION")
            if row["room_id"] != self.room_id:
                raise LedgerError("ROOM_MISMATCH")
            self._db.commit()
        except (sqlite3.Error, OSError) as error:
            self.close()
            raise LedgerError("STORAGE_ERROR") from error
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None

    def writer_binding(self):
        """Capture trusted existing store identity on this connection's thread."""
        rows = self._connection().execute('PRAGMA database_list').fetchall()
        paths = [Path(row[2]) for row in rows if row[1] == 'main']
        if len(paths) != 1 or not paths[0].is_absolute():
            raise LedgerError('INVALID_STORE')
        path = paths[0]
        info = path.stat()
        return path, (info.st_dev, info.st_ino)

    @classmethod
    def open_reader(cls, path: str | Path, room_id: str):
        return cls._open_existing(path, room_id)

    @classmethod
    def open_writer(cls, path: str | Path, room_id: str, *, identity):
        """One thread-local connection to the same existing canonical store.

        Never initializes a schema or creates a missing database. Authority and
        exact attachment validation still belong inside the consuming transaction.
        """
        return cls._open_existing(path, room_id, writable=True, identity=identity)

    @classmethod
    def _open_existing(cls, path: str | Path, room_id: str, *, writable=False, identity=None):
        """Open a validated existing store on its calling thread, never create.

        Readers remain query-only. Writers require the trusted inode binding;
        each connection retains SQLite's normal thread-affinity and transactions.
        """
        reader = cls.__new__(cls)
        reader.room_id, reader._db = _token(room_id), None
        try:
            path = Path(path)
            if str(path) == ':memory:':
                raise LedgerError('INVALID_STORE')
            if writable:
                info = path.stat()
                if type(identity) is not tuple or len(identity) != 2 or (info.st_dev, info.st_ino) != identity:
                    raise LedgerError('STORE_REPLACED')
            reader._db = sqlite3.connect(path.absolute().as_uri() + ('?mode=rw' if writable else '?mode=ro'),
                                         uri=True, timeout=5, isolation_level=None)
            reader._db.row_factory = sqlite3.Row
            if writable:
                info = path.stat()
                if (info.st_dev, info.st_ino) != identity:
                    raise LedgerError('STORE_REPLACED')
                reader._db.execute('PRAGMA foreign_keys=ON')
                reader._db.execute('PRAGMA synchronous=FULL')
            else:
                reader._db.execute('PRAGMA query_only=ON')
            tables = {row[0] for row in reader._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if tables != {'room', 'operations', 'events'}:
                raise LedgerError('INVALID_STORE')
            row = reader._db.execute('SELECT version, room_id FROM room WHERE singleton=1').fetchone()
            if row is None or row['version'] != 1:
                raise LedgerError('UNSUPPORTED_STORE_VERSION')
            if row['room_id'] != reader.room_id:
                raise LedgerError('ROOM_MISMATCH')
            return reader
        except (sqlite3.Error, OSError) as error:
            reader.close()
            raise LedgerError('STORAGE_ERROR') from error
        except BaseException:
            reader.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _connection(self):
        if self._db is None:
            raise LedgerError("CLOSED")
        return self._db

    def _commit(self):
        # A narrow storage boundary also permits real process-kill recovery tests.
        self._connection().commit()

    def apply(self, command: Command, origin: Origin, *,
              authorize: Callable[[Origin, Command], bool],
              decide: Callable[[dict, Command], Transition]) -> dict:
        """Authorize, deduplicate, decide and commit; acknowledge only after COMMIT.

        authorize runs under the write lock, before any duplicate disclosure.
        It may read snapshot() on this connection for transaction-consistent
        policy state. Both callbacks must be local/pure, without nested writes.
        decide validates the command-kind-specific typed payload and generation.
        It is called only for new IDs, under the write lock, with detached state.
        Exact authorized retries precede those freshness/domain checks. A storage
        failure is not a negative acknowledgement: reopen and retry the same ID.
        """
        if type(command) is not Command or type(origin) is not Origin:
            raise LedgerError("INVALID_COMMAND")
        canonical = _json({"room_id": self.room_id, "command": command.canonical(), "origin": origin.canonical()})
        # Detach mutable payload from caller and callback mutation.
        envelope = json.loads(canonical)
        operation = Command(**envelope["command"])
        db = self._connection()
        try:
            db.execute("BEGIN IMMEDIATE")
            # Fresh policy authorization must follow lock acquisition: waiting
            # for another writer can invalidate a previously allowed decision.
            if authorize(origin, operation) is not True:
                raise LedgerError("FORBIDDEN")
            # Authorization code must not rewrite the operation being authorized.
            operation = Command(**json.loads(canonical)["command"])
            previous = db.execute("SELECT canonical, receipt FROM operations WHERE id=?", (operation.id,)).fetchone()
            if previous is not None:
                if previous["canonical"] != canonical:
                    raise LedgerError("ID_CONFLICT")
                receipt = json.loads(previous["receipt"])
                db.rollback()
                return receipt
            row = db.execute("SELECT seq, state FROM room WHERE singleton=1").fetchone()
            transition = decide(json.loads(row["state"]), operation)
            if type(transition) is not Transition or type(transition.state) is not dict or type(transition.result) is not dict:
                raise LedgerError("INVALID_TRANSITION")
            if type(transition.events) is not tuple or not 1 <= len(transition.events) <= MAX_EVENTS:
                raise LedgerError("INVALID_TRANSITION")
            state = _json(transition.state)
            result = json.loads(_json(transition.result))
            first_seq = row["seq"] + 1
            last_seq = row["seq"] + len(transition.events)
            if last_seq > MAX_SEQUENCE:
                raise LedgerError("SEQUENCE_EXHAUSTED")
            timestamp = datetime.now(timezone.utc).isoformat()
            for seq, event in enumerate(transition.events, first_seq):
                if type(event) is not Event or type(event.payload) is not dict:
                    raise LedgerError("INVALID_TRANSITION")
                record = {"room_id": self.room_id, "room_seq": seq, "operation_id": envelope["command"]["id"],
                          "kind": _token(event.kind), "payload": event.payload,
                          "origin": envelope["origin"], "target": envelope["command"]["target"],
                          "generation": envelope["command"]["generation"], "timestamp": timestamp}
                db.execute("INSERT INTO events VALUES (?, ?, ?)", (seq, envelope["command"]["id"], _json(record)))
            receipt = {"room_id": self.room_id, "operation_id": envelope["command"]["id"],
                       "first_seq": first_seq, "last_seq": last_seq, "result": result}
            db.execute("INSERT INTO operations VALUES (?, ?, ?)", (envelope["command"]["id"], canonical, _json(receipt)))
            db.execute("UPDATE room SET seq=?, state=? WHERE singleton=1", (last_seq, state))
            self._commit()
            return receipt
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError("STORAGE_ERROR") from error
        except BaseException:
            db.rollback()
            raise

    def exact_receipt(self, command: Command, origin: Origin, *, authorize):
        """Authorize and compare the complete request before read-side effects.

        Trusted domain services use this before a read-only external resolver.
        A missing receipt is not a reservation: apply must still authorize,
        deduplicate and atomically reserve before any materialization/launch.
        No generation or domain freshness check precedes this exact lookup.
        """
        if type(command) is not Command or type(origin) is not Origin:
            raise LedgerError('INVALID_COMMAND')
        canonical = _json({'room_id': self.room_id, 'command': command.canonical(),
                           'origin': origin.canonical()})
        operation = Command(**json.loads(canonical)['command'])
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            if authorize(origin, operation) is not True:
                raise LedgerError('FORBIDDEN')
            row = db.execute('SELECT canonical, receipt FROM operations WHERE id=?',
                             (command.id,)).fetchone()
            if row is not None and row['canonical'] != canonical:
                raise LedgerError('ID_CONFLICT')
            receipt = None if row is None else json.loads(row['receipt'])
            db.rollback()
            return receipt
        except sqlite3.Error as error:
            db.rollback()
            raise LedgerError('STORAGE_ERROR') from error
        except BaseException:
            db.rollback()
            raise

    def matched_receipt(self, operation_id, origin, *, authorize, matches):
        """Trusted owner read: authorize stored command and match exact request.

        Callbacks are fixed owner code, never browser-selected predicates. This
        reserves nothing and cannot turn an absent receipt into permission to
        retry. No stored command or unrelated receipt is disclosed on mismatch.
        """
        _token(operation_id)
        if type(origin) is not Origin or not callable(authorize) or not callable(matches):
            raise LedgerError('INVALID_COMMAND')
        db = self._connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT canonical, receipt FROM operations WHERE id=?', (operation_id,)).fetchone()
            if row is None:
                if authorize(origin, None) is not True: raise LedgerError('FORBIDDEN')
                return None
            canonical = json.loads(row['canonical'])
            command = Command(**canonical['command'])
            if authorize(origin, command) is not True: raise LedgerError('FORBIDDEN')
            if canonical['origin'] != origin.canonical() or matches(command) is not True:
                raise LedgerError('ID_CONFLICT')
            return json.loads(row['receipt'])
        except sqlite3.Error as error:
            raise LedgerError('STORAGE_ERROR') from error
        finally:
            db.rollback()

    def operation_receipt(self, operation_id, origin, *, authorize):
        """Trusted read-side reconciliation, not a client operation-ID endpoint.

        Require fresh authority and the exact stored Origin before disclosure.
        Callers must first validate their request's canonical equality via apply;
        this helper only retrieves a server-derived related terminal operation.
        """
        _token(operation_id)
        if type(origin) is not Origin:
            raise LedgerError('INVALID_COMMAND')
        canonical_origin = origin.canonical()
        try:
            if authorize() is not True:
                raise LedgerError('FORBIDDEN')
            row = self._connection().execute(
                'SELECT canonical, receipt FROM operations WHERE id=?', (operation_id,)).fetchone()
            if row is None:
                return None
            if json.loads(row['canonical'])['origin'] != canonical_origin:
                raise LedgerError('FORBIDDEN')
            return json.loads(row['receipt'])
        except sqlite3.Error as error:
            raise LedgerError('STORAGE_ERROR') from error

    def snapshot(self) -> dict:
        """Materialized state and sequence from one SQLite read statement/cut."""
        try:
            row = self._connection().execute("SELECT seq, state FROM room WHERE singleton=1").fetchone()
            return {"room_id": self.room_id, "room_seq": row["seq"], "state": json.loads(row["state"])}
        except sqlite3.Error as error:
            raise LedgerError("STORAGE_ERROR") from error

    def replay(self, after_seq: int, *, limit: int = 100, through_seq: int | None = None) -> list[dict]:
        """One bounded ordered range. Continue from last room_seq; no subscriptions.

        through_seq optionally pins a finite catch-up high-water mark. Repeating
        the same range returns the same events, not exactly-once network delivery.
        """
        if type(after_seq) is not int or not 0 <= after_seq <= MAX_SEQUENCE:
            raise LedgerError("INVALID_CURSOR")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise LedgerError("INVALID_CURSOR")
        if through_seq is None:
            through_seq = MAX_SEQUENCE
        if type(through_seq) is not int or not after_seq <= through_seq <= MAX_SEQUENCE:
            raise LedgerError("INVALID_CURSOR")
        try:
            rows = self._connection().execute(
                "SELECT event FROM events WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?",
                (after_seq, through_seq, limit),
            ).fetchall()
            return [json.loads(row["event"]) for row in rows]
        except sqlite3.Error as error:
            raise LedgerError("STORAGE_ERROR") from error
