"""Disk-backed synthetic receiver. No Pi/Claude or production authentication.

A receiver's durable inbox demonstrates acceptance and envelope deduplication,
not exactly-once execution of arbitrary work. Each incarnation has its own inbox.
"""
import json
from pathlib import Path
import sqlite3

from uas.ledger import LedgerError, _json, _token
from uas.peer import digest


class FixtureReceiver:
    def __init__(self, path, room_id, participant_id, incarnation_id, context_generation=1):
        if str(path) == ":memory:":
            raise LedgerError("INVALID_STORE")
        self.binding = {"room_id": _token(room_id), "participant_id": _token(participant_id),
                        "incarnation_id": _token(incarnation_id), "context_generation": context_generation}
        if type(context_generation) is not int or context_generation < 1:
            raise LedgerError("INVALID_BINDING")
        self.db = sqlite3.connect(Path(path), isolation_level=None)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise LedgerError("INVALID_STORE")
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("CREATE TABLE IF NOT EXISTS binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value TEXT NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS inbox (delivery_id TEXT PRIMARY KEY, envelope TEXT NOT NULL, receipt TEXT NOT NULL)")
            existing = self.db.execute("SELECT value FROM binding WHERE singleton=1").fetchone()
            if existing and existing[0] != _json(self.binding):
                raise LedgerError("RECEIVER_BINDING_CONFLICT")
            if not existing:
                self.db.execute("INSERT INTO binding VALUES (1, ?)", (_json(self.binding),))
            self.db.commit()
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _commit(self):
        self.db.commit()

    def accept(self, envelope):
        """Acknowledge only the committed, exactly-bound immutable envelope."""
        canonical = _json(envelope)
        envelope = json.loads(canonical)
        if any(envelope.get(key) != value or type(envelope.get(key)) is not type(value)
               for key, value in self.binding.items()):
            raise LedgerError("RECEIVER_BINDING_CONFLICT")
        delivery_id = _token(envelope.get("delivery_id"))
        receipt = {"delivery_id": delivery_id, "digest": digest(envelope),
                   **{key: self.binding[key] for key in ("participant_id", "incarnation_id", "context_generation")}}
        try:
            self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute("SELECT envelope, receipt FROM inbox WHERE delivery_id=?", (delivery_id,)).fetchone()
            if existing:
                if existing[0] != canonical:
                    raise LedgerError("ID_CONFLICT")
                self.db.rollback()
                return json.loads(existing[1])
            self.db.execute("INSERT INTO inbox VALUES (?, ?, ?)", (delivery_id, canonical, _json(receipt)))
            self._commit()
            return receipt
        except BaseException:
            self.db.rollback()
            raise

    def inbox(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT envelope FROM inbox ORDER BY rowid")]
