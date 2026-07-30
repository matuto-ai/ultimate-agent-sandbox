#!/usr/bin/env python3
"""PROTOTYPE: localhost peer-message Hub with a durable SQLite ledger."""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import secrets
import sqlite3
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse


def timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def encode(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


class Store:
    def __init__(self, path: str):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        with self.db:
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS participants(
                    actor TEXT PRIMARY KEY,
                    badge TEXT UNIQUE NOT NULL,
                    runtime TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    connected INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    target TEXT,
                    client_id TEXT UNIQUE,
                    correlation_id TEXT,
                    parent_seq INTEGER,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_correlation ON events(correlation_id);
                CREATE INDEX IF NOT EXISTS events_target ON events(target);
                """
            )
            # Badges authorize one Hub process only; every restart requires rejoin.
            self.db.execute("UPDATE participants SET connected=0")

    def _append(
        self,
        kind: str,
        actor: str,
        target: str | None = None,
        client_id: str | None = None,
        correlation_id: str | None = None,
        parent_seq: int | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        cur = self.db.execute(
            "INSERT INTO events(ts,type,actor,target,client_id,correlation_id,parent_seq,payload_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                timestamp(), kind, actor, target, client_id, correlation_id,
                parent_seq, json.dumps(payload or {}, separators=(",", ":")),
            ),
        )
        return self._event(self.db.execute("SELECT * FROM events WHERE seq=?", (cur.lastrowid,)).fetchone())

    @staticmethod
    def _event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "seq": row["seq"], "ts": row["ts"], "type": row["type"],
            "actor": row["actor"], "target": row["target"],
            "client_id": row["client_id"], "correlation_id": row["correlation_id"],
            "parent_seq": row["parent_seq"], "payload": json.loads(row["payload_json"]),
        }

    def join(self, actor: str, runtime: str, profile: str, after_seq: int) -> dict[str, Any]:
        badge = "b-" + secrets.token_hex(16)
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO participants(actor,badge,runtime,profile,connected,updated_at) VALUES (?,?,?,?,1,?) "
                "ON CONFLICT(actor) DO UPDATE SET badge=excluded.badge,runtime=excluded.runtime,"
                "profile=excluded.profile,connected=1,updated_at=excluded.updated_at",
                (actor, badge, runtime, profile, timestamp()),
            )
            self._append("join", actor, payload={"runtime": runtime, "profile": profile})
        return {"badge": badge, "after_seq": after_seq}

    def actor_for(self, badge: str) -> str:
        with self.lock:
            row = self.db.execute(
                "SELECT actor FROM participants WHERE badge=? AND connected=1", (badge,)
            ).fetchone()
        if not row:
            raise PermissionError("unauthorized")
        return str(row["actor"])

    def disconnect(self, badge: str) -> None:
        with self.lock, self.db:
            row = self.db.execute("SELECT actor FROM participants WHERE badge=?", (badge,)).fetchone()
            if row:
                self.db.execute(
                    "UPDATE participants SET connected=0,updated_at=? WHERE badge=?",
                    (timestamp(), badge),
                )
                self._append("disconnect", str(row["actor"]))

    def submit(self, badge: str, data: dict[str, Any]) -> dict[str, Any]:
        actor = self.actor_for(badge)
        kind = data.get("type")
        if kind not in {"message", "request", "reply", "broadcast"}:
            raise ValueError("type must be message, request, reply, or broadcast")
        client_id = data.get("client_id")
        if not client_id:
            raise ValueError("client_id is required")
        target = data.get("target")
        correlation = data.get("correlation_id")
        parent_seq = data.get("parent_seq")
        payload = data.get("payload") or {}
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")

        with self.lock, self.db:
            existing = self.db.execute("SELECT * FROM events WHERE client_id=?", (client_id,)).fetchone()
            if existing:
                event = self._event(existing)
                expected = {
                    "type": kind, "actor": actor, "target": target,
                    "correlation_id": correlation, "parent_seq": parent_seq, "payload": payload,
                }
                actual = {key: event[key] for key in expected}
                if actual != expected:
                    raise ValueError("client_id conflict")
                return event

            if kind == "broadcast":
                target = None
            elif not target and kind != "reply":
                raise ValueError("target is required")

            if kind == "request":
                correlation = correlation or "c-" + secrets.token_hex(12)
            elif kind == "reply":
                if not correlation or parent_seq is None:
                    raise ValueError("reply requires correlation_id and parent_seq")
                parent = self.db.execute("SELECT * FROM events WHERE seq=?", (parent_seq,)).fetchone()
                if not parent or parent["type"] != "request" or parent["correlation_id"] != correlation:
                    raise ValueError("reply does not match its request")
                if actor != parent["target"]:
                    raise PermissionError("only the request target may reply")
                target = str(parent["actor"])

            return self._append(kind, actor, target, client_id, correlation, parent_seq, payload)

    def participants(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT actor,runtime,profile,connected,updated_at FROM participants ORDER BY actor"
            ).fetchall()
            return [dict(row) for row in rows]

    def events_after(self, actor: str, after_seq: int) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM events WHERE seq>? AND "
                "(actor=? OR target=? OR type IN ('broadcast','join','disconnect')) ORDER BY seq",
                (after_seq, actor, actor),
            ).fetchall()
            return [self._event(row) for row in rows]

    def dump(self) -> dict[str, Any]:
        with self.lock:
            participants = [dict(row) for row in self.db.execute(
                "SELECT actor,runtime,profile,connected,updated_at FROM participants ORDER BY actor"
            )]
            events = [self._event(row) for row in self.db.execute("SELECT * FROM events ORDER BY seq")]
        return {"participants": participants, "events": events}


class Handler(http.server.BaseHTTPRequestHandler):
    server: "HubServer"

    def reply(self, status: int, value: Any) -> None:
        body = encode(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self) -> dict[str, Any]:
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")

    def do_POST(self) -> None:
        try:
            data = self.body()
            badge = self.headers.get("X-Room-Badge", "")
            if self.path == "/join":
                self.reply(200, self.server.store.join(
                    data["actor"], data["runtime"], data["profile"], int(data.get("after_seq", 0))
                ))
            elif self.path == "/disconnect":
                self.server.store.disconnect(badge)
                self.reply(200, {"ok": True})
            elif self.path == "/traffic":
                self.reply(200, self.server.store.submit(badge, data))
            else:
                self.reply(404, {"error": "not found"})
        except PermissionError as error:
            self.reply(401, {"error": str(error)})
        except (KeyError, TypeError, ValueError) as error:
            self.reply(409 if "conflict" in str(error) else 400, {"error": str(error)})

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/dump":
                if not secrets.compare_digest(
                    self.headers.get("X-Debug-Token", ""), self.server.debug_token
                ):
                    raise PermissionError("unauthorized")
                self.reply(200, self.server.store.dump())
                return
            actor = self.server.store.actor_for(self.headers.get("X-Room-Badge", ""))
            if parsed.path == "/participants":
                self.reply(200, self.server.store.participants())
            elif parsed.path == "/events":
                query = parse_qs(parsed.query)
                after = int(query.get("after_seq", ["0"])[0])
                # Optional long poll: pull stays cheap without a hot spin loop.
                deadline = time.monotonic() + min(float(query.get("wait", ["0"])[0]), 30)
                events = self.server.store.events_after(actor, after)
                while not events and time.monotonic() < deadline:
                    time.sleep(0.1)
                    events = self.server.store.events_after(actor, after)
                self.reply(200, {"events": events})
            else:
                self.reply(404, {"error": "not found"})
        except PermissionError as error:
            self.reply(401, {"error": str(error)})
        except ValueError as error:
            self.reply(400, {"error": str(error)})

    def log_message(self, _format: str, *args: Any) -> None:
        pass


class HubServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    store: Store
    debug_token: str


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--debug-token", required=True)
    args = parser.parse_args()
    server = HubServer(("127.0.0.1", args.port), Handler)
    server.store = Store(args.db)
    server.debug_token = args.debug_token
    print(f"http://127.0.0.1:{server.server_port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
