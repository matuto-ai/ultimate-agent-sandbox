#!/usr/bin/env python3
"""PROTOTYPE: stdio or Streamable HTTP MCP adapter for Claude-to-Hub traffic."""
from __future__ import annotations

import argparse
import http.server
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse


class Hub:
    def __init__(self, url: str, actor: str, profile: str, state_file: str, wait: float = 0):
        self.url = url
        self.actor = actor
        self.profile = profile
        self.state_file = state_file
        self.wait = wait
        self.badge = ""
        self.last_seq = 0
        self.badge_lock = threading.Lock()
        self.join_lock = threading.Lock()
        self.state_lock = threading.Lock()
        try:
            with open(state_file, encoding="utf-8") as handle:
                self.last_seq = int(json.load(handle).get("last_seq", 0))
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            pass

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as handle:
            json.dump({"last_seq": self.last_seq}, handle)

    def raw(self, path: str, method: str = "GET", body: Any = None, badge: str = "") -> Any:
        request = urllib.request.Request(
            self.url + path,
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={
                "content-type": "application/json",
                **({"X-Room-Badge": badge} if badge else {}),
            },
        )
        with urllib.request.urlopen(request, timeout=3 + self.wait) as response:
            return json.loads(response.read() or b"{}")

    def join(self, stale_badge: str = "") -> None:
        with self.join_lock:
            with self.badge_lock:
                if stale_badge and self.badge and self.badge != stale_badge:
                    return
            result = self.raw("/join", "POST", {
                "actor": self.actor,
                "runtime": "claude",
                "profile": self.profile,
                "after_seq": self.last_seq,
            })
            with self.badge_lock:
                self.badge = result["badge"]

    def call(self, path: str, method: str = "GET", body: Any = None) -> Any:
        with self.badge_lock:
            badge = self.badge
        if not badge:
            self.join()
            with self.badge_lock:
                badge = self.badge
        try:
            return self.raw(path, method, body, badge)
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise
            self.join(badge)
            with self.badge_lock:
                badge = self.badge
            return self.raw(path, method, body, badge)

    def heartbeat(self) -> None:
        self.call("/heartbeat", "POST", {})

    def disconnect(self) -> None:
        with self.badge_lock:
            badge = self.badge
        if badge:
            self.raw("/disconnect", "POST", {}, badge)

    def next(self) -> Any:
        # Peer traffic only: our own events advance the cursor but are never delivered back to us.
        deadline = time.monotonic() + self.wait
        while True:
            with self.state_lock:
                after = self.last_seq
            remaining = max(0.0, deadline - time.monotonic())
            result = self.call(f"/events?after_seq={after}&wait={remaining}")
            events = result.get("events") or []
            if events:
                with self.state_lock:
                    self.last_seq = max(self.last_seq, int(events[-1]["seq"]))
                    self.save()
            peers = [item for item in events if item.get("actor") != self.actor]
            if peers or time.monotonic() >= deadline:
                return {"events": peers}

    def submit(self, kind: str, arguments: dict[str, Any]) -> Any:
        body = {
            "type": kind,
            "client_id": arguments.get("client_id") or f"{self.actor}-{os.urandom(8).hex()}",
            "payload": {"text": arguments.get("text", "")},
        }
        for key in ("target", "correlation_id", "parent_seq"):
            if arguments.get(key) is not None:
                body[key] = arguments[key]
        return self.call("/traffic", "POST", body)


def tool(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required or [],
            "additionalProperties": False,
        },
    }


TOOLS = [
    tool("hub_peers", "List Room peers", {}),
    tool("hub_next", "Pull peer traffic available after the last durable sequence", {}),
    tool("hub_send", "Send a correlated request", {
        "target": {"type": "string"}, "text": {"type": "string"}, "client_id": {"type": "string"},
    }, ["target", "text"]),
    tool("hub_reply", "Reply to a request", {
        "correlation_id": {"type": "string"}, "parent_seq": {"type": "integer"},
        "text": {"type": "string"}, "client_id": {"type": "string"},
    }, ["correlation_id", "parent_seq", "text"]),
    tool("hub_broadcast", "Broadcast an informational message", {
        "text": {"type": "string"}, "client_id": {"type": "string"},
    }, ["text"]),
]


class MCP:
    def __init__(self, hub: Hub, record: Callable[[dict[str, Any]], None] | None = None):
        self.hub = hub
        self.record = record or (lambda _value: None)

    def respond(self, message: dict[str, Any]) -> dict[str, Any] | None:
        request_id = message.get("id")
        method = message.get("method")
        if method and method.startswith("notifications/"):
            return None
        try:
            self.record({"event": "request", "method": method})
            if method == "initialize":
                result = {
                    "protocolVersion": message.get("params", {}).get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "peer-hub-prototype", "version": "0.2"},
                }
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = message.get("params", {})
                name = params.get("name")
                arguments = params.get("arguments", {})
                self.record({"event": "tool-call", "tool": name})
                if name == "hub_peers":
                    value = self.hub.call("/participants")
                elif name == "hub_next":
                    value = self.hub.next()
                elif name == "hub_send":
                    value = self.hub.submit("request", arguments)
                elif name == "hub_reply":
                    value = self.hub.submit("reply", arguments)
                elif name == "hub_broadcast":
                    value = self.hub.submit("broadcast", arguments)
                else:
                    raise ValueError(f"unknown tool: {name}")
                result = {"content": [{"type": "text", "text": json.dumps(value, separators=(",", ":"))}]}
            else:
                raise ValueError(f"unsupported method: {method}")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as error:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(error)}}


def emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, separators=(",", ":")), flush=True)


def append_record(path: str, value: dict[str, Any], lock: threading.Lock) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with lock, open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": time.time(), "pid": os.getpid(), **value}, separators=(",", ":")) + "\n")


class MCPHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    mcp: MCP
    hub: Hub
    evidence: str
    evidence_lock: threading.Lock
    auth_token: str

    def record(self, value: dict[str, Any]) -> None:
        append_record(self.evidence, value, self.evidence_lock)


class MCPHandler(http.server.BaseHTTPRequestHandler):
    server: MCPHTTPServer
    protocol_version = "HTTP/1.1"

    def authorized(self) -> bool:
        return secrets.compare_digest(
            self.headers.get("Authorization", ""), f"Bearer {self.server.auth_token}"
        )

    def valid_origin(self) -> bool:
        origin = self.headers.get("Origin")
        return not origin or urlparse(origin).hostname in {"127.0.0.1", "localhost", "::1"}

    def json_reply(self, status: int, value: Any) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def empty_reply(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/mcp":
            self.json_reply(404, {"error": "not found"})
            return
        if not self.authorized():
            self.json_reply(401, {"error": "unauthorized"})
            return
        if not self.valid_origin():
            self.json_reply(403, {"error": "invalid origin"})
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            messages = body if isinstance(body, list) else [body]
            responses = [response for message in messages if (response := self.server.mcp.respond(message))]
            if not responses:
                self.empty_reply(202)
            else:
                self.json_reply(200, responses if isinstance(body, list) else responses[0])
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            self.json_reply(400, {"error": str(error)})

    def do_GET(self) -> None:
        if urlparse(self.path).path != "/mcp":
            self.json_reply(404, {"error": "not found"})
            return
        if not self.authorized():
            self.json_reply(401, {"error": "unauthorized"})
            return
        if not self.valid_origin():
            self.json_reply(403, {"error": "invalid origin"})
            return
        if "text/event-stream" not in self.headers.get("Accept", ""):
            self.empty_reply(405)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.server.record({"event": "sse-connect"})
        try:
            while True:
                try:
                    self.server.hub.heartbeat()
                except Exception as error:
                    self.server.record({"event": "heartbeat-error", "error": str(error)})
                self.wfile.write(b": heartbeat\n\n")
                self.wfile.flush()
                time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.server.record({"event": "sse-disconnect"})

    def do_DELETE(self) -> None:
        if not self.authorized():
            self.json_reply(401, {"error": "unauthorized"})
            return
        self.empty_reply(405)

    def log_message(self, _format: str, *args: Any) -> None:
        pass


def heartbeat_loop(hub: Hub, stop: threading.Event) -> None:
    while not stop.wait(0.5):
        try:
            hub.heartbeat()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hub", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--actor", default="claude")
    parser.add_argument("--profile", default="claude-default")
    parser.add_argument("--wait", type=float, default=0, help="seconds hub_next may long poll for traffic")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--evidence", default="")
    args = parser.parse_args()
    hub = Hub(args.hub, args.actor, args.profile, args.state, args.wait)
    record_lock = threading.Lock()
    mcp = MCP(hub, lambda value: append_record(args.evidence, value, record_lock))

    if args.transport == "http":
        auth_token = os.environ.get("MCP_AUTH_TOKEN", "")
        if not auth_token:
            parser.error("MCP_AUTH_TOKEN is required for HTTP transport")
        server = MCPHTTPServer(("127.0.0.1", args.port), MCPHandler)
        server.mcp = mcp
        server.hub = hub
        server.evidence = args.evidence
        server.evidence_lock = record_lock
        server.auth_token = auth_token
        print(f"http://127.0.0.1:{server.server_port}/mcp", flush=True)
        server.serve_forever()
        return

    stop = threading.Event()
    heartbeat = threading.Thread(target=heartbeat_loop, args=(hub, stop), daemon=True)
    heartbeat.start()
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            response = mcp.respond(json.loads(line))
            if response:
                emit(response)
    finally:
        stop.set()
        try:
            hub.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    main()
