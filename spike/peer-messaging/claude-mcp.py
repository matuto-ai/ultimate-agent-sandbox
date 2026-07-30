#!/usr/bin/env python3
"""PROTOTYPE: stdio MCP adapter for Claude-to-Hub peer traffic."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any


class Hub:
    def __init__(self, url: str, actor: str, profile: str, state_file: str):
        self.url = url
        self.actor = actor
        self.profile = profile
        self.state_file = state_file
        self.badge = ""
        self.last_seq = 0
        try:
            with open(state_file, encoding="utf-8") as handle:
                self.last_seq = int(json.load(handle).get("last_seq", 0))
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            pass

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as handle:
            json.dump({"last_seq": self.last_seq}, handle)

    def raw(self, path: str, method: str = "GET", body: Any = None) -> Any:
        request = urllib.request.Request(
            self.url + path,
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={
                "content-type": "application/json",
                **({"X-Room-Badge": self.badge} if self.badge else {}),
            },
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.loads(response.read() or b"{}")

    def join(self) -> None:
        result = self.raw("/join", "POST", {
            "actor": self.actor,
            "runtime": "claude",
            "profile": self.profile,
            "after_seq": self.last_seq,
        })
        self.badge = result["badge"]

    def call(self, path: str, method: str = "GET", body: Any = None) -> Any:
        if not self.badge:
            self.join()
        try:
            return self.raw(path, method, body)
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise
            self.join()
            return self.raw(path, method, body)

    def next(self) -> Any:
        result = self.call(f"/events?after_seq={self.last_seq}")
        if result.get("events"):
            self.last_seq = int(result["events"][-1]["seq"])
            self.save()
        return result

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


def emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, separators=(",", ":")), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hub", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--actor", default="claude")
    parser.add_argument("--profile", default="claude-default")
    args = parser.parse_args()
    hub = Hub(args.hub, args.actor, args.profile, args.state)

    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        request_id = message.get("id")
        method = message.get("method")
        if method and method.startswith("notifications/"):
            continue
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": message.get("params", {}).get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "peer-hub-prototype", "version": "0.1"},
                }
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = message.get("params", {})
                name = params.get("name")
                arguments = params.get("arguments", {})
                if name == "hub_peers":
                    value = hub.call("/participants")
                elif name == "hub_next":
                    value = hub.next()
                elif name == "hub_send":
                    value = hub.submit("request", arguments)
                elif name == "hub_reply":
                    value = hub.submit("reply", arguments)
                elif name == "hub_broadcast":
                    value = hub.submit("broadcast", arguments)
                else:
                    raise ValueError(f"unknown tool: {name}")
                result = {"content": [{"type": "text", "text": json.dumps(value, separators=(",", ":"))}]}
            else:
                raise ValueError(f"unsupported method: {method}")
            emit({"jsonrpc": "2.0", "id": request_id, "result": result})
        except Exception as error:
            emit({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(error)}})


if __name__ == "__main__":
    main()
