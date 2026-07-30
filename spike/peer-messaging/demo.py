#!/usr/bin/env python3
"""One-command evidence harness for the peer-messaging prototype."""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).resolve().parent
SCRATCH = ROOT / ".demo"


def debug_dump(url: str, token: str) -> Any:
    request = urllib.request.Request(url + "/dump", headers={"X-Debug-Token": token})
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.loads(response.read() or b"{}")


def post(url: str, body: dict[str, Any], badge: str = "") -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **({"X-Room-Badge": badge} if badge else {})},
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.loads(response.read() or b"{}")


def start_hub(database: pathlib.Path, debug_token: str, port: int = 0) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        [
            sys.executable, str(ROOT / "hub.py"), "--db", str(database),
            "--port", str(port), "--debug-token", debug_token,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout
    url = process.stdout.readline().strip()
    if not url:
        assert process.stderr
        raise RuntimeError(process.stderr.read())
    return process, url


def stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def exchange(process: subprocess.Popen[str], message: dict[str, Any]) -> dict[str, Any]:
    assert process.stdin and process.stdout
    process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    process.stdin.flush()
    while line := process.stdout.readline():
        value = json.loads(line)
        if value.get("id") == message.get("id"):
            if value.get("error"):
                raise RuntimeError(value["error"])
            return value
    raise RuntimeError("adapter exited before replying")


def pi_command(process: subprocess.Popen[str], request_id: str, command: str) -> dict[str, Any]:
    result = exchange(process, {"id": request_id, "type": "prompt", "message": command})
    if not result.get("success"):
        raise RuntimeError(result)
    return result


def mcp_tool(process: subprocess.Popen[str], request_id: int, name: str, arguments: dict[str, Any] | None = None) -> Any:
    response = exchange(process, {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })
    return json.loads(response["result"]["content"][0]["text"])


def eventually(check: Callable[[], Any], timeout: float = 8) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except Exception as error:
            last_error = error
        time.sleep(0.1)
    raise TimeoutError(str(last_error or "condition not reached"))


def evidence_lines(path: pathlib.Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def event(hub: str, debug_token: str, kind: str, actor: str, text: str) -> dict[str, Any] | None:
    for item in reversed(debug_dump(hub, debug_token)["events"]):
        if item["type"] == kind and item["actor"] == actor and item["payload"].get("text") == text:
            return item
    return None


def start_mcp(hub: str, state: pathlib.Path) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "claude-mcp.py"), "--hub", hub, "--state", str(state)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    exchange(process, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "demo", "version": "1"}},
    })
    return process


def main() -> int:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir()
    database = SCRATCH / "events.sqlite"
    pi_evidence = SCRATCH / "pi-evidence.jsonl"
    debug_token = os.urandom(24).hex()
    hub_process, hub = start_hub(database, debug_token)
    port = urlparse(hub).port or 0
    processes: list[subprocess.Popen[str]] = [hub_process]
    checks: list[dict[str, Any]] = []

    pi_env = {
        **os.environ,
        "HUB_URL": hub,
        "HUB_ACTOR": "pi",
        "HUB_PROFILE": "pi-default",
        "HUB_STATE": str(SCRATCH / "pi-state.json"),
        "HUB_EVIDENCE": str(pi_evidence),
    }
    pi = subprocess.Popen(
        ["pi", "--mode", "rpc", "--no-session", "--extension", str(ROOT / "pi-adapter.ts")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=pi_env,
    )
    processes.append(pi)
    mcp = start_mcp(hub, SCRATCH / "claude-state.json")
    processes.append(mcp)

    try:
        exchange(pi, {"id": "state", "type": "get_state"})
        tool_list = exchange(mcp, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        mcp_tool(mcp, 3, "hub_peers")

        def registered() -> list[dict[str, Any]] | None:
            peers = debug_dump(hub, debug_token)["participants"]
            return peers if {peer["actor"] for peer in peers if peer["connected"]} == {"pi", "claude"} else None

        peers = eventually(registered)
        pi_command(pi, "send-1", "/hub-send claude hello-from-pi")
        request = eventually(lambda: event(hub, debug_token, "request", "pi", "hello-from-pi"))
        inbox = mcp_tool(mcp, 4, "hub_next")
        assert any(item["seq"] == request["seq"] for item in inbox["events"])

        intruder = post(hub + "/join", {
            "actor": "intruder", "runtime": "fixture", "profile": "untrusted", "after_seq": 0,
        })
        try:
            post(hub + "/traffic", {
                "type": "reply", "client_id": "forged-reply",
                "correlation_id": request["correlation_id"], "parent_seq": request["seq"],
                "payload": {"text": "forged"},
            }, intruder["badge"])
            raise AssertionError("non-target forged a reply")
        except urllib.error.HTTPError as error:
            assert error.code == 401

        reply = mcp_tool(mcp, 5, "hub_reply", {
            "correlation_id": request["correlation_id"],
            "parent_seq": request["seq"],
            "text": "hello-from-claude",
            "client_id": "claude-reply-1",
        })
        pi_command(pi, "inbox-1", "/hub-inbox")
        eventually(lambda: any(
            line.get("action") == "receive" and line.get("event", {}).get("seq") == reply["seq"]
            for line in evidence_lines(pi_evidence)
        ))

        broadcast = mcp_tool(mcp, 6, "hub_broadcast", {
            "text": "broadcast-from-claude", "client_id": "claude-broadcast-1",
        })
        pi_command(pi, "inbox-2", "/hub-inbox")
        eventually(lambda: any(
            line.get("action") == "receive" and line.get("event", {}).get("seq") == broadcast["seq"]
            for line in evidence_lines(pi_evidence)
        ))

        # A replacement MCP process resumes from its durable after_seq and receives queued traffic.
        stop(mcp)
        pi_command(pi, "send-2", "/hub-send claude queued-for-replacement")
        queued = eventually(lambda: event(hub, debug_token, "request", "pi", "queued-for-replacement"))
        mcp = start_mcp(hub, SCRATCH / "claude-state.json")
        processes.append(mcp)
        replacement_inbox = mcp_tool(mcp, 7, "hub_next")
        assert any(item["seq"] == queued["seq"] for item in replacement_inbox["events"])

        before_restart = debug_dump(hub, debug_token)["events"]
        stop(hub_process)
        hub_process, restarted_url = start_hub(database, debug_token, port)
        processes.append(hub_process)
        assert restarted_url == hub

        # Old badges are rejected after restart; each live adapter rejoins and retries.
        mcp_tool(mcp, 8, "hub_peers")
        eventually(lambda: any(line.get("action") == "join" for line in evidence_lines(pi_evidence)[1:]))
        pi_command(pi, "peers-after-restart", "/hub-peers")
        after_restart = debug_dump(hub, debug_token)["events"]
        assert {item["seq"] for item in before_restart}.issubset({item["seq"] for item in after_restart})

        pi_lines = evidence_lines(pi_evidence)
        checks.extend([
            {"check": "real-pi-rpc-extension", "status": "pass", "commands": ["hub-send", "hub-inbox", "hub-peers"]},
            {"check": "participant-discovery", "status": "pass", "participants": peers},
            {"check": "correlated-request-reply", "status": "pass", "request": request, "reply": reply},
            {"check": "reply-authorization", "status": "pass", "rejected_actor": "intruder"},
            {"check": "broadcast-delivery", "status": "pass", "broadcast": broadcast},
            {"check": "mcp-process-replacement-replay", "status": "pass", "request_seq": queued["seq"]},
            {"check": "sqlite-hub-restart-replay", "status": "pass", "events_before": len(before_restart), "events_after": len(after_restart)},
            {"check": "claude-mcp-json-rpc", "status": "pass", "tools": [item["name"] for item in tool_list["result"]["tools"]]},
            {"check": "real-claude-code", "status": "blocked", "reason": "claude CLI is unavailable; real runtime execution remains issue #9's closure gate"},
            {"check": "claude-runtime-recovery-h9-04-through-h9-07", "status": "blocked", "reason": "the stdio MCP harness is non-attesting; actual Claude readiness, unresponsive recovery, HTTP/SSE reconnect, and missing-signal hold require a Claude-equipped workstation"},
        ])
        (SCRATCH / "evidence.json").write_text(json.dumps({"checks": checks, "pi_adapter": pi_lines}, indent=2) + "\n")
        print("OK real Pi RPC extension traffic")
        print("OK correlated request/reply")
        print("OK broadcast delivery")
        print("OK MCP process replacement replay")
        print("OK durable SQLite Hub restart replay")
        print("OK Claude MCP JSON-RPC harness")
        print("GATE real Claude evidence missing; keep issue #9 open")
        return 0
    finally:
        for process in reversed(processes):
            stop(process)


if __name__ == "__main__":
    raise SystemExit(main())
