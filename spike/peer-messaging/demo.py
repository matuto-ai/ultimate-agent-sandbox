#!/usr/bin/env python3
"""One-command evidence harness for the peer-messaging prototype."""
from __future__ import annotations

import contextlib
import http.client
import json
import os
import pathlib
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).resolve().parent
SCRATCH = ROOT / ".demo"
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "haiku")
REAL_CLAUDE = os.environ.get("REAL_CLAUDE") == "1"
CLAUDE_TOOLS = ",".join(
    f"mcp__hub__{name}" for name in ("hub_peers", "hub_next", "hub_send", "hub_reply", "hub_broadcast")
)


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


def start_hub(
    database: pathlib.Path, debug_token: str, port: int = 0, lease_seconds: float = 1.5
) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        [
            sys.executable, str(ROOT / "hub.py"), "--db", str(database),
            "--port", str(port), "--debug-token", debug_token,
            "--lease-seconds", str(lease_seconds),
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


def actor_online(hub: str, debug_token: str, actor: str) -> bool:
    return any(
        item["actor"] == actor and bool(item["connected"])
        for item in debug_dump(hub, debug_token)["participants"]
    )


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


def start_mcp_http(
    hub: str,
    state: pathlib.Path,
    evidence: pathlib.Path,
    *,
    actor: str = "claude",
    wait: float = 0,
    port: int = 0,
    auth_token: str = "",
) -> tuple[subprocess.Popen[str], str, int, str]:
    auth_token = auth_token or secrets.token_hex(24)
    process = subprocess.Popen(
        [
            sys.executable, str(ROOT / "claude-mcp.py"), "--hub", hub, "--state", str(state),
            "--actor", actor, "--wait", str(wait), "--transport", "http", "--port", str(port),
            "--evidence", str(evidence),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "MCP_AUTH_TOKEN": auth_token},
    )
    assert process.stdout
    endpoint = process.stdout.readline().strip()
    if not endpoint:
        assert process.stderr
        raise RuntimeError(process.stderr.read())
    return process, endpoint, urlparse(endpoint).port or 0, auth_token


def mcp_http(endpoint: str, auth_token: str, message: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(message).encode(),
        headers={
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-03-26",
            "Authorization": f"Bearer {auth_token}",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.loads(response.read() or b"{}")
    if value.get("error"):
        raise RuntimeError(value["error"])
    return value


def sse_connect(endpoint: str, auth_token: str) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
    parsed = urlparse(endpoint)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=3)
    connection.request("GET", parsed.path, headers={
        "Accept": "text/event-stream", "Authorization": f"Bearer {auth_token}",
    })
    response = connection.getresponse()
    assert response.status == 200 and response.getheader("Content-Type") == "text/event-stream"
    assert response.readline().startswith(b": heartbeat")
    response.readline()
    return connection, response


def claude_config(path: pathlib.Path, endpoint: str, auth_token: str) -> pathlib.Path:
    path.write_text(json.dumps({"mcpServers": {"hub": {
        "type": "http", "url": endpoint,
        "headers": {"Authorization": f"Bearer {auth_token}"},
    }}}))
    path.chmod(0o600)
    return path


def claude_start(prompt: str, config: pathlib.Path, session: str = "", resume: str = "") -> subprocess.Popen[str]:
    command = [
        "claude", "-p", prompt, "--model", CLAUDE_MODEL,
        "--mcp-config", str(config), "--strict-mcp-config",
        "--allowedTools", CLAUDE_TOOLS, "--output-format", "json",
    ]
    if session:
        command += ["--session-id", session]
    if resume:
        command += ["--resume", resume]
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(SCRATCH),
        start_new_session=True,
    )


def claude_wait(process: subprocess.Popen[str], timeout: float = 300) -> dict[str, Any]:
    stdout, stderr = process.communicate(timeout=timeout)
    for line in reversed(stdout.splitlines()):
        with contextlib.suppress(json.JSONDecodeError):
            value = json.loads(line)
            if isinstance(value, dict) and value.get("type") == "result":
                return value
    raise RuntimeError(f"claude produced no result (rc={process.returncode}): {(stderr or stdout)[-400:]}")


def claude_expect(
    prompt: str, config: pathlib.Path, expect: Callable[[], Any], attempts: int = 2, **kwargs: str
) -> tuple[dict[str, Any], Any]:
    """Run Claude until the Hub shows the expected event; a model turn occasionally skips its tool call."""
    result: dict[str, Any] = {}
    for attempt in range(attempts):
        if attempt and kwargs.get("session"):
            kwargs = {"resume": kwargs["session"]}  # the id exists now, so a retry resumes instead of creating
        result = claude_wait(claude_start(prompt, config, **kwargs))
        with contextlib.suppress(TimeoutError):
            return result, eventually(expect, timeout=15)
    raise AssertionError(f"expected Hub event never appeared; last runtime answer: {result.get('result')!r}")


@contextlib.contextmanager
def check(checks: list[dict[str, Any]], name: str) -> Iterator[dict[str, Any]]:
    """Record one evidence check; a failed model-driven step stays inconclusive instead of losing the run."""
    detail: dict[str, Any] = {"check": name, "status": "pass"}
    checks.append(detail)
    try:
        yield detail
    except Exception as error:
        detail["status"] = "inconclusive"
        detail["error"] = f"{type(error).__name__}: {error}"[:600]


def claude_phase(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Issue #9 closure gate: the HTTP MCP adapter driven by the real Claude CLI."""
    hub, token, pi, pi_evidence = ctx["hub"], ctx["debug_token"], ctx["pi"], ctx["pi_evidence"]
    version = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
    state = ctx["mcp_state"]
    evidence = ctx["mcp_evidence"]
    config = claude_config(
        SCRATCH / "claude-real.mcp.json", ctx["mcp_endpoint"], ctx["mcp_auth"],
    )
    session = str(uuid.uuid4())
    checks: list[dict[str, Any]] = []

    def cursor() -> int:
        return int(json.loads(state.read_text())["last_seq"]) if state.exists() else 0

    def claude_traffic_after(seq: int) -> list[dict[str, Any]]:
        return [
            item for item in debug_dump(hub, token)["events"]
            if item["seq"] > seq and item["actor"] == "claude"
            and item["type"] in {"message", "request", "reply", "broadcast"}
        ]

    with check(checks, "real-claude-code") as detail:
        detail.update({"claude_version": version, "model": CLAUDE_MODEL, "session_id": session})
        pi_command(pi, "send-claude-1", "/hub-send claude ping-real-claude")
        request = eventually(lambda: event(hub, token, "request", "pi", "ping-real-claude"))
        result, reply = claude_expect(
            "Call the hub_next tool to pull peer traffic, then call hub_reply with the correlation_id of the "
            "request event it returned, that event's seq as parent_seq, and text 'pong-real-claude'. Answer DONE.",
            config, lambda: event(hub, token, "reply", "claude", "pong-real-claude"), session=session,
        )
        assert reply["correlation_id"] == request["correlation_id"], "reply lost the request correlation"
        assert reply["parent_seq"] == request["seq"], "reply lost its parent seq"
        pi_command(pi, "inbox-claude-1", "/hub-inbox")
        eventually(lambda: any(
            line.get("action") == "receive" and line.get("event", {}).get("seq") == reply["seq"]
            for line in evidence_lines(pi_evidence)
        ))
        detail.update({"request": request, "reply": reply, "claude_result": result.get("result")})

    with check(checks, "h9-04-claude-exit-session-resumable") as detail:
        eventually(lambda: not actor_online(hub, token, "claude"), timeout=8)
        pi_command(pi, "send-claude-2", "/hub-send claude queued-while-claude-absent")
        queued = eventually(lambda: event(hub, token, "request", "pi", "queued-while-claude-absent"))
        before = cursor()
        assert not claude_traffic_after(queued["seq"]), "traffic appeared with no Claude runtime alive"
        assert before < queued["seq"], "durable cursor already passed the queued request"
        result, delivered = claude_expect(
            "Call the hub_next tool, then call hub_broadcast with the exact payload text of the request it "
            "returned. Answer DONE.", config,
            lambda: event(hub, token, "broadcast", "claude", "queued-while-claude-absent"), resume=session,
        )
        detail.update({
            "queued_seq": queued["seq"], "cursor_before_resume": before, "cursor_after_resume": cursor(),
            "resumed_session": session, "delivered_seq": delivered["seq"], "claude_result": result.get("result"),
        })

    with check(checks, "h9-07-missing-signal-hold") as detail:
        pi_command(pi, "send-claude-3", "/hub-send claude no-pull-no-delivery")
        pending = eventually(lambda: event(hub, token, "request", "pi", "no-pull-no-delivery"))
        before = cursor()
        alive = claude_wait(claude_start("Do not call any tool. Answer exactly ALIVE.", config))
        assert not claude_traffic_after(pending["seq"]), "a live but non-pulling runtime still produced traffic"
        assert cursor() == before, "the durable cursor advanced without a pull"
        result, released = claude_expect(
            "Call the hub_next tool, then call hub_broadcast with text 'released-after-pull'. Answer DONE.", config,
            lambda: event(hub, token, "broadcast", "claude", "released-after-pull"),
        )
        detail.update({
            "pending_seq": pending["seq"], "idle_run_result": alive.get("result"),
            "cursor_while_idle": before, "released_seq": released["seq"], "claude_result": result.get("result"),
            "note": "delivery stayed held without an explicit pull; lease presence stayed separate from readiness",
        })

    with check(checks, "h9-05-unresponsive-recovery") as detail:
        eventually(lambda: not actor_online(hub, token, "claude"), timeout=8)
        head = debug_dump(hub, token)["events"][-1]["seq"]
        records_before = len(evidence_lines(evidence))
        process = claude_start(
            "Call the hub_next tool; it blocks until a peer sends traffic. Then call hub_broadcast with text "
            "'recovered-after-freeze'. Answer DONE.", config,
        )
        ctx["processes"].append(process)
        joined = eventually(lambda: next((
            item for item in debug_dump(hub, token)["events"]
            if item["seq"] > head and item["type"] == "join" and item["actor"] == "claude"
        ), None), timeout=120)
        eventually(lambda: any(
            line.get("pid") == ctx["mcp_process"].pid and line.get("event") == "tool-call"
            and line.get("tool") == "hub_next"
            for line in evidence_lines(evidence)[records_before:]
        ), timeout=120)
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGSTOP)
            frozen_at = debug_dump(hub, token)["events"][-1]["seq"]
            pi_command(pi, "send-claude-4", "/hub-send claude wake-the-frozen-runtime")
            time.sleep(2)
            assert not claude_traffic_after(frozen_at), "the frozen runtime still delivered"
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(process.pid), signal.SIGCONT)
        result = claude_wait(process)
        recovered = eventually(lambda: event(hub, token, "broadcast", "claude", "recovered-after-freeze"), timeout=60)
        detail.update({
            "blocked_pull_join_seq": joined["seq"], "frozen_after_seq": frozen_at,
            "recovered_seq": recovered["seq"], "claude_result": result.get("result"),
            "note": "SIGSTOP/SIGCONT on the Claude process group stands in for a sleeping workstation",
        })

    with check(checks, "h9-06-http-mcp-reconnect") as detail:
        records_before = len(evidence_lines(evidence))
        process = claude_start(
            "Call hub_next. If the MCP server disconnects, keep retrying hub_next until it reconnects. After "
            "hub_next returns a request, call hub_broadcast with text 'recovered-after-mcp-reconnect'. "
            "Do not finish before that broadcast succeeds.",
            config,
        )
        ctx["processes"].append(process)
        old_server = ctx["mcp_process"]
        eventually(lambda: any(
            line.get("pid") == old_server.pid and line.get("event") == "tool-call" and line.get("tool") == "hub_next"
            for line in evidence_lines(evidence)[records_before:]
        ), timeout=120)
        down_seq = debug_dump(hub, token)["events"][-1]["seq"]
        stop(old_server)
        new_server, endpoint, _, _ = start_mcp_http(
            hub, state, evidence, wait=20, port=ctx["mcp_port"], auth_token=ctx["mcp_auth"],
        )
        ctx["mcp_process"] = new_server
        ctx["processes"].append(new_server)
        assert endpoint == ctx["mcp_endpoint"]
        reconnected = eventually(lambda: next((
            line for line in evidence_lines(evidence)[records_before:]
            if line.get("pid") == new_server.pid and line.get("event") == "sse-connect"
        ), None), timeout=30)
        assert process.poll() is None, "Claude exited instead of reconnecting the HTTP MCP transport"
        assert not claude_traffic_after(down_seq), "Claude reported delivery while MCP transport was unavailable"
        pi_command(pi, "send-claude-5", "/hub-send claude release-after-mcp-reconnect")
        result = claude_wait(process)
        recovered = eventually(
            lambda: event(hub, token, "broadcast", "claude", "recovered-after-mcp-reconnect"), timeout=60,
        )
        retried = eventually(lambda: next((
            line for line in evidence_lines(evidence)[records_before:]
            if line.get("pid") == new_server.pid and line.get("event") == "tool-call"
            and line.get("tool") == "hub_next"
        ), None))
        detail.update({
            "old_mcp_pid": old_server.pid, "new_mcp_pid": new_server.pid,
            "claude_pid": process.pid, "reconnect_evidence": reconnected,
            "retried_tool": retried, "recovered_seq": recovered["seq"], "claude_result": result.get("result"),
        })

    return checks


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
        "HUB_HEARTBEAT_MS": "400",
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

        # A dead adapter's lease expires; its replacement resumes from the durable cursor.
        stop(mcp)
        eventually(lambda: not actor_online(hub, debug_token, "claude"), timeout=5)
        pi_command(pi, "send-2", "/hub-send claude queued-for-replacement")
        queued = eventually(lambda: event(hub, debug_token, "request", "pi", "queued-for-replacement"))
        mcp = start_mcp(hub, SCRATCH / "claude-state.json")
        processes.append(mcp)
        replacement_inbox = mcp_tool(mcp, 7, "hub_next")
        assert any(item["seq"] == queued["seq"] for item in replacement_inbox["events"])
        eventually(lambda: actor_online(hub, debug_token, "claude"))

        # The same adapter also speaks minimal Streamable HTTP; an SSE client owns its live lease.
        http_state = SCRATCH / "claude-http-state.json"
        http_evidence = SCRATCH / "claude-http-evidence.jsonl"
        http_mcp, http_endpoint, _, http_auth = start_mcp_http(
            hub, http_state, http_evidence, actor="claude-http",
        )
        processes.append(http_mcp)
        unauthorized = urllib.request.Request(
            http_endpoint, data=b"{}", headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(unauthorized, timeout=3)
            raise AssertionError("HTTP MCP accepted a caller without its bearer secret")
        except urllib.error.HTTPError as error:
            assert error.code == 401
        mcp_http(http_endpoint, http_auth, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "demo", "version": "1"}},
        })
        http_tools = mcp_http(
            http_endpoint, http_auth, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        notification = urllib.request.Request(
            http_endpoint,
            data=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode(),
            headers={
                "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {http_auth}",
            },
        )
        with urllib.request.urlopen(notification, timeout=3) as response:
            assert response.status == 202 and not response.read()
        stream, response = sse_connect(http_endpoint, http_auth)
        mcp_http(http_endpoint, http_auth, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "hub_peers", "arguments": {}},
        })
        eventually(lambda: actor_online(hub, debug_token, "claude-http"))
        response.close()
        stream.close()
        stop(http_mcp)
        eventually(lambda: not actor_online(hub, debug_token, "claude-http"), timeout=5)

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

        checks.extend([
            {"check": "real-pi-rpc-extension", "status": "pass", "commands": ["hub-send", "hub-inbox", "hub-peers"]},
            {"check": "participant-discovery", "status": "pass", "participants": peers},
            {"check": "correlated-request-reply", "status": "pass", "request": request, "reply": reply},
            {"check": "reply-authorization", "status": "pass", "rejected_actor": "intruder"},
            {"check": "broadcast-delivery", "status": "pass", "broadcast": broadcast},
            {"check": "mcp-process-replacement-replay", "status": "pass", "request_seq": queued["seq"]},
            {"check": "online-peer-lease-expiry", "status": "pass", "actor": "claude"},
            {"check": "sqlite-hub-restart-replay", "status": "pass", "events_before": len(before_restart), "events_after": len(after_restart)},
            {"check": "claude-mcp-json-rpc", "status": "pass", "tools": [item["name"] for item in tool_list["result"]["tools"]]},
            {"check": "claude-mcp-streamable-http", "status": "pass", "tools": [item["name"] for item in http_tools["result"]["tools"]]},
        ])

        if REAL_CLAUDE and shutil.which("claude"):
            real_state = SCRATCH / "claude-real-state.json"
            real_evidence = SCRATCH / "claude-real-mcp-evidence.jsonl"
            real_mcp, real_endpoint, real_port, real_auth = start_mcp_http(
                hub, real_state, real_evidence, wait=20,
            )
            processes.append(real_mcp)
            context = {
                "hub": hub, "debug_token": debug_token, "pi": pi, "pi_evidence": pi_evidence,
                "processes": processes, "mcp_process": real_mcp, "mcp_endpoint": real_endpoint,
                "mcp_port": real_port, "mcp_auth": real_auth,
                "mcp_state": real_state, "mcp_evidence": real_evidence,
            }
            checks.extend(claude_phase(context))
        elif REAL_CLAUDE:
            checks.append({
                "check": "real-claude-code", "status": "blocked",
                "reason": "REAL_CLAUDE=1 but the claude CLI is unavailable",
            })
        else:
            checks.append({
                "check": "real-claude-code", "status": "skipped",
                "reason": "set REAL_CLAUDE=1 on a Claude-equipped workstation; this opt-in spends tokens",
            })

        pi_lines = evidence_lines(pi_evidence)
        (SCRATCH / "evidence.json").write_text(json.dumps({"checks": checks, "pi_adapter": pi_lines}, indent=2) + "\n")
        for item in checks:
            print(f"{item['status'].upper():13}{item['check']}")
        held = [item for item in checks if item["status"] != "pass"]
        if held:
            print(f"GATE {len(held)} check(s) did not attest; see .demo/evidence.json")
        return 1 if REAL_CLAUDE and held else 0
    finally:
        for process in reversed(processes):
            stop(process)


if __name__ == "__main__":
    raise SystemExit(main())
