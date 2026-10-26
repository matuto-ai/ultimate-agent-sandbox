# Supported TypeScript seam qualification (#71)

This is a controlled native prototype on main `d38aa9f6527d4d124f1f645ce0a946a6b61334ec`,
not a production adapter promotion. The direct-CLI fixture, durable handoff journal,
Hub semantics and unknown-intent holds are unchanged during this first stage.

## Fixed public surfaces

* Official `@anthropic-ai/claude-agent-sdk@0.3.310`, whose package and
  [release](https://github.com/anthropics/claude-agent-sdk-typescript/releases/tag/v0.3.310)
  identify Claude Code 2.1.310 compatibility. The existing exact native binary
  hash is enforced; the SDK's optional additional binaries are not installed.
* Public `query()` with an open AsyncIterable that initially yields nothing;
  `pathToClaudeCodeExecutable`, fixed fixture options, and documented
  `spawnClaudeCodeProcess`. No custom Transport or handcrafted Claude control
  request. The SDK alone reads/writes the native process's streams.
* Public `mcpServerStatus()` is a fresh correlated control round trip, **liveness
  only**. It never substitutes for independent exact PID/session idle evidence.
* Documented replay-user-messages plus public `SDKUserMessageReplay` preserve
  the exact UUID, session ID, content, top-level parent and `isReplay` receipt.
  Released input and terminal completion are not acceptance receipts.
* Documented `CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS=1` exposes idle/running/
  requires_action. Unknown, attention, pending work and unexpected activity
  hold. Missing/duplicate/mismatched listing identity, background work, changed
  process start identity and stale/unresponsive control also hold.

## Authority, containment and local protocol

`runtime/claude/sdk-host.mjs` is an SDK-owned **fixture** child, not a
Supervisor-owned native Participant badge. Host PID and native PID are separate.
The eventual Python journal boundary must not promote a wrapper PID to native
authority or clear an unknown intent because a replacement host reports idle.

The local fixture protocol admits only correlated `probe`, `send` and `close`
commands; it cannot execute an arbitrary command or change native options.
Frames, output buffering and the input slot are bounded. Native control and
listing deadlines fail closed and close the owned query/child. Native replay
frames are forwarded as public SDK messages; no private control frames are
exposed through this protocol. A send's `released` response is not a receipt.

Fresh HOME/environment, empty tools/MCP, dummy fixture key and no-upstream
loopback gateway remain mandatory. CI's disposable loopback-only network
namespace is the real network boundary; source interface/route guards are
defense in depth. No paid bootstrap, invisible no-op, permission bypass, native
mode fallback, credentials or user-host changes are allowed.

## First native proof and limits

The pending native gate must prove no-input readiness and another safe sample
after two seconds without **any** gateway request; busy traffic retention;
exact native replay ACK; actual same-session restored history; and a SIGSTOPped
idle target whose new control request times out/fences without contacting the
gateway. Source policy tests separately cover attention, malformed/duplicate/
missing identities and unknown signals; they are not actual permission-path
evidence. Tool-bearing permission profiles and production authority remain
unqualified. Durable Hub integration and unknown-intent regressions are required
before this prototype can replace synthetic bootstrap/refresh.

The existing automatic Claude job retains its two-minute limit and existing
triggers. Qualification and any eventual adapter changes stay in one draft PR;
work exceeding the normal CI budget must move to a deliberate gate, not extend
automatic CI timeouts.
