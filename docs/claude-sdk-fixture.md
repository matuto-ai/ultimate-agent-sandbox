# Supported TypeScript fixture receiver (#71)

This is the fixed account-free default `uas.claude_runtime.FixtureClaudeReceiver`,
not a production authority or provider qualification. It uses the supported SDK
seam proved below; the old `DirectClaudeDiagnosticReceiver` remains explicit
historical test code, never an automatic fallback. Main's Run-admission and
Forge work are preserved; Claude cross-Run reset/admission is still unqualified.

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
The Python boundary verifies the owned host/native parent and start identities.
It never promotes the wrapper PID to native authority or clears an unknown
intent because a replacement host reports idle.

The receiver exclusively owns the host's wait/reap lifecycle. Held host/native
pidfds provide operational liveness and identity-targeted termination; ordinary
observations never call `Popen.poll()` or reap the host. Close checks waitable
ownership using `waitid(P_PIDFD, ..., WNOWAIT)`, disposes the owned session group
while its leader is still unreaped, and only then waits/reaps. An already reaped
or unverifiable leader permits no numeric group signal: only held identities
are terminated. No process scan or generic kill fallback is used. Constructor
and close faults still release pipes, pidfds and journal ownership; close is
idempotent. Network-free synthetic lifecycle tests are not native SDK evidence.

The local fixture protocol admits only correlated `probe`, `send` and `close`
commands; it cannot execute an arbitrary command or change native options.
Frames, output buffering and the input slot are bounded. Native control and
listing deadlines fail closed and close the owned query/child. Native replay
frames are forwarded as public SDK messages together with the host policy's
explicit fence; Python applies that fence before considering any ACK. No private
control frames are exposed through this protocol. A send's `released` response is not a receipt.

Fresh HOME/environment, empty tools/MCP, dummy fixture key and no-upstream
loopback gateway remain mandatory. CI's disposable loopback-only network
namespace is the real network boundary; source interface/route guards are
defense in depth. No paid bootstrap, invisible no-op, permission bypass, native
mode fallback, credentials or user-host changes are allowed.

## Actual supported native proof

[CI job 121712886783](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40362928254/job/121712886783)
passed all 32 Claude cases in 32.6 seconds on head
`43d68725e59238f6de027cbdbc031933d95a1ae1` (SDK-host qualification stage).
An empty input stream and another sample after 2.2 seconds were safe with **zero
HTTP requests of any method to the gateway**. Held work was busy; a second input
was rejected before release. Exact UUID/content/session replay ACKs passed
through the public SDK; native same-session/new-PID resume retained the prior
nonce exactly once in the next genuine turn. SIGSTOP of the exact owned native
PID made a new public control round trip time out and fence, without any gateway
request. A newly spawned listing process alone is still not responsiveness.

## Durable integration and limits

The default receiver has no `refresh()` API and sends no constructor user turn.
`observe()` and the fixed host's send gate obtain new non-model evidence, rather
than extending a two-second result lease. Missing/duplicate identity, waiting,
background work, attention, unknown events, a stopped/stale target or lost
control response hold. Initial SDK initialization alone is never readiness.

The narrow shared SQLite journal commits immutable intent before the local host
handoff. Only an exact native replay ACK can be persisted and returned to the Hub
for its response clock. A released host input, model request or terminal result
is not a receipt. ACK need not precede the model response/completion: blocking
all provider response bytes can also delay replay ACK.

Only provable pre-effect rejection may be durably classified retryable with the
same logical/native message ID. Before retry, new non-model evidence is required
and intent is re-armed as unknown. Partial local frames, missing ACK, receipt
commit failure or classification failure stay unknown; resume and an otherwise
idle native process cannot clear them or route other traffic around them.
Nonblocking writes recheck asynchronous fences before each remaining chunk.

The same mandatory native gate includes Hub receipt/clock gating, real busy
retention, loss-of-return reconciliation, actual history resume, stale scope,
receipt/classification crash windows, owned-host partial-pipe uncertainty and
native SIGSTOP. Source fault/parser tests are labeled separately. In particular,
requires_action/missing-identity coverage is **not** actual permission-path proof.
Tool-bearing profiles, production Supervisor authority, real authenticated
inference, native reset, compaction and MCP reconnect remain unqualified.

The existing automatic Claude job retains its two-minute limit and existing
triggers. Qualification and adapter changes stay in one draft PR;
work exceeding the normal CI budget must move to a deliberate gate, not extend
automatic CI timeouts.

A separate [manual native-permission qualification fixture](claude-permission-qualification.md)
now prepares one explicitly decided Read request. Its native scenarios are not
yet executed; it neither expands this default profile nor qualifies Hub delivery
during permission waits.
