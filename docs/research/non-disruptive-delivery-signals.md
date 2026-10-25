# Non-disruptive delivery signals for Pi and Claude Code

## Concise decision summary

Use two adapters, not one shared implementation:
- **Pi**: implement against Pi’s documented **extension API** first; optionally support **RPC mode** for external supervisors.
- **Claude Code**: implement against **documented CLI + MCP** only; treat **hooks** as auxiliary telemetry/policy, not the primary transport.

For non-disruptive delivery, the safe rule is:
- separate **process liveness** from **turn readiness**;
- deliver queued traffic only at documented safe points;
- if a signal is absent, **do not infer readiness**; hold traffic or require user/supervisor action.

Pi can expose near-deterministic safe points from first-party lifecycle events. Claude Code cannot be made equally deterministic from first-party surfaces alone; for Claude, the adapter must fail conservatively and accept some ambiguity around “ready vs merely alive” and “stuck vs just long-running.”

## Pinned/versioned capability matrix

### Pi
- Package reviewed: `@earendil-works/pi-coding-agent` **0.82.1**.
- Portable public docs are cited in [Sources](#sources); conclusions below were verified against the matching installed package docs for that version.

| Capability | Pi 0.82.1 | Source |
|---|---|---|
| External headless control | Yes, documented RPC over JSONL stdin/stdout | Pi RPC docs |
| Event stream with turn/tool lifecycle | Yes | Pi JSON docs, Pi extensions docs |
| In-process adapter API | Yes, extensions and SDK | Pi extensions docs, Pi SDK docs |
| Queue message while running | Yes: `steer`, `follow_up` | Pi RPC docs, Pi usage docs |
| Explicit abort/interrupt | Yes: RPC `abort`, SDK `abort()`, UI Escape | Pi RPC docs, Pi SDK docs, Pi usage docs |
| Idle/settled signal | Yes: `agent_settled`, `ctx.isIdle()` | Pi extensions docs |
| Session replacement/new session | Yes | Pi RPC docs, Pi extensions docs, Pi sessions docs |
| Session persistence/resume | Yes | Pi sessions docs, Pi session format docs |
| Compaction lifecycle | Yes, explicit events | Pi JSON docs, Pi extensions docs, Pi compaction docs |
| Durable adapter state | Yes via `appendEntry()` and session replay | Pi extensions docs |

### Claude Code
- Docs/version evidence reviewed from current Anthropic first-party docs plus first-party repo examples/changelog references where the docs call out versions.
- Version cues used where docs state them explicitly: agent view introduced in **v2.1.139**; various behaviors pinned to **v2.1.121+**, **v2.1.163+**, **v2.1.182+**, **v2.1.198+**, **v2.1.203+**, **v2.1.212+**, **v2.1.214+**, **v2.1.219+**.

| Capability | Claude Code | Source |
|---|---|---|
| Headless CLI | Yes: `-p` | Anthropic headless docs |
| Structured streaming output | Yes: `--output-format json|stream-json` | Anthropic headless docs, CLI reference |
| Structured input stream | Yes: `--input-format stream-json` | CLI reference |
| Session continue/resume | Yes: `--continue`, `--resume`, `--session-id` | CLI reference, headless docs |
| Background sessions / agent view | Yes | Agent view docs, CLI reference |
| State buckets in UI | Yes: Working, Needs input, Idle, Completed, Failed, Stopped | Agent view docs |
| Distinct process-shape indicator | Yes in agent view UI: alive vs exited vs sleeping | Agent view docs |
| Hooks | Yes | Hooks reference |
| MCP integration | Yes | MCP docs |
| Channel push from MCP | Yes, opt-in via `--channels`; research preview | CLI reference, MCP docs |
| Automatic reconnect for HTTP/SSE MCP | Yes | MCP docs |
| Automatic backgrounding of long MCP tool calls | Yes, main conversation only, v2.1.212+ | MCP docs |
| Plugin packaging | Yes, first-party examples | plugins README |
| Subscription-auth CLI auth | Yes: Claude.ai login and `CLAUDE_CODE_OAUTH_TOKEN` | Authentication docs |
| API-billed SDK/keys | Also supported, but distinct | Authentication docs, SDK/headless docs |

## Exact lifecycle and delivery signals

### 1) Process state: supervisor layer, not adapter layer

Treat these separately from turn/readiness state.

Normalized process states:
- **process-running**: CLI process or supervisor-managed worker is alive.
- **process-exited**: process ended normally or abnormally.
- **process-disconnected**: adapter lost transport/session attachment but process may still exist.
- **process-restarting**: supervisor is reattaching/restarting.

For Claude agent view, Anthropic explicitly distinguishes row state from process shape: `✻`/animated `✽` means process alive and replies immediately; `∙` means process exited but session can be reopened and restarted; `✢` is sleeping loop state. A session stopped from outside Claude Code shows `Stopped`. This is process evidence, not turn-safe-point evidence. Source: Anthropic agent view docs.

For Pi RPC/extension mode, process liveness is external to the agent lifecycle. `agent_start`/`agent_end` do **not** mean process started/exited; they mean one low-level agent run began/ended. Source: Pi extensions docs, Pi JSON docs.

### 2) Pi turn/readiness signals

#### Ready / idle / safe-to-deliver
Use only these as strong safe points:
1. `agent_settled` event: Pi docs say `agent_end` may still be followed by auto-retry, auto-compaction+retry, or queued follow-up processing; use `agent_settled` when you need to know Pi will not continue automatically. Source: Pi extensions docs.
2. `ctx.isIdle() === true`: docs say it is false while Pi is processing an agent run, automatic retry, auto-compaction retry, or queued continuation. Source: Pi extensions docs.
3. RPC `get_state` with `isStreaming: false`, `isCompacting: false`, and `pendingMessageCount: 0` is useful evidence, but weaker than `agent_settled` because it is a sampled state, not an edge-triggered lifecycle event. Source: Pi RPC docs.

#### Executing
Any of the following indicates active execution:
- `agent_start`
- `turn_start`
- `message_update` on assistant stream
- `tool_execution_start` until corresponding completion
- RPC `get_state.isStreaming === true`
- `ctx.isIdle() === false`

#### Stopped / interrupted
- RPC `abort` is documented.
- SDK `abort()` is documented.
- Interactive Escape aborts current operation and restores queued messages to editor. Source: Pi RPC docs, Pi SDK docs, Pi usage docs.

#### Disconnected
- Loss of RPC transport/stdout stream or extension host shutdown.
- `session_shutdown` is the documented lifecycle event for intentional teardown and session replacement. Source: Pi extensions docs.

#### Unresponsive
There is no separate first-party “hung” event. Infer only from external watchdogs:
- process still alive,
- no event progress for longer than local timeout budget,
- not in documented waiting states like active tool execution or compaction.

That remains an adapter policy, not a Pi guarantee.

### 3) Claude Code turn/readiness signals

#### Ready / idle / safe-to-deliver
Strong documented first-party signals:
1. **Agent view `Idle`** row state: “The session has nothing to do and is ready for your next prompt.” Source: Anthropic agent view docs.
2. **Headless `stream-json` final `result` event** for a one-shot `claude -p` run. This safely marks that invocation complete. Source: Anthropic headless docs.

Prototype-only guidance, not a first-party safe-point guarantee:
- **Session reopened/resumed and no background work indicated** can be used as a conservative adapter hint only if the adapter also lacks contradictory evidence. Anthropic does not document this as a machine-readable ready contract equivalent to Pi.

#### Executing
- Agent view `Working`: “Claude is actively running tools or generating a response.” Source: Anthropic agent view docs.
- In headless mode, streaming events before final `result` indicate execution is in progress. Source: Anthropic headless docs.
- Long-running MCP tool calls may move to background after two minutes in main conversation on v2.1.212+, and Claude receives a task ID while continuing. This means “not blocked” is not the same as “done.” Source: Anthropic MCP docs.

#### Stopped / interrupted
- Docs explicitly mention `Stopped` state when session was stopped with `Ctrl+X` or `claude stop`, or its process ended from outside Claude Code. Source: Anthropic agent view docs.
- For `claude -p`, SIGTERM aborts the in-progress turn, terminates running Bash process tree, runs `SessionEnd` hooks, and exits with code 143. Source: Anthropic headless docs.

#### Disconnected
- Background sessions continue without an attached terminal; process/session survive closing shell and agent view. Source: Anthropic agent view docs.
- MCP HTTP/SSE servers auto-reconnect; stdio servers do not. Source: Anthropic MCP docs.
- Therefore terminal detach is not a stop signal.

#### Unresponsive
- Anthropic documents a real unresponsive case: a session mid-response can return unresponsive after sleep; opening it causes supervisor restart and continuation of interrupted response. Source: Anthropic agent view docs.
- Beyond that, there is no documented local machine-readable “hang” signal. Any hang detection remains heuristic.

## Normalized adapter state model

Use two orthogonal state machines.

### A. Process state
- `RUNNING`
- `EXITED`
- `DISCONNECTED`
- `RESTARTING`

### B. Turn/readiness state
- `READY`: safe to inject immediately.
- `EXECUTING`: model/tool work in progress.
- `WAITING_USER`: needs human input/permission; not safe to silently inject runtime traffic unless policy explicitly allows it.
- `STOPPED`: interrupted or explicitly stopped; session resumable/restartable but not currently executing.
- `UNRESPONSIVE`: process/session exists but no trustworthy progress and no trustworthy ready signal.
- `REPLACING_SESSION`: new/resume/fork/compact transition in progress; freeze deliveries.

### Mapping

#### Pi
- `READY`: after `agent_settled` and `ctx.isIdle()` true.
- `EXECUTING`: from `agent_start` until `agent_settled`, including auto-retry and queued continuation.
- `WAITING_USER`: no explicit first-party state bucket; infer only from explicit extension/RPC UI interactions if your adapter introduces them.
- `STOPPED`: after abort completion or session shutdown without replacement continuation.
- `UNRESPONSIVE`: watchdog only.
- `REPLACING_SESSION`: between documented `session_shutdown` of old instance and `session_start` of new instance.

#### Claude Code
- `READY`: agent view `Idle`, or headless invocation final `result`.
- `EXECUTING`: agent view `Working`, or headless stream before final `result`.
- `WAITING_USER`: agent view `Needs input`.
- `STOPPED`: agent view `Stopped`, or signaled headless termination.
- `UNRESPONSIVE`: documented post-sleep unresponsive case, or watchdog-only heuristic.
- `REPLACING_SESSION`: **adapter-inferred only** around `--resume`, `--continue`, new background session dispatch, or reopen-after-exit; reviewed first-party docs do not expose a dedicated lifecycle hook or state bucket for external adapters.

## Safe-point / delivery algorithm

Goal: release queued traffic only when delivery is non-disruptive, and start acknowledgement timing only after actual delivery.

### Delivery contract
Each queued message has:
- `queueId`
- `targetSession`
- `payload`
- `deliveryClass` = `immediate-safe-point | steer | follow-up`
- `enqueuedAt`
- `deliveredAt` (null until actual injection)
- `ackClockStartAt` (null until actual injection)
- `terminalOutcome`

### Algorithm
1. **Observe process state** separately. If process is not `RUNNING`, do not deliver.
2. **Observe readiness state**.
3. If readiness is `READY`, deliver now.
4. If readiness is `EXECUTING`:
   - **Pi**: if policy allows same-session queued traffic, inject with `steer` for “deliver at next turn boundary before next LLM call” or `follow_up` for “deliver after run finishes.” This is documented and safe. Source: Pi RPC docs, Pi usage docs.
   - **Claude**: do **not** assume an equivalent safe injected queue exists unless your adapter itself owns an MCP channel/tool contract that explicitly stages delivery. Without that, hold until `Idle` or send through an MCP/channel path whose own semantics guarantee deferred presentation.
5. If readiness is `WAITING_USER`, hold unless policy says runtime traffic may break the wait. Default conservative behavior: hold.
6. If readiness is `STOPPED`, `UNRESPONSIVE`, or `REPLACING_SESSION`, hold.
7. Set `deliveredAt` and start acknowledgement timing **only when the adapter has actually handed the message to the target runtime**:
   - Pi RPC: on successful `prompt`/`steer`/`follow_up` response, because docs define success as accepted/queued/handled immediately. Source: Pi RPC docs.
   - Pi extension: when `sendMessage()`/`sendUserMessage()` returns successfully or equivalent adapter-local persistence confirms queued acceptance.
   - Claude headless one-shot: **prototype adapter guidance only** — start timing when the adapter has concrete transport evidence that stdin/JSON input was written successfully to the spawned invocation and the process is still alive. Reviewed Anthropic docs do not separately guarantee this as a first-party acceptance contract.
   - Claude MCP/channel: only when the MCP/channel transport confirms delivery into the session/channel, not when the Hub enqueues locally.
8. Terminal acknowledgement is separate from delivery acceptance. Delivery acceptance means “runtime accepted the traffic.” Business-level ack may require downstream observable effects.

### Pull-based delivery
Recommended default for both:
- Hub keeps queue.
- Adapter polls or subscribes for safe-point state.
- Adapter **pulls** the next deliverable message only when state permits.

Why:
- Pi gives enough signals to do this precisely.
- Claude lacks equally deterministic push-safe-point semantics.
- Pull-based flow cleanly supports “ack timing begins only after actual delivery,” because dequeue can coincide with real injection.

## Failure / recovery matrix

| Case | Pi handling | Claude handling | Conservative rule |
|---|---|---|---|
| Long turn | Use `steer` or `follow_up`; `agent_end` alone is insufficient, wait for `agent_settled` if you need full idle | Hold unless your MCP/channel contract explicitly supports deferred presentation; `Working` may continue while background tasks/MCP tasks exist | Never infer idle from silence alone |
| Manual interrupt | RPC `abort`; observe post-abort idle/settled before releasing held traffic | `Ctrl+X`/`claude stop`/SIGTERM lead to `Stopped` or exit; require explicit resume/new run before delivery | Treat interrupt as stop, not safe-point |
| Process exit | Reattach/restart by session file/session id; session persists unless `--no-session` | Background session may show exited process shape `∙` and can restart on attach/reply | Hold until process and readiness both re-established |
| Hang / no progress | Watchdog only; if process alive but no progress, mark `UNRESPONSIVE` | Same; Anthropic documents post-sleep unresponsive recovery on reopen | Escalate; do not deliver |
| Disconnect | RPC stream loss => process state unknown; re-query on reconnect | Detached terminal is normal for background sessions; not a stop signal | Separate transport loss from session stop |
| Reconnect | Rebuild from session state and file/session id | Reopen session via resume/attach; supervisor may restart worker | Resume only after fresh state sample |
| Compaction | Freeze during `compaction_start`..`compaction_end`; use settled/idle after retry path resolves | No deterministic equivalent documented for external adapters | If compaction signal missing, assume not safe |
| New-session command | `session_shutdown` old instance, then `session_start` new; all old session-bound handles stale | `--resume`/new background session changes target session identity; docs lack low-level external hook | Bind queue to stable session identity and require explicit remap |
| Needs input / permissions | Adapter may see via extension UI or own policy | Agent view `Needs input` is explicit | Default hold |

## Compaction and session-replacement behavior

### Pi
Pi is explicit:
- JSON mode emits `compaction_start` and `compaction_end`.
- Extensions get `session_before_compact` and `session_compact`.
- Overflow/threshold/manual reasons are distinguished.
- `agent_end` can be followed by auto-compaction and retry; `agent_settled` is the safe “nothing else automatic will run” marker.
- Session replacement is explicit: `session_shutdown` old instance, then new runtime/extension binding, then `session_start`; old captured session objects become stale. Sources: Pi JSON docs, Pi extensions docs, Pi compaction docs.

Adapter rule for Pi:
- freeze outbound delivery during compaction and session replacement;
- remap any queue by session file/session id only after the replacement session announces itself;
- discard stale in-memory handles on `session_shutdown`.

### Claude Code
Anthropic docs reviewed here do not expose a comparable external compaction lifecycle. Session continuation/resume is documented, and background sessions persist on disk across restarts/sleep, but compaction is not surfaced as an external adapter event in the reviewed first-party docs.

Adapter rule for Claude:
- do not assume compaction visibility;
- treat session resume/reopen as possible context replacement;
- require a fresh post-resume ready signal (`Idle` or completed one-shot result) before releasing held traffic.

## Documented guarantees vs prototype-only assumptions

### Documented and strong

#### Pi
- RPC request/response correlation and queued-delivery semantics for `prompt`, `steer`, `follow_up`. (Pi RPC docs)
- Event types for lifecycle, tool execution, queue updates, compaction. (Pi JSON docs)
- `agent_settled` meaning and `ctx.isIdle()` semantics. (Pi extensions docs)
- Session replacement lifecycle and stale-handle warning. (Pi extensions docs)
- Session persistence and JSONL session format. (Pi sessions docs, Pi session format docs)

#### Claude Code
- `-p`, `--output-format json|stream-json`, `--input-format stream-json`. (Anthropic headless docs, CLI reference)
- `--continue`, `--resume`, `--session-id`. (CLI reference, Anthropic headless docs)
- Agent view state buckets and separate process-shape indicator. (Anthropic agent view docs)
- Background sessions persist through terminal close, supervisor restart, auto-updates, and sleep; unresponsive-after-sleep recovery on open is documented. (Anthropic agent view docs)
- Hooks lifecycle and async-hook limitations. (Anthropic hooks docs)
- MCP reconnect behavior, long-call backgrounding, channels capability, and channel opt-in flag. (Anthropic MCP docs, CLI reference)
- Auth precedence and distinction between subscription CLI auth and API-key/bearer/API-billed paths; bare mode does not read `CLAUDE_CODE_OAUTH_TOKEN`. (Anthropic authentication docs, Anthropic headless docs)

### Prototype-only / assumption-heavy
- Any Claude adapter that depends on scraping terminal text, inferring row state outside documented machine APIs, or simulating keypresses.
- Treating hooks as a durable bidirectional transport.
- Treating “reopened/resumed and no background work indicated” as a ready signal rather than an adapter-owned inference.
- Treating stdin write success or process spawn success as a documented first-party acceptance guarantee for queued Claude input.
- Treating `REPLACING_SESSION` as a first-party Claude lifecycle state rather than an adapter normalization.
- Assuming Claude has a Pi-like “deliver-after-current-turn-before-next-LLM-call” external queue primitive.
- Assuming absence of output means idle rather than waiting, backgrounded, disconnected, or hung.
- Assuming Claude compaction can be observed externally from reviewed first-party surfaces.

## Reproducible future harness contract for map issues #10 and #11

These are **required future harness contract shapes**, not claims about commands that already exist. The point is to make independent reproduction possible later without inventing undocumented runtime behavior now.

### Required harness command shape

```text
adapter-harness run \
  --runtime <pi-extension|pi-rpc|claude-headless|claude-bg-mcp> \
  --case <TEST-ID> \
  --fixture <fixture-id> \
  --evidence-out <path>
```

Required evidence artifact per run:
- `testId`
- `runtime`
- `fixtureId`
- `observedProcessStateTimeline[]`
- `observedReadinessStateTimeline[]`
- `queueEvents[]` with `enqueuedAt`, `deliveredAt`, `ackClockStartAt`, `terminalOutcome`
- `runtimeEvents[]` copied from the real runtime surface used by that adapter
- `pass`
- `failureReason`

### Required fixtures
- `pi-idle-session`: Pi session already settled and idle.
- `pi-long-turn`: Pi task that emits multiple stream/tool events before settling.
- `pi-compaction`: Pi session configured or scripted to trigger compaction.
- `claude-idle-bg-session`: Claude background session observed as `Idle`.
- `claude-working-bg-session`: Claude background session observed as `Working`.
- `claude-needs-input-session`: Claude session parked in `Needs input`.
- `claude-headless-long-turn`: one-shot `claude -p --output-format stream-json` fixture with observable pre-result events.
- `mcp-reconnectable-server`: HTTP or SSE MCP server fixture that can be severed and restored.

### Observable input rules
- Pi tests must use only documented Pi surfaces: extension callbacks, JSON events, RPC responses, `get_state`, `abort`, `compact`, `new_session`, `steer`, `follow_up`.
- Claude tests must use only documented Anthropic surfaces: agent view states, headless JSON stream events, CLI flags, MCP reconnect behavior, channels when explicitly enabled.
- If a test needs a state the docs do not expose directly, the harness must mark that state as adapter-inferred in the evidence.

### Issue #10: delivery gating and acknowledgement timing

#### H8-01 ready-state immediate delivery
- Command shape: `adapter-harness run --runtime pi-rpc --case H8-01 --fixture pi-idle-session --evidence-out out/H8-01.json`
- Also run with `claude-bg-mcp` + `claude-idle-bg-session`.
- Observable input: idle/ready evidence already present before enqueue.
- Pass evidence:
  - `deliveredAt` is populated immediately after enqueue.
  - `ackClockStartAt == deliveredAt`.
  - no prior runtime event shows executing/waiting state at delivery time.
- Fail evidence:
  - `ackClockStartAt == enqueuedAt` when delivery happened later, or delivery occurs without ready evidence.

#### H8-02 executing-state deferred delivery
- Command shape: `adapter-harness run --runtime <pi-rpc|claude-bg-mcp> --case H8-02 --fixture <pi-long-turn|claude-working-bg-session> --evidence-out out/H8-02.json`
- Observable input:
  - Pi fixture must show active execution before queue injection.
  - Claude fixture must show `Working` before queue injection.
- Pass evidence:
  - Pi: evidence shows queued `steer` acceptance during execution and release at the documented turn boundary, not before.
  - Claude: evidence shows local hold until `Idle` or explicit MCP/channel contract completion.
  - `ackClockStartAt` is absent until actual runtime acceptance.
- Fail evidence:
  - delivery during Claude `Working` with no explicit channel contract, or Pi delivery before the documented boundary.

#### H8-03 after-finish delivery
- Command shape: `adapter-harness run --runtime <pi-rpc|claude-bg-mcp> --case H8-03 --fixture <pi-long-turn|claude-working-bg-session> --evidence-out out/H8-03.json`
- Observable input: queue message arrives while runtime is executing.
- Pass evidence:
  - Pi: `follow_up` accepted during run, delivered only after the active run finishes.
  - Claude: message remains locally queued until `Idle` evidence appears.
- Fail evidence:
  - message marked delivered before finish/idle.

#### H8-04 needs-input hold
- Command shape: `adapter-harness run --runtime claude-bg-mcp --case H8-04 --fixture claude-needs-input-session --evidence-out out/H8-04.json`
- Pi variant may use adapter-owned waiting fixture if one exists.
- Observable input: readiness state is `Needs input` or adapter-owned equivalent.
- Pass evidence: queue item remains pending; no runtime delivery event occurs.
- Fail evidence: silent injection while waiting with no override policy recorded.

#### H8-05 interrupt during queued traffic
- Command shape: `adapter-harness run --runtime <pi-rpc|claude-headless> --case H8-05 --fixture <pi-long-turn|claude-headless-long-turn> --evidence-out out/H8-05.json`
- Observable input: queue message while busy, then interrupt with documented stop/abort path.
- Pass evidence:
  - item is not marked delivered unless runtime already accepted it;
  - evidence clearly shows whether item stayed pending, was requeued, or was canceled by policy.
- Fail evidence: adapter fabricates delivery/ack timestamps after interrupt without runtime acceptance evidence.

#### H8-06 exit before delivery
- Command shape: `adapter-harness run --runtime <pi-rpc|claude-bg-mcp> --case H8-06 --fixture <pi-long-turn|claude-working-bg-session> --evidence-out out/H8-06.json`
- Observable input: enqueue while not ready, then terminate process before release.
- Pass evidence: no `deliveredAt`; no `ackClockStartAt`; process timeline shows exit before readiness.
- Fail evidence: ack clock starts despite process exit before delivery.

#### H8-07 reconnect after exit
- Command shape: `adapter-harness run --runtime <pi-rpc|claude-bg-mcp> --case H8-07 --fixture <pi-idle-session|claude-idle-bg-session> --evidence-out out/H8-07.json`
- Observable input: session exits, resumes, then becomes ready again.
- Pass evidence: held queue releases only after fresh ready evidence post-resume.
- Fail evidence: queue releases on reconnect alone with no ready evidence.

### Issue #11: recovery, replacement, and conservative failure

#### H9-01 Pi compaction freeze
- Command shape: `adapter-harness run --runtime pi-rpc --case H9-01 --fixture pi-compaction --evidence-out out/H9-01.json`
- Observable input: compaction triggered via documented manual or RPC path.
- Pass evidence: no outbound delivery between `compaction_start` and post-`agent_settled` idle.
- Fail evidence: delivery occurs during compaction window.

#### H9-02 Pi auto-compaction+retry path
- Command shape: `adapter-harness run --runtime pi-extension --case H9-02 --fixture pi-compaction --evidence-out out/H9-02.json`
- Observable input: fixture triggers `agent_end` followed by compaction/retry path.
- Pass evidence: adapter does not treat `agent_end` alone as idle; release happens only after `agent_settled` and idle evidence.
- Fail evidence: held queue released after `agent_end` but before settle.

#### H9-03 Pi new session / resume replacement
- Command shape: `adapter-harness run --runtime pi-rpc --case H9-03 --fixture pi-idle-session --evidence-out out/H9-03.json`
- Observable input: `new_session` or equivalent replacement path.
- Pass evidence: old session-bound handles become invalid in evidence; queue remains bound to original identity until explicit remap.
- Fail evidence: stale handle still receives delivery or queue silently jumps sessions.

#### H9-04 Claude background process exit but session resumable
- Command shape: `adapter-harness run --runtime claude-bg-mcp --case H9-04 --fixture claude-idle-bg-session --evidence-out out/H9-04.json`
- Observable input: process exits while session remains resumable.
- Pass evidence: queue stays held until resumed session later emits ready evidence.
- Fail evidence: queue releases on “session resumable” alone.

#### H9-05 Claude sleep/unresponsive recovery
- Command shape: `adapter-harness run --runtime claude-bg-mcp --case H9-05 --fixture claude-working-bg-session --evidence-out out/H9-05.json`
- Observable input: harness records documented unresponsive/reopen recovery path if environment can reproduce it.
- Pass evidence: no delivery while unresponsive; release only after recovered ready state.
- Fail evidence: delivery occurs during unresponsive window.

#### H9-06 Claude MCP disconnect/reconnect
- Command shape: `adapter-harness run --runtime claude-bg-mcp --case H9-06 --fixture mcp-reconnectable-server --evidence-out out/H9-06.json`
- Observable input: sever HTTP/SSE MCP transport, then restore it.
- Pass evidence: reconnect attempts appear in evidence; no channel/tool-dependent delivery while MCP transport is unavailable.
- Fail evidence: adapter reports delivery success while required MCP transport is disconnected.

#### H9-07 missing-signal conservative fail
- Command shape: `adapter-harness run --runtime <pi-rpc|claude-bg-mcp> --case H9-07 --fixture <pi-long-turn|claude-working-bg-session> --evidence-out out/H9-07.json`
- Observable input: withhold or suppress ready evidence while keeping process alive.
- Pass evidence: adapter surfaces `state unknown`/hold behavior rather than `READY`.
- Fail evidence: adapter infers ready from silence alone.

## Smallest adapter seams

### Pi
Prefer this seam order:
1. **Extension seam** for in-session readiness, safe-point observation, durable adapter state, and exact lifecycle handling.
2. **RPC seam** for external control plane and supervisor integration.
3. Avoid TUI scraping.

Minimal Pi adapter surface:
- subscribe to `agent_start`, `agent_settled`, `session_start`, `session_shutdown`, `session_before_compact`/`session_compact` or JSON compaction events,
- use `ctx.isIdle()`,
- inject via `sendMessage`/`sendUserMessage` or RPC `prompt`/`steer`/`follow_up`,
- persist adapter queue metadata in session entries if exact restart recovery is needed.

### Claude Code
Prefer this seam order:
1. **MCP server + optional channels** as the runtime integration seam.
2. **Headless `-p` with `stream-json`** for one-shot scripted turns and future harnesses.
3. **Background sessions / agent view** for long-lived human-visible sessions.
4. Hooks only for notifications/policy glue.
5. Avoid terminal automation.

Minimal Claude adapter surface:
- one MCP server exposing hub tools/resources,
- optional `claude/channel` capability when preview channels are allowed,
- session launch/resume through documented CLI flags,
- external watchdog on session/process state,
- no dependence on plugin internals beyond packaging/distribution.

## What cannot be made deterministic for Claude Code

From reviewed first-party surfaces, these remain non-deterministic or at least not strongly machine-guaranteed:
- a Pi-equivalent external safe-point primitive for “deliver after current tool batch but before next model call”;
- a documented local RPC/state API for background sessions comparable to Pi RPC `get_state` + lifecycle events;
- an externally visible compaction lifecycle;
- reliable distinction between “still working quietly”, “backgrounded long task”, “temporarily disconnected”, and “hung” without additional adapter-owned instrumentation;
- guaranteed automatic inbound delivery semantics outside explicit MCP/channel transport contracts;
- universal availability of channels, since CLI docs label `--channels` as research preview.

So for Claude the adapter must assume:
- **alive != ready**,
- **silent != idle**,
- **session resumable != safe to inject now**.

## Residual risks and recommended decision implications

### Residual risks
- Claude channel support is preview-gated and may vary by environment/policy.
- Claude auth mode changes behavior: `--bare` disables subscription-token path, so headless automation can silently shift from subscription-authenticated CLI assumptions to API-key assumptions if launched incorrectly.
- Claude background/MCP/tool behavior can continue after apparent foreground turn completion.
- Pi hang detection is still heuristic; no explicit hung-state event exists.
- Cross-runtime normalization will necessarily be asymmetric: Pi can be precise; Claude can only be conservative.

### Recommended decision implications
1. **Approve asymmetric adapters.** Do not force a fake common transport abstraction that assumes both CLIs expose the same readiness semantics.
2. **For Pi, build against extensions first.** RPC is the outer control seam, not the only seam.
3. **For Claude, build around MCP plus optional channels.** Use headless `stream-json` for tests and single-turn automation.
4. **Make Hub delivery pull-based.** The adapter should request work only when it has a trustworthy safe point.
5. **Start ack timing only on runtime acceptance.** For Pi RPC that is the successful command response; for Claude it must be the MCP/channel or invocation-level acceptance point, not Hub enqueue time.
6. **Default to hold on ambiguity.** If no strong ready signal exists, do not deliver.
7. **Treat process liveness and readiness as separate axes everywhere.** Especially for Claude background sessions.

## Sources

### Kept
- npm package metadata for `@earendil-works/pi-coding-agent` 0.82.1: <https://www.npmjs.com/package/%40earendil-works/pi-coding-agent/v/0.82.1> — public version pin.
- Pi package README: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/README.md> — package/repo entry point.
- Pi extensions docs: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/docs/extensions.md> — lifecycle, idle/settled, replacement, persistence.
- Pi RPC docs: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/docs/rpc.md> — command semantics, state sampling, abort, new session.
- Pi JSON docs: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/docs/json.md> — event stream and compaction events.
- Pi SDK docs: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/docs/sdk.md> — programmatic session controls.
- Pi sessions docs: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/docs/sessions.md> — persistence and resume behavior.
- Pi session format docs: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/docs/session-format.md> — durable session identity and message tree semantics.
- Pi compaction docs: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/docs/compaction.md> — compaction lifecycle and retry interactions.
- Pi usage docs: <https://github.com/earendil-works/pi/blob/v0.82.1/packages/coding-agent/docs/usage.md> — interactive queueing and abort behavior.
- Anthropic CLI reference: <https://docs.anthropic.com/en/docs/claude-code/cli-usage> — flags for resume, bg, channels, session-id.
- Anthropic headless docs: <https://docs.anthropic.com/en/docs/claude-code/headless> — `-p`, stream-json, SIGTERM, session continuation.
- Anthropic MCP docs: <https://docs.anthropic.com/en/docs/claude-code/mcp> — reconnect, channels, long tool calls, backgrounding.
- Anthropic hooks docs: <https://docs.anthropic.com/en/docs/claude-code/hooks> — lifecycle, async limitations.
- Anthropic agent view docs: <https://docs.anthropic.com/en/docs/claude-code/agent-view> — session state buckets, process-shape distinction, restart/sleep behavior.
- Anthropic authentication docs: <https://docs.anthropic.com/en/docs/claude-code/authentication> — subscription vs API auth and OAuth token precedence.
- Anthropic SDK overview: <https://docs.anthropic.com/en/docs/claude-code/sdk> — used only to distinguish SDK/API agents from CLI runtime paths.
- First-party plugins README: <https://github.com/anthropics/claude-code/blob/main/plugins/README.md> — plugin packaging/examples.

### Dropped
- Internal workspace scratch report — not a public source.
- Absolute local install paths — replaced with portable package/version references and stable public docs.
- General GitHub-rendered Claude changelog page fetched without stable readable content — not reliable enough for citation here.
- Non-first-party commentary and SEO pages — excluded.
- Any channel docs URL not directly retrievable in this run — replaced with CLI/MCP docs that explicitly mention channels.
