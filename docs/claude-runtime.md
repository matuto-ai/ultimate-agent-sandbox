# Claude Code conservative fixture seam (#71)

## Pre-implementation decision and evidence boundary

The exact `fe32b7a5af4ea6df4d86d77c67a379091597eded` source tree, issue #71,
specification #58, the existing MCP prototype, and delivery-signals research
were inspected before implementation. The first bounded experiment selects
official Claude Code **2.1.310**, not a fake Claude process.

The account-free test uses the documented `ANTHROPIC_BASE_URL` gateway route
and a newly generated, fixture-only API-key string. The server binds loopback,
has no upstream, and returns deterministic Anthropic-format protocol replies.
This is **actual CLI / fixture provider** evidence, not real Anthropic model,
subscription, authentication, billing, coding-quality, or deployment acceptance.
No existing credentials, persistent user configuration, or permission bypass is
used. Official docs do not support non-Claude upstream models; this fixture is
a protocol test double, not an alternate model offering.

## Affected seams recorded before code

* **CLI:** documented `-p`, `stream-json`, `--replay-user-messages`, `--resume`,
  and `--session-id`. Spawn, pipe write, init, and MCP connected are not receipts.
* **MCP:** preserve the prototype separately. No HTTP/SSE reconnect or channel
  guarantee is claimed. The first slice selects the documented CLI invocation
  acknowledgment surface instead of pretending MCP connection means idle.
* **Adapter / Hub:** initially fixture-owned authority only. Hub queue admission,
  native acceptance, Participant acceptance, and work completion remain distinct.
  Only correlated native evidence may yield a Hub receipt / start its clock.
* **Supervisor:** no production seat authority yet; never substitute a process
  name, session ID, or connected boolean for the supervisor's process binding.
* **Restoration / reset:** same-Run resume must have a fresh process incarnation
  and fresh safe evidence; no queue remap. A fresh session is not automatically
  a qualified cross-Run reset. Unsupported reset leaves the adapter held.
* **Conservative fallback:** process liveness and turn readiness are separate.
  Working, needs-input, unknown signal, transport loss, process absence,
  unresponsiveness, and replacement hold. No silence-to-idle rule and no
  Pi-equivalent readiness or compaction claim.

## Initial real-runtime experiment

Acquire the pinned official package without lifecycle scripts into an isolated
directory. Launch with fresh HOME and an allowlisted environment, no tools or
auto-discovered MCP, hooks, or plugins, and only the fixture gateway. Record
version, package integrity, native event types, correlated acknowledgment, and
terminal result. Then test a delayed result and resume before attempting any
larger adapter. CI runs in a child network namespace with loopback only; no host
network changes and no networked fallback.

The initial probe passed in [CI run 40329763871](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40329763871)
for head `360548da639173b5e1928a00b79731c10394073e` (test-merge
`b935328ccd4030db2f46d87d856552948258eb2f`). The actual Linux x64 executable's
SHA-256 is `b73676430af12f97316a798b8371f81d640f90a58bdcb8f3ce56a835bb47df56`.
That hash is enforced by the receiver in addition to the npm lock's integrity.
The CLI emitted `tools: []` and `mcp_servers: []`. `--bare` still reported
built-in plugin/skill metadata; this is not a claim that the binary has no
built-in extensions. No external plugin or tool was configured or executed.

## Implemented fixture receiver and durable Hub integration

`uas.claude_runtime.FixtureClaudeReceiver` owns an actual long-lived native
process's stdin; only fixed tool-less CLI arguments are admitted. It retains a
single explicit fixture Run and context generation 1. The constructor checks
the exact binary and loopback-only interfaces plus IPv4/IPv6 route tables before
launch. CI creates the network namespace; the source guard is defense in depth,
not a substitute for that boundary. It does not launch on a normal routed host.

| Fact | Evidence and decision |
| --- | --- |
| Process alive | `Popen.poll()` only; never sufficient for delivery. |
| Working | Adapter has one pending native invocation; all other traffic holds. |
| Runtime acceptance | Native `user` replay ACK must match exact UUID, content, session, and top-level origin. |
| Inferred safe point | Fresh correlated successful terminal result after matching ACK, zero queued turns, no permission denials, supported version, and no tools/MCP. Stdin stays open. |
| Expired/unknown signal | No safe point; explicit fixture control turn can renew an otherwise unfenced idle observation. No automatic model-polling loop. |
| Needs input / unexpected activity | Conservative fenced hold; no approval, queue injection, or silent retry. |
| Proven zero-byte rejection | Durably retain the same logical/native message ID as retryable, not accepted. Require fresh safe evidence before another attempt. |
| Partial/uncertain write or missing ACK | Bounded writes/waits fence the process and retain the unknown durable intent. |
| Same-Run restore | Explicit `--resume`, same journal and native session, new random fixture incarnation, and fresh bootstrap result before any receipt reconciliation. |
| Different Run/context | Rejected. This slice does not implement or qualify native reset. |

The two-second freshness window is an **adapter policy**, not an official Claude
idle guarantee. New unexpected assistant or command lifecycle activity invalidates
it immediately. The richer result correlation/terminal fields are pinned-version
observations, not a promise that all future Claude versions retain them.

**Fixture-only bootstrap / UX limitation:** constructor `refresh()` submits a
real synthetic user turn to the loopback protocol fixture, and expiry requires an
explicit further control turn. This is not a production polling or priming plan,
and must never be redirected to a paid provider as an invisible no-op. The reviewed
documented CLI surfaces do not establish a non-model external safe-point query;
init/connected and replay ACK cannot fill that gap. A useful production adapter
still needs a separately proved MCP pull/initial-invocation contract or other
documented non-disruptive readiness evidence.

SQLite commits each logical handoff intent before touching stdin. A matching
native ACK is stored durably before returning a receipt to `FixturePeerHub`; only
the Hub starts its response clock. ACK is not model success or Participant work
acceptance. An ACK lost before journal commit remains unknown permanently in
this slice: even after resume, the receiver refuses to reinject or fabricate a
receipt. Any unknown journal intent holds the whole receiver, so another
envelope cannot route around an ambiguous head. A recorded ACK can reconcile without reinjection after fresh same-session
readiness. A file lock prevents simultaneous owners of one fixture journal.

A rejection proved to occur before any input byte was written is different from
uncertainty: after a successful durable classification, it becomes retryable with
the **same logical handoff and native UUID**, never a receipt. The previous safe
observation is invalidated. An explicit fresh fixture turn can permit a retry;
the journal is first durably re-armed as unknown before touching stdin again.
Classification-commit failure remains unknown and holds the whole receiver.
Every nonblocking write iteration rechecks asynchronous attention/unknown fences
under the reader's signal lock, with bounded waits outside that lock. A partial
frame remains unknown; no remaining bytes are sent after an observed fence.

Replay ACK timing is **not immediate**: a deterministic fixture blocking all
HTTP response bytes withheld the observable ACK beyond the receiver deadline.
The adapter correctly retained an unknown handoff without starting the clock.
Do not substitute a gateway request, pipe write, or `command_lifecycle` event for
that missing ACK. The working-hold test therefore uses a real in-flight fixture
control turn to prove traffic retention independently of ACK latency; it does
not claim ACK must precede model response or turn completion.

## Validation and remaining gates

The first integrated receiver passed [CI run 40330903455](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40330903455)
for head `61c19cf505c4a7f147ecc2fe1e2d915a874d7bd3` (test-merge
`7ad324b1d6c5c7b0bada30397ac271e34bf56a18`): five actual-native scenarios plus seven source-level cases.
The native scenarios proved multiple turns with stdin still open, ACK clock
gating, working hold, same-session native history
restoration, loss of Hub return without duplicate input, actual SIGSTOP / bounded
partial-pipe uncertainty, no uncertain replay, expiry/exit hold, and rejection of
unsupported reset. Resume evidence comes from the native CLI's next gateway
request containing the prior nonce, never a fabricated session database.

`./validate.sh` always runs the source-level signal/containment tests. The
dedicated `claude-native` workflow acquires official packages, then runs
`tests/claude/run-tests.sh` inside a disposable loopback-only namespace. That
explicit gate fails rather than skipping when its native package or boundary is
missing. Default local aggregate skips are reported as skips, not native passes.

Still **not qualified**: a production Supervisor badge, actual interactive
permission / Needs input behavior, background sessions, authenticated inference,
MCP/channel delivery or HTTP/SSE reconnect, observable compaction, cross-Run native
reset, target Workstation image digest, or the full Pi–Claude–GitHub lifecycle.
Needs-input / missing-signal parser tests are synthetic source coverage, not
native permission-path evidence. The SIGSTOP test is an owned-process failure
injection, not a native documented hung-state signal. **Issue #71 remains open.**

## First-party surfaces checked 2026-10-26

* [Gateway connection](https://code.claude.com/docs/en/llm-gateway-connect)
* [Gateway limitations](https://code.claude.com/docs/en/llm-gateway)
* [CLI reference](https://code.claude.com/docs/en/cli-reference)
* [Programmatic CLI](https://code.claude.com/docs/en/headless)

The installed version's observed behavior, not this living documentation alone,
must qualify each load-bearing signal.

## Non-model readiness applicability investigation

The supported [`claude agents --json --all` query](https://code.claude.com/docs/en/agent-view#read-session-state-from-a-script)
reports live `pid`, `sessionId`, `status` (`busy`, `waiting`, `idle`) and
`waitingFor` for interactive/background sessions. Background `state: working`
also covers autonomous waits, so an instantaneously idle process alone would
not establish a safe point. Pinned 2.1.310 exposes this command, but its
applicability to this adapter's print-mode process is a separate question.

`tests/test_claude_readiness.py` adds a diagnostic only: it suppresses the
fixture constructor's bootstrap within the test, then runs the exact original
CLI mode and arguments. In the mandatory loopback-only CI namespace it samples
the public state query before any input, during a real held fixture request,
after correlated completion, more than two seconds later, after process exit,
and after actual same-session resume. Queries have five-second and 256-KiB
combined-output bounds and must not add gateway requests. The probe records
exact PID/session matches or explicit absence; **neither outcome changes
readiness or authorizes delivery**. Native outcomes are pending the new CI gate.

This is not a move to background sessions or a channel implementation.
[Structured/piped resume cannot inject into a live background session](https://code.claude.com/docs/en/sessions#resume-a-running-background-session),
and [channel notification writes have no acknowledgment](https://code.claude.com/docs/en/channels-reference#notification-format).
Custom development channels are also ignored in print mode. SDK initialization,
MCP connected, stdout silence, and this diagnostic's process-alive observation
remain insufficient. The production-safe replacement for synthetic refresh is
still unqualified; no paid no-op or automatic model polling is introduced.
