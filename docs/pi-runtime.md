# Pi native adapter — bounded fixture qualification (#70)

## Recorded integration plan (before implementation)

Use official Pi 1.4.0 extension lifecycle/injection plus JSONL RPC supervision,
not terminal scraping and not Pi Durable. The adapter translates only generic
readiness into `FixturePeerHub`; Pi state stays outside the Hub domain. The
existing Room ledger owns queue admission, offer/confirmation and response clocks.
A persisted native custom-message on the active Pi session branch is the receipt:
RPC command success, a helper inbox write, and an in-memory message are not one.

Persist handoff intent before native injection. Reconcile a lost receipt against
native session entries without reinjection; missing evidence holds responsibility.
A changed native session/runtime binding fences old handles. Check actual idle,
long-turn hold, abort, compaction, native replacement and same-session restoration
using the official account-free faux provider and separate process. Keep provider
configuration, inference health, liveness and readiness distinct.

The authority boundary remains an explicitly trusted fixture: #63 currently
launches only a fixed synthetic worker. This adapter does not qualify native Pi
badges, product Run admission/reset generation, container image digest, live
providers, or host/Room isolation. Native reset observations do not commit a
cross-Run transition. #70 remains open until those integration obligations pass.

## Run the real native gate

```sh
sh tests/pi/install-dependencies.sh   # isolated npm config/cache; --ignore-scripts
sh tests/pi/run-tests.sh             # requires installed exact Pi, never silently skips
./validate.sh                       # existing aggregate + reports native skips without install
UAS_PI_INSTALL="$PWD/tests/pi" ./validate.sh  # aggregate including native suite
```

The dedicated `pi-native / official-pi-native` CI job always acquires the exact
registry lock and runs the actual CLI in a child network namespace. Test processes
receive a fresh HOME/agent directory, no provider keys, no ambient extensions,
no tools, offline mode and a Node network-API denial guard. The guard is test
instrumentation, **not** an OS security boundary. No global installs, account
settings, host routes, daemon configuration, or other workspaces are changed.

`tests/pi/provider.mjs` registers the official `pi-ai` faux provider through the
supported extension provider API. It controls response delay only; lifecycle,
queue, compaction, session persistence/replacement and RPC are the real Pi
implementation. Neither production provider compatibility nor quota is inferred.

## Delivery and recovery contract

1. The Hub durably queues and offers traffic. The receiver samples fresh native
   readiness, tied to a session ID and extension-runtime UUID.
2. The receiver commits a SQLite FULL-synchronous **intent**, not a receipt.
3. At idle, the extension rechecks native `ctx.isIdle()` and pending-message state
   in the same JS turn as `pi.sendMessage(..., {triggerTurn: true,
   deliverAs: "followUp"})`. Content is a custom untrusted peer message, not a
   system/user instruction or workflow command.
4. First-ever delivery needs no priming prompt: supported `triggerTurn` starts a
   native turn. Pi may keep the custom entry in memory until a user/assistant
   entry first flushes the session. Until then the Hub clock remains unset.
5. Only a matching custom-message entry on the active branch **and** in the
   native session file confirms Runtime delivery. RPC `handled`, API return,
   helper-journal commit and in-memory presence never do. The Hub then starts
   its response clock; Participant acceptance and work completion stay separate.
6. A fresh same-runtime pre-effect refusal with no pending handoff is persisted
   as `NOT_APPLIED` and permits retry after a new safe observation. If persisting
   that classification fails, the intent stays unknown and cannot reinject.
   Pending/uncertain handoffs never qualify as `NOT_APPLIED`.
7. A lost receipt is reconciled read-only. Same-session process restoration uses
   a fresh fixture incarnation but matches stable logical identity, preserving
   work responsibility without injecting the same input twice. A new session or
   branch without the exact receipt cannot reuse it.

The adapter never writes Pi JSONL and never invokes private persistence/flush
methods. Receipt scanning is capped at 8 MiB; larger or malformed transcripts
fail closed. Persistence proof covers process restart, **not power-loss durability
of Pi's own session writes**. There is no exactly-once external side-effect claim.

A crash after intent but before a native receipt is irreducibly uncertain. In a
brand-new session before first flush, there may be no restorable session file.
The retained intent blocks reinjection into a new session; explicit recovery is
still required. Automatic resolution of this case is a remaining #70 blocker,
not a fabricated delivery or a requirement for manual priming on the happy path.

## Native observations and limits

| Native observation | Generic adapter result |
| --- | --- |
| session_start plus fresh isIdle/no pending messages | SAFE |
| agent_start/turn_start/tool execution plus non-idle | BUSY |
| session_before_compact through compact/failed signal | COMPACTING |
| missing, malformed or timed-out state sample | AMBIGUOUS |
| process/stdout loss, replaced session/runtime identity | LOST |
| agent_settled plus fresh native idle check | SAFE |

`agent_end` is not used as a safe point. RPC `abort` waits for idle, but the adapter
still samples readiness. Native `steer`/`follow_up` responses with disposition
`queued` are tested as queue acceptance, **not completion**. The Hub receiver
conservatively injects only when idle; it does not expose a Pi queue selector in
its transport-neutral interface. During compaction and replacement it holds.
RPC writes use unbuffered nonblocking pipes and one end-to-end command deadline.
An incomplete/uncertain JSON frame fences that transport until process replacement;
no subsequent command can be concatenated onto it. A real SIGSTOP + large-packet
test proves bounded return and conservative same-session restart reconciliation.
There is no native hang detector; an alive process and healthy transport do not
prove inference availability. A delayed first response can retain an uncertain
intent until a later explicit retry reconciles the receipt.

Native `new_session` is tested to change session identity and fence the old
receiver. It is **not** a product cross-Run reset: advancing durable context
and Run generations remains unimplemented here. Same-session restoration is a
fixture incarnation, not a supervisor-issued process badge. #63's fixed-worker
SCM_CREDENTIALS/pidfd proof cannot be silently generalized to this native process.

## Version-bound evidence

The fixture verifies both package metadata and actual `pi --version` equal
`1.4.0`; the extension's `api_baseline` is only a compatibility declaration.
`package-lock.json` pins the official package integrity to
`sha512-Z41LpZ3yYHSC/UUps6Mr39UMFPwH8elhJBG9DY1P7kuzsE5qSK/6eMj2EHzO5evJRQWLbKSqUMw+4nCNtIyiQg==`.
This is npm artifact provenance, not a selected deployment image digest.

The mandatory gate prints per-case JSONL evidence (`tests/pi/evidence.jsonl`):
verified CLI version, native signal source, last observed readiness, liveness,
queue dispositions, receipt source/count, unknown intent count and residual hang
uncertainty. It includes no message/transcript content. Test status is the runner
result, not an inference from that evidence.

Version-specific primary references:
- [RPC contract](https://github.com/earendil-works/pi/blob/v1.4.0/packages/coding-agent/docs/rpc.md)
- [Prompt, queue, abort and session commands](https://github.com/earendil-works/pi/blob/v1.4.0/packages/coding-agent/docs/rpc-commands.md)
- [Extension lifecycle and message APIs](https://github.com/earendil-works/pi/blob/v1.4.0/packages/coding-agent/docs/extensions.md)
- [Session persistence implementation](https://github.com/earendil-works/pi/blob/v1.4.0/packages/coding-agent/src/core/session-manager.ts)

The native tests cover first-ever delivery, long-turn hold/abort/settled, actual
steer/follow-up queues, actual compaction hold/release, lost Hub receipt retry,
Hub/process restart, retained accepted responsibility, first-flush crash hold,
SAFE-to-busy refusal/retry and failure to persist its not-applied classification,
native new-session fencing, missing-signal hold and process exit. Test fault
injection only drops observations/receipts or kills the actual process; it does
not simulate Pi lifecycle or claim end-to-end production acceptance.
