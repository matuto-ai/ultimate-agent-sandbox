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

The initial receiver-only proof remains available. The same-Run integration below
now binds actual Pi outbound tools to #63's Linux fixture process authority. This
is still not production Run admission/reset generation, container image digest,
live-provider qualification, or host/Room isolation. Native reset observations do
not commit a cross-Run transition. #70 remains open for those obligations.

The subsequent [durable cross-Run reset fixture](pi-context-reset.md) now extends
this same owned-process seam with per-Participant generation/barrier semantics.
The same-Run sections below describe the original baseline; its former reset gap
is addressed only within that newly documented fixture scope.

## Run the real native gate

```sh
sh tests/pi/install-dependencies.sh   # isolated npm config/cache; --ignore-scripts
sh tests/pi/run-tests.sh             # requires installed exact Pi, never silently skips
./validate.sh                       # existing aggregate + reports native skips without install
UAS_PI_INSTALL="$PWD/tests/pi" ./validate.sh  # aggregate including native suite
```

The `pi-native` CI matrix runs the two existing exhaustive, disjoint partitions as `official-pi-native-0` and `official-pi-native-1` on separate runners, rather than making their native processes compete on one runner. Both jobs must pass; each acquires the exact registry lock, runs the serial contracts, and invokes its selected partition through `sh tests/pi/run-tests.sh --partition 0` or `--partition 1`. Ordinary invocations without a selector still run both partitions locally. The runtime budget measures the slower complete job, including setup and cleanup, against the historical workflow baseline.

The actual CLI runs in a child network namespace. Test processes receive a fresh HOME/agent directory, no provider keys, no ambient extensions, no built-in tools (only the fixed `uas_peer` extension tool in the process-bound suite), offline mode and a Node network-API denial guard. The guard is test instrumentation, **not** an OS security boundary. No global installs, account settings, host routes, daemon configuration, or other workspaces are changed.

`tests/pi/provider.mjs` registers the official `pi-ai` faux provider through the
supported extension provider API. It scripts responses/delay and real native tool
calls; lifecycle, queue, compaction, session persistence/replacement and RPC are the real Pi
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
and Run generations requires the separate [durable reset barrier](pi-context-reset.md). Native `new_session` also closes
the peer descriptor; it cannot grant the new session continued authority. The
receiver-only suite uses trusted harness incarnation; the process-bound suite
below uses a fresh Supervisor badge, distinct from the native runtime UUID.

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

## Supervisor-owned Pi: same-Run fixture integration

`FixtureParticipantController.launch_pi(seat, FixturePiRecipe(...))` admits only
`runtime="pi-fixture"` with no seat startup arguments. The fixed recipe selects
locked official Pi 1.4.0, a clean HOME, a persistent fixture workspace/session
store, the two repository extensions and account-free faux provider. It provides
no shell, caller argv, arbitrary extension, ambient provider credential, adopted
PID, or runtime-selection callback. Paths and installed bytes are trusted fixture
inputs, not protected against same-UID filesystem mutation.

The controller persists starting intent, directly starts **one Node Pi process**,
opens its pidfd and persists pending PID before any native handshake. There is no
relay/helper PID with the Participant badge. The receiver attaches to that exact
`Popen`; it never spawns, terminates, or adopts a process. RPC handshake runs
outside the lifecycle lock, then instance/controller/epoch/status/credentials,
current handle and pidfd liveness are rechecked before active publication. Stop,
revoke, replacement or storage uncertainty wins over a late handshake. Controller
cleanup terminates/reaps its own child before closing receiver/database/FDs; it
never recursively removes native sessions or the stable fixture workspace.

The Supervisor incarnation is authoritative for Hub envelopes. Pi runtime UUID
and session ID remain observed adapter facts tied to that process, not a child
identity assertion that can replace the badge. Native tools carry no actor,
profile, epoch or PID authority. The Supervisor reads every record with recvmsg,
checks exactly one SCM_CREDENTIALS tuple plus the held live pidfd/current badge,
and only then parses `{request_id, envelope}` and submits with its badge Origin.
The original fixed synthetic launch and wire format remain supported unchanged.

`runtime/pi/channel.mjs` uses public Node numeric-FD `fs.writeSync/readSync` on an
inherited **nonblocking SOCK_SEQPACKET**, not Node streams, `net.Socket`, an addon,
or a proxy. Each bounded request is one atomic packet; a short write fences and
never sends a remainder. EAGAIN/EINTR retries yield to the native event loop under
a deadline. One request is in flight, at most four are admitted (including that request), and every reply
must match a fresh 32-hex correlation ID. Timeout/abort/EOF/malformed/uncorrelated
reply fences the channel until process replacement: late replies never match a
new tool. Reading MAX_REPLY+1 detects oversized packets, including valid JSON
prefixes whose excess read(2) would discard. A correlated application denial is
not an uncertain transport failure. Lost receipts are not automatic tool retries.
Ledger idempotency continues to bind each operation to its exact security context.

The fixture harness runs `observe/deliver/receive` and active lifecycle actions
on the ledger/journal-owning thread. Background readers only collect RPC events;
they never touch SQLite. General cross-thread Stop after active attachment is not
supported without marshaling that work back to the owner thread.
It may service the outbound authority channel after native persistence confirms
delivery, without holding a lifecycle lock while waiting for RPC. First-ever
queued work starts the supported native turn; the actual faux provider produces
`uas_peer` acceptance/completion calls. The tests do not fabricate tool success
through direct Hub submission or require a manual priming prompt.

Same-session restart creates a fresh process badge and preserves accepted work
and native delivery deduplication. It remains distinct from the [cross-Run reset
barrier](pi-context-reset.md), which advances generation only after fresh native
proof. Uncertain first-flush recovery still holds; no image/live-provider or
production Workstation isolation is inferred. Passing the FD can steal replies
or cause denial of service between trusted same-UID peers; it cannot make a child
or SCM_RIGHTS recipient the original Actor. A Pi-mediated child request would be
attributed to Pi, not an independently authorized child.

### Additional evidence

The required native gate includes actual Pi first-work→tool acceptance→completion,
exact ledger Origin, same-Run restore/revocation, malformed/max+1 records,
Node inherited-FD and SCM_RIGHTS→Node handoff attacks, lost/late replies,
unsupported native reset fencing, late-ready Stop/revoke and actual active plus
compensating persistence failures. Separate actual Node transport tests cover
MAX/MAX+1 requests/replies, bounded serialization, EOF, wrong correlation and
EAGAIN with event-loop heartbeat. Separate controller fault tests use synthetic
children for concurrent Stop, replacement/controller replacement and cleanup;
those are not labeled actual Pi evidence.

Primary transport semantics:
- [Node 24 numeric-FD filesystem APIs](https://nodejs.org/docs/latest-v24.x/api/fs.html)
- [Node 24.22.1 synchronous FS implementation](https://github.com/nodejs/node/blob/v24.22.1/src/node_file.cc)
- [Bundled libuv read/write syscall paths](https://github.com/nodejs/node/blob/v24.22.1/deps/uv/src/unix/fs.c)
- [Linux Unix sockets: record boundaries and per-message credentials](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Linux send/write atomicity and EAGAIN](https://man7.org/linux/man-pages/man2/send.2.html)
- [Linux read/recv truncation semantics](https://man7.org/linux/man-pages/man2/recv.2.html)
