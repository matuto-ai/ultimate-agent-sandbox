# Claude Participant authority and context reset (#71)

## Recorded implementation seams

This adapter delta completes the existing Claude fixture, not a new runtime or
workflow engine. The fixed SDK 0.3.310 / native CLI 2.1.310 receiver keeps its
qualified public readiness and replay-ACK surface. The existing Supervisor owns
immutable Actor/Participant/profile badges and the actual native PID/pidfd;
the SDK host remains a separate owned process, never native authority. The Hub
keeps generic readiness, scoped queues and receipt-only response clocks.

Same-Run restoration selects only a private Supervisor checkpoint and the exact
journal/session, with new native process authority and fresh non-model evidence.
An unknown handoff remains unknown; restoring never remaps queues or injects it.
Cross-Run reset uses the existing context ledger's request-before-effect barrier,
verified old-process disposal, an isolated fresh HOME/session with no resume or
priming input, native idle/control evidence, private checkpoint, then the existing
monotonic success transaction. Failed or uncertain reset stays held; old native
artifacts and dirty Project/workspace bytes remain intact.

Controlled hosted proof must cross actual native launch, delivery, revocation,
restore, reset and subsequent genuine invocation, proving retained old history on
restore and its absence after reset. Source faults must cover late authority,
checkpoint/commit failure and exact completed retry. No HTTP/SSE reconnect,
compaction visibility, arbitrary tool or production permission authority is added.
The existing automatic Claude job remains bounded at two minutes; no full VM run
or live account is required for this adapter change.

## Fixed integration

```python
recipe = FixtureClaudeRecipe(binary, sdk_install=sdk_install, node=node,
    directory=private_native_root, scope=hub.contexts.scope('claude'),
    gateway_url=loopback_fixture_url, fixture_key=fixture_only_key)
handle = controller.launch_claude(immutable_claude_seat, recipe)
# After explicit revoke/verified stop, only the current private checkpoint:
replacement = controller.restore_claude(immutable_claude_seat, recipe)
# After an explicit trusted terminal fact for the preceding Run:
replacement = controller.reset_claude(reset_id, immutable_claude_seat,
    fixed_recipe_for_target_scope, expected_context_generation=1,
    target_run=FixtureRun('next-run'))
```

The controller records a pending epoch before spawn. Under the lifecycle lock it
starts the fixed SDK host **without awaiting native initialization** and records
its owned handle. An early fixed-host native-spawn ownership frame binds a
held native pidfd before initialization; it grants no readiness. Stop can dispose
even this pending host. A durable unknown-native marker stays set until the exact
native identity is recorded; loss of a constructor/owner cannot clear that gap. Initialization and
native probes then run outside the lock; a new guard checks Room/controller,
epoch, handle, credentials and liveness before publishing native identity. The
host cannot become active authority. The receiver owns normal host-group cleanup
and reap; the controller does not `poll()` that group leader. Independent held
host/native descriptors survive a failed receiver close. A durable cleanup-pending
marker and the retained handle prohibit treating a repeated no-op close as stop.
Bounded retry targets only those held identities; successful stop requires both
host reap and an explicit held-native-pidfd exit observation before releasing
evidence. Reconstruction tracks both recorded PIDs but never adopts or kills
them. If startup lost ownership before any native identity was recorded, the
unknown marker remains held; absence of the wrapper alone is not native absence.

Every active observation, invocation write chunk and returned receipt rechecks
current Supervisor authority. Native idle never revives an old badge, and a late
revocation cannot return acceptance to start a Hub clock. The selected direction
is Hub → SDK → native invocation; this does **not** claim an outbound MCP/tool
channel or transfer a bearer badge to Claude.

Fresh attempts get distinct `contexts/<generation>/attempt-<uuid>` directories,
with new HOME, empty journal and explicit new native session, never `resume`.
The fixed input stream has not released a user message. Fresh public native
control plus exact live-session idle listing and an empty journal qualify the
bounded fresh-context proof. This is a construction-and-native-observation
inference, not a fabricated native transcript query; the integration test also
checks that the next **genuine native provider request** omits the old nonce.
The same persistent fixture workspace is retained across these attempts.

The private fsynced checkpoint holds scope, exact attempt directory and native
session ID. No native path or transcript is stored in Hub state. Reset writes
that checkpoint before `context.reset.succeeded`; only the existing transaction
advances generation. A failure before success leaves both Run deliveries held.
A lost success return or failure publishing the active manifest cannot downgrade
success or trigger another reset. Explicit restore uses only the approved current
checkpoint; missing native artifacts or an unresumable empty session stay held,
not silently replaced. An unknown old invocation remains an immutable unknown
in its original journal and Hub offer even after explicit terminal reset.

## Evidence and exact limits

`test_claude_participant.py` adds two actual native cases to the existing short
Claude gate: Supervisor PID-vs-host authority, native ACK clock, same-session
history with a new badge, stale authority/queue fencing, fresh cross-Run history,
unchanged sibling and dirty bytes, exact reset retry, and unresolved old receipt
retention. `test_claude_participant_source.py` and `test_claude_authority.py` cover
checkpoint/commit/publication failures, pending Stop/revoke, stale restore,
late authority and fresh-proof negatives with **synthetic processes only**.
Hosted results must bind the exact candidate; source-only passes are not native
qualification. The automatic job remains at its existing two-minute timeout.

The executable identity is SHA-256
`b73676430af12f97316a798b8371f81d640f90a58bdcb8f3ce56a835bb47df56`,
CLI **2.1.310**, SDK **0.3.310**, with locked npm package integrity. That is
**package/executable evidence, not a built Workstation image digest**. The hosted
runner image/version is recorded by CI separately. The file-backed Supervisor's
synthetic image values are never promoted to image proof. No actual Claude
Workstation image integration, paid inference, arbitrary tools, permission-state
restoration, compaction visibility, HTTP/SSE reconnect or full-product acceptance
is asserted here. The conservative default remains tool-less; the existing
separate fixed Read permission qualification retains its own evidence boundary.
