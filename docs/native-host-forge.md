# Direct native helper Forge boundary (#78)

The fixed Claude MCP helper has two same-task seqpacket connections:

* FD3: admitted peer/Run traffic, transferred to the isolated Hub.
* FD4: Forge and native review traffic, retained by the trusted Supervisor. The Hub never receives
  this descriptor. Native provider credentials are cleared before the helper's
  fixed Node entrypoint, as before.

The helper connects FD4 to the same Supervisor-issued endpoint after its first
release and before SDK initialization completes. `NativeDescendantLease` matches
its fixed hello against the **same retained kernel task** already lineage-bound
as the native Claude child. Release enables initialization, not Forge effects.
Both root and helper ADMIT acknowledgments are mandatory. A queued packet or EOF
on FD4 at the helper admission handoff is rejected, just like FD3.

`NativeClaudeRoot.initialize_helper(..., forge_client=existing_read_broker)`
constructs `NativeHostForge` only after both acknowledgments. The trusted caller
selects its retained FD4 for bounded `root.receive_forge_once()` processing; this
is a source composition seam, not a new daemon or production deployment launcher.
Missing exact Broker input leaves Forge unavailable. Fixture launch defaults do
not gain a native or credential path.

The original native packet and its SCM_PIDFD record remain held at the Supervisor
through request preparation, Broker authorization challenges and disclosure.
Actor, capabilities, incarnation and epoch are derived from the exact registered
native root, not supplied by the Hub or native JSON. The resulting authority
version is identical to the canonical Hub dispatcher version.

Before provider contact, the trusted host sends `RESERVE_FORGE` on its existing
private Hub control channel. This carries only the existing root operation,
helper operation, unchanged envelope, digest, controller and exchange ID. The
actual `workstation_service` entrypoint, when configured with an explicit trusted
Forge Project binding and seat capabilities, calls the canonical
`reserve_forge_operation` under local admission authorization. Its digest-bound
acknowledgment reserves the Room-wide operation namespace; **it grants no Actor
or process authority**. A hostile Hub cannot replace the original request bytes
or make the host invoke a request it did not receive from the held helper.

No lifecycle/admission/SQLite lock spans the Hub reservation RPC or provider I/O.
ReadBrokerClient still owns lifecycle rechecks, external Broker framing and
canonical audit/idempotency. The host rechecks helper/root/SDK host/controller/
epoch and Room before preparation, contact and disclosure. Requests and private
reservation frames are bounded to one 64 KiB record. Other private control
commands retain their original 8 KiB bound. Replies reuse bounded Broker framing.

There is no automatic resend. Timeout, malformed response or lost transport
fences the direct channel. A possible write remains uncertain; the existing
explicit `forge-reconcile` path retains the original mutation ID/body and audit
reference. No new workflow journal, credential, bearer token or replay cache is
introduced.

## Evidence and remaining composition

Pure guarded checks cover ownership, correlation, stale authority, lock placement,
queued pre-admission data and lost responses. The hosted-only Node transport test
now supplies distinct FD3/FD4 and checks `gh` goes only to FD4. These are not real
native Claude/SDK, account, namespace or complete-lifecycle qualification.

Native review acceptance is now composed on the trusted host as described below.
The deployment launcher and live end-to-end qualification still need integration. The old same-process `attach_read_service`
remains a controlled test seam, not permission to mount a Supervisor store in Hub.

## Native Pi direct route

The opt-in native Pi bootstrap likewise opens a second connection in its exact
launch task. `ExecLaunch` verifies the fixed Pi Forge hello against the same held
kernel origin, retains FD4 and releases initialization before SDK startup. The
native entrypoint requires exact FD3/FD4 socket setup before reading provider auth;
it cannot silently fall back to the Hub. The legacy fixture entrypoint preserves
its existing single-channel behavior.

Before root ADMIT, queued FD4 bytes/EOF are rejected. After its acknowledged
admission, `SupervisorAdmission.attach_forge_service(existing_read_broker)` builds
an exact `NativePiHostForge`; `receive_forge_once()` consumes original Pi records.
It reuses the reviewed packet/Broker mechanics with direct root authority, not
Claude helper authority. `RESERVE_PI_FORGE` uses canonical direct Hub admission
and ledger reservation; its acknowledgment still grants no authority. Pi's Origin
hash preserves the existing omitted native-payload field, rather than adding null.

The shared extension routes native `gh` and `uas_review` to FD4 and bounds the whole request
before contact; peer tools stay on FD3. Hosted-only Node transport tests use a
fake SDK tool registry to verify routing, oversize rejection, both-channel cleanup
and missing-native-FD denial without executing a model or contacting accounts.
This completes the equivalent source route, not its native runtime qualification.


## Pi typed review tool

Pi now exposes `uas_review` with the same submit-for-review/review-result schema
as Claude. It preserves stable operation IDs, Run/generation, observation and
payload fields. Native mode sends original review records to trusted host FD4;
the existing fixture mode retains Hub FD3. Malformed/oversized envelopes are
rejected before either transport. Hub rejection remains a tool error; the tool
never infers role, reviewer independence, current revision or a successful verdict.
Those remain canonical native admission/RunReview decisions. The hosted
controlled routing test compares the tool schemas, checks both review operations
and verifies rejected requests leave both channels empty. This adds a callable
proposal path; live runtime qualification remains separate.

## Native trusted-host review acceptance

`NativeReviewStartup` is an explicit trusted argument to the existing
`NativeClaudeRoot.initialize_helper`. It pairs the already admitted Pi direct
receiver with Claude's admitted helper receiver and constructs `NativeReviewHost`.
It requires the host connection to the **same existing Hub Room database**, the
canonical controlled Git provenance owner, actual source resolver, fixed reviewer
Forge IDs and authorized human merger IDs. Missing inputs fail closed. It neither
creates another workflow store nor mounts Supervisor-private state in the Hub.
No credentials or permissions are changed by this source composition.

Original `uas_review` records travel on FD4. Native identity comes only from the
retained exact root/helper/SDK-host admission and controller. Current canonical
peer attachment, incarnation, context, Run generation and LOST state are also
required. Unlike Forge external operations, review uses RunReview's existing main
operation ID and hashed durable observation intents directly in the same Room
ledger; it does not consume that ID with a fake Forge reservation first.

Provider/Gate observations run without lifecycle or Git locks. Final acceptance
uses the existing writer order: **lifecycle → Git history → Room transaction**.
An owner-bound lifecycle capability permits the existing resolver to read without
reacquiring flock. Full source equality includes head SHA and worktree binding.
The invocation records exact Gate evaluation rows and terminal refresh IDs at
the canonical refresh finish, then rejects replacement even when a dependency
digest happens to match. Local identity/independence is recomputed with current
fenced contribution history. The same RunReview reducers commit the transition;
no provider RPC happens in their transaction.

The transient invocation scope cannot be deserialized or reused. Existing read
attempt IDs, explicit fresh observation IDs and uncertain comment reconciliation
remain unchanged. Exact completed command receipts do not trigger another read.
Known Git history is not proof about unreported raw filesystem edits.

Authenticated Manager actions use the existing `HumanSession` and `OwnerFence`
through RunReview's normal Manager entrypoints. Eligibility is read-only. Native
packets cannot become human actions. The trusted host's `observe_completion`
uses the existing review service identity to observe an already performed human
GitHub merge; configured User ID, method, exact reviewed candidate and integration
SHA checks remain canonical. No new merge endpoint exists.

The host Gate composition includes canonical command/diff projection owners with
read-only actual source adapters. It consumes existing evaluations; it does not
implicitly launch evaluators or replace their existing trusted launch owners.
Hosted Node tests cover native review routing, not model inference. Guarded tests
use real SQLite and explicitly controlled provider/kernel seams; neither those
nor source composition establish installed permissions, live credentials,
container isolation, native startup or complete real lifecycle qualification.
