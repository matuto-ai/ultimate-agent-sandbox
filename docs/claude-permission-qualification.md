# Deliberate native permission qualification (#71)

**Status: fixed nonce-Read attention, Hub queue holding and allow-only recovery qualified.**
The default `FixtureClaudeReceiver` tool-less policy, permanent attention fence,
durable journal and all automatic CI budgets remain unchanged. An explicit
nonce-Read diagnostic opt-in passed the bounded Hub integration below.
This does not qualify production permissions, Supervisor badges, human authority
or recovery for arbitrary tool-bearing profiles.

## Smallest supported experiment

`tests/claude/permission/runner.mjs` uses the pinned official TypeScript SDK
0.3.310 and exact Claude Code 2.1.310 binary through `query()`. SDK alone owns
native streams. The fixed profile exposes only built-in `Read`, no MCP or
subagents, empty setting sources, isolated HOME and an allowlisted environment.
The existing loopback-namespace guard runs before launch; the gateway has no
upstream and uses a newly generated fixture-only key. No real credentials,
accounts, provider billing, permission bypass or persistent permission updates
are involved. No user configuration or host network policy is modified.

One generated provider response asks native Claude to read one fixture-owned
nonce file. Public SDK `settings: {permissions: {ask: ['Read']}}` places a
session-only ask rule before native Read auto-approval. It writes no user/project
settings and grants no persistent permission. `bare` and `restricted` remain
enabled; both support explicit flag settings. The callback still rejects any
request other than the exact fixture-owned path and input shape.
`canUseTool` returns a pending Promise. Its attention record binds native request
ID, tool-use ID, native session, fresh fixture-host incarnation, invocation UUID
and immutable exact-input digest. The controller's separate allow/deny command
must match that whole identity; it resolves one callback only. It is explicitly
**fixture-controller authority, not human approval**. Suggestions and
`updatedPermissions` are never returned. Abort, close or controller loss cannot
approve; cancellation is labelled as cancellation, not user denial.

The public APIs are documented in [permissions](https://code.claude.com/docs/en/agent-sdk/permissions),
[user input](https://code.claude.com/docs/en/agent-sdk/user-input) and
[CLI flags](https://code.claude.com/docs/en/cli-reference) and
[bare mode](https://code.claude.com/docs/en/headless#start-faster-with-bare-mode),
with exact fields checked
against the installed official SDK's `CanUseTool`, `PermissionResult`,
`Options.settings` and `SDKSessionStateChangedMessage` types.
No raw control response, custom Transport or private Claude state is used.

## Evidence and gates

The aggregate runs twelve fast source correlation/profile/lifecycle cases via
`tests/test_claude_permission_policy.py`: exact Read/input limits, pending until
an explicit matching decision, all identity-field mismatches, single consumption,
mutable-input protection, denial, abort/close and malformed/subagent requests.
These are source tests, **not** native or Hub integration evidence.

The `claude-permission-qualification` workflow has a three-minute cap and
runs only by manual dispatch or the exact `qualify-claude-permission` label event
from `puglab-reviewer` on a same-repository PR. It checks out that event's exact
head SHA, not a later moving branch or test-merge. Push and PR synchronization
do not trigger it. Source tests lock this explicit qualification contract. Existing automatic `claude-native` retains its two-minute
cap. The new native file is deliberately outside unittest's `test*.py`
discovery. Selecting this deliberate tier requires the pinned packages and isolated
loopback boundary; a missing prerequisite fails rather than skips or falls back.

The three actual-native scenarios require:

1. Genuine callback plus exact-session `requires_action`; while pending, no
   terminal result, provider tool result or nonce disclosure. A stale-incarnation
   decision and a second input are rejected. The runner permanently prohibits a
   second invocation, even after completion: this proves fixture input isolation,
   NOT native attention-based delivery gating or recovery after allow. Explicit matching allow yields one
   correlated native Read result containing the nonce; repeated allow is rejected.
2. Explicit deny yields an error tool result without nonce disclosure. Later
   allow cannot change that decision. Denial is not promoted to a safe point.
3. Closing while waiting terminates the owned host and native process without a
   tool result. Late callback approval is covered by source cancellation tests;
   no live reconnect or restored approval claim is made. Every scenario records
   post-disposal held-host/native-pidfd exit evidence and host reap status before
   releasing descriptors; those cleanup checks must also pass.

Reports identify real SDK/native versions, session/process observations, actual
attention, correlated decisions and terminal output. The fake provider is only
protocol evidence, not actual inference or model quality. A runner input-release
reply is explicitly not a delivery receipt.

## First native result and correction

[Run 40381147991](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40381147991)
checked out exact head `25d1f8e18061e41f4deb709ba0b91d94200e28b2` and failed
all three tests in 26.191 seconds. Native init confirmed only `Read`, no MCP,
version 2.1.310 and default permission mode. Native replay ACK, actual Read
results containing each fixture nonce, successful terminal results and idle were
observed, but no host permission callback or `requires_action` appeared.
The native tool-result metadata reported
`permission_decision: {decision: 'accept', source: 'config', reason_type: 'mode'}`.
Two gateway requests occurred in each case. This is real evidence of automatic
Read acceptance under the initial profile, **not** attention/allow/deny/exit proof.
The listed cost fields were native estimates against a fake provider, not billing.

The initial SDK `PreToolUse` ask hook did not establish the required prompt. The
logs do not establish why: bare mode documents skipped discovery, not a reliable
claim here about explicitly registered SDK callbacks. The correction removes
that dependency and uses the documented `permissions.ask` evaluation step via
public transient SDK flag settings. It does not remove bare/restricted, expand
tools, use allow rules, or relax the mandatory native assertions. The next run established the narrower behavior below.

Failure cleanup ran without reported cleanup exceptions and the job ended, but
the first harness printed observations before disposal and supplied no explicit
held-pidfd cleanup receipt. Therefore it does not establish the exit-while-waiting
assertions. The correction prints post-disposal identity observations and requires
host/native exit; generic GitHub runner cleanup is not substituted for this proof.

## Ask-rule result and pending-close correction

[Run 40383229304](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40383229304)
checked out `1b2fb5bd84c98eb5eaa681d6fd0356db78a1285e`: two tests passed,
one failed in 6.537 seconds. Both allow and deny passed the mandatory genuine
callback, exact-session `requires_action`, no-early-provider-request/nonce and
correlated result assertions. All three scenarios recorded positive held-pidfd
host/native exit and host-reaped receipts. The pending-close test failed because
it observed two gateway requests, not one, after close. This is not successful
cancellation qualification. No automatic rerun was performed.

That report preserved sampled attention/terminal/cleanup records, not the whole
native event stream or gateway payloads. The passing assertions establish
`requires_action` and allow/deny nonce behavior, but the exit-case second payload
and whether it contained the nonce cannot be reconstructed from the report. Do
not describe that unrecorded payload as proven denial or proven execution.

Source inspection identifies a release-before-termination hazard: shutdown
resolved the pending callback as deny/interrupt before graceful `query.close()`.
Official `SpawnOptions.signal` documents stdin EOF and an approximately two-second
grace period before its forwarded abort signal fires. A deny callback is not a
no-further-provider-work barrier. This explains a supported path for the observed
extra request, but is not a recovered trace of its exact content.

The qualification-only correction fences decisions immediately and leaves the
callback pending while sending SIGKILL to the exact captured owned child. Only
a child exit observation permits callback settlement and SDK disposal. The barrier removes
the original abort listener, so concurrent/late SDK abort cannot settle the frozen
callback; ordinary abort outside termination remains unchanged. Already
exited children are never signaled; a 2.2-second kill/exit failure deadline exits
the fixture host without resolving permission or invoking graceful query close.
The existing outer held-pidfd disposer remains responsible for cleanup. No PID
lookup, process-group signal or post-reap numeric signal is introduced. Pure
lifecycle tests cover controller/signal/error close, spontaneous exit, recursive
exit notification and failed kill/exit. They are not native proof. The mandatory
no-post-close-request assertion remained unchanged and passed in the run below.

Reports capture native frames (at most 256 and 2 MiB total), up to three
bounded gateway requests (each at most 1 MiB), capture errors and cleanup receipts.
Evidence overflow fails rather than silently discarding earlier frames. Values
remain fixture-only; no external provider or credentials are introduced.

## Qualified bounded result

[Run 40393356811](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40393356811),
job `121819826370`, checked out exact source head
`dc209721f01734c300ae639d3c1086d2751c857a` (tree
`aa08fe190ea893ce49b74f267fe67b30ac7a6cfc`). All three cases passed in
6.053 seconds, under the unchanged deliberate three-minute job cap. Complete
job log SHA-256:
`64eebecb5626aa81f57cb933de6a9bfb34f4e0a06ffea8afc0ad8120a64c9f26`.

All three captured reports have no capture errors, fresh distinct identities,
exact-session `requires_action`, and positive held-host/native exit plus host-reap
receipts. Allow and deny each made two gateway requests: allow returned exactly
one correlated Read result with the nonce; deny returned a correlated error
without the nonce and recorded the matching terminal permission denial. The
pending-close case made exactly one gateway request, with no tool result,
terminal result or nonce disclosure. The stale/duplicate decision and bounded
no-early-request assertions passed. These are actual pinned SDK/native lifecycle
observations against a loopback fake provider, not live inference or billing.

The captured allow/deny states were `running → requires_action → running`,
followed by terminal results. No fresh post-result idle/recovery qualification is
claimed. The exit scenario stopped at `requires_action` before owned termination.
Pure failed-kill/timeout and concurrent-abort tests are not native fault-injection
proof. The historical failures above remain relevant evidence, not hidden retries.

## Limits of the qualified standalone integration

The qualified standalone runner cannot receive Hub envelopes and never opens or rewrites a handoff
journal. Its second-input rejection is not proof of Hub traffic retention. The
existing receiver's unknown intents therefore remain unchanged, not cleared by
the standalone mechanism. The separately qualified receiver integration below
distinguishes pending attention from terminal identity/transport/journal fences; exact replay ACK remains the sole
receipt; tool results must not be mistaken for user replay; renewed delivery
needs fresh liveness and exact idle identity after a qualified terminal state.

The successful run qualifies only this fixed diagnostic profile, not production
integration or general cancellation behavior. Missing or unexpected native
evidence still fails the gate. No permit replay across process restoration,
`defer` continuation, production approval UI or generic permission policy engine
is added. Actor identity, Broker capabilities, Forge authority and human merge
remain enforced at their existing independent seams.


## Hub-connected diagnostic

The explicit `FixtureClaudeReceiver(..., diagnostic_nonce_file=...)` profile uses
its existing SDK host, RoomLedger-facing receiver and native handoff journal.
It does not introduce another transport, approval engine or production profile.
The default constructor still exposes no tools and permanently fences attention.
Diagnostic resume is rejected: decisions never transfer across incarnations.
The fixed file must be a bounded regular nonsymlink directly in the fixture cwd;
Read, host prompts and the transient ask rule are unchanged from the qualified
standalone experiment. PermissionSlot and its pending-close exit barrier are now
shared from `runtime/claude/permission-policy.mjs` with that standalone runner.

An exact current-session pending permission holds subsequent Hub traffic. The
first envelope may already have its exact native replay receipt and response
clock before attention; this is legitimate acceptance, not permission approval.
`fixture_decide(identity, behavior)` represents only the test controller, never
a human, Actor/Broker capability, Forge permission or merge authority. Stale,
duplicate or nonmatching decisions cannot resolve the callback. Only one Read
permission request is admitted for the diagnostic host lifetime.

Allow is not readiness. The separate native tool-result user frame must match
the decided request, tool-use ID, current invocation, exact file and observed
native temporary-decision metadata. It can never replace or manufacture the
original replay receipt. Recovery additionally requires the exact qualified
successful terminal result with no denials/queued turns, followed by fresh public
SDK liveness and exact native idle identity/state. Missing signals remain held.
Denial deliberately remains held; this slice does not qualify deny recovery.
Transport, identity, unknown-event and journal fences remain irreversible.
No permission decision edits or clears unknown native handoffs.

The source regressions cover the captured ordering, malformed/mismatched tool
results, unchanged replay identity, stale decisions, irreversible fences,
post-terminal fresh-probe requirements and unknown-intent retention. They run
without SDK/native execution and are not runtime qualification.

`tests/claude/permission/hub_native.py` adds the real RoomLedger/FixturePeerHub
proof to the existing deliberate isolated tier (same three-minute cap). Its
required allow path queues two envelopes, confirms the first by exact replay,
observes genuine permission attention, proves the second has neither a native
intent nor response clock, rejects a stale decision, then requires fresh idle
before confirming the second exact replay and clock. Deny and pending-close
retain the queue. A separately labelled injected-journal fault checks that even
successful permission resolution cannot erase an unknown intent. Native versions,
process/session identity, journal receipts, Hub state and fixture provider calls
are recorded. The first native round failed; the corrected round below passed.
Source tests and the earlier standalone run are not substitutes for this proof.

No local namespace/listener/native execution is used for this change. Review the
exact source before explicitly selecting the mandatory isolated qualification
tier. If post-result idle is absent or the unchanged budget is exceeded, the gate
fails rather than accepting terminal success as readiness or extending automatic
CI budgets. Production authority, authenticated inference, reset, compaction,
reconnect and cross-Run admission remain outside this slice.


## First Hub integration round and bounded continuation correction

[Run 40401046723](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40401046723),
job `121846658724`, checked out exact head
`62aa02b44a83cdef6c942f368faddb0f5724ec26` (tree
`ed5b6070f578225eb85ff0be03f5301c3082e78d`). The standalone three scenarios
passed in 5.821 seconds. The four Hub scenarios took 11.993 seconds: deny hold
and pending-close passed; allow recovery errored and source-injected unknown
intent preservation failed while awaiting accepted terminal state. All seven
reports contain positive held-host/native exit and host-reap receipts. Full log
SHA-256: `6bf70de5f4c872b396b5b9f4a41f40dace9dff8e77f6c91898f88fccd6e69c47`.

The failed allow cases captured exact replay, genuine attention, a correlated
Read result, terminal UUID and native idle. Offline replay identifies the first
fence at the post-tool assistant text frame: it has no `user_message_uuid`.
Official SDK 0.3.310 `SDKAssistantMessage` (`sdk.d.ts`, lines 3688–3704) declares
that field optional and documents first-frame stamping, not a stamp on every
assistant frame. The fixture's previous reducer incorrectly required every
assistant frame to repeat it. This is not evidence of a missing native idle,
and the failure does not justify relaxing the fresh probe or journal fences.

The diagnostic-only correction retains one text-only continuation after an
already validated allow/tool-result for its single owned pending invocation.
Session and explicit top-level parent must match; a present invocation UUID
must match, and any supplied consumed-UUID list must contain only that invocation.
Pre-tool missing correlation, new tool-use, duplicate continuation and mismatched
identity still fence. Text is never used to infer identity. This frame changes
neither receipt, pending work nor readiness: an exact terminal UUID and subsequent
fresh non-model liveness/idle remain mandatory. The default tool-less policy is
unchanged. No safe resumption claim follows from the failed first round; the
corrected native result is recorded separately below.


## Qualified Hub holding and allow-only recovery

[Run 40403924792](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40403924792),
job `121856667131`, checked out exact source head
`3274e8835449d7626832f46af39dbe8da4a22b4f`, tree
`31beaaab063c200eacf6b55058c84220ed2d3558` (not a PR test-merge).
Pinned SDK 0.3.310/CLI 2.1.310 passed all three standalone scenarios in 6.283
seconds and all four Hub scenarios in 10.311 seconds, within the unchanged
three-minute deliberate gate. Complete job-log SHA-256:
`efd8698513048642308b4c8e8f5d0c586f8da32bba3920d28e225d0462536c96`.

The allow case used the real RoomLedger/FixturePeerHub and shared handoff journal.
During genuine attention, the second envelope stayed QUEUED without a native
handoff intent, delivery receipt or response clock. After an explicit correlated
fixture-controller allow, the native stream was
`running → requires_action → running → idle → running → idle`.
The mandatory fresh public SDK control plus exact native idle checks passed
before resuming delivery. Those probe assertions establish liveness/idle;
reports retain native state events and receipts, not raw probe reply frames.
Two distinct exact native replay receipts persisted for the same session and
receiver incarnation, and only the second receipt started the second response
clock. Exactly three provider requests occurred: Read, its result, then the
resumed peer envelope; readiness polling created no synthetic model turn.

Deny left the second envelope held despite native idle (two provider requests).
Pending-close stopped at requires_action, retained the queue and made only one
provider request. The explicitly **source-injected** unknown journal row remained
unresolved after actual native allow, and the second envelope remained held;
this is not native crash-window fault-injection evidence. All four Hub captures
were complete, and all seven scenarios reported held-host/native exit and host
reap after cleanup. Stale and duplicate controller decisions were rejected.

This qualifies only the fixed account-free nonce-Read profile's bounded
holding/allow-recovery path. Default tool-less policy, irreversible fences,
unknown-intent responsibility and Actor/Broker/human authority are unchanged.
Deny recovery, permission replay across restoration, production permissions,
real inference, native reset, compaction, reconnect, cross-Run admission and
full #71/#58 acceptance remain unqualified. Earlier failures remain evidence;
this pass does not retroactively identify the separate startup-loss cause.
