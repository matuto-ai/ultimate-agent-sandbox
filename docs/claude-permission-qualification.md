# Deliberate native permission qualification (#71)

**Status: ask-rule run proved native attention/allow/deny; pending-close still failed.**
This does not expand `FixtureClaudeReceiver`: its tool-less policy, permanent
attention fence, durable journal and all automatic CI budgets remain unchanged.
It does not qualify production permissions, Supervisor badges, human authority,
Hub queue retention during native permission waits, or post-permission readiness.

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
no-post-close-request assertion is unchanged and awaits separate qualification.

Future reports capture native frames (at most 256 and 2 MiB total), up to three
bounded gateway requests (each at most 1 MiB), capture errors and cleanup receipts.
Evidence overflow fails rather than silently discarding earlier frames. Values
remain fixture-only; no external provider or credentials are introduced.

## Deliberately unresolved integration

This fixture cannot receive Hub envelopes and never opens or rewrites a handoff
journal. Its second-input rejection is not proof of Hub traffic retention. The
existing receiver's unknown intents therefore remain unchanged, not cleared by
this new mechanism. Integrating native permission attention with the real
receiver needs a separate reviewed change: pending attention must differ from
terminal identity/transport/journal fences; exact replay ACK remains the sole
receipt; tool results must not be mistaken for user replay; renewed delivery
needs fresh liveness and exact idle identity after a qualified terminal state.

The ask-rule run establishes the narrow allow/deny behavior above, not a
completed qualification or production integration. Pending-close cancellation
and the corrected termination order remain unproven until a reviewed manual run. Missing or unexpected
native evidence fails the gate. No permit replay across process restoration,
`defer` continuation, production approval UI or generic permission policy engine
is added. Actor identity, Broker capabilities, Forge authority and human merge
remain enforced at their existing independent seams.
