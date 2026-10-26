# Deliberate native permission qualification (#71)

**Status: source fixture implemented; actual native scenarios not yet executed.**
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
nonce file. An exact-input `PreToolUse` callback returns `ask`, not `allow`:
otherwise in-directory Read can complete without calling the permission handler.
`canUseTool` returns a pending Promise. Its attention record binds native request
ID, tool-use ID, native session, fresh fixture-host incarnation, invocation UUID
and immutable exact-input digest. The controller's separate allow/deny command
must match that whole identity; it resolves one callback only. It is explicitly
**fixture-controller authority, not human approval**. Suggestions and
`updatedPermissions` are never returned. Abort, close or controller loss cannot
approve; cancellation is labelled as cancellation, not user denial.

The public APIs are documented in [permissions](https://code.claude.com/docs/en/agent-sdk/permissions),
[user input](https://code.claude.com/docs/en/agent-sdk/user-input) and
[hooks](https://code.claude.com/docs/en/agent-sdk/hooks), with exact fields checked
against the installed official SDK's `CanUseTool`, `PermissionResult`,
`PreToolUseHookSpecificOutput` and `SDKSessionStateChangedMessage` types.
No raw control response, custom Transport or private Claude state is used.

## Evidence and gates

The aggregate runs five fast source correlation cases via
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
   no live reconnect or restored approval claim is made.

Reports identify real SDK/native versions, session/process observations, actual
attention, correlated decisions and terminal output. The fake provider is only
protocol evidence, not actual inference or model quality. A runner input-release
reply is explicitly not a delivery receipt.

## Deliberately unresolved integration

This fixture cannot receive Hub envelopes and never opens or rewrites a handoff
journal. Its second-input rejection is not proof of Hub traffic retention. The
existing receiver's unknown intents therefore remain unchanged, not cleared by
this new mechanism. Integrating native permission attention with the real
receiver needs a separate reviewed change: pending attention must differ from
terminal identity/transport/journal fences; exact replay ACK remains the sole
receipt; tool results must not be mistaken for user replay; renewed delivery
needs fresh liveness and exact idle identity after a qualified terminal state.

Native event order, Read normalization, `bare`/`restricted` compatibility, deny
terminal details and cancellation timing are hypotheses to establish in the
manual run, not assertions of a completed qualification. Missing or unexpected
native evidence fails the gate. No permit replay across process restoration,
`defer` continuation, production approval UI or generic permission policy engine
is added. Actor identity, Broker capabilities, Forge authority and human merge
remain enforced at their existing independent seams.
