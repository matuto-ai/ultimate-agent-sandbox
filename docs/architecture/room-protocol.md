# Room protocol and workflow invariants

This document fixes the smallest protocol required for the collaborative-agent spike. It defines durable coordination and recovery rules without turning the Hub into a task dispatcher or the agents into a rigid workflow.

## Ownership boundaries

- The Forge owns durable work items, pull requests, registered Findings, and merge outcomes.
- The Hub owns explicit Runs, Participant identity and desired state, presence, protocol traffic, policy gates, and an append-only audit ledger.
- Runtime adapters own CLI process launch, resume, stop, attachment, and safe-point detection.
- The Manager is a client and read model. It exposes typed workflow actions only; it cannot submit shell commands, filesystem operations, arbitrary process arguments, or container-runtime actions.
- Participants remain peers. The Hub validates state changes but does not poll the Forge backlog or assign work automatically.

One Deployment contains one Room and normally one repository. A Room may contain Maps and standalone Forge work items. Multiple active repositories in one Room are outside the spike.

## Work and Run model

A Forge issue or pull request owns the durable work lifecycle. A Run is one bounded coordination attempt against an explicitly activated work item and belongs to at most one Map.

- At most one non-closed Run exists for a work item.
- Several Runs may proceed concurrently in a Room, subject to Participant capacity and checkout-collision warnings.
- Worktrees are optional; the Hub does not impose a repository-wide writer lock.
- Runs are opened explicitly by a human or another permitted typed client. The Hub does not continuously select work from the backlog.

### Lifecycle

```text
ACTIVE ↔ PAUSED → CLOSED
```

`PAUSED → ACTIVE` resumes the same Run and generation. `CLOSED` is terminal and records one outcome:

- `completed`: the snapshotted Run Policy is satisfied;
- `stopped`: the attempt ended early, with a reason and optional successor Run.

Later work starts a new Run. Forge outcomes such as merged, rejected, or cancelled do not become extra Run outcomes.

### Run Policy and generations

A deployment-configured, versioned Run Policy defines completion gates for each ticket type. Review, validation, approval, Findings, and attention are independent gates rather than mandatory phases.

A Run snapshots its policy ID and version when opened. Configuration changes affect new Runs only. Migrating an active Run requires an explicit human action, is recorded in the ledger, and fences the old generation.

Every Run-scoped Request and Command carries `run_id` and `generation`.

- Pausing and resuming retains the generation.
- Policy migration or an executed force-stop fences the current generation before work may resume.
- Input for a stale generation is rejected without side effects and returns current Run metadata so the caller can rehydrate.
- Closed Runs reject further state-changing input.

## Participants and coordination

Profiles describe Participant behavior and capabilities. Runtime state belongs to Participants; Git and Forge attribution belongs to durable Agent Identities.

Peer mode is the default. A human may temporarily assign one Participant as a Run coordinator. During the spike:

- only humans assign, replace, or remove a coordinator;
- agents may nominate a coordinator or request a handoff;
- coordinators may recruit configured peers, delegate, message, reprioritize, and request review within policy and concurrency limits;
- cancellation, capability changes, security-sensitive actions, merge, and force-stop execution remain policy- or human-gated;
- loss of the coordinator returns the Run to peer mode and alerts a human instead of freezing work.

A coordinator's Requests receive priority over ordinary peer Requests but cannot force acceptance.

## Protocol traffic

| Type | Meaning | Response obligation |
| --- | --- | --- |
| Message | Informational or conversational traffic | None |
| Request | Supervised work or response traffic | Explicit lifecycle response |
| Command | A validated deterministic Hub or runtime operation | Recorded result |

A client submits a Run-scoped Request or Command with only:

```text
id, run_id, generation, kind, typed payload
```

The Hub derives the Room, authenticated actor, and capabilities. It assigns the durable `room_seq`, timestamp, and status. Client-supplied actor, status, timestamps, and arbitrary metadata are rejected.

Operation IDs are unique within a Room and act as idempotency keys:

- an identical retry returns the original recorded result, even if the Run generation has since changed;
- reusing an ID with different content returns `ID_CONFLICT` without side effects;
- duplicate detection happens before stale-generation validation.

## Request delivery and capacity

Delivery is pull-based from adapter-observed safe points. Process liveness and turn readiness are separate signals; ambiguity holds traffic rather than guessing that an agent is idle. The detailed Pi and Claude evidence is recorded in [Non-disruptive delivery signals](../research/non-disruptive-delivery-signals.md).

Every Request has two clocks:

- queue age starts at submission and detects starvation;
- response time starts only after the adapter confirms delivery to the target runtime.

Expiry escalates through reminder, coordinator when present, and human attention. It never silently cancels work.

A Participant has one active work Request slot by default. A Profile or runtime may explicitly allow more. Work Requests follow:

```text
QUEUED → DELIVERED → ACCEPTED → COMPLETED
                   ↘ DECLINED
                   ↘ DEFERRED
                   ↘ BLOCKED
         any state → CANCELLED
```

`ACCEPTED` consumes the work slot. `DEFERRED` and `BLOCKED` release it; `BLOCKED` retains responsibility and escalates the blocker.

## Preemption

Force-stop is an out-of-band Command, not a Message that the target must read.

- A coordinator may propose an exact target, scope, and reason. The Hub alerts a human; only a human may approve execution.
- Humans may issue the Command directly.
- An ordinary proposal does not pause work.
- An emergency proposal may request a short, audited hold on new delivery. The hold cannot interrupt active work and expires automatically without approval.
- Execution fences the old Run generation, cancels stale queued traffic, invokes and verifies the runtime's native stop, and preserves filesystem changes for inspection.

Safe-point interruption, preemptive stop, and emergency hold remain distinct policies.

## Findings and independent review

Durable Findings are explicitly registered Forge comments:

- an inline pull-request review comment for a code-specific concern;
- a top-level pull-request or issue comment otherwise.

A hidden machine marker registers the comment; its Forge URL and comment ID form the durable identity. Ordinary comments are never inferred as Findings. A Run holds only a disposable synchronized projection, hydrated at start and reconnect; typed mutations write through to the Forge.

```text
OPEN → AWAITING_REVIEW → RESOLVED
  └─→ DISPUTED → ESCALATED → OPEN | RESOLVED
RESOLVED → OPEN
```

- An implementer submits a fix or dispute with evidence but cannot self-resolve the Finding.
- The opener resolves it, requests more work, or upholds the dispute.
- An upheld dispute escalates to a human.
- A human may appoint an eligible replacement reviewer when the opener is unavailable.
- Reopening requires new evidence and reviewer or human authority.

Independent-review eligibility belongs to the durable Agent Identity, not a session, Participant, or Profile. An identity is ineligible when it edited the reviewed artifact, authored or amended a reviewed commit or conflict resolution, or supplied an exact patch that was adopted. Coordination, research, test execution, and problem reporting do not make an identity ineligible. A new session cannot clear the history; a human override is recorded as an override, not independent review.

## Validation, approval, and merge

Validation records evidence without imposing one global strictness level. Each record includes the check, target revision or scope, source, time, result, and evidence link. The Run Policy decides acceptable provenance and freshness. Only a `current-commit` gate automatically becomes stale after a new commit; looser policies may accept attestations or non-commit-scoped evidence.

Humans, the active coordinator, and Profiles with `can-approve-run=true` may approve a Run. Approval satisfies only gates for which that identity is eligible and never bypasses required review or validation.

For an implementation Run, `completed` means its pull request is accepted and ready to merge. The Run records the pull-request URL and accepted head SHA. Acceptance and delivery remain visibly distinct:

- a human merges later through the native Forge UI;
- the Hub does not require, perform, or wait for merge during the spike;
- a changed pull-request head or code-changing conflict resolution invalidates the acceptance, and later work starts a new Run.

## Ledger and recovery

Each Room uses one append-only SQLite ledger.

- Durable commands and events receive a monotonic `room_seq`.
- Initial clients receive a snapshot plus its sequence.
- Reconnecting clients request events with `after_seq`.
- Forge-backed projections rehydrate at Run start, resume, or reconnect and remain synchronized through typed write-through operations.

The spike does not add an event broker, vector clocks, log compaction, automatic backlog polling, or cross-Room routing.
