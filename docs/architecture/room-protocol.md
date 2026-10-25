# Room protocol and workflow invariants

This document describes the target protocol, not implemented guarantees. The [current successor specification](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58) and [October reconciliation](source-reconciliation.md) control where historical prototypes or closed decisions differ.

## Contents

- [Ownership boundaries](#ownership-boundaries)
- [Work and Run model](#work-and-run-model)
- [Participants and coordination](#participants-and-coordination)
- [Protocol traffic](#protocol-traffic)
- [Request delivery and capacity](#request-delivery-and-capacity)
- [Preemption](#preemption)
- [Independent review](#independent-review)
- [Gates and human merge](#gates-and-human-merge)
- [Ledger and recovery](#ledger-and-recovery)

## Ownership boundaries

- GitHub is the first product Forge and owns work items, dependencies, assignments, pull requests, detailed review, and merge facts.
- Each Room Hub owns Runs, claims, policy snapshots, protocol traffic, Gates, reviewer eligibility, review returns, attention, and its append-only workflow ledger. Forge lifecycle labels are projections, not locks.
- The supervisor owns process authority, lifecycle, checkout slots, and reconciliation. Runtime adapters provide native launch/restore/stop/reset, process observation, safe-point detection, and delivery.
- The Room Broker owns Git/Forge authorization, provider execution, receipts, and canonical Forge audit outside the Workstation.
- Manager is a versioned read model and typed command client, not a shell, filesystem proxy, process launcher, or workflow authority.

One Deployment contains one or more Rooms. Each Room is permanently bound to one Project and one writable repository and has its own Hub, Broker, state, endpoints, network, Workstation, and outbound Manager connection. A Room may contain Maps and standalone Forge work items. Participants remain peers; the Hub never selects backlog work automatically.

## Work and Run model

A Forge issue or pull request owns the durable work lifecycle. A Run is one bounded coordination attempt against an explicitly activated work item and belongs to at most one Map.

- At most one non-closed Run exists for a work item.
- Several Runs may proceed concurrently subject to Participant capacity and supervisor-owned checkout allocation. The primary checkout is the default; actual concurrent writing receives a host-visible additional slot.
- Context reset never edits Project files. Before another Run uses an existing checkout, it must observe a clean state or explicitly adopt the exact existing state; otherwise reassignment is blocked. Dirty or unverifiable slots are retained.
- A human opens one exact work item. A Participant needs `can-open-requested-run=true` and one unused authenticated human Run Request; a proposal still needs exact human approval. No selector, scheduler, batch, backlog poll, queued admission, or automatic retry grants authority.
- Admission refreshes native dependencies and assignment, snapshots delivery class and Run Policy, and binds implementer, checkout, and context. Conflicting external assignment pauses activation; unavailable capacity consumes no human authorization.

### Lifecycle

```text
ACTIVE ↔ PAUSED → CLOSED
```

`PAUSED → ACTIVE` resumes the same Run and generation. `CLOSED` is terminal and records one outcome:

- `completed`: for implementation work, the snapshotted policy is satisfied and the Broker has freshly verified authorized human merge of the unchanged candidate;
- `stopped`: the attempt ended early, with a reason and optional successor Run.

Later work starts a new Run. Forge outcomes such as merged, rejected, or cancelled do not become extra Run outcomes.

### Run Policy and generations

A Room-configured, versioned Run Policy defines required Gates, protected operations, eligible actors, evidence scope and freshness, timeouts, human attention, and the review cap. Implementation and review are Work Requests inside the Run, not extra lifecycle phases. Policy contains no arbitrary scripts, runtime conditionals, or workflow DAG.

A Run snapshots its policy ID and version when opened. Configuration changes affect new Runs only. Migrating an active Run requires an explicit human action, is recorded in the ledger, and fences the old generation.

Every Run-scoped Request and Command carries `run_id` and `generation`.

- Pausing and resuming retains the generation.
- Policy migration or an executed force-stop fences the current generation before work may resume.
- Input for a stale generation is rejected without side effects and returns current Run metadata so the caller can rehydrate.
- Closed Runs reject further state-changing input.

## Participants and coordination

Participant Profiles describe behavior and declared capabilities; prose grants no authority. Each seat directly names Runtime, startup arguments, Actor Identity, and Participant Profile. Runtime state may be shared; Git, Forge, Hub, branch, and audit attribution belongs to durable Actor Identities. Presence separates seat state, process incarnation, adapter connection, readiness, context-bound Run, provider validity, inference availability, and last observation.

A Participant is a stable, named Room member. Its running process, process-bound badge, runtime-native session, and conversation context are replaceable. The Participant persists across those replacements until explicitly closed or replaced.

A Participant's context generation binds to one Run when the first Run-scoped item is delivered. Pause, resume, policy migration, and ordinary process restoration retain that binding. Before traffic for a different Run may be delivered, a successful native context reset must advance the generation. Run Policy cannot waive this invariant, and compaction cannot satisfy it.

Reset preserves durable Room, Forge, Project, identity, profile, and ledger state while replacing the process, badge, runtime-native session, conversation context, and transient adapter state. Old Runtime session artifacts may remain under normal retention but are never resumed or injected automatically. Closed-Run traffic remains ledger history and is never delivered to the replacement session.

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
| Work Request | Supervised work or response traffic | Explicit lifecycle response |
| Command | A validated deterministic Hub or runtime operation | Recorded result |

A client submits a Run-scoped Request or Command with only:

```text
id, run_id, generation, kind, typed payload
```

The Hub derives the Room, authenticated actor, and capabilities. It assigns the durable `room_seq`, timestamp, and status. Client-supplied actor, status, timestamps, and arbitrary metadata are rejected.

Operation IDs are unique within a Room and act as idempotency keys:

- an authorized exact retry returns the original recorded result, even if the Run generation has since changed;
- canonical equality binds command kind, target, applicable generation, typed payload, and authenticated origin/security context; another Actor cannot retrieve a result merely by repeating an ID;
- reusing an ID with different content returns `ID_CONFLICT` without side effects;
- authenticated duplicate lookup precedes stale-generation validation.

## Request delivery and capacity

Delivery is pull-based from adapter-observed safe points. Process liveness and turn readiness are separate signals; ambiguity holds traffic rather than guessing that an agent is idle. The detailed Pi and Claude evidence is recorded in [Non-disruptive delivery signals](../research/non-disruptive-delivery-signals.md).

Every Request has two clocks:

- queue age starts at submission and detects starvation;
- response time starts only after the adapter confirms delivery to the target runtime.

Expiry escalates through reminder, coordinator when present, and human attention. It never silently cancels work.

Durable queue acceptance, confirmed Runtime delivery, Participant acceptance, and completed work are separate facts. Recovery may redeliver; receiver identity and deduplication protect accepted transitions, not exactly-once external execution.

A Participant has one active Work Request slot by default. A Participant Profile or Runtime may allow more slots within the same context-bound Run. Concurrent work across Runs requires another Participant. Work Requests follow:

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

## Independent review

`submit-for-review` binds the Run generation, exact pull request, candidate SHA, and evidence set. Idleness, prose, and pull-request existence do not submit work. The Hub selects an eligible Reviewer Participant; absence of one raises human attention rather than substituting identity.

One independent owner covers Standards, Specification, and Runtime at the exact candidate. Additional independent review addresses a named unresolved assurance need. Detailed findings and discussion stay in GitHub; the Hub stores the canonical review reference and one aggregate `review-result`, not a registered-Finding state machine or a `findings-clear` evaluator.

| Aggregate result | Hub outcome |
| --- | --- |
| `pass` | Proceed toward required Gates and human merge |
| `changes-requested` | Return the same Run to its implementer, subject to the cap |
| `human-needed` | Pause for human judgment without consuming a return |

The Hub derives reviewer identity and round, checks the review's repository, PR, author, submitted state, and candidate `commit_id`, and deduplicates by operation identity plus review reference and candidate. Pending, dismissed, stale, superseded, unavailable, crashed, timed-out, or incomplete reviews cannot qualify. Native review state alone does not choose the Hub verdict; see the [GitHub mapping](source-reconciliation.md#github-provider-contract).

The default cap is five valid changes-requested returns. The fifth pauses before a sixth implementation request. Pending CI and invalid attempts consume no return. An authenticated human may add bounded rounds, waive the cap, or issue a scoped audited override. Reviewer failure retains responsibility and has its own recovery/attention path.

Independent-review eligibility belongs to the durable Actor Identity, not a session, Participant, Runtime, model, or profile. Editing the artifact, authoring or amending a reviewed commit or conflict resolution, or supplying an adopted exact patch makes that identity ineligible. Coordination, research, test execution, and problem reporting alone do not. Sibling seats and native child processes cannot clear contribution history. A human override is recorded as an override, not independent review.

## Gates and human merge

The Hub adjudicates mechanical, attestation, and decision Gates from immutable Evaluations, each binding Run generation, policy version, producer, source, subject dependencies, Checks, and evidence. Missing, stale, malformed, ineligible, superseded, in-flight, or unverifiable evidence blocks protected operations. Only affected evidence is invalidated when a dependency changes; optional advice does not manufacture another mandatory Gate.

Repository-local `artifacts`, `diff-claims`, and exact-argv `command` checks use a supervisor-launched one-shot helper against a private disposable exact-revision target. It has no shell, network, deployment credentials, or Participant authority. It returns observations directly to the Hub, never verdicts. Pre/post target identity and bounded output carry `workstation-local / tamper-evident` provenance. `forge-state` comes through the Broker.

Complete-suite coverage, branch-required checks, focused proof, and specialized runtime/security/host evidence are distinct inputs. Bind CI to the exact candidate and relevant base, producer, run/job and attempt. A skipped or placeholder check is not coverage. Recheck target ancestry and evidence after waits; unavailable protection/rules information is unknown, not evidence that no checks are required. One durable owner resumes a pending CI checkpoint after restart.

After reviewer pass and required Gates, Manager presents a factual summary and **Open in GitHub**, without an approval or merge control. Only a fresh Broker read of the exact repository and PR, unchanged candidate, merged state, and authorized human merger permits `CLOSED/completed`. Record the integration commit separately from the reviewed head: GitHub's test-merge, merge, squash, or rebase SHA is not automatically the candidate SHA. Unknown or unsupported merge attribution raises attention rather than fabricating completion.

A human changes request binds the exact Run, PR, revision, and observed state. The Hub posts one ordinary GitHub comment through the Broker and routes implementation only after confirmed write or authoritative reconciliation. A changed head invalidates affected evidence and returns through the same Run's review path.

Overrides record the human, target, scope, reason, and result. They may change policy but cannot forge identity, invent cross-Project authority, suppress audit, disclose secrets, destroy unnamed work, or reattribute evidence.

## Ledger and recovery

Each Room uses its own append-only SQLite ledger. A command's result, events, materialized state, and committed sequence change atomically. Interrupted commit exposes all or none; restart preserves exact retry results. Snapshot state and sequence come from one consistent read cut. Cursor-range replay is ordered and bounded; network delivery may repeat.

Context reset is fail-closed and auditable:

- the ledger records reset requested, succeeded, or failed with the Participant, preceding Run, operation ID, actor, timestamp, and old/new monotonic context generation;
- native-session handles and transcript contents remain outside the Hub ledger;
- reset uses the existing idempotency key and an expected context generation, so stale completions and concurrent delivery attempts fail without advancing the generation;
- failure leaves the preceding Run closed and the Participant unavailable for another Run until retry succeeds; compaction is never a fallback.

- Durable commands and events receive a monotonic `room_seq`.
- Initial clients receive a snapshot plus its sequence.
- Reconnecting clients request events with `after_seq`.
- Hub-owned Forge projections use an idempotent outbox; authoritative provider reads reconcile pending, partial, or unknown writes before any repeat mutation. External assignment conflicts raise attention instead of being overwritten. Ordinary Participant mutations need the same no-blind-retry discipline.
- Process crash retains the active Work Request. Same-Participant restoration issues a new badge, waits for fresh safe-point evidence, and redelivers without consuming a review return. Failed restoration asks the human and lists eligible replacements.
- Manager replay retains source, version, staleness, and unknown state. Disconnection does not stop Room work, and stale typed human actions cannot mutate current state.

The successor does not add an event broker, vector clocks, log compaction, automatic backlog polling, or cross-Room routing. Pi Durable remains a [research candidate](../research/pi-durable-continuous-agents.md), not an implemented or approved replacement for this contract.
