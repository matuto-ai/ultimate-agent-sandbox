# Pi Durable as a continuous agent foundation

Research record, 2026-10-25. **Exploration, not an approved architecture change or implementation authorization.**

## Why this changes the discussion

Pi Durable should be evaluated as a foundation for continuous, event-driven agent work and its execution coordination—not merely as crash recovery around an existing CLI. The useful picture is an agent that receives an event, investigates, performs authorized work, accepts human steering, and remains available through multiple clients before, during, and after delivery.

For Ultimate Agent Sandbox, this could remove substantial custom conversation, task, inbox, observation, and recovery machinery. It does not remove the application's responsibility for deciding which work is authorized, what constitutes independent review, which side effects are allowed, or when a Run is complete.

The current approved contract remains [successor specification #58](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58), with its [specification lock #14](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/14). This note records a candidate direction to investigate against that contract. It does not change existing backlog scope, authorize automatic work intake, replace the native runtimes, or authorize implementation, deployment, merge, or migration.

## Evidence and its limits

The evidence combines the user-provided transcript of the [Pi Durable demonstration](https://youtu.be/BLRReTwV8Fc), the [official introduction](https://earendil.com/posts/pi-durable/), and the upstream README and examples. The transcript was read, rather than inferring the demonstration from the video's title or introductory material. No upstream example or end-to-end integration was executed for this research.

Upstream source was inspected at commit `d5b3de22d0e24a3e9c38a9410d3329b099717283`. The [README](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/README.md) identifies the package as experimental, with an API that can change without notice. Source examples demonstrate mechanisms; they are not evidence that Ultimate already implements them or that every native CLI supports the same capabilities.

### What the demonstration actually adds

| Video segment | Observed demonstration or explanation | Implication for this exploration |
| --- | --- | --- |
| 06:24–07:23 | Multiple clients share the same agent state; users can steer, fork, and interact with subagents. | A terminal, browser, and other client can be views of continuing work rather than separate agent sessions. Authentication and action authorization still belong to the application. |
| 08:19–10:35 | A Sentry event reaches the author's application by webhook; it triages the event, obtains root-cause analysis, fixes code, tests, and creates a PR. At 09:11 the author stops the agent; around 09:39 it continues. | The primary use case is an event-to-work lifecycle with intervention, not only recovery after process death. |
| 10:35–11:30 | The author merges the demonstrated PR, observes resolution, and can return to the same agent conversation. The author also describes other private software with different delivery policies. | Work remains inspectable and conversational after delivery. PR creation is one possible application output; automatic merge in someone else's setup grants no authority here. |
| Around 12:00 | The author describes additional guards for tracked projects, valid work, and one PR per incoming issue. | These guards are application logic, not guarantees obtained merely by installing the harness. |
| Around 14:15 | The author points to the upstream examples. | Evaluate concrete contracts through small examples rather than treating the demo as a turnkey sandbox. |

The proposed general flow is therefore:

```text
authorized event or human request
  -> intake and scope validation
  -> triage / diagnosis
  -> implementation and tests
  -> human steering, stop, or decision when needed
  -> policy-selected delivery (possibly a PR)
  -> continuing conversation and traceable outcome
```

This is a research model, not a replacement completion policy. Under #58, an implementation Run still completes only after the authorized human merges the unchanged candidate and the Hub verifies that fact through the Forge Broker. Event-driven intake would need an explicit authorization design; an external event is data, not permission to open arbitrary Runs.

## Candidate direction: durable primary agents plus native participants

Evaluate a hybrid system in which Pi Durable supplies the primary agent execution and coordination foundation, while native CLI participants remain available through adapters. Preserve the option to use existing Claude and Google-provider subscription workflows through their supported native clients instead of requiring every participant to move to direct model API billing.

This is a design objective, not a claim that a particular subscription can be used through Pi Durable. Model availability, account entitlement, supported authentication, and native-client integration must be checked independently. Programmatic OAuth support in a model library does not establish that an existing subscription automatically works in a different harness.

A durable coordinator can remember that it delegated work, wait for a result, and recover its own state. **That does not make a native CLI's internal model/tool loop durable.** A native participant might support session resume but not checkpointed tool execution; it might accept queued input only when idle, rather than live steering. The design must preserve those differences.

Use capability-based adapters rather than promising a universal runtime interface with identical behavior. Relevant capabilities include:

- observable process liveness and trustworthy readiness;
- input admission, receipt, correlation, and result observation;
- steering, follow-up queueing, and withdrawal of undelivered input;
- scoped cancellation, same-work restoration, and fresh-context reset;
- snapshot/event observation and independently verified tool-effect recovery.

For each capability, distinguish supported, unsupported, and unknown; record the evidence source. Manager must not display “stopped,” “delivered,” or “resumed” solely because a command was sent. A broker transport receipt is not proof that a model consumed input. Registration and runtime-specific adapter patterns are useful prior art, but need validation against the successor's identity and safe-point contracts.

## Revisit duplicated Hub plumbing, preserve domain authority

The opportunity is broader than adding checkpoints beneath the existing Hub. Inventory which planned execution mechanisms the harness already supplies before building a second inbox, task scheduler, conversation store, task ownership tree, or live event stream.

| Concern | Candidate reuse or simplification | Authority that must remain explicit |
| --- | --- | --- |
| Conversation, tasks, inbox, and execution recovery | Pi Durable storage, tasks, submission IDs, and checkpoints. | The application binds these IDs to Participant identity, Room, Run, and context generation. They are not interchangeable IDs. |
| Client views and ongoing intervention | Committed snapshots, event streams, steering, follow-ups, and scoped abort. | Client authentication, authorization, stale-action fencing, and truthful runtime-specific status. |
| Delegation and review execution | Separate conversations, configurable tools/models, child ownership, and background reporting. | Reviewer eligibility by Actor contribution history, exact candidate binding, required evidence, and human decisions. |
| External mutations | Harness tools can call bounded application services. | Forge Broker credentials, Project pinning, operation receipts, uncertain-outcome reconciliation, and merge verification. |
| Workstation and knowledge | Execution-environment integration can connect tools to the intended environment. | Room isolation, resource/lifecycle policy, Project data ownership, and the separate authored Librarian knowledge contract. |

This is a logical ownership split, not a decision to deploy every concern as a separate new service. A later design may express some deterministic application logic using harness tasks and documents; doing so must not turn model output into policy authority or weaken the external security boundary.

## Replay, cancellation, and approval boundaries

Submission deduplication is not universal exactly-once execution of external effects. A tool interrupted after a provider accepted a write can leave an uncertain result even if its input was admitted only once. Distinguish retry-safe reads, provider-supported idempotent operations, and mutations requiring authoritative reconciliation. Do not mark a Forge mutation replay-safe merely because the wrapper is durable.

Cancellation also has scopes: cancelling a client's wait is not cancelling work; stopping one conversation is not necessarily stopping background children; stopping a process cannot undo an already accepted external write. Record the requested scope, fence stale work, confirm native cancellation where supported, and reconcile outstanding effects. A resumed task must not revive revoked authority or an obsolete Run generation.

Approvals must bind to the exact action, candidate, Run generation, and relevant evidence. Human input in a shared conversation is not automatically approval for every tool action. Review completion and an agent's final answer cannot substitute for the application's delivery decision.

Stored sleep deadlines do not guarantee universal autonomous wakeup. The host must keep the scheduler running or supply an appropriate wake/alarm mechanism after process eviction. Restart, missing definitions, parked tasks, and unsupported native-runtime actions must remain visible rather than being reported as successful continuation.

## What to preserve from the original sandbox

The reviewed original source is useful operational evidence, not a frozen architecture to reproduce. It already embodies valuable contracts for repository/workspace/reference separation, project-local runtime state, identity-aware Forge routing, credential degradation, bounded native command policy, sanitized audit, stale launch preflight rejection, and conservative checkout cleanup. Its regression scenarios can guide successor acceptance without assuming the old implementation proves the new boundary.

Do not mechanically preserve a disposable per-session container as the successor's persistent Room workstation, mounted Git private-key bundles as the successor's external credential boundary, or agent-maintained workflow prose as authoritative Run state. Likewise, optional original nested-container settings and per-session broker identity assumptions require fresh review against the successor's confinement and multiple-participant model.

The useful migration principle is **retain tested behavior and operator needs; reconsider implementation ownership and simplify where the new foundation genuinely replaces custom machinery**. This note authorizes no change to the original installation.

## Smallest useful next experiment

If implementation is later authorized, prefer one vertical event-to-delivery slice over a crash-only demonstration:

1. Admit one explicitly authorized fixture issue/event with stable correlation, reject an out-of-scope event, and show repeated intake does not create duplicate work.
2. Let a durable primary agent triage, diagnose, fix, and test a disposable fixture. Attach a second client mid-run and verify both observe the same committed state.
3. Exercise steering, withdrawal of queued input, and scoped stop/continue. Delegate one bounded task to a native CLI participant and show its actual capability limits rather than emulating unsupported guarantees.
4. Interrupt execution and simulate a lost response after a Forge-like side effect. Prove retained responsibility, stale-generation rejection, and reconciliation without a duplicate mutation.
5. Present the exact candidate and evidence, then perform only the separately authorized delivery action. Preserve a conversation in which the human can question the completed work. For #58 implementation acceptance, retain the real independent-review and human-merge requirements.

The decision should establish what custom machinery can be removed, what must remain application-owned, whether native-client subscription workflows remain usable, and what cannot yet be guaranteed. A successful demo would justify a proposed design revision, not silently ratify it.

## Primary implementation references

The following source links are pinned to the inspected upstream revision:

- [Pi repository](https://github.com/earendil-works/pi) and [Pi Durable README](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/README.md).
- [19 — Inbox](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/19-inbox.ts): busy input, steering, follow-ups, rejection, and queued-input withdrawal.
- [20 — Late join](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/20-late-join.ts): current-state snapshot followed by incremental observation.
- [22 — Background subagents](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/22-subagent-background.ts): application-defined spawn/send/stop/list behavior, ownership, and durable result reporting.
- [27 — Reviewer](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/27-reviewer.ts): distinct model, role, tools, directory, and yield loop; not proof of Ultimate's independent-review policy.
- [23 — Child tasks](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/23-child-tasks.ts): ownership, wait/failure/cancellation, and restart in a synthetic example.
- [30 — Reload and restart](https://github.com/earendil-works/pi/blob/d5b3de22d0e24a3e9c38a9410d3329b099717283/packages/durable/test/examples/30-reload-and-restart.ts): extension lifecycle and restart behavior.

## Message-broker and native-adapter reference links

- [Psst](https://github.com/matuto-ai/psst)
- [Pi broker connector](https://github.com/matuto-ai/pi-broker-connector)
- [Claude Code broker connector](https://github.com/matuto-ai/claude-code-broker-connector)
- [OpenCode broker connector](https://github.com/matuto-ai/opencode-broker-connector)
- [Antigravity broker connector](https://github.com/matuto-ai/antigravity-broker-connector)
