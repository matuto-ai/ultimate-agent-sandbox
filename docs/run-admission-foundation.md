# Bounded Run admission and control

This completes the **account-free fixture scope** of [#72](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/72): one exact Forge item, authenticated Participant entry paths, canonical Run controls, owned native stop and context/checkout reconciliation. It reuses `RunAdmission`, the RoomLedger, Participant controller, CheckoutAllocator, Pi adapter, and existing Forge observation/assignment/projection services. It is not Manager login, production Workstation authentication, live GitHub/account qualification, review adjudication, authorized merge verification, or whole-product completion.

## Admission and authority

`RunAdmission(controller, broker, allocator, config, ..., authorize_human=...)` accepts trusted human commands through a freshly checked scoped `Origin` callback. That callback is an integration seam, **not a production human-authentication implementation**. `controller.bind_runs(admission)` connects Participant requests to the existing per-record Linux credentials, held child/pidfd, immutable badge and revocation checks. A client cannot supply an Origin, actor, Project, repository, policy, or human capability.

Three explicit paths share the same admission transaction:

- `open(operation_id, issue_number, implementer, human=...)`: trusted human opens one exact positive issue number in the pinned Project.
- `issue_request(operation_id, issue_number, requester, implementer, human=...)`: persists one exact authenticated human Run Request. The named requester needs `can-open-requested-run` in its current configured profile **and** effective process badge to consume it with `open_requested(operation_id, request_id, origin=..., authorize=...)`.
- `propose(operation_id, issue_number, implementer, origin=..., authorize=...)` records data only. `approve_proposal(operation_id, proposal_id, digest, human=...)` requires the exact immutable proposal digest and creates a Run Request for that same requester/issue/implementer. Repeated or conflicting approvals cannot create another grant.

The process channel accepts only `{id, kind, payload}` with `run-propose`, `run-open-requested`, or `run-coordinator-nominate`; each payload has an exact allowlist. The official Pi fixture exposes these through `uas_run`. Human creation/approval needs `human-open-run`; revocation and lifecycle controls need `human-control-run`. Human and Participant operation attribution remain separate in the durable admission and grant records.

No selectors, batch opening, schedule, backlog polling, external label event, implicit coordinator authority, or retry queue exists. Grants/proposals each have a 32-row bound; admission and canonical Run tables retain their existing bounds. Exhaustion is an explicit refusal, not hidden intake or automatic pruning.

## One atomic binding

1. The ledger reserves the exact issue, implementer, native context namespace and future bounded Run/request footprint. Competing SQLite connections serialize. At most one non-closed reservation/Run owns the same issue or implementer. A Run Request may be reserved by only that admission root; it remains **UNUSED**, not consumed.
2. The authoritative allocator inspects/reuses the exact owned Run/Participant checkout. Admission authorization is checked inside its mutation lock. Dirty, mismatched or uncertain state is preserved. No cleanup, branch reset or overwrite is inferred from a new Run.
3. A first Run requires an unused native context and fresh official Pi context proof. A later Run requires a verified stopped/closed predecessor, a new exact authorization, and the existing native reset protocol. Reserving the next Run does not relabel the old context. Successful reset advances context generation before delivery; dirty/unknown checkout reuse remains blocked independently.
4. Fresh bounded native GitHub reads bind the exact open issue, complete all-closed dependencies, current sole assignment, and known delivery class. The optional audited self-assignment path never overwrites another assignee. Conflicts/unknown facts hold activation with durable attention. Git is observed again after provider I/O; the final Forge read must be at most five seconds old. This is a bounded observation interval, not an atomic remote GitHub lock.
5. Activation refreshes the configured default Run Policy and binds its complete versioned evidence contract, implementer, checkout, Run generation and native context generation. One ledger transaction commits `ACTIVE`, exactly one implementation Work Request, Run Request consumption (when applicable), and the existing Forge projection outbox intent. Capacity/storage failure rolls the transaction back without consuming the grant.

A pending admission may own an unused process/checkout before eligibility succeeds, but owns no active Run and queues no implementation request. Explicit `attempt_id` refreshes retain the same exact root/grant/target and re-read facts. Exact retries return immutable receipts after fresh authority checks; they do not repeat remote contact or consume another grant. Revocation during preparation fences subsequent effects and consumption.

## Pause, migration, and native restoration

`pause` and `resume` require exact `(run_id, generation, expected_revision)` and a bounded reason. `ACTIVE ↔ PAUSED` retains generation, policy, context and checkout. A monotonic control revision prevents an old Resume from affecting a newer pause cycle. Pause holds **Hub delivery**, not native inference or Project writes. Unknown native handoffs stay unknown.

`migrate_policy(operation_id, run_id, generation, revision, policy_id, policy_version, reason, human=...)` selects one exact currently configured policy. Its first transaction pauses/fences the old Run generation, cancels stale traffic, snapshots the new policy, and queues one new-generation implementation request while delivery remains held. It preserves context generation, Run binding, native session and old handoff records. The owner advances the Pi journal and existing context checkpoint with exact scope CAS; an interrupted two-store update remains pending and the same explicit operation repairs it. A successful migration still needs explicit Resume.

Every native handoff is serialized with journal scope CAS. An old prepared offer cannot inject after rebind. A checkpoint keeps its exact native session and original reset lineage; missing native proof fails closed rather than being reconstructed from a canonical Run row. Ordinary explicit `controller.restore_pi(seat, recipe)` uses the same checkpoint/session and passes through the exact checkout. Restoration is not a new Run or a context reset.

## Force-stop, terminal stop and withdrawal

`force_stop(operation_id, run_id, generation, revision, reason, human=...)` is an out-of-band human command, not a Message. It durably pauses/fences the old generation and cancels stale traffic before stopping exact owned native children. It attempts same-context generation/checkpoint preservation first; missing restoration metadata cannot prevent the stop, and is retained as explicit restore attention. Stop succeeds only after exact ownership and native exit are verified. Persisted numeric PIDs are never adopted as kill authority; possible retired writers and replacement races remain unresolved.

A stopped Run cannot resume by flipping its status. Explicit same-context native restoration must first establish a live owned handle in the current scope and **canonical checkout**. Human Resume then queues one current-generation implementation request; it does not replay cancelled/unknown old traffic. Failed native restoration remains held, or a human may terminal-stop the attempt.

`terminal_stop(..., reason, human=..., successor_run=None)` records `CLOSED`, outcome `stopped`, the exact reason and optional successor reference after verified stop. A later exact Run uses the native-reset path; closed history is never reactivated. `completed` still requires later policy/review/human-merge evidence and is not produced here.

`withdraw(operation_id, pending_run_id, reason, human=...)` first fences a pending admission as `WITHDRAWING`. Allocator and launch/reset callbacks recheck that fence inside effect locks. Funded Forge reads and uncertain assignment writes must settle/reconcile before closure; withdrawal never retries a POST or rewrites an unknown outcome as absent. Owned native children are stopped, checkout release is delegated to its authoritative allocator, and dirty/unknown resources remain preserved. Failed/in-progress resets retain their exact unknown context state. Only terminal withdrawal releases an unused grant's reservation; it never changes its exact issue/requester/implementer. Retargeting requires a separate exact command, never editing the held root.

Stop/release actions recheck the exact pending command and fresh human authority inside each owner's effect lock. A loss of acknowledgement is reconciled against immutable receipts before repeating effects. No filesystem cleanup, assignment removal, new permissions, deployment or credential changes are implied by stop/withdrawal.

## Temporary coordination

`appoint_coordinator(..., participant_id, human=..., ttl_seconds=300, request_budget=8)` can assign, replace or remove one configured, current, same-Run Participant. Bounds are 1–3600 seconds and 1–16 prioritized Work Requests; appointment is tied to the exact process incarnation and Run generation. It changes no capability, merge, cancellation or force-stop permission.

A coordinator's bounded Requests receive delivery priority but never forced acceptance or additional work slots. Excess Requests remain ordinary peer traffic. Participant nomination/handoff is data requiring a human appointment. Loss or connection replacement atomically clears coordination and records human attention while the Run continues in peer mode. Expired appointments immediately lose effective priority; the owner's explicit reconciliation records expiry attention without a background intake scheduler.

## Evidence and limits

Pure tests (`test_run_requests`, `test_run_lifecycle_control`, `test_run_coordination`, `test_run_generation_binding`) exercise positive/negative admission, exact approval, capacity, storage rollback/lost acknowledgements, stale generations/revisions, ownership races, migration CAS, checkpoint recovery, uncertainty, and bounded coordinator authority. Their synthetic handles/observations are **not process, native Runtime or live-provider proof**.

The existing automatic `pi-native` workflow, still capped at **three minutes**, runs `test_pi_run_management` alongside the original admission/context suites. The new fixture crosses actual owned Git, official Pi 1.4.0, a kernel-authenticated fixture requester, durable ledger and controlled account-free GitHub responses. It covers request/proposal approval, wrong-process refusal, no-capacity/no-consumption, migration with same native context, verified force/terminal stop, same-session restoration in the canonical checkout, dirty-state retention, cross-Run native reset, and coordinator loss. Existing tests retain human open, duplicate race, dependencies, assignment conflict, pause/resume, provider uncertainty and projection coverage.

Local source-only work must run only explicitly audited pure cases with fail-closed native guards installed before repository imports. Real process/socket/Git/native fixtures belong in bounded hosted CI; skipped or unexecuted checks are not evidence. No VM, live account, paid inference or production qualification is added by this slice.
