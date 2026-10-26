# Restricted canonical Run-admission foundation

This is an account-free, source-level vertical slice of [#72](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/72), **not complete or generally usable Run management**. #72's formal dependency on #69 remains unsatisfied. No production human authentication, external credential authority, Forge write/projection, human merge, deployment/image, or hostile-Hub qualification is claimed.

## Connected path

`RunAdmission` in `uas/run_admission.py` connects the existing RoomLedger, Supervisor/CheckoutAllocator, process-owned official Pi 1.4.0 adapter and read-only Forge Broker. The only caller is a trusted typed human-command seam with a freshly checked `Origin`/authorization callback. No native Participant tool or untrusted payload can select human authority. The callback is an integration boundary, **not** a Manager login implementation.

The command names one positive issue number and one configured Pi implementer in the pinned Room Project. The configured Actor has an explicit immutable `github_user_id`; it is configuration, not live credential/account proof. A pending refresh rejects changed Actor-ID, configured seat/profile/capability or process-seat binding before Git, provider or native effects. An already-terminal exact attempt still returns its immutable result under fresh human authorization; configuration changes do not migrate the snapshotted policy. The configured profile and supplied seat must both permit implementation. The default configured policy is snapshotted, and its complete bounded policy/evidence contract is included in the implementation Work Request rather than merely its name. Policies too large for that delivery fail before admission or Git effects.

1. One ledger transaction reserves the exact issue, Participant, bounded context entry and future Run/request footprint. Concurrent reservations serialize. The pending admission has no product Run status and has **not consumed** the human authorization. Capacity rejection leaves no partial reservation, no Git effect and no queued retry.
2. The existing allocator commits its own intent before actual Git effects. Explicit recovery first inspects its authoritative manifest/Git state and reuses only the exact owned Run/Participant slot. Dirty, unknown, mismatched or oversized observations hold; nothing calls `git clean`, force-delete or global prune.
3. Only an unused first native context is admitted. A fresh official Pi process starts in the actual owned checkout, with the existing fixed account-free recipe and process-bound authority. An already-used or live preceding Run is not relabelled. Native empty-session proof, immutable scope, PID-owned working directory, safe-point evidence and fresh authority must agree. A dead exact pending child can be replaced; unverified live retired PIDs block replacement.
4. The trusted controller requests an audited Broker read under its owned process authority. This is not a claim that the human request originated as a Pi `gh` tool call. The same provider reads the exact issue, all bounded native blocker pages and all bounded label pages. Eligibility requires an open issue, complete all-closed blockers, exactly the configured implementer's GitHub ID as sole assignee, and one known delivery class. Missing assignment, external conflict, permissions, missing/conflicting labels and incomplete reads hold with durable attention. No assignment is created or overwritten.
5. Git is reobserved after provider I/O. The final observation must be at most five seconds old; the provider traversal itself is bounded to thirty seconds. This is a bounded observation interval, **not an atomic GitHub snapshot or assignment lock**.
6. One transaction commits the canonical `ACTIVE` Run, policy/issue/slot/context binding, exactly one `QUEUED` implementation request, and authorization consumption. Existing safe-point delivery then advances the request; timing starts only after the native receipt. Work-request completion or `FixtureContextHub.close_run` cannot complete the canonical Run.

The checkout/process are prepared before the final eligibility read because this restricted Broker seam needs owned process authority. An ineligible issue may therefore retain a clean owned checkout and an unused native context, but receives no implementation request and no canonical ACTIVE Run.

## Immutable attempts and uncertainty

`open(root_operation_id, issue_number, participant_id, human=...)` uses a stable initial attempt ID. An explicit human refresh supplies a **new** `attempt_id` while retaining the same admission root and exact human authorization. Exact retries preserve immutable attempt results: a held attempt returns the original reason without another provider contact, and an activated attempt returns its original result rather than a mutable Run projection. Conflicting operation reuse fails.

Each attempt has a stable Broker observation ID. Before read contact, the Broker atomically transfers its bounded pending-read footprint from that admission's reserved bytes, retaining a durable refund record. The joint peer/context reservation model budgets the eventual refund and maximum attention reason, so other traffic cannot consume temporary padding. Terminal read, abandonment and restart recovery refund exactly once; a completed canonical activation retires obsolete funding. Saturated peer traffic and all 64 context rows do not strand the admitted read/activation/delivery. A pending read is recovered as unknown, never blindly repeated; an existing completed read is not reused as fresh activation proof. A new explicit refresh is required. Possible activation-commit acknowledgement loss is reconciled against the immutable terminal receipt before any compensating hold. Verified late process-authority loss uses the existing Broker abandonment path and cannot leak pending-read reservations or downgrade a committed read.

Known eligibility failures record `PREPARING` admission attention with authorization unconsumed. Storage uncertainty retains intent/ownership for explicit recovery. There is no background retry, backlog selection, scheduler, label-triggered opening, selector, batch intake, or coordinator privilege.

## Explicit pause/resume

The same `RunAdmission` owner exposes `pause(operation_id, run_id, generation,
expected_revision, reason, human=...)` and `resume(...)`. These typed trusted
calls require the separate `human-control-run` capability and the fresh scoped
human authorization callback on every attempt, including exact retries. The
callback is still not human authentication. The bounded reason is a token,
recorded with the authenticated origin in the ledger.

`ACTIVE → PAUSED → ACTIVE` preserves Run generation, native context generation,
policy, issue/Participant binding, checkout, implementation request, and
consumed admission. A separate monotonic `control_revision` starts at zero and
increments on each transition. Callers must supply the current revision; an old
Resume cannot apply to a later pause cycle with the same Run generation. At the
maximum revision (`2**53 - 1`), new controls fail closed. Existing canonical rows
without that field are treated as revision zero. The immutable exact operation
receipt is returned before current revision/state checks, but only after fresh
authorization. A retried admission still returns its original ACTIVE receipt,
not the mutable current Run status; read the canonical ledger projection for
current state.

Pause is a **Hub traffic hold, not native inference interruption or verified
process stop**. Work already handed to Pi may continue, including Project-file
changes. New Run-scoped submissions, offers and confirmations are fenced by
the existing canonical Run scope gate. An in-flight native receipt arriving
after pause leaves its durable Hub offer UNCONFIRMED; neither control changes
that unknown into success, cancellation or failure. Resume does not contact the
provider, relaunch, reset, automatically deliver, or inject another request.
Normal safe-point delivery may subsequently reconcile the same native receipt
without reinjection; an unresolved native intent remains unknown. Policy
migration, process restoration and native stop remain distinct operations.

Control commits serialize with admission on the existing RoomLedger. A control
cannot queue itself against a pending admission: before canonical activation it
fails UNKNOWN_RUN; after activation it applies only to the exact current
revision. Reserved projection capacity includes the largest future revision and
reason, so ordinary traffic cannot consume already-admitted control headroom.

Admission withdrawal is deliberately still unavailable. Current admission can
allocate Git state and launch an owned Pi outside its final activation lock;
merely writing a withdrawn tombstone would fence final activation but could
still permit an in-flight launch. Safe cancellation requires explicit stage and
ownership reconciliation before it can claim cancellation or resource release.
Held admissions retain their exact owned process, context and checkout for
inspection/explicit same-root refresh. No new orphan or cleanup state is added.

## Exact specification boundary

The frozen #58/#72 contracts require fresh facts, exact human authority, unique non-closed work-item ownership, policy/checkout/context binding, conflict attention, and no authorization consumption on capacity failure. This restricted path implements those source invariants for an **already correctly assigned issue**; the protocol explicitly calls Forge lifecycle labels projections, not locks. No accepted sentence makes successful assignment-write/label projection a precondition for a correctly preassigned issue, so no-write source admission can be exercised without inventing #68/#69 behavior. Nevertheless, the formal dependency graph is unchanged and this is not #72 acceptance.

Canonical Run rows explicitly report `projection: unavailable-no-write-support`. This does not mean a projection succeeded, is absent, or was reconciled. #68/#69 still own audited mutations, uncertain-write reconciliation and the idempotent projection outbox. The existing RoomLedger read audit is not the required Deployment-level Forge audit service.

**Deliberately unavailable:** admission withdrawal/retargeting, Participant Run Requests/proposal approval, policy migration, coordinator changes, force-stop/terminal stop, canonical Run completion and later cross-Run admission. A held intent retains its issue/Participant/checkout; another issue cannot take that seat. Explicit same-root refresh can resolve repaired facts, but changing one's mind requires later withdrawal/native-reset work. Do not advertise this as general operational Run management or bypass these limitations with fixture close/reset calls. No production CLI/Manager action is exposed.

The controlled Pi recipe has no built-in coding tools and uses a local faux provider. Evidence proves **delivery of an implementation Work Request**, not autonomous issue implementation, paid inference, live GitHub permissions, or the full Pi/Claude/review/merge lifecycle.

## Verification

```sh
./validate.sh
UAS_PI_INSTALL=/path/to/locked/pi-install sh tests/pi/run-tests.sh
```

`test_run_control.py` covers fresh scoped authority, immutable retry/reopen/replay, stale generation/revision, ABA fencing, concurrent same-revision controls, exhaustion, control-commit rollback and lost-acknowledgement recovery. Actual Pi admission tests additionally cover paused queued delivery, same-binding resume, dirty-byte retention, activation/control serialization, late-ACK reconciliation without reinjection and literal native unknown retention, and maximal control revision/reason growth after peer/context capacity saturation.

`test_run_admission.py` covers typed authority/capability refusal, exact selectors, immutable IDs, bounded policy/context/shared projection capacity and a concurrent separate-SQLite-connection reservation race. `test_pi_run_admission.py` crosses actual Git, actual official Pi and controlled GitHub responses: durable canonical admission/delivery, exact retries, conflict/unknown/dependency holds, explicit refresh, Git-effect and activation-acknowledgement loss, native exit, stale-read recovery and late process revocation. Provider/configuration tests cover bounded label pagination and immutable-ID validation. Existing Claude/CI/VM policy sources are unchanged; no VM or paid provider is triggered by this work.
