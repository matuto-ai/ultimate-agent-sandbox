# Hub Gate evidence and protected-operation checks

`GateHub` extends the existing artifact Gate owner in the same `RoomLedger`.
The Hub derives Checks and immutable Evaluation verdicts. Participant prose,
helper verdict fields, policy names or a green provider rollup cannot advance a
Run. An exact retry reauthorizes and returns the original operation's attempt;
deliberate reruns require new IDs. No retry implicitly restarts uncertain helper
or Broker contact.

## Definitions and identity evidence

A Run snapshots the complete validated policy before effects. Stable Gate IDs
map to the two protected operation names `submit-for-review` and `complete`, with
simple conjunction. Definitions specify a mechanical evaluator or a typed
`attestation`/`decision`. Scope, source, guarded operations and dependency-based
freshness are compiler outputs; runtime input cannot choose them. Unknown fields,
unsupported evaluators, unsafe commands/paths or incomplete eligibility fail
admission rather than removing checks. The superseded `findings-clear` evaluator
is not accepted.

Identity configuration names an exact statement ID, `run` or `head` scope,
bounded eligible durable Actor IDs, an explicit relationship, required Hub
capability, self-assertion permission and continuing-authority requirement.
Independent review requires head scope, `review` capability, no self approval and
continuing authority. Its eligibility uses durable Actor contribution history;
changing a seat, session, Runtime or model does not establish independence.

An attestation accepts `assert`/`withdraw`; a decision accepts
`approve`/`reject`/`withdraw`. Payloads contain only Gate/statement IDs, typed
action, bounded note and bounded evidence references. Trusted authority reads
establish current Actor kind, epoch, capability and contribution evidence. Missing
or unverifiable authority produces error; ineligible identity produces an explicit
failed Evaluation. The latest submission per identity supersedes that identity's
prior approval, without rewriting history or vetoing another eligible approval.
An unresolved newer identity Evaluation blocks the shared Gate until its outcome
is reconciled; it cannot be hidden by another Actor's earlier terminal approval.

Every Evaluation records the authenticated source, exact Run/generation/policy
scope, Hub sequence/time, Checks and evidence references. Attestation passes are
displayed as **attested**, decisions as **decided**, never mechanically verified.
Current projections re-evaluate required continuing authority and eligibility.
Head changes stale head-scoped evidence; run-scoped historical statements do not
become stale merely because a commit changed. Generation/policy changes fence
every old Evaluation.

## Trusted target binding

`bind_target(operation_id, run_id, generation, target, origin=...,
expected_binding=...)` belongs to a separately authorized trusted workflow owner.
Its `authorize_target` callback defaults to denial and is independent of ordinary
evaluation authority. The target is an exact repository, PR ID/number, head/base
SHAs and base ref; payload alone does not establish truth.

The Hub first reserves a bounded durable binding intent, checks the owned source
head, asks the authenticated external Broker for fresh exact target observations,
then atomically rechecks source/Run/policy and the expected previous binding digest.
Only verified open, unmerged targets become the canonical Run binding. A stale CAS,
retargeted PR, lost authority or unknown read does not replace the old binding.
Interrupted binding recovery records an explicit error without replaying contact.
This narrow seam is not PR creation, candidate selection, review routing or final
merge authority.

## Current Gate views and acceptance boundary

Immutable historical verdicts are `passed`, `failed` or `error`. Projections also
represent missing, stale and in-flight evidence. Every state except `passed`
blocks a protected operation. A newer failed, errored or in-flight mechanical
attempt cannot fall back to an older pass. Forge passes require an explicit fresh,
audited read; interrupted refresh intent remains unresolved until trusted recovery,
not a reason to reuse cached authorization.

`operation_gates()` returns current Gate projections, blockers, policy and Run
dependency digests. It does not run long repository checks implicitly or close a
Run. `require_operation_gates(state, view)` is the no-I/O acceptance check inside
the canonical transition transaction. It rejects changed Run/generation/policy,
checkout/target bindings, superseding Evaluations, or an unqualified Forge refresh.
The transition owner must retain its external source/identity authority fence;
this view is not a transferable capability or a reusable authorization token.

Exact-candidate aggregate review, authorized-human merge and the acceptance-
evidence outbox remain responsibilities of their canonical #74 workflow owner.
There is no separate final Run approval or registered-Finding lifecycle in this
contract. Satisfying Gate predicates alone does not implement or waive the
remaining workflow, grant merge permission, or append `CLOSED/completed`.

## Proof boundaries

Pure identity and connected Forge tests exercise policy rejection, positive and
negative Checks, ineligibility, staleness, concurrent/uncertain attempts, exact
retry, restart and refresh recovery. Synthetic authority/source/client fixtures
prove reducer and state behavior, not process identity or native confinement.
The separate hosted external-Broker smoke uses real processes and a private
fixture-only credential, but no live account. Repository helper confinement and
the complete Run/review/merge workflow require their own explicit qualification;
ordinary green CI is not a substitute for those observations.

## Canonical known-contribution adapter

`ContributionOwner` records only positive, authenticated reports on the existing
Room ledger. The admitted peer dispatcher derives Actor and epoch from the current
process admission; packets cannot supply an Actor, clean flag, withdrawal, or
capability. A direct-edit report immediately retains that Actor. A patch offer
retains its authenticated source and exact content digest, but only adoption of
that exact report taints source and adopter. Merely offering an unused patch is
not contribution to the candidate. Metadata is bounded and no patch contents are
stored. Reports survive process resets, sibling seats, and later Run generations.

`AdmittedGateIdentity` combines this ledger with an atomic `GitProvenance` known
history snapshot, including controlled mutations and anchored commit lineage.
Unknown commit objects and failed reads are unavailable, never clean. The adapter
matches the submission's exact admission epoch and capabilities; it cannot borrow
a sibling seat's stronger profile. The host retains the admission fence through
the consuming Gate transaction. Human authority is a separate authenticated host
integration, not a synthetic Participant or fallback identity.

The contract uses `history_status: read` plus a content version, not an omniscient
`complete` claim. This follows the accepted trusted-peer boundary: unobservable
raw writes are not prevented or magically attributed. Positive declarations are
not mechanical proof of authorship; known positive history and controlled Git
records disqualify an independent reviewer. A new session never cleans that
history. Pure tests exercise actual routing, canonical persistence, exact retries,
known-history union, and an actual Gate submission/projection turning stale after
a later known edit. They do not constitute new kernel-admission qualification.

For protected transitions, the host holds `identity.operation_fence(admission_id)`
across `operation_gates()` and the consuming `RoomLedger.apply()`. Lock order is
admission, controlled-Git history, then Room ledger. The Git write transaction
pins the history cut: other connections cannot write, and same-owner mutation
attempts fail without releasing the fence. The consuming pure guard also compares
a digest of canonical positive reports, so a newly committed report between the
read and transition rejects the old view. Calling `operation_gates()` with this
adapter outside the required fence fails closed. No evaluator or Git subprocess
is launched by these reads.
