# Canonical review owner

`RunReview` owns review acceptance in the existing Room ledger. It does not
launch agents, merge a PR, interpret prose, or introduce a second workflow DB.
The persistent host composes the same ledger, GateHub, admitted identity,
`ReviewBrokerClient`, configured Reviewer seats/Forge user IDs, authorized human
merger IDs, and its existing source/worktree fence. It then calls
`AdmittedPeerDispatcher.attach_reviews(owner)`. The admitted dispatcher derives
the Origin and admission operation; packets cannot supply either.

Before submission, the trusted host binds the exact PR through the existing
`GateHub.bind_target`, and required Gates are evaluated for that subject.
`submit-for-review` carries only target and evidence references. The owner
consumes the current Gate view in its transaction and selects a currently
admitted independent Actor using the canonical positive/controlled Git history.
Missing or unreadable eligibility raises attention, never a replacement identity.

The assigned review is a normal peer Work Request. Existing offers, confirmed
receipts and acceptance are required before `review-result`. All three lenses
are one aggregate verdict and exact GitHub review reference. Native submitted
state supports, but does not choose, the explicit verdict. Latest author review,
exact candidate, repository, PR, stable author ID and admitted Actor epoch must
match. Detailed findings remain in GitHub.

Only a valid `changes-requested` result increments the persisted return count.
The configured policy cap defaults to five; the fifth return pauses before any
sixth implementation request. A scoped authenticated human control may add
bounded rounds, waive the cap, retry, or override review. Overrides retain their
human identity, exact target and reason; they never become independent passes,
fabricated Gate results or permission to merge. They cannot revive a stopped
native owner without its existing restoration path.

`complete` only observes GitHub. Pending merge stays ready; unknown attribution,
changed head and unsupported integration methods become attention. A qualified
human merge plus current required Gates closes the canonical Run, admission and
context together, preserving the reviewed candidate separately from integration
SHA. Outstanding work is cancelled with an event, not described as executed.
Existing delivery receipts remain immutable. Normal closure is not evidence of
native process termination or checkout deletion; those resources stay under the
existing lifecycle owner.

`request_changes` first reserves the exact human action, posts one ordinary
comment via the Broker, then routes implementation only after confirmed or
reconciled identity and a fresh exact-target observation. Unknown writes are
reconcile-only. Explicit `reconciliation_id` values reserve bounded new reads;
replaying one attempt uses its receipt. `retry_changes_preflight` is permitted
only after a proven rejection before any mutation journal/write, uses an explicit
new `preflight_id`, and preserves the original comment operation/target/body.
A generation or target change prevents routing even if the comment exists.

`snapshot_run` is a passive Manager source. Its Room sequence and `updated_at`
are stored observation metadata, not a claim that GitHub is currently unchanged.
Manager reads Gate/CI projections from their owners and exposes no merge action.

Controlled tests exercise actual SQLite transactions, the peer offer/receipt
outbox, authenticated dispatcher routing, dependency-bound Gate consumption and
synthetic Broker facts. Broker contract tests exercise its real audited adapter
with controlled transport. They do not qualify native startup or live accounts.
See [Review Broker boundary](review-broker.md) for supported merge shapes and
explicit uncertainty/reconciliation behavior.

Recovery is explicit and bounded. `refresh_request` observes the existing review
request/seat/context and policy timeout; failed responsibility becomes attention
without consuming a return. An authenticated retry control permits a new review
submission. A newly bound candidate/generation supersedes the old assignment and
approval, fences its old request, and starts a fresh exact-target attempt.

A successful stored observation is not a transferable freshness token. If a
caller crashes after recording it but before the final consuming transaction,
replaying that unfinished operation requires an explicit new `observation_id`
read attempt while retaining the original command ID and body. A completed
command still returns its exact terminal receipt without contacting providers.
A confirmed comment whose target refresh is temporarily unavailable remains
`confirmed-awaiting-target`; an explicit reconciliation read can route that same
comment once, without posting it again.
