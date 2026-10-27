# Review Broker boundary

The Hub's `ReviewBrokerClient` uses the existing private Supervisor-to-Broker
channel and its held kernel identity. There is no Participant review-control
route. Trusted external startup selects `review_actor` from `mutation_actors`;
neither the request nor a credential name supplied by a Participant selects it.
Every provider call and response disclosure rechecks the current Room authority.

## Read observations

`observe(target, operation_id, authorize=...)` accepts the existing exact Gate
repository/PR ID/number/head/base SHA/base ref target. It returns an audited,
bounded normalized PR and complete review collection, never a verdict derived
from review prose. Reviews retain stable author and review IDs, commit SHA,
submitted state, timestamp and canonical GitHub reference. Incomplete pagination,
duplicates, changed targets and malformed provider responses remain unknown.
The closing PR reread also checks merger identity, not only normalized PR fields.
A repeated observation ID cannot cause another provider call or reconstruct lost
read evidence into a pass; a separately reserved observation is required.

Merged observations take `merged_by.id` and `merged_by.type` from authenticated
GitHub data. Login spelling is not a human-role signal. The Run reducer remains
responsible for its trusted authorized-human ID policy.

**Supported automatic integration qualification:** an exact two-parent merge
commit whose parents, in order, are the captured base and reviewed candidate.
The integration SHA is independent from the candidate SHA. A merged PR's raw
base SHA may equal the captured base or the integration SHA, but the verified
commit parents must still anchor the captured base. Squash, rebase, queue,
changed-base and ambiguous commit shapes do not qualify. GitHub PR responses do
not provide an authoritative merge-method field, so these cases return unknown
instead of inferring a method from commit message, author name or equal trees.
This is a deliberate support limit, not evidence of live GitHub qualification.

## Human changes comments

`comment(target, body, operation_id, authorize=...)` is an ordinary PR comment,
not a review or merge operation. It reuses the existing mutation journal,
trusted credential mapping, hidden mutation marker and read-only reconciliation.
A deterministic target marker binds the body to the exact candidate. The Broker
checks the target both during preflight and in the mutation provider's PR read.
GitHub comments do not expose compare-and-swap: the marker and the Run's fresh
observation fence a target moving after that read; the comment itself does not
claim an immutable provider snapshot.

`status: error` means preflight rejection or an audited authoritative observation
that no mutation journal exists. The latter recovers a Hub crash after recording
its intent but before Broker dispatch: because audit precedes provider contact,
absence proves that the external write never started. This conclusion is never
guessed from a GitHub error or timeout. A journal found on a later retry always
routes to mutation reconciliation, never back to an old absence receipt;
it permits only an explicitly reserved new preflight attempt with the same write
identity. All unconfirmed journaled outcomes remain `unknown`, never a signal
to retry the write.

Only a verified/reconciled comment produces `status: confirmed` and its stable
`{kind: comment, id, url}` reference. A replay never issues another POST.
`reconcile_comment` uses the same original operation, target and body and performs
only bounded reads. A lost response remains unknown until evidence reconciles;
absence or conflict does not authorize another write. Repeated reconciliation of
the same attempt reuses its durable result rather than secretly polling.
An explicit `reconciliation_id` reserves a distinct bounded read attempt while
preserving the original write ID, target and body. Similarly, an explicit
`preflight_id` permits a fresh target read when no mutation has been journaled.
The Hub must durably reserve these attempt identities; neither ID is an implicit
retry or permission to POST again. Omitting an attempt ID selects a stable first
attempt for compatibility.

Operation keys are scoped to the Room incarnation as in the existing mutation
owner. A Hub/Broker process restart within that incarnation can reconcile the
same request. A replacement Room incarnation must not silently reissue an old
human action; its existing lifecycle fencing must leave that action unresolved
rather than treating a new key as permission to duplicate it.

Tests use controlled providers and temporary SQLite. No live account, process
credential, socket, native VM or end-to-end deployed boundary claim is made by
these tests.
