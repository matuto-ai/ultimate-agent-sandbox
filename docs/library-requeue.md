# Releasing parked work after its prerequisite resolves (T27)

The authenticated Library Service operator transport accepts `requeue` with
current Project `library-requeue` authority. Observe the Project with
`for_action: requeue`, then send version 1, `action: requeue`, `project_id`, the
recorded parking `drain_id`, a unique `request_id`, the observed `settings_id`
and `observed_version`. No caller path, queue list, reason, identity or commit is
admitted; the existing 8192-byte transport bound and typed envelope apply.

## What is released

Parking leaves a draft in `pending/` with draft status and a pending-index entry
labelled `DRAFT PARKED: <REASON>`, so ordinary selection skips it. Requeue
rewrites that entry back to its ordinary draft form for the parked outcomes the
named drain recorded in canonical `log.md`, and appends one `Library requeue
receipt` line naming the released and retained queue IDs with their safe reason
tokens. The draft file itself is byte-identical; only the pending index and the
log change in one canonical commit. Nothing is deleted, reinterpreted or
re-verified.

A queue is released only when both checks pass. Its recorded reason must be a
service source prerequisite (`SOURCE_*`/`SECRET_DETECTED`), so a model- or
human-declared contradiction is never released. Its recorded source pins must
resolve now through the same trusted resolver and secret policy assembly uses;
a missing, still-failing or uncertain pin keeps the draft parked. A draft with no
recheckable pinned source therefore stays parked rather than being guessed at:
requeue is not a repair path, and a malformed declaration needs a new draft.

The canonical state is authoritative at restart: released drafts stay released
because Git no longer marks them parked, and the scheduler rebuilds from Git
plus external records. Parked drafts that were not eligible are unchanged, and a
later request may release them once their prerequisite resolves.

## What it does not do

Scheduling state is not touched. Requeue invents no drain, no attempt, no model
call and no scheduling acknowledgement, so a `BLOCKED` Project stays blocked, a
`DISPOSED` drain stays disposed, a backoff is not cleared and fair priority is
unchanged: released work becomes ordinary pending work and is executed only by
the existing `drain`, `retry` or separately receipted `resume` actions. An
archived Project refuses the action. An active attempt refuses the release only
when the released queue is one of its own selected inputs, which is the input
change that attempt's fences protect.

## Fences, identity and recovery

Observe binds immutable Project identity, current coordinates, configured
settings, complete durable scheduling state and the canonical Project-content
digest. A changed state, content or configuration requires a refreshed
observation instead of a forced write. The action binds the authenticated human
and Actor, action-specific Project capability, Project identity, settings
identity, request ID, drain ID and observed version, and the same request ID
under a changed payload or identity is a conflict. An accepted request returns
its recorded receipt without a second commit.

Only a pushed commit establishes success, and its receipt cites that commit and
`log.md`; no receipt invents a Git commit for a scheduling-only effect and none
retains a draft body. A crash after push but before the receipt reconciles
against canonical publication, returning the original commit without another
write. An unresolved pre-push operation remains `CONTROL_OUTCOME_UNKNOWN` until
reconciliation or restart; authoritative absence never re-applies the old
payload, so the human refreshes and uses a new request ID.

## Evidence boundary

`tests/test_library_requeue.py` uses disposable real Git repositories, SQLite and
the started Service: a mixed resolved/unresolved drain released in one commit
with the draft preserved, a retained draft released later, a model-declared
contradiction left parked, stale/archived/busy/revoked refusals, a `BLOCKED`
Project that neither clears nor executes the release, exact retry,
changed-payload conflict, restart eligibility, lost acknowledgement and an
unknown pre-push outcome. These are deterministic fixture proofs. Manager/Hub
transport for this action (T32), real deployment authority (T31), the separate
disposed-batch resume (T26) and any live-provider or target qualification remain
outside this slice.
