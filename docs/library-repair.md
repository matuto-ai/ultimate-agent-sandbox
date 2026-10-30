# Explicit deterministic index repair (T37)

`Controls` accepts `observe` with `for_action: repair`, then `repair` with
`version: 1`, `project_id`, `request_id`, `settings_id`, and the returned
`observed_version`. Both calls require a fresh trusted `LocalHuman` grant for
`library-repair` on that immutable Project. No caller supplies paths, content,
identity, authority, or a replacement tree. No Room, Run, model, or provider is
needed. This is an explicit human action, not a scanner auto-fix.

The observation hashes the complete canonical Project and scheduler state and
returns metadata-only `reports` naming reserved indexes and uncertainty reasons.
That report is bound to the mandatory observation version; the human should
inspect it before requesting repair. An unknown/authored index is retained in
full, not partially rewritten. An otherwise valid uncertain index can coexist
with repaired reproducible indexes. If retained uncertainty leaves the complete
Project structurally invalid, the full gate refuses publication. The error code
reports the blocker without inventing history or rewriting knowledge.

Recognized service root/header/notice/identity/link forms and directory index
entries must be exactly reproducible from canonical documents. Missing known
root links or accepted-document entries can be restored. Unknown prose, ambiguous entry
forms, conflicting parked reasons, malformed input, or absent files whose prior
ownership is unknown are preserved/reported. Existing PARKED labels are retained;
a missing pending entry is always uncertain and is never recreated as ordinary
eligible work. Absence of a parked marker in possibly damaged history does not
prove active eligibility. No log is appended, reconstructed, truncated, or synthesized. No
concept, queue document, source pin, or semantic conclusion is changed.

The complete Project write gate derives the reconstruction independently. Only
those index bytes may normalize the predecessor structural check; all original
bytes remain the basis for proposed-tree history, actual diff, and changed-path
content policy. A caller cannot use the repair flag to smuggle arbitrary index,
concept, or history changes. Damaged logs still fail the normal complete gate.

Execution shares the non-preemptive scheduler turn and synthesis locks, yields
to older eligible Projects, persists least-recently-served accounting, and runs
under a 30-second cooperative budget propagated through canonical Git/record
operations. Existing file/byte limits remain in effect. Current human authority,
settings, service lifecycle, archive state, and input versions are checked before
publication. A changed Project input requires reconciliation and a fresh human
observation/request; there is no automatic retry or resurrection.

Ordinary fast-forward publication supplies canonical Git audit trailers and the
external metadata record supplies the terminal receipt. No-change requests are
explicitly audited `ACKNOWLEDGED / REPAIR_NO_CHANGE` without an empty Git commit.
The same request identity replays its durable receipt after fresh authorization;
a conflicting identity is rejected. Lost acknowledgement reconciles canonical
publication after restart without writing again. An unpublished unknown outcome
is reported as unknown, never reapplied. `Controls.reconcile` is receipt-only and
cannot create a new reservation.

`tests/test_library_repair.py` exercises public service requests against isolated
real Git repositories, SQLite and service restart. The native transport test uses
the actual authenticated private Unix socket; local EPERM is an explicit skip,
while hosted CI must execute it. These tests never repair user data.
