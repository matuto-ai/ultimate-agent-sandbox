# Recoverable Library service and lifecycle reports

`uas.library_service.Service` is the T21 trusted Supervisor composition, not a
Participant command, deployment entry point, target provisioner or model client.
The Supervisor supplies a leased `LibraryGit`, a Project inventory factory, an
authenticated Hub transport, trusted permanent Room routing and an aware UTC clock.
The factory runs **after** lease acquisition, clone/fetch and canonical in-flight
reconciliation. It yields `Project(scope, runner, context)` descriptors: immutable
trusted inventory binding, actual T19 `Attempts`, and the T20 context selector.
Live Participant authority is checked independently; revocation cannot erase the
inventory identity or prevent an unrelated Project from starting.

Startup refuses a competing process before clone access, reconciles stable
operation identities against canonical Git before resetting its local cache,
and reconstructs fixed batches, attempt numbers, backoff deadlines and blocking
from the external SQLite journal. Canonical publication recovery precedes
validation of the next pending batch. Synthesis and source-parking commits carry
strict metadata receipts so a push followed by process death does not cause a
second model invocation/publication or lose per-draft outcomes. Project-local
corrupt/oversized bundles block that Project; shared Git/record-store failures
stop service progress. An interrupted uncommitted attempt may be retried with a
new numbered identity; its model output is never stored for replay.

Scheduler state intents include an optional strict lifecycle transition. STARTED,
RETRY_SCHEDULED, COMMITTED (including each draft outcome and canonical SHA), BLOCKED
and the later trusted OPERATOR_DISPOSED outcome are durable before report delivery.
The scheduler manifest remains bounded separately from the <=256 KiB safe outcome
metadata; no prompt, draft body, model output or source bytes enter the journal or
Hub report. The disposition is preserved as terminal; this module exposes no
human disposal control.

The external journal is also the outbox. Reports use immutable Project identity,
permanent Room ID, drain identity and transition sequence. `uas.library_hub.DrainReports` requires a trusted service
authentication callback and exact Project/Room binding. `RoomLedger` commits a
stable idempotent event without a Run or Participants. Lost acknowledgement means
at-least-once resend, not exactly-once transport; the ledger rejects a changed
payload under the same identity. Durable sender acknowledgements and paged cursors
avoid repeatedly scanning a lifetime prefix during bounded sweeps.

Hub delivery runs in a bounded Linux fork worker with an independent alarm and
process-group cleanup. It closes its inherited lease descriptor without unlocking
the parent lease. Offline/hung Hub delivery neither rolls back canonical work nor
changes drain backoff. A sweep bounds transport and SQLite waits; deadline expiry
leaves uncertain delivery replayable. Genuine shared-store errors are not disguised
as a Hub outage. Per-Project rotating sweeps avoid a dead Room starving another.
The transport must be safe to invoke in this isolated process; it should open its
own client/ledger connections, not depend on mutable parent memory or thread locks.

`tick()` selects at most one unit and flushes reports; `run()` polls until stopped.
The Supervisor can call `request_stop()` from its own signal handling: no new work
is selected, an active attempt finishes within the existing configured attempt
bound, reports receive one bounded flush and the lease is released. If the active
unit violates that bound, shutdown raises and retains its lease rather than
releasing ownership under live work; the Supervisor may force termination, after
which normal startup recovery applies. `flush()` and lifecycle methods are intended
for the single service-loop owner, not concurrent callers.

`tests/test_library_service.py` uses real temporary Git remotes, SQLite stores,
RoomLedger, bounded provider fixture subprocesses and actual process death after
intent/model return/push/report. It covers restart identity/outcome recovery,
revocation, source parking, cross-process lease exclusion, Hub outage/lost ACK,
malformed live Projects, shared-store failure, fairness and shutdown. These are
local deterministic acceptance proofs, **not** live-provider, production Supervisor,
operator-target qualification, VM, account or deployment evidence.
