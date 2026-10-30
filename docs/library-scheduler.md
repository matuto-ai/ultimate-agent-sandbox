# Fair Library drain scheduler

`uas.library_scheduler.Scheduler` is the T20 trusted service owner. It registers
actual T19 `Attempts` compositions sharing one leased publisher, polls bounded
publication mailboxes and performs at most one unit per `tick()`. It does not add
Participant commands, HTTP routes, a model client or a background timer. T21 owns
the process loop, startup inventory and report replay; T22 authenticates human
controls before invoking `request(project)` or the distinct `retry=True` action.

Registration/reconciliation makes an eligible Project runnable. A publication
wakes an idle Project after the configured coalescing interval (initially ten
seconds). Further publications cannot postpone its first wake, clear backoff or
release BLOCKED state. Explicit drain removes delay but neither preempts the
active unit nor changes fair priority. Explicit retry releases a blocked drain
with its complete original queue IDs and a new attempt number.

The eligible least-recently-served Project wins, with immutable canonical identity
as tie-breaker. A durable service timestamp/monotonic tie counter reserves the
turn before inference, including failed turns. Wall-clock deadlines are stored as
UTC timestamps; the injected clock must be timezone aware. The service should
supply a synchronized wall clock. An attempt yields whether it commits, parks,
fails or finds an empty queue. Project-local revoked authority, archived/invalid
queues and model blocking do not prevent unrelated eligible Projects progressing.
Shared operational-store failure fences selection until recovery.

Canonical Git creation order, then queue ID, selects pending drafts. The bounded
history scan returns only the selected Project's content-addressed queue IDs and
preserves original creation order across later coordinate changes. Parked entries
are excluded. A batch stops before exceeding configured count or complete draft
bytes; a first draft that cannot fit blocks rather than silently skipping it.
Initial limits are eight drafts, 64 KiB and 120 seconds. They come from validated
shared settings with existing fixed maxima, not scheduler constants. T19 snapshots
its operation settings and retains its bounded inference/publication contract.
Later enqueues cannot enter an existing drain.

Scheduling metadata is a strict <=8 KiB manifest in the existing external
LibraryRecords journal: identities, ordered queue hashes, counters, state and
deadlines only. No content, prompts or model output is stored. Transitions use
unique identities; a lost acknowledgement is reconciled by reading the latest
durable intent. In-process uncertainty fences selection. Re-registering after
restart preserves backoff, BLOCKED and fixed batch; an interrupted active unit
gets a new numbered attempt, whose T19 reconciliation checks canonical publication
before any new model contact. T21 startup/report recovery is composed by `Service`; see
[Library service](library-service.md).

Retry delays are 5, 30, 120, 600 and then 1800 seconds capped. Transport failures
have no fixed retry-count limit. Prior T19 intents are settled only after
successful authoritative canonical-history reconciliation proves no publication;
all evidence is retained and the settled numbered attempt cannot execute again.
Paged history avoids the previous 256-read ceiling, and settled absence does not
cause an unbounded sequence of repeated network searches. The current unresolved
attempt remains recoverable; a lost push is reconciled before settling anything.
Three model timeouts/deterministically invalid outputs block the Project and
original drain. Storage, source, authorization and transport failures never count
as model invalidity; successful work or explicit retry resets the model streak.

A short scheduler lock protects selection/state only. T19's separate synthesis
lock and the service's exclusive publisher lease retain global serialization;
neither Git writes nor an SQLite transaction are held during provider latency.
A context selector may provide accepted concept/index references to T19; it is
trusted service composition, not model-controlled retrieval authority.

Tests exercise real disposable Git, actual operational SQLite records, bounded
provider subprocesses, two Projects, fairness, coalescing, explicit controls,
backoff/blocking, later drafts, authorization races, lost push/records and retained
histories beyond 256 attempts. No live model/provider, credential, privileged host
or target qualification is claimed. A measured parallel scheduler CI lane keeps
this ~25-second suite out of existing near-minute lanes while preserving all
unit inventory and existing timeout/downstream gates.
