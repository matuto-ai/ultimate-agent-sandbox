# Private Manager Library transport — T31 / #189 and T32 / #193

`FieldNotesLibraryHost` is an attachment to the existing authenticated Manager
host, not a new listener, login, UI, credential or deployment. The host supplies
trusted request context and resolves a fresh `HumanSession`. Its fixed
`ManagerLibraryHub` owns deployment/Room/instance and immutable Project identity.
`LibraryServiceContact` independently resolves a current `LocalHuman`; both host
and service grants fence every service read/publication and response disclosure.
A same-named Project with a different immutable source identity is denied.
Installation settings authority never implies a Project grant. No Run state,
Workstation process, active generation or browser-provided authority is required.
An authorized Hub path therefore remains usable with no Run or stopped Workstation.

The wire envelope is `{version:1, operation_id, mode, request}`. `request` uses
`library_controls.decode`: inspect observation, bounded private inspection or
reasoned rejection or adjudication. This slice proves the accepted T24 reject
path independently; composition with merged T25 additionally proves private
conclusion/rationale submission and lost-response reconciliation. Modes are `execute` and
`reconcile`. Unknown fields, duplicate JSON keys, settings operations and oversized
requests fail closed. Responses preserve inert plain text, do not fetch resources,
and remain bounded by the owning inspection service and complete transport cap.

## Persistence and uncertainty

A ledger reservation contains only fixed scope, unchanged authenticated Origin,
request digest and service operation identity. The generic `RoomLedger` canonical
comparison is unchanged: a different payload digest, scope or Origin conflicts.
Only the atomic reservation winner can submit a new write. Concurrent/duplicate
reservations invoke service reconciliation, which requires an existing service
record under its scheduler lock. Missing records mean unknown, never permission
to replay a content write. A canonical publication with a lost response is
reconciled through existing disposition receipt/publication evidence, not rewritten.

Receipt events contain only finite outcome, service operation ID and commit SHA;
no reason, conclusion, rationale, draft body, arbitrary service path or diagnostic
is retained. Unknown exceptions become a fixed unavailable result, not raw text.
Inspection bodies are only returned to the currently authorized caller. Receipt
lookup/reconnect returns `FRESH_OPEN_REQUIRED`; an explicit authorized open reads
again. There is no offline decision/autosave, request queue, body cache, log sink,
notification payload or browser-storage integration in this attachment. Existing
Manager projections/replay caches consume only ledger metadata. Canonical Library
Git deliberately retains the accepted human reason; that is the intended content
publication, not intermediary operational storage. Python memory is not zeroized.

A future containing web host must not add body logging, persisted request/reply
tracing or caches, and must keep human authentication outside request JSON. The
inert existing UI remains unchanged: T32/T33/T44 supply subsequent controls. This
implementation does not claim deployed browser login or production HTTP proof.

## Bounded executable proof

`tests/test_manager_library_transport.py` attaches the actual host, Hub, Controls,
service, Git publisher and SQLite owners. It verifies private inspect + one
canonical rejection, two registered Projects with distinct markers, settings-only
and revoked authority, wrong immutable binding, stale/conflicting request,
response loss, service-absent uncertainty, concurrent reservation and restart.
The real RoomStream/ManagerSession/ManagerReadModel snapshot and paged event
replay paths are exercised; DB/WAL,
ledger replay and serialized consumer frames are scanned for body/reason markers.
Authentication is controlled trusted-host fixture context, not a mocked service;
there is no live provider, network listener, browser suite or heavy VM. Native
Git subprocesses, SQLite and a bounded two-thread race execute locally. Existing
service/inspection/native suites continue covering the separate OS transport.

## T32 intervention attachment and reconnect receipts

The same authenticated envelope also admits Project `drain`, `retry`, `defer`,
`requeue` and `resume` controls and their explicit `observe` requests. It does
not admit settings, archive/restore/repair, arbitrary paths or Participant APIs.
Every new action still runs the service's existing current grant, configuration
and target/content fences. Drain is a scheduling acknowledgement, retry keeps
its original blocked batch, defer only snoozes attention, requeue publishes only
eligible parked-item release, and resume is a separate acknowledgement which
never revives the disposed drain. Inspection includes the service-selected
`drain_id` (or null), bound into its version, so the browser never invents the
batch affected by a rejection or adjudication.

An explicit body-free reconciliation uses the original envelope `operation_id`,
`mode: "reconcile"`, and a request containing exactly `version: 1`,
`action: "receipt"`, `project_id` and `for_action` (the original write kind).
The Hub reads its existing metadata-only reservation using exact stored Origin,
session and Project equality. Its trusted service-operation identity, not any
browser-supplied record identity, selects a read-only Library receipt lookup.
Current Project authority and original human/actor/kind scope are checked again
at the service and before disclosure. An absent or pending operation remains
unknown; this query never reserves, schedules, completes a pending publication
or replays a body. Reconnect may retain the opaque operation/action/Project
handle, but inspection text and unsubmitted form text must be discarded. A fresh
explicit open is required. A lost pre-service or refusal response can remain
unknown; there is no automatic new write to resolve that uncertainty.

Original T31 canonical reservation metadata is unchanged, so upgrading does not
invalidate an exact old request. Result projections now also include the finite
kind, drain identity, acknowledgement and allowlisted reason. They never include
private reason/conclusion/rationale fields, service-selected paths, or raw errors.
Historical receipt reads do not claim a newly configured operation is valid.

A direct `REFUSED` response is not a durable operation receipt. It is emitted
only for a small finite set of control refusals while the scheduling lock is
held, the owner has not entered uncertain/recovery state, the original service
operation identity is authoritatively absent and the current grant still holds.
The Git publisher reserves that identity before any push; scheduling and defer
atomically commit their effect with their record. Publication-possible failures
mark the scheduler failed. Any present record, uncertain owner, revoked grant
or unrecognized exception remains `UNCONFIRMED`; a post-publication stale error
cannot be mistaken for no effect. A lost refusal response remains unknown rather
than authorizing an automatic retry. The UI may refresh after a received definite
refusal, using a new request identity only for a new explicit human action.

`test_manager_library_transport.py` now exercises every exposed control against
real Git/SQLite/service owners, no-repeat scheduling and publication, blocked
batch disposal/separate resume, attention-only defer, parked-item release,
body-free private-response recovery, pre-service uncertainty, current revocation,
wrong-kind/body/Origin refusal, post-publication uncertainty, and old-format
reservation compatibility. Actual browser proof is owned by the T32 Field Notes
check; no VM or real provider invocation is required by this attachment.
