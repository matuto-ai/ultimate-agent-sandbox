# Private Manager Library transport — T31 / #189

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
