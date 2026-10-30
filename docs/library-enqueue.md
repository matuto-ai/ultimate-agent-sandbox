# Explicit Library capture

`uas.library_enqueue.Enqueuer.enqueue` is the service-side T08 contract. The
trusted owner supplies a started canonical `LibraryGit`, a fresh authenticated
Participant-scope callback and an optional authenticated Run callback. The Run
is provenance only; this code neither looks up Run state nor intercepts Run
completion or context reset. Only an explicit method call enqueues content.
The later T09 Hub route owns authenticated transport and exact Command replay;
T10/T11 own native Runtime surfaces. They are not implemented by this slice.

The public call accepts admitted settings, a Hub Command `operation_id`, opaque
librarian `request_id`, the typed capture `value`, and attempt timestamp `at`.
Only type/title/body/sources and optional relationship hints belong in `value`.
Scope, paths, raw frontmatter and service metadata cannot be supplied there.
The trusted current-context callbacks derive Project, Participant, Actor and
optional Run. Current authority is rechecked before reads, reconciliation and
commit/push, including retries. No credential or target is selected by a capture.

The existing finite settings enforce the settled 200-character title, 16 KiB
body, sixteen sources and 32 KiB canonical payload initial limits. Research
requires a source; empty bodies and raw frontmatter are refused. The service
serializes strict quoted YAML, stamps draft/generated status and original
submission provenance, updates pending index and dated log, then sends the
**complete proposed Project tree** through the single T05 gate. Reference-only
notices remain intact. No source fetch, transcript scan, model, fallback queue
or hidden workspace copy is created.

## Outcomes and identity

`CaptureResult` is content-free and contains `outcome`, safe `request_id`,
`reason`, `retryable`, `queue_id`, bundle-relative `path`, `published_sha`,
`projection_sha` and `visible`.

- `DURABLY_QUEUED` requires a reconciled canonical publication and a durable
  metadata receipt. Projection failure or lag does not undo that publication.
- `REJECTED` is a deterministic refusal, including identity or current-authority
  refusal. Invalid opaque IDs are not echoed. Gate refusals bind that librarian
  identity; corrected content needs a new request ID.
- `NOT_DURABLE` means infrastructure/publication/receipt failure or uncertainty,
  is retryable, and never asserts that canonical content is absent. A new Hub
  Command ID retries the same librarian request/payload. An exact old Command
  returns its immutable recorded outcome.

Same librarian ID/canonical payload recovers the original publication without
another content commit or log entry. Different payload under that ID conflicts;
different IDs remain distinct drafts. Original Actor, optional Run and submission
time are read from durable records on every retry; each admitted capture/retry
attempt retains its actual Actor, time, Command and outcome separately. Malformed
input and conflicting identities are refused before attempt admission and do not
replace an existing journal row; T09 owns any separate Hub refusal audit. Retry does not weaken Hub
origin equality. The metadata schema remains backward-compatible with records
that have no optional Run field.

`LibraryGit.publication_for` fetches and reconciles an already-recorded operation
under fresh authority before any repeat write. Uncertain pushes and crashes
between commit and receipt recover the original commit, including after the
draft has subsequently been integrated. An exact successful historical receipt
is not a claim that the draft remains pending. Archived Projects reject new
capture and are never automatically restored. A concurrent canonical change
causes retryable stale-basis refusal rather than overwriting it.

Projection visibility is a separate current observation from the already-bound
T07 reader. Both Project identities must match and the exact draft bytes must be
present in its coherent snapshot; a newer commit containing those same bytes
can report visible. Unknown/unreadable projections return null SHA/false. No
refresh is awaited, no warning is injected into Runtime context, and no caller
path selects a projection. Operational receipts and diagnostics contain only
identity/digest/provenance/outcome references, never capture bodies or titles.
Blocking and observe-only credential findings are stored as bounded rule, path,
line and digest facts in the optional receipt evidence field, never matched
bytes. A lost response preserves already-observed facts. After a receipt crash,
the exact original draft can be scanned observation-only with the same policy
scanner to reconstruct current recovery findings; this does not claim the old
policy verdict or reapply a blocking decision to historical publication.
Canonical Git is the content store; these tests make no claim about unrelated
Runtime/provider storage.

## Verification

`tests/test_library_enqueue.py` exercises the public service against disposable
real Git, metadata SQLite records and real filesystem projections: immutable
provenance, exact/new-Actor retries, distinct Projects/IDs, gate refusals, archive,
revocation, transport/lost-response/storage failures, restart reconciliation,
concurrent calls and projection lag/advance. No live SSH credentials, native Hub
or Runtime route, production target qualification, backup or host deployment
was executed. Those remain their dedicated slices, including #157.

Run the focused route with installed requirements:

```
PYTHONPATH=.:tests python3 -m unittest test_library_enqueue test_library test_library_records test_library_git test_library_projection
```
