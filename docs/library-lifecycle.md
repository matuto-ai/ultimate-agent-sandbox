# Explicit Project archive and restore (T35)

The host-owned `Controls` interface accepts `observe` with `for_action` equal to
`archive` or `restore`, then the corresponding action with Project ID, request
ID, settings ID and observed version. Existing fresh local human Project grants
are required (`library-archive` or `library-restore`); Unix ownership alone is not
a grant. No participant command, export or Room-lifecycle hook is added.

Archive reserves a durable metadata-only intent under the same lock as capture.
New captures are refused immediately. The global active turn may finish; archive
never preempts it or waits while holding the scheduler selection lock. Waiting is
bounded to the smaller of 30 seconds and the configured attempt bound. A busy or
lost response is pending/unknown, not archived success. Retry the exact request
identity; do not invent another request or clear the fence.

After the global turn, at most one fixed final batch is attempted. A durable
reservation precedes any source/model work. A failed, blocked or disposed batch
is not implicitly retried. Remaining drafts, parked entries, identity, directory
and history are preserved. The existing attempt owner bounds actual synthesis,
records contact, validates outputs and reconciles publication. Recovery never
calls the final model a second time, including a crash before/after contact.
Its prior scheduler state is persisted and restored before archival publication;
STARTED is followed by truthful COMMITTED/BLOCKED metadata, not a false orphan.
An interrupted ordinary active batch is preserved blocked, not silently retried.

Archive and restore each change only the root lifecycle marker and append a
lifecycle log entry through the complete-result gate and normal fast-forward Git
publisher. Changed or malformed content, authority or policy refuses the write.
Only canonical pushed commits establish success. Failed/uncertain publication
retries may repeat Git publication/reconciliation, never failed model work.
Canonical recovery works with a renewed valid grant while preserving the original
operation identity. `reconcile` never starts an unreserved request or republishes.

Archived complete snapshots remain valid for read-only checks, and matching
registration reports `archived` without reopening it. Ordinary content gates
refuse every archived write and any implicit lifecycle transition. Explicit
restore reopens the same Project; no pending document or history is removed.
Room Stop/Destroy does not invoke archive and leaves Library storage unchanged.

## Configuration and failure boundaries

A pending operation keeps its originally observed configuration identity.
Already-published results can be reconciled under fresh valid authority even if
non-target settings changed. Unpublished work under changed settings is refused
with `STALE_CONTROL_STATE` and keeps its durable fence: it does not silently
adopt another model/route/policy or reset its final-attempt allowance. Restoring
the exact approved configuration permits the original request to continue.
There is no cancellation/configuration-migration operation in this slice.
Target/branch changes remain the external canonical-repository owner's concern.

## Evidence and owning aggregate

`./validate.sh archive` discovers the complete three-module acceptance partition:
`test_library_archive`, `test_library_archive_integration`, and
`test_library_archive_native`. Tests use disposable real Git repositories, actual
SQLite/service/scheduler, and an inert bounded provider subprocess, not a real
model or user data. The Room lifecycle test uses the actual Supervisor with a
file-backed resource fixture, not Docker or VM qualification. Native tests use a
real private Unix socket; an executor EPERM is explicitly skipped locally but
cannot skip on GitHub Actions. Failure, restart, lost synthesis/archive/restore
acknowledgements, fresh authority, history preservation and gate rejection are
covered. Independent full-diff Standards/Specification/Runtime review and exact
hosted CI remain required; this does not qualify production model/storage/VM.
