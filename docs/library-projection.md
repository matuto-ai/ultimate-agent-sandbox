# Project Library projection

`uas.library_projection.ProjectProjection` is the supervisor-owned T07 seam.
Construct it with the started singleton `LibraryGit`, admitted settings and a
trusted current Room/Project `LibraryScope` plus fresh binding callback. Its
fixed destination comes from `scope.reference_root`, which the existing
`project_binding` derives as `<approved-reference-root>/library`. Neither an
operation payload nor a Runtime chooses source/destination paths. The approved
reference parent must already exist, be canonical and supervisor-owned, and
must not overlap the service root. Existing unknown public paths are refused,
not replaced. Another supervisor cannot hold the same projection lease.

Construction publishes a null manifest and absent bundle if no generation has
ever been published. `start()` subscribes to the shared publisher and schedules
reconciliation in a background worker. `LibraryGit.publish` delivers only a
bounded latest-value metadata notification, including recovered/no-change
publication identities. Later import/enqueue/drain writers use that same seam.
`LibraryGit.startup` and `reconnect` notify subscribers; a newly started worker
also reconciles. `ProjectProjection.reconcile()` schedules a local reconnect
refresh. A notification is not acknowledgement of projection visibility.

Snapshot acquisition fetches an observed exact canonical SHA without a ref
update or `FETCH_HEAD` write, and reads only the bound Project's regular files.
It does not take the canonical publication mutex, change the publisher's head,
read source documents, invoke models or execute the content write gate. Thus
transport/read latency and blocked write policy do not block canonical writes
or hide an already readable snapshot. Existing unknown authored content is
preserved. Bounds, safe paths, required bundle files and immutable root identity
are checked; no sibling bundle, Git metadata, symlink or service credential is
copied. A missing or unusable new bundle preserves the old publication.

## Atomic publication and consumption

One immutable generation contains `library/` and `library.snapshot.json`.
The two fixed public links both traverse `.library-current`, switched once with
atomic `os.replace`. Preparation is beneath a supervisor-only mode-0700 staging
directory, not an enumerable partial public generation. Only complete, fsynced
files and directories leave it; the moved generation and its parent are synced
before pointer replacement. Files are mode 0444 and published directories 0555.
The existing supervisor-owned, read-only Project reference mount is still the
Participant write boundary; the supervisor's OS identity must be distinct from
untrusted readers. This module does not create mounts, add host privileges or
qualify a real deployment. The same-host supervisor can see staging; a Runtime
must never run with that supervisor identity or a writable reference mount.

`read_projection(scope, settings)` pins the generation under a shared lock and
copies one bounded complete manifest/tree. `ProjectProjection.read()` uses the
same consumer. Multi-file consumers must use this seam, or bracket native
read/search operations with the manifest and retry if the commit changes.
Independent opens across a publication boundary are not one transaction, even
though each published generation is coherent. Native tools retain the fixed
`library/` and sibling manifest paths. A failed traversal is an error, never a
partial snapshot bearing a complete manifest. The new generation switch and
reclamation take the exclusive lock; stale generations are reclaimed only after
pinned consumers release it. Startup reclaims UUID-named owned orphan generations
but preserves unknown files. The source Git clone is not exposed in this tree.

The manifest uses the existing `library.snapshot` contract: Project ID and
immutable identity, exact commit SHA and original publication time. Before a
first success both commit and time are null. Unchanged commits do not refresh
the timestamp. Pre-switch failures preserve the entire old publication. A sync
failure **after** the pointer is already visible is reported as
`PROJECTION_SYNC_UNCERTAIN`, not a false refresh failure or a rollback; visibility
is real but power-loss durability is uncertain. Cleanup failures likewise do not
undo an already visible publication.

`visibility(commit_sha)` reports the current projected SHA and conservative
exact-commit visibility separately from canonical durability. A newer projection
does not prove an older draft is still present: the T08 capture owner can inspect
that newer pinned tree for its exact draft. `last_error` carries a safe diagnostic
code only; refresh failures never rewrite canonical receipts or inject Runtime
context. `wait_idle(timeout)` is a bounded diagnostic/testing convenience, not a
capture-path wait. Close workers before closing their publisher.

## Verification boundary

`tests/test_library_projection.py` exercises actual disposable Git publication,
filesystem generations and the real consumer/notification seams, including two
Projects, first-null, read/switch races, stalled projection transport concurrent
with publication, source/path refusals, disk/rename/sync failures, revocation,
reconnect/restart and cleanup. This is not live mounting, native Pi/Claude,
credential, backup or target-host qualification; those accepted later slices
remain separate. Run with installed repository requirements:

```
PYTHONPATH=.:tests python3 -m unittest test_library_projection test_library_git test_library_registration
```
