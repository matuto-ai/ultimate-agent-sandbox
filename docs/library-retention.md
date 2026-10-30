# Library operational retention (T39)

`LibraryGit(..., audit=deployment.audit)` installs the existing trusted Deployment
`audit.retention_days` and `audit.max_bytes` policy before accepting operations.
Composition must pass this policy; the compatibility default `audit=None` does
not invent a retention policy. Once installed, it persists in SQLite and applies
to every writer handle, including scheduler, import, controls and reporting.
`LibraryRecords.configure_retention` is a trusted configuration boundary, never
an endpoint accepting caller-supplied retention authority.

Settled detail expires by age or storage pressure. Atomic tombstones preserve
immutable Project/command/request/kind/content identities, original identity and
receipt digests, and minimal outcomes. Evidence and completed manifests disappear;
projection visibility becomes unknown. Exact capture retries return the original
durable acknowledgement with `DETAIL_EXPIRED`, without publishing again. Human
control acknowledgements remain reconcilable without reapplying scheduling.
Import/attempt execution refuses expired detail, never reruns inference or Git.
Current authority checks and conflicting command/request refusal still apply.
Observation coverage is partial once history is incomplete, never a false zero.

Pending and uncertain attempts, latest scheduler state and observation, unresolved
fixed batches, and transitions awaiting report acknowledgement remain intact.
Report acknowledgement tombstones preserve delivery deduplication. Required
identity/recovery state has no unsafe eviction path: when it alone fills capacity,
new writes fail with `RECORD_CAPACITY`. This means the journal eventually refuses
rather than promising unlimited writes with permanent deduplication in finite space.

Writers serialize checkpoint/transactions with a private checked advisory lock.
SQLite page limits reserve main database, a VACUUM temporary copy, full WAL frames,
shared memory and overhead. WAL must truncate before further writes; a reader
preventing checkpoint causes safe refusal rather than accumulating WAL. A rolled
back SQLite-full metadata transaction may retry once after settled-detail
compaction. Maintenance observes the current operation deadline and a five-second
local ceiling, including lock waiting and SQLite progress. Interruption or lost
commit acknowledgement requires reopen/reconciliation, never assumed rollback.

The bound covers the managed SQLite files and its VACUUM working copy, not the
canonical Git repository or arbitrary external files. Installing a smaller bound
on an already larger legacy journal cannot retroactively satisfy that bound;
configuration persists, compaction is attempted, and writes remain refused if
required state cannot fit. Exact legacy schema migrates; alien schemas fail closed.
No canonical Git history/body is pruned, no content cache is created, and no Git
maintenance/deployment/account changes are performed.

`tests/test_library_retention.py` uses temporary real SQLite/Git/service fixtures:
restart, actual-file bounds and exhaustion, checkpoint obstruction, atomic lost
commit reconciliation, schema migration, safe locks/deadlines, public capture,
import/control replay and revocation, partial observation, and pending report/batch
recovery. Existing process-death suites remain in exhaustive CI. These are fixture
proofs, not production-host or live-provider evidence. Retention shares the existing
operator CI partition; no tests are excluded and no timeout is increased.
