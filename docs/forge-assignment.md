# Audited self-assignment — bounded connected source slice

This extends the existing process-owned Pi/Forge and first-Run admission seams,
not a second workflow engine. It does **not** complete #66, #68, #69 or #72.

## One route and one effect

The validated route table now includes:

```text
gh issue edit NUMBER --add-assignee @me [--repo OWNER/REPO]
```

The Room's trusted construction explicitly supplies `AssignmentBroker` with a
`ForgeAudit`, configured immutable Actor GitHub user IDs, and an Actor-selected
`GitHubAssignmentProvider`. Without it, writes remain unavailable. A fresh
process badge must include `forge-write`; `forge-read`, UID, caller identity text,
and human Run authority alone cannot grant this capability. The Pi `gh` tool uses
the existing kernel-authenticated owned-process socketpair. No new transport,
credential, endpoint, scheduler or operator configuration surface is introduced.
Canonical Run admission also compares the audit store Deployment ID with trusted
installation configuration before any provider, native launch or checkout effect.
Standalone broker fixtures explicitly choose their own trusted Deployment store;
Participant input never supplies or selects Deployment identity.

The provider verifies the authenticated account ID (`GET user`), validates the
pinned repository/issue object, and refuses closed issues, PRs or other assignees.
For an empty assignment it persists the exact issue ID before one additive POST.
The provider never removes, replaces or repairs another assignee. A concurrent
external assignment can still race GitHub reads; the additive request preserves
it and canonical admission remains held. HTTP success alone is insufficient:
GitHub can silently ignore unassignable users. The exact response object and
immutable assignee IDs are checked.

The accepted API mapping is documented by [GitHub's assignee API](https://docs.github.com/en/rest/issues/assignees#add-assignees-to-an-issue).
This documentation is not live provider or credential qualification.

## Audit, retry and reconciliation

`ForgeAudit(path, deployment_id)` is a narrow FULL-synchronous SQLite WAL store
owned outside the Room/Workstation. It appends start, pre-write issue-identity,
terminal and explicit read-reconciliation facts. It stores only validated
identity/target metadata, request digest, bounded status, observed numeric IDs,
confirmed field names and timestamps—never raw argv, bodies, credentials, token
paths or provider errors. The Room ledger reserves the operation ID across
read/write/peer commands; it is not substituted for canonical Forge audit.

Missing/failed audit blocks provider contact. Failure of the pre-write checkpoint
blocks POST. Terminal-audit failure fences the whole Broker and leaves the
committed start/pre-write evidence; it never returns durable success. Reopening
can inspect and reconcile this evidence, but cannot replay that operation's POST.
An unresolved scope also blocks new operation IDs from bypassing its intent.
An unfinished in-flight intent is not automatically declared fenced or released.
The existing supervisor reconstruction hook must prove the old process fenced.
It then terminalizes a missing pre-write checkpoint as `NOT_EXECUTED` (no POST
could have been authorized), or a committed checkpoint as `UNKNOWN_OUTCOME`.
The former permits a new explicit native operation; human admission refresh never
automatically retries it. The latter still requires explicit authoritative reads.

`ASSIGNED` means the exact successful provider response confirmed the added field.
`ALREADY_ASSIGNED` is an observation, not an executed write. A lost response or
ambiguous result is `UNKNOWN_OUTCOME`. An explicit `AssignmentBroker.reconcile`
first commits a bounded reconciliation-start record, then reads authoritative current assignment and appends `MATCHED`, `ABSENT`, `CONFLICT`
or `UNKNOWN`. `MATCHED` is **observed-only**, never proof that this operation
caused the assignment. Inaccessible/failed reads and changed issue identities
remain unknown. Exact reconciliation-ID retries reuse their immutable result; an interrupted read remains UNKNOWN without recontact until a new explicit reconciliation ID.
No reconciliation path invokes POST; no timer or queued retry exists.

## Canonical Run integration

Preassigned exact issues retain the existing no-write admission behavior. An
explicit human admission of an unassigned issue may use the opt-in self-assignment
service only after dependency/state/classification eligibility and current human
plus process authority pass. Admission then obtains a new complete Forge read;
a mutation receipt never substitutes for admission facts. Unknown effects hold
the existing intent without consuming authorization or enqueueing work. A new
explicit human refresh reconciles the same assignment, never resends it, and may
activate exactly one Run and implementation Work Request after current facts pass.
External conflicts are preserved. `projection: unavailable-no-write-support`
continues to refer to **lifecycle-label projections**, which this slice does not add.

## Evidence and limits

- Pure controlled tests: sanitized receipts, immutable retry/reopen, changed-ID
  uncertainty guard, wrong Actor/capability/repository, conflicting assignment,
  silently ignored write, invalid PR/object/output, audit failures before reads,
  before POST and after possible contact, late revocation and read-only recovery.
- Audit tests include separate-connection reservation races, hard child-process
  exit after checkpoint commit, lost commit acknowledgement and bounded reads.
- Actual official Pi 1.4.0 tests use the existing supported extension and owned
  socketpair, actual local Git, and account-free provider fixtures: native `gh`
  write/retry/capability refusal, unassigned issue → canonical Run → native delivered
  request, lost response → explicit read reconciliation, and preserved conflict.
- No live GitHub calls/credentials, paid inference, production mutation transport,
  OS isolation, external audit-service deployment, multi-Room security, other
  mutation routes, lifecycle outbox, review/merge completion or production CLI/
  Manager wiring are qualified. `GhTransport` remains read-only; the typed mutation
  transport is supplied by trusted construction and must enforce I/O deadlines.
- No CI workflow or install changes. New native scenarios take a few seconds;
  heavier host/VM/Claude qualification remains separate/manual.

Focused checks:

```sh
python3 -m unittest discover -s tests -p 'test_forge*.py'
UAS_PI_INSTALL=/path/to/locked/pi python3 -m unittest discover -s tests -p 'test_pi_assignment.py'
```

Do not enable local listener, Claude namespace or Docker
qualification where permission was denied. This slice's initial local aggregate
inadvertently reached four existing `test_launch` listener permission probes;
they were denied/skipped, not qualified. Subsequent aggregate selections omit
those exact tests **before execution**; no escalation or transport workaround was
used.
