# Hub lifecycle projection outbox

Issue [#69](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/69) keeps
canonical Run and Work Request state in the existing `RoomLedger`. Forge labels
are derived projections, never locks, Run admission, review verdicts, or merge
permission. [Decision #50](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/50#issuecomment-6397341915)
assigns lifecycle/Run labels to the Hub and leaves their exact names to the
specification. The initial product mapping is:

| Canonical facts | Desired Hub-owned labels |
| --- | --- |
| `ACTIVE`, no blocked Work Request | `run:active`, `lifecycle:active` |
| `ACTIVE`, a current-generation Work Request is `BLOCKED` | `run:active`, `lifecycle:blocked` |
| `PAUSED` | `run:paused`, `lifecycle:attention` |
| `CLOSED` | `run:closed` |

`lifecycle:review` is reserved and cleaned up when externally inconsistent; no
review-ready fact is fabricated. Its authoritative producer belongs to #74.
These are **product** labels, not this repository's contributor `agent:*`
workflow. Work-type labels, including delivery and Wayfinder labels, remain
agent-owned. A projection repairs individual missing/extra labels from the
fixed owned catalog, never replaces all labels or creates catalog entries.

## Canonical transaction and bounded state

`enqueue_run_projection(state, room_id, run_id)` derives intent from a fully
bound canonical Run and existing current-generation Work Requests. Actual Run
activation, pause/resume and peer block/unblock/cancel transitions call it in the
same transaction as their original state/event changes. No provider call occurs
inside those transactions. A read-only or unavailable Broker therefore leaves
an honestly `pending` outbox item, not a fabricated successful projection or a
rolled-back Run.

Each Run retains its latest derived intent/version, one active synchronization
attempt, one unresolved mutation-operation reference, and bounded current
observations. Histories remain immutable ledger events/operation receipts. Each
item reserves 12 KiB against the existing shared Room capacity model; at most 32
items are retained, matching current canonical Run admission capacity. Changing
intent never discards an in-flight or uncertain mutation. The next explicit
synchronization can also initialize an older, fully bound Run's derived outbox;
it does not invent a Run or infer one from Forge labels.

## Trusted integration seam

The Supervisor constructs `ProjectionOutbox` with its existing ledger/binding
and the private `ProjectionBrokerClient`. The adapter communicates through the
same external Broker owner/credential/audit boundary; Participant mutation
vocabulary cannot invoke this privileged projection route.

```python
outbox = ProjectionOutbox(ledger, binding, ProjectionBrokerClient(read_client))
result = outbox.advance(operation_id, run_id,
    origin=trusted_hub_origin, authorize=current_hub_authority)
```

The trusted origin must carry `forge-project`; this is not an agent-supplied
capability or a Manager authentication implementation. The callback is checked
before reservation/disclosure and each provider step, including current intent
version. The Broker additionally enforces its fixed Project and configured
projection Actor. `advance` handles one explicitly requested Run, not backlog
polling, a scheduler, or automatic work activation.

The provider seam is deliberately narrow:

- `observe(intent, operation_id, authorize=...)` returns complete bounded owned
  labels, exact immutable issue identity and complete assignee IDs, or explicit
  unknown/conflict, with its audit reference. A prior uncertain mutation's
  stable operation reference is in `intent.reconcile_operation`.
- `repair(intent, operation_id, observed, authorize=...)` performs only the
  missing/extra owned-label effects after authoritative observation and returns
  the shared mutation audit/confirmed-field receipt shape.

Intent contains fixed Room/Project/repository/Run/generation/issue identity,
expected implementer ID, derived labels/version and prior reconciliation
reference. It contains no endpoint, credential, arbitrary field, body or shell.
A conflicting external assignment remains visible and prevents repair; the
outbox does not overwrite assignees.

## Recovery and truthful Manager outcomes

1. Commit synchronization reservation before read contact. Competing exact
   operation IDs can have only one transaction creator/provider caller.
2. Read authoritative provider state and reconcile any prior uncertain write.
   Permission/rate-limit/failure/incomplete enumeration is unknown, never absence.
3. Commit drift observation and the stable send-operation reservation **before**
   possible mutation contact.
4. Commit the terminal projection result before acknowledging it.

Exact retries return immutable completed results or `IN_FLIGHT_OR_INTERRUPTED`
without provider recontact. After an interrupted attempt, the trusted replacement
calls `recover(..., fenced=...)` only when it positively proves the preceding
owner stopped. Age, disconnected UI, or an unverified PID is not that proof.
The next **new** operation reads authoritative state before any repair. Lost
provider success therefore converges through a match, not a duplicate write.
Late authority/source changes fence subsequent steps; old results cannot replace
new desired intent or canonical Run state.

`projection(...)` plus ordered ledger replay expose:

| State | Meaning |
| --- | --- |
| `pending` | Derived intent has not converged, or newer canonical intent superseded the attempt. |
| `drifted` | A complete read observed different Hub-owned labels; repair has been durably reserved. |
| `repaired` | Confirmed bounded repair or authoritative observed match; attribution distinguishes them. |
| `partial` | Only the returned confirmed fields executed; a fresh read is required for remaining work. |
| `unknown` | Observation/contact/storage outcome is unresolved; no blind replay. |
| `failed` | Definite provider rejection or visible external assignment conflict. |

Views retain desired intent/version, observed data, audit reference, original
attempt result/receipt, attribution and unresolved operation. `observed-only`
never claims that the Hub caused an already-matching label state. Transport or
validation failure records a Hub attempt failure with no fabricated provider
observation. Run status, policy, request responsibility and consumed human
admission remain intact in every failure case.

## Evidence boundary

`test_forge_projections.py` uses real disk SQLite transactions with an account-free
in-memory provider seam. It covers outbox-before-send crash, provider-before-receipt
loss, terminal-commit failure, restart/fenced recovery, partial mutation, external
label drift, assignment conflict, exact retries/races, late source changes,
constant bounded storage and the actual pause/resume/peer lifecycle hooks. These
pure checks do not claim native process authentication or live GitHub account
qualification. The external Broker integration and hosted controlled fixtures
supply their own exact-candidate evidence; no deployment, label-catalog changes,
or production workflow transition is performed by these tests.
