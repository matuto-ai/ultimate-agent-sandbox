# Bounded GitHub mutations

Issue [#68](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/68) extends the
external process-bound Broker from #66. This is the selected GitHub surface, not
a transparent `gh` proxy. `github_mutation_routes.py` is the single mutation
vocabulary used for help and enforcement. Its fourteen routes cover:

- Issue creation, title/body edits, close/reopen, and comments.
- PR creation, title/body/base edits, close/reopen, comments, replies to verified
  PR review comments, and immediately submitted reviews at an explicit full SHA.
- Add/remove **only the authenticated Actor** as assignee (`@me`).
- Add/remove trusted configured work-type labels, never Hub lifecycle labels.
- Native issue dependency add/remove, with both same-Project issue numbers
  resolved to immutable IDs. PR, self, mismatched repository, and equal-ID
  targets are rejected before mutation.

No merge, label-catalog administration, repository administration, workflow
control, arbitrary API/GraphQL, pending review, parent hierarchy, binary
attachment, caller endpoint, credential or local body-file path is admitted.
`--body-file -` consumes the supplied body. It never opens a Participant path.
The Broker executes fixed REST paths through its pinned external `gh api`
executable; it never forwards caller argv to the executable. Review/dependency
API mappings are the documented API version `2026-03-10`:
[dependencies](https://docs.github.com/en/rest/issues/issue-dependencies),
[reviews](https://docs.github.com/en/rest/pulls/reviews), and
[review replies](https://docs.github.com/en/rest/pulls/comments).

## Authority and configuration

External startup retains the #66 private Supervisor channel, held kernel process
identity, fixed Project/host, separate Broker UID, private credential lookup and
pinned executable. The optional trusted startup fields are:

```json
{"mutation_actors":{"actor-a":41},"work_labels":["type:bug","type:feature"]}
```

These are immutable GitHub user IDs and explicitly selected work labels, not
Participant input. Omitting the fields keeps the Broker read-only; authenticated bootstrap reports
write enablement, so a read-only service does not steal an explicitly configured
legacy assignment route. There is no caller-controlled post-contact fallback. A seat must
also carry `forge-write`. Every invocation reads `/user` and compares the selected
credential's immutable identity. Text/state/base and dependency changes require
the target author's identity; comments, independent submitted reviews, and
self-assignment do not imply target authorship. Work-label edits likewise require
target ownership. Existing labels and assignees are never replaced wholesale.

The external Broker challenges the Supervisor for current process/epoch
permission before each provider call and each prepared write. The Supervisor
rechecks the original authenticated seat under the lifecycle lock. Provider I/O
never holds that lock. A revoke can race already-authorized contact; no later
step starts and no stale successful receipt is disclosed. The Broker does not
turn a submitted review into a Hub verdict, Run transition, or merge permission.

## Corrections and bounds

Case-only spelling of the pinned repository and duplicated identical allowed
list values are harmless corrections. Execution returns the corrected result,
fixed warnings and exit code zero. Unsupported/security-sensitive inputs are
rejected rather than silently rewritten. Diagnostics name the failing token
position and a fixed correction without reflecting raw body, secret or path.

Body input is at most **512 KiB UTF-8**; argv plus supplied stdin is bounded to
512 KiB + 16 KiB, 64 arguments. Provider output across an invocation is at most
**1 MiB**; per-command deadline is at most 10 seconds, overall provider deadline
30-second dispatch budget (an already-entered bounded call may finish within its
10-second deadline). JSON request framing has a separate 1,114,112-byte encoded ceiling to
accommodate worst-case escaping of the full 512 KiB body; results remain capped
at 1 MiB. Large write requests use bounded digest-bound frames;
every Participant and Supervisor frame is authenticated independently. A partial,
changed, oversized or timed-out frame sequence cannot reach provider contact.

## Receipts, audit and uncertainty

`ForgeAudit` migrates additively from assignment v1/read v2 to mutation v3 in the
same Deployment database. Canonical records contain binding, origin/request
digests, route and executed field names, immutable object IDs, contact state and
fixed error codes. They never contain body values, raw argv, provider prose,
attachments, secrets, temporary paths or content. Receipt field names identify
what actually executed; object identities bind each effect. `executed_steps` lists
confirmed step IDs and zero-based normalized `item_index` for individual label
values, so a partial list edit never pretends every requested label succeeded. Body values are not
copied into audit just to make a receipt richer.

1. Commit invocation start before even selecting a provider.
2. Verify authenticated user and exact provider object identity.
3. Commit each prepared target before possible mutation contact.
4. Commit each confirmed field/object checkpoint after a verified response.
5. Commit the terminal result before returning authoritative success.

A verified authority loss after prepare but before transport is recorded as a
definite no-contact rejection; it cannot masquerade as an ambiguous remote write.
A definite later HTTP rejection yields `PARTIAL_MUTATION` with earlier confirmed
fields; a definite first rejection is `PROVIDER_FAILURE`. Lost/malformed/oversized
responses or ambiguous contact yield `UNKNOWN_OUTCOME`, preserving any earlier
confirmed fields and the audit reference. A terminal/checkpoint audit failure
after possible contact returns unknown, never success, and stops the Broker.
Pre-contact audit failure is `AUDIT_UNAVAILABLE` and makes no provider contact.

Exact retry returns the immutable terminal receipt or an interrupted unknown;
it never repeats a POST/PATCH/DELETE. Pending and uncertain records fence further
writes for the same Room/Project, including a new Actor/epoch and legacy assignment
routes. A fenced replacement owner can terminalize interrupted work without
provider contact. Definitively rejected steps recover their known partial/failure
receipt. A prepared-but-unconfirmed step remains unknown. The [#69 reconciliation layer](forge-reconciliation.md) now supplies read-side
resolution, ordinary-write reconciliation, outbox/label projection repair and
uncertainty un-fencing, without changing these immutable receipts. Review-loop
authority remains #74.

## Evidence and limits

Pure tests cover route corrections/denials, bounds, all mutation categories,
field receipts, dependency/review identities, partial and unknown responses,
start/checkpoint/terminal failures, restart/retry, migration and cross-route
uncertainty fences. Hosted-only Linux fixtures exercise real pinned child
process execution, distinct Broker/Supervisor UIDs, private synthetic credentials,
framing, authority challenges and representative writes against an account-free
provider fixture. They must run on the exact reviewed candidate; local source
checks are not substituted for these runtime checks.

No live GitHub account mutations, permission/scopes, rate-limit behavior or live
credential revocation are asserted by these fixtures. No deployment or account
configuration is performed. The existing #66 dedicated executor containment
proof remains required; this extension adds controlled mutation semantics without
claiming a full VM or real-account qualification.
