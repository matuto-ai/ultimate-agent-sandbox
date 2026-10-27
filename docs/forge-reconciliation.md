# Forge reconciliation and Hub projection recovery

Issue [#69](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/69) extends
one existing Deployment `ForgeAudit` and one authoritative Room ledger. It does
not make native reviews into Hub decisions, advance a Run from GitHub labels,
introduce another workflow store, or grant merge authority (#74).

## Ordinary Participant writes

A `forge-write` operation remains immutable after its first committed start.
Repeating its ID returns the recorded terminal receipt, including its original
partial/unknown result; it never retries a provider mutation. An unresolved write
fences new writes for its Room and Project, including another Actor or epoch.

`forge-reconcile` is an explicit **read-only** operation with a new operation ID,
the original `audit_reference`, and the exact original write envelope. The
Broker checks the original request digest and immutable Actor/repository/issue
binding before provider contact. A current replacement seat of the same Actor
may reconcile a terminal write; it cannot adopt an in-flight old owner. A
pending write first needs the existing fenced-owner recovery path.

The Pi `gh` tool exposes this without a shell or caller-selected endpoint:

```json
{"id":"inspect-lost-comment","argv":["issue","comment","17","--body-file","-"],
 "body":"the exact original body",
 "reconcile":{"operation_id":"original-comment-id","audit_reference":"mutation-…"}}
```

Both `forge-read` and `forge-write` capabilities and fresh process/epoch authority
are required. The original body is ephemeral input, never canonical audit or
Room event content. Changed argv/body/Actor/binding cannot reuse an old operation.
Large reconciliation requests use the same digest-bound, per-record-authenticated
framing as writes. Participant packets cannot invoke Hub projection routes.

The resulting observation contains per-field `MATCHED`, `ABSENT`, `CONFLICT`, or
`UNKNOWN`, including an index for each individual label. Its aggregate is
`UNKNOWN` if any field is unknown, the common status when all agree, or `PARTIAL`
for mixed known states. It references immutable objects and explicitly says
`attribution: observed-only`: matching remote state is not proof of causation.
The original confirmed-write receipt is never rewritten or inflated.

### Stable identity, not blind replay

New issue/PR creations, comments/replies, and submitted reviews receive a bounded
server-owned hidden Markdown marker. Clients cannot supply the reserved marker
prefix. The marker binds Deployment, operation, and original request digest;
matching also requires the exact provider object, Actor, parent, and review
candidate/submitted state. Multiple matches are conflicts, not permission to
choose a convenient object. Review reconciliation does not issue a Hub verdict.

Before duplicate-producing writes, bounded collection enumeration captures only
a digest of existing immutable IDs. If a later complete collection has no marker,
`ABSENT` requires the same pre-contact identity set; a changed set is a conflict
(possible marker editing), and an unavailable baseline stays unknown. A legacy
v3 write with no recorded marker or confirmed child identity cannot acquire a
fabricated marker and be declared absent. Existing object identities remain
useful even if their text was externally changed.

Scalar edits record only preimage digests, not title/body values. A desired value
matches; the unchanged known preimage is absent; another value is a conflict.
Assignments preserve external conflicts rather than replacing other assignees.
Labels and native dependencies use complete membership reads, not body inference.
Collection pages are fixed, bounded, and enumerated before absence claims. A cap,
failed page, malformed identity, permission/rate-limit error, or 404 is unknown,
not proof of nonexistence. The provider retains the 1 MiB total response budget,
10-page ceiling and 30-second dispatch deadline; these may prevent reconciliation
of unusually large objects, safely leaving their write fence in place.

A known observation lifts the uncertainty barrier, not an automatic retry grant.
No reconciliation path executes POST/PATCH/DELETE. A separately requested new
write still undergoes the ordinary fresh authorization and policy. Exact old IDs
remain immutable forever, even after a later read matches or conflicts.

## Durable audit and restart

The additive v4 migration validates and preserves v1 assignment, v2 read, and v3
mutation records. It adds per-step sanitized intent digests, committed
reconciliation starts/observations, and fixed-label projection plans to the same
Deployment database. It never stores ordinary bodies, argv, credential values,
provider prose or filesystem paths. A prepared target and its preimage intent are
committed atomically before that step can contact GitHub.

Reconciliation commits its own start before GETs and commits its observation
before disclosing success. Exact reconciliation retries never repeat even GETs.
If an attempt was interrupted, it returns unknown; a new explicitly authorized
read attempt is required. Start failure makes no provider contact. Post-contact
checkpoint/terminal failure stops the owner; a replacement inspects durable facts
rather than treating missing acknowledgement as permission to repeat a mutation.
Corrupt intent, observation, identity, schema or noncanonical JSON fails closed.
Before lifting a write fence, the owner validates historical uncertain receipts
and their observations in 256-record pages (at most 4096 candidate records per
check); exceeding that examination budget fails closed with capacity attention,
never silently dropping an unresolved operation.

## Hub-owned projections

See [Hub projection outbox](forge-projections.md) for the authoritative source
hooks, exact label catalog, Manager states and crash boundaries. Trusted startup
can add `projection_actor` to the existing mutation-enabled external Broker
configuration; it must name an Actor already present in `mutation_actors`. No
credential or account is created or changed. A read-only or mutation-only
installation retains its original behavior and cannot silently acquire projection
authority. Pending Hub intent is preserved while no projection owner is enabled.

`ProjectionBrokerClient(read_client)` adapts the same inherited private
Supervisor channel to `ProjectionOutbox`. The server accepts only its fixed
synthetic Hub Origin for `forge-projection`, selects the configured credential
Actor itself, and challenges current Supervisor/outbox authority before each
provider call. This route is not in Participant native `gh` help or dispatch.
A supplied issue ID must match the pinned repository and fresh provider object;
assignment conflicts remain visible and are never repaired by changing assignees.

Projection repairs use the same prepared/confirmed/terminal mutation journal and
uncertainty fence. A missing outbox acknowledgement retains the stable write
operation ID even when no audit reference reached the Hub. The next complete
observation reconciles the original durable plan before any new repair. It adds
or removes individual catalogued Hub labels only; unrelated/work-type labels are
never replaced wholesale. A source-version change defeats later steps and stale
success disclosure without rolling back authoritative Run state.

## Evidence boundary

Pure suites connect the real Room ledger, outbox, external Broker, mutation and
reconciliation providers, and Deployment audit to an account-free stateful
GitHub-response fixture. They cover positive, denied, partial, unknown, corrupt
storage, failed/lost commit acknowledgement, reopen/recovery, external assignment
conflict, label drift, complete pagination and no duplicate mutation paths.

The hosted-only `tests/linux/forge_mutation_smoke.py` additionally crosses the
actual pinned child executable and distinct Supervisor/Broker Unix identities,
private synthetic credentials, authenticated framing and authority challenges.
It severs responses after create/comment/review/multifield/label effects, restarts
the external owner, reopens the Hub outbox, and checks read-side convergence and
preservation of work labels. Run it only on reviewed code in controlled hosted
Linux CI; source parsing and pure tests are not that process-bound proof.
The existing automatic workflow budget remains at most three minutes, with no
new VM job. Live GitHub account permissions, scopes, network behavior and complete
Pi–Claude–GitHub product qualification remain separate #78/#81 evidence; these
fixtures do not claim live account mutations or deploy anything.
