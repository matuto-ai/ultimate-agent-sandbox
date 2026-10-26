# Durable fixture peer traffic

`uas.peer.FixturePeerHub` integrates the protocol behavior in [#65](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/65) with the existing [Room application ledger](room-ledger.md). It is **not another network prototype**: the same `RoomLedger.apply` transaction owns operation receipts, events, materialized traffic state, and the Room sequence. The domain preserves other Room-state namespaces. The historical `spike/peer-messaging` server is unchanged and is not the implementation entry point.

**Qualification remains fixture-only.** There is no socket, production authentication, process badge, real agent, Forge work admission, native context reset, or credential access. `configure`, `connect`, `observe`, and `cancel` are trusted test-harness actions, not client APIs. A fixture connection object's identity rejects accidental cross-peer use; it is not a security boundary against arbitrary Python code. Production exposure remains blocked on [#63](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/63), qualified adapters, and their integration. **#65 stays open.**

## Protocol and ownership

The integration plan is deliberately small:

- **Protocol:** `Message`, `WorkRequest`, and `RequestCommand` are distinct typed inputs. `submit` also accepts a strict JSON object with exactly `id`, `run_id`, `generation`, `kind`, and `payload`. No arbitrary metadata or client authority fields are accepted.
- **Persistence:** the Hub derives the sender/Actor, recipients, status, submission timestamp, and sequence. The ledger supplies canonical operation identity, fresh authorization under the write lock, duplicate-before-generation handling, atomic receipt/state/event commit, and ordered replay. There is no second workflow store.
- **Delivery:** an adapter pulls only at a fresh `Readiness.SAFE` observation. The Hub first commits an immutable delivery offer; a separate fixture receiver durably accepts the envelope; only a matching receipt and still-current attachment/observation permit Hub confirmation.
- **Recovery:** admissions replay after each recipient's durable cursor. Unconfirmed offers and nonterminal Work Request responsibility remain independently eligible so a cursor never discards them. Receiver deduplication is durable and binds the complete envelope, Room, recipient, process incarnation, and context generation.
- **Integration scenario:** queue a request, hold through ambiguous/busy/compacting states, deliver and explicitly accept it, reply with authorized parentage, release/reacquire capacity, complete, broadcast, and reopen the same Room ledger. Actual subprocess kills cover both databases' commit boundaries.

All fixture peers are configured in one synthetic Run/context. This does not create a product Run or admit a Forge issue. Configuration is immutable. A different `run_id`/generation is rejected, and `connect` cannot claim a different context generation. Native reset and cross-Run rebinding are intentionally unavailable until their own qualified seam exists. A replacement incarnation stays in this same context and starts ambiguous. The current incarnation may reconnect after a Hub restart; a previously superseded incarnation cannot be recycled under a new attachment. The immutable attachment history enforces that rule without an unbounded state list.

### Inputs

```python
Message(id, run_id, generation, recipient, text, parent_id=None)
WorkRequest(id, run_id, generation, recipient, text)
RequestCommand(id, run_id, generation, request_id, action, reason=None)
```

A Message has no response obligation or Work Request status. Its recipient may be `"*"` for a snapshot of all configured eligible peers except the sender, including temporarily offline peers. Work Requests target exactly one other Participant. Reply Messages use `recipient=None` and a parent that was delivered to the sender; the Hub derives the reply recipient and root correlation ID. Another peer cannot claim parentage or redirect a reply. Text is bounded at 16 KiB of JSON-encoded string content (excluding its surrounding quotes); configured fixture membership is 2–32 peers and capacity 1–16 slots. These are implementation bounds, not measured production defaults.

JSON kinds and exact payloads are:

| `kind` | Payload fields |
| --- | --- |
| `message` | `recipient`, `text`, `parent_id` |
| `work-request` | `recipient`, `text` |
| `command` | `request_id`, `action`, `reason` |

Use explicit `null` for unused optional fields in JSON. Actor, Participant, capabilities, timestamps, sequence, authoritative status, repository, and Room are never client fields. Authorized exact retries return the original ledger receipt. Conflicting ID reuse is rejected before generation checks; revoked/stale connections cannot disclose a previous receipt. A new incarnation has a different origin/security context and cannot silently impersonate the preceding operation origin.

### Work Request transitions

| From | Typed action / confirmed observation | To |
| --- | --- | --- |
| `QUEUED` | Matching durable receiver receipt | `DELIVERED` |
| `DELIVERED`, `DEFERRED`, `BLOCKED` | `accept` | `ACCEPTED` |
| `ACCEPTED` | `complete` | `COMPLETED` |
| `DELIVERED`, `DEFERRED`, `BLOCKED` | `decline` with reason | `DECLINED` |
| `DELIVERED`, `ACCEPTED` | `defer` with reason | `DEFERRED` |
| `DELIVERED`, `ACCEPTED` | `block` with reason | `BLOCKED` |
| Any nonterminal state | Trusted fixture cancellation with reason | `CANCELLED` |

Only the target Participant can issue a response Command. Successful Commands have an atomic `command_status: APPLIED` receipt; rejected Commands commit nothing. They are deterministic Hub operations, not queued shell commands. Peers cannot issue `cancel`, `force-stop`, or arbitrary commands. Terminal states cannot regress, and duplicate Commands do not repeat effects.

Only `ACCEPTED` consumes a configured work slot. `DEFERRED` and `BLOCKED` release it; `BLOCKED` retains responsibility and a structured attention reason. Reacceptance is explicit, checks capacity again, and does not restart the response clock. Completion/cancellation releases capacity but **never releases a checkout, cleans files, changes a Run, or claims native stop**. Concurrent acceptance is serialized by the application-ledger transaction.

## Safe delivery and uncertain outcomes

Submission time starts queue age. Neither queue admission, the committed offer, nor receiver contact starts response timing. The Hub records `response_started_at` only when it commits confirmation of a matching receiver receipt. It uses the confirmation time conservatively; no outage interval is retroactively presented as an established response timer. Later process restoration does not reset it.

The receiver's `accept` returns only after its SQLite transaction commits. Its independent inbox is deliberately not Hub truth: after a crash it may contain an accepted envelope while the Hub still says `QUEUED` and the offer says `UNCONFIRMED`. That is an unknown confirmation outcome, not proof of no receiver effect. Repeating the **same** immutable envelope reconciles via receiver deduplication. Reusing its delivery ID for changed text or binding is rejected. A mismatched receipt, receiver exception, cancellation, replaced attachment, changed readiness, or stale context cannot fabricate confirmation.

Delivery identity includes recipient, incarnation, and context. Restoring the same incarnation after a Hub crash reuses its durable inbox. Replacing the Participant process uses a newly bound receiver and delivery identity while retaining the original Work Request identity and responsibility. An accepted request still consumes capacity, and the replacement must receive it before a new completion response is legal. Already confirmed informational Messages are not re-presented as new obligations.

Every new Hub starts with no connections. Every attach/re-attach starts ambiguous, even when replaying an exact attach operation after a crash. `BUSY`, `AMBIGUOUS`, `COMPACTING`, and `LOST` hold delivery. Process loss invalidates that fixture connection and leaves queued or accepted work intact. Observation freshness fences the offer and confirmation. The two stores are not one distributed transaction: cancellation or process loss can race receiver acceptance after an offer, but confirmation is fenced, responsibility never becomes fabricated completion, and the unresolved offer remains visible.

This is **at-least-once presentation and deduplicated fixture acceptance**, not exactly-once external work. Real Runtime acceptance evidence, native process liveness, timeout policy, authenticated read-model filtering, reset, and human attention escalation still require their later integrations. Trusted `snapshot()` is not a public peer-readable endpoint. There is no polling daemon, scheduler, or background delivery during Hub outage.

## Try the integration

No dependency installation, account, paid inference, Docker, or network is needed:

```sh
python3 -m unittest discover -s tests -p test_peer.py -v
./validate.sh
```

The first command runs focused domain/receiver integration. The second is the existing repository aggregate used by GitHub `validate`; test discovery includes this slice without a separate validation path.

The focused suite covers typed request/reply/broadcast, derived identity and status, forbidden fields and parentage, exact retries/conflicts/stale generations, every transition, default and configured multi-slot capacity, release, blocked responsibility, queue/response clocks, safe-point ambiguity, wrong/malformed/type-confused receipts, receiver errors, incarnation replacement, cancellation during an offer, shared Room state/sequence, receiver binding/dedupe, durable cursor replay, and fresh readiness after Hub restart. Admission is filled until its reserved-capacity limit rejects more traffic; after restart, every accepted broadcast is still confirmed to every recipient, and all accepted requests can be delivered, replaced with maximum-length identity fields, and completed or cancelled with maximum-length reasons. Reopening remains readable.

A real Python subprocess is killed with `SIGKILL` at five separate points: after Hub offer commit, before receiver commit, after receiver commit, before Hub confirmation commit, and after confirmation commit before return. Fresh connections reopen the actual disk databases, assert the observed pre-recovery truth, hold without a fresh safe point, and replay to one receiver inbox entry. These are executable fixture crash/replay observations, **not** actual Pi/Claude delivery, host-power-loss, process-authentication, or boundary qualification.

## Bounded admission, not stranded queues

Before acknowledging `QUEUED`, the Hub computes a conservative maximal materialized projection of every accepted item: all recipient offer metadata and confirmations, clocks, terminal statuses, maximum-length reasons and incarnation/attachment IDs, cursors, and unresolved-history summaries. If this projection cannot fit the ledger's existing one-MiB JSON/state bound, admission returns `QUEUE_CAPACITY_EXHAUSTED` without committing. This reserves space for subsequent delivery, completion and cancellation rather than accepting work that cannot later progress. Other Room-owned state already present is included; any future domain sharing this ledger must preserve the Hub's reserve rather than consuming it independently.

The immutable traffic record owns the text once. The materialized offer keeps only its digest, binding and latest result per traffic/recipient. Replaced unconfirmed offers are **not** treated as no effect: an explicit count and first/last Room-sequence references remain in the current projection, and immutable offer events retain the exact delivery IDs, bindings, digests, and supersession links. This prevents unbounded duplication in state without dropping responsibility or rewriting uncertain history. Confirmed histories also remain in the application ledger.

Like the underlying ledger, these stores assume a filesystem honoring SQLite locks and sync. The finite fixture history eventually stops new admission; no automatic eviction, retention/compaction framework, generic broker, or durable execution engine is introduced.
