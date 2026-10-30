# Authenticated Library enqueue routing

T09 attaches `LibraryHub` to the existing `AdmittedPeerDispatcher`. Trusted
Supervisor composition supplies the Room's configured Project and immutable
source repository identity, plus a preauthenticated external service contact.
The Participant frame is exactly:

```
{"request_id":"<32 hex transport correlation>","envelope":{
  "id":"<Hub Command ID>","kind":"library.enqueue",
  "request_id":"<librarian request ID>",
  "capture":{"type":"decision","title":"Decision","body":"Markdown",
             "sources":[],"hints":[]}}}
```

The ordinary single-record native frame bound is unchanged. A missing route
returns `LIBRARY_UNAVAILABLE`; it never falls through to generic content-bearing
peer persistence. Native Pi/Claude tool presentation is T10/T11, not this slice.

The admitted kernel process binding supplies Participant, Actor and effective
capabilities. `library:enqueue` is accepted as an exact namespaced capability
without relaxing ordinary seat identifiers. Every attempt, including a cached
retry, rechecks the live admission and current Hub connection. Capture cannot
supply Project, path, Actor, authority, timestamp, generated status or Run.
Optional Run provenance comes from the Hub's current bound/reserved context; it
is not a completion gate and does not require that Run to remain open.

## Two identities and crash boundaries

Before service contact the Hub reserves its Room-wide Command ID with the exact
canonical request digest, authenticated origin and trusted Project target.
The service operation ID is a deterministic digest of Room, immutable Project
identity and Command ID, preserving the deployment-wide service namespace even
when two independent Rooms choose the same Command ID. Its metadata linkage
retains the original Room Command identity without retaining capture content. Only
request ID/digest, Project identity, first attempt time and optional Run enter
that reservation. No title, body, source resource or relationship hint enters
RoomLedger callbacks, operations, snapshots, events or replay. The transient
capture remains in memory until contact completes; there is no fallback queue.
This is a maintained-store guarantee, not physical-memory remanence protection.

The Hub releases its admission fence and database transaction before external
contact. The service gets a fresh-authority callback, and authority is checked
again before disclosure and outcome persistence. The service-side
`EnqueueEndpoint` composes the existing T08 Enqueuer and keeps canonical Git,
settings and credentials on that side. The contact is a trusted integration
seam, not a Participant-selected address or a newly provisioned network listener.
This slice does not claim actual external-host authentication deployment.

An exact Hub Command retry must match its original origin and request digest.
It reuses the first recorded time/Run, even after that Run closes. Another Actor
cannot reuse the Command. A new Command may submit the same librarian request
under current authority; T08 reconciles its original publication and preserves
first-submission provenance. A crash after reservation or publication but before
Hub outcome recording resubmits the same service operation for reconciliation,
never blindly chooses a new content identity.

Validated content-free outcomes are recorded as linked internal ledger events.
An exact retry returns the immutable recorded outcome. Service exception, loss
or malformed response becomes retryable `NOT_DURABLE`, never a claim that no
commit exists. A lost Hub result write returns `HUB_RECEIPT_UNAVAILABLE` rather
than successful durability; a later exact attempt reconciles the service.
If the uncertain outcome was recorded, retry with a new Hub Command and the same
librarian request/payload. Current revocation prevents historical receipt
release. None of these outcomes modify Run completion or context-reset state.

## Verification

`tests/test_library_hub.py` uses the actual socketpair/SCM credentials/pidfd
admission path with distinct owned child processes, real RoomLedger SQLite,
real disposable canonical Git and T08 metadata records. Coverage includes
Project binding, Actor attribution, capability refusal, changed origins and
payloads, first Run/time, closed Run submission, service loss, publication and
receipt crashes, current revocation, hostile service replies, namespace conflict
and marker absence from maintained intermediary tables/snapshots/replay/files.
The fixture's native readiness is synthetic; no container, live Pi/Claude,
provider, actual Library target qualification, host install or production
credential setup is claimed. Those retain their dedicated acceptance slices.
