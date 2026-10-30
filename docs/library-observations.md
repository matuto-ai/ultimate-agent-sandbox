# Passive Library observations (T29)

`library_observations.Owner` is a trusted Library-owner composition, not a new
Participant, Manager command, content API or refresh timer. Explicit startup,
change or diagnostic sampling reads one authorized bounded canonical Project
snapshot and a bounded existing operational-history cut. It persists a strict
content-free `library-observation` manifest in the existing Library records.
`latest()` recovers that source version after restart; re-sending the same
observation does not re-sample or claim a fresh timestamp.

The Supervisor binds `HubObservations` to the authenticated service transport,
Room ledger and immutable Project identity. Its receive operation refuses foreign
Projects, unauthenticated calls, changed same-version payloads and stale versions.
A retained observation is sent to the existing `RoomStream.capture(..., observations=hub.manager_observations())`
and `ManagerReadModel` seam. The finite `library` external section is owned by
`library-service`, not by the Hub: source time and version survive replay. The
Hub cut is explicitly not atomic with the Library snapshot. Missing observation
means unknown, not an empty queue. Older schema-1/2 source frames without this
optional section remain readable; updated producers send it. Older consumers
must be updated before consuming this added section.

The schema permits only fixed enums, counters, timestamps, safe immutable IDs and
commit/content hashes. It rejects unknown keys on both sending and receiving
sides. Titles, bodies, prompts, raw model output, source text and secrets never
enter Library observation records, Hub state/events, Manager storage or replay.
Raw Library paths and provider endpoints are not included. No UI or notification
is added here (T30/T38).

Queue depth is current for the sampled canonical SHA. Oldest active age uses immutable submission provenance; adjudication wait uses
the latest committed parking transition, never the original enqueue time. Both
are known only when the bounded
record inventory covers those queue IDs; absent provenance is unknown. Projection
SHA/time come from an actual fixed supervisor projection, not canonical success;
an equal SHA is current at sampling, a different SHA stale, absent data unknown,
and read failure unavailable. Manager replay never reads the clone, projection
filesystem, provider or operational journal. A newer Hub capture cannot renew an
old external timestamp. Manager disconnected/catching-up/aged reads mark the
cached Library envelope stale while retaining its observation time and values.

Windowed throughput is the count of distinct durably queued captures, separately
from committed synthesis outcomes. Duplicate-merge effectiveness is observed
`merged` outcomes divided by all committed outcomes in the explicit observation
window, not a semantic-quality score. Human correction feedback remains unmeasured until an explicit human-recorded
correction source supplies its denominator and observation window. Adjudication
alone is not evidence of a correction. Missing feedback is unmeasured. No inference from an empty queue is made.
Truncated history is labeled partial and yields unknown aggregate counts/ages,
not an overall successful report. Details that expire under future T31 retention
must similarly remain partial/unmeasured; do not manufacture zero feedback.

Reports expose scheduler drain/attempt/retry state and classified safe failures.
Replay lag counts durable transitions not yet acknowledged by the Hub, including
ones not yet attempted. Source, model, validation, transport, capture, audit and
recovery categories do not copy raw reason strings. The default provider fact is
literal unknown: a successful drain is not a provider probe. A trusted provider
adapter may supply a separately versioned/timestamped `ProviderObservation`
(profile hash, local/hosted mode and observed availability only). This neither
qualifies nor authorizes a provider, changes credentials, probes quota, or calls
an external model.

Sampling, forwarding and replay are separate facts. The service continues even
when Manager/Hub is absent. The trusted host composition must retry `Owner.latest()` until accepted;
this slice supplies the transport seam, not a background forwarding worker.
A Project has one active observation owner; concurrent owners are not supported.
Internal random operation IDs cannot be preempted by participant request IDs;
observations supersede older snapshots, whereas the independent T21 lifecycle
outbox retains its own ordered durable report acknowledgements.
