# Manager live read model — issue #75

The [Field Notes consumer](manager-field-notes.md) (#76) extends the projection
to schema v2 with one bounded, source-owned journey window. Existing v1 data is
readable with history explicitly unavailable; upgrade the consumer first. The
original replay event shape, Room identity, source watermarks and mutation-free
transport vocabulary remain unchanged.

This is the read-only source/transport integration for [#75](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/75),
not the Manager UI (#76), actions (#77), or completed real-product acceptance.
It has no Run, Gate, review, Forge, Supervisor, shell, filesystem, or container
mutation command. Export failures and a disconnected Manager do not stop a Hub.

## Source and ownership map

The implementation began at `8fd9ae0c2d7a9c664ec4be67317b1768f0253d85` and
includes non-destructive #73/#74 main unions through
`4c970c66925fb7a724dc15680fe1743da1b47617`.
The installed Bruno workflow, #75/#74, source reconciliation, and actual owners
were read before implementation. Gate schema ownership was coordinated with
the #73 owner. This slice adds the Gate-owned passive snapshot helper and an
existing-store read-only Room ledger constructor; it does not change Gate
adjudication or the Hub's write transitions.

| Seam | Existing authority | Passive export and limit |
| --- | --- | --- |
| Hub | `RoomLedger.snapshot()` and `replay()` | One SQLite snapshot cut; ordered original events through that cut. Manager never calls `apply()`. |
| Run / Work Request | Hub `runs`, peer traffic and context state | Allowlisted status, generation, request lifecycle, context-bound versus reserved Run, attention. No request text or instructions. |
| Seat / process | Supervisor Participant controller | Stable seat, incarnation/epoch and **persisted** authority status remain separate. No PID or fresh liveness claim. |
| Adapter / readiness | Hub's recorded connection/observation state | Attachment, readiness and last observation ID are separate facts; freshness remains unknown without a fresh adapter observation. |
| Lifecycle / profile | Supervisor lifecycle store | Persisted desired/phase/authority, expected image/profile and staged update. Actual image/profile remains explicitly unknown. No Engine inspect. |
| Checkout | Supervisor checkout manifest | Exact host path, branch, Run, Participant, intent and phase; retained owner-probed working-tree state and its own observation time, or explicitly unknown. `manager_observations()` never enters the Git-probing path. |
| Forge diagnostics | `ForgeAudit` | One read transaction, Room-filtered metadata, committed outcome/contact/completeness. No provider access, payload, stdout, body, signed URL or credential. |
| Dependencies | `ReadOnlyForgeBroker` | Exact immutable Broker receipt referenced by the canonical Run, fenced to the Hub cut and checked against Project/repository/issue identity. Existing observation, not a fresh provider query. |
| Gate / external checkpoint | Hub Gate owner | Owner-defined pure `snapshot_gate_state()` exposes retained verdict/version/time, known generation/policy staleness, missing evaluations and actual in-flight owner checkpoints. Historical pass is **never current pass**. |
| Review / candidate | Hub review owner (#74) | `snapshot_review_run()` consumes the identical Hub cut. Canonical submission, candidate, reviewer, round, stage, timestamp and finite attention reason are allowlisted; stale generation/target remains stale. |
| Provider / inference / quota / context measurements | Runtime adapter | Separate finite typed observations; unsupported existing provider telemetry remains unavailable, not zero quota, healthy inference or ready state. |

`RoomStream` accepts the actual Supervisor, Participant controller, checkout
allocator, Forge audit and retained-read Broker objects through fixed, Room-checked constructor
parameters. It invokes their passive export methods, rather than asking an
application to invent `SourceObservation` values. The finite typed observation
interface also defines unavailable runtime observations; it does
not grant a caller authority over those sources.

The three Supervisor manifests retain their existing required version-1 fields
and accept two optional metadata fields: `observation_revision` and
`observation_committed_at`. Only an existing owner `_save()` increments them,
inside the same atomic manifest write. Legacy manifests without both fields
remain unknown until a real owner save. Missing or partial metadata is never
interpreted as revision 1.

`source_committed_at` is deliberately distinct from `observed_at`. Saving an
unrelated field does not refresh process liveness, adapter readiness, provider
health, working-tree state, or actual image identity. Passive persisted facts
keep freshness unknown; no probes are hidden in serialization.

The trusted host can explicitly call `CheckoutAllocator.refresh_observation(slot)`
for one owned slot. This reuses the existing authorized, Room-locked Git
admission and `_observe()` path, including ignored/untracked files. Only a
dirty/clean/unknown result, finite reason and its actual observation timestamp
are retained in `checkouts.json`; file names, content, raw output and errors are
never exported. This is a historical observation, not a current filesystem
lease or cleanup authorization. Every ordinary slot owner save invalidates
retained probes; the next refresh must inspect the new binding. Read failures
are unavailable, and an unsuccessful probe replaces an earlier clean result
with unknown. Manager reads and responses cannot request a probe. Host
scheduling stays outside the Hub thread and is bounded to one slot per call;
this adds no scanner daemon or network action.

## Snapshot and replay contract

Each fact envelope has an explicit source owner, observed revision, source
observation time (possibly unknown), source commit time (possibly unknown),
status, freshness and reason. Its provenance applies to every field in its
value. Facts from different owners are never merged under one envelope.
Independently captured external owners are not advertised as an atomic cut
with the Hub.

The Gate and Review passive helpers consume this exact same Hub cut, not new
per-Run reads. Gate currentness remains unknown without a fresh dependency
observation; retained completed verdict/version/time are separate fields. A
generation/policy mismatch already established by the cut is explicitly stale.
The `pending_ci` rows identify an actual external Gate owner checkpoint
(`evaluation` or `refresh`), **not a claim that remote CI is pending**. Remote CI
state remains unobserved there; no provider request is triggered by reading it.
These exports contain no Gate authorization token, review evidence body, request
text, native review payload or generic action vocabulary.

`submission_id` is the internal review submission operation; `review_reference`
is the exact verified GitHub review URL and stays null until a result exists.
They are not interchangeable identifiers. A canonical Gate-bound candidate is
visible before review starts, and an older review cannot replace a newer bound
candidate in the read model.

1. A new authenticated Room connection asks for the Manager's durable cursor.
2. The source captures one detached projection at Hub sequence `cut`.
3. A new Manager may bootstrap directly from that snapshot. An existing
   Manager must receive every original Hub event after its cursor through `cut`,
   in contiguous sequence order.
4. Replayed events contain only owner, sequence, kind and original timestamp.
   Project-bearing payloads are deliberately omitted. These are original-event
   metadata, **not invented intermediate fact deltas**.
5. Manager retains its previous snapshot and marks catch-up stale until the
   entire event range is durable. Only then does one Manager transaction install
   the final projection and cursor together.
6. Events committed after the captured cut belong to the next transfer. A lost
   final acknowledgement is reconciled with the durable cursor, never by
   repeating a workflow operation.

The final installed projection reconstructs identically after replay. There is
no claim that this source can reconstruct intermediate fact states which its
original events did not retain. Partial pages, gaps, changed duplicates,
conflicting snapshots, source revision regressions and Room epoch replacement
are explicit errors. Exact page retries are idempotent. Source-version
watermarks survive an unavailable interval and Manager restart.

Completed Destroy removes the Hub state as well as instance-owned Participant
and checkout stores (security-boundary.md, lifecycle contract). A recreated Room
is therefore a new source epoch, not a reconnect of the destroyed Room. Ordinary
Stop/Start retains the same instance and stream. The source must not reuse an old
Manager stream after Destroy or reset its revision watermarks: the Manager
rejects that regression and preserves the last accepted projection. A different
stream identity also cannot silently overwrite it. Authorized host integration
must reconcile the destroyed epoch and provision the replacement explicitly;
a connection attempt alone does not authorize that replacement. This draft has
no automatic epoch-replacement mutation API.

Connection status, catch-up status, age-based staleness, source unknown,
source unavailable and failed observations are separate. A connected socket is
not a healthy source. Reopening Manager storage starts disconnected; it cannot
restore a live connection from a persisted boolean.

## HTTPS and authentication

Transport uses ordinary bounded HTTP/1.1 JSON POST batches over mutually
authenticated TLS 1.3. There is no private binary framing behind an HTTPS URL.
The vocabulary is only `hello`, `begin`, `events`, and `finish`, with explicit
acknowledgements. No response contains a workflow action for the Room.

`ManagerAddress.from_url()` uses the existing configuration's credential-free
public HTTPS URL validation. A root URL uses `/v1/room-stream`; a non-root path
is the exact configured endpoint. Host service setup must configure that same
path on `accept_session()`. Redirects are not followed; caller-selected hosts,
credential URLs, queries, fragments, traversal paths, compression, chunked
encoding and ambiguous Content-Length are rejected. Header limit is 8 KiB;
JSON body limit is 1 MiB; one absolute receive deadline covers header and body.

Manager validates the certificate chain and binds the exact client certificate
SHA-256 fingerprint to one `(deployment_id, room_id, stream_id)`. A valid chain
alone does not authorize selecting a Room or another Deployment. The Room
validates the Manager certificate and configured hostname. Credentials are
supplied by the trusted host, never by a frame or Project data. The code does
not install certificates, modify a trust store, or manage account permissions.

`stream_id` is an operator-owned persistent source identity, not an arbitrary
connection ID. Replacing a source store/Room epoch is an explicit integration
decision; a new connection cannot silently reset an existing Manager cursor.

## Host integration

`export_once()` composes one real client cursor/snapshot/replay/ack iteration;
it reports ordinary outages without controlling the Hub. The modules provide a
real client and accepted-session service, not a deployed Manager listener.
`RoomManagerExport.from_configuration(source, configuration_file, resolve_tls)`
validates the existing deployment/Room and resolves its existing client/trust
reference IDs through the trusted host callback once. That callback returns a
configured TLS context; no credential store or secrets protocol is added.
`step(now=monotonic_time, captured_at=utc_timestamp)` performs one eligible
transfer and returns the next deadline. Success uses the configured snapshot
interval; failure uses capped exponential backoff. It launches no thread and
has no sleep/retry loop. `close()` is terminal. Workstation Stop is not a reason
to stop exporting; Destroy/replacement ends the host-owned source epoch.

`RoomLedger.open_reader(path, room_id)` gives the exporter a separate SQLite
`mode=ro`/`query_only` connection to the existing exact Room store, without
creating schemas or changing journal mode. Construct/use it on the exporter
thread rather than sharing the Hub connection. The trusted host still owns
launch, service lifetime and the actual credential resolver. The host must:

- resolve the existing Manager credential/trust references outside Project
  space and bind each Room certificate to its exact identity;
- run a separate exporter worker with its own Room-ledger connection, so the
  Hub owner thread never waits for Manager networking;
- schedule accepted Manager sessions on the Manager store's owning thread;
- reconnect through the durable cursor, periodically capture a fresh snapshot,
  and stop only the exporter when Manager is unavailable;
- connect canonical #73/#74/runtime exports where those owners actually hold
  the required observations, without enabling UI/actions in this slice.

`RoomManagerWorker` provides the actual owned exporter thread for that host. It
creates the separate read-only connection on its thread, resolves the fixed
configuration there and uses `RoomManagerExport.step()` plus interruptible waits.
Trusted `open_source(reader, identity)` construction supplies a context manager
for real passive owners; it cannot be selected by a wire message. A host-minted
read-only `worker_id` identifies this exact execution separately from the
persistent Room stream identity. A new worker cannot prove termination of an
older worker that used the same stream.

Start is explicit and one-shot. Workstation Stop retains the worker. Destroy
calls nonblocking `request_stop()` while holding lifecycle authority and waits
or reconciles **outside** the Supervisor lock: capture can need that lock.
`join(timeout)` is bounded to at most five seconds; false retains the exact
owned worker and must not authorize resource removal or replacement. Interrupted
construction closes owned readers; uncertain start retains any live thread.
Terminal status requires both completed cleanup and no live thread. No second
daemon, credential store, remote action route or thread-kill mechanism is added.

The existing hosted-only mTLS job also exercises the real worker, stopped-Room
exports at an unchanged Hub sequence, automatic reconnect after a real accepted
socket interruption, exporter restart with the retained stream/cursor, and termination before
fixture Destroy. `tests/manager_worker_fixture.py` exposes that same bounded
receiver proof for #61's real control-plane harness. Only its exact temporary
fixture endpoint is routed to loopback; TLS hostname and certificate checks
remain real. This hosted proof is not executed by ordinary local unit discovery.

There is no deployment, external probe, production credential use, account
change, or permissions change in this work. Manager storage keeps the replay
archive; retention/capacity policy must not silently discard required events.

## Evidence and acceptance limits

`tests/test_manager_read_model.py` is pure plus temporary filesystem/SQLite.
It covers two Rooms, an event arriving after the snapshot cut, strict ordering,
partial replay, disconnected Hub progress, replay/restart, same-version
conflict, stale/unknown/failed distinction, real peer presence state, passive
Supervisor/Broker integration, inert Participant/checkout owner-store export,
legacy metadata, destroyed/recreated source refusal, redaction, HTTP bounds and
forbidden mutation messages.

`tests/test_manager_tls.py` is an explicit hosted-only test guarded by
`UAS_MANAGER_TLS_TEST=1`, `GITHUB_ACTIONS=true`, and `RUNNER_OS=Linux`. It creates
temporary EC fixture certificates and localhost sockets, then tests actual
two-Room HTTPS/mTLS, replay, client-certificate/Room mismatch, absent and
unregistered client certificates, wrong server trust, and rejected actions.
The dedicated one-minute `manager-mtls` CI job runs it with a 40-second process
bound after both one-minute unit roots; it adds no serial stage beyond the
existing three-minute critical-path budget. Source is independently reviewed
before publication/execution. Merely
adding this file, skipping it, or passing pure checks is not TLS evidence.

The real HTTPS/mTLS fixture passed on PR #128 head `4f368ac9` (job
`122461101827`); the subsequent metadata-compatibility candidate `aed246e`
passed the complete automatic CI path in 148 seconds. Those receipts do not
substitute for running a newer candidate. The checkout observation integration
has guarded filesystem/controlled-Git-response coverage plus a focused real-Git
test in `test_checkouts.py`, reserved for hosted CI. `test_manager_host.py`
covers the actual separate SQLite reader, inert protocol transfer, scheduling,
outage backoff and fixed reference resolution without sockets or threads.

The worker is the concrete #75 outbound connection/lifetime interface. #61 owns
its attachment to the persistent launcher and service revocation, rather than
duplicating the exporter or its credential store. The direct #75 worker fixture
crosses real Hub SQLite, real HTTPS/mTLS and lifecycle transitions; #61 reuses
the same receiver helper in its service-process proof. Neither slice claims
deployment into a user's environment from these controlled hosted results.

The #73 Gate and merged #74 Review passive owners are integrated at the same
read-only Hub cut. Provider/quota/context observations unsupported by the current
runtime owner remain explicitly unavailable; this slice does not invent native
telemetry or turn missing measurements into readiness. Final acceptance requires
the new exact candidate's hosted worker proof, aggregate CI and independent
Standards/Specification/Runtime review. Earlier receipts alone do not qualify it.
