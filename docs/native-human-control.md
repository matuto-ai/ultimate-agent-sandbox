# Retained native human transport checkpoint (#78)

`uas.native_human_control` implements an explicit transport lifetime, not the
native launcher, Run admission, Manager owner, credential setup or completed
real Pi/Claude scenario. Existing request-scoped B0 authentication remains
unchanged. A B0 frame session cannot be retained or upgraded into this session.

## Ownership and authority

The final host supplies an **already-established exact server-side
`ssl.SSLSocket`**, exact `HumanActionBindings`, the original trusted resource
instance ID and absolute monotonic session deadline. Construction checks B0's
TLS 1.3 / CERT_REQUIRED / peer DER SHA-256 contract and exact immutable grant
object and generation. There is no certificate, TLS-context or listener
construction and no import-time thread creation.

The explicit `start()` starts one fixed non-daemon TLS owner thread. The creating
thread thereafter never reads, writes, inspects or closes the TLS socket; the
worker receives, responds, and closes it. The binding registry stays confined to
its original main thread. Every main session check and data handoff compares its
current grant object and generation. Removal, equal replacement and re-addition
cannot authorize a former session. A mismatch latches terminal denial before
any queued command can be consumed. A queued frame is data, not authority.

The one read-only `.session` property returns the **same exact `HumanSession`**
throughout. Its callbacks work only on the creating thread and check shared
state, monotonic freshness, original instance and registry identity. They do no
TLS, provider, lifecycle or SQLite I/O. Worker and wrong-thread callback checks
return false. `open-run` and `authorize-run-request` each require explicit scopes
and `human-open-run`; control actions each require their own explicit scope,
explicit `observe`, and `human-control-run`. No inherited or wire-claimed grant
exists. These are necessary host checks, not replacements for canonical owners.

The production default clock is `time.monotonic`. An optional trusted clock-only
test seam is not a configuration, JSON or authorization callback. A future fixed
bootstrap must use the default clock and derive the instance and deadline from
its original resources; callers cannot use this module to select another Room.

## Bounded transport and freshness

The existing bounded HTTP/JSON framing and B0 `/uas/human-action/v1` envelope
are reused. Each complete valid frame renews freshness by at most five seconds,
never beyond the original absolute deadline. Both the old freshness deadline
and absolute deadline must still be valid **before** renewal. The initial
five-second window starts at construction; delaying start does not extend it.

The session is unusable until the first complete authorized `open-run` frame.
EOF, receive/send error, failed start, exited pump, close, expiry or main-observed
revocation terminally invalidate it. A stopped/blocked pump cannot leave cached
authorization usable beyond freshness. Late frames never revive an expired
session. Idle clients need explicit `observe` frames before expiry. Certificate
getters are authentication checks, never evidence of continued peer liveness.

The worker checks the terminal latch after receive and before each response.
The last-published response is explicitly not a live owner observation; bytes
already in flight cannot be retracted on disconnect/revocation. No transport I/O
is performed while holding the shared-state lock. `close()` denies immediately,
then joins for at most 5.25 seconds. A still-running worker reports
`NATIVE_HUMAN_PUMP_STOP_PENDING`; it is not replaced or silently declared stopped.
The owning thread alone eventually closes its socket. Before start, or if thread
creation failed before ownership transfer, the creating thread may close it.

## Finite request vocabulary

The first frame must be:

```json
{"version":1,"action":"open-run","payload":{"operation_id":"original-operation","issue_number":78}}
```

No Participant, identity or capabilities are accepted from this payload. The
future trusted native plan selects the Participant. Exact duplicates only report
queued status; changing either field terminates the connection. The main owner
calls `first_request()` for the frozen `NativeHumanOpen`. It returns `None` while
awaiting receipt, and a second acquisition after handoff is refused.

Subsequent frames may contain:

- `observe` with exactly `{}`: heartbeat and coalesced observation request.
- `request-changes` or `reconcile-changes`: an unchanged exact Manager envelope
  as payload, with matching outer/inner action and B0 scope correlations. The
  existing canonical request parser and body bounds are reused.
- The same initial `open-run`, never a second Run.

There is no standalone `authorize-run-request` wire action in this native mode.
Start, Stop, merge, reset, replacement and arbitrary actions remain unavailable.
Exactly eight distinct control-operation identities may be recorded during the
connection's entire lifetime, not eight at a time. Same-operation/same-payload
duplicates do not enqueue again; conflicting payloads fail closed. Draining or
publishing an unknown result does not discard identities or schedule retries.

## Main-owner data APIs and response meaning

`drain_commands()` returns deep-copied original Manager packets once.
`take_observation_request()` consumes a boolean latch; the future native owner
must obtain its canonical Broker/current-Run view outside lifecycle/SQLite locks.
The TLS thread never calls an inbox, Broker, provider or Room owner.

`publish(view, statuses)` permits only a view containing `run_id`, `generation`,
`status`, `observed_version`, nullable `review_stage` and `submission_id`, and
boolean `forge_uncertain`, plus up to eight known operation/status pairs.
The fixed review-stage vocabulary comes from the canonical Run review owner;
the original submission ID supplies the Manager request's object correlation.
It accepts no bodies, raw errors, secrets, Origin or arbitrary response objects.
The worker sends one bounded reply per frame, labeled
`view_kind: last-published-not-live`. `queued` means only transport scheduling;
neither it nor cached status is an acceptance, commit or provider receipt.

## Consumed integration still pending

The fixed launcher must establish TLS **after exec in the final host**, not pass
a numeric FD and pretend to preserve negotiated SSL state. That host must pass
this same session to `NativeHumanRunRequest` and, after `native_session.run`
creates its original Broker client, to `NativeBrokerAudit` and
`NativeHumanReviewInbox`. The driver must drain commands and requested
observations outside owner locks and keep all existing canonical authorization,
unknown-effect and reconciliation checks. None of those consumed seams is
changed by this checkpoint.

`python3 tests/run_native_human_control_source.py` imports only the explicitly
listed source test class after installing process/socket/thread/permission/
ctypes/SSL-context and certificate-loading guards. Tests use scripted transport,
thread and clock seams, not real TLS, threads or native qualification. Any
prohibited effect attempt fails the run, including a caught attempt.
