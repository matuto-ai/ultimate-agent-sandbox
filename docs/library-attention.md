# Deduplicated Library attention and safe notifications (T38)

`uas.library_attention.Owner` is a trusted Library-owner composition, not a
Participant command, content API, polling daemon or notification account. It
derives attention only from the latest T29 `library` observation row
(`library_observations.Owner.capture`) plus the Project's own durable attention
records. It never reads drafts, titles, bodies, prompts, model output, logs,
secrets, canonical paths or provider endpoints.

Derived rows are fixed metadata: `PARKED_CONFLICT` (parked depth and
adjudication wait), `PROJECT_BLOCKED` (the scheduler's `BLOCKED` drain state),
`AUDIT_FAILURE`/`RECOVERY_FAILURE` (classified observation failure counts), and
`OLDEST_DRAFT_WARNING` (active oldest age at or above the configured
`limits.warning_seconds`, published default 86400 seconds). Each row carries
only an enum kind, a literal count, an optional age and an optional
`snoozed_until`. Parked conflicts and the oldest-draft warning are Manager
attention only; they never notify externally. The oldest-draft row is derived
from the source's active oldest age, so parked drafts are represented by
`PARKED_CONFLICT` instead of being counted as a warning.

Missing, partial-coverage or unknown-queue source state yields an `unknown`
attention cut with no rows, never an empty healthy report. An absent observation
is unknown, not a captured empty queue. Rows and the sample time are copied from
the source observation, so Manager keeps the owner, time and stale state of the
fact it was derived from, and a newer Manager cut cannot renew an old source
time.

`Owner.sample()` persists one versioned metadata-only `library-attention`
manifest in the existing Library records; `latest()` recovers the version after
restart. Each cut carries the immutable Project identity it was derived for, and
the Hub rejects a cut whose binding is not its own Project before recording
anything, so attention cannot be shown under another Project. The Supervisor forwards it with
`RoomStream.capture(..., observations=hub.manager_observations())`, which now
carries the `library_attention` external section owned by `library-service`.
That section is subject to the same Project binding, monotonic version, replay
deduplication and stale marking as the T29 `library` section. Older schema-1/2
frames without this optional section remain readable; consumers must be updated
before reading it.

## Notifications

External notification reuses the existing host-composed Gotify transport
(`manager_attention.GotifyDelivery.deliver_payload`) with one existing endpoint
and credential reference. No account, token, subscription, retry loop or
polling is created, and no notification is sent at import or construction.
Passing no delivery means no configured preference exists and nothing is sent.

Only `PROJECT_BLOCKED`, `AUDIT_FAILURE` and `RECOVERY_FAILURE` are external
candidates. Each identity is `project + kind + evidence`, committed as a durable
`attention-notice` intent before the single bounded POST. Evidence is the
blocked drain identity or the per-kind episode number that the cut carries
forward: a retry of the same blocked batch, a later sample of the same state or
an increased failure count reuses the stored identity and sends nothing, while a
different drain, or a failure that cleared and appeared again, is a new episode
and may notify once more. A blocked Project without any batch has no drain
identity and is separated by the same episode number. Confirmed, unknown and
undeliverable outcomes are recorded as ACKNOWLEDGED, UNKNOWN and NOT_DURABLE
receipts. An uncertain or raising delivery is settled as UNKNOWN and never
retried automatically, so a lost response cannot repeat a notice; only an
undeliverable attempt (no resolvable credential at that moment) is retried on a
later sample. Payloads contain one fixed reason sentence, a bounded
count/age, the observation time and the canonical Project link derived from the
trusted binding. They contain no titles, bodies, prompts, raw output, secrets,
private paths or Project identity strings.

## Defer

`defer` is a receipted attention snooze through the existing T22 host-local
human admission. It binds a unique request ID, the current settings identity and
the exact durable attention cut; a newer observation or configuration requires
refresh, a submitted settings identity that is not the current one is refused,
changed-payload ID reuse conflicts, and an exact request retry reads the stored
receipt without reapplying anything. The snooze receipt and the snoozed
attention cut are committed in one SQLite transaction, so a lost acknowledgement
can only be reconciled, not duplicated. A second snooze while one is active is
refused rather than silently extended.

One active attention writer per Project is supported, like the T29 observation
owner. A raced cut sequence is refused by the durable record identity (ID
conflict) instead of being overwritten or duplicated.

Defer applies only to the attention kinds present when it was admitted, for the
fixed bounded snooze window of 86400 seconds from admission. That constant is
the issue's stated default; it is not read from configuration in this slice,
unlike the oldest-draft warning threshold. The admitted window and kinds travel
on the durable attention cut, so an intervening unknown or partial observation
cannot silently end the snooze early. Rows keep their literal counts and ages, and
`snoozed_until` merely suppresses display urgency and the external notice. Drafts,
parking, the blocked drain, retry state, scheduler state, canonical Git and the
source observation are unchanged. Expiry restores the same Manager attention
without resolving the underlying work and without repeating an already
deduplicated notification.

Defer requires the accepting host to hold the current authenticated Project
scope, exactly as the T29 observation owner does; it introduces no new authority
path. Like the T29 slice, this slice supplies the attention owner and transport
seam: the host composition that schedules sampling and forwards the projection
is deployment wiring, not part of this issue.

`tests/test_library_attention.py` exercises the real service, canonical Git,
SQLite records, Room ledger, Manager read model and Unix-socket defer path, plus
an inert HTTP channel for the exact bounded Gotify bytes and an explicit
failure-mode recorder. It is deterministic fixture evidence, not live-provider,
real notification account, VM or deployment evidence.
