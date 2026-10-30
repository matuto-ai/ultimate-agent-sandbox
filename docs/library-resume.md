# Resume only the remaining disposed-batch work (T26)

A blocked-batch disposition ends the drain but leaves every untouched draft
pending; [canonical rejection](library-disposition.md) deliberately does not
release it. `resume` is the separate human action that does. It is not part of a
reject/adjudicate request, an ordinary `drain`, `retry` or startup
reconciliation, and no Participant command reaches it.

The started Library Service's private local operator transport accepts `resume`
beside the existing actions. The trusted host resolves a fresh `LocalHuman`; a
UID or Participant badge is not Project authority. The human needs current
`library-resume` access for that immutable Project. The request carries version
1, action `resume`, `project_id`, a unique `request_id`, the disposed `drain_id`
seen in an observation, the inspection's `settings_id` and the observed
`observed_version`. No caller-supplied path, scope, batch or identity is
admitted, and the payload accepts no partial queue selection: the whole retained
remainder is the remainder.

## One receipted scheduling action

Admission rechecks current human authority, the observed disposed drain,
configuration and the complete Project target version, including active (not
archived) state and the current bundle gate. Stale content, state, settings or
authority requires a refreshed observation; an archived Project refuses because
release is a write freeze it does not lift. Resume publishes no Git commit and
calls no model.

The scheduling transition and its human acknowledgement commit in one SQLite
transaction. Success cites that durable operational acknowledgement
(`ACKNOWLEDGED`), never an invented content commit. The resumed Project becomes
fairly eligible like any other explicit drain request: it does not preempt an
active unit and does not jump the least-recently-served queue.

Releasing never continues the disposed drain. Its recorded identity, ordered
batch and terminal `OPERATOR_DISPOSED` outcome stay as they are, its uncommitted
proposal is not reused, and the released Project starts with no drain. The next
scheduler turn mints a newly identified drain from the incremented durable
sequence, so the old drain ID cannot reappear and direct attempt recovery of it
still refuses with `DRAIN_DISPOSED`. The canonical tombstone and its human
decision remain in `log.md`.

An empty remainder stays a legitimate outcome: the resumed Project runs one
scheduler turn, finds nothing pending and returns to idle without any model
contact. Nothing is released silently, so an empty release is observable as that
no-work turn rather than as a fabricated commit.

## Retries and uncertainty

An exact retry of the same request ID under current human authority reads and
reconciles its first result instead of applying a second scheduling effect.
Reusing that ID with a different payload, drain, settings, action or human
identity is a conflict. A lost commit response leaves the outcome unknown until
the same request reconciles against durable records; it never authorizes
repeating a stale release. Publication of a later disposition request is
unaffected, and replaying an old rejection does not re-dispose a Project that
was resumed afterwards.

Restart reads the durable schedule: a released Project stays released, startup
recovery never re-adopts the old batch from its tombstone, and a Project whose
disposition is still outstanding is still disposed.

`tests/test_library_disposition.py` and its recovery and native cases use
temporary real Git repositories, SQLite and the authenticated Unix socket to
prove release with a nonempty and an empty remainder, an unresolved or archived
Project, revoked and cross-Project authority, stale state, exact and conflicting
retries, a lost commit response and restart recovery. No model, credential or
live user draft is involved.