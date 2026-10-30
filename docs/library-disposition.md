# Canonical human rejection (T24)

The started Library Service's private local operator transport accepts `reject`.
The trusted host resolves a fresh `LocalHuman`; a UID or Participant badge is not
Project authority. The human needs current `library-reject` and inspection access
for that immutable Project. No caller-supplied path, identity or batch is admitted.

Inspect the pending item through T23, then submit version 1, action `reject`,
`project_id`, `queue_id`, a unique `request_id`, the inspection's `settings_id` and
`observed_version`, a nonempty bounded Markdown `reason`, and `drain_id` (the
currently blocked selected drain, otherwise null). The existing request envelope
is limited to 8 KiB. Configuration, complete Project content, target and human
scope are fenced against the inspection. Refresh after stale evidence.

One complete-result policy gate removes only the rejected pending document and
its index entry, and appends the reason and canonical disposition evidence to
`log.md`. Git history preserves the former draft. Markdown, paths and secret
policies cannot be bypassed by human authority; the unescaped reason is checked
before its single-line canonical JSON encoding. No model is called.

An active selected item is busy. Rejection of a blocked selected item atomically
records the original ordered batch, attempt, terminal operator-disposed drain,
and per-item `rejected`/`retained` outcomes in the same Git transition. Untouched
drafts remain byte-identical and pending, but the Project remains blocked under
`DISPOSED`. Neither old retries nor direct attempt recovery can resurrect that
drain. A later rejection of a retained item uses `drain_id:null`, preserves the
original terminal report and still does not release the Project. Releasing
the remainder is the separate receipted [resume](library-resume.md) action.

Only a pushed commit produces `COMMITTED`; its receipt cites that commit.
Metadata records, logs and Hub reports contain no human reason or draft body.
The OPERATOR_DISPOSED report includes the pushed SHA, original drain and durably allocated
sequence, and is never reported as successful model integration. Reports remain
at-least-once with receiver deduplication. The canonical marker stores a sequence
lower bound; recovery allocates above any intervening authority-failure reports
and persists that exact outbox identity before sending. Arbitrary deletion of
operational history is not a supported way to preserve earlier report IDs.

An exact request retry under current human authority reads/reconciles its first
result; changed payload or actor under the same ID conflicts. Historical success
does not require the now-removed target or today's old configuration to reappear.
An unresolved intent remains unknown until canonical Git reconciliation, never
permission to repeat a stale write. Publication uncertainty fail-closes new
Service turns until restart; exact request reconciliation remains available. Even authoritative absence does
not reapply an old payload: refresh inspection and use a new request ID.
Startup verifies canonical publication and
its original marker before rebuilding operational disposition state. Untrusted
markers cannot create human identities in the record store. Canonical scopes are
historical evidence only, never grants for reading or writing.

Tests use temporary real Git repositories, SQLite, Service restarts, actual child
process death at commit/push/receipt/report boundaries, and authenticated Unix
sockets. Socket-denying local sandboxes explicitly skip native transport tests;
GitHub CI must execute them without that skip. No real user draft is disposed by
these tests, and no deployment/provider/account changes are needed.
