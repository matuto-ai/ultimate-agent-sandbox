# Faithful human adjudication (T25)

The authenticated Library Service operator transport accepts `adjudicate` with
current Project `library-adjudicate` and `library-inspect` authority. It does not
call a model. Observe/open the pending item through T23, then send version 1,
`action: adjudicate`, `project_id`, `queue_id`, nullable `drain_id`, `request_id`,
`settings_id`, `observed_version`, `conclusion`, and `rationale`. No paths, trust
flags, actor identities, titles, or sources can be supplied by the caller.
Requests retain the existing 8192-byte transport bound and configured body bounds.

Both authored fields are preserved under UTF-8/NFC/LF canonical normalization,
including spaces, tabs, paragraph breaks and Markdown. Empty/whitespace-only
fields are refused. Deterministic sections record them in a new
`decisions/adjudication-<queue-id>.md`, using the inspected draft's title and source
declarations. Provenance identifies the authenticated human/Actor, request,
service time, input commit, and source-draft digest. No semantic reinterpretation
or claim of verification is made: this human-authored decision is stable,
`generated: false`, `verified: false`. Existing accepted concepts, including any
verification evidence, remain byte-identical. This is not a general editor.

The complete proposed Project passes the normal content/path/secret/bounds gate;
both raw authored sections are checked before formatting as well. Publication
atomically adds the decision, updates decision and pending indexes, removes only
the inspected pending item, and records the shared canonical disposition. Only
the pushed commit establishes success. Canonical Git/history contains the body;
operational SQLite records, reports, receipts and safe errors contain only safe
identity/digests, never the conclusion or rationale.

T24's shared active-input busy rule, terminal blocked-batch disposal, untouched
pending retention, publication recovery and exact request deduplication apply.
Reports say `adjudicated`/`retained`, not successful model integration. Old drains
cannot run/recover over the human decision. A later action against a retained item
uses `drain_id: null`; a separately authorized resume remains T26. Current human
and Project authority is rechecked even for historical receipts. Unknown writes
are reconciled against canonical publication, never blindly repeated. An absent
pre-push operation remains unknown and needs fresh inspection/new request.

## Evidence boundary

`test_library_adjudication*` exercises actual disposable Git and SQLite through
service admission, normal policy, confidential recording, authority/version/busy
fences, exact retries, lost receipts and process death around commit/push/record/
report. Native tests additionally use the authenticated private Unix socket and
must run (not skip) in hosted CI. Local socket-denied skips are not native proof.
No actual user content is adjudicated by these fixtures. Intermediary Manager/Hub
privacy (T31), UI panels (T32), actual provider qualification (#171) and canonical
target/backup qualification (#157) remain separate acceptance gates.
