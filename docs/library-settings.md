# Durable installation Library settings

T28 is owned by `SettingsOwner`, a private local SQLite configuration store,
not canonical Git or the operational-record journal. A trusted installer creates
its private directory and calls `initialize` exactly once with admitted shared
`limits` and `filters`. Existing, missing-on-restart, malformed, unsafe or corrupt
state never triggers defaults or automatic replacement. Keep this store across
service restarts; do not delete it to clear request history.

The trusted Supervisor supplies the existing independent authority-settings
reader (repository, model and egress), and wires the owner as the settings callback
for its enqueuer, assembler and dispatcher. Pass `settings_owner=owner` to
`Controls(service, ...)` to expose it on the existing authenticated private Unix
operator transport. No new listener, credential or authentication mechanism is
introduced. Both sides strictly decode the bounded version-1 request. An absent
owner refuses settings requests. The transport's current `LocalHuman` must have
the explicit installation `library-settings` grant; OS ownership or Project grants
are insufficient. This grant never permits Project content operations.

`settings-observe` requires `version:1`, `action` and the configured `deployment`.
Its response explicitly says `impact:all-projects`, and includes shared values,
`configuration_version` and `settings_id`. `settings-update` additionally requires
a unique `request_id`, those observed version/hash fences and the complete
`shared:{limits,filters}` document. No Project overrides, caller paths, actor
identities, repository, model, credentials or egress changes are accepted. All
finite maxima and cross-bounds are checked by the existing core validator;
heuristic blocking additionally requires the shipped corpus qualification gate.

A FULL-synchronous transaction atomically installs the next revision and its
safe audit receipt. Stale, invalid, unchanged and exhausted-version updates do
not change active configuration. Admitted rejections have durable receipts.
Malformed wire, unavailable storage and unauthorized callers fail before durable
admission. Current authorization is checked again before observing, committing or
replaying. A matching request ID/payload/human returns its original receipt, even
after restart; a conflicting payload or identity refuses. Lost commit replies
are **unknown**, not failure: reconcile using exactly the same request. Never
invent a replacement request to retry an uncertain write.

`CONFIGURED` means a durable configuration revision, not a Git commit or model
qualification. Receipts contain actor/human, timestamp, prior/result hashes,
changed key names, revision, validation outcome and reason; never changed values,
Project content or secrets. Active shared values live only in the private
configuration row. Receipt integrity hashes detect damaged stored responses.
This is a bounded store: at most 10,000 retained request identities and a 16 MiB
SQLite database (plus SQLite's bounded transaction journal). At capacity new
requests fail closed; exact receipts remain reconcilable. No automatic eviction
can reopen a request ID. Planned migration/replacement needs explicit installer
handling, not a silent reset.

Every new callback read sees the latest committed revision without service
restart. Returned values are detached. The actual synthesis `Attempts.run` takes
one starting snapshot before its deadline; its assembly, dispatch, limits and
filtering retain that snapshot. Existing fresh repository/model/egress checks
remain independent and can still stop an in-flight attempt. Other multi-stage
trusted consumers can use `with owner.operation():` to pin shared values in their
execution context; separate operations see new values. Even pinned reads refuse
missing/invalid active state, and never pin egress authority.

`tests/test_library_settings.py` covers real SQLite transactions, concurrent CAS,
process-exit/restart reconciliation, rollback/lost ACK, corruption, revocation,
bounds, finite capacity and isolated contexts. Real temporary Git enqueue and
synthesis fixtures prove next-operation adoption and in-flight consistency. The
same operator-only update/restart/replay runs through the actual Unix socket in
CI. Cloud EPERM socket restrictions are explicit skips, never passing evidence;
GitHub Actions must execute the native case. No VM, live provider, user host,
account, network authorization or deployment is changed by these tests.
