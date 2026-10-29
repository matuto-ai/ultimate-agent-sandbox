# Original Broker audit fence for native human actions

This opt-in source adapter resolves the private-audit ownership seam; it is not
an authenticated hosting entry or native/account qualification result. The
trusted native host cannot open the external Broker's private audit database.
It must not create an empty substitute audit or relax directory permissions.

`NativeBrokerAudit` is bound to the original held `ReadBrokerClient` and one
actual `HumanSession`. It supports only existing `request-changes` and
`reconcile-changes` owner envelopes. It requires current observation and exact
action authority; it grants neither. The private kernel-authenticated Supervisor
channel binds Deployment, Room, instance, repository, original operation/action,
request digest and human Origin. Participants cannot select this control route.

The Broker computes only the existing bounded audit version and
blocked/partial/reason fields from its canonical audit, including ordinary
Participant mutations and their unknown outcomes. No rows, bodies, credentials
or provider calls are exposed. It retains the original `BEGIN IMMEDIATE` writer
fence until the exact original Supervisor releases it. The host prepares this
fence **before** lifecycle, Git provenance and Room locks; cached typed state is
checked during the short canonical consumption; release occurs after those locks
exit. Each consuming authorization rechecks the original held Broker identity
before/after current liveness, including when the audit version is cached.
Revoked, dead, changed or unavailable Broker identity denies consumption; this
does not use conservative liveness denial as a server-side release proof.
Provider reads/writes and reconciliation happen outside the audit fence.
The local `ForgeAudit` path is unchanged.

Lost acquisition/release poisons the original client, with no replacement nonce
retry. Timeout, EOF, invalid descriptor state or malformed release cannot retire
the Broker guard while its Supervisor may still commit. After protocol loss the
Broker remains deny-only until the unchanged retained holder pidfd proves exit
(`POLLIN`, or `POLLIN|POLLHUP` after reaping). No numeric PID adoption or automatic
reconnect exists. The outer native qualification owner retains its original
whole-session deadline and exact cleanup responsibility; this source does not
claim indefinite host-restart recovery.

The finite guarded runner is `python3 tests/run_native_broker_audit_source.py`.
It selects named source/SQLite and AST-closure classes only, with process,
socket, thread, ctypes and permission effect guards installed before repository
imports. Tests separately exercise controlled wire retirement, real SQLite
writer exclusion, original ordinary-mutation uncertainty and the actual native
driver/Manager/RunReview owner path. Controlled IPC is not kernel process proof.

The existing hosted-only external mutation fixture also includes the real
distinct-UID private audit route and preserved unknown state. That authored
fixture is not a local passing result. Human mTLS grants, full retained hosting,
actual selected Project/policy, provider credentials and original #78 execution
remain separate prerequisites; no operator permission was changed here.
