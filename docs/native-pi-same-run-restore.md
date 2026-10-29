# Retained-owner Pi crash restoration (#78)

This is source integration, not executed native lifecycle evidence. The bounded
one-Run qualification driver now composes `NativePiSameRunRestore` after initial
Pi admission, Claude recruitment and optional Git/Gate composition. It handles
one Pi task crash while the same host, Hub, Claude, Room and owners remain alive.
It cannot recover a restarted host, adopt persisted PIDs, replace Claude, or
reset a context. The optional second-Run scenario does not enable this path.

## Consumed path

At the driver's loop preflight, a nonblocking observation of the original held
pidfd must establish exact task exit: `POLLIN` for exited or `POLLIN|POLLHUP`
for reaped, with unchanged held identity before and after observation. This is
the [Linux pidfd poll contract](https://github.com/torvalds/linux/blob/v6.12/fs/pidfs.c#L95-L115),
not socket hangup authority. Invalid/error, bare hangup or changed identity is
unknown, not exit. Live Pi, model failure or lost transport alone cannot trigger
a replacement. Exceptions raised by delivery, Forge, Git, Gates or human actions
exit with their original owner state: no effect catch retries through restoration.

The current authenticated HumanSession, unchanged active Run/Actor/context and
owned checkout are checked under the lifecycle fence. The original Pi native
session facts and existing handoff SQLite binding must match. Then canonical Hub
revocation must return an authenticated absent/revoked result before any new
launch. Only the exited task's exact retained transport/receiver is closed.
Nothing releases, reallocates, deletes or claims quiescence of the checkout or
arbitrary descendants. Revoke/launch/ADMIT uncertainty fences the one attempt.

The immutable native recipe supplies the exact existing session file and ID.
The pinned Pi 1.4.0 SDK public `SessionManager.open(file, sessions, cwd)` is used,
not private SDK fields or session discovery. Because that SDK can initialize
missing/empty files, the entry rejects them before opening; it verifies canonical
owned paths, a nonempty current-v3 matching header, complete newline and stable
file identity, then validates the public session getters. There is no fallback
to `SessionManager.create` on resume. Existing settings/plugins/context files
remain disabled. Native state is not an authority store, and same-UID concurrent
state corruption is not newly claimed to be prevented.

The new native task gets a fresh held identity/incarnation and incremented epoch.
It opens the original handoff journal with SQLite `mode=rw`, never creates a
missing journal, and establishes the same session plus fresh native runtime.
After ADMIT, a fresh correlated SAFE sample is consumed once under the lifecycle
fence before publishing the new typed references. The existing canonical Hub
delivery/receipt and Runtime logical-digest reconciliation provide redelivery;
unknown handoffs are not blindly reinjected. Work Request and context generation
remain unchanged.

Reconciliation of an already persisted handoff is not a second model-turn
trigger. This source does not promise automatic continuation of inference
interrupted mid-turn. A qualifying safe-point crash can occur after the session
exists but before the next Work Request is injected; that pending new logical
request may then be injected once after restoration. Missing original native
receipts remain unknown instead of adding a prompt retry to force progress.

Review/Gate/Git services are retained, not reconstructed. Only exact Pi ingress,
process and Git-seat references change. Git corroborates the new held process's
original namespace before publication; listeners, coordinator, provenance,
unknown operation registries, Gate offers/launches and review receipts retain
their owners. Old Git lineage bindings keep their revoked old process.

## Evidence and limits

`python3 tests/run_native_pi_restore_source.py` selects only two named source-test
classes, installs process/socket/thread/permission guards before repository
imports, and fails on every prohibited attempt—even if code catches it. These
are controlled source/file/SQLite checks, not native recovery proof.

Hosted-only tests additionally exercise the entry body with controlled SDK
boundaries and public locked SDK session-open behavior; their presence is not a
passing result. Actual image build, native process crash/SAFE redelivery, full
Pi–Claude–GitHub lifecycle and authenticated human merge remain unexecuted here.
The original #78 acceptance is unchanged and remains open. No prior lost-source
review or test result applies to this reconstructed candidate.
