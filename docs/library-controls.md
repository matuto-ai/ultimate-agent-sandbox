# Fenced host-local Library controls

`uas.library_controls.Controls` implements T22 for a started, leased T21
`Service`. The trusted Supervisor can run `serve(private_root, controls,
authenticate=resolver, stopped=stop_callback)` beside the service loop. This is
an integration surface, not an installed daemon, login service or new credential
store. The installation must supply its existing trusted human authentication
and current immutable-Project grant resolver. It must not map every socket owner
to every Project or accept a principal from request JSON.

The private absolute directory and kernel Unix peer-owner check fence the local
transport. `LocalHuman` additionally binds human/Actor identity, authority version,
connection state and a fresh action-specific Project grant. OS ownership alone,
a Participant capability, a Manager badge and the separate installation settings
grant confer no Project authority. `local_settings_scope` checks only the explicit
settings grant; it cannot authorize Project controls. No Room, active Run or Hub
session is needed. The interface uses a separate `library-operator.sock`; an
exclusive private lock prevents competing listeners and permits recovery of the
owned stale socket after process death. No shell, arbitrary path, clone edit,
configuration mutation or Participant route is exposed.

The bounded version-1 request contract has `observe`, `inspect`, `reject`,
`adjudicate`, `drain`, `retry`, `resume` and `defer`; each action's own module
owns its fields and evidence. Defer is the T38 attention snooze, binds no
drain/queue/content identity, and is admitted through the same current Project
grant and settings fence; it is described in
[Library attention](library-attention.md).
An observation names the Project and intended action; it returns current settings
identity, opaque observed version, scheduler state and drain identity. For the
`defer` action it instead returns the current durable attention-cut version. The
scheduling version binds immutable Project identity/current coordinates, full
durable scheduling state, configured settings and canonical Project-content
digest. Admission reads
and validates the current Project (including active state), without invoking a
model or publishing Git. Request JSON may not supply identities, grants or paths.

Drain/retry/resume sends that observed version, settings identity and a unique
request ID. Retry additionally names the observed drain identity; resume names
the disposed drain whose remainder it releases, see
[Library resume](library-resume.md). State/content/configuration
changes require refresh. Reuse of an ID with a different action, human identity,
settings or payload is a conflict. Fresh authority is checked even when replaying
an old receipt; a new authority version for the same currently authorized human
can reconcile that receipt without reapplying its scheduling effect.

The scheduling state and human acknowledgement are committed in **one SQLite
transaction**. ACK means durable fair scheduling eligibility, never a synthesis
commit or successful model call. Lost responses/commit acknowledgements remain
unknown until the same request is reconciled against durable records. Rollback
leaves neither half; process-death recovery cannot repeat a committed transition.
The scheduler selection lock preserves fair order and never interrupts inference.
Ordinary drain does not release BLOCKED. Retry preserves the original full fixed
batch and creates a new attempt when selected. A Project blocked during validation
before a batch exists can retry its selection ticket with explicit `drain_id:null`;
this invents no drain or batch and still requires a currently valid active Project.
Actual execution retains the existing execution-time authority/configuration gates.

`tests/test_library_controls.py` exercises real temporary Git, SQLite and Service
with current-grant and cross-Project refusals, stale content/state/configuration,
archive refusal, exact replay, rollback, lost commit ACK, process death and full
batch retry. The same cases run through the actual Unix socket, with kernel-peer
refusal, disconnected senders, listener ownership and crash recovery. The cloud
sandbox denies Unix socket creation (EPERM), so its native cases are explicitly
skipped, not claimed passing; GitHub Actions must execute them and **fails** rather
than skipping on EPERM. This is deterministic fixture evidence, not live-provider,
production-host authentication integration, account, VM or deployment evidence.

Explicit index-only repair and its conservative uncertainty/recovery contract are documented in [library-repair.md](library-repair.md).

Archive and restore are documented in [library-lifecycle.md](library-lifecycle.md).
