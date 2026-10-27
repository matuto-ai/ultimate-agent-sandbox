# Controlled native Git (#67)

This implements the controlled-command mechanism. **It does not close the live
acceptance proof:** real GitHub SSH fetch/push, host-key and Actor credential
qualification, remote permission changes, and replacement/revocation against
that endpoint remain pending at the user's explicit direction. Account-free
fixtures are not that evidence. The current native Pi image's exact Git backend
and shared-library pairing also remains an explicit image-readiness gate.

## Authority and execution

- Public `git` and installed `git-*`/`scalar` entries are copies of one isolated
  Python RPC launcher. Its payload has only operation ID, invocation, argv and
  cwd; it cannot select Actor, key, executable, result or attribution.
- `git_policy.ROUTES` drives enforcement and help. Unsupported helpers, aliases,
  config operations, `-c`, config-env, alternate exec paths, author overrides,
  `git am`, raw upload/receive-pack, arbitrary SSH, SCP and rsync are unavailable.
  Push force/delete and upstream-config persistence are deliberately unsupported.
  A command runs at an explicitly configured checkout root; use `git -C ROOT`
  from elsewhere. Nested cwd is not silently treated as the root.
- The Supervisor starts from **SCM_PIDFD**, corroborates a fresh bounded live
  parent chain to an already admitted Participant, and checks current Room,
  incarnation and authority epoch. PID/UID equality, inherited sockets and
  caller strings never admit an Actor. Every relationship is observed against
  held pidfds and an authenticated `/proc/self` mapping. Foreign/ancestor proc
  views, namespace changes, dead/reparented links and ambiguity refuse.
- Linux x86-64, pidfs (6.9+), SO_PASSPIDFD and SO_PEERPIDFD are mandatory. There is
  no numeric-PID fallback. Ancestry is at most 32 links and one absolute 50 ms
  admission budget; positive ancestry is not cached across requests.
- The launcher does **not** execute trusted Git. A fixed Supervisor/Engine
  `GitExecLaunch` starts a credential-free worker at UID 65530 / GID 65532 in the
  existing admitted Workstation, with zero effective/bounding capabilities,
  no-new-privileges and seccomp still enabled. No setgid elevation or NNP
  relaxation is used. Existing Project owner/access is checked, never repaired.
- The worker receives only a sealed, digest-pinned Git ELF descriptor, mapped to
  FD 19, and fixed view/command/identity metadata. It opens directories **inside**
  the Workstation; no host directory descriptor exposes host mount ancestry.
  The Supervisor must qualify the backend **with the exact admitted image ABI**;
  a runner-matched fixture does not qualify the production Pi image.
- The fixed worker channel and public reply endpoint pin the actual connected
  peer with SO_PEERPIDFD and authenticate each SCM_PIDFD record. Worker readiness
  uncertainty is fenced. During execution, Supervisor receives and both stream
  pumps recheck authority at intervals no greater than 100 ms. Backpressure never
  holds the lifecycle lock through a blocking send.
- A durable private checkout lease precedes **every** worker launch, including
  reads. Only an authenticated worker quiescence acknowledgement, an exit ACK,
  and exit observed through an independently owned exact pidfd release it.
  Quiescence means native group cleanup, exactly one owned reap and pipe disposal
  completed; closing an ExecLaunch or channel is not exit evidence. Launch,
  cleanup or controller uncertainty fences the checkout across restart. No generic
  stopped-writer recovery or automatic fence clearing is implemented. A new
  explicit request may run only after positive cleanup; original IDs never replay.

## Host-visible Project and immutable worker view

The host checkout stays in its configured location. Human host Git is not routed
through the Participant launcher. The worker uses fixed bind aliases
`/opt/uas/git-views/<slot>/gitdir` and `/common`, below root-owned immutable
ancestors. Worktree, admin and common directories are exact mount roots. This is
bind placement, **not** a private repository copy or synchronization filesystem.
The original Project inode owners and existing shared-group access are retained.

**Admission precondition:** the host-visible worktree's ancestor chain must not
be renamable/replaced by the Participant or worker. The hosting Supervisor must
establish that boundary with its admitted readonly rootfs/disjoint writable mount
placement and withhold mount administration. A leaf mount root alone cannot
prevent renaming a writable ancestor; `RuntimeView` does not independently prove
this full admission invariant. The fixture uses root-owned protected ancestors.

The Supervisor supplies readonly overlays for the complete compiled Git config,
private helper directory and admin `commondir`. Repository includes, filters,
credential helpers, local hooks, worktree config, user/system config, replacement
objects, editors, pagers and ambient Git/SSH environment cannot select code or
credentials. Native Git's private helpers resolve only to the sealed backend.
The only hook is the fixed readonly `reference-transaction` reporter in a
worker-only directory; Project hooks are never executed.

**Why `commondir` needs its own binding:** Git's files-ref backend calls
`get_common_dir_noenv`, independently of `GIT_COMMON_DIR`, and canonicalizes the
pointer. An absence check has a creation race. The worker therefore verifies an
immutable exact pointer to the held common alias, including for primary
checkouts. See [Git files backend](https://github.com/git/git/blob/v2.50.0/refs/files-backend.c#L96-L108)
and [pointer resolution](https://github.com/git/git/blob/v2.43.7/setup.c#L296-L316).

For a primary repository, `GitPrimarySetup.prepare` is an **explicit quiescent
Project-setup** operation, never a launcher-time fix. After authorization,
writer-quiescence and parent-owner/inode checks, it journals intent and creates
an absent `.git/commondir` containing `.` plus newline using O_EXCL. The private
journal binds the exact created inode, owner and digest. This directs ordinary
host Git to the same common directory. The hosted fixture must establish normal
host Git before/after behavior; source reasoning alone is insufficient.

A pre-existing human marker is neither overwritten nor adopted, even if its
bytes are identical. Interrupted setup, replaced metadata or a collision raises
attention. There is no automatic deletion/rollback that could remove human
work. Existing linked-worktree pointers are validated and preserved; only the
worker alias receives the readonly absolute-pointer overlay. Host config,
branches, commits and history are not rewritten by setup.

## SSH-compatible byte Broker

`GitBrokerClient` is the Supervisor's private external channel, not an Actor
credential-bearing agent socket. `ExternalGitBroker` derives Actor and exact
scope from this authenticated Supervisor binding. The fixed shim accepts only
Git's bounded SSH argv, not shell or caller-selected SSH configuration.

- Host/user/port are fixed to `github.com`, `git`, 22.
- `git-upload-pack` follows the selected Actor's native same-Forge permissions;
  no extra repository allowlist is invented.
- `git-receive-pack` is case-normalized and pinned to the Project repository.
- Private Actor key and known-hosts paths stay external. Ownership, regular-file
  identity, no-symlink traversal and the pinned SSH executable are checked before
  launch. No key contents, reusable agent socket or raw SSH diagnostics enter the
  Workstation. OpenSSH is given held **Broker** proc-FD paths because it closes
  its inherited FDs early; actual OpenSSH/host-key interoperability remains pending.

Streams have 32 KiB data frames, 64 MiB byte limits, a 30-second external pump,
32-second Supervisor relay, bounded queues and strict EOF/cancel framing. Git
stdout/stderr exposed to the caller are bounded to 1 MiB total; remote SSH stderr
is drained but never disclosed. Up to 1,024 authenticated advertised OIDs fit in
one bounded control terminal; this evidence limit does not enlarge byte limits.

Git start/terminal records extend the **same Deployment ForgeAudit** (schema v5,
after #69's v4); there is no second Deployment audit owner. A durable start
precedes contact. Exact retry never reexecutes a byte stream, even after success.
Possible push contact followed by failure is `UNKNOWN_OUTCOME`, not no-contact.
A failed terminal commit fences the owner and cannot produce success. Recovery
requires positive old-owner fencing: an exclusive Broker lock alone does not
prove an old SSH child exited. The fixed host entrypoint blocks on pending prior
starts rather than silently recovering/replaying them.

## Attribution, source anchors and contribution history

Trusted Actor config supplies `git_identity: {"name": "...", "email": "..."}`.
Missing identity disables this controlled Git path; no local config fallback is
used. Ordinary commit and amend use canonical Actor author and committer. An
anchored cherry-pick preserves the complete source author/date, sets the current
committer, and requires the exact `-x` source-SHA trailer, including continuation.

The immutable hook reports native reference transactions over a private
per-command nonce/operation channel, authenticated to the owned native process
session. Complete phase/ref/old/new expectations select the created OID. The
worker then reads and hashes that exact raw commit; the external store verifies
identity, expected parent and source attribution. Filenames, terminal output,
post-command mutable HEAD and caller-reported commit bytes never select evidence.
Unexpected multiple/partial/aborted transactions or failed post-effect object
verification retain uncertainty and fence the checkout rather than replay.

Sources must be anchored in a completed authenticated upload-pack advertisement.
Historical source support verifies a raw hash/parent chain from one of the 32
most recently retained advertised tips: at most 64 objects, 512 KiB raw bytes and
five seconds. The Supervisor independently verifies the chain and records its tip
and proof digest. Unrelated, forged, incomplete or over-bound sources refuse.
This is source anchoring, **not** push quarantine or arbitrary object validation.

The Supervisor—not launcher payload—resolves the current canonical Run and
generation. Participant mutations without an admitted Run refuse; reads remain
available. Controlled staging by Actor A followed by Actor B's commit retains A
in the Run's monotonic contribution history. Commit/cherry receipts union those
Actors with exact source taint; conflict edits and replacement/continuation add
contributors rather than laundering them. Abort, context reset and sibling seats
do not clear history. Explicit new Run scope does not automatically inherit an
unrelated prior Run merely because it reuses the checkout. An explicit amend
inherits the replaced controlled HEAD's trusted taints and transitive lineage,
including across Run transitions; canonicalizing the new author is not a way to
erase earlier controlled contributors. Unregistered objects remain mutable data,
not invented contribution evidence.

**Trust limit:** Project files and `.git` remain mutable shared data. Copied Git,
raw file edits and arbitrary objects do not automatically acquire verified
contribution receipts. These Git-specific records do not claim to observe all
artifact edits or implement the Hub's complete independent-review eligibility
policy. Public author names/emails never identify an Actor.

## Integration and evidence

`GitSupervisor` is the concrete callable assembly. The hosting Supervisor supplies
already-admitted `GitSeat`/fixed worker `ExecSeat` bindings, existing protected
request/worker listeners and endpoint leases, private launch journal, exact
checkout views, pinned backend, lifecycle lock and current Run resolver. The
assembly constructs `GitChildAuthority`, `GitCoordinator` and the one-shot
`GitExecLaunch` factory; `serve_next(timeout=...)` bounds acceptance and dispatches
the actual public request. Version 1 explicitly supports identity-mapped worker
UID/GID (65530/65532); other user-namespace translations require separate admitted
mapping support, never a numeric fallback. It creates no mounts or listeners.
The external
host entrypoint is `python -m uas.git_service FD` with trusted startup metadata.
Neither endpoint accepts a public executable/credential/identity selector.
The missing persistent authenticated Room start flow (#61) is not fabricated by
this module.

The existing offline native payload builder optionally stages the fixed Git
assets when explicitly included with their complete checked Python import
closure in its source allowlist. It installs ordinary
controlled launcher copies at `/usr/bin` and both conventional git-core paths;
existing collisions fail rather than overwrite. Old profiles and RPM roots stay
unchanged. In particular, the existing Pi manual profile does not list these
assets and is **not** silently upgraded to an installed Git service. The new
composed fixture profile supplies the required paths and runtime projection.
This stages the controlled surface, not a newly qualified native Git
backend/image dependency closure.

| Check | Evidence class |
| --- | --- |
| `test_git_*.py` | Pure/SQLite/mocked contracts; no native proof |
| `tests/linux/git_process_smoke.py` | Actual child ancestry, same-UID sibling denial, revocation, parent exit/reparent; no GitHub |
| `tests/linux/git_smoke.py` | Actual native Git/worker view/reference transactions, primary+linked and host marker compatibility; no full Supervisor or provider qualification |
| `tests/linux/git_composition_smoke.py` | Actual public launcher → `GitSupervisor` → Coordinator → fixed connector/configure/native worker → provenance → response; authenticated quiescence + exact pidfd exit, next command and uncertain-start replacement fence. Engine adapter is an explicitly owned-process fixture, not Docker admission. |
| `tests/linux/git_stream_smoke.py` | Actual native fetch/push through fixed shim and byte Broker, account-free allowlisted local transport, audit and Project denial; **not OpenSSH or GitHub permission proof** |

Hosted scripts require a disposable GitHub Linux runner, bounded private fixture
state and explicit source review. They are never run merely by importing or by
the pure suite. The four short seams run in parallel within the existing
2–3-minute CI envelope; no full VM/image rebuild is added per fix. Actual pass,
failed and unrun stages belong to the exact candidate CI record, not this table.

The connected fixture exercises `/opt/uas/bin/git-add`, `git-commit` and
`git-status`. The runner's native `/usr/bin/git` supplies its matching sealed
backend; **installed-all-public-paths/image readiness is NOT_TESTED** there.
The offline installer covers all declared public paths only in an explicitly
selected image profile. The connected fixture does not claim active-native
cancellation integration (pure cleanup/fence tests cover that contract), Engine
admission, Room lifecycle, OpenSSH or live GitHub qualification.
