# Artifacts-only helper boundary — source profile, not qualification

This slice implements the narrow `artifacts` observation boundary from accepted
issues #25/#26 and #58/#73. Production launch remains disabled. It does **not**
implement `command`, `diff-claims`, Forge Gates, review decisions, candidate/PR
projection, protected-operation advancement or Run completion. Existing native
Pi/Workstation evidence does not qualify this new helper or its mounts/profile.

## Owners and sequence

The Hub is the only Gate/Run authority and uses its existing `RoomLedger`.
A public request contains only operation ID, Run ID/generation and Gate ID.
Authorization and exact retry lookup precede source resolution or effects.
The snapshotted policy supplies ordered paths; no caller selects a host path,
revision, argv, environment, execution identity or evaluator.

1. The Supervisor independently resolves the current committed HEAD of its
   recorded active, ready Run slot. It never invokes `CheckoutAllocator._git`,
   `_locked`, `_registered` or `_observe` for this proof.
2. Hub reserves the Evaluation and bounded capacity. Supervisor capacity
   admission separately proves **currently free Room quota**, accounting for
   other usage and outstanding/quarantined reservations, before preparation.
3. Supervisor copies bounded ordinary object data into a private generated bare
   store, verifies raw used objects and materializes the entire exact tree.
   The Hub binds commit, tree, full-tree SHA-256 manifest and filesystem identity
   to the already-reserved Evaluation before launch.
4. A fixed static bootstrap starts as dedicated UID/GID **65530** (mapped
   **165530**), not Hub65531, Participant65532 or Supervisor65533. It wipes the
   inherited environment and execs the immutable static evaluator with fixed
   argv and an empty environment. Docker `Env: []` alone is not a scrub.
5. `GATE_BIND` transfers only the direct helper channel, held pidfd and exact
   immutable scope/profile over the authenticated Supervisor–Hub connection.
   No Participant seat, Actor badge, `ADMIT` or Engine authority is transferred.
6. Hub receives kernel-authenticated raw facts and checks order, count, digest,
   scope and target. Facts are provisional. Only after a valid final record is
   acknowledged while held alive, actual held-task exit, Supervisor full target
   reproof, owned cleanup and fresh dependencies may the Hub finalize.

Unknown starts, lost control, malformed output, unsupported confinement, failed
postproof, missing exit or failed cleanup produce error/quarantine, never pass.
There is no hidden relaunch or replay. Restart cannot adopt a PID, EOF, persisted
exec ID or resource journal as live authority. Cleanup failure retains capacity;
a later cleanup observation does not rewrite an immutable Evaluation.

## Source and target integrity

`uas/artifact_target.py` accepts only an ordinary primary `.git` directory and
SHA-1 object IDs in this first profile. Linked slots must have exact bounded
`.git`, `commondir`, `gitdir`, HEAD and reciprocal administrative-directory
bindings. Branches use an intentionally conservative ASCII subset: letters, digits,
underscore, hyphen and slash components after `refs/heads/`; even otherwise
ordinary dotted branch names are currently unsupported. Detached
HEAD, external primary gitdir layouts, ambiguous refs, hard-linked source files,
symlink components, missing/promisor/alternate dependencies and unsupported
object layouts are explicit errors. Packed storage supports only ordinary paired
`.pack`/`.idx` files; reverse indexes (`.rev`), bitmaps and other auxiliary pack
files are currently rejected, including those produced by common modern Git
maintenance defaults. This is a compatibility limitation, not an instruction to
change or prune a user repository.

All metadata is read with descriptor-relative no-follow opens and bounded
inert parsing. Source config, config.worktree, hooks, index, attributes as
configuration, replacements, grafts, alternates, credentials and working-tree
content are never copied or executed. Dirty and untracked checkout bytes are
irrelevant to this committed-revision evaluator.

The only Git command is fixed absolute `/usr/bin/git ... cat-file --batch`,
started by fixed `/usr/bin/prlimit` with fixed lower limits (no Python
`preexec_fn`, which can deadlock in a threaded Supervisor),
inside a fresh generated bare store with fixed configuration/environment and
resource/output/deadline bounds. No Git command runs in the source repository;
no checkout, archive, clone, filter, submodule, shell, provider or network route
exists. Git parses packs; this slice adds no pack parser. Every used raw
commit/tree/blob is checked against its exact type, size and object hash.

Materialization rejects symlinks, gitlinks, special files, unsafe names and
unsupported paths. Read-only modes preserve executable-bit identity. A separate
full traversal reconstructs the Git tree and SHA-256 manifest from target bytes;
helper header/final manifest echoes are **correlation only**, not content proof.
Current source ownership and HEAD are rechecked before release and acceptance.

## Helper containment and lifetime

See [`ARTIFACTS-PROFILE.md`](../runtime/workstation/ARTIFACTS-PROFILE.md) for the
fixed binary wire/profile and source proof details. The evaluator requires
unprivileged Landlock ABI>=3, target-only read permissions, rooted `openat2`
with BENEATH/NO_SYMLINKS/NO_MAGICLINKS/NO_XDEV and an architecture-checked
seccomp allowlist. Missing or denied support fails closed. No privileged exec,
capability addition, host setting, custom SELinux allow or unconfined fallback
is available.

Landlock is not represented as blocking all metadata operations or preopened
FDs. Fixed FD inventory, root-relative opens, ordinary-node checks and the
syscall allowlist provide the remaining containment. Network, child creation,
exec, descriptor-passing receive, arbitrary metadata paths, writes, namespace,
mount, privilege, timer and signal-policy changes are denied after setup.

The bootstrap arms `alarm(2)` with default unblocked SIGALRM before rendezvous;
that timer survives exec, unlike POSIX `timer_create` timers. The evaluator
verifies the remaining timer and freezes timer/mask/handler changes. Kernel
scheduling may still delay exit. Holding pidfd grants no signal permission:
unconfirmed exit causes quarantine, not container-wide kill or guessed cleanup.

## Conservative unmeasured resource profile

`artifacts-v1-source` is a **source constant set**, not a measured release default:

| Resource | Initial source bound |
| --- | ---: |
| Compressed copied object bytes | 16 MiB |
| Expanded target bytes | 8 MiB |
| Allocation/metadata reservation | 8 MiB |
| Combined reservation per Evaluation | **32 MiB** |
| Source object files / tree entries | 512 / 512 |
| Individual blob / tree depth | 4 MiB / 32 |
| Requested artifact paths | 1–128 |
| Path Unicode scalars / UTF-8 bytes | 1024 / 4095 |
| Component UTF-8 bytes | 255 |
| Helper request / raw output | 1 MiB / 128 KiB |
| Helper packet | 16 KiB |
| Helper AS / CPU / lifetime / FDs | 128 MiB / 5 s / 15 s / 64 |
| Materializer AS / CPU / total wall | 256 MiB / 10 s / 30 s |

The Room's existing external quotas remain mandatory. Rlimits are not per-helper
cgroups, RSS reservations or a signal authority. Capacity admission cannot be
implemented as merely `32MiB <= configuredDiskLimit`. It must include current
Room usage, simultaneous Evaluations and retained quarantine. The Hub caps
outstanding evaluations independently; the Supervisor must not silently inflate
quota or exempt scratch from the admitted Room disk budget.

The target owner requires an allocation unit no greater than4096, checks free
filesystem space and totals actual target/cache allocated blocks before release,
leaving1MiB of the reservation for control/inode accounting. A trusted quota
admission implementation must validate filesystem-specific metadata accounting;
these checks alone do not establish target-host defaults or universal quota
accounting. Retained resource/launch journals remain charged as existing Room
usage after scratch reservations release; both stores cap lifetime records at16
and fail closed when full. No automatic sweep or reset is provided. Compression bombs, excess history/object files or oversized trees
are refused rather than evaluated partially. This repo's initial inspected
source tree had281 entries,2,889,522 logical bytes/3,575,808 allocated bytes; that is a local
size observation, not proof that every history layout or future tree will fit.

## Provisioning requirements and evidence limits

The launch profile must admit an immutable static pair, a read-only scratch bind
mount at `/uas/gate-targets`, a narrowly labeled private endpoint, exact UID/GID
mapping and outer confinement. Scratch stays outside Participant mounts. The
Supervisor must already possess the fixed helper-group access needed to create
0710 private target parents; no account/group changes are performed by this code.
The endpoint listener must actually be created/listened by the Supervisor UID:
root creation followed by chown does not change `SO_PEERCRED` at connection time.

Local tests are pure/mocked/source/build only. They do not install Landlock,
seccomp, namespaces or listeners and do not run the helper. In the development
executor `/usr/bin/git` is visible as overflow-owned UID65534, so the trusted-root
binary check correctly refused real copied-store execution. Materialization
unit tests use explicitly synthetic verified raw-object readers; this is **not**
a real Git/materializer or native boundary qualification.

Ordinary GitHub CI additionally runs `tests/linux/artifact_smoke.py` on a disposable
Ubuntu runner: the exact generated two-Room raw config is relocated under one
exclusive `/tmp` tree. A root fixture provisions only that tree; numeric nonroot
Supervisor/helper/control processes exercise real root-owned 0711 search-only
ancestry, unreadable-leaf and no-follow refusals, the shared VM listener child and
SCM_RIGHTS/SCM_CREDENTIALS parser, inherited listener descriptors, endpoint identity
replacement fencing, and real Supervisor/allocator/resolver/target/launch-journal
constructors. The fixed trusted Git/prlimit reader materializes actual packed
committed bytes despite dirty files and poisoned source hooks/config, then removes
only its owned target. No Engine or native admission is called. Account creation,
mounts, host policy changes, dependency installation and permissive fallbacks are
absent. A fixed bounded allowlist is staged into the root-owned fixture, without
changing checkout/home permissions. Missing prerequisites fail rather than skip.
On any failure, the private fixture is retained on the disposable runner and
cleanup is not claimed; uncertain/reaped process-group identities are not signaled.
Numeric children have their own bounded expiry (27 seconds maximum for the
Supervisor, 5 for a connector), independent of the parent wait and additionally
capped by the original parent deadline plus at most 3 seconds for cleanup/rounding.

This narrow smoke has a 40-second internal deadline, a 43-second command timeout plus a 2-second hard-kill grace (45 seconds maximum) and
a 1-minute job bound, running alongside the existing 2-minute Docker fixture after
the 1-minute aggregate: the automatic critical-path budget remains 3 minutes, not
another VM build. Its report records per-Room and total elapsed seconds; actual
GitHub job timestamps establish observed CI duration (runner queue time is not
controlled by these execution bounds). Passing it is Linux DAC/FD/config/Git
evidence only—not SELinux/MCS, Landlock, seccomp, XFS quota, mount/namespace,
kernel-bound helper, full-VM or production admission evidence. Development
executors with native restrictions run only its pure source-contract tests.

A separate deliberate disposable-VM artifacts profile must exercise the real
trusted Git reader, poison-source negatives, static binaries, UID/outer profile,
actual target-only filesystem access, syscall/network/FD constraints, exact
channel identity, target mutation/loss/malformed/resource cases, two-Room
noninterference and confirmed cleanup. Only an exact-source successful run can
qualify that profile. Production must remain disabled until independently
reviewed, ordinary-CI-green source and the required manual proof succeed.
