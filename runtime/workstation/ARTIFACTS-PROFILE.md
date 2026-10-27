# Artifacts v1 native source profile — not qualification

These are the only fixed helper programs. Build both with `gcc -std=c11 -Wall
-Wextra -Werror -O2 -fstack-protector-strong -static -Wl,-z,noexecstack
-Wl,-z,relro -Wl,-z,now`. The immutable admitted image installs them as
`/opt/uas/bin/artifact-bootstrap` and `/opt/uas/bin/artifact-evaluator`, executable
but not writable by helper, Participant, Hub or Supervisor. The admitted image
and both exact binary hashes must be verified. A dynamic bootstrap is forbidden:
`Docker Env: []` retains inherited container environment, and clearing it in
`main` cannot undo an earlier dynamic-loader injection. Source/build checks
verify ELF64 x86-64, no interpreter, no dynamic section, and no writable
executable segment. They do not execute either program.

## Fixed image/mount/identity inputs

- Helper UID/GID `65530:65530`, host-mapped `165530:165530`, no capabilities or
  supplementary groups other than `65530`. Hub `65531`, Participant `65532` and
  Supervisor `65533` remain distinct. Mapping and overflow identities require
  actual native admission proof; these integers do not supply that proof.
- Fixed argv is exactly `["/opt/uas/bin/artifact-bootstrap"]`; cwd `/`; no
  caller-selected command, args or environment. The static bootstrap clears
  its environment and execs only the fixed static evaluator with an empty one.
- A separately provisioned Supervisor-owned scratch root is mounted read-only
  as `/uas/gate-targets`. It exposes neither Supervisor journal nor Hub ledger.
  Only a 32-lowercase-hex target ID is accepted; actual root is
  `/uas/gate-targets/<id>/tree`. The target-ID parent is owner `65533`, group
  `65530`, mode `0710`; the tree is owner `65533`, mode `0555`. Tree regular
  files are readonly, single-link, `0444`/`0555`, preserving executable identity.
  The target-ID parent protects otherwise world-readable tree data from
  Participant traversal. The private generated object cache is not traversable
  by the helper and is never its target. All mounts and mappings need proof.
- The static endpoint `/uas/gate/gate.sock` has parent owner `65533`, group
  `65530`, mode `0710`; socket owner `65533`, group `65530`, mode `0620`.
  Bootstrap checks path identities before/after connection and `SO_PEERCRED`
  UID/GID `65533:65533`. The listener must actually be created/listened as that
  Supervisor identity. Creating it as root and merely chowning/passing the FD
  does **not** update its connection credentials and fails closed.
- A nonroot Supervisor cannot arbitrarily chgrp files to the helper group.
  Fresh native Room provisioning must prove narrowly granted setup membership
  or preprovisioning for this fixed group. No host account, privilege, SELinux
  rule or permissive fallback is introduced by these files. If that provisioning
  is absent, this source profile is unavailable rather than silently weakened.

## Bootstrap and lifetime

The trusted Engine stdin carries exactly a 32-byte random one-use challenge.
Bootstrap opens its fixed Unix seqpacket endpoint and sends `AGH1 || challenge`.
Supervisor authenticates the exact kernel task and fixed launch before sending
`AGR1 || target_id_ascii32`. This contains no filesystem path and no FDs.
Bootstrap opens the target itself through the **readonly Workstation mount**;
passing a writable-host-view FD would bypass that mount guarantee and is not
supported. `openat2` prevents symlink/magic-link traversal, escape and crossing
mounts below the fixed scratch root. `fstatvfs(ST_RDONLY)` is mandatory.

FD3 is the private channel, FD4 the held target directory, and FDs0..2 are
readonly `/dev/null`. Every other inherited descriptor is closed. The final
filter denies all stdio reads/writes. The harmless stdio placeholders ensure
future target descriptors are 5..63 rather than reusing stdin.

Before rendezvous bootstrap sets default SIGALRM disposition, unblocks signals,
and calls `alarm(15)` once. Linux `alarm(2)` survives `execve`; POSIX
`timer_create` timers do not. Evaluator verifies a nonzero remaining interval,
default disposition and unblocked signal, then freezes timer/handler/mask
changes out of its syscall policy. It never rearms or cancels the timer. The
hard/soft limits are lowered to at most 128 MiB address space, 5 CPU seconds,
64 FDs, 1 process, 8 MiB stack, and zero core/file-output sizes. Rlimits are
not per-helper cgroup/RSS/bandwidth guarantees. Signal delivery depends on
kernel scheduling; neither elapsed wall time nor EOF confirms exit. A held
pidfd does not give signal permission. The Supervisor must confirm actual exit
or retain/quarantine resources, never claim cleanup or kill a guessed task.

## Evaluator confinement and observations

Before reading request bytes, mandatory Landlock ABI >=3 denies execute/write,
create/remove/rename/refer/truncate rights and allows target READ_FILE/READ_DIR
only. Required `openat2` features are probed; unsupported or denied setup exits
125. There is no best-effort path, added capability or host-policy repair.
Landlock does not constrain every metadata operation or already opened FD.
Fixed descriptor inventory and fixed `openat2` roots/resolve flags supply the
remaining metadata-path containment; no path-based metadata syscall is allowed.
`O_PATH` inspection avoids opening special files. Only separately identity-
matched `O_DIRECTORY` descriptors may be enumerated. No artifact file bytes are
read or emitted; file facts come from ordinary, bounded, single-link metadata.

The final arch-checked seccomp policy allows only: read/write on FD3; openat2
rooted at FD4; fstat on 4..63; getdents64/close on 5..63; and exit/exit_group.
Everything else kills the helper, including network, recvmsg/FD reception,
process creation, exec, signals/timers/rlimits, ptrace, io_uring, mmap, ioctl,
namespace/mount and filesystem mutation syscalls. x32/i386 ABIs are denied.
There is no project code execution or verdict/check generation.

### Wire v1 (unsigned big endian integers, no C struct serialization)

| Packet | Bytes | Fields after magic |
| --- | ---: | --- |
| `AGH1` | 36 | challenge32 |
| `AGR1` | 36 | target ID: 32 ASCII lowerhex |
| `AGQ1` | 104 | scope digest32, target ID16 raw, manifest digest32, device u64, inode u64, count u32 |
| `AGP1` | 12 + path length | index u32, path length u32, canonical UTF-8 path |
| `AGS1` | 104 | same request binding, observed actual root device/inode checked |
| `AGI1` | 60 | index u32, SHA-256(path bytes)32, type u32, length u64, nonempty u32, errno u32 |
| `AGF1` | 104 | same binding after actual root identity/metadata recheck |
| `AGA1` | 36 | exact scope digest32; final acknowledgment |

Types are file=1, directory=2, missing=3, error=4. Missing is only ENOENT or
ENOTDIR from initial beneath traversal. Other traversal failures emit explicit
error then exit 125; malformed setup/request/metadata also exits 125 and cannot
supply a credible final observation. Directory records use length=0 and
nonempty=0/1; regular file records use nonempty=0. No record repeats path names,
contents, expected item type, `ok`, Check, verdict or advancement claim.

The fixed scope digest must bind profile, Evaluation/Run/generation, policy,
Gate/config, repository/head/tree, source ownership and exact target. Target ID
and manifest echo are **correlation only**, not independent content evidence.
Supervisor independently reconstructs the target tree/manifest before release
and after confirmed exit; Hub alone judges checks after fresh dependencies and
successful owned cleanup. Root metadata equality alone never proves content.

Paths: 1..128 ordered unique items, canonical shortest UTF-8, at most1024 scalar
characters,4095 bytes,255 bytes/component and32 components; reject C0/C1
controls, backslash, globs, empty/dot/dotdot and case-insensitive `.git`
components. Bound requests to1 MiB, records16 KiB and raw output128 KiB; this
profile's actual maximum output is104+128*60+104=7888 bytes. Individual blobs
are at most4 MiB and expanded targets8 MiB, with at most512 entries. The parent
profile reserves32 MiB total (16 object cache +8 target +8 metadata), **inside**
the already admitted Room disk budget. These are conservative source limits,
not measured release defaults.

The helper waits for the exact final acknowledgment while alive, then exits.
Only Hub's held-task/per-record authenticated channel can consume evidence;
stdout, numeric PID, claimed identity, socket EOF or a copied observation
cannot qualify it. Loss/restart/uncertain start is not replayable; no hidden
relaunch exists.

## Still required

A fresh explicit disposable-VM proof must demonstrate actual dedicated/mapped
UID, immutable static payload, outer confinement and readonly target mount,
Landlock/seccomp, fd inventory and per-record identity, target-only access,
network/process denial, mutation/loss/extra-output/resource exhaustion,
final-ACK/actual-exit semantics, source/target reproof, owned cleanup/quarantine,
and two-Room noninterference. Existing Pi PR108 qualification proves none of
these new helper controls. Production remains disabled.

Primary semantics: [alarm(2)](https://man7.org/linux/man-pages/man2/alarm.2.html),
[Landlock](https://www.kernel.org/doc/html/v6.6/userspace-api/landlock.html),
[seccomp](https://www.kernel.org/doc/html/v6.10/userspace-api/seccomp_filter.html),
[openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html).

## Explicit manual source qualification (not yet run)

`.github/workflows/artifacts-native.yml` is a separate explicit-only, globally
serialized 45-minute job. It accepts manual dispatch, or a `pull_request:labeled`
event adding `qualify-native-artifacts` by `puglab-reviewer` on a same-repository
head. Source review and ordinary CI must pass first. It checks out and verifies
the exact event head SHA, never a moving branch; no opened, synchronize, push or
cron event launches this heavy job. A changed head requires fresh review/CI and
another deliberate label event; an existing label does not auto-qualify it.
It builds the exact allowlisted source, stages signed offline
packages, and boots the existing no-NIC disposable VM machinery. It does not
reuse the Pi qualification or enable production. `util-linux` supplies the
trusted host `/usr/bin/prlimit`; `git-core` supplies `/usr/bin/git`, both hashed
in the report. Package signatures and payload manifests are checked before use.

The fixture creates two independently labeled Rooms, each with an enforced
256 MiB/8192-inode XFS project quota. Private target, launch and probe journals
are distinct children of the Room quota, never mounted into the Workstation.
Admission conservatively charges allocated blocks, bounded inode counts,
retained quarantine reservations and outside-quota lifecycle/rendezvous
metadata. Each 32 MiB reservation includes the object cache, expanded tree and
metadata; 1536 reserved inodes cover this source profile's 512 object files,
512 tree entries and ancillary directories. A separate fixed nonroot quota
probe must actually receive EDQUOT for an excess allocation. No quota inflation
or literal-true capacity callback qualifies the profile.

The fixture seeds a real persisted Supervisor checkout and a trusted Hub Run
record, then exercises concrete `ArtifactSourceResolver`, `ArtifactTargets`,
`GateHelperLaunch`, `GateSupervisorService`, `GateControlClient` and
`ArtifactGateHub`. This is **not** qualification of Run/Participant admission.
The source repo is Supervisor-controlled; packed objects, poisoned config,
hooks/filters, alternates and dirty worktree are deliberate fixed source attacks,
not a claim that the Participant can write this fixture repo. Actual trusted Git
executes only against the generated copied-object store after poisoning. The
benign fixture packing command explicitly disables reverse indexes/bitmaps and
asserts paired `.pack`/`.idx` only; the strict materializer still rejects all
auxiliary pack files. Ordinary repositories containing `.rev`, bitmap or other
pack accelerators are therefore **unsupported by this initial source profile**,
even if Git itself regards them as healthy; no production repository settings
are changed or auxiliaries silently discarded. [Git configuration](https://git-scm.com/docs/git-config#Documentation/git-config.txt-packwriteReverseIndex) documents why the modern reverse-index default must not be inherited here.

The disposable Supervisor process alone receives the fixed helper supplementary
group. Only its own Room's already selected stock `container_file_t` MCS label
is used while creating targets; the thread-local fscreate context is reset on
all exits. Listeners are created by an exact fixture child that drops to mapped
Supervisor UID before listen, not inferred from chown. This creates neither
accounts nor custom SELinux policy. A denied stock operation blocks the proof;
there is no privilege expansion, permissive fallback or generic per-session
label command. Core target materialization does not acquire this fixture setup
authority. Production admission must independently prove labels and mappings.

Two extra statically linked files, `artifact-test-bootstrap` and
`artifact-confinement-probe`, are explicitly TEST payloads with distinct hashes.
They reuse the evaluator's actual setup/filter, not production command options.
Their independently reserved, journaled target is outside Hub RPC deadlines.
Every test task must have an authenticated held kernel origin and confirmed exit
before that target is removed; unknown create/start/loss retains quarantine.
Fixed probes distinguish seccomp network denial from the outer no-NIC namespace
by first proving an ordinary Workstation AF_INET socket succeeds. A deliberate
resolution bypass in the test-only Landlock probe must fail on an otherwise
readable immutable image file. Other probes cover FD misuse, child/exec/timer/
memory-allocation syscalls, traversal, writes, CPU and wall limits, excessive
records and a same-UID child sending through an inherited channel. Rlimits and
mmap denial do not claim a per-helper cgroup or measured production defaults.

Gate scenarios use real channels and the production evaluator: present, missing,
alternates, target mutation, loss, malformed request, withheld request until the
self-alarm, and failed ownership cleanup. Hub alone evaluates and exact retry
returns the existing immutable result. Mutation/cleanup failures must remain
errors with quarantine; final whole-VM teardown never rewrites those results.
Room B must retain its exact container and complete fresh helper evaluations
after Room A stops. The final report is accepted only when every required check
and owned VM teardown actually succeeds; absent checks remain not-run.

Primary setup semantics: [setfscreatecon(3)](https://man7.org/linux/man-pages/man3/setfscreatecon.3.html),
[setsockcreatecon(3)](https://man7.org/linux/man-pages/man3/setsockcreatecon.3.html),
[Unix peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html),
[Fedora util-linux package files](https://packages.fedoraproject.org/pkgs/util-linux/util-linux/fedora-44.html).
