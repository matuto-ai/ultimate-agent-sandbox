# Bounded command Gate source profile

`command-v1-source` is separate from `artifacts-v1-source`. Its source and mocked
tests are not native qualification, and adding the binaries to an image does
not admit that image or enable a Participant execution tool. Fresh real hosted
runtime evidence and independent review remain required before the issue's
command acceptance can be claimed.

## Definition and observations

The snapshotted policy owns exact `argv`, target-relative `cwd`,
`timeout_seconds` (1–10), `process_limit` (1–32), per-process `memory_bytes`
(64–128 MiB), and per-stream `output_bytes` (1 KiB–1 MiB). `argv[0]` is a
provisioned non-shell `/usr/bin` ELF whose `executable_sha256` is required.
Up to eight `executables` entries explicitly pin additional child executable
paths and SHA-256 digests. Unknown configuration is rejected rather than
ignored. The bounded configurable environment allows fixed locale/time/Python
bytecode values only; no inherited environment, credentials, PATH lookup,
LD variables, shell composition or command selected by Participant prose exists.

The helper returns raw stream counts, complete captured-stream SHA-256 hashes,
final 16 KiB tails as bytes, truncation flags, exit code or signal, timeout and
output-limit facts, duration, exact executable digest, whole-tree exit and work
cleanup facts. Hub checks correlation, strict shape/order/cardinality, target
identity and freshness, then derives Checks and the verdict. The helper cannot
send a verdict. Exceeding capture bounds, malformed evidence or unavailable
complete stream evidence is an error, never an implicit pass. Output tails are
untrusted bytes and must be escaped before display.

## Child-tree ownership and limits

The observer is the exact held process authenticated by the existing private
Gate channel. It spawns one fixed guard, keeps that guard unreaped using
`waitid(..., WNOWAIT)`, and is itself a child subreaper. The guard is a process
group leader and supervises the command and its descendants. Child seccomp
forbids new sessions/groups, parent reassignment, namespaces, signaling other
processes, ptrace, process-memory operations, UID/capability changes, and raising
limits. `clone3` returns ENOSYS so supported runtimes can use the explicitly
bounded legacy clone flags; unknown clone flags are denied.

The guard has an independent alarm and a parent-death signal handler that kills
its own fixed group. Observer timeout, output failure or guard loss signals that
same pinned group exactly once **before** reaping. Every successful terminal
path establishes `waitpid(-1) == ECHILD`; root-command exit or pipe EOF is never
whole-tree proof. Guard and observer are trusted fixed code, not project code.
The command receives no Gate, guard-metadata or liveness channel.

Hard NPROC counts processes/threads sharing the dedicated real UID, including
the observer and guard. A configured limit of 8 therefore permits at most six
command-tree tasks when no other Evaluation is active; concurrent Evaluations
may encounter a stricter effective limit. Address-space
limits are per process, with a conservative tree bound from process count, not
a claim of per-Evaluation cgroup/RSS accounting. The admitted outer Room limits
remain mandatory. A loss without credible completion remains error/quarantine;
no process is adopted after restart from a numeric PID, and no whole-Room kill
is inferred to be authorized recovery.

## Exact source, runtime dependencies and writable work

The source tree remains the existing disposable exact-commit target; this
separate command profile additionally requires its mount to be read-only and
noexec. Exact source device/inode are checked before launch and after tree exit.
Runtime image and mount inventory must be freshly admitted: readonly runtime
roots and no writable nested mounts are required. The helper independently
checks immutable runtime ownership/mount facts, hashes every declared executable,
and grants execute access only to those inodes and the fixed ELF loader. Runtime
library directories are readable, not recursively executable. This is an execve
policy, not a claim that interpreted project code cannot compute arbitrary
results; inherited syscall and filesystem limits provide confinement. No network syscall
is permitted by either native filter.

The command profile additionally requires a separately admitted hard 8 MiB
nosuid/nodev/noexec tmpfs work root mounted at `/uas/gate-work`. Each Evaluation
gets an exclusive Supervisor-owned `<target_id>` work directory. Exact work
device/inode/limit are part of the target and correlation. The shared hard mount
bound conservatively caps every Evaluation; concurrent resource competition can
fail a command but cannot enlarge its bound. The Room ledger reserves 40 MiB
(existing 32 MiB source lease plus 8 MiB work) before effects.

The child has a **data-only** scratch FD4 and fixed `TMPDIR`/`HOME` values pointing
to that descriptor. This is not the private Gate capability. Landlock permits
filesystem data mutations only below scratch; path-based chmod and timestamp
operations are separately denied because Landlock does not mediate them. Measured
source and runtime dependencies remain read-only. Commands must put generated files in scratch; tests/builds
which insist on modifying their source tree, executing generated scratch files,
using undeclared executables, network access, or unsupported process operations
fail rather than silently broadening the profile.

After confirmed whole-tree exit, trusted native code performs bounded
descriptor-relative work cleanup without following symlinks. Supervisor then
independently checks the exact work identity is empty, removes it and removes the
owned source lease. Uncertain creation, changed identity, unknown descendant
state, mutation or cleanup failure quarantines resources and retains capacity.
Later verified cleanup changes operational state only, not immutable verdicts.

## Current evidence boundary

`test_gate_command.py`, `test_command_target.py` and explicit source checks cover
strict policy/wire contracts, malformed evidence, partial preparation, exact
cleanup, refusal before work effects and loss quarantine using synthetic
observations. `CommandNativeBuildTests` compiles and inspects static payloads on
hosted CI without executing them. Neither category proves native confinement,
command behavior, ordinary test/build support, kernel process identity, target
or work mounts, command/guard loss containment or real cleanup. Those require
the separate admitted hosted fixture; no local native opt-in is enabled here.

`tests/linux/command_smoke.py --run` is a separately reviewed hosted-only source
fixture, not automatic profile admission. It stages a bounded exact read-only
source closure before UID drops and uses private mount/PID namespaces. It
provisions an exact Python 3.12 ELF, its observed loader/library dependencies and
a small bounded standard-library subset, then runs a committed revision test
with a separately pinned child and writable scratch. Further cases exercise
limits, cross-work metadata denials, source-root mismatch and independently
pinned observer/guard loss. Its reported source/binary/image hashes identify the
actual candidate; a run is evidence only after every case and cleanup succeed.
It does not substitute for Workstation image, Docker, stock MAC, quota, live Forge
or full product admission.
