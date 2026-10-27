# Exact base/head diff Gate

`diff-claims` is a fixed one-shot Gate profile, not a generic repository executor.
It uses the existing authenticated Supervisor–Hub control path and the same
immutable Evaluation lifecycle as artifacts. The Hub alone creates Checks and
derives the verdict. Native source/build checks are not installed-boundary
qualification; hosted positive, negative, failure and recovery evidence must be
reported separately.

## Authoritative subject and declarations

The trusted target owner first calls `GateHub.bind_target`. A successful,
audited Broker observation binds repository, PR number/identity, base ref,
exact base SHA and exact head SHA to the Run generation and policy. A Participant
cannot supply that subject through `evaluate` or a diff declaration.

The implementing Actor uses `declare_diff` with a bounded list of literal
Project-relative file paths. The Hub authenticates the identity and capability,
snapshots the exact subject, and binds the declaration into the Evaluation's
configuration digest. A changed declaration, policy, generation or subject
invalidates the old scope. Claims and path constraints never influence which
files the native helper actually compares.

`DiffSourceResolver` receives the subject only from authenticated Hub control.
It independently resolves owned checkout identity and requires the owned HEAD
to equal the bound subject head. The checkout HEAD is **not** a substitute for
the authoritative base. A missing exact base object fails materialization;
there is no fetch, merge-base guess, mutable checkout inspection or fallback.
`current` reports a later owned HEAD without rewriting the historical subject.
The Hub also refreshes the authoritative Broker subject after helper waits and
before protected-operation acceptance.

## Two immutable target leases

`DiffTargets` admits 64 MiB before effects: two independent 32-MiB artifact-tree
reservations. Each side has its own exclusive target ID, ownership journal,
copied ordinary object store, exact commit/tree measurement, filesystem inode
identity, full manifest, and verified cleanup. The base side retains the real
owned source HEAD in its source evidence while materializing the separate exact
base commit; it never forges an artifact source to impersonate a base checkout.

Both slots count against the 16-record lifetime journal bound, including partial
or failed preparation. A fresh pair therefore needs two free records. A failure
preparing the second side retains the first side's ownership. Reconciliation
may remove only known, never-launched resources, or resources whose exact held
helper has verifiably exited. Restart never reconstructs launch authority from
journal JSON or adopts a PID. Cleanup attempts both sides even when one fails;
uncertain cleanup retains the pair's accounting and quarantine evidence.

## Fixed native evidence

The separately installed static `diff-bootstrap` accepts one process-bound
challenge and the two Supervisor-owned target IDs. It clears inherited
environment, verifies dedicated identity, applies the fixed fatal wall timer
and resource limits, opens both read-only target roots, and releases only the
private channel (FD3), base (FD4), and head (FD5) to `diff-evaluator`.

The evaluator installs mandatory Landlock and a default-kill seccomp allowlist
before parsing any request or target data. It has no process, exec, network,
descriptor-receipt, mutation, credential, timer-reset or namespace authority.
The only path opens are contained, no-symlink, no-magic-link, same-filesystem
`openat2` operations beneath FD4 or FD5. Both roots must be read-only,
Supervisor-owned directories. Every file/directory is identity checked before
and after access; unsupported nodes, aliases, malformed paths and incomplete
reads terminate without final evidence.

The evaluator walks both complete trees and compares regular-file presence,
executable mode, byte length and SHA-256. Additions/deletions and renamed paths
are represented as an exact set of changed file names; rename inference is not
used. Per-side bounds remain 512 entries, depth 32, 4 MiB per file and 8 MiB
expanded contents. At most 128 changed paths and 128 KiB total wire output are
accepted. Exceeding a bound is an error, never a truncated successful diff.

The wire contains a correlated header, indexed canonical UTF-8 byte-sorted
paths, and a correlated final count. It contains no `ok`, Check or verdict.
After the Hub validates completeness, ordering and correlation it sends the
single final ACK. Actual helper exit, independent full post-measurement of both
targets, source-binding checks and cleanup must complete before evidence can
qualify. No implicit retry follows helper loss or uncertain execution.

## Hub adjudication and evidence limits

The Hub requires exact equality between the complete actual file set and the
bound declaration, applies literal allowed/forbidden path sets, and enforces the
configured nonempty rule. It keeps a Check for set equality, for the nonempty
rule when configured, and for each actual path's constraint result. These are
mechanical support for a declaration, not an assertion of semantic correctness.
Malformed/incomplete facts, target mismatch or mutation, missing final ACK/exit,
Broker unavailability, and cleanup uncertainty cannot pass. Newer in-flight,
failed or errored attempts do not fall back to an older pass.

`tests/test_diff_gate.py`, `tests/test_diff_native.py` and
`tests/test_gate_diff_hub.py` distinguish pure mocked protocol/lifecycle checks,
static source/ELF checks, and actual native qualification. An explicit local
pure-test selection must deny native/process/socket/Git effects before imports;
ordinary test discovery is not a substitute for that restriction.

The explicit cheap hosted fixture stages its fixed transitive Python/native
source closure into a private `/tmp/uas-*/source` tree before lowering identity.
Every source ancestor and file is opened without following symlinks; hard links,
changed source identities and unbounded copies are refused. Copies are
root-owned, files are read-only, directories are read/search-only, and matching
content hashes are retained. Both Supervisor and namespace child execute the
staged script with the staged root as cwd; C builds also consume staged bytes.
The original runner checkout and its ancestor permissions are never changed.
