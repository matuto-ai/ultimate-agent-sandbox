# Artifacts-only Gate Evaluation

This connected source slice implements Hub adjudication for the already compiled
mechanical `artifacts` evaluator under [#25](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/25#issuecomment-6397323807),
[#26](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/26#issuecomment-6397324347),
and the surviving [#58](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58)/[#73](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/73)
contracts. It does **not** complete those issues or enable production execution.
The existing two-Pi/outside-Hub qualification does not qualify this new helper.

## Authority and input

`ArtifactGateHub` owns policy, freshness, Checks and immutable verdicts in the
existing `RoomLedger`. Its trusted installation binding names the current Room
instance, Project, repository and configured Room disk limit. The caller supplies
only operation ID, Run ID/generation and Gate ID. Origin and authorization come
from the existing trusted control seam, not the request payload. There is no new
Participant capability, tool, badge, ADMIT route, credential or operator/session
command. No command evaluator, review, candidate, submit-for-review, completion or
human-merge authority is implemented.

`RoomLedger.exact_receipt` acquires the existing write lock, reauthorizes and
compares the complete typed request before any source resolver runs. An exact
retry returns the same attempt, including after restart, policy/head changes or
Room replacement. It does not launch again or make an old result current.
Conflicting reuse fails before Run staleness. A missing receipt is not a
reservation: the subsequent `apply` reauthorizes and deduplicates atomically.

The Hub recompiles and compares the existing Run's **snapshotted** policy, derives
the Gate configuration and canonical ordered items, and binds policy/config
SHA-256 digests. The Supervisor's read-only resolver supplies exact owned
Run/Participant slot, branch, Room instance, repository and committed head. That
resolver is not source Git execution, and the allocator's existing `_git` and
working-tree observations are not the hostile-metadata boundary. Dirty/untracked
working-tree files never become Evaluation evidence.

## Durable lifecycle and resource bounds

1. Persist `gate.started`, the exact scope/source, item configuration, operation
   identity, Hub sequence/time and bounded ledger/scratch reservations.
2. Supervisor prepares a disposable committed target; append `gate.target-bound`
   with commit/tree, independently reconstructed full-tree manifest, source token,
   unique target ID and inode/device. Persist `gate.launch-reserved` before any
   potentially uncertain helper launch. In that same ledger transaction,
   reauthorize and recheck the current Run generation/status, policy/config and
   canonical checkout ownership binding; changes during preparation fence launch.
3. Receive a gate-specific authenticated `GATE_BIND`, separate from Participant
   ADMIT. Retain actual profile/binding/scope digest provenance. The private
   process-bound channel supplies raw observations directly to the Hub, never via
   a Participant, Runtime adapter, numeric-PID claim or JSON identity assertion.
4. Validate header, ordered item cardinality/index/path digest, strict field/type
   schema and final target/correlation record. Store observations as provisional
   evidence; they are not an immutable Evaluation or a helper verdict.
5. Acknowledge the validated final record while the exact held helper task is
   alive, then establish actual held-task exit (EOF is insufficient). Supervisor
   additionally verifies successful exact Engine exec completion, independently
   rechecks the target and removes only the owned target/cache.
6. Recheck current authorization, canonical Run/policy and source dependencies;
   only then append the immutable per-item Checks and Evaluation verdict.

The canonical checkout ownership digest includes its slot/path/branch, recorded
base, Run/Participant, lifecycle and filesystem identities when present. It is
checked inside both the launch-reservation and terminal ledger decisions, and in
current projections. Mutable `observed_head`, dirtiness and observation notes are
excluded: they cannot replace the independently verified committed target.

All outstanding and quarantined attempts reserve the fixed protocol's 32 MiB
scratch budget cumulatively against the Room limit, with at most two outstanding
leases. Supervisor separately checks actual available Room quota and allocation
bounds before copying; a configured maximum alone is not evidence of free space.
The existing bounded Room state reserves future observation/terminal growth
before effects, preserving peer/context/Forge owners' admitted work. At most 16
Evaluation rows are retained in this initial bounded projection; reaching the
limit explicitly refuses a new attempt, not silent eviction or history rewriting.
Immutable events remain in the RoomLedger. These are source admission constants,
not measured production defaults or a scheduler.

Interrupted or uncertain launch/session loss becomes `error` with unknown
operational state, never an automatic helper replay. Exact retries read the same
pending or terminal attempt. Trusted startup reconciliation is invoked only after
the previous Hub owner is fenced. A cleanup failure produces error plus quarantine
attention and retains scratch capacity; the error handler does not secretly retry
that cleanup. Later targeted verified cleanup appends `gate.cleaned` and releases
capacity without changing the historical verdict or evidence.

## Adjudication and staleness

The helper reports only item index, path digest, observed type, bounded byte
length, directory nonempty fact or typed read error. It supplies no `ok`, Check,
file contents, verdict or advancement claim. The Hub derives:

- `failed`: a required path is absent, the wrong ordinary type, or empty when the
  snapshotted item requires nonempty;
- `error`: malformed/missing/extra/duplicate/out-of-order facts, wrong correlation,
  symlink/read errors, lost identity/task, target mutation, uncertain exit,
  unauthorized acceptance, failed cleanup or another incomplete boundary;
- `passed`: every required item credibly completes and satisfies policy, only
  after the complete terminal proof/cleanup sequence.

Each Check retains `{item, ok, note, evidence_refs}`. The item is its canonical
index/path digest; the original configured path is retained once in the start
record and snapshot. Provisional raw facts remain separately referenced even when
later lifecycle proof prevents qualification. Every result records
`workstation-local / tamper-evident` provenance; presence is not semantic correctness.

The immutable historical result is distinct from `projection()`, which rereads
current authoritative dependencies. A head change after measurement preserves
credible historical facts for the old commit/tree while making the current
projection `stale`. Generation, policy/config, Room/Project/slot/branch or source
identity changes cannot qualify the old Evaluation for a new subject. A newer
in-flight, failed or errored rerun blocks fallback to an older pass. Missing and
stale projections never launch evaluations implicitly. No projection here grants
a protected operation.

## Evidence and remaining qualification

`tests/test_gate_evaluation.py` mocks only the trusted private Supervisor client;
its deterministic tests prove Hub policy, ordering, recovery, resource reservation,
idempotency and failure reduction. Ledger tests cover authorized exact lookup;
compiler tests cover Unicode byte/depth alignment. These tests deliberately prove
neither an actual kernel sender nor a static-helper/isolation capability.
`tests/test_artifact_connected.py` additionally connects the real Hub, private
control client/dispatcher, Supervisor service, GateOffer binary codec and finish
reducer with fully mocked kernel transport and Engine startup. It catches API,
ordering and negative-result propagation mismatches, not native confinement.

Fresh manual disposable-VM qualification is still required for the dedicated
helper UID, static bootstrap/evaluator, read-only target visibility, inherited-FD
inventory, no-new-privileges, mandatory Landlock/openat2/seccomp, no network or
credentials, process-bound control/data channels, actual exit, hostile target
mutation, quota/CPU/memory/output/lifetime bounds, cleanup and two-Room isolation.
Unsupported controls fail closed without host changes or relaxed confinement.
No local native/listener/Docker opt-in is enabled by this slice.
