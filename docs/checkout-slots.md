# Host-visible checkout slots (partial #64)

The existing fixture `Supervisor` now owns a real host-Git allocation seam:
`supervisor.checkouts(configuration_source, writer_quiescent=trusted_observer)`. It uses the same Room lifecycle lock,
current authorization callback and immutable Project binding as Start/Stop, plus
an fsynced `checkouts.json` intent record in the private Room control store. This
is not a production launcher, new agent engine, or a substitute for #62/#63.

## Working flow

1. Start the fixture Room with its configured Project roots in `FixtureSpec`.
2. `allocate(run_id, participant_id)` gives the first writer the configured primary
   repository. An actual simultaneous writer gets a normal Git worktree under the
   configured checkout root, with a unique `uas-slot/<id>` branch.
3. The result exposes the exact host path, branch, base commit, Run, Participant,
   active assignment, observed dirty state and disposition. Ordinary host Git and
   editors can inspect the path; metadata is not hidden inside the container.
4. Stop prevents new allocation but preserves work and status; Start uses the same
   Room. Repeating an active exact binding recovers its existing slot, not another.
5. `release(run_id, participant_id)` ends the trusted assignment, without deleting
   work. It must be called only after the supervisor has stopped/quiesced that
   writer; the caller is trusted supervisor code, not a Participant request. A trusted
   `writer_quiescent(run, participant)` observer must return literal true both at
   release and again before reconciliation removes data. Missing/negative observation
   retains work. The fixture has no agent processes, so its observer reports that
   empty writer set; real #63 process/epoch revocation is not claimed.
6. `reconcile()` removes only an inactive, registered, matching, clean secondary
   worktree whose commits are reachable from the primary's current HEAD. Primary
   paths and branches are never deleted. Clean primary assignments can be reused.

No per-session checkout is created merely because an agent opens. No `git clean`,
recursive deletion, force-removal, branch deletion or global worktree pruning is
used. Dirty tracked files, untracked **and ignored** data, unmerged commits, locked,
unregistered, mismatched or unverifiable paths remain available for human repair.
There is no automatic adoption/reset of a changed primary branch or partial path.

## Safety and recovery boundary

Run/Participant IDs are bindings supplied by the trusted supervisor, not verified
native process badges. Its authorization callback executes under the lifecycle lock
before allocation or result disclosure. This does not complete #63 authentication.
Device/inode identities bind the repository, checkout root, Git common directory
and each allocated directory/`.git` metadata object, in addition to exact Git
registration, branch and common-directory checks. Same-path replacements and
symlinked Git metadata cannot silently become owned cleanup targets.
The control store must remain private/trusted; filesystem/Process isolation is not
implemented here. A recreated Room cannot silently adopt an older instance's store.

Git effects follow durable intent. Restart reconciles a completed add/remove after
lost control flow. Partial Git state that cannot be proved remains retained and
blocks allocation pending explicit repair. Branches created during an incomplete
add are not reset or deleted speculatively. Storage and Git errors are not success
receipts. Store admission enforces 1,000 recorded slots and 1 MiB before writing
intent or attempting Git creation; exhaustion returns `CHECKOUT_CAPACITY_EXCEEDED`
without damaging the prior manifest. Ownership tombstones are not automatically
pruned to hide capacity exhaustion. Operator-directed archival/retention is not
implemented here. This is process-crash evidence, not a power-loss guarantee.

Git runs without ambient account/config environment, hooks, fsmonitor or transport;
repository-configured filter processes are unsupported and rejected before checkout.
It uses bounded subprocess timeouts. It does not clone, fetch, push or contact Forge.
Repositories needing filters require a later explicitly qualified integration.

Observations are not atomic filesystem leases. The host must be trusted and released
writers quiescent: this API does not protect cleanup against a malicious host process
changing a path between checks and the Git operation. Production process/mount
qualification and non-empty authority revocation remain #61/#62/#63 obligations.

## Executable evidence

```sh
python3 -m unittest discover -s tests -p test_checkouts.py -v
./validate.sh
```

The focused suite uses real temporary Git repositories through the actual Supervisor,
with a file-backed fixture container backend. It crosses Start, concurrent allocation,
host editing, Stop/Start, retained work, explicit repair, release, and targeted cleanup.
It checks six parallel allocations, metadata/identity mismatch, unavailable Git,
ignored/untracked/unmerged retention, disabled hooks and unsupported filters, and real
SIGKILL of a disposable allocator process immediately after Git add/remove effects.
All effects are confined to generated fixture paths; no user checkout is cleaned.

#64 remains open: same-absolute-path visibility inside the actual Workstation and
production integration are not proved by these host-only tests. The existing Docker
lifecycle job is regression evidence, not proof of checkout mounting. There is no new
configuration command for each session; the eventual supervisor/Run admission flow
calls this seam directly.

## Same-path Docker fixture integration

The dedicated actual-Docker suite also exercises the allocator against a running
persistent fixture, not only a simulated backend. The harness mounts its synthetic
repository and checkout roots read-only at their exact host paths, then allocates a
concurrent worktree **after** container startup. A non-root reader observes matching
path/content digests in both primary and concurrent checkout. Host edits remain
visible after Stop/Start of the same container; dirty release retains that data,
and explicit fixture-human repair permits targeted removal observed by the reader.

The test-image reader accepts harness-selected canonical root/checkout paths,
rejects escapes and symlinks, reads only `uas-checkout-fixture.txt` (at most 4 KiB,
with the mandatory `uas-checkout-fixture-v1` marker), and returns only path, size,
SHA-256 and UID—not contents. No service exposes it to Participants. Negative cases
cover another selected root, a symlink, a non-regular FIFO (opened nonblocking),
oversized data and a removed path.

This proves same-path **read visibility in the controlled Docker fixture**. It does
not add writable mounts or native Git to the scratch image, qualify production
Workstation writes, or create a per-Participant isolation boundary. Mounting the
whole synthetic checkout root in this test is not approval of a production mount
policy. Actual Docker execution is required: local skips are not this evidence.
