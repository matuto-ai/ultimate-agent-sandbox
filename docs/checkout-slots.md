# Host-visible checkout slots (#64)

The existing fixture `Supervisor` now owns a real host-Git allocation seam:
`supervisor.checkouts(configuration_source)`. With `DockerCheckoutBackend`, this
automatically selects the concrete `DockerCheckoutWriters` guard; a custom
empty-set callback is rejected. Host-only synthetic backends may still provide a
trusted `writer_quiescent` callback. The allocator uses the same Room lifecycle lock,
current authorization callback and immutable Project binding as Start/Stop, plus
an fsynced `checkouts.json` intent record in the private Room control store. This
is not a production launcher, new agent engine, or a substitute for #62/#63.

## Working flow

1. Start the fixture Room with its configured Project roots in `FixtureSpec`.
2. `allocate(run_id, participant_id)` gives the first writer the configured primary
   repository. An actual simultaneous writer gets a normal Git worktree under the
   configured checkout root, with a unique `uas-slot/<id>` branch.
3. The result exposes the exact host path, branch, base commit, Run, Participant,
   active assignment, observed dirty state and disposition. Writable Docker slots
   also persist the exact owned container ID, Room instance and observed start
   timestamp before allocation effects. Ordinary host Git and
   editors can inspect the path; metadata is not hidden inside the container.
4. Stop prevents new allocation but preserves work and status; Start uses the same
   Room. Repeating an active exact binding recovers its existing slot, not another.
5. `release(run_id, participant_id)` ends the trusted assignment, without deleting
   work. The concrete Docker guard requires a **fresh observation of the entire
   exact owned Workstation stopped** (`exited`, not restarting/paused/dead, PID 0).
   An exited exec parent, authority revocation, an old receipt or changed start
   timestamp is insufficient. Missing, replaced or unverifiable containers retain
   work. This covers child/orphan writers as well as the direct Runtime process.
6. `reconcile()` removes only an inactive, registered, matching, clean secondary
   worktree whose commits are reachable from the primary's current HEAD. It checks
   quiescence again and **then** re-observes dirty/ignored data and filesystem
   identity, so a writer's last change during Stop cannot be lost. Primary paths
   and branches are never deleted.
7. Clean primary reuse also rechecks quiescence before observing cleanliness. Since
   slots are shared paths, even a *new* running Workstation incarnation blocks reuse
   and removal. The trusted flow is Stop → release/reconcile →
   `reserve(new_run, participant)` while stopped → Start → normal allocation replay.
   An active reservation is never removed or implicitly reused. `allocate()` still
   requires a running Room and supplies first/concurrent slots on demand.

No per-session checkout is created merely because an agent opens. No `git clean`,
recursive deletion, force-removal, branch deletion or global worktree pruning is
used. Dirty tracked files, untracked **and ignored** data, unmerged commits, locked,
unregistered, mismatched or unverifiable paths remain available for human repair.
There is no automatic adoption/reset of a changed primary branch or partial path.

## Safety and recovery boundary

Run/Participant IDs are bindings supplied by the trusted supervisor, not verified
native process badges. Its authorization callback executes under the lifecycle lock
before allocation or result disclosure. This does not complete #63 authentication.
Legacy slots without a recorded writer scope are retained by the Docker guard;
no container/process ownership is inferred during migration. A guarded slot cannot
be downgraded to an empty-set callback after restart. Active allocation replay
re-admits the mount policy and matches the exact container before returning the slot.
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

Observations are not atomic filesystem leases. The host and Docker daemon must be
trusted: this API does not protect against a malicious host changing a path or
starting a container outside the supervisor lifecycle lock. Workstation Start and
slot operations share that lock. Production outer-confinement, native Runtime
identity and remote authority revocation remain separate #61/#62/#63 obligations;
checkout safety does not substitute revocation for actual writer quiescence.

## Executable evidence

```sh
python3 -m unittest discover -s tests -p 'test_checkout*.py' -v
./validate.sh
```

The focused suite uses real temporary Git repositories through the actual Supervisor,
with a file-backed fixture container backend. It crosses Start, concurrent allocation,
host editing, Stop/Start, retained work, explicit repair, release, and targeted cleanup.
It checks six parallel allocations, metadata/identity mismatch, unavailable Git,
ignored/untracked/unmerged retention, disabled hooks and unsupported filters, and real
SIGKILL of a disposable allocator process immediately after Git add/remove effects.
All effects are confined to generated fixture paths; no user checkout is cleaned.

## Same-path writable Docker integration

The existing short `docker-lifecycle` CI job builds the local static test image
without network/package downloads and exercises the actual Supervisor and Docker
Engine. It extends the prior read-only visibility evidence with `DockerCheckoutBackend`:
only the configured synthetic repository and checkout roots are writable, at the
same absolute host/container paths. All other mounts, non-root UID 65532, read-only
root filesystem, no-network policy and resource limits retain actual admission.

After container startup, the allocator selects primary and concurrent worktrees.
The test-image writer modifies only an existing marker-prefixed fixture file;
fixture-owned files alone receive writable DAC modes. Actual orphan child writers
continue changing both host-visible checkouts after their Docker exec parents exit.
Ordinary host Git observes the changes. Early release is rejected, Stop kills the
complete writer set, and reconstructed allocator state retains the resulting dirty
work. Host repair permits primary reservation/reuse and targeted secondary removal.
A restarted container and a new writer in a previously released slot still block
cleanup; an unregistered human directory survives. Same-path read checks across
Stop/Start remain, including wrong roots, symlinks, FIFOs, oversized data and absence.

The reader/writer accepts only harness-selected canonical roots and the bounded
`uas-checkout-fixture.txt` file with `uas-checkout-fixture-v1` marker. It is test-image
functionality, not a Participant-facing service or general file-write API. The
writer has a fixed 20-second deadline in addition to Docker lifecycle cleanup.
No listener, model, account, credential, host policy change or full-VM job is added.

The focused contracts additionally check absent/malformed/replaced Engine evidence,
paused/restarting states, current-incarnation writers, durable-scope downgrade,
active reservation/replay and writes arriving just before quiescence. Existing
ownership, ignored/untracked/unmerged retention and interrupted-add/remove tests
remain binding. Local skips are **not** Docker evidence: the exact candidate's
existing Docker CI job must pass before claiming this writable integration.

This completes the checkout-slot contract, not production Workstation/Runtime
qualification. Git remains the ordinary host Git for allocation, inspection,
repair and testing; no hidden Workstation-only checkout metadata is introduced.
