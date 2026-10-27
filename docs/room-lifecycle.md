# Persistent fixture Room lifecycle

This [#61](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/61) slice introduces `uas.lifecycle.Supervisor` and a deliberately **fixture-only** Docker backend. It implements persistent lifecycle/reconciliation without launching Participants, contacting model providers or Forge, or claiming a qualified production Trusted Workstation. [#62](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/62) remains responsible for real production mount, identity, resource, endpoint, confinement, and network policy.

## The usable seam

A trusted caller supplies:

- a dedicated control-plane root, outside every Project path;
- a `FixtureSpec`: Room, immutable Project identity/paths, local fixture image ID, and managed configuration/profile digests;
- an exact-resource backend;
- current human authorization and idempotent, **verified** authority-revocation callbacks.

`start(spec)`, `stop()`, `destroy()`, `status()`, and `reconcile()` expose the lifecycle. Each result names its persistent instance, desired/observed state, pending managed update, exact unresolved resource names, and `fixture_only: true` / `production_launch: unqualified`. Failure phases carry `START_FAILED`, `STOP_FAILED`, or `DESTROY_FAILED` error codes. Storage-write failure is not a successful acknowledgement; restore storage and reconcile the already persisted intent before any repeat effect.

The trusted caller authenticates human requests before authorizing new intent. A client cannot turn `human: true` or a profile instruction into authority. Callback implementations cannot come from request payloads. The original empty-authority fixture uses that callback; the persistent nonempty control-plane composition below requires concrete service owners and verifies their exit/endpoints independently. The callback alone cannot certify an existing control-plane registry. A false or uncertain verification blocks the relevant effects. A future authority service must also deny new issuance for persisted stopping/destroying intent.

The supervisor's lifecycle manifest is host control state, distinct from the Room Hub's application ledger. It uses a per-Room advisory lock, atomic replacement, file/directory synchronization, and durable intent before external effects. Restore validates the complete versioned manifest, canonical stored/pending specs, phase/intent pairing, timestamps, bounded leftovers, and duplicate/unknown fields before any backend observation or effect; malformed state returns `INVALID_STORE`. Fixture mount paths containing commas or control characters are rejected before even persisting intent. No second agent-execution engine or generalized event system is added. The control directory must be private trusted host state, not a Workstation mount. These mechanisms do not claim #62's complete ownership/mode, endpoint, or hostile-process protections.

## Lifecycle and reconciliation

- **Start** persists the new instance identity and desired state before creating resources. It creates/resumes exactly one named volume and one canonical fixture container. Repeated Start/reconcile retains those identities.
- **Stop** first verifies Participant-authority revocation, then stops only the Workstation container. It retains the volume and control data. The supervisor remains available for status and later Start. The persistent control-plane composition below keeps its real Hub/Broker owners alive; the Workstation backend never owns those processes.
- **Destroy** requires a new human authorization for the irreversible intent, verifies all Room authority revoked, and persists that fact **before** stopping/removing resources. It removes only verified exact resources and the exact instance control directory carrying its ownership marker. It never deletes Project roots or performs global Docker cleanup.
- **Partial Destroy** reports exact leftovers, returns `DESTROY_FAILED`, and blocks Start/recreation. Reconcile retries the persisted authorized intent, inspecting each exact resource first. Confirmed absence skips deletion; uncertainty never means absence.
- **Completed Destroy** publishes a minimal no-overwrite tombstone outside removable instance data. Tombstones retain Room/instance/Project IDs and lifecycle times, not transcripts, credentials, or project contents. The interface never edits an existing tombstone; mode 0400 is not a tamper-proof guarantee against privileged host access. A later explicit Start can create a new instance while preserving the previous tombstone.

Docker call timeouts/lost responses are uncertain outcomes, not a reason to repeat a create/start/remove blindly. The next observation reconciles the exact named resource; if observation is unavailable, effects stop and status remains failed/unknown. The Docker backend checks required ownership labels and exact names before operations, and uses the inspected container ID for stop/remove. Unowned labels/settings are retained, not rewritten. Only the test's own uniquely named image/build directory are removed by its outer harness.

Room/Project binding cannot change while an instance exists. New image/config/profile values are recorded as `pending_spec`; repeated Start, Stop/resume, and reconcile do not silently replace loaded code or alter active policy. This slice **stages** updates; it does not implement applying them through Participant restart or one-for-one Workstation replacement. Actual image mismatch is reported rather than silently repaired. Additional settings unknown to the supervisor are not synchronized or discarded.

## Disposable Docker evidence

The dedicated `docker-lifecycle` GitHub Actions job runs on `ubuntu-24.04`. It checks actual Docker/Go versions and daemon availability, compiles a tiny standard-library-only Go fixture, and builds it `FROM scratch` without a base-image pull or model account. The Go code is test infrastructure, not a second production language/runtime choice. The test image counts starts in a named volume and handles termination.

The fixture runs non-root with a read-only root filesystem, no network, no added capabilities, no-new-privileges, bounded memory/CPU/PIDs/log rotation, a named volume, and read-only temporary Project bind mounts. No host runtime socket is mounted inside it. These conservative fixture settings are **not** the approved production policy: public egress, writable Project repositories, actual disk quotas, Broker transport/SELinux, process-bound authority, and production endpoint checks remain unqualified.

Run only on an explicitly selected **disposable Docker test host**:

```sh
./tests/docker-lifecycle.sh
```

The script fails if tools/daemon are unavailable; it does not silently replace the actual Docker proof with mocks. `./validate.sh` runs local contract/recovery tests and explicitly skips the two actual-Docker cases when their fixture image is absent. CI supplies that image and runs both cases in the dedicated job. Docs-only exemption is preserved; a skipped integration job is not runtime evidence.

The real integration covers:

- create, repeated Start with the same actual container ID, Stop, fresh supervisor reopen, and resumed container/volume startup count;
- actual non-root/container configuration inspection, retained control-state sentinel, and staged managed drift;
- lost create responses reconciled by inspecting actual Docker resources;
- failed volume cleanup after container removal, exact leftover reporting, blocked unsafe recreation, and targeted retry;
- actual `SIGKILL` after Docker removed the container but before the supervisor completed Destroy, followed by persisted-intent recovery;
- Project-data and unrelated-volume preservation, tombstone retention, and clean new-instance recreation.

## Enforced fixture execution admission

The lifecycle now calls the backend's mandatory `admit(state)` after creation,
before Start/resume, after a successful start observation, and when reconciling an
already-running fixture. `DockerFixtureBackend.start` also repeats admission
immediately before starting the inspected container ID. Creation arguments and
ownership labels are not treated as evidence that the actual boundary matches.

Admission reads the actual Docker container, named volume, daemon seccomp
support, and no-follow Project directory observations. It requires the exact
fixture image, non-root user, read-only root filesystem and Project binds,
Room-owned plain local state volume, dropped capabilities, no-new-privileges,
default seccomp support, private namespaces, network-none, no devices or
published ports, disabled restart policy, bounded memory/swap/CPU/PIDs/logs, and
retained kernel path masks. Missing metadata or unavailable observations fail
closed. A mismatched setting reports `START_FAILED` with a specific
`FIXTURE_BOUNDARY_*` reason; no automatic configuration repair occurs.

Admission is separate from ownership inspection: a rejected owned container
remains visible and can still be explicitly stopped/destroyed. Reconciliation of
drift in an already-running fixture reports failure and the actual running state;
it does not claim that reporting failure has stopped it. This is not a continuous
watchdog or Participant authority revocation service. The daemon and the local
fixture image remain trusted test infrastructure, not adversaries.

The dedicated Docker job additionally proves two created mismatches (a changed
PID bound and a writable synthetic Project mount) remain in Docker's `created`
state with no workload output, repeated reconciliation does not start them, and
targeted Destroy succeeds. A stopped fixture with a changed PID bound cannot
resume; explicit test-operator repair permits recovery. Running drift is reported
without silent rewrite, and Stop/Destroy remains available.

The fixture's bounded `--probe` mode runs inside the actual container and reports
kernel UID/GID, capability sets, no-new-privileges, seccomp mode and cgroup-v2
memory/CPU/PID bounds. Direct root/Project writes must fail specifically `EROFS`
(not mere permission denial); a TEST-NET connection must fail locally with
`ENETUNREACH`, with only loopback present. No resource exhaustion or escape test
is performed. The synthetic Project directory is writable by DAC so the read-only
mount, not file ownership, supplies the negative write evidence.

These checks qualify only this conservative fixture. Network-none is **not**
public-egress filtering. SELinux transport, disk quotas, process-bound badges,
hostile path-replacement/mount-lease races and production launch remain
unqualified. The production launcher stays disabled. The earlier local skip rule
now applies to all four actual-Docker cases, not only the original two. A runner
without Docker/Go/cgroup-v2/default seccomp support must fail this integration,
not silently substitute mock evidence or relax confinement.

Local contract tests additionally cover authorization/revocation failure, unavailable observations, unowned resource refusal, control-state marker mismatch, symlink non-traversal, tombstone-write failure/retry, and command construction. They do not substitute for the real Docker job. Production isolation, SELinux, public-egress deny routes, host power loss, participant/session behavior, paid providers, Forge, and the later 100-cycle host-capacity proof are not established by this slice.

## Persistent nonempty fixture control plane

`RoomControlPlane` attaches real authenticated `RoomHubClient`,
`ReadBrokerClient`, and `GitBrokerClient` owners to the Supervisor. The Hub owns a
real `RoomLedger`/`FixturePeerHub` in a separate unprivileged process; the Forge
and Git Brokers retain their existing external service protocols and identities.
The lifecycle status channel does not replace native Participant admission.
Trusted launchers supply existing endpoint leases; clients never choose paths,
UIDs, process IDs, callbacks, credentials, or launch recipes.

The persistent owner registry binds the exact instance, kernel process objects,
endpoint inode/parent identity and one Manager stream ID. Stop revokes
Participants and stops the Workstation, but leaves the control-plane services,
ledger and stream identity intact. Existing #75 exporters can open the ledger
read-only in their own worker, using that stream ID and their fixed credential
reference resolver; network work must not run on the Hub's ledger thread.
`attach_manager_worker` records the exact host-minted worker ID before starting
that real exporter outside the lifecycle lock. Stop retains it; Destroy requests
nonblocking shutdown and retains resources until the exact worker reports actual
termination. A replacement worker with the same stream cannot certify the old
worker's exit. Lost ownership stays an explicit leftover until the retained exact
worker is recovered.

The narrow human remote Start endpoint is TLS 1.3 mutual authentication with an
operator-fixed certificate fingerprint bound to a human and a specific Room
instance. It accepts only an operation ID and observed lifecycle revision, uses
the already stored specification, and rechecks current Supervisor authorization.
It records authorized intent before effects and retains idempotent receipts.
A certificate for another instance, stale observation, payload identity/spec,
or changed retry is refused. This does not introduce #77's general Manager
workflow actions or provision any production certificate.

Destroy persists revocation intent and first acquires each actual Broker client operation lock nonblocking. Busy or uncertain provider work retains an exact leftover instead of being killed. The lifecycle owner retains its own kernel descriptor when a failed client closes. It then closes each quiescent real service channel, verifies
exit through the held kernel object, and removes only exact owned endpoints.
Verified process-exit proof is persisted before endpoint deletion. Interrupted
cleanup can therefore resume deletion without adopting a numeric PID. A missing
process handle before verified exit remains unknown and requires the trusted
launcher to recover its exact held identity; it cannot be certified by an empty
callback. Replaced endpoints are preserved and named as service-specific
leftovers. Workstation removal cannot begin until all service authority is
verified revoked. Destroy/recreation produces a new stream and instance.

`tests/linux/room_control_smoke.py` is an explicit hosted-only, account-free
integration: actual distinct-UID Hub/Forge/Git processes, actual owned Unix
endpoints, real human mTLS Start and receipt replay, retained Hub state across
Stop/Start, replaced-path refusal, verified service termination, partial Destroy
and reconstructed targeted cleanup. Its Workstation is a **file-backed
simulator**, not Docker or native admission. The older actual Docker lifecycle
proof is complementary; neither test claims production launch, live Forge/SSH
credentials, or a VM qualification. Local unit tests cover only pure persistence
and authorization contracts. No production credential is needed for this proof.
