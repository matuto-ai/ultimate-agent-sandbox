# Enforceable security boundary

This document defines the successor's target boundary, not demonstrated enforcement. Read it with the [current specification](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58) and [October reconciliation](source-reconciliation.md). GitHub is the initial product Forge; historical Gitea proofs remain historical.

## Contents

- [Threat model](#threat-model)
- [Boundary ownership](#boundary-ownership)
- [Room and Project boundary](#room-and-project-boundary)
- [Workstation launch requirements](#workstation-launch-requirements)
- [Networking and mounted-data risk](#networking-and-mounted-data-risk)
- [Participant and Actor authentication](#participant-and-actor-authentication)
- [Forge and Git boundary](#forge-and-git-boundary)
- [Manager boundary](#manager-boundary)
- [Ambient capabilities](#ambient-capabilities)
- [Library boundary](#library-boundary)
- [Lifecycle, storage, and recovery](#lifecycle-storage-and-recovery)
- [Required evidence](#required-evidence)
- [Explicit non-goals](#explicit-non-goals)

## Threat model

Assume a poisoned Participant can run arbitrary code and deliberately search for escape paths. The hard boundary protects the host and every other Room. A host or cross-Room escape is release-blocking.

Participants inside one Trusted Workstation remain trusted peers for product purposes. The spike does not isolate them from one another. A poisoned Participant may read, alter, delete, or upload data and runtime credentials intentionally made available inside its own Room.

## Boundary ownership

The Trusted Workstation contains:

- the Project's writable repository and workspace;
- its read-only reference set;
- Runtime-owned state and provider authentication needed by its Participants;
- narrowly scoped Hub, Forge, and Git capability endpoints.

The following stay outside it:

- the Hub, append-only Room ledger, deployment configuration, and audit records;
- the supervisor that starts Participants and issues their capabilities;
- Forge API tokens and Git private keys;
- Manager administration credentials;
- host credentials, filesystems outside the approved Project paths, container-runtime control, and network administration.

Each Room has persistent Hub and Broker processes in a Room-scoped control-plane sandbox, running as separate unprivileged identities. The Hub cannot read the machine-wide Actor credential table. The Broker derives Room from its supervisor-issued endpoint, Actor from process authority, and writable repository from the permanent Project binding, even for requests originating in a hostile Hub.

Mount selection, Room lifecycle, capability issuance, and boundary policy are external control operations. Agent code cannot weaken them. Manager actions remain typed requests that the Room Hub authenticates, authorizes, and records.

A Broker takeover can reach every repository available to the machine-wide Actor credentials. Broker, credential-store, supervisor, host, container-runtime, or GitHub compromise is a trusted-computing-base failure, not a fault this boundary claims to contain. Revoking an Actor credential affects that identity across installations.

## Room and Project boundary

One Room is permanently bound to one Project, one writable Git repository, and one canonical Trusted Workstation container. Several Rooms may run concurrently, but they do not share container state or networks.

Repository and workspace roots are read-write; references are read-only. The supervisor validates their real paths and the checkout-slot root and exposes each at the same configured absolute host and Workstation path. It rejects traversal, symlink escapes, unexpected mounts, and attempts to remap a live Room to another Project. Runtime state and Broker endpoints are separate narrow mounts; they do not expand the Project filesystem boundary.

The primary checkout is the default. The supervisor allocates an additional host-visible checkout slot only for actual concurrent writing. CLI and Manager expose branch, base, Run, Participant, exact host path, and dirty state. Checkout slots are not peer-isolation boundaries. Cleanup requires verified ownership and safe reconciliation; dirty, untracked, unmerged, unowned, or unverifiable work is retained. Ignored files are not disposable merely because Git ignores them.

## Workstation launch requirements

Room startup fails closed unless the Trusted Workstation:

- runs Participants as non-root users;
- grants no privileged mode, host devices, or host PID, IPC, or network namespace outside the gated nested-container exception;
- exposes no host Docker or Podman socket;
- mounts only the validated Project data, required Runtime state, and narrow capability endpoints;
- retains the container runtime's normal outer confinement;
- joins a Room-specific network whose policy is controlled outside the container;
- applies configured hard disk, memory, CPU, and process limits plus log rotation.

One operating-system user exists per Runtime, not per Actor Identity or Participant. This is shared state, not identity isolation; UID alone cannot authenticate a seat. Missing mounts, network controls, required limits, peer binding, or confined shared transport fails Room startup. Missing Actor credentials disable only affected seats.

## Networking and mounted-data risk

Public internet access remains available for model providers, research, package registries, and dependencies. The external network policy blocks the host, private LAN, metadata services, and every other Room. Domain allowlists are not treated as an exfiltration defense.

Anything under the three Project paths is readable by agent code and may be uploaded. Read-only reference data has integrity protection, not confidentiality. Users must keep secrets out of all mounted Project paths.

Provider credentials required by a Runtime may be present inside the Workstation. Their theft or misuse by a poisoned Participant is an accepted Room-local risk. Forge tokens, Git private keys, host credentials, and Manager administration credentials are not accepted there.

Automated secret scanning and sanitized reference snapshots are deferred. The product must warn users about this boundary at startup and in its documentation.

Source Pi Local's host-loopback route is not an approved exception. Local inference needs a separately authorized narrow endpoint or external proxy compatible with the host/LAN deny rule. An unavailable provider may prevent inference without making the process absent; it cannot trigger identity, credential, provider, model, or billing fallback.

## Participant and Actor authentication

A supervisor-issued badge binds Room, Actor Identity, Participant, Participant Profile capabilities, process incarnation, and capability epoch. The Hub and Broker derive authority from that binding rather than message fields or environment claims. Credential selection uses exact identity and provider-host lookup with no sibling, generic, or legacy fallback.

A seat directly names Runtime, startup arguments, Actor Identity, and Participant Profile. The live Participant never changes Actor Identity. Process exit/replacement, Participant closure, or epoch revocation invalidates old authority. PID or UID reuse cannot restore it. Repairing a credential permits explicit restart of affected seats without restarting the Room.

Two Pi seats may share image, Runtime state, provider authentication, and OS user while retaining distinct Actor attribution. Shared mutable state is an accepted influence risk. Native children and auxiliary calls inherit the parent's bounded attribution unless the supervisor explicitly launches a separately bound Participant. Changing a model or profile does not grant another identity or clear [review contribution history](room-protocol.md#independent-review).

## Forge and Git boundary

Participants use controlled native `gh` and Git executable boundaries. One validated route table drives both enforcement and generated help. The [frozen GitHub capability baseline](source-reconciliation.md#github-provider-contract) selects supported operations; source command availability is not authority. Writes remain pinned to the Project. Typed same-Forge code, PR, issue, comment, and diff reads follow the Actor's native permissions without inventing another repository allowlist.

Every Broker request requires kernel peer credentials plus current process-bound authority. UID alone, caller-provided identity, a shared bearer secret, or an agent-selected remote is insufficient. Verify endpoint and parent ownership/mode; keep narrowly labelled SELinux transport and outer confinement enabled. Missing required controls fails closed. Source `0666` sockets, best-effort peer checks, mounted keys, and `label=disable` are deliberately rejected.

Native Git uses a controlled launcher and fixed SSH-compatible Broker shim. The external Broker derives credential, host, target, and allowed Git service and proxies protocol bytes only. `git-upload-pack` follows native same-Forge read permission; `git-receive-pack` is Project-pinned. No private key, reusable credential-bearing agent socket, arbitrary SSH, shell, SCP, rsync, or caller-selected host configuration enters the Workstation. Broker-side host/credential qualification is readiness evidence, not repository authorization or immunity to revocation.

Ordinary commits use canonical Actor author and committer identity. An anchored cherry-pick preserves source author, records current committer and source SHA, and retains contribution taint including conflict resolution. `git am` remains unavailable.

Body input is bounded at 512 KiB and ordinary output/completed-job logs at 1 MiB. The historical 4 MiB upload bound does not create a GitHub issue-attachment API. Binary issue/PR attachment upload and download remain unavailable in the initial GitHub surface; the proposed 32 MiB download channel is not accepted. No release/artifact endpoint substitutes for it.

Completed job logs are the exception to CI-log denial: validate Project, completed run and job, exact candidate relationship, attempt, and conclusions first; return a bounded tail with an exact dropped-byte count. GitHub's short-lived log redirect is fetched only inside the Broker under validated provider-host policy, without forwarding credentials to storage or disclosing signed URLs. An incomplete transfer cannot claim a complete byte count. Live streaming, whole-run archive routes, CI artifacts, rerun, dispatch, cancellation, arbitrary API/GraphQL, and repository administration remain unavailable.

Every invocation has an operation ID. Commit canonical Deployment-level start audit before provider contact and terminal audit after the result. Keep warning/correction, confirmed fields, `PARTIAL_MUTATION`, `UNKNOWN_OUTCOME`, `NOT_FOUND`, provider failure, and `AUDIT_UNAVAILABLE` distinct. Audit contains bounded identities, route, requested/effective repository, digests, counts, deviations, and receipts, never raw body, attachment, credential, argv, temporary-path, or signed-URL data.

Pre-contact audit failure makes no provider call. After possible contact, lost response or terminal-audit failure leaves an unknown outcome for authoritative reconciliation; terminal-audit failure stops that Broker rather than reporting durable success. Ordinary Participant writes and Hub outbox projections both forbid blind replay. Native merge commands never grant a Participant or Hub human merge authority.

## Manager boundary

Each Room Hub maintains its own mutually authenticated outbound Manager connection. Manager groups them by Deployment, without a local cross-Room relay. The Manager may observe source-tagged versioned state and request eligible typed actions only; stale, duplicate, revoked, or cross-Room requests fail without side effects.

The Manager receives no shell, arbitrary process arguments, filesystem or mount access, host secrets, or container-runtime control. The local Hub revalidates every action and records both the Manager and human identity. Compromise of the Manager is therefore limited to the configured action vocabulary; it does not cross the Workstation or host boundary.

## Ambient capabilities

Browser and nested-container capabilities are explicit default-off Workstation image/launch variants, not per-Participant isolation. Source Pi and Claude browser defaults do not change that policy. Browser support needs outer-boundary proof; a profile denial cannot remove a shared binary. Published preview ports default to none and are not Manager transport. Any future preview allocation must be explicit, loopback-bound, exclusive, and cleaned up; agent-written pages belong in a separate browser profile because localhost cookies are not isolated by port.

The host Docker or Podman socket is never mounted. Enable nested rootless containers only after dedicated escape, network, disk-growth, and resource tests prove that outer confinement remains intact. Disabled SELinux labelling, broadly unmasked kernel paths, or equivalent relaxation is rejected. Use CI or a disposable VM when a confined variant cannot meet the boundary.

## Library boundary

The separate [Library map](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/30) owns its external singleton, private canonical Git store, and per-Project read-only projections. This is sibling scope, not an extra first-delivery service. Its credential and clone stay outside Rooms and the Actor credential table. Every write crosses one deterministic Project-bound commit gate; model output and stored knowledge remain reference data, not instruction authority.

Hosted synthesis requires an approved provider profile and explicit Project egress authorization. Only selected bounded drafts, necessary accepted Project knowledge, and explicit pinned excerpts may enter a request. Sibling Projects, transcripts, credentials, and unrelated content may not. Local inference and its quality qualification are external provider concerns, distinct from interactive Pi readiness. No silent provider fallback occurs. Structural validation cannot prove semantic truth or undo disclosure; Library Service compromise has the accepted whole-library blast radius.

## Lifecycle, storage, and recovery

Room lifecycle is human-triggered:

- **Start** resumes the canonical stopped Room or creates it when none exists.
- **Stop** halts Participant and Workstation activity and revokes active Participant authority while preserving the Workstation and Room state. Hub and Broker remain available for status, reconciliation, and remote Start.
- **Destroy** revokes Hub, Forge, and Git capabilities first, then removes only resources carrying that Room's identity.

Destroy is human-only, irreversible, idempotent, and verified. It removes the Room-owned container, volumes, caches, sessions, and Hub state while preserving user-owned Project paths, Forge history, normal backups, and a minimal immutable audit tombstone. Project-file deletion remains a separate host action.

Residual managed resources produce `DESTROY_FAILED`, list exact leftovers, block unsafe recreation, and permit targeted retry. Broad host cleanup such as `docker system prune` is forbidden. Native context reset replaces Participant context/process authority, not the Workstation. Necessary Workstation replacement is one-for-one and verifies the previous managed container's removal. Anonymous persistent storage is forbidden.

Reconciliation distinguishes Room-owned resources, Project-owned data, externally provisioned inputs, and ambient tooling. Report image/config/profile drift and stage process-affecting managed updates for explicit restart or replacement; never silently change loaded code or an active Run's snapshotted policy. Ownership-aware synchronization preserves unowned settings and artifacts.

At a storage limit, writes fail and the human is alerted; Project data is never deleted automatically. A 100-cycle stop/reopen check must still show one canonical container and no unexplained storage growth.

Repository and workspace recovery use the Forge and the user's host backups. The sandbox backs up only its external ledger, configuration, and audit records.

## Required evidence

These are implementation acceptance requirements; this documentation repository does not yet provide their harness.

Safe invariant checks must run at every Room start. They verify mount identity, launch policy, external capability availability, network isolation, and resource limits before Participants start.

Destructive security tests must run only in disposable virtual machines. Boundary-changing work reruns the relevant cases before release:

- traversal and symlink escape plus reads or writes outside approved mounts;
- access to host runtime sockets, namespaces, devices, or privileged mode;
- access to the host, private LAN, metadata services, or another Room;
- cross-Actor badge or credential use and revoked-capability replay;
- Forge write redirection and denied operation attempts;
- Manager attempts to request shell, filesystem, mount, or runtime operations;
- disk, memory, CPU, and process exhaustion;
- nested-container escape, resource, and network behavior when enabled;
- repeated stop/reopen and partial Destroy failures.

Crashes, denied commands, unusual output, and high resource use may alert a human, but they are not treated as reliable poison detection.

## Explicit non-goals

The spike does not add per-Participant containers, peer confidentiality, automated poison detection, quarantine state, domain allowlists, automatic Project-data deletion, or automated secret-sanitization machinery. Those omissions do not weaken the host and cross-Room boundary defined above.
