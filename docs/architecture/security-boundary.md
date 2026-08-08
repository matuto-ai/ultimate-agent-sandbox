# Enforceable security boundary

This document defines the target security boundary for the collaborative-agent spike. It is a specification for the spike, not a claim about the current Agent Sandbox or Herdr implementations.

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

Mount selection, Room lifecycle, capability issuance, and boundary policy are external control operations. Agent code cannot weaken them. Manager actions remain typed requests that the local Hub authenticates, authorizes, and records.

## Room and Project boundary

One Room is permanently bound to one Project, one writable Git repository, and one canonical Trusted Workstation container. Several Rooms may run concurrently, but they do not share container state or networks.

Project data appears at fixed paths:

```text
/project/repo       read-write
/project/workspace  read-write
/project/reference  read-only
```

The launcher resolves and validates real host paths before mounting them. It rejects traversal, symlink escapes, unexpected mounts, and attempts to remap a live Room to another Project. Runtime state and broker endpoints are separate narrow mounts; they do not expand the Project filesystem boundary.

Direct checkout is the default. Optional worktrees live under `/project/workspace/worktrees/<run-id>` and are not a security boundary. The Hub never creates them automatically. Cleanup removes only clean, merged worktrees and preserves and reports anything dirty or unverifiable.

## Workstation launch requirements

Room startup fails closed unless the Trusted Workstation:

- runs Participants as non-root users;
- grants no privileged mode, host devices, or host PID, IPC, or network namespace outside the gated nested-container exception;
- exposes no host Docker or Podman socket;
- mounts only the validated Project data, required Runtime state, and narrow capability endpoints;
- retains the container runtime's normal outer confinement;
- joins a Room-specific network whose policy is controlled outside the container;
- applies configured hard disk, memory, CPU, and process limits plus log rotation.

One operating-system user exists per Runtime, not per Runtime Launch Profile, Actor Identity, Deployment Profile, or Participant. This is an honest shared-state boundary, not a claim of isolation between Actor Identities using the same Runtime.

## Networking and mounted-data risk

Public internet access remains available for model providers, research, package registries, and dependencies. The external network policy blocks the host, private LAN, metadata services, and every other Room. Domain allowlists are not treated as an exfiltration defense.

Anything under the three Project paths is readable by agent code and may be uploaded. Read-only reference data has integrity protection, not confidentiality. Users must keep secrets out of all mounted Project paths.

Provider credentials required by a Runtime may be present inside the Workstation. Their theft or misuse by a poisoned Participant is an accepted Room-local risk. Forge tokens, Git private keys, host credentials, and Manager administration credentials are not accepted there.

Automated secret scanning and sanitized reference snapshots are deferred. The product must warn users about this boundary at startup and in its documentation.

## Participant and Actor authentication

A supervisor-issued Participant badge binds the Room, Actor Identity, Deployment Profile, capabilities, Participant, and one running process incarnation. The Hub derives authority from that badge and ignores identity or capability claims in protocol messages.

Badges are private, revocable, and invalidated when their bound process stops or is replaced, or when their Participant closes or is replaced. Cross-identity use and reuse after revocation must fail. Runtime Launch Profile selection uses exact identity lookup with no generic, legacy, or cross-profile fallback.

The identity model is:

- **Runtime**: the CLI implementation and shared state/authentication domain, such as Pi or Claude;
- **Runtime Launch Profile**: a Runtime-owned startup preset that selects invocation parameters and an Actor Identity;
- **Actor Identity**: durable Git, Forge, Hub, branch, and audit attribution;
- **Deployment Profile**: Room-local responsibilities, instructions, tools, and capabilities;
- **Participant**: a stable, named Room member bound to an Actor Identity and Deployment Profile; its process, badge, runtime-native session, and conversation context are replaceable.

Pi's `pi-agent-gpt` and `pi-agent-kimi` Runtime Launch Profiles intentionally share the Pi image, Project-scoped Pi Runtime state, provider authentication, and OS user while using distinct Actor Identities and Git/Forge credentials. Shared mutable Pi state is an accepted influence risk. It does not merge their attribution, and the [independent-review eligibility rules](room-protocol.md#findings-and-independent-review) still apply.

## Forge and Git boundary

Forge operations pass through an external broker that selects credentials from the authenticated Actor Identity, enforces deterministic policy, and writes metadata-only audit records. Agent-controlled repository configuration or request fields cannot redirect its identity or write target.

- Writes remain pinned to the Project repository.
- Cross-repository reads may target repositories the Actor Identity can already read through the Forge.
- The allowed cross-repository surface is limited to deterministic code, pull-request, issue, comment, and diff operations.
- Agent-controlled raw API access, CI logs or artifacts, and cross-repository mutations are denied.
- Native Forge permissions remain authoritative; the broker does not add a second repository allowlist, temporary grants, or separate read tokens.

Git uses a revocable external SSH agent or broker connection. Private keys are never mounted, including read-only mounts.

Existing Agent Sandbox and Herdr policy code is a foundation, not the final boundary. The spike must tighten inherited behavior that still mounts Git private keys, exposes restricted raw API or CI-log reads, or disables outer confinement for broker access.

On SELinux hosts, Forge connectivity must work through a narrowly labelled socket policy or isolated broker service while normal process labelling remains enabled. If confined broker transport is unavailable, Room startup fails.

## Manager boundary

Each Deployment connects outbound to the Manager, and both sides authenticate one another. The Manager may observe state and request configured typed actions only.

The Manager receives no shell, arbitrary process arguments, filesystem or mount access, host secrets, or container-runtime control. The local Hub revalidates every action and records both the Manager and human identity. Compromise of the Manager is therefore limited to the configured action vocabulary; it does not cross the Workstation or host boundary.

## Nested containers

The host Docker or Podman socket is never mounted. Nested rootless Podman is default-off and requires an explicit per-Project capability.

Enable it only after dedicated escape, network, disk-growth, and resource tests prove that it does not weaken outer confinement. A configuration requiring disabled SELinux labelling, broadly unmasked kernel paths, or equivalent boundary relaxation is rejected. Use CI or a disposable VM when nested containers cannot meet the boundary.

## Lifecycle, storage, and recovery

Room lifecycle is human-triggered:

- **Start** resumes the canonical stopped Room or creates it when none exists.
- **Stop** halts processes and revokes active Participant capabilities while preserving the container, sessions, and Room state.
- **Destroy** revokes Hub, Forge, and Git capabilities first, then removes only resources carrying that Room's identity.

Destroy is human-only, irreversible, idempotent, and verified. It removes the Room-owned container, volumes, caches, sessions, and Hub state while preserving user-owned Project paths, Forge history, normal backups, and a minimal immutable audit tombstone. Project-file deletion remains a separate host action.

Residual managed resources produce `DESTROY_FAILED`, list the exact leftovers, block restart or recreation, and allow a safe retry. Broad host cleanup commands such as `docker system prune` are forbidden. Replacement during reset or update is one-for-one and verifies removal of the previous managed container. Anonymous persistent storage is forbidden.

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
