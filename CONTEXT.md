# Collaborative Agent Sandbox

This context defines the stable language for a sandbox where long-lived coding agents collaborate through a deterministic communication layer.

## Language

**Deployment**:
One isolated installation containing one Room, its Trusted Workstation, Hub, Forge Broker, and deployment-local configuration.
_Avoid_: Project, tenant, cluster

**Project**:
The user-owned work context permanently bound to one Room, with one writable Git repository, a writable workspace, and read-only references.
_Avoid_: Deployment, Room, repository

**Room**:
The collaboration boundary belonging to one Deployment and permanently bound to one Project. Its Participants are trusted peers.
_Avoid_: Project, channel, workspace

**Trusted Workstation**:
The single persistent container in which all Participants run and share the approved repository, workspace, and read-only reference mounts.
_Avoid_: Participant container, secure multi-tenant sandbox

**Runtime**:
A CLI implementation and its shared state and provider-authentication domain, such as Pi, Claude, or native Kimi.
_Avoid_: Actor Identity, Runtime Launch Profile, Participant

**Runtime Launch Profile**:
A Runtime-owned startup preset that selects invocation parameters and an Actor Identity, such as Pi · GPT or Pi · Kimi.
_Avoid_: Deployment Profile, Runtime, role

**Actor Identity**:
The durable accountability identity used for Git, Forge, Hub, branch, and audit attribution.
_Avoid_: Runtime, Runtime Launch Profile, Participant

**Deployment Profile**:
Deployment-local configuration describing a Participant's responsibilities, instructions, tools, skills, and capabilities.
_Avoid_: Runtime Launch Profile, fixed role, Actor Identity

**Participant**:
One live Runtime session joined to a Room under an Actor Identity and Deployment Profile.
_Avoid_: Actor Identity, Deployment Profile, subagent

**Capability**:
A configurable permission or workflow eligibility declared by a Deployment Profile, such as implementing, testing, advising, or independently reviewing.
_Avoid_: Hard-coded role

**Hub**:
The deployment-owned service that routes peer traffic, tracks presence, records workflow state, and enforces only configured invariants.
_Avoid_: Dispatcher, manager, orchestrator

**Map**:
A Forge work item that groups related decision and delivery work toward one destination. A Run may belong to at most one Map.
_Avoid_: Epic, parent issue, project

**Run**:
One bounded Hub coordination attempt against an explicitly activated Forge work item. A paused Run may resume; a closed Run is terminal.
_Avoid_: Task, session, Workstream

**Run Policy**:
Versioned completion rules that a Run snapshots when it opens.
_Avoid_: Deployment Profile, workflow, hard-coded phase

**Coordinator**:
A Participant temporarily authorized by a human to coordinate a Run while remaining a peer.
_Avoid_: Manager, orchestrator, permanent lead

**Message**:
Informational Room traffic with no response obligation.
_Avoid_: Request, Command, event

**Request**:
Room traffic whose delivery and response lifecycle the Hub supervises without forcing acceptance.
_Avoid_: Task, Message, Command

**Command**:
A typed deterministic operation that the Hub validates and records.
_Avoid_: Shell command, Message, Request

**Finding**:
An explicitly registered Forge review concern that an implementer fixes or disputes and an eligible reviewer resolves or upholds.
_Avoid_: Chat message, ordinary review comment

**Forge**:
A Git collaboration service such as Gitea, GitHub, or GitLab that remains authoritative for issues, pull requests, registered Findings, formal pull-request approvals, and merge state.
_Avoid_: Git server, Gitea when referring to the general concept

**Forge Broker**:
The deployment-side security boundary that keeps Forge credentials outside the Trusted Workstation, maps requests to Actor Identities, enforces policy, and records an audit trail.
_Avoid_: Hub, Forge adapter

**Manager**:
A separate central service that observes one or more Deployments and offers notifications and typed workflow actions without shell, filesystem, or container-runtime access.
_Avoid_: Hub, remote shell, control plane
