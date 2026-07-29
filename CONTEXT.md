# Collaborative Agent Sandbox

This context defines the stable language for a sandbox where long-lived coding agents collaborate through a deterministic communication layer.

## Language

**Deployment**:
One isolated installation containing a trusted workstation, its Hub, its Forge Broker, and deployment-local configuration.
_Avoid_: Project, tenant, cluster

**Room**:
The collaboration boundary belonging to one Deployment. Participants in a Room are trusted peers and normally work on one repository at a time.
_Avoid_: Project, channel, workspace

**Trusted Workstation**:
The single persistent container in which all Participants run and share the approved repository, workspace, and read-only reference mounts.
_Avoid_: Participant container, secure multi-tenant sandbox

**Agent Identity**:
A durable CLI-family identity such as Pi or Claude that owns Git authorship, CLI authentication, and a mapped Forge account.
_Avoid_: Profile, Participant, role

**Profile**:
Deployment-local configuration describing an agent's responsibilities, instructions, runtime, model, effort, tools, skills, and capabilities.
_Avoid_: Fixed role, Agent Identity

**Participant**:
One live agent session joined to a Room under an Agent Identity and Profile.
_Avoid_: Agent Identity, Profile, subagent

**Capability**:
A configurable permission or workflow eligibility declared by a Profile, such as implementing, testing, advising, or independently reviewing.
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
_Avoid_: Profile, workflow, hard-coded phase

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
The deployment-side security boundary that keeps Forge credentials outside the Trusted Workstation, maps requests to Agent Identities, enforces policy, and records an audit trail.
_Avoid_: Hub, Forge adapter

**Manager**:
A separate central service that observes one or more Deployments and offers notifications and typed workflow actions without shell, filesystem, or container-runtime access.
_Avoid_: Hub, remote shell, control plane
