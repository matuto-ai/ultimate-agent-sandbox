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
The deployment-owned service that routes peer messages, tracks presence, records workflow state, and enforces only configured invariants.
_Avoid_: Dispatcher, manager, orchestrator

**Run**:
The durable Hub record for one issue-to-approval lifecycle and its related messages, findings, transitions, and Forge references.
_Avoid_: Task, session, Workstream

**Finding**:
A structured review concern that a developer fixes or disputes and a reviewer resolves or upholds.
_Avoid_: Chat message, review conversation

**Forge**:
A Git collaboration service such as Gitea, GitHub, or GitLab that remains authoritative for issues, pull requests, formal findings, approvals, and merge state.
_Avoid_: Git server, Gitea when referring to the general concept

**Forge Broker**:
The deployment-side security boundary that keeps Forge credentials outside the Trusted Workstation, maps requests to Agent Identities, enforces policy, and records an audit trail.
_Avoid_: Hub, Forge adapter

**Manager**:
A separate central service that observes one or more Deployments and offers notifications and typed workflow actions without shell, filesystem, or container-runtime access.
_Avoid_: Hub, remote shell, control plane
