# Collaborative Agent Sandbox

This context defines the stable language for a sandbox where long-lived coding agents collaborate through a deterministic communication layer. Decisions closed before the August 2026 rename use Deployment in its older, single-Room sense.

## Language

**Deployment**:
One isolated installation containing one or more Rooms and installation-level configuration and credential references.
_Avoid_: Project, tenant, cluster

**Project**:
The user-owned work context permanently bound to one Room, with one writable Git repository, a writable workspace, and read-only references.
_Avoid_: Deployment, Room, repository

**Room**:
The collaboration and control boundary belonging to one Deployment and permanently bound to one Project, with its own Hub, Forge Broker, and Trusted Workstation. Its Participants are trusted peers.
_Avoid_: Project, channel, workspace

**Trusted Workstation**:
A Room's single persistent container in which its Participants run and share the approved Project paths and Runtime state.
_Avoid_: Participant container, secure multi-tenant sandbox

**Runtime**:
A CLI implementation and its shared state and provider-authentication domain, such as Pi or Claude.
_Avoid_: Actor Identity, Participant, model preset

**Seat**:
A Room configuration entry naming one Participant, Runtime, startup arguments, Actor Identity, and Participant Profile.
_Avoid_: Runtime Launch Profile, Work Role

**Actor Identity**:
The durable accountability identity used for Git, Forge, Hub, branch, and audit attribution.
_Avoid_: Runtime, Seat, Participant

**Participant Profile**:
Room-local configuration describing a Participant's responsibilities, instructions, tools, skills, and declared capabilities.
_Avoid_: Deployment Profile, Runtime Launch Profile, fixed role, Actor Identity

**Participant**:
A stable, named Room member bound to an immutable Actor Identity and a Participant Profile. It persists across replacement of its running process, badge, runtime-native session, and conversation context until explicitly closed or replaced.
_Avoid_: Actor Identity, Participant Profile, running process, runtime-native session, subagent

**Capability**:
A configurable permission or workflow eligibility declared by a Participant Profile and enforced by its authoritative module, such as implementing or independently reviewing.
_Avoid_: Hard-coded role

**Hub**:
The Room-owned service that routes peer traffic and owns workflow state, evidence adjudication, and review eligibility.
_Avoid_: Dispatcher, manager, orchestrator

**Map**:
A Forge work item that groups related decision and delivery work toward one destination. A Run may belong to at most one Map.
_Avoid_: Epic, parent issue, project

**Run**:
One bounded Hub coordination attempt against an explicitly activated Forge work item. A paused Run may resume; a closed Run is terminal.
_Avoid_: Task, session, Workstream

**Run Policy**:
Versioned completion rules that a Run snapshots when it opens.
_Avoid_: Participant Profile, workflow, hard-coded phase

**Coordinator**:
A Participant temporarily authorized by a human to coordinate a Run while remaining a peer.
_Avoid_: Manager, orchestrator, permanent lead

**Message**:
Informational Room traffic with no response obligation.
_Avoid_: Request, Command, event

**Work Request**:
Room traffic whose delivery and response lifecycle the Hub supervises without forcing acceptance.
_Avoid_: Task, Message, Command

**Command**:
A typed deterministic operation that the Hub validates and records.
_Avoid_: Shell command, Message, Work Request

**Review Result**:
One independent reviewer's aggregate judgment bound to an exact candidate and canonical Forge review reference.
_Avoid_: Individual finding, merge approval

**Checkout Slot**:
A host-visible checkout associated with a Run and Participant, with an exact path, branch, and observed working state.
_Avoid_: Session container, security boundary

**Forge**:
A Git collaboration service that remains authoritative for issues, dependencies, assignments, pull requests, detailed reviews, and merge facts.
_Avoid_: Git server, Hub

**Forge Broker**:
The Room-bound security reference monitor that keeps Git and Forge credentials outside the Trusted Workstation, authenticates process authority, pins writes to the Project, and records canonical Forge audit.
_Avoid_: Hub, Forge adapter

**Manager**:
A separate central service that observes one or more Deployments and offers notifications and typed workflow actions without shell, filesystem, or container-runtime access.
_Avoid_: Hub, remote shell, control plane
