# Ultimate Agent Sandbox

A spike for a sandboxed coding workstation where long-lived CLI agents can communicate, delegate, review, and escalate without a human manually relaying every handoff.

> [!WARNING]
> This repository is an active spike, not an installable replacement for the existing sandboxes. The current work is tracked in [Chart the evolvable collaborative agent sandbox spike](https://git.puglab.im/puglab/ultimate-agent-sandbox/issues/1).

## Goal

Prove a reusable path from a Forge issue to an approved pull request:

1. A human turns a CLI conversation into an agent-ready issue.
2. An implementer claims the issue and opens a pull request.
3. An independent reviewer raises structured findings.
4. The implementer fixes or disputes each finding.
5. The reviewer resolves or upholds it.
6. Upheld disagreements notify the human and resume after a decision.
7. A human, the active coordinator, or a Profile with `can-approve-run=true` approves the Run after its policy gates pass.
8. A human merges the accepted pull request separately through the Forge.

The agents remain peers. A deterministic Hub records the workflow and rejects invalid transitions; it does not assign marching orders, prevent disagreement, or merge pull requests during the spike.

## Architecture direction

```text
                         outbound authenticated events
                    ┌──────────────────────────────────┐
                    ▼                                  │
          ┌───────────────────┐              ┌─────────┴────────┐
          │ Manager           │              │ Deployment Hub   │
          │ web view + Gotify │              │ messages + ledger│
          └───────────────────┘              └─────────┬────────┘
                                                       │ adapters
                                            ┌──────────▼──────────┐
                                            │ Trusted Workstation │
                                            │ Pi · Claude · others│
                                            └──────────┬──────────┘
                                                       │ policy shims
                                            ┌──────────▼──────────┐
                                            │ Forge Broker        │
                                            └──────────┬──────────┘
                                                       ▼
                                            Gitea · GitHub · GitLab
```

A Deployment contains one Room and one persistent Trusted Workstation container. Participants share three deliberate mounts:

```text
/project/repo       read-write source
/project/workspace  read-write working artifacts
/project/reference  read-only source material
```

The Hub, its durable ledger, and Forge credentials stay outside the Trusted Workstation.

## Profiles and communication

Agent boundaries are deployment-local Profiles rather than fixed built-in roles. A Profile may define:

- CLI runtime, model, and reasoning effort;
- responsibilities and base instructions;
- tools, skills, and workflow capabilities;
- Agent Identity and mapped Forge account.

A live Participant joins the Room under one Profile. Minimal Pi and Claude adapters connect it to the neutral Hub for presence, peer discovery, correlated messages, replies, and attention state. Current research favors a Pi extension and a Claude Code MCP adapter while preserving subscription-authenticated CLI use instead of API-priced managed agents.

## Security boundary

Participants inside the Trusted Workstation are mutually trusted peers. The spike does not claim isolation between them.

The intended hard boundaries are:

- only the three approved project mounts enter the workstation;
- no host container-runtime socket enters it;
- Forge PATs remain in the external Forge Broker;
- the Manager receives no shell, filesystem, or container control;
- Manager connections originate outbound from each Deployment;
- Git commits retain per-agent authorship, while Forge mutations retain mapped identities and broker audit records.

Worktrees are optional. The Hub warns when multiple writers target the same checkout; it does not prohibit manually isolated worktrees or enforce a repository-wide writer lock.

## What the spike must prove

A small fixture application will exercise five repeatable scenarios:

1. clean implementation and review;
2. a seeded defect caught and corrected through review;
3. a legitimate disagreement escalated to a human;
4. an unauthorized host, credential, or Forge action being denied;
5. continued Room operation while the Manager disconnects and later replays events.

Prototype code may be merged here when it is useful for the eventual production system. Production migration and hardening happen after the spike has produced evidence.

## Deliberate non-goals

- replacing or migrating the existing sandboxes during the spike;
- automatic loops that continuously consume the issue backlog;
- hostile multi-tenancy or per-participant containers;
- multiple active repositories in one Deployment;
- production GitHub or GitLab adapters;
- a polished production frontend;
- a mandatory orchestrator, lead, and worker hierarchy;
- restoring legacy headless task mode.

## Project references

- [Domain language](CONTEXT.md)
- [Room protocol and workflow invariants](docs/architecture/room-protocol.md)
- [Non-disruptive delivery signals](docs/research/non-disruptive-delivery-signals.md)
- [Agent issue workflow](docs/agents/issue-management.md)
- [Original Agent Sandbox](https://git.puglab.im/puglab/ai-agents-sandbox)
- [Herdr Sandbox](https://git.puglab.im/puglab/herdr-sandbox)
- [Pi vs Claude Code](https://github.com/disler/pi-vs-claude-code)
- [Cmux orchestration companion](https://github.com/disler/learning-cmux-with-agents)
- [Cmux orchestration video](https://www.youtube.com/watch?v=WAFUMBLOjHo)

## License

[MIT](LICENSE)
