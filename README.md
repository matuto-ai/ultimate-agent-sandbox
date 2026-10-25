# Ultimate Agent Sandbox

A deterministic successor to `ai-agents-sandbox`: long-lived coding agents collaborate while software owns identity, workflow state, safe delivery, evidence, and recovery.

> [!WARNING]
> This repository contains research and prototypes, not an installable successor. The [current specification](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/58) governs delivery. Its [October reconciliation](docs/architecture/source-reconciliation.md) selects GitHub as the first product Forge and retains Pi and Claude as the first Runtimes.

## Workflow

1. A human authorizes one exact Forge work item. The Hub validates admission and binds a Run, implementer, policy, and checkout slot.
2. The implementer submits an exact pull-request candidate and evidence through a typed command.
3. One eligible independent reviewer covers Standards, Specification, and Runtime, records detailed findings in GitHub, and returns one aggregate result to the Hub.
4. The Hub routes changes back to the implementer, raises human attention, or presents a candidate whose required Gates pass. Five valid changes-requested returns pause the loop before another implementation request.
5. An authorized human merges the unchanged candidate in GitHub. The Hub verifies the merge, candidate, and merger through the Broker before recording completion.

Agents remain peers. A human may appoint a temporary coordinator, but coordination grants neither security authority nor merge permission. Manager has no separate approval or merge button. The Hub does not select work from the backlog automatically.

## Architecture direction

```text
Deployment: installation configuration, supervisor, external credentials/audit
  |
  +-- Room Alpha: one Project and writable repository
  |     |
  |     +-- Room control plane (outside the Workstation)
  |     |     Hub ---------------- outbound mutual authentication --> Manager
  |     |     Forge Broker ------ external Git / GitHub credentials --> GitHub
  |     |
  |     +-- Persistent Trusted Workstation
  |           Pi / Claude Participants and narrow Runtime adapters
  |           validated Project roots and host-visible checkout slots
  |           process-bound Hub / Broker endpoints; no Git or Forge secrets
  |
  +-- Room Beta: separate Hub, Broker, Workstation, state, and network
```

Each Room is permanently bound to one Project. Its Hub and Broker run as separate unprivileged identities in a Room-scoped control-plane sandbox. Each Hub owns its outbound Manager connection; there is no local cross-Room workflow relay. Manager groups Rooms by Deployment and provides literal state, typed actions, and Gotify attention.

The supervisor validates repository, workspace, read-only references, and checkout-slot roots and exposes them at the same configured absolute host and Workstation paths. A primary checkout serves ordinary work; additional host-visible slots are allocated only for actual concurrent writers. Dirty, unowned, or unverifiable paths are retained, not cleaned speculatively.

Ordinary Stop/Start reuses the Workstation. Participant processes, badges, sessions, and contexts can be replaced independently. Stop retains control-plane status; human-only Destroy removes verified Room-owned resources while preserving Project data and an audit tombstone.

## Identities and profiles

A seat directly names its Participant, Runtime, startup arguments, Actor Identity, and Participant Profile. A live Participant never changes Actor Identity. Profiles carry responsibilities, guidance, tools, and declared capabilities; process-bound authority and deterministic policy enforce permissions.

Independent-review eligibility follows Actor contribution history. Changing model, Runtime, seat, context, or profile cannot make an implementing identity independent. Missing credentials disable affected seats rather than the entire Room.

Pi uses documented extension/RPC surfaces. Claude uses documented MCP and CLI/session surfaces with conservative readiness. Process liveness, adapter connection, safe-point readiness, provider validity, and inference availability are separate facts. Historical prototype results do not qualify the current runtime versions.

## Security boundary

Assume a poisoned Participant can execute arbitrary code. The hard boundary protects the host and sibling Rooms, not Participants sharing a Workstation.

- Validated mounts, non-root processes, hard resource limits, and normal outer confinement are mandatory.
- Host runtime sockets, privileged namespaces, host/LAN/metadata access, and sibling Room access are denied.
- Git private keys, Forge tokens, reusable credential-bearing agent sockets, Manager credentials, and control-plane stores remain outside the Workstation.
- Kernel peer credentials and current process-bound authority select Actor and Room; callers cannot select credentials or redirect writes beyond the Project.
- Browser and nested-container capabilities remain default-off. A profile cannot turn ambient shared tooling into per-Participant isolation.

Room-local Project data and available Runtime provider credentials may be read, changed, deleted, or exfiltrated by poisoned code. Read-only references protect integrity, not confidentiality. See the [security contract](docs/architecture/security-boundary.md) for audit, uncertain writes, completed-job logs, lifecycle, and required isolation evidence.

## Delivery and evidence

The existing [23 implementation slices](docs/architecture/source-reconciliation.md#implementation-slices) start with [versioned configuration](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/59), then durable Hub state and supervisor foundations. The first executable seam is the [versioned configuration validator](docs/configuration.md): `python3 -m uas validate-config tests/fixtures/two-rooms.json`. It validates and normalizes configuration without starting a Room or contacting a provider. The [Room application ledger](docs/room-ledger.md) adds atomic command persistence, retry, snapshot, and replay without starting agents or contacting Forge. `./validate.sh` runs the current configuration/CLI and ledger recovery suites, and GitHub CI invokes the same entry point. Later slices must add their own checks; a green run is not whole-product acceptance.

Release requires real Pi–Claude–GitHub integration, exact-candidate review and CI, a disposable-VM two-Room security scenario, 100 Stop/Start cycles, and measured target-host limits. Synthetic lifecycle and Manager prototypes demonstrate design coherence only.

`ai-agents-sandbox` supplies frozen behavior and proof evidence, not a permanent dependency. This product does not migrate, coordinate, modify, or retire another installation. Gitea/GitLab adapters, additional native Runtimes, GitHub Projects-board automation, Library implementation, and rich artifact review are outside first delivery. [Pi Durable research](docs/research/pi-durable-continuous-agents.md) remains exploratory; it does not replace the accepted architecture.

## References

- [Domain language](CONTEXT.md)
- [Room protocol](docs/architecture/room-protocol.md)
- [Source reconciliation and GitHub contract](docs/architecture/source-reconciliation.md)
- [Historical non-disruptive delivery evidence](docs/research/non-disruptive-delivery-signals.md)
- [Contributor issue workflow](docs/agents/issue-management.md)

## License

[MIT](LICENSE)

