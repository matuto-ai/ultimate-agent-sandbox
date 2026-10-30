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

The existing [23 implementation slices](docs/architecture/source-reconciliation.md#implementation-slices) start with [versioned configuration](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/59), then durable Hub state and supervisor foundations. The first executable seam is the [versioned configuration validator](docs/configuration.md): `python3 -m uas validate-config tests/fixtures/two-rooms.json`. It validates and normalizes configuration without starting a Room or contacting a provider. The [Room application ledger](docs/room-ledger.md) adds atomic command persistence, retry, snapshot, and replay without starting agents or contacting Forge. The [fixture supervisor](docs/room-lifecycle.md) reconciles persistent Room-owned resources and targeted cleanup; its separate Docker CI job exercises real disposable containers, not production isolation. The [read-only launch preflight](docs/launch-preflight.md), `python3 -m uas check-launch CONFIG --room ROOM`, reports actual path/kernel observations while keeping production launch blocked. The [host checkout allocator](docs/checkout-slots.md) connects the same supervisor to real Git primary/concurrent slots and conservative recovery without enabling production mounts. The [Participant process fixture](docs/participant-processes.md) adds actual Linux per-record kernel credentials and pidfd-bound immutable seats, revocation, and synthetic credential recovery through that Supervisor and the peer ledger, without qualifying production Runtime or Workstation isolation. `./validate.sh` runs the current configuration/CLI, ledger recovery, supervisor, Participant process, peer and preflight contract suites, and GitHub CI invokes the same entry point. Later slices must add their own checks; a green run is not whole-product acceptance.

Release requires real Pi–Claude–GitHub integration, exact-candidate review and CI, a disposable-VM two-Room security scenario, 100 Stop/Start cycles, and measured target-host limits. Synthetic lifecycle and Manager prototypes demonstrate design coherence only.

The [Pi native fixture adapter](docs/pi-runtime.md) crosses the actual official Pi 1.4.0 extension/RPC surface with the durable Hub ledger using an account-free provider. Its fixed same-Run launcher now attaches that actual Pi process to Linux per-record credentials and a held pidfd; native peer tools reach the ledger with its Supervisor badge. The [durable context-reset fixture](docs/pi-context-reset.md) adds per-Participant cross-Run fencing, verified fresh native replacement and monotonic generation, without claiming canonical GitHub Run admission/completion. This remains same-UID fixture authority, not production Workstation qualification or complete unknown-handoff recovery.

The [Claude native fixture adapter](docs/claude-runtime.md) crosses official Claude Code 2.1.310's documented invocation/replay-acknowledgment surface with the same durable Hub. Its long-lived tool-less process uses a loopback protocol fixture, not authenticated inference. Its [supported TypeScript SDK seam](docs/claude-sdk-fixture.md) obtains fresh non-model liveness and exact native idle evidence without synthetic bootstrap/refresh; unknown handoffs never automatically reinject. SDK host and native process ownership remain distinct. Its [Supervisor-owned context lifecycle](docs/claude-context-reset.md) adds native process badges, same-Run restoration and cross-Run reset through the existing ledger. Production authority, arbitrary permission/tool profiles and MCP delivery remain unqualified.

`ai-agents-sandbox` supplies frozen behavior and proof evidence, not a permanent dependency. This product does not migrate, coordinate, modify, or retire another installation. Gitea/GitLab adapters, additional native Runtimes, GitHub Projects-board automation, Library implementation, and rich artifact review are outside first delivery. [Pi Durable research](docs/research/pi-durable-continuous-agents.md) remains exploratory; it does not replace the accepted architecture.

## References

- [Domain language](CONTEXT.md)
- [Room protocol](docs/architecture/room-protocol.md)
- [Source reconciliation and GitHub contract](docs/architecture/source-reconciliation.md)
- [Historical non-disruptive delivery evidence](docs/research/non-disruptive-delivery-signals.md)
- [Contributor issue workflow](docs/agents/issue-management.md)

## License

[MIT](LICENSE)


### Connected read-only Forge seam

The existing official Pi Participant channel now supports bounded native `gh issue view` observations through authenticated process authority and durable sanitized RoomLedger results. See [connected GitHub read observations](docs/forge-read-observations.md) for supported routes, account-free tests, uncertainty handling, and the still-open production/Run/credential qualification limits.

### Bounded Run admission and control

The account-free [Run admission/control fixture](docs/run-admission-foundation.md) connects exact human commands and authenticated Participant Run Requests/proposals to fresh Forge facts, atomic Run/policy/checkout binding and actual Pi Work Requests. It adds exact human proposal approval, generation-preserving pause/resume, policy migration fencing, bounded human-appointed coordination, verified owned force/terminal stop and safe withdrawal/retarget reconciliation. Native context reset and clean checkout rules remain mandatory across Runs. Review/merge completion, Manager login and production authentication remain separate; controlled GitHub responses are not live-account qualification.

The optional [audited self-assignment source slice](docs/forge-assignment.md) connects
one bounded write and read-only uncertain-outcome reconciliation to canonical Run
admission. Tests use controlled GitHub responses, not live credentials or writes.

The [PR/review observation prerequisite](docs/forge-pull-observations.md) adds
bounded exact-revision Forge reads through the existing Broker, without Gate or
review-routing authority.

Gate-policy configuration: [bounded artifacts compilation](docs/gate-policy-compilation.md).
The [artifacts-only Evaluation slice](docs/gate-artifact-evaluation.md) connects
Hub adjudication to the private Supervisor boundary; pure tests are not native
helper qualification, production enablement, or protected-operation authority.

The [external read Broker](docs/forge-read-service.md) documents the full declared GitHub read vocabulary, process-bound external credential boundary, metadata-only Deployment read audit and completed-job log safeguards.

The [bounded mutation Broker](docs/forge-mutations.md) extends that same external
owner with Project-pinned issue/PR/comment/work-label/dependency/submitted-review
routes, per-step authority, durable executed-field receipts and partial/unknown
fences. Account-free hosted proof is separate from live-account qualification;
#74 review workflow is not implied.

[Forge reconciliation](docs/forge-reconciliation.md) resolves ordinary uncertain
writes with read-only, identity-bound observations and connects the same external
Broker to the [Hub projection outbox](docs/forge-projections.md). Run state remains
authoritative when labels drift or provider/audit responses are lost.

### Controlled native Git

[Native Git mediation and attribution](docs/native-git.md) adds a public typed
launcher, fixed credential-free worker, external SSH-compatible byte Broker,
canonical commit/source receipts and Run-scoped contribution history. Short
account-free hosted seams are separate from the deferred real GitHub SSH and
exact-image qualification; #67 is not closed by source tests alone.

## Local test installation

Use Python 3.11+ with `venv` and `pip` available. Install the hash-pinned Python dependencies before running checks or importing the Library content gate; validation does not install packages into your environment automatically. Keep the virtual environment outside the checkout:

```sh
python3 -m venv /tmp/uas-python
. /tmp/uas-python/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements.txt
./validate.sh
```

The Library gate uses `markdown-it-py` in CommonMark mode (no rendering, plugins, or automatic bare-URL linking). HTML, images and destinations are checked as parsed tokens; fenced and indented code remain literal. Parser nesting at 32 levels is refused rather than silently leaving content unchecked. The parser and its sole runtime dependency, `mdurl`, are pinned with wheel hashes in `requirements.txt`; CI installs the same file in an isolated environment before each aggregate partition.

### CI runtime budget

The `validate`, `pi-native`, and `claude-native` workflows enforce `min(150 seconds, median of the last five eligible main measurements × 1.10)`. Each workflow uses five distinct main commits preceding the current run, restricted to the tested base's history. Only the first attempt of the first push run for a commit can supply a sample, and that attempt must have completed successfully. Re-running or re-pushing a commit cannot replace its measurement or count it twice. Documentation-only validation runs do not supply full-suite samples. Existing Actions history supplies the initial baseline; no guessed seed or writable baseline artifact is needed.

The measurement includes setup, tests, and cleanup of each validation job. For `validate`, it is the longest unit job plus the longest dependent seam job; parallel jobs are not summed. Pi's three disjoint native partitions run on separate runners and contribute the longest complete job; all three must pass. Runner queue time and the final accounting job are excluded. GitHub's job timestamps supply the evidence. The final `runtime-budget` check reports the measured duration, source run/commit, and allowed duration in its job summary. Missing, failed, skipped, duplicate, or unrecognized validation jobs cannot produce acceptance, except for the existing explicit documentation-only exemption.

The current PR is also judged on its first-attempt job measurements: retrying the same run cannot turn an over-budget result green. A failed first-attempt functional job likewise cannot become runtime evidence through a retry. This protects against retrying until a favorable runner appears; it does not prevent someone with branch-write authority from creating new commits, which remains a review responsibility.

The three-minute unit/native job watchdogs only stop stuck jobs; they are not the accepted runtime budget. A completed workflow still fails its runtime check above the moving limit or the absolute 150-second ceiling. Existing shorter seam/process watchdogs remain in place. New tests can grow within the allowance without repeatedly redistributing tests to satisfy an unrelated one-minute unit-job ceiling.

The accounting job has read-only Actions access. It fails closed if evidence is unavailable or fewer than five eligible distinct commits exist among the last 100 main push runs. Restore access to the retained baseline evidence before retrying the accounting check; do not substitute PR results or silently reset the baseline. Historical seven- and eight-unit-lane validation and single-job Pi runs remain comparable with today's graphs, but missing jobs are never accepted in the current run. When adding jobs or changing dependencies, update `tests/ci_runtime_budget.py` and the graph assertions in `tests/test_vm_ci_policy.py` together.

See [the persistent local entrypoint](docs/local/entrypoint.md) for explicit setup,
start/status/stop and authenticated Manager inspection. This is separate from
disposable native qualification; required host preparation and currently absent
provider/runtime bindings are reported rather than simulated.
