# Configuration admission (schema version 1)

The first executable successor interface is `uas.config.load(stream,
available_credentials=())`, with an offline CLI:

```sh
python3 -m uas validate-config tests/fixtures/two-rooms.json
./validate.sh
```

Python 3.11+ and its standard library are sufficient. No dependencies, provider
accounts, containers, or network connections are needed. JSON is the initial
serialization adapter, not a permanent format commitment. The package does not
implement Room startup, workflow execution, credential loading, or Pi Durable.

## Ownership and schema

The [two-Room fixture](../tests/fixtures/two-rooms.json) is the complete runnable
example. Its image digest, endpoint, Actors, and limits are illustrative—not a
runnable image, operational credential inventory, or measured host defaults.

- Top-level `version: 1` contains one `deployment` and a nonempty `rooms` array.
- Deployment owns `id`, external `state_root`, Manager HTTPS URL and mutual-auth
  credential references, credential reference declarations (`id` and `kind`),
  Actor records, digest-pinned image references, provider configurations, and
  audit retention/byte limits. It contains no credential contents or token paths.
- Each versioned Room owns its `id`, disjoint `state_root` inside Deployment state,
  image reference, network identity/deny controls, required boundary controls,
  hard resource limits, profiles, policies/default-policy reference, and seats.
- A Project binding names one `id`, GitHub `owner/repository`, and canonical
  absolute `repo`, `workspace`, `reference`, and `checkouts` roots. No separate
  container path mapping exists: host and Workstation use these same paths.
- Profiles contain instructions, descriptive tool names, and a small recognized
  capability vocabulary. The normalized `capability_enforcement` map identifies
  Hub versus Broker ownership; prose and tool names do not grant permission.
  Runtime process binding is a mandatory boundary control, not an optional profile
  capability. Browser/nested-container tools are ambient Room capabilities, not
  per-Participant permissions.
- Policies have their own positive version, named typed Gates, gate references
  for `submit-for-review` and `complete`, positive queue/response timeouts, and a
  review-return cap from 1 to 5. Raising/waiving the cap requires the later human
  override path. This slice validates references, not Gate verdicts. Empty gate
  sets and unknown operations are rejected. Independent review and verified human
  merge remain non-waivable workflow invariants in the later Hub implementation;
  naming a Gate cannot establish either fact.
- Each seat directly names a unique Room-local Participant, Runtime (`pi` or
  `claude`), argv array, Actor, Room-local profile, and matching Runtime provider.
  An Actor may occur in multiple seats/Rooms; duplicate Actor definitions or two
  seats binding the same Participant in one Room are rejected. Argv is data and
  is never executed, interpolated, or interpreted as authority here. Native launch
  adapters must qualify arguments before starting a process.

IDs are lowercase letters/digits/hyphens, start with a letter, and are at most 64
characters. Inputs are bounded to 1 MiB and arrays to 1,024 entries. Unknown fields,
duplicate JSON members, unsupported versions, null/type confusion, unresolved
references, and duplicate identities fail closed with a field path. There is no
partial normalized output when any Room is invalid.

## Validation versus runtime evidence

The loader is read-only. It does not create directories, read secrets, probe a
provider, launch a process, or change configuration. Paths may not exist yet;
existing symlinks/non-directory ancestors and reserved host paths are rejected.
Project roots must be disjoint from control state and each other, including across
Rooms. Shared read-only references between Rooms are allowed. The launch supervisor
must revalidate real paths, ownership, mounts, and race-sensitive filesystem facts
at activation; configuration success is not filesystem confinement evidence.

All required network/boundary controls must explicitly be `true`. Missing/disabled
controls invalidate configuration even when every credential is available. These
are requested controls, not evidence that a host implements them. Normalized Rooms
say `boundary: declared-not-verified` and `activation: not-evaluated`.

Every resource limit must be finite, bounded, and positive; booleans and numeric
strings are not numbers. CPU is bounded at 1,024, integer quantities at 2^53−1,
and log bytes cannot exceed disk bytes. These are representation/validation
ceilings, not recommendations or proof that a workload fits. Host feasibility,
limit enforcement, and measured defaults belong to lifecycle/capacity slices.

Omitted `ambient` normalizes to `browser: false, nested_containers: false`.
Enabling either is rejected in v1 until a later explicitly qualified boundary
variant exists. Local inference routing is deferred: endpoint URLs must be
credential-free HTTPS with a public-looking host, not a local/private literal.
There is no DNS lookup; launch-time egress policy must reject private addresses
resolved from public-looking hostnames and defend against rebinding/redirects.

Provider configuration validity and inference health are separate. A valid endpoint
can be offline: normalized seats say `provider_configuration: valid` and
`inference_health: unknown`. No fallback provider, model, identity, or billing route
is selected.

## Credential availability without credential access

`available_credentials` is an externally supplied inventory of **declared reference
IDs**, not secret bytes or verified authentication. The CLI accepts repeated
`--available-credential ID` options for inspection. An unknown ID or wrong reference
kind is invalid. References supplied by an Actor must resolve; omission is allowed
and records missing prerequisites rather than selecting a fallback.

Without available Git/Forge references, only seats using the affected Actor receive
`credential_status: unavailable` and the missing credential kinds. Other seats and
Room configuration remain intact. A successful credential inventory marks only
that prerequisite `available`; it never changes `activation: not-evaluated`.
Manager reference declarations are validated structurally. Actual mutual-auth
material and credential/host qualification must be verified by their authoritative
modules before activation. Do not treat a CLI inventory flag as authorization.

## Output, errors, and tests

Successful CLI execution exits 0 and prints normalized JSON, with registries sorted
by ID, explicit ownership, ambient defaults, and derived prerequisite observations.
Output is an inspection artifact, not a second accepted input format: revalidate
original versioned configuration for activation, not previously emitted observations.
Invalid configuration exits 2, prints a structured error with `field`/`reason` on
stderr, and emits no stdout. Unreadable files return `CONFIG_UNREADABLE` without
printing the supplied path or contents.

`./validate.sh` runs table-driven public-loader and subprocess CLI tests, including
cross-Room binding, malformed references/types, filesystem aliases, unavailable
credentials, offline providers, required controls, and failure without partial
output. CI invokes the same aggregate for non-docs changes; docs-only changes retain
the existing explicit exemption. Historical spike demos are not part of this
successor suite and no real Runtime, container, VM, or external Forge acceptance
is claimed. Future slices extend this aggregate rather than replacing it with a
placeholder.
