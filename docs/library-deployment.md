# Deployment Library composition (T40)

`uas.library_deployment.DeploymentLibrary` is the trusted host composition that
places the external Library service into one Deployment. It wires the existing
T02/T05/T07/T09/T21/T22 seams; it does not reimplement them. The canonical
target, its host-local working clone, credential references, model runner,
qualification evidence, Room reference mounts and backups stay external operator
configuration. This owner validates and wires; it provisions no service,
credential, container, mount, network route, host/LAN exemption or proxy.

## Trusted inputs

| Input | Owner |
| --- | --- |
| `settings` | External authority document: canonical target/branch, credential and model references, filters, limits. Admitted here with the existing settings validator; `egress_approvals` are supplied separately. |
| `credentials` | Deployment credential store: maps the settings `credential_ref` to the exact Git transport environment. Service code never reads a secret value. |
| `rooms` | Approved Deployment Room bindings: each Room's configured Project plus its immutable source identity. The deployment config already requires one Project per Room and rejects overlapping writable Project paths. |
| `scope_for` | Live authenticated authority for the bound Project (the existing admission owner). Inventory identity survives later revocation. |
| `runner_for` | External model composition: returns the T19 `Attempts` runner and the fixed batch context for a Project. Model profile/qualification remain T17/T42 concerns. |
| `ledger_for` | The Room Hub store owner; returns a `RoomLedger` for an approved Room. |
| `authenticate` | Transport-bound service authentication for service-to-Room report ingress. |
| `qualification` | Externally established target qualification evidence. Absent, false or later-revoked evidence refuses new writes. |
| `operator` | Optional host-local human principal resolver for the T22 operator interface. |
| `settings_owner` | Optional existing T22/#179 durable shared-settings owner. When supplied it is the only source of current settings, so a validated update applies to new operations without restart and a missing or invalid store refuses them. |

`audit` is forwarded to the existing operational-retention owner. This composition
adds no endpoint exposure: the T09 Hub route inside the Room Hub and the T22
`library-operator.sock` in the private service root are the only authenticated
interfaces, and the existing Host/Room boundary still owns their publication.

## Ordering and lifetime

`start()` validates the deployment state root, its `library` child (a symlink,
foreign owner or writable child is refused before any clone work), the credential
reference, target qualification, every Room binding, reference-mount ownership
and real-path disjointness, and every model runner's Project/target binding. Only
then does `Service.startup()` take the host-local lease and reconstruct the
working clone. Every new capture also revalidates qualification, the credential
reference and current settings; the service loop rechecks them at least twice a
second and fails closed, and operator controls run the same guard, so revoked
qualification or an unavailable settings store blocks drain/retry/observe writes
instead of continuing on the startup values.
A second instance is refused by that lease before it reads or writes the clone.
Configuration is never silently repaired and no fallback target, credential or
Room binding exists.

The service owns one singleton lifetime for the whole Deployment, independent of
any Room: `stop_room(room)` releases only that Room's projection lease and its
Hub handle, and `start_room(room)` republishes the current coherent generation
from canonical Git. Room Stop or Destroy therefore deletes no Library data and
does not end draining or report replay. `stop()` stops the drain loop, closes
Room projections and the operator listener, and runs the existing bounded service
shutdown. If a live attempt exceeds its configured bound the shutdown raises and
the lease stays held, so the Supervisor must force termination rather than let a
second writer start; normal startup recovery then applies.

## Published projection

Each bound Room receives exactly its approved Project's `library/` tree and
`library.snapshot.json` at the configured reference-root interface through the
existing T07 owner. One canonical commit is published atomically per generation
with its original timestamp. The canonical clone, records store, Git metadata,
sibling Project bundles and credentials never enter the published tree. A failed
refresh preserves the previous coherent bundle rather than publishing an empty
or partial one. A Room without a current projection is reported by the existing
owner, not patched with fabricated content.

## Not in this slice

This is the trusted composition seam, not an installed daemon. Wiring it into the
installed Deployment — a digest-pinned installation selection for the Library
document, credential references and Room bindings, the split-process Room Hub to
host transport, and Room Start/Stop bind/unbind — is tracked as #252; the human
operator waived that wiring from #185. The actual target qualification of #157,
the model/version qualification of T42, provider and backup provisioning, and a
real two-Room VM proof all remain with their own owners. Shared-settings update
routing and the Manager Settings page stay with #192: this composition admits
the authority document it is given, and a changed canonical target or branch is
refused by the existing publisher pin instead of silently repointing a clone. Until they supply
qualification evidence and the external configuration, a real host startup is
expected to fail closed at `TARGET_NOT_QUALIFIED`; no fallback target, credential
or Room binding is selected in the meantime.

## Proof

`tests/test_library_deployment.py` composes the real disposable canonical Git,
operational records, Room ledgers, Unix operator socket and Room projections. It
covers two Projects with distinct markers, Room stop/destroy/restart, a second
definition instance refused by the lease, missing credential, qualification and
reference-mount refusal before any clone, a symlinked service-state child refused
before clone work, qualification revocation blocking capture and stopping writes,
a current durable settings owner applying a validated update to the next
operation and refusing an unavailable store, an operator observation for a
stopped Room with no Hub, service reports reaching only the reporting Room's
ledger, and a stop while a live model attempt is in flight (lease retained,
second instance refused, restart recovers and reports resume).
The model runner is a deterministic fixture adapter; no live provider, installed
daemon, actual target qualification, split-process Room Hub transport, VM,
account, backup or deployment evidence is claimed here.

Run `PYTHONPATH=.:tests python3 -m unittest test_library_deployment` with the
repository requirements installed.

## Installed Deployment wiring (#252)

The installation selects the composition with one digest-pinned Library
deployment document. `installation.json` gains an optional `library` reference
beside `native`, `manager` and `runtime`; `uas.local_installation.selection`
admits it through the existing closed schema and `Installation.inspect` validates
the pinned bytes before any host effect. An installation that selects no Library
keeps running exactly as before.

The selected document is version 1 with these fields:

| Field | Content |
| --- | --- |
| `settings` | The complete Library settings document, admitted by the existing validator. Hosted egress needs an approval this document cannot grant. |
| `credentials` | Maps each referenced credential to the exact host environment variable names that carry its Git transport environment. Each reference must be a configured `git` credential; a missing variable fails the host closed. |
| `rooms` | Approved Rooms and their immutable source identity. The Project binding itself stays in the closed installation configuration, so paths, repository coordinates and Room ownership cannot drift from it. |
| `qualification` | Externally established target qualification evidence: target, branch and the `qualified` flag it establishes. False, absent or mismatched evidence fails startup at `TARGET_NOT_QUALIFIED` before any clone work. |
| `model` | The fixed synthesis route: one qualified profile identity plus the exact adapter argv. The adapter inherits only the host environment; it never receives Library content on its command line. |
| `operator` | Optional host-local human principal (`human_id`, `actor_id`). When present it grants the installation owner the Library human actions over the approved Projects only. |

`uas/local_library.py` builds the composition from that document
(`open_library`), and `uas.local_cli.run_host` constructs exactly one
`DeploymentLibrary` for the installation lifetime:

- `library.start()` runs before any Room binds. Absent, unsafe, unqualified or
  credential-less configuration raises there, so the host refuses to serve
  instead of running without its Library.
- Room Start publishes that Room's read-only projection through
  `DeploymentLibrary.start_room` before the Room's container starts, and unbinds
  it if the native start fails. Room Stop calls `stop_room` after the native
  stop, which releases only that projection; canonical content and the singleton
  keep running.
- The T22 operator endpoint in `<installation root>/library/operator` serves the
  authenticated installation owner with no Hub and no bound Room, including
  after a Room stopped.
- Host shutdown stops the remaining Rooms, then the Library singleton, then the
  Hub service owner.

The supervisor mints `scope_for` from an installation-authority origin over the
exact approved binding. That origin is used only inside the host service for
projection and scheduling authority; it never leaves the host, and a Participant
capture still requires the Room Hub's authenticated Participant origin.

### Not wired by this slice

The Participant `library.enqueue` route across the Room Hub process boundary is
not established here. The production Room Hub is the fixed-uid
`uas.workstation_service` process with its own hardened bootstrap and
`/uas/hub/room.db` ledger, and `AdmittedPeerDispatcher.attach_library` currently
requires the Library owner to share that in-process ledger. Connecting the
host's `EnqueueEndpoint` to it needs a new authenticated duplex channel carried
through the Hub startup document, with its own kernel peer verification, request
framing and bounded failure behaviour; that channel does not exist yet, so no
candidate claims it. `DeploymentLibrary._transport` report ingress is bound to
the running Room's ledger through `LocalController.ledger`, and a Room whose
ledger is unavailable stays replayable rather than losing its reports.

## Proof for the installed wiring

`tests/test_local_library_wiring.py` drives the real `run_host`, installation
selection, document admission, Room controller and T40 composition over a real
disposable canonical Git target, two configured Rooms and their real reference
mounts, with the native Room backend, Hub service owner and Manager owner as
controlled fixtures. It covers:

- host start and stop with two Rooms, each publishing only its own `library/`
  tree and `library.snapshot.json`;
- Room Stop leaving canonical head unchanged, the other Room's projection bound
  and the singleton running, plus an authenticated operator observation for the
  stopped Room;
- a missing referenced credential variable refusing to serve at all;
- false qualification evidence stopping the host before any clone exists;
- a document naming a foreign Room, an unknown credential or malformed
  qualification evidence refused by the closed selection schema.

It proves installed wiring and projection boundaries. It does not prove a VM,
Docker or live native Room, a live model provider, actual target qualification,
or the split-process Hub enqueue route above.
