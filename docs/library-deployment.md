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
working clone. Every new capture also revalidates qualification, the credential reference and
current settings at the endpoint's admission and publication authority
callbacks; the service loop rechecks them and fails closed,
operator controls run the same guard, and each composed runner and dispatcher is
bound to that live reader so the existing admission and publication fences refuse
a revoked qualification or an unavailable settings store even mid-attempt. An
in-flight attempt still pins its starting limits and filter versions.
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
expected to fail closed at target or model evidence admission; no fallback target, credential
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
ledger, a stop while a live model attempt is in flight (lease retained, second
instance refused, restart recovers and reports resume), revocation or loss of the
active settings store after the model returned but before publication (no
canonical commit), and recovery after a forcibly killed composed service process
(lease released, projection republished, stale operator socket replaced and
observation served).
The model runner is a deterministic fixture adapter; no live provider, installed
daemon, actual target qualification, split-process Room Hub transport, VM,
account, backup or deployment evidence is claimed here.

Run `PYTHONPATH=.:tests python3 -m unittest test_library_deployment` with the
repository requirements installed.

## Installed Deployment wiring (#252)

The installation selects the composition with one digest-pinned Library
deployment document. `installation.json` gains a `library` reference beside
`native`, `manager` and `runtime`; `uas.local_installation.selection`
admits it through the existing closed schema and `Installation.inspect` validates
the pinned bytes before any host effect. The installed host has no Library-free
mode: a selection that omits the reference is refused at `LIBRARY_NOT_CONFIGURED`
before the host serves.

The selected document is version 1 with these fields:

| Field | Content |
| --- | --- |
| `settings` | The complete Library settings document, admitted by the existing validator. Hosted egress needs an approval this document cannot grant. |
| `credentials` | Maps each referenced credential to the exact host environment variable names that carry its Git transport environment, limited to the admitted Git transport variables. Each reference must be a configured `git` credential; a missing variable fails the host closed. |
| `rooms` | Approved Rooms and their immutable source identity. Every configured Room must be bound, so no Room is left without an admitted Library by omission. The Project binding itself stays in the closed installation configuration, so paths, repository coordinates and Room ownership cannot drift from it. |
| `qualification` | Operator-supplied evidence for the exact target and branch it names: the target, the branch and the `qualified` flag. Establishing that evidence stays with #157; this wiring only refuses to run when it is absent, false or inconsistent. Failure happens at `TARGET_NOT_QUALIFIED` before any clone work. |
| `model` | The fixed synthesis profile, exact adapter argv and required `selection` path/SHA256 reference to separately established model evidence. The adapter never receives Library content on its command line. |
| `operator` | Optional host-local human principal (`human_id`, `actor_id`). Omitted, it is the installation owner, which grants the Library human actions over the approved Projects only; an explicit `null` disables the T22 endpoint. |

`uas/local_library.py` builds the composition from that document
(`open_library`), and `uas.local_cli.run_host` constructs exactly one
`DeploymentLibrary` for the installation lifetime:

- `open_library` refuses an installation that selects no Library, and
  `library.start()` runs before any Room binds. Absent, unsafe, unqualified or
  credential-less configuration raises there, so the host refuses to serve
  instead of running without its Library.
- The composition publishes every approved Room's read-only projection when the
  Library starts, so the first Room Start finds its projection current. A Room
  Start whose projection an earlier Stop released binds it again before the
  Room's container starts, and if that start or its Hub service fails the
  binding is released again; releasing a binding removes no content.
- Room Stop releases only that Room's projection, including when the native stop
  fails or is unconfirmed, so a Room whose outcome is unknown is never left
  publishing a projection. Canonical content and the singleton keep running, and
  the caller still receives the native error.
- The T22 operator endpoint in `<installation root>/library/operator` serves the
  authenticated installation owner with no Hub and no bound Room, including
  after a Room stopped.
- Host shutdown stops the Rooms it still owned, then the Library singleton, then
  the Hub service owner, and the proof records that order. A refused Library
  selection runs the same shutdown accounting, so a failed start cannot skip it.

The supervisor mints `scope_for` from an installation-authority origin over the
exact approved binding. That origin is used only inside the host service for
projection and scheduling authority; it never leaves the host, and a Participant
capture still requires the Room Hub's authenticated Participant origin.

### Authenticated installed Hub route

The selected Library binding is carried through the closed native Hub startup
document. The root owner supplies an anonymous, inherited Unix seqpacket channel
to its fixed-identity supervisor helper. That helper transfers a separate
connected descriptor to the actual Hub during the existing authenticated control
bootstrap. No filesystem listener, credential, mount, network route or host/LAN
exemption is added. Each record pins and rechecks the sending kernel process.

The Hub keeps its own canonical ledger and derives Participant authority through
its existing admission owner. The host reconstructs the immutable Project scope
from its selected Room binding, accepts only that Room's configured actors and
capabilities, and challenges the live Hub authority at capture fences. Capture
content is bounded and transient across the relay; no intermediary content queue
or autosave exists. Publication and projection receipts remain distinct, and an
uncertain disconnect is not a false rejection or successful commit.

Service reports return over that authenticated channel and are committed by the
Hub's own ledger owner. The root host does not create the Room database or its WAL
files. A stopped/unavailable Hub, foreign Project, timeout or uncertain reply
leaves the report replayable. Report-worker termination cannot retain a shared
mutex or turn an unrelated later acknowledgement into success.

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
- an installation selecting no Library refused before the host serves, and a
  missing referenced credential variable refusing to serve at all;
- false qualification evidence stopping the host before any clone exists;
- a Room restart after Stop republishing the same canonical generation;
- a failed native Stop releasing the projection while keeping the error and the
  running singleton, and a failed Hub service start releasing a rebound
  projection;
- an unsafe, group-writable service-state directory stopping the host before any
  clone exists;
- host shutdown stopping the Rooms it still owned, then the singleton, with the
  operator path still serving a Room that is not bound;
- a document naming a foreign Room, a Room outside the configured set, an
  unknown credential, a non-Git-transport environment name or malformed
  qualification evidence refused by the closed selection schema.

It also covers the default installation-owner operator path, an explicit `null`
that disables only the operator endpoint while the host and Rooms keep running,
and both Rooms' published roots so neither carries the other's Project. It proves the in-process wiring and projection boundaries, not actual native
host acceptance. Separate transport tests exercise the split-process channel.
Neither suite proves a VM, Docker/native Room, live model provider, or actual
target qualification. The candidate-pinned prepared-host result remains a
separate acceptance gate.

### External model-selection evidence

`model.selection` is an owner-controlled `{path, sha256}` reference, separate
from the installation/Room settings document. Its closed schema is:

- `version`: 1;
- `profile_sha256`: the existing `Profile.identity()` digest;
- `command_sha256`: the canonical digest of the exact fixed adapter argv;
- `selections`: one entry per configured immutable Project identity, containing
  `qualification`, `authorization`, and `hosted_approval` (null for a local route).

Each non-null entry uses the existing dispatcher `Evidence` fields:
`reference`, `profile_sha256`, `project_identity`, `valid_until`, `qualified`.
The consumer checks the existing qualification/profile reference contracts and
expiry rules. It does not manufacture a qualification result or turn a profile
name into evidence. The external T42/#171 owner still supplies the real result.

The evidence file must be a regular, owner-controlled, non-group/world-writable,
non-symlink file with the selected digest. Startup validates every configured
Project before clone work; each dispatch fence reads and validates the file
again. Missing, changed, expired or revoked evidence refuses dispatch and output
release. Replacing evidence requires deliberate re-selection of its digest and
host restart; this change provisions no model, account or authorization.

`tests/test_local_library_model.py` verifies the actual installed composition
through Attempts, a fixed deterministic adapter and real disposable Git,
including revocation after adapter contact. Its external evidence and provider
are explicitly synthetic. This proves evidence consumption, not actual model
quality, remote retention policy or target qualification.

### Actual prepared-host acceptance probe

`tests/native/library_installation_probe.py` is a separately opt-in probe for an
already prepared, disposable two-Room native installation. It retains all
`LocalNativeHost` checks, compares the candidate commit and clean tracked source,
starts the real foreground host and Rooms, observes the stopped Room through the
independent Library operator path, checks the sibling projection and performs
bounded orderly cleanup. It provisions nothing and must not run against an
unapproved existing installation. A source or unit pass of this script is not an
actual-host acceptance result; candidate-pinned execution evidence is required.

The installed native profile now requires the `reference` parent to be
`root:root` mode `0755`: the singleton publishes there and the Room receives the
existing read-only mount. Repo, workspace, checkouts and runtime retain the
shifted runtime UID/GID. Guided fresh preparation records this reference role in
its closed operation plan and only hands off a newly owned empty directory;
retries observe completed directories rather than repairing populated data.
Older runtime-owned reference selections fail closed and are not migrated by
startup. The disposable qualification profile's ownership contract is unchanged.
