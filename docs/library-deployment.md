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
