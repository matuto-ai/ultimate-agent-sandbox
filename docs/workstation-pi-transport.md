# Workstation Pi transport — private source, not qualified

This source advances #62/#63/#70; it does not complete #58, #78 or #81. No real
two-Pi Docker-to-outside-Hub execution is established. Participants within one
Workstation are trusted peers, not mutually memory-isolated. A bootstrap
challenge is launch correlation, never bearer authority; no nonce-secrecy or
malicious-in-process-influence immunity is claimed.

## Preferred topology: separate ordinary confined Hub container

Run the Hub in its own unprivileged control-plane container **outside** the
Workstation, with separate PID and mount namespaces. Keep stock `container_t`
and the exact same single-level Room MCS pair for Hub, Workstation and the narrow
peer endpoint. Other Rooms receive distinct disjoint pairs. No bespoke host
SELinux domain or allow rule is proposed unless observed stock-policy evidence
establishes a concrete need and that minimal change is independently reviewed.

This follows [#62](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/62)
(endpoint ownership/mode, kernel-peer support, narrowly labelled transport and
normal outer confinement) and
[#63](https://github.com/matuto-ai/ultimate-agent-sandbox/issues/63)
(immutable Actor binding, wrong-process denial, replacement and revocation).
Neither requires custom type names or host-native Hub execution.
[Boundary ownership](architecture/security-boundary.md#boundary-ownership)
requires Hub/ledger outside Workstation and Hub/Broker as separate unprivileged
identities in a Room-scoped control-plane sandbox. It permits this topology.

| Component | Resources | Explicit exclusions |
| --- | --- | --- |
| Supervisor | Engine client, launch journal, lifecycle/native RPC adapter, held task objects | No Engine object/socket, callable or control-store FD crosses admission |
| Hub container | Private Room ledger volume, authenticated private control endpoint, admitted Pi channel/pidfd | No Engine mount, Actor credential table, Workstation writable runtime/project mounts |
| Workstation | Approved Project/runtime paths and narrow **read-only endpoint directory** mount | No Hub ledger/configuration/control socket; no host PID/network/IPC, devices or privileged mode |
| Broker | Separate unprivileged identity and independently enforced Room/Actor/repository authority | Hostile Hub cannot choose credentials, issue Actor authority or clear Broker epochs |

Keep non-root identities, dropped capabilities, no-new-privileges, normal
seccomp/SELinux confinement, Room-owned network policy and hard resource bounds.
Only the narrow endpoint is shared—not Hub state. Endpoint parent/socket retain
exact 0710/0620 modes and trusted owner/group validation. Read-only mounting
protects filesystem mutation; it does **not** make socket communication read-only.
Hub survives ordinary Workstation Stop; both remain independently owned lifecycle
resources. Broker credentials never enter either Hub or Workstation.

### Stock-policy tradeoff and unresolved gates

Same type/category does not itself isolate Hub from Workstation: separate
namespaces, different unprivileged identities, exact mounts and descriptor
ownership provide that inner control-plane separation. An accidentally shared
ledger is a serious failure, not an accepted trusted-peer risk.

Upstream [container policy](https://raw.githubusercontent.com/containers/container-selinux/main/container.te)
contains intra-type Unix-stream connection permissions. Reference
[MCS constraints](https://raw.githubusercontent.com/SELinuxProject/refpolicy/master/policy/mcs)
use category dominance, not universal equality. These are design references,
not observations of the selected guest. Admission must enforce exact reserved
pairs; reject reused pairs, empty categories, supersets, broad ranges and
unconstrained processes. No `:z` shared label, `label=disable`, permissive domain,
`spc_t`, `unconfined_t`, 0666 endpoint or broad allow workaround.

The following remain explicit qualification gates—no success is assumed:

1. **Socket creation context:** capture the actual Supervisor-created socket
   object SID, inode/parent labels and Room categories. Determine whether trusted
   creation in the needed stock container context is permitted without broad
   changes. Do not grant every container access to a Supervisor-domain socket or
   relabel Supervisor as the container runtime to inherit broad privileges.
2. **Descriptor transfer:** capture the actual Supervisor and Hub process labels,
   exact `fd use` checks and socket read/write/getopt/setopt permissions for the
   private channel and handed-off peer FD. `fd use` cannot by itself restrict
   descriptor kind: the fixed two-FD decoder and absence of ambient inheritance
   are also mandatory. No `domain:fd use` wildcard proposal.
3. **Process objects:** observe the held pidfs inode/filesystem SID and actual
   permissions for SCM_PIDFD reception, fstat, fstatfs and poll. Do not guess
   `pidfs_t`, `anon_inodefs_t`, `kernel_t` or `unlabeled_t`, or add blanket ioctl,
   process, ptrace, signal, pidfd_getfd or setns access to make a test pass.
4. **Real receiver mapping:** pin namespace identity, user/group maps and actual
   overflow UID/GID configuration for the selected Hub/Workstation setup.
   No translation is verified by a JSON claim or by injected unit-test metadata.
5. **Deliberate negatives:** own-Room traffic succeeds; sibling categories cannot
   connect even when a test-only path and DAC access are provided; Workstation
   cannot mutate endpoint or open Hub state/Engine; same-UID wrong-process,
   fork/passed-FD, exit, replacement and revocation cannot acquire another Actor.

Host/private/metadata/sibling-network denial, quota enforcement and resource
limits remain separate required proof, not consequences of this transport.

## Namespace-aware kernel binding

`kernel_origin.py` uses real SO_PASSCRED + SO_PASSPIDFD records and stable held
pidfs objects. Its source ABI remains x86-64/64-bit pidfs; unsupported support
fails closed. Same-namespace defaults still compare the entire credential tuple.

The explicit frozen `ReceiverIdentity` is trusted admission configuration:
expected receiver-visible UID/GID, receiver context, mapping-observation digest
and configured overflow UID/GID. Its values cannot come from a Participant.
The ADMIT receiver compares transmitted metadata against its already configured
value; it never adopts a caller-selected mapping. Root/overflow identities are
rejected. The real preflight must verify those mappings, including non-default
overflow settings; the dataclass does not perform namespace inspection.

In explicit receiver-namespace mode, every packet must match both the held pidfs
object and configured receiver-visible UID/GID. Numeric SCM PID may be zero in a
sibling PID namespace: it is neither looked up nor treated as authority. Exact
Engine exec/container/host-PID corroboration remains Supervisor-side, where that
PID is meaningful. No PID scan, PID reuse assumption or init-PID Actor authority
is introduced. The old `participant.py` same-UID guards remain unchanged.

### Startup probe choice

Prefer a fixed, pinned minimal init in the future Hub container profile, with Hub
as its ordinary child, for normal orphan reaping. The current capability probe
can then compare its own pidfd against its known parent object. There is no
selected/qualified init payload yet. A Hub started as namespace PID1 with parent0
now explicitly fails capability admission (`qualified Hub init required`) rather
than invoking pidfd_open(0), pretending support, or scanning for another task.
No fallback fork/probe or runtime-profile change is introduced in this slice.
The init binary/digest, lifecycle and actual startup capability result still
require deliberate container qualification.

## Single authenticated ADMIT

`workstation_admission.py` is a private source library, **not yet a deployed Hub
control service**. Its decoder is separate from ordinary participant receive,
which continues to reject SCM_RIGHTS. All socket/namespace/SELinux preflight
above remains required; the library does not manufacture that evidence.

1. Supervisor preflights the immutable Room boundary and journals intent before
   exact Engine exec create/start. Fixed connector disables dumpability before
   challenge input, rendezvous on seqpacket, then awaits explicit release.
2. Supervisor holds the received kernel task and corroborates exact exec ID,
   ContainerID and host PID while live. It releases the connector into fixed
   Node/Pi execve in the **same task/FD**, verifies fresh native readiness over its
   own RPC transport and durably records it. Hub has no peer FD or authority yet.
3. Supervisor journals a single admission operation and sends one authenticated
   `ADMIT` record with exactly two SCM_RIGHTS FDs: connected peer channel and
   duplicate held runtime pidfd. Kernel SCM_PIDFD/SCM_CREDENTIALS authenticate the
   control sender separately. Bounded metadata contains immutable seat identity,
   profile/capabilities, receiver mapping, incarnation/epoch, readiness digest
   and expected pidfs identity—never Engine access, credentials or store handles.
4. Hub authenticates the held Supervisor task, validates the exact schema against
   trusted local seat/mapping configuration, validates CLOEXEC, FD count/order,
   connected Unix seqpacket type, runtime object identity/liveness, current local
   endpoint lease and monotonically increasing epoch. An already active held
   pidfs object cannot be installed under another Participant/Actor seat. It commits a durable
   receipt and installs the in-memory binding under one serialized lock before
   enabling dispatch. It returns `ADMITTED`; the enclosing control loop sends ACK.
5. Lost ACK is **unknown outcome**. Read-only operation-ID status can reconcile
   the receipt and whether this exact controller still has the live binding.
   There is no automatic resend or relaunch; a duplicate ADMIT is refused with
   instructions to read status. After ACK, Supervisor closes its duplicate peer
   channel but retains lifecycle responsibility and held-task reference.

There is no Hub PREPARE phase: connector release/native readiness do not need one.
Supervisor never dispatches queued participant records and must stop reading the
peer channel before handoff; retained duplicates must not create two consumers.
A full queue is bounded availability failure, not grounds to grant early authority.
Queued packets undergo current Run/context/epoch checks after installation, and
native delivery still follows the independent safe-point gate.

### Source durability and fencing

The Hub journal contains receipts, not recoverable process authority. An
exclusive controller lease prevents concurrent owners; journal scope pins Room,
instance and Participant→Actor identity. Restart fences historical receipt state
and never recreates FDs/PIDs. A receipt surviving a crash between commit and
in-memory installation does not become an active binding.

Transport receive/decode runs outside the authority lock, so a stalled private
control read cannot block revocation or control-loss fencing. Installation then
rechecks the current controller, Supervisor and endpoint under that lock. The
trusted application uses `authorize()` through the consuming ledger transaction,
serializing dispatch against revocation. Endpoint loss, Supervisor
loss/revocation, malformed control traffic or control EOF fences admission.
Revocation fences memory before durable projection and disposal; persistence
failure still closes resources and leaves the controller fenced. The external
control loop must detect EOF/errors promptly and call `control_lost()`—a library
method alone is not a complete live connection monitor. It also owns serialized
send/revoke operations, pre-send journal intent and authenticated ACK/status
framing. These orchestration pieces remain integration work.

Tests prove a strict two-rights decoder, FD closure on rejection, Actor/mapping
mismatch denial, actual same-UID wrong control sender denial, queued-record
installation, absent/third/swapped/file/substituted/exited task FDs, malformed and
oversized packets, ACK-loss read-only status, pre/postcommit failure, restart,
controller exclusion, revocation/endpoint loss, stalled-read fencing and control
EOF. Partial close-failure cases verify every owned descriptor receives its one
cleanup attempt and DB close failure cannot strand the exclusive controller
lease; uncertain fd close is never blindly retried. Tests using
receiver-visible PID0 or alternative UID/GID are explicitly **injected projections,
not executed cross-namespace or stock-SELinux proof**.

## Thin existing-Hub dispatcher

`workstation_peer.py` receives Pi's existing request-ID/envelope framing and
passes its unchanged typed traffic into `FixturePeerHub.submit` and
`RoomLedger.apply`. Actor, capabilities and effective authority version derive
only from the frozen admission binding. Trusted orchestration attaches the
existing current Hub connection/context generation; a packet cannot create one.
There is no second workflow reducer, launch API or Engine/RPC object in this
adapter, and Forge remains unavailable until its independent Broker is wired.

Peer receive and reply I/O stay outside the authority lock. The dispatcher holds
admission authorization across the consuming ledger transaction; its fresh
transaction-time `recheck()` is pure, performs no authority-store writes and
acquires no lock in reverse order. Authority failure rolls back the existing
ledger transaction before lifecycle fencing occurs. Exact retries/conflicts,
Run/context freshness, WorkRequest state and receipt durability remain the
existing Hub's decisions; losing a reply cannot retract a committed receipt.

The source integration test uses **two distinct owned Python child task origins**
with real kernel pidfds, not two sockets from the same process. It proves exact
Actor attribution, rejected forged fields/wrong origins, duplicate-task admission
denial, late revocation, process exit after ledger BEGIN, and nonblocking
revocation during stalled peer receive/reply. These children are not Pi and do
not supply container/namespace/SELinux proof or outward native safe-point delivery.

## Engine and payload qualification

`docker_exec_api.py` implements bounded API 1.48 non-TTY upgrade/multiplex framing
and partial-constructor FD/thread cleanup. Source reference
[Moby v28.0.0 exec route](https://raw.githubusercontent.com/moby/moby/v28.0.0/api/server/router/container/exec.go)
emits 101 UPGRADED with the multiplexed content type for non-TTY API >=1.42.
Parser checks that type and rejects Content-Length/Transfer-Encoding ambiguity.
An HTTP upgrade precedes actual exec start and is not task/readiness proof.

No reproducibly pinned native-integration Engine binary exists in this checkout.
The independent [synthetic boundary snapshot](vm-network-quota.md#successful-synthetic-qualification-snapshot)
qualified Docker 29.8.2 / Fedora moby-engine 29.8.2-2.fc44 with container-selinux
2.251.0-1.fc44 under normal NAT, userns and enforcing MCS. Its recorded package
closure is not an immutable native payload or exec-handshake qualification;
exact package/hash/API and actual handshake remain required before this launch
can be promoted. Node binary/hash,
Pi 1.4.0 lock/package contents, connector, extension, offline guard and account-free
faux provider must likewise form an immutable selected image payload.

Measure real two-seat startup/idle/turn/reset RSS, CPU, PID and disk use under a
**separate native resource profile**. Do not silently inflate #98's small
synthetic limits or call local RSS observations enforced Docker quotas.

## Evidence and local restrictions

Local real socketpair kernel/ADMIT tests and Engine doubles are separated from
native host-fixture Pi regressions. C connector compiles with warnings as errors.
None establishes actual two-Pi Workstation/Hub execution, confinement or release.

Filesystem AF_UNIX SOCK_SEQPACKET listener integration remains **UNEXECUTED**:
the prior attempt returned EPERM and the one escalation failed infrastructure
before execution. No further listener attempt, escalation, alternate transport
or bypass is authorized here. Later ordinary authorized CI may test a supported
listener platform; that must not be reported as local success.

No policy installation, VM launch, publication, credential contact, paid provider,
user-host setting change or release qualification occurred. This private candidate now overlays remote main
`f265b0ce262c2160e5136c167028dc84c38eb9e3` through verified content-identical local
materialization `98246772efd8ac8bb13545f559a17eb0cb52264b`, base tree
`f61f8c0bacf01309b7501781ce4a50ea24b9f0c5`. All 22 Claude/main files are preserved;
all 16 incoming #98 files were verified byte/mode-identical before the explicitly
requested successful-snapshot documentation correction. Local synthetic ancestry
is not remote history, and no remote branch was changed. The future single draft
integration PR must remain open through actual two-Pi/outside-Hub integration,
not treat source or ordinary CI listener tests as completed qualification.
