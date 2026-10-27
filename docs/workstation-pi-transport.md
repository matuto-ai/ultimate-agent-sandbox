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
failure still closes resources and leaves the controller fenced. The concrete source `AdmittedHubLoop` now monitors the private control socket,
held Supervisor pidfd and admitted task/channel descriptors on the existing
ledger-owning thread. Bounded polls prioritize control EOF/revocation and task
exit over ready peer traffic; a still-pending bounded control batch defers peers.
It never reconstructs a process from selector descriptor integers. This loop is
not yet running in an admitted container/profile.

`SupervisorAdmission` serializes single ADMIT, authenticated STATUS and REVOKE
against the existing `ExecLaunch` journal. Intent is fsynced before FD transfer;
unknown ACK outcomes permit status only, never another ADMIT. ACK/status must
match the held Hub task, exact controller, operation, independent per-exchange
correlation ID and canonical durable receipt. A delayed earlier STATUS response
cannot satisfy a later STATUS after revocation/control change; it fails closed.
Correlation IDs are not bearer authority or a substitute for kernel identity. Local revoke fences before waiting for bounded control I/O. Persistence
failure closes control even when recording revocation fails; Hub EOF observation
fences transferred authority. The control channel and initial held Hub/Supervisor
origins must still be established by trusted container startup, not packet claims.

`ExecLaunch.attach_native` concretely attaches the existing Pi RPC receiver,
checks its fresh empty context proof and records bounded profile/scope/session
metadata plus digest in the same launch journal. Receiver, Engine stream and
native handoff journal remain Supervisor-only. A trusted profile digest is not
independent verification of the Node/Pi image; that qualification is still due.
Hub-local ADMIT attachment reuses `FixturePeerHub.connect` before ACK; its explicit
inbound-only receiver refuses delivery until an authenticated Supervisor delivery
bridge is independently wired. No callable or store handle crosses the wire.

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

No policy installation, VM launch, credential contact, paid provider or user-host
setting change has occurred in this source work. The first reviewed ingress source
was published as draft PR 108; the subsequent private integration candidate now
preserves remote main `4234e67127e9af4cd8de087b85c17da3d4490948` through verified
content-identical local materialization `cdc4d80ec519d6f6aae0e0785fff4045a55e3e35`,
base tree `415f5449977ba9fa1fb4c30eac3351f263d18cd0`. The six Run pause/resume files
are preserved. Existing Claude sources remain unchanged; README follows latest
main. Local synthetic ancestry is not remote history. The one draft integration
PR remains open; ordinary CI or initial ingress qualification does not complete
the frozen contracts or parent issues.


## First ordinary CI and next deliberate integration

Draft [PR 108](https://github.com/matuto-ai/ultimate-agent-sandbox/pull/108), head
`45dcf70c8515ff1a87b2a9b0769c60bac44677f1`, passed ordinary validate, Pi-native and
Claude-native runs `40379595504`, `40379595515`, `40379595747`. All six filesystem
bootstrap/listener cases passed in CI. These are not local listener results or
Docker/SELinux evidence. Later control/selector additions need their own review
and CI; the draft remains open through actual two-seat/outside-Hub integration.

The smallest deliberate guest scenario reuses the no-NIC Fedora/QEMU harness,
but needs a distinct native payload and resource profile, not changes to #98's
synthetic limits. The existing static `/fixture` image cannot run Pi or the Hub.
Required immutable payload contents are Node 24.22.1, locked Pi 1.4.0, fixed C
connector, extension/offline faux provider, Python Hub/standard-library closure,
ELF dependencies and fixed minimal init. The previous signed RPM closure includes
Python 3.14.8 and tini-static 0.19.0-12.fc44, but is not reproducibly pinned.

Before any Pi release, the scenario must admit the exact actual Engine package/API,
container images/labels/mounts, socket creation context and user mappings. Host
root maps to overflow UID in the sibling Hub namespace and is not acceptable as
an unchecked control sender. A deliberately mapped nonroot Supervisor identity
and immutable receiver-visible credentials are required. Stock-policy socket
connect, fd-use and pidfs permissions must be observed with same-Room positives
and sibling-Room negatives; no broad allow, permissive mode or relabeling the
Supervisor as runtime is a fallback. Startup/idle/turn/reset RSS, CPU, PID and disk
measurements must accompany the separately selected bounded native quota profile.


### Concrete deliberate native candidate (guest qualification pending)

`tests/vm/run_workstation.py` and `guest_workstation.py` reuse the pinned no-NIC
Fedora/QEMU carrier, but select `native-pi-v1` explicitly. The workflow accepts
manual dispatch or only the same-repository `qualify-native-workstation` label
from `puglab-reviewer`, checking out that exact event head. No push/synchronize
can trigger this heavy scenario. Root review and fast CI precede the label.

The native image is assembled from the hash-bound Node/Pi/source archive and
signed offline RPM roots with package scriptlets disabled by `tsflags=noscripts`.
RPM automatic sysusers remains enabled; it is distinct from package scriptlets. Exact file bytes, modes,
ownership and safe links form an external whole-rootfs manifest before import.
The fixed connector, service and probes all use `/uas/peer/pi.sock`. Hub startup
is fixed `/opt/uas/bin/tini -- /usr/bin/python3 -m uas.workstation_service`;
Engine attach/start conveys trusted startup metadata, while held SCM_PIDFD—not
container init PID—establishes the actual Hub task. Two Pi execs retain their
separate exact exec create/start/inspect corroboration.

The Room uses exact MCS `s0:c101,c102`; the DAC-equivalent sibling uses
`s0:c103,c104`. Guest-only trusted root setup requests socket object context
`system_u:system_r:container_t:s0:c101,c102` through `setsockcreatecon`, resets it
immediately, and never changes the Supervisor process domain. It labels only
owned endpoint/storage inodes `container_file_t` with exact categories. Any
stock-policy denial stops the scenario; no custom allow rule or fallback exists.
The endpoint directories/socket modes remain 0710/0620 and are read-only mounts
inside the Workstation. Mapped host identities are Hub 165531, Pi 165532 and
Supervisor 165533 (receiver-visible 65531/65532/65533). Actual maps and overflow
UID/GID settings are checked and bound into the immutable mapping digest. Actual
`/proc/self/status` must show CapEff/CapBnd zero, NoNewPrivs 1 and Seccomp 2 for
both Workstation and Hub; Docker create/inspect intent alone is insufficient.

Initial separately named diagnostic ceilings are Workstation 1 GiB RAM, 1 CPU,
128 PIDs, 256 MiB/8192-inode writable project quota; Hub 256 MiB RAM, 0.25 CPU,
32 PIDs, 64 MiB/2048-inode quota. Both have read-only images, no network, dropped
capabilities and no-new-privileges; bounded /tmp is separate tmpfs. These do not
change #98's small synthetic profile. Startup, idle and tool phases collect real
cgroup observations and inspect XFS enforcement/limits. Native reset/resource
sizing, quota exhaustion and production capacity remain unqualified.

The first frozen candidate (`a8d2f170`, tree `6d2d709c`) was **ingress only**:
Pi tool calls, exact retries and forged-Actor rejection were intended to reach
the outside Hub ledger, without recipient native delivery. Its deliberate run
40390271361 stopped in npm payload staging before launching a guest. It supplies
no native-container/stock-policy evidence. Ordinary CI passed separately.

The combined candidate `ab1a3d1c` (tree `65cef175`) subsequently passed all
ordinary CI, including 80 native Pi tests. Deliberate run 40392808660 completed
payload staging and guest boot, but stopped before native rootfs/Hub/seat tests:
the signed candidate pool contained `container-selinux-4:2.251.0-1.fc44.noarch`,
while the guest's actual RPM query showed `4:2.247.0-1.fc44.noarch`. The unversioned
DNF install had retained the older OS root. Engine `29.8.2-2.fc44` did match.
No stock-policy socket/pidfs test was reached and no AVC denial was observed.
The ten fallback failure entries are not ten individually executed checks.

The corrected native-only install requests the exact reviewed manifest-bound
NEVRA roots (including epoch and architecture), from the already signature-checked
offline pool, then checks actual installed equality before starting Docker.
Missing/ambiguous candidates or post-install mismatch fail closed. It neither
installs the union of dependency alternatives nor enables allowerasing, weak
dependencies or signature bypass. The default synthetic #98 installer remains
name-based and unchanged; candidate metadata alone never proves installed
versions. Deliberate run 40401426777 on `5c0d628e` subsequently verified both
actual installed exact roots, clearing that specific mismatch. It then failed
`native_rootfs.guest_guard` before rootfs construction or Hub/seat execution. The
logged guard bundled marker owner/mode/nonce and loopback-only checks, so its
individual failing subcondition is unknown. Docker had been explicitly started
first; a Docker-created bridge conflicting with `['lo']` is a source-order
hypothesis, **not an observed interface fact**. No AVC denial was observed.

The next source candidate defers only the native profile's explicit Docker start
until offline rootfs construction completes. Root identity, ordinary root-owned
0600 marker, exact nonce and `['lo']` checks are unchanged, with bounded individual
diagnostic facts added. Only then does the unchanged Engine startup/security
verification run. The default #98 order is unchanged. Main112's exact Pi extension
and related assignment sources are preserved, but no Broker capability is wired
into this Hub. The resulting new payload still requires its own qualification;
previous-head package or ordinary native evidence does not qualify this image.

Run 40405157482 on `fe66d938` then explicitly passed the strict guard (EUID 0,
root-owned ordinary 0600 matching marker and complete interface list `['lo']`),
and reached the offline rootfs RPM transaction. DNF returned `Rpm transaction
failed`; the helper's 2048-byte output tails lost the earlier cause. Rootfs
completion, Engine startup and native container/security/delivery tests were not
reached. No AVC denial was observed and runner cleanup completed. This is not
proof that no underlying permission error occurred: the useful error was lost.

The next candidate changes diagnostics only: this credential-free native DNF
call retains up to 64 KiB per stream (bounded head/tail with explicit truncation
and original byte counts), plus the first bounded RPM error lines even if they
occur in the omitted middle. It does not read arbitrary host logs or environment,
change packages, enable scriptlets, weaken signatures or alter policy. The root
cause remains unknown until a reviewed deliberate run captures it. The exact
main111 Claude-only overlay is preserved; its paths do not intersect the fixed
Workstation source/payload allowlist, but the diagnostic carrier itself changed.

The private next candidate adds one bounded authenticated Supervisor poll and
confirmation seam. `POLL_DELIVERY` requires the current exact admission and an
owned receiver safe-point observation. The Hub reuses its existing offer reducer
and holds at most one immutable pending offer per seat. The Supervisor alone
calls its native receiver's `accept`, outside admission and Room control locks.
`CONFIRM_DELIVERY` carries only the existing receipt and uses the same Hub confirm
reducer under fresh admission authorization with a pure transaction-time recheck.
Delivery replies are bounded at 64 KiB, sufficient for the existing 16 KiB
text contract including worst-case ASCII JSON expansion and bounded tokens.
ADMIT and incoming control commands retain their 8 KiB bound; oversized ingress
text is rejected before admission, not stranded as an undeliverable head item.
Each control exchange has its own correlation ID; the stable admission operation
is never retransmitted. Lost native outcomes use the existing native journal;
lost confirmation ACKs retry only that receipt, never reinjection. No new durable
workflow engine, Engine object, RPC receiver or Broker enters the Hub.

The revised deliberate scenario must prove Alice -> Bob -> Alice using each
recipient's `native-active-branch-and-session-file` receipt and matching exact
Hub ledger confirmation. `tool_execution_end` alone is not acceptance. These
source changes and injected-receiver tests are **not** actual native delivery
qualification. Actual inherited-FD transfer to another task must still fence
that seat; Workstation Stop must exit both held Pi tasks while the held Hub stays
alive, then explicit control EOF fences the Hub. Owned artifacts are cleaned up.
No new heavy run or publication is implied by this private candidate.


### Rootfs usrmerge correction after run 40411383492

The deliberate run on `2d7468c7` preserved the first useful RPM cause:
`filesystem-3.18-52.fc44` failed unpacking `/lib64` because that path already
existed as a directory. The strict guard and installed Engine/policy checks
passed. Docker had not started; native container/security/delivery checks were
not reached. Cleanup completed. The serial report truncated the beginning of
one diagnostic JSON record, but this cause survived in the retained output.

The source starts with an empty installroot. RPM can unpack libgcc before
filesystem, creating `/lib64`; disabling package scriptlets also disables the
filesystem pretransaction step that normally establishes usrmerge. This matches
the [RPM maintainer explanation](https://bugzilla.redhat.com/show_bug.cgi?id=1822951)
and [upstream empty-root reproduction](https://github.com/rpm-software-management/rpm/issues/3186).
The narrow correction seeds only `usr/lib64` and the relative `lib64 -> usr/lib64`
link in a fresh, owned, empty root before the unchanged offline transaction. It
refuses existing contents and never deletes, repairs or overwrites another
shape. The exact shape is checked again before runtime extraction. Package
scriptlets remain disabled; signatures, dependency checks, SELinux and default
synthetic #98 behavior are unchanged.

The same log reports a successful setup **automatic RPM sysusers helper**,
creating users/groups inside the disposable installroot. This is not evidence
of package scriptlets escaping `noscripts`, nor the fatal cause. The automatic
helper remains enabled and is reported separately; no macro/config override or
extra version pin is introduced. Actual installed `rpm`, `rpm-libs`, `dnf5` and
`libdnf5` NEVRA are captured as diagnostic facts rather than inferred from pool
membership. `rpm_scriptlets: false` means package scriptlets, while
`rpm_automatic_sysusers: true` discloses this separate mechanism.

Main115 is preserved. Its `uas/forge.py` change is a real staged runtime input;
the new PR-provider import remains deferred to Broker paths unavailable in this
Hub. The isolated selected-source configure/connect/submit/retry smoke passes
without adding provider modules. The changed image still needs fresh exact-head
qualification; no full-image byte identity or native delivery success is claimed.

Main116 is also preserved: its unconditional config import requires the explicit
`uas/gate_policy.py` staged source. The isolated smoke checks only staged files,
not checkout import fallback. Config, Gate module and carrier changes also
require the new image to be qualified; prior image proof is not transferred.

### Complete documented usrmerge aliases after run 40414751543

Run 40414751543 on `d5a3ae3e` advanced past the prior RPM conflict: the offline
package transaction returned successfully, runtime extraction completed, and the
whole-rootfs fingerprint then failed at missing `usr/sbin`. No rootfs manifest
completed and Docker had not started; no native confinement or delivery check
ran. Cleanup completed. Actual installed tools were RPM/rpm-libs 6.0.1-2.fc44
and DNF5/libdnf5 5.4.1.0-1.fc44, distinct from the newer RPM in the payload pool.
The original error did not identify its originating link, only the missing path.

The [Fedora 44 filesystem package](https://packages.fedoraproject.org/pkgs/filesystem/filesystem/fedora-44.html)
and its [f44 spec](https://src.fedoraproject.org/rpms/filesystem/raw/f44/f/filesystem.spec)
define the related x86_64 aliases. `sbin -> usr/sbin` is packaged, whereas
`usr/sbin -> bin` and `usr/local/sbin -> bin` are ghost paths established by the
pretransaction script, which this profile deliberately does not execute.
The fresh-root seed now covers six exact relative links: `bin -> usr/bin`,
`sbin -> usr/sbin`, `lib -> usr/lib`, `lib64 -> usr/lib64`, `usr/sbin -> bin` and
`usr/local/sbin -> bin`, with ordinary parents and target directories. It does
not recreate unrelated proc/sys/debug/runtime pretransaction effects or repair
an existing root.

Before runtime extraction the guest queries the installed, signature-verified
filesystem package header and pretrans text without executing it. Payload link
types/targets must match. Ghost paths must carry the ghost flag; their expected
targets come from the exact documented creation in the signed pretrans text,
not an assumed ghost payload mode or link target. Observed ghost header fields
are recorded separately, and actual on-disk symlink targets are always checked.
Metadata/script hashes bind this evidence. Fingerprint failures now identify
bounded root-relative originating link, declared target and missing path;
containment and existence checks remain unchanged. This is reviewed source,
not a successful image or native-container qualification.

### Signed optional ncurses debug indexes after run 40418174955

Run 40418174955 on `349942aa` advanced through installed filesystem metadata and
actual usrmerge shape validation, but the strict fingerprint found a missing
optional C++ target: `usr/lib/.build-id/47/437b4066718b825b28e816f46c58ab30a3f7cf`
points to `usr/lib64/libncurses++w.so.6.6`. The completed image manifest and native
containers were not reached; cleanup completed. This is not a SELinux denial.

The exact Fedora 44 [ncurses-libs 6.6-1 file list](https://packages.fedoraproject.org/pkgs/ncurses/ncurses-libs/fedora-44.html)
includes both C++ build-id links while excluding the C++ binaries. The separate
[ncurses-c++-libs file list](https://packages.fedoraproject.org/pkgs/ncurses/ncurses-c%2B%2B-libs/fedora-44.html)
contains those binaries and the same indexes. The [package spec](https://src.fedoraproject.org/rpms/ncurses/raw/f44/f/ncurses.spec)
explicitly splits `libncurses++*.so.6*` out of the base libs package. Only
ncurses-libs/base are in this image dependency closure; installing optional
libraries solely to satisfy debug indexes is unnecessary.

The correction represents **only these two frozen index paths** as unresolved
optional debug metadata when the target is absent: the `47/437b...` wide C++
index above and `f0/1d24b6f5c772ff3f9a9e452bac67d356a96a31` for
`usr/lib64/libncurses++.so.6.6`. The guest queries installed signature-verified
ncurses-libs metadata and requires exact owner, canonical path, symlink mode,
non-ghost flag and declared target. The full manifest records owner NEVRA,
header hash, exact declared/missing target and `unresolved-optional-debug-index`;
it does not pretend a runtime library exists. Existing targets resolve normally.
All other dangling links remain errors, and the same containment and loop checks
apply. There is no package addition, link deletion, generic build-id exemption,
scriptlet enablement or security-policy change. Actual ownership for the previous
failed guest was not separately logged; the new check must establish it in the
next exact-head qualification rather than infer it from the web file lists.

### Coreutils split index and bounded failure inventory

Run 40421159623 on `ef5551f1` passed the prior ncurses traversal and next failed
at `usr/lib/.build-id/f2/ced0172d0e9e58f7a646abd3b7dea17799d34f`, pointing to
missing `usr/bin/coreutils.single`. Guard and installed Engine/policy checks
passed; no completed image, Docker startup or native scenario was reached.
Cleanup completed. The ten fallback report failures are not ten executed tests.

The [exact Fedora coreutils 9.10-5 file list](https://packages.fedoraproject.org/pkgs/coreutils/coreutils/fedora-44-updates.html)
contains this build-id but not the optional single binary. The [f44 spec](https://src.fedoraproject.org/rpms/coreutils/raw/f44/f/coreutils.spec)
excludes `*.single` from coreutils and assigns it to the separate, conflicting
coreutils-single package. This one frozen index now uses the same explicit
unresolved-debug representation, but requires its own installed signed
**coreutils** owner/path/target evidence, never ncurses owner reuse. No extra
package is installed, and no other build-id path is exempted.

Unknown missing targets are now inventoried before fingerprint failure instead
of failing on only the first. The scan still never returns a manifest when any
unknown missing target exists. It retains at most 16 facts and 60,000 encoded
bytes, reports total count and explicit truncation, and queries exact installed
owner/header path+target for retained paths only (fixed RPM query, 10-second
per-query limit, bounded metadata and owner count). Owner-query failure remains
a diagnostic fact, never authorization. Escapes, cycles, special files and
other containment violations still fail immediately. This is bounded diagnosis,
not a generic dangling-link exception or an assertion that missing executables
exist. Actual exact image/native qualification remains pending.

### Serial-stall instrumentation after run 40423347331

Run 40423347331 on `63e889f2` ended at the runner's unchanged 300-second serial
inactivity guard. Last guest facts were the passed rootfs guard and actual
RPM/DNF identities. No completed rootfs or unresolved-link inventory was emitted;
the silent phase and underlying cause remain unknown. QEMU termination and
scratch cleanup completed. This does not establish hidden guest progress.

The previous helper captured DNF output until exit, while native installation
has a 900-second process deadline. Instrumentation now emits fixed start/complete
markers for each rootfs phase. Only the fixed native DNF call uses incremental
bounded stdout/stderr capture, retaining head/tail and first error lines while
reporting byte counters only after actual received output advances. No timer-only
heartbeat is emitted. Extraction and fingerprint progress similarly counts real
verified file bytes and processed entries; phase completion is not printed after
a failed operation. Native DNF timeout still kills its owned process group,
reaps the leader and closes all resources, retaining bounded error context.
The native 900-second process limit, runner 300-second idle limit and global
manual budget remain unchanged. Default synthetic #98 command behavior is
unchanged. No arbitrary log, environment or credential collection is introduced.
These are visibility changes, not proof the previous stall was load-related or
that any native/container qualification has passed.

### Required trust/configuration generation after run 40426350440

Run 40426350440 on `03f2a04b` completed the RPM transaction, signed filesystem
metadata checks, runtime extraction and tini copy. Fingerprinting processed
24,786 entries / 373,067,696 bytes and reported all six unresolved links (not
truncated). Cleanup completed in 594.05 seconds. No container, kernel-origin or
native-delivery scenario was reached. The absence of a serial stall in this run
does not establish the cause of the preceding stall.

The installed signed-header inventory identified:

| Link | Missing target | Installed owner |
|---|---|---|
| `etc/pki/tls/fips_local.cnf` | `etc/crypto-policies/back-ends/openssl_fips.config` | `openssl-libs-1:3.5.9-1.fc44.x86_64` |
| `etc/pki/java/cacerts` | `etc/pki/ca-trust/extracted/java/cacerts` | `ca-certificates-0:2026.2.92_v9.0.319-2.fc44.noarch` |
| `etc/ssl/cert.pem` | `etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | same CA package |
| `etc/ssl/certs/ca-bundle.crt` | same PEM target | same CA package |
| `etc/ssl/certs/ca-bundle.trust.crt` | `etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt` | same CA package |
| `etc/ssl/certs/ca-certificates.crt` | same PEM target | same CA package |

These are required runtime configuration/trust links, **not optional debug
indexes**. They remain strict: no exemption, deletion, dummy CA material or
placeholder backend. With package scriptlets still disabled, the native profile
explicitly includes signed `crypto-policies-scripts` and invokes supported tools
inside the fresh guarded no-NIC installroot. The [Fedora crypto-policies spec](https://src.fedoraproject.org/rpms/crypto-policies/raw/f44/f/crypto-policies.spec)
identifies DEFAULT generation; the [Fedora update-ca-trust source](https://src.fedoraproject.org/rpms/ca-certificates/raw/f44/f/update-ca-trust)
and [p11-kit trust manual](https://p11-glue.github.io/p11-glue/p11-kit/manual/trust.html)
supply the three extract operations below. The broader update-ca-trust script is
not executed, avoiding unrelated hashed-directory and additional-format changes.

All four fixed commands use `/usr/bin/chroot /var/lib/uas-native-rootfs`, then
`/usr/bin/env -i` with only fixed PATH, LC_ALL, HOME and
`P11_KIT_NO_USER_CONFIG=1` values. Their inner argv are:

```
/usr/bin/python3 -B /usr/share/crypto-policies/python/update-crypto-policies.py --no-reload --set DEFAULT
/usr/bin/trust extract --format=openssl-bundle --filter=certificates --overwrite --comment /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
/usr/bin/trust extract --format=pem-bundle --filter=ca-anchors --overwrite --comment --purpose server-auth /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
/usr/bin/trust extract --format=java-cacerts --filter=ca-anchors --overwrite --purpose server-auth /etc/pki/ca-trust/extracted/java/cacerts
```

The three CA outputs must be absent before invocation despite the documented
`--overwrite` option. Tools and packaged trust input are checked against installed
RPM header SHA-256 digests, relying on the preceding signature-verified offline
transaction. This is not a fresh signature verification of the RPM database.
Bounded before/after whole-root inventories allow changes only in
`etc/crypto-policies` and the three exact CA files; expected directory timestamps
are excluded, while modes, owners, bytes and link changes remain checked.
Unexpected changes fail before image import. Generated targets must resolve
inside the root to ordinary nonempty files. The final strict link fingerprint
still applies without any new unresolved-link exception.

Each fixed child has a hard 90-second deadline with bounded output and owned
process-group cleanup. Only actual received byte deltas produce progress, never
a timer-only heartbeat. Default synthetic #98 commands, native DNF's 900-second
limit, serial idle limit and global round budget are unchanged. No shell, host
mount/configuration, user trust store, guest fetch, broadened weak dependencies,
generic package scriptlets or security-policy relaxation is involved. Actual
signed-tool execution and the resulting image remain **unqualified** until the
next reviewed exact-head deliberate run.


### Fixed packaged Python entrypoint after run 40429443685

Run 40429443685 on `e9605e77` completed the RPM and filesystem phases, then
failed the first trust command. `/usr/bin/update-crypto-policies` is a shell
wrapper: the captured line 3 invokes
`/usr/share/crypto-policies/python/update-crypto-policies.py`. Passing the wrapper
to Python produced a SyntaxError (return code 1, complete 277-byte stderr).
The failure inventory recorded zero changed files across 8,467 entries /
133,925,307 bytes. Cleanup completed in 560.145 seconds. Trust output validation,
image completion, container security and native delivery were not reached.
Individual verified-input owner/digest details were not separately emitted.

The fixed argv now passes the observed packaged Python entrypoint to Python 3
with `-B`, unchanged DEFAULT/no-reload options and no shell. The
[f44 package file declaration](https://src.fedoraproject.org/rpms/crypto-policies/raw/f44/f/crypto-policies.spec)
places this Python subtree in crypto-policies-scripts. Its actual installed
owner, header digest and mode are independently checked before execution, in
addition to the retained wrapper provenance check. No executable path is chosen
from wrapper content or peer input. All other fresh-output, mutation, containment,
strict-link, signature, deadline and environment checks remain unchanged.
This source correction is not evidence that actual generation has passed.

### Signed pre-generated DEFAULT after run 40431200029

Run 40431200029 on `94067032` passed the RPM transaction and signed filesystem
metadata checks. The corrected Python entrypoint executed, then failed before
policy mutation: its `is_fips_auto_bind_mounted()` opens
`/proc/self/mountinfo`, which is absent in the deliberately mount-free chroot.
The complete 973-byte stderr identifies `FileNotFoundError`; the failure
inventory reports zero changed files across 8,466 entries / 133,924,742 bytes.
Runner scratch cleanup completed in 870.452 seconds. Trust validation, runtime
extraction, final fingerprint, Docker startup and native delivery were not reached.

The live-system updater has no offline application option. Its separate build
entrypoint generates backend text and invokes backend-specific test tools, not
fresh installed policy state. Neither is necessary for a fixed DEFAULT image:
the [Fedora 44 package contract](https://src.fedoraproject.org/rpms/crypto-policies/raw/f44/f/crypto-policies.spec)
already installs signed pre-generated DEFAULT assets, and its post-install
initialization maps these assets to the corresponding ghost backend paths.
The [exact package file list](https://packages.fedoraproject.org/pkgs/crypto-policies/crypto-policies/fedora-44.html)
contains 13 DEFAULT backends and their ghost destinations.

The current implementation supersedes the updater invocation above. It accepts
only `bind`, `gnutls`, `java`, `krb5`, `libreswan`, `libssh`, `nss`, `openssh`,
`opensshserver`, `openssl_fips`, `opensslcnf`, `rpm-sequoia` and `sequoia`. It checks
the installed crypto-policies owner, SHA-256 algorithm, each ordinary asset's
mode/digest, the complete fixed DEFAULT directory and all 15 exact ghost
contracts (13 backend targets, config and current marker). All outputs and their
canonical parents must be fresh/ordinary as applicable before writing anything.

It copies the exact signed `default-config` bytes to `etc/crypto-policies/config`
after verifying that its only non-comment directive is DEFAULT. The current
marker contains only `DEFAULT\n`, matching package initialization rather than
copying configuration comments. Each backend receives its exact absolute
in-image `/usr/share/crypto-policies/DEFAULT/<name>.txt` link. No backend crypto
content is handwritten or fetched; no `CURRENT.pol` dump or updater-parity claim
is manufactured. This is explicit fixed package-default materialization, not
execution of general package scriptlets.

The package intentionally hardlinks some data assets. Before accepting these,
a bounded whole-root inventory counts every device/inode occurrence and rejects
external or changing hardlinks; the same proof runs afterward and the final
strict fingerprint still applies. This does not relax the single-link ordinary
checks for executable tools, runtime archives, tini or fresh CA files.

The three CA extract commands, clean environment and 90-second child deadlines
remain unchanged. The unused explicit crypto-policies-scripts RPM root, updater
execution and wrapper/Python verification machinery are removed. The mutation
allowlist is narrowed to exactly 18 generated paths: 13 backend links, config,
current and the three CA outputs. Other crypto-policy subtree changes, including
any `CURRENT.pol`, fail closed. Post-generation checks also verify the exact
config/current bytes and all backend targets; permitted paths cannot silently
change to another in-root policy. Partial materialization/command failures retain
bounded before/after inventory. No proc fabrication/mount, host trust import,
policy change or native security weakening is introduced. Pure tests do not
qualify actual package materialization, CA execution or native delivery; a fresh
reviewed exact-head deliberate run remains required.

### Completed rootfs, bounded image-import failure: run 40436690890

The [exact-head native run](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40436690890)
on `f607de9d` completed the signed RPM transaction, filesystem contract,
signed pre-generated DEFAULT materialization, all three CA extracts and their
strict postchecks, runtime extraction, tini copy, debug-index checks, final
strict fingerprint and manifest write. This qualifies that image-build sequence
in the disposable guest, not a successfully imported image or native delivery.

Docker 29.8.2 started and its Engine/profile checks returned. The unchanged
`docker import /var/lib/uas-native-rootfs.tar` client then exceeded its 120-second
deadline. No image ID was returned; no Workstation/Hub containers or native
two-seat checks were reached. Retained daemon logs show successful startup, not
an import-specific cause. No disk-full, OOM or AVC cause was established; missing
AVC output is not proof of no denials. The runner removed its temporary directory
after 1,255.683 seconds, destroying the disposable VM and any uncertain in-guest
import. This is not evidence that terminating the CLI cancelled daemon work.

The completed manifest digest, exact final entry/byte totals, installed trust
input digests and archive size/hash were not emitted before that failure. The
manifest was subsequently cleaned up. Periodic fingerprint counters are not
final totals and cannot reconstruct the missing evidence.

The next diagnostic candidate emits the complete bounded rootfs/trust result
before archive/import, as ordered JSON fragments with an overall digest. It
records the completed archive's actual size and SHA-256, fixed phase boundaries,
and start/end daemon CPU/I/O plus filesystem free-space facts. Daemon observations
use a held pidfd and proc-directory descriptor, fixed `stat`/`io` names, matching
task start time and before/after exit checks; unavailable or changed tasks produce
explicit unknown diagnostics, not guessed counters. These facts are diagnostic
only and do not grant authority, qualify liveness or reset a deadline.

The file-argument import and 120-second limit remain unchanged. Only this exact
native argv opts into the existing bounded-output, owned-process-group runner;
failure kills the owned CLI group before reaping and reports client cleanup
separately from the unknown daemon outcome. Fixed, five-second journal/AVC reads
retain bounded failure summaries, including empty/nonzero/unavailable results.
Import observations and output are best-effort: diagnostic sample/log/write/close
errors cannot replace the original import exception or prevent a confirmed image
ID from reaching the caller for cleanup. Unavailable markers are emitted when
the output channel permits; no successful diagnostic result is manufactured.
Actual command/process-resource cleanup failures remain distinct from writer
failures and are not silently declared successful.
No polling heartbeat, stdin transport change, timeout increase, arbitrary log
collection, custom policy, proc mount, confinement change or retry is introduced.
The original outer/serial limits and final disposable-VM cleanup still apply.
Pure/mock diagnostic tests do not establish an import cause or native success.
