# Composed Room launch fixture — candidate, not qualified

This is the original #62 fixture boundary, not an installation or production
readiness gate. It reuses the existing `Supervisor`, `DockerFixtureBackend`,
`GuestBoundaryBackend`, kernel-origin and endpoint-lease implementations. The
previous synthetic network/XFS and native-Pi endpoint results do not qualify
this combined candidate. No acceptance checkbox is complete from this document.

## Selected source

`RoomLaunchFixtureBackend` binds one immutable, bounded fixture resource profile
and a nonempty set of retained, actually bound Room endpoint objects. The same
profile digest binds lifecycle intent and actual Docker labels. It rejects
unqualified endpoints before creating resources, and repeats actual endpoint,
network, XFS, identity, confinement and mount admission before Start/resume.

The baseline Docker fixture retains network-none, read-only Project mounts and
its original resource limits. Private backend hooks supply exact additional
read-only endpoint mounts and selected memory/CPU/PID/log limits; they are not
request flags, a configuration override API, or a validation receipt. The guest
backend retains the existing user-namespace remap and quota-escape checks.

Endpoint directories contain only their selected socket leaves. Their exact
ancestor ownership/modes, parent/socket lease, Room file labels, listener type
and mandatory kernel credential/pidfd support are rechecked. A read-only bind
protects the socket directory from filesystem mutation, not from communication.
A successful metadata check alone is not a successful Broker call: actual
service readiness and same-Room positive/sibling negative transport remain
mandatory guest checks before admitting Participants.

The listener reuses `guest_workstation.labeled_listener`: trusted setup selects
the exact `container_t`/Room MCS **socket-object** SID with `setsockcreatecon`,
then resets the creation context; the Supervisor process label is not changed.
The socket pathname and directory separately carry `container_file_t`/Room MCS.
Every canonical admission observes the retained listener's exact socket SID via
`security.selinux` on its open descriptor; missing, foreign or malformed labels
fail closed. Connected `SO_PEERSEC` observations alone cannot establish the
listener's original MCS because an accepted child may inherit the client's MLS
range. The Supervisor separately observes connecting Participant socket SIDs
on accepted sockets. These observations do not infer either process label
from a filesystem `chcon`; actual process labels are recorded separately.

After the held bootstrap's pidfd signals exit and service/Broker teardown has
completed, a locked trusted-root admission/drift negative temporarily parks the
original leased socket inode outside its mounted directory. A disposable
Beta-SID socket occupies the same Alpha pathname, with an Alpha filesystem
label. The held descriptor establishes its Beta socket SID. This deliberately
models trusted-host pathname tampering,
not an operation available to the confined Participant: host/Supervisor takeover
is outside the accepted threat boundary. It does not require an independent
kernel socket-object category denial after root supplies an Alpha pathname.
The replacement must fail both the original inode lease and canonical admission
with a fresh lease. Caller-owned evidence retains actual labels and the bounded
probe return code, timeout, stdout/stderr and decoded result before assertions.
The raw transport outcome is explicitly observational: `connected: true` means
the raw connection succeeded, never that it was denied or authenticated. Capture
integrity and owned cleanup remain required, regardless of transport outcome.
A bounded read-only diagnostic records fixed libselinux decisions and actual
loaded/installed policy metadata; it never repairs policy or substitutes for
admission or transport evidence. Unavailable policy diagnostics do not skip the
raw observation. The disposable socket is removed and the exact original
inode/lease restored in `finally`, or qualification fails without
further admission. A separate negative changes only the pathname MCS and still
requires Alpha's actual raw connect to return exactly `EACCES`. Existing
per-request kernel identity/authority checks remain mandatory. No new
mount, policy allow rule, permissive mode or Supervisor process transition is
used to make either test pass.

`tests/vm/room_service.py` assembles the actual help-only consumer and private
Broker. `tests/vm/guest_room.py` composes that service with admitted storage,
network, mounts and live resource observations. The immutable Python-only image
contains the existing synthetic Go probe and no Pi/Node or native Git worker
entrypoints. The selected Git/OpenSSH descriptors are real signed guest package
files; help never executes either, and the credential configuration is empty.

The fixture's observed authority freshly validates the full endpoint (including
retained descriptors and labels) and private Broker before and after every
`bind`, `current` and `require`, while the caller holds the existing lifecycle
lock and before the result can reach disclosure. These resource checks enclose,
not consume, the unchanged core lineage operation's absolute 50 ms budget.
Core `seat.current` still freshly reads the Room manifest and checks active
instance and retained bootstrap-origin liveness twice during final observation;
there is no positive cache, removed check, retry or time-limit increase. Direct
bootstrap and workload-release gates retain their resource checks as well.
A post-bind resource failure closes the newly created binding before exposure,
retaining the first failure even if cleanup also fails. Fixed phase aggregates
(count, failures and elapsed last/max/total seconds, at most seventeen keys) retain
resource pre/post, core operation, fresh-current and failed-bind cleanup timing
without storing requests or an unbounded history. The six fixed release phases
also retain lock acquisition, current authority, resources, full admission,
final Broker check and the release write; their accounting never restarts either
five-second phase or the core 50 ms budget. Callback timing bookkeeping
still participates in the core deadline. This separation is source-backed
composition alignment, not proof of which subphase exhausted the previous
run's deadline; final VM qualification remains required.

One admission now shares only its duplicate command observations: the same owned
firewall document supplies existence and rule checks, and one fixed Docker-info
projection supplies typed security options and the remapped root. An admission-
local SELinux command observation is discarded on return or failure; every
original nonce/root/sysfs guard and all three storage-manifest validations still
run. Standalone helpers retain their complete fresh guards, and each later
admission starts from fresh commands. No caller evidence, backend cache or
cross-call reuse is introduced. A file/mock-only full-chain comparison observes
23 baseline commands versus 15 after consolidation. This is not a runtime
latency guarantee or VM qualification; endpoint and Broker pre/post checks,
including the final Broker check after slow admission, remain mandatory.

The unrelated same-UID task negative retains caller-owned evidence before its
fixed Docker CLI launch. Launch, accept, service and output-collection stages
have elapsed timestamps; each output stream retains at most 4096 bytes (also
bounded after JSON escaping), with total byte counts and EOF/truncation state.
Preparation has one fixed, ordered diagnostic sequence: Python entry (after
only os/sys imports), probe-module imports complete, actual launcher imports
complete, then READY. Entry is emitted only for the exact standalone unrelated
probe mode; ordinary imports and all other modes emit none of these entry bytes.
The bounded parent receipt records complete milestone observation times, not
child execution durations or authority. No milestone substitutes for READY or
a real authority refusal. Missing, malformed, reordered or duplicate markers
fail closed; fragments/coalescence do not restart the clock. No new process,
transport, thread, positive cache or scheduling assumption is introduced.
Mode-only ctypes and HTTPS imports are local to their existing consumers; the
actual launcher import still completes before READY. This is dependency cleanup
and observability, not a measured startup performance fix.

Preparation has a five-second marker-readiness phase and a separate five-second
parent release phase, started once on validating the complete marker, before
lock acquisition and every fresh release check. The hosted smoke follows the
same phase boundary. The child independently requires G within five seconds
after emitting its marker; delayed delivery or scheduling can still exhaust
that stricter child window. Parent release eligibility is checked immediately
before G, not a hard wall-time interruption of synchronous callbacks. No
check is cached or skipped; all fresh checks and G remain under the same lock.
Release start/deadline/write timestamps are diagnostics, not authority evidence.
The accept and collection deadlines remain five seconds each, and draining
output does not restart them. A timeout or early client exit is incomplete
evidence, never an authority refusal. Pre-cleanup process state is distinct
from a forced-kill return code; output and cleanup errors survive failures
without masking the original exception. Cleanup has a shared five-second
drain/reap bound and must succeed. Killing the owned CLI does not establish
that its daemon-owned in-container task died: exact Room teardown remains
mandatory. Qualification still requires an actual connected `serve_one`
authority rejection, client exit zero with code 128, and zero worker effects.

## Selected privilege and namespace profile (qualification pending)

The accepted boundary keeps the Supervisor and Docker authority outside the
Workstation; it requires Participants, Hub and Broker to be non-root. It does
not require that the trusted host Supervisor share the Hub's unprivileged
identity. The existing synthetic guest lifecycle and #67 composition/byte Broker
fixtures already use a root trusted Supervisor in the initial user namespace
(the hosted #67 fixtures use a private PID namespace).
The existing native-Pi fixture separately uses a non-root Supervisor. Neither
choice is silently promoted to the other profile.

The candidate selects:

- Trusted lifecycle/Git Supervisor: root in the disposable VM's initial user/PID
  namespaces, outside Workstation and outside Hub/Broker. This is already the
  owner of the guest-only Docker/network/XFS effects. It obtains no new host
  capability, policy exception or namespace membership.
- Workstation Participants: internal `65532:65532`, translated by the exact
  admitted `0 100000 65536` map to `165532:165532` in the Supervisor's view.
- External Broker: a distinct non-root identity; its private stores and control
  channel stay outside the Workstation. No Hub or native Git worker is enabled
  in this selected help-only fixture. No live account or private key is needed.
- Narrow socket leaves: non-root service/supervisor owner `165533`, group
  `165532`, parent `0710`, socket `0620`, exact Room MCS pair, mounted read-only.
  Root creating/holding a listener does not authorize a Participant; the actual
  service still authenticates every sender with existing kernel process objects.

The root Supervisor can perform #67's bounded read-only `/proc` lineage and
namespace corroboration without any new `SYS_PTRACE` grant, relaxing SELinux, or
moving that authority into the Hub. Its existing root capability baseline must be observed; denied reads fail, not
trigger a policy change. All existing pidfd, same-task, ancestry,
process-incarnation, epoch and deadline checks remain. This choice must receive
independent review; the root Supervisor is in the existing trusted computing
base, not a new claimed isolation boundary.

### Actual mounted endpoint, deliberately help-only

The selected fixture does not enable native Git workers or mutations. The real
mounted request path uses `serve_one → GitChildAuthority.bind →
GitCoordinator.request(help) → disclose`. The allowed result is the existing
canonical generated help, not a fabricated fixture reply. Every request still
uses the current held Participant process, observed namespace/lineage and
per-record kernel identity. A non-help request must fail without creating a
worker or contacting the provider. A same-UID unrelated task must be rejected.

The actual non-root `ExternalGitBroker` and `GitBrokerClient` perform their
existing private authenticated readiness exchange for the same Room/instance.
Both private socketpair ends enable mandatory credential/pidfd reception before
fork and before any possible HELLO. The parent requires default `SIGCHLD` and
remains the sole reaper of the held Broker child.
The held Broker process must remain live and bound immediately before workload
release. The mounted endpoint's Supervisor consumer must actually be installed;
a private HELLO plus an unserved socket is insufficient. Help does not contact
the Broker, so this proves real service transport plus separate Broker readiness,
not remote Git bytes or a native Git mutation.

This original #62 fixture scope does not require replacing the already tested
#67 command semantics. Full native Git workers remain explicitly unavailable:
identity-mapped-only GitSupervisor, the immutable RuntimeView alias/config/pointer
mounts and effective group access are separate selected-profile integration.
No Git mapping/RuntimeView guard is weakened. The synthetic Participant's actual
`165532:165532` translation, namespace and kernel lineage still require proof.
No native Pi/Hub topology is claimed; #61's persistent control-plane integration
remains open. If a Hub is later enabled, its existing mapped non-root Supervisor
control sender remains mandatory; root cannot satisfy its receiver contract.

## Fixed real-network profile (execution not authorized here)

The existing no-NIC VM entrypoints and guards remain unchanged. A distinct fixed
owned fixture has one QEMU user-mode IPv4 NIC, no host forwarding, no SSH,
no shared host filesystem/device and no runtime socket. Its capability is
general public IPv4 egress, not a hypervisor allowlist for the probe destination;
the guest's existing per-Room deny policy remains mandatory. QEMU remains an
unprivileged owned process on a disposable hosted runner. The selected external
probe is one HTTPS `HEAD /` to `1.1.1.1:443` with SNI and Host
`one.one.one.one`, certificate/hostname verification, bounded bytes/time, no
credential, redirect following or retry. The exact request is in
`uas/room_probe.py`; response bodies are neither needed nor logged. The selected
address/hostname is documented by [Cloudflare](https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/).
The fixed no-forwarding user-mode NIC follows [QEMU
networking](https://www.qemu.org/docs/master/system/devices/net.html). Root must
review this concrete network destination and cleanup before authorizing a run.

Inside the guest, the already-owned per-Room network/filter rules must block
all host destinations, private LAN, metadata and sibling Room paths. Existing
live synthetic decoys and attributed drop counters remain, including the
public-looking guest-host address. The new real public IPv4 positive must run
from the admitted Workstation, not the host. IPv6 remains unavailable and
explicitly filtered; enabling dual stack is not an invented #62 requirement.
No rule may be weakened to obtain a successful external request.

The original `build_rootfs` entrypoint still requires a no-NIC boot. The separate
`build_room_rootfs` entrypoint observes this exact boot-selected NIC contract
before sharing only the offline assembly implementation. Room admission repeats
the actual selected interface/MAC/address/default-route checks. No monkeypatch,
generic allow-network flag or later attachment bypasses the old guard.
`room-launch.yml` is deliberately triggered only by manual dispatch or the
trusted exact-review label; it is not automatic per-patch CI. The one authorized NIC-enabled VM run is recorded below; it failed during
preflight and does not qualify the composed candidate.

## Evidence plan and stopping condition

1. Explicit audited pure tests cover the actual source seams and all policy
   negatives; local process/socket/kernel/container execution is prohibited.
2. A cheap hosted Docker smoke proves real read-only endpoint mounting,
   configured live cgroup/log limits, pre-start drift denial and owned cleanup.
   A bound test socket is not counted as authenticated Broker integration.
3. Only after source completion and independent review, one deliberately chosen
   batched disposable-VM qualification covers the combined service endpoint,
   stock SELinux, userns/quota, public-egress/deny and lifecycle recovery checks.
   Per-patch full-VM runs are not the development feedback loop.
4. Closure requires all five original #62 criteria on the exact candidate, with
   one independent Standards/Specification/Runtime owner, required CI within the
   automatic three-minute critical path, and verified post-merge status.

The source includes all composed checks above; they still require independent
exact-candidate review and real hosted qualification. Pure tests are policy/source
evidence, not successful sockets, SCM pidfds, SELinux, Docker, quotas or egress.
The recovery check covers container/network/storage after the service has been
torn down; it is not persistent Participant/Broker restart integration for #61.
No acceptance checkbox or production-launch claim is made from source alone.

## Single-run checkpoint — 2026-10-27

The explicitly authorized single [run 40577280219](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40577280219)
on head `94797363a1cb1467332a1081d15730c7f6d15a2a` failed before any
qualification checks. Guest preflight reported `RuntimeError: wrong actual NIC`.
The guest shut down and the outer runner confirmed removal of its owned temporary
directory after 323.304 seconds. No retry is authorized or scheduled.

The guard incorrectly expected the link-layer `address` (MAC) field in
`ip -j -4 address` output. Upstream iproute2's `print_linkinfo` emits that field
only for an unspecified/link family or detailed output; IPv4-only output omits
it. The pure fixture had supplied the nonexistent field, masking the defect.
See [iproute2 ipaddress.c](https://github.com/iproute2/iproute2/blob/main/ip/ipaddress.c).
Both boot preflight and Room admission now obtain a separate bounded
`ip -j link show dev uas-egress` observation and verify its exact MAC and
interface, while retaining the sysfs MAC, IPv4 address/prefix and route checks.
No network policy or identity check is relaxed. Regression fixtures use the
IPv4-only shape without a MAC and explicitly deny missing, malformed, extra,
or mismatched link observations. These are pure parser/policy tests; actual
composed VM qualification remains pending.

## Offline guest package compatibility checkpoint — 2026-10-27

The subsequently authorized [run 40589296271](https://github.com/matuto-ai/ultimate-agent-sandbox/actions/runs/40589296271)
on `735c574b5d1ddf77bf0f147acbab8bbef503a65a` passed the corrected NIC
observation but failed in the offline guest package transaction, before composed
checks. The fixed Cloud image contains `openssh-server-10.2p1-7.fc44`, which
requires the exact matching `openssh` core. The signed candidate pool selected
`openssh-clients` and core `10.2p1-16.fc44`, but omitted the matching server
counterpart. An empty-installroot dependency download cannot discover this
installed reverse dependency. Owned outer cleanup completed after 499.676 seconds.

The Room-only candidate pool now explicitly includes core, client and the
already-installed server counterpart. Payload preparation requires one signed
package per root and equal epoch/version/release/architecture across the OpenSSH
family before building the payload. The guest repeats that selection, confirms
the server is already installed, masks/stops its service and socket, and requests
all exact NEVRAs in one offline transaction. It verifies every installed NEVRA
and confirms both units remain inactive and masked after package scriptlets.
The client and Git executable-package integrity checks remain unchanged.

There is no new guest login route, account, credential, service activation,
forwarding rule or Workstation SSH server. The Workstation rootfs roots remain
Python/tini/glibc/libstdc++; the SSH family only supplies the outside guest's
pinned descriptor packages. Fedora signing-key checks, hash-bound repository
metadata and fail-closed DNF behavior remain mandatory. No `--skip-broken`,
`--allowerasing`, downgrade, forced RPM install or online guest repository is
used. Pure tests prove family rejection, exact command construction, ordering
and failed-state handling, not compatibility of the installed image transaction.
A further VM is only run within the owner's explicit remaining execution budget.
