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
The held bootstrap observes the listener socket SID through client-side
`SO_PEERSEC`; the Supervisor observes the connecting Participant socket SID
on its accepted sockets. These observations do not infer either process label
from a filesystem `chcon`; actual process labels are recorded separately.

After the held bootstrap's pidfd signals exit and service/Broker teardown has
completed, a locked negative temporarily parks the original leased socket inode
outside its mounted directory. A disposable Beta-SID socket occupies the same
Alpha pathname, with an Alpha filesystem label. A trusted local connection
observes its Beta socket SID; Alpha's connect must be denied and the replacement
must fail the original endpoint lease. The disposable socket is removed and the
exact original inode/lease restored in `finally`, or qualification fails without
further admission. A separate negative changes only the pathname MCS. No new
mount, policy allow rule, permissive mode or Supervisor process transition is
used to make either test pass.

`tests/vm/room_service.py` assembles the actual help-only consumer and private
Broker. `tests/vm/guest_room.py` composes that service with admitted storage,
network, mounts and live resource observations. The immutable Python-only image
contains the existing synthetic Go probe and no Pi/Node or native Git worker
entrypoints. The selected Git/OpenSSH descriptors are real signed guest package
files; help never executes either, and the credential configuration is empty.

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
trusted exact-review label; it is not automatic per-patch CI. No NIC-enabled VM
has run for this candidate.

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
