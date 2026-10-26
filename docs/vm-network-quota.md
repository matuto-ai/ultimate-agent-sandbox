# Guest-only Docker network and disk enforcement (partial #62)

This is an executable **disposable CI fixture**, not a production launcher,
installation command, or completed Room security boundary. It uses the same
`uas.lifecycle.Supervisor` for two Rooms and the accepted Docker/Moby engine.
The existing network-none/read-only Docker fixture keeps its original defaults.

This expensive tier is manual: use Actions **Run workflow**, or the review account
`puglab-reviewer` deliberately adds `qualify-vm-boundary` to a same-repository PR.
Only that exact `labeled` event or dispatch launches it; pushes, opening a PR and
retaining the label across later commits do not. Checkout is bound to the event's
head SHA. Later relevant changes invalidate that evidence and require a new
explicit qualification decision. Ordinary offline tests remain automatic.

The manual job is capped at 30 minutes (runner-tool setup 10, payload build 15,
guest installation/scenario/shutdown 15, all also within the overall ceiling).
Timestamped phases, verified-package counts and 30-second guest-output progress
make slow stages visible. A guest with no serial boot output fails at 180 seconds;
after boot, 300 seconds without any new serial bytes fails and cleans up owned QEMU.
Progress output is liveness diagnostics, never a replacement for passing security
assertions. No mutable guest state is reused or cached.

Runner setup reads the stock Ubuntu 24.04 deb822 source and creates an owned,
publicly readable temporary copy for APT's sandbox reader. Only recognized
Ubuntu archive URI fields change to official HTTPS endpoints; suites,
components and the installed Ubuntu archive `Signed-By` keyring stay unchanged.
No `/etc` source or permission is edited. APT retains signed Release/package-hash
and freshness verification, rejects incomplete index updates, and uses a
20-second transport timeout with no implicit retries. Normal package installation
and APT metadata updates remain confined to the disposable hosted runner.
This avoids the Azure HTTP mirror route that exhausted the manual setup budget
in run 40353107455 before any payload or guest executed; it is not new guest proof.
See [Ubuntu archive verification](https://documentation.ubuntu.com/security/software-integrity/archive-verification/)
and the [Ubuntu deb822 source format](https://manpages.ubuntu.com/manpages/noble/man5/sources.list.5.html).
The runner image also uses the exact literal `mirror+file:/etc/apt/apt-mirrors.txt`,
verified in its [tagged source configuration](https://github.com/actions/runner-images/blob/ubuntu24/20261012.334/images/ubuntu/scripts/build/configure-apt-sources.sh).
That one input representation is replaced, not followed; arbitrary mirror files,
alternate spellings, queries and fragments remain rejected. The earlier parser
rejected it before APT in the five-second run 40358024317, producing no guest evidence.

## What runs

`vm-boundary` boots the pinned, signature-verified Fedora Cloud image under
unprivileged QEMU TCG, still with **no NIC, forwarding, SSH, shared host directory,
host runtime socket or host block device**. A separate read-only payload contains
explicit source files, a static synthetic Workstation, and Fedora-signed RPMs.
A generated 512 MiB raw disk is the only quota backing device. RPM installation,
XFS formatting/mounting, Docker, network namespaces and firewall rules execute
only inside this disposable guest. Nothing installs this policy on the runner or
operator's machine. The CI/nonce markers are accidental-use guards, not security
credentials.

The verified OS overlay is the sole explicitly boot-prioritized disk; payload,
seed and quota disks never rely on implicit BIOS ordering. Empty serial output
fails within 180 seconds, with bounded file-only firmware diagnostics, rather
than consuming the full guest installation budget without evidence of boot.

Payload preparation uses private DNF/RPM/cache/key directories, HTTPS-only bounded
downloads, the independently pinned Fedora 44 signing certificate, and an exact
nonce-bound file-hash manifest, including generated local-repository metadata.
Native guest DNF enables only that read-only file repository, retains package
signature checks, and solves the eight requested roots against its installed OS.
It does not force-install every downloaded alternative provider or permit erasing
conflicting OS packages. All configured external repositories are excluded.
The RPM dependency closure
is Fedora-signed and recorded in a nonce-bound hash manifest, with versions/manifest digest logged, **not a reproducibly pinned
closure**. The base OS image remains exactly pinned. Missing tools/packages or
signature failure cannot select an unsigned fallback.

## Enforcement source and lifecycle

`uas/guest_fixture.py` is a fixed alpha/beta guest backend, not a generic policy
framework. The Supervisor retains the lifecycle lock, immutable Project binding,
intent record, ownership checks, reconciliation and Destroy tombstone.

- Each instance gets one labelled Docker bridge and a separately owned nftables
  table, installed before container creation. Input denies all Workstation-to-host
  traffic, including host addresses that look public. Forwarding denies private,
  link-local/metadata, loopback, shared-address, documentation, benchmark,
  multicast and reserved IPv4 ranges. Sibling bridges use denied private ranges.
  IPv6 is explicitly unavailable in this initial IPv4 fixture and additionally
  denied by policy; dual-stack public egress is not claimed.
- The guest has only synthetic responders: one reachable public-looking IPv4
  endpoint plus live host-private, host-public, LAN, metadata and sibling decoys.
  Real packet drops must increment nft counters. This proves actual filtering,
  **not real Internet reachability**. It never contacts a real metadata service.
  Router setup/responder children enter only the parent's held network namespace
  descriptor. They do not remount sysfs or relax SELinux mount policy.
- Fresh XFS project-quota roots hold synthetic repository/workspace/checkouts,
  references and instance Runtime state. Block and inode hard limits are checked
  from XFS and exercised with bounded writes that must return XFS project-quota `ENOSPC`, with abundant filesystem free space. Beta must
  allocate fresh data while Alpha remains exhausted. Only test-created exhaustion
  files are explicitly removed afterward; product data is never evicted.
- Workstations remain non-root, read-only-rootfs, capability-free, no-new-privileges,
  seccomp-filtered and SELinux-enforcing with distinct Room MCS labels. Guest-only
  Docker userns-remap prevents inode owners changing project IDs/inheritance;
  actual UID mapping and denied `FSSETXATTR` attempts are required, with unchanged
  inode attributes afterward. The identical ioctl probe must first succeed as a
  non-root owner in the initial user namespace on a separate empty synthetic
  directory; its attributes are restored and it is removed before workloads.
  Thus `EINVAL` alone cannot masquerade as quota-escape enforcement. Memory,
  CPU, PID and rotating log bounds retain the conservative Docker fixture values.
  Project mounts preserve their exact absolute paths; references remain read-only.
- A real labelled volume is created before the network/policy and remains the
  cleanup anchor until exact owned network/policy and Runtime cleanup succeed.
  The volume precedes Runtime mkdir as well as network effects. Immutable pre-mkdir
  intent and inode identity recover SIGKILL after volume creation, mkdir and marker
  publication (completed-effect boundaries, not arbitrary torn writes);
  arbitrary unmarked paths are never adopted. Dangling links and pending record
  leftovers fail closed and retain the anchor. Lost network-create
  responses reconcile by exact observation. Failed removal
  leaves `destroy_failed` plus the anchor for targeted retry. A missing anchor
  with remaining owned resources is unknown, never a clean-absence receipt.
- Private manifests bind synthetic root and Runtime directory inode/device
  identity. Unknown replacements are not adopted. Destroy preserves Project
  roots and unowned resources and removes only exact instance resources. No
  daemon-wide pruning or speculative cleanup occurs.

Admission checks current policy and quota enforcement at Start/resume. It does
not continuously watch root-owned host policy. A drifted running workload is not
magically stopped by a failed check; the scenario stops the fixture before
injecting drift and proves denied resume leaves it stopped. The backend never
silently repairs drift. Only the trusted test harness repairs its stopped
synthetic policy for recovery evidence. Cleanup checks ownership separately from
execution policy, including when SELinux has ceased enforcing.

## Evidence and remaining work

```sh
./validate.sh                    # offline contracts; no VM enforcement claim
python3 tests/vm/run_boundary.py  # guarded disposable GitHub CI only
```

Real CI must prove the two-Room positive/negative flow, block and inode exhaustion,
sibling health, persistent Stop/Start, denied drifted resume, uncertain creation,
partial Destroy and exact cleanup. Local mocks/skips are not this evidence.

No Participant badge, kernel-peer authority, Broker Unix transport, provider key,
real agent Runtime, real user data or production launch is enabled. Narrow SELinux
socket transport and process authority remain separate reviewed work. Public
Internet and dual-stack qualification, full destructive escape/resource testing,
100 lifecycle cycles and target-host qualification remain outstanding. #62 is not
closed by this fixture.
