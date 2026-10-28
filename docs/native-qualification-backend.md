# Disposable native backend

This is a source-level, opt-in qualification route, not the production launcher
and not a change to the #62 alpha/beta fixture. The paired startup milestone does
not manufacture a Run: native RunAdmission remains a separate prerequisite.

## Existing installation prerequisites

`disposable-native-v1` uses an already prepared disposable guest, the existing
nonce marker, enforcing stock SELinux, remapped Docker 29.8.2, and XFS project
quotas. It neither formats storage nor repairs Project/provider ownership,
labels, quota assignments, or authentication. Missing observations fail before
container creation. No API-billing/provider/model fallback is introduced.

The fixed storage namespace is `/mnt/uas-native/<nonce>`; the selected Room's
canonical state is `state/<room-id>` underneath it. Four configured Project
roots and `state/<room-id>/runtime` must already exist on that XFS filesystem,
owned by mapped Runtime UID/GID165532, with project301 and inherited quota
accounting, MCS `s0:c301,c302`, and the exact configured disk limit. Prepared
root/state ancestors are root-owned, not group/world writable, and traversable
by the distinct trusted host roles. The backend only reads public installation
manifests and filesystem metadata; it does not copy/read provider secrets.

The public boundary manifest has exactly `version:1`, `nonce`, `room_id`,
`project_id:301`, `level`, `root_identity:[device,inode]`, and `paths`. Each of the
five path records (`repo`, `workspace`, `reference`, `checkouts`, `runtime`) has
exactly `path` and `identity:[device,inode]`. These are expected values, not an
attestation: quota enforcement, existing tree membership, ownership and labels
are independently observed. Trusted control-plane pathname observations are
not claims of protection against an adversarial host's concurrent renames.

The public Hub manifest has exactly `version:1`, digest-pinned `image_reference`,
`image_id`, and the fixed entrypoint list:
`["/opt/uas/bin/tini","--","/usr/bin/python3","-m","uas.workstation_service"]`.
Pi and Claude image manifests retain their existing exact inventory contract.

## Ownership and handoff

The root owner calls canonical `Supervisor.start`, never fabricating lifecycle
state. A guest-wide exclusive owner file serializes this **single-Room
qualification profile**; fixed quota/MCS/subnet assignments are not product
multi-Room isolation proof. Existing lifecycle state requires explicit
reconciliation rather than adoption. A unique attempt provenance and exact
instance checks prevent cleanup from targeting another invocation.

The Workstation has exactly four Project binds, shared Runtime state and a
read-only peer directory. Its short host endpoint root is
`/run/uas-native/<instance>` with an exact owner/identity marker, covered by the
canonical volume cleanup anchor. The Workstation peer bind uses the **same
absolute path**; Hub retains its fixed `/uas/peer` and `/uas/control` views.
This preserves native launch/lease path equality within Unix socket address
limits. Binds are nonrecursive/private; memory, CPU, PID, disk
and log controls retain configured values. Only public IPv4 egress is allowed;
host/private/metadata/other-Room destinations and IPv6 are denied. Hub has only
its shared ledger directory and narrow socket directories, never Engine access.

Root owns lifecycle mutations and teardown. Fixed trusted Supervisor UID165533
has Engine access as part of the existing TCB, read access to canonical lifecycle
state and write access to its lock, but no lifecycle-directory write permission.
HubUID165531 and BrokerUID165534 remain separate. Root-owned0711 ancestors give
traversal, not listing or file access; Supervisor/Broker directories are0700,
and only the shared Hub ledger directory is02770. No Engine group or socket is
propagated into Hub, Workstation or Broker. Public image manifests alone are
copied, byte/digest-preserving, to host-owned0400 files.

The fixed wrapper records spawn intent before each child/Broker spawn and binds
the actual returned `Popen` object immediately. An uncertain spawn, live trusted
issuer, live Broker, failed resource removal or uncertain cleanup retains the
owner lease and audit subtree. Channel closure is not process termination and
does not undo an already accepted provider action. Exact owned container stop
is verified separately. All issued-session audit/journals are retained, including
successful dispatches: after both trusted roles exit, Workstation and Hub stop,
but instance data, anchors and singleton remain for explicit reconciliation or
disposable-guest destruction. The result reports `stopped-evidence-retained`,
not complete resource removal. Pre-issuance setup failures may destroy their
exact owned attempt. No live SQLite copy or provider-state archive is made.

## Evidence limits

Guarded tests cover policy, custody and canonical file-backed lifecycle failure
windows without native execution. Actual XFS/SELinux/network/process/auth tests,
image build, deployment and provider accounts have not been exercised by these
tests and require separately authorized qualification.

The metadata-only recursive quota check follows upstream
[xfsprogs project checking](https://kernel.googlesource.com/pub/scm/linux/kernel/git/djwong/xfsprogs-dev/+/refs/tags/djwong-wtf_2025-12-09/quota/project.c):
nonconforming inode diagnostics can occur with a zero exit code, so only exact
clean output and empty stderr are accepted. Nonrecursive bind behavior follows
[Docker's bind mount contract](https://docs.docker.com/engine/storage/bind-mounts/#recursive-mounts).
