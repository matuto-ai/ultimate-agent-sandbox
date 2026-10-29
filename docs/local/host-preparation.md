# Persistent local host preparation (source checkpoint)

This path prepares storage for an existing **compatible** local native Engine.
It reuses quota-enabled XFS or, with an explicitly sized plan, creates a private
installation-owned XFS image and mounts it at the new storage root. It does not
install an alternate Docker daemon, change global Docker configuration, start
Rooms, or authorize host changes. Owned Engine provisioning remains unfinished.

The image lives inside the private receipt root, which must be on the selected
storage-parent filesystem. Size is explicitly selected (512 MiB–1 TiB), checked
against available space, and physically allocated before formatting. No block
device or existing file is formatted; there is no force-format option. Mounting
uses project quotas, nodev and nosuid. Receipts bind file inode, filesystem UUID,
mountpoint ownership and observed loop backing. Unknown operations are observed,
not reissued; incomplete ownership evidence requires operator investigation.

New image-backed preparation emits `local-native-v3` automatically. Only this
owned-image path uses stable filesystem UUID plus inode identities; ordinary
v1/v2 hosts retain exact device/inode checks. Every admission still verifies the
live mount device, backing image ownership, UUID, quotas and path identities.
A changed UUID, backing image, inode, ownership, MCS label or quota is refused.

Normal local host startup re-admits completed v3 storage under its existing
exclusive lock, before starting helpers. A new boot has a distinct mount and
endpoint issuance record; unknown operations in the same boot are never retried.
Re-admission observes existing Room ownership, never recursively repairs data.
Installation metadata and Project/native references must remain outside the
owned filesystem so startup can read them before mounting. No additional
mandatory daemon, fstab edit or storage service is introduced. No separate storage service is required; the existing host startup owns this
re-admission.

The existing host plan must select Docker 29.8.2, an explicitly selected nonoverlapping subordinate mapping
of size 65536 and SELinux enforcing. Storage is either an existing quota-enabled
XFS parent or the explicitly sized owned-image fallback described above.
The Engine socket, data/exec roots and remap account may be explicitly selected;
ambient Docker contexts and DOCKER_HOST are never used. Existing human trees
are not imported.

A `host_profile` in the preparation settings emits `local-native-v2`; the same
validated profile must match the host plan and is carried through the Hub owner,
Docker CLI checks and native Participant API. Existing `local-native-v1` input
retains the fixed qualification defaults. Selecting another endpoint does not
install a daemon or make two daemons' network/firewall policies independent.

For version 2, all host identities derive from the selected mapping offset:
Gate +65530, Hub +65531, runtime +65532, Supervisor +65533, and Broker +65534.
Preparation, retained owners, endpoint credentials and kernel map checks use
that same profile. An overlapping rootless Podman or other allocation is still
refused; never move an existing user's allocation to bypass the refusal. Select
an existing compatible Engine with an independently allocated nonoverlapping
range. This does not configure a new daemon or allocate a subordinate range.
Qualification and version 1 retain offset 100000. Version 3 uses the same
selected Engine/mapping as version 2.

`python -m uas.local_room_prepare plan` reads `--host-plan`, `--project`,
`--settings`, `--workstation-output`, `--hub-output`, and `--revision`, then
writes a new `--output` directory containing `request.json`. It checks exact
successful image-build reports and current source payloads before producing a
proposal. Review its selected paths, quotas, labels, network ranges and input
hashes before explicitly invoking the privileged apply command:

```text
python -m uas.local_room_prepare apply --plan /absolute/proposal/request.json --output /absolute/new-handoff
```

Apply never escalates privilege. Its inputs must satisfy the existing canonical
owned-file rules; it does not copy, chown or rewrite user configuration files.
It verifies the proposal again, holds an installer lock on the declared
root-managed storage-parent directory inode, and runs the host-directory owner.
It rejects occupied Docker labels/subnets and route overlaps before Room effects.
The lock coordinates this installer, not Docker or independent administrators;
future runtime admission must recheck the host rather than trust this receipt.

Each Room gets one reserved project quota and five newly owned, initially empty
leaves. Root-managed ancestor directories and external ownership markers keep
Git trees clean. Project assignment and nonrecursive SELinux labeling precede
the final runtime UID/GID handoff. An interrupted operation retains its intent;
retry observes the exact inode, quota, label and owner before deciding whether
any missing effect can be completed. Foreign or changed resources fail closed.
A quota-ID lookup uses an explicit numeric range rather than assuming the full
`xfs_quota` report enumerates every project.

The final step collects real inode identities, runs the existing canonical
storage checks, and emits the same #198 native/installation/runtime references.
It does not replace image build evidence with planned IDs or claim that an agent
or provider has started. Output writes are exclusive: after an uncertain output
failure preserve and inspect the partial directory, not overwrite it.

Source tests use controlled command/privilege observations and ordinary temporary
files. They are not evidence of a privileged apply on a real host. This checkpoint
does not yet close #202's general existing-machine installation acceptance.

### Remaining integration boundary

New v3 Rooms persist a root-private listener-layout ownership manifest in their
durable lifecycle directory. After a different boot, the existing locked startup
can recreate only the missing volatile layout after proving the exact volume
anchor and stopped Workstation/Hub. Durable Room trees are verified, never repaired.
Git overlays are regenerated from the bound plan; all four Git-enabled listener
endpoints retain their selected identities and listening modes. Per-boot intent
and confirmation records prevent retries of uncertain partial restoration.
Running resources, same-boot loss, foreign layouts, or missing manifests refuse
recovery. Existing v1/v2 installations are not silently upgraded. Owned Engine
provisioning is not implemented by this path.
