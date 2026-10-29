# Persistent local host preparation (source checkpoint)

This path prepares storage for an existing **compatible** local native host;
it does not install an alternate Docker daemon, create an XFS backing image,
change global Docker configuration, start Rooms, or authorize any host change.
The isolated Engine/non-XFS installation path remains unfinished in #202.

The existing host plan must select Docker 29.8.2, an explicitly selected nonoverlapping subordinate mapping
of size 65536, SELinux enforcing, and an existing quota-enabled XFS parent.
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
Qualification and version 1 retain offset 100000.

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
