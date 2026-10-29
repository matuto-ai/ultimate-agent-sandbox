# Native Git prepared resources (#78)

This opt-in `native-git-primary-v1` resource profile supplies concrete fixed
resources to the existing Git Supervisor. It does not build an image, repair a
Project, grant an Actor permission, or qualify a native lifecycle. Default
six-mount fixtures remain unchanged. Gate execution is not added here.

## Installation prerequisite, not a new build system

Both `git_manifest` and `git_broker_manifest` are selected private `{path,sha256}`
references. The former contains exactly version1, profile, final image reference
and content ID, pinned `python_version` (3.11 patch version), `artifacts`,
`abi_artifacts`, `uas_tree_sha256`, `backend_path` and `backend_sha256`.

`native_git_resources.FIXED_ARTIFACTS` names the isolated Python interpreter,
controlled public launcher, fixed worker connector and entry, SSH-compatible
shim, public alias inventory and reference-transaction hook. The ABI map hashes
bounded actual loader/library files, including the x86-64 ELF loader and libc.
It must describe the complete selected backend/Python dynamic dependency
closure, not just executable bytes. The same exact final image ID/reference
must match the Pi/Claude image and actual Engine observation. There is no
`qualified: true` field or mutable-label shortcut.

The trusted session reads the **actual selected container** through the Engine's
read-only archive API, before any Git authority becomes active. No host readback
directory or JSON assertion substitutes for that observation. The parser hashes
fixed files, ABI files, every prescribed public alias under `/opt/uas/bin`,
`/usr/bin` and the exact `/usr/lib/git-core` inventory, plus the flat UAS Python
source package. It checks the fixed Python/helper links and worker-only hook.
Tar archives are never extracted. Duplicate/traversal/hardlink/special entries
are rejected; library symlinks may resolve only within the exact selected image
closure. Reads are capped at 128MiB overall, 64MiB per archive and the lesser of
60seconds and the existing remaining session deadline. No additional process,
image build, install, download, or command is executed. The ordinary Node-slim
renderer does **not** supply these prepared-image prerequisites.

The backend is a separate root-maintained regular ELF at exactly
`/mnt/uas-native/<nonce>/git-backend`. Trusted startup reads it without following
symlinks, checks its independently selected SHA256 and stable file metadata,
then copies it to a fully sealed memfd. Only the sealed FD is inherited by the
trusted session; the raw backend path never enters the Workstation or a public
request. Immutable image identity binds the corresponding dynamic loader/libs;
actual ABI execution remains separate qualification evidence. Do not infer
runtime compatibility from a manifest or source tests.

## Exact primary view and endpoint resources

The initial fresh allocator may use `primary` at the configured repository root.
That worktree must already be a mount root with existing shared access. Its
`.git` must be a directory and its neutral `.git/commondir` marker must already
contain `.\n`, through the separately authorized quiescent Git setup. Missing
metadata refuses startup; this path never creates or edits Project metadata.

Seven generated mounts are appended, in parent-before-child order:

1. Owned Git view root → `/opt/uas/git-views`, read-only.
2. Existing primary `.git` → `primary/gitdir`, read-write.
3. Same existing `.git` → `primary/common`, read-write.
4. Newly owned compiled config → `primary/common/config`, read-only.
5. Newly owned canonical common pointer → `primary/gitdir/commondir`, read-only.
6. Owned endpoint directory → `/uas/git`, read-only.
7. Empty owned worker cwd → `/uas/workspace`, read-only.

Only this exact typed profile permits these nested mounts. No generic `/opt`
overlay, recursive propagation, mount command, or caller-selected destination
is granted. The canonical runtime still validates held view inodes and controls
before Git runs. Later linked slots are explicitly unavailable until an actual
owned mount publication path exists; a checkout under the parent is not silently
treated as a mount root.

`request.sock` is bound but initially **not listening**. Only the constructed
ACTIVE operation owner enables its bounded listener; startup Git probes therefore
fail rather than queue unauthenticated work. `worker.sock` listens for the exact
Supervisor-created worker. Both sockets and the private launch journal are owned
by the existing attempt and cleanup anchor. The separate Git Broker retains its
own private directory and child custody, never PAT-to-SSH credential inference.

## Live identity and cleanup

`NativeGitResources.from_session` uses the exact readonly Supervisor, actual
Engine image/mount inspection and kernel UID/GID maps. Container UID65530/GID65532
must map to host165530/165532. PID1 capture also corroborates exact container cgroup membership, mapped status,
namespace PID1 and stable process starttime. A second Engine observation after
readback must report the same running container/PID while the captured pidfd is
still alive and identical. It holds that current PID1 pidfd, exact
listener inodes and fully sealed backend descriptor. Subsequent `require` calls
run under the caller-held lifecycle lock: they check current running instance,
configuration, held task, endpoint leases and sealed inode. They do not acquire
a nested lock, rehash immutable backend bytes, or call Engine under that lock.

The resource object owns listeners and PID1 pidfd. The enclosing session owns
the inherited backend FD. Closing channels does not revoke already accepted
work: original lifecycle/worker custody remains authoritative. Root cleanup
waits for native session, read Broker **and Git Broker** children; uncertainty
retains evidence rather than declaring revocation.

Source tests are bounded pure descriptor/declaration doubles. No image build,
installation, actual sockets, mounts, credential access or VM was performed for
this increment. Real native execution, actual prepared-image ABI pairing, SSH
account/host qualification and later linked-slot publication remain outstanding.
