"""Guest-only offline native rootfs assembly, never a host installer.

Runtime tar extraction deliberately accepts less than general tar. RPM-created
usrmerge links are handled separately as root-relative links when fingerprinting
an immutable image; host path resolution must never follow an absolute target.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile

PAYLOAD = Path('/mnt/uas-payload')
ROOTS = ('python3', 'tini', 'glibc', 'libstdc++')
MAX_FILES = 30000
MAX_FILE_BYTES = 160 * 1024 * 1024
MAX_RUNTIME_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 544 * 1024 * 1024
MAX_ROOT_FILES = 100000
MAX_ROOT_BYTES = 2 * 1024 * 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}\Z')


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def ordinary(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('ordinary unlinked file required')
    return info


def relative(name):
    if (type(name) is not str or not name or len(name) > 1024 or '\\' in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError('invalid relative path')
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or str(path) != name:
        raise ValueError('noncanonical relative path')
    return path


def checked_asset(payload, descriptor, expected_name, maximum):
    if (type(descriptor) is not dict or set(descriptor) != {'file', 'bytes', 'sha256'}
            or descriptor['file'] != expected_name
            or type(descriptor['bytes']) is not int or not 0 < descriptor['bytes'] <= maximum
            or type(descriptor['sha256']) is not str or not HEX.fullmatch(descriptor['sha256'])):
        raise ValueError('invalid native asset description')
    path = payload / expected_name
    info = ordinary(path)
    if info.st_size != descriptor['bytes'] or digest(path) != descriptor['sha256']:
        raise ValueError('native asset hash/size mismatch')
    return path


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate manifest key')
        result[key] = value
    return result


def verify_runtime(payload, native):
    """Verify both complete assets before any rootfs creation or extraction."""
    if not payload.is_absolute() or payload.resolve() != payload or not stat.S_ISDIR(payload.lstat().st_mode):
        raise ValueError('canonical read-only payload directory required')
    if (type(native) is not dict or native.get('profile') != 'native-pi-v1'
            or native.get('node_version') != '24.22.1' or native.get('pi_version') != '1.4.0'
            or native.get('rpm_roots') != list(ROOTS) or native.get('rpm_scriptlets') is not False
            or native.get('dependencies_reproducibly_pinned') is not False):
        raise ValueError('unsupported native payload profile')
    archive = checked_asset(payload, {k: native.get(k) for k in ('file', 'bytes', 'sha256')},
                            'native-runtime.tar', MAX_ARCHIVE_BYTES)
    listing = checked_asset(payload, native.get('file_manifest'), 'native-files.json', 8 * 1024 * 1024)
    data = json.loads(listing.read_bytes(), object_pairs_hook=unique)
    if (type(data) is not dict or set(data) != {'version', 'profile', 'files'}
            or type(data['version']) is not int or data['version'] != 1
            or data['profile'] != 'native-pi-v1' or type(data['files']) is not list
            or not 0 < len(data['files']) <= MAX_FILES):
        raise ValueError('invalid native file manifest')
    files, total = {}, 0
    for item in data['files']:
        if (type(item) is not dict or set(item) != {'file', 'bytes', 'sha256', 'mode'}
                or type(item['bytes']) is not int or not 0 <= item['bytes'] <= MAX_FILE_BYTES
                or type(item['mode']) is not int or item['mode'] not in (0o444, 0o555)
                or type(item['sha256']) is not str or not HEX.fullmatch(item['sha256'])):
            raise ValueError('invalid native file entry')
        name = item['file']; relative(name)
        if not name.startswith('opt/uas/') or name in files:
            raise ValueError('unexpected or duplicate runtime file')
        files[name] = dict(item)
        total += item['bytes']
    if (total > MAX_RUNTIME_BYTES or type(native.get('unpacked_bytes')) is not int
            or total != native['unpacked_bytes'] or type(native.get('file_count')) is not int
            or len(files) != native['file_count']):
        raise ValueError('native file budgets disagree')
    return archive, files


def _directory(root, parts):
    current = root
    for part in parts:
        current /= part
        try:
            current.mkdir(mode=0o755)
        except FileExistsError:
            if not stat.S_ISDIR(current.lstat().st_mode):
                raise ValueError('runtime parent is not an ordinary directory')
    return current


def extract_runtime(archive_path, files, root):
    """No extractall, links, special files, overwrite, or unmanifested members."""
    if not stat.S_ISDIR(root.lstat().st_mode) or root.resolve() != root:
        raise ValueError('canonical owned root required')
    seen = set()
    with tarfile.open(archive_path, 'r:') as archive:
        for entry in archive:
            name = entry.name
            relative(name)
            expected = files.get(name)
            if (expected is None or name in seen or entry.type != tarfile.REGTYPE
                    or entry.size != expected['bytes'] or entry.mode != expected['mode']
                    or entry.uid != 0 or entry.gid != 0 or entry.mtime != 0 or entry.linkname
                    or set(entry.pax_headers) - {'path'}):
                raise ValueError('archive member not exact ordinary manifest file')
            seen.add(name)
            target = _directory(root, PurePosixPath(name).parts[:-1]) / PurePosixPath(name).name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, expected['mode'])
            hasher = hashlib.sha256()
            with os.fdopen(fd, 'wb') as output, archive.extractfile(entry) as source:
                remaining = expected['bytes']
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError('truncated native file')
                    hasher.update(block); output.write(block); remaining -= len(block)
                if source.read(1):
                    raise ValueError('native file length exceeded')
                output.flush(); os.fsync(output.fileno())
                os.fchmod(output.fileno(), expected['mode'])
            if hasher.hexdigest() != expected['sha256']:
                raise ValueError('native file content mismatch')
        # Tar readers normally ignore anything after the end marker. Reject a
        # concatenated second archive or arbitrary trailing data explicitly.
        archive.fileobj.seek(archive.offset)
        while block := archive.fileobj.read(1024 * 1024):
            if block.strip(b'\0'):
                raise ValueError('nonzero archive trailer')
    if seen != set(files):
        raise ValueError('archive omitted manifest files')


def resolve_inside(root, name, *, runtime_target=None):
    """Resolve RPM links using container-root semantics, not host semantics."""
    pending, resolved, links = list(relative(name).parts), [], 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if not resolved:
                raise ValueError('rootfs symlink escapes image root')
            resolved.pop(); continue
        candidate = root.joinpath(*resolved, part)
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            # Only the caller's exact documented runtime-provided target may
            # be absent. Existing prefixes were checked without host following.
            remainder = PurePosixPath(*resolved, part, *pending)
            if runtime_target is not None and str(remainder) == runtime_target:
                return root / runtime_target
            raise
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > 40:
                raise ValueError('rootfs symlink cycle/chain too deep')
            target = os.readlink(candidate)
            if not target or '\0' in target or any(ord(c) < 32 for c in target):
                raise ValueError('invalid rootfs symlink')
            if target.startswith('/'):
                resolved = []
            pending = target.split('/') + pending
        else:
            if pending and not stat.S_ISDIR(info.st_mode):
                raise ValueError('rootfs link traverses a nondirectory')
            resolved.append(part)
    return root.joinpath(*resolved)


def fingerprint(root):
    """Hash every installed byte, mode and link target, rejecting special files."""
    if not root.is_absolute() or root.resolve() != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('canonical image root required')
    entries, total, inodes = [], 0, {}
    for base, dirs, names in os.walk(root, followlinks=False):
        for name in sorted(dirs + names):
            path = Path(base) / name
            key = path.relative_to(root).as_posix(); relative(key)
            info = path.lstat()
            item = {'path': key, 'mode': stat.S_IMODE(info.st_mode),
                    'uid': info.st_uid, 'gid': info.st_gid}
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > MAX_ROOT_BYTES:
                    raise ValueError('native image byte budget exceeded')
                item.update(kind='file', bytes=info.st_size, sha256=digest(path))
                inode = (info.st_dev, info.st_ino)
                count, expected = inodes.get(inode, (0, info.st_nlink))
                inodes[inode] = (count + 1, expected)
            elif stat.S_ISDIR(info.st_mode):
                item['kind'] = 'directory'
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                runtime_target = ('proc/self/mounts' if key == 'etc/mtab'
                                  and target == '../proc/self/mounts' else None)
                resolve_inside(root, key, runtime_target=runtime_target)
                item.update(kind='symlink', target=target)
            else:
                raise ValueError('special file in native image')
            entries.append(item)
            if len(entries) > MAX_ROOT_FILES:
                raise ValueError('native image file budget exceeded')
    if any(count != expected for count, expected in inodes.values()):
        raise ValueError('rootfs contains external hardlink')
    document = {'version': 1, 'root_mode': stat.S_IMODE(root.stat().st_mode),
                'root_uid': root.stat().st_uid, 'root_gid': root.stat().st_gid,
                'entries': sorted(entries, key=lambda item: item['path'])}
    return {'rootfs_manifest_sha256': hashlib.sha256(canonical(document)).hexdigest(),
            'rootfs_entries': len(entries), 'rootfs_bytes': total, 'manifest': document}


def guest_guard(nonce):
    if type(nonce) is not str or not re.fullmatch(r'[0-9a-f]{32}', nonce) or os.geteuid() != 0:
        raise RuntimeError('native rootfs assembly requires this root-only no-NIC disposable boot')
    marker = Path('/run/uas-vm-fixture')
    info = ordinary(marker)
    if (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600
            or marker.read_text().strip() != nonce
            or sorted(path.name for path in Path('/sys/class/net').iterdir()) != ['lo']):
        raise RuntimeError('native rootfs assembly requires this root-only no-NIC disposable boot')


def build_rootfs(nonce, manifest, destination, *, run):
    guest_guard(nonce)
    archive, files = verify_runtime(PAYLOAD, manifest['native_runtime'])
    root = Path(destination)
    if not root.is_absolute() or root.parent.resolve() != root.parent or root.exists() or root.is_symlink():
        raise ValueError('fresh canonical rootfs path required')
    root.mkdir(mode=0o755)
    # Payload hashes/signatures and repodata were verified by guest install;
    # only this read-only file repository is made visible to the native solver.
    run('dnf', '-y', '--installroot=' + str(root), '--releasever=44',
        '--disablerepo=*', '--repofrompath=uas-native,file://' + str(PAYLOAD / 'rpms'),
        '--enablerepo=uas-native', '--setopt=uas-native.gpgcheck=1',
        '--setopt=uas-native.repo_gpgcheck=0', '--setopt=uas-native.gpgkey=file://' + str(PAYLOAD / 'fedora-44.asc'),
        '--setopt=localpkg_gpgcheck=True', '--setopt=install_weak_deps=False',
        '--setopt=tsflags=noscripts', '--setopt=plugins=False',
        'install', *ROOTS, timeout=900)
    extract_runtime(archive, files, root)
    source = resolve_inside(root, 'usr/bin/tini')
    ordinary(source)
    target = root / 'opt/uas/bin/tini'
    _directory(root, ('opt', 'uas', 'bin'))
    with source.open('rb') as input_, target.open('xb') as output:
        shutil.copyfileobj(input_, output)
    target.chmod(0o555)
    # mkdir is umask-sensitive and RPM may adjust the installroot mode. The
    # imported image root must be traversable by both fixed unprivileged UIDs.
    root.chmod(0o755)
    result = fingerprint(root)
    manifest_path = root.with_name(root.name + '.manifest.json')
    with manifest_path.open('xb') as output:
        output.write(canonical(result.pop('manifest')))
        output.flush(); os.fsync(output.fileno())
    manifest_path.chmod(0o444)
    return {**result, 'rootfs_manifest': str(manifest_path), 'runtime_sha256': manifest['native_runtime']['sha256'],
            'tini_sha256': digest(target), 'rpm_roots': list(ROOTS), 'rpm_scriptlets': False}
