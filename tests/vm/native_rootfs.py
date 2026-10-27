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
PROGRESS_FILES = 1024
PROGRESS_BYTES = 64 * 1024 * 1024
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
    extracted_bytes, reported_files, reported_bytes = 0, 0, 0
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
            extracted_bytes += expected['bytes']
            if len(seen) - reported_files >= PROGRESS_FILES or extracted_bytes - reported_bytes >= PROGRESS_BYTES:
                print('Native extraction progress:', json.dumps({'files': len(seen), 'bytes': extracted_bytes}), flush=True)
                reported_files, reported_bytes = len(seen), extracted_bytes
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


NCURSES_DEBUG_INDEXES = {
    'usr/lib/.build-id/47/437b4066718b825b28e816f46c58ab30a3f7cf': 'usr/lib64/libncurses++w.so.6.6',
    'usr/lib/.build-id/f0/1d24b6f5c772ff3f9a9e452bac67d356a96a31': 'usr/lib64/libncurses++.so.6.6',
}


COREUTILS_DEBUG_INDEXES = {
    'usr/lib/.build-id/f2/ced0172d0e9e58f7a646abd3b7dea17799d34f': 'usr/bin/coreutils.single',
}
DEBUG_INDEXES = {**NCURSES_DEBUG_INDEXES, **COREUTILS_DEBUG_INDEXES}


def installed_ncurses_indexes(root, *, run):
    return installed_debug_indexes(root, 'ncurses-libs', run=run)


def installed_debug_indexes(root, package, *, run):
    """Only the three frozen optional indexes in their exact signed owners.

    Package installation verified signatures; this query binds exact installed
    owner/header bytes. No extra optional package is installed for debug indexes.
    """
    expected_indexes = {'ncurses-libs': NCURSES_DEBUG_INDEXES, 'coreutils': COREUTILS_DEBUG_INDEXES}[package]
    query = '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n[%{FILENAMES}\t%{FILEMODES}\t%{FILELINKTOS}\t%{FILEFLAGS}\n]'
    text = run('rpm', '--root', str(root), '-q', '--qf', query, package, timeout=30)
    if len(text.encode()) > 65536:
        raise ValueError('ncurses metadata exceeds bound')
    rows = text.splitlines()
    if not rows or not re.fullmatch(re.escape(package) + r'\t[0-9]+:[A-Za-z0-9._+~-]+\.x86_64', rows[0]):
        raise ValueError('invalid ncurses/coreutils index owner')
    owner = rows[0].replace('\t', '-')
    digest_ = hashlib.sha256(text.encode()).hexdigest()
    result = {}
    for row in rows[1:]:
        fields = row.split('\t')
        if len(fields) != 4:
            raise ValueError('malformed ncurses file metadata')
        path, mode, target, flags = fields
        name = path[1:] if path.startswith('/') else ''
        if name not in expected_indexes:
            continue
        expected = '../../../../' + expected_indexes[name]
        if (name in result or not mode.isdecimal() or not flags.isdecimal()
                or not stat.S_ISLNK(int(mode)) or int(flags) & 64 or target != expected):
            raise ValueError('ncurses debug index metadata mismatch')
        result[name] = {'owner': owner, 'header_sha256': digest_, 'target': target,
                        'missing_target': expected_indexes[name]}
    return result


def unresolved_debug_index(root, key, target, indexes):
    """A narrow manifest fact, never permission for a runtime dangling link."""
    expected = DEBUG_INDEXES.get(key)
    package = 'ncurses-libs' if key in NCURSES_DEBUG_INDEXES else 'coreutils'
    evidence = indexes.get(key)
    if (expected is None or not re.fullmatch(r'usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38}', key)
            or target != '../../../../' + expected or type(evidence) is not dict
            or set(evidence) != {'owner', 'header_sha256', 'target', 'missing_target'}
            or evidence['target'] != target or evidence['missing_target'] != expected
            or type(evidence['owner']) is not str or type(evidence['header_sha256']) is not str
            or not re.fullmatch(re.escape(package) + r'-[0-9]+:[A-Za-z0-9._+~-]+\.x86_64', evidence['owner'])
            or not HEX.fullmatch(evidence['header_sha256'])):
        return None
    # Existing prefixes, root containment and loop bounds are still checked by
    # the same resolver. Only this exact missing target may be represented.
    resolved = resolve_inside(root, key, runtime_target=expected)
    if resolved != root / expected:
        raise ValueError('debug index target changed during resolution')
    return {'status': 'unresolved-optional-debug-index', **evidence}


def installed_link_owner(root, path, *, run):
    """Bounded failure inventory only; these records never authorize a link."""
    relative(path)
    query = 'OWNER\t%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n[FILE\t%{FILENAMES}\t%{FILEMODES}\t%{FILELINKTOS}\t%{FILEFLAGS}\n]'
    try:
        text = run('rpm', '--root', str(root), '-qf', '/' + path, '--qf', query, timeout=10)
    except Exception as error:
        return {'status': 'query-failed', 'error_type': type(error).__name__[:64]}
    if len(text.encode()) > 4 * 1024 * 1024:
        return {'status': 'metadata-too-large'}
    owners, current = [], None
    for row in text.splitlines():
        fields = row.split('\t')
        if len(fields) == 2 and fields[0] == 'OWNER':
            current = fields[1][:256]
        elif len(fields) == 5 and fields[0] == 'FILE' and fields[1] == '/' + path:
            if current is None or len(owners) == 8:
                return {'status': 'ambiguous-or-excessive-owners'}
            owners.append({'owner': current, 'path': fields[1][:1024], 'mode': fields[2][:32],
                           'target': fields[3][:1024], 'flags': fields[4][:32]})
    return {'status': 'observed' if owners else 'no-exact-file-row', 'owners': owners,
            'header_sha256': hashlib.sha256(text.encode()).hexdigest()}


def fingerprint(root, *, debug_indexes=None, unresolved_owner=None):
    """Hash every installed byte, mode and link target, rejecting special files."""
    if not root.is_absolute() or root.resolve() != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('canonical image root required')
    debug_indexes = {} if debug_indexes is None else debug_indexes
    entries, total, inodes = [], 0, {}
    unresolved, unresolved_count = [], 0
    inventory_bytes, inventory_full = 0, False
    reported_entries, reported_bytes = 0, 0
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
                try:
                    resolve_inside(root, key, runtime_target=runtime_target)
                except FileNotFoundError as error:
                    allowed = unresolved_debug_index(root, key, target, debug_indexes)
                    if allowed is not None:
                        item['debug_index'] = allowed
                    else:
                        missing = Path(error.filename).relative_to(root).as_posix()
                        unresolved_count += 1
                        if len(unresolved) < 16 and not inventory_full:
                            fact = {'link': key[:1024], 'target': target[:1024], 'missing': missing[:1024]}
                            if unresolved_owner is not None:
                                fact['installed_owner'] = unresolved_owner(key)
                            size = len(json.dumps(fact, ensure_ascii=True).encode())
                            if inventory_bytes + size <= 60000:
                                unresolved.append(fact)
                                inventory_bytes += size
                            else:
                                inventory_full = True
                item.update(kind='symlink', target=target)
            else:
                raise ValueError('special file in native image')
            entries.append(item)
            if len(entries) > MAX_ROOT_FILES:
                raise ValueError('native image file budget exceeded')
            if len(entries) - reported_entries >= PROGRESS_FILES or total - reported_bytes >= PROGRESS_BYTES:
                print('Native fingerprint progress:', json.dumps({'entries': len(entries), 'bytes': total}), flush=True)
                reported_entries, reported_bytes = len(entries), total
    if any(count != expected for count, expected in inodes.values()):
        raise ValueError('rootfs contains external hardlink')
    if unresolved_count:
        raise FileNotFoundError('unresolved rootfs links: ' + json.dumps({
            'count': unresolved_count, 'retained': len(unresolved),
            'truncated': unresolved_count > len(unresolved), 'links': unresolved}, ensure_ascii=True))
    document = {'version': 1, 'root_mode': stat.S_IMODE(root.stat().st_mode),
                'root_uid': root.stat().st_uid, 'root_gid': root.stat().st_gid,
                'entries': sorted(entries, key=lambda item: item['path'])}
    return {'rootfs_manifest_sha256': hashlib.sha256(canonical(document)).hexdigest(),
            'rootfs_entries': len(entries), 'rootfs_bytes': total, 'manifest': document}


def guest_guard(nonce):
    facts = {'effective_uid': os.geteuid(), 'nonce_valid': type(nonce) is str
             and re.fullmatch(r'[0-9a-f]{32}', nonce) is not None}
    def denied():
        # Individual bounded facts, never the nonce, marker contents or an
        # unbounded system dump. Diagnostics do not change any admission check.
        raise RuntimeError('native rootfs assembly requires this root-only no-NIC disposable boot: '
                           + json.dumps(facts, sort_keys=True, separators=(',', ':')))
    if facts['effective_uid'] != 0 or not facts['nonce_valid']:
        denied()
    marker = Path('/run/uas-vm-fixture')
    try:
        info = ordinary(marker)
        facts.update(marker_ordinary=True, marker_uid=info.st_uid,
                     marker_mode=oct(stat.S_IMODE(info.st_mode)),
                     marker_nonce_matches=marker.read_text().strip() == nonce)
    except (OSError, ValueError):
        facts['marker_ordinary'] = False
        denied()
    names = []
    try:
        for path in Path('/sys/class/net').iterdir():
            names.append(path.name)
            if len(names) > 16:
                break
        facts.update(interface_names=sorted(name[:32] for name in names),
                     interface_list_complete=len(names) <= 16,
                     loopback_only=names == ['lo'])
    except OSError:
        facts['interfaces_readable'] = False
        denied()
    if (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600
            or not facts['marker_nonce_matches'] or names != ['lo']):
        denied()
    print('Native rootfs guard:', json.dumps(facts, sort_keys=True), flush=True)


USRMERGE_DIRECTORIES = ('usr', 'usr/bin', 'usr/lib', 'usr/lib64', 'usr/local', 'usr/local/bin')
USRMERGE_LINKS = {'bin': 'usr/bin', 'sbin': 'usr/sbin', 'lib': 'usr/lib',
                  'lib64': 'usr/lib64', 'usr/sbin': 'bin', 'usr/local/sbin': 'bin'}
USRMERGE_GHOSTS = frozenset(('usr/sbin', 'usr/local/sbin'))


def seed_usrmerge(root):
    """Seed only documented x86_64 aliases, never repair an existing root."""
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or root.resolve() != root
            or info.st_uid != os.geteuid() or any(root.iterdir())):
        raise ValueError('fresh owned empty root required for usrmerge seed')
    for name in USRMERGE_DIRECTORIES:
        (root / name).mkdir(mode=0o755)
    for name, target in USRMERGE_LINKS.items():
        (root / name).symlink_to(target, target_is_directory=True)


def require_usrmerge(root):
    for name in USRMERGE_DIRECTORIES:
        if not stat.S_ISDIR((root / name).lstat().st_mode):
            raise ValueError('native usrmerge shape changed: ' + name)
    for name, target in USRMERGE_LINKS.items():
        if (not stat.S_ISLNK((root / name).lstat().st_mode)
                or os.readlink(root / name) != target):
            raise ValueError('native usrmerge shape changed: ' + name)


def verify_filesystem_layout(root, *, run):
    """Check installed signed package contract; ghost targets come from pretrans.

    The offline transaction already enforces signature verification. These are
    read-only RPM queries, never execution of the package's pretrans script.
    """
    query = '%{NAME}\t%{ARCH}\n[%{FILENAMES}\t%{FILEMODES}\t%{FILELINKTOS}\t%{FILEFLAGS}\n]'
    metadata = run('rpm', '--root', str(root), '-q', '--qf', query, 'filesystem', timeout=30)
    pretrans = run('rpm', '--root', str(root), '-q', '--qf', '%{PRETRANS}', 'filesystem', timeout=30)
    if len(metadata.encode()) > 4 * 1024 * 1024 or len(pretrans.encode()) > 65536:
        raise ValueError('filesystem metadata exceeds bound')
    rows = metadata.splitlines()
    if not rows or rows[0] != 'filesystem\tx86_64' or len(rows) > MAX_ROOT_FILES + 1:
        raise ValueError('unsupported installed filesystem package')
    seen, observed_ghosts = set(), {}
    for row in rows[1:]:
        fields = row.split('\t')
        if len(fields) != 4:
            raise ValueError('malformed filesystem file metadata')
        path, mode, target, flags = fields
        name = path[1:] if path.startswith('/') else ''
        if name not in USRMERGE_LINKS:
            continue
        if name in seen or not mode.isdecimal() or not flags.isdecimal():
            raise ValueError('ambiguous filesystem alias metadata')
        seen.add(name)
        ghost = name in USRMERGE_GHOSTS
        if (not ghost and not stat.S_ISLNK(int(mode))) or bool(int(flags) & 64) != ghost:
            raise ValueError('filesystem alias type/ghost mismatch: ' + name)
        if not ghost and target != USRMERGE_LINKS[name]:
            raise ValueError('filesystem payload alias mismatch: ' + name)
        if ghost:
            # Ghost files need not carry a payload link target. Require the
            # exact documented creation in signed package pretrans instead.
            pattern = r'posix\.symlink\(\s*"bin"\s*,\s*"/' + re.escape(name) + r'"\s*\)'
            observed_ghosts[name] = {'mode': int(mode), 'link_target': target, 'flags': int(flags)}
            if not re.search(pattern, pretrans):
                raise ValueError('filesystem ghost pretrans mismatch: ' + name)
    if seen != set(USRMERGE_LINKS):
        raise ValueError('filesystem aliases missing from metadata')
    require_usrmerge(root)
    return {'architecture': 'x86_64', 'aliases': dict(USRMERGE_LINKS),
            'ghost_target_source': 'installed-signed-package-pretrans-not-executed',
            'observed_ghost_metadata': observed_ghosts,
            'metadata_sha256': hashlib.sha256(metadata.encode()).hexdigest(),
            'pretrans_sha256': hashlib.sha256(pretrans.encode()).hexdigest()}


def build_rootfs(nonce, manifest, destination, *, run):
    guest_guard(nonce)
    archive, files = verify_runtime(PAYLOAD, manifest['native_runtime'])
    root = Path(destination)
    if not root.is_absolute() or root.parent.resolve() != root.parent or root.exists() or root.is_symlink():
        raise ValueError('fresh canonical rootfs path required')
    root.mkdir(mode=0o755)
    seed_usrmerge(root)
    # Observe the tools actually executing, not versions merely in the RPM pool.
    package_tools = run('rpm', '-q', '--qf', '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n',
                        'rpm', 'rpm-libs', 'dnf5', 'libdnf5', timeout=30)
    if len(package_tools.encode()) > 4096:
        raise ValueError('oversized package tool identity')
    print('Native package tools:', json.dumps(package_tools), flush=True)
    # Payload hashes/signatures and repodata were verified by guest install;
    # only this read-only file repository is made visible to the native solver.
    print('Native rootfs phase: rpm-transaction start', flush=True)
    run('dnf', '-y', '--installroot=' + str(root), '--releasever=44',
        '--disablerepo=*', '--repofrompath=uas-native,file://' + str(PAYLOAD / 'rpms'),
        '--enablerepo=uas-native', '--setopt=uas-native.gpgcheck=1',
        '--setopt=uas-native.repo_gpgcheck=0', '--setopt=uas-native.gpgkey=file://' + str(PAYLOAD / 'fedora-44.asc'),
        '--setopt=localpkg_gpgcheck=True', '--setopt=install_weak_deps=False',
        '--setopt=tsflags=noscripts', '--setopt=plugins=False',
        'install', *ROOTS, timeout=900, native_failure_context=True)
    print('Native rootfs phase: rpm-transaction complete', flush=True)
    print('Native rootfs phase: filesystem-metadata start', flush=True)
    filesystem_layout = verify_filesystem_layout(root, run=run)
    print('Native rootfs phase: filesystem-metadata complete', flush=True)
    print('Native rootfs phase: runtime-extraction start', flush=True)
    extract_runtime(archive, files, root)
    print('Native rootfs phase: runtime-extraction complete', flush=True)
    print('Native rootfs phase: tini-copy start', flush=True)
    source = resolve_inside(root, 'usr/bin/tini')
    ordinary(source)
    target = root / 'opt/uas/bin/tini'
    _directory(root, ('opt', 'uas', 'bin'))
    with source.open('rb') as input_, target.open('xb') as output:
        shutil.copyfileobj(input_, output)
    target.chmod(0o555)
    print('Native rootfs phase: tini-copy complete', flush=True)
    # mkdir is umask-sensitive and RPM may adjust the installroot mode. The
    # imported image root must be traversable by both fixed unprivileged UIDs.
    root.chmod(0o755)
    print('Native rootfs phase: debug-metadata start', flush=True)
    debug_indexes = installed_ncurses_indexes(root, run=run)
    debug_indexes.update(installed_debug_indexes(root, 'coreutils', run=run))
    print('Native rootfs phase: debug-metadata complete', flush=True)
    print('Native rootfs phase: fingerprint start', flush=True)
    result = fingerprint(root, debug_indexes=debug_indexes,
                         unresolved_owner=lambda path: installed_link_owner(root, path, run=run))
    print('Native rootfs phase: fingerprint complete', flush=True)
    print('Native rootfs phase: manifest-write start', flush=True)
    manifest_path = root.with_name(root.name + '.manifest.json')
    with manifest_path.open('xb') as output:
        output.write(canonical(result.pop('manifest')))
        output.flush(); os.fsync(output.fileno())
    manifest_path.chmod(0o444)
    print('Native rootfs phase: manifest-write complete', flush=True)
    return {**result, 'rootfs_manifest': str(manifest_path), 'runtime_sha256': manifest['native_runtime']['sha256'],
            'tini_sha256': digest(target), 'rpm_roots': list(ROOTS), 'rpm_scriptlets': False,
            'rpm_automatic_sysusers': True, 'package_tools': package_tools,
            'filesystem_layout': filesystem_layout}
