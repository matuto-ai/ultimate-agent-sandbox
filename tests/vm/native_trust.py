"""Signed DEFAULT materialization and three fixed offline CA generators.

Never runs package scriptlets, imports host trust or relaxes dangling-link checks.
Signature provenance is the preceding verified offline RPM transaction; installed
header digests additionally bind the exact tools and CA source used here.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

CA_OUTPUTS = (
    'etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt',
    'etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
    'etc/pki/ca-trust/extracted/java/cacerts',
)
FIPS_OUTPUT = 'etc/crypto-policies/back-ends/openssl_fips.config'
VERIFIED_INPUTS = {
    'usr/bin/env': 'coreutils',
    'usr/bin/trust': 'p11-kit-trust',
    'usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit': 'ca-certificates',
}
POLICY_BACKENDS = ('bind', 'gnutls', 'java', 'krb5', 'libreswan', 'libssh', 'nss',
                   'openssh', 'opensshserver', 'openssl_fips', 'opensslcnf',
                   'rpm-sequoia', 'sequoia')
POLICY_ASSETS = {name: 'usr/share/crypto-policies/DEFAULT/' + name + '.txt'
                 for name in POLICY_BACKENDS}
POLICY_LINKS = {'etc/crypto-policies/back-ends/' + name + '.config': '/' + path
               for name, path in POLICY_ASSETS.items()}
DEFAULT_CONFIG = 'usr/share/crypto-policies/default-config'
POLICY_CONFIG = 'etc/crypto-policies/config'
POLICY_CURRENT = 'etc/crypto-policies/state/current'
POLICY_OUTPUTS = (*POLICY_LINKS, POLICY_CONFIG, POLICY_CURRENT)
ALLOWED_OUTPUTS = frozenset((*CA_OUTPUTS, *POLICY_OUTPUTS))
MAX_POLICY_BYTES = 65536
ENVIRONMENT = ('P11_KIT_NO_USER_CONFIG=1', 'PATH=/usr/bin:/usr/sbin', 'LC_ALL=C', 'HOME=/nonexistent')


def fixed_commands(root):
    prefix = ('/usr/bin/chroot', str(root), '/usr/bin/env', '-i', *ENVIRONMENT)
    return (
        (*prefix, '/usr/bin/trust', 'extract', '--format=openssl-bundle', '--filter=certificates',
         '--overwrite', '--comment', '/' + CA_OUTPUTS[0]),
        (*prefix, '/usr/bin/trust', 'extract', '--format=pem-bundle', '--filter=ca-anchors',
         '--overwrite', '--comment', '--purpose', 'server-auth', '/' + CA_OUTPUTS[1]),
        (*prefix, '/usr/bin/trust', 'extract', '--format=java-cacerts', '--filter=ca-anchors',
         '--overwrite', '--purpose', 'server-auth', '/' + CA_OUTPUTS[2]),
    )


def _snapshot(root):
    from native_rootfs import MAX_ROOT_FILES, MAX_ROOT_BYTES, digest, canonical, relative
    records, total, inodes = {}, 0, {}
    paths = [root]
    def walk_error(error):
        raise error
    for base, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        paths.extend(Path(base) / name for name in sorted(dirs + files))
        if len(paths) > MAX_ROOT_FILES + 1:
            raise ValueError('trust inventory file budget exceeded')
    for number, path in enumerate(paths):
        key = path.relative_to(root).as_posix()
        if key != '.': relative(key)
        info = path.lstat()
        row = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > MAX_ROOT_BYTES: raise ValueError('trust inventory byte budget exceeded')
            row.update(kind='file', bytes=info.st_size, sha256=digest(path),
                       device=info.st_dev, inode=info.st_ino, links=info.st_nlink)
            after = path.lstat()
            if (info.st_dev, info.st_ino, info.st_nlink, info.st_mode, info.st_uid, info.st_gid,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_nlink, after.st_mode, after.st_uid, after.st_gid,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('trust inventory file changed during hashing')
            inode = (info.st_dev, info.st_ino)
            count, expected = inodes.get(inode, (0, info.st_nlink))
            if expected != info.st_nlink: raise ValueError('trust inventory hardlink changed')
            inodes[inode] = (count + 1, expected)
        elif stat.S_ISDIR(info.st_mode): row['kind'] = 'directory'
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if len(os.fsencode(target)) > 4096: raise ValueError('trust inventory link target exceeds bound')
            row.update(kind='symlink', target=target)
        else: raise ValueError('special file in trust inventory')
        records[key] = row
        if number and number % 1024 == 0:
            print('Native trust inventory progress:', json.dumps({'files': number, 'bytes': total}), flush=True)
    if any(count != expected for count, expected in inodes.values()):
        raise ValueError('trust inventory contains external hardlink')
    return records, {'files': len(records), 'bytes': total, 'internal_hardlinks_verified': True,
                     'sha256': hashlib.sha256(canonical(records)).hexdigest()}


def _verify_input(root, path, owner, *, run):
    from native_rootfs import resolve_inside, ordinary, digest
    resolved = resolve_inside(root, path)
    info = ordinary(resolved)
    key = resolved.relative_to(root).as_posix()
    query = '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEMODES}\t%{FILEDIGESTS}\n]'
    text = run('rpm', '--root', str(root), '-qf', '/' + key, '--qf', query, timeout=30)
    if len(text.encode()) > 4 * 1024 * 1024: raise ValueError('trust tool header exceeds bound')
    rows = text.splitlines()
    if not rows: raise ValueError('missing trust tool owner')
    header = rows[0].split('\t')
    if (len(header) != 3 or header[0] != owner or header[2] != '8'
            or not re.fullmatch(r'[0-9]+:[A-Za-z0-9._+~-]+\.(?:x86_64|noarch)', header[1])):
        raise ValueError('unexpected trust tool owner/digest algorithm')
    matches = []
    for line in rows[1:]:
        fields = line.split('\t')
        if len(fields) != 3: raise ValueError('malformed trust tool file header')
        if fields[0] == '/' + key: matches.append(fields)
    actual = digest(resolved)
    if (len(matches) != 1 or not matches[0][1].isdecimal()
            or int(matches[0][1]) != info.st_mode
            or not re.fullmatch(r'[0-9a-f]{64}', matches[0][2]) or matches[0][2] != actual):
        raise ValueError('trust tool bytes/mode differ from installed header')
    return {'path': path, 'resolved_path': key, 'owner': owner + '-' + header[1],
            'sha256': actual, 'header_sha256': hashlib.sha256(text.encode()).hexdigest()}


def _check_changes(before, after):
    changed = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
    forbidden = [key for key in changed if key not in ALLOWED_OUTPUTS]
    if forbidden:
        raise ValueError('unexpected trust generation changes: ' + json.dumps({
            'changed_count': len(changed), 'forbidden_count': len(forbidden),
            'truncated': len(forbidden) > 16, 'paths': forbidden[:16]}))
    return changed


def _policy_asset(root, key, entry, inventory):
    """Accept packaged hardlinks only after the whole-root inode-count proof.

    This is deliberately separate from ordinary(): executable tools, copied
    payloads and fresh CA files retain their single-link requirement.
    """
    from native_rootfs import resolve_inside, digest
    path = resolve_inside(root, key)
    info = path.lstat()
    observed = inventory.get(key, {})
    mode, flags, expected, target = entry
    if (path != root / key or not stat.S_ISREG(info.st_mode)
            or mode != (stat.S_IFREG | 0o644) or mode != info.st_mode or flags != 0 or target
            or not 0 < info.st_size <= MAX_POLICY_BYTES
            or not re.fullmatch(r'[0-9a-f]{64}', expected)
            or observed.get('kind') != 'file'
            or (info.st_dev, info.st_ino, info.st_nlink, info.st_size) != (
                observed.get('device'), observed.get('inode'), observed.get('links'), observed.get('bytes'))
            or observed.get('sha256') != expected or digest(path) != expected):
        raise ValueError('policy asset differs from installed header/inventory: ' + key)
    return {'sha256': expected, 'bytes': info.st_size, 'mode': 0o644, 'links': info.st_nlink}


def _verify_default_policy(root, before, *, run):
    from native_rootfs import canonical, resolve_inside, MAX_ROOT_FILES, relative
    query = '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEMODES}\t%{FILEFLAGS}\t%{FILEDIGESTS}\t%{FILELINKTOS}\n]'
    text = run('rpm', '--root', str(root), '-q', '--qf', query, 'crypto-policies', timeout=30)
    if len(text.encode()) > 4 * 1024 * 1024: raise ValueError('policy header exceeds bound')
    rows = text.splitlines()
    if not rows or len(rows) > MAX_ROOT_FILES + 1: raise ValueError('missing/excessive policy header')
    header = rows[0].split('\t')
    if (len(header) != 3 or header[0] != 'crypto-policies' or header[2] != '8'
            or not re.fullmatch(r'[0-9]+:[A-Za-z0-9._+~-]+\.noarch', header[1])):
        raise ValueError('unexpected policy owner/digest algorithm')
    required = {*POLICY_ASSETS.values(), DEFAULT_CONFIG, *POLICY_OUTPUTS}
    entries, actual_assets = {}, set()
    for row in rows[1:]:
        fields = row.split('\t')
        if (len(fields) != 5 or not fields[0].startswith('/')
                or not fields[1].isdecimal() or not fields[2].isdecimal()):
            raise ValueError('malformed policy file header')
        key = fields[0][1:]; relative(key)
        if key.startswith('usr/share/crypto-policies/DEFAULT/'):
            actual_assets.add(key)
        if key in required:
            if key in entries: raise ValueError('duplicate policy file header')
            entries[key] = (int(fields[1]), int(fields[2]), fields[3], fields[4])
    if entries.keys() != required or actual_assets != set(POLICY_ASSETS.values()):
        raise ValueError('policy header does not match fixed DEFAULT contract')
    directory = root / 'usr/share/crypto-policies/DEFAULT'
    if (resolve_inside(root, 'usr/share/crypto-policies/DEFAULT') != directory
            or not stat.S_ISDIR(directory.lstat().st_mode)
            or set(path.name for path in directory.iterdir()) != {name + '.txt' for name in POLICY_BACKENDS}):
        raise ValueError('unexpected DEFAULT asset directory')
    ghosts = {}
    for key in POLICY_OUTPUTS:
        mode, flags, digest_, target = entries[key]
        expected_mode = stat.S_IFLNK | 0o777 if key in POLICY_LINKS else stat.S_IFREG | 0o644
        expected_flags = 64 if key == POLICY_CURRENT else 89  # ghost [+ config, missingok, noreplace]
        if (mode != expected_mode or flags != expected_flags or digest_
                or target != POLICY_LINKS.get(key, '')):
            raise ValueError('policy ghost destination mismatch: ' + key)
        ghosts[key] = {'mode': mode, 'flags': flags, 'target': target}
    assets = {name: _policy_asset(root, key, entries[key], before) for name, key in POLICY_ASSETS.items()}
    config = _policy_asset(root, DEFAULT_CONFIG, entries[DEFAULT_CONFIG], before)
    with (root / DEFAULT_CONFIG).open('rb') as source:
        data = source.read(MAX_POLICY_BYTES + 1)
    if len(data) > MAX_POLICY_BYTES: raise ValueError('default config exceeds bound')
    if hashlib.sha256(data).hexdigest() != config['sha256']:
        raise ValueError('default config changed during read')
    directives = [line.split('#', 1)[0].strip() for line in data.decode('ascii').splitlines()]
    if [line for line in directives if line] != ['DEFAULT']:
        raise ValueError('packaged default config must select only DEFAULT')
    return data, {'mode': 'signed-pregenerated-DEFAULT', 'owner': 'crypto-policies-' + header[1],
                  'header_sha256': hashlib.sha256(text.encode()).hexdigest(), 'default_config': config,
                  'backend_inputs': assets, 'ghost_destination_count': len(ghosts),
                  'ghost_contract_sha256': hashlib.sha256(canonical(ghosts)).hexdigest(),
                  'state_current': 'DEFAULT\\n', 'current_pol_created': False, 'updater_executed': False}


def _materialize_default(root, data):
    # Exact fresh package-default shape, not generic package scriptlet execution.
    for key, content in ((POLICY_CONFIG, data), (POLICY_CURRENT, b'DEFAULT\n')):
        with (root / key).open('xb') as output:
            output.write(content); output.flush(); os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
    for key, target in POLICY_LINKS.items():
        (root / key).symlink_to(target)


def _validate_default(root, data):
    from native_rootfs import resolve_inside, ordinary
    for key, expected in ((POLICY_CONFIG, data), (POLICY_CURRENT, b'DEFAULT\n')):
        path = root / key
        info = ordinary(path)
        if (stat.S_IMODE(info.st_mode) != 0o644 or path.read_bytes() != expected
                or (info.st_uid, info.st_gid) != (root.stat().st_uid, root.stat().st_gid)):
            raise ValueError('materialized policy file changed: ' + key)
    for key, target in POLICY_LINKS.items():
        path = root / key
        info = path.lstat()
        if (not stat.S_ISLNK(info.st_mode) or os.readlink(path) != target
                or (info.st_uid, info.st_gid) != (root.stat().st_uid, root.stat().st_gid)
                or resolve_inside(root, key) != root / target.lstrip('/')):
            raise ValueError('materialized policy link changed: ' + key)


def generate_trust(root, *, run):
    from native_rootfs import resolve_inside, ordinary, digest, canonical
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('canonical trust installroot required')
    before, before_summary = _snapshot(root)
    for key in (*CA_OUTPUTS, *POLICY_OUTPUTS):
        if key in before: raise ValueError('trust output must be fresh: ' + key)
        parent = resolve_inside(root, str(Path(key).parent))
        if parent != root / Path(key).parent or not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError('noncanonical trust output parent')
    verified = [_verify_input(root, path, owner, run=run) for path, owner in VERIFIED_INPUTS.items()]
    default_data, policy = _verify_default_policy(root, before, run=run)
    try:
        _materialize_default(root, default_data)
        for command in fixed_commands(root):
            run(*command, timeout=90, native_trust_context=True)
    except BaseException as error:
        try:
            after, summary = _snapshot(root)
            changed = _check_changes(before, after)
            error.add_note('Native trust failure inventory: ' + json.dumps({'after': summary, 'changed_count': len(changed), 'truncated': len(changed) > 16, 'changed': changed[:16]}))
        except BaseException as inventory_error:
            error.add_note('Native trust failure inventory: ' + str(inventory_error)[:2048])
        raise
    after, after_summary = _snapshot(root)
    changed = _check_changes(before, after)
    _validate_default(root, default_data)
    outputs = []
    for key in (*CA_OUTPUTS, FIPS_OUTPUT):
        target = resolve_inside(root, key)
        info = ordinary(target) if key in CA_OUTPUTS else target.lstat()
        if not stat.S_ISREG(info.st_mode): raise ValueError('generated output is not regular')
        if not info.st_size: raise ValueError('empty generated trust output: ' + key)
        if key in CA_OUTPUTS and target != root / key: raise ValueError('generated CA output is not ordinary')
        outputs.append({'path': key, 'resolved_path': target.relative_to(root).as_posix(),
                        'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode),
                        'uid': info.st_uid, 'gid': info.st_gid, 'sha256': digest(target)})
    evidence = {'version': 2, 'policy': 'DEFAULT', 'commands': 3, 'package_scriptlets': False,
                'policy_materialization': policy,
                'verified_inputs': verified, 'before': before_summary, 'after': after_summary,
                'changed_count': len(changed), 'changed_sha256': hashlib.sha256(canonical(changed)).hexdigest(),
                'outputs': outputs}
    if len(canonical(evidence)) > 8192: raise ValueError('trust evidence exceeds bound')
    return evidence


def validate_public_ca(root):
    """Offline parse of the exact generated server-auth PEM, never host defaults.

    This proves native SSL can load anchors, not that a remote peer will verify.
    No socket, fallback store, verification override or certificate text output.
    """
    import ssl
    from native_rootfs import resolve_inside, ordinary, digest
    root = Path(root)
    key = CA_OUTPUTS[1]
    target = resolve_inside(root, key)
    info = ordinary(target)
    if target != root / key or not 0 < info.st_size <= 4 * 1024 * 1024:
        raise ValueError('generated server-auth PEM path or size invalid')
    before = digest(target)
    context = ssl.create_default_context(cafile=str(target))
    if context.verify_mode != ssl.CERT_REQUIRED or context.check_hostname is not True:
        raise ValueError('native SSL verification defaults invalid')
    stats = context.cert_store_stats()
    if type(stats.get('x509_ca')) is not int or stats['x509_ca'] <= 0:
        raise ValueError('generated server-auth PEM contains no CA anchors')
    if digest(target) != before:
        raise ValueError('generated server-auth PEM changed during validation')
    return {'status': 'passed', 'path': key, 'sha256': before,
            'bytes': info.st_size, 'ca_anchors': stats['x509_ca'],
            'certificate_required': True, 'hostname_check': True,
            'scope': 'offline-native-SSL-load-only'}
