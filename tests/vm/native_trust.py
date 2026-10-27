"""Four fixed offline trust generators for the already verified guest installroot.

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
    'usr/bin/python3': 'python3',
    'usr/bin/update-crypto-policies': 'crypto-policies-scripts',
    'usr/bin/trust': 'p11-kit-trust',
    'usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit': 'ca-certificates',
}
ENVIRONMENT = ('P11_KIT_NO_USER_CONFIG=1', 'PATH=/usr/bin:/usr/sbin', 'LC_ALL=C', 'HOME=/nonexistent')


def fixed_commands(root):
    prefix = ('/usr/bin/chroot', str(root), '/usr/bin/env', '-i', *ENVIRONMENT)
    return (
        (*prefix, '/usr/bin/python3', '-B', '/usr/bin/update-crypto-policies', '--no-reload', '--set', 'DEFAULT'),
        (*prefix, '/usr/bin/trust', 'extract', '--format=openssl-bundle', '--filter=certificates',
         '--overwrite', '--comment', '/' + CA_OUTPUTS[0]),
        (*prefix, '/usr/bin/trust', 'extract', '--format=pem-bundle', '--filter=ca-anchors',
         '--overwrite', '--comment', '--purpose', 'server-auth', '/' + CA_OUTPUTS[1]),
        (*prefix, '/usr/bin/trust', 'extract', '--format=java-cacerts', '--filter=ca-anchors',
         '--overwrite', '--purpose', 'server-auth', '/' + CA_OUTPUTS[2]),
    )


def _snapshot(root):
    from native_rootfs import MAX_ROOT_FILES, MAX_ROOT_BYTES, digest, canonical, relative
    records, total = {}, 0
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
            row.update(kind='file', bytes=info.st_size, sha256=digest(path))
            after = path.lstat()
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('trust inventory file changed during hashing')
        elif stat.S_ISDIR(info.st_mode): row['kind'] = 'directory'
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if len(os.fsencode(target)) > 4096: raise ValueError('trust inventory link target exceeds bound')
            row.update(kind='symlink', target=target)
        else: raise ValueError('special file in trust inventory')
        records[key] = row
        if number and number % 1024 == 0:
            print('Native trust inventory progress:', json.dumps({'files': number, 'bytes': total}), flush=True)
    return records, {'files': len(records), 'bytes': total,
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
    forbidden = [key for key in changed if key not in CA_OUTPUTS
                 and key != 'etc/crypto-policies' and not key.startswith('etc/crypto-policies/')]
    if forbidden:
        raise ValueError('unexpected trust generation changes: ' + json.dumps({
            'changed_count': len(changed), 'forbidden_count': len(forbidden),
            'truncated': len(forbidden) > 16, 'paths': forbidden[:16]}))
    return changed


def generate_trust(root, *, run):
    from native_rootfs import resolve_inside, ordinary, digest, canonical
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('canonical trust installroot required')
    before, before_summary = _snapshot(root)
    for key in CA_OUTPUTS:
        if key in before: raise ValueError('trust output must be fresh: ' + key)
        parent = resolve_inside(root, str(Path(key).parent))
        if parent != root / Path(key).parent or not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError('noncanonical trust output parent')
    verified = [_verify_input(root, path, owner, run=run) for path, owner in VERIFIED_INPUTS.items()]
    try:
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
    outputs = []
    for key in (*CA_OUTPUTS, FIPS_OUTPUT):
        target = resolve_inside(root, key)
        info = ordinary(target)
        if not info.st_size: raise ValueError('empty generated trust output: ' + key)
        if key in CA_OUTPUTS and target != root / key: raise ValueError('generated CA output is not ordinary')
        outputs.append({'path': key, 'resolved_path': target.relative_to(root).as_posix(),
                        'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode),
                        'uid': info.st_uid, 'gid': info.st_gid, 'sha256': digest(target)})
    evidence = {'version': 1, 'policy': 'DEFAULT', 'commands': 4, 'package_scriptlets': False,
                'verified_inputs': verified, 'before': before_summary, 'after': after_summary,
                'changed_count': len(changed), 'changed_sha256': hashlib.sha256(canonical(changed)).hexdigest(),
                'outputs': outputs}
    if len(canonical(evidence)) > 8192: raise ValueError('trust evidence exceeds bound')
    return evidence
