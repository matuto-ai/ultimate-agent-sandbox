"""Explicit immutable Room preparation contract; never a cached test result.

The selected receipt digest must come from the reviewed producer, not from an
untrusted artifact's own contents. No discovery, latest-selection or cold fallback.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time

VERSION = 1
PROFILE = 'room-launch-ipv4-v1'
BASE_SOURCES = ('tests/vm/prepared_room.py', 'tests/vm/guest_boundary.py',
                'tests/vm/room_profile.py', 'tests/vm/fedora-image.json')
MAX_RECEIPT = 2 * 1024**2
MAX_BASE = 8 * 1024**3
MAX_POOL = 1100 * 1024**2
GUEST_RECEIPT = Path('/var/lib/uas-prepared-room.json')


def require(value, message):
    if not value: raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate prepared key')
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hash_file(path, maximum):
    path = Path(path)
    node = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISREG(node.st_mode)
            and node.st_nlink == 1 and node.st_uid == os.getuid()
            and not node.st_mode & 0o022 and 0 < node.st_size <= maximum,
            'ordinary bounded prepared file required')
    with path.open('rb') as source: actual = hashlib.file_digest(source, 'sha256').hexdigest()
    after = path.lstat()
    require((node.st_dev, node.st_ino, node.st_size, node.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            'prepared file changed while hashing')
    return {'bytes': node.st_size, 'sha256': actual}


def hex_digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'exact prepared digest required')
    return value


def pool_contract(manifest):
    require(type(manifest) is dict and manifest.get('version') == 1
            and manifest.get('release') == '44' and manifest.get('profile') == PROFILE,
            'prepared pool profile differs')
    fingerprint = manifest.get('signing_fingerprint')
    require(type(fingerprint) is str and re.fullmatch('[A-F0-9]{40}', fingerprint), 'invalid release signer')
    packages = manifest.get('packages')
    require(type(packages) is list and 0 < len(packages) <= 512, 'bounded package pool required')
    seen, total = set(), 0
    for package in packages:
        require(type(package) is dict and set(package) == {'file','name','epoch','version','release','arch',
                'bytes','sha256','signature_verified'}, 'invalid package record')
        name = package['file']
        require(type(name) is str and re.fullmatch('[A-Za-z0-9._+~^%-]{1,240}\\.rpm', name)
                and name not in seen, 'invalid or duplicate RPM path')
        seen.add(name)
        require(all(type(package[field]) is str and re.fullmatch('[A-Za-z0-9._+~^%-]{1,256}', package[field])
                    for field in ('name','epoch','version','release','arch'))
                and package['arch'] in ('x86_64','noarch') and package['epoch'].isdigit()
                and package['signature_verified'] is True, 'unsigned or invalid package identity')
        require(type(package['bytes']) is int and 0 < package['bytes'] <= 128 * 1024**2, 'RPM byte bound')
        hex_digest(package['sha256']); total += package['bytes']
    require(total <= 1024**3, 'pool byte bound')
    metadata = manifest.get('repository_metadata')
    require(type(metadata) is list and 0 < len(metadata) <= 16, 'bounded repodata required')
    for entry in metadata:
        require(type(entry) is dict and set(entry) == {'file','bytes','sha256'}, 'invalid repodata record')
        name = entry['file']
        require(type(name) is str and re.fullmatch(r'repodata/[A-Za-z0-9._-]{1,240}', name)
                and name not in seen, 'unsafe or duplicate repodata path')
        seen.add(name)
        require(type(entry['bytes']) is int and 0 < entry['bytes'] <= 8 * 1024**2, 'repodata byte bound')
        hex_digest(entry['sha256']); total += entry['bytes']
    require('repodata/repomd.xml' in {entry['file'] for entry in metadata}, 'repomd index required')
    key = manifest.get('key')
    require(type(key) is dict and set(key) == {'file','bytes','sha256'}
            and key['file'] == 'fedora-44.asc' and type(key['bytes']) is int
            and 0 < key['bytes'] <= 1024**2, 'invalid signing key record')
    hex_digest(key['sha256'])
    require(total <= MAX_POOL, 'pool size exceeded')
    return {'version': VERSION, 'profile': PROFILE, 'release': '44',
            'signing_fingerprint': fingerprint, 'key': key,
            'packages': sorted(packages, key=lambda item:item['file']),
            'repository_metadata': sorted(metadata, key=lambda item:item['file'])}


def foundation(manifest):
    pool = pool_contract(manifest)
    source = manifest.get('source')
    require(type(source) is list, 'source identities required')
    selected = []
    for name in BASE_SOURCES:
        matches = [item for item in source if type(item) is dict and item.get('file') == name]
        require(len(matches) == 1 and set(matches[0]) == {'file','bytes','sha256'}, 'missing base source')
        item = matches[0]
        require(type(item['bytes']) is int and 0 < item['bytes'] <= 1024**2, 'base source size')
        hex_digest(item['sha256']); selected.append(item)
    return {'version': VERSION, 'profile': PROFILE, 'architecture': 'x86_64',
            'pool': pool, 'setup_sources': selected}


def verify_pool(root, pool, *, source_has_payload=False):
    pool_contract(pool)
    require(root.is_absolute() and root.resolve() == root and root.is_dir()
            and root.stat().st_uid == os.getuid() and not root.stat().st_mode & 0o022,
            'owned non-writable prepared pool required')
    expected = {'fedora-44.asc'}
    for prefix, entries in (('', [pool['key']]), ('rpms/', pool['packages'] + pool['repository_metadata'])):
        for entry in entries:
            relative = prefix + entry['file']; expected.add(relative)
            require(hash_file(root / relative, MAX_POOL) == {key:entry[key] for key in ('bytes','sha256')},
                    'prepared pool file differs')
    actual = set()
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'symlink in prepared pool')
        if path.is_file(): actual.add(path.relative_to(root).as_posix())
        else: require(path.is_dir(), 'special node in prepared pool')
    require(expected <= actual if source_has_payload else actual == expected, 'unexpected prepared pool entries')


def current_sources(root, contract):
    for entry in contract['setup_sources']:
        require(hash_file(root / entry['file'], 1024**2) == {key:entry[key] for key in ('bytes','sha256')},
                'prepared base setup changed; explicit rebuild required')


def select(directory, expected_digest, repository_root):
    """Verify everything before QEMU or payload creation; caller supplies trusted digest."""
    directory = Path(directory)
    require(directory.is_absolute() and directory.resolve() == directory and directory.is_dir(),
            'explicit canonical prepared directory required')
    require(directory.stat().st_uid == os.getuid() and not directory.stat().st_mode & 0o022,
            'owned non-writable prepared directory required')
    expected_digest = hex_digest(expected_digest)
    receipt = directory / 'receipt.json'
    require(hash_file(receipt, MAX_RECEIPT)['sha256'] == expected_digest, 'prepared receipt digest differs')
    value = json.loads(receipt.read_bytes(), object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {'version','profile','base_key','foundation',
            'base','guest_receipt','producer','qualification','created_at'}, 'prepared receipt schema')
    require(value['version'] == VERSION and value['profile'] == PROFILE
            and value['qualification'] == 'NOT_RUN', 'not a clean prepared base')
    now = time.time()
    require(type(value['created_at']) is int and 0 <= now - value['created_at'] <= 7*24*3600,
            'prepared artifact expired or from the future; explicit rebuild required')
    contract = value['foundation']
    require(type(contract) is dict and set(contract) == {'version','profile','architecture','pool','setup_sources'}
            and contract['version'] == VERSION and contract['profile'] == PROFILE
            and contract['architecture'] == 'x86_64', 'invalid base foundation')
    require(value['base_key'] == digest(contract), 'base key differs')
    # Reconstruct the canonical contract, including exact source list/order.
    reconstructed = foundation({**contract['pool'], 'source':contract['setup_sources']})
    require(contract == reconstructed, 'noncanonical base foundation')
    current_sources(Path(repository_root), contract)
    require(type(value['producer']) is dict and set(value['producer']) == {'commit','run_id'}
            and re.fullmatch('[0-9a-f]{40}', value['producer']['commit'] or '')
            and re.fullmatch('[1-9][0-9]{0,19}', value['producer']['run_id'] or ''), 'producer identity required')
    require(type(value['base']) is dict and set(value['base']) == {'bytes','sha256'}, 'base identity required')
    require(hash_file(directory / 'base.qcow2', MAX_BASE) == value['base'], 'prepared disk differs')
    verify_pool(directory / 'pool', contract['pool'])
    require({p.name for p in directory.iterdir()} == {'receipt.json','base.qcow2','pool'},
            'unexpected prepared artifact entries')
    guest = value['guest_receipt']
    validate_guest_receipt(guest, value['base_key'])
    return value


def validate_guest_receipt(value, key):
    require(type(value) is dict and set(value) == {'version','base_key','inventory','kernel','clean','scenario_started'}
            and value['version'] == VERSION and value['base_key'] == hex_digest(key)
            and value['clean'] is True and value['scenario_started'] is False, 'unclean prepared guest')
    require(type(value['inventory']) is str and 0 < len(value['inventory']) <= 128*1024
            and type(value['kernel']) is str and re.fullmatch('[A-Za-z0-9._+-]{1,128}', value['kernel']),
            'bounded installed inventory required')
    return value


def standalone_info(value):
    require(type(value) is dict and value.get('format') == 'qcow2'
            and not any(value.get(key) for key in ('backing-filename','full-backing-filename','backing-filename-format','data-file'))
            and type(value.get('virtual-size')) is int and 0 < value['virtual-size'] <= 64*1024**3,
            'standalone bounded qcow2 required')
    specific = value.get('format-specific', {}).get('data', {})
    require(type(specific) is dict and not specific.get('data-file'), 'external qcow data file forbidden')


def copy_pool(source, target, pool, *, source_has_payload=False):
    verify_pool(source, pool, source_has_payload=source_has_payload)
    target.mkdir()
    for prefix, entries in (('', [pool['key']]), ('rpms/', pool['packages'] + pool['repository_metadata'])):
        for entry in entries:
            relative = prefix + entry['file']; output = target / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            with (source / relative).open('rb') as old, output.open('xb') as new:
                shutil.copyfileobj(old, new)
    verify_pool(target, pool)


def inventory(run):
    raw = run('rpm', '-qa', '--queryformat', '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n', timeout=90)
    require(0 < len(raw) <= 128 * 1024, 'bounded installed package inventory required')
    return '\n'.join(sorted(raw.splitlines())) + '\n'


def provision(manifest, nonce, boundary, profile):
    """Cold-only signed package setup. Never starts the Docker engine or a Room."""
    boundary.install_packages(nonce, manifest, exact_roots=profile.PACKAGE_PROFILE)
    profile.guest_package_install(manifest, run=boundary.run)
    boundary.run('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'uas-remap')
    Path('/etc/subuid').write_text('uas-remap:100000:65536\n')
    Path('/etc/subgid').write_text('uas-remap:100000:65536\n')
    Path('/etc/docker').mkdir(exist_ok=True)
    Path('/etc/docker/daemon.json').write_text(json.dumps(boundary.DOCKER_CONFIGURATION))


def validate_installed(manifest, boundary, profile):
    boundary.require_installed_roots(profile.PACKAGE_PROFILE)
    for name, values in profile.guest_package_roots(manifest).items():
        epoch, version, release, arch = values
        require(boundary.run('rpm', '-q', '--queryformat', '%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n', name)
                == f'{epoch}:{version}-{release}.{arch}\n', 'prepared installed guest root differs')
    # Configuration files legitimately changed during provisioning (subuid and
    # subgid) are checked explicitly below, not mistaken for RPM corruption.
    for name in (*boundary.REQUIRED_PACKAGES, 'git-core', 'openssh-clients'):
        require(not boundary.run('rpm', '-V', '--noconfig', name).strip(), 'prepared installed executable differs')
    require(Path('/etc/subuid').read_text() == 'uas-remap:100000:65536\n'
            and Path('/etc/subgid').read_text() == 'uas-remap:100000:65536\n'
            and json.loads(Path('/etc/docker/daemon.json').read_text()) == boundary.DOCKER_CONFIGURATION,
            'prepared Docker/remap configuration differs')
    for unit in ('sshd.service','sshd.socket'):
        state = boundary.run('systemctl', 'show', '--property=ActiveState,UnitFileState', unit)
        require(dict(line.split('=',1) for line in state.splitlines() if '=' in line)
                == {'ActiveState':'inactive','UnitFileState':'masked'}, 'prepared SSH service changed')


def require_runtime_stopped(boundary):
    for unit in ('docker.service','docker.socket','containerd.service'):
        raw = boundary.run('systemctl','show','--property=ActiveState,UnitFileState',unit)
        state = dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        require(set(state) == {'ActiveState','UnitFileState'} and state['ActiveState'] == 'inactive'
                and state['UnitFileState'] in ('disabled','static'), 'prepared runtime may auto-start or is active')


def consume_guest(manifest, key, boundary, profile):
    require(digest(foundation(manifest)) == key, 'fresh payload does not match prepared foundation')
    hash_file(GUEST_RECEIPT, MAX_RECEIPT)
    node = GUEST_RECEIPT.stat()
    require(node.st_uid == 0 and stat.S_IMODE(node.st_mode) == 0o600, 'prepared receipt ownership differs')
    value = json.loads(GUEST_RECEIPT.read_bytes(), object_pairs_hook=unique)
    validate_guest_receipt(value, key)
    require(inventory(boundary.run) == value['inventory'] and boundary.run('uname','-r').strip() == value['kernel'],
            'prepared installed inventory/kernel differs')
    # Repeat release-signature checks against the fresh readonly payload; the
    # prepared receipt is not permission to trust unsigned runtime packages.
    boundary.run('rpmkeys','--checksig', *[str(boundary.PAYLOAD / 'rpms' / p['file']) for p in manifest['packages']], timeout=180)
    validate_installed(manifest, boundary, profile)
    require_runtime_stopped(boundary)
    require(not boundary.ROOT.exists(), 'prepared base contains source/scenario state')
    # These are live observations, not trusted booleans in a previous report.
    require(boundary.run('getenforce').strip() == 'Enforcing', 'prepared SELinux disabled')
    for path in ('/var/lib/docker','/var/lib/containerd','/var/lib/uas-native-rootfs','/var/lib/uas-native-rootfs.tar'):
        node = Path(path)
        require(not node.exists() or (node.is_dir() and not any(node.iterdir())), 'prepared base contains runtime state')


def seal_guest(manifest, key, boundary, profile):
    """Only called by dedicated prepare mode, before source staging or scenario."""
    require(digest(foundation(manifest)) == key, 'prepare foundation differs')
    validate_installed(manifest, boundary, profile)
    require(not boundary.ROOT.exists() and not GUEST_RECEIPT.exists(), 'preparation must be fresh')
    for unit in ('docker.service','docker.socket','containerd.service'):
        boundary.run('systemctl','stop',unit)
        boundary.run('systemctl','disable',unit)
    require_runtime_stopped(boundary)
    for path in ('/var/lib/docker','/var/lib/containerd','/var/lib/uas-native-rootfs','/var/lib/uas-native-rootfs.tar'):
        node = Path(path)
        require(not node.exists() or (node.is_dir() and not any(node.iterdir())), 'preparation contains runtime state')
    value = {'version':VERSION, 'base_key':key, 'inventory':inventory(boundary.run),
             'kernel':boundary.run('uname','-r').strip(), 'clean':True, 'scenario_started':False}
    validate_guest_receipt(value, key)
    # Only fixed known credential-free disposable preparation paths are touched.
    boundary.run('umount', str(boundary.PAYLOAD)); boundary.PAYLOAD.rmdir()
    boundary.run('cloud-init','clean','--logs','--seed','--machine-id')
    for path in Path('/etc/ssh').glob('ssh_host_*'):
        require(path.is_file() and not path.is_symlink(), 'unexpected generated host key path')
        path.unlink()
    with GUEST_RECEIPT.open('x') as output: output.write(canonical(value).decode() + '\n')
    GUEST_RECEIPT.chmod(0o600)
    return value
