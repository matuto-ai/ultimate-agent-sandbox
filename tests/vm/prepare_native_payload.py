#!/usr/bin/env python3
"""Opt-in native runtime staging; never launches the runtime or a VM.

RPMs stay in the existing Fedora-signature-verified pool. The guest builds its
root with the native package solver, offline and without RPM scriptlets.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile

PROFILE = 'native-pi-v1'
RPM_ROOTS = ('python3', 'tini', 'glibc', 'libstdc++', 'crypto-policies-scripts')
NODE_VERSION = '24.22.1'
NODE_FILE = 'node-v24.22.1-linux-x64.tar.xz'
NODE_URL = 'https://nodejs.org/dist/v24.22.1/' + NODE_FILE
NODE_SHA256 = '6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6'
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_FILES = 30000
MAX_FILE_BYTES = 160 * 1024 * 1024
MAX_RUNTIME_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 544 * 1024 * 1024
MAX_WORK_BYTES = 3 * 1024 * 1024 * 1024
BUILD_TIMEOUT = 1200


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_lock(manifest, lock):
    expected = {'@earendil-works/pi-ai': '1.4.0', '@earendil-works/pi-coding-agent': '1.4.0'}
    if (manifest.get('dependencies') != expected or lock.get('lockfileVersion') != 3
            or lock.get('packages', {}).get('', {}).get('dependencies') != expected
            or not 1 < len(lock['packages']) <= 1024):
        raise ValueError('native Pi requires the reviewed exact 1.4.0 lock')
    for name, item in lock['packages'].items():
        if not name:
            continue
        path = PurePosixPath(name)
        if (not name.startswith('node_modules/') or str(path) != name or '..' in path.parts
                or item.get('link') or not re.fullmatch(r'https://registry\.npmjs\.org/[A-Za-z0-9@._/+%~-]+\.tgz', item.get('resolved', ''))
                or not re.fullmatch(r'sha512-[A-Za-z0-9+/]{86}==', item.get('integrity', ''))):
            raise ValueError('native dependency must be an integrity-locked official registry tarball')


def archive_tree(root, target):
    """Deterministic root-relative archive; no host owners, links or special files."""
    entries, total = [], 0
    with tarfile.open(target, 'x', format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                # npm creates command aliases; launch uses exact JS entrypoint,
                # so these are neither needed nor copied into the runtime.
                if '.bin' in path.relative_to(root).parts:
                    continue
                raise ValueError('unexpected runtime symlink: ' + relative)
            if path.is_dir():
                continue
            if not path.is_file() or path.stat().st_nlink != 1:
                raise ValueError('runtime contains nonordinary files')
            size = path.stat().st_size
            total += size
            if size > MAX_FILE_BYTES or total > MAX_RUNTIME_BYTES or len(entries) >= MAX_FILES:
                raise ValueError('native runtime file/byte budget exceeded')
            mode = 0o555 if path.stat().st_mode & 0o111 else 0o444
            info = tarfile.TarInfo(relative)
            info.size, info.mode, info.mtime = size, mode, 0
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                stream.seek(0)
                archive.addfile(info, stream)
            entries.append({'file': relative, 'bytes': size, 'sha256': digest, 'mode': mode})
    if target.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError('native runtime archive byte budget exceeded')
    target.chmod(0o444)
    return {'files': entries, 'unpacked_bytes': total, 'file_count': len(entries),
            'file': target.name, 'bytes': target.stat().st_size,
            'sha256': sha256(target)}


def stage_native(work, payload, run, fetch):
    """Use only manifest-bound source copies under payload/repo, not originals."""
    source = payload / 'repo'
    for relative in ('tests/pi/package.json', 'tests/pi/package-lock.json', 'runtime/workstation/pi_connector.c'):
        if not (source / relative).is_file():
            raise ValueError('native source allowlist missing ' + relative)
    manifest = json.loads((source / 'tests/pi/package.json').read_text())
    lock = json.loads((source / 'tests/pi/package-lock.json').read_text())
    validate_lock(manifest, lock)
    root = work / 'native-root'
    base = root / 'opt/uas'
    (base / 'node/bin').mkdir(parents=True)
    download = work / NODE_FILE
    fetch(NODE_URL, download, MAX_DOWNLOAD)
    if sha256(download) != NODE_SHA256:
        raise ValueError('official Node archive hash mismatch')
    # Do not extract an upstream archive wholesale or run its binaries here.
    with tarfile.open(download, 'r:xz') as archive:
        for relative in ('bin/node', 'LICENSE'):
            entry = archive.getmember('node-v24.22.1-linux-x64/' + relative)
            if not entry.isfile() or not 0 < entry.size <= MAX_FILE_BYTES:
                raise ValueError('invalid official Node artifact')
            with archive.extractfile(entry) as stream, (base / 'node' / relative).open('xb') as output:
                shutil.copyfileobj(stream, output)
    (base / 'node/bin/node').chmod(0o555)
    pi = base / 'pi'
    pi.mkdir()
    for name in ('package.json', 'package-lock.json'):
        shutil.copyfile(source / 'tests/pi' / name, pi / name)
    npm = shutil.which('npm')
    node = shutil.which('node')
    if not npm or not node:
        raise RuntimeError('native staging requires runner Node/npm')
    if run([node, '--version']).strip() != 'v' + NODE_VERSION:
        raise RuntimeError('native staging runner Node version mismatch')
    # npm rejects loading the same path as both user and global config.
    # Separate empty files preserve sterile configuration without ambient reads.
    user_config = (work / 'empty-user.npmrc').resolve()
    global_config = (work / 'empty-global.npmrc').resolve()
    user_config.write_text('')
    global_config.write_text('')
    run([npm, 'ci', '--prefix', str(pi), '--ignore-scripts', '--no-audit', '--no-fund',
         '--registry=https://registry.npmjs.org', '--userconfig=' + str(user_config), '--globalconfig=' + str(global_config),
         '--cache=' + str(work / 'npm-cache'), '--fetch-retries=0', '--fetch-timeout=20000', '--update-notifier=false'],
        timeout=300, environment={'PATH': str(Path(node).parent) + ':' + os.defpath,
                                  'NPM_CONFIG_IGNORE_SCRIPTS': 'true'})
    if json.loads((pi / 'package-lock.json').read_text()) != lock:
        raise RuntimeError('npm mutated the reviewed lock')
    for directory in ('uas', 'runtime/pi', 'tests/pi'):
        for path in sorted((source / directory).glob('*')):
            if path.suffix not in ('.py', '.mjs'):
                continue
            target = base / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    (base / 'bin').mkdir()
    # Static libc avoids binding the connector to the runner distribution ABI.
    run(['cc', '-static', '-Os', '-Wall', '-Wextra', '-Werror', '-o', str(base / 'bin/pi-connector'),
         str(source / 'runtime/workstation/pi_connector.c')], timeout=60)
    result = archive_tree(root, payload / 'native-runtime.tar')
    result.update({'profile': PROFILE, 'node_version': NODE_VERSION, 'node_archive_sha256': NODE_SHA256,
                   'pi_version': '1.4.0', 'pi_lock_sha256': hashlib.sha256((pi / 'package-lock.json').read_bytes()).hexdigest(),
                   'rpm_roots': list(RPM_ROOTS), 'rpm_scriptlets': False,
                   'dependencies_reproducibly_pinned': False})
    # RPM candidates are signature verified and manifest-pinned for this build,
    # not a claim that Fedora repository resolution is reproducible over time.
    details = payload / 'native-files.json'
    details.write_text(json.dumps({'version': 1, 'profile': PROFILE, 'files': result.pop('files')},
                                  sort_keys=True, separators=(',', ':')) + '\n')
    if details.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('native file manifest budget exceeded')
    details.chmod(0o444)
    result['file_manifest'] = {'file': details.name, 'bytes': details.stat().st_size, 'sha256': sha256(details)}
    return result
