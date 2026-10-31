#!/usr/bin/env python3
"""Disposable warm-guest actual LocalNativeHost/Library installation acceptance.

The guest prepares only its fresh nonce-owned XFS disk and test image. Production
native admission remains intact. Canonical Git transport/model evidence are
controlled fixtures, not actual target/model qualification or a provider call.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import traceback
import zipfile

import guest_boundary as boundary
import room_profile
import prepared_room

PROFILE = 'library-installation-v1'
CANDIDATE = Path('/var/lib/uas-library-source')
# Existing native trust command guard admits only this disposable installroot.
ROOTFS = Path('/var/lib/uas-native-rootfs')
STORAGE = Path('/mnt/uas-library')
CONFIG = Path('/var/lib/uas-library-config')
INSTALL = Path('/var/lib/uas-library-install')
ENDPOINTS = Path('/run/uas-library')
run, require = boundary.run, boundary.expect


def safe_name(name):
    path = PurePosixPath(name)
    require(type(name) is str and not path.is_absolute() and '..' not in path.parts
            and str(path) == name and '\\' not in name, 'candidate relative path required')
    return path


def unpack_candidate(archive, destination):
    """The enclosing verified payload pins this bounded archive before parsing."""
    require(not destination.exists(), 'fresh candidate root required')
    with zipfile.ZipFile(archive) as source:
        names = source.namelist()
        require(len(names) == len(set(names)) and len(names) <= 513, 'candidate entry bound')
        require('candidate.json' in names, 'candidate manifest required')
        require(source.getinfo('candidate.json').file_size <= 262144, 'candidate manifest bound')
        manifest = json.loads(source.read('candidate.json'), object_pairs_hook=prepared_room.unique)
        require(set(manifest) == {'version', 'commit', 'files'} and manifest['version'] == 1
                and re.fullmatch('[0-9a-f]{40}', manifest['commit']) is not None
                and type(manifest['files']) is list, 'candidate manifest schema')
        require(set(names) == {'candidate.json'} | {x['file'] for x in manifest['files']},
                'candidate archive inventory differs')
        total = 0
        for entry in manifest['files']:
            require(set(entry) == {'file', 'bytes', 'sha256'}, 'candidate source entry')
            name = entry['file']; safe_name(name)
            info = source.getinfo(name)
            total += info.file_size
            require(not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16)
                    and info.file_size == entry['bytes'] and info.file_size <= 1024 * 1024
                    and total <= 8 * 1024 * 1024, 'candidate source bound')
            raw = source.read(name)
            require(hashlib.sha256(raw).hexdigest() == entry['sha256'], 'candidate source differs')
        destination.mkdir(mode=0o755)
        for entry in manifest['files']:
            path = destination / entry['file']; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source.read(entry['file'])); path.chmod(0o444)
        (destination / 'candidate.json').write_text(json.dumps(manifest, sort_keys=True))
    # Both wheels are already exact hash-bound by the candidate producer's
    # requirements lock and enclosing immutable source manifest. No pip/network.
    wheels = sorted((destination / 'wheels').glob('*.whl'))
    require(len(wheels) == 2, 'two locked parser wheels required')
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as source:
            total = 0
            for info in source.infolist():
                safe_name(info.filename)
                total += info.file_size
                require(not stat.S_ISLNK(info.external_attr >> 16)
                        and info.file_size <= 1024 * 1024 and total <= 4 * 1024 * 1024,
                        'wheel extraction bound')
                if info.is_dir(): continue
                path = destination / info.filename
                require(not path.exists(), 'wheel overwrites candidate')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.read(info)); path.chmod(0o444)
    return manifest


def ref(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True)); path.chmod(0o600)
    return ref(path)


def prepare_storage(config, image, nonce):
    from uas.local_native import LOCAL_HUB_COMMAND, validate_document
    from uas.native_qualification_backend import directory_identity
    require(STORAGE.is_dir() and run('stat', '-f', '-c', '%T', str(STORAGE)).strip() == 'xfs',
            'fresh XFS storage required')
    (STORAGE / 'state').mkdir(mode=0o755)
    (STORAGE / 'projects').mkdir(mode=0o755)
    config['deployment']['state_root'] = str(STORAGE / 'state')
    document = {'version': 1, 'profile': 'local-native-v1', 'installation_id': nonce,
        'storage_root': str(STORAGE), 'endpoints_root': str(ENDPOINTS),
        'engine_version': '29.8.2', 'mapping': {'offset': 100000, 'size': 65536}, 'rooms': {}}
    for index, room in enumerate(config['rooms']):
        room_id = room['id']; project = 601 + index
        level = f's0:c{601 + index*2},c{602 + index*2}'
        root = STORAGE / 'projects' / room_id
        root.mkdir(mode=0o755)
        state = STORAGE / 'state' / room_id
        state.mkdir(mode=0o755)
        room['state_root'] = str(state)
        room['resources'] = {'cpu': 1, 'memory_bytes': 128 * 1024**2,
                              'disk_bytes': 64 * 1024**2, 'pids': 64, 'log_bytes': 1024**2}
        paths = {name: root / name for name in ('repo', 'workspace', 'reference', 'checkouts')}
        paths['runtime'] = state / 'runtime'
        for name, path in paths.items():
            path.mkdir(mode=0o755)
            # Read-only reference is managed by the host projection owner;
            # actual installed native admission must agree, never patched here.
            owner = 0 if name == 'reference' else 165532
            os.chown(path, owner, owner)
            run('xfs_quota', '-x', '-D', '/dev/null', '-P', '/dev/null', '-c',
                f'project -s -p {path} {project}', str(STORAGE))
            run('chcon', '-t', 'container_file_t', '-l', level, str(path))
        run('xfs_quota', '-x', '-c', f'limit -p bhard=65536k ihard=8192 {project}', str(STORAGE))
        room['project']['roots'] = {k: str(v) for k, v in paths.items() if k != 'runtime'}
        document['rooms'][room_id] = {'quota_project_id': project, 'mcs_level': level,
            'subnet': f'10.92.{index+1}.0/24', 'gateway': f'10.92.{index+1}.1',
            'root_identity': directory_identity(STORAGE),
            'paths': {k: {'path': str(p), 'identity': directory_identity(p)} for k, p in paths.items()},
            'workstation': {'image_id': image, 'image_reference': image},
            'hub': {'image_id': image, 'image_reference': image, 'entrypoint': LOCAL_HUB_COMMAND[:]}}
    return validate_document(document)


def prepare_library(config):
    from uas import library
    from uas.library_git import LibraryGit
    from uas.library_registration import Registrar
    import library_support as support
    from fixture_library_selection import write_selection
    target = CONFIG / 'canonical.git'
    run('git', 'init', '--bare', '-q', str(target))
    transport = CONFIG / 'fixture-ssh'
    transport.write_text('#!/usr/bin/python3\nimport os,sys\n'
        'last=sys.argv[-1] if len(sys.argv)>1 else ""\n'
        'kind=last.split(" ",1)[0]\n'
        'if kind not in ("git-upload-pack","git-receive-pack"):sys.exit(1)\n'
        f'os.execv("/usr/bin/"+kind,[kind,{str(target)!r}])\n')
    transport.chmod(0o700)
    os.environ['GIT_SSH_COMMAND'] = str(transport)
    settings = support.document()
    settings['repository'].update(target='ssh://git@fixture.invalid/library.git', credential_ref='alice-git')
    profile = {'reference': 'synth-local', 'placement': 'local', 'provider': 'fixture-only',
        'version': 'no-inference-v1', 'endpoint': 'http://127.0.0.1:1/unused',
        'region': 'local', 'retention': 'zero', 'terms': 'fixture-only'}
    bindings = [library.project_binding(r['project'], source_identity=str(1001+i))
                for i, r in enumerate(config['rooms'])]
    command = ['/usr/bin/false']  # This lifecycle proof deliberately performs no inference.
    evidence = write_selection(CONFIG / 'model-evidence.json', profile=profile,
                                command=command, bindings=bindings)
    value = {'version': 1, 'settings': settings,
        'credentials': {'alice-git': {'environment': ['GIT_SSH_COMMAND']}},
        'rooms': {r['id']: {'source_identity': str(1001+i)} for i, r in enumerate(config['rooms'])},
        'qualification': {'evidence': {'version': 1, 'target': settings['repository']['target'],
                                      'branch': settings['repository']['branch'], 'qualified': True}},
        'model': {'profile': profile, 'command': command, 'selection': evidence}}
    admitted = support.settings(settings)
    publisher = LibraryGit(CONFIG / 'seed-service', records_path=CONFIG / 'seed-records.db',
        deployment_id=config['deployment']['id'], target=settings['repository']['target'],
        branch=settings['repository']['branch'], environment={'GIT_SSH_COMMAND': str(transport)})
    publisher.startup()
    try:
        for i, binding in enumerate(bindings):
            human = library.human_scope(support.session(('library-register',)), binding=binding, kind='register')
            Registrar(publisher, current_scope=lambda human=human: human).register(
                library.action(human, admitted, kind='register', operation_id=f'register-{i}',
                               request_id=f'register-{i}', payload={}, at=support.AT), admitted)
    finally:
        publisher.close()
    # Controlled fixture publication, not an authenticated Participant capture.
    # These distinct canonical documents make sibling projection leakage visible.
    seed = CONFIG / 'marker-seed'
    branch = settings['repository']['branch']
    run('git', 'clone', '-q', '--branch', branch, str(target), str(seed))
    for room, binding in zip(config['rooms'], bindings):
        path = seed / 'projects' / binding['project_path'] / 'context/index.md'
        with path.open('a') as output:
            output.write('\nFixture isolation marker: ' + fixture_marker(room['id']) + '\n')
    run('git', '-C', str(seed), 'add', 'projects')
    run('git', '-C', str(seed), '-c', 'user.name=Library fixture',
        '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'Seed isolated fixture documents')
    run('git', '-C', str(seed), 'push', '-q', 'origin', 'HEAD:' + branch)
    return value


def fixture_marker(room_id):
    return 'UAS-PRIVATE-LIBRARY-MARKER-' + room_id + '-7e034c8b'


def startup_refusal(result, expected):
    require(result.returncode == 3 and not result.stderr
            and 0 < len(result.stdout) <= 1024, 'startup refusal receipt invalid')
    receipt = json.loads(result.stdout, object_pairs_hook=prepared_room.unique)
    require(receipt == {'outcome': 'unknown', 'error': expected},
            'startup refusal code differs')


def negative_startup(selection, *, name, expected, unsafe=False):
    from uas.local_installation import Installation
    root = Path('/var/lib/uas-library-' + name)
    installation = Installation(root)
    installation.setup(json.dumps(selection).encode())
    if unsafe:
        (root / 'library').mkdir(mode=0o777); (root / 'library').chmod(0o777)
    result = subprocess.run([sys.executable, '-m', 'uas', 'local', '--root', str(root), 'serve'],
        cwd=CANDIDATE, capture_output=True, timeout=20)
    startup_refusal(result, expected)
    require(not (root / 'operator.sock').exists()
            and not (root / 'library' / 'clone.git').exists(), 'startup did not fail closed')


def image_diagnostic(image):
    require(type(image) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', image),
            'exact owned image diagnostic required')
    raw = run('docker', 'image', 'inspect', '--format', '{{json .Config.User}}', image)
    require(len(raw) <= 128, 'image user receipt bound')
    user = json.loads(raw)
    require(type(user) is str and re.fullmatch(r'[0-9]{1,6}:[0-9]{1,6}', user),
            'numeric image user required')
    result = {'stage': 'owned-image-imported', 'image_id': image, 'image_user': user}
    print('Library guest phase: ' + json.dumps(result, sort_keys=True), flush=True)
    return result


def scenario(nonce, manifest, candidate):
    from native_rootfs import build_room_rootfs
    from guest_room_base import import_image
    from uas.local_installation import Installation
    CONFIG.mkdir(mode=0o700)
    root = ROOTFS
    build_room_rootfs(nonce, manifest, root, run=run)
    shutil.rmtree(root / 'opt/uas/uas')
    shutil.copytree(CANDIDATE / 'uas', root / 'opt/uas/uas')
    for package in ('markdown_it', 'mdurl'):
        shutil.copytree(CANDIDATE / package, root / 'opt/uas' / package)
    archive = root.with_suffix('.tar')
    with tarfile.open(archive, 'x', format=tarfile.PAX_FORMAT) as output:
        for item in sorted(root.iterdir()): output.add(item, arcname=item.name)
    boundary.start_engine()
    require(run('docker', 'version', '--format', '{{.Server.Version}}').strip() == '29.8.2',
            'exact Engine required')
    image = import_image(archive)
    image_diagnostic(image)
    device = Path('/dev/disk/by-id/virtio-uas-quota')
    require(device.exists() and run('blockdev', '--getsize64', str(device)).strip() == str(2*1024**3),
            'exact disposable disk required')
    run('mkfs.xfs', '-f', str(device)); STORAGE.mkdir(mode=0o755)
    run('mount', '-o', 'prjquota,nodev,nosuid', str(device), str(STORAGE))
    config = json.loads((CANDIDATE / 'tests/fixtures/two-rooms.json').read_text())
    native = prepare_storage(config, image, nonce)
    library = prepare_library(config)
    print('Library guest phase: configuration-prepared', flush=True)
    selection = {'version': 1, 'project': write(CONFIG / 'project.json', config),
                 'native': write(CONFIG / 'native.json', native), 'manager': None,
                 'library': write(CONFIG / 'library.json', library)}
    negative_startup({k: v for k, v in selection.items() if k != 'library'},
                     name='absent', expected='LIBRARY_NOT_CONFIGURED')
    negative_startup(selection, name='unsafe', expected='INVALID_DEPLOYMENT_STATE', unsafe=True)
    print('Library guest phase: negative-startup-confirmed', flush=True)
    installation = Installation(INSTALL); installation.setup(json.dumps(selection).encode())
    path = CANDIDATE / 'tests/native/library_installation_probe.py'
    spec = importlib.util.spec_from_file_location('installation_probe', path)
    probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
    proof = probe.run(str(INSTALL), candidate['commit'], source_manifest=CANDIDATE / 'candidate.json',
                      expected_markers={r['id']: fixture_marker(r['id']) for r in config['rooms']})
    return {'proof': proof, 'absent_configuration': 'refused', 'unsafe_configuration': 'refused',
            'cleanup': 'confirmed'}


def main():
    require(len(sys.argv) == 5 and sys.argv[3] == 'warm', 'exact warm candidate invocation required')
    nonce, digest, _mode, base_key = sys.argv[1:]
    report = {'version': 1, 'nonce': nonce, 'profile': PROFILE, 'production_enabled': False,
              'status': 'failed'}
    try:
        room_profile.guest_guard(nonce, run=run)
        require(run('getenforce').strip() == 'Enforcing', 'stock SELinux required')
        boundary.PAYLOAD.mkdir()
        run('mount', '-o', 'ro,nodev,nosuid,noexec', '/dev/disk/by-label/UAS_PAYLOAD', str(boundary.PAYLOAD))
        manifest = boundary.verify_payload(nonce, digest)
        prepared_room.consume_guest(manifest, base_key, boundary, room_profile)
        shutil.copytree(boundary.PAYLOAD / 'repo', boundary.ROOT)
        parts = [(boundary.PAYLOAD / ('repo/tests/vm/library-candidate.' + index)).read_bytes()
                 for index in ('00', '01')]
        require(all(0 < len(part) <= 1024 * 1024 for part in parts), 'candidate archive part bound')
        candidate = unpack_candidate(io.BytesIO(b''.join(parts)), CANDIDATE)
        sys.path[:0] = [str(CANDIDATE), str(CANDIDATE / 'tests'), str(boundary.ROOT / 'tests/vm')]
        report.update(scenario(nonce, manifest, candidate), status='passed')
    except BaseException as error:
        print(traceback.format_exc()[-16384:], flush=True)
        report['failure'] = {'error_type': type(error).__name__}
    # The existing harness destroys this exact VM overlay and disk regardless
    # of outcome. No broad host cleanup or unrelated resource adoption occurs.
    with open('/dev/ttyS0', 'w') as serial:
        serial.write('\nUAS_LIBRARY_REPORT:' + nonce + ':' + json.dumps(report, sort_keys=True) + '\n')
        serial.flush()


if __name__ == '__main__':
    main()
