"""Fixed Room-boundary Python source staging; no runtime/provider download.

This adapter is selected only by the new room-launch-ipv4-v1 payload profile.
It does not run code, a container, a guest, or a native runtime. The existing
Fedora-signature-checked resolver owns the declared RPM candidate pool.
"""
import json
import shutil
import stat

from prepare_native_payload import archive_tree, sha256
from room_profile import PROFILE, GUEST_RPM_ROOTS, guest_package_roots

ROOTFS_RPM_ROOTS = ('python3', 'tini', 'glibc', 'libstdc++')
RPM_ROOTS = ROOTFS_RPM_ROOTS + GUEST_RPM_ROOTS
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_WORK_BYTES = 3 * 1024 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 1024 * 1024
BUILD_TIMEOUT = 1200
# Exact reviewed source closure. No ambient repository glob can add a runtime,
# provider implementation, launcher script, package lock, Node/npm or Pi asset.
ROOM_MODULES = (
    '__init__', 'config', 'gate_policy', 'forge', 'ledger', 'typed_json',
    'lifecycle', 'manager_owner', 'manager_projection', 'manager_journey', 'launch', 'docker_fixture', 'guest_fixture', 'room_fixture',
    'room_probe', 'docker_exec_api', 'kernel_origin', 'workstation_exec',
    'workstation_probe', 'forge_audit', 'git_audit', 'git_controller',
    'git_endpoint', 'git_launcher', 'git_protocol', 'git_policy', 'git_process', 'git_provenance',
    'git_runtime', 'git_service', 'git_sources',
    'git_stream', 'git_transaction', 'git_transport', 'git_worker', 'git_worker_native')


def stage_native(work, payload, run, fetch):
    del run, fetch  # No compiler, subprocess, package manager or network here.
    source = payload / 'repo/uas'
    if source.resolve() != source or not source.is_dir():
        raise ValueError('canonical staged Room source directory required')
    expected = {name + '.py' for name in ROOM_MODULES}
    paths = sorted(source.glob('*.py'))
    if {path.name for path in paths} != expected:
        raise ValueError('exact reviewed Room source closure required')
    checked, total = [], 0
    for path in paths:
        node = path.lstat()
        if (not stat.S_ISREG(node.st_mode) or node.st_nlink != 1 or path.resolve() != path
                or not 0 <= node.st_size <= MAX_SOURCE_FILE_BYTES):
            raise ValueError('ordinary bounded Room source required')
        total += node.st_size
        if total > MAX_SOURCE_BYTES:
            raise ValueError('Room source budget exceeded')
        checked.append(path)
    root = work / 'room-root'
    target = root / 'opt/uas/uas'
    target.mkdir(parents=True)  # Never adopt a previous partial staging tree.
    for path in checked:
        destination = target / path.name
        with path.open('rb') as source_file, destination.open('xb') as output:
            shutil.copyfileobj(source_file, output)
        destination.chmod(0o444)
    result = archive_tree(root, payload / 'room-runtime.tar')
    if result['bytes'] > MAX_ARCHIVE_BYTES:
        raise ValueError('Room source archive exceeds budget')
    result.update(profile=PROFILE, rpm_roots=list(ROOTFS_RPM_ROOTS),
                  guest_rpm_roots=list(GUEST_RPM_ROOTS), rpm_scriptlets=False,
                  dependencies_reproducibly_pinned=False, production_enabled=False,
                  help_only=True, runtime_python_only=True)
    listing = payload / 'room-files.json'
    encoded = json.dumps({'version': 1, 'profile': PROFILE, 'files': result.pop('files')},
                         sort_keys=True, separators=(',', ':')).encode()
    if len(encoded) > 128 * 1024:
        raise ValueError('Room source file manifest exceeds budget')
    with listing.open('xb') as output:
        output.write(encoded)
    listing.chmod(0o444)
    result['file_manifest'] = {'file': listing.name, 'bytes': listing.stat().st_size,
                               'sha256': sha256(listing)}
    return result
