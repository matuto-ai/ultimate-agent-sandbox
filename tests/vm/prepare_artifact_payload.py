"""Explicit artifact-only source payload staging; builds, never runs helpers."""
import hashlib
import json
from pathlib import Path
import shutil
import struct

from prepare_native_payload import archive_tree, sha256

PROFILE = 'artifacts-v1-source'
RPM_ROOTS = ('python3', 'tini', 'glibc', 'libstdc++', 'git-core', 'util-linux')
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_WORK_BYTES = 3 * 1024 * 1024 * 1024
BUILD_TIMEOUT = 1200


def static_elf(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or len(data) > 8 * 1024 * 1024:
        raise ValueError('bounded little-endian ELF64 required')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    if header[2] != 62:
        raise ValueError('x86-64 static helper required')
    segments = [struct.unpack_from('<IIQQQQQQ', data, header[5]+i*header[9])
                for i in range(header[10])]
    if any(p[0] in (2, 3) or p[1] & 3 == 3 for p in segments):
        raise ValueError('dynamic/interpreted or WX helper rejected')
    return hashlib.sha256(data).hexdigest()


def stage_native(work, payload, run, fetch):
    del fetch  # No runtime/provider fetch, Node/npm or account configuration.
    source = payload / 'repo'
    base = work / 'artifact-root' / 'opt/uas'
    binaries = base / 'bin';binaries.mkdir(parents=True)
    for directory in ('uas', 'tests/vm'):
        for path in sorted((source / directory).glob('*.py')):
            target = base / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    flags = ['cc', '-static', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
             '-fstack-protector-strong', '-Wl,-z,noexecstack', '-Wl,-z,relro', '-Wl,-z,now']
    builds = (
        ('artifact-bootstrap', 'runtime/workstation/artifact_bootstrap.c', []),
        ('artifact-evaluator', 'runtime/workstation/artifact_evaluator.c', []),
        ('artifact-test-bootstrap', 'runtime/workstation/artifact_bootstrap.c', ['-DUAS_ARTIFACT_PROBE']),
        ('artifact-confinement-probe', 'tests/vm/artifact_confinement_probe.c', []))
    hashes = {}
    for name, relative, options in builds:
        run([*flags, *options, str(source/relative), '-o', str(binaries/name)], timeout=60)
        hashes[name] = static_elf(binaries/name)
        (binaries/name).chmod(0o555)
    result = archive_tree(work/'artifact-root', payload/'artifact-runtime.tar')
    result.update(profile=PROFILE, rpm_roots=list(RPM_ROOTS[:4]), rpm_scriptlets=False,
                  dependencies_reproducibly_pinned=False, production_enabled=False, helper_sha256=hashes)
    listing = payload/'artifact-files.json'
    listing.write_text(json.dumps({'version':1, 'profile':PROFILE, 'files':result.pop('files')},
                                 sort_keys=True, separators=(',', ':')))
    listing.chmod(0o444)
    result['file_manifest'] = {'file':listing.name, 'bytes':listing.stat().st_size, 'sha256':sha256(listing)}
    return result
