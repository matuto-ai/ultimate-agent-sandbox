#!/usr/bin/env python3
"""Explicit candidate-pinned Library host proof on the existing warm Room VM.

Reuses the selected signed Fedora pool/foundation without modifying it. Builds
only a fresh source/dependency payload until main() deliberately boots the VM.
No host path, runtime socket or credential is exposed to the guest.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
import zipfile

import run as feasibility
import run_room
import prepared_room
from prepare_payload import build_payload

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PROFILE = 'library-installation-v1'
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024
MAX_FILES = 512
EXTRA_SOURCES = ('tests/native/library_installation_probe.py',
                 'tests/fixtures/two-rooms.json', 'tests/fixture_library_selection.py',
                 'tests/library_support.py', 'tests/vm/guest_library_installation.py')
WHEELS = {
    'markdown_it_py-4.2.0-py3-none-any.whl': '9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a',
    'mdurl-0.1.2-py3-none-any.whl': '84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def candidate_archive(root, target, wheels, expected_commit):
    require(re.fullmatch('[0-9a-f]{40}', expected_commit) is not None, 'exact commit required')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(head == expected_commit, 'checkout differs from selected commit')
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=root),
            'tracked candidate changes forbidden')
    paths = subprocess.check_output(['git', 'ls-files', 'uas/*.py'], cwd=root, text=True).splitlines()
    paths += list(EXTRA_SOURCES)
    subprocess.run(['git', 'ls-files', '--error-unmatch', *EXTRA_SOURCES], cwd=root,
                   check=True, stdout=subprocess.DEVNULL)
    entries, total = [], 0
    with zipfile.ZipFile(target, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name in sorted(paths):
            path = root / name
            info = path.lstat()
            require(path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    'ordinary candidate source required')
            raw = path.read_bytes()
            total += len(raw)
            require(len(raw) <= 1024 * 1024 and total <= MAX_EXPANDED, 'source byte budget')
            entries.append({'file': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
            output.writestr(name, raw)
        for name, digest in sorted(WHEELS.items()):
            path = wheels / name
            require(path.is_file() and not path.is_symlink(), 'locked wheel missing')
            raw = path.read_bytes()
            require(hashlib.sha256(raw).hexdigest() == digest, 'locked wheel differs')
            name = 'wheels/' + name
            entries.append({'file': name, 'bytes': len(raw), 'sha256': digest})
            output.writestr(name, raw)
        require(len(entries) <= MAX_FILES, 'candidate file count bound')
        output.writestr('candidate.json', json.dumps({'version': 1, 'commit': expected_commit,
                        'files': entries}, sort_keys=True))
    require(target.stat().st_size <= MAX_ARCHIVE, 'candidate archive bound')
    return hashlib.sha256(target.read_bytes()).hexdigest()


def parse_report(serial, nonce):
    prefix = 'UAS_LIBRARY_REPORT:' + nonce + ':'
    records = [line[len(prefix):] for line in serial.splitlines() if line.startswith(prefix)]
    require(len(records) == 1 and len(records[0]) <= 65536, 'one bounded Library report required')
    report = json.loads(records[0], object_pairs_hook=prepared_room.unique)
    require(type(report.get('version')) is int and report['version'] == 1 and report.get('nonce') == nonce
            and report.get('profile') == PROFILE and report.get('production_enabled') is False
            and report.get('status') == 'passed' and 'failure' not in report,
            'actual Library installation proof incomplete')
    proof = report.get('proof', {})
    require(proof.get('status') == 'passed' and proof.get('stopped_room_operator') == 'observed'
            and proof.get('sibling') == 'running' and proof.get('rooms') == ['alpha', 'beta']
            and proof.get('project_content_isolation') == 'own-marker-present-sibling-markers-absent'
            and len(set(proof.get('projection_identities', {}).values())) == 2
            and report.get('absent_configuration') == 'refused'
            and report.get('unsafe_configuration') == 'refused'
            and report.get('cleanup') == 'confirmed', 'required host observations absent')
    return report


def main():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux'
            and os.geteuid() != 0 and os.environ.get('UAS_LIBRARY_VM_APPROVED') == '1',
            'explicit unprivileged hosted Library VM approval required')
    expected_commit = os.environ.get('UAS_LIBRARY_EXPECTED_COMMIT', '')
    selected_dir = Path(os.environ.get('UAS_ROOM_PREPARED_DIR', ''))
    selected_hash = os.environ.get('UAS_ROOM_PREPARED_SHA256', '')
    selected = prepared_room.select(selected_dir, selected_hash, ROOT)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='uas-library-vm-') as temporary:
        directory = Path(temporary)
        nonce = uuid.uuid4().hex
        stage = directory / 'source'
        stage.mkdir()
        for name in run_room.SOURCES:
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        # The unchanged Room bootstrap is available for its install routine.
        shutil.copyfile(ROOT / 'tests/vm/guest_room.py', stage / 'tests/vm/guest_room_base.py')
        shutil.copyfile(HERE / 'guest_library_installation.py', stage / 'tests/vm/guest_room.py')
        wheels = directory / 'wheels'
        wheels.mkdir()
        feasibility.command([os.sys.executable, '-m', 'pip', 'download', '--disable-pip-version-check',
            '--only-binary=:all:', '--require-hashes', '--no-deps', '-r', str(ROOT / 'requirements.txt'),
            '--dest', str(wheels)])
        archive = directory / 'library-candidate.zip'
        candidate_archive(ROOT, archive, wheels, expected_commit)
        raw_candidate = archive.read_bytes()
        middle = (len(raw_candidate) + 1) // 2
        # Two bounded source assets preserve the existing 1MiB per-file gate.
        (stage / 'tests/vm/library-candidate.00').write_bytes(raw_candidate[:middle])
        (stage / 'tests/vm/library-candidate.01').write_bytes(raw_candidate[middle:])
        sources = run_room.SOURCES + ('tests/vm/guest_room_base.py',
            'tests/vm/library-candidate.00', 'tests/vm/library-candidate.01')
        payload = build_payload(directory, stage, nonce, source_paths=sources,
            profile=run_room.PROFILE, prepared_directory=selected_dir, prepared_sha256=selected_hash)
        manifest_root = payload.parent / 'payload'
        raw = (manifest_root / 'manifest.json').read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        require(prepared_room.digest(prepared_room.foundation(json.loads(raw))) == selected['base_key'],
                'prepared foundation changed')
        overlay, quota = directory / 'guest.qcow2', directory / 'quota.raw'
        feasibility.command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
                             '-b', str(selected_dir / 'base.qcow2'), str(overlay)])
        with quota.open('xb') as output:
            output.truncate(2 * 1024**3)
        seed = run_room.seed(directory, nonce, digest, payload_root=manifest_root,
                            mode='warm', base_key=selected['base_key'])
        try:
            report, seconds = run_room.boot(directory,
                run_room.arguments(directory, overlay, seed, payload, quota), nonce,
                report_parser=parse_report)
            require(report['proof']['commit'] == expected_commit, 'reported candidate mismatch')
            print('Library VM: ' + json.dumps({'guest': report, 'payload_manifest_sha256': digest,
                  'prepared_base_key': selected['base_key'], 'seconds': seconds,
                  'production_enabled': False}, sort_keys=True), flush=True)
        except BaseException:
            for name in run_room.LOG_FILES:
                path = directory / name
                if path.exists():
                    print(name + ' tail: ' + path.read_bytes()[-131072:].decode(errors='replace'), flush=True)
            raise
    print('Library VM cleanup: ' + json.dumps({'owned_temporary_directory_removed': True,
          'elapsed_seconds': round(time.monotonic() - started, 3)}), flush=True)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    main()
