#!/usr/bin/env python3
"""Opt-in acceptance probe for an ALREADY prepared two-Room native installation.

Never provisions Docker, storage, identities, credentials, models, or policies.
Run only with the operator's separate approval on a disposable prepared host.
This is not the T42 model/target qualification or T41 VM isolation proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def require(value, code):
    if not value:
        raise RuntimeError(code)


def candidate_identity(expected_commit, source_manifest=None):
    if source_manifest is None:
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        require(head == expected_commit, 'candidate commit mismatch')
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT),
                'candidate tracked files changed')
        return head
    manifest_path = Path(source_manifest)
    require(manifest_path == ROOT / 'candidate.json' and manifest_path.resolve() == manifest_path,
            'exact staged candidate manifest required')
    raw = manifest_path.read_bytes()
    require(0 < len(raw) <= 262144, 'candidate manifest bound')
    value = json.loads(raw)
    require(set(value) == {'version', 'commit', 'files'} and value['version'] == 1
            and value['commit'] == expected_commit and type(value['files']) is list
            and 0 < len(value['files']) <= 512, 'candidate commit mismatch')
    names = set()
    for entry in value['files']:
        require(type(entry) is dict and set(entry) == {'file', 'bytes', 'sha256'}, 'candidate entry schema')
        relative = Path(entry['file'])
        require(not relative.is_absolute() and '..' not in relative.parts
                and str(relative) == entry['file'] and entry['file'] not in names,
                'candidate path invalid')
        names.add(entry['file'])
        path = ROOT / relative
        require(path.resolve() == path and path.is_file() and path.stat().st_nlink == 1,
                'candidate source invalid')
        source = path.read_bytes()
        require(len(source) == entry['bytes'] and len(source) <= 1024 * 1024
                and hashlib.sha256(source).hexdigest() == entry['sha256'], 'candidate source changed')
    require({'uas/local_cli.py', 'uas/local_library.py', 'tests/native/library_installation_probe.py'} <= names,
            'required candidate sources absent')
    return expected_commit


def isolated_marker(bundle, own, siblings):
    files = list(bundle.rglob('*'))
    require(not any(path.is_symlink() for path in files), 'projection symlink exposed')
    content = b'\n'.join(path.relative_to(bundle).as_posix().encode() + b'\n' + path.read_bytes()
                         for path in files if path.is_file())
    require(own.encode() in content, 'own Project marker absent')
    require(all(marker.encode() not in content for marker in siblings), 'sibling Project content exposed')


def run(installation_root, expected_commit, *, source_manifest=None, expected_markers=None):
    from uas.local_installation import Installation
    from uas.local_host import request
    from uas.library_controls import request as library_request
    require(os.geteuid() == 0, 'prepared native host root owner required')
    head = candidate_identity(expected_commit, source_manifest)
    installation = Installation(installation_root)
    selection, config, selected = installation.open()
    require(selected['native'] is not None and selected['library'] is not None,
            'prepared native and Library selections required')
    rooms = config['rooms']
    require(len(rooms) == 2, 'exactly two disposable prepared Rooms required')
    if expected_markers is not None:
        require(set(expected_markers) == {r['id'] for r in rooms}
                and len(set(expected_markers.values())) == 2
                and all(type(v) is str and 0 < len(v) <= 128 for v in expected_markers.values()),
                'distinct fixed fixture markers required')
    require(not (installation.root / 'operator.sock').exists(), 'existing host owner must be stopped')
    before = (installation.root / 'installation.json').read_bytes()
    host = subprocess.Popen([sys.executable, '-m', 'uas', 'local', '--root', str(installation.root), 'serve'],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 60
    started = []
    proof = {'commit': head, 'selection_sha256': hashlib.sha256(before).hexdigest(),
             'kind': 'actual-prepared-native-installation-two-room',
             'target_qualification': 'external-not-established-by-probe',
             'model_qualification': 'external-not-established-by-probe'}
    try:
        while not (installation.root / 'operator.sock').exists():
            require(host.poll() is None, 'host exited before readiness')
            require(time.monotonic() < deadline, 'host readiness deadline')
            time.sleep(.05)
        generations = {}
        for room in rooms:
            result = request(installation, 'start', room['id'])
            require(result.get('outcome') == 'observed', 'Room Start outcome unknown')
            state = result['result']
            require(state.get('infrastructure', {}).get('phase') == 'running'
                    and not state['infrastructure'].get('leftovers')
                    and state.get('services', {}).get('hub') == 'ready', 'real Room/Hub not ready')
            started.append(room['id'])
            reference = Path(room['project']['roots']['reference'])
            snapshot = json.loads((reference / 'library.snapshot.json').read_text())
            require(snapshot['project_id'] == room['project']['id'], 'projection Project mismatch')
            bundle = reference / 'library'
            require(bundle.is_dir(), 'coherent projection missing')
            require(not any(p.name in ('.git', 'clone.git', 'records.db') for p in bundle.rglob('*')),
                    'canonical state exposed in projection')
            require(set(p.name for p in reference.iterdir() if not p.name.startswith('.'))
                    == {'library', 'library.snapshot.json'}, 'unexpected published projection content')
            if expected_markers is not None:
                isolated_marker(bundle, expected_markers[room['id']],
                    [value for key, value in expected_markers.items() if key != room['id']])
            generations[room['id']] = snapshot
        alpha, beta = rooms
        stopped = request(installation, 'stop', alpha['id'])
        from uas.local_cli import stopped_result
        require(stopped.get('outcome') == 'observed' and stopped_result(stopped['result']),
                'Room Stop unconfirmed')
        started.remove(alpha['id'])
        observation = library_request(installation.root / 'library' / 'operator',
            {'version': 1, 'action': 'observe', 'project_id': alpha['project']['id'], 'for_action': 'drain'})
        require(observation.get('outcome') == 'observed', 'stopped-Room operator unavailable')
        require(host.poll() is None, 'singleton host ended with Room')
        beta_state = request(installation, 'status', beta['id'])
        require(beta_state.get('outcome') == 'observed'
                and beta_state['result']['infrastructure']['phase'] == 'running', 'sibling Room stopped')
        require(json.loads((Path(beta['project']['roots']['reference']) / 'library.snapshot.json').read_text())
                == generations[beta['id']], 'sibling projection changed')
        if expected_markers is not None:
            proof['project_content_isolation'] = 'own-marker-present-sibling-markers-absent'
        proof.update(status='passed', rooms=[r['id'] for r in rooms],
                     stopped_room_operator='observed', sibling='running',
                     projection_identities={r: s['project_identity'] for r, s in generations.items()})
    finally:
        failures = []
        for room in reversed(started):
            try:
                result = request(installation, 'stop', room)
                from uas.local_cli import stopped_result
                if result.get('outcome') != 'observed' or not stopped_result(result['result']):
                    failures.append('Room Stop unconfirmed')
            except Exception:
                failures.append('Room Stop unavailable')
        # Always request orderly termination of the exact child owned here, even
        # when a Room Stop failed. Do not scan PIDs or force-kill native owners.
        if host.poll() is None:
            host.send_signal(signal.SIGTERM)
        try:
            out, error = host.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            raise RuntimeError('host shutdown uncertain; operator reconciliation required') from None
        if host.returncode != 0 or error:
            failures.append('host shutdown unconfirmed')
        else:
            try:
                if json.loads(out) != {'state': 'host-stopped'}:
                    failures.append('host shutdown receipt invalid')
            except ValueError:
                failures.append('host shutdown receipt invalid')
        require((installation.root / 'installation.json').read_bytes() == before, 'selection changed')
        require(not failures, '; '.join(failures))
    return proof


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--installation-root', required=True)
    parser.add_argument('--expected-commit', required=True)
    args = parser.parse_args(argv)
    require(args.run and os.environ.get('UAS_LIBRARY_INSTALLATION_PROOF') == '1',
            'explicit prepared-host execution approval required')
    print(json.dumps(run(args.installation_root, args.expected_commit), sort_keys=True))


if __name__ == '__main__':
    main()
