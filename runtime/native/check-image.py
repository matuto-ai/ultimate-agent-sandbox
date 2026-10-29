#!/usr/bin/env python3
"""Manual credential-free build/readback, never native lifecycle qualification.

Run from a clean checkout of the reviewed revision. No image is pushed and no
container is started. The stopped readback container is owned by this invocation.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from types import SimpleNamespace
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from uas.native_image_package import canonical, dockerfile, build_inventory, payload
from uas.native_git_resources import verify_engine_payload, validate_payload
from uas.native_image_archive import export_archive
from uas.docker_exec_api import _UnixHTTP, API

MAX_FILE = 512 * 1024 * 1024
RETAINED_FILES = {'selection.json': 65536, 'Dockerfile.native-check': 65536,
                  'pi-payload.json': 65536, 'claude-payload.json': 65536,
                  'git-payload.json': 65536, 'git-backend': 64 * 1024 * 1024}


def require(value, message):
    if not value:
        raise ValueError(message)


def single_archive(raw, name):
    """Hash a bounded single regular Engine file without extracting it."""
    require(0 < len(raw) <= MAX_FILE + 1024 * 1024, 'archive size exceeds budget')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        member = archive.next()
        require(member is not None and member.name == name and member.isfile()
                and not member.issparse() and not member.islnk()
                and member.uid == 0 and not member.mode & 0o022
                and 0 <= member.size <= MAX_FILE, 'unexpected payload file metadata')
        stream = archive.extractfile(member)
        digest = hashlib.sha256()
        small = bytearray()
        read = 0
        while read < member.size:
            block = stream.read(min(65536, member.size - read))
            require(block, 'truncated image file')
            digest.update(block)
            read += len(block)
            if member.size <= 65536:
                small.extend(block)
        require(archive.next() is None, 'unexpected extra archive entry')
        return {'sha256': digest.hexdigest(), 'size': read,
                'data': bytes(small) if member.size <= 65536 else None}


def read_file(container, pathname):
    connection = _UnixHTTP('/var/run/docker.sock', 10)
    deadline = time.monotonic() + 30
    try:
        connection.request('GET', API + '/containers/' + container + '/archive?path=' + quote(pathname, safe=''))
        response = connection.getresponse()
        require(response.status == 200, 'image file unavailable: ' + pathname)
        raw = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'image file readback deadline')
            if connection.sock is not None:
                connection.sock.settimeout(min(10, remaining))
            block = response.read1(65536)
            if not block:
                break
            raw.extend(block)
            require(len(raw) <= MAX_FILE + 1024 * 1024, 'image file readback budget')
        return single_archive(bytes(raw), pathname.rsplit('/', 1)[1])
    finally:
        connection.close()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def document(raw):
    require(type(raw) is bytes and len(raw) <= 65536, 'bounded JSON required')
    return json.loads(raw, object_pairs_hook=unique)


def validate_native(selected, runtime, observe):
    require(type(selected) is dict and selected.get('runtime') == runtime, 'runtime differs')
    expected = payload(runtime, selected.get('artifacts'))
    require(canonical(selected) == canonical(expected), 'payload metadata differs')
    for name, digest in expected['artifacts'].items():
        require(observe(name)['sha256'] == digest, 'native artifact hash differs: ' + name)
    return {'manifest_sha256': hashlib.sha256(canonical(expected)).hexdigest(),
            'artifact_count': len(expected['artifacts'])}


def validate_export(selected, exported, backend):
    require(canonical(selected) == canonical(exported), 'export payload differs from final image')
    require(type(selected) is dict and re.fullmatch(r'[0-9a-f]{64}', selected.get('backend_sha256', '')),
            'backend digest missing')
    require(hashlib.sha256(backend).hexdigest() == selected['backend_sha256'], 'exported backend differs')
    require(0 < len(backend) <= 64 * 1024 * 1024 and backend.startswith(b'\x7fELF'), 'bounded ELF backend required')


def command(args, *, cwd=None, timeout=60, output=False):
    # Docker uses only this invocation's empty client config, never the user's.
    result = subprocess.run(args, cwd=cwd, check=True, timeout=timeout,
                            stdout=subprocess.PIPE if output else None)
    if output:
        require(len(result.stdout) <= 65536, 'command metadata oversized')
        return result.stdout


def cleanup_container(docker, name, owner, image_id, *, uncertain=False):
    """Reconcile an uncertain create by its unique name and ownership label."""
    values = json.loads(command(docker + ['container', 'ls', '-a', '--no-trunc',
        '--filter', 'name=^/' + name + '$', '--format', '{{json .}}'], output=True) or b'null')
    if values is None:
        require(not uncertain, 'create outcome remains unknown despite absent listing')
        return
    # Inspect the name; never remove by a loose listing match.
    state = json.loads(command(docker + ['inspect', name], output=True))[0]
    require(state['Name'] == '/' + name and state['Image'] == image_id
            and state['Config'].get('Labels', {}).get('io.uas.image-check') == owner
            and state['State']['Status'] == 'created' and state['State']['Running'] is False,
            'cleanup ownership/state is uncertain')
    require(re.fullmatch(r'[0-9a-f]{64}', state['Id']), 'cleanup identity invalid')
    command(docker + ['rm', state['Id']], output=True)


def retain_artifact(directory, name, raw, report):
    """Retain only named public build products, never a whole work directory."""
    require(name in RETAINED_FILES and type(raw) is bytes
            and 0 < len(raw) <= RETAINED_FILES[name], 'bounded named artifact required')
    with (directory / name).open('xb') as stream:
        stream.write(raw)
    report.setdefault('retained_artifacts', {})[name] = {
        'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--retain-image-archive', action='store_true', help='retain bounded public Docker image archive after readback')
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(exist_ok=False)
    selection = document(Path(args.selection).read_bytes())
    require(type(selection) is dict and set(selection) == {'node_image', 'compiler_image', 'git_packages'},
            'exact build selection required')
    recipe = dockerfile(**selection)
    require('FROM payload AS combined' in recipe, 'combined image selection required')
    revision = command(['git', 'rev-parse', 'HEAD'], cwd=ROOT, output=True).decode().strip()
    require(re.fullmatch(r'[0-9a-f]{40}', revision), 'exact source revision required')
    require(not command(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT, output=True).strip(),
            'clean tracked source required')
    report = {'version': 1, 'source_revision': revision, 'selection': selection,
              'status': 'running', 'stage': 'build', 'build_execution': 'not-started', 'archive_export': 'not-started' if args.retain_image_archive else 'not-requested', 'native_lifecycle': 'not-run'}
    container_name = None
    create_confirmed = False
    image_id = None
    owner = uuid.uuid4().hex
    config = out / 'docker-config'
    config.mkdir()
    docker = ['docker', '--config', str(config), '--host', 'unix:///var/run/docker.sock']
    cleanup_error = None
    artifacts = out / 'artifacts'
    artifacts.mkdir()
    try:
        retain_artifact(artifacts, 'selection.json', canonical(selection), report)
        retain_artifact(artifacts, 'Dockerfile.native-check', recipe.encode('utf-8'), report)
        with tempfile.TemporaryDirectory(prefix='uas-image-check-') as temporary:
            work = Path(temporary)
            context = work / 'context'
            context.mkdir()
            archive = work / 'source.tar'
            command(['git', 'archive', '--format=tar', '--output=' + str(archive), revision], cwd=ROOT)
            with tarfile.open(archive) as stream:
                stream.extractall(context, filter='data')
            (context / 'Dockerfile.native-check').write_text(recipe)
            (context / 'native-inventory.json').write_bytes(canonical(build_inventory()))
            # No implicit mutable image inputs, push, secret mount, or native run.
            report['build_execution'] = 'running'
            command(docker + ['build', '--platform=linux/amd64', '--target=combined',
                    '--iidfile', str(out / 'image-id'), '-f', 'Dockerfile.native-check', '.'],
                    cwd=context, timeout=600)
            report['build_execution'] = 'completed'
            image_id = (out / 'image-id').read_text().strip()
            require(re.fullmatch(r'sha256:[0-9a-f]{64}', image_id), 'observed image ID required')
            observed = json.loads(command(docker + ['image', 'inspect', image_id], output=True))[0]
            require(observed['Id'] == image_id and observed['Os'] == 'linux'
                    and observed['Architecture'] == 'amd64'
                    and observed['Config']['User'] == '65532:65532'
                    and observed['Config'].get('Entrypoint') in (None, [])
                    and observed['Config'].get('Cmd') in (None, []), 'built image identity/platform/config differs')
            report.update(image_id=image_id, stage='export')
            report['build_execution'] = 'export-running'
            command(docker + ['build', '--platform=linux/amd64', '--target=git-backend-export',
                    '--output=type=local,dest=' + str(out / 'backend'), '-f', 'Dockerfile.native-check', '.'],
                    cwd=context, timeout=600)
            report['build_execution'] = 'completed'
            # Creation only: no process, provider, Git mutation or native launch.
            container_name = 'uas-image-check-' + owner
            container = command(docker + ['create', '--network=none', '--read-only',
                                '--name=' + container_name, '--label=io.uas.image-check=' + owner,
                                '--entrypoint=/uas-readback-never-start', image_id], output=True).decode().strip()
            require(re.fullmatch(r'[0-9a-f]{64}', container), 'owned stopped container ID required')
            create_confirmed = True
            state = json.loads(command(docker + ['inspect', container], output=True))[0]
            require(state['Image'] == image_id and state['State']['Status'] == 'created'
                    and state['State']['Running'] is False, 'readback container identity/state differs')
            report['stage'] = 'readback'
            report['native_payloads'] = {}
            for runtime in ('pi', 'claude'):
                value = document(read_file(container, '/opt/uas/' + runtime + '-manifest.json')['data'])
                report['native_payloads'][runtime] = validate_native(value, runtime, lambda p: read_file(container, p))
                retain_artifact(artifacts, runtime + '-payload.json', canonical(value), report)
            git = validate_payload(document(read_file(container, '/opt/uas/git-payload.json')['data']))
            require(git['python_version'] == selection['git_packages']['python_version'],
                    'built Python version differs from selection')
            backend = out / 'backend' / 'git-backend'
            exported = out / 'backend' / 'git-payload.json'
            require(backend.is_file() and not backend.is_symlink() and backend.stat().st_size <= 64 * 1024 * 1024
                    and exported.is_file() and not exported.is_symlink(), 'regular bounded export required')
            backend_bytes = backend.read_bytes()
            validate_export(git, document(exported.read_bytes()), backend_bytes)
            # Reuse the production Engine readback owner, not a second Git verifier.
            report['git_payload'] = verify_engine_payload(
                SimpleNamespace(socket_path='/var/run/docker.sock', timeout=10), container,
                {**git, 'image_id': image_id}, deadline=time.monotonic() + 60)
            retain_artifact(artifacts, 'git-payload.json', canonical(git), report)
            retain_artifact(artifacts, 'git-backend', backend_bytes, report)
            report['backend_sha256'] = git['backend_sha256']
            if args.retain_image_archive:
                report.update(stage='archive', archive_export='running')
                report['image_archive'] = export_archive(image_id, artifacts, artifact_name='combined-image.tar',
                    max_bytes=2*1024**3, readback={'source_revision':revision,'image_id':image_id,
                        'native_payloads':report['native_payloads'],'git_payload':report['git_payload'],
                        'backend_sha256':report['backend_sha256']})
                report['archive_export'] = 'complete'
            report['status'] = 'passed'
            report['stage'] = 'complete'
            # A local config ID is not a published digest-pinned reference.
            report['installation_envelopes'] = 'not-created-no-published-reference'
    except BaseException as error:
        notes = getattr(error, '__notes__', ())
        if notes: report['error_notes'] = [str(note)[:500] for note in notes[:8]]
        report['status'] = 'failed'
        if report['archive_export'] == 'running': report['archive_export'] = 'failed'
        report['error'] = type(error).__name__ + ': ' + str(error)[:1000]
        if report['build_execution'] in ('running', 'export-running'):
            report['build_execution'] = ('unknown-daemon-outcome' if isinstance(error, subprocess.TimeoutExpired)
                                         else 'failed')
    finally:
        if container_name is not None:
            # Exact returned ID only; never prune shared images/containers.
            try:
                cleanup_container(docker, container_name, owner, image_id, uncertain=not create_confirmed)
            except BaseException as error:
                cleanup_error = type(error).__name__
        report['container_cleanup'] = 'failed' if cleanup_error else ('complete' if container_name else 'not-created')
        if cleanup_error:
            report['cleanup_error'] = cleanup_error
            report['status'] = 'failed'
        (out / 'report.json').write_bytes(canonical(report))
        print(canonical(report).decode())
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
