#!/usr/bin/env python3
"""Disposable CI-only actual two-Room network/quota scenario, no guest NIC."""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid

import run as feasibility
from prepare_payload import build_payload

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BOOT_TIMEOUT = 1800
REQUIRED = {'runtime', 'network', 'writable_mounts', 'block_quota', 'inode_quota',
            'recovery', 'drift', 'destroy', 'sibling_health', 'guest_cleanup'}
SOURCES = ('uas/__init__.py', 'uas/lifecycle.py', 'uas/docker_fixture.py', 'uas/guest_fixture.py',
           'uas/launch.py', 'uas/config.py', 'tests/vm/fedora-image.json',
           'tests/vm/boundary_fixture.go', 'tests/vm/guest_boundary.py')


def seed(directory, nonce, manifest_hash):
    payload = {'disable_root': True, 'ssh_pwauth': False, 'users': [],
               'write_files': [
                   {'path': '/run/uas-guest-boundary.py', 'permissions': '0600', 'encoding': 'b64',
                    'content': base64.b64encode((HERE / 'guest_boundary.py').read_bytes()).decode()},
                   {'path': '/run/uas-vm-fixture', 'permissions': '0600', 'content': nonce}],
               'runcmd': [['python3', '/run/uas-guest-boundary.py', nonce, manifest_hash]],
               'power_state': {'mode': 'poweroff', 'delay': 'now', 'timeout': 30, 'condition': True}}
    (directory / 'user-data').write_text('#cloud-config\n' + json.dumps(payload))
    (directory / 'meta-data').write_text(json.dumps({'instance-id': 'uas-boundary-' + nonce, 'local-hostname': 'uas-boundary'}))
    output = directory / 'seed.iso'
    feasibility.command(['cloud-localds', str(output), str(directory / 'user-data'), str(directory / 'meta-data')])
    return output


def arguments(directory, overlay, seed_image, payload, quota):
    values = feasibility.qemu_arguments(directory, overlay, seed_image)
    values[values.index('-m') + 1] = '4096'
    return [*values, '-drive', f'file={payload},format=raw,if=virtio,readonly=on',
            '-drive', f'file={quota},format=raw,if=none,id=quota',
            '-device', 'virtio-blk-pci,drive=quota,serial=uas-quota']


def parse_report(serial, nonce):
    prefix = 'UAS_BOUNDARY_REPORT:' + nonce + ':'
    lines = [line[len(prefix):] for line in serial.splitlines() if line.startswith(prefix)]
    if len(lines) != 1 or len(lines[0]) > 32768:
        raise RuntimeError('expected one bounded report from this boot')
    report = json.loads(lines[0])
    if (report.get('version') != 1 or report.get('nonce') != nonce or set(report.get('checks', {})) != REQUIRED
            or any(item.get('status') != 'passed' for item in report['checks'].values())):
        raise RuntimeError('guest boundary scenario failed: ' + json.dumps(report))
    return report


def boot(directory, values, nonce):
    started = time.monotonic()
    with (directory / 'qemu.log').open('w') as output:
        process = subprocess.Popen(values, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        try:
            while process.poll() is None:
                if time.monotonic() - started > BOOT_TIMEOUT:
                    raise RuntimeError('guest install/scenario/poweroff exceeded budget')
                for name in ('qemu.log', 'serial.log'):
                    path = directory / name
                    if path.exists() and path.stat().st_size > feasibility.LOG_LIMIT:
                        raise RuntimeError('guest log budget exceeded')
                time.sleep(1)
            if process.returncode != 0:
                raise RuntimeError('QEMU abnormal exit')
            return parse_report((directory / 'serial.log').read_text(errors='replace'), nonce), round(time.monotonic() - started, 3)
        finally:
            feasibility.stop_process(process)


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() == 0:
        raise RuntimeError('run only as unprivileged user on disposable GitHub CI')
    started = time.monotonic(); directory = None
    try:
        with tempfile.TemporaryDirectory(prefix='uas-boundary-vm-') as temporary:
            directory = Path(temporary); nonce = uuid.uuid4().hex
            try:
                lock = json.loads((HERE / 'fedora-image.json').read_text())
                image = feasibility.fetch_image(lock, directory)
                payload = build_payload(directory, ROOT, nonce, source_paths=SOURCES)
                manifest = payload.parent / 'payload/manifest.json'
                digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
                overlay, quota = directory / 'guest.qcow2', directory / 'quota.raw'
                feasibility.command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image), str(overlay)])
                with quota.open('xb') as source:
                    source.truncate(512 * 1024 * 1024)
                report, seconds = boot(directory, arguments(directory, overlay, seed(directory, nonce, digest), payload, quota), nonce)
                print('VM boundary:', json.dumps({'guest': report, 'boot_install_scenario_shutdown_seconds': seconds,
                      'image_sha256': lock['sha256'], 'payload_manifest_sha256': digest, 'no_guest_external_network': True}, sort_keys=True), flush=True)
            except BaseException:
                for name in ('qemu.log', 'serial.log'):
                    path = directory / name
                    if path.exists():
                        with path.open('rb') as source:
                            source.seek(max(0, path.stat().st_size - 65536))
                            print(name + ' tail:', source.read(65536).decode(errors='replace'), flush=True)
                raise
    finally:
        print('VM boundary cleanup:', json.dumps({'temporary_directory_removed': directory is None or not directory.exists(),
              'elapsed_seconds': round(time.monotonic() - started, 3)}), flush=True)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    main()
