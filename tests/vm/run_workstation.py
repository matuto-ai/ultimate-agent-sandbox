#!/usr/bin/env python3
"""Deliberate CI-only native two-seat outside-Hub scenario, no guest NIC."""
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
BOOT_TIMEOUT = 1200
SILENT_BOOT_TIMEOUT = 180
IDLE_SERIAL_TIMEOUT = 300
LOG_FILES = ('qemu.log', 'serial.log', 'firmware.log')
REQUIRED = {'payload', 'confinement', 'socket_policy', 'hub_startup', 'native_two_seats',
            'actor_attribution', 'wrong_process', 'control_loss', 'resources', 'guest_cleanup'}
SOURCES = ('uas/__init__.py', 'uas/config.py', 'uas/gate_policy.py', 'uas/context.py', 'uas/forge.py', 'uas/ledger.py', 'uas/lifecycle.py', 'uas/launch.py', 'uas/peer.py', 'uas/pi_runtime.py', 'uas/participant.py', 'uas/docker_fixture.py', 'uas/guest_fixture.py', 'uas/docker_exec_api.py', 'uas/kernel_origin.py', 'uas/workstation_admission.py', 'uas/workstation_control.py', 'uas/workstation_exec.py', 'uas/workstation_hub.py', 'uas/workstation_peer.py', 'uas/workstation_service.py', 'uas/workstation_probe.py', 'tests/vm/fedora-image.json', 'tests/vm/boundary_fixture.go', 'tests/vm/guest_boundary.py', 'tests/vm/guest_workstation.py', 'tests/vm/native_supervisor.py', 'tests/vm/native_rootfs.py', 'tests/vm/native_trust.py', 'runtime/workstation/pi_connector.c', 'runtime/pi/extension.mjs', 'runtime/pi/channel.mjs', 'tests/pi/package.json', 'tests/pi/package-lock.json', 'tests/pi/network-guard.mjs', 'tests/pi/provider.mjs', 'tests/pi/channel-probe.mjs', 'tests/pi/handoff-probe.py')

def seed(directory, nonce, manifest_hash):
    payload = {'disable_root': True, 'ssh_pwauth': False, 'users': [],
               'write_files': [
                   {'path': '/run/uas-guest-workstation.py', 'permissions': '0600', 'encoding': 'b64',
                    'content': base64.b64encode((HERE / 'guest_workstation.py').read_bytes()).decode()},
                   {'path': '/run/guest_boundary.py', 'permissions': '0600', 'encoding': 'b64',
                    'content': base64.b64encode((HERE / 'guest_boundary.py').read_bytes()).decode()},
                   {'path': '/run/uas-vm-fixture', 'permissions': '0600', 'content': nonce}],
               'runcmd': [['python3', '/run/uas-guest-workstation.py', nonce, manifest_hash]],
               'power_state': {'mode': 'poweroff', 'delay': 'now', 'timeout': 30, 'condition': True}}
    (directory / 'user-data').write_text('#cloud-config\n' + json.dumps(payload))
    (directory / 'meta-data').write_text(json.dumps({'instance-id': 'uas-workstation-' + nonce, 'local-hostname': 'uas-boundary'}))
    output = directory / 'seed.iso'
    feasibility.command(['cloud-localds', str(output), str(directory / 'user-data'), str(directory / 'meta-data')])
    return output


def arguments(directory, overlay, seed_image, payload, quota):
    values = feasibility.qemu_arguments(directory, overlay, seed_image)
    values[values.index('-m') + 1] = '4096'
    # Mixing implicit virtio disks with an explicit quota device left firmware
    # disk order unspecified. PC BIOS may try only one hard disk. Name every
    # device and give ONLY the verified OS overlay an explicit boot priority.
    # bootindex must not be combined with legacy -boot order/once parameters.
    for option in ('-drive', '-boot'):
        while option in values:
            index = values.index(option)
            del values[index:index + 2]
    values += ['-boot', 'strict=on,menu=off']
    for name, path, format_, readonly in (('os', overlay, 'qcow2', False),
            ('seed', seed_image, 'raw', True), ('payload', payload, 'raw', True),
            ('quota', quota, 'raw', False)):
        values += ['-drive', f'file={path},format={format_},if=none,id={name}' + (',readonly=on' if readonly else ''),
                   '-device', f'virtio-blk-pci,drive={name}' + (',bootindex=1' if name == 'os' else '')
                   + (',serial=uas-quota' if name == 'quota' else '')]
    # File-only bounded SeaBIOS diagnostics, not a monitor/network listener.
    return [*values, '-chardev', f'file,id=firmware,path={directory / "firmware.log"}',
            '-device', 'isa-debugcon,iobase=0x402,chardev=firmware']


def parse_report(serial, nonce):
    prefix = 'UAS_WORKSTATION_REPORT:' + nonce + ':'
    lines = [line[len(prefix):] for line in serial.splitlines() if line.startswith(prefix)]
    if len(lines) != 1 or len(lines[0]) > 32768:
        raise RuntimeError('expected one bounded report from this boot')
    report = json.loads(lines[0])
    if (report.get('version') != 1 or report.get('nonce') != nonce or 'failure' in report
            or set(report.get('checks', {})) != REQUIRED
            or any(item.get('status') != 'passed' for item in report['checks'].values())):
        raise RuntimeError('guest native scenario failed: ' + json.dumps(report))
    return report


def boot(directory, values, nonce):
    started = time.monotonic()
    last_activity, last_progress = started, started
    serial = directory / 'serial.log'
    previous_bytes = serial.stat().st_size if serial.exists() else 0
    with (directory / 'qemu.log').open('w') as output:
        process = subprocess.Popen(values, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        try:
            while process.poll() is None:
                now = time.monotonic()
                elapsed = now - started
                if elapsed > BOOT_TIMEOUT:
                    raise RuntimeError('guest install/scenario/poweroff exceeded budget')
                serial_bytes = serial.stat().st_size if serial.exists() else 0
                if elapsed > SILENT_BOOT_TIMEOUT and serial_bytes == 0:
                    raise RuntimeError('guest produced no serial boot output within 180 seconds')
                if serial_bytes != previous_bytes:
                    last_activity, previous_bytes = now, serial_bytes
                if now - last_activity > IDLE_SERIAL_TIMEOUT:
                    raise RuntimeError('guest serial output stalled for 300 seconds')
                if now - last_progress >= 30:
                    print('VM guest progress:', json.dumps({'elapsed_seconds': round(elapsed),
                          'serial_bytes': serial_bytes, 'serial_idle_seconds': round(now - last_activity)}), flush=True)
                    last_progress = now
                for name in LOG_FILES:
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
        with tempfile.TemporaryDirectory(prefix='uas-workstation-vm-') as temporary:
            directory = Path(temporary); nonce = uuid.uuid4().hex
            try:
                lock = json.loads((HERE / 'fedora-image.json').read_text())
                print('VM native Workstation phase: downloading/verifying pinned image', flush=True)
                image = feasibility.fetch_image(lock, directory)
                print('VM native Workstation phase: verified image; preparing signed payload; elapsed_seconds=', round(time.monotonic() - started, 3), flush=True)
                payload = build_payload(directory, ROOT, nonce, source_paths=SOURCES, profile='native-pi-v1')
                manifest = payload.parent / 'payload/manifest.json'
                digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
                overlay, quota = directory / 'guest.qcow2', directory / 'quota.raw'
                feasibility.command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image), str(overlay)])
                with quota.open('xb') as source:
                    source.truncate(2 * 1024 * 1024 * 1024)
                print('VM native Workstation phase: payload ready; booting explicit OS disk; elapsed_seconds=', round(time.monotonic() - started, 3), flush=True)
                report, seconds = boot(directory, arguments(directory, overlay, seed(directory, nonce, digest), payload, quota), nonce)
                print('VM native Workstation:', json.dumps({'guest': report, 'boot_install_scenario_shutdown_seconds': seconds,
                      'image_sha256': lock['sha256'], 'payload_manifest_sha256': digest, 'no_guest_external_network': True}, sort_keys=True), flush=True)
            except BaseException:
                for name in LOG_FILES:
                    path = directory / name
                    if path.exists():
                        with path.open('rb') as source:
                            source.seek(max(0, path.stat().st_size - 131072))
                            print(name + ' tail:', source.read(131072).decode(errors='replace'), flush=True)
                raise
    finally:
        print('VM native Workstation cleanup:', json.dumps({'temporary_directory_removed': directory is None or not directory.exists(),
              'elapsed_seconds': round(time.monotonic() - started, 3)}), flush=True)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    main()
