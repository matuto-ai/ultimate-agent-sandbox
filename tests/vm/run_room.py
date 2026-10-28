#!/usr/bin/env python3
"""Explicit hosted Room-launch qualification; one fixed IPv4 NIC from boot.

Source-only candidate until independent review and deliberate run authorization.
No old no-NIC entrypoint is altered, no interface is hot-added, and QEMU has no
host forwarding, shared host path, runtime socket, SSH, monitor, or TAP helper.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time
import uuid

import run as feasibility
from prepare_payload import build_payload
from prepare_room_payload import ROOM_MODULES
import room_profile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PROFILE = room_profile.PROFILE
BOOT_TIMEOUT = 1200
SILENT_BOOT_TIMEOUT = 180
IDLE_SERIAL_TIMEOUT = 300
LOG_FILES = ('qemu.log', 'serial.log', 'firmware.log')
REQUIRED = {'payload', 'confinement', 'mounts', 'limits', 'endpoint_service',
            'network', 'recovery', 'guest_cleanup'}
DENIED = {'host-private', 'host-public', 'LAN', 'metadata', 'sibling'}
BOOTSTRAP_SOURCES = ('guest_room.py', 'guest_boundary.py', 'room_profile.py')
SOURCES = tuple('uas/' + name + '.py' for name in ROOM_MODULES) + (
    'tests/vm/fedora-image.json', 'tests/vm/boundary_fixture.go',
    'tests/vm/guest_boundary.py', 'tests/vm/guest_workstation.py',
    'tests/vm/native_rootfs.py', 'tests/vm/native_trust.py',
    'tests/vm/room_profile.py', 'tests/vm/room_service.py', 'tests/vm/guest_room.py',
    'tests/vm/room_policy_diagnostics.py')


def _nonce(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{32}', value) is None:
        raise ValueError('exact Room boot nonce required')


def seed(directory, nonce, manifest_hash, *, payload_root):
    _nonce(nonce)
    if type(manifest_hash) is not str or re.fullmatch('[0-9a-f]{64}', manifest_hash) is None:
        raise ValueError('exact payload manifest digest required')
    # Seed only the already manifest-bound copied bytes, never mutable checkout
    # files after the payload was built. That keeps boot code on the same source.
    if payload_root.resolve() != payload_root or not payload_root.is_dir():
        raise ValueError('canonical staged payload root required')
    manifest_path = payload_root / 'manifest.json'
    node = manifest_path.lstat()
    if (manifest_path.resolve() != manifest_path or not stat.S_ISREG(node.st_mode)
            or node.st_nlink != 1 or not 0 < node.st_size <= 2 * 1024**2):
        raise ValueError('ordinary bounded staged payload manifest required')
    manifest_bytes = manifest_path.read_bytes()
    if len(manifest_bytes) > 2 * 1024**2 or hashlib.sha256(manifest_bytes).hexdigest() != manifest_hash:
        raise ValueError('staged payload manifest differs')
    manifest = json.loads(manifest_bytes, object_pairs_hook=_unique)
    if (type(manifest) is not dict or manifest.get('nonce') != nonce
            or manifest.get('profile') != PROFILE or type(manifest.get('source')) is not list):
        raise ValueError('staged Room payload scope differs')
    bootstrap = {}
    for name in BOOTSTRAP_SOURCES:
        relative = 'tests/vm/' + name
        entries = [item for item in manifest['source'] if type(item) is dict and item.get('file') == relative]
        if len(entries) != 1 or set(entries[0]) != {'file', 'bytes', 'sha256'}:
            raise ValueError('exact copied bootstrap source required')
        path = payload_root / 'repo' / relative
        node = path.lstat()
        if (path.resolve() != path or not stat.S_ISREG(node.st_mode)
                or node.st_nlink != 1 or not 0 < node.st_size <= 1024**2):
            raise ValueError('ordinary copied bootstrap source required')
        raw = path.read_bytes()
        if (type(entries[0]['bytes']) is not int or not 0 < len(raw) <= 1024**2
                or len(raw) != entries[0]['bytes'] or hashlib.sha256(raw).hexdigest() != entries[0]['sha256']):
            raise ValueError('copied bootstrap source differs')
        bootstrap[name] = base64.b64encode(raw).decode('ascii')
    payload = {'disable_root': True, 'ssh_pwauth': False, 'users': [],
        'package_update': False, 'package_upgrade': False,
        'write_files': [{'path': '/run/' + name, 'permissions': '0600', 'encoding': 'b64',
            'content': bootstrap[name]}
            for name in BOOTSTRAP_SOURCES] + [
                {'path': '/run/uas-vm-fixture', 'permissions': '0600', 'content': nonce},
                {'path': str(room_profile.MARKER), 'permissions': '0600',
                 'content': json.dumps(room_profile.marker(nonce), sort_keys=True, separators=(',', ':'))}],
        'runcmd': [['python3', '/run/guest_room.py', nonce, manifest_hash]],
        'power_state': {'mode': 'poweroff', 'delay': 'now', 'timeout': 30, 'condition': True}}
    user_data, metadata, network = (directory / name for name in ('user-data', 'meta-data', 'network-config'))
    user_data.write_text('#cloud-config\n' + json.dumps(payload))
    metadata.write_text(json.dumps({'instance-id': 'uas-room-' + nonce, 'local-hostname': 'uas-room-fixture'}))
    network.write_text(json.dumps(room_profile.network_config(), sort_keys=True))
    output = directory / 'seed.iso'
    feasibility.command(['cloud-localds', '--network-config=' + str(network),
                         str(output), str(user_data), str(metadata)])
    return output


def arguments(directory, overlay, seed_image, payload, quota):
    return room_profile.qemu_arguments(directory, overlay, seed_image, payload, quota)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate Room report key')
        value[key] = item
    return value


def parse_report(serial, nonce):
    _nonce(nonce)
    prefix = 'UAS_ROOM_REPORT:' + nonce + ':'
    lines = [line[len(prefix):] for line in serial.splitlines() if line.startswith(prefix)]
    if len(lines) != 1 or len(lines[0]) > 65536:
        raise RuntimeError('one bounded exact Room launch report required')
    value = json.loads(lines[0], object_pairs_hook=_unique)
    if (type(value) is not dict or type(value.get('version')) is not int or value['version'] != 1
            or value.get('nonce') != nonce or value.get('profile') != PROFILE
            or value.get('production_enabled') is not False or 'failure' in value
            or type(value.get('checks')) is not dict or set(value['checks']) != REQUIRED
            or any(type(item) is not dict or item.get('status') != 'passed'
                   for item in value['checks'].values())):
        raise RuntimeError('Room launch qualification incomplete or failed')
    network = value['checks']['network']
    denied = network.get('denied')
    if (network.get('real_public_https') is not True or type(denied) is not list
            or len(denied) != len(DENIED) or any(type(item) is not str for item in denied)
            or set(denied) != DENIED):
        raise RuntimeError('real public egress and every required deny must be proved')
    return value


def boot(directory, values, nonce):
    started = last_activity = last_progress = time.monotonic()
    serial = directory / 'serial.log'
    previous_bytes = serial.stat().st_size if serial.exists() else 0
    with (directory / 'qemu.log').open('x') as output:
        process = subprocess.Popen(values, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        try:
            while process.poll() is None:
                now = time.monotonic()
                elapsed = now - started
                serial_bytes = serial.stat().st_size if serial.exists() else 0
                if elapsed > BOOT_TIMEOUT:
                    raise RuntimeError('Room guest install/scenario/shutdown exceeded budget')
                if elapsed > SILENT_BOOT_TIMEOUT and serial_bytes == 0:
                    raise RuntimeError('Room guest produced no serial boot output')
                if serial_bytes != previous_bytes:
                    last_activity, previous_bytes = now, serial_bytes
                if now - last_activity > IDLE_SERIAL_TIMEOUT:
                    raise RuntimeError('Room guest serial output stalled')
                if now - last_progress >= 30:
                    print('Room VM progress:', json.dumps({'elapsed_seconds': round(elapsed),
                        'serial_bytes': serial_bytes, 'serial_idle_seconds': round(now - last_activity)}), flush=True)
                    last_progress = now
                for name in LOG_FILES:
                    path = directory / name
                    if path.exists() and path.stat().st_size > feasibility.LOG_LIMIT:
                        raise RuntimeError('Room VM log budget exceeded')
                time.sleep(1)
            if process.returncode != 0:
                raise RuntimeError('Room QEMU abnormal exit')
            # Recheck logs after exit; a final burst must not bypass the budget.
            for name in LOG_FILES:
                path = directory / name
                if path.exists() and path.stat().st_size > feasibility.LOG_LIMIT:
                    raise RuntimeError('Room VM final log budget exceeded')
            report = parse_report(serial.read_text(errors='replace'), nonce)
            return report, round(time.monotonic() - started, 3)
        finally:
            feasibility.stop_process(process)  # This exact owned Popen only.


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux'
            or os.geteuid() == 0 or os.environ.get('UAS_ROOM_VM_PROFILE') != PROFILE):
        raise RuntimeError('explicit unprivileged hosted Room IPv4 profile required')
    started = time.monotonic()
    directory = None
    try:
        with tempfile.TemporaryDirectory(prefix='uas-room-vm-') as temporary:
            directory = Path(temporary)
            nonce = uuid.uuid4().hex
            try:
                lock = json.loads((HERE / 'fedora-image.json').read_text())
                print('Room VM phase: verifying pinned guest image', flush=True)
                image = feasibility.fetch_image(lock, directory)
                print('Room VM phase: preparing signed offline source payload', flush=True)
                payload = build_payload(directory, ROOT, nonce, source_paths=SOURCES, profile=PROFILE)
                manifest = payload.parent / 'payload/manifest.json'
                digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
                overlay, quota = directory / 'guest.qcow2', directory / 'quota.raw'
                feasibility.command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
                                     '-b', str(image), str(overlay)])
                with quota.open('xb') as output:
                    output.truncate(2 * 1024**3)
                print('Room VM phase: booting fixed IPv4 profile; no host forwarding', flush=True)
                selected = arguments(directory, overlay, seed(directory, nonce, digest,
                    payload_root=payload.parent / 'payload'), payload, quota)
                report, seconds = boot(directory, selected, nonce)
                print('Room VM:', json.dumps({'guest': report, 'image_sha256': lock['sha256'],
                    'payload_manifest_sha256': digest, 'boot_install_scenario_shutdown_seconds': seconds,
                    'profile': PROFILE, 'guest_ipv4_network': True, 'host_forwarding': False,
                    'production_enabled': False}, sort_keys=True), flush=True)
            except BaseException:
                for name in LOG_FILES:
                    path = directory / name
                    if path.exists():
                        with path.open('rb') as source:
                            source.seek(max(0, path.stat().st_size - 131072))
                            print(name + ' tail:', source.read(131072).decode(errors='replace'), flush=True)
                raise
    finally:
        print('Room VM cleanup:', json.dumps({'owned_temporary_directory_removed': directory is None or not directory.exists(),
            'elapsed_seconds': round(time.monotonic() - started, 3)}), flush=True)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    main()
