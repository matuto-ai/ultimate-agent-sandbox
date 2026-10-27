#!/usr/bin/env python3
"""Fixed from-boot IPv4 Room boundary; disposable guest only, no production API."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import traceback

import guest_boundary as boundary
import room_profile

run, require = boundary.run, boundary.expect
PROFILE = room_profile.PROFILE
REQUIRED = {'payload', 'confinement', 'mounts', 'limits', 'endpoint_service',
            'network', 'recovery', 'guest_cleanup'}
PACKAGE_PROFILE = {'moby-engine': ('0', '29.8.2', '2.fc44', 'x86_64'),
                   'container-selinux': ('4', '2.251.0', '1.fc44', 'noarch')}


def install(nonce, digest):
    # Separate fixed entrypoint: the old install() still excludes every NIC.
    observed = room_profile.guest_guard(nonce, run=run)
    require(run('getenforce').strip() == 'Enforcing', 'stock SELinux enforcing required')
    boundary.PAYLOAD.mkdir()
    run('mount', '-o', 'ro,nodev,nosuid,noexec', '/dev/disk/by-label/UAS_PAYLOAD', str(boundary.PAYLOAD))
    manifest = boundary.verify_payload(nonce, digest)
    require(manifest.get('profile') == PROFILE, 'exact fixed Room payload required')
    boundary.install_packages(nonce, manifest, exact_roots=PACKAGE_PROFILE)
    # Only this profile's signed pool supplies the real, uninvoked descriptors.
    roots = []
    for name in ('git-core', 'openssh-clients'):
        candidates = [item for item in manifest['packages'] if item['name'] == name]
        require(len(candidates) == 1, 'unique signed Room guest package required')
        item = candidates[0]
        roots.append(f"{name}-{item['epoch']}:{item['version']}-{item['release']}.{item['arch']}")
    run('dnf', '-y', '--setopt=reposdir=/run/uas-repositories', '--disable-repo=*',
        '--enable-repo=uas-offline', '--setopt=localpkg_gpgcheck=True',
        '--setopt=install_weak_deps=False', 'install', *roots, timeout=180)
    for name in ('git-core', 'openssh-clients'):
        result = run('rpm', '-V', name)
        require(not result.strip(), 'signed Room executable package changed')
    shutil.copytree(boundary.PAYLOAD / 'repo', boundary.ROOT)
    shutil.copyfile(boundary.PAYLOAD / 'fixture', boundary.ROOT / 'fixture')
    (boundary.ROOT / 'fixture').chmod(0o555)
    run('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'uas-remap')
    Path('/etc/subuid').write_text('uas-remap:100000:65536\n')
    Path('/etc/subgid').write_text('uas-remap:100000:65536\n')
    Path('/etc/docker').mkdir(exist_ok=True)
    Path('/etc/docker/daemon.json').write_text(json.dumps(boundary.DOCKER_CONFIGURATION))
    return manifest, observed


def stop_child(process):
    # Popen has not been polled/reaped anywhere: sole owned child remains held.
    descriptor = os.pidfd_open(process.pid)
    try:
        try: signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=5)
    finally: os.close(descriptor)


def import_image(archive):
    arguments = ('docker', 'import', '--change', 'USER 65532:65532',
                 '--change', 'ENTRYPOINT ["/fixture"]', str(archive))
    code, result = boundary.native_command(arguments, timeout=240, phase='image-import')
    require(code == 0, 'Room image import failed: ' + json.dumps(result))
    image = result['stdout']['output'].strip()
    require(image.startswith('sha256:') and len(image) == 71, 'exact immutable Room image required')
    return image


def scenario(nonce, manifest, boot_network, checks):
    sys.path.insert(0, str(boundary.ROOT)); sys.path.insert(0, str(boundary.ROOT / 'tests/vm'))
    from native_rootfs import build_room_rootfs
    from room_service import endpoint, prove_service, prove_foreign_socket_sid
    from uas.guest_fixture import CONTROL, ROOMS, STORAGE, prepare_storage, network_names, firewall_document, command
    from uas.lifecycle import Supervisor
    from uas.room_fixture import RoomFixtureLimits, RoomLaunchFixtureBackend
    supervisors, backends, endpoints, specs, containers, states = {}, {}, {}, {}, {}, {}
    children, created = [], set()
    image = None
    cleanup_errors = []
    limits = RoomFixtureLimits(memory_bytes=96 * 1024**2, nano_cpus=750_000_000,
                               pids=24, disk_bytes=8 * 1024**2, inodes=128, log_bytes=524288)
    try:
        root = Path('/var/lib/uas-native-rootfs'); archive = root.with_suffix('.tar')
        image_facts = build_room_rootfs(nonce, manifest, root, run=run)
        boundary.start_engine()
        require(run('docker', 'version', '--format', '{{.Server.Version}}').strip() == '29.8.2', 'exact selected Engine required')
        with tarfile.open(archive, 'x', format=tarfile.PAX_FORMAT) as target:
            for path in sorted(root.iterdir()): target.add(path, arcname=path.name, recursive=True)
        image = import_image(archive)
        checks['payload'] = {'status': 'passed', 'image': image, 'rootfs': image_facts,
                             'boot_network': boot_network, 'native_pi_enabled': False}
        device = Path('/dev/disk/by-id/virtio-uas-quota')
        require(device.exists() and run('blockdev', '--getsize64', str(device)).strip() == str(2 * 1024**3),
                'exact owned quota disk required')
        run('mkfs.xfs', '-f', str(device)); STORAGE.mkdir()
        run('mount', '-o', 'prjquota,nodev,nosuid', str(device), str(STORAGE)); created.add('storage')
        prepare_storage(nonce, limits={room: (limits.disk_bytes // 1024, limits.inodes) for room in ROOMS})
        attribute_control = boundary.attribute_positive_control(STORAGE)
        for room in ROOMS:
            endpoints[room] = endpoint(room, run)
            backend = backends[room] = RoomLaunchFixtureBackend(nonce, room, limits=limits, endpoints=(endpoints[room],))
            supervisor = supervisors[room] = Supervisor(CONTROL / 'lifecycle', room, backend,
                authorize=lambda *_: True, revoke=lambda *_: True)
            specs[room] = backend.fixture_spec(image)
            status = supervisor.start(specs[room])
            require(status['phase'] == 'running', 'actual Room launch failed: ' + json.dumps(status))
            containers[room] = status['observed']['container']['id']
            states[room] = supervisor._read()
        def probe(room, *args):
            return json.loads(run('docker', 'exec', containers[room], '/fixture', *args, timeout=8))
        def python_probe(room, mode):
            return json.loads(run('docker', 'exec', containers[room], '/usr/bin/python3', '-I',
                                  '/opt/uas/uas/room_probe.py', mode, timeout=8))
        confinement, observed_limits = {}, {}
        for room in ROOMS:
            actual = probe(room, 'observe'); files = actual['files']
            require(actual['uid'] == actual['gid'] == 65532, 'nonroot Workstation required')
            status = dict(line.split(':', 1) for line in files['/proc/self/status'].splitlines() if ':' in line)
            process = {key: status[key].strip() for key in ('CapEff', 'CapBnd', 'NoNewPrivs', 'Seccomp')}
            require(process == {'CapEff': '0000000000000000', 'CapBnd': '0000000000000000',
                                'NoNewPrivs': '1', 'Seccomp': '2'}, 'actual Workstation confinement differs')
            boundary.require_process_label(files['/proc/self/attr/current'], ROOMS[room][3])
            require(files['/proc/self/uid_map'].split() == files['/proc/self/gid_map'].split() == ['0', '100000', '65536'],
                    'actual userns remapping differs')
            require(files['/sys/fs/cgroup/memory.max'] == str(limits.memory_bytes)
                    and files['/sys/fs/cgroup/pids.max'] == str(limits.pids), 'actual cgroup limits differ')
            quota, period = map(int, files['/sys/fs/cgroup/cpu.max'].split())
            require(quota * 4 == period * 3, 'actual CPU bound differs')
            info = backends[room].admit(states[room]); backends[room]._quota()
            confinement[room] = {'kernel_status': process, 'uid_map': files['/proc/self/uid_map'],
                                  'gid_map': files['/proc/self/gid_map'], 'label': files['/proc/self/attr/current']}
            observed_limits[room] = {'memory': files['/sys/fs/cgroup/memory.max'], 'pids': files['/sys/fs/cgroup/pids.max'],
                'cpu': files['/sys/fs/cgroup/cpu.max'], 'log': info['HostConfig']['LogConfig'],
                'xfs_block_hard_kib': limits.disk_bytes // 1024, 'xfs_inode_hard': limits.inodes}
            for flag in ('b','i'):
                report = command('xfs_quota','-x','-c',f'report -p -{flag} -n -N',str(STORAGE))
                require(len(report) <= 16384, 'bounded quota observation required')
                rows = [line.split() for line in report.splitlines() if line.split() and line.split()[0] == '#'+str(ROOMS[room][0])]
                require(len(rows) == 1, 'exact observed quota project required')
                observed_limits[room]['actual_xfs_'+flag] = rows[0]
            attrs = probe(room, 'attributes', str(STORAGE / room / 'workspace'))
            require(attrs['clear_inherit'] in ('EPERM', 'EACCES', 'EINVAL')
                    and attrs['change_project'] in ('EPERM', 'EACCES', 'EINVAL')
                    and attrs['initial_project'] == attrs['after_change_project'] == ROOMS[room][0]
                    and attrs['after_clear_inherit'] is True, 'quota escape permitted')
        checks['confinement'] = {'status': 'passed', 'workstations': confinement,
            'fssetxattr_initial_userns_positive_control':attribute_control}
        private = {}
        for room in ROOMS:
            for name in ('repository', 'workspace', 'checkouts'):
                require(probe(room, 'write', str(STORAGE / room / name))['error'] == 'OK', 'admitted writable mount denied')
            require(probe(room, 'write', str(STORAGE / room / 'references'))['error'] == 'EROFS', 'readonly reference writable')
            require(probe(room, 'write', '/state')['error'] == 'OK', 'admitted Runtime state not writable')
            private[room] = python_probe(room, 'private')
            require(private[room]['endpoint_unlink'] == 'EROFS'
                    and all(value in ('ENOENT','EACCES') for key,value in private[room].items() if key != 'endpoint_unlink'),
                    'private stores/Engine exposed or endpoint writable')
        checks['mounts'] = {'status': 'passed', 'private':private,
            'actual_mounts': {room: backends[room].admit(states[room])['Mounts'] for room in ROOMS}}
        # The bootstrap receives no workload release until the actual mounted
        # service and same live Broker have both passed their checks.
        checks['endpoint_service'] = prove_service(supervisors['alpha'], backends['alpha'], endpoints['alpha'], containers['alpha'], run=run)
        require(checks['endpoint_service']['held_bootstrap_exit_observed'] is True,
                'held workload must exit before destructive endpoint negatives')
        checks['endpoint_service']['foreign_socket_sid'] = prove_foreign_socket_sid(
            supervisors['alpha'], endpoints['alpha'], python_probe, run=run)
        # Actual stock SELinux denial, not an invented receipt or off-host policy.
        directory, leaf = endpoints['alpha'].parent, endpoints['alpha'].leases[0].path
        try:
            run('chcon', '-l', ROOMS['beta'][3], str(directory), str(leaf))
            denied = python_probe('alpha', 'endpoint')
            require(denied == {'connected': False, 'error': 'EACCES'}, 'foreign Room MCS endpoint not denied')
        finally: run('chcon', '-l', ROOMS['alpha'][3], str(directory), str(leaf))
        endpoints['alpha'].require()
        checks['endpoint_service']['foreign_room_mcs_denied'] = denied
        for kind in ('block', 'inode'):
            result = probe('alpha', 'quota-' + kind, str(STORAGE / 'alpha/workspace'))
            require(result['error'] == 'ENOSPC', 'configured XFS bound not enforced')
            space = os.statvfs(STORAGE)
            require(space.f_bavail * space.f_frsize > 64 * 1024 * 1024 and space.f_favail > 1000,
                    'underlying filesystem exhausted instead of selected project')
            path = Path(result['probe_path'])
            require(path.parent == STORAGE / 'alpha/workspace' and path.name.startswith('quota-probe-')
                    and path.resolve() == path, 'unsafe owned quota probe cleanup')
            require(probe('beta', 'write-new', str(STORAGE / 'beta/workspace'))['error'] == 'OK', 'sibling quota isolation failed')
            shutil.rmtree(path)
            observed_limits['exhaustion_' + kind] = result
        checks['limits'] = {'status': 'passed', 'observed': observed_limits}
        # Live in-guest decoys retain the existing attributed deny controls.
        run('ip', 'netns', 'add', 'uas-public'); created.add('netns')
        run('ip', 'link', 'add', 'uas-public', 'type', 'veth', 'peer', 'name', 'uas-peer'); created.add('veth')
        run('ip', 'link', 'set', 'uas-peer', 'netns', 'uas-public')
        run('ip', 'addr', 'add', '10.254.0.1/30', 'dev', 'uas-public'); run('ip', 'link', 'set', 'uas-public', 'up')
        for address in ('93.184.216.34', '169.254.169.254', '192.168.50.1'):
            run('ip', 'route', 'add', address + '/32', 'via', '10.254.0.2')
        run('ip', 'addr', 'add', '93.184.216.35/32', 'dev', 'lo'); created.add('public-host')
        run('sysctl', '-w', 'net.ipv4.ip_forward=1')
        namespace = os.open('/run/netns/uas-public', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            run('python3', str(boundary.ROOT / 'tests/vm/guest_boundary.py'), '--configure-public', nonce, str(namespace), pass_fds=(namespace,))
            children.append(subprocess.Popen(['python3', str(boundary.ROOT / 'tests/vm/guest_boundary.py'),
                '--responder', nonce, str(namespace)], pass_fds=(namespace,)))
        finally: os.close(namespace)
        children.append(subprocess.Popen(['python3', __file__, '--host-responder', nonce]))
        for _ in range(40):
            try:
                if all(boundary.connect(ip) for ip in ('93.184.216.34', '169.254.169.254', '192.168.50.1', '93.184.216.35')): break
            except OSError: time.sleep(.05)
        else: raise RuntimeError('live decoys not ready')
        public = python_probe('alpha', 'public-head')
        require(public['certificate_hostname_verified'] is True, 'real verified public HTTPS unavailable')
        def dropped(chain): return boundary.denial_counter(backends['alpha']._firewall(states['alpha']), chain)
        counts = {}
        for address, chain in (('10.89.1.1', 'input'), ('93.184.216.35', 'input'),
                               ('169.254.169.254', 'forward'), ('192.168.50.1', 'forward')):
            before = dropped(chain)
            require(probe('alpha', 'connect', address + ':5000')['error'] == 'TIMEOUT', 'forbidden destination reachable')
            after = dropped(chain); require(after > before, 'missing exact firewall deny')
            counts[address] = {'before': before, 'after': after, 'chain': chain}
        sibling = boundary.require_sibling_denial(probe, backends['beta'], states['beta'], containers['beta'])
        require(probe('alpha', 'connect', '[2606:4700:4700::1111]:5000')['error'] == 'ENETUNREACH', 'IPv6 must remain unavailable')
        checks['network'] = {'status': 'passed', 'real_public_https': True, 'public': public,
            'denied': ['host-private', 'host-public', 'LAN', 'metadata', 'sibling'], 'counters': counts,
            'sibling': sibling, 'ipv6': 'disabled-and-filtered'}
        original = containers['alpha']
        require(supervisors['alpha'].stop()['phase'] == 'stopped', 'Room stop failed')
        resumed = supervisors['alpha'].start(specs['alpha'])
        require(resumed['phase'] == 'running' and resumed['observed']['container']['id'] == original, 'resume replaced owned image')
        require(supervisors['alpha'].stop()['phase'] == 'stopped', 'stop for drift failed')
        table = network_names(states['alpha'])[2]
        command('nft', 'flush', 'chain', 'inet', table, 'forward')
        rejected = supervisors['alpha'].start(specs['alpha'])
        require(rejected['phase'] == 'start_failed' and rejected['observed']['container']['running'] is False,
                'drift restarted stopped workload')
        command('nft', 'delete', 'table', 'inet', table)
        command('nft', '-j', '-f', '-', input=json.dumps(firewall_document(states['alpha'], nonce)))
        require(supervisors['alpha'].reconcile()['phase'] == 'running', 'owned explicit recovery failed')
        checks['recovery'] = {'status': 'passed', 'same_container_resume': True, 'drift_failed_closed': True,
            'scope':'container-network-storage-after-service-teardown', 'persistent_participant_service_restart':False}
    finally:
        for room, supervisor in supervisors.items():
            try: require(supervisor.destroy()['phase'] == 'destroyed', 'owned Room cleanup failed')
            except BaseException as error: cleanup_errors.append(type(error).__name__ + ':' + room)
        for item in endpoints.values():
            for listener in item.listeners: listener.close()
        for process in children:
            try: stop_child(process)
            except BaseException as error: cleanup_errors.append(type(error).__name__ + ':responder')
        commands = []
        if 'veth' in created: commands.append(('ip', 'link', 'del', 'uas-public'))
        if 'netns' in created: commands.append(('ip', 'netns', 'del', 'uas-public'))
        if 'public-host' in created: commands.append(('ip', 'addr', 'del', '93.184.216.35/32', 'dev', 'lo'))
        if image is not None: commands.append(('docker', 'image', 'rm', image))
        if 'storage' in created: commands.append(('umount', str(STORAGE)))
        for arguments in commands:
            try: run(*arguments)
            except BaseException as error: cleanup_errors.append(type(error).__name__ + ':' + arguments[0])
        checks['guest_cleanup'] = {'status': 'failed' if cleanup_errors else 'passed', 'errors': cleanup_errors,
            'outer_disposable_vm_removal_remains_mandatory': True}
    require(not cleanup_errors, 'owned guest cleanup incomplete')
    return checks


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--host-responder':
        require(os.getuid() == 0 and Path('/run/uas-vm-fixture').read_text().strip() == sys.argv[2], 'owned guest responder required')
        boundary.responder(); return
    require(len(sys.argv) == 3, 'fixed nonce/manifest required')
    nonce, digest = sys.argv[1:]
    checks, failure = {}, None
    try:
        manifest, network = install(nonce, digest)
        scenario(nonce, manifest, network, checks)
        require(set(checks) == REQUIRED and all(value.get('status') == 'passed' for value in checks.values()), 'incomplete Room qualification')
    except BaseException as error:
        print(traceback.format_exc()[-16384:], flush=True)
        failure = {'error_type': type(error).__name__}
    report = {'version': 1, 'nonce': nonce, 'profile': PROFILE, 'production_enabled': False, 'checks': checks}
    if failure is not None: report['failure'] = failure
    with open('/dev/ttyS0', 'w') as serial:
        serial.write('\nUAS_ROOM_REPORT:' + nonce + ':' + json.dumps(report, sort_keys=True) + '\n'); serial.flush()


if __name__ == '__main__': main()
