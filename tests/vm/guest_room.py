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
PACKAGE_PROFILE = room_profile.PACKAGE_PROFILE
# One four-responder pass at the existing two-second connect bound, not 40
# independently renewed attempts. This is strictly below the former ceiling.
DECOY_TIMEOUT = 8
DECOYS = ('93.184.216.34', '169.254.169.254', '192.168.50.1', '93.184.216.35')


def install(nonce, digest):
    # Separate fixed entrypoint: the old install() still excludes every NIC.
    observed = room_profile.guest_guard(nonce, run=run)
    require(run('getenforce').strip() == 'Enforcing', 'stock SELinux enforcing required')
    boundary.PAYLOAD.mkdir()
    run('mount', '-o', 'ro,nodev,nosuid,noexec', '/dev/disk/by-label/UAS_PAYLOAD', str(boundary.PAYLOAD))
    manifest = boundary.verify_payload(nonce, digest)
    require(manifest.get('profile') == PROFILE, 'exact fixed Room payload required')
    boundary.install_packages(nonce, manifest, exact_roots=PACKAGE_PROFILE)
    # Resolve the installed cloud-image SSH family as one signed exact transaction.
    room_profile.guest_package_install(manifest, run=run)
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



def wait_decoys(children):
    """One absolute readiness phase; observing exit never reaps our children."""
    deadline = time.monotonic() + DECOY_TIMEOUT
    while True:
        for process in children:
            require(os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None,
                    'owned decoy exited before readiness')
        ready = True
        for address in DECOYS:
            require(time.monotonic() < deadline, 'live decoys readiness deadline expired')
            try: ready = boundary.connect(address, deadline=deadline) and ready
            except OSError: ready = False
        require(time.monotonic() < deadline, 'live decoys readiness deadline expired')
        if ready: return
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'live decoys readiness deadline expired')
        time.sleep(min(.05, remaining))


def prove_network(probe, python_probe, backends, states, containers, children, checks):
    """Independent observations, never an OR gate or an admission bypass."""
    checks.update(status='incomplete', observations={}, counters={}, denied=[])
    observations, first, admission_failed = checks['observations'], None, False

    def observe(name, call, *, needs_decoys=False):
        nonlocal first, admission_failed
        entry = observations[name] = {'status': 'blocked'}
        if admission_failed:
            entry['reason'] = 'fresh_room_admission_failed'
            return
        # Every further workload probe requires fresh valid containment. A
        # failure here blocks ALL later probes, even if a prior probe failed.
        try:
            for room in ('alpha', 'beta'): backends[room].admit(states[room])
        except Exception as error:
            admission_failed = True
            entry.update(reason='fresh_room_admission_failed', error_type=type(error).__name__[:64])
            if first is None: first = error
            return
        if needs_decoys and observations['decoys']['status'] != 'passed':
            entry['reason'] = 'live_decoy_positive_control_failed'
            return
        try:
            call(entry)
            entry['status'] = 'passed'
        except Exception as error:
            entry.update(status='failed', error_type=type(error).__name__[:64])
            if first is None: first = error

    observe('decoys', lambda entry: wait_decoys(children))
    def public(entry):
        value = entry['result'] = python_probe('alpha', 'public-head')
        require(value['certificate_hostname_verified'] is True, 'real verified public HTTPS unavailable')
        checks.update(real_public_https=True, public=value)
    observe('public_https', public)
    for address, chain, name in (('10.89.1.1', 'input', 'host-private'),
            ('93.184.216.35', 'input', 'host-public'), ('169.254.169.254', 'forward', 'metadata'),
            ('192.168.50.1', 'forward', 'LAN')):
        def denial(entry, address=address, chain=chain, name=name):
            def dropped(): return boundary.denial_counter(backends['alpha']._firewall(states['alpha']), chain)
            entry['before'] = dropped()
            entry['result'] = probe('alpha', 'connect', address + ':5000')
            entry['after'] = dropped()
            require(entry['result']['error'] == 'TIMEOUT', 'forbidden destination reachable')
            require(entry['after'] > entry['before'], 'missing exact firewall deny')
            checks['counters'][address] = {'before': entry['before'], 'after': entry['after'], 'chain': chain}
            checks['denied'].append(name)
        observe(name, denial, needs_decoys=True)
    def sibling(entry):
        entry['result'] = boundary.require_sibling_denial(probe, backends['beta'], states['beta'], containers['beta'])
        checks['sibling'] = entry['result']; checks['denied'].append('sibling')
    observe('sibling', sibling)
    def ipv6(entry):
        entry['result'] = probe('alpha', 'connect', '[2606:4700:4700::1111]:5000')
        require(entry['result']['error'] == 'ENETUNREACH', 'IPv6 must remain unavailable')
        checks['ipv6'] = 'disabled-and-filtered'
    observe('ipv6', ipv6)
    checks['status'] = 'failed' if first is not None else 'passed'
    if first is not None: raise first



def prove_foreign_pathname(endpoint_, probe, pathname_checks):
    """Actual stock-policy path denial; restoration uncertainty is terminal."""
    from uas.guest_fixture import ROOMS
    directory, leaf = endpoint_.parent, endpoint_.leases[0].path
    try:
        run('chcon', '-l', ROOMS['beta'][3], str(directory), str(leaf))
        pathname_checks['directory_label'] = os.getxattr(directory, 'security.selinux', follow_symlinks=False).decode()
        pathname_checks['pathname_label'] = os.getxattr(leaf, 'security.selinux', follow_symlinks=False).decode()
        pathname_checks['socket_object_label'] = os.getxattr(endpoint_.listeners[0].fileno(), 'security.selinux').decode()
        raw = probe('alpha', 'endpoint')
        pathname_checks['raw_probe'] = raw
        denied = raw.get('decoded')
        require(raw.get('returncode') == 0 and raw.get('timeout') is False
                and raw.get('status') != 'unavailable' and raw.get('cleanup_errors') == []
                and raw.get('stdout', {}).get('truncated') is False
                and raw.get('stderr', {}).get('truncated') is False
                and denied == {'connected': False, 'error': 'EACCES'}, 'foreign Room MCS endpoint not denied')
    finally:
        primary = sys.exc_info()[1]
        try:
            run('chcon', '-l', ROOMS['alpha'][3], str(directory), str(leaf))
            pathname_checks['label_restore'] = {'status': 'passed'}
        except BaseException as error:
            pathname_checks['label_restore'] = {'status': 'failed', 'error_type': type(error).__name__[:64]}
            if primary is None: raise
    require(pathname_checks['label_restore']['status'] == 'passed', 'original endpoint label not restored')
    endpoint_.require()
    return denied


def prove_recovery(supervisor, spec, state, container, nonce, checks):
    from uas.guest_fixture import command, network_names, firewall_document
    checks.update(status='incomplete', observations={})
    observed = checks['observations']
    def capture(name, value):
        # Lifecycle results include entire container/config documents. Keep
        # only this proof's fixed outcomes, never duplicate the full state.
        task = value.get('observed', {}).get('container') or {}
        observed[name] = {'phase': str(value.get('phase', 'unknown'))[:64],
            'container': {}}
        if 'id' in task: observed[name]['container']['id'] = str(task['id'])[:128]
        if 'running' in task: observed[name]['container']['running'] = task['running'] is True
        observed[name]['error'] = str(value['error'])[:64] if value.get('error') is not None else None
        observed[name]['cleanup_uncertain'] = bool(value.get('leftovers'))
        if value.get('leftovers'):
            observed[name]['leftover_reasons'] = [str(item.get('reason', 'unknown'))[:128]
                                                 for item in value['leftovers'][:8]]
        return value
    original = container
    stopped = capture('stop', supervisor.stop())
    require(stopped['phase'] == 'stopped', 'Room stop failed')
    resumed = capture('resume', supervisor.start(spec))
    require(resumed['phase'] == 'running' and resumed['observed']['container']['id'] == original, 'resume replaced owned image')
    stopped = capture('stop_for_drift', supervisor.stop())
    require(stopped['phase'] == 'stopped', 'stop for drift failed')
    table = network_names(state)[2]
    command('nft', 'flush', 'chain', 'inet', table, 'forward')
    rejected = capture('drift_refusal', supervisor.start(spec))
    require(rejected['phase'] == 'start_failed' and rejected['observed']['container']['running'] is False,
            'drift restarted stopped workload')
    command('nft', 'delete', 'table', 'inet', table)
    command('nft', '-j', '-f', '-', input=json.dumps(firewall_document(state, nonce)))
    reconciled = capture('reconcile', supervisor.reconcile())
    require(reconciled['phase'] == 'running', 'owned explicit recovery failed')
    checks.update(status='passed', same_container_resume=True, drift_failed_closed=True,
        scope='container-network-storage-after-service-teardown', persistent_participant_service_restart=False)

def cleanup_owned(supervisors, endpoints, children, created, image, storage, checks):
    errors = []
    for room, supervisor in supervisors.items():
        try: require(supervisor.destroy()['phase'] == 'destroyed', 'owned Room cleanup failed')
        except BaseException as error: errors.append(type(error).__name__ + ':' + room)
    for room, item in endpoints.items():
        for index, listener in enumerate(item.listeners):
            try: listener.close()
            except BaseException as error: errors.append(type(error).__name__ + ':listener:' + room + ':' + str(index))
    for process in children:
        try: stop_child(process)
        except BaseException as error: errors.append(type(error).__name__ + ':responder')
    commands = []
    if 'veth' in created: commands.append(('ip', 'link', 'del', 'uas-public'))
    if 'netns' in created: commands.append(('ip', 'netns', 'del', 'uas-public'))
    if 'public-host' in created: commands.append(('ip', 'addr', 'del', '93.184.216.35/32', 'dev', 'lo'))
    if image is not None: commands.append(('docker', 'image', 'rm', image))
    if 'storage' in created: commands.append(('umount', str(storage)))
    for arguments in commands:
        try: run(*arguments)
        except BaseException as error: errors.append(type(error).__name__ + ':' + arguments[0])
    checks['guest_cleanup'] = {'status': 'failed' if errors else 'passed', 'errors': errors,
        'outer_disposable_vm_removal_remains_mandatory': True}
    return errors


CHECKPOINT_STAGES = frozenset(('rootfs', 'engine', 'archive', 'image-import', 'storage',
    'launch-alpha', 'launch-beta', 'observe-alpha', 'observe-beta',
    'mounts-alpha', 'mounts-beta', 'endpoint-service', 'endpoint-negatives',
    'quota-block', 'quota-inode', 'network', 'recovery', 'cleanup', 'scenario'))


def checkpoint_writer(nonce, checks):
    """Finite diagnostic checkpoints, never qualification or a liveness lease."""
    started = time.monotonic()
    sequence = 0
    def emit(stage, event):
        nonlocal sequence
        require(stage in CHECKPOINT_STAGES and event in ('begin', 'end'), 'fixed checkpoint required')
        sequence += 1
        require(sequence <= 40, 'checkpoint budget exceeded')
        value = {'version': 1, 'sequence': sequence, 'stage': stage, 'event': event,
                 'elapsed_seconds': round(max(0, time.monotonic() - started), 3),
                 'completed_checks': sorted(key for key in REQUIRED
                     if checks.get(key, {}).get('status') == 'passed'),
                 'terminal': False}
        try:
            print('UAS_ROOM_CHECKPOINT:' + nonce + ':' + json.dumps(value, sort_keys=True), flush=True)
        except OSError:
            # Diagnostics must not mask the primary failure or stop owned cleanup.
            pass
    return emit


def scenario(nonce, manifest, boot_network, checks):
    sys.path.insert(0, str(boundary.ROOT)); sys.path.insert(0, str(boundary.ROOT / 'tests/vm'))
    from native_rootfs import build_room_rootfs
    from room_service import endpoint, prove_service, prove_foreign_listener_admission
    from room_policy_diagnostics import capture_endpoint_probe, capture_policy_diagnostic
    from uas.guest_fixture import CONTROL, ROOMS, STORAGE, prepare_storage, network_names, firewall_document, command
    from uas.lifecycle import Supervisor
    from uas.room_fixture import RoomFixtureLimits, RoomLaunchFixtureBackend
    supervisors, backends, endpoints, specs, containers, states = {}, {}, {}, {}, {}, {}
    children, created = [], set()
    image = None
    cleanup_errors = []
    active_stage = 'payload'
    checkpoint = checkpoint_writer(nonce, checks)
    limits = RoomFixtureLimits(memory_bytes=96 * 1024**2, nano_cpus=750_000_000,
                               pids=24, disk_bytes=8 * 1024**2, inodes=128, log_bytes=524288)
    try:
        root = Path('/var/lib/uas-native-rootfs'); archive = root.with_suffix('.tar')
        checkpoint('rootfs', 'begin')
        image_facts = build_room_rootfs(nonce, manifest, root, run=run)
        checkpoint('rootfs', 'end')
        checkpoint('engine', 'begin')
        boundary.start_engine()
        require(run('docker', 'version', '--format', '{{.Server.Version}}').strip() == '29.8.2', 'exact selected Engine required')
        checkpoint('engine', 'end')
        checkpoint('archive', 'begin')
        with tarfile.open(archive, 'x', format=tarfile.PAX_FORMAT) as target:
            for path in sorted(root.iterdir()): target.add(path, arcname=path.name, recursive=True)
        checkpoint('archive', 'end')
        checkpoint('image-import', 'begin')
        image = import_image(archive)
        checkpoint('image-import', 'end')
        checks['payload'] = {'status': 'passed', 'image': image, 'rootfs': image_facts,
                             'boot_network': boot_network, 'native_pi_enabled': False}
        checkpoint('storage', 'begin')
        device = Path('/dev/disk/by-id/virtio-uas-quota')
        require(device.exists() and run('blockdev', '--getsize64', str(device)).strip() == str(2 * 1024**3),
                'exact owned quota disk required')
        run('mkfs.xfs', '-f', str(device)); STORAGE.mkdir()
        run('mount', '-o', 'prjquota,nodev,nosuid', str(device), str(STORAGE)); created.add('storage')
        prepare_storage(nonce, limits={room: (limits.disk_bytes // 1024, limits.inodes) for room in ROOMS})
        attribute_control = boundary.attribute_positive_control(STORAGE)
        checkpoint('storage', 'end')
        active_stage = 'confinement'
        for room in ROOMS:
            checkpoint('launch-' + room, 'begin')
            endpoints[room] = endpoint(room, run)
            backend = backends[room] = RoomLaunchFixtureBackend(nonce, room, limits=limits, endpoints=(endpoints[room],))
            supervisor = supervisors[room] = Supervisor(CONTROL / 'lifecycle', room, backend,
                authorize=lambda *_: True, revoke=lambda *_: True)
            specs[room] = backend.fixture_spec(image)
            status = supervisor.start(specs[room])
            require(status['phase'] == 'running', 'actual Room launch failed: ' + json.dumps(status))
            containers[room] = status['observed']['container']['id']
            states[room] = supervisor._read()
            checkpoint('launch-' + room, 'end')
        def probe(room, *args):
            return json.loads(run('docker', 'exec', containers[room], '/fixture', *args, timeout=8))
        def python_probe(room, mode):
            return json.loads(run('docker', 'exec', containers[room], '/usr/bin/python3', '-I',
                                  '/opt/uas/uas/room_probe.py', mode, timeout=8))
        confinement, observed_limits = {}, {}
        checks['limits'] = {'status': 'incomplete', 'observed': observed_limits}
        checks['confinement'] = {'status': 'incomplete', 'workstations': confinement}
        for room in ROOMS:
            active_stage = 'confinement'
            checkpoint('observe-' + room, 'begin')
            actual = probe(room, 'observe'); files = actual['files']
            require(actual['uid'] == actual['gid'] == 65532, 'nonroot Workstation required')
            status = dict(line.split(':', 1) for line in files['/proc/self/status'].splitlines() if ':' in line)
            process = {key: status[key].strip() for key in ('CapEff', 'CapBnd', 'NoNewPrivs', 'Seccomp')}
            require(process == {'CapEff': '0000000000000000', 'CapBnd': '0000000000000000',
                                'NoNewPrivs': '1', 'Seccomp': '2'}, 'actual Workstation confinement differs')
            boundary.require_process_label(files['/proc/self/attr/current'], ROOMS[room][3])
            require(files['/proc/self/uid_map'].split() == files['/proc/self/gid_map'].split() == ['0', '100000', '65536'],
                    'actual userns remapping differs')
            active_stage = 'limits'
            observed_limits[room] = {'memory': files['/sys/fs/cgroup/memory.max'],
                'pids': files['/sys/fs/cgroup/pids.max'], 'cpu': files['/sys/fs/cgroup/cpu.max']}
            require(files['/sys/fs/cgroup/memory.max'] == str(limits.memory_bytes)
                    and files['/sys/fs/cgroup/pids.max'] == str(limits.pids), 'actual cgroup limits differ')
            quota, period = map(int, files['/sys/fs/cgroup/cpu.max'].split())
            require(quota * 4 == period * 3, 'actual CPU bound differs')
            info = backends[room].admit(states[room]); backends[room]._quota()
            confinement[room] = {'kernel_status': process, 'uid_map': files['/proc/self/uid_map'],
                                  'gid_map': files['/proc/self/gid_map'], 'label': files['/proc/self/attr/current']}
            observed_limits[room].update(log=info['HostConfig']['LogConfig'],
                xfs_block_hard_kib=limits.disk_bytes // 1024, xfs_inode_hard=limits.inodes)
            for flag in ('b','i'):
                report = command('xfs_quota','-x','-c',f'report -p -{flag} -n -N',str(STORAGE))
                require(len(report) <= 16384, 'bounded quota observation required')
                rows = [line.split() for line in report.splitlines() if line.split() and line.split()[0] == '#'+str(ROOMS[room][0])]
                require(len(rows) == 1, 'exact observed quota project required')
                observed_limits[room]['actual_xfs_'+flag] = rows[0]
            attrs = observed_limits[room]['attributes'] = probe(room, 'attributes', str(STORAGE / room / 'workspace'))
            require(attrs['clear_inherit'] in ('EPERM', 'EACCES', 'EINVAL')
                    and attrs['change_project'] in ('EPERM', 'EACCES', 'EINVAL')
                    and attrs['initial_project'] == attrs['after_change_project'] == ROOMS[room][0]
                    and attrs['after_clear_inherit'] is True, 'quota escape permitted')
            checkpoint('observe-' + room, 'end')
        checks['confinement'] = {'status': 'passed', 'workstations': confinement,
            'fssetxattr_initial_userns_positive_control':attribute_control}
        active_stage = 'mounts'
        private = {}
        for room in ROOMS:
            checkpoint('mounts-' + room, 'begin')
            for name in ('repository', 'workspace', 'checkouts'):
                require(probe(room, 'write', str(STORAGE / room / name))['error'] == 'OK', 'admitted writable mount denied')
            require(probe(room, 'write', str(STORAGE / room / 'references'))['error'] == 'EROFS', 'readonly reference writable')
            require(probe(room, 'write', '/state')['error'] == 'OK', 'admitted Runtime state not writable')
            private[room] = python_probe(room, 'private')
            require(private[room]['endpoint_unlink'] == 'EROFS'
                    and all(value in ('ENOENT','EACCES') for key,value in private[room].items() if key != 'endpoint_unlink'),
                    'private stores/Engine exposed or endpoint writable')
            checkpoint('mounts-' + room, 'end')
        checks['mounts'] = {'status': 'passed', 'private':private,
            'actual_mounts': {room: backends[room].admit(states[room])['Mounts'] for room in ROOMS}}
        # The bootstrap receives no workload release until the actual mounted
        # service and same live Broker have both passed their checks.
        active_stage = 'endpoint_service'
        checks['endpoint_service'] = {}
        checkpoint('endpoint-service', 'begin')
        prove_service(supervisors['alpha'], backends['alpha'], endpoints['alpha'], containers['alpha'],
                      run=run, checks=checks['endpoint_service'])
        checkpoint('endpoint-service', 'end')
        checkpoint('endpoint-negatives', 'begin')
        checks['endpoint_service']['status'] = 'incomplete'
        require(checks['endpoint_service']['held_bootstrap_exit_observed'] is True,
                'held workload must exit before destructive endpoint negatives')
        checks['endpoint_service']['foreign_listener_admission'] = {}
        def raw_endpoint_probe(room, mode):
            require(room == 'alpha' and mode == 'endpoint', 'fixed Alpha endpoint probe required')
            return capture_endpoint_probe(containers[room])
        prove_foreign_listener_admission(supervisors['alpha'], endpoints['alpha'], raw_endpoint_probe,
            run=run, checks=checks['endpoint_service']['foreign_listener_admission'],
            diagnostic=capture_policy_diagnostic)
        # Actual stock SELinux denial, not an invented receipt or off-host policy.
        checks['endpoint_service']['foreign_room_mcs'] = {}
        checks['endpoint_service']['foreign_room_mcs_denied'] = prove_foreign_pathname(
            endpoints['alpha'], raw_endpoint_probe, checks['endpoint_service']['foreign_room_mcs'])
        checks['endpoint_service']['status'] = 'passed'
        checkpoint('endpoint-negatives', 'end')
        active_stage = 'limits'
        for kind in ('block', 'inode'):
            checkpoint('quota-' + kind, 'begin')
            result = observed_limits['exhaustion_' + kind] = probe('alpha', 'quota-' + kind, str(STORAGE / 'alpha/workspace'))
            require(result['error'] == 'ENOSPC', 'configured XFS bound not enforced')
            space = os.statvfs(STORAGE)
            require(space.f_bavail * space.f_frsize > 64 * 1024 * 1024 and space.f_favail > 1000,
                    'underlying filesystem exhausted instead of selected project')
            path = Path(result['probe_path'])
            require(path.parent == STORAGE / 'alpha/workspace' and path.name.startswith('quota-probe-')
                    and path.resolve() == path, 'unsafe owned quota probe cleanup')
            require(probe('beta', 'write-new', str(STORAGE / 'beta/workspace'))['error'] == 'OK', 'sibling quota isolation failed')
            shutil.rmtree(path)
            checkpoint('quota-' + kind, 'end')
        checks['limits'] = {'status': 'passed', 'observed': observed_limits}
        active_stage = 'network'
        checkpoint('network', 'begin')
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
        checks['network'] = {}
        prove_network(probe, python_probe, backends, states, containers, children, checks['network'])
        checkpoint('network', 'end')
        active_stage = 'recovery'
        checkpoint('recovery', 'begin')
        checks['recovery'] = {}
        prove_recovery(supervisors['alpha'], specs['alpha'], states['alpha'], containers['alpha'], nonce, checks['recovery'])
        checkpoint('recovery', 'end')
    except BaseException as error:
        checks.setdefault(active_stage, {}).update(status='failed', error_type=type(error).__name__[:64])
        for entry in checks.values():
            if entry.get('status') == 'incomplete':
                entry.update(status='blocked', reason='earlier_required_gate_failed', blocked_by=active_stage)
        raise
    finally:
        checkpoint('cleanup', 'begin')
        cleanup_errors = cleanup_owned(supervisors, endpoints, children, created, image, STORAGE, checks)
        checkpoint('cleanup', 'end')
    require(not cleanup_errors, 'owned guest cleanup incomplete')
    checkpoint('scenario', 'end')
    return checks



def encode_report(report):
    """Keep the existing wire cap; overflow is a failed compact diagnostic."""
    encoded = json.dumps(report, sort_keys=True)
    if len(encoded) <= 65536: return encoded
    compact = {key: report[key] for key in ('version','nonce','profile','production_enabled')}
    compact.update(failure={'error_type':'ReportBudgetExceeded'}, report_overflow=True,
        evidence_omitted=True, original_report_bytes=len(encoded), checks={})
    if 'failure' in report:
        compact['primary_failure'] = {'error_type':str(report['failure'].get('error_type','unknown'))[:64]}
    for name in sorted(REQUIRED):
        original = report['checks'].get(name, {})
        entry = compact['checks'][name] = {'status':str(original.get('status','blocked'))[:32]}
        if 'error_type' in original: entry['error_type'] = str(original['error_type'])[:64]
        if name == 'guest_cleanup':
            entry.update(errors=[str(error)[:128] for error in original.get('errors',[])[:16]],
                outer_disposable_vm_removal_remains_mandatory=True)
        if name == 'endpoint_service':
            for key in ('cleanup', 'broker'):
                cleanup = original.get(key, {})
                if key == 'broker': cleanup = cleanup.get('cleanup', {})
                if cleanup:
                    entry[key + '_cleanup' if key == 'broker' else key] = {
                        'status':str(cleanup.get('status','unknown'))[:32],
                        'errors':[{field:str(error.get(field,''))[:64] for field in ('owner','error_type')}
                                  for error in cleanup.get('errors',[])[:8]]}
            # Fixed prelaunch/release/final gates only; no arbitrary phase names or payloads
            # survive overflow. Invalid/non-finite diagnostics are omitted, not
            # converted into authority or a successful compact report.
            phases = original.get('authority_phases', {})
            if isinstance(phases, dict):
                projected = {}
                for key in ('prelaunch.lock', 'prelaunch.current', 'prelaunch.resources',
                            'prelaunch.admission', 'release.current', 'release.resources',
                            'release.broker', 'release.write', 'final.lock', 'final.current',
                            'final.resources', 'final.admission', 'final.post_current',
                            'final.post_resources', 'final.broker', 'final.write'):
                    timing = phases.get(key)
                    if not isinstance(timing, dict): continue
                    fields = {}
                    for field in ('calls', 'failures', 'last_seconds', 'max_seconds', 'total_seconds'):
                        value = timing.get(field)
                        if field in ('calls', 'failures'):
                            valid = type(value) is int and 0 <= value <= 2**63 - 1
                        else:
                            valid = type(value) in (int, float) and 0 <= value <= sys.float_info.max
                        if valid: fields[field] = value
                    if fields: projected[key] = fields
                if projected: entry['authority_phases'] = projected
            held = original.get('held_pre_cleanup')
            if isinstance(held, dict):
                diagnostic = {}
                if type(held.get('alive')) is bool: diagnostic['alive'] = held['alive']
                if held.get('stderr') == 'NOT_CAPTURED_NO_OWNED_BOUNDED_FACILITY':
                    diagnostic['stderr'] = held['stderr']
                if type(held.get('error_type')) is str:
                    diagnostic['error_type'] = held['error_type'][:64]
                if diagnostic: entry['held_pre_cleanup'] = diagnostic
            if 'authority_failure' in original:
                entry['authority_failure'] = {key:str(original['authority_failure'].get(key,''))[:256]
                    for key in ('operation','phase','error_type','message')}
            if 'bind_cleanup' in original:
                cleanup = original['bind_cleanup']
                entry['bind_cleanup'] = {'attempted':cleanup.get('attempted') is True,
                    'closed':cleanup.get('closed') is True, 'error_type':str(cleanup.get('error_type',''))[:64]}
            restore = original.get('foreign_room_mcs', {}).get('label_restore')
            if restore:
                entry['label_restore'] = {key:str(restore.get(key,''))[:64] for key in ('status','error_type')}
            unrelated = original.get('unrelated_task', {})
            if unrelated:
                cleanup = unrelated.get('cleanup', {})
                entry['unrelated_task'] = {key:str(unrelated.get(key,''))[:64]
                                           for key in ('status','stage','error_type')}
                entry['unrelated_task']['cleanup'] = {
                    'kill_attempted': cleanup.get('kill_attempted') is True,
                    'reaped': cleanup.get('reaped') is True,
                    'errors':[{field:str(error.get(field,''))[:64] for field in ('operation','error_type')}
                              for error in cleanup.get('errors',[])[:16]]}
            foreign = original.get('foreign_listener_admission', {})
            if foreign:
                entry['foreign_listener_admission'] = {
                    'status':str(foreign.get('status','unknown'))[:32],
                    'original_lease_restored':foreign.get('original_lease_restored') is True,
                    'cleanup_errors':[str(error)[:64] for error in foreign.get('cleanup_errors',[])[:8]]}
    return json.dumps(compact, sort_keys=True)

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
    for name in REQUIRED:
        checks.setdefault(name, {'status': 'blocked', 'reason': 'earlier_required_gate_failed'})
    report = {'version': 1, 'nonce': nonce, 'profile': PROFILE, 'production_enabled': False, 'checks': checks}
    if failure is not None: report['failure'] = failure
    with open('/dev/ttyS0', 'w') as serial:
        serial.write('\nUAS_ROOM_REPORT:' + nonce + ':' + encode_report(report) + '\n'); serial.flush()


if __name__ == '__main__': main()
