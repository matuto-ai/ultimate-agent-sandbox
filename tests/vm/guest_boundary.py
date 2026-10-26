#!/usr/bin/env python3
"""End-to-end synthetic two-Room enforcement in the disposable no-NIC VM."""
import hashlib
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import threading
import time
import traceback

PAYLOAD = Path('/mnt/uas-payload')
ROOT = Path('/opt/uas-fixture')
REQUIRED_PACKAGES = ('moby-engine', 'docker-cli', 'container-selinux', 'nftables',
                     'iproute', 'xfsprogs', 'policycoreutils', 'shadow-utils')
# Fedora's signed service already passes --selinux-enabled. Repeating that
# directive in daemon.json is an error, not stronger enforcement. Actual engine
# security options are mandatory below and again on every backend admission.
DOCKER_CONFIGURATION = {'storage-driver': 'overlay2', 'userns-remap': 'uas-remap',
                        'exec-opts': ['native.cgroupdriver=systemd']}
REQUIRED = {'runtime', 'network', 'writable_mounts', 'block_quota', 'inode_quota',
            'recovery', 'drift', 'destroy', 'sibling_health', 'guest_cleanup'}


def run(*arguments, timeout=90, pass_fds=()):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=timeout, check=False, pass_fds=pass_fds)
    if result.returncode:
        raise RuntimeError(f'{arguments[0]} failed: {result.stderr[-2048:]} {result.stdout[-2048:]}')
    return result.stdout


def expect(value, message):
    if not value:
        raise AssertionError(message)


def require_process_label(observed, level):
    # procfs may include the kernel context's single terminal NUL. Accept no
    # other suffix/prefix, type, or MCS difference; do not use suffix matching.
    expected = 'system_u:system_r:container_t:' + level
    expect(observed in (expected, expected + '\0'), 'actual SELinux label')


def require_sibling_listener(probe, address):
    # All bridge-to-host traffic is forbidden, including replies to host probes.
    # Exercise the actual assigned bridge address from Beta's own namespace.
    expect(probe('beta', 'connect', address + ':5000') ==
           {'error': 'OK', 'reply': 'uas-boundary-ok\n'}, 'sibling bridge-address responder unhealthy')


def denial_counter(document, chain):
    """Read the exact input or IPv4-forward drop rule, not unrelated counters."""
    expect(chain in ('input', 'forward'), 'unknown denial chain')
    destination = {'payload': {'protocol': 'ip', 'field': 'daddr'}}
    rules = [item['rule'] for item in document['nftables'] if 'rule' in item
             and item['rule']['chain'] == chain
             and (chain == 'input' or any(expr.get('match', {}).get('left') == destination
                                         for expr in item['rule']['expr']))]
    expect(len(rules) == 1 and {'drop': None} in rules[0]['expr'], 'ambiguous denial rule')
    counters = [expr['counter'] for expr in rules[0]['expr'] if 'counter' in expr]
    expect(len(counters) == 1 and type(counters[0].get('packets')) is int
           and counters[0]['packets'] >= 0, 'invalid denial counter')
    return counters[0]['packets']


def require_engine_security():
    expect(run('getenforce').strip() == 'Enforcing', 'SELinux changed during installation')
    options = json.loads(run('docker', 'info', '--format', '{{json .SecurityOptions}}'))
    expect(isinstance(options, list) and {'name=selinux', 'name=userns'} <= set(options),
           'Docker SELinux and user namespace enforcement required before scenario')


def verify_payload(nonce, manifest_hash):
    raw = (PAYLOAD / 'manifest.json').read_bytes()
    expect(len(raw) <= 1024 * 1024 and hashlib.sha256(raw).hexdigest() == manifest_hash, 'payload manifest mismatch')
    data = json.loads(raw)
    expect(data['version'] == 1 and data['nonce'] == nonce, 'payload nonce mismatch')
    for prefix, entries in (('repo', data['source']), ('rpms', data['packages']),
                            ('rpms', data['repository_metadata'])):
        for entry in entries:
            name = entry['file']
            expect(not name.startswith('/') and '..' not in Path(name).parts, 'unsafe payload path')
            path = PAYLOAD / prefix / name
            expect(path.is_file() and path.resolve() == path and path.stat().st_size == entry['bytes'], 'payload file mismatch')
            with path.open('rb') as source:
                expect(hashlib.file_digest(source, 'sha256').hexdigest() == entry['sha256'], 'payload digest mismatch')
    for name, entry in (('fixture', data['fixture']), ('fedora-44.asc', data['key'])):
        path = PAYLOAD / name
        expect(path.stat().st_size == entry['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'], 'payload asset mismatch')
    return data


def install_packages(nonce, manifest):
    expect(os.geteuid() == 0 and Path('/run/uas-vm-fixture').read_text().strip() == nonce, 'not this disposable boot')
    expect(run('getenforce').strip() == 'Enforcing', 'SELinux not enforcing before packages')
    packages = [str(PAYLOAD / 'rpms' / item['file']) for item in manifest['packages']]
    run('rpmkeys', '--import', str(PAYLOAD / 'fedora-44.asc'))
    run('rpmkeys', '--checksig', *packages, timeout=180)
    # DNF4's download closure may union conflicting alternative providers. Do
    # not request every RPM as an installation root. The native guest solver
    # selects only required roots/dependencies against its actual installed OS.
    # Repodata bytes were hash-verified above and are on a read-only payload;
    # every package is release-signature verified both before and during install.
    repositories = Path('/run/uas-repositories')
    repositories.mkdir(mode=0o700)
    (repositories / 'uas.repo').write_text('[uas-offline]\nname=Verified disposable payload\n'
        f'baseurl=file://{PAYLOAD}/rpms\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=0\n'
        f'gpgkey=file://{PAYLOAD}/fedora-44.asc\nskip_if_unavailable=0\n')
    run('dnf', '-y', '--setopt=reposdir=' + str(repositories), '--disable-repo=*',
        '--enable-repo=uas-offline', '--setopt=localpkg_gpgcheck=True',
        '--setopt=install_weak_deps=False', 'install', *REQUIRED_PACKAGES, timeout=900)


def install(nonce, manifest_hash):
    expect(os.geteuid() == 0 and Path('/run/uas-vm-fixture').read_text().strip() == nonce, 'not this disposable boot')
    expect(sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'], 'external guest NIC present')
    expect(run('getenforce').strip() == 'Enforcing', 'SELinux not enforcing before installation')
    PAYLOAD.mkdir()
    run('mount', '-o', 'ro,nodev,nosuid,noexec', '/dev/disk/by-label/UAS_PAYLOAD', str(PAYLOAD))
    manifest = verify_payload(nonce, manifest_hash)
    install_packages(nonce, manifest)
    shutil.copytree(PAYLOAD / 'repo', ROOT)
    shutil.copyfile(PAYLOAD / 'fixture', ROOT / 'fixture')
    (ROOT / 'fixture').chmod(0o555)
    run('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'uas-remap')
    Path('/etc/subuid').write_text('uas-remap:100000:65536\n')
    Path('/etc/subgid').write_text('uas-remap:100000:65536\n')
    Path('/etc/docker').mkdir(exist_ok=True)
    Path('/etc/docker/daemon.json').write_text(json.dumps(DOCKER_CONFIGURATION))
    run('systemctl', 'start', 'docker', timeout=120)
    require_engine_security()
    print('Guest installed roots:', run('rpm', '-q', '--queryformat',
          '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n', *REQUIRED_PACKAGES), flush=True)


def responder():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', 5000)); listener.listen()
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.sendall(b'uas-boundary-ok\n')


def enter_public_namespace(nonce, descriptor):
    """Enter only the parent's held owned network namespace, without mounts.

    ip -n/netns exec also attempts a new mount namespace and sysfs remount. The
    fixture needs neither; leave SELinux's denial of those mounts unchanged.
    """
    expect(os.geteuid() == 0 and Path('/run/uas-vm-fixture').read_text().strip() == nonce,
           'not this disposable boot')
    descriptor = int(descriptor)
    try:
        held = os.fstat(descriptor)
        initial = Path('/proc/self/ns/net').stat()
        expect((initial.st_dev, initial.st_ino) != (held.st_dev, held.st_ino), 'router namespace must differ from parent')
        os.setns(descriptor, 0x40000000)  # Linux CLONE_NEWNET, no CLONE_NEWNS.
        actual = Path('/proc/self/ns/net').stat()
        expect((actual.st_dev, actual.st_ino) == (held.st_dev, held.st_ino), 'wrong held network namespace')
    finally:
        os.close(descriptor)


def configure_public_namespace(nonce, descriptor):
    enter_public_namespace(nonce, descriptor)
    run('ip', 'addr', 'add', '10.254.0.2/30', 'dev', 'uas-peer')
    run('ip', 'link', 'set', 'uas-peer', 'up')
    run('ip', 'link', 'set', 'lo', 'up')
    for address in ('93.184.216.34', '169.254.169.254', '192.168.50.1'):
        run('ip', 'addr', 'add', address + '/32', 'dev', 'lo')
    run('ip', 'route', 'add', 'default', 'via', '10.254.0.1')


def connect(address):
    with socket.create_connection((address, 5000), timeout=2) as connection:
        return connection.recv(64) == b'uas-boundary-ok\n'


def attribute_positive_control(storage):
    """The exact ioctl probe must succeed for an owner in the initial userns.

    This fresh empty sibling is not either Room's Project or Runtime data. Run
    the same binary as non-root, restore the probe attributes, then remove it
    before creating any workload. EINVAL alone is not enforcement evidence.
    """
    from uas.guest_fixture import project_attributes
    path = storage / 'attribute-control'
    path.mkdir(mode=0o700)  # Never adopt an existing path.
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    original = bytearray(28)
    try:
        fcntl.ioctl(descriptor, 0x801C581F, original, True)
        seeded = bytearray(original)
        struct.pack_into('=I', seeded, 0, struct.unpack_from('=I', seeded, 0)[0] | 0x200)
        struct.pack_into('=I', seeded, 12, 103)
        fcntl.ioctl(descriptor, 0x401C5820, seeded)
        os.chown(path, 65532, 65532)
        result = subprocess.run([str(ROOT / 'fixture'), 'attributes', str(path)],
                                user=65532, group=65532, extra_groups=[],
                                capture_output=True, text=True, timeout=30, check=True)
        value = json.loads(result.stdout)
        expect(value['uid'] == 65532 and value['uid_map'].split() == ['0', '0', '4294967295'], 'positive control not initial userns owner')
        expect(value['initial_project'] == 103 and value['clear_inherit'] == 'OK'
               and value['change_project'] == 'OK' and value['after_clear_inherit'] is False
               and value['after_change_project'] == 0 and project_attributes(path) == (0, True), 'FSSETXATTR positive control failed')
        print('FSSETXATTR initial-userns positive control:', json.dumps(value), flush=True)
    finally:
        fcntl.ioctl(descriptor, 0x401C5820, original)
        os.close(descriptor)
        path.rmdir()  # Empty, exact test-created probe only; no recursive delete.
    expect(not path.exists(), 'attribute control cleanup failed')
    return value


def crash_start(nonce, image, point):
    """SIGKILL a real disposable controller immediately after owned effects."""
    sys.path.insert(0, str(ROOT))
    import signal
    from uas import guest_fixture as guest
    from uas.lifecycle import FixtureSpec, Supervisor
    backend = guest.GuestBoundaryBackend(nonce, 'alpha')
    supervisor = Supervisor(guest.CONTROL / 'lifecycle', 'alpha', backend, authorize=lambda *_: True, revoke=lambda *_: True)
    paths = tuple(str(guest.STORAGE / 'alpha' / name) for name in ('repository', 'workspace', 'checkouts', 'references'))
    spec = FixtureSpec('alpha', 'alpha-project', paths, image, 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
    def die():
        os.kill(os.getpid(), signal.SIGKILL)
    if point == 'volume':
        original = backend._run
        def effect(arguments, **kwargs):
            result = original(arguments, **kwargs)
            if arguments[:2] == ['volume', 'create']:
                die()
            return result
        backend._run = effect
    elif point == 'mkdir':
        original = Path.mkdir
        def effect(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path.parent == guest.STORAGE / 'alpha/runtime':
                die()
            return result
        Path.mkdir = effect
    elif point == 'marker':
        original = guest.publish
        def effect(path, value):
            result = original(path, value)
            if path.name.endswith('.runtime.json'):
                die()
            return result
        guest.publish = effect
    else:
        raise AssertionError('unknown crash boundary')
    supervisor.start(spec)
    raise AssertionError('crash effect boundary was not reached')


def scenario(nonce):
    sys.path.insert(0, str(ROOT))
    from uas.guest_fixture import (GuestBoundaryBackend, STORAGE, CONTROL, ROOMS, prepare_storage,
                                   firewall_document, network_names, command)
    from uas.lifecycle import BackendUnknown, FixtureSpec, Supervisor
    checks = {}
    device = Path('/dev/disk/by-id/virtio-uas-quota')
    expect(device.exists() and run('blockdev', '--getsize64', str(device)).strip() == str(512 * 1024 * 1024), 'wrong synthetic quota disk')
    run('mkfs.xfs', '-f', str(device))
    STORAGE.mkdir()
    run('mount', '-o', 'prjquota,nodev,nosuid', str(device), str(STORAGE))
    prepare_storage(nonce)
    attribute_control = attribute_positive_control(STORAGE)
    image_tar = Path('/run/uas-fixture.tar')
    with tarfile.open(image_tar, 'w') as archive:
        item = tarfile.TarInfo('fixture'); item.mode = 0o555
        binary = (ROOT / 'fixture').read_bytes(); item.size = len(binary)
        archive.addfile(item, io.BytesIO(binary))
    image = run('docker', 'import', '--change', 'USER 65532:65532', '--change', 'ENTRYPOINT ["/fixture"]', str(image_tar)).strip()
    expect(image.startswith('sha256:') and len(image) == 71, 'unexpected fixture image')

    # One guest-only router namespace provides reachable decoys. No NIC leaves VM.
    run('ip', 'netns', 'add', 'uas-public')
    run('ip', 'link', 'add', 'uas-public', 'type', 'veth', 'peer', 'name', 'uas-peer')
    run('ip', 'link', 'set', 'uas-peer', 'netns', 'uas-public')
    run('ip', 'addr', 'add', '10.254.0.1/30', 'dev', 'uas-public')
    run('ip', 'link', 'set', 'uas-public', 'up')
    for address in ('93.184.216.34', '169.254.169.254', '192.168.50.1'):
        run('ip', 'route', 'add', address + '/32', 'via', '10.254.0.2')
    run('ip', 'addr', 'add', '93.184.216.35/32', 'dev', 'lo')  # Public host address must also be blocked.
    run('sysctl', '-w', 'net.ipv4.ip_forward=1')
    # The namespace was freshly created above (never adopted). Hold its exact
    # kernel object across child launch rather than reopening its name there.
    namespace = os.open('/run/netns/uas-public', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        run('python3', __file__, '--configure-public', nonce, str(namespace), pass_fds=(namespace,))
        responder_process = subprocess.Popen(['python3', __file__, '--responder', nonce, str(namespace)],
                                             pass_fds=(namespace,))
    finally:
        os.close(namespace)
    threading.Thread(target=responder, daemon=True).start()
    for _ in range(100):
        try:
            if all(connect(ip) for ip in ('93.184.216.34', '169.254.169.254', '192.168.50.1', '93.184.216.35')):
                break
        except OSError:
            time.sleep(.05)
    else:
        raise AssertionError('decoy readiness failed')

    class FaultBackend(GuestBoundaryBackend):
        lose_network_response = False
        fail_network_remove = False
        def _run(self, arguments, **kwargs):
            if arguments[:2] == ['network', 'rm'] and self.fail_network_remove:
                raise BackendUnknown('injected known no-effect remove failure')
            result = super()._run(arguments, **kwargs)
            if arguments[:2] == ['network', 'create'] and self.lose_network_response:
                self.lose_network_response = False
                raise BackendUnknown('injected lost response after real network creation')
            return result

    backends, supervisors, specs, containers = {}, {}, {}, {}
    for room in ROOMS:
        backends[room] = FaultBackend(nonce, room)
        supervisors[room] = Supervisor(CONTROL / 'lifecycle', room, backends[room], authorize=lambda *_: True, revoke=lambda *_: True)
        paths = tuple(str(STORAGE / room / name) for name in ('repository', 'workspace', 'checkouts', 'references'))
        specs[room] = FixtureSpec(room, room + '-project', paths, image, 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
    for point in ('volume', 'mkdir', 'marker'):
        print('Guest boundary phase: controller crash/recovery at', point, flush=True)
        result = subprocess.run(['python3', __file__, '--crash-start', nonce, image, point], timeout=180)
        expect(result.returncode == -9, 'real controller crash boundary not reached: ' + point)
        interrupted = supervisors['alpha'].status()
        expect(interrupted['observed']['volume'] is not None and interrupted['observed']['container'] is None, 'cleanup anchor missing after ' + point)
        expect(supervisors['alpha'].reconcile()['phase'] == 'running', 'crash recovery failed after ' + point)
        expect(supervisors['alpha'].destroy()['phase'] == 'destroyed', 'crash recovered Destroy failed')
        instance = interrupted['instance_id']
        expect(not (STORAGE / 'alpha/runtime' / instance).exists(), 'runtime directory leftover after ' + point)
        expect(not list(CONTROL.glob(instance + '.*')), 'runtime marker/intent leftover after ' + point)
        print('Guest boundary phase: recovered and destroyed crash instance at', point, flush=True)
    backends['alpha'].lose_network_response = True
    first = supervisors['alpha'].start(specs['alpha'])
    expect(first['phase'] == 'start_failed' and first['observed']['container'] is None, 'uncertain partial create not retained')
    recovered = supervisors['alpha'].reconcile()
    expect(recovered['phase'] == 'running', str(recovered))
    for room in ROOMS:
        result = supervisors[room].start(specs[room])
        expect(result['phase'] == 'running', str(result))
        containers[room] = result['observed']['container']['id']
    checks['recovery'] = {'status': 'passed', 'lost_network_response_reconciled': True, 'sigkill_boundaries': ['volume', 'mkdir', 'marker']}
    print('Guest boundary phase: both Rooms running; probing actual enforcement', flush=True)

    def probe(room, *args):
        value = json.loads(run('docker', 'exec', containers[room], '/fixture', *args))
        print('Workstation probe:', room, args, json.dumps(value), flush=True)
        return value
    for room in ROOMS:
        value = probe(room, 'observe')
        expect(value['uid'] == 65532 and value['gid'] == 65532, 'root fixture')
        files = value['files']; process = files['/proc/self/status']
        for key, expected in (('CapEff', '0000000000000000'), ('CapBnd', '0000000000000000'), ('NoNewPrivs', '1'), ('Seccomp', '2')):
            expect(any(line.split(':', 1)[0] == key and line.split(':', 1)[1].strip() == expected for line in process.splitlines()), 'kernel ' + key)
        require_process_label(files['/proc/self/attr/current'], ROOMS[room][3])
        expect(files['/proc/self/uid_map'].split() == ['0', '100000', '65536']
               and files['/proc/self/gid_map'].split() == ['0', '100000', '65536'], 'actual user namespace mapping')
        attrs = probe(room, 'attributes', str(STORAGE / room / 'workspace'))
        expect(attrs['clear_inherit'] in ('EPERM', 'EACCES', 'EINVAL') and attrs['change_project'] in ('EPERM', 'EACCES', 'EINVAL'), 'project attribute quota escape allowed')
        expect(attrs['initial_project'] == ROOMS[room][0] and attrs['after_clear_inherit'] is True
               and attrs['after_change_project'] == ROOMS[room][0], 'project attributes changed during denied attempts')
        backends[room]._quota()  # Host inode project/inherit state must remain unchanged.
        expect(files['/sys/fs/cgroup/memory.max'] == '67108864' and files['/sys/fs/cgroup/pids.max'] == '32', 'actual cgroup limits')
        quota, period = map(int, files['/sys/fs/cgroup/cpu.max'].split()); expect(quota * 2 == period, 'actual CPU quota')
    checks['runtime'] = {'status': 'passed', 'selinux': 'Enforcing', 'docker': run('docker', 'version', '--format', '{{.Server.Version}}').strip(),
                         'fssetxattr_initial_userns_positive_control': attribute_control}

    for room in ROOMS:
        for name in ('repository', 'workspace', 'checkouts'):
            result = probe(room, 'write', str(STORAGE / room / name))
            expect(result['error'] == 'OK', 'writable tree denied')
            expect((STORAGE / room / name / 'fixture-data').read_text() == 'uas-boundary-data\n', 'same-path host data mismatch')
        expect(probe(room, 'write', str(STORAGE / room / 'references'))['error'] == 'EROFS', 'reference writable')
    checks['writable_mounts'] = {'status': 'passed', 'same_absolute_paths': True, 'references': 'EROFS'}
    state = json.loads((supervisors['alpha'].directory / 'lifecycle.json').read_text())
    def dropped(chain):
        return denial_counter(backends['alpha']._firewall(state), chain)
    beta_ip = json.loads(run('docker', 'inspect', containers['beta']))[0]['NetworkSettings']['Networks'][backends['beta']._network_name(json.loads((supervisors['beta'].directory / 'lifecycle.json').read_text()))]['IPAddress']
    require_sibling_listener(probe, beta_ip)
    expect(probe('alpha', 'connect', '93.184.216.34:5000') == {'error': 'OK', 'reply': 'uas-boundary-ok\n'}, 'public-address positive failed')
    for address, chain in (('10.89.1.1', 'input'), ('93.184.216.35', 'input'),
                           ('169.254.169.254', 'forward'), ('192.168.50.1', 'forward'), (beta_ip, 'forward')):
        before = dropped(chain)
        expect(probe('alpha', 'connect', address + ':5000')['error'] == 'TIMEOUT', 'blocked destination unexpectedly reachable')
        expect(dropped(chain) > before, 'no exact firewall denial observed')
    expect(probe('alpha', 'connect', '[2606:4700:4700::1111]:5000')['error'] == 'ENETUNREACH', 'IPv6 must be unavailable in this IPv4 fixture')
    checks['network'] = {'status': 'passed', 'public_address_synthetic_only': True,
                         'denied': ['host-private', 'host-public', 'LAN', 'metadata', 'sibling'], 'ipv6': 'disabled-and-filtered',
                         'sibling_positive_vantage': 'beta-own-bridge-address'}

    for kind in ('block', 'inode'):
        value = probe('alpha', 'quota-' + kind, str(STORAGE / 'alpha' / 'workspace'))
        expect(value['error'] == 'ENOSPC', kind + ' XFS project quota not enforced')
        space = os.statvfs(STORAGE)
        expect(space.f_bavail * space.f_frsize > 64 * 1024 * 1024 and space.f_favail > 1000, 'filesystem itself exhausted')
        expect(probe('beta', 'write-new', str(STORAGE / 'beta' / 'workspace')) == {'error': 'OK', 'bytes': 65536, 'uid': 65532}, 'sibling quota isolation failed during exhaustion')
        owned_probe = Path(value['probe_path'])
        expect(owned_probe.parent == STORAGE / 'alpha/workspace' and owned_probe.name.startswith('quota-probe-')
               and owned_probe.resolve() == owned_probe and owned_probe.is_dir(), 'unsafe probe cleanup')
        shutil.rmtree(owned_probe)  # Only the just-created synthetic exhaustion probe.
        checks[kind + '_quota'] = {'status': 'passed', **value}
    expect(probe('beta', 'connect', '93.184.216.34:5000')['error'] == 'OK', 'sibling public positive failed')
    checks['sibling_health'] = {'status': 'passed'}

    original = containers['alpha']
    expect(supervisors['alpha'].stop()['phase'] == 'stopped', 'stop failed')
    resumed = supervisors['alpha'].start(specs['alpha'])
    expect(resumed['phase'] == 'running' and resumed['observed']['container']['id'] == original, 'restart replaced canonical container')
    for _ in range(100):
        if (backends['alpha']._runtime(state) / 'starts').read_text() == '2':
            break
        time.sleep(.05)
    else:
        raise AssertionError('runtime state not persistent')
    expect((STORAGE / 'alpha/repository/fixture-data').exists(), 'Project data not persistent')
    expect(supervisors['alpha'].stop()['phase'] == 'stopped', 'stop before drift failed')
    table = network_names(state)[2]
    command('nft', 'flush', 'chain', 'inet', table, 'forward')
    rejected = supervisors['alpha'].start(specs['alpha'])
    expect(rejected['phase'] == 'start_failed' and rejected['observed']['container']['running'] is False, 'drift allowed resume')
    expect(any(item['reason'] == 'GUEST_FIREWALL_DRIFT' for item in rejected['leftovers']), 'drift reason missing')
    # Trusted harness repairs only its stopped synthetic policy; backend never auto-repairs drift.
    command('nft', 'delete', 'table', 'inet', table)
    command('nft', '-j', '-f', '-', input=json.dumps(firewall_document(state, nonce)))
    expect(supervisors['alpha'].reconcile()['phase'] == 'running', 'explicit fixture repair did not recover')
    checks['drift'] = {'status': 'passed', 'stopped_workload_remained_stopped': True}

    unowned = 'uas-unowned-' + nonce
    run('docker', 'volume', 'create', '--label', 'uas-unowned=' + nonce, unowned)
    backends['alpha'].fail_network_remove = True
    failed = supervisors['alpha'].destroy()
    expect(failed['phase'] == 'destroy_failed' and failed['observed']['volume'] is not None, 'partial destroy lost cleanup anchor')
    expect(supervisors['beta'].status()['phase'] == 'running', 'destroy harmed sibling')
    require_sibling_listener(probe, beta_ip)
    backends['alpha'].fail_network_remove = False
    expect(supervisors['alpha'].destroy()['phase'] == 'destroyed', 'targeted destroy retry failed')
    expect((STORAGE / 'alpha/repository/fixture-data').read_text() == 'uas-boundary-data\n', 'Destroy deleted Project data')
    unowned_info = json.loads(run('docker', 'volume', 'inspect', unowned))[0]
    expect(unowned_info['Labels']['uas-unowned'] == nonce, 'unowned resource changed')
    expect(supervisors['beta'].destroy()['phase'] == 'destroyed', 'beta destroy failed')
    checks['destroy'] = {'status': 'passed', 'project_and_unowned_preserved': True, 'targeted_retry': True}
    # Only harness-created exact resource; no engine-wide pruning.
    run('docker', 'volume', 'rm', unowned)
    for room in ROOMS:
        current = json.loads((supervisors[room].directory / 'lifecycle.json').read_text())
        expect(backends[room]._network(current) is None and backends[room]._firewall(current) is None, 'owned network/policy leftover')
    run('docker', 'image', 'rm', image)
    responder_process.terminate(); responder_process.wait(timeout=5)
    run('ip', 'link', 'del', 'uas-public')
    run('ip', 'netns', 'del', 'uas-public')
    run('ip', 'addr', 'del', '93.184.216.35/32', 'dev', 'lo')
    run('umount', str(STORAGE))
    checks['guest_cleanup'] = {'status': 'passed', 'owned_networks_removed': True, 'synthetic_disk_unmounted': True}
    return checks


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--configure-public':
        configure_public_namespace(*sys.argv[2:]); return
    if len(sys.argv) == 4 and sys.argv[1] == '--responder':
        enter_public_namespace(*sys.argv[2:])
        responder(); return
    if len(sys.argv) == 5 and sys.argv[1] == '--crash-start':
        crash_start(*sys.argv[2:]); return
    nonce, manifest_hash = sys.argv[1:]
    checks = {}
    try:
        print('Guest boundary phase: verifying offline payload and installing signed packages', flush=True)
        install(nonce, manifest_hash)
        print('Guest boundary phase: signed Docker ready; starting synthetic scenario', flush=True)
        checks = scenario(nonce)
        expect(set(checks) == REQUIRED, 'incomplete scenario')
    except Exception:
        print(traceback.format_exc()[-16384:], flush=True)
        for command in (['journalctl', '-u', 'docker', '--no-pager', '-n', '30'], ['dmesg', '--level=err,warn'],
                        ['nft', '-j', 'list', 'ruleset']):
            try:
                print('Guest diagnostic:', command, run(*command)[-8192:], flush=True)
            except Exception:
                pass
        checks = {name: {'status': 'failed', 'error': 'SCENARIO_FAILED'} for name in REQUIRED}
    report = {'version': 1, 'nonce': nonce, 'checks': checks}
    # Keep the strict record parser independent of an unterminated login prompt.
    line = '\nUAS_BOUNDARY_REPORT:' + nonce + ':' + json.dumps(report, sort_keys=True) + '\n'
    with open('/dev/ttyS0', 'w') as serial:
        serial.write(line); serial.flush()


if __name__ == '__main__':
    main()
