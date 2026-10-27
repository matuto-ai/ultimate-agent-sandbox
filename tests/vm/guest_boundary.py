#!/usr/bin/env python3
"""End-to-end synthetic two-Room enforcement in the disposable no-NIC VM."""
import hashlib
import fcntl
import io
import ipaddress
import json
import os
import re
import selectors
import signal
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


def failure_context(text):
    """Bounded fixed-tool diagnostics: retain first RPM errors, not just progress.

    The opt-in caller is the credential-free offline native-rootfs DNF command.
    No environment, credential file or arbitrary host log is collected here.
    """
    raw = text.encode('utf-8', errors='replace')
    limit = 65536
    if len(raw) <= limit:
        excerpt = raw.decode('utf-8', errors='replace')
    else:
        excerpt = (raw[:limit//2].decode('utf-8', errors='ignore')
                   + '\n[... bounded output omitted ...]\n'
                   + raw[-limit//2:].decode('utf-8', errors='ignore'))
    first_errors = []
    error_lines_truncated = False
    for line in io.StringIO(text):
        if re.search(r'\b(?:error|failed|failure|fatal)\b|cpio:', line, re.IGNORECASE):
            encoded = line.encode('utf-8', errors='replace')
            error_lines_truncated |= len(encoded) > 512
            first_errors.append(encoded[:512].decode('utf-8', errors='ignore'))
            if len(first_errors) == 8:
                break
    return {'bytes': len(raw), 'truncated': len(raw) > limit,
            'first_error_lines': first_errors, 'first_error_lines_truncated': error_lines_truncated,
            'first_error_limit_reached': len(first_errors) == 8, 'output': excerpt}


class NativeCapture:
    """Bounded head/tail plus first error lines while consuming real bytes."""
    def __init__(self):
        self.count = 0
        self.head = bytearray()
        self.tail = bytearray()
        self.line = bytearray()
        self.line_bytes = 0
        self.line_match = False
        self.scan_tail = b''
        self.errors = []
        self.errors_truncated = False

    def feed(self, data):
        self.count += len(data)
        self.head.extend(data[:max(0, 32768 - len(self.head))])
        self.tail.extend(data)
        del self.tail[:-32768]
        parts = data.split(b'\n')
        for index, part in enumerate(parts):
            self.line.extend(part[:max(0, 512 - len(self.line))])
            self.line_bytes += len(part)
            self.line_match |= bool(re.search(rb'\b(?:error|failed|failure|fatal)\b|cpio:',
                                               self.scan_tail + part, re.IGNORECASE))
            self.scan_tail = (self.scan_tail + part)[-16:]
            if index < len(parts) - 1:
                self._line_end()

    def _line_end(self):
        if self.line_match and len(self.errors) < 8:
            self.errors.append(bytes(self.line).decode('utf-8', errors='ignore'))
            self.errors_truncated |= self.line_bytes > 512
        self.line.clear(); self.line_bytes = 0; self.line_match = False; self.scan_tail = b''

    def context(self):
        if self.line_bytes:
            self._line_end()
        if self.count <= 65536:
            remaining = self.count - len(self.head)
            raw = bytes(self.head) + (bytes(self.tail[-remaining:]) if remaining else b'')
            output = raw.decode('utf-8', errors='ignore')
        else:
            output = (bytes(self.head).decode('utf-8', errors='ignore')
                      + '\n[... bounded output omitted ...]\n'
                      + bytes(self.tail).decode('utf-8', errors='ignore'))
        return {'bytes': self.count, 'truncated': self.count > 65536, 'output': output,
                'first_error_lines': list(self.errors), 'first_error_lines_truncated': self.errors_truncated,
                'first_error_limit_reached': len(self.errors) == 8}


def native_command(arguments, *, timeout, pass_fds=(), phase="DNF"):
    """Fixed native commands: real-output progress, original hard deadline."""
    if phase not in ("DNF", "trust-generation", "image-import"):
        raise ValueError("invalid native command phase")
    started = time.monotonic()
    deadline = started + timeout
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, pass_fds=pass_fds, start_new_session=True)
    selector = None
    captures = {'stdout': NativeCapture(), 'stderr': NativeCapture()}
    reported, last_report = (0, 0), started
    reaped = False
    cleanup_code = None
    group_killed = False
    try:
        selector = selectors.DefaultSelector()
        for name in captures:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(arguments, timeout)
            for key, _ in selector.select(min(1, remaining)):
                try:
                    data = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if data:
                    captures[key.data].feed(data)
                else:
                    selector.unregister(key.fileobj)
            counts = tuple(captures[name].count for name in ('stdout', 'stderr'))
            now = time.monotonic()
            if counts != reported and (now - last_report >= 30 or not selector.get_map()):
                try:
                    print('Native ' + phase + ' output progress:', json.dumps(dict(zip(('stdout_bytes', 'stderr_bytes'), counts))), flush=True)
                except Exception:
                    if phase != 'image-import': raise
                reported, last_report = counts, now
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(arguments, timeout)
        code = process.wait(timeout=remaining)
        cleanup_code = code
        reaped = True
        return code, {name: capture.context() for name, capture in captures.items()}
    except subprocess.TimeoutExpired:
        try:
            print('Native ' + phase + ' timeout evidence:', json.dumps({
                'timeout_seconds': timeout, **{name: capture.context() for name, capture in captures.items()}},
                ensure_ascii=True), flush=True)
        except Exception:
            if phase != 'image-import': raise
        raise
    finally:
        # The owned new process group is killed before leader reaping on errors;
        # never signal a PID after wait() could release it for reuse.
        failures = []
        if not reaped:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                group_killed = True
            except ProcessLookupError:
                pass
            except BaseException as error:
                failures.append(error)
            try:
                cleanup_code = process.wait(timeout=5)
            except BaseException as error:
                failures.append(error)
        for resource in (selector, process.stdout, process.stderr):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    failures.append(error)
        if phase == 'image-import':
            try:
                print('Native image-import client cleanup:', json.dumps({
                    'group_sigkill_sent': group_killed, 'returncode': cleanup_code,
                    'cleanup_errors': [type(error).__name__ for error in failures],
                    'daemon_import_outcome_inferred': False}), flush=True)
            except Exception:
                pass  # Output failure cannot replace the command/cleanup outcome.
        if failures and sys.exc_info()[0] is None:
            raise failures[0]


def run(*arguments, timeout=90, pass_fds=(), native_failure_context=False,
        native_trust_context=False, native_import_context=False):
    if type(native_failure_context) is not bool:
        raise ValueError("invalid native failure diagnostic option")
    if type(native_trust_context) is not bool:
        raise ValueError("invalid native trust diagnostic option")
    if type(native_import_context) is not bool:
        raise ValueError("invalid native import diagnostic option")
    if native_import_context:
        if (native_failure_context or native_trust_context or pass_fds or timeout != 120
                or arguments != ('docker', 'import', '/var/lib/uas-native-rootfs.tar')):
            raise ValueError('native import requires fixed archive-file command')
        code, streams = native_command(arguments, timeout=timeout, phase='image-import')
        if code:
            raise RuntimeError('native image import failed: ' + json.dumps(
                {'returncode': code, **streams}, ensure_ascii=True))
        return streams['stdout']['output']
    if native_trust_context:
        from native_trust import fixed_commands
        if (native_failure_context or pass_fds or timeout != 90
                or arguments not in fixed_commands(Path("/var/lib/uas-native-rootfs"))):
            raise ValueError("native trust requires fixed offline installroot command")
        code, streams = native_command(arguments, timeout=timeout, phase="trust-generation")
        if code:
            raise RuntimeError("native trust command failed: " + json.dumps(
                {"tool": arguments[0], "returncode": code, **streams}, ensure_ascii=True))
        return streams["stdout"]["output"]
    if native_failure_context and (not arguments or arguments[0] != 'dnf'
            or not any(type(value) is str and value.startswith('--installroot=') for value in arguments)
            or not {'--disablerepo=*', '--enablerepo=uas-native', '--setopt=tsflags=noscripts',
                    '--setopt=uas-native.gpgcheck=1'} <= set(arguments)):
        raise ValueError('native diagnostics require offline noscripts rootfs command')
    if native_failure_context:
        code, streams = native_command(arguments, timeout=timeout, pass_fds=pass_fds)
        if code:
            context = {'tool': arguments[0], 'returncode': code, **streams}
            raise RuntimeError('native rootfs command failed: ' + json.dumps(context, ensure_ascii=True))
        return streams['stdout']['output']
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


def verified_sibling(backend, state, container_id):
    """Bind attribution to current admitted owned objects, not an IP guess."""
    from uas.guest_fixture import network_names
    resource = backend.admit(state)  # Exact ownership, confinement and no published ports.
    network = backend._network(state)  # Exact owned labels and admitted NAT options.
    name, bridge, _ = network_names(state)
    expect(resource['Id'] == container_id and resource['State']['Running'] is True,
           'sibling container replaced or stopped')
    attachments = resource['NetworkSettings']['Networks']
    expect(set(attachments) == {name} and network is not None, 'sibling network attachment mismatch')
    attachment = attachments[name]
    address = str(ipaddress.IPv4Address(attachment['IPAddress']))
    expect(address == attachment['IPAddress'] and
           ipaddress.IPv4Address(address) in ipaddress.IPv4Network(backend.subnet), 'sibling address invalid')
    endpoint = network['Containers'][container_id]
    expect(attachment['NetworkID'] == network['Id'] and
           attachment['EndpointID'] == endpoint['EndpointID'] and bool(attachment['EndpointID']) and
           endpoint['IPv4Address'] == address + '/24', 'sibling endpoint identity mismatch')
    return {'container': container_id, 'network': network['Id'],
            'endpoint': attachment['EndpointID'], 'address': address, 'bridge': bridge}


def sibling_raw_counter(document, address, bridge):
    """Accept one exact Docker-associated raw DROP, never an arbitrary drop.

    iptables-save's counter-bearing format is deliberately strict. A new engine
    representation needs review rather than a permissive fallback.
    """
    expect(isinstance(document, str) and len(document) <= 65536, 'raw evidence oversized')
    expect(str(ipaddress.IPv4Address(address)) == address and
           re.fullmatch(r'uas[0-9a-f]{12}', bridge), 'invalid sibling identity')
    lines = [line for line in document.splitlines() if line and not line.startswith('#')]
    expect(lines and lines[0] == '*raw' and lines[-1] == 'COMMIT' and
           lines.count('*raw') == 1 and lines.count('COMMIT') == 1, 'incomplete raw evidence')
    chains = [line.split()[0] for line in lines if line.startswith(':')]
    expect(chains.count(':PREROUTING') == 1 and len(chains) == len(set(chains)), 'ambiguous raw chains')
    candidates = []
    for line in lines[1:-1]:
        if line.startswith(':'):
            expect(re.fullmatch(r':[A-Z0-9_-]+ (?:ACCEPT|DROP|-) \[[0-9]+:[0-9]+\]', line), 'malformed raw chain')
            continue
        match = re.fullmatch(r'\[([0-9]+):([0-9]+)\] (-A .+)', line)
        expect(match is not None, 'malformed raw rule counters')
        tokens = match[3].split()
        # Include altered /32 spelling and extra-condition variants as candidates
        # so they cannot hide beside an otherwise valid rule for this address.
        if any(token.split('/')[0] == address for token in tokens):
            candidates.append((tokens, int(match[1]), int(match[2])))
    expect(len(candidates) == 1, 'missing or ambiguous sibling raw rule')
    tokens, packets, byte_count = candidates[0]
    expect(packets <= 2**64 - 1 and byte_count <= 2**64 - 1, 'raw counters out of range')
    expect(tokens == ['-A', 'PREROUTING', '-d', address + '/32', '!', '-i', bridge, '-j', 'DROP'],
           'sibling raw rule has wrong identity or extra conditions')
    return {'rule': tokens, 'packets': packets, 'bytes': byte_count}


def read_sibling_raw(identity):
    # No counter reset, restore or rule mutation. Oversize/nonzero/timeout fails.
    return sibling_raw_counter(run('iptables-legacy-save', '-c', '-t', 'raw', timeout=3),
                               identity['address'], identity['bridge'])


def require_sibling_denial(probe, backend, state, container_id):
    identity = verified_sibling(backend, state, container_id)
    require_sibling_listener(probe, identity['address'])
    before = read_sibling_raw(identity)
    expect(probe('alpha', 'connect', identity['address'] + ':5000')['error'] == 'TIMEOUT',
           'sibling unexpectedly reachable')
    after = read_sibling_raw(identity)
    expect(verified_sibling(backend, state, container_id) == identity, 'sibling identity changed during probe')
    expect(after['rule'] == before['rule'] and after['packets'] > before['packets'] and
           after['bytes'] > before['bytes'], 'no exact sibling raw denial or counters reset')
    evidence = {'identity': identity, 'before': before, 'after': after}
    print('Sibling raw denial:', json.dumps(evidence), flush=True)
    return evidence


def network_diagnostics(phase, alpha_ip, bridge):
    """Read-only guest evidence, not a policy repair or qualification assertion.

    Capture exact counters before/after the existing synthetic connection. Never
    zero counters, probe another endpoint, change routes, or relax confinement.
    Missing tools/denied reads remain explicit unknowns rather than successes.
    """
    commands = [
        ['iptables-legacy', '--version'],
        *[['iptables-legacy', '-w', '1', '-t', table, '-L', '-n', '-v', '-x']
          for table in ('raw', 'filter', 'nat')],
        ['ip', '-4', 'route', 'show', 'table', 'all'],
        ['ip', '-4', 'rule', 'show'],
        ['ip', '-4', 'route', 'get', '93.184.216.34', 'from', alpha_ip, 'iif', bridge],
        ['ip', '-4', 'route', 'get', alpha_ip, 'from', '93.184.216.34', 'iif', 'uas-public'],
        ['sysctl', 'net.ipv4.ip_forward',
         *['net.ipv4.conf.' + interface + '.' + setting
           for interface in ('all', 'default', 'uas-public', bridge)
           for setting in ('forwarding', 'rp_filter')]],
        ['journalctl', '-k', '-b', '--no-pager', '-n', '20', '--grep=avc:.*denied'],
    ]
    for arguments in commands:
        try:
            output = run(*arguments, timeout=3)
            observation = {'output': output[:4096], 'truncated': len(output) > 4096}
        except Exception as error:
            observation = {'error': str(error)[:512]}
        # JSON escapes terminal control bytes from diagnostics.
        print('Guest network diagnostic:', json.dumps({'phase': phase,
              'command': arguments, **observation}), flush=True)


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


def exact_install_roots(manifest, exact_roots=None):
    """Native opt-in only: select reviewed NEVRA roots from verified pool.

    Unversioned install can retain an older OS package. Do not install the full
    candidate closure or relax the solver: request only these exact roots.
    The default synthetic boundary profile keeps its existing behavior.
    """
    if exact_roots is None:
        return REQUIRED_PACKAGES
    expect(manifest.get('profile') == 'native-pi-v1' and type(exact_roots) is dict
           and bool(exact_roots) and set(exact_roots) <= set(REQUIRED_PACKAGES),
           'exact package roots require explicit native profile')
    selected = {}
    for name, expected in exact_roots.items():
        expect(type(expected) is tuple and len(expected) == 4
               and all(type(value) is str for value in expected), 'invalid exact package profile')
        epoch,version,release,arch = expected
        expect(re.fullmatch(r'[0-9]+', epoch) is not None
               and all(re.fullmatch(r'[A-Za-z0-9._+~^\-]{1,256}', value) for value in (version,release))
               and arch in ('x86_64','noarch'), 'invalid exact package NEVRA')
        candidates = [item for item in manifest['packages'] if item['name'] == name]
        expect(len(candidates) == 1 and tuple(candidates[0].get(key) for key in
               ('epoch','version','release','arch')) == expected,
               'missing, ambiguous or mismatched exact native root: ' + name)
        selected[name] = f'{name}-{epoch}:{version}-{release}.{arch}'
    return tuple(selected.get(name,name) for name in REQUIRED_PACKAGES)


def require_installed_roots(exact_roots):
    if exact_roots is None:
        return
    for name,(epoch,version,release,arch) in exact_roots.items():
        expected = f'{epoch}:{version}-{release}.{arch}\n'
        actual = run('rpm','-q','--queryformat','%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n',name)
        expect(actual == expected,
               f'installed native root mismatch {name}: expected={expected!r} observed={actual[:512]!r}')
        print('Verified installed native root:', name + '-' + actual.strip(), flush=True)


def install_packages(nonce, manifest, *, exact_roots=None):
    expect(os.geteuid() == 0 and Path('/run/uas-vm-fixture').read_text().strip() == nonce, 'not this disposable boot')
    expect(run('getenforce').strip() == 'Enforcing', 'SELinux not enforcing before packages')
    roots = exact_install_roots(manifest, exact_roots)
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
        '--setopt=install_weak_deps=False', 'install', *roots, timeout=900)
    require_installed_roots(exact_roots)


def install(nonce, manifest_hash, *, exact_roots=None, defer_engine_start=False):
    expect(os.geteuid() == 0 and Path('/run/uas-vm-fixture').read_text().strip() == nonce, 'not this disposable boot')
    expect(sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'], 'external guest NIC present')
    expect(run('getenforce').strip() == 'Enforcing', 'SELinux not enforcing before installation')
    PAYLOAD.mkdir()
    run('mount', '-o', 'ro,nodev,nosuid,noexec', '/dev/disk/by-label/UAS_PAYLOAD', str(PAYLOAD))
    manifest = verify_payload(nonce, manifest_hash)
    expect(type(defer_engine_start) is bool and (not defer_engine_start
           or manifest.get('profile') == 'native-pi-v1'), 'daemon deferral requires native profile')
    install_packages(nonce, manifest, exact_roots=exact_roots)
    shutil.copytree(PAYLOAD / 'repo', ROOT)
    shutil.copyfile(PAYLOAD / 'fixture', ROOT / 'fixture')
    (ROOT / 'fixture').chmod(0o555)
    run('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'uas-remap')
    Path('/etc/subuid').write_text('uas-remap:100000:65536\n')
    Path('/etc/subgid').write_text('uas-remap:100000:65536\n')
    Path('/etc/docker').mkdir(exist_ok=True)
    Path('/etc/docker/daemon.json').write_text(json.dumps(DOCKER_CONFIGURATION))
    if not defer_engine_start:
        start_engine()


def start_engine():
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
    backends['alpha'].lose_network_response = True
    first = supervisors['alpha'].start(specs['alpha'])
    expect(first['phase'] == 'start_failed' and first['observed']['container'] is None, 'uncertain partial create not retained')
    recovered = supervisors['alpha'].reconcile()
    expect(recovered['phase'] == 'running', str(recovered))
    for room in ROOMS:
        result = supervisors[room].start(specs[room])
        expect(result['phase'] == 'running', str(result))
        containers[room] = result['observed']['container']['id']
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
    beta_state = json.loads((supervisors['beta'].directory / 'lifecycle.json').read_text())
    beta_ip = verified_sibling(backends['beta'], beta_state, containers['beta'])['address']
    require_sibling_listener(probe, beta_ip)
    alpha_ip = json.loads(run('docker', 'inspect', containers['alpha']))[0]['NetworkSettings']['Networks'][backends['alpha']._network_name(state)]['IPAddress']
    bridge = network_names(state)[1]
    network_diagnostics('before-public-positive', alpha_ip, bridge)
    try:
        expect(probe('alpha', 'connect', '93.184.216.34:5000') == {'error': 'OK', 'reply': 'uas-boundary-ok\n'}, 'public-address positive failed')
    finally:
        network_diagnostics('after-public-positive', alpha_ip, bridge)
    for address, chain in (('10.89.1.1', 'input'), ('93.184.216.35', 'input'),
                           ('169.254.169.254', 'forward'), ('192.168.50.1', 'forward')):
        before = dropped(chain)
        expect(probe('alpha', 'connect', address + ':5000')['error'] == 'TIMEOUT', 'blocked destination unexpectedly reachable')
        expect(dropped(chain) > before, 'no exact firewall denial observed')
    sibling_denial = require_sibling_denial(probe, backends['beta'], beta_state, containers['beta'])
    expect(probe('alpha', 'connect', '[2606:4700:4700::1111]:5000')['error'] == 'ENETUNREACH', 'IPv6 must be unavailable in this IPv4 fixture')
    checks['network'] = {'status': 'passed', 'public_address_synthetic_only': True,
                         'denied': ['host-private', 'host-public', 'LAN', 'metadata', 'sibling'], 'ipv6': 'disabled-and-filtered',
                         'sibling_positive_vantage': 'beta-own-bridge-address',
                         'sibling_denial': sibling_denial}

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
    # Defer expensive crash cycles until network/quota/Destroy have passed.
    # These remain mandatory, with the same assertions and exact owned cleanup.
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
    checks['recovery'] = {'status': 'passed', 'lost_network_response_reconciled': True, 'sigkill_boundaries': ['volume', 'mkdir', 'marker']}
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
