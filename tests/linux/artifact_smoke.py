#!/usr/bin/env python3
"""Fast GitHub Linux DAC/FD/materializer smoke, NOT native qualification.

Root only provisions/removes its private /tmp fixture and drops numeric IDs.
All Gate/path/Git work runs as a nonroot, capability-free Supervisor. No accounts,
Docker, VM, mounts, labels, policy changes or native helper are involved. A missing
prerequisite fails; this is not a fallback for the manual stock-policy VM test.
Importing this module has no filesystem, listener or subprocess effects.
"""
from contextlib import ExitStack, closing
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
VM = ROOT / 'tests/vm'
sys.path[:0] = [str(ROOT), str(VM)]
import guest_artifacts as guest
import artifact_supervisor as fixture_supervisor
from uas import artifact_helper as helper, artifact_target as target
from uas.artifact_protocol import ArtifactError, RESERVATION_BYTES
from uas.config import load

UID, HELPER, HUB = 165533, 165530, 165531
NONCE = 'a' * 32
PACKET = b'linux-dac-fd-smoke'
LIMIT_SECONDS = 40
DEADLINE_ENV = 'UAS_ARTIFACT_SMOKE_DEADLINE'
SOURCES = (
    'tests/linux/artifact_smoke.py', 'tests/fixtures/two-rooms.json',
    'tests/vm/guest_artifacts.py', 'tests/vm/guest_boundary.py',
    'tests/vm/artifact_supervisor.py', 'tests/vm/artifact_hub.py', 'tests/vm/artifact_diagnostics.py',
    'uas/__init__.py', 'uas/config.py', 'uas/gate_policy.py', 'uas/ledger.py', 'uas/typed_json.py',
    'uas/manager_owner.py', 'uas/manager_projection.py', 'uas/library_observation_schema.py', 'uas/manager_journey.py', 'uas/lifecycle.py', 'uas/checkouts.py', 'uas/checkout_scope.py', 'uas/artifact_protocol.py', 'uas/artifact_paths.py',
    'uas/artifact_target.py', 'uas/artifact_helper.py', 'uas/gate_evaluation.py',
    'uas/docker_exec_api.py', 'uas/kernel_origin.py', 'uas/workstation_exec.py', 'uas/workstation_probe.py')


def expect(value, message):
    if not value:
        raise AssertionError(message)


def require_unblocked_alarm():
    # A blocked mask survives fork/exec and would defeat the self-deadlines.
    # Empty SIG_BLOCK queries it without changing this process's signal mask.
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    expect(signal.SIGALRM not in blocked, 'unblocked SIGALRM required; no mask repair')


def relocated_plan(root):
    """Use the exact generated raw config; relocate only its two path roots."""
    root = Path(root)
    expect(root.is_absolute() and '..' not in root.parts, 'absolute fixture root required')
    original = guest.fixture_layout(NONCE, json.loads((ROOT / 'tests/fixtures/two-rooms.json').read_text()))
    prefixes = {original['scratch_root']: str(root / 'scratch'), str(guest.STORAGE): str(root / 'storage')}
    def relocate(value):
        if isinstance(value, dict):
            return {key: relocate(item) for key, item in value.items()}
        if isinstance(value, list):
            return [relocate(item) for item in value]
        if isinstance(value, str):
            for source, destination in prefixes.items():
                if value == source or value.startswith(source + '/'):
                    return destination + value[len(source):]
        return value
    result = relocate(original)
    load(io.StringIO(json.dumps(result['configuration'])))
    return result


def provision(root, plan):
    def directory(path, mode, uid=0, gid=0):
        path = Path(path)
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        path.chmod(mode)
    root.chmod(0o711)
    directory(plan['scratch_root'], 0o711)
    directory(Path(plan['scratch_root']) / 'search-only-leaf', 0o711)
    directory(root / 'storage', 0o755)
    directory(plan['state_root'], 0o700, UID, UID)
    for paths in plan['rooms'].values():
        directory(paths['room_root'], 0o755, UID, UID)
        for name in ('repo', 'checkouts', 'reference'):
            directory(paths[name], 0o755, UID, UID)
        directory(paths['workspace'], 0o755, 165532, 165532)
        directory(paths['scratch'], 0o711, UID, UID)
        directory(paths['journal'], 0o700, UID, UID)
        directory(paths['hub'], 0o700, HUB, HUB)
        directory(paths['gate'], 0o710, UID, HELPER)
        directory(paths['control'], 0o710, UID, HUB)
    path = Path(plan['configuration_path'])
    path.write_text(json.dumps(plan['configuration']))
    path.chmod(0o444)
    path = root / 'plan.json'
    path.write_text(json.dumps(plan))
    path.chmod(0o444)
    return path


def stage_sources(root):
    """Fixed bounded ordinary-source copies; no checkout ancestor chmod."""
    destination = root / 'source'
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)
    total = 0
    for relative in SOURCES:
        path = ROOT / relative
        for parent in path.relative_to(ROOT).parents:
            expect(stat.S_ISDIR((ROOT / parent).lstat().st_mode), 'ordinary source ancestor required')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            expect(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 256 << 10,
                   'bounded ordinary source required')
            data = stream.read((256 << 10) + 1)
            after = os.fstat(stream.fileno())
        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        expect(stamp(before) == stamp(after) and len(data) == before.st_size, 'source changed while staging')
        total += len(data)
        expect(total <= 2 << 20, 'source payload byte bound exceeded')
        output = destination / relative
        parent = destination
        for name in Path(relative).parts[:-1]:
            parent = parent / name
            parent.mkdir(mode=0o755, exist_ok=True)
            parent.chmod(0o755)
        with output.open('xb') as stream:
            stream.write(data)
        output.chmod(0o444)
        expect(hashlib.sha256(output.read_bytes()).digest() == hashlib.sha256(data).digest(), 'source copy differs')
    return destination


def transfer_listener(path, group, *, deadline):
    """Run the VM's exact unprivileged child and ancillary parser, without MAC."""
    guest.require_setup_reaping()
    expect(time.monotonic() + 12 <= deadline, 'insufficient lifetime for fixed listener child')
    child = None
    reaped = False
    listener = None
    with ExitStack() as stack:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        stack.callback(left.close)
        stack.callback(right.close)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        left.settimeout(5)
        try:
            child = os.fork()
            if child == 0:
                guest.setup_listener_child(left, right, path, group)
            right.close()
            diagnostic = {}
            listener = guest.receive_setup_listener(left, child, diagnostic)
            outcome = guest.setup_child_outcome(child, time.monotonic() + 2)
            reaped = outcome['outcome'] in ('exit', 'signal')
            expect(outcome == {'outcome': 'exit', 'exit_code': 0}, 'listener setup child failed')
            expect(not diagnostic['cleanup_errors'], 'listener transfer cleanup failed')
            expect(listener.getsockname() == str(path), 'listener path changed')
            expect(not os.get_inheritable(listener.fileno()), 'received listener must be CLOEXEC')
            result, listener = listener, None
            return result
        finally:
            try:
                if listener is not None:
                    listener.close()
            finally:
                if child is not None and child > 0 and not reaped:
                    outcome = guest.setup_child_outcome(child, time.monotonic())
                    if outcome['outcome'] == 'unconfirmed':
                        os.kill(child, signal.SIGKILL)  # This still-unreaped fork child only.
                        outcome = guest.setup_child_outcome(child, time.monotonic() + 1)
                    expect(outcome['outcome'] in ('exit', 'signal'), 'listener child cleanup unconfirmed')


def numeric_command(payload, uid, groups, *arguments):
    return ['/usr/bin/setpriv', '--reuid=' + str(uid), '--regid=' + str(uid),
            '--groups=' + ','.join(map(str, groups)), '--inh-caps=-all',
            '--ambient-caps=-all', '--bounding-set=-all', '--no-new-privs',
            '/usr/bin/python3', str(payload / 'tests/linux/artifact_smoke.py'), *map(str, arguments)]


def run_owned(command, *, payload, deadline, pass_fds=()):
    """Bound and reap only this direct child/session; never adopt another task."""
    guest.require_setup_reaping()
    expect(threading.active_count() == 1, 'single-threaded direct-child ownership required')
    expect(time.monotonic() < deadline, 'smoke deadline exhausted before spawn')
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, pass_fds=pass_fds, start_new_session=True, cwd=payload,
        env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1', 'LC_ALL': 'C', DEADLINE_ENV: str(deadline)})
    try:
        out, err = process.communicate(timeout=max(0, min(20, deadline - time.monotonic())))
    except subprocess.TimeoutExpired as original:
        # communicate's timeout has not reaped a returncode=None leader. Never
        # poll/reap it before signaling its fresh session: descendants may hold
        # the pipes after the leader exits. A reaped/uncertain leader is no
        # longer numeric process-group authority; retain the failed fixture.
        if process.returncode is not None:
            raise RuntimeError('child group cleanup unconfirmed: leader already reaped') from original
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=2)
            expect(process.returncode is not None, 'direct child exit unconfirmed')
        except BaseException as error:
            raise RuntimeError('child group cleanup unconfirmed') from error
        raise
    except BaseException as original:
        # A signal may interrupt wait after consuming the child status. Do not
        # guess PID/group ownership; numeric children also have self-deadlines.
        raise RuntimeError('child group cleanup unconfirmed: interrupted wait') from original
    expect(len(out) <= 16384 and len(err) <= 65536, 'bounded smoke child output required')
    if process.returncode:
        raise RuntimeError('Linux smoke child failed:\n' + err.decode(errors='replace'))
    return out


def child_deadline(seconds):
    """Allow fixed cleanup, then hard-expire even if the parent became unknown."""
    require_unblocked_alarm()
    def expired(*_):
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(2)
        raise TimeoutError('numeric smoke child expired')
    remaining = float(os.environ[DEADLINE_ENV]) - time.monotonic()
    expect(0 < remaining <= LIMIT_SECONDS, 'trusted bounded parent deadline required')
    signal.signal(signal.SIGALRM, expired)
    # At most one second rounding plus two seconds final cleanup: even a late
    # child expires by the parent's 40-second deadline +3, inside the 45-second cap.
    signal.alarm(max(1, min(seconds, int(remaining))))


def unprivileged(uid, groups):
    expect((os.getuid(), os.geteuid(), os.getgid()) == (uid, uid, uid), 'exact nonroot numeric identity required')
    expect(set(os.getgroups()) == set(groups), 'exact supplementary groups required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    expect(all(int(status[key].strip(), 16) == 0 for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd')),
           'capability-free smoke child required')
    expect(status['NoNewPrivs'].strip() == '1', 'nonprivileged child required')


def read_denied(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except PermissionError as error:
        expect(error.errno == errno.EACCES, 'expected actual DAC EACCES')
    else:
        os.close(fd)
        raise AssertionError('search-only directory was unexpectedly readable')


def connect_child(path, group):
    child_deadline(3)
    unprivileged(group, (group,))
    path = Path(path)
    read_denied(path.parent)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(2)
        connection.connect(str(path))
        peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        expect(peer[1:] == (UID, UID), 'listener was not created by the nonroot Supervisor')
        expect(connection.send(PACKET) == len(PACKET), 'complete nonroot packet required')


class ForbiddenNativeAuthority:
    def __getattr__(self, name):
        raise AssertionError('Linux smoke must not invoke Engine/native admission: ' + name)


def supervisor_child(plan_path, room, gate_fd, control_fd):
    child_deadline(25)
    unprivileged(UID, (HELPER, HUB))
    plan = json.loads(Path(plan_path).read_text())
    paths = plan['rooms'][room]
    scratch = Path(plan['scratch_root'])
    expect((scratch.stat().st_uid, stat.S_IMODE(scratch.stat().st_mode)) == (0, 0o711), 'real root-owned 0711 ancestry required')
    read_denied(scratch)
    try:
        descriptor = helper._directory(scratch / 'search-only-leaf')
    except PermissionError as error:
        expect(error.errno == errno.EACCES, 'unreadable leaf must remain EACCES')
    else:
        os.close(descriptor)
        raise AssertionError('unreadable leaf accepted as an O_PATH directory')
    config = {**paths, 'image_digest': 'a' * 64, 'profile_digest': 'b' * 64}
    started = time.monotonic()
    with ExitStack() as stack:
        for descriptor, name, group in ((int(gate_fd), 'gate', HELPER), (int(control_fd), 'control', HUB)):
            listener = stack.enter_context(closing(socket.socket(fileno=descriptor)))
            expect(listener.getsockname() == str(Path(paths[name]) / ('gate.sock' if name == 'gate' else 'hub.sock')),
                   'inherited exact listener path required')
            expect(listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1, 'inherited listener not listening')
            endpoint = helper.GateEndpointLease(listener.getsockname(), owner=UID, group=group)
            expect(endpoint.require(), 'exact endpoint lease required')
            listener.settimeout(2)
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                client.settimeout(2)
                client.connect(listener.getsockname())
                client.sendall(PACKET)
                with closing(listener.accept()[0]) as accepted:
                    expect(accepted.recv(64) == PACKET, 'inherited listener did not carry actual packet')
        supervisor, allocator, resolver, source, marker = fixture_supervisor.setup_source(config)
        journal = Path(paths['journal'])
        for name in ('targets', 'launches', 'probes'):
            (journal / name).mkdir(mode=0o700)
        reservations = {}
        def capacity(scope, size):
            expect(size == RESERVATION_BYTES, 'fixed materializer reservation required')
            used, nodes = fixture_supervisor.allocated((Path(paths['room_root']), supervisor.directory))
            available = os.statvfs(paths['scratch'])
            if (used + sum(reservations.values()) + size > 256 << 20 or nodes + 1536 > 8192
                    or available.f_bavail * available.f_frsize < size):
                return False
            reservations[scope['evaluation_id']] = size
            return True  # Real local free-space budget only; NOT project-quota admission.
        targets = target.ArtifactTargets(paths['scratch'], journal / 'targets', resolver, reserve_capacity=capacity)
        scope = {'version': 1, 'evaluation_id': 'linux-smoke-' + room, 'room_id': room,
            'room_instance': paths['room_instance'], 'project_id': room, 'repository': 'example/' + room,
            'run_id': 'artifact-run', 'generation': 1, 'participant_id': 'builder',
            'policy_id': 'fixed', 'policy_version': 1, 'policy_digest': 'c' * 64,
            'gate_id': 'fixed', 'config_digest': 'd' * 64}
        fd_count = len(os.listdir('/proc/self/fd'))
        document = targets.prepare(scope, source)
        lease = targets.lease(document)
        expect(lease.recheck(), 'materialized target recheck failed')
        expect((lease.path / 'tree/README.md').read_bytes() == b'committed artifact proof\n', 'committed bytes were not materialized')
        expect((Path(paths['repo']) / 'README.md').read_bytes() == b'', 'dirty source discriminator missing')
        expect(not marker.exists(), 'poisoned source config or hooks executed')
        endpoint = helper.GateEndpointLease(Path(paths['gate']) / 'gate.sock', owner=UID, group=HELPER)
        workstation = helper.GateWorkstation(room, paths['room_instance'], *(['e' * 64] * 6), 'hub-' + room)
        forbidden = ForbiddenNativeAuthority()
        launch = helper.GateHelperLaunch(forbidden, workstation, endpoint, journal / 'launches/fixed.json',
            admission=forbidden, target_lease=lease, scope=scope)
        expect(launch.state == 'new', 'constructor launched a native helper')
        record = helper._LaunchJournal(launch.journal_path)
        try:
            record.append({'version': 1, 'state': 'linux-smoke-construction-only'})
        finally:
            record.close()
        expect(json.loads(launch.journal_path.read_text()) == {'version': 1, 'state': 'linux-smoke-construction-only'},
               'launch journal did not persist exact construction record')
        expect(targets.cleanup(document), 'owned target cleanup failed')
        expect(not lease.path.exists(), 'target survived successful cleanup')
        expect(len(os.listdir('/proc/self/fd')) == fd_count, 'constructor/materializer descriptor leak')
        # No-follow refusal remains a real kernel check.
        alias = journal / 'gate-alias'
        alias.symlink_to(paths['gate'], target_is_directory=True)
        try:
            try:
                helper.GateEndpointLease(alias / 'gate.sock', owner=UID, group=HELPER)
            except OSError as error:
                expect(error.errno in (errno.ELOOP, errno.ENOTDIR), 'unexpected symlink refusal')
            else:
                raise AssertionError('symlink endpoint ancestor accepted')
        finally:
            alias.unlink()
        expect(len(os.listdir('/proc/self/fd')) == fd_count, 'negative traversal descriptor leak')
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as replacement:
            temporary = endpoint.path.with_name('replacement.sock')
            replacement.bind(str(temporary))
            replacement.listen(1)
            os.chown(temporary, -1, HELPER)
            temporary.chmod(0o620)
            os.replace(temporary, endpoint.path)
            try:
                endpoint.require()
            except ArtifactError as error:
                expect(error.code == 'GATE_ENDPOINT_REPLACED', 'wrong replacement refusal')
            else:
                raise AssertionError('replaced endpoint accepted')
        expect(len(os.listdir('/proc/self/fd')) == fd_count, 'endpoint replacement descriptor leak')
    print(json.dumps({'room': room, 'uid': UID, 'generated_config': True, 'real_dac': True,
        'inherited_listener_packets': 2, 'copied_git_materialization': True,
        'source_poison_not_executed': True, 'target_removed': True,
        'seconds': round(time.monotonic() - started, 3)}, sort_keys=True))


def main():
    expect(sys.platform == 'linux', 'Linux runner required')
    if len(sys.argv) == 6 and sys.argv[1] == '--supervisor':
        supervisor_child(*sys.argv[2:])
        return
    if len(sys.argv) == 4 and sys.argv[1] == '--connect':
        connect_child(sys.argv[2], int(sys.argv[3]))
        return
    expect(sys.argv[1:] == ['--run'], 'explicit --run required')
    expect(os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
           and os.environ.get('RUNNER_OS') == 'Linux', 'owned GitHub Linux root fixture required')
    require_unblocked_alarm()
    started = time.monotonic()
    def expired(*_):
        raise TimeoutError('Linux artifact smoke exceeded 40 seconds')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(LIMIT_SECONDS)
    root = Path(tempfile.mkdtemp(prefix='uas-gate-', dir='/tmp'))
    identity = (root.stat().st_dev, root.stat().st_ino)
    fd_count = len(os.listdir('/proc/self/fd'))
    complete = False
    try:
        plan = relocated_plan(root)
        plan_path = provision(root, plan)
        payload = stage_sources(root)
        rooms = []
        for room, paths in plan['rooms'].items():
            with ExitStack() as stack:
                listeners = []
                for name, group, filename in (('gate', HELPER, 'gate.sock'), ('control', HUB, 'hub.sock')):
                    path = Path(paths[name]) / filename
                    listener = stack.enter_context(closing(transfer_listener(path, group, deadline=started + LIMIT_SECONDS)))
                    listeners.append(listener)
                    run_owned(numeric_command(payload, group, (group,), '--connect', path, group),
                              payload=payload, deadline=started + LIMIT_SECONDS)
                    listener.settimeout(2)
                    with closing(listener.accept()[0]) as accepted:
                        peer = struct.unpack('3i', accepted.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        expect(peer[1:] == (group, group), 'actual connecting group identity differs')
                        expect(accepted.recv(64) == PACKET, 'group-search connection failed')
                fds = tuple(listener.fileno() for listener in listeners)
                output = run_owned(numeric_command(payload, UID, (HELPER, HUB), '--supervisor', plan_path, room, *fds),
                                   payload=payload, deadline=started + LIMIT_SECONDS, pass_fds=fds)
                rooms.append(json.loads(output))
        expect(len(os.listdir('/proc/self/fd')) == fd_count, 'root listener/transfer descriptor leak')
        expect((Path(plan['scratch_root']).stat().st_uid, stat.S_IMODE(Path(plan['scratch_root']).stat().st_mode)) == (0, 0o711),
               'search-only ownership/mode was widened')
        report = {'check': 'artifact-linux-smoke', 'rooms': rooms,
            'native_qualification': False,
            'scope': 'Linux DAC/FD/generated-config/copied-Git only; no SELinux/Landlock/quota/VM/helper proof'}
        complete = True
    finally:
        try:
            if complete:
                expect((root.lstat().st_dev, root.lstat().st_ino) == identity, 'owned cleanup root replaced')
                expect(shutil.rmtree.avoids_symlink_attacks, 'fd-safe fixture cleanup required')
                shutil.rmtree(root)
            else:
                print('Linux smoke failed; private fixture retained, cleanup NOT claimed: ' + str(root), file=sys.stderr)
        finally:
            signal.alarm(0)
    # A cleanup error must never leave a success-looking result in the log.
    report['seconds'] = round(time.monotonic() - started, 3)
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
