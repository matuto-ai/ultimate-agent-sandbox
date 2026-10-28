#!/usr/bin/env python3
"""Cheap hosted Room help protocol seam, never native Room qualification.

Actual RoomHelpOnlyCoordinator, ObservedAuthority, BrokerProcess, ExecLaunch,
room_probe.bootstrap and public Git launcher, with real seqpacket/SCM_PIDFD.
The owned-process Engine, same-namespace UID 65532 (not remapped 165532), private
Broker pathname, live-task-only current callback and DAC/inode EndpointLease
are explicit substitutions. No Room manifest or full RoomEndpoint admission,
Docker/TCG startup, SELinux/quota/egress proof is claimed.
All mounts are private; the participant sees only a staged chroot. No accounts,
credentials, host-policy edits, VM, target prove_service or native Git workers.
Importing is effect-free. Run only in reviewed disposable hosted CI.
"""
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
DEADLINE = 'UAS_ROOM_PROTOCOL_DEADLINE'
LIMIT_SECONDS = 25
CONTAINER = 'a' * 64
UID = 65532


def require(value, message):
    if not value: raise AssertionError(message)


def load_source(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def helpers():
    return load_source('room_protocol_helpers', Path(__file__).with_name('git_composition_smoke.py'))


def recipe():
    return {'AttachStdin': True, 'AttachStdout': True, 'AttachStderr': True,
            'Tty': False, 'Privileged': False, 'User': '65532:65532', 'WorkingDir': '/',
            'Cmd': ['/usr/bin/python3', '-I', '/opt/uas/uas/room_probe.py', 'bootstrap'], 'Env': []}


def stage(root, smoke):
    """Existing private-mount/chroot pattern; no real repository or host writes."""
    smoke.command('/usr/bin/mount', '--make-rprivate', '/')
    smoke.command('/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=755,nosuid,nodev',
                  'uas-room-protocol', '/opt')
    package = Path('/opt/uas'); package.mkdir(mode=0o755)
    source = ROOT / 'uas'
    require(not source.is_symlink() and all(not path.is_symlink() for path in source.rglob('*')),
            'ordinary reviewed package sources required')
    shutil.copytree(source, package / 'uas', ignore=shutil.ignore_patterns('__pycache__'))
    for path in (package / 'uas').rglob('*'):
        path.chmod(0o555 if path.is_dir() else 0o444)
    shutil.copyfile(ROOT / 'tests/vm/room_service.py', package / 'room_service.py')
    (package / 'room_service.py').chmod(0o444)
    smoke.command('/usr/bin/mount', '-o', 'remount,ro,nosuid,nodev', '/opt')
    root.chmod(0o755)
    endpoint = root / 'endpoint'; endpoint.mkdir(mode=0o710)
    os.chown(endpoint, 0, UID); endpoint.chmod(0o710)
    jail = root / 'jail'; jail.mkdir(mode=0o755)
    for name in ('opt', 'proc', 'dev', 'tmp', 'uas', 'etc'):
        (jail / name).mkdir(mode=0o755)
    (jail / 'tmp').chmod(0o1777)
    for name in ('usr', 'bin', 'lib', 'lib64'):
        source, target = Path('/') / name, jail / name
        if source.is_symlink(): target.symlink_to(os.readlink(source))
        elif source.is_dir():
            target.mkdir(mode=0o755)
            smoke.command('/usr/bin/mount', '--bind', str(source), str(target))
            smoke.command('/usr/bin/mount', '-o', 'remount,bind,ro,nosuid,nodev', str(target))
    for name in ('opt', 'proc'):
        smoke.command('/usr/bin/mount', '--bind', '/' + name, str(jail / name))
    (jail / 'dev/null').touch()
    smoke.command('/usr/bin/mount', '--bind', '/dev/null', str(jail / 'dev/null'))
    (jail / 'uas/git').mkdir(mode=0o755)
    smoke.command('/usr/bin/mount', '--bind', str(endpoint), str(jail / 'uas/git'))
    return jail, endpoint


class BootstrapEngine:
    """One owned real process; Engine API shape only, never Docker evidence."""
    def __init__(self, jail, helper):
        self.jail, self.helper = jail, helper
        self.created, self.child, self.transport = False, None, None

    def create(self, container, spec):
        require(not self.created and container == CONTAINER and spec == recipe(),
                'single fixed Room bootstrap recipe required')
        self.created = True
        return 'b' * 64

    def start(self, identifier):
        require(self.created and self.child is None and identifier == 'b' * 64,
                'single owned bootstrap start required')
        read, write = os.pipe2(os.O_CLOEXEC)
        try: pid = os.fork()
        except BaseException:
            os.close(read); os.close(write); raise
        if pid == 0:
            try:
                os.close(write); os.dup2(read, 0, inheritable=True)
                os.chroot(self.jail); os.chdir('/')
                self.helper.close_fds_except(set()); self.helper.isolate(UID)
                os.execve('/usr/bin/python3', recipe()['Cmd'],
                          {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
            except BaseException:
                import traceback
                traceback.print_exc(); os._exit(125)
        self.child = self.helper.OwnedChild(pid)
        os.close(read)
        self.transport = self.helper.FixtureTransport(write)
        return self.transport

    def inspect(self, identifier):
        require(identifier == 'b' * 64 and self.child is not None, 'unknown bootstrap exec')
        return {'ID': identifier, 'ContainerID': CONTAINER, 'Pid': self.child.pid,
                'Running': self.child.observation() is None}

    def close(self):
        failures = []
        for owner, method in ((self.transport, 'close'), (self.child, 'finish')):
            if owner is not None:
                try: getattr(owner, method)()
                except BaseException as error: failures.append(error)
        if failures: raise AssertionError('owned bootstrap cleanup incomplete') from failures[0]



def read_probe_ready(listener, stdout, stderr, child, expected, deadline):
    """One bounded exact stderr marker; no stdout/socket/exit before release."""
    data = bytearray()
    while bytes(data) != expected:
        remaining = deadline - time.monotonic()
        require(remaining > 0 and child.observation() is None, 'unrelated readiness expired or exited')
        ready, _, _ = select.select([listener, stdout, stderr], [], [], remaining)
        require(time.monotonic() < deadline, 'unrelated readiness deadline')
        require(stderr in ready and listener not in ready and stdout not in ready,
                'unrelated request/stdout/exit preceded readiness')
        raw = os.read(stderr, 65)
        require(time.monotonic() < deadline, 'unrelated readiness deadline')
        require(bool(raw), 'unrelated readiness EOF')
        data.extend(raw)
        require(len(data) <= 64 and expected.startswith(data), 'invalid or duplicate unrelated readiness marker')
    require(child.observation() is None
            and not select.select([listener, stdout, stderr], [], [], 0)[0],
            'unexpected activity after unrelated readiness')
    require(time.monotonic() < deadline, 'unrelated readiness deadline')


def collect_probe_output(stdout, stderr, deadline):
    """Bounded owned pipes, drained together; EOF is not task-exit evidence."""
    buffers = {stdout: bytearray(), stderr: bytearray()}
    pending = set(buffers)
    while pending:
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'unrelated output deadline')
        ready, _, _ = select.select(list(pending), [], [], remaining)
        require(time.monotonic() < deadline, 'unrelated output deadline')
        require(bool(ready), 'unrelated output deadline')
        for fd in ready:
            raw = os.read(fd, 4097)
            require(time.monotonic() < deadline, 'unrelated output deadline')
            if not raw: pending.remove(fd); continue
            buffers[fd].extend(raw)
            require(len(buffers[fd]) <= 4096, 'unrelated output exceeded capture bound')
    require(time.monotonic() < deadline, 'unrelated output deadline')
    return bytes(buffers[stdout]), bytes(buffers[stderr])


def protocol(root, jail, endpoint):
    sys.path.insert(0, '/opt/uas')
    for name in tuple(sys.modules):
        if name == 'uas' or name.startswith('uas.'): del sys.modules[name]
    from uas.forge import ForgeBinding
    from uas.git_controller import GitCheckout, serve_one
    from uas.git_policy import GitIdentity
    from uas.git_process import GitChildAuthority, GitSeat, parse_status
    from uas.git_provenance import GitProvenance
    from uas.git_service import decode, send
    from uas.kernel_origin import OriginDenied, _identity, alive, receive
    from uas.ledger import LedgerError, Origin
    from uas.room_probe import DENIED_HELP_READY, DENIED_HELP_RELEASE, DENIED_HELP_SETUP_SECONDS
    from uas.workstation_exec import EndpointLease, ExecLaunch, ExecSeat
    room = load_source('room_protocol_actual_service', Path('/opt/uas/room_service.py'))
    # Explicit path relocation only. Broker confinement/handshake remain real.
    room.BROKER_ROOT = root / 'brokers'
    helper = helpers()
    class Bootstrap(ExecLaunch):
        def _create_spec(self): return recipe()
    private = root / 'supervisor'; private.mkdir(mode=0o700)
    engine = BootstrapEngine(jail, helper)
    broker = launch = authority = held = provenance = listener = None
    sibling = None
    pipe_fds = set()
    backend_fd = -1
    active = True
    lock = threading.RLock()
    checks = {'native_qualification': False, 'stage': 'start', 'worker_starts': 0}
    failure = None
    def current():
        if not active or launch.origin.revoked or not alive(launch.origin.pidfd):
            raise OriginDenied('hosted Room bootstrap no longer current')
        return True
    def resources():
        lease.require(); broker.require()
    def no_worker(_origin):
        checks['worker_starts'] += 1
        raise OriginDenied('native workers disabled in Room fixture')
    def no_run(_origin, _checkout): raise LedgerError('ROOM_FIXTURE_HELP_ONLY')
    def close_pipe(fd):
        if fd in pipe_fds:
            pipe_fds.remove(fd)  # Never retry an uncertain descriptor close.
            os.close(fd)
    def control(expected, *, bind=False):
        nonlocal held
        with receive(launch.channel) as record:
            launch.origin.require(record)
            value = decode(record.data)
            require(value == expected if expected is not None else value.get('kind') == 'HELD_BOOTSTRAP',
                    'authenticated Room control differs')
            if bind:
                with lock:
                    held = authority.bind(record)
                    held.require(record)
            return value
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        path = endpoint / 'request.sock'
        listener.bind(str(path)); os.chown(path, 0, UID); path.chmod(0o620); listener.listen(4)
        lease = EndpointLease(path, owner=0, group=UID)
        binding, instance = ForgeBinding('alpha', 'alpha', 'owner/repo'), 'hosted-room-protocol'
        broker = room.BrokerProcess(binding, instance)
        checks['broker'] = broker.observe()
        seat = ExecSeat('alpha', instance, 'fixture-participant', 'fixture-actor', 'seat-a', CONTAINER, UID, UID)
        launch = Bootstrap(engine, seat, lease, private / 'bootstrap.json', timeout=5)
        checks['stage'] = 'bootstrap'
        launch.launch(listener)
        observation = control(None)
        require(observation['uid'] == observation['gid'] == UID
                and observation['peer_credentials'] == [os.getpid(), 0, 0], 'hosted peer credentials differ')
        descriptor = os.pidfd_open(os.getpid())
        try: require(observation['peer_identity'] == list(_identity(descriptor)), 'actual Supervisor pidfd differs')
        finally: os.close(descriptor)
        pid = launch.origin.credentials[0]
        namespace = tuple((node.st_dev, node.st_ino) for node in
                          (os.stat(f'/proc/{pid}/ns/pid'), os.stat(f'/proc/{pid}/ns/user')))
        depth = len(parse_status(Path(f'/proc/{pid}/status').read_bytes())['NSpid'])
        origin = Origin('fixture-actor', 'fixture-participant', launch.incarnation, 'fixture-epoch', ('git-read',))
        authority = room.ObservedAuthority(GitChildAuthority((GitSeat(origin, launch.origin, current, namespace, depth),)),
                                           checks, resources)
        provenance = GitProvenance(private / 'provenance.db', 'alpha', 'alpha')
        metadata = private / 'metadata'; metadata.mkdir(mode=0o700)
        checkout = GitCheckout('fixture', '/', str(metadata), str(metadata), str(metadata / 'config'),
                               str(metadata / 'helpers'), UID)
        backend_fd, digest = room.fixed_executable('/usr/bin/git')
        service = room.RoomHelpOnlyCoordinator(binding, instance,
            {'fixture-actor': GitIdentity('fixture-actor', 'Fixture', 'fixture@example.invalid')},
            (checkout,), provenance, broker.client, no_worker, backend_fd=backend_fd, backend_sha256=digest,
            lifecycle_lock=lambda: lock, run_scope=no_run)
        with lock:
            current(); resources(); send(launch.channel, {'kind': 'PROVE_HELP_ONLY'})
        for index in range(2):
            checks['stage'] = 'help' if index == 0 else 'nonhelp'
            ready, _, _ = select.select([listener, launch.channel], [], [], 3)
            if launch.channel in ready:
                with receive(launch.channel) as record:
                    launch.origin.require(record)
                    diagnostic = decode(record.data)
                if (type(diagnostic) is dict and set(diagnostic) == {'kind', 'stage', 'error_type'}
                        and diagnostic['kind'] == 'BOOTSTRAP_FAILED'
                        and all(type(diagnostic[key]) is str and len(diagnostic[key]) <= 64
                                for key in ('stage', 'error_type'))):
                    checks['bootstrap_failure'] = diagnostic
                    send(launch.channel, {'kind': 'BOOTSTRAP_FAILURE_RECORDED'})
                raise AssertionError('bootstrap ended before mounted request')
            require(listener in ready and launch.channel not in ready, 'bootstrap ended before mounted request')
            listener.settimeout(3)
            channel, _ = listener.accept()
            with channel:
                reply = serve_one(channel, service, authority, lifecycle_lock=lambda: lock)
                room.require_help_reply(reply, checks, index)
        control({'kind': 'HELP_ONLY_PROVED'}, bind=True)
        checks['stage'] = 'same_uid_unrelated'
        # A fresh interpreter imports the actual probe and launcher before its
        # diagnostic-only barrier. Readiness never substitutes for SCM_PIDFD.
        def pipe():
            pair = os.pipe2(os.O_CLOEXEC); pipe_fds.update(pair); return pair
        go_r, go_w = pipe(); out_r, out_w = pipe(); err_r, err_w = pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.dup2(go_r, 0, inheritable=True); os.dup2(out_w, 1, inheritable=True)
                os.dup2(err_w, 2, inheritable=True)
                os.chroot(jail); os.chdir('/')
                helper.close_fds_except(set()); helper.isolate(UID)
                os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I',
                    '/opt/uas/uas/room_probe.py', 'denied-help-ready'],
                    {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
            except BaseException:
                import traceback
                traceback.print_exc(); os._exit(125)
        sibling = helper.OwnedChild(pid)
        for fd in (go_r, out_w, err_w): close_pipe(fd)
        for fd in (out_r, err_r): os.set_blocking(fd, False)
        read_probe_ready(listener, out_r, err_r, sibling, DENIED_HELP_READY,
                         time.monotonic() + DENIED_HELP_SETUP_SECONDS)
        checks['unrelated_readiness'] = {'observed': True, 'role': 'DIAGNOSTIC_ONLY_NOT_AUTHORITY'}
        with lock:
            current(); resources(); held.current(); broker.require()
            require(sibling.observation() is None, 'ready unrelated task already exited')
            probe_status = parse_status(Path(f'/proc/{pid}/status').read_bytes())
            require(probe_status['Uid'] == probe_status['Gid'] == (UID,) * 4,
                    'fresh unrelated probe credentials differ')
            fresh_fd, fresh_digest = room.fixed_executable('/usr/bin/git')
            try:
                old, fresh = os.fstat(backend_fd), os.fstat(fresh_fd)
                require((old.st_dev, old.st_ino) == (fresh.st_dev, fresh.st_ino)
                        and fresh_digest == digest, 'retained backend changed before probe release')
            finally: os.close(fresh_fd)
            # Recheck after executable observation and through the single G write.
            current(); resources(); held.current(); broker.require()
            require(os.write(go_w, DENIED_HELP_RELEASE) == 1, 'probe release incomplete')
            close_pipe(go_w)
        listener.settimeout(5)
        channel, _ = listener.accept()
        with channel: denied = serve_one(channel, service, authority, lifecycle_lock=lambda: lock)
        stdout, stderr = collect_probe_output(out_r, err_r, time.monotonic() + 5)
        require(denied is None and json.loads(stdout) == {'code': 128}
                and DENIED_HELP_READY not in stderr, 'fresh same-UID task was not refused cleanly')
        deadline = time.monotonic() + 2
        while sibling.observation() is None and time.monotonic() < deadline: time.sleep(.005)
        require(sibling.observation() is not None, 'unrelated task exit not observed')
        sibling.finish(success=True)
        checks['unrelated_fresh_exec'] = True
        checks['unrelated_refusal'] = checks.pop('authority_failure')
        require(checks['unrelated_refusal']['phase'] == 'lineage', 'unrelated refused outside ancestry check')
        with lock:
            current(); resources(); held.current(); broker.require()
            send(launch.channel, {'kind': 'RELEASE_WORKLOAD'})
        control({'kind': 'WORKLOAD_STARTED'})
        checks['stage'] = 'held_exit'
        send(launch.channel, {'kind': 'EXIT'})
        poll = select.poll(); poll.register(launch.origin.pidfd, select.POLLIN)
        require(poll.poll(2000) and not alive(launch.origin.pidfd), 'held bootstrap exit missing')
        with lock:
            try: held.current()
            except OriginDenied: pass
            else: raise AssertionError('exited held bootstrap remained current')
        checks['exited_refusal'] = checks.pop('authority_failure')
        engine.child.finish(success=True)
        require(checks['worker_starts'] == 0, 'Room help unexpectedly started native worker')
        checks.update(status='passed', stage='complete', mounted_real_help=True, non_help_refused=True,
            same_uid_unrelated_task_refused=True, held_bootstrap_exit_observed=True,
            exited_authority_refused=True, same_live_private_broker_rechecked=True,
            engine='OWNED_PROCESS_ADAPTER_NOT_DOCKER', namespaces='SAME_PRIVATE_PID_AND_HOST_USER_NAMESPACE',
            selinux='NOT_TESTED', quota='NOT_TESTED', network_policy='NOT_TESTED',
            room_manifest_and_full_endpoint='NOT_TESTED', docker_tcg_startup='NOT_TESTED',
            remapped_container='NOT_TESTED', native_git_worker_enabled=False, credentials_created=False)
    except BaseException as error:
        failure = error
        checks.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        active = False
        errors = []
        def dispose(name, action):
            try: action()
            except BaseException as error: errors.append({'owner': name, 'error_type': type(error).__name__})
        for name, owner in (('binding', held), ('authority', authority), ('launch', launch),
                            ('provenance', provenance), ('broker', broker), ('listener', listener)):
            if owner is not None: dispose(name, owner.close)
        for fd in tuple(pipe_fds): dispose('probe_pipe', lambda fd=fd: close_pipe(fd))
        if sibling is not None: dispose('sibling', sibling.finish)
        dispose('engine', engine.close)
        if backend_fd >= 0: dispose('backend', lambda: os.close(backend_fd))
        checks['cleanup_errors'] = errors
        if failure is not None or errors:
            checks['status'] = 'failed'
            print(json.dumps(checks, sort_keys=True), flush=True)
        if errors and failure is None: raise AssertionError('Room protocol cleanup incomplete')
    print(json.dumps(checks, sort_keys=True), flush=True)


def namespace(root):
    helper = helpers(); smoke = helper.helpers(); smoke.gate()
    require(os.getpid() == 1 and root.parent == Path('/tmp') and root.name.startswith('uas-room-protocol-')
            and root.resolve() == root and root.is_dir() and root.stat().st_uid == 0
            and stat.S_IMODE(root.stat().st_mode) == 0o700, 'owned private fixture root required')
    require(signal.getsignal(signal.SIGCHLD) is signal.SIG_DFL, 'exclusive child reaping required')
    remaining = float(os.environ[DEADLINE]) - time.monotonic()
    require(0 < remaining <= LIMIT_SECONDS, 'Room protocol deadline expired')
    def expired(*_): raise TimeoutError('Room protocol deadline exceeded')
    signal.signal(signal.SIGALRM, expired); signal.alarm(max(1, int(remaining)))
    jail, endpoint = stage(root, smoke)
    pid = os.fork()
    if pid == 0:
        try:
            require(os.getpid() != 1 and os.getppid() == 1, 'live namespace parent required')
            protocol(root, jail, endpoint)
            sys.stdout.flush(); sys.stderr.flush()
        except BaseException:
            import traceback
            traceback.print_exc(); os._exit(125)
        os._exit(0)
    child = helper.OwnedChild(pid)
    try:
        while child.observation() is None: time.sleep(.01)
        child.finish(success=True)
    finally: child.finish()


def main():
    helper = helpers(); helper.helpers().gate()
    if len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2])); return
    require(len(sys.argv) == 1, 'no caller-selected Room fixture execution')
    with tempfile.TemporaryDirectory(prefix='uas-room-protocol-', dir='/tmp') as temporary:
        env = {'PATH': '/usr/bin:/bin', 'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
               'PYTHONDONTWRITEBYTECODE': '1', DEADLINE: str(time.monotonic() + LIMIT_SECONDS)}
        result = subprocess.run(['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork',
            '--kill-child=KILL', '--mount-proc', sys.executable, str(Path(__file__).resolve()),
            '--namespace', temporary], env=env, timeout=27, check=False)
        require(result.returncode == 0, 'hosted Room protocol seam failed')


if __name__ == '__main__': main()
