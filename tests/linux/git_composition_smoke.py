#!/usr/bin/env python3
"""Hosted-only public Git -> concrete Supervisor -> actual worker composition.

The Engine adapter below owns real connector processes, not Docker containers.
Thus this qualifies the callable composition/cleanup seam, NOT an Engine/image
ABI, Room admission, deployment, provider or live GitHub. No credentials exist.
All mounts and ownership changes are inside a private namespace/temp tree;
even /uas is created only in a staged chroot, never in the host filesystem.
Importing is effect-free. Independent review is required before hosted use.
"""
import ctypes
import errno
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
DEADLINE = 'UAS_GIT_COMPOSITION_DEADLINE'
CONTAINER = 'a' * 64


def require(value, message):
    if not value: raise AssertionError(message)


def helpers():
    spec = importlib.util.spec_from_file_location('uas_composition_helpers', Path(__file__).with_name('git_smoke.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_root(root, smoke):
    """Only fixed paths in this disposable namespace; no host /uas creation."""
    smoke.command('/usr/bin/mount', '-o', 'remount,rw,nosuid,nodev', '/opt')
    try:
        runtime = Path('/opt/uas/runtime/git')
        runtime.mkdir(parents=True, mode=0o755)
        shutil.copyfile(ROOT / 'runtime/git/worker.py', runtime / 'worker.py')
        (runtime / 'worker.py').chmod(0o444)
        subprocess.run(['/usr/bin/cc', '-O2', '-Wall', '-Wextra', '-Werror', '-o',
            '/opt/uas/bin/git-worker-connector', str(ROOT / 'runtime/workstation/git_worker_connector.c')],
            check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4)
        Path('/opt/uas/bin/git-worker-connector').chmod(0o555)
    finally:
        smoke.command('/usr/bin/mount', '-o', 'remount,ro,nosuid,nodev', '/opt')
    jail = root / 'jail'
    jail.mkdir(mode=0o755)
    for name in ('opt', 'proc', 'dev', 'tmp', 'uas', 'etc'):
        (jail / name).mkdir(mode=0o755)
    (jail / 'tmp').chmod(0o1777)
    for name in ('usr', 'bin', 'lib', 'lib64'):
        source, target = Path('/') / name, jail / name
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        elif source.is_dir():
            target.mkdir(mode=0o755)
            smoke.command('/usr/bin/mount', '--bind', str(source), str(target))
            smoke.command('/usr/bin/mount', '-o', 'remount,bind,ro,nosuid,nodev', str(target))
    for name in ('opt', 'proc'):
        # /proc is already the private PID namespace's view. Recursive /opt
        # preserves its independently read-only config/pointer/hook mounts.
        smoke.command('/usr/bin/mount', '--rbind', '/' + name, str(jail / name))
    (jail / 'dev/null').touch()
    smoke.command('/usr/bin/mount', '--bind', '/dev/null', str(jail / 'dev/null'))
    inside = jail / root.relative_to('/')
    inside.mkdir(parents=True, mode=0o755)
    (inside / 'project-parent').mkdir(mode=0o755)
    smoke.command('/usr/bin/mount', '--rbind', str(root / 'project-parent'), str(inside / 'project-parent'))
    # No inherited host directory FDs are passed across this chroot boundary.
    (jail / 'uas/workspace').mkdir(mode=0o755)
    (jail / 'uas/git').mkdir(mode=0o710)
    os.chown(jail / 'uas/git', 0, 65532)
    (jail / 'uas/git').chmod(0o710)
    return jail


def close_fds_except(keep):
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd <= 2 or fd in keep: continue
        try: os.close(fd)
        except OSError as error:
            if error.errno != errno.EBADF: raise


def isolate(uid):
    """Fixture-only AF_UNIX bootstrap profile, not a production image claim."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    libc.prctl.restype = ctypes.c_int
    def prctl(option, argument):
        require(libc.prctl(option, argument, 0, 0, 0) == 0, 'fixture privilege reduction failed')
    for cap in range(int(Path('/proc/sys/kernel/cap_last_cap').read_text()) + 1): prctl(24, cap)
    os.setgroups([]); os.setgid(65532); os.setuid(uid); prctl(38, 1)
    class Compare(ctypes.Structure):
        _fields_ = [('argument', ctypes.c_uint), ('operation', ctypes.c_int),
                    ('left', ctypes.c_uint64), ('right', ctypes.c_uint64)]
    sec = ctypes.CDLL('libseccomp.so.2')
    sec.seccomp_init.argtypes = (ctypes.c_uint32,); sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,); sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
    sec.seccomp_rule_add_array.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                          ctypes.c_uint, ctypes.POINTER(Compare))
    sec.seccomp_rule_add_array.restype = ctypes.c_int
    sec.seccomp_load.argtypes = (ctypes.c_void_p,); sec.seccomp_load.restype = ctypes.c_int
    sec.seccomp_release.argtypes = (ctypes.c_void_p,)
    context = sec.seccomp_init(0x7fff0000)
    require(context, 'fixture seccomp unavailable')
    try:
        def deny(name, condition=None):
            number = sec.seccomp_syscall_resolve_name(name.encode())
            require(number >= 0 and sec.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM,
                number, int(condition is not None), ctypes.byref(condition) if condition is not None else None) == 0,
                'fixture syscall constraint unavailable')
        for name in ('socket', 'socketpair'):
            deny(name, Compare(0, 1, socket.AF_UNIX, 0))  # SCMP_CMP_NE.
        for name in ('mount', 'umount2', 'pivot_root', 'chroot', 'unshare', 'setns', 'ptrace', 'bpf',
                     'perf_event_open', 'kexec_load', 'init_module', 'finit_module', 'delete_module',
                     'reboot', 'open_by_handle_at', 'fsopen', 'fsmount', 'move_mount', 'mount_setattr',
                     'process_vm_writev'):
            deny(name)
        require(sec.seccomp_load(context) == 0, 'fixture seccomp installation failed')
    finally:
        sec.seccomp_release(context)
    os.umask(0o002)
    for domain in (socket.AF_INET, socket.AF_INET6):
        try: channel = socket.socket(domain, socket.SOCK_STREAM)
        except PermissionError: continue
        channel.close()
        raise AssertionError('external socket domain available')


class OwnedChild:
    def __init__(self, pid): self.pid, self.owned = pid, True

    def observation(self):
        require(self.owned, 'fixture child already released')
        try: return os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            self.owned = False
            raise AssertionError('fixture child ownership uncertain') from None

    def finish(self, *, success=False):
        if not self.owned: return
        observed = self.observation()
        if observed is None:
            try: os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        self.owned = False  # Never signal this number again after wait begins.
        _, status = os.waitpid(self.pid, 0)
        if success: require(os.waitstatus_to_exitcode(status) == 0, 'owned fixture child failed')


class FixtureTransport:
    def __init__(self, descriptor): self.fd = descriptor
    def write(self, data, *, timeout):
        require(self.fd >= 0 and len(data) == 32 and select.select([], [self.fd], [], timeout)[1],
                'fixture challenge pipe unavailable')
        require(os.write(self.fd, data) == len(data), 'fixture challenge incomplete')
    def close(self):
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            os.close(fd)


class FixtureEngine:
    """Real owned child behind the existing narrow Engine create/start/inspect."""
    def __init__(self, jail):
        self.jail, self.records, self.fail_next = jail, {}, False
    def create(self, container, spec):
        require(container == CONTAINER and spec == {'AttachStdin': True, 'AttachStdout': True,
            'AttachStderr': True, 'Tty': False, 'Privileged': False, 'User': '65530:65532',
            'WorkingDir': '/uas/workspace', 'Cmd': ['/opt/uas/bin/git-worker-connector', 'seat-a'], 'Env': []},
            'fixed Git Engine recipe differs')
        for record in self.records.values():
            if record.get('child') is not None and record['child'].owned:
                require(record['child'].observation() is not None, 'new worker overlapped a live owned worker')
        identifier = format(len(self.records) + 1, '064x')
        self.records[identifier] = {}
        return identifier
    def start(self, identifier):
        read, write = os.pipe2(os.O_CLOEXEC)
        try:
            pid = os.fork()
        except BaseException:
            os.close(read); os.close(write); raise
        if pid == 0:
            try:
                os.close(write); os.dup2(read, 0, inheritable=True)
                os.chroot(self.jail); os.chdir('/uas/workspace')
                close_fds_except(set())
                isolate(65530)
                os.execve('/opt/uas/bin/git-worker-connector',
                    ['/opt/uas/bin/git-worker-connector', 'seat-a'], {'PATH': '/usr/bin:/bin'})
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(125)
        os.close(read)
        transport = FixtureTransport(write)
        self.records[identifier] = {'child': OwnedChild(pid), 'transport': transport}
        if self.fail_next:
            self.fail_next = False
            # Actual connector exists but no challenge/release/config was sent.
            # This deliberately models an uncertain Engine start response.
            from uas.workstation_exec import ExecUnavailable
            raise ExecUnavailable('fixture injected uncertain owned start')
        return transport
    def inspect(self, identifier):
        child = self.records[identifier]['child']
        return {'ID': identifier, 'ContainerID': CONTAINER,
                'Running': child.observation() is None, 'Pid': child.pid}
    def close(self):
        failures = []
        for record in self.records.values():
            for name, method in (('transport', 'close'), ('child', 'finish')):
                if name in record:
                    try: getattr(record[name], method)()
                    except BaseException as error: failures.append(error)
        if failures: raise AssertionError('fixture Engine cleanup uncertain') from failures[0]


def participant(channel, jail, worktree):
    os.chroot(jail); os.chdir(worktree)
    close_fds_except({channel.fileno()})
    isolate(65532)
    channel.send(b'participant-ready')
    (worktree / 'composition.txt').write_text('controlled composition body\n')
    while True:
        raw = channel.recv(4096)
        if raw == b'exit': return
        require(raw, 'fixture Participant control disconnected')
        request = json.loads(raw)
        require(set(request) == {'entry', 'argv'} and request['entry'] in {'git', 'git-add', 'git-commit', 'git-status'},
                'fixed fixture public invocation required')
        result = subprocess.run(['/opt/uas/bin/' + request['entry'], *request['argv']],
            env={'PATH': '/opt/uas/bin:/usr/bin:/bin', 'HOME': '/tmp', 'LC_ALL': 'C',
                 'GIT_AUTHOR_NAME': 'FORGED', 'GIT_AUTHOR_EMAIL': 'forged@example.invalid',
                 'GIT_EXEC_PATH': '/usr/lib/git-core'}, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        require(len(result.stdout) + len(result.stderr) <= 65536, 'fixture public output bound')
        channel.send(json.dumps({'code': result.returncode, 'stdout': result.stdout.decode(errors='replace'),
                                 'stderr': result.stderr.decode(errors='replace')}).encode())


def connected_checks(root, jail, worktree, digest):
    sys.path.insert(0, '/opt/uas')
    for name in tuple(sys.modules):
        if name == 'uas' or name.startswith('uas.'): del sys.modules[name]
    from uas.forge import ForgeBinding
    from uas.git_controller import GitCheckout
    from uas.git_policy import GitIdentity
    from uas.git_process import GitSeat, parse_status
    from uas.git_provenance import GitProvenance
    from uas.git_supervisor import GitSupervisor
    from uas.kernel_origin import HeldOrigin, enable, receive
    from uas.ledger import Origin
    from uas.workstation_exec import EndpointLease, ExecSeat, ExecUnavailable
    smoke = helpers()
    private = root / 'supervisor'
    private.mkdir(mode=0o700)
    journal = private / 'launches'
    journal.mkdir(mode=0o700)
    listeners, endpoints = [], []
    for name in ('request.sock', 'worker.sock'):
        path = jail / 'uas/git' / name
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.bind(str(path)); os.chown(path, 0, 65532); path.chmod(0o620)
        listener.listen(8); listeners.append(listener)
        endpoints.append(EndpointLease(path, owner=0, group=65532))
    control, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    enable(control); control.settimeout(10)
    child = origin = service = store = None
    engine = FixtureEngine(jail)
    try:
        pid = os.fork()
        if pid == 0:
            try:
                control.close()
                participant(child_channel, jail, worktree)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(125)
            os._exit(0)
        child = OwnedChild(pid); child_channel.close()
        with receive(control) as record:
            require(record.data == b'participant-ready' and record.credentials == (pid, 65532, 65532),
                    'actual Participant binding differs')
            origin = HeldOrigin(record)
        namespace = tuple((node.st_dev, node.st_ino) for node in
                          (os.stat(f'/proc/{pid}/ns/pid'), os.stat(f'/proc/{pid}/ns/user')))
        depth = len(parse_status(Path(f'/proc/{pid}/status').read_bytes())['NSpid'])
        actor = Origin('actor-a', 'seat-a', 'fixture-incarnation', 'epoch1', ('git-read', 'git-push'))
        seat = GitSeat(actor, origin, lambda: True, namespace, depth)
        worker_seat = ExecSeat('fixture-room', 'fixture-instance', 'seat-a', 'actor-a', 'seat-a',
                               CONTAINER, 65530, 65532)
        store = GitProvenance(private / 'provenance.db', 'fixture-room', 'fixture-project')
        paths = smoke.view_paths()
        checkout = GitCheckout('primary', str(worktree), paths['gitdir'], paths['common'], paths['config'],
                               paths['helpers'], 65532)
        class NoRemote:
            def relay(self, *_args, **_kwargs): raise AssertionError('remote Git is outside this fixture')
        lock = threading.RLock()
        service = GitSupervisor(ForgeBinding('fixture-room', 'fixture-project', 'owner/repo'),
            'fixture-instance', {'actor-a': GitIdentity('actor-a', 'Actor A', 'actor-a@example.invalid')},
            (checkout,), store, NoRemote(), engine, (seat,), (worker_seat,), request_listener=listeners[0],
            worker_listener=listeners[1], request_endpoint=endpoints[0], worker_endpoint=endpoints[1],
            journal_dir=journal, backend_fd=19, backend_sha256=digest,
            lifecycle_lock=lambda: lock, run_scope=lambda _origin, _checkout: {'run_id': 'fixture-run', 'generation': 1})
        def invoke(entry, argv, *, expected=0, uncertain=False):
            control.send(json.dumps({'entry': entry, 'argv': argv}).encode())
            result = None
            try: result = service.serve_next(timeout=3)
            except ExecUnavailable as error:
                require(uncertain and str(error) == 'fixture injected uncertain owned start', 'unexpected launch failure')
            response = json.loads(control.recv(65536))
            require(response['code'] == expected, 'public invocation failed: ' + response['stderr'][-1000:])
            return result, response
        added, _ = invoke('git-add', ['--', 'composition.txt'])
        require(added['status'] == 'OK' and store.pending_worker('primary') is None, 'add cleanup not durable')
        committed, output = invoke('git-commit', ['-m', 'composition commit'])
        receipt = committed['receipt']
        require(committed['status'] == 'COMMITTED' and receipt['status'] == 'COMMITTED'
                and receipt['contributors'] == ['actor-a'] and receipt['provenance'] == 'controlled-command'
                and len(receipt['commit_oid']) == 40 and 'FORGED' not in output['stdout']
                and store.pending_worker('primary') is None, 'canonical controlled receipt differs')
        follow, _ = invoke('git-status', ['--short'])
        require(follow['status'] == 'OK' and store.pending_worker('primary') is None, 'next command overlapped cleanup')
        # Actual owned connector is still alive after an intentionally uncertain
        # start. A second public call must refuse before another Engine create.
        engine.fail_next = True
        invoke('git-status', ['--short'], expected=128, uncertain=True)
        pending = store.pending_worker('primary')
        require(pending is not None, 'uncertain native launch lost its durable fence')
        count = len(engine.records)
        require(engine.records[format(count, '064x')]['child'].observation() is None,
                'uncertain-start child exited before overlap-fence observation')
        refused, output = invoke('git-status', ['--short'], expected=128)
        require(refused is None and 'GIT_WORKER_QUIESCENCE_UNKNOWN' in output['stderr']
                and len(engine.records) == count and store.pending_worker('primary') == pending,
                'unverified worker permitted a replacement')
        rows = store._connection().execute('SELECT evidence FROM worker_finishes').fetchall()
        require(len(rows) == 3 and all(json.loads(row[0])['quiescent'] is True
                and json.loads(row[0])['exited'] is True for row in rows), 'actual worker cleanup evidence missing')
        require(len({tuple(json.loads(row[0])['worker_identity']) for row in rows}) == 3,
                'cleanup proof reused another worker')
        control.send(b'exit')
        deadline = time.monotonic() + 2
        while child.observation() is None and time.monotonic() < deadline: time.sleep(.005)
        require(child.observation() is not None, 'Participant did not exit')
        child.finish(success=True)
        print(json.dumps({'public_launcher_to_supervisor_worker': 'PASS', 'canonical_commit_receipt': receipt,
            'worker_quiescence_then_pidfd_exit': 'PASS', 'next_command_after_cleanup': 'PASS',
            'uncertain_owned_start_replacement': 'DENIED', 'kernel_participant_ancestry': 'PASS',
            'fixed_connector_challenge_and_scm_rights': 'PASS', 'engine': 'OWNED_PROCESS_FIXTURE_NOT_DOCKER',
            'public_paths_exercised': ['/opt/uas/bin/git-add', '/opt/uas/bin/git-commit', '/opt/uas/bin/git-status'],
            'installed_all_public_paths_image_readiness': 'NOT_TESTED',
            'image_abi_admission': 'NOT_TESTED', 'room_lifecycle': 'NOT_TESTED', 'active_native_cancel': 'NOT_TESTED',
            'external_broker': 'NOT_TESTED', 'live_github': 'NOT_TESTED', 'credentials_created': False}), flush=True)
    finally:
        failures = []
        def dispose(function):
            try: function()
            except BaseException as error: failures.append(error)
        if service is not None: dispose(service.close)
        dispose(control.close); dispose(child_channel.close)
        if child is not None: dispose(child.finish)
        dispose(engine.close)
        if origin is not None: dispose(origin.close)
        if store is not None: dispose(store.close)
        for listener in listeners: dispose(listener.close)
        if failures: raise AssertionError('composition fixture cleanup uncertain') from failures[0]


def owned_supervisor(root, jail, worktree, digest):
    """PID1 owns/reaps one Supervisor child; it is not the Supervisor itself.

    The unmodified kernel probe requires a known live parent. Keep namespace
    init alive for that proof, retaining the outer absolute deadline and
    kill-child namespace cleanup rather than weakening production admission.
    """
    require(os.getpid() == 1, 'fixture namespace init must own Supervisor')
    pid = os.fork()
    if pid == 0:
        try:
            require(os.getpid() != 1 and os.getppid() == 1,
                    'Supervisor requires its live owned namespace parent')
            connected_checks(root, jail, worktree, digest)
            sys.stdout.flush(); sys.stderr.flush()
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(125)
        os._exit(0)
    child = OwnedChild(pid)
    try:
        while child.observation() is None:
            time.sleep(.01)  # PID1's absolute SIGALRM deadline remains active.
        child.finish(success=True)
    finally:
        child.finish()  # Only this unreaped child; never adopt a numeric PID.


def namespace(root):
    smoke = helpers(); smoke.gate()
    require(signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, ()),
            'unblocked composition deadline required')
    require(os.getpid() == 1 and root.parent == Path('/tmp') and root.name.startswith('uas-git-composition-')
            and root.resolve() == root and root.is_dir() and root.stat().st_uid == 0
            and stat.S_IMODE(root.stat().st_mode) == 0o700, 'private namespace fixture root required')
    require(signal.getsignal(signal.SIGCHLD) is signal.SIG_DFL, 'exclusive child reaper required')
    remaining = float(os.environ[DEADLINE]) - time.monotonic()
    require(0 < remaining <= 40, 'composition deadline expired')
    def expired(*_): raise TimeoutError('composition fixture deadline exceeded')
    signal.signal(signal.SIGALRM, expired); signal.alarm(max(1, int(remaining)))
    worktree, _home = smoke.provision(root)
    jail = private_root(root, smoke)
    digest = smoke.sealed_backend()
    try: owned_supervisor(root, jail, worktree, digest)
    finally: os.close(19)


def main():
    smoke = helpers(); smoke.gate()
    if len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2])); return
    require(len(sys.argv) == 1, 'no caller-selected fixture execution')
    with tempfile.TemporaryDirectory(prefix='uas-git-composition-', dir='/tmp') as temporary:
        env = {'PATH': '/usr/bin:/bin', 'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
               'PYTHONDONTWRITEBYTECODE': '1', DEADLINE: str(time.monotonic() + 38)}
        result = subprocess.run(['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork',
            '--kill-child=KILL', '--mount-proc', sys.executable, str(Path(__file__).resolve()),
            '--namespace', temporary], env=env, timeout=40, check=False)
        require(result.returncode == 0, 'hosted Git composition fixture failed')


if __name__ == '__main__': main()
