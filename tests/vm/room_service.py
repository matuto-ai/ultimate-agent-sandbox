"""Actual help-only Git endpoint in the fixed disposable Room profile.

The root listener owner itself consumes requests; no forked acceptor changes its
pinned kernel peer. The non-root Broker has a private inherited socket and no
credentials, executable-child capability or network creation. This is not the
native Git worker/RuntimeView profile or the native Pi/Hub topology.
"""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess
import sys
import time

from uas.git_controller import GitCoordinator
from uas.git_policy import parse_git
from uas.ledger import LedgerError

BROKER_UID = 65531
BROKER_ROOT = Path('/var/lib/uas-room-brokers')


class RoomHelpOnlyCoordinator(GitCoordinator):
    """Fixed fixture subset; no native worker or remote provider admission."""
    def request(self, request, authority):
        if type(request) is not dict or parse_git(request.get('invoked_as'), request.get('argv')).kind != 'help':
            raise LedgerError('ROOM_FIXTURE_HELP_ONLY')
        return super().request(request, authority)


def require(value, message):
    if not value: raise RuntimeError(message)


class ObservedAuthority:
    """Fixture-only delegation: retain first denial without changing admission."""
    def __init__(self, delegate, checks):
        self.delegate, self.checks = delegate, checks

    @property
    def origin(self): return self.delegate.origin

    def _call(self, method, *args):
        try: return getattr(self.delegate, method)(*args)
        except Exception as error:
            self.checks.setdefault('authority_failure', {
                'operation': method, 'error_type': type(error).__name__,
                'message': str(error)[:256]})
            raise

    def bind(self, record):
        return ObservedAuthority(self._call('bind', record), self.checks)

    def current(self): return self._call('current')
    def require(self, record): return self._call('require', record)
    def close(self): return self.delegate.close()


def require_help_reply(reply, checks, index):
    """Do not wait for a second request after first help already failed."""
    checks.setdefault('help_replies', []).append(
        None if reply is None else {'code': reply['code'], 'status': reply['status']})
    require((reply is not None and reply['code'] == 0) if index == 0 else reply is None,
            'mounted help refused' if index == 0 else 'non-help unexpectedly admitted')


def fixed_executable(path):
    path = Path(path)
    require(path.as_posix() in ('/usr/bin/git', '/usr/bin/ssh') and path.resolve() == path,
            'fixed canonical signed executable required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        node = os.fstat(descriptor)
        require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and not node.st_mode & 0o022
                and node.st_mode & 0o111 and 0 < node.st_size <= 32 * 1024 * 1024,
                'signed executable inode rejected')
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        return descriptor, digest
    except BaseException:
        os.close(descriptor); raise


def confine_broker():
    """Only the newly forked fixture child; no host policy/capability additions."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    libc.prctl.restype = ctypes.c_int
    def prctl(option, value):
        require(libc.prctl(option, value, 0, 0, 0) == 0, 'Broker privilege reduction failed')
    for cap in range(int(Path('/proc/sys/kernel/cap_last_cap').read_text()) + 1): prctl(24, cap)
    os.setgroups([]); os.setgid(BROKER_UID); os.setuid(BROKER_UID)
    prctl(4, 0); prctl(38, 1)
    sec = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    sec.seccomp_init.argtypes = (ctypes.c_uint32,); sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,); sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
    sec.seccomp_rule_add.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint)
    sec.seccomp_rule_add.restype = ctypes.c_int
    sec.seccomp_load.argtypes = (ctypes.c_void_p,); sec.seccomp_load.restype = ctypes.c_int
    sec.seccomp_release.argtypes = (ctypes.c_void_p,)
    context = sec.seccomp_init(0x7fff0000)
    require(context, 'Broker seccomp unavailable')
    try:
        for name in ('socket', 'socketpair', 'connect', 'execve', 'execveat', 'mount', 'umount2',
                     'pivot_root', 'unshare', 'setns', 'ptrace', 'bpf', 'perf_event_open',
                     'kexec_load', 'init_module', 'finit_module', 'delete_module', 'reboot',
                     'open_by_handle_at', 'fsopen', 'fsmount', 'move_mount', 'mount_setattr',
                     'process_vm_writev'):
            number = sec.seccomp_syscall_resolve_name(name.encode())
            require(number >= 0 and sec.seccomp_rule_add(context, 0x00050000 | errno.EPERM,
                    number, 0) == 0, 'Broker syscall confinement unavailable')
        require(sec.seccomp_load(context) == 0, 'Broker seccomp not installed')
    finally: sec.seccomp_release(context)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    facts = {key: status[key].strip() for key in ('CapEff', 'CapBnd', 'NoNewPrivs', 'Seccomp')}
    require(facts == {'CapEff': '0000000000000000', 'CapBnd': '0000000000000000',
                     'NoNewPrivs': '1', 'Seccomp': '2'}, 'Broker actual confinement differs')
    for family in (socket.AF_INET, socket.AF_INET6):
        try: probe = socket.socket(family, socket.SOCK_STREAM)
        except PermissionError: continue
        probe.close(); raise RuntimeError('Broker can open external socket')
    return facts


class BrokerProcess:
    def __init__(self, binding, instance):
        from uas.forge_audit import ForgeAudit
        from uas.git_audit import GitAudit
        from uas.git_service import ExternalGitBroker, GitBrokerClient, serve
        from uas.git_transport import GitTransportConfig, SshTransport
        from uas.kernel_origin import enable
        require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
                'sole-reaper default SIGCHLD disposition required')
        self.pid = self.pidfd = None
        self.client = None
        self.binding, self.instance = binding, instance
        BROKER_ROOT.mkdir(mode=0o755, exist_ok=True)
        info = BROKER_ROOT.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755,
                'private Broker ancestor differs')
        self.directory = BROKER_ROOT / instance
        self.directory.mkdir(mode=0o700); os.chown(self.directory, BROKER_UID, BROKER_UID)
        descriptor, digest = fixed_executable('/usr/bin/ssh'); os.close(descriptor)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            # Authentication options precede fork and the first possible send;
            # enabling them after an already queued HELLO is too late.
            enable(parent); enable(child)
            self.pid = os.fork()
            if self.pid == 0:
                phase = 'descriptor-isolation'
                try:
                    parent.close()
                    # No Engine, listener, root directory or other private FD
                    # crosses the identity reduction. Sole inherited channel.
                    keep = {0, 1, 2, child.fileno()}
                    for name in os.listdir('/proc/self/fd'):
                        descriptor = int(name)
                        if descriptor not in keep:
                            try: os.close(descriptor)
                            except OSError as error:
                                if error.errno != errno.EBADF: raise
                    phase = 'process-confinement'; confine_broker()
                    phase = 'private-audit'
                    owner = ForgeAudit(self.directory / 'audit.db', 'room-fixture')
                    try:
                        phase = 'pinned-unused-transport'
                        transport = SshTransport(GitTransportConfig('/usr/bin/ssh', digest, ()), binding)
                        broker = ExternalGitBroker(binding, instance, GitAudit(owner), transport)
                        phase = 'private-service'
                        serve(child, broker, supervisor_uid=0, supervisor_gid=0)
                    finally: owner.close()
                except BaseException as error:
                    os.write(2, ('Room Broker failure: ' + json.dumps({'phase':phase,
                        'error_type':type(error).__name__,'errno':getattr(error,'errno',None)}) + '\n').encode())
                    os._exit(1)
                os._exit(0)
            child.close()
            self.pidfd = os.pidfd_open(self.pid)
            self.client = GitBrokerClient(parent, binding, instance, broker_uid=BROKER_UID, broker_gid=BROKER_UID)
            self.require()
        except BaseException:
            parent.close(); child.close(); self.close(); raise

    def require(self):
        from uas.kernel_origin import _identity, alive
        from dataclasses import asdict
        client = self.client
        require(client is not None and not client.closed and client.scope == {
                **asdict(self.binding), 'room_instance': self.instance}
                and not client.worker.revoked and alive(client.worker.pidfd)
                and alive(self.pidfd) and _identity(self.pidfd) == client.worker.identity
                and client.worker.credentials == (self.pid, BROKER_UID, BROKER_UID),
                'same live Room Broker readiness required')
        return True

    def observe(self):
        """Actual retained Broker process facts, not a readiness payload flag."""
        from uas.git_process import ProcView, _Task, _read_at
        self.require()
        view = ProcView()
        try:
            task = _Task(view, self.pid, expected=self.client.worker.identity)
            try:
                raw = Path('/proc/' + str(self.pid) + '/status').read_text()
                require(len(raw) <= 16384, 'Broker kernel observation exceeds bound')
                fields = dict(line.split(':',1) for line in raw.splitlines() if ':' in line)
                facts = {key:fields[key].strip() for key in ('CapEff','CapBnd','NoNewPrivs','Seccomp')}
                require(facts == {'CapEff':'0000000000000000','CapBnd':'0000000000000000',
                                 'NoNewPrivs':'1','Seccomp':'2'}
                        and task.status['Uid'] == task.status['Gid'] == (BROKER_UID,) * 4
                        and task.namespace == view.receiver_namespace, 'actual outside Broker confinement differs')
                process_label = _read_at(task.directory, 'attr/current').decode().rstrip('\0\n')
                task.check(); self.require()
                return {'credentials':list(self.client.worker.credentials), 'kernel_status':facts,
                        'namespaces':task.namespace, 'private_directory':str(self.directory),
                        'process_label':process_label,
                        'credentials_configured':False, 'network_creation_and_exec_denied':True}
            finally: task.close()
        finally: view.close()

    def close(self):
        try:
            if self.client is not None:
                client, self.client = self.client, None
                client.close()
        finally:
            try:
                if self.pid is not None:
                    pid, self.pid = self.pid, None
                    # Sole unreaped child ownership remains until waitpid.
                    if self.pidfd is not None:
                        try: signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                        except ProcessLookupError: pass
                    else:
                        os.kill(pid, signal.SIGKILL)  # Exclusively owned unreaped child.
                    os.waitpid(pid, 0)
            finally:
                if self.pidfd is not None:
                    descriptor, self.pidfd = self.pidfd, None; os.close(descriptor)


def endpoint(room, run):
    from guest_workstation import labeled_listener
    from uas.guest_fixture import ROOMS, WORKSTATION_HOST_UID
    from uas.room_fixture import ENDPOINT_ROOT, SUPERVISOR_UID, RoomEndpoint
    from uas.workstation_exec import EndpointLease
    ENDPOINT_ROOT.mkdir(mode=0o755, exist_ok=True)
    parent = ENDPOINT_ROOT / room
    parent.mkdir(mode=0o711); parent.chmod(0o711)
    directory = parent / 'git'; directory.mkdir(mode=0o710)
    os.chown(directory, SUPERVISOR_UID, WORKSTATION_HOST_UID); directory.chmod(0o710)
    path = directory / 'request.sock'
    listener = labeled_listener(path, WORKSTATION_HOST_UID, level=ROOMS[room][3])
    try:
        run('chcon', '-t', 'container_file_t', '-l', ROOMS[room][3], str(directory))
        lease = EndpointLease(path, owner=SUPERVISOR_UID, group=WORKSTATION_HOST_UID)
        return RoomEndpoint(room, 'git', (listener,), (lease,))
    except BaseException:
        listener.close(); raise


def prove_foreign_listener_admission(supervisor, endpoint_, probe, *, run, checks, diagnostic):
    """Trusted-root admission/drift negative after bootstrap and service exit.

    Keep every original socket object/inode; replace only the pathname during
    this locked negative, with an owned disposable socket. Its pathname label
    stays Alpha while its kernel socket SID is Beta. No service/workload is
    admitted until exact restoration succeeds. Raw transport is observational:
    trusted-host pathname tampering is outside the Participant threat boundary.
    Canonical admission must reject the foreign listener, regardless of connect.
    This is not a policy repair or a claim of independent socket-SID denial.
    """
    from guest_boundary import require_process_label
    from guest_workstation import labeled_listener
    from uas.guest_fixture import ROOMS, WORKSTATION_HOST_UID
    from uas.lifecycle import LifecycleError
    from uas.room_fixture import RoomEndpoint, SUPERVISOR_UID
    from uas.workstation_exec import EndpointLease, ExecUnavailable
    checks.update(status='in_progress', stage='original_admission')
    require(endpoint_.room == 'alpha' and len(endpoint_.leases) == 1, 'exact Alpha endpoint required')
    with supervisor._locked():
        endpoint_.require()
        lease = endpoint_.leases[0]
        path = lease.path
        original = lease.expected
        checks['original_lease'] = list(original)
        parking = endpoint_.parent.parent / 'git-sid-negative'
        parking.mkdir(mode=0o700)  # Exclusive owned destination; never adopt one.
        saved = parking / 'request.sock'
        foreign = foreign_inode = None
        parked = False
        try:
            checks['stage'] = 'foreign_listener_creation'
            path.rename(saved); parked = True
            foreign = labeled_listener(path, WORKSTATION_HOST_UID, level=ROOMS['beta'][3])
            node = path.lstat(); foreign_inode = (node.st_dev, node.st_ino)
            # Admission denial cannot rely on a Beta pathname: only the socket
            # object carries Beta. Parent, DAC and mounted path stay Alpha.
            run('chcon', '-t', 'container_file_t', '-l', ROOMS['alpha'][3], str(path))
            file_label = os.getxattr(path, 'security.selinux', follow_symlinks=False).rstrip(b'\0').decode()
            checks['pathname_label'] = file_label
            require(file_label == 'system_u:object_r:container_file_t:' + ROOMS['alpha'][3],
                    'foreign-SID negative pathname must remain Alpha')
            try: endpoint_.require()
            except ExecUnavailable: checks['replacement_lease_denied'] = True
            else: raise RuntimeError('replacement socket passed original endpoint lease')
            # SO_PEERSEC reports the accepted connection's SID, whose MLS
            # range SELinux copies from the connecting client. It does NOT
            # measure this listener's original MCS. Query the retained socket
            # descriptor's sockfs inode instead, not its relabeled pathname.
            foreign_label = os.getxattr(foreign.fileno(), 'security.selinux').decode()
            checks.update(socket_object_label=foreign_label,
                          socket_label_source='held-listener-fd-security.selinux')
            require_process_label(foreign_label, ROOMS['beta'][3])
            foreign_label = foreign_label.removesuffix('\0')
            checks['socket_object_label'] = foreign_label
            # A fresh lease must not hide a foreign SID behind the correct DAC,
            # pathname label and inode. Exercise canonical admission itself.
            checks['stage'] = 'foreign_listener_admission'
            fresh = EndpointLease(path, owner=SUPERVISOR_UID, group=WORKSTATION_HOST_UID)
            try: RoomEndpoint('alpha', 'git', (foreign,), (fresh,))
            except LifecycleError as error:
                require(str(error) == 'ROOM_FIXTURE_LISTENER_LABEL',
                        'foreign listener rejected for a different admission invariant')
                checks['fresh_lease_foreign_listener_denied'] = True
            else: raise RuntimeError('foreign listener passed fresh canonical admission')
            checks['stage'] = 'loaded_policy_diagnostic'
            try: checks['policy_diagnostic'] = diagnostic()
            except Exception as error:
                # Read-only policy diagnostics cannot suppress raw observation.
                checks['policy_diagnostic'] = {'status': 'unavailable', 'error_type': type(error).__name__}
            checks['stage'] = 'foreign_socket_observation'
            checks['raw_probe_role'] = 'observational_only'
            checks['raw_probe'] = probe('alpha', 'endpoint')
            raw = checks['raw_probe']
            checks['observed_connect'] = raw.get('decoded')
            # Capture integrity/owned cleanup remain mandatory; no transport
            # outcome is reinterpreted as admission or kernel denial here.
            require(raw.get('returncode') == 0 and raw.get('timeout') is False
                    and raw.get('status') != 'unavailable' and raw.get('cleanup_errors') == []
                    and raw.get('stdout', {}).get('truncated') is False
                    and raw.get('stderr', {}).get('truncated') is False
                    and isinstance(checks['observed_connect'], dict),
                    'foreign listener raw observation incomplete or unclean')
        except BaseException as error:
            checks.update(status='failed', error_type=type(error).__name__)
            raise
        finally:
            cleanup_errors = []
            if foreign is not None:
                try: foreign.close()
                except BaseException as error: cleanup_errors.append(error)
            # An uncertain helper failure never licenses deleting an untracked
            # inode or proceeding with drift. Guest cleanup/VM teardown remains.
            try:
                if parked:
                    if path.exists():
                        node = path.lstat()
                        require(foreign_inode is not None and (node.st_dev, node.st_ino) == foreign_inode,
                                'foreign-SID cleanup ownership uncertain')
                        path.unlink()
                    node = saved.lstat()
                    require((node.st_dev, node.st_ino) == original[2:], 'parked original endpoint changed')
                    saved.rename(path)
                    endpoint_.require()
                    require(lease.expected == original, 'original endpoint lease changed')
                parking.rmdir()
            except BaseException as error: cleanup_errors.append(error)
            if cleanup_errors:
                checks.update(status='failed', cleanup_errors=[type(error).__name__ for error in cleanup_errors])
                raise RuntimeError('foreign-SID negative cleanup failed; no further admission') from cleanup_errors[0]
            checks['original_lease_restored'] = True
        checks.update(status='passed', stage='complete')
        return checks


def observe_unrelated_cli(listener, container, serve, *, checks):
    """Bounded evidence around the existing fixed same-UID negative, not denial.

    Draining output never extends either five-second deadline. Killing this
    owned docker CLI does not prove its daemon-owned container task stopped;
    the caller's exact Room teardown remains mandatory on every failure.
    """
    from room_policy_diagnostics import _output
    started = time.monotonic()
    checks.update(status='in_progress', stage='launch', stage_elapsed_seconds={},
                  connected=False, returncode=None, capture_limit_bytes=4096,
                  timeout_seconds={'accept': 5, 'collect': 5, 'cleanup': 5})
    buffers = {name: bytearray() for name in ('stdout', 'stderr')}
    counts = {name: 0 for name in buffers}
    eof = {name: False for name in buffers}
    streams = {}
    process = None
    failure = None
    def stage(name):
        checks['stage'] = name
        checks['stage_elapsed_seconds'][name] = round(time.monotonic() - started, 6)
    def drain(ready):
        for stream in ready:
            if stream not in streams: continue
            name = streams[stream]
            try: data = os.read(stream.fileno(), 65536)
            except BlockingIOError: continue
            if not data:
                eof[name] = True
                del streams[stream]
                continue
            counts[name] += len(data)
            buffers[name].extend(data[:max(0, 4096 - len(buffers[name]))])
    def collect(deadline):
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('unrelated CLI output deadline')
            ready, _, _ = select.select(list(streams), [], [], remaining)
            drain(ready)
    try:
        stage('launch')
        process = subprocess.Popen(['docker', 'exec', container, '/usr/bin/python3', '-I',
            '/opt/uas/uas/room_probe.py', 'denied-help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        checks['pid'] = process.pid  # Diagnostic CLI PID, never request authority.
        stage('pipe_setup')
        for name in buffers:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            streams[stream] = name
        stage('accept')
        deadline = time.monotonic() + 5
        listener.settimeout(5)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('unrelated CLI connection deadline')
            ready, _, _ = select.select([listener, *streams], [], [], remaining)
            drain(ready)
            if listener in ready:
                # Recheck the same deadline after draining; never add another
                # five seconds to a late listener-readiness notification.
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise TimeoutError('unrelated CLI connection deadline')
                listener.settimeout(remaining)
                channel, _ = listener.accept()
                break
        checks['connected'] = True
        stage('serve')
        with channel: denied = serve(channel)
        stage('collect')
        deadline = time.monotonic() + 5
        collect(deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('unrelated CLI exit deadline')
        checks['returncode'] = process.wait(timeout=remaining)
        stage('complete')
        checks['status'] = 'collected'  # The caller must still prove refusal.
        return denied, bytes(buffers['stdout']), bytes(buffers['stderr'])
    except BaseException as error:
        failure = error
        checks.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        cleanup = {'kill_attempted': False, 'reaped': False, 'errors': [],
                   'started_elapsed_seconds': round(time.monotonic() - started, 6)}
        checks['cleanup'] = cleanup
        if process is not None:
            try:
                code = process.poll()
                checks['pre_cleanup_poll'] = {'status': 'observed', 'returncode': code}
            except BaseException as error:
                checks['pre_cleanup_poll'] = {'status': 'unavailable', 'error_type': type(error).__name__}
                cleanup['errors'].append({'operation': 'poll', 'error_type': type(error).__name__})
            if process.returncode is None:
                cleanup['kill_attempted'] = True
                try: process.kill()
                except BaseException as error:
                    cleanup['errors'].append({'operation': 'kill', 'error_type': type(error).__name__})
            # Drain buffered evidence even after accept/serve fails or the CLI
            # has already exited, with one bounded cleanup collection window.
            deadline = time.monotonic() + 5
            try: collect(deadline)
            except BaseException as error:
                cleanup['errors'].append({'operation': 'drain', 'error_type': type(error).__name__})
            try:
                checks['returncode'] = process.wait(timeout=max(0, deadline - time.monotonic()))
                cleanup['reaped'] = True
            except BaseException as error:
                cleanup['errors'].append({'operation': 'wait', 'error_type': type(error).__name__})
            for name in buffers:
                try: getattr(process, name).close()
                except BaseException as error:
                    cleanup['errors'].append({'operation': name + '_close', 'error_type': type(error).__name__})
        for name in buffers:
            checks[name] = _output(buffers[name], counts[name], 4096)
            checks[name]['eof_observed'] = eof[name]
        checks['elapsed_seconds'] = round(time.monotonic() - started, 6)
        if cleanup['errors'] and failure is None:
            checks.update(status='failed', error_type='RuntimeError', stage='cleanup')
            raise RuntimeError('unrelated CLI cleanup incomplete')


def prove_service(supervisor, backend, endpoint_, container, *, run, checks=None):
    """Preflight service/lineage, then recheck actual boundary before release."""
    from uas.docker_exec_api import DockerExecAPI
    from uas.forge import ForgeBinding
    from uas.git_controller import GitCheckout, serve_one
    from uas.git_policy import GitIdentity
    from uas.git_process import GitChildAuthority, GitSeat, ProcView, _Task, _read_at
    from uas.git_provenance import GitProvenance
    from uas.git_service import decode, send
    from uas.kernel_origin import OriginDenied, _identity, alive, receive
    from uas.ledger import LedgerError, Origin
    from uas.workstation_exec import ExecLaunch, ExecSeat
    from guest_boundary import require_process_label
    from uas.guest_fixture import ROOMS
    state = supervisor._read()
    require(state['phase'] == 'running' and state['room_id'] == 'alpha', 'running selected Room required')
    instance = state['instance_id']
    binding = ForgeBinding('alpha', 'alpha', 'owner/repo')
    private = supervisor.directory / ('service-' + instance); private.mkdir(mode=0o700)
    checks = {} if checks is None else checks
    checks.update(status='in_progress', stage='bootstrap_launch')
    active, effects = True, {'worker': 0}
    listener = endpoint_.listeners[0]
    broker = launch = authority = provenance = None
    backend_fd = -1
    class Bootstrap(ExecLaunch):
        def _create_spec(self):
            return {'AttachStdin': True, 'AttachStdout': True, 'AttachStderr': True,
                    'Tty': False, 'Privileged': False, 'User': '65532:65532', 'WorkingDir': '/',
                    'Cmd': ['/usr/bin/python3', '-I', '/opt/uas/uas/room_probe.py', 'bootstrap'], 'Env': []}
    def no_worker(_origin):
        effects['worker'] += 1
        raise OriginDenied('native workers are not enabled by the Room fixture')
    def no_run(_origin, _checkout):
        raise LedgerError('ROOM_FIXTURE_HELP_ONLY')
    def current():
        # Called inside the lifecycle lock; all ownership objects are retained.
        now = supervisor._read()
        if (not active or now is None or now['phase'] != 'running' or now['instance_id'] != instance
                or launch.origin.revoked or not alive(launch.origin.pidfd)):
            raise OriginDenied('Room preflight seat no longer current')
        endpoint_.require(); broker.require()
        return True
    def control(expected):
        with receive(launch.channel) as record:
            launch.origin.require(record)
            value = decode(record.data)
            require(value == expected if expected is not None else value.get('kind') == 'HELD_BOOTSTRAP',
                    'held bootstrap control differs')
            return value
    try:
        broker = BrokerProcess(binding, instance)
        checks['broker'] = broker.observe()
        seat = ExecSeat('alpha', instance, 'fixture-participant', 'fixture-actor', 'seat-a', container, 165532, 165532)
        launch = Bootstrap(DockerExecAPI('/var/run/docker.sock'), seat, endpoint_.leases[0], private / 'bootstrap.json')
        launch.launch(listener)
        observation = control(None)
        require(observation['uid'] == observation['gid'] == 65532, 'bootstrap internal identity differs')
        peer_label = launch.channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 1024).decode().rstrip('\0')
        require_process_label(peer_label, ROOMS['alpha'][3])
        require_process_label(observation['peer_label'], ROOMS['alpha'][3])
        checks['socket_policy'] = {'participant_socket_peer_label': peer_label,
                                  'supervisor_socket_peer_label': observation['peer_label']}
        descriptor = os.pidfd_open(os.getpid())
        try:
            require(observation['peer_identity'] == list(_identity(descriptor))
                    and observation['peer_credentials'] == [0,65534,65534],
                    'mapped bootstrap did not pin this unmapped root Supervisor task')
        finally: os.close(descriptor)
        view = ProcView()
        try:
            initial = tuple((node.st_dev,node.st_ino) for node in
                            (Path('/proc/1/ns/pid').stat(),Path('/proc/1/ns/user').stat()))
            require(os.getuid() == os.getgid() == 0 and view.receiver_namespace == initial
                    and Path('/proc/self/uid_map').read_text().split() == ['0','0','4294967295'],
                    'trusted Supervisor must use guest initial user/PID namespaces')
            raw = Path('/proc/self/status').read_text()
            require(len(raw) <= 16384, 'Supervisor kernel observation exceeds bound')
            fields = dict(line.split(':',1) for line in raw.splitlines() if ':' in line)
            checks['supervisor'] = {'uid':os.getuid(),'gid':os.getgid(),'namespaces':view.receiver_namespace,
                'kernel_status':{key:fields[key].strip() for key in ('CapEff','CapBnd','NoNewPrivs','Seccomp')},
                'label':Path('/proc/self/attr/current').read_text().rstrip('\0\n'), 'new_capability_grant':False}
            task = _Task(view, launch.origin.credentials[0], expected=launch.origin.identity)
            try:
                require(task.status['Uid'] == task.status['Gid'] == (165532,) * 4
                        and len(task.status['NSpid']) == 2
                        and all(left != right for left, right in zip(task.namespace, view.receiver_namespace)),
                        'actual remapped task facts differ')
                namespace, depth = task.namespace, len(task.status['NSpid'])
                process_label = _read_at(task.directory, 'attr/current').decode().rstrip('\0\n')
                require_process_label(process_label, ROOMS['alpha'][3]); task.check()
                checks['participant'] = {'credentials': list(launch.origin.credentials),
                    'pidfd_identity': list(launch.origin.identity), 'status': task.status,
                    'process_label': process_label,
                    'namespaces': namespace, 'supervisor_namespaces': view.receiver_namespace,
                    'observed_supervisor_peer': observation['peer_credentials'],
                    'observed_supervisor_pidfd': observation['peer_identity']}
            finally: task.close()
        finally: view.close()
        origin = Origin('fixture-actor', 'fixture-participant', launch.incarnation, 'fixture-epoch', ('git-read',))
        authority = GitChildAuthority((GitSeat(origin, launch.origin, current, namespace, depth),))
        authority = ObservedAuthority(authority, checks)
        provenance = GitProvenance(private / 'provenance.db', 'alpha', 'alpha')
        metadata = private / 'metadata'; metadata.mkdir(mode=0o700)
        for name in ('objects', 'refs', 'helpers'): (metadata / name).mkdir(mode=0o700)
        (metadata / 'HEAD').write_text('ref: refs/heads/main\n')
        (metadata / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = true\n')
        checkout = GitCheckout('fixture', str(backend.root / 'workspace'), str(metadata), str(metadata),
                               str(metadata / 'config'), str(metadata / 'helpers'), 165532)
        backend_fd, backend_digest = fixed_executable('/usr/bin/git')
        service = RoomHelpOnlyCoordinator(binding, instance, {'fixture-actor': GitIdentity('fixture-actor', 'Fixture', 'fixture@example.invalid')},
            (checkout,), provenance, broker.client, no_worker, backend_fd=backend_fd, backend_sha256=backend_digest,
            lifecycle_lock=supervisor._locked, run_scope=no_run)
        with supervisor._locked():
            current(); backend.admit(state)
            send(launch.channel, {'kind': 'PROVE_HELP_ONLY'})
        replies = []
        for index in range(2):
            checks['stage'] = 'help_accept' if index == 0 else 'nonhelp_accept'
            ready, _, _ = select.select([listener, launch.channel], [], [], 5)
            if launch.channel in ready:
                with receive(launch.channel) as record:
                    launch.origin.require(record)
                    value = decode(record.data)
                if (type(value) is dict and set(value) == {'kind', 'stage', 'error_type'}
                        and value['kind'] == 'BOOTSTRAP_FAILED'
                        and type(value['stage']) is str and len(value['stage']) <= 64
                        and type(value['error_type']) is str and len(value['error_type']) <= 64):
                    checks['bootstrap_failure'] = value
                    send(launch.channel, {'kind': 'BOOTSTRAP_FAILURE_RECORDED'})
                raise RuntimeError('bootstrap ended before expected help request')
            require(listener in ready, 'mounted help request not received at ' + checks['stage'])
            listener.settimeout(5)
            channel, _ = listener.accept()
            with channel:
                require_process_label(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 1024).decode(), ROOMS['alpha'][3])
                checks['stage'] = 'help_serve' if index == 0 else 'nonhelp_serve'
                replies.append(serve_one(channel, service, authority, lifecycle_lock=supervisor._locked))
                require_help_reply(replies[-1], checks, index)
        checks['stage'] = 'help_confirmation'
        control({'kind': 'HELP_ONLY_PROVED'})
        require(replies[0] is not None and replies[0]['code'] == 0 and replies[1] is None
                and effects['worker'] == 0, 'help-only real service proof differs')
        # An unrelated Engine exec has the same numeric UID and mount but no
        # ancestry to the held bootstrap. The real service must reject it.
        checks['stage'] = 'unrelated_task_refusal'
        checks['unrelated_task'] = {}
        denied, stdout, stderr = observe_unrelated_cli(listener, container,
            lambda channel: serve_one(channel, service, authority, lifecycle_lock=supervisor._locked),
            checks=checks['unrelated_task'])
        observed = checks['unrelated_task']
        require(not observed['stdout']['truncated'] and not observed['stderr']['truncated'],
                'unrelated CLI evidence exceeded capture bound')
        require(observed['returncode'] == 0 and denied is None and json.loads(stdout) == {'code':128}
                and len(stderr) <= 4096 and effects['worker'] == 0, 'same-UID unrelated task admitted')
        observed['authority_refusal_proved'] = True
        # Final actual liveness and launch-boundary observation immediately before
        # granting the synthetic workload its release, not a cached HELLO bit.
        with supervisor._locked():
            current(); backend.admit(state); broker.require()
            send(launch.channel, {'kind': 'RELEASE_WORKLOAD'})
        control({'kind': 'WORKLOAD_STARTED'})
        checks.update(status='passed', mounted_real_help=True, non_help_refused=True, worker_starts=effects['worker'],
            same_uid_unrelated_task_refused=True,
            provider_execution_disabled=True, broker_credentials=list(broker.client.worker.credentials),
            broker_pidfd=list(broker.client.worker.identity), same_live_broker_rechecked_before_release=True,
            native_git_worker_enabled=False, native_pi_hub_enabled=False)
        send(launch.channel, {'kind': 'EXIT'})
        exited = select.poll(); exited.register(launch.origin.pidfd, select.POLLIN)
        require(bool(exited.poll(5000)) and not alive(launch.origin.pidfd),
                'held bootstrap exit was not observed before service teardown')
        checks['held_bootstrap_exit_observed'] = True
        checks['stage'] = 'complete'
        return checks
    except BaseException as error:
        checks.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        active = False
        errors = []
        for owner in (authority, launch, provenance, broker):
            if owner is not None:
                try: owner.close()
                except BaseException as error: errors.append(error)
        if backend_fd >= 0:
            try: os.close(backend_fd)
            except BaseException as error: errors.append(error)
        if errors and sys.exc_info()[0] is None: raise errors[0]
