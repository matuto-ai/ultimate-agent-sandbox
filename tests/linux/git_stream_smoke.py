#!/usr/bin/env python3
"""Hosted-only account-free native Git byte-Broker composition (35s maximum).

This is NOT OpenSSH, host-key verification, provider authorization, Supervisor
admission, or live GitHub qualification. The pinned transport executable below
is a compiled fixture dispatcher to private upload-pack/receive-pack servers.
The only credential-path files contain literal NOT_A_CREDENTIAL markers. No
keys, accounts, external endpoints, Docker, VM or host policy are provisioned.
Every mount and UID-owned fixture file lives in the disposable namespace/tree.
Importing is effect-free. Run only after independent source review on hosted CI:
    sudo -E python3 tests/linux/git_stream_smoke.py
"""
from contextlib import ExitStack, nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[2]
BROKER_UID = BROKER_GID = 65531
WORKER_UID, WORKER_GID = 65530, 65532
DEADLINE = 'UAS_GIT_STREAM_SMOKE_DEADLINE'
MARKER = b'NOT_A_CREDENTIAL\n'
BODY = b'STREAM_BODY_IS_NOT_AUDIT\n'


def require(value, message):
    if not value:
        raise AssertionError(message)


def helpers():
    spec = importlib.util.spec_from_file_location('uas_reviewed_git_smoke', Path(__file__).with_name('git_smoke.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gate():
    require(os.getuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_OS') == 'Linux', 'disposable hosted Linux root fixture required')
    require(signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, ()),
            'unblocked fixture deadline required')


def write_object(repo, kind, data):
    raw = kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data
    oid = hashlib.sha1(raw).hexdigest()
    parent = repo / 'objects' / oid[:2]
    parent.mkdir(exist_ok=True)
    (parent / oid[2:]).write_bytes(zlib.compress(raw))
    return oid


def bare_repository(path, content):
    for directory in (path, path / 'objects', path / 'refs', path / 'refs/heads'):
        directory.mkdir(mode=0o700)
    (path / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = true\n')
    (path / 'HEAD').write_text('ref: refs/heads/main\n')
    blob = write_object(path, 'blob', content)
    tree = write_object(path, 'tree', b'100644 shared.txt\0' + bytes.fromhex(blob))
    commit = ('tree ' + tree + '\nauthor Fixture <fixture@example.invalid> 1 +0000\n'
              'committer Fixture <fixture@example.invalid> 1 +0000\n\nFixture remote seed\n').encode()
    oid = write_object(path, 'commit', commit)
    (path / 'refs/heads/main').write_text(oid + '\n')
    return oid


def compile_dispatcher(private, project, other):
    """No shell, URL, arbitrary command or external SSH in this fixture binary."""
    options = ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes', '-o', '@HOSTS',
        '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UpdateHostKeys=no', '-o', 'VerifyHostKeyDNS=no',
        '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'ClearAllForwardings=yes',
        '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'PermitLocalCommand=no',
        '-o', 'LocalCommand=none', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
        '-o', 'ControlPersist=no', '-o', 'CanonicalizeHostname=no', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no', '-o', 'PreferredAuthentications=publickey',
        '-i', '@IDENTITY', '-p', '22', '-T', 'git@github.com']
    source = r'''#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static void fail(void) { _exit(126); }
static void marker(const char *path) {
    int pid, fd; char tail;
    if(sscanf(path,"/proc/%d/fd/%d%c",&pid,&fd,&tail)!=2 || pid!=getppid() || fd<3) fail();
    int handle=open(path,O_RDONLY|O_CLOEXEC); if(handle<0) fail();
    char data[64]; ssize_t count=read(handle,data,sizeof(data)); close(handle);
    if(count!=17 || memcmp(data,"NOT_A_CREDENTIAL\n",17)) fail();
}
int main(int argc,char **argv) {
    static const char *options[]={OPTIONS};
    size_t count=sizeof(options)/sizeof(options[0]);
    if(argc!=(int)count+2) fail();
    for(size_t i=0;i<count;i++) {
        const char *value=argv[i+1];
        if(!strcmp(options[i],"@HOSTS")) {
            const char *prefix="UserKnownHostsFile=";
            if(strncmp(value,prefix,strlen(prefix))) fail();
            marker(value+strlen(prefix));
        } else if(!strcmp(options[i],"@IDENTITY")) marker(value);
        else if(strcmp(options[i],value)) fail();
    }
    const char *route=argv[argc-1], *service=NULL, *repository=NULL;
    if(!strcmp(route,"git-upload-pack 'owner/repo.git'")) {service="upload-pack";repository=PROJECT;}
    else if(!strcmp(route,"git-receive-pack 'owner/repo.git'")) {service="receive-pack";repository=PROJECT;}
    else if(!strcmp(route,"git-upload-pack 'other/read.git'")) {service="upload-pack";repository=OTHER;}
    else fail();
    int log=open(LOGFILE,O_WRONLY|O_APPEND|O_CLOEXEC); if(log<0) fail();
    size_t length=strlen(route);
    if(write(log,route,length)!=(ssize_t)length || write(log,"\n",1)!=1) fail();
    close(log);
    setenv("GIT_CONFIG_NOSYSTEM","1",1); setenv("GIT_CONFIG_SYSTEM","/dev/null",1);
    setenv("GIT_CONFIG_GLOBAL","/dev/null",1); setenv("GIT_NO_REPLACE_OBJECTS","1",1);
    execl("/usr/bin/git","git",service,repository,(char*)NULL); fail();
}
'''
    for key, value in {'OPTIONS': ','.join(json.dumps(value) for value in options),
                       'PROJECT': json.dumps(str(project)), 'OTHER': json.dumps(str(other)),
                       'LOGFILE': json.dumps(str(private / 'contacts'))}.items():
        source = source.replace(key, value)
    c_file, executable = private / 'dispatcher.c', private / 'dispatcher'
    c_file.write_text(source)
    subprocess.run(['/usr/bin/cc', '-O2', '-Wall', '-Wextra', '-Werror', '-o', str(executable), str(c_file)],
        check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4)
    executable.chmod(0o555)
    return hashlib.sha256(executable.read_bytes()).hexdigest()


def private_broker_files(root):
    private = root / 'external-broker'
    private.mkdir(mode=0o700)
    project, other = private / 'project.git', private / 'other.git'
    seed, other_seed = bare_repository(project, b'project seed\n'), bare_repository(other, b'other seed\n')
    for name in ('identity-marker', 'hosts-marker'):
        path = private / name
        path.write_bytes(MARKER)
        path.chmod(0o600)
    (private / 'contacts').write_bytes(b'')
    digest = compile_dispatcher(private, project, other)
    for path in (private, *private.rglob('*')):
        require(not path.is_symlink(), 'fixture private symlink unavailable')
        os.chown(path, BROKER_UID, BROKER_GID)
    return private, digest, seed, other_seed


def stop_owned_child(pid, *, expect_success=False):
    """No poll/wait before final signal: an unreaped child reserves its PID."""
    owned = True
    try:
        deadline = time.monotonic() + 1
        while os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            if time.monotonic() >= deadline:
                break
            time.sleep(.005)
        # Still exclusively owned: no background reaper is permitted here.
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        owned = False  # Never retry a numeric signal after crossing waitpid.
        _, status = os.waitpid(pid, 0)
        if expect_success:
            require(os.waitstatus_to_exitcode(status) == 0, 'fixture worker did not terminate successfully')
    except ChildProcessError:
        owned = False
        raise AssertionError('fixture child ownership lost') from None
    finally:
        # The outer private PID namespace is the fail-closed descendant cleanup
        # boundary; this routine never signals a PID after ownership uncertainty.
        if owned:
            raise AssertionError('fixture child cleanup unverified')


def broker_process(channel, private, digest, supervisor_gid):
    from uas.forge import ForgeBinding
    from uas.forge_audit import ForgeAudit
    from uas.git_audit import GitAudit
    from uas.git_service import ExternalGitBroker, serve
    from uas.git_transport import GitTransportConfig, SshActorCredential, SshTransport
    require(os.getuid() == os.geteuid() == BROKER_UID
            and os.getgid() == os.getegid() == BROKER_GID, 'fixed external Broker identity required')
    binding = ForgeBinding('fixture-room', 'fixture-project', 'owner/repo')
    config = GitTransportConfig(str(private / 'dispatcher'), digest,
        (SshActorCredential('actor-a', str(private / 'identity-marker'), str(private / 'hosts-marker')),))
    owner = ForgeAudit(private / 'audit.db', 'fixture-deployment')
    try:
        broker = ExternalGitBroker(binding, 'fixture-instance', GitAudit(owner), SshTransport(config, binding))
        serve(channel, broker, supervisor_uid=0, supervisor_gid=supervisor_gid)
    finally:
        owner.close()


def install_bridge_diagnostics():
    """Observe only this fixture's bridge code; preserve every production call.

    The original loop catches its inner failure, so an outer wrapper cannot
    expose the decisive stage. A thread-local Python trace records only fixed
    frame kinds, source locations and exception types, never packet/argv/error
    text. It does not perform extra reads, sends, authentication or retries.
    """
    import uas.git_worker_native as worker
    original = worker.WorkerBridge._loop
    budget = {'ordinary': 64, 'failure': 8}

    def observed(self):
        previous = sys.gettrace()
        last_value = None

        def trace(frame, event, argument):
            nonlocal last_value
            if frame.f_code is not original.__code__:
                return None
            try:
                error = argument[1] if event == 'exception' else None
                value = frame.f_locals.get('value')
                if error is None and (event != 'line' or value is last_value):
                    return trace
                last_value = value
                slot = 'failure' if error is not None else 'ordinary'
                if budget[slot] <= 0:
                    return trace
                budget[slot] -= 1
                kind = value.get('kind') if type(value) is dict else None
                if kind not in {'ssh-open', 'ready', 'data', 'eof', 'cancel', 'exit', 'refused'}:
                    kind = 'REDACTED'
                key = frame.f_locals.get('key')
                direction = getattr(key, 'data', None)
                if direction not in {'shim', 'supervisor'}:
                    direction = 'UNKNOWN'
                row = {'fixture_bridge_stage': event, 'line': frame.f_lineno,
                       'kind': kind, 'direction': direction, 'active': self._active}
                if error is not None:
                    row['error_type'] = type(error).__name__
                    row['errno'] = error.errno if isinstance(error, OSError) else None
                    frames, traceback = [], argument[2]
                    while traceback is not None:
                        frames.append([Path(traceback.tb_frame.f_code.co_filename).name,
                                       traceback.tb_frame.f_code.co_name, traceback.tb_lineno])
                        traceback = traceback.tb_next
                    row['frames'] = frames[-8:]
                print(json.dumps(row, sort_keys=True), file=sys.stderr, flush=True)
            except Exception:
                pass  # A diagnostic failure never replaces the original decision.
            return trace

        try:
            try:
                sys.settrace(trace)
            except Exception:
                pass
            return original(self)
        finally:
            try:
                sys.settrace(previous)
            except Exception:
                pass

    worker.WorkerBridge._loop = observed


def worker_process(channel, worktree, home, digest, private, seed, other_seed, smoke):
    from uas.forge import ForgeBinding
    from uas.git_policy import GitIdentity, parse_git
    from uas.git_runtime import GitRuntime, RuntimeView, SealedGit
    from uas.git_service import decode, send
    from uas.git_transaction import ReferenceTransaction
    from uas.git_worker_native import WorkerBridge
    from uas.kernel_origin import HeldOrigin, enable, receive
    install_bridge_diagnostics()
    smoke.isolate_process()
    os.umask(0o002)
    enable(channel)
    channel.settimeout(10)
    send(channel, {'kind': 'fixture-worker-ready'})
    with receive(channel) as record:
        require(record.credentials[1] == 0 and decode(record.data) == {'kind': 'fixture-go'}, 'fixture Supervisor differs')
        supervisor = HeldOrigin(record)
    try:
        for path in (private / 'identity-marker', private / 'hosts-marker'):
            try:
                path.read_bytes()
            except PermissionError:
                pass
            else:
                raise AssertionError('external marker path entered Workstation authority')
        with ExitStack() as stack:
            def opened(path, directory=True):
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0))
                stack.callback(os.close, fd)
                return fd
            paths = smoke.view_paths('primary')
            view = RuntimeView(opened(worktree), opened(paths['gitdir']), opened(paths['config'], False),
                opened(paths['helpers']), binding=ForgeBinding('fixture-room', 'fixture-project', 'owner/repo'),
                common_fd=opened(paths['common']), checkout_owner=65532)
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            stack.callback(left.close)
            stack.callback(right.close)
            enable(left)
            runtime = GitRuntime(view, SealedGit(19, digest),
                GitIdentity('actor-a', 'Actor A', 'actor-a@example.invalid'), transport_fd=right.fileno(), home=str(home))
            def local(argv):
                result = runtime.run(parse_git('git', argv), timeout=3)
                require(result.returncode == 0, 'fixture local Git failed: ' + result.stderr.decode(errors='replace')[-1000:])
                return result.stdout
            def remote(operation, argv, *, expected=0):
                send(channel, {'kind': 'fixture-command', 'operation': operation})
                with receive(channel) as record:
                    supervisor.require(record)
                    require(decode(record.data) == {'kind': 'fixture-command-go'}, 'fixture command grant differs')
                bridge = WorkerBridge(channel, supervisor, left)
                bridge.start()
                try:
                    result = runtime.run(parse_git('git', argv), timeout=5, current=bridge.current)
                finally:
                    bridge.stop()
                require(result.returncode == expected, 'fixture remote Git result differs: '
                        + result.stderr.decode(errors='replace')[-1200:])
                send(channel, {'kind': 'fixture-result', 'operation': operation, 'code': result.returncode})
            remote('fetch-project', ['fetch', 'origin'])
            require(local(['rev-parse', '--verify', 'refs/remotes/origin/main']).strip().decode() == seed, 'Project fetch object differs')
            remote('fetch-other', ['fetch', 'git@github.com:other/read.git', 'refs/heads/main:refs/remotes/other/main'])
            require(local(['rev-parse', '--verify', 'refs/remotes/other/main']).strip().decode() == other_seed, 'same-Forge read differs')
            remote('one-shot', ['ls-remote', 'origin'])
            remote('one-shot', ['ls-remote', 'origin'], expected=128)
            local(['switch', '-c', 'stream-feature', 'refs/remotes/origin/main'])
            (worktree / 'shared.txt').write_bytes(BODY)
            local(['add', '--', 'shared.txt'])
            with ReferenceTransaction('stream-fixture-commit', expected_old=seed,
                    expected_ref='refs/heads/stream-feature', kind='commit') as receipt:
                result = runtime.run(parse_git('git', ['commit', '-m', 'STREAM_BODY_IS_NOT_AUDIT']), timeout=4, transaction=receipt)
                require(result.returncode == 0, 'fixture commit failed')
                created = receipt.committed_oid(required=True)
            remote('push-project', ['push', 'origin', 'HEAD:refs/heads/from-worker'])
            remote('push-other-denied', ['push', 'git@github.com:other/read.git', 'HEAD:refs/heads/forbidden'], expected=128)
            send(channel, {'kind': 'fixture-done', 'commit_oid': created})
            with receive(channel) as record:
                supervisor.require(record)
                require(decode(record.data) == {'kind': 'fixture-finish'}, 'fixture finish differs')
    finally:
        supervisor.close()


def namespace(root):
    gate()
    require(os.getpid() == 1 and root.parent == Path('/tmp')
            and root.name.startswith('uas-git-stream-') and root.resolve() == root
            and root.is_dir() and root.stat().st_uid == 0 and stat.S_IMODE(root.stat().st_mode) == 0o700,
            'namespace-init and uniquely staged fixture root required')
    remaining = float(os.environ[DEADLINE]) - time.monotonic()
    require(0 < remaining <= 35, 'fixture deadline expired')
    def expired(*_):
        raise TimeoutError('native Git byte-Broker fixture deadline exceeded')
    # Default signal dispositions are not a dependable self-deadline for PID1.
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(max(1, int(remaining)))
    require(signal.getsignal(signal.SIGCHLD) is signal.SIG_DFL, 'exclusive fixture child reaper required')
    smoke = helpers()
    worktree, home = smoke.provision(root)
    backend_digest = smoke.sealed_backend()
    private, transport_digest, seed, other_seed = private_broker_files(root)
    sys.path.insert(0, '/opt/uas')
    for name in tuple(sys.modules):
        if name == 'uas' or name.startswith('uas.'):
            del sys.modules[name]
    from uas.forge import ForgeBinding
    from uas.git_policy import GitPolicyError
    from uas.git_service import GitBrokerClient, decode, send
    from uas.kernel_origin import HeldOrigin, alive, enable, receive
    from uas.ledger import Origin
    broker_parent, broker_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    broker_pid = worker_pid = None
    client = worker_parent = worker_child = worker_origin = None
    supervisor_gid = os.getgid()
    try:
        broker_pid = os.fork()
        if broker_pid == 0:
            broker_parent.close()
            os.close(19)
            try:
                # Model a normally exec-launched dedicated daemon. Fork+setuid
                # alone leaves dumpable=0 and would reject its same-UID SSH
                # child's /proc/<broker>/fd opens. Never relax dumpability.
                os.setgroups([])
                os.setgid(BROKER_GID)
                os.setuid(BROKER_UID)
                broker_child.set_inheritable(True)
                os.execve(sys.executable, [sys.executable, '/opt/uas/fixture-sources/git_stream_smoke.py', '--broker',
                    str(broker_child.fileno()), str(private), transport_digest, str(supervisor_gid)],
                    {'PATH': '/usr/bin:/bin', 'PYTHONPATH': '/opt/uas', 'PYTHONDONTWRITEBYTECODE': '1',
                     'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'})
            except BaseException:
                os._exit(125)
            os._exit(0)
        broker_child.close()
        client = GitBrokerClient(broker_parent, ForgeBinding('fixture-room', 'fixture-project', 'owner/repo'),
            'fixture-instance', broker_uid=BROKER_UID, broker_gid=BROKER_GID)
        worker_parent, worker_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        enable(worker_parent)
        worker_parent.settimeout(10)
        worker_pid = os.fork()
        if worker_pid == 0:
            worker_parent.close()
            client.close()  # No external Broker endpoint/pidfd enters the worker.
            try:
                worker_process(worker_child, worktree, home, backend_digest, private, seed, other_seed, smoke)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(125)
            os._exit(0)
        worker_child.close()
        with receive(worker_parent) as record:
            require(record.credentials == (worker_pid, WORKER_UID, WORKER_GID)
                    and decode(record.data) == {'kind': 'fixture-worker-ready'}, 'fixture worker kernel binding differs')
            worker_origin = HeldOrigin(record)
        class Authority:
            origin = Origin('actor-a', 'seat-a', 'fixture-incarnation', 'epoch1', ('git-read', 'git-push'))
            def current(self):
                require(not worker_origin.revoked and alive(worker_origin.pidfd), 'fixture worker revoked')
                return True
            def require(self, record):
                worker_origin.require(record)
                return self.current()
        authority = Authority()
        send(worker_parent, {'kind': 'fixture-go'})
        operation = None
        direct_finish_pending = False
        results, terminals = [], []
        while True:
            with receive(worker_parent) as record:
                authority.require(record)
                value = decode(record.data)
            if set(value) == {'kind', 'operation'} and value['kind'] == 'fixture-command':
                operation = value['operation']
                send(worker_parent, {'kind': 'fixture-command-go'})
            elif set(value) == {'kind', 'argv'} and value['kind'] == 'ssh-open':
                require(operation is not None, 'SSH appeared outside fixture operation')
                try:
                    terminal = client.relay(worker_parent, authority, operation_id=operation, argv=value['argv'], lock=nullcontext)
                    terminals.append(terminal)
                except GitPolicyError:
                    require(operation == 'push-other-denied', 'unexpected fixture policy denial')
                    direct_finish_pending = True
                    send(worker_parent, {'kind': 'refused', 'error': 'GIT_PROJECT_MISMATCH', 'record': None})
            elif value == {'kind': 'stream-finished'}:
                # Only this deliberately local policy refusal bypasses relay().
                # No ready/data was sent, so its exact finish marker is next.
                require(operation == 'push-other-denied' and direct_finish_pending, 'unexpected direct stream finish')
                direct_finish_pending = False
            elif set(value) == {'kind', 'operation', 'code'} and value['kind'] == 'fixture-result':
                require(value['operation'] == operation and not direct_finish_pending, 'fixture operation result crossed')
                results.append(value)
                operation = None
            elif set(value) == {'kind', 'commit_oid'} and value['kind'] == 'fixture-done':
                created = value['commit_oid']
                require(type(created) is str and len(created) == 40 and all(c in '0123456789abcdef' for c in created), 'fixture created OID malformed')
                send(worker_parent, {'kind': 'fixture-finish'})
                break
            else:
                raise AssertionError('unexpected fixture worker control')
        pid, worker_pid = worker_pid, None
        stop_owned_child(pid, expect_success=True)
        require([row['code'] for row in results] == [0, 0, 0, 128, 0, 128], 'native Git read/push/denial outcomes differ')
        require((private / 'project.git/refs/heads/from-worker').read_text().strip() == created, 'native push did not update pinned Project ref')
        require(not (private / 'other.git/refs/heads/forbidden').exists(), 'cross-Project push changed a ref')
        contacts = (private / 'contacts').read_text().splitlines()
        require(contacts == ["git-upload-pack 'owner/repo.git'", "git-upload-pack 'other/read.git'",
            "git-upload-pack 'owner/repo.git'", "git-receive-pack 'owner/repo.git'"], 'replay or forbidden route reached transport')
        require(any(row.get('error') == 'GIT_STREAM_ALREADY_CONSUMED' for row in terminals), 'replay did not use durable denial')
        with sqlite3.connect('file:' + str(private / 'audit.db') + '?mode=ro', uri=True) as db:
            rows = db.execute('SELECT s.metadata,t.result FROM git_starts s JOIN git_terminals t ON s.id=t.id').fetchall()
        require(len(rows) == 4, 'actual byte streams lack exactly four durable terminals')
        for meta, terminal in rows:
            data, result = json.loads(meta), json.loads(terminal)
            require(data['actor_id'] == 'actor-a' and result['status'] == 'OK'
                    and result['output_bytes'] > 0 and len(result['output_sha256']) == 64,
                    'Broker audit did not record actual successful byte stream')
            require('NOT_A_CREDENTIAL' not in meta + terminal and 'STREAM_BODY_IS_NOT_AUDIT' not in meta + terminal,
                    'content or credential marker appeared in metadata audit')
        evidence = {'native_fetch_push': 'PASS', 'fixed_shim_real_broker_byte_path': 'PASS',
            'same_forge_other_repo_read': 'PASS', 'project_only_push': 'PASS', 'durable_replay_denial': 'PASS',
            'workstation_credential_paths_absent': 'PASS', 'broker_uid': BROKER_UID, 'worker_uid': WORKER_UID,
            'transport_contacts': 4, 'audit_terminals': 4, 'credentials_created': False,
            'marker_files_only': True, 'openssh': 'NOT_TESTED', 'host_key_checking': 'NOT_TESTED',
            'provider_authorization': 'NOT_TESTED', 'supervisor_admission': 'NOT_TESTED',
            'live_github': 'NOT_TESTED'}
    finally:
        # Each owned resource is attempted once even if another disposal fails;
        # no uncertain fd/PID is retried. PIDns exit is the descendant backstop.
        errors = []
        def dispose(callback):
            try:
                callback()
            except BaseException as error:
                errors.append(error)
        if client is not None:
            dispose(client.close)
        if worker_origin is not None:
            dispose(worker_origin.close)
        for channel in (worker_parent, worker_child, broker_parent, broker_child):
            if channel is not None:
                dispose(channel.close)
        if worker_pid is not None:
            dispose(lambda: stop_owned_child(worker_pid))
        if broker_pid is not None:
            dispose(lambda: stop_owned_child(broker_pid))
        dispose(lambda: os.close(19))
        if errors:
            raise AssertionError('fixture cleanup unverified') from errors[0]
    print(json.dumps(evidence), flush=True)


def main():
    if len(sys.argv) == 6 and sys.argv[1] == '--broker':
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux'
                and os.getuid() == os.geteuid() == BROKER_UID, 'fixed hosted fixture Broker required')
        with socket.socket(fileno=int(sys.argv[2])) as channel:
            broker_process(channel, Path(sys.argv[3]), sys.argv[4], int(sys.argv[5]))
        return
    gate()
    if len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2]))
        return
    require(len(sys.argv) == 1, 'no caller-selected fixture commands')
    with tempfile.TemporaryDirectory(prefix='uas-git-stream-', dir='/tmp') as temporary:
        env = {'PATH': '/usr/bin:/bin', 'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
            'PYTHONDONTWRITEBYTECODE': '1', DEADLINE: str(time.monotonic() + 33)}
        result = subprocess.run(['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork',
            '--kill-child=KILL', '--mount-proc', sys.executable, str(Path(__file__).resolve()),
            '--namespace', temporary], env=env, timeout=35, check=False)
        require(result.returncode == 0, 'hosted Git byte-Broker fixture failed')


if __name__ == '__main__':
    main()
