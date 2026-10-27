"""External, fixed SSH byte transport; no key or agent enters a Workstation.

This owner belongs to the dedicated single-threaded Broker. It must be the sole
reaper of its SSH children, with SIGCHLD at its default disposition. Callers may
stream the nonblocking pipes but MUST NOT poll/wait/reap ``session.process``.
The session deadline, process authority, byte limits and durable audit belong to
the calling Broker loop. This module never qualifies a provider or provisions a
credential. Trusted configuration supplies existing exact Actor file references.
"""
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time

from .forge import ForgeBinding
from .git_policy import GitTarget, GitPolicyError, parse_ssh


class GitTransportError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise GitTransportError(code)


def _canonical_path(value):
    if type(value) not in (str, Path) and not isinstance(value, Path):
        _fail('INVALID_SSH_CONFIGURATION')
    path = Path(value)
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            _fail('INVALID_SSH_CONFIGURATION')
    except (OSError, ValueError, RuntimeError):
        _fail('INVALID_SSH_CONFIGURATION')
    return path


def _open_without_links(path):
    """Hold each directory while opening the next; no resolve/open link race."""
    directory = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    result = -1
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            previous, directory = directory, child
            os.close(previous)
        result = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=directory)
    finally:
        previous, directory = directory, -1
        try:
            os.close(previous)
        except BaseException:
            # Ownership has not reached the caller. A failing parent close
            # must still dispose the opened leaf, without retrying either fd.
            if result >= 0:
                descriptor, result = result, -1
                os.close(descriptor)
            raise
    return result


@dataclass(frozen=True)
class SshActorCredential:
    actor_id: str
    key_path: str
    known_hosts_path: str

    def __post_init__(self):
        if (type(self.actor_id) is not str
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', self.actor_id)):
            _fail('INVALID_SSH_CONFIGURATION')
        # Shape validation only: current ownership/content availability is
        # checked afresh immediately before each session, never cached here.
        for value in (self.key_path, self.known_hosts_path):
            if type(value) is not str or not value or len(value) > 4096 or '\x00' in value:
                _fail('INVALID_SSH_CONFIGURATION')
            path = Path(value)
            if (not path.is_absolute() or str(path) != value or '..' in path.parts
                    or value.startswith('//')):
                _fail('INVALID_SSH_CONFIGURATION')
        if self.key_path == self.known_hosts_path:
            _fail('INVALID_SSH_CONFIGURATION')


@dataclass(frozen=True)
class GitTransportConfig:
    executable: str
    sha256: str
    credentials: tuple[SshActorCredential, ...] = field(repr=False)

    def __post_init__(self):
        if (type(self.executable) is not str or not self.executable
                or type(self.sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', self.sha256)
                or type(self.credentials) is not tuple or len(self.credentials) > 1024
                or any(type(item) is not SshActorCredential for item in self.credentials)
                or len({item.actor_id for item in self.credentials}) != len(self.credentials)):
            _fail('INVALID_SSH_CONFIGURATION')


def _private_file(value):
    """Open only a current-owner private ordinary file; never read its bytes."""
    descriptor = -1
    try:
        path = _canonical_path(value)
        descriptor = _open_without_links(path)
        node = os.fstat(descriptor)
        if (not stat.S_ISREG(node.st_mode) or node.st_uid != os.getuid()
                or node.st_nlink != 1 or node.st_mode & 0o177 or not node.st_mode & 0o400
                or not 0 < node.st_size <= 1024 * 1024):
            _fail('SSH_CREDENTIAL_UNAVAILABLE')
        return descriptor
    except (OSError, ValueError, GitTransportError):
        if descriptor >= 0:
            os.close(descriptor)
        _fail('SSH_CREDENTIAL_UNAVAILABLE')


class OwnedSshSession:
    """One child/session ownership boundary; signal before exactly one reap.

    Even an exited leader remains unreaped while its numeric process group is
    signaled. ECHILD, another wait failure, or an interrupted reap permanently
    fences this transport; the old numeric group is never signaled again.
    """
    def __init__(self, owner, process, descriptors, home):
        self.owner, self.process = owner, process
        self.stdin, self.stdout, self.stderr = process.stdin, process.stdout, process.stderr
        self._descriptors, self._home = list(descriptors), home
        self._owned = True
        self._closed = False
        self.returncode = None

    def observe(self):
        if self._closed or not self._owned:
            _fail('SSH_SESSION_CLOSED')
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            self._owned = False
            self.owner.failed = True
            _fail('SSH_OWNERSHIP_UNKNOWN')
        try:
            return os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except BaseException:
            # Failure to establish ownership permits no numeric signal.
            self._owned = False
            self.owner.failed = True
            _fail('SSH_OWNERSHIP_UNKNOWN')

    def _release(self):
        if self._closed:
            return
        self._closed = True
        errors = False
        for stream in (self.stdin, self.stdout, self.stderr):
            try:
                if stream is not None:
                    stream.close()
            except BaseException:
                errors = True
        while self._descriptors:
            descriptor = self._descriptors.pop()
            try:
                os.close(descriptor)
            except BaseException:
                errors = True  # Never retry a possibly released fd number.
        try:
            self._home.cleanup()
        except BaseException:
            errors = True
        self.owner._sessions.discard(self)
        if errors:
            self.owner.failed = True
            _fail('SSH_CLEANUP_UNKNOWN')

    def _reap(self):
        try:
            self.observe()  # Required even after a prior observed leader exit.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # wait can reap and then raise. Clear ownership BEFORE that one
            # call so no finally/retry can signal an already recycled group.
            self._owned = False
            self.returncode = self.process.wait(timeout=2)
            if type(self.returncode) is not int:
                _fail('SSH_CLEANUP_UNKNOWN')
            return self.returncode
        except BaseException:
            self._owned = False
            self.owner.failed = True
            _fail('SSH_CLEANUP_UNKNOWN')
        finally:
            self._release()

    def finish(self, *, timeout=2):
        """Wait boundedly for the leader, clean any descendants, reap once."""
        if self._closed:
            if self.returncode is not None and not self.owner.failed:
                return self.returncode
            _fail('SSH_SESSION_CLOSED')
        if type(timeout) not in (int, float) or not 0 <= timeout <= 2:
            _fail('INVALID_SSH_TIMEOUT')
        deadline = time.monotonic() + timeout
        try:
            while self.observe() is None:
                if time.monotonic() >= deadline:
                    self._reap()
                    _fail('SSH_TIMEOUT')
                time.sleep(.001)
            return self._reap()
        except BaseException:
            # observe() can fail before _reap begins. Ownership is then
            # unknown, so release files/pipes without attempting a signal.
            if not self._closed:
                if self._owned:
                    self._reap()
                else:
                    self._release()
            raise

    def abort(self):
        if self._closed:
            if self.returncode is not None and not self.owner.failed:
                return self.returncode
            _fail('SSH_SESSION_CLOSED')
        if not self._owned:
            self._release()
            _fail('SSH_OWNERSHIP_UNKNOWN')
        return self._reap()


class SshTransport:
    """Fixed GitHub transport; one pinned executable and exact Actor lookup."""
    def __init__(self, config, binding):
        self.fd = -1
        self.failed = False
        self._closed = False
        self._sessions = set()
        if type(config) is not GitTransportConfig or type(binding) is not ForgeBinding:
            _fail('INVALID_SSH_CONFIGURATION')
        try:
            parse_ssh(['git@github.com', "git-receive-pack '" + binding.repository + ".git'"], binding)
        except (GitPolicyError, TypeError):
            _fail('INVALID_SSH_CONFIGURATION')
        self.config, self.binding = config, binding
        self._credentials = {item.actor_id: item for item in config.credentials}
        try:
            path = _canonical_path(config.executable)
            self.fd = _open_without_links(path)
            self.identity = (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino)
            self._pin()
        except BaseException:
            if self.fd >= 0:
                descriptor, self.fd = self.fd, -1
                os.close(descriptor)
            _fail('SSH_EXECUTABLE_UNAVAILABLE')

    def _pin(self):
        if self.fd < 0 or self.failed or self._closed:
            _fail('SSH_TRANSPORT_UNAVAILABLE')
        try:
            node = os.fstat(self.fd)
            if (not stat.S_ISREG(node.st_mode) or node.st_uid not in (0, os.getuid())
                    or node.st_mode & 0o022 or not node.st_mode & 0o111
                    or (node.st_dev, node.st_ino) != self.identity
                    or not 0 < node.st_size <= 128 * 1024 * 1024):
                _fail('SSH_EXECUTABLE_UNAVAILABLE')
            digest, offset = hashlib.sha256(), 0
            while offset < node.st_size:
                block = os.pread(self.fd, min(65536, node.st_size - offset), offset)
                if not block:
                    _fail('SSH_EXECUTABLE_UNAVAILABLE')
                digest.update(block)
                offset += len(block)
            if digest.hexdigest() != self.config.sha256:
                _fail('SSH_EXECUTABLE_UNAVAILABLE')
        except (OSError, ValueError, GitTransportError):
            self.failed = True
            _fail('SSH_EXECUTABLE_UNAVAILABLE')

    def open(self, actor_id, target):
        if self.failed or self._closed:
            _fail('SSH_TRANSPORT_UNAVAILABLE')
        if type(target) is not GitTarget:
            _fail('INVALID_GIT_TARGET')
        # Reconstruct through the policy rather than trusting a deserialized or
        # mutated dataclass, and apply Project binding again at actual contact.
        try:
            checked = parse_ssh(['git@' + target.host,
                target.service + " '" + target.repository + ".git'"], self.binding)
            if checked != target:
                # Case-insensitive push aliases reduce to configured spelling.
                if (target.service != 'git-receive-pack'
                        or checked.repository.casefold() != target.repository.casefold()):
                    _fail('INVALID_GIT_TARGET')
        except (GitPolicyError, TypeError, AttributeError):
            _fail('INVALID_GIT_TARGET')
        if type(actor_id) is not str or actor_id not in self._credentials:
            _fail('SSH_CREDENTIAL_UNAVAILABLE')
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            self.failed = True
            _fail('SSH_OWNERSHIP_UNKNOWN')
        if len(self._sessions) >= 8:
            _fail('SSH_SESSION_CAPACITY')
        self._pin()
        credential = self._credentials[actor_id]
        descriptors, home = [], None
        session = None
        try:
            key = _private_file(credential.key_path)
            descriptors.append(key)
            hosts = _private_file(credential.known_hosts_path)
            descriptors.append(hosts)
            home = tempfile.TemporaryDirectory(prefix='uas-git-ssh-')
            # Official OpenSSH closes inherited descriptors >=3 before parsing
            # options (openssh-portable V_9_6_P1 ssh.c:647-654). The external
            # Broker keeps these descriptors alive; SSH opens the same-owner
            # Broker's proc descriptor paths, never its own closed descriptors.
            # This Linux procfs access is an explicit hosted qualification seam.
            broker = os.getpid()
            argv = [f'/proc/self/fd/{self.fd}', '-F', '/dev/null',
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
                '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile=/proc/{broker}/fd/{hosts}',
                '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UpdateHostKeys=no',
                '-o', 'VerifyHostKeyDNS=no', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
                '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
                '-o', 'PermitLocalCommand=no', '-o', 'LocalCommand=none',
                '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ControlPersist=no',
                '-o', 'CanonicalizeHostname=no', '-o', 'PasswordAuthentication=no',
                '-o', 'KbdInteractiveAuthentication=no', '-o', 'PreferredAuthentications=publickey',
                '-i', f'/proc/{broker}/fd/{key}', '-p', '22', '-T', 'git@github.com',
                checked.service + " '" + checked.repository + ".git'"]
            try:
                process = subprocess.Popen(argv, cwd=home.name, env={'HOME': home.name, 'LC_ALL': 'C'},
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    shell=False, close_fds=True, start_new_session=True,
                    pass_fds=(self.fd,))
            except BaseException:
                self.failed = True
                _fail('SSH_LAUNCH_UNKNOWN')
            session = OwnedSshSession(self, process, descriptors, home)
            self._sessions.add(session)
            descriptors, home = [], None  # Ownership moves exactly once.
            try:
                for stream in (session.stdin, session.stdout, session.stderr):
                    os.set_blocking(stream.fileno(), False)
            except BaseException:
                _fail('SSH_PIPE_SETUP_FAILED')
            return session
        except BaseException:
            if session is not None:
                session.abort()
            raise
        finally:
            cleanup_failed = False
            while descriptors:
                descriptor = descriptors.pop()
                try:
                    os.close(descriptor)
                except BaseException:
                    cleanup_failed = True  # Released-or-uncertain fd: never retry.
            if home is not None:
                pending_home, home = home, None
                try:
                    pending_home.cleanup()
                except BaseException:
                    cleanup_failed = True
            if cleanup_failed:
                self.failed = True
                _fail('SSH_CLEANUP_UNKNOWN')

    def close(self):
        if self._closed:
            return
        self._closed = True
        errors = False
        for session in tuple(self._sessions):
            try:
                session.abort()
            except BaseException:
                errors = True
        if self.fd >= 0:
            descriptor, self.fd = self.fd, -1
            try:
                os.close(descriptor)
            except BaseException:
                errors = True
        if errors:
            self.failed = True
            _fail('SSH_CLEANUP_UNKNOWN')
