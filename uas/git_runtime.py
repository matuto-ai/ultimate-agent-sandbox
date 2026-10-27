"""Controlled native Git inside an admitted Workstation, never a host launcher.

The Supervisor supplies pinned descriptors after installation/namespace checks.
This module neither mounts files nor installs binaries, resolves credentials or
accepts ambient Git configuration. Its runtime assertions are mandatory, not a
source-test substitute for the reviewed native fixture.
"""
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from types import MappingProxyType

from .forge import ForgeBinding
from .git_policy import GitCommand, GitIdentity, GitPolicyError, GitTarget, parse_git
from .git_transaction import HOOK_DIRECTORY, HOOK_SCRIPT, GitTransactionError, ReferenceTransaction

BACKEND_FD = 19
WORKER_UID = 65530
PROJECT_GID = 65532
SSH_SHIM = '/opt/uas/bin/git-ssh-shim'
VIEW_ROOT = '/opt/uas/git-views'
_VIEW_ALIAS = re.compile(r'/opt/uas/git-views/([A-Za-z0-9][A-Za-z0-9_-]{0,63})/(gitdir|common)\Z')
MAX_OUTPUT = 1_048_576
MAX_INPUT = 524_288
MAX_BACKEND = 64 * 1024 * 1024
_HEX = re.compile(r'[0-9a-f]{64}\Z')
# Linux UAPI values (linux/fcntl.h); some Python builds omit the named
# constants. The real F_GET_SEALS call remains mandatory and fails closed.
_F_GET_SEALS = 1034
_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008


class GitRuntimeError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fd(value):
    if type(value) is not int or not 3 <= value <= 2**20:
        raise GitRuntimeError('INVALID_GIT_DESCRIPTOR')
    return value


def _path(fd):
    return '/proc/self/fd/' + str(_fd(fd))


def _node_id(node):
    return node.st_dev, node.st_ino


def _bytes(fd, maximum):
    node = os.fstat(fd)
    if not stat.S_ISREG(node.st_mode) or not 0 < node.st_size <= maximum:
        raise GitRuntimeError('INVALID_GIT_PROJECTION')
    result = bytearray()
    while len(result) < node.st_size:
        block = os.pread(fd, min(65536, node.st_size - len(result)), len(result))
        if not block:
            raise GitRuntimeError('INVALID_GIT_PROJECTION')
        result.extend(block)
    if os.pread(fd, 1, len(result)):
        raise GitRuntimeError('INVALID_GIT_PROJECTION')
    return bytes(result)


def _read_proc(path, maximum):
    with open(path, 'rb') as source:
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise GitRuntimeError('GIT_MOUNT_ROOT_UNVERIFIED')
    return raw


def _worktree_mount_root(fd, node, *, with_path=False):
    """Git realpaths worktrees: require the held inode to be a mount root.

    The trusted Supervisor must also admit non-renamable worktree ancestry
    (readonly rootfs/disjoint writable mounts) and withhold mount administration
    from both worker and Participant. A mount root protects the leaf, not writable
    ancestors. This function does not independently prove that admission; FD
    pinning alone cannot protect Git's canonicalized pathname from replacement.
    """
    info = _read_proc('/proc/self/fdinfo/' + str(fd), 65536)
    identifiers = [line.split()[1:] for line in info.splitlines() if line.startswith(b'mnt_id:')]
    if (len(identifiers) != 1 or len(identifiers[0]) != 1
            or not identifiers[0][0].isdigit()):
        raise GitRuntimeError('GIT_MOUNT_ROOT_UNVERIFIED')
    mount_id = int(identifiers[0][0])
    matches = []
    for line in _read_proc('/proc/self/mountinfo', 4 * 1024 * 1024).splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[0] == str(mount_id).encode('ascii') and b'-' in fields[6:]:
            matches.append(fields[4])
    if mount_id <= 0 or len(matches) != 1:
        raise GitRuntimeError('GIT_MOUNT_ROOT_UNVERIFIED')
    mountpoint = re.sub(rb'\\(040|011|012|134)',
        lambda match: bytes([int(match[1], 8)]), matches[0])
    if not mountpoint.startswith(b'/') or b'\0' in mountpoint:
        raise GitRuntimeError('GIT_MOUNT_ROOT_UNVERIFIED')
    visible = os.stat(os.fsdecode(mountpoint), follow_symlinks=False)
    if not stat.S_ISDIR(visible.st_mode) or _node_id(visible) != _node_id(node):
        raise GitRuntimeError('GIT_WORKTREE_NOT_MOUNT_ROOT')
    return (mount_id, os.fsdecode(mountpoint)) if with_path else mount_id


def _view_parent(path, role):
    """Fixed alias parents are image/Supervisor-owned, never Project metadata.

    A mounted leaf alone is insufficient: a writable ancestor could be renamed
    after Git canonicalizes a path. Walk every ancestor without symlink following
    and require root-controlled ancestry plus a readonly view root and slot.
    """
    match = _VIEW_ALIAS.fullmatch(path) if type(path) is str else None
    if match is None or match[2] != role:
        raise GitRuntimeError('GIT_VIEW_ALIAS_REQUIRED')
    descriptor = None
    identity = []
    try:
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        components = ('', 'opt', 'uas', 'git-views', match[1])
        for index, component in enumerate(components):
            if component:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
                previous, descriptor = descriptor, child
                os.close(previous)
            node = os.fstat(descriptor)
            if (not stat.S_ISDIR(node.st_mode) or node.st_uid != 0 or node.st_mode & 0o022
                    or index >= 3 and not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY):
                raise GitRuntimeError('GIT_VIEW_ANCESTRY_UNSAFE')
            identity.append(_node_id(node))
        return match[1], tuple(identity)
    except OSError:
        raise GitRuntimeError('GIT_VIEW_ANCESTRY_UNSAFE') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_commondir(gitdir_fd, common_path):
    """Files-ref backend ignores GIT_COMMON_DIR: pin its actual pointer too.

    Git 2.43.7/2.50 refs/files-backend.c uses get_common_dir_noenv(), which
    realpaths gitdir/commondir. This exact readonly overlay is required even
    for a primary checkout; absence checks would race attacker file creation.
    The host's neutral primary marker or existing linked pointer is not edited.
    """
    descriptor = None
    try:
        descriptor = os.open('commondir', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=gitdir_fd)
        node = os.fstat(descriptor)
        visible = os.stat('commondir', dir_fd=gitdir_fd, follow_symlinks=False)
        if (not stat.S_ISREG(node.st_mode) or not stat.S_ISREG(visible.st_mode)
                or node.st_uid != 0 or stat.S_IMODE(node.st_mode) != 0o444
                or node.st_nlink != 1 or not 0 < node.st_size <= 4096 or _node_id(node) != _node_id(visible)
                or not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY
                or _bytes(descriptor, 4096) != (common_path + '\n').encode('ascii')):
            raise GitRuntimeError('GIT_COMMON_DIR_UNBOUND')
        return _node_id(node)
    except OSError:
        raise GitRuntimeError('GIT_COMMON_DIR_UNBOUND') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_hooks():
    """The sole hook is immutable and unreachable by the Participant UID."""
    directory = hook = None
    try:
        directory = os.open(HOOK_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        node = os.fstat(directory)
        if (not stat.S_ISDIR(node.st_mode) or node.st_uid != WORKER_UID
                or stat.S_IMODE(node.st_mode) != 0o500 or not os.fstatvfs(directory).f_flag & os.ST_RDONLY
                or os.listdir(directory) != ['reference-transaction']):
            raise GitRuntimeError('GIT_HOOK_NOT_IMMUTABLE')
        hook = os.open('reference-transaction', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        node = os.fstat(hook)
        if (not stat.S_ISREG(node.st_mode) or node.st_uid not in (0, WORKER_UID)
                or stat.S_IMODE(node.st_mode) != 0o555 or not os.fstatvfs(hook).f_flag & os.ST_RDONLY
                or _bytes(hook, 4096) != HOOK_SCRIPT):
            raise GitRuntimeError('GIT_HOOK_NOT_IMMUTABLE')
    except OSError:
        raise GitRuntimeError('GIT_HOOK_UNAVAILABLE') from None
    finally:
        for fd in (hook, directory):
            if fd is not None:
                os.close(fd)


def compile_git_config(binding):
    """The complete projected local config; no repository-controlled includes."""
    if type(binding) is not ForgeBinding:
        raise GitRuntimeError('INVALID_GIT_BINDING')
    try:
        GitTarget(binding.host, binding.repository, 'git-upload-pack')
    except GitPolicyError:
        raise GitRuntimeError('INVALID_GIT_BINDING') from None
    return ('''[core]
\trepositoryFormatVersion = 0
\tbare = false
\tfileMode = true
\tabbrev = 40
\tlogAllRefUpdates = true
\thooksPath = /opt/uas/git-hooks
\tfsmonitor = false
\tattributesFile = /dev/null
\teditor = /bin/false
[extensions]
\tworktreeConfig = false
[remote "origin"]
\turl = git@github.com:''' + binding.repository + '''.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[protocol]
\tallow = never
[protocol "ssh"]
\tallow = always
[ssh]
\tvariant = ssh
[fetch]
\trecurseSubmodules = false
[push]
\trecurseSubmodules = no
\tdefault = simple
[branch]
\tautoSetupMerge = false
\tautoSetupRebase = never
[submodule]
\trecurse = false
[commit]
\tgpgSign = false
[tag]
\tgpgSign = false
[gpg]
\tprogram = /bin/false
[gc]
\tauto = 0
[maintenance]
\tauto = false
[credential]
\thelper =
[color]
\tui = false
''').encode('ascii')


class RuntimeView:
    """Borrow immutable projection descriptors for one trusted checkout.

    Config must be a real read-only mount at the held common-dir/config inode.
    Mode bits alone do not prevent same-UID rewriting. Both gitdir and common
    must be explicit fixed aliases under immutable Supervisor-owned parents,
    exact mount roots, with an exact readonly commondir pointer overlay. Native
    files-ref backends consult that pointer even when GIT_COMMON_DIR is supplied.
    checkout_owner comes from trusted Project configuration, not the caller's
    claimed identity. Existing owner and effective worker access are preserved;
    no permission repair is attempted. Worktree must be an exact mount root.
    All descriptors remain owned/open by the caller for the invocation lifetime.
    """
    def __init__(self, worktree_fd, gitdir_fd, config_fd, helpers_fd, *, binding, checkout_owner, common_fd=None):
        if type(checkout_owner) is not int or not 0 <= checkout_owner < 2**32 - 1:
            raise GitRuntimeError('INVALID_GIT_CHECKOUT_OWNER')
        self.checkout_owner = checkout_owner
        self.worktree_fd, self.gitdir_fd, self.config_fd, self.helpers_fd = map(_fd,
            (worktree_fd, gitdir_fd, config_fd, helpers_fd))
        if common_fd is None:
            raise GitRuntimeError('GIT_COMMON_DIR_UNBOUND')
        self.common_fd = _fd(common_fd)
        if (len({self.worktree_fd, self.gitdir_fd, self.config_fd, self.helpers_fd}) != 4
                or BACKEND_FD in self.fds or self.common_fd in {self.worktree_fd, self.config_fd, self.helpers_fd}):
            raise GitRuntimeError('INVALID_GIT_DESCRIPTOR')
        self.binding = binding
        self.config = compile_git_config(binding)
        self.config_sha256 = hashlib.sha256(self.config).hexdigest()
        self.identities = None
        self.mount_id = None
        self.view_identity = None
        self.require()

    @property
    def fds(self):
        return tuple(sorted({self.worktree_fd, self.gitdir_fd, self.config_fd, self.helpers_fd, self.common_fd}))

    def require(self, *, requested_cwd=None):
        try:
            uid = os.getuid()
            if uid != WORKER_UID or os.geteuid() != uid or os.getgid() != PROJECT_GID or os.getegid() != PROJECT_GID:
                raise GitRuntimeError('UNPRIVILEGED_WORKSTATION_REQUIRED')
            _require_hooks()
            nodes = {fd: os.fstat(fd) for fd in self.fds}
            directories = {self.worktree_fd, self.gitdir_fd, self.common_fd, self.helpers_fd}
            if (any(not stat.S_ISDIR(nodes[fd].st_mode) for fd in directories)
                    or any(nodes[fd].st_uid != self.checkout_owner for fd in {self.worktree_fd, self.gitdir_fd, self.common_fd})
                    or nodes[self.helpers_fd].st_uid not in {0, uid}
                    or nodes[self.helpers_fd].st_mode & 0o022
                    or _node_id(nodes[self.worktree_fd]) == _node_id(nodes[self.gitdir_fd])):
                raise GitRuntimeError('INVALID_GIT_PROJECTION')
            for fd in {self.worktree_fd, self.gitdir_fd, self.common_fd}:
                if not os.access(_path(fd), os.R_OK | os.W_OK | os.X_OK, effective_ids=True):
                    raise GitRuntimeError('GIT_CHECKOUT_ACCESS_UNAVAILABLE')
            identities = {fd: _node_id(node) for fd, node in nodes.items()}
            if self.identities is not None and identities != self.identities:
                raise GitRuntimeError('GIT_PROJECTION_CHANGED')
            mount_id = _worktree_mount_root(self.worktree_fd, nodes[self.worktree_fd])
            if self.mount_id is not None and mount_id != self.mount_id:
                raise GitRuntimeError('GIT_PROJECTION_CHANGED')
            git_mount, git_path = _worktree_mount_root(self.gitdir_fd, nodes[self.gitdir_fd], with_path=True)
            common_mount, common_path = _worktree_mount_root(self.common_fd, nodes[self.common_fd], with_path=True)
            git_slot, git_parents = _view_parent(git_path, 'gitdir')
            common_slot, common_parents = _view_parent(common_path, 'common')
            if git_slot != common_slot or git_parents != common_parents:
                raise GitRuntimeError('GIT_COMMON_DIR_UNBOUND')
            common_pointer = _require_commondir(self.gitdir_fd, common_path)
            view_identity = (git_mount, git_path, common_mount, common_path, git_parents, common_pointer)
            if self.view_identity is not None and self.view_identity != view_identity:
                raise GitRuntimeError('GIT_PROJECTION_CHANGED')
            config = nodes[self.config_fd]
            visible = os.stat('config', dir_fd=self.common_fd, follow_symlinks=False)
            if (not stat.S_ISREG(config.st_mode) or not stat.S_ISREG(visible.st_mode)
                    or config.st_uid not in {0, uid} or config.st_mode & 0o022
                    or _node_id(config) != _node_id(visible)
                    or not os.fstatvfs(self.config_fd).f_flag & os.ST_RDONLY
                    or not os.fstatvfs(self.helpers_fd).f_flag & os.ST_RDONLY):
                raise GitRuntimeError('GIT_CONFIG_NOT_IMMUTABLE')
            raw = _bytes(self.config_fd, 8192)
            if raw != self.config or hashlib.sha256(raw).hexdigest() != self.config_sha256:
                raise GitRuntimeError('GIT_CONFIG_MISMATCH')
            for directory in {self.gitdir_fd, self.common_fd}:
                try:
                    os.stat('config.worktree', dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise GitRuntimeError('GIT_WORKTREE_CONFIG_UNAVAILABLE')
            if (os.listdir(self.helpers_fd) != ['git']
                    or not stat.S_ISLNK(os.stat('git', dir_fd=self.helpers_fd, follow_symlinks=False).st_mode)
                    or os.readlink('git', dir_fd=self.helpers_fd) != _path(BACKEND_FD)):
                raise GitRuntimeError('INVALID_GIT_HELPERS')
            if requested_cwd is not None:
                target = os.stat(requested_cwd, follow_symlinks=False)
                if not stat.S_ISDIR(target.st_mode) or _node_id(target) != _node_id(nodes[self.worktree_fd]):
                    raise GitRuntimeError('GIT_CHECKOUT_MISMATCH')
            self.identities = identities
            self.mount_id = mount_id
            self.view_identity = view_identity
        except (OSError, ValueError) as error:
            if isinstance(error, GitRuntimeError):
                raise
            raise GitRuntimeError('GIT_PROJECTION_UNAVAILABLE') from None


class SealedGit:
    """Supervisor-remapped reserved FD19; no installed raw backend path."""
    def __init__(self, backend_fd, sha256):
        if backend_fd != BACKEND_FD or type(backend_fd) is not int or type(sha256) is not str or not _HEX.fullmatch(sha256):
            raise GitRuntimeError('INVALID_GIT_BACKEND')
        self.fd, self.sha256, self.identity = backend_fd, sha256, None
        self.require()

    def require(self):
        try:
            node = os.fstat(self.fd)
            if (not stat.S_ISREG(node.st_mode) or not node.st_mode & 0o111
                    or fcntl.fcntl(self.fd, _F_GET_SEALS) & _SEALS != _SEALS
                    or (self.identity is not None and _node_id(node) != self.identity)):
                raise GitRuntimeError('INVALID_GIT_BACKEND')
            raw = _bytes(self.fd, MAX_BACKEND)
            if not raw.startswith(b'\x7fELF') or hashlib.sha256(raw).hexdigest() != self.sha256:
                raise GitRuntimeError('GIT_BACKEND_MISMATCH')
            self.identity = _node_id(node)
        except OSError:
            raise GitRuntimeError('GIT_BACKEND_UNAVAILABLE') from None


@dataclass(frozen=True)
class GitInvocation:
    argv: tuple
    env: object
    pass_fds: tuple
    cwd: str


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class GitRuntime:
    """Fixed native launcher, borrowed FDs and caller-managed private empty HOME.

    The caller handles the credential-free shim bridge concurrently and never
    holds the lifecycle lock while run() waits. This object exclusively reaps
    its native Git child; no background SIGCHLD reaper may consume that child.
    """
    def __init__(self, view, backend, identity, *, transport_fd, home):
        if type(view) is not RuntimeView or type(backend) is not SealedGit or type(identity) is not GitIdentity:
            raise GitRuntimeError('INVALID_GIT_RUNTIME')
        self.view, self.backend, self.identity = view, backend, identity
        self.transport_fd = _fd(transport_fd)
        if self.transport_fd in (*view.fds, backend.fd):
            raise GitRuntimeError('INVALID_GIT_DESCRIPTOR')
        self.home = str(home)
        self.failed = False
        self._quiescent = True
        self._require()

    @property
    def quiescent(self):
        """True only before contact or after positively verified owned cleanup.

        This is not inferred from native output, transport closure, or poll().
        A spawn/ownership/disposal uncertainty permanently withholds this proof.
        """
        return self._quiescent

    def _require(self, *, requested_cwd=None):
        if self.failed or not self.quiescent:
            raise GitRuntimeError('GIT_RUNTIME_FENCED')
        self.view.require(requested_cwd=requested_cwd)
        self.backend.require()
        try:
            home = Path(self.home)
            node = home.lstat()
            if (not home.is_absolute() or home.resolve() != home or not stat.S_ISDIR(node.st_mode)
                    or node.st_uid != os.getuid() or node.st_mode & 0o077 or os.listdir(home)):
                raise GitRuntimeError('INVALID_GIT_HOME')
            # An inherited private endpoint is not a credential or identity;
            # its per-record process authentication lives in the Broker bridge.
            if not stat.S_ISSOCK(os.fstat(self.transport_fd).st_mode):
                raise GitRuntimeError('INVALID_GIT_TRANSPORT')
        except OSError:
            raise GitRuntimeError('GIT_RUNTIME_UNAVAILABLE') from None

    def plan(self, command, *, source_author=None, transaction=None):
        if type(command) is not GitCommand:
            raise GitRuntimeError('INVALID_GIT_COMMAND')
        try:
            argv = (['-C', command.cwd] if command.cwd is not None else []) + [command.command, *command.args]
            if parse_git('git', argv) != command:
                raise GitRuntimeError('INVALID_GIT_COMMAND')
        except (GitPolicyError, TypeError):
            raise GitRuntimeError('INVALID_GIT_COMMAND') from None
        if command.command == '--help':
            raise GitRuntimeError('GIT_HELP_IS_LOCAL')
        self._require(requested_cwd=command.cwd)
        gitdir, worktree, common, helpers = map(_path,
            (self.view.gitdir_fd, self.view.worktree_fd, self.view.common_fd, self.view.helpers_fd))
        env = {'HOME': self.home, 'XDG_CONFIG_HOME': self.home, 'LC_ALL': 'C', 'LANG': 'C',
            'PATH': helpers, 'GIT_EXEC_PATH': helpers, 'GIT_DIR': gitdir, 'GIT_WORK_TREE': worktree,
            'GIT_COMMON_DIR': common, 'GIT_INDEX_FILE': gitdir + '/index',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_ATTR_NOSYSTEM': '1', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_GRAFT_FILE': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '/bin/false', 'SSH_ASKPASS': '/bin/false',
            'GIT_EDITOR': '/bin/false', 'GIT_SEQUENCE_EDITOR': '/bin/false',
            'GIT_PAGER': '', 'PAGER': '', 'GIT_ALLOW_PROTOCOL': 'ssh', 'GIT_PROTOCOL_FROM_USER': '0',
            'GIT_SSH_VARIANT': 'ssh', 'GIT_SSH_COMMAND': SSH_SHIM + ' --fd ' + str(self.transport_fd),
            'GIT_COMMITTER_NAME': self.identity.name, 'GIT_COMMITTER_EMAIL': self.identity.email}
        arguments = list(command.args)
        if command.kind == 'cherry-pick':
            if command.args not in (('--continue',), ('--abort',)):
                arguments.insert(0, '-x')
            # Native cherry-pick preserves the source author/date; canonical
            # author env would override it. External finish verifies the full
            # anchored author and final source trailer, including continuation.
            if source_author is not None:
                from .git_provenance import _ident
                try:
                    _ident(source_author)
                except Exception:
                    raise GitRuntimeError('INVALID_GIT_SOURCE_AUTHOR') from None
        else:
            if source_author is not None:
                raise GitRuntimeError('UNEXPECTED_GIT_SOURCE_AUTHOR')
            env.update(GIT_AUTHOR_NAME=self.identity.name, GIT_AUTHOR_EMAIL=self.identity.email)
        if command.kind == 'commit':
            if '--amend' in arguments:
                arguments.append('--reset-author')
            else:
                # A participant-written CHERRY_PICK_HEAD otherwise overrides
                # author environment in native commit. Explicit trusted author
                # wins over that hint; --reset-author is invalid for a plain
                # non-amend commit and cannot be combined with --author.
                arguments.extend(('--author=' + self.identity.name + ' <' + self.identity.email + '>', '--date=now'))
        receipt_fds = ()
        if transaction is not None:
            kind = 'abort' if command.command == 'cherry-pick' and command.args == ('--abort',) else command.kind
            if type(transaction) is not ReferenceTransaction or transaction.kind != kind:
                raise GitRuntimeError('INVALID_GIT_TRANSACTION')
            try:
                transaction.require_fresh()
                receipt_fd = _fd(transaction.child_fd)
                if receipt_fd in (*self.view.fds, self.backend.fd, self.transport_fd):
                    raise GitRuntimeError('INVALID_GIT_DESCRIPTOR')
                receipt_fds = (receipt_fd,)
                env.update(transaction.environment)
            except GitTransactionError:
                raise GitRuntimeError('GIT_TRANSACTION_UNVERIFIED') from None
        command_line = (_path(self.backend.fd), '--no-pager', '--no-replace-objects',
            '--git-dir=' + gitdir, '--work-tree=' + worktree, command.command, *arguments)
        return GitInvocation(command_line, MappingProxyType(env),
            tuple(sorted({*self.view.fds, self.backend.fd, self.transport_fd, *receipt_fds})), worktree)

    def run(self, command, *, source_author=None, input_bytes=None, timeout=30, current=lambda: True, transaction=None):
        if (type(timeout) not in (int, float) or not 0 < timeout <= 60
                or (input_bytes is not None and (type(input_bytes) is not bytes or len(input_bytes) > MAX_INPUT))):
            raise GitRuntimeError('INVALID_GIT_IO_BOUND')
        if not callable(current):
            raise GitRuntimeError('INVALID_GIT_AUTHORITY_CHECK')
        if (transaction is not None and type(transaction) is not ReferenceTransaction
                or type(command) is GitCommand and command.kind in ('commit', 'cherry-pick') and transaction is None):
            raise GitRuntimeError('GIT_TRANSACTION_REQUIRED')

        def require_current():
            try:
                active = current() is True
            except Exception:
                active = False
            if not active:
                self.failed = True
                raise GitRuntimeError('GIT_AUTHORITY_REVOKED')
            if transaction is not None:
                try:
                    transaction.require()
                except GitTransactionError:
                    self.failed = True
                    raise GitRuntimeError('GIT_TRANSACTION_UNVERIFIED') from None

        require_current()
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise GitRuntimeError('GIT_CHILD_REAPER_CONFLICT')
        invocation = self.plan(command, source_author=source_author, transaction=transaction)
        require_current()
        proc = None
        self._quiescent = False  # Before even a potentially partial native spawn.
        try:
            proc = subprocess.Popen(invocation.argv, cwd=invocation.cwd, env=dict(invocation.env),
                pass_fds=invocation.pass_fds, stdin=subprocess.PIPE if input_bytes else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, start_new_session=True)
        except BaseException as error:
            self.failed = True
            if isinstance(error, OSError):
                raise GitRuntimeError('GIT_EXECUTION_UNAVAILABLE') from None
            raise
        data = {'stdout': bytearray(), 'stderr': bytearray()}
        deadline = time.monotonic() + timeout
        owned = True
        pending_pipes = [pipe for pipe in (proc.stdin, proc.stdout, proc.stderr) if pipe is not None]
        pipe_disposal_failed = False

        def dispose_pipe(pipe):
            nonlocal pipe_disposal_failed
            # A close may release its fd and then raise. Never retry that number.
            pending_pipes.remove(pipe)
            try:
                pipe.close()
            except BaseException:
                pipe_disposal_failed = True
                raise

        def observe_owned():
            nonlocal owned
            try:
                return os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except BaseException:
                owned = False
                self.failed = True
                raise GitRuntimeError('GIT_CHILD_OWNERSHIP_LOST') from None

        try:
            if transaction is not None:
                transaction.start(proc.pid)
            with selectors.DefaultSelector() as poll:
                for label in ('stdout', 'stderr'):
                    pipe = getattr(proc, label)
                    os.set_blocking(pipe.fileno(), False)
                    poll.register(pipe, selectors.EVENT_READ, label)
                pending = memoryview(input_bytes or b'')
                if pending:
                    os.set_blocking(proc.stdin.fileno(), False)
                    poll.register(proc.stdin, selectors.EVENT_WRITE, 'stdin')
                while poll.get_map():
                    require_current()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GitRuntimeError('GIT_TIMEOUT')
                    ready = poll.select(min(remaining, .1))
                    require_current()
                    for key, _ in ready:
                        if key.data == 'stdin':
                            try:
                                count = os.write(key.fileobj.fileno(), pending[:65536])
                            except BlockingIOError:
                                continue
                            except BrokenPipeError:
                                count = 0
                            if count <= 0:
                                pending = pending[:0]
                            else:
                                pending = pending[count:]
                            if not pending:
                                poll.unregister(key.fileobj)
                                dispose_pipe(key.fileobj)
                        else:
                            try:
                                block = os.read(key.fileobj.fileno(), 65536)
                            except BlockingIOError:
                                continue
                            if not block:
                                poll.unregister(key.fileobj)
                            else:
                                data[key.data].extend(block)
                                if sum(map(len, data.values())) > MAX_OUTPUT:
                                    raise GitRuntimeError('GIT_OUTPUT_LIMIT')
                while True:
                    require_current()
                    if observe_owned() is not None:
                        break
                    if time.monotonic() >= deadline:
                        raise GitRuntimeError('GIT_TIMEOUT')
                    time.sleep(.001)
        except GitTransactionError:
            self.failed = True
            raise GitRuntimeError('GIT_TRANSACTION_UNVERIFIED') from None
        except OSError:
            raise GitRuntimeError('GIT_IO_UNAVAILABLE') from None
        finally:
            cleanup_verified = False
            cleanup_error = None
            try:
                try:
                    if transaction is not None:
                        transaction.stop()  # Before releasing numeric-PID ownership.
                finally:
                    if owned:
                        observe_owned()  # Ownership before every numeric-group signal.
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        owned = False  # Never signal/retry after crossing wait/reap.
                        code = proc.wait(timeout=2)
                        if type(code) is not int or code != proc.returncode:
                            raise GitRuntimeError('GIT_CLEANUP_UNVERIFIED')
                        cleanup_verified = True
            except BaseException as error:
                cleanup_error = error
            finally:
                for pipe in tuple(pending_pipes):
                    try:
                        dispose_pipe(pipe)
                    except BaseException as error:
                        if cleanup_error is None:
                            cleanup_error = error
            self._quiescent = cleanup_verified and cleanup_error is None and not pipe_disposal_failed
            if cleanup_error is not None or pipe_disposal_failed:
                self.failed = True
                raise GitRuntimeError('GIT_CLEANUP_UNVERIFIED') from None
        try:
            require_current()
            self._require()
            require_current()
        except GitRuntimeError:
            self.failed = True
            raise
        return GitResult(proc.returncode, bytes(data['stdout']), bytes(data['stderr']))
