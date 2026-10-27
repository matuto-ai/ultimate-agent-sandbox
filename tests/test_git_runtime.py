"""Mocked Workstation Git plans/execution: never runs Git, mounts or processes."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import selectors
import signal
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.forge import ForgeBinding
from uas.git_policy import GitCommand, GitIdentity, parse_git
from uas.git_runtime import (BACKEND_FD, GitInvocation, GitResult, GitRuntime, GitRuntimeError,
    MAX_OUTPUT, PROJECT_GID, WORKER_UID, RuntimeView, SealedGit, SSH_SHIM, _SEALS, _require_hooks, compile_git_config)
from uas.git_transaction import HOOK_DIRECTORY, HOOK_SCRIPT, GitTransactionError, ReferenceTransaction


BINDING = ForgeBinding('room', 'project', 'Owner/Project')
IDENTITY = GitIdentity('alice', 'Alice Canonical', 'alice@example.invalid')
ELF = b'\x7fELFfixed-git-fixture-bytes'
CHECKSUM = hashlib.sha256(ELF).hexdigest()


def node(inode, mode, *, uid=65532, size=0):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_size=size, st_nlink=1)


class Projection:
    """All descriptor/path observations are inert fabricated records."""
    def __init__(self):
        config = compile_git_config(BINDING)
        self.nodes = {10: node(10, stat.S_IFDIR | 0o700), 11: node(11, stat.S_IFDIR | 0o700),
            12: node(12, stat.S_IFREG | 0o444, uid=0, size=len(config)),
            13: node(13, stat.S_IFDIR | 0o555, uid=0), 14: node(14, stat.S_IFDIR | 0o700),
            BACKEND_FD: node(19, stat.S_IFREG | 0o500, size=len(ELF)),
            20: node(20, stat.S_IFSOCK | 0o600)}
        self.aliases = {11: '/opt/uas/git-views/checkout/gitdir', 14: '/opt/uas/git-views/checkout/common'}
        pointer = (self.aliases[14] + '\n').encode()
        self.nodes.update({fd: node(fd, stat.S_IFDIR | 0o555, uid=0) for fd in range(51, 56)})
        self.nodes[61] = node(61, stat.S_IFREG | 0o444, uid=0, size=len(pointer))
        self.contents = {12: config, BACKEND_FD: ELF, 61: pointer}
        self.visible_config = self.nodes[12]
        self.readonly = {12, 13, 54, 55, 61}
        self.special = {}
        self.helper_names = ['git']
        self.helper_target = '/proc/self/fd/19'
        self.home = node(100, stat.S_IFDIR | 0o700, uid=WORKER_UID)
        self.home_entries = []
        self.denied = set()
        self.proc = {'/proc/self/fdinfo/10': b'pos:\t0\nmnt_id:\t42\n',
            '/proc/self/fdinfo/11': b'mnt_id:\t43\n', '/proc/self/fdinfo/14': b'mnt_id:\t44\n',
            '/proc/self/mountinfo': self.mounts(b'42 1 0:1 / /project rw - tmpfs tmpfs rw\n')}

    def mounts(self, worktree):
        return worktree + b''.join((str(index + 43) + ' 1 0:1 / ' + path + ' rw - tmpfs tmpfs rw\n').encode()
                                  for index, path in enumerate(self.aliases.values()))

    def open(self, path, *_args, **kwargs):
        return {'/': 51, 'opt': 52, 'uas': 53, 'git-views': 54, 'checkout': 55, 'commondir': 61}[path]

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        if path == 'config':
            return self.visible_config
        if path == 'git' and dir_fd == 13:
            return node(30, stat.S_IFLNK | 0o777, uid=0)
        if (dir_fd, path) in self.special:
            return self.special[(dir_fd, path)]
        if path == 'commondir':
            return self.nodes[61]
        for fd, alias in self.aliases.items():
            if path == alias:
                return self.nodes[fd]
        if path == '/project':
            return self.nodes[10]
        if path == '/other':
            return node(999, stat.S_IFDIR | 0o700)
        raise FileNotFoundError()

    def install(self, stack):
        stack.enter_context(patch('uas.git_runtime._require_hooks'))
        stack.enter_context(patch('uas.git_runtime.os.getuid', return_value=WORKER_UID))
        stack.enter_context(patch('uas.git_runtime.os.geteuid', return_value=WORKER_UID))
        stack.enter_context(patch('uas.git_runtime.os.getgid', return_value=PROJECT_GID))
        stack.enter_context(patch('uas.git_runtime.os.getegid', return_value=PROJECT_GID))
        stack.enter_context(patch('uas.git_runtime.os.open', side_effect=self.open))
        stack.enter_context(patch('uas.git_runtime.os.close'))
        stack.enter_context(patch('uas.git_runtime.os.access', side_effect=lambda path, mode, **kwargs: path not in self.denied))
        stack.enter_context(patch('uas.git_runtime._read_proc', side_effect=lambda path, maximum: self.proc[path]))
        stack.enter_context(patch('uas.git_runtime.os.fstat', side_effect=lambda fd: self.nodes[fd]))
        stack.enter_context(patch('uas.git_runtime.os.stat', side_effect=self.stat))
        stack.enter_context(patch('uas.git_runtime.os.fstatvfs', side_effect=lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if fd in self.readonly else 0)))
        stack.enter_context(patch('uas.git_runtime.os.pread', side_effect=lambda fd, size, offset: self.contents[fd][offset:offset + size]))
        stack.enter_context(patch('uas.git_runtime.os.listdir', side_effect=lambda path: self.helper_names if path == 13 else self.home_entries))
        stack.enter_context(patch('uas.git_runtime.os.readlink', side_effect=lambda path, **kwargs: self.helper_target))
        stack.enter_context(patch('uas.git_runtime.fcntl.fcntl', return_value=_SEALS))
        stack.enter_context(patch.object(Path, 'resolve', lambda path: path))
        stack.enter_context(patch.object(Path, 'lstat', lambda path: self.home))

    def runtime(self, *, common_fd=14, checkout_owner=65532):
        return GitRuntime(RuntimeView(10, 11, 12, 13, binding=BINDING, common_fd=common_fd, checkout_owner=checkout_owner),
            SealedGit(19, CHECKSUM), IDENTITY, transport_fd=20, home='/temporary/private-home')


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.projection = Projection()
        self.projection.install(self.stack)

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(GitRuntimeError) as raised:
            fn(*args, **kwargs)
        self.assertEqual(code, raised.exception.code)

    def test_fixed_config_has_only_pinned_transport_no_includes_or_program_routes(self):
        config = compile_git_config(BINDING)
        self.assertIn(b'url = git@github.com:Owner/Project.git', config)
        for required in (b'hooksPath = /opt/uas/git-hooks', b'fsmonitor = false', b'worktreeConfig = false',
                         b'allow = never', b'allow = always', b'autoSetupMerge = false', b'abbrev = 40'):
            self.assertIn(required, config)
        for forbidden in (b'include', b'insteadOf', b'filter ', b'sshCommand', b'proxy', b'http'):
            self.assertNotIn(forbidden, config)
        self.error('INVALID_GIT_BINDING', compile_git_config, ForgeBinding('r', 'p', 'x/y', 'evil.invalid'))

    def test_new_runtime_is_quiescent_but_not_writable_by_result_callers(self):
        runtime = self.projection.runtime()
        self.assertIs(runtime.quiescent, True)
        with self.assertRaises(AttributeError):
            runtime.quiescent = True

    def test_readonly_filesystem_not_mode_bits_is_required_for_config_and_helpers(self):
        for fd in (12, 13):
            self.projection.readonly.remove(fd)
            self.error('GIT_CONFIG_NOT_IMMUTABLE', self.projection.runtime)
            self.projection.readonly.add(fd)

    def test_visible_config_must_be_exact_pinned_regular_inode(self):
        self.projection.visible_config = node(999, stat.S_IFREG | 0o444)
        self.error('GIT_CONFIG_NOT_IMMUTABLE', self.projection.runtime)
        self.projection.visible_config = node(12, stat.S_IFLNK | 0o777)
        self.error('GIT_CONFIG_NOT_IMMUTABLE', self.projection.runtime)

    def test_config_extra_includes_or_exact_byte_drift_refuse(self):
        self.projection.contents[12] += b'[include]\npath=/project/evil\n'
        self.projection.nodes[12].st_size = len(self.projection.contents[12])
        self.error('GIT_CONFIG_MISMATCH', self.projection.runtime)

    def test_config_worktree_and_unbound_linked_gitdir_refuse(self):
        self.projection.special[(11, 'config.worktree')] = node(888, stat.S_IFREG | 0o600)
        self.error('GIT_WORKTREE_CONFIG_UNAVAILABLE', self.projection.runtime)
        self.projection.special.clear()
        self.projection.special[(11, 'commondir')] = node(888, stat.S_IFREG | 0o600)
        self.error('GIT_COMMON_DIR_UNBOUND', self.projection.runtime)
        self.projection.special.clear()
        self.error('GIT_COMMON_DIR_UNBOUND', self.projection.runtime, common_fd=None)
        runtime = self.projection.runtime(common_fd=14)
        invocation = runtime.plan(parse_git('git', ['status']))
        self.assertEqual('/proc/self/fd/14', invocation.env['GIT_COMMON_DIR'])
        self.assertEqual('/proc/self/fd/11/index', invocation.env['GIT_INDEX_FILE'])

    def test_helper_directory_has_one_exact_readonly_self_backend_link(self):
        for names, target in ((['git', 'evil'], '/proc/self/fd/19'), (['git'], '/usr/bin/git'),
                              (['git'], '/proc/self/fd/18'), ([], '/proc/self/fd/19')):
            self.projection.helper_names, self.projection.helper_target = names, target
            self.error('INVALID_GIT_HELPERS', self.projection.runtime)

    def test_sealed_backend_is_reserved_fd_exact_elf_and_all_four_seals(self):
        self.error('INVALID_GIT_BACKEND', SealedGit, 18, CHECKSUM)
        for missing in (1, 2, 4, 8):
            with patch('uas.git_runtime.fcntl.fcntl', return_value=_SEALS & ~missing):
                self.error('INVALID_GIT_BACKEND', SealedGit, 19, CHECKSUM)
        self.error('GIT_BACKEND_MISMATCH', SealedGit, 19, '0' * 64)
        self.projection.contents[19] = b'#!/bin/sh\nevil'
        self.projection.nodes[19].st_size = len(self.projection.contents[19])
        self.error('GIT_BACKEND_MISMATCH', SealedGit, 19, hashlib.sha256(self.projection.contents[19]).hexdigest())

    def test_unprivileged_owner_pins_and_current_inode_are_required(self):
        runtime = self.projection.runtime()
        self.projection.nodes[10] = node(999, stat.S_IFDIR | 0o700)
        self.error('GIT_PROJECTION_CHANGED', runtime.plan, parse_git('git', ['status']))
        with patch('uas.git_runtime.os.getuid', return_value=0):
            self.error('UNPRIVILEGED_WORKSTATION_REQUIRED', self.projection.runtime)

    def test_distinct_worker_preserves_explicit_project_owner_and_requires_existing_access(self):
        for owner in (0, 1000, 65532):
            for fd in (10, 11, 14):
                self.projection.nodes[fd].st_uid = owner
            self.assertEqual(owner, self.projection.runtime(checkout_owner=owner).view.checkout_owner)
        self.error('INVALID_GIT_PROJECTION', self.projection.runtime, checkout_owner=WORKER_UID)
        for owner in (True, -1, 2**32 - 1, '65532'):
            self.error('INVALID_GIT_CHECKOUT_OWNER', self.projection.runtime, checkout_owner=owner)
        for fd in (10, 11, 14):
            self.projection.denied.add('/proc/self/fd/' + str(fd))
            self.error('GIT_CHECKOUT_ACCESS_UNAVAILABLE', self.projection.runtime, common_fd=14)
            self.projection.denied.clear()
        with patch('uas.git_runtime.os.getuid', return_value=65532):
            self.error('UNPRIVILEGED_WORKSTATION_REQUIRED', self.projection.runtime)
        with patch('uas.git_runtime.os.getgid', return_value=1000):
            self.error('UNPRIVILEGED_WORKSTATION_REQUIRED', self.projection.runtime)

    def test_worktree_is_exact_mounted_root_not_just_pinned_directory(self):
        self.projection.proc['/proc/self/mountinfo'] = self.projection.mounts(b'42 1 0:1 / /other rw - tmpfs tmpfs rw\n')
        self.error('GIT_WORKTREE_NOT_MOUNT_ROOT', self.projection.runtime)
        for raw in (b'', b'43 1 0:1 / /project rw - tmpfs tmpfs rw\n',
                    b'42 1 0:1 / relative rw - tmpfs tmpfs rw\n',
                    b'42 1 0:1 / /project rw - tmpfs tmpfs rw\n' * 2):
            self.projection.proc['/proc/self/mountinfo'] = self.projection.mounts(raw)
            self.error('GIT_MOUNT_ROOT_UNVERIFIED', self.projection.runtime)
        self.projection.proc['/proc/self/mountinfo'] = self.projection.mounts(b'42 1 0:1 / /project rw - tmpfs tmpfs rw\n')
        runtime = self.projection.runtime()
        self.projection.proc['/proc/self/fdinfo/10'] = b'mnt_id:\t45\n'
        self.projection.proc['/proc/self/mountinfo'] = self.projection.mounts(b'45 1 0:1 / /project rw - tmpfs tmpfs rw\n')
        self.error('GIT_PROJECTION_CHANGED', runtime.plan, parse_git('git', ['status']))
        for raw in (b'', b'mnt_id:\tinvalid\n', b'mnt_id:\t42 extra\n', b'mnt_id:\t42\n' * 2):
            self.projection.proc['/proc/self/fdinfo/10'] = raw
            self.error('GIT_MOUNT_ROOT_UNVERIFIED', self.projection.runtime)

    def test_mountinfo_kernel_escaped_paths_are_decoded(self):
        self.projection.proc['/proc/self/mountinfo'] = self.projection.mounts(b'42 1 0:1 / /project\\040space rw - tmpfs tmpfs rw\n')
        self.projection.special[(None, '/project space')] = self.projection.nodes[10]
        self.assertEqual(42, self.projection.runtime().view.mount_id)

    def test_commondir_requires_exact_immutable_pointer_despite_environment_override(self):
        original = self.projection.contents[61]
        for raw in (b'', b'.\n', b'../../elsewhere\n', b'/tmp/foreign\n', original + b'\n',
                    b'/proc/self/fd/14\n'):
            self.projection.contents[61] = raw
            self.projection.nodes[61].st_size = len(raw)
            self.error('GIT_COMMON_DIR_UNBOUND', self.projection.runtime)
        self.projection.contents[61] = original
        self.projection.nodes[61].st_size = len(original)
        self.projection.readonly.remove(61)
        self.error('GIT_COMMON_DIR_UNBOUND', self.projection.runtime)
        self.projection.readonly.add(61)
        for key, value in (('st_uid', 65532), ('st_mode', stat.S_IFREG | 0o644),
                           ('st_nlink', 2), ('st_mode', stat.S_IFLNK | 0o444)):
            old = getattr(self.projection.nodes[61], key)
            setattr(self.projection.nodes[61], key, value)
            self.error('GIT_COMMON_DIR_UNBOUND', self.projection.runtime)
            setattr(self.projection.nodes[61], key, old)
        with patch('uas.git_runtime.os.open', side_effect=FileNotFoundError()):
            self.error('GIT_VIEW_ANCESTRY_UNSAFE', self.projection.runtime)

    def test_gitdir_common_mounts_and_fixed_alias_slot_are_required(self):
        original = self.projection.proc['/proc/self/mountinfo']
        for fd in (11, 14):
            mount = self.projection.proc['/proc/self/fdinfo/' + str(fd)]
            self.projection.proc['/proc/self/fdinfo/' + str(fd)] = b'mnt_id:\t999\n'
            self.error('GIT_MOUNT_ROOT_UNVERIFIED', self.projection.runtime)
            self.projection.proc['/proc/self/fdinfo/' + str(fd)] = mount
        self.projection.aliases[11] = '/project/.git'
        self.projection.proc['/proc/self/mountinfo'] = self.projection.mounts(b'42 1 0:1 / /project rw - tmpfs tmpfs rw\n')
        self.error('GIT_VIEW_ALIAS_REQUIRED', self.projection.runtime)
        self.projection.aliases[11] = '/opt/uas/git-views/checkout/gitdir'
        self.projection.aliases[14] = '/opt/uas/git-views/other/common'
        self.projection.proc['/proc/self/mountinfo'] = self.projection.mounts(b'42 1 0:1 / /project rw - tmpfs tmpfs rw\n')
        with patch('uas.git_runtime.os.open', side_effect=lambda path, *a, **k:
                   55 if path == 'other' else self.projection.open(path, *a, **k)):
            self.error('GIT_COMMON_DIR_UNBOUND', self.projection.runtime)
        self.projection.proc['/proc/self/mountinfo'] = original

    def test_root_owned_nonwritable_readonly_alias_ancestry_cannot_be_renamed(self):
        for fd in range(51, 56):
            original = self.projection.nodes[fd].st_uid
            self.projection.nodes[fd].st_uid = WORKER_UID
            self.error('GIT_VIEW_ANCESTRY_UNSAFE', self.projection.runtime)
            self.projection.nodes[fd].st_uid = original
            self.projection.nodes[fd].st_mode |= 0o020
            self.error('GIT_VIEW_ANCESTRY_UNSAFE', self.projection.runtime)
            self.projection.nodes[fd].st_mode &= ~0o020
        for fd in (54, 55):
            self.projection.readonly.remove(fd)
            self.error('GIT_VIEW_ANCESTRY_UNSAFE', self.projection.runtime)
            self.projection.readonly.add(fd)

    def test_replaced_mount_ancestor_or_pointer_fences_existing_view(self):
        for fd in (54, 61):
            runtime = self.projection.runtime()
            self.projection.nodes[fd].st_ino += 1
            self.error('GIT_PROJECTION_CHANGED', runtime.plan, parse_git('git', ['status']))
            self.projection.nodes[fd].st_ino -= 1
        runtime = self.projection.runtime()
        self.projection.proc['/proc/self/fdinfo/14'] = b'mnt_id:\t99\n'
        self.projection.proc['/proc/self/mountinfo'] = self.projection.proc['/proc/self/mountinfo'].replace(b'44 1 ', b'99 1 ')
        self.error('GIT_PROJECTION_CHANGED', runtime.plan, parse_git('git', ['status']))

    def test_cwd_selection_checks_inode_but_native_argv_pins_descriptor_paths(self):
        runtime = self.projection.runtime()
        invocation = runtime.plan(parse_git('git', ['-C', '/project', 'status']))
        self.assertEqual('/proc/self/fd/10', invocation.cwd)
        self.assertIn('--git-dir=/proc/self/fd/11', invocation.argv)
        self.assertIn('--work-tree=/proc/self/fd/10', invocation.argv)
        self.assertNotIn('/project', invocation.argv)
        self.error('GIT_CHECKOUT_MISMATCH', runtime.plan, parse_git('git', ['-C', '/other', 'status']))

    def test_home_must_be_private_empty_and_transport_must_be_socket(self):
        self.projection.home_entries = ['.gitconfig']
        self.error('INVALID_GIT_HOME', self.projection.runtime)
        self.projection.home_entries = []
        self.projection.home.st_mode = stat.S_IFDIR | 0o755
        self.error('INVALID_GIT_HOME', self.projection.runtime)
        self.projection.home.st_mode = stat.S_IFDIR | 0o700
        self.projection.nodes[20] = node(20, stat.S_IFREG | 0o600)
        self.error('INVALID_GIT_TRANSPORT', self.projection.runtime)

    def test_plan_has_no_incoming_environment_identity_or_host_configuration(self):
        incoming = {'GIT_CONFIG_COUNT': '9', 'GIT_SSH_COMMAND': 'evil', 'GIT_AUTHOR_NAME': 'forged',
                    'SSH_AUTH_SOCK': '/secret/socket', 'LD_PRELOAD': '/evil.so', 'PATH': '/evil',
                    'GH_TOKEN': 'private-secret', 'SSH_CONFIG': '/evil', 'HOME': '/evil'}
        runtime = self.projection.runtime()
        with patch.dict(os.environ, incoming, clear=True):
            invocation = runtime.plan(parse_git('git', ['commit', '-m', 'change']))
        self.assertEqual('Alice Canonical', invocation.env['GIT_AUTHOR_NAME'])
        self.assertEqual('alice@example.invalid', invocation.env['GIT_COMMITTER_EMAIL'])
        self.assertEqual('/proc/self/fd/13', invocation.env['PATH'])
        self.assertEqual(SSH_SHIM + ' --fd 20', invocation.env['GIT_SSH_COMMAND'])
        self.assertEqual('/dev/null', invocation.env['GIT_CONFIG_GLOBAL'])
        self.assertEqual('/dev/null', invocation.env['GIT_CONFIG_SYSTEM'])
        for key in ('SSH_AUTH_SOCK', 'LD_PRELOAD', 'GH_TOKEN', 'SSH_CONFIG', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS'):
            self.assertNotIn(key, invocation.env)
        self.assertEqual((10, 11, 12, 13, 14, 19, 20), invocation.pass_fds)
        with self.assertRaises(TypeError):
            invocation.env['GIT_SSH_COMMAND'] = 'evil'

    def test_amend_forces_reset_author_and_cherry_has_source_author_environment_unset(self):
        runtime = self.projection.runtime()
        ordinary = runtime.plan(parse_git('git', ['commit', '-m', 'change']))
        self.assertEqual(('--author=Alice Canonical <alice@example.invalid>', '--date=now'), ordinary.argv[-2:])
        amend = runtime.plan(parse_git('git', ['commit', '--amend', '--no-edit']))
        self.assertEqual('--reset-author', amend.argv[-1])
        self.assertFalse(any(argument.startswith('--author=') for argument in amend.argv))
        for args in (['cherry-pick', 'a' * 40], ['cherry-pick', '--continue'], ['cherry-pick', '--abort']):
            invocation = runtime.plan(parse_git('git', args), source_author='Source <source@example.invalid> 1 +0230')
            for name in ('GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_AUTHOR_DATE'):
                self.assertNotIn(name, invocation.env)
            self.assertEqual('Alice Canonical', invocation.env['GIT_COMMITTER_NAME'])
            self.assertEqual(args[1] == 'a' * 40, '-x' in invocation.argv)
            self.assertFalse(any(argument.startswith(('--author=', '--date=')) for argument in invocation.argv))

    def test_tampered_command_help_and_unexpected_source_author_never_spawn(self):
        runtime = self.projection.runtime()
        self.error('INVALID_GIT_COMMAND', runtime.plan, GitCommand('status', (), 'commit'))
        self.error('INVALID_GIT_COMMAND', runtime.plan, GitCommand('config', ('--global',), 'local-read'))
        self.error('GIT_HELP_IS_LOCAL', runtime.plan, parse_git('git', ['--help']))
        self.error('UNEXPECTED_GIT_SOURCE_AUTHOR', runtime.plan, parse_git('git', ['status']), source_author='Source <s@x> 1 +0000')
        self.error('INVALID_GIT_SOURCE_AUTHOR', runtime.plan, parse_git('git', ['cherry-pick', 'a' * 40]), source_author='bad\nheader')

    def test_plan_adds_only_exact_private_receipt_context_to_attributed_command(self):
        runtime = self.projection.runtime()
        receipt = object.__new__(ReferenceTransaction)
        receipt.closed, receipt.kind = False, 'commit'
        receipt.right, receipt.require_fresh = Mock(), Mock()
        receipt.right.fileno.return_value = 30
        receipt.nonce, receipt.operation_id, receipt.worker_pid = 'a' * 64, 'op-1', 123
        invocation = runtime.plan(parse_git('git', ['commit', '-m', 'change']), transaction=receipt)
        self.assertIn(30, invocation.pass_fds)
        self.assertEqual('30', invocation.env['UAS_GIT_TX_FD'])
        self.assertEqual('op-1', invocation.env['UAS_GIT_TX_OPERATION'])
        self.assertEqual('a' * 64, invocation.env['UAS_GIT_TX_NONCE'])
        self.error('INVALID_GIT_TRANSACTION', runtime.plan, parse_git('git', ['status']), transaction=receipt)
        receipt.right.fileno.return_value = 19
        self.error('INVALID_GIT_DESCRIPTOR', runtime.plan, parse_git('git', ['commit', '-m', 'x']), transaction=receipt)


class HookProjectionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.nodes = {71: node(71, stat.S_IFDIR | 0o500, uid=WORKER_UID),
                      72: node(72, stat.S_IFREG | 0o555, uid=0, size=len(HOOK_SCRIPT))}
        self.raw = HOOK_SCRIPT
        self.readonly = {71, 72}
        self.names = ['reference-transaction']
        self.open = self.stack.enter_context(patch('uas.git_runtime.os.open', side_effect=lambda path, *args, **kwargs: 71 if path == HOOK_DIRECTORY else 72))
        self.close = self.stack.enter_context(patch('uas.git_runtime.os.close'))
        self.stack.enter_context(patch('uas.git_runtime.os.fstat', side_effect=lambda fd: self.nodes[fd]))
        self.stack.enter_context(patch('uas.git_runtime.os.fstatvfs', side_effect=lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if fd in self.readonly else 0)))
        self.stack.enter_context(patch('uas.git_runtime.os.listdir', side_effect=lambda fd: self.names))
        self.stack.enter_context(patch('uas.git_runtime.os.pread', side_effect=lambda fd, size, offset: self.raw[offset:offset + size]))

    def test_exact_worker_only_readonly_single_hook_and_bounded_bytes(self):
        _require_hooks()
        self.assertEqual([72, 71], [call.args[0] for call in self.close.call_args_list])
        self.assertTrue(self.open.call_args_list[0].args[1] & os.O_NOFOLLOW)
        self.assertEqual(HOOK_SCRIPT, Path(__file__).resolve().parents[1].joinpath('runtime/git/reference-transaction.py').read_bytes())

    def test_permission_filename_mount_and_code_drift_refuse(self):
        modifications = [lambda: setattr(self.nodes[71], 'st_uid', 65532),
            lambda: setattr(self.nodes[71], 'st_mode', stat.S_IFDIR | 0o555),
            lambda: self.readonly.remove(71), lambda: self.names.append('pre-commit'),
            lambda: setattr(self.nodes[72], 'st_mode', stat.S_IFREG | 0o755),
            lambda: self.readonly.remove(72), lambda: setattr(self, 'raw', b'x' * len(HOOK_SCRIPT))]
        for change in modifications:
            with self.subTest(change=change):
                self.nodes[71] = node(71, stat.S_IFDIR | 0o500, uid=WORKER_UID)
                self.nodes[72] = node(72, stat.S_IFREG | 0o555, uid=0, size=len(HOOK_SCRIPT))
                self.readonly, self.names, self.raw = {71, 72}, ['reference-transaction'], HOOK_SCRIPT
                change()
                with self.assertRaises(GitRuntimeError):
                    _require_hooks()


class Pipe:
    def __init__(self, fd):
        self.fd, self.closed = fd, False
    def fileno(self):
        return self.fd
    def close(self):
        self.closed = True


class Poll:
    def __init__(self):
        self.mapping = {}
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def register(self, pipe, mask, data):
        self.mapping[pipe.fd] = (SimpleNamespace(fileobj=pipe, data=data), mask)
    def unregister(self, pipe):
        del self.mapping[pipe.fd]
    def get_map(self):
        return self.mapping
    def select(self, timeout):
        if timeout > .1:
            raise AssertionError('cancellation check exceeded 100ms tick')
        return list(self.mapping.values())


class RuntimeExecutionTests(unittest.TestCase):
    def setUp(self):
        self.runtime = object.__new__(GitRuntime)
        self.runtime.failed = False
        self.runtime._quiescent = True
        self.command = parse_git('git', ['status'])
        self.invocation = GitInvocation(('/proc/self/fd/19', 'status'), {}, (19,), '/proc/self/fd/10')
        self.runtime.plan = Mock(return_value=self.invocation)
        self.runtime._require = Mock()
        self.order = []
        self.proc = SimpleNamespace(pid=123, stdin=None, stdout=Pipe(50), stderr=Pipe(51), returncode=0)
        self.proc.wait = Mock(side_effect=lambda **kwargs: self.order.append('wait') or self.proc.returncode)
        self.blocks = {50: [b'stdout', b''], 51: [b'stderr', b'']}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.popen = self.stack.enter_context(patch('uas.git_runtime.subprocess.Popen', return_value=self.proc))
        self.stack.enter_context(patch('uas.git_runtime.signal.getsignal', return_value=signal.SIG_DFL))
        self.stack.enter_context(patch('uas.git_runtime.selectors.DefaultSelector', side_effect=Poll))
        self.stack.enter_context(patch('uas.git_runtime.os.set_blocking'))
        self.stack.enter_context(patch('uas.git_runtime.os.read', side_effect=lambda fd, size: self.blocks[fd].pop(0)))
        self.waitid = self.stack.enter_context(patch('uas.git_runtime.os.waitid', side_effect=lambda *args: self.order.append('observe') or SimpleNamespace(si_status=0)))
        self.kill = self.stack.enter_context(patch('uas.git_runtime.os.killpg', side_effect=lambda *args: self.order.append('kill')))
        self.stack.enter_context(patch('uas.git_runtime.time.monotonic', return_value=0))
        self.stack.enter_context(patch('uas.git_runtime.time.sleep'))

    def error(self, code, **kwargs):
        with self.assertRaises(GitRuntimeError) as raised:
            self.runtime.run(self.command, **kwargs)
        self.assertEqual(code, raised.exception.code)

    def test_native_result_is_bounded_and_cleanup_signals_owned_group_before_single_wait(self):
        result = self.runtime.run(self.command)
        self.assertEqual(GitResult(0, b'stdout', b'stderr'), result)
        self.assertEqual(['observe', 'observe', 'kill', 'wait'], self.order)
        self.proc.wait.assert_called_once_with(timeout=2)
        self.assertTrue(self.proc.stdout.closed and self.proc.stderr.closed)
        kwargs = self.popen.call_args.kwargs
        self.assertFalse(kwargs['shell'])
        self.assertTrue(kwargs['start_new_session'])
        self.assertEqual((19,), kwargs['pass_fds'])
        self.runtime._require.assert_called_once_with()
        self.assertIs(self.runtime.quiescent, True)

    def test_quiescence_is_withheld_before_spawn_until_wait_and_every_pipe_close(self):
        checks = []
        self.popen.side_effect = lambda *args, **kwargs: checks.append(self.runtime.quiescent) or self.proc
        self.proc.wait.side_effect = lambda **kwargs: checks.append(self.runtime.quiescent) or 0
        for pipe in (self.proc.stdout, self.proc.stderr):
            pipe.close = Mock(side_effect=lambda: checks.append(self.runtime.quiescent))
        self.runtime.run(self.command)
        self.assertEqual([False, False, False, False], checks)
        self.assertIs(self.runtime.quiescent, True)

    def test_spawn_uncertainty_never_claims_quiescence_or_attempts_numeric_cleanup(self):
        for error in (OSError('spawn uncertain'), RuntimeError('spawn may have happened')):
            with self.subTest(error=type(error).__name__):
                self.runtime._quiescent = True
                self.popen.side_effect = error
                with self.assertRaises((GitRuntimeError, RuntimeError)):
                    self.runtime.run(self.command)
                self.assertIs(self.runtime.quiescent, False)
                self.assertTrue(self.runtime.failed)
        self.kill.assert_not_called()
        self.proc.wait.assert_not_called()

    def test_failed_pipe_disposal_attempts_others_once_but_withholds_quiescence(self):
        self.proc.stdout.close = Mock(side_effect=OSError('possibly already closed'))
        self.proc.stderr.close = Mock()
        self.error('GIT_CLEANUP_UNVERIFIED')
        self.proc.stdout.close.assert_called_once_with()
        self.proc.stderr.close.assert_called_once_with()
        self.proc.wait.assert_called_once_with(timeout=2)
        self.assertIs(self.runtime.quiescent, False)

    def test_uncertain_early_stdin_close_is_not_retried_or_called_quiescent(self):
        self.proc.stdin = Pipe(52)
        self.proc.stdin.close = Mock(side_effect=OSError('close uncertain'))
        with patch('uas.git_runtime.os.write', return_value=1):
            self.error('GIT_CLEANUP_UNVERIFIED', input_bytes=b'x')
        self.proc.stdin.close.assert_called_once_with()
        self.assertTrue(self.proc.stdout.closed and self.proc.stderr.closed)
        self.assertIs(self.runtime.quiescent, False)

    def test_non_integer_wait_result_is_not_positive_quiescence(self):
        self.proc.wait.side_effect = None
        self.proc.wait.return_value = None
        self.error('GIT_CLEANUP_UNVERIFIED')
        self.assertIs(self.runtime.quiescent, False)

    def test_nonzero_native_exit_is_reported_not_claimed_success(self):
        self.proc.returncode = 128
        self.assertEqual(128, self.runtime.run(self.command).returncode)

    def receipt(self):
        result = object.__new__(ReferenceTransaction)
        result.kind = 'commit'
        result.require = Mock()
        result.start = Mock(side_effect=lambda pid: self.order.append('receipt-start'))
        result.stop = Mock(side_effect=lambda: self.order.append('receipt-stop'))
        return result

    def test_commit_requires_receipt_before_native_spawn(self):
        self.command = parse_git('git', ['commit', '-m', 'change'])
        self.error('GIT_TRANSACTION_REQUIRED')
        self.popen.assert_not_called()

    def test_receipt_collector_stops_before_native_identity_is_reaped(self):
        receipt = self.receipt()
        self.runtime.run(self.command, transaction=receipt)
        self.assertEqual(['receipt-start', 'observe', 'receipt-stop', 'observe', 'kill', 'wait'], self.order)
        receipt.start.assert_called_once_with(123)
        receipt.stop.assert_called_once_with()

    def test_receipt_failure_owned_aborts_and_never_returns_success(self):
        receipt = self.receipt()
        receipt.start.side_effect = lambda pid: setattr(receipt.require, 'side_effect', GitTransactionError())
        self.error('GIT_TRANSACTION_UNVERIFIED', transaction=receipt)
        self.assertEqual(['receipt-stop', 'observe', 'kill', 'wait'], self.order)
        self.assertTrue(self.runtime.failed)

    def test_collector_start_or_stop_failure_does_not_skip_owned_native_cleanup(self):
        receipt = self.receipt()
        receipt.start.side_effect = GitTransactionError()
        self.error('GIT_TRANSACTION_UNVERIFIED', transaction=receipt)
        self.assertEqual(['receipt-stop', 'observe', 'kill', 'wait'], self.order)
        self.order.clear()
        receipt = self.receipt()
        receipt.stop.side_effect = RuntimeError('private')
        self.error('GIT_CLEANUP_UNVERIFIED', transaction=receipt)
        self.assertEqual(['receipt-start', 'observe', 'observe', 'kill', 'wait'], self.order)

    def test_revocation_before_spawn_prevents_native_execution(self):
        self.error('GIT_AUTHORITY_REVOKED', current=lambda: False)
        self.popen.assert_not_called()
        self.assertTrue(self.runtime.failed)
        self.assertIs(self.runtime.quiescent, True)

    def test_revocation_after_plan_still_prevents_native_execution(self):
        self.error('GIT_AUTHORITY_REVOKED', current=Mock(side_effect=[True, False]))
        self.popen.assert_not_called()

    def test_revocation_on_select_tick_cleans_up_owned_native_group(self):
        self.error('GIT_AUTHORITY_REVOKED', current=Mock(side_effect=[True, True, True, False]))
        self.assertEqual(['observe', 'kill', 'wait'], self.order)
        self.assertTrue(self.runtime.failed)
        self.assertIs(self.runtime.quiescent, True)

    def test_revocation_while_waiting_after_output_closure_still_aborts(self):
        current = Mock(side_effect=[True] * 6 + [False])
        self.error('GIT_AUTHORITY_REVOKED', current=current)
        self.assertEqual(['observe', 'kill', 'wait'], self.order)

    def test_revocation_after_native_cleanup_is_not_returned_as_success(self):
        self.runtime._require.side_effect = lambda: setattr(self.runtime, 'revoked', True)
        self.runtime.revoked = False
        self.error('GIT_AUTHORITY_REVOKED', current=lambda: not self.runtime.revoked)
        self.assertEqual(['observe', 'observe', 'kill', 'wait'], self.order)
        self.assertTrue(self.runtime.failed)
        self.assertIs(self.runtime.quiescent, True)

    def test_authority_callback_errors_fail_closed_without_details(self):
        self.error('GIT_AUTHORITY_REVOKED', current=Mock(side_effect=RuntimeError('private details')))
        self.popen.assert_not_called()
        self.error('INVALID_GIT_AUTHORITY_CHECK', current=None)

    def test_combined_stdout_stderr_limit_kills_before_reaping(self):
        self.blocks = {50: [b'a' * (MAX_OUTPUT // 2 + 1)], 51: [b'b' * (MAX_OUTPUT // 2)]}
        self.error('GIT_OUTPUT_LIMIT')
        self.assertEqual(['observe', 'kill', 'wait'], self.order)

    def test_timeout_uses_same_owned_cleanup_even_when_descendant_retains_output(self):
        with patch('uas.git_runtime.time.monotonic', side_effect=[0, 31]):
            self.error('GIT_TIMEOUT')
        self.assertEqual(['observe', 'kill', 'wait'], self.order)
        self.assertIs(self.runtime.quiescent, True)

    def test_lost_child_ownership_never_signals_or_reaps_a_reused_pid(self):
        self.waitid.side_effect = ChildProcessError()
        self.error('GIT_CHILD_OWNERSHIP_LOST')
        self.kill.assert_not_called()
        self.proc.wait.assert_not_called()
        self.assertTrue(self.runtime.failed)
        self.assertIs(self.runtime.quiescent, False)

    def test_selector_setup_failure_still_observes_ownership_before_cleanup(self):
        with patch.object(Poll, 'register', side_effect=OSError('private detail')):
            self.error('GIT_IO_UNAVAILABLE')
        self.assertEqual(['observe', 'kill', 'wait'], self.order)

    def test_uncertain_wait_never_resignals_and_latches_runtime(self):
        self.proc.wait.side_effect = OSError('private detail')
        self.error('GIT_CLEANUP_UNVERIFIED')
        self.kill.assert_called_once()
        self.proc.wait.assert_called_once()
        self.assertTrue(self.runtime.failed)
        self.assertIs(self.runtime.quiescent, False)

    def test_post_execution_projection_change_fences_runtime(self):
        self.runtime._require.side_effect = GitRuntimeError('GIT_PROJECTION_CHANGED')
        self.error('GIT_PROJECTION_CHANGED')
        self.assertTrue(self.runtime.failed)

    def test_bounded_stdin_uses_partial_nonblocking_writes_and_closes(self):
        self.proc.stdin = Pipe(52)
        writes = []
        with patch('uas.git_runtime.os.write', side_effect=lambda fd, data: writes.append(bytes(data[:2])) or min(2, len(data))):
            result = self.runtime.run(self.command, input_bytes=b'12345')
        self.assertEqual(b'12345', b''.join(writes))
        self.assertEqual(0, result.returncode)
        self.assertTrue(self.proc.stdin.closed)

    def test_input_timeout_reaper_and_spawn_failures_are_sanitized_without_native_retries(self):
        for timeout in (0, 61, True, float('nan'), '30'):
            self.error('INVALID_GIT_IO_BOUND', timeout=timeout)
        self.error('INVALID_GIT_IO_BOUND', input_bytes=b'x' * 524289)
        with patch('uas.git_runtime.signal.getsignal', return_value=signal.SIG_IGN):
            self.error('GIT_CHILD_REAPER_CONFLICT')
        self.popen.assert_not_called()
        self.popen.side_effect = OSError('private executable path')
        self.error('GIT_EXECUTION_UNAVAILABLE')
        self.popen.assert_called_once()


if __name__ == '__main__':
    unittest.main()
