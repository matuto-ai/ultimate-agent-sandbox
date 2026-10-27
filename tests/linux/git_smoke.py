#!/usr/bin/env python3
"""Hosted-only native Runtime/reference-transaction seam; never live GitHub.

The entry point requires an explicitly disposable GitHub Linux runner and root.
All mounts live in private mount/PID/network namespaces, /opt is a private tmpfs,
and ownership changes affect only this fixture's temporary files. No accounts,
credentials, host policy, Docker or VM are created. Importing is effect-free.
Run only after source review, preserving only GITHUB_ACTIONS and RUNNER_OS.
"""
from contextlib import ExitStack
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
UID, GID = 65530, 65532
CHECKOUT_OWNER = 65532
DEADLINE = 'UAS_NATIVE_GIT_SMOKE_DEADLINE'


def require(value, message):
    if not value:
        raise AssertionError(message)


def gate():
    require(os.getuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_OS') == 'Linux',
            'requires explicitly disposable hosted Linux root fixture')
    require(signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, ()),
            'unblocked fixture deadline required')


def command(*argv):
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=4)


def mount_readonly(path):
    command('/usr/bin/mount', '--bind', str(path), str(path))
    command('/usr/bin/mount', '-o', 'remount,bind,ro,nosuid,nodev', str(path))


def isolate_process():
    """Only this process tree loses privileges; never modifies host policy."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_ulong, ctypes.c_ulong)
    libc.prctl.restype = ctypes.c_int
    def prctl(option, argument):
        if libc.prctl(option, argument, 0, 0, 0):
            raise OSError(ctypes.get_errno(), 'fixture prctl failed')
    for cap in range(int(Path('/proc/sys/kernel/cap_last_cap').read_text()) + 1):
        prctl(24, cap)  # PR_CAPBSET_DROP, before losing transient root.
    os.setgroups([])
    os.setgid(GID)
    os.setuid(UID)
    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS.
    seccomp = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    seccomp.seccomp_init.argtypes = (ctypes.c_uint32,)
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint)
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = (ctypes.c_void_p,)
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = (ctypes.c_void_p,)
    context = seccomp.seccomp_init(0x7fff0000)  # Allow ordinary Git filesystem/process syscalls.
    require(context, 'seccomp context unavailable')
    try:
        # Private inherited AF_UNIX socketpair is the receipt path. No socket()
        # or connect() can open an external endpoint, even inside the netns.
        for name in ('socket', 'connect', 'mount', 'umount2', 'pivot_root', 'unshare', 'setns',
                     'ptrace', 'bpf', 'perf_event_open', 'kexec_load', 'init_module', 'finit_module',
                     'delete_module', 'reboot', 'open_by_handle_at', 'fsopen', 'fsmount',
                     'move_mount', 'mount_setattr', 'process_vm_writev'):
            number = seccomp.seccomp_syscall_resolve_name(name.encode())
            require(number >= 0 and seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) == 0,
                    'fixture seccomp rule unavailable: ' + name)
        require(seccomp.seccomp_load(context) == 0, 'fixture seccomp load failed')
    finally:
        seccomp.seccomp_release(context)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    require(all(status[key].strip() == value for key, value in
                {'CapEff': '0000000000000000', 'CapBnd': '0000000000000000',
                 'NoNewPrivs': '1', 'Seccomp': '2'}.items()), 'worker security status differs')
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError:
        pass
    else:
        raise AssertionError('worker opened an external-capable socket')


def view_paths(checkout='primary'):
    require(checkout in {'primary', 'linked'}, 'fixed fixture view slot required')
    slot = '/opt/uas/git-views/' + checkout
    return {'gitdir': slot + '/gitdir', 'common': slot + '/common',
            'config': slot + '/common/config', 'helpers': '/opt/uas/git-helpers'}


def provision(root):
    sys.path.insert(0, str(ROOT))
    from uas.forge import ForgeBinding
    from uas.git_runtime import compile_git_config
    from uas.git_setup import GitPrimarySetup
    from uas.git_transaction import HOOK_SCRIPT
    command('/usr/bin/mount', '--make-rprivate', '/')
    # Hides the runner's /opt only in this namespace; no host directory writes.
    command('/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=755,nosuid,nodev', 'uas-git-fixture', '/opt')
    package = Path('/opt/uas')
    package.mkdir(mode=0o755)
    shutil.copytree(ROOT / 'uas', package / 'uas', ignore=shutil.ignore_patterns('__pycache__'))
    for path in (package / 'uas').rglob('*'):
        require(not path.is_symlink(), 'source symlink is not fixture code')
        path.chmod(0o555 if path.is_dir() else 0o444)
    helpers = package / 'git-helpers'
    helpers.mkdir(mode=0o755)
    (helpers / 'git').symlink_to('/proc/self/fd/19')
    hooks = package / 'git-hooks'
    hooks.mkdir(mode=0o500)
    os.chown(hooks, UID, GID)
    (hooks / 'reference-transaction').write_bytes(HOOK_SCRIPT)
    (hooks / 'reference-transaction').chmod(0o555)
    binaries = package / 'bin'
    binaries.mkdir(mode=0o755)
    shutil.copyfile(ROOT / 'runtime/git/ssh-shim.py', binaries / 'git-ssh-shim')
    (binaries / 'git-ssh-shim').chmod(0o555)
    entries = json.loads((ROOT / 'runtime/git/public-entries.json').read_text())
    launcher = (ROOT / 'runtime/git/launcher.py').read_bytes()
    # The runner checkout's ancestors need not be traversable by fixture UIDs.
    # Stage reviewed source bytes while privileged; never chmod runner paths or
    # read/re-exec that checkout after dropping identity. /opt becomes readonly.
    sources = package / 'fixture-sources'
    sources.mkdir(mode=0o755)
    for source, name in ((ROOT / 'runtime/git/launcher.py', 'launcher.py'),
                         (ROOT / 'runtime/git/public-entries.json', 'public-entries.json'),
                         (ROOT / 'tests/linux/git_stream_smoke.py', 'git_stream_smoke.py')):
        shutil.copyfile(source, sources / name)
        (sources / name).chmod(0o444)
    require(type(entries) is list and len(entries) == len(set(entries))
            and all(type(name) is str and name in {'git', 'scalar'} or
                    type(name) is str and name.startswith('git-') and name[4:].replace('-', '').isalpha()
                    for name in entries), 'fixed public Git entries required')
    for name in entries:
        entry = binaries / name
        entry.write_bytes(launcher)
        entry.chmod(0o555)
        require(not entry.is_symlink() and hashlib.sha256(entry.read_bytes()).digest()
                == hashlib.sha256(launcher).digest(), 'public alias is not the exact controlled launcher')
    root.chmod(0o755)
    parent = root / 'project-parent'
    parent.mkdir(mode=0o770)
    os.chown(parent, UID, GID)
    parent.chmod(0o770)
    worktree = parent / 'worktree'
    gitdir = worktree / '.git'
    for path in (worktree, gitdir, gitdir / 'objects', gitdir / 'refs', gitdir / 'refs/heads', gitdir / 'hooks'):
        path.mkdir(mode=0o770)
        os.chown(path, CHECKOUT_OWNER, GID)
        path.chmod(0o770)
    (gitdir / 'HEAD').write_text('ref: refs/heads/main\n')
    os.chown(gitdir / 'HEAD', CHECKOUT_OWNER, GID)
    (gitdir / 'HEAD').chmod(0o660)
    (gitdir / 'config').write_text('[core]\n\tbare = false\n\tlogAllRefUpdates = true\n')
    os.chown(gitdir / 'config', CHECKOUT_OWNER, GID)
    (gitdir / 'config').chmod(0o660)
    host_home = root / 'host-home'
    host_home.mkdir(mode=0o700)
    os.chown(host_home, CHECKOUT_OWNER, GID)
    def host(argv, cwd=worktree):
        result = subprocess.run(['/usr/bin/git', '--no-pager', *argv], cwd=cwd,
            env={'HOME': str(host_home), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                 'GIT_AUTHOR_NAME': 'Fixture Host', 'GIT_AUTHOR_EMAIL': 'host@example.invalid',
                 'GIT_COMMITTER_NAME': 'Fixture Host', 'GIT_COMMITTER_EMAIL': 'host@example.invalid',
                 'GIT_TERMINAL_PROMPT': '0', 'GIT_EDITOR': '/bin/false'},
            user=CHECKOUT_OWNER, group=GID, extra_groups=(), umask=0o002,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4)
        require(result.returncode == 0, 'ordinary host Git failed: ' + result.stderr.decode(errors='replace')[-1500:])
        return result.stdout
    (worktree / 'host.txt').write_text('before marker\n')
    os.chown(worktree / 'host.txt', CHECKOUT_OWNER, GID)
    (worktree / 'host.txt').chmod(0o660)
    host(['add', '--', 'host.txt'])
    host(['commit', '-m', 'host before marker'])
    before = host(['rev-parse', '--verify', 'HEAD'])
    status = host(['status', '--porcelain'])
    journal = root / 'setup-journal'
    journal.mkdir(mode=0o700)
    setup = GitPrimarySetup(journal / 'primary.json', room_id='fixture-room', project_id='fixture-project')
    descriptor = os.open(gitdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        node = os.fstat(descriptor)
        setup.prepare(descriptor, expected_identity=(node.st_dev, node.st_ino), project_owner=CHECKOUT_OWNER,
                      authorize=lambda: True, quiescent=lambda: True)
    finally:
        os.close(descriptor)
        setup.close()
    require((gitdir / 'commondir').read_bytes() == b'.\n', 'setup did not create neutral host marker')
    require(host(['rev-parse', '--verify', 'HEAD']) == before and host(['status', '--porcelain']) == status,
            'neutral marker changed ordinary host Git observation')
    (worktree / 'host.txt').write_text('after marker\n')
    host(['add', '--', 'host.txt'])
    host(['commit', '-m', 'host after marker'])
    after = host(['rev-parse', '--verify', 'HEAD'])
    require(after != before and host(['rev-parse', '--verify', 'HEAD^']) == before,
            'ordinary host Git commit failed after marker')
    linked = parent / 'linked'
    host(['worktree', 'add', '-b', 'linked', str(linked)])
    linked_gitdir = Path(host(['rev-parse', '--absolute-git-dir'], linked).decode().strip())
    require(linked_gitdir.is_relative_to(gitdir / 'worktrees'), 'unexpected linked metadata path')
    linked_pointer = (linked_gitdir / 'commondir').read_bytes()
    require(host(['rev-parse', '--verify', 'HEAD'], linked) == after, 'ordinary linked checkout differs')
    baseline = {'primary_head': after.decode().strip(), 'linked_gitdir': str(linked_gitdir),
                'linked_pointer': linked_pointer.decode(), 'host_config': (gitdir / 'config').read_text()}
    (root / 'host-baseline.json').write_text(json.dumps(baseline))
    (root / 'host-baseline.json').chmod(0o444)
    # Stable worker mount roots remain the same source inodes/host ownership.
    command('/usr/bin/mount', '--bind', str(worktree), str(worktree))
    command('/usr/bin/mount', '--bind', str(linked), str(linked))
    views, controls = package / 'git-views', package / 'git-control'
    views.mkdir(mode=0o755)
    controls.mkdir(mode=0o755)
    for label, source in (('primary', gitdir), ('linked', linked_gitdir)):
        paths = view_paths(label)
        slot = views / label
        slot.mkdir(mode=0o755)
        for name, target in (('gitdir', source), ('common', gitdir)):
            (slot / name).mkdir(mode=0o755)
            command('/usr/bin/mount', '--bind', str(target), str(slot / name))
        # Alias mounts first, readonly nested control overlays second. No host
        # config or existing linked commondir content is changed or adopted.
        config = controls / (label + '-config')
        config.write_bytes(compile_git_config(ForgeBinding('fixture-room', 'fixture-project', 'owner/repo')))
        config.chmod(0o444)
        pointer = controls / (label + '-commondir')
        pointer.write_text(paths['common'] + '\n')
        pointer.chmod(0o444)
        for source_file, target_file in ((config, paths['config']), (pointer, paths['gitdir'] + '/commondir')):
            command('/usr/bin/mount', '--bind', str(source_file), str(target_file))
            command('/usr/bin/mount', '-o', 'remount,bind,ro,nosuid,nodev', str(target_file))
    command('/usr/bin/mount', '-o', 'remount,ro,nosuid,nodev', '/opt')
    home = root / 'home'
    home.mkdir(mode=0o700)
    os.chown(home, UID, GID)
    print(json.dumps({'host_git_before_neutral_marker': 'PASS', 'host_git_after_neutral_marker': 'PASS',
                      'ordinary_linked_checkout': 'PASS', 'host_marker': 'neutral dot', 'host_owner': CHECKOUT_OWNER}), flush=True)
    return worktree, home


def sealed_backend():
    path = Path('/usr/bin/git').resolve(strict=True)
    node = path.stat()
    require(stat.S_ISREG(node.st_mode) and node.st_uid == 0 and not node.st_mode & 0o022
            and 0 < node.st_size <= 64 * 1024 * 1024, 'runner Git must be bounded and root-maintained')
    raw = path.read_bytes()
    require(raw.startswith(b'\x7fELF') and len(raw) == node.st_size, 'bounded actual ELF Git required')
    fd = os.memfd_create('uas-hosted-git', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'incomplete sealed Git')
            view = view[count:]
        os.fchmod(fd, 0o555)
        fcntl.fcntl(fd, 1033, 0x0001 | 0x0002 | 0x0004 | 0x0008)  # F_ADD_SEALS.
        if fd != 19:
            try:
                os.fstat(19)
            except OSError as error:
                require(error.errno == errno.EBADF, 'backend slot check failed')
            else:
                raise AssertionError('reserved fixture FD19 already occupied')
            os.dup2(fd, 19, inheritable=False)
    finally:
        if fd != 19:
            os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def native_checks(worktree, home, digest):
    # Re-import from the immutable image projection, not a writable checkout.
    sys.path.insert(0, '/opt/uas')
    for name in tuple(sys.modules):
        if name == 'uas' or name.startswith('uas.'):
            del sys.modules[name]
    from uas.forge import ForgeBinding
    from uas.git_policy import GitIdentity, GitPolicyError, parse_git
    from uas.git_provenance import parse_commit
    from uas.git_runtime import GitRuntime, GitRuntimeError, RuntimeView, SealedGit
    from uas.git_transaction import ReferenceTransaction
    binding = ForgeBinding('fixture-room', 'fixture-project', 'owner/repo')
    actor = GitIdentity('actor-a', 'Actor A', 'actor-a@example.invalid')
    other = GitIdentity('actor-b', 'Actor B', 'actor-b@example.invalid')
    root = worktree.parent.parent
    baseline = json.loads((root / 'host-baseline.json').read_text())
    # Real public entry processes reject before socket creation; there is no
    # request endpoint in this Runtime-only fixture and native Git is never a
    # fallback for a public helper spelling or command/config escape.
    sources = Path('/opt/uas/fixture-sources')
    for name in ('launcher.py', 'public-entries.json'):
        source = sources / name
        require(not source.is_symlink() and source.stat().st_uid == 0
                and stat.S_IMODE(source.stat().st_mode) == 0o444
                and os.statvfs(source).f_flag & os.ST_RDONLY,
                'reviewed fixture source projection differs')
    launcher_digest = hashlib.sha256((sources / 'launcher.py').read_bytes()).hexdigest()
    for name in json.loads((sources / 'public-entries.json').read_text()):
        entry = Path('/opt/uas/bin') / name
        require(not entry.is_symlink() and entry.stat().st_uid == 0
                and stat.S_IMODE(entry.stat().st_mode) == 0o555
                and os.statvfs(entry).f_flag & os.ST_RDONLY
                and hashlib.sha256(entry.read_bytes()).hexdigest() == launcher_digest,
                'public launcher projection differs')
    for name, argv in (('git', ['-c', 'alias.evil=!sh', 'evil']),
                       ('git-commit', ['--author=forged', '-m', 'bad']),
                       ('git-fetch', ['--upload-pack=/bin/sh']),
                       ('git-push', ['--receive-pack=/bin/sh']),
                       ('git-upload-pack', ['.']), ('git-receive-pack', ['.']),
                       ('git-remote-ext', ['origin', 'ext::sh']), ('scalar', ['run'])):
        rejected = subprocess.run([str(Path('/opt/uas/bin') / name), *argv], cwd=worktree,
            env={'PATH': '/opt/uas/bin:/usr/bin:/bin', 'HOME': str(home), 'LC_ALL': 'C',
                 'GIT_EXEC_PATH': '/usr/lib/git-core', 'GIT_CONFIG_COUNT': '1',
                 'GIT_CONFIG_KEY_0': 'alias.evil', 'GIT_CONFIG_VALUE_0': '!sh'},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        require(rejected.returncode == 128 and not rejected.stdout
                and rejected.stderr == b'Controlled Git: UNSUPPORTED_GIT_COMMAND\n',
                'public alias escaped controlled policy or reached an endpoint')
    with ExitStack() as stack:
        def opened(path, directory=True):
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0))
            stack.callback(os.close, fd)
            return fd
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        stack.callback(left.close)
        stack.callback(right.close)
        def runtime_for(tree, label):
            paths = view_paths(label)
            view = RuntimeView(opened(tree), opened(paths['gitdir']), opened(paths['config'], False),
                opened(paths['helpers']), common_fd=opened(paths['common']), binding=binding,
                checkout_owner=CHECKOUT_OWNER)
            return GitRuntime(view, SealedGit(19, digest), actor, transport_fd=right.fileno(), home=str(home))
        runtime = runtime_for(worktree, 'primary')
        counter = 0
        def run(argv, expected=0):
            result = runtime.run(parse_git('git', argv), timeout=3)
            require(result.returncode == expected, 'native ' + argv[0] + ' failed: ' + result.stderr.decode(errors='replace')[-1500:])
            return result
        def head():
            result = run(['rev-parse', '--verify', 'HEAD'])
            return result.stdout.decode().strip()
        def object_at(oid):
            result = run(['cat-file', '-p', oid])
            value = parse_commit(result.stdout)
            require(value.oid == oid, 'native object hash mismatch')
            return value
        def mutate(argv, *, old=None, branch='main', expected=0):
            nonlocal counter
            counter += 1
            cmd = parse_git('git', argv)
            kind = 'abort' if argv == ['cherry-pick', '--abort'] else cmd.kind
            with ReferenceTransaction('fixture-operation-' + str(counter), expected_old=old,
                    expected_ref='refs/heads/' + branch, kind=kind) as transaction:
                result = runtime.run(cmd, timeout=4, transaction=transaction)
                require(result.returncode == expected, 'native attributed ' + argv[0] + ' failed: '
                        + result.stderr.decode(errors='replace')[-1500:])
                oid = transaction.committed_oid(required=expected == 0 and kind != 'abort')
            if oid is not None:
                object_at(oid)
            return oid
        def write(value):
            (worktree / 'shared.txt').write_text(value + '\n')
            run(['add', '--', 'shared.txt'])
        # Ambient identity/config never enter GitRuntime's exact environment.
        os.environ.update(GIT_AUTHOR_NAME='Forged', GIT_AUTHOR_EMAIL='forged@example.invalid',
                          GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='core.hooksPath', GIT_CONFIG_VALUE_0='/tmp')
        write('base')
        first = mutate(['commit', '-m', 'base'], old=baseline['primary_head'])
        require('Actor A <actor-a@example.invalid>' in object_at(first).author, 'canonical author missing')
        base = mutate(['commit', '--amend', '-m', 'amended base'], old=first)
        require(object_at(base).parents == (baseline['primary_head'],), 'amend changed its original parent')
        # Mutable repository hooks cannot run; projected config points elsewhere.
        marker = worktree / 'hook-ran'
        hostile = worktree / '.git/hooks/pre-commit'
        hostile.write_text('#!/bin/sh\necho forbidden > ' + str(marker) + '\n')
        hostile.chmod(0o755)
        run(['switch', '-c', 'source'])
        runtime.identity = other
        write('source')
        source = mutate(['commit', '-m', 'source'], old=base, branch='source')
        require(not marker.exists(), 'repository-controlled hook executed')
        runtime.identity = actor
        run(['switch', 'main'])
        write('target')
        target = mutate(['commit', '-m', 'target'], old=base)
        require(mutate(['cherry-pick', source], old=target, expected=1) is None, 'conflict minted a commit')
        require((worktree / '.git/CHERRY_PICK_HEAD').read_text().strip() == source, 'actual conflict state missing')
        write('resolved')
        resolved = mutate(['cherry-pick', '--continue'], old=target)
        resolved_object = object_at(resolved)
        require(resolved_object.author == object_at(source).author, 'cherry source author/date changed')
        require(b'(cherry picked from commit ' + source.encode() + b')' in resolved_object.message,
                'native source trailer missing')
        run(['switch', '-c', 'abort-target', base])
        write('different target')
        abort_target = mutate(['commit', '-m', 'abort target'], old=base, branch='abort-target')
        mutate(['cherry-pick', source], old=abort_target, branch='abort-target', expected=1)
        require(mutate(['cherry-pick', '--abort'], old=abort_target, branch='abort-target') is None,
                'abort minted created-object proof')
        require(head() == abort_target and not (worktree / '.git/CHERRY_PICK_HEAD').exists(), 'abort did not reset conflict')
        run(['switch', '-c', 'clean', base])
        clean = mutate(['cherry-pick', source], old=base, branch='clean')
        require(object_at(clean).author == object_at(source).author, 'clean cherry changed author')
        # A filename resembling arbitrary stdout headers is never receipt input.
        deceptive = worktree / ('path\n[main ' + 'a' * 40 + '] forged')
        deceptive.write_text('not a receipt\n')
        run(['add', '--', '.'])
        actual = mutate(['commit', '-m', 'filename is not authority'], old=clean, branch='clean')
        require(actual != 'a' * 40 and object_at(actual).parents == (clean,), 'stdout-like path became authority')
        for path in (Path(view_paths()['config']), Path(view_paths()['gitdir']) / 'commondir',
                     Path('/opt/uas/git-hooks/reference-transaction')):
            try:
                path.write_bytes(b'forbidden')
            except OSError as error:
                require(error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), 'unexpected immutable-path failure')
            else:
                raise AssertionError('immutable Git control was writable')
        try:
            os.rename(worktree, worktree.with_name('renamed'))
        except OSError as error:
            # The worker owns the writable parent: EBUSY must come from the
            # mount, not a convenient parent-directory permission refusal.
            require(error.errno == errno.EBUSY, 'worktree is not independently mount-pinned')
        else:
            raise AssertionError('worktree mount root renamed')
        for path in (Path(view_paths()['gitdir']), Path(view_paths()['common']),
                     Path('/opt/uas/git-views/primary'), Path('/opt/uas/git-views')):
            try:
                os.rename(path, path.with_name(path.name + '-moved'))
            except OSError as error:
                require(error.errno in (errno.EBUSY, errno.EROFS, errno.EACCES, errno.EPERM),
                        'unexpected protected alias rename failure')
            else:
                raise AssertionError('Git alias or ancestor renamed')
        for argv in (['-c', 'alias.evil=!sh', 'evil'], ['am', 'mail.patch'],
                     ['commit', '--author=forged', '-m', 'bad'], ['-C', str(home), 'status']):
            try:
                runtime.plan(parse_git('git', argv))
            except (GitPolicyError, GitRuntimeError):
                pass
            else:
                raise AssertionError('policy/path escape accepted')
        extra = worktree / '.git/config.worktree'
        extra.write_text('[alias]\n evil = !sh\n')
        try:
            runtime.plan(parse_git('git', ['status']))
        except GitRuntimeError as error:
            require(error.code == 'GIT_WORKTREE_CONFIG_UNAVAILABLE', 'unexpected config.worktree refusal')
        else:
            raise AssertionError('mutable worktree config admitted')
        finally:
            extra.unlink()
        run(['status', '--short'])
        # A real host-created linked checkout uses a separate pinned gitdir,
        # while sharing its Project's exact common inode through its own alias.
        linked = worktree.with_name('linked')
        runtime = runtime_for(linked, 'linked')
        require(head() == baseline['primary_head'], 'linked checkout head drifted')
        (linked / 'linked.txt').write_text('controlled linked commit\n')
        run(['add', '--', 'linked.txt'])
        linked_oid = mutate(['commit', '-m', 'linked controlled commit'], old=baseline['primary_head'], branch='linked')
        require(object_at(linked_oid).parents == (baseline['primary_head'],), 'linked commit parent differs')
        require((worktree / '.git/commondir').read_bytes() == b'.\n'
                and (Path(baseline['linked_gitdir']) / 'commondir').read_text() == baseline['linked_pointer']
                and (worktree / '.git/config').read_text() == baseline['host_config'],
                'runtime projections modified host Git controls')
        print(json.dumps({'native_git_runtime': 'PASS', 'reference_transaction': 'PASS',
            'commit_amend': 'PASS', 'cherry_clean_conflict_continue_abort': 'PASS',
            'immutable_config_hook_and_mount': 'PASS', 'filename_not_receipt': 'PASS',
            'readonly_commondir_alias': 'PASS', 'primary_and_linked_runtime': 'PASS',
            'host_controls_unchanged': 'PASS', 'gitdir_common_ancestor_rename': 'DENIED',
            'public_launcher_aliases': 'EXACT_READONLY_COPIES', 'public_entry_bypass_invocations': 'DENIED',
            'worker_uid': UID, 'worker_gid': GID, 'capabilities': 'none', 'no_new_privileges': True,
            'preserved_checkout_owner': CHECKOUT_OWNER, 'checkout_access': 'preexisting shared group',
            'seccomp': True, 'network_namespace': 'private', 'backend_sha256': digest,
            'supervisor_admission': 'NOT_TESTED', 'external_ssh_broker': 'NOT_TESTED',
            'live_github': 'NOT_TESTED', 'credentials_created': False}), flush=True)


def namespace(root):
    gate()
    require(os.getpid() == 1 and root.parent == Path('/tmp')
            and root.name.startswith('uas-native-git-') and root.resolve() == root
            and root.is_dir() and root.stat().st_uid == 0 and stat.S_IMODE(root.stat().st_mode) == 0o700,
            'namespace-init and uniquely staged fixture root required')
    remaining = float(os.environ[DEADLINE]) - time.monotonic()
    require(0 < remaining <= 40, 'expired fixture deadline')
    def expired(*_):
        raise TimeoutError('native Git fixture deadline exceeded')
    # Namespace init must install an explicit handler; default dispositions
    # have special semantics for PID1 and are not a dependable self-deadline.
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(max(1, int(remaining)))
    worktree, home = provision(root)
    digest = sealed_backend()
    isolate_process()
    os.umask(0o002)  # Group-writable new entries, without changing existing ownership.
    try:
        native_checks(worktree, home, digest)
    finally:
        os.close(19)


def main():
    gate()
    if len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2]))
        return
    require(len(sys.argv) == 1, 'no caller-selected fixture commands')
    with tempfile.TemporaryDirectory(prefix='uas-native-git-', dir='/tmp') as temporary:
        env = {'PATH': '/usr/bin:/bin', 'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
               'PYTHONDONTWRITEBYTECODE': '1', DEADLINE: str(time.monotonic() + 38)}
        # PID namespace plus kill-child guarantees timeout cleanup; no lingering
        # process can retain these mounts or write into the temporary worktree.
        result = subprocess.run(['/usr/bin/unshare', '--mount', '--net', '--pid', '--fork',
            '--kill-child=KILL', '--mount-proc', sys.executable, str(Path(__file__).resolve()),
            '--namespace', temporary], env=env, timeout=40, check=False)
        require(result.returncode == 0, 'hosted native Git fixture failed')


if __name__ == '__main__':
    main()
