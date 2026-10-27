"""Fixed hosted-fixture user map; no subordinate-ID files or host setup changes.

The privileged parent writes only its held child's namespace maps. Never used
for production admission. Importing this file has no effects.
"""
import os
from pathlib import Path
import select
import stat
import subprocess
import sys

MAP = '0 100000 65536\n'
READY = b'UAS_PRIVATE_USERNS_READY\n'
FIXTURES = ('diff_smoke.py', 'command_smoke.py', 'artifact_native_smoke.py')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def fixed_argv(argv, *, staged=False):
    require(type(argv) is list and len(argv) >= 3 and argv[0] == '/usr/bin/python3'
            and argv[2] == '--namespace-helper', 'fixed Python fixture required')
    script = Path(argv[1])
    require(script.name in FIXTURES and script.is_absolute(), 'fixed fixture entrypoint required')
    if not staged:
        require(script.parent == Path(__file__).resolve().parent, 'staged fixture entrypoint required')
    else:
        candidate = script.parent / 'mapped_namespace.py'
        for directory in (candidate.parent, *candidate.parent.parents):
            require(not directory.is_symlink(), 'symlink in staged wrapper path')
        info = candidate.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222
                and info.st_size <= 16384, 'immutable staged wrapper required')
        require(candidate.read_bytes() == Path(__file__).read_bytes(), 'staged wrapper source mismatch')
    return argv


def install_maps(pid):
    # Caller holds an unreaped, ready child: no PID reuse until writes finish.
    require(type(pid) is int and pid > 0, 'invalid owned namespace child')
    directory = Path('/proc') / str(pid)
    require((directory / 'uid_map').read_text() == ''
            and (directory / 'gid_map').read_text() == '', 'namespace maps already installed')
    (directory / 'uid_map').write_text(MAP)
    (directory / 'gid_map').write_text(MAP)
    require((directory / 'uid_map').read_text().split() == MAP.split()
            and (directory / 'gid_map').read_text().split() == MAP.split(), 'namespace map mismatch')
    # The parent's CAP_SETGID permits the range without setgroups=deny.
    require((directory / 'setgroups').read_text().strip() == 'allow', 'group clearing unavailable')


def mapped_popen(argv, **kwargs):
    require(os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_OS') == 'Linux', 'owned hosted root fixture required')
    fixed_argv(argv, staged=True)
    require('pass_fds' not in kwargs and 'preexec_fn' not in kwargs, 'unsupported fixture launch options')
    ready_r = ready_w = go_r = go_w = -1
    child = None
    try:
        ready_r, ready_w = os.pipe()
        go_r, go_w = os.pipe()
        child = subprocess.Popen(['/usr/bin/python3', str(Path(argv[1]).parent / 'mapped_namespace.py'),
                                  str(ready_w), str(go_r), '--', *argv],
                                 pass_fds=(ready_w, go_r), **kwargs)
        os.close(ready_w); ready_w = -1
        os.close(go_r); go_r = -1
        require(select.select([ready_r], [], [], 2)[0] == [ready_r], 'namespace readiness timeout')
        require(os.read(ready_r, len(READY) + 1) == READY, 'invalid namespace readiness')
        require(child.poll() is None, 'namespace child exited')
        install_maps(child.pid)
        require(child.poll() is None, 'namespace child lost during mapping')
        require(os.write(go_w, b'G') == 1, 'namespace release failed')
        return child
    except BaseException:
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
        raise
    finally:
        for fd in (ready_r, ready_w, go_r, go_w):
            if fd >= 0:
                os.close(fd)


def child_main(args):
    require(len(args) >= 6 and args[2] == '--', 'invalid fixed wrapper arguments')
    argv = fixed_argv(args[3:])
    ready, go = int(args[0]), int(args[1])
    require(ready > 2 and go > 2 and ready != go, 'invalid private descriptors')
    require(stat.S_ISFIFO(os.fstat(ready).st_mode) and stat.S_ISFIFO(os.fstat(go).st_mode), 'private pipes required')
    os.unshare(os.CLONE_NEWUSER)
    require(os.write(ready, READY) == len(READY), 'namespace readiness failed')
    os.close(ready)
    require(select.select([go], [], [], 3)[0] == [go] and os.read(go, 1) == b'G', 'namespace map release missing')
    os.close(go)
    require(Path('/proc/self/uid_map').read_text().split() == MAP.split()
            and Path('/proc/self/gid_map').read_text().split() == MAP.split(), 'fixed mapped namespace required')
    os.setgroups([])
    os.setgid(0)
    os.setuid(0)
    os.unshare(os.CLONE_NEWNS)
    os.execve(argv[0], argv, dict(os.environ))


if __name__ == '__main__':
    child_main(sys.argv[1:])
