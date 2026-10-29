"""Bounded fixed-tool transport for the single-threaded preparation owner.

Uses the repository Pi runner's retained-child/WNOWAIT, signal-before-reap and
record-only cancellation pattern. It is not a general concurrent subprocess API.
"""
import os
import selectors
import signal
import subprocess
import threading
import time
from .local_host_profile import LocalHostProfile, require


def run_fixed(arguments, *, limit=1024*1024, deadline=None):
    require(threading.current_thread() is threading.main_thread()
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            'HOST_COMMAND_EXCLUSIVE_REAPER_REQUIRED')
    deadline = min(time.monotonic() + 10, deadline) if deadline is not None else time.monotonic() + 10
    process = None
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    cancelled = [False]
    previous = {}
    installed = []

    def interrupted(signum, frame):
        # Never raise across Popen -> retained-handle assignment.
        cancelled[0] = True

    def check_cancelled():
        require(not cancelled[0], 'HOST_COMMAND_CANCELLED')

    def observe_owned():
        require(process.returncode is None, 'HOST_COMMAND_OWNERSHIP_LOST')
        try:
            value = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            require(False, 'HOST_COMMAND_OWNERSHIP_LOST')
        require(value is None or value.si_pid == process.pid, 'HOST_COMMAND_WAIT_IDENTITY')
        return value

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, interrupted)
            installed.append(sig)
        try:
            check_cancelled()
            require(time.monotonic() < deadline, 'HOST_READ_TIMEOUT')
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=LocalHostProfile.environment(), start_new_session=True)
            check_cancelled()
            with selectors.DefaultSelector() as selector:
                for stream, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    check_cancelled()
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'HOST_READ_TIMEOUT')
                    for key, _ in selector.select(min(remaining, .05)):
                        target = output[key.data]
                        chunk = os.read(key.fileobj.fileno(), min(8192, limit + 1 - len(target)))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        target.extend(chunk)
                        require(len(target) <= limit, 'HOST_READ_BOUND')
                while True:
                    check_cancelled()
                    value = observe_owned()
                    if value is not None:
                        break
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'HOST_READ_TIMEOUT')
                    time.sleep(min(.01, remaining))
            require(value.si_code == os.CLD_EXITED and value.si_status == 0
                    and not output['stderr'], 'HOST_READ_COMMAND')
            check_cancelled()
            return output['stdout'].decode('utf-8', errors='strict').strip()
        finally:
            # Cancellation stays suppressed until owned groups are fenced. The
            # retained leader reserves PID/PGID through the final numeric signal.
            for sig in installed:
                signal.signal(sig, signal.SIG_IGN)
            if process is not None:
                try:
                    observe_owned()
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    # Exactly one reap boundary. It may reap before raising;
                    # there are no numeric signals or retry after this boundary.
                    process.wait(timeout=1)
                finally:
                    for stream in (process.stdout, process.stderr):
                        stream.close()
            check_cancelled()
    finally:
        for sig in reversed(installed):
            signal.signal(sig, previous[sig])
