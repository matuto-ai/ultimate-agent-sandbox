#!/usr/bin/env python3
"""Hosted-only real kernel ancestry/reparent/revocation evidence; no credentials.

No accounts, mounts, listeners, provider traffic, permission-policy changes or
native Git execution. The root fixture owns two transient same-UID seat trees;
descendants terminate via private channels. Direct children are exactly waited;
the reparented grandchild is observed exited through its held pidfd.
"""
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux'
            or sys.platform != 'linux' or os.getuid() != 0):
        raise RuntimeError('explicit disposable GitHub Linux root fixture required')
    from uas.git_process import GitChildAuthority, GitSeat, parse_status
    from uas.kernel_origin import HeldOrigin, OriginDenied, alive, enable, receive
    from uas.ledger import Origin
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        raise RuntimeError('exclusive child reaping required')
    signal.alarm(15)
    channels, owned = [], []
    authority = binding = seat_origin = None
    active = [True]
    def pair():
        result = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        for channel in result:
            enable(channel); channel.settimeout(5); channels.append(channel)
        return result
    parent, seat = pair(); caller, child = pair(); foreign_recv, foreign_send = pair()
    pid = os.fork()
    if pid == 0:
        try:
            parent.close(); caller.close(); foreign_recv.close(); foreign_send.close()
            os.setgroups([]); os.setgid(65532); os.setuid(65532)
            seat.send(b'seat')
            if seat.recv(16) != b'spawn': os._exit(2)
            native = os.fork()
            if native == 0:
                seat.close()
                old_parent = os.getppid()
                child.send(b'child')
                if child.recv(16) != b'reparent': os._exit(3)
                # Parent exit must become observable before the second record.
                deadline = time.monotonic() + 3
                while os.getppid() == old_parent and time.monotonic() < deadline:
                    time.sleep(.005)
                if os.getppid() == old_parent: os._exit(7)
                child.send(b'reparented')
                child.recv(16)
                os._exit(0)
            child.close()
            if seat.recv(16) != b'exit': os._exit(4)
            os._exit(0)
        except BaseException:
            os._exit(5)
    owned.append(pid); seat.close(); child.close()
    try:
        with receive(parent) as record:
            if record.data != b'seat': raise AssertionError('seat handshake differs')
            seat_origin = HeldOrigin(record)
        namespace = tuple((node.st_dev, node.st_ino) for node in (
            os.stat(f'/proc/{pid}/ns/pid'), os.stat(f'/proc/{pid}/ns/user')))
        depth = len(parse_status(Path(f'/proc/{pid}/status').read_bytes())['NSpid'])
        admitted = GitSeat(Origin('alice', 'seat-a', 'inc1', 'epoch1', ('git-read', 'git-push')),
            seat_origin, lambda: active[0], namespace, depth)
        authority = GitChildAuthority((admitted,))
        parent.send(b'spawn')
        started = time.monotonic()
        with receive(caller) as record:
            if record.data != b'child': raise AssertionError('child handshake differs')
            binding = authority.bind(record)
            if binding.origin.actor_id != 'alice': raise AssertionError('child attribution differs')
        admission_ms = (time.monotonic() - started) * 1000
        if binding.current() is not True: raise AssertionError('fresh child not current')
        active[0] = False
        try: binding.current()
        except OriginDenied: pass
        else: raise AssertionError('revoked root still authorized')
        active[0] = True
        sibling = os.fork()
        if sibling == 0:
            try:
                parent.close(); caller.close(); foreign_recv.close()
                os.setgroups([]); os.setgid(65532); os.setuid(65532)
                foreign_send.send(b'sibling'); foreign_send.recv(16)
                os._exit(0)
            except BaseException: os._exit(6)
        owned.append(sibling)
        foreign_send.close()
        with receive(foreign_recv) as record:
            try: authority.bind(record)
            except OriginDenied: pass
            else: raise AssertionError('same-UID unrelated sibling authorized')
        foreign_recv.send(b'exit')
        status = os.waitpid(sibling, 0)[1]
        owned.remove(sibling)
        if status != 0: raise AssertionError('sibling failed')
        caller.send(b'reparent')
        # Give child permission to observe exit before terminating the seat.
        parent.send(b'exit')
        status = os.waitpid(pid, 0)[1]
        owned.remove(pid)
        if status != 0: raise AssertionError('seat failed')
        with receive(caller) as record:
            if record.credentials != binding.credentials: raise AssertionError('reparented task credentials differ')
            if record.data != b'reparented': raise AssertionError('missing reparent observation')
            for check in (binding.current, lambda: authority.bind(record)):
                try: check()
                except OriginDenied: pass
                else: raise AssertionError('dead/reparented root authorized')
        caller.send(b'exit')
        deadline = time.monotonic() + 2
        while alive(binding.tasks[0].pidfd) and time.monotonic() < deadline:
            time.sleep(.005)
        if alive(binding.tasks[0].pidfd): raise AssertionError('exact native child did not exit')
        print(json.dumps({'native_git_ancestry': 'PASS', 'child_actor': 'alice',
            'same_uid_sibling': 'DENIED', 'root_revocation': 'DENIED', 'actual_parent_exit_reparent': 'DENIED',
            'admission_ms': round(admission_ms, 3), 'live_github': 'NOT_TESTED'}, sort_keys=True), flush=True)
    finally:
        if binding is not None: binding.close()
        if authority is not None: authority.close()
        if seat_origin is not None: seat_origin.close()
        for channel in channels:
            channel.close()
        # Only unreaped children created above; no adoption/global PID lookup.
        for pid in owned:
            try: observed = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                continue  # Ownership unknown: never signal an adopted/reused number.
            if observed is None:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
            os.waitpid(pid, 0)
        signal.alarm(0)


if __name__ == '__main__': main()
