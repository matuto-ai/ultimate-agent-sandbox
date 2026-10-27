"""Independent #67 low-level regressions. All native effects are mocked.

Copyable unittest module; run only with the qualified source on PYTHONPATH.
These tests establish Python rejection/control behavior, not kernel proof.
"""
from contextlib import ExitStack
import ctypes
import os
import select
import socket
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas import git_process as gp


NS = ((11, 22), (11, 33))
OTHER_NS = ((11, 44), (11, 33))


class NativeEffect(BaseException):
    """Cannot accidentally satisfy an expected OriginDenied assertion."""


def blocked(*args, **kwargs):
    raise NativeEffect('unaudited native-effect call')


def raw_status(pid=20, parent=10, uid=1000, gid=1000, nspid=None):
    nspid = (pid,) if nspid is None else nspid
    fields = {'Pid': (pid,), 'Tgid': (pid,), 'PPid': (parent,),
              'Uid': (uid,) * 4, 'Gid': (gid,) * 4,
              'NSpid': nspid, 'NStgid': nspid}
    return ''.join(key + ':\t' + '\t'.join(map(str, value)) + '\n'
                   for key, value in fields.items()).encode()


def native_tripwires():
    stack = ExitStack()
    for module, names in (
            (os, ('open', 'read', 'readlink', 'close', 'fstat', 'getpid',
                  'pidfd_open', 'fork', 'forkpty', 'pipe', 'pipe2', 'system',
                  'posix_spawn', 'posix_spawnp', 'kill', 'execve', 'execv',
                  'unshare', 'setns')),
            (socket, ('socket', 'socketpair', 'create_connection')),
            (ctypes, ('CDLL', 'PyDLL')),
            (select, ('poll', 'select', 'epoll')),
            (subprocess, ('Popen', 'run'))):
        for name in names:
            if hasattr(module, name):
                stack.enter_context(patch.object(module, name, side_effect=blocked))
    return stack


class GitProcessLowLevelReviewTests(unittest.TestCase):
    def setUp(self):
        self.barriers = native_tripwires()
        self.addCleanup(self.barriers.close)

    def patched(self, obj, name, **kwargs):
        value = self.barriers.enter_context(patch.object(obj, name, **kwargs))
        return value

    def mocked_task(self, *, raws=None, namespaces=None, alive=None, identities=None):
        closed = []
        self.patched(gp.os, 'pidfd_open', side_effect=[101, 102, 103])
        self.patched(gp.os, 'open', return_value=99)
        self.patched(gp.os, 'close', side_effect=closed.append)
        self.patched(gp, '_identity', side_effect=identities or [(7, 20)] * 3)
        self.patched(gp, 'alive', side_effect=alive or [True] * 20)
        self.patched(gp, '_read_at', side_effect=raws or [raw_status()] * 3)
        view = SimpleNamespace(fd=98, require=Mock(return_value=True),
            namespaces=Mock(side_effect=namespaces or [NS] * 3))
        return view, closed

    def seat(self, pid=10, *, namespace=NS, depth=1, current=None):
        root = object.__new__(gp.HeldOrigin)
        root.pidfd = pid
        root.identity = (7, pid)
        root.credentials = (pid, 1000, 1000)
        root.revoked = False
        return gp.GitSeat(gp.Origin('alice', 'seat-a', 'incarnation', 'epoch-1',
                                   ('git-read', 'git-push')),
                          root, current or (lambda: True), namespace, depth)

    def proc_model(self, *, self_pid=42, self_nspid=(42,), self_link='42',
                   namespace=NS, process_rows=None, fs_magic=0x9fa0):
        """Actual ProcView/_Task logic with deterministic kernel observations."""
        state = SimpleNamespace(self_pid=self_pid, self_nspid=self_nspid,
            self_link=self_link, namespace=namespace,
            process_rows={} if process_rows is None else process_rows,
            opened=[], closed=[], pidfd_calls=[])
        rootfd, selfdir = 900000, 800000

        def fake_open(name, flags, *, dir_fd=None):
            state.opened.append((name, dir_fd))
            if name == '/proc' and dir_fd is None:
                return rootfd
            if dir_fd == rootfd and name == 'self':
                return selfdir
            if dir_fd == rootfd and name.isdecimal():
                return 100000 + int(name)
            raise AssertionError(('unexpected path', name, dir_fd))

        def read_at(directory, name):
            self.assertEqual(name, 'status')
            if directory == selfdir:
                return raw_status(pid=state.self_pid, parent=1,
                                  nspid=state.self_nspid)
            pid = directory - 100000
            if pid not in state.process_rows:
                raise gp.OriginDenied('no modeled process')
            row = state.process_rows[pid]
            return raw_status(pid=pid, parent=row['parent'],
                              nspid=row.get('nspid', (pid,)))

        def namespaces(directory):
            if directory == selfdir:
                return state.namespace
            return state.process_rows[directory - 100000].get('namespace', NS)

        def readlink(name, *, dir_fd=None):
            self.assertEqual((name, dir_fd), ('self', rootfd))
            return state.self_link

        def pidfd_open(pid):
            state.pidfd_calls.append(pid)
            return pid

        def fstatfs(fd, ptr):
            self.assertEqual(fd, rootfd)
            ptr._obj[0] = fs_magic
            return 0

        for obj, name, kwargs in (
                (gp.os, 'open', {'side_effect': fake_open}),
                (gp.os, 'close', {'side_effect': state.closed.append}),
                (gp.os, 'getpid', {'return_value': 42}),
                (gp.os, 'readlink', {'side_effect': readlink}),
                (gp.os, 'pidfd_open', {'side_effect': pidfd_open}),
                (gp, '_identity', {'side_effect': lambda fd: (7, fd)}),
                (gp, 'alive', {'return_value': True}),
                (gp, '_read_at', {'side_effect': read_at}),
                (gp.ProcView, 'namespaces', {'side_effect': namespaces}),
                (ctypes, 'CDLL', {'return_value': SimpleNamespace(fstatfs=fstatfs)}),
                (gp.time, 'monotonic', {'return_value': 0})):
            self.patched(obj, name, **kwargs)
        return state

    def test_expected_identity_mismatch_before_proc_lookup(self):
        closed = []
        self.patched(gp.os, 'pidfd_open', return_value=101)
        self.patched(gp, '_identity', return_value=(7, 200))
        self.patched(gp.os, 'close', side_effect=closed.append)
        with self.assertRaises(gp.OriginDenied):
            gp._Task(SimpleNamespace(fd=98), 20, expected=(7, 20))
        self.assertEqual(closed, [101])

    def test_relookup_pid_reuse_rejects_and_cleans_all_fds(self):
        view, closed = self.mocked_task(identities=[(7, 20), (7, 21)])
        self.patched(gp, '_read_at', side_effect=blocked)
        with self.assertRaises(gp.OriginDenied):
            gp._Task(view, 20, expected=(7, 20))
        self.assertEqual(closed, [102, 99, 101])

    def test_wrong_proc_status_pid_rejects(self):
        view, closed = self.mocked_task(raws=[raw_status(pid=21)])
        with self.assertRaises(gp.OriginDenied):
            gp._Task(view, 20, expected=(7, 20))
        self.assertEqual(closed, [102, 99, 101])

    def test_exit_during_status_observation_rejects(self):
        view, closed = self.mocked_task(alive=[True, True, False])
        with self.assertRaises(gp.OriginDenied):
            gp._Task(view, 20, expected=(7, 20))
        self.assertEqual(closed, [102, 99, 101])

    def test_actual_task_check_reparent_rejects(self):
        view, closed = self.mocked_task(raws=[raw_status(), raw_status(parent=30)])
        task = gp._Task(view, 20, expected=(7, 20))
        try:
            with self.assertRaises(gp.OriginDenied):
                task.check()
        finally:
            task.close()
        self.assertEqual(closed, [102, 103, 99, 101])

    def test_actual_task_check_credential_change_rejects(self):
        view, _ = self.mocked_task(raws=[raw_status(), raw_status(uid=1001)])
        task = gp._Task(view, 20, expected=(7, 20))
        try:
            with self.assertRaises(gp.OriginDenied):
                task.check()
        finally:
            task.close()

    def test_actual_task_check_namespace_change_rejects(self):
        view, _ = self.mocked_task(namespaces=[NS, OTHER_NS])
        task = gp._Task(view, 20, expected=(7, 20))
        try:
            with self.assertRaises(gp.OriginDenied):
                task.check()
        finally:
            task.close()

    def test_changed_proc_view_denies_before_task_relookup(self):
        view, closed = self.mocked_task()
        view.require.side_effect = gp.OriginDenied('receiver changed')
        self.patched(gp, '_read_at', side_effect=blocked)
        with self.assertRaises(gp.OriginDenied):
            gp._Task(view, 20, expected=(7, 20))
        self.assertEqual(closed, [99, 101])

    def test_read_at_oversize_rejects_and_closes(self):
        closed = []
        self.patched(gp.os, 'open', return_value=88)
        self.patched(gp.os, 'read', return_value=b'x' * (gp.MAX_STATUS + 1))
        self.patched(gp.os, 'close', side_effect=closed.append)
        with self.assertRaises(gp.OriginDenied):
            gp._read_at(99, 'status')
        self.assertEqual(closed, [88])

    def test_namespace_non_regular_fd_rejects_and_closes(self):
        closed = []
        self.patched(gp.os, 'open', return_value=88)
        self.patched(gp.os, 'fstat', return_value=SimpleNamespace(
            st_mode=0o040755, st_ino=22, st_dev=11))
        self.patched(gp.os, 'close', side_effect=closed.append)
        with self.assertRaises(gp.OriginDenied):
            gp.ProcView.namespaces(99)
        self.assertEqual(closed, [88])

    def test_correct_proc_view_uses_kernel_self_and_retains_directory(self):
        state = self.proc_model()
        view = gp.ProcView()
        self.assertEqual(state.opened, [('/proc', None), ('self', 900000)])
        self.assertEqual(view.receiver_directory, 800000)
        view.require()
        view.close()
        self.assertEqual(state.closed, [42, 800000, 900000])
        with self.assertRaises(gp.OriginDenied):
            view.require()

    def test_non_procfs_refuses_before_self_lookup(self):
        state = self.proc_model(fs_magic=0x1234)
        with self.assertRaises(gp.OriginDenied):
            gp.ProcView()
        self.assertEqual(state.opened, [('/proc', None)])
        self.assertEqual(state.closed, [900000])

    def test_same_numeric_self_in_ancestor_mount_still_refuses(self):
        state = self.proc_model(self_nspid=(42, 42))
        with self.assertRaises(gp.OriginDenied):
            gp.ProcView()
        self.assertEqual(state.pidfd_calls, [])
        self.assertEqual(state.closed, [800000, 900000])

    def test_mismounted_proc_cannot_splice_sibling_identity_onto_foreign_ancestry(self):
        # Actual receiver-N root2000/caller3000 are siblings. Ancestor proc-H
        # instead exposes unrelated N tasks with H3000->H2000 ancestry.
        actual_parent = {2000: 1, 3000: 1}
        state = self.proc_model(self_pid=1042, self_nspid=(1042, 42),
            self_link='1042', process_rows={
                2000: {'parent': 1, 'nspid': (2000, 1000)},
                3000: {'parent': 2000, 'nspid': (3000, 1500)}})
        seat = self.seat(2000, depth=2)
        self.assertNotEqual(actual_parent[3000], 2000)
        with self.assertRaises(gp.OriginDenied):
            gp.GitChildAuthority((seat,))
        self.assertEqual(state.opened, [('/proc', None)])
        self.assertEqual(state.pidfd_calls, [])
        self.assertEqual(state.closed, [900000])

    def test_pinned_receiver_mapping_rechecked_after_construction(self):
        for changed in ('self_link', 'self_pid', 'self_nspid', 'namespace'):
            with self.subTest(changed=changed):
                # Each nested fixture is isolated from the next iteration.
                saved = self.barriers
                self.barriers = ExitStack()
                try:
                    state = self.proc_model()
                    view = gp.ProcView()
                    setattr(state, changed, {'self_link': '1042', 'self_pid': 1042,
                        'self_nspid': (42, 42), 'namespace': OTHER_NS}[changed])
                    with self.assertRaises(gp.OriginDenied):
                        view.require()
                    view.close()
                finally:
                    self.barriers.close()
                    self.barriers = saved

    def test_actual_view_and_task_chain_control_accepts_correct_mapping(self):
        state = self.proc_model(process_rows={
            2000: {'parent': 42}, 3000: {'parent': 2000}})
        allowed = [True]
        authority = gp.GitChildAuthority((self.seat(2000, current=lambda: allowed[0]),))
        binding = authority.bind(gp.Record(b'{}', (3000, 1000, 1000), 3000))
        self.assertEqual(binding.origin.actor_id, 'alice')
        self.assertTrue(binding.require(gp.Record(b'{}', (3000, 1000, 1000), 3000)))
        self.assertEqual([task.pid for task in binding.tasks], [3000, 2000])
        allowed[0] = False
        with self.assertRaises(gp.OriginDenied):
            binding.current()
        binding.close()
        authority.close()
        self.assertIn(('self', 900000), state.opened)
        self.assertNotIn(('42', 900000), state.opened)

    def test_actual_view_and_task_chain_refuses_sibling(self):
        self.proc_model(process_rows={
            2000: {'parent': 42}, 3000: {'parent': 1}, 1: {'parent': 0}})
        authority = gp.GitChildAuthority((self.seat(2000),))
        try:
            with self.assertRaises(gp.OriginDenied):
                authority.bind(gp.Record(b'{}', (3000, 1000, 1000), 3000))
        finally:
            authority.close()

    def test_slow_final_observation_now_refuses(self):
        now = [0.0]
        seat = self.seat()
        task = SimpleNamespace(identity=(7, 10),
            check=lambda: now.__setitem__(0, .060))
        binding = gp.GitProcessBinding([task], seat, (10, 1000, 1000))
        self.patched(gp.time, 'monotonic', side_effect=lambda: now[0])
        self.patched(gp, '_identity', return_value=(7, 10))
        self.patched(gp, 'alive', return_value=True)
        with self.assertRaises(gp.OriginDenied):
            binding.current()

    def test_slow_final_epoch_guard_now_refuses(self):
        now, checks = [0.0], [0]
        def guard():
            checks[0] += 1
            if checks[0] == 2:
                now[0] = .060
            return True
        seat = self.seat(current=guard)
        task = SimpleNamespace(identity=(7, 10), check=lambda: None)
        binding = gp.GitProcessBinding([task], seat, (10, 1000, 1000))
        self.patched(gp.time, 'monotonic', side_effect=lambda: now[0])
        self.patched(gp, '_identity', return_value=(7, 10))
        self.patched(gp, 'alive', return_value=True)
        with self.assertRaises(gp.OriginDenied):
            binding.current()
        self.assertEqual(checks[0], 2)

    def test_inherited_absolute_deadline_is_not_reset(self):
        now = [.040]
        seat = self.seat()
        task = SimpleNamespace(identity=(7, 10),
            check=lambda: now.__setitem__(0, .060))
        binding = gp.GitProcessBinding([task], seat, (10, 1000, 1000))
        self.patched(gp.time, 'monotonic', side_effect=lambda: now[0])
        self.patched(gp, '_identity', return_value=(7, 10))
        self.patched(gp, 'alive', return_value=True)
        with self.assertRaises(gp.OriginDenied):
            binding.current(deadline=.050)


if __name__ == '__main__':
    unittest.main()
