"""Pure lineage algorithms. Real kernel/process evidence is hosted-only."""
import unittest
from unittest.mock import patch

from uas.git_process import GitChildAuthority, GitSeat, parse_status
from uas.kernel_origin import HeldOrigin, OriginDenied, Record
from uas.ledger import Origin


NS = ((11, 22), (11, 33))


def status(pid=20, parent=10, uid=1000, gid=1000):
    return {'Pid': (pid,), 'Tgid': (pid,), 'PPid': (parent,),
            'Uid': (uid,) * 4, 'Gid': (gid,) * 4, 'NSpid': (pid,), 'NStgid': (pid,)}


def raw_status(**kwargs):
    return ''.join(key + ':\t' + '\t'.join(map(str, value)) + '\n'
                   for key, value in status(**kwargs).items()).encode()


class FakeView:
    fd = 99
    def close(self): self.closed = True
    def require(self): return True


class FakeTask:
    graph = None
    constructed = []
    def __init__(self, view, pid, *, expected=None):
        data = self.graph.get(pid)
        if data is None: raise OriginDenied('no task')
        self.pid = pid
        self.identity = data.get('identity', (7, pid))
        if expected is not None and expected != self.identity: raise OriginDenied('stale PID')
        self.status = data.get('status', status(pid=pid, parent=data['parent']))
        self.namespace = data.get('namespace', NS)
        self.pidfd = pid
        self.closed = False
        self.constructed.append(self)
    def check(self):
        data = self.graph[self.pid]
        if data.get('changed') or data.get('dead'): raise OriginDenied('changed')
    def close(self): self.closed = True


class GitProcessTests(unittest.TestCase):
    def setUp(self):
        self.allowed = True
        self.root = object.__new__(HeldOrigin)
        self.root.identity = (7, 10)
        self.root.pidfd = 10
        self.root.credentials = (10, 1000, 1000)
        self.root.revoked = False
        self.origin = Origin('alice', 'seat-a', 'incarnation', 'epoch-1', ('git-read', 'git-push'))
        self.seat = GitSeat(self.origin, self.root, lambda: self.allowed, NS, 1)
        self.graph = {20: {'parent': 10}, 10: {'parent': 1}}
        FakeTask.graph = self.graph
        FakeTask.constructed = []
        self.patches = [patch('uas.git_process.ProcView', FakeView),
                        patch('uas.git_process._Task', FakeTask),
                        patch('uas.git_process._identity', lambda fd: (7, fd)),
                        patch('uas.git_process.alive', lambda fd: fd >= 0),
                        patch('uas.git_process.time.monotonic', return_value=0)]
        for item in self.patches: item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])
        self.authority = GitChildAuthority((self.seat,))

    def record(self, pid=20, uid=1000, gid=1000):
        return Record(b'{}', (pid, uid, gid), pid)

    def denied(self, record=None):
        with self.assertRaises(OriginDenied): self.authority.bind(record or self.record())
        self.assertTrue(all(item.closed for item in FakeTask.constructed))

    def test_bounded_status_shape_and_namespace_mapping(self):
        self.assertEqual(parse_status(raw_status()), status())
        for raw in (b'', b'x' * 16385, raw_status() + b'Pid: 20\n',
                    raw_status().replace(b'PPid:\t10', b'PPid:\t-1'),
                    raw_status().replace(b'NSpid:\t20', b'NSpid:\t21'),
                    raw_status().replace(b'Gid:\t1000\t1000\t1000\t1000', b'Gid:\t1000'),
                    raw_status().replace(b'Pid:\t20', b'Pid:\t0', 1),
                    raw_status().replace(b'NStgid:\t20\n', b''),
                    raw_status() + b'Uid: 1000 1000 1000 1000\n'):
            with self.subTest(raw=raw[:30]), self.assertRaises(OriginDenied): parse_status(raw)

    def test_native_child_retains_root_actor_and_each_packet_is_bound(self):
        bound = self.authority.bind(self.record())
        self.assertEqual(bound.origin, self.origin)
        self.assertEqual([task.pid for task in bound.tasks], [20, 10])
        self.assertTrue(bound.require(self.record()))
        with self.assertRaises(OriginDenied): bound.require(self.record(pid=21))
        with self.assertRaises(OriginDenied): bound.require(self.record(gid=1001))
        bound.close()
        self.assertTrue(all(task.closed for task in FakeTask.constructed))
        with self.assertRaises(OriginDenied): bound.current()

    def test_direct_root_is_permitted_but_no_lookup_without_kernel_record(self):
        binding = self.authority.bind(self.record(pid=10)); binding.close()
        for record in (None, {}, Record(b'{}', (20, 1000, 1000), -1),
                       Record(b'{}', (0, 1000, 1000), 20),
                       Record(b'{}', (20, 0, 0), 20),
                       Record(b'{}', (True, 1000, 1000), 20)):
            with self.subTest(record=record), self.assertRaises(OriginDenied): self.authority.bind(record)

    def test_sibling_socket_inheritance_does_not_grant_actor(self):
        self.graph[30] = {'parent': 31}
        self.graph[31] = {'parent': 1}
        self.denied(self.record(pid=30))

    def test_credential_namespace_and_root_mapping_mismatch_refuse(self):
        for field, value in [('status', status(uid=1001)), ('namespace', ((11, 99), (11, 33))),
                             ('status', {**status(), 'NSpid': (20, 5), 'NStgid': (20, 5)})]:
            with self.subTest(field=field, value=value):
                self.graph[20] = {'parent': 10, field: value}; FakeTask.constructed = []
                self.denied()
        self.graph[20] = {'parent': 10}
        self.graph[10]['namespace'] = ((11, 44), (11, 33)); FakeTask.constructed = []
        self.denied()

    def test_root_namespace_is_pinned_at_supervisor_admission(self):
        new_ns = ((11, 44), (11, 55))
        self.graph[20]['namespace'] = new_ns
        self.graph[10]['namespace'] = new_ns
        self.denied()

    def test_pid_reuse_and_reparent_during_final_check_refuse(self):
        self.graph[20]['identity'] = (7, 200)
        self.denied()
        self.graph[20] = {'parent': 10, 'changed': True}; FakeTask.constructed = []
        self.denied()
        self.graph[20] = {'parent': 10}; self.graph[10]['dead'] = True
        FakeTask.constructed = []; self.denied()

    def test_depth_cycles_and_deadline_are_bounded(self):
        self.graph.clear()
        self.graph.update({pid: {'parent': pid + 1} for pid in range(20, 53)})
        self.denied()
        self.assertEqual(len(FakeTask.constructed), 32)
        self.graph.clear(); self.graph.update({20: {'parent': 21}, 21: {'parent': 20}})
        FakeTask.constructed = []; self.denied()
        with patch('uas.git_process.time.monotonic', side_effect=(0, .051)):
            FakeTask.constructed = []; self.denied()

    def test_root_revocation_and_replacement_fence_existing_stream(self):
        binding = self.authority.bind(self.record())
        self.allowed = False
        with self.assertRaises(OriginDenied): binding.current()
        self.allowed = True
        self.root.revoked = True
        with self.assertRaises(OriginDenied): binding.current()
        self.root.revoked = False; self.root.pidfd = 99
        with self.assertRaises(OriginDenied): binding.current()
        binding.close()

    def test_each_request_rebuilds_lineage_and_never_reuses_old_positive(self):
        first = self.authority.bind(self.record()); first.close()
        self.graph[20]['parent'] = 30
        self.graph[30] = {'parent': 1}
        FakeTask.constructed = []; self.denied()

    def test_revocation_during_revalidation_is_rechecked(self):
        binding = self.authority.bind(self.record())
        with patch.object(FakeTask, 'check', side_effect=lambda: setattr(self, 'allowed', False)):
            with self.assertRaises(OriginDenied): binding.current()
        binding.close()

    def test_final_slow_observation_does_not_escape_time_limit(self):
        binding = self.authority.bind(self.record())
        clock = [0]
        with patch('uas.git_process.time.monotonic', side_effect=lambda: clock[0]), \
                patch.object(FakeTask, 'check', side_effect=lambda: clock.__setitem__(0, .060)):
            with self.assertRaises(OriginDenied): binding.current()
        binding.close()

    def test_admission_and_final_revalidation_share_absolute_deadline(self):
        clock = [0]
        original = FakeTask.__init__
        def delayed(task, *args, **kwargs):
            original(task, *args, **kwargs)
            clock[0] += .020
        def slow_check(): clock[0] += .020
        with patch('uas.git_process.time.monotonic', side_effect=lambda: clock[0]), \
                patch.object(FakeTask, '__init__', delayed), patch.object(FakeTask, 'check', side_effect=slow_check):
            self.denied()


if __name__ == '__main__': unittest.main()
