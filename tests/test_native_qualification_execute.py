"""Root wrapper lifecycle with explicit process/socket doubles only."""
from contextlib import contextmanager, ExitStack
import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas.native_qualification import execute, QualificationError


class NativeQualificationExecuteTests(unittest.TestCase):
    def fixture(self, root, *, child_timeout=False, broker_timeout=False):
        events = []
        supervisor = root / 'supervisor'; supervisor.mkdir()
        private = root / 'broker'; private.mkdir(mode=0o700)
        credential = root / 'credential'; credential.write_text('never read by test or wrapper')
        plan = N(room={'id': 'room', 'project': {'id': 'project', 'repository': 'owner/repo'}},
            config={'deployment': {'id': 'deployment'}}, config_text='{}', config_digest='a' * 64,
            installation={'timeout_seconds': 90}, installation_digest='b' * 64,
            require_unchanged=Mock(), preflight=lambda: {'missing_prerequisites': []})
        data = {'instance': 'c' * 32, 'supervisor_directory': str(supervisor)}
        resources = N(data=data, pass_fds=(31, 32),
            expect_broker=lambda: events.append('expect-broker'),
            hold_broker=lambda p: events.append(('hold-broker', p)),
            expect_child=lambda: events.append('expect-child'),
            hold_child=lambda p: events.append(('hold-child', p)))
        @contextmanager
        def provision(_):
            events.append('provision')
            try: yield resources
            finally:
                events.append('cleanup-owner')
                resources.retained_evidence = {'status': 'stopped-evidence-retained',
                                              'instance': data['instance'], 'path': str(root)}
        class Channel:
            def __init__(self, number): self.number = number
            def fileno(self): return self.number
            def close(self): events.append(('close-channel', self.number))
        channels = (Channel(41), Channel(42))
        class Process:
            def __init__(self, role):
                self.role = role; self.returncode = None; self.terminated = False
                self.stdin = N(write=lambda raw: events.append(('stdin', role)), close=lambda: None)
            def poll(self): return self.returncode
            def communicate(self, raw, timeout):
                events.append('communicate-child')
                if child_timeout: raise subprocess.TimeoutExpired('fixed-child', timeout)
                self.returncode = 0
                return json.dumps({'status': 'NATIVE_PAIR_ATTACHED', 'instance': data['instance'],
                    'configuration_sha256': plan.config_digest,
                    'installation_sha256': plan.installation_digest}).encode(), None
            def wait(self, timeout):
                events.append(('wait', self.role))
                if self.role == 'broker' and broker_timeout: raise subprocess.TimeoutExpired('fixed-broker', timeout)
                self.returncode = 0; return 0
            def terminate(self): self.terminated = True; events.append(('terminate', self.role))
            def kill(self): events.append(('kill', self.role))
        broker, child = Process('broker'), Process('child')
        def popen(argv, **kwargs):
            role = 'broker' if argv[2] == 'uas.forge_read_service' else 'child'
            events.append(('spawn', role))
            self.assertNotIn('shell', kwargs)
            self.assertEqual(kwargs['user'], 165534 if role == 'broker' else 165533)
            return broker if role == 'broker' else child
        original_lstat = Path.lstat
        def lstat(path):
            if path == credential: return N(st_mode=stat.S_IFREG | 0o600, st_uid=165534, st_nlink=1)
            if path == private: return N(st_mode=stat.S_IFDIR | 0o700, st_uid=165534)
            return original_lstat(path)
        original_stat = __import__('os').stat
        def osstat(path, *args, **kwargs):
            if str(path) == '/run/docker.sock': return N(st_gid=1999)
            return original_stat(path, *args, **kwargs)
        stack = ExitStack()
        stack.enter_context(patch('uas.native_qualification_backend.provision', provision))
        stack.enter_context(patch('uas.native_qualification.broker_selection', return_value={
            'version': 1, 'credential_path': str(credential), 'gh_executable': '/usr/bin/gh',
            'gh_sha256': 'e' * 64, 'gate_actor': 'gate', 'review_actor': 'review'}))
        stack.enter_context(patch('os.getuid', return_value=0))
        stack.enter_context(patch('os.chown', side_effect=lambda *a: events.append('chown-result-dir')))
        stack.enter_context(patch('os.stat', side_effect=osstat))
        stack.enter_context(patch.object(Path, 'lstat', lstat))
        stack.enter_context(patch('socket.socketpair', return_value=channels))
        stack.enter_context(patch('subprocess.Popen', side_effect=popen))
        stack.enter_context(patch('uas.native_qualification.write_startup',
                                  side_effect=lambda stream, raw, deadline: events.append('bounded-broker-startup')))
        self.addCleanup(stack.close)
        return plan, events, broker, child

    def test_fixed_children_intent_custody_and_cleanup_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, events, broker, child = self.fixture(Path(tmp))
            result = execute(plan)
            self.assertEqual(result['status'], 'NATIVE_PAIR_ATTACHED')
            self.assertLess(events.index('expect-broker'), events.index(('spawn', 'broker')))
            self.assertLess(events.index(('hold-broker', broker)), events.index('expect-child'))
            self.assertLess(events.index('expect-child'), events.index(('spawn', 'child')))
            self.assertLess(events.index(('hold-child', child)), events.index('communicate-child'))
            self.assertEqual(events[-1], 'cleanup-owner')

    def test_child_timeout_stops_only_owned_child_and_never_resends(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, events, broker, child = self.fixture(Path(tmp), child_timeout=True)
            with self.assertRaises(subprocess.TimeoutExpired): execute(plan)
            self.assertTrue(child.terminated); self.assertFalse(broker.terminated)
            self.assertEqual(events.count(('spawn', 'child')), 1)
            self.assertEqual(events.count('communicate-child'), 1)

    def test_stuck_broker_is_pending_not_killed_or_successful(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan, events, broker, child = self.fixture(Path(tmp), broker_timeout=True)
            with self.assertRaisesRegex(QualificationError, 'BROKER_CLEANUP_PENDING'): execute(plan)
            self.assertFalse(broker.terminated)
            self.assertNotIn(('kill', 'broker'), events)
