"""Pure source/mock contracts; importing or testing never runs the Linux seam."""
import ast
from contextlib import ExitStack, contextmanager
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tests/linux/room_service_smoke.py'


@contextmanager
def no_native_effects():
    """Installed before module imports, not merely around a test invocation."""
    with ExitStack() as stack:
        for owner, names in (
            (os, ('fork', 'forkpty', 'posix_spawn', 'posix_spawnp', 'execve', 'execv',
                  'pipe', 'pipe2', 'socketpair', 'pidfd_open', 'memfd_create', 'chroot',
                  'unshare', 'setuid', 'setgid', 'setgroups', 'chown', 'chmod', 'kill',
                  'waitpid', 'waitid', 'system', 'read', 'write', 'close', 'dup2', 'set_blocking')),
            (socket, ('socket', 'socketpair')),
            (subprocess, ('Popen', 'run')),
            (ctypes, ('CDLL',)),
            (signal, ('signal', 'alarm', 'pidfd_send_signal')),
            (threading.Thread, ('start',)),
            (Path, ('mkdir', 'chmod', 'unlink', 'rmdir', 'rename', 'write_text', 'write_bytes')),
            (shutil, ('copytree', 'copyfile', 'rmtree')),
            (tempfile, ('mkdtemp', 'TemporaryDirectory')),
        ):
            for name in names:
                if hasattr(owner, name):
                    stack.enter_context(patch.object(owner, name,
                        side_effect=AssertionError('native/source-write effect forbidden: ' + name)))
        yield


# All import-time target effects are trapped before the first source instruction.
with no_native_effects():
    from uas.room_probe import DENIED_HELP_STARTUP, DENIED_HELP_STARTUP_STEPS
    spec = importlib.util.spec_from_file_location('room_service_smoke_source', SCRIPT)
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)


class RoomServiceSmokeSourceTests(unittest.TestCase):
    def setUp(self):
        self.guards = no_native_effects()
        self.guards.__enter__()
        self.addCleanup(self.guards.__exit__, None, None, None)
        self.source = SCRIPT.read_text()
        self.tree = ast.parse(self.source)

    def test_import_and_existing_helper_imports_are_effect_free(self):
        helper = smoke.helpers()
        self.assertTrue(callable(helper.OwnedChild))
        self.assertTrue(callable(helper.FixtureTransport))
        self.assertTrue(callable(helper.helpers().gate))

    def test_nonhost_and_unprivileged_entry_reject_before_provisioning(self):
        for uid, env in ((0, {}), (1000, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'}),
                         (0, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'macOS'})):
            with self.subTest(uid=uid, env=env), patch.object(smoke.os, 'getuid', return_value=uid), \
                    patch.dict(smoke.os.environ, env, clear=True), \
                    patch.object(smoke.sys, 'argv', [str(SCRIPT)]):
                with self.assertRaisesRegex(AssertionError, 'explicitly disposable hosted Linux root'):
                    smoke.main()

    def test_caller_arguments_refuse_without_launch_even_in_hosted_gate(self):
        with patch.object(smoke.os, 'getuid', return_value=0), \
                patch.dict(smoke.os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'}, clear=True), \
                patch.object(smoke.signal, 'pthread_sigmask', return_value=set()), \
                patch.object(smoke.sys, 'argv', [str(SCRIPT), '/arbitrary/command']):
            with self.assertRaisesRegex(AssertionError, 'no caller-selected'):
                smoke.main()

    def test_fixed_bootstrap_is_original_room_probe_not_mock_or_new_protocol(self):
        spec = smoke.recipe()
        self.assertEqual(spec, {'AttachStdin': True, 'AttachStdout': True, 'AttachStderr': True,
            'Tty': False, 'Privileged': False, 'User': '65532:65532', 'WorkingDir': '/',
            'Cmd': ['/usr/bin/python3', '-I', '/opt/uas/uas/room_probe.py', 'bootstrap'], 'Env': []})
        spec['Cmd'].append('tampered')
        self.assertEqual(len(smoke.recipe()['Cmd']), 4)
        self.assertNotIn('unittest.mock', self.source)
        calls = {ast.unparse(n.func) for n in ast.walk(self.tree) if isinstance(n, ast.Call)}
        for name in ('room.RoomHelpOnlyCoordinator', 'room.ObservedAuthority', 'room.BrokerProcess',
                     'launch.launch', 'broker.observe', 'broker.require', 'serve_one',
                     'authority.bind', 'held.require', 'held.current', 'receive'):
            self.assertIn(name, calls)
        self.assertNotIn('room.prove_service', calls)
        self.assertNotIn('DockerExecAPI', calls)

    def test_engine_shape_is_single_fixed_owned_process_not_a_success_stub(self):
        engine = smoke.BootstrapEngine(Path('/tmp/owned/jail'), Mock())
        for container, spec in ((smoke.CONTAINER, {}), ('f' * 64, smoke.recipe())):
            with self.assertRaisesRegex(AssertionError, 'single fixed'):
                engine.create(container, spec)
        self.assertEqual(engine.create(smoke.CONTAINER, smoke.recipe()), 'b' * 64)
        with self.assertRaisesRegex(AssertionError, 'single fixed'):
            engine.create(smoke.CONTAINER, smoke.recipe())
        with self.assertRaisesRegex(AssertionError, 'single owned'):
            engine.start('f' * 64)
        with self.assertRaisesRegex(AssertionError, 'unknown bootstrap'):
            engine.inspect('b' * 64)
        start = next(n for n in ast.walk(self.tree) if isinstance(n, ast.FunctionDef) and n.name == 'start')
        body = ast.unparse(start)
        for operation in ('os.fork()', 'os.chroot(self.jail)', 'self.helper.isolate(UID)',
                          'os.execve(', 'self.helper.OwnedChild(pid)'):
            self.assertIn(operation, body)

    def test_engine_cleanup_attempts_owned_child_after_transport_failure(self):
        engine = smoke.BootstrapEngine(Path('/tmp/owned/jail'), Mock())
        engine.transport = Mock(); engine.transport.close.side_effect = RuntimeError('transport fault')
        engine.child = Mock()
        with self.assertRaisesRegex(AssertionError, 'owned bootstrap cleanup incomplete'):
            engine.close()
        engine.transport.close.assert_called_once_with()
        engine.child.finish.assert_called_once_with()

    def test_real_resources_enclose_each_authority_check_under_existing_lock(self):
        resource = next(n for n in ast.walk(self.tree) if isinstance(n, ast.FunctionDef) and n.name == 'resources')
        self.assertEqual([ast.unparse(n) for n in resource.body], ['lease.require()', 'broker.require()'])
        self.assertIn('checks, resources)', self.source)
        self.assertIn('lifecycle_lock=lambda: lock', self.source)
        self.assertIn('current(); resources(); held.current(); broker.require()', self.source)
        self.assertIn("send(launch.channel, {'kind': 'RELEASE_WORKLOAD'})", self.source)
        self.assertIn("probe_status['Uid'] == probe_status['Gid'] == (UID,) * 4", self.source)
        self.assertIn("checks['unrelated_refusal']['phase'] == 'lineage'", self.source)
        self.assertIn('poll.poll(2000) and not alive(launch.origin.pidfd)', self.source)
        self.assertIn("raise AssertionError('exited held bootstrap remained current')", self.source)

    def test_fresh_unrelated_exec_uses_shared_barrier_and_rechecks_through_G(self):
        self.assertIn("'/opt/uas/uas/room_probe.py', 'denied-help-ready'", self.source)
        self.assertIn('from uas.room_probe import DENIED_HELP_READY, DENIED_HELP_RELEASE, DENIED_HELP_SETUP_SECONDS',
                      self.source)
        self.assertIn('sibling, DENIED_HELP_STARTUP,', self.source)
        self.assertIn('all(marker not in stderr for _, marker in DENIED_HELP_STARTUP_STEPS)', self.source)
        self.assertNotIn('from uas.git_launcher import main as git', self.source)
        self.assertIn('DIAGNOSTIC_ONLY_NOT_AUTHORITY', self.source)
        self.assertIn('fresh_digest == digest', self.source)
        release_lock = next(n for n in ast.walk(self.tree) if isinstance(n, ast.With)
                            and 'os.write(go_w, DENIED_HELP_RELEASE)' in ast.unparse(n))
        block = ast.unparse(release_lock)
        self.assertTrue(block.startswith('with lock:'))
        self.assertGreater(block.rindex('current()'), block.index('fresh_digest == digest'))
        self.assertGreater(block.rindex('resources()'), block.index('fresh_digest == digest'))
        self.assertGreater(block.rindex('broker.require()'), block.index('fresh_digest == digest'))
        self.assertLess(block.rindex('held.current()'), block.index('os.write(go_w'))
        self.assertIn('close_pipe(go_w)', block)
        self.assertLess(block.rindex('broker.require()'), block.index('time.monotonic() < release_deadline'))
        self.assertLess(block.index('time.monotonic() < release_deadline'), block.index('os.write(go_w'))
        self.assertNotIn('release_deadline =', block)
        self.assertIn('release_deadline = marker_observed + DENIED_HELP_SETUP_SECONDS', self.source)
        self.assertLess(self.source.index('release_deadline = marker_observed'),
                        self.source.index("checks['unrelated_readiness'] ="))
        source = ast.parse((ROOT / 'uas/room_probe.py').read_text())
        constants = {n.targets[0].id: ast.literal_eval(n.value) for n in source.body
                     if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                     and n.targets[0].id in ('DENIED_HELP_READY', 'DENIED_HELP_RELEASE', 'DENIED_HELP_SETUP_SECONDS')}
        self.assertEqual(constants, {'DENIED_HELP_READY': b'UAS_ROOM_DENIED_HELP_READY\n',
            'DENIED_HELP_RELEASE': b'G', 'DENIED_HELP_SETUP_SECONDS': 5})

    def test_fragmented_ready_marker_is_accepted_without_real_pipes(self):
        marker = DENIED_HELP_STARTUP
        child = Mock(); child.observation.return_value = None
        with patch.object(smoke.time, 'monotonic', return_value=0), \
                patch.object(smoke.select, 'select', side_effect=[([30], [], []), ([30], [], []), ([], [], [])]), \
                patch.object(smoke.os, 'read', side_effect=[marker[:8], marker[8:]]) as read:
            self.assertEqual(0, smoke.read_probe_ready(10, 20, 30, child, marker, 5))
        self.assertEqual(read.call_args_list[0].args, (30, len(marker) + 1))

    def test_readiness_rejects_early_socket_stdout_exit_bad_duplicate_eof_and_timeout(self):
        marker = DENIED_HELP_STARTUP
        cases = (([10], b''), ([20], b''), ([], b''), ([30], b''),
                 ([30], b'wrong\n'), ([30], marker * 2))
        for ready, raw in cases:
            with self.subTest(ready=ready, raw=raw), \
                    patch.object(smoke.time, 'monotonic', return_value=0), \
                    patch.object(smoke.select, 'select', return_value=(ready, [], [])), \
                    patch.object(smoke.os, 'read', return_value=raw):
                child = Mock(); child.observation.return_value = None
                with self.assertRaises(AssertionError): smoke.read_probe_ready(10, 20, 30, child, marker, 5)
        for time_, status in ((6, None), (0, object())):
            with patch.object(smoke.time, 'monotonic', return_value=time_):
                child = Mock(); child.observation.return_value = status
                with self.assertRaisesRegex(AssertionError, 'expired or exited'):
                    smoke.read_probe_ready(10, 20, 30, child, marker, 5)
        with patch.object(smoke.time, 'monotonic', return_value=0), \
                patch.object(smoke.select, 'select', side_effect=[([30], [], []), ([20], [], [])]), \
                patch.object(smoke.os, 'read', return_value=marker):
            child = Mock(); child.observation.return_value = None
            with self.assertRaisesRegex(AssertionError, 'unexpected activity'):
                smoke.read_probe_ready(10, 20, 30, child, marker, 5)

    def test_output_capture_drains_both_owned_pipes_and_refuses_overflow_or_deadline(self):
        with patch.object(smoke.time, 'monotonic', return_value=0), \
                patch.object(smoke.select, 'select', side_effect=[([20, 30], [], []), ([20, 30], [], [])]), \
                patch.object(smoke.os, 'read', side_effect=[b'{"code":128}\n', b'refused\n', b'', b'']):
            self.assertEqual(smoke.collect_probe_output(20, 30, 5), (b'{"code":128}\n', b'refused\n'))
        with patch.object(smoke.time, 'monotonic', return_value=0), \
                patch.object(smoke.select, 'select', return_value=([20], [], [])), \
                patch.object(smoke.os, 'read', return_value=b'x' * 4097):
            with self.assertRaisesRegex(AssertionError, 'capture bound'): smoke.collect_probe_output(20, 30, 5)
        with patch.object(smoke.time, 'monotonic', return_value=6):
            with self.assertRaisesRegex(AssertionError, 'deadline'): smoke.collect_probe_output(20, 30, 5)

    def test_last_ready_marker_and_final_ready_observation_cannot_cross_deadline(self):
        marker = DENIED_HELP_STARTUP
        for clock in ([0, 5], [0, 0, 5], [0, 0, 0, 5]):
            with self.subTest(clock=clock), patch.object(smoke.time, 'monotonic', side_effect=clock), \
                    patch.object(smoke.select, 'select', side_effect=[([30], [], []), ([], [], [])]), \
                    patch.object(smoke.os, 'read', return_value=marker):
                child = Mock(); child.observation.return_value = None
                with self.assertRaisesRegex(AssertionError, 'readiness deadline'):
                    smoke.read_probe_ready(10, 20, 30, child, marker, 5)

    def test_last_output_eof_and_final_return_cannot_cross_deadline(self):
        for clock in ([0, 5], [0, 0, 0, 5], [0, 0, 0, 0, 5]):
            with self.subTest(clock=clock), patch.object(smoke.time, 'monotonic', side_effect=clock), \
                    patch.object(smoke.select, 'select', return_value=([20, 30], [], [])), \
                    patch.object(smoke.os, 'read', return_value=b''):
                with self.assertRaisesRegex(AssertionError, 'output deadline'):
                    smoke.collect_probe_output(20, 30, 5)

    def test_private_namespace_custody_never_mutates_or_deletes_host_broker_paths(self):
        self.assertIn("room.BROKER_ROOT = root / 'brokers'", self.source)
        self.assertNotIn('/var/lib/uas-room-brokers', self.source)
        self.assertIn("'--make-rprivate', '/'", self.source)
        self.assertIn("'--kill-child=KILL', '--mount-proc'", self.source)
        self.assertIn("os.getpid() != 1 and os.getppid() == 1", self.source)
        self.assertIn('finally: child.finish()', self.source)
        calls = {ast.unparse(n.func) for n in ast.walk(self.tree) if isinstance(n, ast.Call)}
        self.assertNotIn('shutil.rmtree', calls)
        self.assertNotIn('os.kill', calls)
        self.assertNotIn('os.waitpid', calls)  # Existing OwnedChild retains sole-reaper custody.
        self.assertNotIn('os.setns', calls)
        self.assertIn("tempfile.TemporaryDirectory(prefix='uas-room-protocol-', dir='/tmp')", self.source)

    def test_only_documented_broker_path_substitution_leaves_target_guards_intact(self):
        assignments = [ast.unparse(target) for node in ast.walk(self.tree)
                       if isinstance(node, ast.Assign) for target in node.targets
                       if isinstance(target, ast.Attribute) and ast.unparse(target).startswith('room.')]
        self.assertEqual(assignments, ['room.BROKER_ROOT'])
        target = (ROOT / 'tests/vm/room_service.py').read_text()
        for guard in ('165532, 165532', 'require_process_label(peer_label',
                      "['0','0','4294967295']", "'trusted Supervisor must use guest initial user/PID namespaces'"):
            self.assertIn(guard, target)
        lineage = (ROOT / 'uas/git_process.py').read_text()
        self.assertIn('MAX_DEPTH = 32', lineage)
        self.assertIn('MAX_SECONDS = .050', lineage)
        self.assertNotIn('MAX_SECONDS =', self.source)

    def test_scope_and_fail_closed_cleanup_are_not_native_qualification(self):
        for claim in ("'native_qualification': False", "selinux='NOT_TESTED'", "quota='NOT_TESTED'",
                      "network_policy='NOT_TESTED'", "remapped_container='NOT_TESTED'",
                      "engine='OWNED_PROCESS_ADAPTER_NOT_DOCKER'", "credentials_created=False"):
            self.assertIn(claim, self.source)
        self.assertIn("checks['cleanup_errors'] = errors", self.source)
        self.assertIn('if errors and failure is None: raise AssertionError', self.source)
        self.assertIn("checks.update(status='failed', error_type=type(error).__name__)", self.source)
        self.assertIn("if failure is not None or errors:", self.source)
        self.assertEqual(smoke.LIMIT_SECONDS, 25)
        self.assertIn('signal.alarm(max(1, int(remaining)))', self.source)
        self.assertIn('deadline = time.monotonic() + 27', self.source)
        self.assertIn('child.wait(timeout=max(.001, deadline - time.monotonic()))', self.source)

    def test_composed_case_uses_exact_old_source_not_shortened_current_timeout(self):
        old = ROOT / 'tests/linux/fixtures/room_probe_96f6.py'
        self.assertEqual(hashlib.sha256(old.read_bytes()).hexdigest(), smoke.LEGACY_SHA256)
        self.assertNotIn('BOOTSTRAP_CONTROL_SECONDS', old.read_text())
        self.assertIn('channel.settimeout(12)', old.read_text())
        self.assertEqual(smoke.recipe('legacy-96f6')['Cmd'][2], '/opt/uas/room_probe_96f6.py')
        self.assertNotIn('BOOTSTRAP_CONTROL_SECONDS =', self.source)
        with self.assertRaisesRegex(AssertionError, 'unknown fixed Room case'): smoke.recipe('other')

    def test_two_latency_boundaries_enclose_actual_helper_and_final_live_checks(self):
        self.assertEqual(smoke.ADMISSION_DELAY_SECONDS, 8)
        start = self.source.index("admission_boundary('before_unrelated_helper')")
        helper = self.source.index('pid = os.fork()', start)
        refusal = self.source.index("checks['unrelated_refusal'] =", helper)
        end = self.source.index("admission_boundary('before_workload_release')", refusal)
        release = self.source.index("send(launch.channel, {'kind': 'RELEASE_WORKLOAD'})", end)
        self.assertLess(start, helper); self.assertLess(helper, refusal)
        self.assertLess(refusal, end); self.assertLess(end, release)
        self.assertIn('current(); resources(); held.current(); current(); resources(); broker.require()',
                      self.source[end:release])
        self.assertIn("observed['exit_code'] == 1", self.source[end:release])
        self.assertIn("'TimeoutError: timed out' in observed['stderr']", self.source[end:release])
        self.assertIn('timed-out bootstrap remained current', self.source[end:release])
        self.assertIn("not checks['workload_release_sent']", self.source[end:release])

    def test_capture_is_bounded_and_uses_waitid_observation_not_pipe_eof(self):
        engine = smoke.BootstrapEngine(Path('/tmp/owned/jail'), Mock())
        engine.stderr_fd = 42
        engine.child = Mock(owned=True)
        engine.child.observation.return_value = None
        with patch.object(smoke.os, 'read', side_effect=[b'TimeoutError: timed out\n', b'']):
            result = engine.observe_exit()
        self.assertFalse(result['exit_observed'])
        self.assertIsNone(result['exit_code'])
        engine.child.observation.return_value = type('Exit', (), {'si_status': 1, 'si_code': os.CLD_EXITED})()
        with patch.object(smoke.os, 'read', side_effect=BlockingIOError):
            result = engine.observe_exit()
        self.assertTrue(result['exit_observed']); self.assertEqual(result['exit_code'], 1)
        self.assertIn('TimeoutError', result['stderr'])
        with patch.object(smoke.os, 'read', side_effect=[b'x' * 4096]):
            result = engine.observe_exit()
        self.assertTrue(result['stderr_truncated']); self.assertLessEqual(len(result['stderr']), 4096)
        engine.child.finish.assert_not_called()

    def test_main_cases_have_distinct_roots_and_are_started_before_any_wait(self):
        self.assertEqual(smoke.CASES, ('current', 'legacy-96f6'))
        main = next(n for n in ast.walk(self.tree) if isinstance(n, ast.FunctionDef) and n.name == 'main')
        loops = [n for n in ast.walk(main) if isinstance(n, ast.For)]
        launch = next(n for n in loops if 'subprocess.Popen' in ast.unparse(n))
        self.assertIn('tempfile.TemporaryDirectory', ast.unparse(launch))
        self.assertNotIn('.wait(', ast.unparse(launch))
        self.assertIn("'--namespace', temporary, case", ast.unparse(launch))
        self.assertIn('if child.poll() is None: child.kill()', self.source)
        self.assertIn('try: child.wait(timeout=1)', self.source)
        self.assertIn('if primary is None: raise AssertionError', self.source)

    def test_workflow_adds_one_parallel_child_without_new_job_or_budget(self):
        workflow = (ROOT / '.github/workflows/validate.yml').read_text()
        job = workflow.split('  git-native-seams:\n', 1)[1].split('  gate-linux-smoke:\n', 1)[0]
        self.assertIn('timeout-minutes: 1', job)
        self.assertIn('needs: [validate, unit-slow]', job)
        self.assertIn('persist-credentials: false', job)
        self.assertIn('timeout --signal=TERM --kill-after=2s 29s sudo -n', job)
        self.assertIn('tests/linux/room_service_smoke.py & room_protocol=$!', job)
        self.assertIn('"$composition" "$room_protocol"; do', job)
        self.assertNotIn('run_room.py', job)
        self.assertNotIn('apt-get', job)
        self.assertNotIn('pip install', job)
        self.assertNotIn('timeout-minutes: 2', job)


if __name__ == '__main__': unittest.main()
