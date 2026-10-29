"""Pure contracts for runner-only smoke; never execute its Linux operations."""
import ast
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tests/linux/artifact_smoke.py'
spec = importlib.util.spec_from_file_location('artifact_linux_smoke_source', SCRIPT)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class ArtifactLinuxSmokeSourceTests(unittest.TestCase):
    def test_complete_generated_config_is_relocated_not_rebuilt_or_normalized(self):
        root = Path('/tmp/uas-gate-source-test')
        original = smoke.guest.fixture_layout(smoke.NONCE, json.loads((ROOT / 'tests/fixtures/two-rooms.json').read_text()))
        plan = smoke.relocated_plan(root)
        restored = deepcopy(plan)
        def restore(value):
            if isinstance(value, dict):
                return {key: restore(item) for key, item in value.items()}
            if isinstance(value, list):
                return [restore(item) for item in value]
            if isinstance(value, str):
                for current, before in ((str(root / 'scratch'), original['scratch_root']),
                                        (str(root / 'storage'), str(smoke.guest.STORAGE))):
                    if value == current or value.startswith(current + '/'):
                        return before + value[len(current):]
            return value
        self.assertEqual(restore(restored), original)
        config = smoke.load(io.StringIO(json.dumps(plan['configuration'])))
        self.assertEqual({room['id'] for room in config['rooms']}, {'alpha', 'beta'})
        for room, paths in plan['rooms'].items():
            selected = next(item for item in plan['configuration']['rooms'] if item['id'] == room)
            self.assertEqual(selected['state_root'], str(Path(plan['state_root']) / room))
            self.assertEqual(selected['project']['roots']['repo'], paths['repo'])
            self.assertLess(len(str(Path(paths['gate']) / 'gate.sock').encode()), 108)

    def test_relative_or_parent_component_relocation_is_refused_without_effects(self):
        for root in ('relative', '/tmp/../escape'):
            with self.subTest(root=root), self.assertRaises(AssertionError):
                smoke.relocated_plan(root)

    def test_numeric_commands_drop_all_capabilities_without_creating_accounts(self):
        payload = Path('/tmp/uas-gate-fixed/source')
        command = smoke.numeric_command(payload, smoke.UID, (smoke.HELPER, smoke.HUB), '--supervisor', 'plan', 'alpha', 7, 8)
        self.assertEqual(command[:8], ['/usr/bin/setpriv', '--reuid=165533', '--regid=165533',
            '--groups=165530,165531', '--inh-caps=-all', '--ambient-caps=-all',
            '--bounding-set=-all', '--no-new-privs'])
        self.assertEqual(command[8], '/usr/bin/python3')
        self.assertEqual(command[9], str(payload / 'tests/linux/artifact_smoke.py'))
        self.assertEqual(command[-5:], ['--supervisor', 'plan', 'alpha', '7', '8'])

    def test_default_or_nonrunner_execution_cannot_provision_a_fixture(self):
        for arguments, uid, environment in (([], 0, {}), (['--run'], 1000, {}), (['--run'], 0, {})):
            with self.subTest(arguments=arguments, uid=uid), \
                    patch.object(smoke.sys, 'argv', ['artifact_smoke.py', *arguments]), \
                    patch.object(smoke.os, 'geteuid', return_value=uid), \
                    patch.dict(smoke.os.environ, environment, clear=True), \
                    patch.object(smoke.tempfile, 'mkdtemp') as create, \
                    patch.object(smoke.signal, 'signal') as handler, \
                    patch.object(smoke.subprocess, 'Popen') as spawn:
                with self.assertRaises(AssertionError):
                    smoke.main()
                create.assert_not_called()
                handler.assert_not_called()
                spawn.assert_not_called()

    def test_native_authority_is_a_tripwire_not_a_successful_admission_stub(self):
        authority = smoke.ForbiddenNativeAuthority()
        for name in ('create', 'inspect', 'require'):
            with self.assertRaisesRegex(AssertionError, 'must not invoke Engine/native admission'):
                getattr(authority, name)

    def test_runner_uses_real_shared_sender_receiver_and_full_constructor_materializer(self):
        source = SCRIPT.read_text()
        tree = ast.parse(source)
        calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        for name in ('guest.setup_listener_child', 'guest.receive_setup_listener',
                     'fixture_supervisor.setup_source', 'target.ArtifactTargets',
                     'helper.GateEndpointLease', 'helper.GateHelperLaunch', 'helper._LaunchJournal',
                     'targets.prepare', 'targets.cleanup', 'lease.recheck', 'os.fork'):
            self.assertIn(name, calls)
        for name in ('guest.labeled_listener', 'fixture_supervisor.scenario',
                     'fixture_supervisor.NativeAdmission', 'launch.start', 'ctypes.CDLL'):
            self.assertNotIn(name, calls)
        self.assertNotIn('unittest.mock', source)
        self.assertIn("'native_qualification': False", source)
        self.assertIn("read_denied(scratch)", source)
        self.assertIn("helper._directory(scratch / 'search-only-leaf')", source)
        self.assertIn("error.code == 'GATE_ENDPOINT_REPLACED'", source)

    def test_workflow_is_bounded_parallel_readonly_and_never_runs_full_vm(self):
        workflow = (ROOT / '.github/workflows/validate.yml').read_text()
        job = workflow.split('  artifact-linux-smoke:\n', 1)[1].split('  docker-lifecycle:\n', 1)[0]
        self.assertIn('needs: [validate, unit-slow]', job)
        self.assertIn('timeout-minutes: 1', job)
        self.assertIn("needs.validate.outputs.skip_tests != 'true'", job)
        self.assertIn("needs.unit-slow.outputs.skip_tests != 'true'", job)
        self.assertIn('persist-credentials: false', job)
        self.assertIn('timeout --signal=TERM --kill-after=2s 43s sudo -n', job)
        self.assertIn('tests/linux/artifact_smoke.py --run', job)
        self.assertNotIn('install', job)
        self.assertNotIn('run_artifacts.py', job)
        self.assertEqual(smoke.LIMIT_SECONDS, 40)

    def test_staged_sources_are_exact_bounded_readonly_ordinary_copies(self):
        self.assertEqual(len(smoke.SOURCES), 27)
        self.assertIn('uas/typed_json.py', smoke.SOURCES)
        self.assertEqual(len(set(smoke.SOURCES)), len(smoke.SOURCES))
        with tempfile.TemporaryDirectory() as directory:
            payload = smoke.stage_sources(Path(directory))
            copied = {str(path.relative_to(payload)) for path in payload.rglob('*') if path.is_file()}
            self.assertEqual(copied, set(smoke.SOURCES))
            for name in smoke.SOURCES:
                self.assertEqual((payload / name).read_bytes(), (ROOT / name).read_bytes())
                self.assertEqual((payload / name).stat().st_mode & 0o777, 0o444)
            for path in (payload, *(p for p in payload.rglob('*') if p.is_dir())):
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        self.assertIn('uas/gate_policy.py', smoke.SOURCES)  # Config's lazy schema import.
        for relative in smoke.SOURCES:
            if not relative.endswith('.py'):
                continue
            for node in ast.parse((ROOT / relative).read_text()).body:
                names = [item.name for item in node.names] if isinstance(node, ast.Import) else (
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for name in names:
                    candidates = [Path(name.replace('.', '/') + '.py'), Path('tests/vm') / (name + '.py')]
                    if isinstance(node, ast.ImportFrom) and node.level:
                        candidates.append(Path(relative).parent / (name.replace('.', '/') + '.py'))
                    for candidate in candidates:
                        if (ROOT / candidate).is_file():
                            self.assertIn(candidate.as_posix(), smoke.SOURCES, relative)

    def test_staged_host_checkout_and_artifact_imports_do_not_load_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = smoke.stage_sources(Path(directory))
            code = '''import pathlib,sys
sys.path.insert(0,sys.argv[1])
from uas.lifecycle import Supervisor
from uas.checkouts import CheckoutAllocator
from uas.artifact_target import ArtifactSourceResolver
supervisor=Supervisor('/srv/uas/state','alpha',None,authorize=lambda *_:True,revoke=lambda *_:True)
with (pathlib.Path(sys.argv[1])/'tests/fixtures/two-rooms.json').open() as source:
    allocator=CheckoutAllocator(supervisor,source)
ArtifactSourceResolver(supervisor,allocator)
assert 'uas.checkout_writers' not in sys.modules
assert 'uas.docker_fixture' not in sys.modules
assert 'uas.launch' not in sys.modules
'''
            # Import/construction only: no child fixture, listener, kernel
            # boundary, Git, Docker or credential operation is executed.
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(payload)],
                cwd=directory, capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_staging_refuses_symlink_sources_and_oversized_files(self):
        for kind in ('symlink', 'oversized'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'input'
                source.mkdir()
                original = source / 'fixed.py'
                if kind == 'symlink':
                    original.symlink_to(SCRIPT)
                else:
                    original.write_bytes(b'x' * ((256 << 10) + 1))
                destination = root / 'output'
                destination.mkdir()
                with patch.object(smoke, 'ROOT', source), patch.object(smoke, 'SOURCES', ('fixed.py',)):
                    with self.assertRaises((OSError, AssertionError)):
                        smoke.stage_sources(destination)

    def test_child_self_deadline_allows_two_seconds_then_hard_expires(self):
        with patch.object(smoke.signal, 'signal') as handler, patch.object(smoke.signal, 'alarm') as alarm, \
                patch.object(smoke.signal, 'pthread_sigmask', return_value=set()), \
                patch.dict(smoke.os.environ, {smoke.DEADLINE_ENV: '140'}), \
                patch.object(smoke.time, 'monotonic', return_value=100):
            smoke.child_deadline(25)
            callback = handler.call_args.args[1]
            with self.assertRaises(TimeoutError):
                callback()
        self.assertEqual(alarm.call_args_list, [unittest.mock.call(25), unittest.mock.call(2)])
        self.assertEqual(handler.call_args.args, (signal.SIGALRM, signal.SIG_DFL))

    def test_late_child_deadline_is_capped_by_parent_and_expired_deadline_refuses_effects(self):
        with patch.object(smoke.signal, 'signal') as handler, patch.object(smoke.signal, 'alarm') as alarm, \
                patch.object(smoke.signal, 'pthread_sigmask', return_value=set()), \
                patch.dict(smoke.os.environ, {smoke.DEADLINE_ENV: '140'}), \
                patch.object(smoke.time, 'monotonic', return_value=139.5):
            smoke.child_deadline(25)
            alarm.assert_called_once_with(1)
        with patch.object(smoke.signal, 'signal') as handler, patch.object(smoke.signal, 'alarm') as alarm, \
                patch.object(smoke.signal, 'pthread_sigmask', return_value=set()), \
                patch.dict(smoke.os.environ, {smoke.DEADLINE_ENV: '140'}), \
                patch.object(smoke.time, 'monotonic', return_value=140):
            with self.assertRaises(AssertionError):
                smoke.child_deadline(25)
            handler.assert_not_called()
            alarm.assert_not_called()

    def test_alarm_mask_query_is_empty_and_blocked_or_missing_support_fails_closed(self):
        with patch.object(smoke.signal, 'pthread_sigmask', return_value=set()) as query:
            smoke.require_unblocked_alarm()
            query.assert_called_once_with(signal.SIG_BLOCK, ())
        for result, failure in (({signal.SIGALRM}, None), (None, AttributeError('unavailable'))):
            with self.subTest(result=result), \
                    patch.object(smoke.signal, 'pthread_sigmask', return_value=result, side_effect=failure), \
                    patch.object(smoke.signal, 'signal') as handler, patch.object(smoke.signal, 'alarm') as alarm:
                with self.assertRaises((AssertionError, AttributeError)):
                    smoke.child_deadline(25)
                handler.assert_not_called()
                alarm.assert_not_called()

    def test_blocked_alarm_refuses_root_before_fixture_or_timer_effects(self):
        with patch.object(smoke.sys, 'argv', ['fixed', '--run']), \
                patch.object(smoke.os, 'geteuid', return_value=0), \
                patch.dict(smoke.os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'}, clear=True), \
                patch.object(smoke.signal, 'pthread_sigmask', return_value={signal.SIGALRM}), \
                patch.object(smoke.signal, 'signal') as handler, patch.object(smoke.signal, 'alarm') as alarm, \
                patch.object(smoke.tempfile, 'mkdtemp') as create:
            with self.assertRaisesRegex(AssertionError, 'unblocked SIGALRM'):
                smoke.main()
            handler.assert_not_called()
            alarm.assert_not_called()
            create.assert_not_called()

    def process_fixture(self, process, kill=None):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(smoke.guest, 'require_setup_reaping'))
        stack.enter_context(patch.object(smoke.threading, 'active_count', return_value=1))
        spawn = stack.enter_context(patch.object(smoke.subprocess, 'Popen', return_value=process))
        signal_group = stack.enter_context(patch.object(smoke.os, 'killpg', side_effect=kill))
        return spawn, signal_group

    def test_successful_owned_child_is_reaped_by_communicate_without_group_signal(self):
        process = Mock(pid=123, returncode=0)
        process.communicate.return_value = (b'ok', b'')
        spawn, kill = self.process_fixture(process)
        payload = Path('/tmp/uas-gate-fixed/source')
        self.assertEqual(smoke.run_owned(['fixed'], payload=payload, deadline=smoke.time.monotonic() + 40), b'ok')
        self.assertEqual(spawn.call_args.kwargs['cwd'], payload)
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        process.poll.assert_not_called()
        kill.assert_not_called()

    def test_pipe_timeout_signals_group_before_reaping_even_if_leader_has_exited(self):
        process = Mock(pid=123, returncode=None)
        events = []
        def communicate(*, timeout):
            events.append(('communicate', timeout))
            if timeout == 20:
                raise subprocess.TimeoutExpired('fixed', timeout)  # Descendant still holds the pipe.
            process.returncode = -signal.SIGKILL
            return b'', b''
        process.communicate.side_effect = communicate
        _, kill = self.process_fixture(process, lambda *args: events.append(('kill', args)))
        with self.assertRaises(subprocess.TimeoutExpired):
            smoke.run_owned(['fixed'], payload=Path('/tmp/fixed'), deadline=smoke.time.monotonic() + 40)
        self.assertEqual(events, [('communicate', 20), ('kill', (123, signal.SIGKILL)), ('communicate', 2)])
        process.poll.assert_not_called()
        kill.assert_called_once()

    def test_already_reaped_or_interrupted_child_never_authorizes_numeric_group_signal(self):
        for code, failure in ((0, subprocess.TimeoutExpired('fixed', 20)), (None, KeyboardInterrupt())):
            with self.subTest(code=code, failure=type(failure).__name__):
                process = Mock(pid=123, returncode=code)
                process.communicate.side_effect = failure
                _, kill = self.process_fixture(process)
                with self.assertRaisesRegex(RuntimeError, 'cleanup unconfirmed'):
                    smoke.run_owned(['fixed'], payload=Path('/tmp/fixed'), deadline=smoke.time.monotonic() + 40)
                process.poll.assert_not_called()
                kill.assert_not_called()

    def test_signal_or_reap_failure_is_explicitly_unconfirmed_not_success(self):
        for failure in ('signal', 'reap'):
            with self.subTest(failure=failure):
                process = Mock(pid=123, returncode=None)
                process.communicate.side_effect = [subprocess.TimeoutExpired('fixed', 20),
                                                  subprocess.TimeoutExpired('fixed', 2)]
                _, kill = self.process_fixture(process, PermissionError('fixed') if failure == 'signal' else None)
                with self.assertRaisesRegex(RuntimeError, 'cleanup unconfirmed'):
                    smoke.run_owned(['fixed'], payload=Path('/tmp/fixed'), deadline=smoke.time.monotonic() + 40)
                process.poll.assert_not_called()
                self.assertEqual(process.communicate.call_count, 1 if failure == 'signal' else 2)
                kill.assert_called_once_with(123, signal.SIGKILL)

    def test_failed_smoke_retains_private_fixture_and_never_prints_success(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(patch.object(smoke.sys, 'argv', ['fixed', '--run']))
            stack.enter_context(patch.object(smoke.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(smoke.os, 'listdir', return_value=[]))
            stack.enter_context(patch.dict(smoke.os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'}, clear=True))
            stack.enter_context(patch.object(smoke.signal, 'signal'))
            stack.enter_context(patch.object(smoke.signal, 'alarm'))
            stack.enter_context(patch.object(smoke.signal, 'pthread_sigmask', return_value=set()))
            stack.enter_context(patch.object(smoke.tempfile, 'mkdtemp', return_value=directory))
            stack.enter_context(patch.object(smoke, 'provision', side_effect=RuntimeError('uncertain fixed child')))
            remove = stack.enter_context(patch.object(smoke.shutil, 'rmtree'))
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors), self.assertRaisesRegex(RuntimeError, 'uncertain'):
                smoke.main()
            remove.assert_not_called()
            self.assertEqual(output.getvalue(), '')
            self.assertIn('retained, cleanup NOT claimed', errors.getvalue())

    def test_listener_close_failure_cannot_skip_exact_child_cleanup(self):
        for close_error in (OSError('fixed close failure'), KeyboardInterrupt()):
            with self.subTest(error=type(close_error).__name__), ExitStack() as stack:
                left, right, listener = Mock(), Mock(), Mock()
                listener.close.side_effect = close_error
                stack.enter_context(patch.object(smoke.guest, 'require_setup_reaping'))
                stack.enter_context(patch.object(smoke.socket, 'socketpair', return_value=(left, right)))
                stack.enter_context(patch.object(smoke.os, 'fork', return_value=123))
                stack.enter_context(patch.object(smoke.guest, 'receive_setup_listener', return_value=listener))
                wait = stack.enter_context(patch.object(smoke.guest, 'setup_child_outcome', side_effect=[
                    {'outcome': 'unconfirmed'}, {'outcome': 'unconfirmed'}, {'outcome': 'signal', 'signal': 9}]))
                kill = stack.enter_context(patch.object(smoke.os, 'kill'))
                with self.assertRaises(type(close_error)):
                    smoke.transfer_listener(Path('/tmp/fixed/gate.sock'), smoke.HELPER, deadline=smoke.time.monotonic() + 40)
                self.assertEqual(wait.call_count, 3)
                kill.assert_called_once_with(123, signal.SIGKILL)
                left.close.assert_called_once()



if __name__ == '__main__':
    unittest.main()
