"""Safety/source contracts only: does not run a prepared native installation."""
import importlib.util
import io
import json
from contextlib import redirect_stdout
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).parent/'native/library_installation_probe.py'
spec = importlib.util.spec_from_file_location('library_installation_probe', PATH)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class LibraryInstallationProbeTests(unittest.TestCase):
    def test_explicit_opt_in_before_host_effects(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(probe, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'explicit'):
                probe.main(['--run', '--installation-root', '/prepared', '--expected-commit', 'a'*40])
        run.assert_not_called()

    def test_no_implicit_run_even_with_environment(self):
        with patch.dict(os.environ, {'UAS_LIBRARY_INSTALLATION_PROOF': '1'}), patch.object(probe, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'explicit'):
                probe.main(['--installation-root', '/prepared', '--expected-commit', 'a'*40])
        run.assert_not_called()

    def test_candidate_gate_precedes_process(self):
        with patch.object(probe.os, 'geteuid', return_value=0), \
             patch.object(probe.subprocess, 'check_output', return_value='b'*40), \
             patch.object(probe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'candidate commit mismatch'):
                probe.run('/prepared', 'a'*40)
        spawn.assert_not_called()


    def test_real_bundle_markers_detect_missing_and_sibling_content(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'context').mkdir()
            own = root / 'context/index.md'; own.write_text('alpha-private')
            probe.isolated_marker(root, 'alpha-private', ['beta-private'])
            with self.assertRaisesRegex(RuntimeError, 'own Project marker absent'):
                probe.isolated_marker(root, 'missing', ['beta-private'])
            leak = root / 'context/leak.md'; leak.write_text('beta-private')
            with self.assertRaisesRegex(RuntimeError, 'sibling Project content exposed'):
                probe.isolated_marker(root, 'alpha-private', ['beta-private'])
            leak.unlink(); (root / 'beta-private.md').write_text('innocent')
            with self.assertRaisesRegex(RuntimeError, 'sibling Project content exposed'):
                probe.isolated_marker(root, 'alpha-private', ['beta-private'])


    def test_startup_diagnostic_preserves_code_and_owned_phase_without_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            room = {'id': 'alpha', 'state_root': temp}
            receipt = {'room_id': 'alpha', 'instance_id': 'a'*32, 'phase': 'start_failed',
                       'spec': {'credential': 'never-print-this'},
                       'leftovers': [{'kind': 'reconciliation', 'name': '/private/path',
                                      'reason': 'ADMISSION_FAILED'}]}
            path = Path(temp) / 'lifecycle.json'; path.write_text(json.dumps(receipt))
            response = {'outcome': 'unknown', 'error': 'LOCAL_HUB_START_FAILED',
                        'details': 'never-print-this'}
            output = io.StringIO()
            with redirect_stdout(output): result = probe.startup_diagnostic(room, response)
            self.assertEqual(result['error'], 'LOCAL_HUB_START_FAILED')
            self.assertEqual(result['owned_receipt']['phase'], 'start_failed')
            self.assertNotIn('never-print-this', output.getvalue())
            self.assertNotIn('/private/path', output.getvalue())
            path.unlink(); path.symlink_to(Path(temp) / 'elsewhere')
            with redirect_stdout(io.StringIO()): result = probe.startup_diagnostic(room, response)
            self.assertEqual(result['owned_receipt'], {'state': 'unavailable'})

    def test_startup_diagnostic_rejects_oversize_wrong_scope_and_arbitrary_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            room = {'id': 'alpha', 'state_root': temp}
            path = Path(temp) / 'lifecycle.json'
            for raw in ('x'*1048577, json.dumps({'room_id': 'beta', 'phase': 'running'})):
                path.write_text(raw)
                with redirect_stdout(io.StringIO()):
                    result = probe.startup_diagnostic(room, {'outcome': 'unknown', 'error': '/secret/token'})
                self.assertEqual(result['error'], 'REDACTED')
                self.assertEqual(result['owned_receipt'], {'state': 'unavailable'})

    def test_owned_hub_diagnostic_requires_exact_labels_before_logs(self):
        receipt = {'room_id': 'alpha', 'instance_id': 'a'*32,
                   'spec': {'config_digest': 'sha256:'+'b'*64, 'profile_digest': 'sha256:'+'c'*64}}
        from uas.local_native import LocalNativeBackend
        backend = object.__new__(LocalNativeBackend)
        prefix = backend.LABEL
        labels = backend._labels(receipt, 'hub')
        def wire(selected):
            return ' '.join(json.dumps(x) for x in ('d'*64, '/uas-native-'+'a'*32+'-hub', selected,
                                                   False, 1, False, '2026-10-31T17:00:00.000000000Z',
                                                   'system_u:system_r:container_t:s0:c601,c602', 123)).encode()
        logs = b'File "/opt/uas/uas/local_hub.py", line 1\nModuleNotFoundError: No module named \'_sqlite3\'\nsecret-credential\n'
        logs = b'\n'.join(b'2026-10-31T17:00:01.000000000Z ' + line for line in logs.split(b'\n'))
        with patch.object(probe, 'owned_hub_avc', return_value={'state': 'fixture'}), \
             patch.object(probe, 'diagnostic_command', side_effect=[wire(labels), logs]) as command:
            result = probe.owned_hub_diagnostic(receipt, 'alpha')
        self.assertEqual(result['state'], 'owned')
        self.assertFalse(result['running']); self.assertEqual(result['exit_code'], 1)
        self.assertEqual(result['errors']['missing_modules'], ['_sqlite3'])
        self.assertIn('local_hub', result['errors']['uas_frames'])
        self.assertNotIn('secret-credential', json.dumps(result))
        self.assertEqual(command.call_args_list[1].args[0], ['logs', '--timestamps', '--tail', '80', 'd'*64])
        with patch.object(probe, 'owned_hub_avc') as avc, \
             patch.object(probe, 'diagnostic_command', return_value=wire({**labels, prefix+'.room': 'beta'})) as command:
            self.assertEqual(probe.owned_hub_diagnostic(receipt, 'alpha'), {'state': 'unavailable'})
        self.assertEqual(command.call_count, 1)
        avc.assert_not_called()
        bad_start = wire(labels).replace(b'2026-10-31T17:00:00.000000000Z', b'malformed-time')
        with patch.object(probe, 'diagnostic_command', return_value=bad_start) as command:
            result = probe.owned_hub_diagnostic(receipt, 'alpha')
        self.assertEqual(result['errors'], {'state': 'unavailable'})
        self.assertEqual(command.call_count, 1)

    def test_hub_log_filter_excludes_unknown_paths_modules_and_message_contents(self):
        self.assertEqual(probe.filtered_hub_errors(b'uas.kernel_origin.OriginDenied: private message')['exception_classes'], ['OriginDenied'])
        result = probe.filtered_hub_errors(b'PermissionError: [Errno 13] Permission denied: /secret/path\n'
            b'ModuleNotFoundError: No module named \'private_secret\'\nFile "/secret/not_ours.py", line 1\n')
        self.assertEqual(result['missing_modules'], [])
        self.assertEqual(result['uas_frames'], [])
        self.assertEqual(result['known_failures'], ['permission-denied'])
        self.assertNotIn('secret', json.dumps(result))


    def test_hub_phase_parser_requires_closed_exact_whole_lines(self):
        phases = ('import-start', 'import-done', 'entrypoint-validated', 'probe-start', 'probe-done',
                  'metadata-wait', 'metadata-read', 'config-decoded', 'forge-import', 'forge-imported',
                  'library-import', 'library-imported', 'binding-validated', 'seats-validated',
                  'metadata-parsed', 'mapping-validated', 'paths-validated',
                  'control-connect', 'control-connected')
        from uas.local_hub import PHASES
        self.assertEqual(set(phases), PHASES)
        raw = ('\n'.join('UAS_LOCAL_HUB_PHASE ' + phase for phase in phases) + '\n').encode()
        result = probe.filtered_hub_errors(raw)
        self.assertEqual(result['startup_phases'], list(phases))
        self.assertFalse(result['startup_phase_overflow'])
        for invalid in ('UAS_LOCAL_HUB_PHASE unknown', 'prefix UAS_LOCAL_HUB_PHASE import-start',
                        'UAS_LOCAL_HUB_PHASE import-start secret', ' UAS_LOCAL_HUB_PHASE import-start',
                        'UAS_LOCAL_HUB_PHASE import-start\r', 'UAS_LOCAL_HUB_PHASE import-start\x00'):
            with self.subTest(invalid=invalid):
                self.assertEqual(probe.filtered_hub_errors(invalid.encode())['startup_phases'], [])
        overflow = probe.filtered_hub_errors(raw * 10)
        self.assertEqual(len(overflow['startup_phases']), len(phases))
        self.assertTrue(overflow['startup_phase_overflow'])


    def test_phase_timestamps_are_bounded_relative_and_never_raw_log_content(self):
        start = '2026-10-31T17:00:00.123456789Z'
        raw = ('2026-10-31T17:00:00.123456789Z UAS_LOCAL_HUB_PHASE import-start\n'
               '2026-10-31T17:00:08.123456789Z UAS_LOCAL_HUB_PHASE control-connected\n'
               "2026-10-31T17:00:09.123456789Z ModuleNotFoundError: No module named '_sqlite3'\n"
               '2026-10-31T17:00:09.123456789Z secret-token\n').encode()
        result = probe.timestamped_hub_errors(raw, start)
        self.assertEqual(result['phase_timings'], [{'phase': 'import-start', 'elapsed_ms': 0},
                                                  {'phase': 'control-connected', 'elapsed_ms': 8000}])
        self.assertEqual(result['missing_modules'], ['_sqlite3'])
        self.assertNotIn('secret-token', json.dumps(result))
        self.assertIn('not-supervisor-deadline', result['timing_basis'])
        for stamp in ('2026-10-31T16:59:59.123456789Z', '2026-10-31T17:02:00.123456790Z',
                      '2026-10-31T17:00:08Z', '2026-13-31T17:00:08.123456789Z',
                      '2026-10-31T17:00:08.123456789+00:00'):
            with self.subTest(stamp=stamp):
                value = probe.timestamped_hub_errors((stamp+' UAS_LOCAL_HUB_PHASE import-start').encode(), start)
                self.assertEqual(value['phase_timings'], [])
        for suffix in ('unknown', 'import-start secret', 'import-start\r', 'import-start\x00'):
            value = probe.timestamped_hub_errors((start+' UAS_LOCAL_HUB_PHASE '+suffix).encode(), start)
            self.assertEqual(value['phase_timings'], [])
        overflow = probe.timestamped_hub_errors(raw * 20, start)
        self.assertEqual(len(overflow['phase_timings']), 19)
        self.assertTrue(overflow['phase_timing_overflow'])


    def test_avc_filter_requires_exact_owned_context_time_and_closed_fields(self):
        label = 'system_u:system_r:container_t:s0:c601,c602'
        start = '2026-10-31T17:00:00.000000000Z'
        seconds = probe.docker_time_ns(start) // 1000000000
        def row(context=label, timestamp=seconds+1, target='unconfined_t', perms='use'):
            return (f'type=AVC msg=audit({timestamp}.123:7): avc:  denied  {{ {perms} }} for pid=123 '
                    f'comm="python3" path="/private/secret" scontext={context} '
                    f'tcontext=system_u:system_r:{target}:s0 tclass=fd permissive=0\n').encode()
        result = probe.scoped_avc_rows(row(), label, start)
        self.assertEqual(result['denials'], [{'class': 'fd', 'permissions': ['use'], 'target_type': 'unconfined_t'}])
        self.assertNotIn('secret', json.dumps(result)); self.assertNotIn('123', json.dumps(result))
        for raw in (row(context=label.replace('602', '603')), row(timestamp=seconds-1), row(timestamp=seconds+121)):
            self.assertEqual(probe.scoped_avc_rows(raw, label, start)['denials'], [])
        redacted = probe.scoped_avc_rows(row(target='secret_type', perms='secret_permission'), label, start)
        self.assertEqual(redacted['denials'][0]['target_type'], 'redacted')
        self.assertEqual(redacted['denials'][0]['permissions'], [])
        overflow = probe.scoped_avc_rows(row()*20, label, start)
        self.assertEqual(len(overflow['denials']), 16); self.assertTrue(overflow['overflow'])

    def test_avc_reader_refuses_invalid_scope_before_open_and_symlink(self):
        with patch.object(probe.os, 'open') as opened:
            self.assertEqual(probe.owned_hub_avc('foreign-label', 'invalid-time'), {'state': 'unavailable'})
        opened.assert_not_called()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'audit.log'; path.symlink_to(Path(temp)/'elsewhere')
            with patch.object(probe, 'AUDIT_LOG', path):
                result = probe.owned_hub_avc('system_u:system_r:container_t:s0:c601,c602',
                                           '2026-10-31T17:00:00.000000000Z')
            self.assertEqual(result, {'state': 'unavailable'})


    def test_container_process_scope_requires_exact_init_descendants_and_fixed_roles(self):
        rows = probe.owned_hub_processes(b'PID PPID COMMAND\n123 1 tini\n124 123 python3.14\n', 123)
        self.assertEqual(rows, {123: (1, 'tini'), 124: (123, 'python3')})
        for raw in (b'PID PPID COMMAND\n124 123 python3\n',
                    b'PID PPID COMMAND\n123 1 tini\n124 999 python3\n',
                    b'PID PPID COMMAND\n123 1 tini\n124 123 secret-command\n',
                    b'PID PPID COMMAND\n123 1 tini\n124 123 python3 --secret\n'):
            with self.assertRaises(RuntimeError): probe.owned_hub_processes(raw, 123)
        with patch.object(probe, 'diagnostic_command', return_value=b'PID PPID COMMAND\n124 1 python3\n'), \
             patch.object(probe.os, 'pidfd_open') as opened:
            self.assertEqual(probe.owned_hub_fd_limits('a'*64, 123), {'state': 'unavailable'})
        opened.assert_not_called()


    def test_owned_fd_limit_diagnostic_emits_only_numeric_limits_and_roles(self):
        from unittest.mock import MagicMock
        listing = MagicMock(); listing.__enter__.return_value = iter([object(), object()])
        top = b'PID PPID COMMAND\n123 1 tini\n'
        with patch.object(probe, 'diagnostic_command', return_value=top), \
             patch.object(probe.os, 'pidfd_open', return_value=10), \
             patch.object(probe.os, 'open', return_value=11), \
             patch.object(probe.os, 'read', return_value=b'Max open files     1024    4096    files   \n'), \
             patch.object(probe.os, 'scandir', return_value=listing), \
             patch.object(probe.os, 'close'), \
             patch.object(probe.select, 'select', return_value=([], [], [])):
            result = probe.owned_hub_fd_limits('a'*64, 123)
        self.assertEqual(result, {'state': 'observed', 'processes': [
            {'role': 'tini', 'soft': 1024, 'hard': 4096, 'count': 2}]})
        self.assertNotIn('123', json.dumps(result))
