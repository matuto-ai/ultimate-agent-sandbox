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
                                                   False, 1, False)).encode()
        logs = b'File "/opt/uas/uas/local_hub.py", line 1\nModuleNotFoundError: No module named \'_sqlite3\'\nsecret-credential\n'
        with patch.object(probe, 'diagnostic_command', side_effect=[wire(labels), logs]) as command:
            result = probe.owned_hub_diagnostic(receipt, 'alpha')
        self.assertEqual(result['state'], 'owned')
        self.assertFalse(result['running']); self.assertEqual(result['exit_code'], 1)
        self.assertEqual(result['errors']['missing_modules'], ['_sqlite3'])
        self.assertIn('local_hub', result['errors']['uas_frames'])
        self.assertNotIn('secret-credential', json.dumps(result))
        self.assertEqual(command.call_args_list[1].args[0], ['logs', '--tail', '80', 'd'*64])
        with patch.object(probe, 'diagnostic_command', return_value=wire({**labels, prefix+'.room': 'beta'})) as command:
            self.assertEqual(probe.owned_hub_diagnostic(receipt, 'alpha'), {'state': 'unavailable'})
        self.assertEqual(command.call_count, 1)

    def test_hub_log_filter_excludes_unknown_paths_modules_and_message_contents(self):
        result = probe.filtered_hub_errors(b'PermissionError: [Errno 13] Permission denied: /secret/path\n'
            b'ModuleNotFoundError: No module named \'private_secret\'\nFile "/secret/not_ours.py", line 1\n')
        self.assertEqual(result['missing_modules'], [])
        self.assertEqual(result['uas_frames'], [])
        self.assertEqual(result['known_failures'], ['permission-denied'])
        self.assertNotIn('secret', json.dumps(result))
