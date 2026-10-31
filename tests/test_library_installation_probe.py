"""Safety/source contracts only: does not run a prepared native installation."""
import importlib.util
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
