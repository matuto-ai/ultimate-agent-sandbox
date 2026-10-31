"""Cheap isolation/failure proof for the test-only official Pi version probe."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_pi_runtime as fixture


class PiVersionFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.install = Path(self.temp.name)
        self.package = self.install / 'node_modules/@earendil-works/pi-coding-agent'
        self.package.mkdir(parents=True)
        (self.package / 'package.json').write_text(json.dumps({'version': '1.4.0'}))
        self.patch = patch.object(fixture, 'INSTALL', str(self.install))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.addCleanup(setattr, fixture.PiNativeTests, 'runtime_version', None)

    def test_probe_is_real_cli_clean_environment_and_scoped_temporary_home(self):
        seen = []
        def probe(argv, **kwargs):
            env = kwargs['env']; home = Path(env['HOME']); seen.append(home)
            self.assertTrue(home.is_dir())
            self.assertEqual(str(home / 'agent'), env['PI_CODING_AGENT_DIR'])
            self.assertNotIn('SECRET_SENTINEL', env)
            self.assertEqual('1', env['PI_OFFLINE'])
            self.assertTrue(env['NODE_OPTIONS'].endswith('/tests/pi/network-guard.mjs'))
            self.assertEqual([str(self.package / 'dist/cli.js'), '--version'], argv[1:])
            self.assertTrue(kwargs['check']); self.assertEqual(10, kwargs['timeout'])
            return Mock(stdout='1.4.0\n')
        with patch.dict(os.environ, {'SECRET_SENTINEL': 'never inherited'}), \
             patch.object(fixture.subprocess, 'run', side_effect=probe) as run:
            fixture.PiNativeTests.setUpClass()
            self.assertEqual('1.4.0', fixture.PiNativeTests.runtime_version)
            self.assertEqual(1, run.call_count)
            fixture.PiNativeTests.setUpClass()
            self.assertEqual(2, run.call_count)  # Not a process-global cached pass.
        self.assertEqual(2, len(set(seen)))
        self.assertTrue(all(not home.exists() for home in seen))

    def test_wrong_version_timeout_and_failure_clear_previous_proof(self):
        for outcome in (Mock(stdout='9.9.9\n'), subprocess.TimeoutExpired('node', 10),
                        subprocess.CalledProcessError(1, 'node'), OSError('launch failed')):
            fixture.PiNativeTests.runtime_version = '1.4.0'
            with self.subTest(outcome=type(outcome).__name__), \
                 patch.object(fixture.subprocess, 'run') as run:
                if isinstance(outcome, Exception): run.side_effect = outcome
                else: run.return_value = outcome
                with self.assertRaises((AssertionError, subprocess.SubprocessError, OSError)):
                    fixture.PiNativeTests.setUpClass()
                self.assertIsNone(fixture.PiNativeTests.runtime_version)

    def test_wrong_package_version_fails_before_cli(self):
        (self.package / 'package.json').write_text(json.dumps({'version': '9.9.9'}))
        with patch.object(fixture.subprocess, 'run') as run, self.assertRaises(AssertionError):
            fixture.PiNativeTests.setUpClass()
        run.assert_not_called()
        self.assertIsNone(fixture.PiNativeTests.runtime_version)
