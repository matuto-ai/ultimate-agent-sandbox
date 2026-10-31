"""Cheap subprocess contracts for job-private compile cache, not native substitutes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PiCompileCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / 'cache'
        self.module = self.root / 'compile-cache.mjs'
        shutil.copyfile(ROOT / 'tests/pi/compile-cache.mjs', self.module)

    def invoke(self, extra='', env=None):
        script = (f'import {{enableJobCompileCache}} from {json.dumps(self.module.as_uri())}; '
                  f'console.log(enableJobCompileCache({json.dumps(str(self.cache))})); ' + extra)
        clean = {'PATH': os.environ['PATH'], 'HOME': str(self.root)}
        clean.update(env or {})
        return subprocess.run(['node', '--input-type=module', '-e', script], env=clean,
                              capture_output=True, text=True, timeout=10)

    def test_absent_directory_does_not_enable_or_create_cache(self):
        result = self.invoke()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('false', result.stdout.strip())
        self.assertFalse(self.cache.exists())

    def test_private_cache_reexecutes_code_and_invalidates_changed_source(self):
        self.cache.mkdir(mode=0o700)
        source = self.root / 'source.mjs'
        for value in ('first', 'first', 'changed'):
            source.write_text('console.log(' + json.dumps(value) + ')')
            result = self.invoke('await import(' + json.dumps(source.as_uri()) + ');')
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(['true', value], result.stdout.splitlines())
        self.assertTrue(any(self.cache.rglob('*')))

    def test_symlink_file_and_permissive_directory_are_rejected(self):
        target = self.root / 'target'
        target.mkdir(mode=0o700)
        self.cache.symlink_to(target, target_is_directory=True)
        self.assertNotEqual(0, self.invoke().returncode)
        self.cache.unlink()
        self.cache.write_text('not a directory')
        self.assertNotEqual(0, self.invoke().returncode)
        self.cache.unlink()
        self.cache.mkdir(mode=0o755)
        self.assertNotEqual(0, self.invoke().returncode)
        self.assertEqual([], list(target.iterdir()))

    def test_coverage_and_explicit_disable_bypass_cache(self):
        self.cache.mkdir(mode=0o700)
        for env in ({'NODE_V8_COVERAGE': str(self.root / 'coverage')}, {'NODE_DISABLE_COMPILE_CACHE': '1'}):
            result = self.invoke(env=env)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual('false', result.stdout.strip())
        self.assertEqual([], list(self.cache.iterdir()))

    def test_cached_guard_still_denies_network(self):
        shutil.copyfile(ROOT / 'tests/pi/network-guard.mjs', self.root / 'network-guard.mjs')
        (self.root / '.compile-cache').mkdir(mode=0o700)
        for _ in range(2):
            result = subprocess.run(['node', '--import=' + str(self.root / 'network-guard.mjs'),
                                     '-e', 'fetch("https://example.invalid")'],
                                    env={'PATH': os.environ['PATH'], 'HOME': str(self.root)},
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Network is forbidden', result.stderr)

    def test_shell_cleans_cache_on_failure_and_carries_coverage_optout(self):
        shell = self.root / 'tests/pi/run-tests.sh'
        shell.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / 'tests/pi/run-tests.sh', shell)
        fake_bin = self.root / 'bin'
        fake_bin.mkdir()
        fake = fake_bin / 'node'
        fake.write_text('#!/bin/sh\nif [ -d tests/pi/.compile-cache ]; then echo cached; else echo uncached; fi\nexit 23\n')
        fake.chmod(0o700)
        for extra, expected in (({}, 'cached'), ({'NODE_V8_COVERAGE': 'coverage'}, 'uncached'),
                                ({'NODE_DISABLE_COMPILE_CACHE': '1'}, 'uncached')):
            env = {'PATH': str(fake_bin) + ':' + os.environ['PATH'], **extra}
            result = subprocess.run(['sh', str(shell)], env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(23, result.returncode, result.stderr)
            self.assertEqual(expected, result.stdout.strip())
            self.assertFalse((shell.parent / '.compile-cache').exists())

    def test_shell_refuses_preexisting_cache_before_contracts(self):
        shell = self.root / 'tests/pi/run-tests.sh'
        shell.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / 'tests/pi/run-tests.sh', shell)
        cache = shell.parent / '.compile-cache'
        cache.mkdir(mode=0o700)
        marker = cache / 'untouched'
        marker.write_text('preserve')
        result = subprocess.run(['sh', str(shell)], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual('preserve', marker.read_text())


if __name__ == '__main__':
    unittest.main()
