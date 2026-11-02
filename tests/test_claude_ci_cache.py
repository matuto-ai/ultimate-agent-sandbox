"""Public acquisition-cache policy and fixture worker checks; no npm or native runtime."""
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class ClaudeCICacheTests(unittest.TestCase):
    def test_only_content_addressed_public_cache_paths_and_exact_action(self):
        workflow=(ROOT/'.github/workflows/claude-native.yml').read_text()
        self.assertEqual(re.findall(r'uses: actions/cache/(restore|save)@([a-f0-9]+)',workflow),
            [('restore','0057852bfaa89a56745cba8c7296529d2fc39830'),('save','0057852bfaa89a56745cba8c7296529d2fc39830')])
        paths=re.findall(r'          path: \|\n((?:            [^\n]+\n)+)',workflow)
        self.assertEqual(paths,['            tests/claude/.npm-cache/_cacache\n            tests/claude/sdk/.npm-cache/_cacache\n']*2)
        self.assertNotIn('restore-keys:',workflow)
        self.assertIn("runner.os }}-${{ runner.arch }}-node24.22.1-${{ hashFiles('tests/claude/package-lock.json', 'tests/claude/sdk/package-lock.json')",workflow)
        self.assertIn("key: ${{ steps.claude-npm-cache.outputs.cache-primary-key }}",workflow)
    def test_verification_always_runs_before_save_and_all_tests_after_save(self):
        workflow=(ROOT/'.github/workflows/claude-native.yml').read_text()
        cli=workflow.index('run: sh tests/claude/install-dependencies.sh')
        sdk=workflow.index('run: sh tests/claude/sdk/install-dependencies.sh')
        parser=workflow.index('run: sh tests/claude/library/install-dependencies.sh')
        save=workflow.index('uses: actions/cache/save@')
        tests=workflow.index('sh "$2/tests/claude/run-tests.sh"')
        self.assertTrue(cli<sdk<parser<save<tests)
        self.assertEqual(workflow.count('        if:'),1)
        self.assertIn("if: ${{ steps.claude-npm-cache.outputs.cache-hit != 'true' }}",workflow)
        self.assertNotIn('continue-on-error',workflow)
    def test_both_installs_keep_scrubbed_configuration_lock_checks_and_integrity_path(self):
        for name in ('tests/claude/install-dependencies.sh','tests/claude/sdk/install-dependencies.sh','tests/claude/library/install-dependencies.sh'):
            script=(ROOT/name).read_text()
            self.assertIn('check-lock.mjs',script);self.assertIn('exec env -i',script)
            self.assertIn('"$npm_path" ci ',script);self.assertIn('--ignore-scripts',script)
            self.assertIn('--prefer-offline --fetch-retries=0 --fetch-timeout=20000',script)
            self.assertIn('NPM_CONFIG_CACHE="$PWD/.npm-cache"',script)
            self.assertIn('NPM_CONFIG_USERCONFIG="$PWD/.home/empty-user.npmrc"',script)
            self.assertIn('NPM_CONFIG_GLOBALCONFIG="$PWD/.home/empty-global.npmrc"',script)
            self.assertLess(script.index('check-lock.mjs'),script.index('"$npm_path" ci '))


class ClaudeCIRunnerTests(unittest.TestCase):
    def run_fixture(self, *, fail=None, partition=None, args=None, missing=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'tests/claude').mkdir(parents=True)
            (root/'tests/pi').mkdir()
            script = root/'tests/claude/run-tests.sh'
            script.write_text((ROOT/'tests/claude/run-tests.sh').read_text())
            (root/'tests/pi/library-scan-contract.mjs').write_text(
                "from pathlib import Path\nPath('events').write_text('scan\\n')\n")
            (root/'tests/claude/probe.py').write_text(
                "with open('events', 'a') as output: output.write('probe\\n')\n")
            names = ('first', 'sdk_receiver', 'participant', 'sdk', 'readiness',
                     'runtime', 'library_read', 'library', 'future')
            for name in names:
                if name == missing: continue
                (root/f'tests/test_claude_{name}.py').write_text(
                    'import time, unittest\n'
                    'class Fixture(unittest.TestCase):\n'
                    ' def test_payload(self):\n'
                    f"  with open('events', 'a') as output: output.write('start:{name}\\n')\n"
                    '  time.sleep(.15)\n'
                    f"  with open('events', 'a') as output: output.write('end:{name}\\n')\n"
                    f'  self.assertFalse({name == fail!r})\n')
            arguments = args if args is not None else ([] if partition is None else ['--partition', str(partition)])
            result = subprocess.run(['sh', str(script), *arguments], cwd=root,
                env={**os.environ, 'UAS_CLAUDE_INSTALL':'fixture',
                     'UAS_CLAUDE_SDK_INSTALL':'fixture', 'UAS_CLAUDE_NODE':sys.executable},
                capture_output=True, text=True, timeout=10)
            events = (root/'events').read_text().splitlines() if (root/'events').exists() else []
        if args is not None or missing is not None:
            self.assertNotEqual(0, result.returncode)
            self.assertEqual([], events)
            return result
        if partition is not None:
            names = tuple(name for name in names if (name == 'sdk_receiver') == (partition == 0))
        self.assertEqual(['scan', 'probe'], events[:2])
        self.assertCountEqual([f'{phase}:{name}' for phase in ('start', 'end')
                              for name in names], events[2:])
        active = peak = 0
        for event in events[2:]:
            active += 1 if event.startswith('start:') else -1
            self.assertTrue(0 <= active <= 2)
            peak = max(peak, active)
        self.assertEqual(0, active)
        self.assertEqual(min(2, len(names)), peak)
        starts = [event for event in events[2:] if event.startswith('start:')]
        first = ['sdk_receiver', 'participant'] if partition is None else ['sdk_receiver'] if partition == 0 else ['participant', 'sdk']
        self.assertCountEqual(['start:' + name for name in first], starts[:len(first)])
        # Every discovered module ran exactly once, including future/unranked ones.
        self.assertEqual(len(names), len(starts))
        return result

    def test_all_modules_execute_with_two_workers_after_serial_contracts(self):
        result = self.run_fixture()
        self.assertEqual(0, result.returncode, result.stderr)

    def test_a_worker_failure_cannot_be_hidden_by_other_successes(self):
        result = self.run_fixture(fail="first")
        self.assertNotEqual(0, result.returncode)
        self.assertIn('FAILED', result.stderr)

    def test_a_prioritized_worker_failure_keeps_complete_discovery_binding(self):
        result = self.run_fixture(fail='sdk_receiver')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('FAILED', result.stderr)

    def test_runner_partitions_cover_disjoint_full_inventory_including_future_modules(self):
        for partition in (0, 1):
            result = self.run_fixture(partition=partition)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_each_partition_propagates_its_worker_failure(self):
        for partition, failed in ((0, 'sdk_receiver'), (1, 'future')):
            result = self.run_fixture(partition=partition, fail=failed)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('FAILED', result.stderr)

    def test_invalid_partition_arguments_fail_before_probes(self):
        for args in (['--partition'], ['--partition', '2'], ['--partition', '-1'],
                     ['--partition', 'all'], ['--other', '0'], ['--partition', '0', 'extra']):
            self.run_fixture(args=args)

    def test_missing_required_inventory_fails_before_probes(self):
        for missing in ('sdk_receiver', 'participant'):
            for partition in (None, 0, 1):
                self.run_fixture(partition=partition, missing=missing)

    def test_ci_runs_both_partitions_and_binds_both_to_runtime_guard(self):
        workflow = (ROOT/'.github/workflows/claude-native.yml').read_text()
        self.assertIn('name: official-claude-fixture-${{ matrix.partition }}', workflow)
        self.assertIn('fail-fast: false', workflow)
        self.assertIn('partition: [0, 1]', workflow)
        self.assertIn('needs: [official-claude-fixture]', workflow)
        self.assertIn('run-tests.sh" --partition "$5"', workflow)
        self.assertIn('"$RUNNER_TEMP/uas-python" "${{ matrix.partition }}"', workflow)
