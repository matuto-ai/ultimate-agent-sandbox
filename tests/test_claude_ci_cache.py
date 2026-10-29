"""Pure fixed public acquisition-cache policy, no npm/actions execution."""
from pathlib import Path
import re
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
        save=workflow.index('uses: actions/cache/save@')
        tests=workflow.index('sh "$2/tests/claude/run-tests.sh"')
        self.assertTrue(cli<sdk<save<tests)
        self.assertEqual(workflow.count('        if:'),1)
        self.assertIn("if: ${{ steps.claude-npm-cache.outputs.cache-hit != 'true' }}",workflow)
        self.assertIn('timeout-minutes: 2',workflow)
        self.assertNotIn('continue-on-error',workflow)
    def test_both_installs_keep_scrubbed_configuration_lock_checks_and_integrity_path(self):
        for name in ('tests/claude/install-dependencies.sh','tests/claude/sdk/install-dependencies.sh'):
            script=(ROOT/name).read_text()
            self.assertIn('check-lock.mjs',script);self.assertIn('exec env -i',script)
            self.assertIn('"$npm_path" ci ',script);self.assertIn('--ignore-scripts',script)
            self.assertIn('--prefer-offline --fetch-retries=0 --fetch-timeout=20000',script)
            self.assertIn('NPM_CONFIG_CACHE="$PWD/.npm-cache"',script)
            self.assertIn('NPM_CONFIG_USERCONFIG="$PWD/.home/empty-user.npmrc"',script)
            self.assertIn('NPM_CONFIG_GLOBALCONFIG="$PWD/.home/empty-global.npmrc"',script)
            self.assertLess(script.index('check-lock.mjs'),script.index('"$npm_path" ci '))
