"""Fast source-only permission correlation; no native or Hub acceptance claim."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
NODE = os.environ.get('UAS_CLAUDE_NODE') or shutil.which('node')


class ClaudePermissionPolicyTests(unittest.TestCase):
    @unittest.skipUnless(NODE, 'Node required for pure permission policy tests')
    def test_source_policy(self):
        result = subprocess.run([NODE, '--test', 'tests/claude/permission/policy.test.mjs',
                                 'tests/claude/permission-state.test.mjs'],
                                cwd=ROOT, env={'PATH': '/usr/bin:/bin'}, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_gate_requires_manual_or_exact_trusted_label(self):
        workflow = (ROOT / '.github/workflows/claude-permission.yml').read_text()
        triggers = workflow.split('\non:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertEqual('  workflow_dispatch:\n  pull_request:\n    types: [labeled]', triggers.strip('\n'))
        self.assertIn("github.event_name == 'workflow_dispatch' || (github.event.label.name == 'qualify-claude-permission' && github.event.sender.login == 'puglab-reviewer' && github.event.pull_request.head.repo.full_name == github.repository)", workflow)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha || github.sha }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('permissions:\n  contents: read', workflow)
        self.assertEqual(1, workflow.count('timeout-minutes: 3'))
        self.assertNotIn('pull_request_target', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertIn('sudo unshare --net --', workflow)
        self.assertIn('env -i PATH=/usr/bin:/bin', workflow)
