"""Hosted cheap compile/pure-JS checks; never launch Claude or a bootstrap."""
from pathlib import Path
import shutil
import subprocess
import unittest

class NativeClaudeSourceChecks(unittest.TestCase):
    def test_fixed_bootstraps_and_pure_policy(self):
        self.assertIsNotNone(shutil.which('cc'),'hosted C compiler is required')
        self.assertIsNotNone(shutil.which('node'),'hosted Node runtime is required')
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run(['sh',str(root/'tests/claude/native/check.sh')],
            cwd=root,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
