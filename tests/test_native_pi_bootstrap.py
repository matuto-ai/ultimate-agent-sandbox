"""Compile-only C check. Never execute a bootstrap, socket, namespace or image."""
from pathlib import Path
import shutil
import subprocess
import unittest


class NativePiBootstrapTests(unittest.TestCase):
    def test_native_connector_compiles_without_warnings(self):
        compiler=shutil.which('cc')
        if compiler is None:self.skipTest('C compiler unavailable; bootstrap syntax unverified')
        source=Path(__file__).resolve().parents[1]/'runtime/workstation/pi-native-connector.c'
        result=subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-fsyntax-only',str(source)],
            capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
