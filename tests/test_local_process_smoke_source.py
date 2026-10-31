"""Guardable source contracts for hosted-only real process smoke (not execution)."""
import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/'tests/linux/local_process_smoke.py'
spec=importlib.util.spec_from_file_location('local_process_smoke_source',FILE)
smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)


class LocalProcessSmokeSourceTests(unittest.TestCase):
    def test_import_and_nonhosted_main_do_not_start_anything(self):
        with patch.dict(os.environ,{},clear=True),patch.object(smoke.subprocess,'Popen') as spawn,patch.object(smoke.tempfile,'TemporaryDirectory') as temporary:
            with self.assertRaisesRegex(AssertionError,'explicit hosted'):smoke.main(['--run'])
        spawn.assert_not_called();temporary.assert_not_called()

    def test_direct_script_fixture_import_has_no_ambient_pythonpath(self):
        code = ('import runpy; ns=runpy.run_path(' + repr(str(FILE)) + '); '
                'support=ns["fixture_support"](); assert support.document()["version"] == 1')
        result=subprocess.run([sys.executable,'-I','-c',code],cwd='/tmp',
                              capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_all_explicit_hosted_gates_required(self):
        env={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','UAS_LOCAL_PROCESS_SMOKE':'1'}
        with patch.dict(os.environ,env,clear=True),patch.object(smoke.sys,'platform','linux'):
            smoke.hosted_gate(True)
            with self.assertRaises(AssertionError):smoke.hosted_gate(False)
            for name in env:
                with patch.dict(os.environ,{name:''}):
                    with self.assertRaises(AssertionError):smoke.hosted_gate(True)

    def test_actual_cli_argv_and_environment_are_fixed(self):
        owner=smoke.Smoke(Path('/tmp/owned-smoke'));child=Mock()
        with patch.object(smoke.subprocess,'Popen',return_value=child) as spawn:
            self.assertIs(owner.spawn('inspect'),child)
        args,kwargs=spawn.call_args
        self.assertEqual(args[0],[smoke.sys.executable,'-m','uas','local','--root','/tmp/owned-smoke/install','inspect'])
        self.assertEqual(kwargs['cwd'],ROOT)
        self.assertEqual(set(kwargs['env']),{'PATH','PYTHONPATH','PYTHONDONTWRITEBYTECODE'})
        self.assertEqual(kwargs['env']['PYTHONPATH'],str(ROOT))
        self.assertEqual(owner.children,[child])

    def test_cleanup_only_uses_owned_handles_and_finite_waits(self):
        owner=smoke.Smoke(Path('/tmp/owned-smoke'));child=Mock();child.poll.return_value=None
        child.wait.side_effect=[subprocess.TimeoutExpired('owned',.5),0]
        owner.children=[child];owner.cleanup()
        child.terminate.assert_called_once();child.kill.assert_called_once()
        self.assertEqual([call.kwargs for call in child.wait.call_args_list],[{'timeout':.5},{'timeout':.5}])
        self.assertLessEqual(smoke.WORK_SECONDS+2,15)

    def test_work_deadline_cannot_extend_per_call(self):
        with patch.object(smoke.time,'monotonic',side_effect=[10,11,23]):
            owner=smoke.Smoke(Path('/tmp/owned-smoke'))
            self.assertEqual(owner.left(20),11)
            with self.assertRaisesRegex(AssertionError,'deadline'):owner.left()

    def test_workflow_keeps_bounded_process_smoke_in_root_lane(self):
        text=(ROOT/'.github/workflows/validate.yml').read_text()
        lane=text.split('  validate:\n',1)[1].split('\n  unit-slow:',1)[0]
        self.assertIn('15s python3 tests/linux/local_process_smoke.py --run',lane)
        self.assertIn('UAS_LOCAL_PROCESS_SMOKE: "1"',lane)
        self.assertNotIn('sudo',lane)
        self.assertNotIn('needs:',lane)
        source=FILE.read_text();tree=ast.parse(source)
        self.assertIn("'native':None,'manager':None",source)
        self.assertIn("'native_room_run_manager':'not-exercised'",source)
        self.assertIn("'native_uncertain_effect_recovery':'not-exercised'",source)
        self.assertTrue(any(isinstance(node,ast.If) and '__name__' in ast.unparse(node.test) for node in tree.body))
