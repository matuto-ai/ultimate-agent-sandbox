"""Finite AST/file/mock scheduling contracts; never run a shell or compiler."""
import ast
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tests/linux/diff_smoke.py'
WORKFLOW = ROOT / '.github/workflows/validate.yml'


class DiffBuildBarrierTests(unittest.TestCase):
    def exercise(self, failed_compile=None, timeout=False):
        tree = ast.parse(SOURCE.read_text())
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                     and n.name in ('expect', 'build', 'main')]
        events = []
        error = subprocess.TimeoutExpired('fixed gcc', 5) if timeout else RuntimeError('compile failed')
        def run(argv, **kwargs):
            events.append(('compile', argv, kwargs))
            if len([e for e in events if e[0] == 'compile']) == failed_compile: raise error
        def emit(value): events.append(('emit', value))
        remove = Mock(); remove.avoids_symlink_attacks = True
        env = dict(ROOT=ROOT, Path=Path, sys=SimpleNamespace(argv=['diff_smoke.py','--run']),
                   os=SimpleNamespace(geteuid=lambda:0, environ={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux'}),
                   signal=SimpleNamespace(SIGALRM=signal.SIGALRM, SIG_BLOCK=signal.SIG_BLOCK,
                       pthread_sigmask=Mock(return_value=set()), signal=Mock(), alarm=Mock()),
                   time=SimpleNamespace(monotonic=lambda:0), tempfile=SimpleNamespace(mkdtemp=lambda **kw:'/tmp/inert-diff'),
                   identity=Mock(return_value='same-owned-root'), stage_sources=Mock(return_value=(Path('/inert-payload'), {})),
                   subprocess=SimpleNamespace(run=run), hashlib=hashlib, emit=emit, CASES=(),
                   DEADLINE_SECONDS=30, shutil=SimpleNamespace(rmtree=remove))
        exec(compile(ast.Module(body=functions,type_ignores=[]), '<fixed diff owner>', 'exec'), env)
        with patch.dict(sys.modules, {'mapped_namespace':SimpleNamespace(mapped_popen=Mock())}), \
             patch.object(Path, 'mkdir'), patch.object(Path, 'chmod'), patch.object(Path, 'read_bytes', return_value=b'inert binary'):
            caught=None
            try: env['main']()
            except BaseException as failure: caught=failure
        return events, caught, error, env, remove

    def test_marker_only_after_both_fixed_builds_and_before_cases(self):
        events, caught, _, env, remove = self.exercise()
        self.assertIsNone(caught)
        self.assertEqual(['emit','compile','compile','emit','emit'],[e[0] for e in events])
        self.assertEqual({'stage':'build-ready'},events[3][1])
        for event, name in zip(events[1:3], ('diff_bootstrap','diff_evaluator')):
            self.assertEqual({'check':True,'timeout':5},event[2])
            self.assertIn('/inert-payload/runtime/workstation/'+name+'.c',event[1])
            self.assertEqual('/usr/bin/gcc',event[1][0]);self.assertIn('-static',event[1])
        self.assertEqual([((30,),{}),((0,),{})],[(c.args,c.kwargs) for c in env['signal'].alarm.call_args_list])
        remove.assert_called_once_with(Path('/tmp/inert-diff'))
        source=SOURCE.read_text()
        self.assertLess(source.index("emit({'stage':'build-ready'})"),source.index('for index,case in enumerate(CASES)'))
        self.assertIn('print(json.dumps(value,sort_keys=True),flush=True)',source)
        self.assertEqual('{"stage": "build-ready"}',json.dumps({'stage':'build-ready'},sort_keys=True))

    def test_either_build_failure_or_timeout_never_signals_or_claims_cleanup(self):
        for index in (1,2):
            for timeout in (False,True):
                with self.subTest(index=index,timeout=timeout):
                    events,caught,error,env,remove=self.exercise(index,timeout)
                    self.assertIs(error,caught)
                    self.assertEqual(index,len([e for e in events if e[0]=='compile']))
                    emitted=[e[1] for e in events if e[0]=='emit']
                    self.assertFalse(any(e['stage']=='build-ready' for e in emitted))
                    self.assertEqual({'stage':'quarantine','path':'/tmp/inert-diff','cleanup_claimed':False},emitted[-1])
                    remove.assert_not_called();env['signal'].alarm.assert_called_with(0)

    def test_workflow_barrier_failure_paths_have_no_siblings_and_wait_owner(self):
        job=WORKFLOW.read_text().split('  gate-linux-smoke:\n',1)[1].split('  gate-command-native:',1)[0]
        self.assertIn('timeout-minutes: 1',job)
        self.assertIn('needs: [validate, unit-slow]',job)
        self.assertIn('log=$(mktemp) || exit 1',job)
        self.assertIn('deadline=$((SECONDS + 15))',job)
        self.assertIn('while (( SECONDS < deadline )); do',job)
        self.assertIn("if grep -Fxq '{\"stage\": \"build-ready\"}' \"$log\"; then ready=true; break; fi",job)
        self.assertLess(job.index('grep -Fxq'),job.index('kill -0'))
        self.assertIn('kill -0 "$diff" 2>/dev/null || break',job)
        self.assertIn('sleep .05',job)
        self.assertIn('ready=false',job)
        gate=job.split('          if "$ready"; then\n',1)[1].split('          fi\n',1)[0]
        success,failure=gate.split('          else\n')
        self.assertIn('gate_forge_smoke.py & broker=$!\n            children+=("$broker")',success)
        self.assertIn('review_forge_smoke.py & review=$!\n            children+=("$review")',success)
        self.assertIn('status=1',failure);self.assertNotIn('timeout ',failure)
        self.assertEqual(3,job.count('timeout --signal=TERM --kill-after=2s'))
        self.assertIn('40s sudo',job);self.assertIn('15s sudo',success);self.assertIn('30s sudo',success)
        self.assertIn('children=("$diff")',job)
        self.assertIn('for child in "${children[@]}"; do\n            wait "$child" || status=1\n          done',job)
        # No early success/exit at readiness: marker+later owner failure still fails,
        # every launched sibling is waited even after another nonzero status.
        tail=job.split('          fi\n',1)[1]
        self.assertLess(tail.index('wait "$child"'),tail.index('exit "$status"'))
        self.assertIn('cat "$log" || status=1',tail)
        self.assertIn('rm -f "$log" || status=1\n          trap - EXIT\n          exit "$status"',tail)
        self.assertIn('>"$log" 2>&1 & diff=$!',job)
        self.assertIn("trap 'rm -f \"$log\"' EXIT",job)
        self.assertNotIn('| tee',job);self.assertNotIn('kill -9',job)
        self.assertNotIn('wait -n',job)


if __name__=='__main__':unittest.main()
