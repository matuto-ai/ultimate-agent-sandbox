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
    def exercise(self, failed_compile=None, timeout=False, *, compile_costs=(0,0),
                 hash_costs=(0,0), mkdir_cost=0, late_compiler_return=False):
        tree = ast.parse(SOURCE.read_text())
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                     and n.name in ('expect', 'build', 'main')]
        events = []
        clock = [0.0]
        hashes = [0]
        error = subprocess.TimeoutExpired('fixed gcc', 5) if timeout else RuntimeError('compile failed')
        def run(argv, **kwargs):
            events.append(('compile', argv, kwargs))
            index=len([e for e in events if e[0] == 'compile'])
            self.assertGreater(kwargs['timeout'],0)
            self.assertLessEqual(kwargs['timeout'],10)
            if index == failed_compile: raise error
            cost=compile_costs[index-1]
            clock[0]+=cost
            if cost>kwargs['timeout'] and not late_compiler_return:
                raise subprocess.TimeoutExpired('fixed gcc',kwargs['timeout'])
        def digest(_raw):
            def finish():
                clock[0]+=hash_costs[hashes[0]]
                hashes[0]+=1
                return 'a'*64
            return SimpleNamespace(hexdigest=finish)
        def mkdir(*args,**kwargs):clock[0]+=mkdir_cost
        def emit(value): events.append(('emit', value))
        remove = Mock(); remove.avoids_symlink_attacks = True
        env = dict(ROOT=ROOT, Path=Path, sys=SimpleNamespace(argv=['diff_smoke.py','--run']),
                   os=SimpleNamespace(geteuid=lambda:0, environ={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux'}),
                   signal=SimpleNamespace(SIGALRM=signal.SIGALRM, SIG_BLOCK=signal.SIG_BLOCK,
                       pthread_sigmask=Mock(return_value=set()), signal=Mock(), alarm=Mock()),
                   time=SimpleNamespace(monotonic=lambda:clock[0]), tempfile=SimpleNamespace(mkdtemp=lambda **kw:'/tmp/inert-diff'),
                   identity=Mock(return_value='same-owned-root'), stage_sources=Mock(return_value=(Path('/inert-payload'), {})),
                   compile_fixed=lambda argv,timeout:run(argv,check=True,timeout=timeout),
                   hashlib=SimpleNamespace(sha256=digest), emit=emit, CASES=(),
                   DEADLINE_SECONDS=30, BUILD_SECONDS=10, shutil=SimpleNamespace(rmtree=remove))
        exec(compile(ast.Module(body=functions,type_ignores=[]), '<fixed diff owner>', 'exec'), env)
        with patch.dict(sys.modules, {'mapped_namespace':SimpleNamespace(mapped_popen=Mock())}), \
             patch.object(Path, 'mkdir', side_effect=mkdir), patch.object(Path, 'chmod'), patch.object(Path, 'read_bytes', return_value=b'inert binary'):
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
            self.assertEqual({'check':True,'timeout':10},event[2])
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


    def test_first_build_can_use_spare_second_allowance_without_growing_aggregate(self):
        events,caught,_,env,remove=self.exercise(compile_costs=(6,2),hash_costs=(.25,.25))
        self.assertIsNone(caught)
        calls=[e for e in events if e[0]=='compile']
        self.assertEqual([10,3.75],[e[2]['timeout'] for e in calls])
        self.assertTrue(any(e[0]=='emit' and e[1]['stage']=='build-ready' for e in events))
        self.assertEqual(8.5,env['time'].monotonic())
        remove.assert_called_once()

    def test_shared_budget_expires_before_next_compile_or_ready_and_quarantines(self):
        cases=(
            dict(mkdir_cost=10),
            dict(compile_costs=(10,0)),
            dict(compile_costs=(10.1,0),late_compiler_return=True),
            dict(compile_costs=(6,4)),
            dict(compile_costs=(6,4.1),late_compiler_return=True),
            dict(compile_costs=(6,1),hash_costs=(3,0)),
            dict(compile_costs=(6,1),hash_costs=(0,3)),
            dict(compile_costs=(6,1),hash_costs=(0,3.1)),
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                events,caught,_,env,remove=self.exercise(**kwargs)
                self.assertIsInstance(caught,TimeoutError)
                emitted=[e[1] for e in events if e[0]=='emit']
                self.assertFalse(any(e['stage']=='build-ready' for e in emitted))
                self.assertEqual({'stage':'quarantine','path':'/tmp/inert-diff','cleanup_claimed':False},emitted[-1])
                remove.assert_not_called();env['signal'].alarm.assert_called_with(0)

    def test_shared_budget_is_fixed_and_all_rechecks_precede_ready(self):
        tree=ast.parse(SOURCE.read_text())
        constants={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body
                   if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)
                   and n.targets[0].id in ('BUILD_SECONDS','DEADLINE_SECONDS')}
        self.assertEqual({'BUILD_SECONDS':10,'DEADLINE_SECONDS':30},constants)
        build=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='build')
        source=ast.unparse(build)
        self.assertEqual(1,source.count('deadline ='))
        self.assertLess(source.index('deadline ='),source.index('installed.mkdir'))
        self.assertIn('remaining())',source)
        loop=next(n for n in build.body if isinstance(n,ast.For))
        self.assertEqual('remaining()',ast.unparse(loop.body[-1]))
        self.assertIn('compile_fixed(',ast.unparse(loop.body[1]))
        self.assertEqual('remaining()',ast.unparse(loop.body[2]))
        self.assertEqual('remaining()',ast.unparse(build.body[-2]))
        self.assertIsInstance(build.body[-1],ast.Return)


if __name__=='__main__':unittest.main()
