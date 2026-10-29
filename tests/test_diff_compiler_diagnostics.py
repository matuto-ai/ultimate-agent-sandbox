"""Compiler-owner contracts using AST and inert mocks only; no native execution."""
import ast
from pathlib import Path
import signal
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

SOURCE=Path(__file__).parent/'linux/diff_smoke.py'


class CompilerDiagnosticsTests(unittest.TestCase):
    def exercise(self, *, blocks=(b' cc1 stage\n',b''), exited=True, code=0,
                 fault=None, lost=False, wait_fault=None, timeout=1, sigchld=signal.SIG_DFL,
                 close_fault=None,kill_fault=None,lost_final=False,late=False):
        events=[];emitted=[];clock=[0.];blocks=list(blocks)
        stream=Mock();stream.fileno.return_value=91
        stream.close.side_effect=close_fault
        process=SimpleNamespace(pid=431,stdout=stream,returncode=None)
        def wait(**kwargs):
            events.append(('wait',kwargs))
            if wait_fault:raise wait_fault
            process.returncode=code
            return code
        process.wait=wait
        def popen(argv,**kwargs):
            events.append(('spawn',argv,kwargs))
            if fault=='spawn':raise OSError('spawn failure')
            return process
        def observe(*args):
            events.append(('observe',args))
            if lost or (lost_final and len([e for e in events if e[0]=='observe'])==3):
                raise ChildProcessError('external reap')
            return SimpleNamespace(si_status=code) if exited else None
        def ready(*args):
            clock[0]+=.01 if not late else timeout
            if fault=='select':raise OSError('select failure')
            return ([stream],[],[])
        def read(*args):
            if fault=='read':raise OSError('read failure')
            return blocks.pop(0) if blocks else b''
        def block(*args):
            if fault=='setup':raise OSError('setup failure')
        def kill(*args):
            events.append(('kill',args))
            if kill_fault:raise kill_fault
        def sleep(seconds):clock[0]+=seconds
        env=dict(Path=Path,signal=SimpleNamespace(SIGCHLD=signal.SIGCHLD,SIG_DFL=signal.SIG_DFL,
                    SIGKILL=signal.SIGKILL,getsignal=lambda _:sigchld),
                 threading=SimpleNamespace(active_count=lambda:1),
                 time=SimpleNamespace(monotonic=lambda:clock[0],sleep=sleep),
                 os=SimpleNamespace(P_PID=1,WEXITED=4,WNOHANG=1,WNOWAIT=16777216,
                    waitid=observe,set_blocking=block,read=read,killpg=kill),
                 select=SimpleNamespace(select=ready),
                 subprocess=SimpleNamespace(Popen=popen,DEVNULL=-3,PIPE=-1,STDOUT=-2,
                    TimeoutExpired=subprocess.TimeoutExpired,CalledProcessError=subprocess.CalledProcessError),
                 emit=lambda value:emitted.append(value))
        tree=ast.parse(SOURCE.read_text())
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('expect','compile_fixed')]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<inert compiler owner>','exec'),env)
        caught=None
        try:env['compile_fixed'](['/usr/bin/gcc','-v','/owned/diff_bootstrap.c','-o','/owned/output'],timeout)
        except BaseException as error:caught=error
        return events,emitted,caught,stream

    def test_success_holds_leader_until_group_signal_then_single_reap(self):
        events,reports,error,stream=self.exercise()
        self.assertIsNone(error)
        self.assertEqual(['kill','wait'],[e[0] for e in events if e[0] in ('kill','wait')])
        self.assertEqual(('wait',{'timeout':2}),events[-1])
        self.assertEqual('observe',events[-3][0])
        self.assertTrue(events[0][2]['start_new_session'])
        self.assertEqual(-2,events[0][2]['stderr'])
        self.assertEqual(-3,events[0][2]['stdin'])
        self.assertEqual(0,reports[-1]['returncode'])
        self.assertTrue(reports[-1]['group_disposed']);stream.close.assert_called_once()

    def test_timeout_with_live_leader_and_eof_disposes_descendant_group(self):
        events,reports,error,_=self.exercise(blocks=(b'',),exited=False,timeout=.025)
        self.assertIsInstance(error,subprocess.TimeoutExpired)
        self.assertEqual(['kill','wait'],[e[0] for e in events if e[0] in ('kill','wait')])
        self.assertEqual('TimeoutExpired',reports[-1]['error'])

    def test_exit_with_descendant_pipe_open_still_times_out_and_kills_group(self):
        events,reports,error,_=self.exercise(blocks=(b'x',)*20,timeout=.025)
        self.assertIsInstance(error,subprocess.TimeoutExpired)
        self.assertEqual(1,len([e for e in events if e[0]=='kill']))

    def test_setup_read_select_failure_still_disposes_owned_group(self):
        for fault in ('setup','read','select'):
            with self.subTest(fault=fault):
                events,reports,error,_=self.exercise(fault=fault)
                self.assertIsInstance(error,OSError)
                self.assertEqual(['kill','wait'],[e[0] for e in events if e[0] in ('kill','wait')])
                self.assertTrue(reports[-1]['group_disposed'])

    def test_echild_never_signals_or_reaps_numeric_identity(self):
        events,reports,error,_=self.exercise(lost=True)
        self.assertIsInstance(error,ChildProcessError)
        self.assertFalse(any(e[0] in ('kill','wait') for e in events))
        self.assertFalse(reports[-1]['group_disposed'])

    def test_wait_failure_never_retries_group_signal_and_retains_initial_failure(self):
        events,reports,error,_=self.exercise(exited=False,timeout=.025,wait_fault=OSError('wait failed'))
        self.assertIsInstance(error,subprocess.TimeoutExpired)
        self.assertEqual(['kill','wait'],[e[0] for e in events if e[0] in ('kill','wait')])
        self.assertEqual('TimeoutExpired',reports[-1]['error'])
        self.assertEqual('OSError',reports[-1]['cleanup_error'])
        self.assertFalse(reports[-1]['group_disposed'])

    def test_close_failure_preserves_timeout_and_result(self):
        _,reports,error,_=self.exercise(exited=False,timeout=.025,close_fault=OSError('close'))
        self.assertIsInstance(error,subprocess.TimeoutExpired)
        self.assertEqual('TimeoutExpired',reports[-1]['error'])
        self.assertEqual('OSError',reports[-1]['close_error'])

    def test_final_ownership_loss_suppresses_numeric_signal(self):
        events,reports,error,_=self.exercise(lost_final=True)
        self.assertIsInstance(error,ChildProcessError)
        self.assertFalse(any(e[0] in ('kill','wait') for e in events))
        self.assertEqual('ChildProcessError',reports[-1]['cleanup_error'])

    def test_kill_errors_are_not_retried_and_process_lookup_is_benign(self):
        events,reports,error,_=self.exercise(kill_fault=PermissionError('kill'))
        self.assertIsInstance(error,PermissionError)
        self.assertEqual(1,len([e for e in events if e[0]=='kill']))
        self.assertFalse(reports[-1]['group_disposed'])
        events,reports,error,_=self.exercise(kill_fault=ProcessLookupError())
        self.assertIsNone(error);self.assertTrue(reports[-1]['group_disposed'])

    def test_wait_failure_after_success_is_not_success_or_second_signal(self):
        events,reports,error,_=self.exercise(wait_fault=OSError('wait'))
        self.assertIsInstance(error,OSError)
        self.assertEqual(['kill','wait'],[e[0] for e in events if e[0] in ('kill','wait')])
        self.assertFalse(reports[-1]['group_disposed'])

    def test_late_eof_exit_still_requires_build_deadline_recheck(self):
        # The helper may observe EOF/exit together on the final poll. The owner
        # build's mandatory remaining() check refuses a late hash/ready marker.
        _,reports,error,_=self.exercise(blocks=(b'',),late=True)
        self.assertIsNone(error);self.assertEqual(1,reports[-1]['seconds'])

    def test_output_is_drained_but_only_bounded_tail_retained(self):
        raw=b'a'*8192
        events,reports,error,_=self.exercise(blocks=(raw,)*10+(b'collect2 final\n',b''))
        self.assertIsNone(error)
        report=reports[-1]
        self.assertEqual(81920+15,report['diagnostic_bytes'])
        self.assertEqual(65536,len(report['diagnostic_tail']))
        self.assertTrue(report['diagnostic_truncated'])
        self.assertTrue(report['diagnostic_tail'].endswith('collect2 final\n'))

    def test_nonzero_is_failure_even_with_complete_diagnostics(self):
        _,reports,error,_=self.exercise(code=1)
        self.assertIsInstance(error,subprocess.CalledProcessError)
        self.assertEqual(1,reports[-1]['returncode'])

    def test_spawn_failure_and_ignored_sigchld_have_no_group_authority(self):
        events,reports,error,_=self.exercise(fault='spawn')
        self.assertIsInstance(error,OSError)
        self.assertFalse(any(e[0] in ('kill','wait') for e in events))
        self.assertFalse(reports[-1]['group_disposed'])
        events,_,error,_=self.exercise(sigchld=signal.SIG_IGN)
        self.assertIsInstance(error,AssertionError);self.assertEqual([],events)


if __name__=='__main__':unittest.main()
