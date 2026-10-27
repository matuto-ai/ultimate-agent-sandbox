"""Pure fixed-proc diagnostic tests; no process, procfs, listener or Engine I/O."""
import ast
from contextlib import ExitStack
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).parent/'vm'))
import native_supervisor as supervisor


class HeldPiStartupFactsTests(unittest.TestCase):
    @staticmethod
    def stat(*,state='R',utime=13,stime=4,starttime=99,pid=234):
        fields=['0']*20
        fields[0]=state;fields[11]=str(utime);fields[12]=str(stime);fields[19]=str(starttime)
        return (str(pid)+' (PRIVATE ) COMMAND) '+' '.join(fields)).encode()

    def harness(self):
        stack=ExitStack();self.addCleanup(stack.close)
        self.origin=SimpleNamespace(identity=(7,9),pidfd=22,credentials=(234,165532,165532),revoked=False)
        self.launch=SimpleNamespace(origin=self.origin)
        self.live=True
        self.alive=stack.enter_context(patch.object(supervisor,'alive',side_effect=lambda fd:self.live))
        self.identity=stack.enter_context(patch.object(supervisor,'_identity',return_value=(7,9)))
        self.opened=stack.enter_context(patch.object(supervisor.os,'open',side_effect=lambda name,*a,**k:20 if name=='/proc/234' else 30))
        self.read=stack.enter_context(patch.object(supervisor.os,'read',return_value=self.stat()))
        self.close=stack.enter_context(patch.object(supervisor.os,'close'))
        self.lookup=stack.enter_context(patch.object(supervisor.os,'pidfd_open',side_effect=AssertionError('no task adoption')))
        stack.enter_context(patch.object(supervisor.os,'fstat',return_value=SimpleNamespace(st_uid=165532)))
        stack.enter_context(patch.object(supervisor.os,'sysconf',return_value=100))
        stack.enter_context(patch.object(supervisor.time,'monotonic',return_value=100.0))
        return stack

    def test_only_fixed_vm_initial_attachment_opts_in_to_exact_thirty_seconds(self):
        tree=ast.parse(Path(supervisor.__file__).read_text())
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
               and isinstance(node.func,ast.Attribute) and node.func.attr=='attach_native']
        self.assertEqual(len(calls),1)
        keywords={item.arg:item.value for item in calls[0].keywords}
        self.assertEqual(ast.literal_eval(keywords['initial_state_timeout']),30)
        self.assertNotIn('timeout',keywords)

    def test_start_and_failure_use_same_held_origin_proc_fd_and_fixed_stat_only(self):
        with self.harness():
            facts=supervisor.HeldPiStartupFacts(self.launch)
            self.read.return_value=self.stat(utime=800,stime=9)
            result=facts.finish();facts.close()
            self.assertEqual(result['held_identity'],[7,9]);self.assertEqual(result['authority'],'observation-only')
            self.assertEqual(result['start']['utime_ticks'],13);self.assertEqual(result['end']['utime_ticks'],800)
            self.assertEqual(result['end']['starttime_ticks'],99)
            self.assertEqual(result['end']['clock_ticks_per_second'],100)
            self.assertEqual(result['close_errors'],[])
            self.assertEqual(result['proc_directory_uid_at_open'],165532)
            self.assertNotIn('PRIVATE',json.dumps(result));self.lookup.assert_not_called()
            self.assertEqual([call.args[0] for call in self.opened.call_args_list],['/proc/234','stat','stat'])
            for call in self.opened.call_args_list[1:]:
                self.assertEqual(call.kwargs,{'dir_fd':20})
                self.assertTrue(call.args[1]&supervisor.os.O_NOFOLLOW)
            self.assertEqual([call.args for call in self.read.call_args_list],[(30,4097),(30,4097)])
            self.assertEqual([call.args[0] for call in self.close.call_args_list],[30,30,20])

    def test_exited_revoked_or_replaced_origin_is_not_read(self):
        for mode in ('exited','revoked','identity','fd'):
            with self.subTest(mode=mode),self.harness():
                facts=supervisor.HeldPiStartupFacts(self.launch);self.opened.reset_mock()
                if mode=='exited':self.live=False
                elif mode=='revoked':self.origin.revoked=True
                elif mode=='identity':self.identity.return_value=(7,10)
                else:self.origin.pidfd=23
                value=facts.finish()
                self.assertEqual(value['end']['unavailable'],'RuntimeError')
                self.assertNotIn('state',value['end']);self.opened.assert_not_called();self.lookup.assert_not_called()

    def test_exit_during_read_discards_counters(self):
        with self.harness():
            facts=supervisor.HeldPiStartupFacts(self.launch)
            def read(*args):self.live=False;return self.stat(utime=999)
            self.read.side_effect=read
            result=facts.finish()
            self.assertEqual(result['end']['unavailable'],'RuntimeError')
            self.assertNotIn('utime_ticks',result['end'])

    def test_initial_exit_prevents_even_proc_directory_open(self):
        with self.harness():
            self.live=False;facts=supervisor.HeldPiStartupFacts(self.launch)
            self.assertEqual(facts.finish()['start']['unavailable'],'RuntimeError')
            self.opened.assert_not_called();self.lookup.assert_not_called()

    def test_proc_read_denial_is_typed_latched_and_never_changes_authority(self):
        with self.harness():
            self.read.side_effect=PermissionError('PRIVATE')
            facts=supervisor.HeldPiStartupFacts(self.launch);value=facts.finish()
            self.assertEqual(value['start']['unavailable'],'PermissionError')
            self.assertEqual(value['end']['unavailable'],'PermissionError')
            self.read.assert_called_once();self.assertFalse(self.origin.revoked)
            self.assertNotIn('PRIVATE',json.dumps(value));self.assertIn(unittest.mock.call(20),self.close.call_args_list)

    def test_mismatched_starttime_pid_or_oversized_stat_is_unknown(self):
        for raw in (self.stat(starttime=100),self.stat(pid=235),b'x'*4097,self.stat(utime=-1)):
            with self.subTest(raw=raw[:50]),self.harness():
                facts=supervisor.HeldPiStartupFacts(self.launch);self.read.return_value=raw
                result=facts.finish()
                self.assertIn('unavailable',result['end']);self.assertNotIn('utime_ticks',result['end'])

    def test_mapped_root_allowance_matches_already_required_fixed_guest_namespace_map(self):
        guest=Path(supervisor.__file__).with_name('guest_workstation.py')
        tree=ast.parse(guest.read_text())
        maps=[ast.literal_eval(node.value) for node in ast.walk(tree)
              if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name)
              and target.id=='expected_map' for target in node.targets)]
        self.assertEqual(maps,['0 100000 65536'])
        self.assertEqual(int(maps[0].split()[1]),100000)

    def test_nondumpable_root_and_fixed_mapped_root_ownership_are_observations_not_authority(self):
        for uid in (0,100000):
            with self.subTest(uid=uid),self.harness(),patch.object(supervisor.os,'fstat',return_value=SimpleNamespace(st_uid=uid)):
                facts=supervisor.HeldPiStartupFacts(self.launch);value=facts.finish()
                self.assertEqual(value['proc_directory_uid_at_open'],uid)
                self.assertEqual(value['start']['state'],'R');self.assertEqual(value['end']['starttime_ticks'],99)
                self.assertEqual(self.read.call_count,2);self.lookup.assert_not_called()
                self.assertFalse(self.origin.revoked)

    def test_root_ownership_cannot_override_exited_or_replaced_held_identity(self):
        for mode in ('exit','identity'):
            with self.subTest(mode=mode),self.harness(),patch.object(supervisor.os,'fstat',return_value=SimpleNamespace(st_uid=0)):
                facts=supervisor.HeldPiStartupFacts(self.launch);self.read.reset_mock()
                if mode=='exit':self.live=False
                else:self.identity.return_value=(7,10)
                value=facts.finish()
                self.assertEqual(value['end']['unavailable'],'RuntimeError');self.read.assert_not_called()

    def test_unexpected_proc_owner_is_not_read(self):
        for uid in (42,165533,True):
            with self.subTest(uid=uid),self.harness(),patch.object(supervisor.os,'fstat',return_value=SimpleNamespace(st_uid=uid)):
                facts=supervisor.HeldPiStartupFacts(self.launch);value=facts.finish()
                self.assertEqual(value['proc_directory_uid_at_open'],uid)
                self.assertEqual(value['start']['unavailable'],'RuntimeError')
                self.read.assert_not_called();self.close.assert_called_once_with(20)

    def test_diagnostic_close_failure_is_retained_without_raising_or_double_close(self):
        with self.harness():
            facts=supervisor.HeldPiStartupFacts(self.launch)
            def close(fd):
                if fd==20:raise OSError('PRIVATE close failure')
            self.close.side_effect=close
            result=facts.finish();facts.close()
            self.assertEqual(result['close_errors'],['OSError']);self.assertNotIn('PRIVATE',json.dumps(result))
            self.assertEqual(sum(call.args==(20,) for call in self.close.call_args_list),1)


if __name__=='__main__':unittest.main()
