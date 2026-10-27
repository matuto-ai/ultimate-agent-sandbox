"""Fake child/selector/clock tests: no subprocesses, sockets or native execution."""
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC=importlib.util.spec_from_file_location('native_progress_boundary',Path(__file__).parent/'vm/guest_boundary.py')
boundary=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(boundary)


class NativeProgressTests(unittest.TestCase):
    def setup_command(self, batches, *, code=0, clock=None):
        stdout=Mock(); stdout.fileno.return_value=11
        stderr=Mock(); stderr.fileno.return_value=12
        process=SimpleNamespace(stdout=stdout,stderr=stderr,pid=54321,wait=Mock(return_value=code))
        selector=Mock(); registered={}; pending=[]
        def register(stream,event,name): registered[name]=SimpleNamespace(fileobj=stream,data=name)
        def select(timeout):
            batch=batches.pop(0) if batches else []
            pending.extend(data for name,data in batch)
            return [(registered[name],1) for name,data in batch]
        def unregister(stream):
            for key,value in list(registered.items()):
                if value.fileobj is stream: del registered[key]
        selector.register.side_effect=register; selector.unregister.side_effect=unregister
        selector.get_map.side_effect=lambda: registered
        selector.select.side_effect=select
        def read(*args):
            value=pending.pop(0)
            if isinstance(value,BaseException): raise value
            return value
        stack=ExitStack()
        popen=stack.enter_context(patch.object(boundary.subprocess,'Popen',return_value=process))
        stack.enter_context(patch.object(boundary.selectors,'DefaultSelector',return_value=selector))
        blocking=stack.enter_context(patch.object(boundary.os,'set_blocking'))
        reader=stack.enter_context(patch.object(boundary.os,'read',side_effect=read))
        kill=stack.enter_context(patch.object(boundary.os,'killpg'))
        stack.enter_context(patch.object(boundary.time,'monotonic',side_effect=clock or (lambda: 0)))
        printed=stack.enter_context(patch('builtins.print'))
        return stack,process,selector,kill,printed,popen,blocking,reader

    def test_silent_eof_produces_no_progress(self):
        stack,process,selector,kill,printed,popen,_,_=self.setup_command([[('stdout',b''),('stderr',b'')]])
        with stack:
            code,streams=boundary.native_command(('dnf',),timeout=900)
        self.assertEqual(code,0); printed.assert_not_called(); kill.assert_not_called()
        self.assertEqual(streams['stdout']['bytes'],0)
        process.wait.assert_called_once_with(timeout=900)
        selector.close.assert_called_once();process.stdout.close.assert_called_once();process.stderr.close.assert_called_once()
        self.assertTrue(popen.call_args.kwargs['start_new_session'])

    def test_only_received_bytes_reported_no_synthetic_idle_progress(self):
        times=iter([0,0,31,31,62,62,63,63])
        stack,process,selector,kill,printed,*_=self.setup_command([
            [('stdout',b'abc')], [], [('stdout',b''),('stderr',b'')]],clock=lambda:next(times))
        with stack: _,streams=boundary.native_command(('dnf',),timeout=900)
        self.assertEqual(printed.call_count,1)
        self.assertEqual(json.loads(printed.call_args.args[1]),{'stdout_bytes':3,'stderr_bytes':0})
        self.assertEqual(streams['stdout']['output'],'abc')
        process.wait.assert_called_once_with(timeout=837)

    def test_hard_deadline_not_reset_by_progress_kills_before_reap(self):
        times=iter([0,0,31,31,901,901]); order=[]
        stack,process,selector,kill,printed,*_=self.setup_command([[('stdout',b'progress')],[]],clock=lambda:next(times))
        kill.side_effect=lambda *a:order.append('kill')
        process.wait.side_effect=lambda **k:order.append('wait')
        with stack,self.assertRaises(subprocess.TimeoutExpired) as caught:
            boundary.native_command(('dnf',),timeout=900)
        self.assertEqual(caught.exception.timeout,900);self.assertEqual(order,['kill','wait'])
        process.wait.assert_called_once_with(timeout=5)
        process.stdout.close.assert_called_once();process.stderr.close.assert_called_once();selector.close.assert_called_once()

    def test_failure_returncode_early_errors_and_bounded_head_tail_preserved(self):
        data=b'error first\n'+b'p'*100000+b'\ncpio: late\n'
        stack,process,selector,kill,printed,*_=self.setup_command([
            [('stdout',data),('stderr',b'fatal stderr\n')],[('stdout',b''),('stderr',b'')]],code=7)
        with stack: code,streams=boundary.native_command(('dnf',),timeout=900)
        self.assertEqual(code,7);kill.assert_not_called()
        context=streams['stdout'];self.assertEqual(context['bytes'],len(data));self.assertTrue(context['truncated'])
        self.assertEqual(context['first_error_lines'],['error first','cpio: late'])
        self.assertTrue(context['output'].startswith('error first'));self.assertTrue(context['output'].endswith('cpio: late\n'))

    def test_capture_stays_bounded_across_chunks_and_split_error_keyword(self):
        capture=boundary.NativeCapture()
        capture.feed(b'fa');capture.feed(b'tal '+('é'*1000).encode()+b'\n')
        for _ in range(40):capture.feed(b'x'*65536)
        capture.feed(b'\nerror final')
        value=capture.context()
        self.assertLessEqual(len(capture.head),32768);self.assertLessEqual(len(capture.tail),32768)
        self.assertLessEqual(len(capture.line),512);self.assertLessEqual(len(capture.scan_tail),16)
        self.assertTrue(value['first_error_lines_truncated'])
        self.assertTrue(value['first_error_lines'][0].startswith('fatal'))
        self.assertTrue(all(len(line.encode())<=512 for line in value['first_error_lines']))
        self.assertEqual(value['first_error_lines'][-1],'error final')

    def test_constructor_registration_nonblocking_and_read_errors_cleanup_every_resource(self):
        for failure in ('selector','register','nonblocking','read'):
            with self.subTest(failure=failure):
                stack,process,selector,kill,printed,popen,blocking,reader=self.setup_command([[('stdout',b'x')]])
                if failure=='register':selector.register.side_effect=RuntimeError('register')
                if failure=='nonblocking':blocking.side_effect=RuntimeError('nonblocking')
                if failure=='read':reader.side_effect=RuntimeError('read')
                with stack:
                    if failure=='selector':
                        with patch.object(boundary.selectors,'DefaultSelector',side_effect=RuntimeError('selector')):
                            with self.assertRaisesRegex(RuntimeError,failure):boundary.native_command(('dnf',),timeout=900)
                    else:
                        with self.assertRaisesRegex(RuntimeError,failure):boundary.native_command(('dnf',),timeout=900)
                kill.assert_called_once();process.wait.assert_called_once_with(timeout=5)
                process.stdout.close.assert_called_once();process.stderr.close.assert_called_once()
                if failure!='selector':selector.close.assert_called_once()

    def test_close_failure_does_not_skip_later_resources_or_retry_close(self):
        stack,process,selector,kill,printed,*_=self.setup_command([[('stdout',b''),('stderr',b'')]])
        selector.close.side_effect=RuntimeError('close selector');process.stdout.close.side_effect=RuntimeError('close pipe')
        with stack,self.assertRaisesRegex(RuntimeError,'close selector'):
            boundary.native_command(('dnf',),timeout=900)
        process.stdout.close.assert_called_once();process.stderr.close.assert_called_once();kill.assert_not_called()

    def test_wait_timeout_after_eof_kills_and_reaps(self):
        stack,process,selector,kill,printed,*_=self.setup_command([[('stdout',b''),('stderr',b'')]])
        process.wait.side_effect=[subprocess.TimeoutExpired(('dnf',),900),0]
        with stack,self.assertRaises(subprocess.TimeoutExpired):
            boundary.native_command(('dnf',),timeout=900)
        kill.assert_called_once()
        self.assertEqual([call.kwargs['timeout'] for call in process.wait.call_args_list],[900,5])
        selector.close.assert_called_once();process.stdout.close.assert_called_once();process.stderr.close.assert_called_once()

    def test_import_phase_retains_240_second_deadline_and_client_cleanup_only(self):
        times=iter([0,0,241,241]);order=[]
        stack,process,selector,kill,printed,*_=self.setup_command([[]],clock=lambda:next(times))
        kill.side_effect=lambda *a:order.append('kill')
        def reap(**kwargs):order.append('wait');return -9
        process.wait.side_effect=reap
        with stack,self.assertRaises(subprocess.TimeoutExpired) as caught:
            boundary.native_command(('docker','import','/var/lib/uas-native-rootfs.tar'),timeout=240,phase='image-import')
        self.assertEqual(caught.exception.timeout,240);self.assertEqual(order,['kill','wait'])
        self.assertEqual(printed.call_args_list[-1].args[0],'Native image-import client cleanup:')
        evidence=json.loads(printed.call_args_list[-1].args[1])
        self.assertEqual(evidence,{'group_sigkill_sent':True,'returncode':-9,
                                  'cleanup_errors':[],'daemon_import_outcome_inferred':False})
        self.assertFalse(any('output progress' in call.args[0] for call in printed.call_args_list))

    def test_successful_import_emits_client_reap_without_signalling(self):
        stack,process,selector,kill,printed,*_=self.setup_command([[('stdout',b''),('stderr',b'')]])
        with stack:boundary.native_command(('docker','import','/var/lib/uas-native-rootfs.tar'),timeout=240,phase='image-import')
        kill.assert_not_called();process.wait.assert_called_once_with(timeout=240)
        evidence=json.loads(printed.call_args.args[1])
        self.assertEqual(evidence['returncode'],0);self.assertFalse(evidence['group_sigkill_sent'])
        self.assertFalse(evidence['daemon_import_outcome_inferred'])

    def test_import_real_output_cannot_renew_fixed_240_second_budget(self):
        times=iter([0,0,31,31,241,241]);order=[]
        stack,process,selector,kill,printed,*_=self.setup_command([[('stdout',b'actual output')],[]],clock=lambda:next(times))
        kill.side_effect=lambda *a:order.append('kill')
        def reap(**kwargs):order.append('wait');return -9
        process.wait.side_effect=reap
        with stack,self.assertRaises(subprocess.TimeoutExpired) as caught:
            boundary.native_command(('docker','import','/var/lib/uas-native-rootfs.tar'),timeout=240,phase='image-import')
        self.assertEqual(caught.exception.timeout,240);self.assertEqual(order,['kill','wait'])
        process.wait.assert_called_once_with(timeout=5)
        progress=[call for call in printed.call_args_list if 'output progress' in call.args[0]]
        self.assertEqual(len(progress),1)
        self.assertEqual(json.loads(progress[0].args[1])['stdout_bytes'],len(b'actual output'))
        self.assertFalse(json.loads(printed.call_args_list[-1].args[1])['daemon_import_outcome_inferred'])

    def test_import_progress_and_cleanup_writer_failure_preserves_output_and_returncode(self):
        stack,process,selector,kill,printed,*_=self.setup_command([
            [('stdout',b'sha256:actual\n')],[('stdout',b''),('stderr',b'')]])
        printed.side_effect=OSError('broken diagnostic writer')
        with stack:
            code,streams=boundary.native_command(('docker','import','/var/lib/uas-native-rootfs.tar'),timeout=240,phase='image-import')
        self.assertEqual(code,0);self.assertEqual(streams['stdout']['output'],'sha256:actual\n')
        self.assertEqual(printed.call_count,2);kill.assert_not_called()
        process.wait.assert_called_once_with(timeout=240)

    def test_import_timeout_and_cleanup_writer_failure_preserves_original_timeout(self):
        stack,process,selector,kill,printed,*_=self.setup_command([[('stdout',b''),('stderr',b'')]])
        original=subprocess.TimeoutExpired(('docker','import'),240)
        process.wait.side_effect=[original,-9];printed.side_effect=OSError('broken diagnostic writer')
        with stack,self.assertRaises(subprocess.TimeoutExpired) as caught:
            boundary.native_command(('docker','import','/var/lib/uas-native-rootfs.tar'),timeout=240,phase='image-import')
        self.assertIs(caught.exception,original);kill.assert_called_once()
        self.assertEqual([call.kwargs['timeout'] for call in process.wait.call_args_list],[240,5])
        self.assertEqual(printed.call_count,2)

    def test_import_writer_failure_does_not_hide_actual_resource_cleanup_failure(self):
        stack,process,selector,kill,printed,*_=self.setup_command([[('stdout',b''),('stderr',b'')]])
        original=OSError('actual pipe close failure')
        process.stdout.close.side_effect=original;printed.side_effect=OSError('broken diagnostic writer')
        with stack,self.assertRaises(OSError) as caught:
            boundary.native_command(('docker','import','/var/lib/uas-native-rootfs.tar'),timeout=240,phase='image-import')
        self.assertIs(caught.exception,original);kill.assert_not_called()
        process.stderr.close.assert_called_once();selector.close.assert_called_once()

    def test_original_read_error_survives_kill_wait_and_close_failures(self):
        stack,process,selector,kill,printed,popen,blocking,reader=self.setup_command([[('stdout',b'x')]])
        reader.side_effect=RuntimeError('original read')
        kill.side_effect=PermissionError('kill failure')
        process.wait.side_effect=subprocess.TimeoutExpired(('dnf',),5)
        selector.close.side_effect=RuntimeError('close failure')
        process.stdout.close.side_effect=OSError('pipe close failure')
        with stack,self.assertRaisesRegex(RuntimeError,'original read'):
            boundary.native_command(('dnf',),timeout=900)
        process.wait.assert_called_once_with(timeout=5)
        selector.close.assert_called_once();process.stdout.close.assert_called_once();process.stderr.close.assert_called_once()


if __name__=='__main__':unittest.main()
