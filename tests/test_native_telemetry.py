"""Pure/mocked retained native telemetry; no guest, Docker, listener or runtime."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, mock_open, patch

sys.path.insert(0,str(Path(__file__).parent/'vm'))
import guest_boundary as boundary
import guest_workstation as guest
import native_rootfs
import native_supervisor as supervisor
import run_workstation as runner

NONCE='a'*32
IMAGE='sha256:'+'b'*64


class NativeSupervisorDiagnosticsTests(unittest.TestCase):
    def launch(self):
        origin=SimpleNamespace(identity=(7,9),pidfd=22,credentials=(234,165532,165532))
        seat=SimpleNamespace(slot='seat-a',container_id='c'*64)
        launch=SimpleNamespace(origin=origin,seat=seat,state='released',exec_id='d'*64,engine=Mock())
        launch.engine.inspect.return_value={'ID':launch.exec_id,'ContainerID':seat.container_id,
            'Running':True,'ExitCode':0,'Pid':234,'ProcessConfig':{'arguments':['DO NOT ECHO']}}
        return launch

    def test_exact_exec_get_and_held_identity_are_observation_only_before_cleanup(self):
        launch=self.launch();receiver=Mock();receiver.startup_diagnostic.return_value={'stage':'state-rpc'}
        with patch.object(supervisor,'alive',side_effect=[True,False]), \
                patch.object(supervisor,'diagnostic_record') as emit:
            supervisor.startup_observer(launch,'alice')(receiver,RuntimeError('do not echo'))
        receiver.startup_diagnostic.assert_called_once_with(include_stderr=True)
        launch.engine.inspect.assert_called_once_with(launch.exec_id)
        record=emit.call_args.args[1]
        self.assertEqual(record['participant'],'alice');self.assertEqual(record['held_identity'],[7,9])
        self.assertTrue(record['held_alive_before']);self.assertFalse(record['held_alive_after'])
        self.assertEqual(record['exec'],{'Running':True,'ExitCode':0,'Pid':234})
        self.assertTrue(record['exec_pid_matches_held_credentials'])
        self.assertNotIn('DO NOT ECHO',json.dumps(record));self.assertEqual(launch.state,'released')

    def test_failed_snapshot_or_get_retains_other_facts_and_never_retries(self):
        launch=self.launch();launch.engine.inspect.side_effect=OSError('private error content')
        receiver=Mock();receiver.startup_diagnostic.side_effect=ValueError('private content')
        with patch.object(supervisor,'alive',return_value=True),patch.object(supervisor,'diagnostic_record') as emit:
            supervisor.startup_observer(launch,'alice')(receiver,RuntimeError())
        record=emit.call_args.args[1]
        self.assertEqual(record['receiver_unavailable'],'ValueError')
        self.assertEqual(record['exec_unavailable'],'OSError');self.assertNotIn('private',json.dumps(record))
        launch.engine.inspect.assert_called_once()

    def test_replaced_exec_record_is_not_reported_as_matching(self):
        launch=self.launch();launch.engine.inspect.return_value['ID']='e'*64
        receiver=Mock();receiver.startup_diagnostic.return_value={}
        with patch.object(supervisor,'alive',return_value=True),patch.object(supervisor,'diagnostic_record') as emit:
            supervisor.startup_observer(launch,'alice')(receiver,RuntimeError())
        self.assertNotIn('exec',emit.call_args.args[1])
        self.assertEqual(emit.call_args.args[1]['exec_unavailable'],'ValueError')

    def test_bounded_records_and_writer_failures_do_not_change_effect(self):
        with patch('builtins.print') as output:
            supervisor.diagnostic_record('pi-startup-failure',{'stderr':'x'*17000})
        self.assertEqual(output.call_args.args[0],'UAS_NATIVE_DIAGNOSTIC_UNAVAILABLE:pi-startup-failure')
        with patch('builtins.print',side_effect=OSError):
            supervisor.diagnostic_record('pi-startup-failure',{'observed':True})


class NativePartialEvidenceTests(unittest.TestCase):
    def test_check_telemetry_does_not_echo_native_delivery_message_content(self):
        checks={'native_two_seats':{'status':'passed','deliveries':[{'payload':'PRIVATE MESSAGE'}]}}
        with patch.object(guest,'emit_evidence') as emit:guest.emit_check(checks,'native_two_seats')
        value=emit.call_args.args[1]
        self.assertNotIn('PRIVATE MESSAGE',json.dumps(value));self.assertEqual(value['delivery_count'],1)
        self.assertEqual(len(value['delivery_evidence_sha256']),64)
        self.assertEqual(checks['native_two_seats']['deliveries'],[{'payload':'PRIVATE MESSAGE'}])

    def test_retained_fixed_records_exclude_arbitrary_output_and_keep_exact_digest(self):
        record={'kind':'pi-startup-failure','value':{'participant':'bob','receiver':{'stderr':{'bytes':0}}}}
        raw=('UAS_NATIVE_PHASE:two-seat-start\nARBITRARY COMMAND CONTENT\n'
             +'UAS_NATIVE_CHECKPOINT:'+json.dumps(record)+'\n'
             +'UAS_NATIVE_DIAGNOSTIC_UNAVAILABLE:seat-admitted\n').encode()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'result.log';path.write_bytes(raw);progress={}
            with patch.object(guest,'emit_evidence') as emit:
                guest.retain_supervisor_records(path,{},progress,None,None)
        summary=emit.call_args_list[0].args[1]
        self.assertEqual(summary['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(summary['bytes'],len(raw));self.assertEqual(summary['unavailable'],['seat-admitted'])
        self.assertEqual(progress,{'check':'native_two_seats','stage':'supervisor:two-seat-start'})
        self.assertEqual(emit.call_args_list[1].args,('supervisor-pi-startup-failure',record['value']))
        self.assertNotIn('ARBITRARY',str(emit.call_args_list))

    def test_malformed_oversized_or_excessive_checkpoint_rejected_without_echo(self):
        for raw in (b'x'*(1024*1024+1),b'UAS_NATIVE_CHECKPOINT:{bad json}\n',
                    (b'UAS_NATIVE_PHASE:hub-start\n')*17,
                    b'UAS_NATIVE_CHECKPOINT:{"kind":"unexpected","value":{}}\n'):
            with self.subTest(bytes=len(raw)),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'result.log';path.write_bytes(raw)
                with patch.object(guest,'emit_evidence') as emit,self.assertRaises((AssertionError,ValueError)):
                    guest.retain_supervisor_records(path,{}, {},None,None)
                emit.assert_not_called()

    def test_failed_stage_distinct_from_prior_pass_unreached_and_cleanup(self):
        checks={'payload':{'status':'passed','image':IMAGE},'guest_cleanup':{'status':'passed'}}
        guest.failed_checks(checks,{'check':'native_two_seats','stage':'supervisor:two-seat-start'})
        self.assertEqual(checks['payload']['image'],IMAGE);self.assertEqual(checks['payload']['status'],'passed')
        self.assertEqual(checks['native_two_seats']['status'],'failed')
        self.assertEqual(checks['actor_attribution']['status'],'not_run')
        self.assertEqual(checks['guest_cleanup']['status'],'passed');self.assertEqual(set(checks),guest.REQUIRED)

    def test_later_failure_does_not_erase_prior_data_but_is_not_a_pass(self):
        checks={'confinement':{'status':'passed','runtime':{'uid':65532}}}
        guest.failed_checks(checks,{'check':'confinement','stage':'later-confinement-check'})
        self.assertEqual(checks['confinement']['runtime'],{'uid':65532})
        self.assertEqual(checks['confinement']['status'],'failed')

    def test_failed_hub_before_actual_observation_preserves_only_partial_confinement(self):
        checks={'confinement':{'status':'partial','runtime':{'uid':65532},
            'completed_scope':'container-configuration-and-workstation-kernel-observations',
            'pending_scope':'actual-Hub-namespace-mapping-kernel-observations'}}
        guest.failed_checks(checks,{'check':'hub_startup','stage':'supervisor:hub-start'})
        self.assertEqual(checks['hub_startup']['status'],'failed')
        self.assertEqual(checks['confinement']['status'],'partial')
        self.assertNotIn('hub_actual',checks['confinement'])
        self.assertIn('pending_scope',checks['confinement'])
        self.assertEqual(checks['native_two_seats']['status'],'not_run')

    def hub_data(self):
        kernel={'CapEff':'0000000000000000','CapBnd':'0000000000000000','NoNewPrivs':'1','Seccomp':'2'}
        actual={'pid_namespace':'pi-pid','mount_namespace':'pi-mount','uid_map':'mapped','gid_map':'mapped'}
        result={'hub_identity':[1,2],'controller':'test-controller','supervisor_label':'trusted',
            'supervisor_uid':165533,'hub_observation':{'pid_namespace':'hub-pid','mount_namespace':'hub-mount',
            'uid_map':'mapped','gid_map':'mapped','overflow_uid':65534,'overflow_gid':65534,
            'kernel_status':kernel,'label':'system_u:system_r:container_t:'+guest.LEVEL}}
        return actual,kernel,result

    def test_completed_hub_checkpoint_still_requires_existing_kernel_namespace_checks(self):
        actual,kernel,result=self.hub_data();checks={'confinement':{'status':'partial','pending_scope':'Hub actual'}}
        with patch.object(guest,'emit_check') as emit:
            guest.record_hub_checks(checks,result,actual,kernel)
        self.assertEqual(checks['hub_startup']['status'],'passed')
        self.assertEqual(checks['confinement']['status'],'passed')
        self.assertNotIn('pending_scope',checks['confinement'])
        self.assertEqual(checks['confinement']['hub_actual'],result['hub_observation'])
        self.assertEqual([call.args[1] for call in emit.call_args_list],['confinement','hub_startup'])
        checks={'confinement':{'status':'partial'}};result['hub_observation']['kernel_status']={}
        with patch.object(guest,'emit_check') as emit,self.assertRaises(AssertionError):
            guest.record_hub_checks(checks,result,actual,kernel)
        self.assertNotIn('hub_startup',checks);emit.assert_not_called()
        self.assertEqual(checks['confinement']['status'],'partial')

    def test_confirmed_image_and_payload_persist_before_next_effect(self):
        class LaterFailure(Exception):pass
        checks={};events=[]
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            root=Path(directory)
            stack.enter_context(patch.object(guest,'Path',side_effect=lambda value:root/Path(value).name))
            def build(nonce,manifest,image_root,**kwargs):
                image_root.mkdir();(image_root/'fixture').write_bytes(b'fixed')
                return {'rootfs_manifest_sha256':'f'*64}
            stack.enter_context(patch.object(native_rootfs,'build_rootfs',side_effect=build))
            stack.enter_context(patch.object(boundary,'start_engine'))
            stack.enter_context(patch.object(guest,'engine_profile',return_value={}))
            stack.enter_context(patch.object(guest,'import_image',return_value=IMAGE))
            stack.enter_context(patch.object(guest,'emit_evidence',side_effect=lambda kind,data:events.append(kind)))
            stack.enter_context(patch.object(guest,'storage',side_effect=LaterFailure))
            run=stack.enter_context(patch.object(guest,'run'))
            stack.enter_context(patch('builtins.print'))
            with self.assertRaises(LaterFailure):guest.scenario(NONCE,{},checks=checks)
        self.assertEqual(checks['payload']['image'],IMAGE)
        self.assertLess(events.index('imported-image'),events.index('check-payload'))
        self.assertEqual(checks['guest_cleanup']['status'],'passed')
        run.assert_called_once_with('docker','image','rm',IMAGE)

    def test_cleanup_failure_is_separate_and_does_not_replace_original(self):
        original=RuntimeError('original rootfs failure');checks={}
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            root=Path(directory)
            stack.enter_context(patch.object(guest,'Path',side_effect=lambda value:root/Path(value).name))
            def build(nonce,manifest,image_root,**kwargs):image_root.mkdir();raise original
            stack.enter_context(patch.object(native_rootfs,'build_rootfs',side_effect=build))
            stack.enter_context(patch.object(guest.shutil,'rmtree',side_effect=OSError('cleanup failure')))
            stack.enter_context(patch.object(guest,'emit_check'))
            with self.assertRaises(RuntimeError) as caught:guest.scenario(NONCE,{},checks=checks)
            self.assertIs(caught.exception,original)
            self.assertEqual(checks['guest_cleanup']['status'],'failed')
            self.assertEqual(checks['guest_cleanup']['cleanup_errors'],[{'resource':'build-scratch','error':'OSError'}])
            self.assertIn('Native cleanup failures:',original.__notes__[0])

    def test_main_retains_partial_checks_and_reports_failure_without_blanket_overwrite(self):
        def scenario(nonce,manifest,*,checks,progress):
            checks.update(payload={'status':'passed','image':IMAGE},guest_cleanup={'status':'passed'})
            progress.update(check='native_two_seats',stage='supervisor:two-seat-start')
            raise RuntimeError('native missing response')
        opened=mock_open()
        with patch.object(sys,'argv',['guest',NONCE,'digest']),patch.object(boundary,'install'), \
                patch.object(boundary,'verify_payload',return_value={'profile':'native-pi-v1'}), \
                patch.object(guest,'scenario',side_effect=scenario),patch.object(guest,'run',return_value=''), \
                patch('builtins.open',opened),patch('builtins.print'):
            guest.main()
        text=opened().write.call_args.args[0];report=json.loads(text.split(':'+NONCE+':',1)[1])
        self.assertEqual(report['checks']['payload']['image'],IMAGE)
        self.assertEqual(report['checks']['native_two_seats']['status'],'failed')
        self.assertEqual(report['checks']['wrong_process']['status'],'not_run')
        self.assertEqual(report['checks']['guest_cleanup']['status'],'passed')
        self.assertEqual(report['failure']['stage'],'supervisor:two-seat-start')

    def test_explicit_failure_cannot_pass_runner_even_with_all_check_flags_passed(self):
        report={'version':1,'nonce':NONCE,'checks':{name:{'status':'passed'} for name in runner.REQUIRED},
                'failure':{'stage':'report-validation','error_type':'RuntimeError'}}
        with self.assertRaises(RuntimeError):runner.parse_report('UAS_WORKSTATION_REPORT:'+NONCE+':'+json.dumps(report),NONCE)


if __name__=='__main__':unittest.main()
