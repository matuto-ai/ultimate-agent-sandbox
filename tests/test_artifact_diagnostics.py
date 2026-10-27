"""Pure/mocked diagnostics and parent quota observations; no native probes."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

VM=Path(__file__).parent/'vm'
sys.path.insert(0,str(VM))
try:
    import artifact_diagnostics as diagnostics
    import guest_artifacts as guest
    import artifact_supervisor as supervisor
finally:sys.path.remove(str(VM))


class DiagnosticTests(unittest.TestCase):
    def test_bounded_binary_and_control_text_never_breaks_json_record(self):
        value=diagnostics.stream_facts(b'\xff\x00\n'*5000)
        self.assertEqual(value['bytes'],15000)
        self.assertEqual(value['retained_bytes'],diagnostics.SAMPLE_BYTES)
        self.assertTrue(value['truncated'])
        error=diagnostics.FixtureCommandFailure('quota-alpha','exit',returncode=1,stdout=value,stderr=value)
        self.assertLess(len(str(error).encode()),diagnostics.MAX_DIAGNOSTIC_BYTES)
        self.assertEqual(error.document['phase'],'quota-alpha')
        self.assertNotIn('\x00',str(error))

    def test_exit_captures_returncode_and_both_streams_without_argv_or_env(self):
        result=subprocess.CompletedProcess(['never-log-argv'],7,b'fixed stdout',b'fixed stderr')
        with patch.object(diagnostics.subprocess,'run',return_value=result) as run:
            with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
                diagnostics.captured('source-pack',['never-log-argv'],output_limit=65536,
                    env={'PRIVATE':'never-log-environment'},timeout=10)
        value=caught.exception.document
        self.assertEqual((value['phase'],value['outcome'],value['returncode']),('source-pack','exit',7))
        self.assertEqual(value['stdout']['head'],'fixed stdout');self.assertEqual(value['stderr']['head'],'fixed stderr')
        self.assertNotIn('never-log',str(caught.exception))
        self.assertEqual(run.call_args.kwargs['timeout'],10)

    def test_timeout_and_launch_have_typed_context_without_chained_command(self):
        for failure,outcome in ((subprocess.TimeoutExpired(['not-for-log'],20,output=b'partial',stderr=b'phase'), 'timeout'),
                                (OSError(13,'not-for-log'),'launch')):
            with self.subTest(outcome=outcome),patch.object(diagnostics.subprocess,'run',side_effect=failure):
                try:diagnostics.captured('quota-beta',['fixed'],output_limit=8192,timeout=20)
                except diagnostics.FixtureCommandFailure as error:
                    self.assertEqual(error.document['outcome'],outcome)
                    self.assertNotIn('not-for-log',''.join(traceback.format_exception(error)))
                else:self.fail('failure was hidden')

    def test_original_exclusive_and_inclusive_output_limits_preserved(self):
        result=subprocess.CompletedProcess([],0,b'a'*8,b'')
        with patch.object(diagnostics.subprocess,'run',return_value=result):
            with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
                diagnostics.captured('quota-alpha',[],output_limit=8)
            self.assertEqual(caught.exception.document['outcome'],'output')
            self.assertIs(diagnostics.captured('outer-facts',[],output_limit=8,inclusive=True),result)
        with patch.object(diagnostics.subprocess,'run') as run:
            with self.assertRaises(ValueError):diagnostics.captured('caller-selected',[],output_limit=8)
            run.assert_not_called()

    def test_file_failure_reads_only_bounded_head_tail_and_preserves_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'out';err=Path(directory)/'err'
            out.write_bytes(b'A'*(2<<20));err.write_bytes(b'fixed failure')
            with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
                diagnostics.require_file_result('supervisor-alpha',1,out,err,output_limit=1<<20)
            value=caught.exception.document
            self.assertEqual(value['outcome'],'output');self.assertEqual(value['stdout']['bytes'],2<<20)
            self.assertEqual(value['stdout']['retained_bytes'],768)
            self.assertEqual(value['stderr']['head'],'fixed failure')

    def test_invalid_json_reports_bounded_phase_not_silent_parse_exception(self):
        result=subprocess.CompletedProcess([],0,b'not JSON',b'')
        with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
            diagnostics.decoded_json('quota-alpha',result)
        self.assertEqual(caught.exception.document['outcome'],'schema')

    def test_middle_quota_errno_is_retained_outside_both_stream_samples(self):
        document={'version':1,'status':'failed','phase':'over-limit-allocation',
            'before_padding':'x'*600,'observed_errno':28,'error_code':'PROJECT_OVERLIMIT_NOT_DENIED',
            'errno':None,'owned_cleanup':True,'after_padding':'y'*600}
        raw=json.dumps(document).encode()
        self.assertNotIn(b'observed_errno',raw[:384]);self.assertNotIn(b'observed_errno',raw[-384:])
        result=subprocess.CompletedProcess([],1,raw,b'')
        with patch.object(diagnostics.subprocess,'run',return_value=result):
            with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
                diagnostics.captured('quota-alpha',[],output_limit=8192)
        value=caught.exception.document['quota_observation']
        self.assertEqual(value['observed_errno'],28);self.assertIsNone(value['errno'])
        self.assertEqual(value['phase'],'over-limit-allocation');self.assertTrue(value['owned_cleanup'])
        self.assertEqual(value['error_code'],'PROJECT_OVERLIMIT_NOT_DENIED')
        self.assertNotIn('before_padding',value);self.assertNotIn('after_padding',value)

    def test_quota_typed_extraction_rejects_unknown_strings_bool_errno_duplicates_and_oversize(self):
        raw=json.dumps({'version':1,'phase':'do-not-log-this','error_code':'DO_NOT_LOG_THIS',
            'errno':True,'observed_errno':13,'owned_cleanup':'claimed','status':'failed'}).encode()
        value=diagnostics.quota_observation('quota-beta',raw)
        self.assertEqual(value['parse_status'],'partial');self.assertEqual(value['observed_errno'],13)
        for field in ('phase','error_code','errno','owned_cleanup'):self.assertNotIn(field,value)
        self.assertNotIn('do-not-log',json.dumps(value));self.assertNotIn('DO_NOT_LOG',json.dumps(value))
        for raw in (b'{"version":1,"errno":28,"errno":122}',b'\xff',b'x'*8193,b'[]',b'{"version":true}'):
            self.assertEqual(diagnostics.quota_observation('quota-alpha',raw)['parse_status'],'unavailable')
        self.assertIsNone(diagnostics.quota_observation('source-pack',b'{"version":1,"errno":28}'))

    def test_quota_diagnostic_whitelist_covers_fixed_probe_codes_and_phases(self):
        import re
        source=(VM/'artifact_quota_probe.py').read_text()
        codes=set(re.findall(r"'([A-Z][A-Z_]+)'",source))
        phases=set(re.findall(r"(?:\['phase'\] = |'phase': )'([a-z-]+)'",source))
        self.assertEqual(codes,diagnostics.QUOTA_CODES);self.assertEqual(phases,diagnostics.QUOTA_PHASES)


class SupervisorDiagnosticTests(unittest.TestCase):
    def record(self,error=None,phase='source-resolve'):
        if error is None:
            error=supervisor.ArtifactError('ARTIFACT_SOURCE_UNVERIFIABLE')
            error.__cause__=OSError(13,'secret path or contents')
        return diagnostics.supervisor_failure(phase,error,supervisor.ArtifactError)

    def wire(self,value):
        return diagnostics.SUPERVISOR_PREFIX+json.dumps(value,separators=(',',':')).encode()+b'\n'

    def test_actual_causal_errno_and_known_code_without_arbitrary_exception_text(self):
        value=self.record()
        self.assertEqual(value,{'version':1,'phase':'source-resolve','code':'ARTIFACT_SOURCE_UNVERIFIABLE',
            'errno':13,'errno_depth':1,'chain_status':'complete'})
        self.assertNotIn('secret',json.dumps(value))
        class SecretFailure(RuntimeError):
            def __str__(self):raise AssertionError('arbitrary text must not be read')
        value=self.record(SecretFailure('private contents'))
        self.assertEqual(value['code'],'UNCLASSIFIED_ERROR');self.assertIsNone(value['errno'])

    def test_suppressed_context_is_typed_but_never_traceback_parsed(self):
        try:
            try:raise OSError(28,'secret object name')
            except OSError:raise supervisor.ArtifactError('ARTIFACT_GIT_EXIT_ERROR') from None
        except supervisor.ArtifactError as error:value=self.record(error)
        self.assertEqual((value['errno'],value['errno_depth']),(28,1))
        self.assertEqual(value['code'],'ARTIFACT_GIT_EXIT_ERROR')

    def test_explicit_cause_precedes_unrelated_context_and_nearest_errno_is_reported(self):
        error=OSError(5,'outer');error.__cause__=OSError(13,'explicit');error.__context__=OSError(28,'other')
        value=self.record(error)
        self.assertEqual((value['code'],value['errno'],value['errno_depth']),('OS_ERROR',5,0))
        error=supervisor.ArtifactError('ARTIFACT_COPY_FAILED');error.__cause__=OSError(13,'explicit')
        error.__context__=OSError(28,'other');self.assertEqual(self.record(error)['errno'],13)

    def test_unknown_codes_and_invalid_errno_cannot_leak_strings_or_booleans(self):
        for code in ('PRIVATE_PATH_CONTENTS',[],True,None):
            value=self.record(supervisor.ArtifactError(code))
            self.assertEqual(value['code'],'ARTIFACT_OTHER_ERROR')
        for number in (True,False,0,-1,4096,'private',None):
            error=OSError();error.errno=number;value=self.record(error)
            self.assertIsNone(value['errno']);self.assertIsNone(value['errno_depth'])
        with self.assertRaises(ValueError):self.record(phase='caller path')

    def test_cycles_and_long_chain_have_fixed_bound_not_false_complete_claim(self):
        error=RuntimeError();error.__cause__=error
        self.assertEqual(self.record(error)['chain_status'],'cycle')
        outer=RuntimeError();node=outer
        for _ in range(diagnostics.MAX_EXCEPTION_CHAIN):
            node.__cause__=RuntimeError();node=node.__cause__
        node.__cause__=OSError(13,'beyond bound')
        value=self.record(outer);self.assertEqual(value['chain_status'],'bounded');self.assertIsNone(value['errno'])

    def test_boundary_rethrows_exact_original_without_success_or_hub_result(self):
        error=supervisor.ArtifactError('ARTIFACT_SOURCE_UNVERIFIABLE');error.__cause__=OSError(13,'private')
        with patch.object(supervisor.sys,'stdout',new_callable=io.StringIO) as output:
            with self.assertRaises(supervisor.ArtifactError) as caught:
                with supervisor.diagnostic_boundary('source-resolve'):raise error
        self.assertIs(caught.exception,error)
        value=diagnostics.supervisor_observation(output.getvalue().encode())
        self.assertEqual(value['parse_status'],'parsed');self.assertEqual(value['records'][0]['errno'],13)
        self.assertNotIn('private',output.getvalue());self.assertNotIn('UAS_ARTIFACT_SUPERVISOR:',output.getvalue())
        for failure in (OSError(32,'broken pipe'),KeyboardInterrupt(),SystemExit()):
            with patch('builtins.print',side_effect=failure),self.assertRaises(supervisor.ArtifactError) as caught:
                with supervisor.diagnostic_boundary('source-resolve'):raise error
            self.assertIs(caught.exception,error)

    def test_successful_boundary_has_no_extra_output(self):
        with patch('builtins.print') as output:
            with supervisor.diagnostic_boundary('source-resolve'):value=object()
        self.assertIsNotNone(value);output.assert_not_called()

    def test_complete_owned_stdout_retains_middle_record_before_sampling(self):
        raw=b'a'*700+b'\n'+self.wire(self.record())+b'z'*700
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'out';err=Path(directory)/'err'
            out.write_bytes(raw);err.write_bytes(b'traceback without actual errno')
            with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
                diagnostics.require_file_result('supervisor-alpha',1,out,err,output_limit=1<<20)
        value=caught.exception.document
        self.assertEqual(value['outcome'],'exit');self.assertEqual(value['returncode'],1)
        stream=value['stdout'];self.assertTrue(stream['truncated'])
        self.assertNotIn('errno',stream['head']+stream['tail'])
        record=stream['supervisor_observation']['records'][0]
        self.assertEqual((record['errno'],record['errno_depth']),(13,1))

    def test_strict_parser_rejects_unknown_fields_strings_types_and_duplicates(self):
        valid=self.record()
        variants=[{**valid,'private':'contents'},{**valid,'phase':'private-path'},
            {**valid,'code':'private-content'},{**valid,'errno':True},{**valid,'errno':4096},
            {**valid,'errno_depth':True},{**valid,'errno_depth':8},{**valid,'errno':None},
            {**valid,'chain_status':'private'},{**valid,'version':True}]
        raw=b''.join(self.wire(value) for value in variants)
        raw+=diagnostics.SUPERVISOR_PREFIX+b'{"version":1,"version":1}\n'
        raw+=diagnostics.SUPERVISOR_PREFIX+b'\xff\n'
        raw+=diagnostics.SUPERVISOR_PREFIX+b'x'*513+b'\n'
        value=diagnostics.supervisor_observation(raw)
        self.assertEqual(value['records'],[]);self.assertEqual(value['rejected_records'],len(variants)+3)
        self.assertNotIn('private',json.dumps(value));self.assertEqual(value['unretained_records'],0)
        for raw,reason in ((b'x','absent'),('not bytes','stream-type'),(b'x'*((1<<20)+1),'oversized')):
            self.assertEqual(diagnostics.supervisor_observation(raw),{'parse_status':'unavailable','reason':reason})

    def test_record_flood_retains_bounded_facts_and_aggregate_count_below_diagnostic_limit(self):
        wire=self.wire(self.record());count=(1<<20)//len(wire)
        value=diagnostics.supervisor_observation(wire*count)
        self.assertEqual(len(value['records']),diagnostics.MAX_SUPERVISOR_RECORDS)
        self.assertEqual(value['unretained_records'],count-diagnostics.MAX_SUPERVISOR_RECORDS)
        self.assertEqual(value['matched_records'],count);self.assertEqual(value['parse_status'],'partial')
        worst=diagnostics.stream_facts(b'\x00'*1000);worst['supervisor_observation']=value
        failure=diagnostics.FixtureCommandFailure('supervisor-alpha','exit',returncode=1,
            stdout=worst,stderr=diagnostics.stream_facts(b'\x00'*1000))
        self.assertLess(len(str(failure).encode()),diagnostics.MAX_DIAGNOSTIC_BYTES)

    def test_oversized_file_keeps_output_failure_and_does_not_read_whole_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'out';err=Path(directory)/'err'
            out.write_bytes(self.wire(self.record())+b'a'*(1<<20));err.write_bytes(b'')
            with patch.object(diagnostics.os,'read',wraps=os.read) as read:
                with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
                    diagnostics.require_file_result('supervisor-beta',1,out,err,output_limit=1<<20)
            self.assertLessEqual(sum(call.args[1] for call in read.call_args_list),1536)
        value=caught.exception.document;self.assertEqual(value['outcome'],'output')
        self.assertEqual(value['stdout']['supervisor_observation']['reason'],'oversized')

    def test_expected_negative_records_do_not_change_success_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'out';err=Path(directory)/'err'
            out.write_bytes(self.wire(self.record())+b'UAS_ARTIFACT_SUPERVISOR:{}\n');err.write_bytes(b'')
            self.assertIsNone(diagnostics.require_file_result('supervisor-alpha',0,out,err,output_limit=1<<20))

    def test_fixed_resolver_materializer_and_control_boundaries_are_wired(self):
        source=(VM/'artifact_supervisor.py').read_text()
        for phase in ('source-resolve','source-setup','target-setup','confinement-probes','supervisor-main'):
            self.assertIn("with diagnostic_boundary('"+phase+"'):",source)
        for command in ('resolve','current','prepare','start','finish','abort','reconcile'):
            self.assertIn("'"+command+"':'control-"+command+"'",source)
        self.assertIn('with diagnostic_boundary(phase):return invoke(command_,payload)',source)

    def test_explicit_resolver_materializer_vocabulary_and_producer_record_bound(self):
        import ast
        for relative in ('uas/artifact_target.py','uas/artifact_protocol.py'):
            module=ast.parse((VM.parent.parent/relative).read_text())
            for node in ast.walk(module):
                if (isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                        and node.func.id in ('ArtifactError','_fail') and node.args
                        and isinstance(node.args[0],ast.Constant) and type(node.args[0].value) is str):
                    self.assertIn(node.args[0].value,diagnostics.SUPERVISOR_CODES)
        for code in diagnostics.SUPERVISOR_CODES:
            value=self.record(supervisor.ArtifactError(code),phase='confinement-probes')
            self.assertLessEqual(len(self.wire(value)),diagnostics.MAX_SUPERVISOR_RECORD_BYTES)
        self.assertIn('ARTIFACT_PATH_TRAVERSAL_UNAVAILABLE',diagnostics.SUPERVISOR_CODES)


def state(kind,accounting,enforcement):
    return (kind+' quota state on /mnt/uas-artifacts (/dev/vdd)\n'
        +'  Accounting: '+accounting+'\n  Enforcement: '+enforcement+'\n')


class ParentQuotaFactsTests(unittest.TestCase):
    def test_exact_mount_root_type_and_device_are_observed_not_asserted(self):
        device=os.makedev(253,3)
        raw='42 31 253:3 / /mnt/uas-artifacts rw,nosuid,nodev - xfs /dev/vdd rw,prjquota\n'
        self.assertEqual(guest.quota_mount_identity(raw,device)['filesystem'],'xfs')
        for bad in (raw.replace('xfs','ext4'),raw.replace('253:3','253:4'),raw.replace(' / /mnt',' /sub /mnt'),
                    raw+raw,raw.replace('/mnt/uas-artifacts','/other')):
            with self.subTest(raw=bad),self.assertRaises(AssertionError):guest.quota_mount_identity(bad,device)

    def test_state_requires_exact_mount_single_actual_accounting_and_enforcement(self):
        valid=state('Project','ON','ON')
        self.assertEqual(guest.quota_state(valid,'Project'),{'accounting':True,'enforcement':True})
        self.assertFalse(guest.quota_state(state('User','OFF','OFF'),'User')['enforcement'])
        for bad in (valid+valid,valid.replace('/mnt/uas-artifacts','/other'),valid.replace('Project','User'),
                    valid.replace('Enforcement: ON','Enforcement: unknown')):
            with self.assertRaises(AssertionError):guest.quota_state(bad,'Project')

    def test_actual_hardlimit_softlimit_and_positive_headroom_not_inflated(self):
        self.assertEqual(guest.quota_hard_limit('#301 64 0 262144 00 [------]\n',301),
            {'used_bytes':65536,'soft_limit_bytes':0,'hard_limit_bytes':256<<20})
        for bad in ('#301 64 0 524288\n','#301 262144 0 262144\n','#301 64 10 262144\n',
                    '#303 64 0 262144\n','#301 64 0 262144\n#301 64 0 262144\n'):
            with self.assertRaises(AssertionError):guest.quota_hard_limit(bad,301)

    def observe(self,*,user_enforcement='OFF',hardlimit=262144,project_enforcement='ON'):
        device=os.makedev(253,3);node=SimpleNamespace(st_uid=0,st_dev=device,st_ino=99)
        mount=b'42 31 253:3 / /mnt/uas-artifacts rw - xfs /dev/vdd rw,prjquota\n'
        values={'state -u':state('User','OFF',user_enforcement),
                'state -g':state('Group','OFF','OFF'),
                'state -p':state('Project','ON',project_enforcement),
                'report -p -b -n -N':'#301 64 0 '+str(hardlimit)+'\n'}
        def capture(phase,args,**kwargs):
            self.assertEqual(args[:3],['xfs_quota','-x','-c'])
            self.assertEqual(args[-1],'/mnt/uas-artifacts');self.assertEqual(kwargs['timeout'],5)
            return subprocess.CompletedProcess(args,0,values[args[3]].encode(),b'')
        with patch.object(guest.os,'open',return_value=55),patch.object(guest.os,'close') as close, \
                patch.object(guest.os,'fstat',return_value=node),patch.object(guest.os,'stat',return_value=node), \
                patch.object(guest.os,'uname',return_value=SimpleNamespace(release='fixture-release')), \
                patch('builtins.open',return_value=io.BytesIO(mount)),patch.object(diagnostics,'captured',side_effect=capture):
            try:return guest.quota_facts('alpha')
            finally:close.assert_called_once_with(55)

    def test_parent_contract_generated_only_from_actual_observations(self):
        facts,evidence=self.observe()
        self.assertEqual(facts,{'version':1,'room':'alpha','project_id':301,'device':os.makedev(253,3),
            'hard_limit_bytes':256<<20,'accounting':True,'enforcement':True,'filesystem':'xfs',
            'user_enforcement':False,'group_enforcement':False})
        self.assertEqual(evidence['limits']['used_bytes'],65536)
        for changes in ({'user_enforcement':'ON'},{'project_enforcement':'OFF'},{'hardlimit':512<<10}):
            with self.subTest(changes=changes),self.assertRaises((AssertionError,diagnostics.FixtureCommandFailure)):
                self.observe(**changes)

    def test_guest_startup_does_not_import_uninstalled_diagnostic_module(self):
        import ast
        module=ast.parse((VM/'guest_artifacts.py').read_text())
        self.assertFalse(any(isinstance(node,ast.ImportFrom) and node.module=='artifact_diagnostics' for node in module.body))
        source=(VM/'guest_artifacts.py').read_text()
        self.assertLess(source.index('facts,before=quota_facts(room)'),source.index("captured('quota-'+room"))
        self.assertIn('after_facts==facts',source)
        self.assertIn("quota_exhaustion[room]['quota_facts']==facts",source)


if __name__=='__main__':unittest.main()
