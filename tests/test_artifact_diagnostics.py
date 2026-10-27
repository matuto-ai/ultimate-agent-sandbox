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
