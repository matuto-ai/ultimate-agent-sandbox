"""Pure partial-evidence reduction; no native fixture execution or discovery."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

VM=Path(__file__).parent/'vm'
spec=importlib.util.spec_from_file_location('artifact_progress_diagnostics',VM/'artifact_diagnostics.py')
diagnostics=importlib.util.module_from_spec(spec);spec.loader.exec_module(diagnostics)


class ArtifactProgressTests(unittest.TestCase):
    def wire(self,value):
        return diagnostics.PROGRESS_PREFIX+json.dumps(value).encode()+b'\n'

    def hub(self,raw=b'{}'):
        return {'version':1,'kind':'hub-terminal','room':'alpha',
            'report_sha256':hashlib.sha256(raw).hexdigest(),'report_bytes':len(raw)}

    def probe(self,kind='N'):
        return {'version':1,'kind':'probe-exit','room':'alpha','probe':kind,
            'running':False,'exit_code':126,'expected_exit':159,'elapsed_ms':45}

    def test_mismatch_actual_expected_and_prior_hub_survive_middle_sampling(self):
        data=b'a'*1000+b'\n'+self.wire(self.hub())+self.wire(self.probe())+b'z'*1000
        result=diagnostics.progress_observation(data)
        self.assertEqual(result,{'hub':self.hub(),'probes':[self.probe()],'rejected':0})
        self.assertNotIn('expected_exit',diagnostics.stream_facts(data)['head'])
        self.assertNotIn('expected_exit',diagnostics.stream_facts(data)['tail'])

    def test_rejects_arbitrary_strings_duplicate_fields_and_bounds(self):
        variants=[{**self.probe(),'probe':'secret'},{**self.probe(),'exit_code':True},
            {**self.probe(),'elapsed_ms':-1},{**self.hub(),'report_sha256':'secret'},
            {**self.hub(),'private':'secret'}]
        raw=b''.join(self.wire(item) for item in variants)+diagnostics.PROGRESS_PREFIX+b'{"version":1,"version":1}\n'
        result=diagnostics.progress_observation(raw)
        self.assertEqual(result,{'hub':None,'probes':[],'rejected':6})
        self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(1,diagnostics.progress_observation(b'x'*((1<<20)+1))['rejected'])

    def test_duplicate_records_remain_bounded_without_replacing_first_facts(self):
        result=diagnostics.progress_observation(self.wire(self.hub())*200+self.wire(self.probe())*200)
        self.assertEqual(398,result['rejected']);self.assertEqual([self.probe()],result['probes'])
        self.assertLess(len(json.dumps(result)),1024)

    def test_partial_hub_outcomes_require_exact_authenticated_report_digest(self):
        raw=json.dumps({'room_id':'alpha','results':[{'scenario':'present',
            'evaluation':{'result':{'verdict':'passed','arbitrary':'not exported'}}},
            {'scenario':'missing','evaluation':{'result':{'verdict':'failed'}}}]}).encode()
        value=diagnostics.partial_hub_results(raw,self.hub(raw))
        self.assertEqual({'present':'passed','missing':'failed'},value['results'])
        self.assertFalse(value['qualification_complete']);self.assertNotIn('arbitrary',json.dumps(value))
        for bad in (raw+b' ',raw.replace(b'alpha',b'other')):
            with self.assertRaises(ValueError):diagnostics.partial_hub_results(bad,self.hub(raw))

    def test_every_known_probe_fits_existing_failure_budget(self):
        raw=self.wire(self.hub())+b''.join(self.wire(self.probe(kind)) for kind in diagnostics.PROBE_KINDS)
        value=diagnostics.progress_observation(raw)
        self.assertEqual(13,len(value['probes']))
        self.assertLess(len(json.dumps(value,separators=(',',':'))),4096)
        stdout=diagnostics.stream_facts(b'\0'*1000)
        stdout['progress_observation']=value
        class KnownError(RuntimeError):code='ARTIFACT_SOURCE_UNVERIFIABLE'
        failure=diagnostics.supervisor_failure('confinement-probes',KnownError(),KnownError)
        stdout['supervisor_observation']=diagnostics.supervisor_observation(
            (diagnostics.SUPERVISOR_PREFIX+json.dumps(failure).encode()+b'\n')*8)
        mount=diagnostics.mount_failure('inspect-mounts',{'Mounts':[
            {'Destination':'unknown-'+str(n),'Type':'volume','RW':True} for n in range(8)],
            'HostConfig':{'Tmpfs':{'unknown-'+str(n):'bad' for n in range(4)}}},{},'none')
        stdout['mount_observation']=diagnostics.mount_observation(
            diagnostics.MOUNT_PREFIX+json.dumps(mount).encode()+b'\n')
        error=diagnostics.FixtureCommandFailure('supervisor-alpha','exit',returncode=1,
            stdout=stdout,stderr=diagnostics.stream_facts(b'\0'*1000))
        self.assertLess(len(str(error).encode()),diagnostics.MAX_DIAGNOSTIC_BYTES)

    def test_native_source_persists_before_decisive_assertion_and_probe_launch(self):
        source=(VM/'artifact_supervisor.py').read_text()
        self.assertLess(source.index("'state':'observed-exit'"),source.index("expect(terminal['Running'] is False"))
        self.assertLess(source.index("journal/'hub-terminal.json'"),source.index("native_probes=confinement_probes"))
        guest=(VM/'guest_artifacts.py').read_text()
        self.assertLess(guest.index("print('UAS_ARTIFACT_PARTIAL_HUB:'"),guest.index("require_file_result('supervisor-'+room"))
        self.assertIn("'progress_observation']=progress_observation(data)",(VM/'artifact_diagnostics.py').read_text())
