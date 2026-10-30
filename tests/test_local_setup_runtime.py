"""Descriptor composition invokes canonical validators, not a new runtime."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uas import local_setup_runtime as subject
from uas.local_host_profile import canonical,HostProfileError
from uas.native_qualification import QualificationError
from tests.test_local_runtime_plan import LocalRuntimePlanTests

class RuntimeHandoffTests(unittest.TestCase):
    def setUp(self):
        self.f=LocalRuntimePlanTests();self.f.setUp()
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.write('project.json',self.f.input_config);self.write('native.json',self.f.doc)
        self.write('installation-selection.json',{'version':1,'project':self.ref('project.json'),'native':self.ref('native.json'),'manager':None})
        for name in ('pi','claude'):
            self.write(name+'.json',self.f.manifests[name]);self.write(name+'-reference.json',self.ref(name+'.json'))
        self.write('broker.json',self.f.broker)
    def write(self,name,value):(self.root/name).write_bytes(canonical(value))
    def ref(self,name):return {'path':str(self.root/name),'sha256':hashlib.sha256((self.root/name).read_bytes()).hexdigest()}
    def stack(self):
        stack=ExitStack()
        reader=lambda p,h:json.loads(subject._read_reference({'path':p,'sha256':h}))
        stack.enter_context(patch('uas.local_runtime_plan.read_manifest',side_effect=reader))
        stack.enter_context(patch('uas.native_qualification.read_manifest',side_effect=reader))
        return stack
    def run_prepare(self,**extra):
        return subject.prepare_runtime(str(self.root),room_id='alpha',broker_manifest=str(self.root/'broker.json'),human_mergers=[7],**extra)
    def test_real_validators_emit_pinned_descriptor_without_opening_secrets(self):
        seen=[];original=subject.read_file
        def reader(p):seen.append(str(p));return original(p)
        with self.stack(),patch.object(subject,'read_file',side_effect=reader):result=self.run_prepare()
        self.assertEqual(result['status'],'runtime-descriptor-prepared')
        ref=json.loads(Path(result['reference']).read_bytes());value=json.loads(subject._read_reference(ref))
        self.assertEqual(value['room_id'],'alpha');self.assertEqual(value['human_mergers'],[7])
        self.assertNotIn(self.f.broker['credential_path'],seen)
        self.assertEqual(value['pi_manifest'],self.ref('pi.json'))
        from uas.local_installation import Installation
        installation=json.loads((self.root/'installation-selection.json').read_bytes())
        installation['runtime']={'alpha':ref}
        with self.stack(),patch('uas.local_installation.read_reference',side_effect=subject._read_reference):
            config,selected=Installation.inspect(installation)
        self.assertEqual(selected['runtime']['alpha'],ref)
    def test_missing_or_bad_broker_never_creates_output(self):
        self.write('broker.json',{'version':1})
        with self.stack(),self.assertRaisesRegex(HostProfileError,'BROKER_INSTALLATION_UNAVAILABLE'):self.run_prepare()
        self.assertFalse((self.root/'runtime-alpha').exists())
    def test_payload_mismatch_and_pairing_rejected_before_write(self):
        self.f.manifests['pi']['image_id']='sha256:'+'0'*64
        self.write('pi.json',self.f.manifests['pi']);self.write('pi-reference.json',self.ref('pi.json'))
        with self.stack(),self.assertRaisesRegex(HostProfileError,'PI_IMAGE_MANIFEST_UNAVAILABLE'):self.run_prepare()
        self.assertFalse((self.root/'runtime-alpha').exists())
    def test_multiple_rooms_require_choice_and_no_git_half_pair(self):
        with self.assertRaisesRegex(HostProfileError,'ROOM_REQUIRED'):
            subject.prepare_runtime(str(self.root),broker_manifest=str(self.root/'broker.json'),human_mergers=[7])
        with self.stack(),self.assertRaisesRegex(QualificationError,'RESOURCE_SELECTION'):
            self.run_prepare(git_manifest=str(self.root/'broker.json'))
        self.assertFalse((self.root/'runtime-alpha').exists())
    def test_repeat_output_not_overwritten(self):
        with self.stack():
            result=self.run_prepare();before=Path(result['reference']).read_bytes()
            with self.assertRaisesRegex(ValueError,'output must not exist'):self.run_prepare()
        self.assertEqual(Path(result['reference']).read_bytes(),before)
