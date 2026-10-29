"""Read-only metadata observation and exclusive scaffold files; no host effects."""
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas import local_prepare as local
from uas.local_installation import Installation
from uas.lifecycle import LifecycleError
from uas.native_image_package import payload, inventory
from uas.native_hub_image import source_inventory, BINARIES, validate_payload


class LocalPrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.data=self.root/'data';self.data.mkdir()
        text=(Path(__file__).parent/'fixtures/two-rooms.json').read_text().replace('/srv',str(self.data))
        self.project=json.loads(text);self.image='sha256:'+'a'*64
        self.project['deployment']['images'][0]['reference']=self.image
        self.project_file=self.root/'project.json';self.write(self.project_file,self.project)
        self.settings={'version':1,'installation_id':'b'*32,'storage_root':str(self.data),
            'endpoints_root':str(self.root/'endpoints'),'engine_version':'29.8.2',
            'mapping':{'offset':100000,'size':65536},'rooms':{}}
        for i,room in enumerate(self.project['rooms']):
            for name in [*room['project']['roots'].values(),room['state_root']+'/runtime']:Path(name).mkdir(parents=True)
            self.settings['rooms'][room['id']]={'quota_project_id':401+i,'mcs_level':f's0:c{401+i*2},c{402+i*2}',
                    'subnet':f'10.91.{i+1}.0/24','gateway':f'10.91.{i+1}.1'}
        (self.root/'endpoints').mkdir()
        self.settings_file=self.root/'settings.json';self.write(self.settings_file,self.settings)
        self.revision='c'*40
        self.ws=self.root/'workstation';self.hub=self.root/'hub'
        for directory,hub in ((self.ws,False),(self.hub,True)):
            (directory/'artifacts').mkdir(parents=True)
            report={'version':1,'source_revision':self.revision,'status':'passed','stage':'complete',
                    'build_execution':'completed','container_cleanup':'complete','image_id':'sha256:'+'d'*64 if hub else self.image,
                    'retained_artifacts':{},'native_payloads':{},'selection':{'python_version':'3.11.2'}}
            values={}
            if hub:
                sources=source_inventory(Path(__file__).resolve().parents[1])
                values['hub']={'version':1,'profile':'fixed-hub-v1','python_version':'3.11.2',
                    'artifacts':{**sources,**dict.fromkeys(BINARIES,'e'*64)}}
            else:
                values={name:payload(name,dict.fromkeys(inventory(name),'e'*64)) for name in ('pi','claude')}
            for name,value in values.items():
                filename=name+'-payload.json';raw=local.canonical(value)
                (directory/'artifacts'/filename).write_bytes(raw)
                digest=hashlib.sha256(raw).hexdigest()
                if hub:
                    report['hub_payload']=validate_payload(value,sources,'3.11.2',
                        lambda path:{'sha256':value['artifacts'][path]})
                    report.pop('retained_artifacts',None)
                    report.pop('native_payloads',None)
                else:
                    report['retained_artifacts'][filename]={'sha256':digest,'size':len(raw)}
                    report['native_payloads'][name]={'manifest_sha256':digest,'artifact_count':len(value['artifacts'])}
            self.write(directory/'report.json',report)
        self.output=self.root/'prepared'
    def write(self,path,value):path.write_bytes(local.canonical(value))
    def prepare(self):return local.prepare(self.project_file,self.settings_file,self.ws,self.hub,self.revision,self.output)
    def test_complete_roundtrip_real_inode_identity_refs_and_distinct_digests(self):
        result=self.prepare();self.assertEqual(result['status'],'prepared-metadata')
        descriptor=json.loads((self.output/'native.json').read_text())
        for room in self.project['rooms']:
            actual=Path(room['project']['roots']['repo']).stat()
            self.assertEqual(descriptor['rooms'][room['id']]['paths']['repo']['identity'],[actual.st_dev,actual.st_ino])
        selection=(self.output/'installation-selection.json').read_bytes()
        self.assertEqual(Installation(self.root/'install').setup(selection)['status'],'installed')
        handoff=json.loads((self.output/'handoff.json').read_text())
        self.assertNotEqual(handoff['configuration_sha256'],handoff['project_file_sha256'])
        for name in ('pi','claude'):
            ref=json.loads((self.output/(name+'-reference.json')).read_text());raw=Path(ref['path']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),ref['sha256'])
            self.assertEqual(json.loads(raw)['image_reference'],self.image)
    def test_old_or_failed_report_and_mutated_artifact_leave_no_output(self):
        original=(self.hub/'report.json').read_bytes()
        for key,value in [('status','failed'),('source_revision','0'*40),('build_execution','unknown-daemon-outcome'),('container_cleanup','failed')]:
            report=json.loads(original);report[key]=value;self.write(self.hub/'report.json',report)
            with self.assertRaises(ValueError):self.prepare()
            self.assertFalse(self.output.exists())
        (self.hub/'report.json').write_bytes(original)
        (self.hub/'artifacts/hub-payload.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'exact Hub payload'):self.prepare()
        self.assertFalse(self.output.exists())
    def test_missing_directory_and_symlink_ancestors_never_invent_identity(self):
        missing=str(self.root/'missing')
        with self.assertRaises(OSError):local.directory_identity(missing)
        alias=self.root/'alias';alias.symlink_to(self.data,target_is_directory=True)
        with self.assertRaises(OSError):local.directory_identity(str(alias))
        with self.assertRaises(OSError):local.directory_identity(str(alias/'projects/alpha/repo'))
    def test_all_rooms_and_current_image_are_required_no_implicit_config_edit(self):
        self.settings['rooms'].pop('beta');self.write(self.settings_file,self.settings)
        with self.assertRaises(ValueError):self.prepare()
        self.assertFalse(self.output.exists())
        self.project['deployment']['images'][0]['reference']='sha256:'+'0'*64;self.write(self.project_file,self.project)
        before=self.project_file.read_bytes()
        with self.assertRaisesRegex(ValueError,'update explicit Project'):self.prepare()
        self.assertEqual(self.project_file.read_bytes(),before)
    def test_existing_output_and_partial_failure_are_not_overwritten(self):
        self.output.mkdir();marker=self.output/'keep';marker.write_text('human')
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(marker.read_text(),'human');marker.unlink();self.output.rmdir()
        with patch('uas.local_prepare.os.fsync',side_effect=OSError('uncertain')):
            with self.assertRaises(OSError):self.prepare()
        self.assertTrue(self.output.exists());before=(self.output/'native.json').read_bytes()
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual((self.output/'native.json').read_bytes(),before)
    def test_quota_and_mcs_declarations_are_validated_not_repaired(self):
        self.settings['rooms']['beta']['quota_project_id']=self.settings['rooms']['alpha']['quota_project_id']
        self.write(self.settings_file,self.settings)
        with self.assertRaises(LifecycleError):self.prepare()
        self.assertFalse(self.output.exists())

    def test_old_hub_payload_without_persistent_module_rejected_even_if_report_hashes_match(self):
        target=self.hub/'artifacts/hub-payload.json';value=json.loads(target.read_text())
        del value['artifacts']['/opt/uas/uas/local_hub.py'];raw=local.canonical(value);target.write_bytes(raw)
        digest=hashlib.sha256(raw).hexdigest();report=json.loads((self.hub/'report.json').read_text())
        report['hub_payload']['manifest_sha256']=digest;self.write(self.hub/'report.json',report)
        with self.assertRaisesRegex(ValueError,'exact checked-out implementation'):self.prepare()
        self.assertFalse(self.output.exists())

    def test_documented_cli_roundtrip(self):
        stdout=StringIO()
        with redirect_stdout(stdout):
            status=local.main(['--project',str(self.project_file),'--settings',str(self.settings_file),
                '--workstation-output',str(self.ws),'--hub-output',str(self.hub),
                '--source-revision',self.revision,'--output-directory',str(self.output)])
        self.assertEqual(status,0)
        self.assertEqual(json.loads(stdout.getvalue())['status'],'prepared-metadata')
        selection=(self.output/'installation-selection.json').read_bytes()
        self.assertEqual(Installation(self.root/'install-cli').setup(selection)['status'],'installed')

    def test_endpoints_must_exist_and_not_be_symlink(self):
        endpoint=self.root/'endpoints';endpoint.rmdir()
        with self.assertRaises(OSError):self.prepare()
        self.assertFalse(self.output.exists())
        endpoint.symlink_to(self.data,target_is_directory=True)
        with self.assertRaises(OSError):self.prepare()
        self.assertFalse(self.output.exists())

    def test_unsafe_parent_rejected_before_creation(self):
        actual=local.os.fstat;identity=self.root.stat()
        def unsafe(fd):
            value=actual(fd)
            if (value.st_dev,value.st_ino)==(identity.st_dev,identity.st_ino):
                return SimpleNamespace(st_mode=value.st_mode|0o002,st_uid=value.st_uid)
            return value
        with patch('uas.local_prepare.os.fstat',side_effect=unsafe):
            with self.assertRaisesRegex(ValueError,'unsafe output parent'):self.prepare()
        self.assertFalse(self.output.exists())

    def test_replaced_output_keeps_writes_on_held_directory_and_refuses_success(self):
        actual=local.os.open;retained=self.root/'retained';replaced=False
        def replace(path,flags,*args,**kwargs):
            nonlocal replaced
            if path=='native.json' and not replaced:
                replaced=True;self.output.rename(retained);self.output.mkdir()
            return actual(path,flags,*args,**kwargs)
        with patch('uas.local_prepare.os.open',side_effect=replace):
            with self.assertRaisesRegex(ValueError,'output pathname changed'):self.prepare()
        self.assertEqual(list(self.output.iterdir()),[])
        self.assertTrue((retained/'native.json').is_file())
        self.assertTrue((retained/'handoff.json').is_file())
        with self.assertRaises(ValueError):self.prepare()
