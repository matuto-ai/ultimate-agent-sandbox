"""Local setup uses real private files, never credentials or host effects."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.local_installation import Installation, LocalInstallationError, document, selection


def native_selection(config):
    """Valid pure prepared-host selection for the existing two-Room fixture."""
    from test_local_native import selections
    from uas.local_native import LOCAL_HUB_COMMAND
    _,document=selections('/srv');document['rooms']={}
    for i,room in enumerate(config['rooms']):
        paths={**room['project']['roots'],'runtime':room['state_root']+'/runtime'}
        document['rooms'][room['id']]={'quota_project_id':401+i,'mcs_level':f's0:c{401+i*2},c{402+i*2}',
            'subnet':f'10.91.{i+1}.0/24','gateway':f'10.91.{i+1}.1','root_identity':[1,2],
            'paths':{k:{'path':p,'identity':[1,i*10+j+3]} for j,(k,p) in enumerate(paths.items())},
            'workstation':{'image_id':'sha256:'+'c'*64,'image_reference':'registry/ws@sha256:'+'d'*64},
            'hub':{'image_id':'sha256:'+'e'*64,'image_reference':'registry/hub@sha256:'+'f'*64,'entrypoint':LOCAL_HUB_COMMAND[:]}}
    return document


class LocalInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project.json'
        self.project.write_bytes((Path(__file__).parent/'fixtures/two-rooms.json').read_bytes())
        self.value = {'version':1, 'project':self.ref(self.project), 'native':None, 'manager':None}
        self.install = Installation(self.root/'install')

    def ref(self, p):
        return {'path':str(p), 'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}

    def raw(self): return json.dumps(self.value).encode()

    def test_setup_is_persistent_idempotent_and_account_free(self):
        self.assertEqual(self.install.setup(self.raw())['status'],'installed')
        saved=(self.install.root/'installation.json').read_bytes()
        self.assertEqual(Installation(self.install.root).setup(self.raw())['status'],'already-installed')
        self.assertEqual((self.install.root/'installation.json').read_bytes(),saved)
        result=self.install.status()
        self.assertEqual(result['native'],'not-configured')
        self.assertEqual(result['runtime'],'not-observed')
        self.assertEqual(result['isolation'],'not-verified')
        self.assertEqual(set(p.name for p in self.install.root.iterdir()),{'installation.json','installation.lock'})
        self.assertNotIn('credential',saved.decode())

    def test_changed_input_and_conflicting_setup_are_not_adopted(self):
        self.install.setup(self.raw()); before=(self.install.root/'installation.json').read_bytes()
        self.project.write_bytes(self.project.read_bytes()+b' ')
        with self.assertRaisesRegex(LocalInstallationError,'REFERENCE_DIGEST_MISMATCH'): self.install.open()
        self.value['project']=self.ref(self.project)
        with self.assertRaisesRegex(LocalInstallationError,'EXISTING_INSTALLATION_DIFFERS'):self.install.setup(self.raw())
        self.assertEqual((self.install.root/'installation.json').read_bytes(),before)

    def test_bad_inputs_do_not_create_installation(self):
        for raw in (b'{}',b'{"version":1,"version":1}',b'null'):
            with self.assertRaises(LocalInstallationError):self.install.setup(raw)
        self.assertFalse(self.install.root.exists())
        for change in ({'version':True},{'extra':'secret'},{'project':{'path':'relative','sha256':'a'*64}}):
            with self.assertRaises(LocalInstallationError):selection(json.dumps({**self.value,**change}).encode())

    def test_symlink_reference_and_existing_foreign_state_refuse(self):
        alias=self.root/'alias';alias.symlink_to(self.project)
        self.value['project']={'path':str(alias),'sha256':self.ref(self.project)['sha256']}
        with self.assertRaises(LocalInstallationError):self.install.setup(self.raw())
        self.value['project']=self.ref(self.project)
        self.install.root.mkdir(mode=0o700)
        (self.install.root/'installation.json').symlink_to(self.project)
        with self.assertRaises(OSError):self.install.setup(self.raw())
        self.assertTrue(self.project.exists())

    def test_partial_write_never_reports_success_or_overwrites_on_retry(self):
        with patch('uas.local_installation.os.fsync',side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):self.install.setup(self.raw())
        # Bytes are valid but durability was uncertain; inspecting them is safe.
        self.assertEqual(self.install.status()['runtime'],'not-observed')
        self.assertEqual(self.install.setup(self.raw())['status'],'already-installed')

    def test_manifest_reference_not_secret_contents_is_persisted(self):
        native=self.root/'native.json';selected=native_selection(json.loads(self.project.read_text()));native.write_text(json.dumps(selected))
        self.value['native']=self.ref(native)
        self.install.setup(self.raw())
        self.assertEqual(self.install.open()[2]['native'],selected)
        self.assertIn(str(native),(self.install.root/'installation.json').read_text())

    def test_invalid_native_profile_or_project_binding_before_state_creation(self):
        for wrong in ('schema','binding','rooms'):
            with self.subTest(wrong=wrong):
                value=native_selection(json.loads(self.project.read_text()))
                if wrong=='schema':value['version']=True
                elif wrong=='binding':value['rooms']['alpha']['paths']['repo']['path']='/srv/other-repo'
                else:del value['rooms']['beta']
                native=self.root/'native.json';native.write_text(json.dumps(value));self.value['native']=self.ref(native)
                with self.assertRaises(LocalInstallationError):self.install.setup(self.raw())
                self.assertFalse(self.install.root.exists())
    def test_manager_scope_and_schema_validated_without_tls_access(self):
        from uas.local_manager import ManagerSelection
        from uas.local_installation import canonical
        from uas.config import load
        from io import StringIO
        from test_local_manager import ManagerSelectionTests
        config=load(StringIO(self.project.read_text()))
        good=ManagerSelectionTests().value();good.update(deployment_id=config['deployment']['id'],room_id='alpha',
                configuration_sha256=hashlib.sha256(canonical(config)).hexdigest())
        manager=self.root/'manager.json'
        fd=os.open(manager,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
        for wrong in ('schema','scope','room','digest'):
            value=dict(good)
            if wrong=='schema':value['extra']='no'
            elif wrong=='scope':value['deployment_id']='foreign'
            elif wrong=='room':value['room_id']='foreign'
            else:value['configuration_sha256']='0'*64
            manager=self.root/'manager.json';manager.write_text(json.dumps(value));self.value['manager']=self.ref(manager)
            with self.assertRaises(ValueError):self.install.setup(self.raw())
            self.assertFalse(self.install.root.exists())
        manager.write_text(json.dumps(good));self.value['manager']=self.ref(manager)
        with patch.object(ManagerSelection,'tls_context',side_effect=AssertionError('no TLS access')):
            self.assertEqual(self.install.setup(self.raw())['status'],'installed')

    def manager_reference(self):
        from io import StringIO
        from uas.config import load
        from uas.local_installation import canonical
        from test_local_manager import ManagerSelectionTests
        config=load(StringIO(self.project.read_text()));value=ManagerSelectionTests().value()
        value.update(deployment_id=config['deployment']['id'],room_id='alpha',
                     configuration_sha256=hashlib.sha256(canonical(config)).hexdigest())
        target=self.root/'manager-choice.json'
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as out:json.dump(value,out)
        return self.ref(target)
    def test_explicit_manager_selection_preserves_project_native_and_is_idempotent(self):
        self.install.setup(self.raw());ref=self.manager_reference();before=self.install.open()[0]
        result=self.install.select_manager(ref);self.assertEqual(result['status'],'selected')
        after=self.install.open()[0]
        self.assertEqual(after,{**before,'manager':ref})
        self.assertEqual(self.install.select_manager(ref)['status'],'already-selected')
        self.assertEqual(self.install.select_manager(None)['status'],'selected')
        self.assertEqual(self.install.open()[0],before)
    def test_manager_selection_denied_while_host_lock_held(self):
        from uas.local_host import host_lock
        self.install.setup(self.raw());ref=self.manager_reference();before=(self.install.root/'installation.json').read_bytes()
        with host_lock(self.install):
            with self.assertRaisesRegex(LocalInstallationError,'LOCAL_HOST_ALREADY_ACTIVE'):
                self.install.select_manager(ref)
        self.assertEqual((self.install.root/'installation.json').read_bytes(),before)
    def test_invalid_manager_selection_changes_nothing(self):
        self.install.setup(self.raw());before=(self.install.root/'installation.json').read_bytes()
        ref=self.manager_reference();target=Path(ref['path']);target.write_text('{"version":1}')
        with self.assertRaises(LocalInstallationError):self.install.select_manager(self.ref(target))
        self.assertEqual((self.install.root/'installation.json').read_bytes(),before)
    def test_manager_selection_directory_sync_failure_reconciles_without_rewrite(self):
        self.install.setup(self.raw());ref=self.manager_reference()
        with patch('uas.local_installation.os.fsync',side_effect=[None,OSError('directory sync')]) as sync:
            with self.assertRaisesRegex(LocalInstallationError,'MANAGER_SELECTION_DURABILITY_UNCONFIRMED'):
                self.install.select_manager(ref)
            self.assertEqual(sync.call_count,2)
        self.assertEqual(self.install.open()[0]['manager'],ref)
        self.assertEqual(list(self.install.root.glob('.manager-selection-*')),[])
    def test_manager_selection_pre_replace_failure_keeps_old_bytes(self):
        self.install.setup(self.raw());ref=self.manager_reference();before=(self.install.root/'installation.json').read_bytes()
        with patch('uas.local_installation.os.replace',side_effect=OSError('replace failed')) as replace:
            with self.assertRaisesRegex(LocalInstallationError,'MANAGER_SELECTION_NOT_REPLACED'):
                self.install.select_manager(ref)
            replace.assert_called_once()
        self.assertEqual((self.install.root/'installation.json').read_bytes(),before)
        self.assertEqual(list(self.install.root.glob('.manager-selection-*')),[])

    def runtime_reference(self):
        from test_native_qualification import NativeQualificationTests
        source=NativeQualificationTests();source.setUp()
        self.project.write_text(json.dumps(source.config));self.value['project']=self.ref(self.project)
        native=self.root/'native.json';native.write_text(json.dumps(native_selection(source.config)))
        self.value['native']=self.ref(native)
        value={'version':1,'profile':'local-runtime-v1','room_id':'alpha','installation_id':'a'*32,
               'human_mergers':[7],**{k+'_manifest':{'path':'/installation/'+k+'.json','sha256':'b'*64}
                                   for k in ('pi','claude','broker')}}
        target=self.root/'runtime-choice.json';fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as out:json.dump(value,out)
        return self.ref(target)
    def test_optional_runtime_selection_is_backward_compatible_and_bound_before_create(self):
        from uas.local_native import LocalNativeHost
        ref=self.runtime_reference();self.install.setup(self.raw());before=self.install.open()[0]
        self.assertNotIn('runtime',before)
        self.assertEqual(self.install.select_runtime('alpha',ref)['status'],'selected')
        value,config,selected=self.install.open()
        self.assertEqual(value['project'],before['project']);self.assertEqual(value['native'],before['native'])
        self.assertEqual(value['manager'],before['manager']);self.assertEqual(value['runtime'],{'alpha':ref})
        native=LocalNativeHost(config,selected['native'],config['deployment']['state_root'],
            authorize=lambda *_:True,revoke=lambda *_:False,runtimeplans={'alpha':self.install.runtime_plan_for})
        from uas.lifecycle import Supervisor
        def root_constructor(*args,**kwargs):
            with patch('uas.lifecycle.os.geteuid',return_value=0):return Supervisor(*args,**kwargs)
        with patch('uas.local_native.Supervisor',side_effect=root_constructor):
            owner,backend=native._owner('alpha')
        plan=backend.profile.runtime_plan
        self.assertIs(plan.native_profile,backend.profile)
        self.assertEqual(plan.installation_digest,ref['sha256'])
        self.assertNotEqual(backend.profile.spec().profile_digest,'sha256:'+backend.profile.digest)
        self.assertIs(self.install.runtime_plan_for(backend.profile),plan)
        self.assertEqual(self.install.select_runtime('alpha',ref)['status'],'already-selected')
    def test_runtime_reconfiguration_after_instance_creation_is_refused_before_write(self):
        ref=self.runtime_reference();self.install.setup(self.raw());before=(self.install.root/'installation.json').read_bytes()
        original=os.path.lexists
        with patch('uas.local_installation.os.path.lexists',side_effect=lambda p: True if str(p).endswith('/lifecycle.json') else original(p)):
            with self.assertRaisesRegex(LocalInstallationError,'UNCREATED_ROOM'):
                self.install.select_runtime('alpha',ref)
        self.assertEqual((self.install.root/'installation.json').read_bytes(),before)
    def test_runtime_selection_unknown_room_or_missing_native_rejected(self):
        ref=self.runtime_reference();self.value['native']=None;self.value['runtime']={'alpha':ref}
        with self.assertRaisesRegex(LocalInstallationError,'LOCAL_RUNTIME_NATIVE_REQUIRED'):self.install.setup(self.raw())
        self.assertFalse(self.install.root.exists())
