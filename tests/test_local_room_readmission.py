"""Actual Room receipts/markers across a modeled authenticated remount."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from tests import test_local_room_prepare as room_fixtures
from tests.test_local_host_plan import profile,observation
from uas import local_room_prepare as prepare
from uas.local_host_plan import plan
from uas.local_host_receipt import PreparationReceipt
from uas.local_host_profile import HostProfileError
ACTUAL_INVENTORY=prepare.observed_engine_allocations

class ReadmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture=room_fixtures.RoomPreparationTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        t=self.fixture;f=t.fixture
        host=patch('uas.local_room_prepare.apply_host',lambda *a,**k:None);host.start();self.addCleanup(host.stop)
        inventory=patch('uas.local_room_prepare.observed_engine_allocations',lambda *a,**k:{'levels':set(),'networks':set()});inventory.start();self.addCleanup(inventory.stop)
        receipt=f.root/'hostreceipts';receipt.mkdir(mode=0o700)
        observed=observation();observed['storage'].update(path=str(f.root),identity=[f.root.stat().st_dev,f.root.stat().st_ino],filesystem='btrfs')
        t.host=plan(profile(),observed,storage_root=str(f.storage),endpoints_root=str(t.endpoints),receipt_root=str(receipt),allocation_bytes=1024**3)
        t.settings.update(version=2,host_profile=profile())
        t.value=prepare.request(t.host,t.config,t.settings,t.ws,t.hub)
        with PreparationReceipt(receipt,t.host,owner_uid=0):pass
        self.owned={'receipt_root':str(receipt),'plan_id':t.host['plan_id'],'image_identity':[8,9],'uuid':'11111111-1111-1111-1111-111111111111'}
        for name,fn in [('selection',lambda _:self.owned),('verify_owned_mount',lambda *a:{'identity':[f.storage.stat().st_dev,f.storage.stat().st_ino],'image_identity':[8,9]})]:
            p=patch('uas.local_xfs_storage.'+name,fn);p.start();self.addCleanup(p.stop)

    def test_completed_setup_readmits_new_live_device_without_mutation(self):
        t=self.fixture;f=t.fixture
        first=prepare.apply(t.value)
        self.assertEqual(first['native']['version'],3)
        effects=len(f.calls)
        inodes={f.real_stat(p).st_ino for p in [f.storage,*f.storage.rglob('*')]}
        original_stat=f.fake_stat;original_fstat=f.fake_fstat
        def remap(info):
            if info.st_ino not in inodes:return info
            values=list(info);values[2]=info.st_dev+100;return os.stat_result(values)
        f.fake_stat=lambda *a,**k:remap(original_stat(*a,**k))
        f.fake_fstat=lambda *a,**k:remap(original_fstat(*a,**k))
        with patch('os.stat',f.fake_stat),patch('os.fstat',f.fake_fstat):
            second=prepare.apply(t.value,readmission=True)
        self.assertEqual(first,second)
        later=f.calls[effects:]
        self.assertFalse(any(a[0]=='/usr/bin/chcon' or (a[0]=='/usr/sbin/xfs_quota' and a[-2].startswith(('limit ','project -s '))) for a in later))

    def test_foreign_engine_collision_still_blocks_readmission(self):
        t=self.fixture;prepare.apply(t.value)
        for allocation,error in [({'levels':{'s0:c200,c201'},'networks':set()},'MCS_COLLISION'),
                ({'levels':set(),'networks':{'10.91.1.0/24'}},'NETWORK_COLLISION')]:
            with patch.object(prepare,'observed_engine_allocations',return_value=allocation) as inventory:
                with self.assertRaisesRegex(HostProfileError,error):prepare.apply(t.value,readmission=True)
                self.assertEqual(inventory.call_args.kwargs['owned_ids'],{'container':set(),'network':set()})

    def test_prepare_bind_persist_remount_readmit_keeps_real_runtime_spec(self):
        import json
        from io import StringIO
        from uas.config import load
        from uas.local_native import LocalNativeProfile,LocalNativeBackend
        from uas.local_runtime_plan import LocalRuntimePlan
        from uas.lifecycle import Supervisor
        from uas.native_qualification_backend import names
        from lifecycle_support import FileFixtureBackend
        t=self.fixture;f=t.fixture
        for agent,provider in zip(('pi','claude'),t.config['deployment']['providers']):
            provider.pop('endpoint',None)
            provider['model']='selected-model'
            provider['auth']={'credential_ref':agent+'-runtime','method':'pi-oauth-json' if agent=='pi' else 'claude-oauth-token'}
            t.config['deployment']['credentials'].append({'id':agent+'-runtime','kind':'runtime-provider'})
        t.config['deployment']['actors'][1]['github_user_id']=8
        raw=json.dumps(t.config);t.config=load(StringIO(raw))
        t.value=prepare.request(t.host,t.config,t.settings,t.ws,t.hub)
        first=prepare.apply(t.value)
        def runtime(profile):
            selection={'version':1,'profile':'local-runtime-v1','room_id':profile.room['id'],
                'installation_id':profile.nonce,'human_mergers':[7],
                **{k+'_manifest':{'path':'/installation/'+k+'.json','sha256':'a'*64} for k in ('pi','claude','broker')}}
            return LocalRuntimePlan(raw,selection,installation_digest='f'*64,native_profile=profile)
        profile=LocalNativeProfile(t.config,first['native'],'alpha',t.config['deployment']['state_root'])
        profile.bind_runtime(runtime(profile))
        disk=FileFixtureBackend(f.root/'engine-records')
        owner=Supervisor(t.config['deployment']['state_root'],'alpha',disk,authorize=lambda *_:True,revoke=disk.revoke)
        owner.start(profile.spec())
        with owner._locked():state=owner._read()
        def command(backend,args,**kwargs):
            if args[:2]==['network','ls']:return names(state)[0]
            if args[:2]==['network','inspect']:
                return json.dumps([{'Id':'3'*64,'Name':names(state)[0],'Labels':backend._labels(state,'network'),
                    'IPAM':{'Config':[{'Subnet':profile.subnet,'Gateway':profile.gateway}]}}])
            kind=args[2];name=args[3]
            if kind=='volume':return json.dumps([{'Name':name,'Labels':backend._labels(state,'volume')}])
            hub=name.endswith('-hub')
            return json.dumps([{'Id':('2' if hub else '1')*64,'Name':name,'Config':{'Labels':backend._labels(state,'hub' if hub else 'container')},'State':{'Running':False}}])
        def inventory(args,**kwargs):
            if 'ps' in args:return '1'*64+'\n'+'2'*64
            if args[3:5]==['network','ls']:return '3'*64
            return '\n'.join(json.dumps({'id':i,'value':['system_u:system_r:container_t:'+profile.level,'system_u:object_r:container_file_t:'+profile.level] if args[3]=='container' else [{'Subnet':profile.subnet}]}) for i in args[7:])
        inodes={f.real_stat(p).st_ino for p in [f.storage,*f.storage.rglob('*')]}
        previous_stat=f.fake_stat;previous_fstat=f.fake_fstat
        def remap(info):
            if info.st_ino not in inodes:return info
            values=list(info);values[2]+=100;return os.stat_result(values)
        f.fake_stat=lambda *a,**k:remap(previous_stat(*a,**k));f.fake_fstat=lambda *a,**k:remap(previous_fstat(*a,**k))
        with patch('os.stat',f.fake_stat),patch('os.fstat',f.fake_fstat),patch.object(LocalNativeBackend,'_run',command),patch.object(prepare,'observed_engine_allocations',ACTUAL_INVENTORY),patch.object(prepare,'run_fixed',side_effect=inventory):
            with self.assertRaisesRegex(Exception,'LIFECYCLE_BINDING'):
                prepare.apply(t.value,readmission=True)
            second=prepare.apply(t.value,readmission=True,runtime_plan_for=runtime)
        self.assertEqual(first,second)
        with owner._locked():self.assertEqual(owner._read()['spec'],state['spec'])

    def test_readmission_refuses_incomplete_setup_without_new_room_effect(self):
        with self.assertRaisesRegex(HostProfileError,'PREPARED_REQUIRED'):
            prepare.apply(self.fixture.value,readmission=True)
        self.assertEqual(self.fixture.fixture.calls,[])


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_metadata_must_live_outside_owned_storage(self):
        from uas.local_installation import Installation,LocalInstallationError
        native={'version':3,'storage_root':'/owned/storage'}
        value={'project':{'path':'/config/project.json'},'native':{'path':'/config/native.json'}}
        Installation('/config/install')._bootstrap_paths(value,native)
        with self.assertRaisesRegex(LocalInstallationError,'BOOTSTRAP_INSIDE'):
            Installation('/owned/storage/install')._bootstrap_paths(value,native)
        value['native']['path']='/owned/storage/native.json'
        with self.assertRaisesRegex(LocalInstallationError,'BOOTSTRAP_INSIDE'):
            Installation('/config/install')._bootstrap_paths(value,native)

    def test_host_readmits_before_constructing_helpers(self):
        from contextlib import nullcontext
        from unittest.mock import Mock
        from uas import local_cli
        events=[];native={'version':3};config={'rooms':[]}
        installation=Mock();installation.bootstrap.return_value=({},config,{'native':native})
        services=Mock();services.rooms=();services.close.return_value=True
        controller=Mock();controller.native=None
        with patch.object(local_cli,'host_lock',return_value=nullcontext(12)),patch.object(prepare,'readmit_document',side_effect=lambda *a,**k:events.append('readmit')) as readmit,patch('uas.local_services.LocalServices',side_effect=lambda *a,**k:events.append('helpers') or services),patch('uas.local_manager_owner.ManagerOwner'),patch('uas.local_library.open_library',return_value=None),patch.object(local_cli,'LocalController',return_value=controller),patch.object(local_cli,'serve'),patch.object(local_cli.signal,'signal'):
            local_cli.run_host(installation)
        self.assertEqual(events,['readmit','helpers']);readmit.assert_called_once_with(config,native,runtime_plan_for=installation.runtime_plan_for)
