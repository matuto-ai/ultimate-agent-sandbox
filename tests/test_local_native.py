"""Account-free persistent profile and canonical-owner controlled tests."""
from contextlib import ExitStack, nullcontext
from types import SimpleNamespace as N
import json
import stat
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uas import local_native as local
from uas.lifecycle import BackendUnknown, LifecycleError
from lifecycle_support import FileFixtureBackend


def selections(root='/srv/uas'):
    roots={k:root+'/project/'+k for k in ('repo','workspace','reference','checkouts')}
    room={'id':'room','state_root':root+'/control/room','project':{'id':'project','roots':roots},
          'resources':{'cpu':2,'memory_bytes':2147483648,'disk_bytes':10737418240,'pids':256,'log_bytes':10485760}}
    paths={**roots,'runtime':room['state_root']+'/runtime'}
    doc={'version':1,'profile':'local-native-v1','installation_id':'a'*32,'storage_root':root,
         'endpoints_root':'/run/uas-local','engine_version':'29.8.2','mapping':{'offset':100000,'size':65536},
         'rooms':{'room':{'quota_project_id':401,'mcs_level':'s0:c401,c402','subnet':'10.91.1.0/24',
             'gateway':'10.91.1.1','root_identity':[1,2],
             'paths':{k:{'path':p,'identity':[1,i+3]} for i,(k,p) in enumerate(paths.items())},
             'workstation':{'image_id':'sha256:'+'c'*64,'image_reference':'registry/ws@sha256:'+'d'*64},
             'hub':{'image_id':'sha256:'+'e'*64,'image_reference':'registry/hub@sha256:'+'f'*64,
                    'entrypoint':local.LOCAL_HUB_COMMAND[:]}}}}
    return {'rooms':[room]},doc


class LocalNativeTests(unittest.TestCase):
    def setUp(self): self.config,self.doc=selections()
    def profile(self): return local.LocalNativeProfile(self.config,self.doc,'room','/srv/uas/control')
    def test_profile_stable_and_exact_distinct_from_qualification(self):
        a,b=self.profile(),self.profile()
        self.assertEqual(a.spec(),b.spec());self.assertEqual(a.digest,b.digest)
        self.assertEqual(a.project_id,401);self.assertEqual(a.level,'s0:c401,c402')
        self.assertIsNone(a.git_plan);self.assertIsNone(a.gate_plan)
        with self.assertRaises(LifecycleError):local.native.NativeQualificationBackend(a)
        backend=local.LocalNativeBackend(a)
        self.assertNotEqual(backend.LABEL,local.native.NativeQualificationBackend.LABEL)
        self.assertEqual(backend._subnet(),'10.91.1.0/24')
    def test_bad_profile_selections_denied(self):
        bad=[]
        for key,value in [('version',True),('storage_root','/'),('endpoints_root','/srv/uas/sockets'),
                          ('engine_version','latest'),('mapping',{'offset':0,'size':65536})]:
            d=deepcopy(self.doc);d[key]=value;bad.append(d)
        for key,value in [('quota_project_id',True),('mcs_level','s0:c2,c1'),('subnet','127.0.0.0/24'),
                          ('gateway','10.91.1.2'),('root_identity',[True,2])]:
            d=deepcopy(self.doc);d['rooms']['room'][key]=value;bad.append(d)
        d=deepcopy(self.doc);d['rooms']['room']['hub']['entrypoint']=local.native.HUB_COMMAND;bad.append(d)
        d=deepcopy(self.doc);d['secret']='not accepted';bad.append(d)
        d=deepcopy(self.doc);d['rooms']['room']['paths']['repo']['path']='/srv/uas/project/workspace/child';bad.append(d)
        for d in bad:
            with self.subTest(d=d),self.assertRaises(LifecycleError):local.validate_document(d)
    def test_config_storage_binding_cannot_drift(self):
        self.config['rooms'][0]['project']['roots']['repo']='/srv/uas/other'
        with self.assertRaises(LifecycleError):self.profile()
    def test_native_arguments_reuse_confinement_with_selected_level(self):
        profile=self.profile();backend=local.LocalNativeBackend(profile)
        state={'room_id':'room','instance_id':'1'*32,'spec':profile.spec().document()}
        args=backend.container_arguments(state)
        self.assertIn('label=level:s0:c401,c402',args)
        self.assertIn('--read-only',args);self.assertIn('ALL',args)
        self.assertNotIn('--privileged',args);self.assertNotIn('docker.sock',' '.join(args))
        self.assertEqual(backend.hub_command,local.LOCAL_HUB_COMMAND)
    def test_uncertain_hub_create_is_observed_not_repeated(self):
        backend=local.LocalNativeBackend(self.profile());state={}
        with patch.object(backend,'_guard'),patch.object(backend,'_binding'),\
             patch.object(backend,'_hub',side_effect=[None,{'Id':'owned'}]),\
             patch.object(backend,'create_hub',side_effect=BackendUnknown()) as create,\
             patch.object(backend,'validate_hub') as validate:
            self.assertEqual(backend.ensure_hub(state),{'Id':'owned'})
            create.assert_called_once();validate.assert_called_once()
    def test_unconfirmed_hub_and_destroy_fail_closed(self):
        backend=local.LocalNativeBackend(self.profile())
        with patch.object(backend,'_guard'),patch.object(backend,'_binding'),\
             patch.object(backend,'_hub',return_value=None),patch.object(backend,'create_hub') as create:
            with self.assertRaises(LifecycleError):backend.ensure_hub({})
            create.assert_called_once()
        with self.assertRaises(LifecycleError):backend.remove({},'volume')
    def test_canonical_supervisor_stop_reopen_preserves_identity_and_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            config,doc=selections(tmp);root=Path(tmp)
            for p in config['rooms'][0]['project']['roots'].values():Path(p).mkdir(parents=True)
            sentinel=root/'project/repo/user-file';sentinel.write_text('retain')
            backend=FileFixtureBackend(root/'resources')
            def factory(profile):
                backend.profile=profile;backend.ensure_hub=Mock(return_value={'Id':'controlled-hub'})
                return backend
            with patch.object(local,'LocalNativeBackend',side_effect=factory),\
                 patch.object(local.LocalNativeProfile,'guard'),patch.object(local.LocalNativeProfile,'observe_storage'):
                host=local.LocalNativeHost(config,doc,root/'control',authorize=lambda *_:True,revoke=backend.revoke)
                first=host.start('room');instance=first['infrastructure']['instance_id']
                self.assertEqual(first['infrastructure']['phase'],'running')
                self.assertEqual(first['runtime_status'],'bindings-required')
                self.assertEqual(host.stop('room')['infrastructure']['phase'],'stopped')
                other=local.LocalNativeHost(config,doc,root/'control',authorize=lambda *_:True,revoke=backend.revoke)
                self.assertEqual(other.start('room')['infrastructure']['instance_id'],instance)
                self.assertEqual(sentinel.read_text(),'retain')
    def test_authority_required(self):
        with self.assertRaises(LifecycleError):
            local.LocalNativeHost(self.config,self.doc,'/srv/uas/control',authorize=None,revoke=lambda *_:True)

    def test_stop_hub_reconciles_timeout_without_destroy(self):
        backend=local.LocalNativeBackend(self.profile());value={'Id':'owned','State':{'Running':True}}
        stopped={'Id':'owned','State':{'Running':False}}
        with patch.object(backend,'_guard'),patch.object(backend,'_binding'),patch.object(backend,'validate_hub'),\
             patch.object(backend,'_hub',side_effect=[value,stopped]),patch.object(backend,'_run',side_effect=BackendUnknown()) as run:
            backend.stop_hub({});run.assert_called_once_with(['stop','--time','3','owned'])
    def recovery(self,stack,*,running=False,existing=False,foreign=False):
        backend=local.LocalNativeBackend(self.profile())
        state={'room_id':'room','instance_id':'1'*32,'spec':backend.profile.spec().document()}
        root=backend.endpoints/state['instance_id']
        record={**backend._endpoint_record(state),'identity':[1,2]}
        stack.enter_context(patch.object(backend,'_guard'));stack.enter_context(patch.object(backend,'_binding'))
        stack.enter_context(patch.object(backend,'_inspect_object',side_effect=lambda _s,k: {'State':{'Running':running}} if k=='container' else {}))
        stack.enter_context(patch.object(backend,'_hub',return_value=None));stack.enter_context(patch.object(backend,'validate_container'))
        stack.enter_context(patch.object(local.os,'fstat',return_value=N(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=100)))
        stack.enter_context(patch.object(local.fcntl,'flock'));stack.enter_context(patch.object(local.os,'open',return_value=55))
        stack.enter_context(patch.object(local.os,'read',return_value=json.dumps(record).encode()));stack.enter_context(patch.object(local.os,'close'))
        stack.enter_context(patch.object(local.native,'directory_identity',return_value=[1,2]))
        stack.enter_context(patch.object(Path,'resolve',lambda p:p))
        def info(p):
            if p==root:return N(st_uid=0,st_mode=stat.S_IFDIR|0o711)
            return N(st_uid=local.native.HOST_UID,st_gid=local.native.RUNTIME_UID if p.name=='peer' else local.native.HUB_UID,st_mode=stat.S_IFDIR|0o710)
        stack.enter_context(patch.object(Path,'stat',info));stack.enter_context(patch.object(local.os.path,'lexists',return_value=existing))
        stack.enter_context(patch.object(Path,'lstat',return_value=N(st_uid=0 if foreign else local.native.HOST_UID,
            st_gid=local.native.RUNTIME_UID,st_mode=stat.S_IFSOCK|0o620,st_dev=1,st_ino=2)))
        unlink=stack.enter_context(patch.object(Path,'unlink'))
        listener=stack.enter_context(patch.object(local.native,'labeled_listener',side_effect=[Mock(),Mock()]))
        return backend,state,listener,unlink
    def test_explicit_recovery_requires_stopped_exact_owned_resources(self):
        with ExitStack() as stack:
            backend,state,listener,unlink=self.recovery(stack)
            self.assertEqual(len(backend.reopen_listeners(state,owner_lock_fd=4)),2)
            self.assertEqual(listener.call_count,2);unlink.assert_not_called()
        for running,foreign in ((True,False),(False,True)):
            with self.subTest(running=running,foreign=foreign),ExitStack() as stack:
                backend,state,listener,unlink=self.recovery(stack,running=running,existing=foreign,foreign=foreign)
                with self.assertRaises(LifecycleError):backend.reopen_listeners(state,owner_lock_fd=4)
                listener.assert_not_called();unlink.assert_not_called()
    def test_listener_partial_failure_closes_handles_preserves_uncertainty(self):
        with ExitStack() as stack:
            backend,state,listener,unlink=self.recovery(stack);first=Mock()
            listener.side_effect=[first,OSError('bind failed')]
            with self.assertRaises(OSError):backend.reopen_listeners(state,owner_lock_fd=4)
            first.close.assert_called_once();self.assertEqual(backend.listeners,[]);unlink.assert_not_called()

    def test_prepare_start_fresh_and_live_listener_noop(self):
        host=local.LocalNativeHost(self.config,self.doc,'/srv/uas/control',authorize=lambda *_:True,revoke=lambda *_:True)
        for state,listeners in ((None,[]),({'instance_id':'owned'},[object()])):
            with self.subTest(state=state):
                owner=Mock();owner._locked.side_effect=lambda:nullcontext();owner._read.return_value=state
                backend=Mock();backend.listeners=listeners
                with patch.object(host,'_owner',return_value=(owner,backend)):
                    host.prepare_start('room',owner_lock_fd=4)
                backend.profile.guard.assert_called_once();backend.reopen_listeners.assert_not_called()
    def test_prepare_start_exact_persisted_state_and_failure_no_retry(self):
        host=local.LocalNativeHost(self.config,self.doc,'/srv/uas/control',authorize=lambda *_:True,revoke=lambda *_:True)
        for failure in (None,LifecycleError('LOCAL_RECOVERY_REQUIRES_STOPPED'),BackendUnknown()):
            with self.subTest(failure=failure):
                owner=Mock();owner._locked.side_effect=lambda:nullcontext();state={'instance_id':'owned'};owner._read.return_value=state
                backend=Mock();backend.listeners=[];backend.reopen_listeners.side_effect=failure
                with patch.object(host,'_owner',return_value=(owner,backend)):
                    if failure is None:host.prepare_start('room',owner_lock_fd=4)
                    else:
                        with self.assertRaises(type(failure)):host.prepare_start('room',owner_lock_fd=4)
                backend._binding.assert_called_once_with(state)
                backend.reopen_listeners.assert_called_once_with(state,owner_lock_fd=4)
                owner.start.assert_not_called()

    def test_local_archive_image_ids_are_exact_pinned_references(self):
        for kind in ('workstation','hub'):
            self.doc['rooms']['room'][kind]['image_reference']=self.doc['rooms']['room'][kind]['image_id']
        profile=self.profile();backend=local.LocalNativeBackend(profile)
        state={'room_id':'room','instance_id':'1'*32,'spec':profile.spec().document()}
        self.assertEqual(backend.container_arguments(state)[-2],profile.image_id)
        self.assertEqual(profile.hub['image_reference'],profile.hub['image_id'])
        from test_native_qualification_backend import NativeQualificationBackendTests
        fixture=NativeQualificationBackendTests();fixture.setUp();observed=fixture.observed()
        # Use the existing exact declaration with only image binding changed.
        observed['Config']['Image']=observed['Image']
        native=local.native
        self.assertTrue(native.validate_native_container(fixture.state,observed,
            image_id=observed['Image'],image_reference=observed['Image'],limits=fixture.profile.limits,
            nano_cpus=fixture.profile.nano_cpus,mounts=fixture.backend.mounts(fixture.state)))
        observed['Config']['Image']='sha256:'+'0'*64
        with self.assertRaises(LifecycleError):
            native.validate_native_container(fixture.state,observed,image_id=fixture.profile.image_id,
                image_reference=fixture.profile.image_id,limits=fixture.profile.limits,
                nano_cpus=fixture.profile.nano_cpus,mounts=fixture.backend.mounts(fixture.state))
    def test_local_image_tags_or_different_config_ids_rejected(self):
        for kind in ('workstation','hub'):
            for reference in ('image:latest','image:v1','sha256:'+'0'*64):
                with self.subTest(kind=kind,reference=reference):
                    _,doc=selections();doc['rooms']['room'][kind]['image_reference']=reference
                    with self.assertRaises(LifecycleError):local.validate_document(doc)
