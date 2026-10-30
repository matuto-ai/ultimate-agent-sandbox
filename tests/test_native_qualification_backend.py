"""Pure native profile/custody checks; actual OS boundary remains hosted."""
from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace as N
import unittest
import tempfile
import os
from contextlib import ExitStack
from unittest.mock import Mock, patch

from uas import native_qualification_backend as native
from uas.lifecycle import LifecycleError, BackendUnknown


class NativeQualificationBackendTests(unittest.TestCase):
    def setUp(self):
        nonce='a'*32;root='/mnt/uas-native/'+nonce
        self.room={'id':'room','state_root':root+'/state/room',
            'project':{'id':'project','roots':{k:root+'/projects/'+k for k in ('repo','workspace','reference','checkouts')}},
            'resources':{'cpu':2,'memory_bytes':2147483648,'disk_bytes':10737418240,'pids':256,'log_bytes':10485760}}
        self.plan=N(room=self.room,installation={'nonce':nonce},config_digest='b'*64,
                    check=lambda:{'missing_prerequisites':[], 'images':{'pi':{
                        'image_id':'sha256:'+'c'*64,'image_reference':'registry/image@sha256:'+'d'*64}}})
        paths={**self.room['project']['roots'],'runtime':self.room['state_root']+'/runtime'}
        self.boundary={'version':1,'nonce':nonce,'room_id':'room','project_id':301,'level':native.LEVEL,
            'root_identity':[1,2],'paths':{k:{'path':p,'identity':[1,i+3]} for i,(k,p) in enumerate(paths.items())}}
        self.hub={'version':1,'image_reference':'registry/hub@sha256:'+'e'*64,
                  'image_id':'sha256:'+'f'*64,'entrypoint':native.HUB_COMMAND.copy()}
        self.profile=native.NativeBoundaryProfile(self.plan,self.boundary,self.hub)
        self.backend=native.NativeQualificationBackend(self.profile)
        self.state={'instance_id':'1'*32,'room_id':'room','spec':self.profile.spec().document()}

    def observed(self):
        limits=self.profile.limits
        host={'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,
            'SecurityOpt':['no-new-privileges','label=level:'+native.LEVEL],
            'NetworkMode':native.names(self.state)[0],'PidMode':'','IpcMode':'private','UTSMode':'',
            'UsernsMode':'','CgroupnsMode':'private','Devices':[],'DeviceRequests':None,'DeviceCgroupRules':None,
            'PublishAllPorts':False,'PortBindings':{},'RestartPolicy':{'Name':'no','MaximumRetryCount':0},
            'Memory':limits['memory_bytes'],'MemorySwap':limits['memory_bytes'],'NanoCpus':2000000000,'PidsLimit':256,
            'LogConfig':{'Type':'local','Config':{'max-size':str(limits['log_bytes']),'max-file':'1','compress':'false'}},
            'MaskedPaths':['/proc/kcore','/proc/keys','/proc/timer_list','/sys/firmware'],
            'ReadonlyPaths':['/proc/bus','/proc/fs','/proc/irq','/proc/sys','/proc/sysrq-trigger']}
        host['Mounts']=[{'Type':'bind','Source':s,'Target':d,'ReadOnly':not w,
                        'BindOptions':{'Propagation':'rprivate','NonRecursive':True}}
                       for s,d,w in self.backend.mounts(self.state)]
        return {'Id':'2'*64,'Image':self.profile.image_id,'Config':{'Image':self.profile.image_reference,
            'User':'65532:65532','Entrypoint':['/bin/sleep'],'Cmd':['infinity'],'Tty':False},'HostConfig':host,
            'NetworkSettings':{'Networks':{native.names(self.state)[0]:{}}},
            'ProcessLabel':'system_u:system_r:container_t:'+native.LEVEL,
            'MountLabel':'system_u:object_r:container_file_t:'+native.LEVEL,'State':{'Running':False},
            'Mounts':[{'Source':s,'Destination':d,'RW':w,'Type':'bind','Propagation':'rprivate'}
                      for s,d,w in self.backend.mounts(self.state)]}

    def test_exact_config_limits_six_mounts_and_no_engine_mount(self):
        self.assertTrue(self.backend.validate_container(self.state,self.observed()))
        args=self.backend.container_arguments(self.state)
        self.assertEqual(args.count('--mount'),6)
        self.assertEqual(args[args.index('--memory')+1],str(self.room['resources']['memory_bytes']))
        self.assertNotIn('docker.sock',' '.join(args));self.assertNotIn('--privileged',args)
        self.assertEqual(args[-3:],['/bin/sleep',self.profile.image_reference,'infinity'])

    def test_limit_or_boundary_drift_is_denied(self):
        for key,value in [('Memory',True),('MemorySwap',0),('PidsLimit',257),('NanoCpus',1),
                          ('Privileged',True),('PidMode','host'),('UsernsMode','host'),('CapAdd',['SYS_ADMIN']),
                          ('PortBindings',{'22/tcp':[]}),('NetworkMode','host')]:
            with self.subTest(key=key):
                observed=self.observed();observed['HostConfig'][key]=value
                with self.assertRaises(LifecycleError):self.backend.validate_container(self.state,observed)

    def test_mount_inventory_rejects_extra_missing_duplicate_and_runtime_remap(self):
        for mutation in ('extra','missing','duplicate','remap','writable-reference'):
            with self.subTest(mutation=mutation):
                observed=self.observed();mounts=observed['Mounts']
                if mutation=='extra':mounts.append(deepcopy(mounts[0]))
                if mutation=='missing':mounts.pop()
                if mutation=='duplicate':mounts[-1]=deepcopy(mounts[0])
                if mutation=='remap':mounts[4]['Destination']='/different-runtime'
                if mutation=='writable-reference':mounts[2]['RW']=True
                with self.assertRaises(LifecycleError):self.backend.validate_container(self.state,observed)

    def test_initial_absence_or_malformed_observation_is_not_admission(self):
        for value in ({}, {'Config':None}, self.observed()|{'Mounts':None}):
            with self.assertRaises((BackendUnknown,LifecycleError)):
                self.backend.validate_container(self.state,value)

    def test_prepared_profile_not_claimed_qualification_or_arbitrary_namespace(self):
        for key,value in [('version',True),('project_id',101),('level','s0:c101,c102'),('qualified',True)]:
            boundary=deepcopy(self.boundary);boundary[key]=value
            with self.assertRaises(LifecycleError):native.NativeBoundaryProfile(self.plan,boundary,self.hub)
        self.plan.room=deepcopy(self.room);self.plan.room['state_root']='/mnt/uas-boundary/alpha'
        with self.assertRaisesRegex(LifecycleError,'STATE_ROOT'):
            native.NativeBoundaryProfile(self.plan,self.boundary,self.hub)

    def test_hub_pid1_or_unpinned_image_is_denied(self):
        for entrypoint in (['/usr/bin/python3','-m','uas.workstation_service'],['/bin/sh']):
            hub=deepcopy(self.hub);hub['entrypoint']=entrypoint
            with self.assertRaisesRegex(LifecycleError,'HUB_MANIFEST'):
                native.NativeBoundaryProfile(self.plan,self.boundary,hub)

    def test_exact_cpu_and_disk_limits_cannot_round(self):
        for field,value in [('disk_bytes',1025),('cpu',0.0000000001)]:
            plan=deepcopy(self.plan);plan.room['resources'][field]=value
            with self.assertRaises(LifecycleError):native.NativeBoundaryProfile(plan,self.boundary,self.hub)

    def test_prerequisite_failure_precedes_any_runtime_effect(self):
        with (patch.object(native,'guard'),patch.object(self.profile,'observe_storage',side_effect=LifecycleError('NO_QUOTA')),
                patch.object(self.backend,'_run') as run):
            with self.assertRaisesRegex(LifecycleError,'NO_QUOTA'):self.backend.create(self.state,'volume')
        run.assert_not_called()

    def test_native_names_and_firewall_are_distinct_from_62(self):
        import json
        text=json.dumps(native.firewall(self.state,self.profile.nonce))
        self.assertIn('uan_'+self.state['instance_id'],text)
        self.assertNotIn('uas_'+self.state['instance_id'],text)
        self.assertIn('169.254.0.0',text);self.assertIn('ipv6',text)
        self.assertNotIn('accept',json.dumps([x for x in native.firewall(self.state,self.profile.nonce)['nftables']
                                            if 'rule' in x.get('add',{})]))

    def test_observer_cannot_perform_lifecycle_effects(self):
        observer=native.NativeQualificationObserver('room','1'*32,'b'*64)
        for name in ('create','start','stop','remove','admit'):
            with self.assertRaisesRegex(LifecycleError,'ROOT_LIFECYCLE_OWNER_REQUIRED'):
                getattr(observer,name)(self.state,'container')
        wrong=deepcopy(self.state);wrong['instance_id']='2'*32
        with patch.object(observer,'_run') as run:
            with self.assertRaisesRegex(LifecycleError,'OBSERVER_BINDING'):observer.inspect(wrong,'container')
        run.assert_not_called()

    def test_child_custody_is_not_a_pid_or_serialized_receipt(self):
        resources=native.LaunchResources({},())
        for fake in (123,{'pid':123,'exited':True},N(poll=lambda:0)):
            with self.assertRaisesRegex(LifecycleError,'CHILD_CUSTODY'):resources.hold_child(fake)

    def test_broker_or_child_alive_blocks_fence_and_role_rebind(self):
        class InertPopen:
            def __init__(self):self.result=None
            def poll(self):return self.result
        with patch.object(native.subprocess,'Popen',InertPopen):
            resources=native.LaunchResources({},());child=InertPopen();broker=InertPopen()
            resources.hold_child(child);resources.hold_broker(broker)
            self.assertFalse(resources.issuer_exited())
            child.result=0;self.assertFalse(resources.issuer_exited())
            broker.result=0;self.assertTrue(resources.issuer_exited())
            with self.assertRaisesRegex(LifecycleError,'CHILD_CUSTODY'):resources.hold_child(child)
            with self.assertRaisesRegex(LifecycleError,'BROKER_CUSTODY'):resources.hold_broker(broker)

    def test_spawn_intent_without_returned_handle_is_unknown_not_revoked(self):
        for role in ('child','broker'):
            resources=native.LaunchResources({},())
            self.assertTrue(resources.issuer_exited())
            getattr(resources,'expect_'+role)()
            self.assertFalse(resources.issuer_exited())
            with self.assertRaises(LifecycleError):getattr(resources,'expect_'+role)()

    def test_same_spec_replaced_instance_is_not_backend_custody(self):
        self.backend._binding(self.state)
        changed=deepcopy(self.state);changed['instance_id']='3'*32
        with self.assertRaisesRegex(LifecycleError,'INSTANCE_REPLACED'):self.backend._binding(changed)

    def _fake_backend(self):
        class ControlledBackend:
            created=[]
            def __init__(self,profile):
                self.profile=profile;self.instance=None;self.listeners=[];self.objects={};self.created.append(self)
            def name(self,state,kind):return state['instance_id']+'-'+kind
            def inspect(self,state,kind):
                if self.instance is None:self.instance=state['instance_id']
                return self.objects.get(kind)
            def create(self,state,kind):
                self.objects[kind]={'id':kind,'name':self.name(state,kind),'running':False,
                                    'image_id':state['spec']['image_id']}
            def admit(self,state):return self.objects['container']
            def start(self,state):self.objects['container']['running']=True
            def stop(self,state):self.objects['container']['running']=False
            def stop_hub(self,state):self.hub_stopped=True
            def layout(self,state):return {'supervisor':self.profile.state_root/'instances'/state['instance_id']/'native'/'supervisor'}
            def remove(self,state,kind):self.objects.pop(kind,None)
            def create_hub(self,state):raise RuntimeError('controlled-setup-failure')
        return ControlledBackend

    def test_own_manifest_then_setup_failure_cleans_only_owned_attempt(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            self.profile.state_root=Path(directory)/'room';self.profile.root=Path(directory);stack.enter_context(patch.object(native,'STORAGE',Path(directory)))
            fake=self._fake_backend()
            stack.enter_context(patch.object(native.NativeBoundaryProfile,'read',return_value=self.profile))
            stack.enter_context(patch.object(self.profile,'observe_storage',return_value=True))
            stack.enter_context(patch.object(native,'NativeQualificationBackend',fake))
            stack.enter_context(patch.object(native.os,'geteuid',return_value=0))
            with self.assertRaisesRegex(RuntimeError,'controlled-setup-failure'):
                with native.provision(self.plan):self.fail('no handoff before setup')
            import json
            state=json.loads((self.profile.state_root/'lifecycle.json').read_text())
            self.assertEqual(state['phase'],'destroyed')
            self.assertFalse(fake.created[-1].objects)
            self.assertFalse((Path(directory)/'.native-qualification-owner').exists())

    def test_preexisting_room_is_neither_adopted_nor_destroyed(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            self.profile.state_root=Path(directory)/'room';self.profile.root=Path(directory);stack.enter_context(patch.object(native,'STORAGE',Path(directory)));fake=self._fake_backend()
            backend=fake(self.profile)
            owner=native.Supervisor(directory,'room',backend,authorize=lambda *_:True,revoke=lambda *_:True)
            owner.start(self.profile.spec())
            before=(self.profile.state_root/'lifecycle.json').read_bytes()
            stack.enter_context(patch.object(native.NativeBoundaryProfile,'read',return_value=self.profile))
            stack.enter_context(patch.object(self.profile,'observe_storage',return_value=True))
            stack.enter_context(patch.object(native,'NativeQualificationBackend',fake))
            stack.enter_context(patch.object(native.os,'geteuid',return_value=0))
            with self.assertRaisesRegex(LifecycleError,'EXISTING_LIFECYCLE'):
                with native.provision(self.plan):self.fail('must not adopt old Room')
            self.assertEqual((self.profile.state_root/'lifecycle.json').read_bytes(),before)
            self.assertTrue(backend.objects['container']['running'])

    def test_absent_precheck_then_foreign_start_does_not_destroy_foreign_room(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            self.profile.state_root=Path(directory)/'room';self.profile.root=Path(directory);stack.enter_context(patch.object(native,'STORAGE',Path(directory)));fake=self._fake_backend()
            foreign_spec=self.profile.spec();original=native.Supervisor.start;injected=[]
            def racing(owner,spec):
                if not injected:
                    injected.append(True)
                    other=native.Supervisor(directory,'room',fake(self.profile),authorize=lambda *_:True,revoke=lambda *_:True)
                    original(other,foreign_spec)
                return original(owner,spec)
            stack.enter_context(patch.object(native.NativeBoundaryProfile,'read',return_value=self.profile))
            stack.enter_context(patch.object(self.profile,'observe_storage',return_value=True))
            stack.enter_context(patch.object(native,'NativeQualificationBackend',fake))
            stack.enter_context(patch.object(native.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(native.Supervisor,'start',racing))
            with self.assertRaisesRegex(LifecycleError,'CLEANUP_INCOMPLETE') as caught:
                with native.provision(self.plan):self.fail('must not adopt concurrent Room')
            self.assertEqual(str(caught.exception.__context__),'FORBIDDEN')
            import json
            state=json.loads((self.profile.state_root/'lifecycle.json').read_text())
            self.assertEqual(state['spec'],foreign_spec.document());self.assertEqual(state['phase'],'running')
            self.assertTrue((Path(directory)/'.native-qualification-owner').exists())

    def test_failure_before_manifest_has_no_destructive_cleanup(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            self.profile.state_root=Path(directory)/'room';self.profile.root=Path(directory);stack.enter_context(patch.object(native,'STORAGE',Path(directory)));fake=self._fake_backend()
            stack.enter_context(patch.object(native.NativeBoundaryProfile,'read',return_value=self.profile))
            stack.enter_context(patch.object(self.profile,'observe_storage',return_value=True))
            stack.enter_context(patch.object(native,'NativeQualificationBackend',fake))
            stack.enter_context(patch.object(native.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(native.Supervisor,'start',side_effect=RuntimeError('before-manifest')))
            destroy=stack.enter_context(patch.object(native.Supervisor,'destroy'))
            with self.assertRaisesRegex(RuntimeError,'before-manifest'):
                with native.provision(self.plan):self.fail('must not hand off')
            destroy.assert_not_called();self.assertFalse((self.profile.state_root/'lifecycle.json').exists())

    def test_nonrecursive_bind_setting_is_admitted_not_just_requested(self):
        for mutation in ('missing','recursive','propagation'):
            value=self.observed()
            if mutation=='missing':value['HostConfig'].pop('Mounts')
            if mutation=='recursive':value['HostConfig']['Mounts'][0]['BindOptions']['NonRecursive']=False
            if mutation=='propagation':value['HostConfig']['Mounts'][0]['BindOptions']['Propagation']='shared'
            with self.assertRaisesRegex(LifecycleError,'BIND_OPTIONS'):
                self.backend.validate_container(self.state,value)

    def test_hub_has_only_db_and_narrow_endpoints_not_engine_or_runtime(self):
        value=self.observed();layout=self.backend.layout(self.state)
        value['Image']=self.hub['image_id'];config=value['Config'];host=value['HostConfig']
        config.update(Image=self.hub['image_reference'],User='65531:65531',Entrypoint=native.HUB_COMMAND[:1],
                      Cmd=native.HUB_COMMAND[1:],OpenStdin=True)
        host.update(NetworkMode='none',GroupAdd=['65532'],Memory=268435456,MemorySwap=268435456,
                    NanoCpus=250000000,PidsLimit=32)
        host['LogConfig']['Config']['max-size']='1048576'
        expected=[(str(layout['peer']),'/uas/peer',False),(str(layout['control']),'/uas/control',False),
                  (str(layout['hub']),'/uas/hub',True)]
        value['Mounts']=[{'Source':s,'Destination':d,'RW':w,'Type':'bind','Propagation':'rprivate'} for s,d,w in expected]
        host['Mounts']=[{'Source':s,'Target':d,'Type':'bind','ReadOnly':not w,
                       'BindOptions':{'Propagation':'rprivate','NonRecursive':True}} for s,d,w in expected]
        self.assertTrue(self.backend.validate_hub(self.state,value))
        for field,modified in [('GroupAdd',['65532','165533']),('UsernsMode','host'),('Memory',0),
                              ('NetworkMode','host')]:
            bad=deepcopy(value);bad['HostConfig'][field]=modified
            with self.assertRaises(LifecycleError):self.backend.validate_hub(self.state,bad)

    def test_uncertain_spawn_retains_owned_audit_and_resources(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            self.profile.state_root=Path(directory)/'room';self.profile.root=Path(directory);stack.enter_context(patch.object(native,'STORAGE',Path(directory)));fake=self._fake_backend()
            resources=native.LaunchResources({},());resources.expect_broker()
            stack.enter_context(patch.object(native.NativeBoundaryProfile,'read',return_value=self.profile))
            stack.enter_context(patch.object(self.profile,'observe_storage',return_value=True))
            stack.enter_context(patch.object(native,'NativeQualificationBackend',fake))
            stack.enter_context(patch.object(native,'LaunchResources',return_value=resources))
            stack.enter_context(patch.object(native.os,'geteuid',return_value=0))
            with self.assertRaisesRegex(LifecycleError,'CLEANUP_INCOMPLETE'):
                with native.provision(self.plan):self.fail('must not hand off')
            import json
            state=json.loads((self.profile.state_root/'lifecycle.json').read_text())
            self.assertEqual(state['phase'],'stop_failed')
            self.assertTrue(fake.created[-1].objects['container']['running'])
            self.assertTrue((self.profile.state_root/'instances'/state['instance_id']/'owner.json').exists())
            self.assertTrue((Path(directory)/'.native-qualification-owner').exists())

    def test_guest_singleton_conflict_precedes_any_runtime_effect(self):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            self.profile.state_root=Path(directory)/'room';self.profile.root=Path(directory)
            stack.enter_context(patch.object(native,'STORAGE',Path(directory)))
            lease=Path(directory)/'.native-qualification-owner';lease.write_text('earlier-owned-attempt')
            stack.enter_context(patch.object(native.NativeBoundaryProfile,'read',return_value=self.profile))
            stack.enter_context(patch.object(self.profile,'observe_storage',return_value=True))
            start=stack.enter_context(patch.object(native.Supervisor,'start'))
            destroy=stack.enter_context(patch.object(native.Supervisor,'destroy'))
            with self.assertRaises(FileExistsError):
                with native.provision(self.plan):self.fail('must not overlap single-profile Rooms')
            start.assert_not_called();destroy.assert_not_called()
            self.assertEqual(lease.read_text(),'earlier-owned-attempt')

    def test_owned_lifecycle_missing_or_replaced_instance_retains_custody(self):
        import json
        for change in ('missing','new-instance'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
                self.profile.state_root=Path(directory)/'room';self.profile.root=Path(directory)
                stack.enter_context(patch.object(native,'STORAGE',Path(directory)))
                fake=self._fake_backend();manifest=self.profile.state_root/'lifecycle.json'
                def changed(backend,state):
                    if change=='missing':manifest.unlink()
                    else:
                        value=json.loads(manifest.read_text());value['instance_id']='4'*32
                        manifest.write_text(json.dumps(value))
                    raise RuntimeError('controlled-replacement')
                fake.create_hub=changed
                stack.enter_context(patch.object(native.NativeBoundaryProfile,'read',return_value=self.profile))
                stack.enter_context(patch.object(self.profile,'observe_storage',return_value=True))
                stack.enter_context(patch.object(native,'NativeQualificationBackend',fake))
                stack.enter_context(patch.object(native.os,'geteuid',return_value=0))
                destroy=stack.enter_context(patch.object(native.Supervisor,'destroy'))
                with self.assertRaisesRegex(LifecycleError,'CLEANUP_INCOMPLETE'):
                    with native.provision(self.plan):self.fail('must not hand off')
                destroy.assert_not_called()
                self.assertTrue((Path(directory)/'.native-qualification-owner').exists())
                self.assertTrue(fake.created[-1].objects['container']['running'])

    def test_clean_quota_stdout_with_stderr_is_not_accepted(self):
        result=N(returncode=0,stdout='Checking project 301...\nProcessed 1 paths.\n',stderr='skipped inode')
        with patch.object(native.subprocess,'run',return_value=result) as run:
            with self.assertRaises(BackendUnknown):
                native.command('xfs_quota','-x','-c','project -c -p /prepared 301','/mnt/uas-native')
        self.assertEqual(run.call_args.kwargs['timeout'],30)
        self.assertEqual(run.call_args.kwargs['env']['LC_ALL'],'C')
        self.assertNotIn('shell',run.call_args.kwargs)
        result.stderr=''
        with patch.object(native.subprocess,'run',return_value=result):
            self.assertEqual(native.command('xfs_quota','-x','-c','state -p','/mnt/uas-native'),result.stdout)

    def test_endpoint_paths_fit_unix_and_workstation_mount_is_same_path(self):
        layout=self.backend.layout(self.state)
        for role,name in (('peer','pi.sock'),('control','hub.sock')):
            self.assertLess(len(os.fsencode(layout[role]/name)),108)
            self.assertTrue(str(layout[role]).startswith('/run/uas-native/'))
        self.assertEqual(self.backend.mounts(self.state)[-1],(str(layout['peer']),str(layout['peer']),False))

    def test_endpoint_cleanup_refuses_stale_replaced_and_symlink_roots(self):
        import json
        # Root UID observations are controlled; no chown/SELinux/socket effects.
        original_stat=os.stat;original_fstat=os.fstat
        def root_stat(*args,**kwargs):
            fields=list(original_stat(*args,**kwargs));fields[4]=0;return os.stat_result(fields)
        def root_fstat(*args,**kwargs):
            fields=list(original_fstat(*args,**kwargs));fields[4]=0;return os.stat_result(fields)
        for scenario in ('valid','stale','replaced','symlink'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
                endpoint=Path(directory)/'endpoints';endpoint.mkdir()
                stack.enter_context(patch.object(native,'ENDPOINTS',endpoint))
                root=endpoint/self.state['instance_id'];root.mkdir(mode=0o711)
                record={**self.backend._endpoint_record(self.state),'identity':native.directory_identity(root)}
                if scenario=='stale':record['identity'][1]+=1
                if scenario in ('replaced','symlink'):
                    old=endpoint/'old';root.rename(old)
                    if scenario=='symlink':root.symlink_to(old,target_is_directory=True)
                    else:root.mkdir(mode=0o711)
                marker=root/'owner.json';marker.write_text(json.dumps(record));marker.chmod(0o600)
                stack.enter_context(patch.object(native.os,'stat',side_effect=root_stat))
                stack.enter_context(patch.object(native.os,'fstat',side_effect=root_fstat))
                if scenario=='valid':
                    self.backend._remove_endpoints(self.state);self.assertFalse(root.exists())
                else:
                    with self.assertRaises(LifecycleError):self.backend._remove_endpoints(self.state)
                    self.assertTrue(root.exists())

    def test_exited_issued_roles_stop_but_retain_audit_without_masking_failure(self):
        class InertPopen:
            def poll(self):return 0
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            self.profile.state_root=Path(directory)/'room';self.profile.root=Path(directory)
            stack.enter_context(patch.object(native,'STORAGE',Path(directory)))
            stack.enter_context(patch.object(native.subprocess,'Popen',InertPopen))
            resources=native.LaunchResources({},());resources.expect_broker();resources.hold_broker(InertPopen())
            fake=self._fake_backend()
            stack.enter_context(patch.object(native.NativeBoundaryProfile,'read',return_value=self.profile))
            stack.enter_context(patch.object(self.profile,'observe_storage',return_value=True))
            stack.enter_context(patch.object(native,'NativeQualificationBackend',fake))
            stack.enter_context(patch.object(native,'LaunchResources',return_value=resources))
            stack.enter_context(patch.object(native.os,'geteuid',return_value=0))
            with self.assertRaisesRegex(RuntimeError,'controlled-setup-failure'):
                with native.provision(self.plan):self.fail('no handoff')
            import json
            state=json.loads((self.profile.state_root/'lifecycle.json').read_text())
            self.assertEqual(state['phase'],'stopped');self.assertFalse(fake.created[-1].objects['container']['running'])
            self.assertTrue(fake.created[-1].hub_stopped)
            self.assertEqual(resources.retained_evidence['status'],'stopped-evidence-retained')
            self.assertTrue((Path(directory)/'.native-qualification-owner').exists())
            self.assertTrue((self.profile.state_root/'instances'/state['instance_id']/'owner.json').exists())

