"""Pure exact-resource contracts; no socket/process/mount/credential operations."""
from copy import deepcopy
from types import SimpleNamespace as N
import hashlib
import os
import stat
import unittest
from unittest.mock import Mock, patch

from uas import native_git_resources as git
from uas.kernel_origin import OriginDenied


def fixture():
    nonce='a'*32;instance='b'*32;root='/mnt/uas-native/'+nonce
    reference='registry/native@sha256:'+'c'*64
    room={'id':'room','image':'image','state_root':root+'/state/room',
          'project':{'id':'project','repository':'owner/repo',
          'roots':{k:root+'/projects/'+k for k in ('repo','workspace','reference','checkouts')}}}
    plan=N(room=room,config={'deployment':{'images':[{'id':'image','reference':reference}]}},
        installation={'nonce':nonce,'git_manifest':{'path':'/trusted/git.json','sha256':'d'*64}},
        config_digest='e'*64,require_unchanged=lambda:None)
    value={'version':1,'profile':'native-git-primary-v1','image_reference':reference,'image_id':'sha256:'+'f'*64,
        'python_version':'3.11.14','artifacts':dict.fromkeys(git.FIXED_ARTIFACTS,'0'*64),
        'abi_artifacts':{git.LOADER:'1'*64,'/lib/x86_64-linux-gnu/libc.so.6':'2'*64},
        'uas_tree_sha256':'3'*64,'backend_sha256':'4'*64,'backend_path':root+'/git-backend'}
    state={'room_id':'room','instance_id':instance,'phase':'running','spec':{'config_digest':'sha256:'+plan.config_digest}}
    return plan,state,value


class NativeGitResourceTests(unittest.TestCase):
    def setUp(self):
        self.plan,self.state,self.selection=fixture()
        self.profile=git.GitMountProfile.from_plan(self.plan,self.state,self.selection,'d'*64,
            container_id='5'*64,mapping_digest='6'*64)

    def test_exact_roles_order_and_primary_only(self):
        mounts=self.profile.mounts
        self.assertEqual(len(mounts),7)
        self.assertEqual([(x.destination,x.read_only) for x in mounts],[
            ('/opt/uas/git-views',True),('/opt/uas/git-views/primary/gitdir',False),
            ('/opt/uas/git-views/primary/common',False),('/opt/uas/git-views/primary/common/config',True),
            ('/opt/uas/git-views/primary/gitdir/commondir',True),('/uas/git',True),('/uas/workspace',True)])
        self.profile.require_checkout('primary',self.profile.repo)
        for slot,checkout in [('later',self.profile.repo),('primary',self.profile.repo+'/nested')]:
            with self.assertRaises(OriginDenied):self.profile.require_checkout(slot,checkout)
        with self.assertRaises(OriginDenied):self.profile.repo='/other'
        doc=self.profile.document();doc['mounts'][0]['source']='/other'
        self.assertNotEqual(doc,self.profile.document())
        with self.assertRaises(OriginDenied):git.GitMountProfile().document()

    def test_selected_payload_and_loader_fail_closed(self):
        for change in ({'version':True},{'artifacts':{}},{'abi_artifacts':{}},
                       {'image_reference':'other@sha256:'+'c'*64},{'backend_path':'/tmp/git'},
                       {'python_version':'latest'},{'qualified':True}):
            with self.subTest(change=change),self.assertRaises(OriginDenied):
                git.validate_selection({**self.selection,**change},self.plan)
        bad=deepcopy(self.selection);bad['artifacts']['/usr/bin/git']='f'*64
        with self.assertRaises(OriginDenied):git.validate_selection(bad,self.plan)

    def test_actual_image_and_exact_nested_mounts_not_labels(self):
        owner=git.NativeGitResources.__new__(git.NativeGitResources)
        owner.plan=self.plan;owner.profile=self.profile;owner.container_id=self.profile.container_id
        peer='/run/uas-native/'+self.state['instance_id']+'/peer'
        resources={'peer_path':peer+'/pi.sock'}
        mounts=[(p,p,k!='reference') for k,p in self.plan.room['project']['roots'].items()]
        runtime=self.plan.room['state_root']+'/runtime'
        mounts += [(runtime,runtime,True),(peer,peer,False)]+list(self.profile.mount_tuples())
        value={'Id':owner.container_id,'Image':self.profile.image_id,
            'Config':{'Image':self.profile.image_reference},'State':{'Running':True},
            'HostConfig':{'ReadonlyRootfs':True,'Privileged':False,'UsernsMode':'','PidMode':'','CapDrop':['ALL'],'CapAdd':[]},
            'Mounts':[{'Type':'bind','Source':s,'Destination':d,'RW':w,'Propagation':'rprivate'} for s,d,w in mounts]}
        owner._verify_container(value,resources)
        for mutate in ('image','extra','config-writable','source-alias','propagation'):
            bad=deepcopy(value)
            if mutate=='image':bad['Image']='sha256:'+'9'*64
            elif mutate=='extra':bad['Mounts'].append(bad['Mounts'][-1])
            elif mutate=='config-writable':bad['Mounts'][9]['RW']=True
            elif mutate=='source-alias':bad['Mounts'][8]['Source']='/tmp/other'
            else:bad['Mounts'][0]['Propagation']='rslave'
            with self.subTest(mutate=mutate),self.assertRaises(OriginDenied):owner._verify_container(bad,resources)

    def test_backend_initial_digest_then_immutable_seal_identity(self):
        raw=b'\x7fELFcontrolled';digest=hashlib.sha256(raw).hexdigest()
        info=N(st_mode=stat.S_IFREG|0o555,st_size=len(raw),st_dev=7,st_ino=8)
        with patch.object(git.os,'fstat',return_value=info),patch.object(git.fcntl,'fcntl',return_value=15),\
                patch.object(git.os,'pread',return_value=raw) as read:
            identity=git.require_sealed(9,digest);self.assertEqual(identity,(7,8));read.assert_called_once()
            read.reset_mock();git.require_sealed(9,digest,identity);read.assert_not_called()
            with self.assertRaises(OriginDenied):git.require_sealed(9,digest,(7,99))
        with patch.object(git.os,'fstat',return_value=info),patch.object(git.fcntl,'fcntl',return_value=7):
            with self.assertRaises(OriginDenied):git.require_sealed(9,digest,identity)

    def test_local_recheck_no_engine_rpc_and_replacement_denied(self):
        owner=git.NativeGitResources.__new__(git.NativeGitResources)
        owner._closed=False;owner._pidfd=42;owner._task_identity=(4,2);owner.plan=self.plan;owner.profile=self.profile
        owner.container_id=self.profile.container_id;owner.config_digest=self.plan.config_digest
        owner.supervisor=Mock();owner.supervisor._read.return_value=deepcopy(self.state)
        owner.backend_fd=50;owner.backend_sha256='4'*64;owner._backend_identity=(8,9)
        owner._socket_identities={'request':(1,2),'worker':(1,2)}
        for kind in ('request','worker'):
            endpoint=Mock();endpoint.path='/owned/'+kind;setattr(owner,kind+'_endpoint',endpoint)
            listener=Mock();listener.getsockname.return_value=endpoint.path;listener.getsockopt.return_value=1;setattr(owner,kind+'_listener',listener)
        with patch.object(git,'alive',return_value=True),patch.object(git,'_identity',return_value=(4,2)),patch.object(git,'require_sealed'),\
                patch.object(git.os,'fstat',return_value=N(st_dev=1,st_ino=2)):
            self.assertTrue(owner.require('room',self.state['instance_id'],owner.container_id))
            owner.supervisor._locked.assert_not_called()
            owner.supervisor._read.return_value['instance_id']='8'*32
            with self.assertRaises(OriginDenied):owner.require()

    def test_git_broker_custody_is_required_for_shutdown(self):
        from uas import native_qualification_backend as backend
        class InertPopen:
            def __init__(self):self.result=None
            def poll(self):return self.result
        with patch.object(backend.subprocess,'Popen',InertPopen):
            resources=backend.LaunchResources({},())
            resources.expect_git_broker();self.assertFalse(resources.issuer_exited())
            broker=InertPopen();resources.hold_git_broker(broker)
            self.assertFalse(resources.issuer_exited());broker.result=0
            self.assertTrue(resources.issuer_exited())
            with self.assertRaises(backend.LifecycleError):resources.hold_git_broker(broker)

    def test_opt_in_backend_mounts_are_exact_and_default_is_six(self):
        from uas import native_qualification_backend as backend
        owner=backend.NativeQualificationBackend.__new__(backend.NativeQualificationBackend)
        roots=self.plan.room['project']['roots']
        profile=N(paths={**roots,'runtime':self.plan.room['state_root']+'/runtime'},git_manifest=None,
            state_root=__import__('pathlib').Path(self.plan.room['state_root']),git_plan=self.plan)
        owner.profile=profile
        self.assertEqual(len(owner.mounts(self.state)),6)
        profile.git_manifest=self.selection
        mounts=owner.mounts(self.state);self.assertEqual(len(mounts),13)
        self.assertEqual(mounts[6:],list(self.profile.mount_tuples()))
        layout=owner.layout(self.state)
        self.assertEqual(str(layout['git']),'/run/uas-native/'+self.state['instance_id']+'/git')
        self.assertEqual(layout['git-broker'].parent,layout['supervisor'].parent)

    def test_prepare_writes_only_new_owned_controls_never_project(self):
        from pathlib import Path
        writes=[]
        def write(fd,raw):
            self.assertIs(type(raw),bytes);writes.append(raw);return len(raw)
        with patch.object(Path,'resolve',lambda p:p),patch.object(Path,'is_dir',return_value=True),\
             patch.object(Path,'stat',return_value=N(st_uid=git.RUNTIME_UID,st_gid=git.RUNTIME_UID)),\
             patch.object(Path,'mkdir'),patch.object(git.os,'chown'),patch.object(git.os,'chmod'),\
             patch.object(git.os,'open',side_effect=[10,11,12,13]) as opened,\
             patch.object(git.os,'fstat',return_value=N(st_mode=stat.S_IFREG|0o660,st_size=2)),\
             patch.object(git.os,'read',return_value=b'.\n'),patch.object(git.os,'write',side_effect=write),\
             patch.object(git.os,'fchown'),patch.object(git.os,'fchmod'),patch.object(git.os,'fsync'),patch.object(git.os,'close'):
            git.prepare_views(self.plan,self.state)
        self.assertEqual(len(writes),2)
        self.assertIn(b'git@github.com:owner/repo.git',writes[0])
        self.assertEqual(writes[1],b'/opt/uas/git-views/primary/common\n')
        for call in opened.call_args_list:
            filename,flags=call.args[:2]
            if flags & os.O_WRONLY:self.assertTrue(str(filename).startswith('/run/uas-native/'+self.state['instance_id']+'/git-fixed/'))
            else:self.assertTrue(str(filename).startswith(self.profile.repo+'/.git/'))

    def test_archive_parser_rejects_path_alias_and_hardlink(self):
        import io,tarfile
        def archive(entries):
            buffer=io.BytesIO()
            with tarfile.open(fileobj=buffer,mode='w') as stream:
                for name,kind in entries:
                    info=tarfile.TarInfo(name);info.mode=0o555
                    if kind=='file':info.size=3;stream.addfile(info,io.BytesIO(b'abc'))
                    else:info.type=tarfile.LNKTYPE;info.linkname='other';stream.addfile(info)
            return buffer.getvalue()
        records=git.archive_records(archive([('git','file')]))
        self.assertEqual(records['git']['sha256'],hashlib.sha256(b'abc').hexdigest())
        for entries in ([('../git','file')],[('/git','file')],[('git','file'),('git','file')],[('git','hardlink')]):
            with self.assertRaises(OriginDenied):git.archive_records(archive(entries))

    def test_archive_symlinks_may_only_resolve_selected_image_closure(self):
        reader=git._ImageReader(N(), '5'*64, {'/lib/a','/lib/b'}, __import__('time').monotonic()+2)
        reader.archive=Mock(side_effect=[{'a':{'kind':'link','target':'b'}},{'b':{'kind':'file','sha256':'a'*64}}])
        self.assertEqual(reader.single('/lib/a',follow=True)['kind'],'file')
        reader.archive=Mock(return_value={'a':{'kind':'link','target':'/etc/shadow'}})
        with self.assertRaises(OriginDenied):reader.single('/lib/a',follow=True)
        reader.archive.assert_called_once_with('/lib/a')

    def test_pid1_cgroup_start_and_mapping_correlation(self):
        pid=123;cid='5'*64
        status=('Pid:123\nTgid:123\nPPid:1\nUid:165532 165532 165532 165532\n'
                'Gid:165532 165532 165532 165532\nNSpid:123 1\nNStgid:123 1\n').encode()
        stat_text='123 (sleep) S '+' '.join(['0']*18+['77'])
        group='0::/system.slice/docker-'+cid+'.scope\n'
        binding=git.parse_process_binding(pid,cid,status,stat_text,group)
        self.assertEqual(binding[1],77)
        self.assertNotEqual(binding,git.parse_process_binding(pid,cid,status,stat_text[:-2]+'78',group))
        for changed in ('0::/docker/'+'9'*64,'0::/prefix/system.slice/docker-'+cid+'.scope',group+'1:name=other:/'):
            with self.assertRaises(OriginDenied):git.parse_process_binding(pid,cid,status,stat_text,changed)
        with self.assertRaises(OriginDenied):git.parse_process_binding(pid,cid,status.replace(b'123 1',b'123 2'),stat_text,group)

    def test_payload_verification_reads_actual_selected_container_only(self):
        import json,time
        value=deepcopy(self.selection)
        value['uas_tree_sha256']=hashlib.sha256(git.canonical({'__init__.py':'a'*64,'git_launcher.py':'b'*64})).hexdigest()
        captured=[]
        def file(digest,**extra):return {'kind':'file','uid':0,'mode':0o555,'sha256':digest,**extra}
        class Reader:
            def __init__(inner,engine,container_id,allowed,deadline):captured.append((engine,container_id,deadline));inner.allowed=allowed
            def single(inner,name,**kwargs):
                if name=='/usr/bin/python3':return {'kind':'link','target':'python3.11'}
                if name=='/opt/uas/runtime/git/public-entries.json':return file(value['artifacts'][name],data=json.dumps(list(git.PUBLIC_ENTRIES)).encode())
                return file({**value['artifacts'],**value['abi_artifacts']}.get(name,value['artifacts']['/opt/uas/bin/git']))
            def archive(inner,name):
                if name=='/opt/uas/git-helpers':return {'git-helpers':{'kind':'directory','uid':0,'mode':0o755},'git-helpers/git':{'kind':'link','target':'/proc/self/fd/19'}}
                if name=='/opt/uas/git-hooks':return {'git-hooks':{'kind':'directory','uid':65530,'mode':0o500},'git-hooks/reference-transaction':file('0'*64)}
                if name=='/opt/uas/uas':return {'uas':{'kind':'directory'},'uas/__init__.py':file('a'*64),'uas/git_launcher.py':file('b'*64)}
                base=name.rsplit('/',1)[-1]
                return {base:{'kind':'directory'},**{base+'/'+n:file(value['artifacts']['/opt/uas/bin/git']) for n in git.PUBLIC_ENTRIES}}
        engine=object();deadline=time.monotonic()+1
        with patch.object(git,'_ImageReader',Reader):
            result=git.verify_engine_payload(engine,'5'*64,value,deadline=deadline)
        self.assertEqual(captured,[(engine,'5'*64,deadline)])
        self.assertEqual(result['image_id'],value['image_id'])
        with patch.object(git,'_ImageReader',Reader),patch.object(Reader,'single',return_value=file('9'*64)):
            with self.assertRaises(OriginDenied):git.verify_engine_payload(engine,'5'*64,value,deadline=deadline)

    def test_archive_http_budget_and_fixed_path_close_without_retry(self):
        import time
        from uas import docker_exec_api
        connection=Mock();connection.getresponse.return_value.status=200
        connection.getresponse.return_value.read1.return_value=b'123'
        reader=git._ImageReader(N(socket_path='/run/docker.sock',timeout=5),'5'*64,{'/usr/bin/git'},time.monotonic()+1)
        reader.remaining=2
        with patch.object(docker_exec_api,'_UnixHTTP',return_value=connection) as factory:
            with self.assertRaises(OriginDenied):reader.archive('/etc/passwd')
            factory.assert_not_called()
            with self.assertRaises(OriginDenied):reader.archive('/usr/bin/git')
            connection.request.assert_called_once()
            self.assertIn('/containers/'+'5'*64+'/archive?path=',connection.request.call_args.args[1])
            connection.close.assert_called_once()

    def test_pid_replacement_after_capture_refuses_before_socket_handoff(self):
        import json,time
        from contextlib import nullcontext,ExitStack
        from uas.docker_exec_api import DockerExecAPI
        from uas.lifecycle import Supervisor
        from uas.native_qualification_backend import NativeQualificationObserver
        supervisor=Supervisor.__new__(Supervisor);supervisor.backend=NativeQualificationObserver.__new__(NativeQualificationObserver)
        supervisor._locked=lambda:nullcontext();supervisor._read=lambda:deepcopy(self.state)
        engine=DockerExecAPI.__new__(DockerExecAPI)
        engine.inspect_container=Mock(side_effect=[{'State':{'Pid':123}},{'State':{'Pid':124}}])
        maps={'uid_map':'0 100000 65536\n','gid_map':'0 100000 65536\n','overflow_uid':65534,'overflow_gid':65534}
        mapping=hashlib.sha256(json.dumps(maps,sort_keys=True).encode()).hexdigest()
        resources={'instance':self.state['instance_id'],'workstation_id':'5'*64,'git_manifest_path':'/trusted/git.json','mapping_digest':mapping}
        with ExitStack() as stack:
            stack.enter_context(patch.object(git,'selection',return_value=self.selection))
            stack.enter_context(patch.object(git.NativeGitResources,'_verify_container'))
            stack.enter_context(patch.object(git,'process_binding',return_value=(123,77)))
            stack.enter_context(patch.object(git.os,'pidfd_open',return_value=42))
            stack.enter_context(patch.object(git,'alive',return_value=True))
            stack.enter_context(patch.object(git,'_identity',return_value=(1,42)))
            stack.enter_context(patch.object(__import__('pathlib').Path,'read_text',lambda p:'65534' if 'overflow' in str(p) else '0 100000 65536\n'))
            readback=stack.enter_context(patch.object(git,'verify_engine_payload'))
            close=stack.enter_context(patch.object(git.os,'close'))
            with self.assertRaisesRegex(OriginDenied,'task replaced'):
                git.NativeGitResources.from_session(self.plan,resources,engine,supervisor=supervisor,deadline=time.monotonic()+1)
            readback.assert_called_once();close.assert_called_once_with(42)
            self.assertEqual(engine.inspect_container.call_count,2)
