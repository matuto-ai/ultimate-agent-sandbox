"""Listener layout generation ownership; syscalls and commands remain inert."""
from contextlib import ExitStack,contextmanager
from copy import deepcopy
from pathlib import Path
import stat
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock,patch
from uas import local_listener_recovery as recovery
from uas.local_host_profile import HostProfileError,digest

A='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';B='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'


class World:
    def __init__(self,git=False,gate=False):
        self.parent=Path('/data/control/instances/'+'a'*32+'/native')
        self.root=Path('/run/endpoints')/('a'*32);self.boot=A
        self.state={'instance_id':'a'*32};self.records={};self.exists=True;self.identity=[1,50]
        self.created=[];self.command=[];self.fail=None;self.volatile={'peer','control'}|({'git'} if git else set())|({'gate'} if gate else set())
        self.description={'binding':{'version':1,'nonce':'b'*32,'instance':'a'*32,'profile_digest':'c'*64,'path':str(self.root)},
             'native_identity':[0,20],'volatile':{name:{'path':str(self.root/name),'uid':165533,
                'gid':165530 if name=='gate' else 165531 if name=='control' else 165532,'mode':0o710} for name in self.volatile},
             'durable':{'supervisor':{'path':str(self.parent/'supervisor'),'identity':[0,21]}},
             'gate':{'scratch_root':{'path':str(self.parent/'gate-targets'),'identity':[0,30],'label':'fixed'}} if gate else None}
        self.backend=N(profile=N(native_document={'version':3},digest='c'*64,git_manifest={} if git else None,git_plan=object()),
                       endpoints=self.root.parent,level='s0:c1,c2')
    def proof(self):
        return {'identity':self.identity[:],'paths':{name:{'identity':[self.identity[0],100+i],
            'label':'system_u:object_r:container_file_t:s0:c1,c2'} for i,name in enumerate(sorted(self.volatile))},'git':{}}
    def observe(self,*args):
        if not self.exists:raise FileNotFoundError('missing')
        if self.fail=='owner':raise HostProfileError('LISTENER_OWNER_BINDING')
        return self.proof()
    def append(self,fd,name,value):
        if name in self.records:
            if self.records[name]!=value:raise HostProfileError('LISTENER_RECORD_CONFLICT')
            return False
        self.records[name]=deepcopy(value)
        if self.fail=='intent' and name.endswith('.intent.json'):raise OSError('lost intent reply')
        if self.fail=='confirmed' and name.endswith('.confirmed.json'):raise OSError('lost confirmation reply')
        return True
    def mkdir(self,path,**kwargs):
        path=Path(path)
        assert self.records.get(recovery.PREFIX+self.boot+'.intent.json') is not None
        self.created.append(path)
        if self.fail=='mkdir':raise OSError('mkdir unknown')
        if path==self.root:
            assert not self.exists
            self.exists=True;self.identity=[2,60]
        assert path==self.root or path in [self.root/name for name in self.volatile]
    def installed(self):
        stack=ExitStack()
        stack.enter_context(patch.object(recovery,'_selection',side_effect=lambda *_:(self.parent,self.root,deepcopy(self.description))))
        stack.enter_context(patch.object(recovery,'_open_native',return_value=10))
        stack.enter_context(patch.object(recovery,'_read',side_effect=lambda fd,name:deepcopy(self.records.get(name))))
        stack.enter_context(patch.object(recovery,'_append',side_effect=self.append))
        stack.enter_context(patch.object(recovery,'_observe',side_effect=self.observe))
        stack.enter_context(patch.object(recovery,'boot_id',side_effect=lambda:self.boot))
        stack.enter_context(patch.object(recovery.os.path,'lexists',side_effect=lambda _:self.exists))
        @contextmanager
        def scan(fd):yield iter(N(name=name) for name in self.records)
        stack.enter_context(patch.object(recovery.os,'scandir',side_effect=scan))
        stack.enter_context(patch.object(Path,'lstat',return_value=N(st_mode=stat.S_IFDIR|0o711,st_uid=0,st_gid=0,st_dev=7,st_ino=20)))
        stack.enter_context(patch.object(Path,'resolve',lambda path:path))
        stack.enter_context(patch.object(Path,'mkdir',lambda path,**kwargs:self.mkdir(path,**kwargs)))
        for name in ('chown','chmod','close'):stack.enter_context(patch.object(recovery.os,name))
        stack.enter_context(patch.object(recovery.os,'open',return_value=22))
        stack.enter_context(patch.object(recovery.os,'fstat',return_value=N(st_dev=7,st_ino=20)))
        stack.enter_context(patch.object(recovery,'_git_expected',return_value=None))
        stack.enter_context(patch.object(recovery.native,'directory_identity',return_value=[2,60]))
        stack.enter_context(patch.object(recovery.native,'command',side_effect=lambda *args:self.command.append(args)))
        stack.enter_context(patch('uas.native_git_resources.prepare_views',side_effect=lambda *_:self.command.append(('prepare_views',))))
        return stack
    def record(self):recovery.record_layout(self.backend,self.state)
    def recover(self):return recovery.recover_layout(self.backend,self.state)


class ListenerRecoveryTests(unittest.TestCase):
    def test_initial_record_and_intact_reopen_no_mutation(self):
        w=World()
        with w.installed():w.record();self.assertFalse(w.recover())
        self.assertEqual(w.created,[]);self.assertEqual(w.command,[])
    def test_newboot_restores_only_volatile_paths_with_git_and_gate(self):
        w=World(git=True,gate=True)
        with w.installed():
            w.record();w.exists=False;w.boot=B
            self.assertTrue(w.recover());self.assertFalse(w.recover())
        self.assertEqual(set(w.created),{w.root,*[w.root/name for name in w.volatile]})
        self.assertIn(('prepare_views',),w.command)
        self.assertIn('gate-scratch.json',w.records);self.assertIn('owner.json',w.records)
        self.assertIn(recovery.PREFIX+B+'.confirmed.json',w.records)
    def test_sameboot_loss_never_creates(self):
        w=World()
        with w.installed():
            w.record();w.exists=False
            with self.assertRaisesRegex(HostProfileError,'LISTENER_SAME_BOOT_LOSS'):w.recover()
        self.assertEqual(w.created,[])
    def test_unknown_intent_or_mkdir_never_reissued(self):
        for stage in ('intent','mkdir'):
            w=World()
            with w.installed():
                w.record();w.exists=False;w.boot=B;w.fail=stage
                with self.assertRaises(OSError):w.recover()
                count=len(w.created);w.fail=None
                with self.assertRaisesRegex(HostProfileError,'LISTENER_RECOVERY_UNKNOWN'):w.recover()
            self.assertEqual(len(w.created),count)
    def test_partial_present_root_cannot_bypass_missing_confirmation(self):
        w=World()
        with w.installed():
            w.record();w.boot=B;w.exists=False;w.fail='owner'
            with self.assertRaises(HostProfileError):w.recover()
            self.assertTrue(w.exists);count=len(w.created);w.fail=None
            with self.assertRaisesRegex(HostProfileError,'LISTENER_RECOVERY_UNKNOWN'):w.recover()
        self.assertEqual(len(w.created),count)
    def test_lost_success_confirmation_reconciles_without_retry(self):
        w=World()
        with w.installed():
            w.record();w.boot=B;w.exists=False;w.fail='confirmed'
            with self.assertRaises(OSError):w.recover()
            count=len(w.created);w.fail=None;self.assertFalse(w.recover())
        self.assertEqual(len(w.created),count)
    def test_existing_foreign_layout_and_changed_durable_description_refuse(self):
        for drift in ('volatile','durable'):
            w=World()
            with w.installed():
                w.record()
                if drift=='volatile':w.identity=[9,9]
                else:w.description['native_identity']=[0,999]
                with self.assertRaises(HostProfileError):w.recover()
            self.assertEqual(w.created,[])
    def test_manifest_missing_or_scope_changed_refuses(self):
        w=World()
        with w.installed():
            with self.assertRaisesRegex(HostProfileError,'LISTENER_RECOVERY_MANIFEST'):w.recover()
            w.record();w.records[recovery.MANIFEST]['description']['binding']['instance']='b'*32
            with self.assertRaises(HostProfileError):w.recover()
    def test_legacy_record_is_noop(self):
        w=World();w.backend.profile.native_document['version']=2
        with w.installed():w.record()
        self.assertEqual(w.records,{})
    def test_history_orphan_foreign_scope_and_bad_name_refuse(self):
        for name,value in [('bad.json',{}),(B+'.confirmed.json',{}),(B+'.intent.json',{'binding':'bad','boot_id':B})]:
            w=World()
            with w.installed():
                w.record();w.records[recovery.PREFIX+name]=value
                with self.assertRaises(HostProfileError):w.recover()
            self.assertEqual(w.created,[])

    def test_corrupt_initial_proof_is_not_adopted_as_authority(self):
        w=World()
        with w.installed():
            w.record();w.records[recovery.MANIFEST]['initial']['paths']['peer']['extra']='bad'
            with self.assertRaisesRegex(HostProfileError,'LISTENER_PROOF_SHAPE'):w.recover()
        self.assertEqual(w.created,[])


class DurableLayoutProofTests(unittest.TestCase):
    def setup_backend(self):
        instance='a'*32;parent=Path('/data/control/instances')/instance/'native';endpoints=Path('/run/endpoints')
        owners={'supervisor':565533,'hub':565531,'broker':565534,'runtime':565532,'gate':565530}
        layout={name:parent/name for name in ('supervisor','broker','hub','git-broker','gate-targets')}
        layout.update({name:endpoints/instance/name for name in ('peer','control','git','gate')})
        selected={'scratch_root':layout['gate-targets'],'journal_root':layout['supervisor']/'gate-target-journals',
                  'launch_journal_root':layout['supervisor']/'gate-launches'}
        nodes={parent:N(st_dev=99,st_ino=20,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o711)}
        for i,name in enumerate(('supervisor','broker','hub','git-broker','gate-targets')):
            owner=owners['broker'] if name in ('broker','git-broker') else owners['supervisor']
            nodes[layout[name]]=N(st_dev=99,st_ino=30+i,st_uid=owner,
                st_gid=owners['hub'] if name=='hub' else owner,
                st_mode=stat.S_IFDIR|(0o2770 if name=='hub' else 0o711 if name=='gate-targets' else 0o700))
        for i,name in enumerate(('journal_root','launch_journal_root')):
            nodes[selected[name]]=N(st_dev=99,st_ino=40+i,st_uid=owners['supervisor'],st_gid=owners['supervisor'],st_mode=stat.S_IFDIR|0o700)
        def verified(path):
            value=nodes[Path(path)]
            if value.st_dev!=99:raise HostProfileError('LOCAL_NATIVE_STORAGE_FILESYSTEM')
            return [0,value.st_ino]
        profile=N(native_document={'version':3},require_host_unchanged=Mock(),storage_identity=Mock(side_effect=verified),
                  owners=owners,git_manifest={},gate_manifest={},gate_plan=object(),project_id=401,digest='c'*64)
        backend=N(profile=profile,_binding=Mock(),layout=lambda _:layout,endpoints=endpoints,level='s0:c1,c2',
                  _endpoint_record=lambda _: {'version':1,'instance':instance,'profile_digest':'c'*64,'path':str(endpoints/instance)})
        return backend,{'instance_id':instance},selected,nodes
    def test_real_selection_revalidates_each_durable_inode_quota_owner_and_label(self):
        backend,state,selected,nodes=self.setup_backend()
        with patch.object(recovery.os,'geteuid',return_value=0),patch.object(Path,'lstat',lambda path:nodes[path]),patch.object(Path,'resolve',lambda path:path),patch('uas.native_gate_resources.paths',return_value=selected),patch.object(recovery.native,'project_attributes',return_value=(401,True)),patch.object(recovery.native,'command',return_value='system_u:object_r:container_file_t:s0:c1,c2'):
            parent,root,value=recovery._selection(backend,state)
            self.assertEqual(value['native_identity'],[0,20])
            self.assertEqual(value['gate']['journal_root']['identity'],[0,40])
            self.assertEqual(backend.profile.storage_identity.call_count,8)
            nodes[selected['journal_root']].st_uid=165533
            with self.assertRaisesRegex(HostProfileError,'LISTENER_DIRECTORY_OWNER'):recovery._selection(backend,state)
            nodes[selected['journal_root']].st_uid=565533;nodes[selected['journal_root']].st_dev=100
            with self.assertRaisesRegex(HostProfileError,'LOCAL_NATIVE_STORAGE_FILESYSTEM'):recovery._selection(backend,state)
    def test_gate_quota_and_label_drift_refuse_before_recovery_issuance(self):
        backend,state,selected,nodes=self.setup_backend()
        with patch.object(recovery.os,'geteuid',return_value=0),patch.object(Path,'lstat',lambda path:nodes[path]),patch.object(Path,'resolve',lambda path:path),patch('uas.native_gate_resources.paths',return_value=selected),patch.object(recovery.native,'project_attributes',return_value=(999,True)),patch.object(recovery.native,'command',return_value='system_u:object_r:container_file_t:s0:c1,c2'):
            with self.assertRaisesRegex(HostProfileError,'LISTENER_GATE_DURABLE_PROOF'):recovery._selection(backend,state)
        with patch.object(recovery.os,'geteuid',return_value=0),patch.object(Path,'lstat',lambda path:nodes[path]),patch.object(Path,'resolve',lambda path:path),patch('uas.native_gate_resources.paths',return_value=selected),patch.object(recovery.native,'project_attributes',return_value=(401,True)),patch.object(recovery.native,'command',return_value='system_u:object_r:default_t:s0'):
            with self.assertRaisesRegex(HostProfileError,'LISTENER_DIRECTORY_LABEL'):recovery._selection(backend,state)
    def test_held_native_directory_must_match_live_verified_device_and_inode(self):
        profile=N(storage_identity=Mock(return_value=[0,20]));parent=Path('/data/native')
        node=N(st_dev=99,st_ino=20,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o711)
        with patch.object(recovery.os,'open',return_value=10),patch.object(recovery.os,'close') as close,patch.object(recovery.os,'fstat',return_value=node),patch.object(Path,'lstat',return_value=N(st_dev=100,st_ino=20)):
            with self.assertRaisesRegex(HostProfileError,'LISTENER_DURABLE_CHANGED'):recovery._open_native(parent,{'native_identity':[0,20]},profile)
            close.assert_called_once_with(10)

    def test_real_volatile_observer_requires_owner_record_and_exact_git_overlay(self):
        root=Path('/run/endpoints')/('a'*32);level='s0:c1,c2';offset=500000
        backend=N(level=level,profile=N(git_manifest={},host_profile=N(offset=offset),
            git_plan=N(room={'id':'room','project':{'id':'project','repository':'org/repo'}})))
        description={'binding':{'instance':'a'*32,'path':str(root)},'gate':None,
            'volatile':{'peer':{'path':str(root/'peer'),'uid':565533,'gid':565532,'mode':0o710}}}
        nodes={root:N(st_dev=1,st_ino=10,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o711),
               root/'peer':N(st_dev=1,st_ino=11,st_uid=565533,st_gid=565532,st_mode=stat.S_IFDIR|0o710)}
        for i,name in enumerate(('git-views','git-views/primary','git-views/primary/gitdir','git-views/primary/common','git-fixed','git-workspace')):
            nodes[root/name]=N(st_dev=1,st_ino=20+i,st_uid=offset,st_gid=offset,st_mode=stat.S_IFDIR|0o755)
        expected=recovery._git_expected(backend);descriptors={};corrupt=[False]
        def opened(path,*args,**kwargs):
            fd=30+len(descriptors);descriptors[fd]=Path(path);return fd
        def info(fd):
            raw=expected[descriptors[fd].name]
            return N(st_dev=1,st_ino=fd,st_mode=stat.S_IFREG|0o444,st_uid=offset,st_gid=offset,st_nlink=1,st_size=len(raw))
        with patch.object(Path,'lstat',lambda path:nodes[path]),patch.object(Path,'resolve',lambda path:path),patch.object(recovery.os,'open',side_effect=opened),patch.object(recovery.os,'close'),patch.object(recovery.os,'fstat',side_effect=info),patch.object(recovery.os,'read',side_effect=lambda fd,size:b'bad' if corrupt[0] else expected[descriptors[fd].name]),patch.object(recovery,'_read',return_value={**description['binding'],'identity':[1,10]}),patch.object(recovery.native,'command',return_value='system_u:object_r:container_file_t:'+level):
            proof=recovery._observe(backend,{},root,description)
            recovery._proof_shape(backend,description,proof)
            self.assertEqual(proof['paths']['peer']['identity'],[1,11])
            self.assertEqual(len(proof['git']),8)
            corrupt[0]=True
            with self.assertRaisesRegex(HostProfileError,'LISTENER_GIT_OVERLAY'):recovery._observe(backend,{},root,description)
