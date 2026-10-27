"""Pure descriptor/mode model of the exact manual path sequence, NOT kernel proof.

No chmod/chown, listeners, signals, forks, Git, Engine or helper execution. Real
constructors and resolver/tree/journal code run only against in-memory FDs.
The model deliberately rejects directory reads of the root-owned0711 ancestor
while allowing search. Actual DAC/MAC/mount qualification remains manual-only.
"""
from contextlib import ExitStack, contextmanager, nullcontext
import errno
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas import artifact_helper as helper, artifact_target as target
from uas.artifact_protocol import ArtifactError
from uas.checkouts import CheckoutAllocator
from uas.lifecycle import Supervisor
from uas.workstation_exec import EndpointLease

VM=Path(__file__).parent/'vm';ROOT=VM.parent.parent
sys.path.insert(0,str(VM))
try:import guest_artifacts as guest
finally:sys.path.remove(str(VM))
UID=165533;HELPER=165530;NONCE='a'*32


class DescriptorModel:
    """Only the path/FD/DAC rules needed by this source regression, no OS calls."""
    def __init__(self,uid=UID,groups=(HELPER,)):
        self.uid=uid;self.groups=set(groups);self.nodes={};self.fds={};self.events=[];self.nextfd=100
        self.directory('/',0o755,0,0)

    def add(self,path,mode,uid,gid,data=b''):
        path=str(PurePosixPath(path))
        for parent in reversed(PurePosixPath(path).parents):
            if str(parent) not in self.nodes:self.directory(parent,0o755,0,0)
        self.nodes[path]=SimpleNamespace(st_mode=mode,st_uid=uid,st_gid=gid,st_dev=9,
            st_ino=len(self.nodes)+1,st_nlink=1,st_size=len(data),st_mtime_ns=1,st_ctime_ns=1,data=data)
        return self.nodes[path]

    def directory(self,path,mode=0o755,uid=UID,gid=UID):
        return self.add(path,stat.S_IFDIR|mode,uid,gid)

    def file(self,path,data=b'',mode=0o600,uid=UID,gid=UID):
        return self.add(path,stat.S_IFREG|mode,uid,gid,data)

    def bits(self,node):
        return (node.st_mode>>(6 if node.st_uid==self.uid else 3 if node.st_gid in self.groups else 0))&7

    def path(self,path,dir_fd=None):
        value=PurePosixPath(path)
        if not value.is_absolute():
            assert dir_fd in self.fds,'relative path requires a held modeled FD'
            value=PurePosixPath(self.fds[dir_fd]['path'])/value
        assert '..' not in value.parts
        return str(value)

    def search(self,path):
        for parent in reversed(PurePosixPath(path).parents):
            node=self.nodes[str(parent)]
            if not stat.S_ISDIR(node.st_mode):raise NotADirectoryError(errno.ENOTDIR,'modeled ancestor')
            if not self.bits(node)&1:raise PermissionError(errno.EACCES,'modeled ancestor search')

    def stat(self,path,*,dir_fd=None,follow_symlinks=True):
        path=self.path(path,dir_fd);self.search(path)
        if path not in self.nodes:raise FileNotFoundError(errno.ENOENT,'modeled missing node')
        return self.nodes[path]

    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        path=self.path(path,dir_fd);self.search(path)
        self.events.append(('open',path,flags))
        if path not in self.nodes:
            if not flags&os.O_CREAT:raise FileNotFoundError(errno.ENOENT,'modeled missing node')
            parent=self.nodes[str(PurePosixPath(path).parent)]
            if self.bits(parent)&3!=3:raise PermissionError(errno.EACCES,'modeled create')
            self.file(path,mode=mode)
        elif flags&os.O_CREAT and flags&os.O_EXCL:raise FileExistsError(errno.EEXIST,'modeled exclusive node')
        node=self.nodes[path]
        if stat.S_ISLNK(node.st_mode) and flags&os.O_NOFOLLOW:raise OSError(errno.ELOOP,'modeled no-follow')
        if flags&os.O_DIRECTORY and not stat.S_ISDIR(node.st_mode):raise NotADirectoryError(errno.ENOTDIR,'modeled directory')
        if not flags&os.O_PATH:
            needed=4 if flags&os.O_ACCMODE==os.O_RDONLY else 2
            if not self.bits(node)&needed:raise PermissionError(errno.EACCES,'modeled leaf access')
        descriptor=self.nextfd;self.nextfd+=1
        self.fds[descriptor]={'path':path,'flags':flags,'offset':0}
        return descriptor

    def close(self,fd):
        assert fd in self.fds,'unknown or double-closed modeled descriptor'
        self.events.append(('close',self.fds[fd]['path'],self.fds[fd]['flags']));del self.fds[fd]

    def dup(self,fd):
        new=self.nextfd;self.nextfd+=1;self.fds[new]=dict(self.fds[fd]);return new

    def fstat(self,fd):return self.nodes[self.fds[fd]['path']]

    def readable(self,fd):
        if self.fds[fd]['flags']&os.O_PATH:raise OSError(errno.EBADF,'search FD is not readable')

    def read(self,fd,size):
        self.readable(fd);record=self.fds[fd];node=self.fstat(fd)
        value=node.data[record['offset']:record['offset']+size];record['offset']+=len(value);return value

    def write(self,fd,data):
        self.readable(fd);node=self.fstat(fd);node.data+=data;node.st_size=len(node.data)
        self.events.append(('write',self.fds[fd]['path'],len(data)));return len(data)

    def fsync(self,fd):
        self.readable(fd);self.events.append(('sync',self.fds[fd]['path'],0))

    @contextmanager
    def scandir(self,fd):
        self.readable(fd);parent=PurePosixPath(self.fds[fd]['path']);entries=[]
        for path,node in self.nodes.items():
            if path!=str(parent) and PurePosixPath(path).parent==parent:
                entries.append(SimpleNamespace(name=PurePosixPath(path).name,
                    is_file=lambda follow_symlinks=False,n=node:stat.S_ISREG(n.st_mode),
                    stat=lambda follow_symlinks=False,n=node:n))
        yield iter(entries)

    @contextmanager
    def installed(self):
        with ExitStack() as stack:
            for name in ('open','close','dup','fstat','stat','read','write','fsync','scandir'):
                stack.enter_context(patch.object(os,name,getattr(self,name)))
            stack.enter_context(patch.object(os,'getuid',return_value=self.uid))
            stack.enter_context(patch.object(Path,'resolve',autospec=True,side_effect=lambda path:path))
            stack.enter_context(patch.object(Path,'lstat',autospec=True,side_effect=lambda path:self.stat(path,follow_symlinks=False)))
            stack.enter_context(patch.object(helper.uuid,'uuid4',return_value=SimpleNamespace(hex='f'*32)))
            for name in ('mkdir','chmod','chown','fork','pidfd_open'):
                stack.enter_context(patch.object(os,name,side_effect=AssertionError('native operation forbidden')))
            stack.enter_context(patch.object(helper.socket,'socket',side_effect=AssertionError('socket forbidden')))
            stack.enter_context(patch.object(target.subprocess,'Popen',side_effect=AssertionError('process forbidden')))
            yield


def fixture():
    return guest.fixture_layout(NONCE,json.loads((ROOT/'tests/fixtures/two-rooms.json').read_text()))


def populate(model,plan,room):
    paths=plan['rooms'][room]
    model.directory(plan['scratch_root'],0o711,0,0)
    model.directory(plan['state_root'],0o700)
    model.directory(Path(plan['state_root'])/room,0o700)
    model.directory(paths['room_root'])
    for name in ('repo','checkouts','workspace','reference'):model.directory(paths[name])
    model.directory(paths['scratch'],0o711)
    model.directory(paths['journal'],0o700)
    for name in ('targets','launches','probes'):model.directory(Path(paths['journal'])/name,0o700)
    for name,group,socket_name in (('gate',HELPER,'gate.sock'),('control',165531,'hub.sock')):
        model.directory(paths[name],0o710,UID,group)
        model.add(Path(paths[name])/socket_name,stat.S_IFSOCK|0o620,UID,group)
    common=Path(paths['repo'])/'.git';model.directory(common)
    model.directory(common/'refs');model.directory(common/'refs/heads')
    model.file(common/'HEAD',b'ref: refs/heads/main\n')
    model.file(common/'refs/heads/main',b'b'*40+b'\n')
    return paths


class ArtifactPathSequenceTests(unittest.TestCase):
    def construct(self,model,plan,room):
        paths=populate(model,plan,room)
        supervisor=Supervisor(plan['state_root'],room,None,authorize=lambda *_:False,revoke=lambda *_:False)
        allocator=CheckoutAllocator(supervisor,io.StringIO(json.dumps(plan['configuration'])))
        common=Path(paths['repo'])/'.git'
        identity=lambda path:[model.nodes[str(path)].st_dev,model.nodes[str(path)].st_ino]
        state={'version':1,'room_id':room,'instance_id':paths['room_instance'],'project_id':room,
            'repo':str(allocator.repo),'root':str(allocator.root),'common':str(common),
            'filesystem':{'repo':identity(allocator.repo),'root':identity(allocator.root),'common':identity(common)},
            'slots':{'primary':{'path':str(allocator.repo),'branch':'refs/heads/main','base':'b'*40,
                'run':'artifact-run','participant':'builder','active':True,'phase':'ready',
                'identity':{'directory':identity(allocator.repo),'git_metadata':identity(common)}}}}
        model.file(allocator.manifest,json.dumps(state).encode())
        supervisor._locked=Mock(return_value=nullcontext())
        supervisor._read=Mock(return_value={'phase':'running','instance_id':paths['room_instance'],
            'spec':{'project_id':room,'project_paths':[str(allocator.repo),str(allocator.root)]}})
        allocator._git=Mock(side_effect=AssertionError('source Git forbidden'))
        resolver=target.ArtifactSourceResolver(supervisor,allocator)
        source=resolver.resolve('artifact-run','builder',paths['room_instance'])
        targets=target.ArtifactTargets(paths['scratch'],Path(paths['journal'])/'targets',resolver,
            reserve_capacity=Mock(side_effect=AssertionError('no materialization/admission claim')))
        endpoint=helper.GateEndpointLease(Path(paths['gate'])/'gate.sock',owner=UID,group=HELPER)
        self.assertTrue(endpoint.require());self.assertEqual(resolver.current(source),source)
        parent=Path(paths['scratch'])/('d'*32);model.directory(parent,0o710,UID,HELPER)
        model.directory(parent/'tree',0o555)
        lease=target.ArtifactTargetLease(targets,'evaluation-'+room,source,'d'*32,identity(parent))
        lease.target={'target_id':lease.target_id,'head_sha':source['head_sha'],'source_digest':source['source_digest'],
            **target.observe_target(parent/'tree',float('inf'))};lease.phase='prepared'
        self.assertTrue(lease.recheck())
        scope={'version':1,'evaluation_id':lease.evaluation_id,'room_id':room,'room_instance':paths['room_instance'],
            'project_id':room,'repository':'example/'+room,'run_id':'artifact-run','generation':1,
            'participant_id':'builder','policy_id':'fixed','policy_version':1,'policy_digest':'a'*64,
            'gate_id':'fixed','config_digest':'c'*64}
        workstation=helper.GateWorkstation(room,paths['room_instance'],*(['e'*64]*6),'hub-'+room)
        engine=Mock();admission=Mock()
        launch=helper.GateHelperLaunch(engine,workstation,endpoint,Path(paths['journal'])/'launches/fixed.json',
            admission=admission,target_lease=lease,scope=scope)
        journal=helper._LaunchJournal(launch.journal_path)
        try:journal.append({'version':1,'state':'fixture-construction-only'})
        finally:journal.close()
        engine.assert_not_called();self.assertEqual(engine.mock_calls,[])
        admission.assert_not_called();self.assertEqual(admission.mock_calls,[])
        allocator._git.assert_not_called();self.assertEqual(launch.state,'new')
        return paths,endpoint,lease,launch

    def test_full_two_room_construction_resolve_target_endpoint_journal_sequence(self):
        plan=fixture();model=DescriptorModel()
        with model.installed():
            for room in ('alpha','beta'):
                with self.subTest(room=room):self.construct(model,plan,room)
        self.assertEqual(model.fds,{})
        traversals=[flags for kind,path,flags in model.events if kind=='open' and path==plan['scratch_root']]
        self.assertTrue(traversals);self.assertTrue(all(flags&os.O_PATH for flags in traversals))
        for room in ('alpha','beta'):
            paths=plan['rooms'][room]
            for leaf in (paths['gate'],str(Path(paths['journal'])/'launches'),paths['scratch'],
                    str(Path(plan['state_root'])/room),str(Path(paths['scratch'])/('d'*32)/'tree')):
                opens=[flags for kind,path,flags in model.events if kind=='open' and path==leaf]
                self.assertTrue(any(not flags&os.O_PATH for flags in opens),leaf)
        self.assertEqual(stat.S_IMODE(model.nodes[plan['scratch_root']].st_mode),0o711)

    def test_unreadable_leaf_is_not_silently_replaced_by_search_descriptor(self):
        plan=fixture();model=DescriptorModel();paths=populate(model,plan,'alpha')
        model.directory(paths['gate'],0o710,0,HELPER)  # Search allowed, read denied.
        with model.installed(),self.assertRaises(PermissionError) as caught:
            helper.GateEndpointLease(Path(paths['gate'])/'gate.sock',owner=UID,group=HELPER)
        self.assertEqual(caught.exception.errno,errno.EACCES)
        self.assertEqual(model.fds,{})

    def test_missing_search_descriptor_support_refuses_generated_paths_before_open(self):
        plan=fixture();model=DescriptorModel();paths=populate(model,plan,'alpha')
        with model.installed(),patch.object(os,'O_PATH'):
            del os.O_PATH  # Pure module mock; no local kernel feature probing.
            for operation,code in (
                    (lambda:helper.GateEndpointLease(Path(paths['gate'])/'gate.sock',owner=UID,group=HELPER),
                     'GATE_PATH_TRAVERSAL_UNAVAILABLE'),
                    (lambda:target._open_dir(Path(plan['state_root'])/'alpha'),
                     'ARTIFACT_PATH_TRAVERSAL_UNAVAILABLE')):
                with self.subTest(code=code),self.assertRaises(ArtifactError) as caught:operation()
                self.assertEqual(caught.exception.code,code)
        self.assertEqual(model.events,[]);self.assertEqual(model.fds,{})

    def test_replaced_endpoint_is_fenced_before_any_mock_engine_or_listener_use(self):
        plan=fixture();model=DescriptorModel()
        with model.installed():
            paths,endpoint,lease,launch=self.construct(model,plan,'alpha')
            model.nodes[str(endpoint.path)].st_ino+=1;launch.admission.require.return_value=True
            listener=Mock()
            with self.assertRaises(ArtifactError) as caught:launch.start(listener)
            self.assertEqual(caught.exception.code,'GATE_ENDPOINT_REPLACED')
            self.assertEqual(launch.engine.mock_calls,[]);self.assertEqual(listener.mock_calls,[])
        self.assertEqual(model.fds,{})

    def test_fixed_trusted_binary_walk_retains_readable_installation_assumption(self):
        model=DescriptorModel()
        for path in ('/usr','/usr/bin'):model.directory(path,0o755,0,0)
        for path in (target.GIT_BINARY,target.LIMIT_BINARY):model.file(path,b'fixed',0o555,0,0)
        with model.installed():
            target._trusted_executable(target.GIT_BINARY);target._trusted_executable(target.LIMIT_BINARY)
            model.nodes['/usr'].st_mode=stat.S_IFDIR|0o711
            with self.assertRaises(PermissionError) as caught:target._trusted_executable(target.GIT_BINARY)
            self.assertEqual(caught.exception.errno,errno.EACCES)
        self.assertEqual(model.fds,{})

    def test_hub_endpoint_metadata_needs_search_not_group_directory_read(self):
        model=DescriptorModel(uid=65531,groups=(65531,))
        model.directory('/uas/control',0o710,65533,65531)
        model.add('/uas/control/hub.sock',stat.S_IFSOCK|0o620,65533,65531)
        with model.installed():
            endpoint=EndpointLease('/uas/control/hub.sock',owner=65533,group=65531)
            endpoint.require()
            with self.assertRaises(PermissionError):model.open('/uas/control',os.O_RDONLY|os.O_DIRECTORY)
        self.assertEqual(model.fds,{})

    def test_bootstrap_search_ancestors_and_readable_tree_are_fixed_source_contract(self):
        source=(ROOT/'runtime/workstation/artifact_bootstrap.c').read_text()
        self.assertIn('open("/",O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)',source)
        self.assertIn('open_beneath(root,AG_TARGETS,O_PATH|O_DIRECTORY|O_CLOEXEC,containment)',source)
        self.assertIn('open_beneath(targets,target,O_PATH|O_DIRECTORY|O_CLOEXEC,containment|RESOLVE_NO_XDEV)',source)
        self.assertIn('open_beneath(parent,"tree",O_RDONLY|O_DIRECTORY|O_CLOEXEC,containment|RESOLVE_NO_XDEV)',source)
        self.assertIn('lstat("/uas/gate",directory)||lstat(AG_ENDPOINT,node)',source)
        self.assertIn('(parent_info.st_mode&07777)!=0710',source)
        self.assertIn('(info.st_mode&07777)!=0555',source)
        self.assertIn('!(filesystem.f_flag&ST_RDONLY)',source)

    def test_helper_group_search_model_does_not_require_parent_directory_listing(self):
        model=DescriptorModel(uid=65530,groups=(65530,))
        model.directory('/uas/gate-targets',0o711,65533,65533)
        parent='/uas/gate-targets/'+('d'*32)
        model.directory(parent,0o710,65533,65530);model.directory(parent+'/tree',0o555,65533,65533)
        descriptor=model.open(parent,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            with self.assertRaises(OSError):
                with model.scandir(descriptor):pass
            leaf=model.open('tree',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
            with model.scandir(leaf) as entries:self.assertEqual(list(entries),[])
            model.close(leaf)
            with self.assertRaises(PermissionError):model.open(parent,os.O_RDONLY|os.O_DIRECTORY)
        finally:model.close(descriptor)
        self.assertEqual(model.fds,{})

    def test_shared_walker_is_shipped_in_exact_manual_payload(self):
        import ast
        module=ast.parse((VM/'run_artifacts.py').read_text())
        assignment=next(node for node in module.body if isinstance(node,ast.Assign)
            and any(isinstance(name,ast.Name) and name.id=='SOURCES' for name in node.targets))
        self.assertIn('uas/artifact_paths.py',ast.literal_eval(assignment.value))


if __name__=='__main__':unittest.main()
