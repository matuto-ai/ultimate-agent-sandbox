#!/usr/bin/env python3
"""Actual mapped Supervisor for the explicit artifacts-only disposable VM.

All authority comes from fixture-owned container/slot/profile observations.
Operational journals persist before effects. Faults are fixed source injections,
not caller-selectable helper commands or mocked admission/verdicts.
"""
from contextlib import ExitStack, closing, contextmanager
import ctypes
import hashlib
import io
import json
import os
import re
from pathlib import Path
import select
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time

from uas.artifact_helper import (GateWorkstation, GateEndpointLease, GateHelperLaunch,
    GateSupervisorService, dispatch_gate_control)
from uas.artifact_protocol import ArtifactError, RESERVATION_BYTES, canonical, decode_record
from uas.artifact_target import ArtifactSourceResolver, ArtifactTargets, observe_target
from uas.checkouts import CheckoutAllocator
from uas.docker_exec_api import DockerExecAPI
from uas.kernel_origin import HeldOrigin, OriginDenied, _identity, alive, enable, probe, receive
from uas.lifecycle import Supervisor, FixtureSpec
from artifact_hub import RELEASE, DONE_ACK
from artifact_diagnostics import (captured, decoded_json, supervisor_failure, SUPERVISOR_PREFIX,
    mount_failure, MOUNT_PREFIX, progress_record, PROGRESS_PREFIX)

UID=165533
HELPER=165530
MAX_LOG=1<<20


def expect(value,message):
    if not value:raise RuntimeError(message)


@contextmanager
def diagnostic_boundary(phase):
    """Fixture-only typed failures; preserve the original operational exception."""
    try:yield
    except BaseException as error:
        try:
            value=supervisor_failure(phase,error,ArtifactError)
            print(SUPERVISOR_PREFIX.decode()+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)
        except BaseException:
            pass  # A broken diagnostic stream cannot replace the actual failure.
        raise


def command(*arguments,timeout=15):
    result=captured('outer-facts',arguments,output_limit=65536,inclusive=True,
        stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,
        env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
    return decoded_json('outer-facts',result)


@contextmanager
def target_labels(level):
    """Fixed per-Room object labels under stock policy; no policy installation."""
    library=ctypes.CDLL('libselinux.so.1',use_errno=True)
    library.setfscreatecon.argtypes=[ctypes.c_char_p];library.setfscreatecon.restype=ctypes.c_int
    context=('system_u:object_r:container_file_t:'+level).encode()
    if library.setfscreatecon(context)!=0:raise OSError(ctypes.get_errno(),'stock target creation label denied')
    try:yield
    finally:
        if library.setfscreatecon(None)!=0:raise OSError(ctypes.get_errno(),'target creation label reset denied')


TMPFS_OPTIONS='rw,nosuid,nodev,noexec,size=8m,mode=0700,uid=65532,gid=65532'


def expected_bind_mounts(config):
    result={'/uas/gate':(config['gate'],False),'/uas/gate-targets':(config['scratch'],False),
        '/uas/project':(config['repo'],True)}
    if config.get('foreign_scratch'):result['/uas/foreign']=(config['foreign_scratch'],False)
    return result


def require_mount_configuration(info,config):
    """Exact Engine inspect binds + separate legacy --tmpfs configuration.

    HostConfig.Tmpfs is configured intent, not an observed runtime mount. The
    fixed in-container probe independently checks the actual /tmp mount below.
    No additional mount representation or destination is silently admitted.
    """
    expected=expected_bind_mounts(config);mounts=info.get('Mounts')
    expect(type(mounts) is list and len(mounts)==len(expected),'mount set cardinality')
    seen=set()
    for item in mounts:
        expect(type(item) is dict and type(item.get('Destination')) is str,'mount record shape')
        destination=item['Destination']
        expect(destination in expected and destination not in seen,'unexpected or duplicate mount')
        seen.add(destination);source,writable=expected[destination]
        expect(item.get('Type')=='bind' and item.get('Source')==source
            and type(item.get('RW')) is bool and item['RW'] is writable
            and item.get('Propagation')=='rprivate','exact bind mount profile')
    expect(seen==set(expected),'missing bind mount')
    tmpfs=info['HostConfig'].get('Tmpfs')
    expect(type(tmpfs) is dict and set(tmpfs)=={'/tmp'} and type(tmpfs['/tmp']) is str,
        'exact singleton tmpfs configuration')
    options=tmpfs['/tmp'].split(',')
    expect(len(options)==8 and len(set(options))==8 and set(options)==set(TMPFS_OPTIONS.split(',')),
        'exact bounded tmpfs options')


def require_runtime_tmpfs(value):
    """Independent observed mount/held-FD facts, never configured=observed."""
    numeric={'mount_id','parent_mount_id','device_major','device_minor','size_bytes',
        'allocation_unit','uid','gid','mode','device','inode'}
    expect(type(value) is dict and set(value)==numeric|{'version','filesystem','mount_flags','statvfs_flags'},
        'actual tmpfs observation shape')
    expect(type(value['version']) is int and value['version']==1 and value['filesystem']=='tmpfs',
        'actual tmpfs filesystem')
    expect(all(type(value[k]) is int and 0<=value[k]<1<<64 for k in numeric),'actual tmpfs numeric facts')
    expected_flags={'readonly':False,'nosuid':True,'nodev':True,'noexec':True}
    for field in ('mount_flags','statvfs_flags'):
        expect(type(value[field]) is dict and set(value[field])==set(expected_flags)
            and all(type(v) is bool for v in value[field].values()) and value[field]==expected_flags,
            'actual tmpfs restrictive flags')
    expect(value['mount_id']>0 and value['parent_mount_id']>0 and value['inode']>0
        and value['allocation_unit'] in (512,1024,2048,4096)
        and value['size_bytes']==8<<20 and value['uid']==65532 and value['gid']==65532
        and value['mode']==0o700 and os.major(value['device'])==value['device_major']
        and os.minor(value['device'])==value['device_minor'],'actual tmpfs identity and resource profile')


def report_mount_failure(phase,info,config,runtime=None):
    try:
        value=mount_failure(phase,info,expected_bind_mounts(config),TMPFS_OPTIONS,runtime)
        print(MOUNT_PREFIX.decode()+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)
    except BaseException:
        pass  # Diagnostics must never replace the actual admission failure.


class NativeAdmission:
    """Fresh actual Engine + kernel/image observations; never a true stub."""
    def __init__(self,engine,config):
        self.engine,self.config=engine,config;self.observations=[];self.target_lease=None
    def require(self,workstation):
        c=self.config;info=self.engine._request('GET','/containers/'+workstation.container_id+'/json')
        host,configuration=info['HostConfig'],info['Config']
        expect(info['Image']=='sha256:'+workstation.image_digest and info['State']['Running'] is True,'exact live immutable image')
        expect(configuration['Labels'].get('uas.artifact-owner')==c['nonce'],'exact disposable ownership')
        expect(host['ReadonlyRootfs'] is True and host['CapDrop']==['ALL'] and not host['Privileged'],'outer readonly/capability boundary')
        expect(host['NetworkMode']=='none' and host['PidMode']=='' and host['UsernsMode']!='host' and host['IpcMode']!='host','private namespaces')
        expect(any(v in host['SecurityOpt'] for v in ('no-new-privileges','no-new-privileges=true')),'outer NNP')
        expect('seccomp=unconfined' not in host['SecurityOpt'] and 'label=disable' not in host['SecurityOpt'],'no permissive fallback')
        expect(host['Memory']==256<<20 and host['MemorySwap']==256<<20 and host['PidsLimit']==64 and host['NanoCpus']==500000000,'admitted Room resource ceiling')
        expect(configuration['User']=='65532:65532' and configuration['Entrypoint']==['/opt/uas/bin/tini'],'fixed Workstation profile')
        expect(info['ProcessLabel'].endswith(':'+c['level']) and ':container_t:' in info['ProcessLabel'],'stock MCS process label')
        try:require_mount_configuration(info,c)
        except BaseException:
            report_mount_failure('inspect-mounts',info,c)
            raise
        facts=command('docker','exec','--user','65532:65532',workstation.container_id,
            '/usr/bin/python3','/opt/uas/tests/vm/artifact_room_probe.py','facts')
        expect(facts['uid']==65532 and facts['gid']==65532 and facts['kernel_status']=={
            'CapEff':'0000000000000000','CapBnd':'0000000000000000','NoNewPrivs':'1','Seccomp':'2'},'actual outer process boundary')
        try:require_runtime_tmpfs(facts.get('tmp_mount'))
        except BaseException:
            report_mount_failure('runtime-tmpfs',info,c,facts.get('tmp_mount'))
            raise
        mapping={key:facts[key] for key in ('uid_map','gid_map','overflow_uid','overflow_gid')}
        expect(' '.join(mapping['uid_map'].split())=='0 100000 65536' and ' '.join(mapping['gid_map'].split())=='0 100000 65536'
            and mapping['overflow_uid']==65534 and mapping['overflow_gid']==65534,'actual dedicated mapping')
        expect(hashlib.sha256(json.dumps(mapping,sort_keys=True).encode()).hexdigest()==workstation.mapping_digest,'mapping digest')
        expect(facts['helper_sha256']==c['helper_sha256'] and facts['outer_socket_creation'] is True,'immutable static files and discriminating network baseline')
        expect(all(value==2 for value in facts['private_paths'].values()),'private authority exposed')
        expect(self.target_lease is not None,'exact target label admission required')
        for directory,dirs,files in os.walk(self.target_lease.path,followlinks=False,
                onerror=lambda error:(_ for _ in ()).throw(error)):
            for node in [Path(directory),*(Path(directory)/name for name in files)]:
                label=os.getxattr(node,'security.selinux',follow_symlinks=False).decode().rstrip('\0')
                expect(label.endswith(':'+c['level']) and ':container_file_t:' in label,'actual target MCS label before release')
        self.observations.append({'kernel_status':facts['kernel_status'],'mapping_digest':workstation.mapping_digest,
            'tmp_mount':facts['tmp_mount'],
            'outer_socket_creation':True,'label':facts['label'],'helper_sha256':facts['helper_sha256']})
        return True



def pack_fixture_source(git,repo):
    """Generate only the supported ordinary pack/index fixture, before poison."""
    git('-c','pack.writeReverseIndex=false','-c','repack.writeBitmaps=false',
        '-c','gc.writeCommitGraph=false','gc','--prune=now')
    entries=list((repo/'.git/objects/pack').iterdir())
    expect(0<len(entries)<=512,'bounded nonempty actual fixture pack required')
    names=set()
    for path in entries:
        node=path.lstat()
        expect(stat.S_ISREG(node.st_mode) and node.st_nlink==1
            and re.fullmatch(r'pack-[0-9a-f]{40}\.(pack|idx)',path.name),'unsupported generated fixture pack auxiliary')
        names.add(path.name)
    packs={name[:-5] for name in names if name.endswith('.pack')}
    indexes={name[:-4] for name in names if name.endswith('.idx')}
    expect(packs and packs==indexes,'paired actual fixture pack/index required')


def setup_source(config):
    """Actual allocator records a benign fixture checkout before poisoning it."""
    from datetime import datetime,timezone
    room=config['room'];base=Path(config['state']);base.mkdir(mode=0o700,exist_ok=True)
    supervisor=Supervisor(base,room,None,authorize=lambda *_:True,revoke=lambda *_:False)
    raw=json.loads(Path(config['configuration']).read_text())
    selected=next(item for item in raw['rooms'] if item['id']==room)
    repo=Path(selected['project']['roots']['repo']);checkouts=Path(selected['project']['roots']['checkouts'])
    # No source-config execution occurs after the intentionally poisoned state.
    env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
         'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_CONFIG_COUNT':'0'}
    def git(*args):
        phase='source-init' if args[0]=='init' else 'source-add' if args[0]=='add' else (
            'source-commit' if 'commit' in args else 'source-pack')
        value=captured(phase,['/usr/bin/git','-C',str(repo),*args],output_limit=65536,
            env=env,capture_output=True,timeout=10)
        return value.stdout.decode().strip()
    git('init','-b','main');(repo/'docs').mkdir();(repo/'README.md').write_text('committed artifact proof\n')
    (repo/'docs/evidence.txt').write_text('committed directory presence\n')
    git('add','README.md','docs/evidence.txt')
    git('-c','user.name=Artifact Fixture','-c','user.email=artifact@example.invalid','commit','-m','fixed qualification subject')
    pack_fixture_source(git,repo)  # Actual Git packs; no new parser or widened layout.
    spec=FixtureSpec(room,selected['project']['id'],tuple(sorted(selected['project']['roots'].values())),
        'sha256:'+config['image_digest'],'sha256:'+hashlib.sha256(canonical(raw)).hexdigest(),'sha256:'+config['profile_digest'])
    with supervisor._locked():
        supervisor._save({'version':1,'room_id':room,'instance_id':config['room_instance'],
            'spec':spec.document(),'phase':'running','desired':'running','created_at':datetime.now(timezone.utc).isoformat(),
            'pending_spec':None,'authority':'not-issued'})
        supervisor._read()  # Existing persisted ownership schema, not a mock.
    allocator=CheckoutAllocator(supervisor,io.StringIO(json.dumps(raw)))
    slot=allocator.allocate('artifact-run','builder')
    marker=Path(config['journal'])/'source-config-executed'
    (repo/'.git/config').write_text('[core]\n\tbare = false\n\tfsmonitor = !touch '+str(marker)+'\n'
        '[filter "poison"]\n\tclean = touch '+str(marker)+'\n\tsmudge = touch '+str(marker)+'\n')
    (repo/'.gitattributes').write_text('* filter=poison\n')
    (repo/'README.md').write_bytes(b'')  # Mutable dirty checkout must not qualify.
    (repo/'.git/hooks/post-checkout').write_text('#!/bin/sh\ntouch '+str(marker)+'\n')
    (repo/'.git/hooks/post-checkout').chmod(0o755)
    resolver=ArtifactSourceResolver(supervisor,allocator)
    with diagnostic_boundary('source-resolve'):
        source=resolver.resolve('artifact-run','builder',config['room_instance'])
    expect(source['head_sha']==slot['observed_head'],'exact committed slot head')
    return supervisor,allocator,resolver,source,marker


def wait_exit(origin,deadline):
    poller=select.poll();poller.register(origin.pidfd,select.POLLIN)
    events=poller.poll(max(0,int((deadline-time.monotonic())*1000)))
    expect(events and not alive(origin.pidfd) and _identity(origin.pidfd)==origin.identity,'actual held test task exit required')


def allocated(roots):
    """Conservative bounded fixture admission; no traversal of file contents."""
    used=nodes=0;deadline=time.monotonic()+5
    for root in roots:
        for directory,dirs,files in os.walk(root,followlinks=False,
                onerror=lambda error:(_ for _ in ()).throw(error)):
            expect(time.monotonic()<deadline and len(Path(directory).relative_to(root).parts)<=64,
                'bounded quota admission traversal')
            for node in [Path(directory),*(Path(directory)/name for name in files)]:
                info=os.lstat(node);used+=info.st_blocks*512;nodes+=1
                expect(nodes<=16384,'bounded quota admission inode scan')
            expect(not any((Path(directory)/name).is_symlink() for name in dirs),'quota directory alias unsupported')
    return used,nodes



def durable_probe_record(path,value,*,create=False):
    """Private fixture journal; durable before any potentially live Engine task."""
    flags=os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_CREAT|os.O_EXCL if create else os.O_TRUNC)
    descriptor=os.open(path,flags,0o600)
    try:
        node=os.fstat(descriptor)
        expect(stat.S_ISREG(node.st_mode) and node.st_uid==os.getuid() and node.st_nlink==1,
            'owned ordinary probe journal required')
        data=canonical(value)
        with os.fdopen(descriptor,'wb',closefd=False) as stream:
            stream.write(data);stream.flush();os.fsync(descriptor)
    finally:os.close(descriptor)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(directory)
    finally:os.close(directory)


def confinement_probes(engine,config,listener,journal,capacity,reservations):
    """Separate fixed TEST resource, never a revision-scoped Gate evaluation.

    This is outside all Hub RPC deadlines. A pre-effect intent and explicit
    reservation protect the independently bounded target. Any uncertain test
    task retains/quarantines it; only confirmed exits permit owned deletion.
    """
    evaluation='qualification-native-probes'
    expect(capacity({'evaluation_id':evaluation},RESERVATION_BYTES),'fixed test target capacity unavailable')
    identifier=hashlib.sha256((config['nonce']+config['room']+'native-probes').encode()).hexdigest()[:32]
    parent=Path(config['scratch'])/identifier;intent=journal/'ownership.json'
    durable_probe_record(intent,{'state':'intent','target_id':identifier,'test_resource':True},create=True)
    results=[];parent_fd=-1;tree_fd=-1;store_fd=-1
    try:
        with target_labels(config['level']):
            parent.mkdir(mode=0o700);os.chown(parent,-1,HELPER);parent.chmod(0o710)
            tree=parent/'tree';tree.mkdir(mode=0o700);(tree/'README.md').write_bytes(b'fixed attack-target marker\n')
            (tree/'README.md').chmod(0o444);tree.chmod(0o555)
            store=parent/'store';store.mkdir(mode=0o700);(store/'config').write_bytes(b'not in target\n')
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
        parent_fd=os.open(parent,flags);identity=(os.fstat(parent_fd).st_dev,os.fstat(parent_fd).st_ino)
        before=observe_target(tree,time.monotonic()+5)
        tree_fd=os.open('tree',flags,dir_fd=parent_fd);store_fd=os.open('store',flags,dir_fd=parent_fd)
        children={name:(os.fstat(fd).st_dev,os.fstat(fd).st_ino) for name,fd in (('tree',tree_fd),('store',store_fd))}
        durable_probe_record(intent,{'state':'launch-possible','target_id':identifier,'test_resource':True})
        for kind in 'NPFETMRLWCOHI':results.append(probe_task(engine,config,listener,{'target_id':identifier},kind,journal))
        expect(all(value['actual_exit'] for value in results),'unconfirmed test task retains target')
        expect(observe_target(tree,time.monotonic()+5)==before,'test target changed')
        current=parent.lstat();expect((current.st_dev,current.st_ino)==identity,'test parent replaced')
        expect(set(os.listdir(parent_fd))=={'tree','store'},'unexpected test-owned entry')
        for name in ('tree','store'):
            current=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
            expect((current.st_dev,current.st_ino)==children[name],'test child replaced')
        expect(set(os.listdir(tree_fd))=={'README.md'} and set(os.listdir(store_fd))=={'config'},'test cleanup shape changed')
        os.fchmod(tree_fd,0o700);os.unlink('README.md',dir_fd=tree_fd);os.unlink('config',dir_fd=store_fd)
        os.rmdir('tree',dir_fd=parent_fd);os.rmdir('store',dir_fd=parent_fd)
        expect((parent.lstat().st_dev,parent.lstat().st_ino)==identity,'test parent replaced before final cleanup')
        parent.rmdir();reservations.pop(evaluation)
        durable_probe_record(intent,{'state':'cleaned','target_id':identifier,'actual_exits':len(results),'test_resource':True})
        return results
    except BaseException:
        durable_probe_record(intent,{'state':'quarantined','target_id':identifier,'confirmed_exits':len(results),'test_resource':True})
        raise
    finally:
        for fd in (tree_fd,store_fd,parent_fd):
            if fd>=0:os.close(fd)


def probe_task(engine,config,listener,target,kind,journal):
    """One fixed TEST binary attempt. Never retries/adopts an exec after loss."""
    intent=journal/('probe-'+kind+'.json')
    durable_probe_record(intent,{'kind':kind,'state':'launch-possible','test_payload':True},create=True)
    wrong=kind=='I';command_=['/usr/bin/python3','/opt/uas/tests/vm/artifact_room_probe.py','wrong-process'] if wrong else ['/opt/uas/bin/artifact-test-bootstrap']
    exec_id=engine.create(config['workstation_id'],{'AttachStdin':True,'AttachStdout':False,'AttachStderr':False,
        'Tty':False,'Privileged':False,'User':'65530:65530','WorkingDir':'/','Cmd':command_,'Env':[]})
    transport=engine.start(exec_id);origin=None;channel=None;started=time.monotonic();deadline=started+18
    try:
        challenge=secrets.token_bytes(32);transport.write(challenge,timeout=5)
        listener.settimeout(5);channel,_=listener.accept();enable(channel);channel.settimeout(5)
        with receive(channel) as record:
            expect(record.data==b'AGH1'+challenge and record.credentials[1:]==(HELPER,HELPER),'actual dedicated test task')
            origin=HeldOrigin(record)
        observed=engine.inspect(exec_id)
        expect(observed['Running'] and observed['Pid']==origin.credentials[0],'exact test exec/held task')
        if wrong:
            channel.send(b'AG-WRONG-PROCESS-1')
            with receive(channel) as record:
                denied=False
                try:origin.require(record)
                except OriginDenied:denied=True
                expect(denied and record.data==b'AG-CHILD-FORGED-FACT','actual duplicate-FD different process rejected')
        else:
            channel.send(b'AGR1'+target['target_id'].encode());channel.send(kind.encode())
            if kind=='O':
                with receive(channel) as record:
                    origin.require(record);expect(len(record.data)==16385,'actual excessive helper record')
                    denied=False
                    try:decode_record(record.data)
                    except ArtifactError:denied=True
                    expect(denied,'over-bound raw output must be rejected')
                channel.close();channel=None
        wait_exit(origin,deadline)
        terminal=engine.inspect(exec_id);expected={'R':0,'L':0,'W':0,'C':137,'H':142,'O':126,'I':0}.get(kind,159)
        elapsed=round(time.monotonic()-started,3)
        checkpoint=progress_record({'version':1,'kind':'probe-exit','room':config['room'],
            'probe':kind,'running':terminal['Running'],'exit_code':terminal['ExitCode'],
            'expected_exit':expected,'elapsed_ms':round(elapsed*1000)})
        durable_probe_record(intent,{'state':'observed-exit','test_payload':True,**checkpoint})
        print(PROGRESS_PREFIX.decode()+canonical(checkpoint).decode(),flush=True)
        expect(terminal['Running'] is False and terminal['ExitCode']==expected,'fixed confinement probe did not produce expected terminal outcome')
        if kind=='C':expect(elapsed<15,'CPU ceiling failed before wall timer')
        if kind=='H':expect(12<=elapsed<=18,'self wall alarm interval outside bound')
        durable_probe_record(intent,{'kind':kind,'state':'exited','test_payload':True,'exec_id':exec_id,
            'held_identity':list(origin.identity),'actual_exit':True,'exit_code':terminal['ExitCode']})
        return {'probe':kind,'exec_id':exec_id,'held_identity':list(origin.identity),'actual_exit':True,
            'exit_code':terminal['ExitCode'],'elapsed_seconds':elapsed,'test_payload':True}
    finally:
        if channel is not None:channel.close()
        if origin is not None:origin.close()
        transport.close()


def scenario(config,gate_fd,control_fd):
    expect((os.getuid(),os.getgid())==(UID,UID) and HELPER in os.getgroups(),'fixed mapped Supervisor and helper group grant')
    expect('container_t' not in Path('/proc/self/attr/current').read_text(),'Supervisor must remain outside Workstation')
    probe();engine=DockerExecAPI('/run/docker.sock')
    with diagnostic_boundary('source-setup'):
        supervisor,allocator,resolver,source,marker=setup_source(config)
    room_root=Path(config['room_root']);journal=Path(config['journal']);reservations={}
    for name in ('targets','launches','probes'):(journal/name).mkdir(mode=0o700)
    def capacity(scope,size):
        expect(size==RESERVATION_BYTES,'fixed reservation only')
        # Journal/lifecycle files physically outside this project quota are
        # conservatively charged to its admitted budget as well. Reservations
        # also remain charged while allocation exists (intentional overcount).
        used,nodes=allocated((room_root,supervisor.directory,Path(config['gate']),Path(config['control'])))
        reserved=sum(reservations.values())
        if used+reserved+size>256<<20 or nodes+(len(reservations)+1)*1536>8192:return False
        reservations[scope['evaluation_id']]=size;return True
    with diagnostic_boundary('target-setup'):
        targets=ArtifactTargets(config['scratch'],journal/'targets',resolver,reserve_capacity=capacity)
    workstation=GateWorkstation(config['room'],config['room_instance'],config['workstation_id'],
        config['image_digest'],config['profile_digest'],config['helper_sha256']['artifact-bootstrap'],
        config['helper_sha256']['artifact-evaluator'],config['mapping_digest'],'artifact-hub-'+config['room_instance'])
    endpoint=GateEndpointLease(Path(config['gate'])/'gate.sock',owner=UID,group=HELPER)
    admission=NativeAdmission(engine,config);native_probes=[];injected=[];launches=[]
    with ExitStack() as stack:
        listener=stack.enter_context(closing(socket.socket(fileno=gate_fd)));enable(listener)
        control_listener=stack.enter_context(closing(socket.socket(fileno=control_fd)));enable(control_listener)
        def factory(scope,target,lease):
            admission.target_lease=lease
            launch=GateHelperLaunch(engine,workstation,endpoint,journal/'launches'/(scope['evaluation_id']+'-launch.json'),
                admission=admission,target_lease=lease,scope=scope)
            original=launch.finish
            def finish(*,final_digest):
                gate=scope['gate_id']
                if gate=='artifact-mutation':
                    path=lease.path/'tree/README.md';path.chmod(0o644);path.write_bytes(b'mutated after helper exit\n');path.chmod(0o444)
                    injected.append({'scenario':'mutation','fault':'actual-target-content-change-before-postproof'})
                elif gate=='artifact-cleanup':
                    # Actual ownership replacement, never simulated cleanup=True.
                    moved=lease.path.with_name(lease.target_id+'-quarantined')
                    os.rename(lease.path,moved);lease.path.mkdir(mode=0o710)
                    injected.append({'scenario':'cleanup','fault':'actual-owned-parent-replacement','retained':moved.name})
                return original(final_digest=final_digest)
            launch.finish=finish;launches.append(launch);return launch
        service=GateSupervisorService(resolver,targets,launch_factory=factory,listener=listener)
        original_handle=service.handle
        def invoke(command_,payload):
            if command_=='prepare':
                with target_labels(config['level']):
                    if payload['scope']['gate_id']=='artifact-alternates':
                        alternate=resolver.repo/'.git/objects/info/alternates'
                        alternate.write_text('/nonexistent/forbidden-object-source\n')
                        try:return original_handle(command_,payload)
                        finally:
                            alternate.unlink();injected.append({'scenario':'alternates','fault':'actual-forbidden-source-object-dependency'})
                    return original_handle(command_,payload)
            result=original_handle(command_,payload)
            if command_ in ('finish','abort','reconcile') and isinstance(result,dict) and result.get('cleanup') is True:
                reservations.pop(payload['evaluation_id'],None)
            return result
        def handle(command_,payload):
            # Exceptions reaching this fixture boundary retain typed causes.
            # Internally quarantined finish/abort/reconcile results are not
            # exceptions here; do not infer errno or rewrite those results.
            phase={'resolve':'control-resolve','current':'control-current','prepare':'control-prepare',
                'start':'control-start','finish':'control-finish','abort':'control-abort',
                'reconcile':'control-reconcile'}.get(command_,'control-unsupported')
            with diagnostic_boundary(phase):return invoke(command_,payload)
        service.handle=handle
        self_pidfd=os.pidfd_open(os.getpid());stack.callback(os.close,self_pidfd)
        metadata={'version':1,'challenge':secrets.token_hex(32),'supervisor_identity':list(_identity(self_pidfd)),
            'mapping_digest':config['mapping_digest'],'profile_digest':config['profile_digest'],'room_id':config['room'],
            'room_instance':config['room_instance'],'project_id':config['room'],'repository':'example/'+config['room'],
            'run_id':'artifact-run','participant_id':'builder','checkout':{'slot':source['slot_id'],'branch':source['branch']},
            'scenarios':config['scenarios']}
        stream=engine.attach_hub(config['hub_id']);stack.callback(stream.close);engine.start_hub(config['hub_id'])
        stream.write(canonical(metadata)+b'\n',timeout=5);control_listener.settimeout(15)
        control,_=control_listener.accept();stack.callback(control.close);enable(control);control.settimeout(60)
        with receive(control) as record:
            expect(record.data==b'AGB1'+bytes.fromhex(metadata['challenge']) and record.credentials[1:]==(165531,165531),'exact Hub bootstrap')
            hub=HeldOrigin(record)
        stack.callback(hub.close);control.send(RELEASE)
        with receive(control) as record:hub.require(record);ready=json.loads(record.data)
        expect(ready['kind']=='GATE_READY' and ready['room_id']==config['room'],'exact Hub readiness')
        controller=ready['controller'];deadline=time.monotonic()+240;terminal=None
        while time.monotonic()<deadline:
            # Peek only routes. Every meaningful record is consumed/authenticated
            # below or by dispatch_gate_control before effects; peek is no proof.
            preview=control.recv(16385,socket.MSG_PEEK)
            expect(preview and len(preview)<=16384,'bounded private control route')
            route=json.loads(preview)
            if route.get('kind')=='GATE_DONE':
                with receive(control) as record:hub.require(record);terminal=json.loads(record.data)
                expect(terminal['controller']==controller and terminal['scenarios']==config['scenarios'],'exact Hub terminal')
                control.send(DONE_ACK);wait_exit(hub,time.monotonic()+5);break
            dispatch_gate_control(control,hub,service,controller=controller)
        expect(terminal is not None,'bounded concrete Hub scenario incomplete')
        checkpoint=progress_record({'version':1,'kind':'hub-terminal','room':config['room'],
            'report_sha256':terminal['report_digest'],'report_bytes':terminal['report_bytes']})
        durable_probe_record(journal/'hub-terminal.json',checkpoint,create=True)
        print(PROGRESS_PREFIX.decode()+canonical(checkpoint).decode(),flush=True)
        if config['room']=='alpha':
            with diagnostic_boundary('confinement-probes'):
                native_probes=confinement_probes(engine,config,listener,journal/'probes',capacity,reservations)
        expect(not marker.exists(),'poisoned source configuration executed')
        return {'version':1,'room':config['room'],'source':source,'actual_hub':ready['observation'],
            'terminal':terminal,'native_probes':native_probes,'injected_faults':injected,
            'admission_observations':admission.observations,'source_config_executed':False,
            'launches':[{'exec_id':x.exec_id,'state':x.state,'target_id':x.target['target_id']} for x in launches],
            'remaining_reservations':reservations,'production_enabled':False}


def main():
    expect(len(sys.argv)==4,'fixed fixture config and listener descriptors required')
    path=Path(sys.argv[1]);expect(path.stat().st_size<65536,'bounded fixture configuration')
    config=json.loads(path.read_text());expect(Path('/run/uas-vm-fixture').read_text().strip()==config['nonce'],'not this disposable guest')
    result=scenario(config,int(sys.argv[2]),int(sys.argv[3]));data=canonical(result)
    expect(len(data)<MAX_LOG,'bounded Supervisor report');print('UAS_ARTIFACT_SUPERVISOR:'+data.decode(),flush=True)


if __name__=='__main__':
    with diagnostic_boundary('supervisor-main'):main()
