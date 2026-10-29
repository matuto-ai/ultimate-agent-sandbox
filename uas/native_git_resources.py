"""Finite prepared native Git resources; declarations never grant Actor authority.

No image construction, repository repair, credential resolution, or arbitrary
mount publication. The first profile supports only the actual primary checkout.
"""
from dataclasses import dataclass
from copy import deepcopy
import fcntl
import io
import posixpath
import tarfile
import time
from urllib.parse import quote
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat

from .native_image_package import canonical, REFERENCE, valid_image_reference
from .native_pi_recipe import read_manifest, path, SHA
from .kernel_origin import OriginDenied, alive, _identity

ENDPOINT_ROOT = Path('/run/uas-native')
STORAGE_ROOT = Path('/mnt/uas-native')
HOST_UID, RUNTIME_UID = 165533, 165532
WORKER_HOST_UID, WORKER_HOST_GID = 165530, 165532
SEALED = 1 | 2 | 4 | 8
FIXED_ARTIFACTS = frozenset(('/usr/bin/python3.11','/usr/bin/git',
    '/opt/uas/bin/git','/opt/uas/bin/git-worker-connector','/opt/uas/bin/git-ssh-shim',
    '/opt/uas/runtime/git/worker.py','/opt/uas/runtime/git/public-entries.json',
    '/opt/uas/runtime/git/launcher.py','/opt/uas/git-hooks/reference-transaction'))
PUBLIC_ENTRIES = tuple(["git","git-add","git-am","git-branch","git-cat-file","git-checkout","git-cherry-pick","git-clone","git-commit","git-config","git-credential","git-credential-cache","git-credential-store","git-daemon","git-diff","git-fetch","git-index-pack","git-init","git-log","git-ls-files","git-ls-remote","git-ls-tree","git-merge","git-merge-base","git-mv","git-pack-objects","git-push","git-rebase","git-receive-pack","git-remote","git-remote-ext","git-remote-file","git-remote-http","git-remote-https","git-remote-ssh","git-reset","git-restore","git-rev-parse","git-rm","git-send-pack","git-shell","git-show","git-show-ref","git-status","git-switch","git-unpack-objects","git-update-ref","git-upload-archive","git-upload-pack","git-worktree","scalar"])
LOADER = '/lib64/ld-linux-x86-64.so.2'
MAX_BACKEND = 64 * 1024 * 1024


def require(value, message):
    if not value: raise OriginDenied('native Git ' + message)


def identifier(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{32}', value) is not None


def local_profile(plan):
    """Only the concrete local declaration selects non-qualification roots."""
    from .native_qualification import is_local_runtime_plan
    if is_local_runtime_plan(plan):
        plan.require_unchanged()
        return plan.native_profile
    return None


def endpoint_root(plan):
    profile=local_profile(plan)
    return ENDPOINT_ROOT if profile is None else profile.endpoints


def backend_path(plan):
    profile=local_profile(plan)
    if profile is not None:return profile.state_root/'git-backend'
    require(identifier(plan.installation.get('nonce')), 'qualification nonce required')
    return STORAGE_ROOT/plan.installation['nonce']/'git-backend'


def selected_image(plan):
    profile=local_profile(plan)
    if profile is not None:return profile.image_reference
    return next(i['reference'] for i in plan.config['deployment']['images'] if i['id']==plan.room['image'])


def selection(plan, *, filename=None):
    ref=plan.installation.get('git_manifest')
    require(type(ref) is dict and set(ref)=={'path','sha256'}, 'prepared image selection required')
    value=read_manifest(filename or ref['path'], ref['sha256'])
    validate_selection(value, plan)
    return value


PAYLOAD_FIELDS = frozenset(('version', 'profile', 'artifacts', 'python_version',
                           'abi_artifacts', 'uas_tree_sha256', 'backend_sha256'))


def validate_payload(value):
    """Validate baked Git metadata without inventing installation identities."""
    require(type(value) is dict and set(value)==PAYLOAD_FIELDS and type(value['version']) is int
        and value['version']==1 and value['profile']=='native-git-primary-v1','invalid prepared selection')
    require(type(value['python_version']) is str and re.fullmatch(r'3\.11\.[0-9]{1,3}',value['python_version']), 'pinned Python required')
    artifacts=value['artifacts'];abi=value['abi_artifacts']
    require(type(artifacts) is dict and set(artifacts)==FIXED_ARTIFACTS
        and all(type(x) is str and SHA.fullmatch(x) for x in artifacts.values()), 'fixed payload inventory required')
    require(artifacts['/usr/bin/git']==artifacts['/opt/uas/bin/git']==artifacts['/opt/uas/runtime/git/launcher.py'], 'public launcher differs')
    require(type(abi) is dict and 2<=len(abi)<=64 and LOADER in abi
        and any(p.endswith('/libc.so.6') for p in abi)
        and all(type(p) is str and path(p)==p and p.startswith(('/lib/','/lib64/','/usr/lib/'))
                and type(v) is str and SHA.fullmatch(v) for p,v in abi.items()), 'loader/library inventory required')
    require(all(type(value[k]) is str and SHA.fullmatch(value[k]) for k in ('uas_tree_sha256','backend_sha256')), 'content identity required')
    return value


def validate_selection(value, plan):
    fields=PAYLOAD_FIELDS|{'image_reference','image_id','backend_path'}
    require(type(value) is dict and set(value)==fields, 'invalid prepared selection')
    validate_payload({key:value[key] for key in PAYLOAD_FIELDS})
    require(valid_image_reference(value['image_reference'],value['image_id']), 'image identity required')
    image=selected_image(plan)
    require(value['image_reference']==image, 'prepared image differs')
    require(value['backend_path']==str(backend_path(plan)), 'fixed backend path required')
    profile=local_profile(plan)
    if profile is not None:require(value['image_id']==profile.image_id,'local image identity differs')
    return value


def git_mounts(plan, state):
    """Parent-before-child mount order is part of this exact finite contract."""
    require(identifier(state['instance_id']), 'instance required')
    backend_path(plan)  # Validate fixed local profile or legacy nonce.
    repo=path(plan.room['project']['roots']['repo'])
    root=endpoint_root(plan)/state['instance_id']; views=root/'git-views'; fixed=root/'git-fixed'
    return (
        NativeGitMount(str(views),'/opt/uas/git-views',True),
        NativeGitMount(repo+'/.git','/opt/uas/git-views/primary/gitdir',False),
        NativeGitMount(repo+'/.git','/opt/uas/git-views/primary/common',False),
        NativeGitMount(str(fixed/'config'),'/opt/uas/git-views/primary/common/config',True),
        NativeGitMount(str(fixed/'commondir'),'/opt/uas/git-views/primary/gitdir/commondir',True),
        NativeGitMount(str(root/'git'),'/uas/git',True),
        NativeGitMount(str(root/'git-workspace'),'/uas/workspace',True))


@dataclass(frozen=True)
class NativeGitMount:
    source: str
    destination: str
    read_only: bool
    def __post_init__(self):
        path(self.source);path(self.destination)
        require(type(self.read_only) is bool,'typed mount mode required')


class GitMountProfile:
    """Immutable canonical generated roles, not a generic /opt mount exception."""
    def __setattr__(self,k,v):
        if getattr(self,'_frozen',False): raise OriginDenied('immutable native Git profile')
        object.__setattr__(self,k,v)

    @classmethod
    def from_plan(cls,plan,state,manifest,manifest_digest,*,container_id,mapping_digest):
        validate_selection(manifest,plan)
        require(type(container_id) is str and re.fullmatch(r'[0-9a-f]{64}',container_id)
            and type(mapping_digest) is str and SHA.fullmatch(mapping_digest)
            and type(manifest_digest) is str and SHA.fullmatch(manifest_digest)
            and manifest_digest==plan.installation['git_manifest']['sha256'], 'selected resource identity required')
        require(state['room_id']==plan.room['id'], 'Room binding differs')
        self=cls();self.room_id=plan.room['id'];self.instance_id=state['instance_id']
        self.container_id=container_id;self.repo=plan.room['project']['roots']['repo']
        self.image_id=manifest['image_id'];self.image_reference=manifest['image_reference']
        self.mapping_digest=mapping_digest;self.manifest_digest=manifest_digest
        self.mounts=git_mounts(plan,state)
        self._document={'version':1,'room_id':self.room_id,'instance_id':self.instance_id,
            'container_id':container_id,'repo':self.repo,'image_id':self.image_id,
            'image_reference':self.image_reference,'mapping_digest':mapping_digest,
            'manifest_digest':manifest_digest,'mounts':[m.__dict__ for m in self.mounts]}
        self._canonical=canonical(self._document);self.digest=hashlib.sha256(self._canonical).hexdigest();self._frozen=True
        return self

    def __init__(self):
        # Empty instances are not valid profiles; public constructors cannot
        # install arbitrary source/destination tuples as admitted Git roles.
        pass

    def document(self):
        require(getattr(self,'_frozen',False),'generated profile required')
        return json.loads(self._canonical)

    def mount_tuples(self):
        self.document()
        return tuple((m.source,m.destination,not m.read_only) for m in self.mounts)

    def require_checkout(self,slot,checkout):
        self.document();require(slot=='primary' and checkout==self.repo,'later checkout projection unavailable')
        return True


def _read_backend(pathname, expected):
    """Root-owned nofollow bytes only; never execute or alter selected source."""
    directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        parts=Path(pathname).parts
        for name in parts[1:-1]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            os.close(directory);directory=child;n=os.fstat(directory)
            require(n.st_uid==0 and not n.st_mode&0o022,'untrusted backend ancestry')
        fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        try:
            n=os.fstat(fd)
            require(stat.S_ISREG(n.st_mode) and n.st_uid==0 and not n.st_mode&0o022 and n.st_nlink==1
                and 0<n.st_size<=MAX_BACKEND,'untrusted backend file')
            raw=bytearray()
            while len(raw)<=n.st_size:
                b=os.read(fd,min(65536,n.st_size+1-len(raw)))
                if not b:break
                raw.extend(b)
            after=os.fstat(fd)
            require((n.st_dev,n.st_ino,n.st_size,n.st_mtime_ns,n.st_ctime_ns)==
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                    and len(raw)==n.st_size and raw.startswith(b'\x7fELF')
                    and hashlib.sha256(raw).hexdigest()==expected,'backend identity differs')
            return bytes(raw)
        finally:os.close(fd)
    finally:os.close(directory)


def seal_backend(manifest):
    raw=_read_backend(manifest['backend_path'],manifest['backend_sha256'])
    fd=os.memfd_create('uas-native-git',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        offset=0
        while offset<len(raw):
            count=os.write(fd,raw[offset:]);require(count>0,'backend copy incomplete');offset+=count
        os.fchmod(fd,0o555);fcntl.fcntl(fd,1033,SEALED)
        require_sealed(fd,manifest['backend_sha256']);return fd
    except BaseException:os.close(fd);raise


def require_sealed(fd,expected,identity=None):
    require(type(fd) is int and fd>=3,'sealed backend descriptor required')
    n=os.fstat(fd)
    require(stat.S_ISREG(n.st_mode) and n.st_mode&0o111 and 0<n.st_size<=MAX_BACKEND
        and fcntl.fcntl(fd,1034)&SEALED==SEALED,'sealed backend required')
    observed=(n.st_dev,n.st_ino)
    require(identity is None or identity==observed,'sealed backend replaced')
    if identity is not None:return observed  # inode + immutable seals retain initial hash proof
    digest=hashlib.sha256();offset=0;prefix=b''
    while offset<n.st_size:
        block=os.pread(fd,min(65536,n.st_size-offset),offset);require(block,'backend incomplete')
        if offset==0:prefix=block[:4]
        offset+=len(block);digest.update(block)
    require(prefix==b'\x7fELF' and digest.hexdigest()==expected,'sealed backend hash differs')
    return observed


def prepare_views(plan,state):
    """New owned overlay files only; never create/repair Project metadata."""
    from .forge import ForgeBinding
    from .git_runtime import compile_git_config
    repo=Path(plan.room['project']['roots']['repo']);gitdir=repo/'.git'
    require(repo.resolve()==repo and gitdir.resolve()==gitdir and gitdir.is_dir(),'primary gitdir required')
    require(gitdir.stat().st_uid==RUNTIME_UID and gitdir.stat().st_gid==RUNTIME_UID,'existing Project ownership differs')
    for filename in ('config','commondir'):
        fd=os.open(gitdir/filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            info=os.fstat(fd);require(stat.S_ISREG(info.st_mode),'existing Git metadata required')
            if filename=='commondir':require(info.st_size==2 and os.read(fd,3)==b'.\n','explicit neutral primary setup required')
        finally:os.close(fd)
    root=endpoint_root(plan)/state['instance_id']
    for relative in ('git-views','git-views/primary','git-views/primary/gitdir','git-views/primary/common','git-fixed','git-workspace'):
        target=root/relative;target.mkdir(mode=0o755);os.chown(target,100000,100000);os.chmod(target,0o755)
    binding=ForgeBinding(plan.room['id'],plan.room['project']['id'],plan.room['project']['repository'])
    for name,raw in (('config',compile_git_config(binding)),
                     ('commondir',b'/opt/uas/git-views/primary/common\n')):
        fd=os.open(root/'git-fixed'/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444)
        try:
            require(os.write(fd,raw)==len(raw),'overlay write incomplete');os.fchown(fd,100000,100000);os.fchmod(fd,0o444);os.fsync(fd)
        finally:os.close(fd)


class NativeGitResources:
    """Live inherited ownership; not serializable/recoverable admission authority.

    require() is called under the canonical Supervisor lifecycle lock. No Engine
    RPC or nested flock occurs there; held PID1 plus immutable container lifetime
    pins the exact initially observed image, mounts and userns mapping.
    """
    @classmethod
    def from_session(cls,plan,resource_dict,engine,*,supervisor,deadline,resume_local_listener=False):
        from .docker_exec_api import DockerExecAPI
        from .lifecycle import Supervisor
        from .native_qualification_backend import NativeQualificationObserver
        from .workstation_exec import EndpointLease
        require(type(resume_local_listener) is bool and (not resume_local_listener or local_profile(plan) is not None),
                'local retained listener resume required')
        expected=NativeQualificationObserver
        if local_profile(plan) is not None:
            from .local_native import LocalNativeObserver
            expected=LocalNativeObserver
        require(type(supervisor) is Supervisor and type(supervisor.backend) is expected
            and type(engine) is DockerExecAPI,'canonical readonly owners required')
        self=cls();self._closed=False;self._pidfd=-1;self._listeners=[]
        self.supervisor=supervisor;self.plan=plan;self.config_digest=plan.config_digest
        with supervisor._locked():
            state=supervisor._read()
            require(state is not None and state['phase']=='running' and state['room_id']==plan.room['id']
                and state['instance_id']==resource_dict['instance']
                and state['spec']['config_digest']=='sha256:'+plan.config_digest,'current lifecycle required')
        manifest=selection(plan,filename=resource_dict['git_manifest_path'])
        self.profile=GitMountProfile.from_plan(plan,state,manifest,plan.installation['git_manifest']['sha256'],
            container_id=resource_dict['workstation_id'],mapping_digest=resource_dict['mapping_digest'])
        self.container_id=self.profile.container_id;self.mapping_digest=self.profile.mapping_digest
        self.gate_profile=None
        if 'gate_manifest' in plan.installation:
            from .native_gate_resources import selection as gate_selection,NativeGateMountProfile
            gate_manifest=gate_selection(plan,filename=resource_dict['gate_manifest_path'])
            require(gate_manifest['image_id']==self.profile.image_id
                and gate_manifest['image_reference']==self.profile.image_reference,'Gate image pairing differs')
            self.gate_profile=NativeGateMountProfile.from_plan(plan,state,gate_manifest,
                plan.installation['gate_manifest']['sha256'],container_id=self.container_id,mapping_digest=self.mapping_digest)
        try:
            observed=engine.inspect_container(self.container_id)
            self._verify_container(observed,resource_dict)
            pid=observed['State']['Pid'];require(type(pid) is int and pid>0,'current container process required')
            before=process_binding(pid,self.container_id)
            self._pidfd=os.pidfd_open(pid);require(alive(self._pidfd),'container process unavailable')
            self._task_identity=_identity(self._pidfd);self._container_pid=pid
            require(process_binding(pid,self.container_id)==before,'container task changed during capture')
            maps={name:Path('/proc/'+str(pid)+'/'+name).read_text() for name in ('uid_map','gid_map')}
            require(all(v.split()==['0','100000','65536'] for v in maps.values()),'observed mapping differs')
            for name in ('uid','gid'):
                maps['overflow_'+name]=int(Path('/proc/sys/kernel/overflow'+name).read_text())
                require(maps['overflow_'+name]==65534,'overflow mapping differs')
            require(hashlib.sha256(json.dumps(maps,sort_keys=True).encode()).hexdigest()==self.mapping_digest
                and alive(self._pidfd),'mapping identity differs')
            verify_engine_payload(engine,self.container_id,manifest,deadline=deadline)
            again=engine.inspect_container(self.container_id);self._verify_container(again,resource_dict)
            require(again['State']['Pid']==pid and alive(self._pidfd)
                and _identity(self._pidfd)==self._task_identity
                and process_binding(pid,self.container_id)==before,'container task replaced during observation')
            self.backend_fd=resource_dict['git_backend_fd'];self.backend_sha256=manifest['backend_sha256']
            self._backend_identity=require_sealed(self.backend_fd,self.backend_sha256)
            root=endpoint_root(plan)/self.profile.instance_id/'git'
            self._socket_identities={}
            for kind in ('request','worker'):
                endpoint=root/(kind+'.sock')
                require(resource_dict['git_'+kind+'_path']==str(endpoint),'fixed endpoint differs')
                lease=EndpointLease(endpoint,owner=HOST_UID,group=RUNTIME_UID)
                fd=resource_dict['git_'+kind+'_fd'];require(type(fd) is int and fd>=3,'inherited listener required')
                listener=socket.socket(fileno=os.dup(fd) if local_profile(plan) is not None else fd);self._listeners.append(listener)
                require(listener.family==socket.AF_UNIX and listener.type==socket.SOCK_SEQPACKET
                    and listener.getsockname()==str(endpoint)
                    and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN) in ((0,1) if kind=='request' and resume_local_listener else (0,) if kind=='request' else (1,)),'prebound listener differs')
                setattr(self,kind+'_listener',listener);setattr(self,kind+'_endpoint',lease)
                info=os.fstat(fd);self._socket_identities[kind]=(info.st_dev,info.st_ino)
            self.worker_host_uid=WORKER_HOST_UID;self.worker_host_gid=WORKER_HOST_GID
            with supervisor._locked():self.require()
            return self
        except BaseException:self.close();raise

    def _verify_container(self,value,resources):
        base=[(p,p,k!='reference') for k,p in self.plan.room['project']['roots'].items() if k in ('repo','workspace','reference','checkouts')]
        runtime=self.plan.room['state_root']+'/runtime';peer=str(Path(resources['peer_path']).parent)
        require(peer==str(endpoint_root(self.plan)/self.profile.instance_id/'peer'),'peer mount differs')
        expected=set(base+[(runtime,runtime,True),(peer,peer,False)]+list(self.profile.mount_tuples()))
        if 'gate_manifest' in self.plan.installation:
            from .native_gate_resources import gate_mounts
            expected.update((m.source,m.destination,False) for m in gate_mounts(self.plan,{'instance_id':self.profile.instance_id}))
        require(type(value) is dict and value.get('Id')==self.container_id
            and value.get('Image')==self.profile.image_id and value.get('Config',{}).get('Image')==self.profile.image_reference
            and value.get('State',{}).get('Running') is True,'observed image differs')
        host=value.get('HostConfig',{})
        require(host.get('ReadonlyRootfs') is True and host.get('Privileged') is False
            and host.get('UsernsMode')=='' and host.get('PidMode')==''
            and host.get('CapDrop')==['ALL'] and host.get('CapAdd') in (None,[]),'container boundary differs')
        mounts=value.get('Mounts')
        require(type(mounts) is list and len(mounts)==len(expected)
            and all(m.get('Type')=='bind' and type(m.get('RW')) is bool and m.get('Propagation')=='rprivate' for m in mounts)
            and {(m.get('Source'),m.get('Destination'),m['RW']) for m in mounts}==expected,'exact resource mounts differ')

    def require(self,room_id=None,instance=None,container_id=None):
        require(not self._closed and self._pidfd>=0 and alive(self._pidfd) and _identity(self._pidfd)==self._task_identity,'container lifetime ended')
        require((room_id or self.profile.room_id)==self.profile.room_id
            and (instance or self.profile.instance_id)==self.profile.instance_id
            and (container_id or self.container_id)==self.container_id,'resource binding differs')
        self.plan.require_unchanged();state=self.supervisor._read()
        require(state is not None and state['phase']=='running'
            and state['room_id']==self.profile.room_id and state['instance_id']==self.profile.instance_id
            and state['spec']['config_digest']=='sha256:'+self.config_digest,'lifecycle replaced')
        self.request_endpoint.require();self.worker_endpoint.require()
        for kind in ('request','worker'):
            listener=getattr(self,kind+'_listener');info=os.fstat(listener.fileno())
            require((info.st_dev,info.st_ino)==self._socket_identities[kind]
                and listener.getsockname()==str(getattr(self,kind+'_endpoint').path)
                and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN) in ((0,1) if kind=='request' else (1,)),'listener replaced')
        require_sealed(self.backend_fd,self.backend_sha256,self._backend_identity)
        return True

    def close(self):
        self._closed=True
        for listener in getattr(self,'_listeners',[]):listener.close()
        self._listeners=[]
        if getattr(self,'_pidfd',-1)>=0:os.close(self._pidfd);self._pidfd=-1
        # Backend FD remains owned by the session ExitStack; never close a
        # borrowed descriptor a caller may still hold for another fixed owner.


def parse_process_binding(pid,container_id,status,stat_text,cgroup):
    from .git_process import parse_status
    parsed=parse_status(status)
    require(parsed['Pid']==(pid,) and parsed['NSpid'][-1]==1
        and len(parsed['NSpid'])>=2 and parsed['Uid']==(RUNTIME_UID,)*4
        and parsed['Gid']==(RUNTIME_UID,)*4,'PID1 mapping differs')
    end=stat_text.rfind(')');require(end>0 and stat_text[:stat_text.find(' ')]==str(pid),'process stat differs')
    tail=stat_text[end+2:].split()
    require(len(tail)>=20 and tail[0] not in ('Z','X','x') and tail[19].isdigit(),'process start identity unavailable')
    rows=[line.split(':',2) for line in cgroup.splitlines()]
    require(len(rows)==1 and len(rows[0])==3 and rows[0][:2]==['0','']
        and rows[0][2] in ('/system.slice/docker-'+container_id+'.scope','/docker/'+container_id),
        'container cgroup profile differs')
    return (pid,int(tail[19]),tuple(parsed['NSpid']),rows[0][2])


def process_binding(pid,container_id):
    directory=os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        values=[]
        for name in ('status','stat','cgroup'):
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            try:
                raw=os.read(fd,16385);require(len(raw)<=16384,'process observation oversized');values.append(raw)
            finally:os.close(fd)
        return parse_process_binding(pid,container_id,values[0],values[1].decode('ascii'),values[2].decode('ascii'))
    finally:os.close(directory)


def archive_records(raw):
    """Uncompressed bounded metadata/hash parser; never extract onto host disk."""
    require(type(raw) is bytes and 0<len(raw)<=64*1024*1024,'bounded Engine archive required')
    records={}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
            for member in archive:
                require(len(records)<256,'Engine archive inventory oversized')
                name=member.name.rstrip('/')
                require(name and not name.startswith('/') and len(name)<=512
                    and all(part not in ('','.','..') for part in name.split('/'))
                    and name not in records,'ambiguous Engine archive path')
                require(not member.islnk() and not member.issparse()
                    and (member.isfile() or member.isdir() or member.issym()),'unsupported Engine archive entry')
                item={'uid':member.uid,'mode':member.mode,'kind':'file' if member.isfile() else 'directory' if member.isdir() else 'link'}
                if member.issym():
                    require(0<len(member.linkname)<=512 and '\0' not in member.linkname,'invalid Engine link')
                    item['target']=member.linkname
                elif member.isfile():
                    require(0<=member.size<=64*1024*1024,'oversized Engine file')
                    stream=archive.extractfile(member);digest=hashlib.sha256();read=0;small=bytearray()
                    while read<member.size:
                        block=stream.read(min(65536,member.size-read));require(block,'truncated Engine file')
                        digest.update(block);read+=len(block)
                        if len(small)<8192:small.extend(block[:8192-len(small)])
                    item.update(sha256=digest.hexdigest(),size=read,data=bytes(small) if member.size<=8192 else None,prefix=bytes(small))
                records[name]=item
        return records
    except (tarfile.TarError,EOFError,ValueError) as error:
        raise OriginDenied('native Git invalid Engine archive') from error


class _ImageReader:
    def __init__(self,engine,container_id,allowed,deadline):
        require(type(deadline) in (int,float) and time.monotonic()<deadline,'remaining session budget required')
        self.deadline=min(time.monotonic()+60,deadline);self.remaining=128*1024*1024
        self.engine=engine;self.container_id=container_id;self.allowed=frozenset(allowed)

    def archive(self,pathname):
        from .docker_exec_api import _UnixHTTP,API
        require(pathname in self.allowed,'image path outside selected closure')
        left=self.deadline-time.monotonic();require(left>0,'image readback deadline')
        connection=_UnixHTTP(self.engine.socket_path,min(self.engine.timeout,left))
        try:
            connection.request('GET',API+'/containers/'+self.container_id+'/archive?path='+quote(pathname,safe=''))
            response=connection.getresponse();require(response.status==200,'selected Engine payload unavailable')
            data=bytearray()
            while True:
                left=self.deadline-time.monotonic();require(left>0,'image readback deadline')
                if connection.sock is not None:connection.sock.settimeout(min(self.engine.timeout,left))
                block=response.read1(min(65536,self.remaining+1))
                if not block:break
                self.remaining-=len(block);data.extend(block)
                require(self.remaining>=0 and len(data)<=64*1024*1024,'Engine readback budget exceeded')
            records=archive_records(bytes(data));require(time.monotonic()<self.deadline,'image readback deadline')
            return records
        finally:connection.close()

    def single(self,pathname,*,follow=False):
        for _ in range(9):
            values=self.archive(pathname);require(set(values)=={posixpath.basename(pathname)},'single Engine file required')
            value=values[posixpath.basename(pathname)]
            if value['kind']!='link' or not follow:return value
            pathname=posixpath.normpath(posixpath.join(posixpath.dirname(pathname),value['target']))
            require(pathname in self.allowed,'image symlink leaves fixed closure')
        raise OriginDenied('native Git image symlink loop')


def verify_engine_payload(engine,container_id,manifest,*,deadline):
    """Observe files of the exact admitted immutable container, not a side tree."""
    aliases={prefix+name for prefix in ('/opt/uas/bin/','/usr/bin/','/usr/lib/git-core/') for name in PUBLIC_ENTRIES}
    directories={'/opt/uas/git-helpers','/opt/uas/git-hooks','/opt/uas/uas','/usr/lib/git-core','/opt/uas/bin'}
    allowed=set(manifest['artifacts'])|set(manifest['abi_artifacts'])|aliases|directories|{'/usr/bin/python3'}
    reader=_ImageReader(engine,container_id,allowed,deadline)
    for name,digest in {**manifest['artifacts'],**manifest['abi_artifacts']}.items():
        record=reader.single(name,follow=name in manifest['abi_artifacts'])
        require(record['kind']=='file' and not record['mode']&0o022
            and record['uid'] in ((0,65530) if name.endswith('/reference-transaction') else (0,))
            and record['sha256']==digest,'actual Engine payload hash differs')
        if name in FIXED_ARTIFACTS and name not in ('/opt/uas/runtime/git/public-entries.json',):
            require(record['mode']&0o111 if name.startswith(('/usr/bin/','/opt/uas/bin/')) else True,'fixed executable unavailable')
    python=reader.single('/usr/bin/python3')
    require(python['kind']=='link' and python['target']=='python3.11','fixed Python link required')
    helpers=reader.archive('/opt/uas/git-helpers')
    require(set(helpers)=={'git-helpers','git-helpers/git'} and helpers['git-helpers']['kind']=='directory'
        and helpers['git-helpers']['uid']==0 and not helpers['git-helpers']['mode']&0o022
        and helpers['git-helpers/git']['kind']=='link' and helpers['git-helpers/git']['target']=='/proc/self/fd/19','fixed private helper required')
    hooks=reader.archive('/opt/uas/git-hooks')
    require(set(hooks)=={'git-hooks','git-hooks/reference-transaction'} and hooks['git-hooks']['kind']=='directory'
        and hooks['git-hooks']['uid']==65530 and hooks['git-hooks']['mode']==0o500,'worker-only fixed hook required')
    listing=reader.single('/opt/uas/runtime/git/public-entries.json')
    require(tuple(json.loads(listing['data']))==PUBLIC_ENTRIES,'public Git inventory differs')
    for prefix,base in (('/opt/uas/bin','bin'),('/usr/lib/git-core','git-core')):
        records=reader.archive(prefix)
        if base=='git-core':require(set(records)=={base}|{base+'/'+n for n in PUBLIC_ENTRIES},'uncontrolled Git helper inventory')
        for name in PUBLIC_ENTRIES:
            item=records.get(base+'/'+name,{})
            require(item.get('kind')=='file' and item['uid']==0 and item['mode']&0o111
                and not item['mode']&0o022 and item['sha256']==manifest['artifacts']['/opt/uas/bin/git'],'public Git entry differs')
    for name in PUBLIC_ENTRIES:
        item=reader.single('/usr/bin/'+name)
        require(item['kind']=='file' and item['uid']==0 and item['mode']&0o111
            and not item['mode']&0o022 and item['sha256']==manifest['artifacts']['/opt/uas/bin/git'],'system Git entry differs')
    sources=reader.archive('/opt/uas/uas');require('uas' in sources and sources['uas']['kind']=='directory','Python source package missing')
    hashes={}
    for name,item in sources.items():
        if name=='uas':continue
        require(re.fullmatch(r'uas/[a-z_][a-z0-9_]*\.py',name) and item['kind']=='file'
            and item['uid']==0 and not item['mode']&0o022,'unexpected Python package artifact')
        hashes[name[4:]]=item['sha256']
    require(1<=len(hashes)<=192 and '__init__.py' in hashes
        and hashlib.sha256(canonical(hashes)).hexdigest()==manifest['uas_tree_sha256'],'actual Python source differs')
    return {'image_id':manifest['image_id'],'artifact_count':len(manifest['artifacts']),
            'abi_artifact_count':len(manifest['abi_artifacts']),'uas_tree_sha256':manifest['uas_tree_sha256']}
