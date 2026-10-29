"""Persistent local native infrastructure using canonical Supervisor ownership.

No daemon, provider launch, guest-marker bypass or implicit host preparation.
Only an explicit privileged operator invocation may mutate selected resources;
Project storage, quota, labels and Engine userns must already be prepared.
"""
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
import hashlib
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat

from .docker_fixture import DockerFixtureBackend
from .lifecycle import Supervisor, LifecycleError, BackendUnknown
from .native_image_package import REFERENCE, canonical
from . import native_qualification_backend as native


FIELDS = {'version','profile','installation_id','storage_root','endpoints_root',
          'engine_version','mapping','rooms'}
ROOM_FIELDS = {'quota_project_id','mcs_level','subnet','gateway','root_identity',
               'paths','workstation','hub'}
LOCAL_HUB_COMMAND = ['/opt/uas/bin/tini','--','/usr/bin/python3','-m','uas.local_hub']


def require(ok, code):
    if not ok: raise LifecycleError(code)


def path(value):
    require(type(value) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+',value)
            and value != '/' and '..' not in Path(value).parts
            and str(Path(value)) == value, 'LOCAL_NATIVE_PATH')
    return Path(value)


def identity(value):
    require(type(value) is list and len(value)==2
            and all(type(n) is int and n>=0 for n in value),'LOCAL_NATIVE_IDENTITY')


def image(value, *, hub=False):
    fields={'image_id','image_reference'} | ({'entrypoint'} if hub else set())
    require(type(value) is dict and set(value)==fields,'LOCAL_NATIVE_IMAGE')
    require(type(value['image_id']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',value['image_id'])
            and type(value['image_reference']) is str
            and (REFERENCE.fullmatch(value['image_reference']) or value['image_reference']==value['image_id']),
            'LOCAL_NATIVE_IMAGE')
    if hub: require(value['entrypoint']==LOCAL_HUB_COMMAND,'LOCAL_NATIVE_HUB_COMMAND')


def selected_host(document):
    """Resolve versioned endpoint selection; never use ambient Docker context."""
    from .local_host_profile import LocalHostProfile
    if document.get('version')==2:
        selected=LocalHostProfile.parse(document['host_profile'])
        require(selected.installation_id==document['installation_id']
                and selected.engine_version==document['engine_version']
                and {'offset':selected.offset,'size':selected.size}==document['mapping'],
                'LOCAL_NATIVE_HOST_BINDING')
    else:
        selected=LocalHostProfile.parse({'version':1,'profile':'local-host-v1',
            'installation_id':document['installation_id'],'mode':'reuse',
            'engine':{'version':'29.8.2','socket':'/run/docker.sock','data_root':'/var/lib/docker','exec_root':'/run/docker'},
            'mapping':{'user':'uas-remap','offset':100000,'size':65536}})
    # Endpoint/data-root selection is usable independently. Offset changes must
    # not enter until broker/Gate/Hub SO_PEERCRED and ownership all consume them.
    require(selected.offset==100000 and selected.size==65536,'LOCAL_NATIVE_MAPPING_INTEGRATION_REQUIRED')
    return selected


def validate_document(document):
    """Pure shape/policy validation, never a claim about the selected machine."""
    require(type(document) is dict,'LOCAL_NATIVE_PROFILE')
    version=document.get('version')
    require(type(version) is int and version in (1,2) and
            set(document)==(FIELDS if version==1 else FIELDS|{'host_profile'})
            and document['profile']=='local-native-v'+str(version),'LOCAL_NATIVE_PROFILE')
    require(type(document['installation_id']) is str
            and re.fullmatch(r'[0-9a-f]{32}',document['installation_id']),'LOCAL_NATIVE_INSTALLATION')
    storage,endpoints=path(document['storage_root']),path(document['endpoints_root'])
    require(storage!=endpoints and storage not in endpoints.parents and endpoints not in storage.parents,
            'LOCAL_NATIVE_ROOT_OVERLAP')
    require(len(str(endpoints).encode())+len('/'+'0'*32+'/control/hub.sock')<108,'LOCAL_NATIVE_SOCKET_PATH')
    require(document['engine_version']=='29.8.2'
            and document['mapping']=={'offset':100000,'size':65536},'LOCAL_NATIVE_ENGINE_PROFILE')
    host=selected_host(document)
    require(all(Path(root)!=Path(engine) and Path(root) not in Path(engine).parents and Path(engine) not in Path(root).parents
                for root in (document['storage_root'],document['endpoints_root'])
                for engine in (host.socket,host.data_root,host.exec_root)), 'LOCAL_NATIVE_ENGINE_PATH_OVERLAP')
    rooms=document['rooms']; require(type(rooms) is dict and 1<=len(rooms)<=64,'LOCAL_NATIVE_ROOMS')
    quotas=set();levels=set();networks=[];all_paths=[]
    for room_id,row in rooms.items():
        require(type(room_id) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}',room_id),'LOCAL_NATIVE_ROOM')
        require(type(row) is dict and set(row)==ROOM_FIELDS,'LOCAL_NATIVE_ROOM_PROFILE')
        quota=row['quota_project_id'];level=row['mcs_level']
        require(type(quota) is int and 1<=quota<2**31 and quota not in quotas,'LOCAL_NATIVE_QUOTA')
        quotas.add(quota)
        match=re.fullmatch(r's0:c([0-9]{1,4}),c([0-9]{1,4})',level) if type(level) is str else None
        require(match is not None and 0<=int(match[1])<int(match[2])<=1023 and level not in levels,'LOCAL_NATIVE_MCS')
        levels.add(level)
        try:
            network=ipaddress.IPv4Network(row['subnet'],strict=True);gateway=ipaddress.IPv4Address(row['gateway'])
        except (ValueError,TypeError):raise LifecycleError('LOCAL_NATIVE_NETWORK') from None
        require(str(network)==row['subnet'] and any(network.subnet_of(ipaddress.IPv4Network(n)) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')) and network.prefixlen==24
                and gateway==network.network_address+1 and all(not network.overlaps(n) for n in networks),
                'LOCAL_NATIVE_NETWORK')
        networks.append(network);identity(row['root_identity'])
        require(type(row['paths']) is dict and set(row['paths'])=={'repo','workspace','reference','checkouts','runtime'},
                'LOCAL_NATIVE_PROJECT_PATHS')
        for record in row['paths'].values():
            require(type(record) is dict and set(record)=={'path','identity'},'LOCAL_NATIVE_PROJECT_PATH')
            selected=path(record['path']);identity(record['identity'])
            require(storage in selected.parents and all(selected!=p and selected not in p.parents and p not in selected.parents
                    for p in all_paths),'LOCAL_NATIVE_PROJECT_OVERLAP')
            all_paths.append(selected)
        image(row['workstation']);image(row['hub'],hub=True)
    return deepcopy(document)


class LocalNativeProfile(native.NativeBoundaryProfile):
    """Prepared local selections, not a disposable QualificationPlan."""
    def __init__(self, config, document, room_id, control_root):
        document=validate_document(document)
        self.native_document=deepcopy(document)
        self.host_profile=selected_host(document)
        require(type(config) is dict and type(config.get('rooms')) is list,'LOCAL_NATIVE_CONFIG')
        selected=[r for r in config['rooms'] if r['id']==room_id]
        require(len(selected)==1 and room_id in document['rooms'],'LOCAL_NATIVE_ROOM')
        self.room=deepcopy(selected[0]);row=document['rooms'][room_id]
        self._storage=path(document['storage_root']);self.endpoints=path(document['endpoints_root'])
        self.root=self._storage;self.state_root=path(self.room['state_root'])
        require(self.state_root==path(str(control_root))/room_id and self._storage in self.state_root.parents,
                'LOCAL_NATIVE_CONTROL_ROOT')
        self.nonce=document['installation_id'];self._level=row['mcs_level'];self._project_id=row['quota_project_id']
        self.subnet=row['subnet'];self.gateway=row['gateway']
        self.paths={k:v['path'] for k,v in row['paths'].items()}
        require(all(self.paths[k]==self.room['project']['roots'][k] for k in ('repo','workspace','reference','checkouts'))
                and self.paths['runtime']==str(self.state_root/'runtime'),'LOCAL_NATIVE_PROJECT_BINDING')
        self.boundary={'root_identity':row['root_identity'],'paths':deepcopy(row['paths'])}
        self.image_id=row['workstation']['image_id'];self.image_reference=row['workstation']['image_reference']
        self.hub=deepcopy(row['hub']);self.hub_command=LOCAL_HUB_COMMAND[:]
        self.limits=deepcopy(self.room['resources'])
        require(type(self.limits) is dict and set(self.limits)=={'cpu','memory_bytes','disk_bytes','pids','log_bytes'},'LOCAL_NATIVE_LIMITS')
        cpu=self.limits['cpu']
        require(type(cpu) in (int,float) and math.isfinite(cpu) and 0<cpu<=1024
                and all(type(self.limits[k]) is int and self.limits[k]>0 for k in ('memory_bytes','disk_bytes','pids','log_bytes'))
                and self.limits['log_bytes']<=self.limits['disk_bytes'],'LOCAL_NATIVE_LIMITS')
        nano=Decimal(str(cpu))*1000000000
        require(nano==nano.to_integral_value() and type(self.limits['disk_bytes']) is int
                and self.limits['disk_bytes']>0 and self.limits['disk_bytes']%1024==0,'LOCAL_NATIVE_LIMITS')
        self.nano_cpus=int(nano);self.config_digest=hashlib.sha256(canonical(config)).hexdigest()
        self.digest=hashlib.sha256(canonical({'installation':document,'room':self.room})).hexdigest()
        # No credential bindings or optional Gate/Git resources are fabricated.
        self.git_manifest=self.git_plan=self.gate_manifest=self.gate_plan=None
        self.runtime_plan=None

    def bind_runtime(self,plan):
        from .local_runtime_plan import LocalRuntimePlan
        require(type(plan) is LocalRuntimePlan and plan.native_profile is self,'LOCAL_RUNTIME_PROFILE_BINDING')
        plan.require_unchanged()
        require(self.runtime_plan is None or self.runtime_plan is plan,'LOCAL_RUNTIME_ALREADY_BOUND')
        git=gate=None
        if 'git_manifest' in plan.installation:
            from .native_git_resources import selection
            git=selection(plan)
            require(git['image_id']==self.image_id,'GIT_IMAGE_PAIRING')
        if 'gate_manifest' in plan.installation:
            from .native_gate_resources import selection
            gate=selection(plan)
            require(git is not None and gate['image_id']==self.image_id,'GATE_GIT_PROFILE_REQUIRED')
        self.git_manifest=git;self.git_plan=plan if git is not None else None
        self.gate_manifest=gate;self.gate_plan=plan if gate is not None else None
        self.runtime_plan=plan

    def spec(self):
        result=super().spec()
        if self.runtime_plan is not None:
            self.runtime_plan.require_unchanged()
            digest=hashlib.sha256(canonical({'native':self.digest,
                'runtime':self.runtime_plan.installation_digest,'selection':self.runtime_plan.installation})).hexdigest()
            return replace(result,profile_digest='sha256:'+digest)
        return result

    @property
    def storage(self): return self._storage
    @property
    def level(self): return self._level
    @property
    def project_id(self): return self._project_id
    def storage_ancestors(self): return (self.storage,self.state_root.parent)

    def guard(self, *, require_selinux=True):
        require(os.geteuid()==0,'LOCAL_NATIVE_OPERATOR_ROOT_REQUIRED')
        if require_selinux:
            require(native.command('getenforce').strip()=='Enforcing'
                    and Path('/sys/fs/selinux/enforce').read_text().strip()=='1','LOCAL_NATIVE_SELINUX_REQUIRED')


class LocalNativeBackend(native.NativeQualificationBackend):
    """Same confinement checks; independent persistent installation ownership."""
    LABEL='im.puglab.uas.local-native'
    def __init__(self, profile):
        require(type(profile) is LocalNativeProfile,'LOCAL_NATIVE_PROFILE_REQUIRED')
        DockerFixtureBackend.__init__(self,executable='/usr/bin/docker',timeout=20)
        self.profile=profile;self.listeners=[];self.instance=None

    def _guard(self, *, require_selinux=True):
        self.profile.guard(require_selinux=require_selinux)

    def _run(self,arguments,*,missing_ok=False):
        return native.fixed_docker(arguments,timeout=self.timeout,missing_ok=missing_ok,
                                   socket_path=self.profile.host_profile.socket)

    def engine_selection(self):
        host=self.profile.host_profile
        return {'version':host.engine_version,'docker_root':host.docker_root,
                'remap_user':host.remap_user,'offset':host.offset,'size':host.size}

    def ensure_hub(self,state):
        self._guard();self._binding(state)
        observed=self._hub(state)
        if observed is None:
            try:self.create_hub(state)
            except BackendUnknown:pass
            observed=self._hub(state)
        require(observed is not None,'LOCAL_HUB_CREATE_UNCONFIRMED')
        self.validate_hub(state,observed)
        return observed

    def stop_hub(self,state):
        """Stop exact owned Hub for host shutdown, preserving every durable tree."""
        self._guard(require_selinux=False);self._binding(state)
        observed=self._hub(state)
        if observed is None:return
        self.validate_hub(state,observed)
        if observed['State']['Running']:
            try:self._run(['stop','--time','3',observed['Id']])
            except BackendUnknown:pass
        current=self._hub(state)
        require(current is not None and current['Id']==observed['Id']
                and current['State']['Running'] is False,'LOCAL_HUB_STOP_UNCONFIRMED')

    def reopen_listeners(self,state,*,owner_lock_fd):
        """Rebind only stopped owned resources while caller retains host flock.

        The host passes its root-owned installation lock descriptor and keeps it
        open in every helper. Never close it here; all live helpers must exit
        before a subsequent host can recover these sockets.
        """
        self._guard();self._binding(state)
        lock=os.fstat(owner_lock_fd)
        require(stat.S_ISREG(lock.st_mode) and lock.st_uid==0 and lock.st_nlink==1
                and not lock.st_mode&0o077,'LOCAL_OWNER_LOCK')
        try:fcntl.flock(owner_lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise LifecycleError('LOCAL_OWNER_ACTIVE') from None
        require(not self.listeners,'LOCAL_LISTENERS_ALREADY_OWNED')
        require(self._inspect_object(state,'volume') is not None,'OWNERSHIP_ANCHOR_REQUIRED')
        container=self._inspect_object(state,'container');hub=self._hub(state)
        for value in (container,hub):
            require(value is None or value['State']['Running'] is False,'LOCAL_RECOVERY_REQUIRES_STOPPED')
        if container is not None:self.validate_container(state,container)
        if hub is not None:self.validate_hub(state,hub)
        root=self.endpoints/state['instance_id'];info=root.stat()
        require(root.resolve()==root and info.st_uid==0 and not info.st_mode&0o022,'ENDPOINT_OWNERSHIP')
        fd=os.open(root/'owner.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                    and not info.st_mode&0o077 and 0<info.st_size<=4096,'ENDPOINT_OWNERSHIP')
            record=json.loads(os.read(fd,4097))
        finally:os.close(fd)
        require(record=={**self._endpoint_record(state),'identity':native.directory_identity(root)},'ENDPOINT_OWNERSHIP')
        layout=self.layout(state)
        selected=[(layout['peer']/'pi.sock',native.RUNTIME_UID),(layout['control']/'hub.sock',native.HUB_UID)]
        observed=[]
        for selected_path,group in selected:
            parent=selected_path.parent;info=parent.stat()
            require(parent.resolve()==parent and info.st_uid==native.HOST_UID and info.st_gid==group
                    and stat.S_IMODE(info.st_mode)==0o710,'LOCAL_ENDPOINT_PARENT')
            if os.path.lexists(selected_path):
                info=selected_path.lstat()
                require(stat.S_ISSOCK(info.st_mode) and info.st_uid==native.HOST_UID
                        and info.st_gid==group and stat.S_IMODE(info.st_mode)==0o620,'LOCAL_ENDPOINT_SOCKET')
                observed.append((selected_path,(info.st_dev,info.st_ino)))
        # No path is removed until all ownership and stopped-state checks pass.
        for selected_path,identity in observed:
            info=selected_path.lstat()
            require((info.st_dev,info.st_ino)==identity,'LOCAL_ENDPOINT_CHANGED')
            selected_path.unlink()
        try:
            for selected_path,group in selected:
                self.listeners.append(native.labeled_listener(selected_path,group,level=self.level))
        except BaseException:
            for listener in self.listeners:listener.close()
            self.listeners=[]
            # Exact retained socket files are re-observed on the next explicit
            # recovery. Do not unlink an uncertain bind after failed creation.
            raise
        return tuple(self.listeners)

    def remove(self,state,kind):
        # Destruction is not an install/start/status/stop operation. Explicit
        # future removal must preserve human data with its own authorization.
        raise LifecycleError('LOCAL_NATIVE_DESTROY_NOT_EXPOSED')


class LocalNativeHost:
    """Canonical infrastructure lifecycle; never claims provider/Hub readiness."""
    def __init__(self, config, native_document, state_root, *, authorize, revoke, runtimeplans=None):
        require(callable(authorize) and callable(revoke),'LOCAL_NATIVE_AUTHORITY_REQUIRED')
        self._config=deepcopy(config);self._document=validate_document(native_document)
        self._root=path(str(state_root));self._authorize=authorize;self._revoke=revoke;self._owners={}
        require(runtimeplans is None or type(runtimeplans) is dict,'LOCAL_RUNTIME_PLANS_REQUIRED')
        self._runtimeplans={} if runtimeplans is None else dict(runtimeplans)

    def _owner(self,room_id):
        if room_id not in self._owners:
            profile=LocalNativeProfile(self._config,self._document,room_id,self._root)
            if room_id in self._runtimeplans:
                selected=self._runtimeplans[room_id]
                plan=selected(profile) if callable(selected) else selected
                if plan is not None:
                    require(plan.native_profile is profile,'LOCAL_RUNTIME_PROFILE_BINDING')
                    profile.bind_runtime(plan)
            backend=LocalNativeBackend(profile)
            owner=Supervisor(self._root,room_id,backend,authorize=self._authorize,revoke=self._revoke,
                             **({'state_reader_gid':native.HOST_UID} if profile.runtime_plan is not None else {}))
            self._owners[room_id]=(owner,backend)
        return self._owners[room_id]

    def prepare_start(self,room_id,*,owner_lock_fd):
        """Recover stopped listeners before start, never adopt a live owner.

        Caller retains the installation host lock through the host and helper
        lifetimes. Canonical Room lock also covers observation and rebinding.
        """
        owner,backend=self._owner(room_id)
        backend.profile.guard()
        with owner._locked():
            state=owner._read()
            if state is None:return
            backend._binding(state)
            if not backend.listeners:
                backend.reopen_listeners(state,owner_lock_fd=owner_lock_fd)

    def start(self,room_id):
        owner,backend=self._owner(room_id);backend.profile.guard();backend.profile.observe_storage()
        # Existing unknown/partial effects are reconciled by Supervisor before
        # any effect can be retried; its exact ownership checks remain binding.
        result=owner.start(backend.profile.spec())
        if result['phase']=='running':
            with owner._locked():state=owner._read()
            backend.ensure_hub(state)
        return self.status(room_id)

    def status(self,room_id):
        owner,backend=self._owner(room_id)
        result=owner.status()
        return {'infrastructure':result,'runtime_status':'bindings-required',
                'hub_status':'host-handshake-required','isolation_qualification':'not-claimed'}

    def stop(self,room_id):
        owner,backend=self._owner(room_id);backend.profile.guard(require_selinux=False)
        owner.stop()  # Only Workstation/Participant scope. Hub and data persist.
        return self.status(room_id)

    def resources(self,room_id):
        """Trusted in-process host seam, never a browser-selected object."""
        owner,backend=self._owner(room_id)
        with owner._locked():state=owner._read()
        require(state is not None,'LOCAL_NATIVE_NOT_STARTED');backend._binding(state)
        return owner,backend,deepcopy(state)


class LocalNativeObserver(native.NativeQualificationObserver):
    """Read-only canonical local ownership; never lifecycle authority."""
    LABEL = LocalNativeBackend.LABEL
    name = LocalNativeBackend.name


def readonly_local_supervisor(plan, resources):
    from .local_runtime_plan import LocalRuntimePlan
    require(type(plan) is LocalRuntimePlan, 'LOCAL_RUNTIME_PLAN_REQUIRED')
    plan.require_unchanged()
    require(resources['room_id']==plan.room['id'], 'OBSERVER_BINDING')
    backend=LocalNativeObserver(plan.room['id'],resources['instance'],plan.config_digest)
    owner=Supervisor(Path(plan.config['deployment']['state_root']),plan.room['id'],backend,
                     authorize=lambda *_:False,revoke=lambda *_:False)
    with owner._locked():
        state=owner._read()
        require(state is not None and state['instance_id']==resources['instance']
                and state['phase']=='running' and state['spec']['config_digest']=='sha256:'+plan.config_digest,
                'OBSERVER_BINDING')
    return owner
