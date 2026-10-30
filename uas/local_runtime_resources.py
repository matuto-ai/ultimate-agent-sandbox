"""Root-owned persistent runtime brokers and checkout channel custody.

Uses existing Forge/Git service protocols and identities. Public startup data
contains credential paths, never credential bytes. No caller-supplied commands,
user/group selections or generic privileged operations are accepted.
"""
from pathlib import Path
import os
import socket
import stat
import subprocess
import sys
import time

from .kernel_origin import enable
from .local_host_profile import plan_owners
from .native_image_package import canonical
from .native_qualification import (broker_selection, git_broker_selection,
    check_git_credentials, write_startup, QualificationError)


def require(ok,code):
    if not ok:raise QualificationError(code)


def private_directory(path, *, owner=165534):
    path=Path(path);info=path.lstat()
    require(path.resolve()==path and stat.S_ISDIR(info.st_mode)
            and info.st_uid==owner and stat.S_IMODE(info.st_mode)==0o700,
            'LOCAL_BROKER_PRIVATE_DIRECTORY_UNAVAILABLE')
    return path


def forge_configuration(plan,instance,private,selection):
    owners=plan_owners(plan)
    value={'room_id':plan.room['id'],'room_instance':instance,
           'project_id':plan.room['project']['id'],'repository':plan.room['project']['repository'],
           'deployment_id':plan.config['deployment']['id'],'audit_path':str(private/'audit.db'),
           'result_root':str(private/'results'),'supervisor_uid':owners['supervisor'],'supervisor_gid':owners['supervisor'],
           **{k:v for k,v in selection.items() if k!='version'}}
    require(len(canonical(value))+1<=16384,'BROKER_STARTUP_TOO_LARGE')
    return value


def git_configuration(plan,instance,private,selection):
    owners=plan_owners(plan)
    value={'binding':{'room_id':plan.room['id'],'project_id':plan.room['project']['id'],
                     'repository':plan.room['project']['repository'],'host':'github.com'},
           'room_instance':instance,'deployment_id':plan.config['deployment']['id'],
           'audit_path':str(private/'audit.db'),'supervisor_uid':owners['supervisor'],'supervisor_gid':owners['supervisor'],
           **{k:v for k,v in selection.items() if k!='version'}}
    require(len(canonical(value))+1<=16384,'GIT_BROKER_STARTUP_TOO_LARGE')
    return value


def missing_bindings(plan):
    owners=plan_owners(plan)
    """Only absent protected files are unavailable bindings, never malformed ones."""
    plan.require_unchanged()
    forge=broker_selection(plan)
    entries=[('forge-credential',Path(forge['credential_path']))]
    git=git_broker_selection(plan) if 'git_manifest' in plan.installation else None
    if git is not None:
        entries += [('git-'+name,Path(row[name])) for row in git['credentials']
                    for name in ('key_path','known_hosts_path')]
    missing=[]
    for name,filename in entries:
        try:info=filename.lstat()
        except FileNotFoundError:missing.append(name);continue
        require(filename.resolve()==filename and stat.S_ISREG(info.st_mode)
                and info.st_uid==owners['broker'] and info.st_nlink==1 and not info.st_mode&0o077,
                'PROTECTED_BROKER_CREDENTIAL_INVALID')
    if not missing and git is not None:check_git_credentials(plan,git)
    return sorted(set(missing))


class LocalRuntimeBrokers:
    """One-shot custody; unknown process launch never becomes retry permission."""
    def __init__(self,plan,instance,layout,host_lock_fd):
        require(type(host_lock_fd) is int and host_lock_fd>=3,'LOCAL_HOST_LOCK_REQUIRED')
        self.plan,self.instance,self.layout=plan,instance,layout
        self.owners=plan_owners(plan)
        self.lock_fd=host_lock_fd;self.attempted=False;self.records={};self.allocation=None

    def start(self):
        require(os.geteuid()==0,'LOCAL_RUNTIME_ROOT_REQUIRED')
        require(not self.attempted,'LOCAL_RUNTIME_BROKER_START_ALREADY_ATTEMPTED')
        self.attempted=True
        self.plan.require_unchanged()
        forge=broker_selection(self.plan)
        credential=Path(forge['credential_path']);info=credential.lstat()
        require(credential.resolve()==credential and stat.S_ISREG(info.st_mode)
                and info.st_uid==self.owners['broker'] and not info.st_mode&0o077 and info.st_nlink==1,
                'PROTECTED_BROKER_CREDENTIAL_UNAVAILABLE')
        private=private_directory(self.layout['broker'],owner=self.owners['broker']);results=private/'results'
        if not os.path.lexists(results):
            results.mkdir(mode=0o700);os.chown(results,self.owners['broker'],self.owners['broker'])
        private_directory(results,owner=self.owners['broker'])
        configurations=[('forge','uas.forge_read_service',forge_configuration(self.plan,self.instance,private,forge))]
        if 'git_manifest' in self.plan.installation:
            selected=git_broker_selection(self.plan);check_git_credentials(self.plan,selected)
            git_private=private_directory(self.layout['git-broker'],owner=self.owners['broker'])
            configurations.append(('git','uas.git_service',git_configuration(self.plan,self.instance,git_private,selected)))
        deadline=time.monotonic()+30
        for key,module,configuration in configurations:
            self._spawn(key,module,configuration,deadline)
        root,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.allocation=(root,child);enable(root)
        return self.host_descriptors()

    def _spawn(self,key,module,configuration,deadline):
        require(key in {'forge','git'} and module=={'forge':'uas.forge_read_service','git':'uas.git_service'}[key]
                and key not in self.records,'LOCAL_BROKER_SELECTION')
        host,service=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        row={'host':host,'service':service,'process':None,'expected':True};self.records[key]=row
        process=subprocess.Popen([sys.executable,'-m',module,str(service.fileno())],
            stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            user=self.owners['broker'],group=self.owners['broker'],extra_groups=[],pass_fds=(service.fileno(),self.lock_fd),cwd='/',
            env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(Path(__file__).resolve().parents[1]),
                 'PYTHONDONTWRITEBYTECODE':'1','HOME':'/nonexistent'})
        row['process']=process
        write_startup(process.stdin,canonical(configuration)+b'\n',deadline)
        service.close()

    def host_descriptors(self):
        require(self.allocation is not None and all(row['process'] is not None
                and row['process'].poll() is None for row in self.records.values()),
                'LOCAL_BROKER_START_UNCONFIRMED')
        return {**{key:row['host'].fileno() for key,row in self.records.items()},
                'checkout':self.allocation[1].fileno()}

    def transferred(self,child):
        """After exact Supervisor child adoption, close root's host copies."""
        require(type(child) is subprocess.Popen and child.poll() is None
                and not hasattr(self,'child'),'LOCAL_RUNTIME_CHILD_CUSTODY')
        self.child=child
        for row in self.records.values():row['host'].close()
        if self.allocation is not None:self.allocation[1].close()

    def close(self):
        for row in self.records.values():
            row['host'].close();row['service'].close()
        if self.allocation is not None:
            self.allocation[0].close();self.allocation[1].close()
        # The exact Supervisor must first exit, causing broker pidfd/EOF exit.
        confirmed=True
        for row in self.records.values():
            process=row['process']
            if process is None:confirmed=False;continue
            try:process.wait(timeout=5)
            except Exception:confirmed=False
        return confirmed


from dataclasses import dataclass
from copy import deepcopy
from .native_checkout_handoff import RootCheckoutHandoff


@dataclass(frozen=True)
class LocalCheckoutResources:
    """Root-only canonical references, never accepted from a wire message."""
    data: dict
    _supervisor: object


class LocalRootCheckoutHandoff(RootCheckoutHandoff):
    """One bounded admission epoch; existing eight requests and pins unchanged.

A persistent owner creates this for an actual finite admission operation, not
on every incoming packet. Retrying within that epoch uses this same instance.
Initial admission and first successor remain the canonical supported scope.
"""
    def __init__(self,plan,owner,backend,state,child,channel,*,deadline):
        from .local_runtime_plan import LocalRuntimePlan
        from .local_native import LocalNativeBackend
        from .lifecycle import Supervisor
        require(type(plan) is LocalRuntimePlan and type(owner) is Supervisor
                and type(backend) is LocalNativeBackend and owner.backend is backend
                and type(child) is subprocess.Popen,'LOCAL_CHECKOUT_ROOT_OWNER_REQUIRED')
        plan.require_unchanged();backend._binding(state)
        require(state['room_id']==plan.room['id'] and state['phase']=='running'
                and state['spec']['config_digest']=='sha256:'+plan.config_digest,
                'LOCAL_CHECKOUT_LIFECYCLE_MISMATCH')
        layout=backend.layout(state)
        resources=LocalCheckoutResources({'hub_ledger_path':str(layout['hub']/'room.db'),
                                           'instance':state['instance_id']},owner)
        self._initialize(plan,resources,child,channel,deadline=deadline)

    def _authorized(self, request, *, initial):
        from .local_successor_checkout import authorize_local
        return authorize_local(self, request, initial=initial)

    def operation(self, request):
        from .local_successor_checkout import reuse_primary
        if request['kind'] == 'REUSE_PRIMARY':
            return reuse_primary(self, request)
        if request['kind'] == 'OBSERVE' and getattr(self, 'reused_primary', None) == request['run_id']:
            from .native_checkout_handoff import ready_slot
            with self.allocator._locked('status') as state:
                self._authorized(request, initial=False)
                slot = self.allocator._observe(state, 'primary')
            return ready_slot(slot, request['run_id'], self.pin[1])
        return super().operation(request)


def retained_manifest(ref,target, *, owner=165533):
    """Create once; a restart verifies exact public bytes instead of replacing."""
    from .native_qualification_backend import copy_public_manifest
    import hashlib
    target=Path(target)
    if not os.path.lexists(target):return copy_public_manifest(ref,target,owner=owner)
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==owner
                and stat.S_IMODE(info.st_mode)==0o400 and 0<info.st_size<=16384,
                'LOCAL_PUBLIC_MANIFEST_CHANGED')
        raw=os.read(fd,16385)
    finally:os.close(fd)
    require(hashlib.sha256(raw).hexdigest()==ref['sha256'],'LOCAL_PUBLIC_MANIFEST_CHANGED')
    # Source reference must still match too, not merely the retained copy.
    from .native_pi_recipe import read_manifest
    return read_manifest(ref['path'],ref['sha256'])


def prepare_supervisor_access(owner,profile,state):
    """Same fixed read/lock projection as native provision, no directory writes."""
    with owner._locked():
        current=owner._read()
        require(current is not None and current['instance_id']==state['instance_id']
                and current['phase']=='running','LOCAL_RUNTIME_LIFECYCLE_CHANGED')
        for path in (profile.state_root,profile.state_root/'instances',profile.state_root/'instances'/state['instance_id']):
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                info=os.fstat(fd)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid==0,'CONTROL_OWNER')
                os.fchown(fd,0,0);os.fchmod(fd,0o711)
            finally:os.close(fd)
        for name,mode in (('lifecycle.lock',0o660),('lifecycle.json',0o640)):
            fd=os.open(profile.state_root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
            try:
                info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1,'CONTROL_OWNER')
                os.fchown(fd,0,profile.host_profile.owners['supervisor']);os.fchmod(fd,mode)
            finally:os.close(fd)


class LocalRuntimeResources:
    """Persistent root owner for selected public runtime resources and brokers."""
    def __init__(self,plan,owner,backend,state,base_resources,host_lock_fd):
        from .local_runtime_plan import LocalRuntimePlan
        from .local_native import LocalNativeBackend
        from .lifecycle import Supervisor
        require(type(plan) is LocalRuntimePlan and type(owner) is Supervisor
                and type(backend) is LocalNativeBackend and owner.backend is backend
                and plan.native_profile is backend.profile,'LOCAL_RUNTIME_ROOT_OWNER_REQUIRED')
        plan.require_unchanged();backend._binding(state)
        require(base_resources['instance']==state['instance_id']
                and state['room_id']==plan.room['id'],'LOCAL_RUNTIME_ROOT_SCOPE')
        self.plan,self.owner,self.backend,self.state=plan,owner,backend,deepcopy(state)
        self.data=deepcopy(base_resources);self.lock_fd=host_lock_fd
        self.layout=backend.layout(state);self.brokers=LocalRuntimeBrokers(plan,state['instance_id'],self.layout,host_lock_fd)
        self.extra_fds=[];self.prepared=False;self.child=None;self.handoff=None;self.services=None

    def prepare(self):
        require(not self.prepared,'LOCAL_RUNTIME_PREPARE_ALREADY_ATTEMPTED');self.prepared=True
        self.plan.require_unchanged()
        prepare_supervisor_access(self.owner,self.backend.profile,self.state)
        workstation=self.backend.admit(self.state)
        require(workstation['State']['Running'] is True,'LOCAL_RUNTIME_WORKSTATION_REQUIRED')
        self.data.update(workstation_id=workstation['Id'],
                         supervisor_directory=str(self.layout['supervisor']),
                         hub_ledger_path=str(self.layout['hub']/'room.db'),
                         peer_path=str(self.layout['peer']/'pi.sock'),observer_profile='local-native-v1')
        for runtime in ('pi','claude'):
            target=self.layout['supervisor']/(runtime+'-manifest.json')
            retained_manifest(self.plan.installation[runtime+'_manifest'],target,owner=plan_owners(self.plan)['supervisor'])
            self.data[runtime+'_manifest_path']=str(target)
        if 'git_manifest' in self.plan.installation:
            from .native_git_resources import seal_backend
            require(self.backend.profile.git_manifest is not None and len(self.backend.listeners)>=4,
                    'LOCAL_GIT_NATIVE_RESOURCES_UNAVAILABLE')
            target=self.layout['supervisor']/'git-manifest.json'
            retained_manifest(self.plan.installation['git_manifest'],target,owner=plan_owners(self.plan)['supervisor'])
            fd=seal_backend(self.backend.profile.git_manifest);self.extra_fds.append(fd)
            self.data.update(git_manifest_path=str(target),git_backend_fd=fd,
                git_request_path=str(self.layout['git']/'request.sock'),git_worker_path=str(self.layout['git']/'worker.sock'),
                git_request_fd=self.backend.listeners[2].fileno(),git_worker_fd=self.backend.listeners[3].fileno(),
                git_broker_directory=str(self.layout['git-broker']))
            self.extra_fds.extend([self.data['git_request_fd'],self.data['git_worker_fd']])
        if 'gate_manifest' in self.plan.installation:
            from .native_gate_resources import paths
            require(self.backend.profile.gate_manifest is not None,'LOCAL_GATE_NATIVE_RESOURCES_UNAVAILABLE')
            selected=paths(self.plan,self.state);target=self.layout['supervisor']/'gate-manifest.json'
            retained_manifest(self.plan.installation['gate_manifest'],target,owner=plan_owners(self.plan)['supervisor'])
            self.data.update(gate_manifest_path=str(target),gate_endpoint_path=str(selected['endpoint_root']/'gate.sock'),
                            **{'gate_'+key:str(selected[key]) for key in ('scratch_root','journal_root','launch_journal_root')})
        descriptors=self.brokers.start()
        self.data.update(broker_fd=descriptors['forge'],checkout_fd=descriptors['checkout'])
        if 'git' in descriptors:self.data['git_fd']=descriptors['git']
        self.extra_fds.extend(descriptors.values())
        return deepcopy(self.data),tuple(self.extra_fds)

    def adopt(self,child):
        require(self.child is None and type(child) is subprocess.Popen and child.poll() is None,
                'LOCAL_RUNTIME_CHILD_CUSTODY')
        self.child=child;self.brokers.transferred(child)
        import threading
        self.handoff=LocalCheckoutServer(self,child)
        self._stop=threading.Event();self.server_error=None
        self._thread=threading.Thread(target=self._serve,name='uas-local-checkout',daemon=True)
        self._thread.start()

    def _serve(self):
        import select
        try:
            while not self._stop.is_set() and self.child.poll() is None:
                ready,_,_=select.select([self.handoff.channel],[],[],.2)
                if ready:self.handoff.serve_one()
        except Exception:
            self.server_error='LOCAL_CHECKOUT_SERVICE_UNCONFIRMED'
            self.handoff.channel.close()  # Fence, do not silently restart server.


    def close(self):
        thread=getattr(self,'_thread',None)
        if thread is not None:
            self._stop.set();thread.join(timeout=5)
            if thread.is_alive():return False
        if self.handoff is not None:self.handoff.close()
        closed=self.brokers.close()
        # Only the sealed backend descriptor is ours; listeners belong to backend.
        fd=self.data.get('git_backend_fd')
        if fd is not None:
            try:os.close(fd)
            except OSError:closed=False
            self.data.pop('git_backend_fd',None)
        return closed


class LocalCheckoutServer:
    """Persistent transport, at most two finite canonical Run owner epochs."""
    def __init__(self,resources,child):
        from .kernel_origin import _identity,alive
        require(type(resources) is LocalRuntimeResources and resources.child is child
                and type(child) is subprocess.Popen,'LOCAL_CHECKOUT_SERVER_OWNER')
        self.resources,self.child=resources,child
        self.channel=resources.brokers.allocation[0];self.epochs={};self.closed=False
        self.pidfd=os.pidfd_open(child.pid,0)
        try:
            self.identity=_identity(self.pidfd)
            require(child.poll() is None and alive(self.pidfd),'LOCAL_CHECKOUT_CHILD_EXITED')
        except BaseException:os.close(self.pidfd);raise

    def _state(self):
        from .ledger import RoomLedger
        filename=self.resources.data['hub_ledger_path'];info=Path(filename).lstat()
        identity=(info.st_dev,info.st_ino)
        require(Path(filename).resolve()==Path(filename) and stat.S_ISREG(info.st_mode)
                and info.st_nlink==1,'LOCAL_CHECKOUT_STORE_CHANGED')
        previous=getattr(self,'ledger_identity',identity)
        require(identity==previous,'LOCAL_CHECKOUT_STORE_CHANGED');self.ledger_identity=identity
        with RoomLedger.open_reader(filename,self.resources.plan.room['id']) as ledger:
            result=ledger.snapshot()['state']
        after=Path(filename).lstat()
        require((after.st_dev,after.st_ino)==identity,'LOCAL_CHECKOUT_STORE_CHANGED')
        return result

    def _epoch(self,request):
        from .local_successor_checkout import local_request
        local_request(request)
        state=self._state()
        if request['kind']=='GATE_QUOTA':
            evaluation=state.get('gate_evaluations',{}).get(request['evaluation_id'],{})
            run=evaluation.get('scope',{}).get('run_id')
            require(run in self.epochs,'LOCAL_CHECKOUT_EPOCH_REQUIRED')
            return self.epochs[run]
        run=request['run_id']
        if run in self.epochs:return self.epochs[run]
        require(len(self.epochs)<1024,'LOCAL_CHECKOUT_SUPPORTED_EPOCH_LIMIT')
        for previous in self.epochs:
            row=state.get('runs',{}).get(previous,{})
            require(row.get('status')=='CLOSED' and row.get('native_stop',{}).get('status')=='VERIFIED',
                    'LOCAL_CHECKOUT_PREVIOUS_EPOCH_UNRESOLVED')
        resource=self.resources
        deadline=time.monotonic()+resource.plan.operation_timeout_seconds
        epoch=LocalRootCheckoutHandoff(resource.plan,resource.owner,resource.backend,resource.state,
                                      self.child,self.channel,deadline=deadline)
        try:
            # No effect before canonical PREPARING/seat/Human reservation proof.
            with resource.owner._locked(deadline=deadline):
                epoch._authorized(request,initial=request['kind'] in ('ALLOCATE','REUSE_PRIMARY'))
        except BaseException:epoch.close();raise
        epoch.local_resources=resource
        self.epochs[run]=epoch
        return epoch

    def serve_one(self):
        import json
        from .kernel_origin import receive,_identity,alive
        from .native_checkout_handoff import MAX_REQUEST,MAX_REPLY,MAX_REQUESTS,request_value,remaining
        from .workstation_admission import _unique
        from .lifecycle import LifecycleError
        from .ledger import LedgerError
        require(not self.closed and self.child.poll() is None and alive(self.pidfd),
                'LOCAL_CHECKOUT_CHILD_EXITED')
        self.channel.settimeout(5)
        with receive(self.channel) as record:
            require(record.credentials==(self.child.pid,plan_owners(self.resources.plan)['supervisor'],plan_owners(self.resources.plan)['supervisor']) and alive(record.pidfd)
                    and _identity(record.pidfd)==self.identity and len(record.data)<=MAX_REQUEST,
                    'LOCAL_CHECKOUT_HOST_MISMATCH')
            from .local_successor_checkout import local_request
            request=local_request(json.loads(record.data,object_pairs_hook=_unique))
        try:
            epoch=self._epoch(request)
            # Each authenticated packet has a bounded I/O budget. Retained pins
            # and one-effect attempts survive; elapsed Run time grants no retry.
            epoch.deadline=time.monotonic()+self.resources.plan.operation_timeout_seconds
            epoch.allocator.deadline=epoch.deadline
            epoch._held()
            if request['kind'] != 'GATE_QUOTA': epoch.count+=1
            require(epoch.count<=MAX_REQUESTS,'CHECKOUT_REQUEST_LIMIT')
            result=epoch.operation(request)
            reply={**request,'status':'OK','quota' if request['kind']=='GATE_QUOTA' else 'slot':result}
        except (LifecycleError,LedgerError,QualificationError) as error:
            reply={**request,'status':'ERROR','error':error.code}
        raw=canonical(reply);require(len(raw)<=MAX_REPLY,'CHECKOUT_REPLY_LIMIT')
        self.channel.settimeout(5)
        require(self.channel.send(raw)==len(raw),'CHECKOUT_REPLY_UNKNOWN')

    def close(self):
        self.closed=True
        for epoch in self.epochs.values():epoch.close()
        if self.pidfd>=0:
            fd,self.pidfd=self.pidfd,-1;os.close(fd)
