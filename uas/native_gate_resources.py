"""Exact artifacts-only native Gate resources; no fixture admission or fallback.

Construction is a source seam for the separately selected prepared profile, not
proof that a helper has installed Landlock/seccomp. Only the fixed helper's real
successful protocol, held exit, postproof and cleanup may establish that result.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time
from decimal import Decimal

from .artifact_helper import GateEndpointLease, GateWorkstation
from .artifact_protocol import ArtifactError, PROFILE_ID, RESERVATION_BYTES, canonical, validate_scope
from .native_git_resources import _ImageReader, NativeGitResources
from .native_pi_recipe import read_manifest

HELPERS = ('/opt/uas/bin/artifact-bootstrap', '/opt/uas/bin/artifact-evaluator')
HOST_TOOLS = ('/usr/bin/git', '/usr/bin/prlimit')
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(condition, code):
    if not condition: raise ArtifactError('NATIVE_GATE_' + code)


def selection(plan, *, filename=None):
    ref = plan.installation['gate_manifest']
    value = read_manifest(filename or ref['path'], ref['sha256'])
    return validate_selection(value,plan)


def validate_selection(value,plan):
    require(type(value) is dict and set(value) == {'version','profile','image_id','image_reference','helpers','host_materializer'}, 'MANIFEST')
    require(type(value['version']) is int and value['version'] == 1
        and value['profile'] == PROFILE_ID and 'git_manifest' in plan.installation, 'PROFILE')
    image=next(i['reference'] for i in plan.config['deployment']['images'] if i['id']==plan.room['image'])
    require(type(value['image_id']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',value['image_id'])
        and value['image_reference']==image,'IMAGE_PAIRING')
    for key, paths in (('helpers',HELPERS),('host_materializer',HOST_TOOLS)):
        require(type(value[key]) is dict and set(value[key]) == set(paths)
            and all(type(v) is str and SHA.fullmatch(v) for v in value[key].values()), 'PAYLOAD_INVENTORY')
    return value


def paths(plan, state):
    instance = state['instance_id']
    require(type(instance) is str and re.fullmatch(r'[0-9a-f]{32}',instance), 'INSTANCE')
    root = Path(plan.room['state_root'])/'instances'/instance/'native'
    return {'scratch_root':root/'gate-targets', 'journal_root':root/'supervisor'/'gate-target-journals',
        'launch_journal_root':root/'supervisor'/'gate-launches',
        'endpoint_root':Path('/run/uas-native')/instance/'gate'}


@dataclass(frozen=True)
class NativeGateMount:
    source: str
    destination: str
    read_only: bool = True


def gate_mounts(plan,state):
    selected = paths(plan,state)
    return (NativeGateMount(str(selected['scratch_root']),'/uas/gate-targets'),
            NativeGateMount(str(selected['endpoint_root']),'/uas/gate'))


class NativeGateMountProfile:
    def __setattr__(self,key,value):
        require(not getattr(self,'_frozen',False),'IMMUTABLE_PROFILE')
        object.__setattr__(self,key,value)

    @classmethod
    def from_plan(cls,plan,state,manifest,manifest_digest,*,container_id,mapping_digest):
        validate_selection(manifest,plan)
        require(state['room_id']==plan.room['id'] and manifest_digest==plan.installation['gate_manifest']['sha256'],'PROFILE_BINDING')
        require(all(type(v) is str and SHA.fullmatch(v) for v in (manifest_digest,container_id,mapping_digest)), 'PROFILE_IDENTITY')
        self=cls(); self.room_id=plan.room['id']; self.instance_id=state['instance_id']
        self.container_id=container_id; self.mapping_digest=mapping_digest
        self.image_id=manifest['image_id']; self.image_reference=manifest['image_reference']
        self.mounts=gate_mounts(plan,state)
        self._document={'version':1,'profile':PROFILE_ID,'room_id':self.room_id,'instance':self.instance_id,
            'container_id':container_id,'image_id':self.image_id,'image_reference':self.image_reference,
            'manifest_digest':manifest_digest,'mapping_digest':mapping_digest,
            'mounts':[{'source':m.source,'destination':m.destination,'read_only':m.read_only} for m in self.mounts]}
        self._canonical=canonical(self._document)
        self.digest=hashlib.sha256(self._canonical).hexdigest();self._frozen=True
        return self

    def document(self):
        require(getattr(self,'_frozen',False),'GENERATED_PROFILE_REQUIRED')
        return json.loads(self._canonical)
    def mount_tuples(self):
        self.document()
        return tuple((m.source,m.destination,False) for m in self.mounts)


def static_elf(prefix):
    """Check bounded ELF/program headers from actual immutable archive bytes."""
    require(type(prefix) is bytes and len(prefix)>=64 and prefix[:7]==b'\x7fELF\x02\x01\x01', 'STATIC_ELF')
    require(struct.unpack_from('<H',prefix,18)[0]==62, 'STATIC_ELF')
    offset=struct.unpack_from('<Q',prefix,32)[0]
    size,count=struct.unpack_from('<HH',prefix,54)
    require(size==56 and 0<count<=64 and offset>=64 and offset+count*size<=len(prefix), 'STATIC_ELF')
    loads=0
    for pos in range(offset,offset+count*size,size):
        kind,flags=struct.unpack_from('<II',prefix,pos)
        require(kind not in (2,3) and not (flags&1 and flags&2), 'STATIC_ELF')
        loads += kind==1
    require(loads>0,'STATIC_ELF')


def verify_payload(engine,container_id,manifest,deadline):
    reader=_ImageReader(engine,container_id,HELPERS,deadline)
    for path in HELPERS:
        item=reader.single(path)
        require(item['kind']=='file' and item['uid']==0 and not item['mode']&0o022
            and item['mode']&0o111 and item['sha256']==manifest['helpers'][path], 'HELPER_PAYLOAD')
        static_elf(item.get('prefix'))
    # These are HOST copied-store tools, never the Workstation public launcher.
    from .artifact_target import _trusted_executable
    for path in HOST_TOOLS:
        _trusted_executable(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022
                and before.st_nlink==1 and 0<before.st_size<=64*1024*1024,'HOST_PAYLOAD')
            digest=hashlib.sha256(); count=0
            while True:
                require(time.monotonic()<deadline,'DEADLINE')
                block=os.read(fd,65536)
                if not block:break
                count+=len(block);require(count<=before.st_size,'HOST_PAYLOAD');digest.update(block)
            after=os.fstat(fd)
            require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                and count==before.st_size and digest.hexdigest()==manifest['host_materializer'][path], 'HOST_PAYLOAD')
        finally:os.close(fd)


def reservation_snapshot(state, scope):
    """Canonical existing ledger only; no second reservation authority/store."""
    validate_scope(scope)
    rows=state.get('gate_evaluations',{})
    row=rows.get(scope['evaluation_id'])
    require(type(row) is dict and row.get('scope')==scope and row.get('result') is None
        and row.get('reservation',{}).get('scratch_bytes')==RESERVATION_BYTES,'RESERVATION')
    outstanding=[]
    for key,value in rows.items():
        amount=value.get('reservation',{}).get('scratch_bytes')
        require(type(amount) is int and amount>=0,'RESERVATION')
        if amount:outstanding.append({'evaluation_id':key,'scratch_bytes':amount})
    outstanding.sort(key=lambda row:row['evaluation_id'])
    return {'scope':deepcopy(scope),'source':deepcopy(row['source']),
        'checkout_digest':row['checkout_digest'],'outstanding':outstanding}


class NativeGateResources:
    @classmethod
    def from_session(cls,plan,data,engine,*,supervisor,listener,git_resources,review_host,quota_client,gate_profile,deadline):
        from .docker_exec_api import DockerExecAPI
        from .native_review_host import NativeReviewHost
        from .native_checkout_handoff import NativeCheckoutClient
        require(type(git_resources) is NativeGitResources and git_resources.supervisor is supervisor
            and git_resources.plan is plan and type(engine) is DockerExecAPI
            and type(review_host) is NativeReviewHost and review_host.identity.supervisor is supervisor
            and type(quota_client) is NativeCheckoutClient, 'CONCRETE_OWNERS')
        self=cls();self.plan=plan;self.data=deepcopy(data);self.engine=engine;self.supervisor=supervisor
        self.git_resources=git_resources;self.review_host=review_host;self.quota_client=quota_client
        self.deadline=deadline;self.listener=listener;self._closed=False
        self.room_id=plan.room['id'];self.instance=data['instance'];self.container_id=data['workstation_id']
        with supervisor._locked():
            git_resources.require(self.room_id,self.instance,self.container_id)
            state=supervisor._read()
        manifest=selection(plan,filename=data['gate_manifest_path'])
        require(manifest['image_id']==git_resources.profile.image_id
            and manifest['image_reference']==git_resources.profile.image_reference,'IMAGE_PAIRING')
        selected=paths(plan,state)
        expected_profile=NativeGateMountProfile.from_plan(plan,state,manifest,plan.installation['gate_manifest']['sha256'],
            container_id=self.container_id,mapping_digest=data['mapping_digest'])
        require(gate_profile is git_resources.gate_profile and type(gate_profile) is NativeGateMountProfile and gate_profile.document()==expected_profile.document()
            and gate_profile.mounts==expected_profile.mounts,'PROFILE_BINDING')
        self.profile=gate_profile
        for key in ('scratch_root','journal_root','launch_journal_root'):
            require(data['gate_'+key]==str(selected[key]),'RESOURCE_PATH');setattr(self,key,selected[key])
        self._directory_identities={}
        for key,mode in (('scratch_root',0o711),('journal_root',0o700),('launch_journal_root',0o700)):
            path=getattr(self,key); node=path.stat(follow_symlinks=False)
            require(path.resolve()==path and stat.S_ISDIR(node.st_mode) and node.st_uid==165533
                and node.st_gid==165533 and stat.S_IMODE(node.st_mode)==mode,'RESOURCE_DIRECTORY')
            self._directory_identities[key]=(node.st_dev,node.st_ino)
        endpoint=selected['endpoint_root']/'gate.sock'
        require(data['gate_endpoint_path']==str(endpoint) and os.getuid()==165533 and os.getgid()==165533
            and 165530 in os.getgroups(),'SUPERVISOR_SETUP_IDENTITY')
        self.endpoint=GateEndpointLease(endpoint,owner=165533,group=165530)
        require(type(listener) is socket.socket and listener.family==socket.AF_UNIX
            and listener.type==socket.SOCK_SEQPACKET and listener.getsockname()==str(endpoint)
            and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'SUPERVISOR_LISTENER')
        node=os.fstat(listener.fileno());self._listener_identity=(node.st_dev,node.st_ino)
        verify_payload(engine,self.container_id,manifest,deadline)
        self.workstation=GateWorkstation(self.room_id,self.instance,self.container_id,manifest['image_id'][7:],
            self.profile.digest,manifest['helpers'][HELPERS[0]],manifest['helpers'][HELPERS[1]],data['mapping_digest'],'native-artifacts')
        self.require(self.workstation)
        return self

    def require(self,workstation):
        require(not self._closed and workstation is self.workstation,'WORKSTATION_BINDING')
        require(time.monotonic()<self.deadline,'DEADLINE')
        # This entry is outside lifecycle/Room locks, before helper creation.
        with self.supervisor._locked():
            self.git_resources.require(self.room_id,self.instance,self.container_id)
            state=self.supervisor._read()
        value=self.engine.inspect_container(self.container_id)
        self.git_resources._verify_container(value,self.data)
        from .native_qualification_backend import validate_native_container
        base=[(p,p,k!='reference') for k,p in self.plan.room['project']['roots'].items()
            if k in ('repo','workspace','reference','checkouts')]
        runtime=self.plan.room['state_root']+'/runtime';peer=str(Path(self.data['peer_path']).parent)
        mounts=base+[(runtime,runtime,True),(peer,peer,False)]+list(self.git_resources.profile.mount_tuples())+list(self.profile.mount_tuples())
        nano=Decimal(str(self.plan.room['resources']['cpu']))*1000000000
        require(nano==nano.to_integral_value(),'CPU_PROFILE')
        validate_native_container(state,value,image_id=self.profile.image_id,image_reference=self.profile.image_reference,
            limits=self.plan.room['resources'],nano_cpus=int(nano),mounts=mounts)
        require(value['State']['Running'] is True and type(value['State'].get('Pid')) is int
            and value['State']['Pid']==self.git_resources._container_pid,'WORKSTATION_PROCESS_CHANGED')
        with self.supervisor._locked():self.git_resources.require(self.room_id,self.instance,self.container_id)
        self.endpoint.require()
        node=os.fstat(self.listener.fileno())
        require((node.st_dev,node.st_ino)==self._listener_identity
            and self.listener.getsockname()==str(self.endpoint.path)
            and self.listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'LISTENER_REPLACED')
        for key,identity in self._directory_identities.items():
            node=getattr(self,key).stat(follow_symlinks=False)
            require(stat.S_ISDIR(node.st_mode) and (node.st_dev,node.st_ino)==identity
                and node.st_uid==165533 and node.st_gid==165533
                and stat.S_IMODE(node.st_mode)==(0o711 if key=='scratch_root' else 0o700),'RESOURCE_REPLACED')
        return True

    def reserve_capacity(self,scope,amount):
        require(type(amount) is int and amount==RESERVATION_BYTES,'ARTIFACTS_ONLY')
        require(scope['room_instance']==self.instance and scope['room_id']==self.room_id,'ROOM_BINDING')
        active=self.review_host.identity.active
        require(active is not None,'ACTIVE_OPERATION_REQUIRED')
        with active.commit():
            first=reservation_snapshot(self.review_host.identity.ledger.snapshot()['state'],scope)
        observation=self.quota_client.observe_gate_quota(scope['evaluation_id'])
        with active.commit():
            again=reservation_snapshot(self.review_host.identity.ledger.snapshot()['state'],scope)
            require(first==again,'RESERVATION_CHANGED')
            require(all(observation.get(k)==v for k,v in again.items()),'QUOTA_BINDING')
            require(observation.get('instance')==self.instance
                and observation.get('scratch_identity')==list(self._directory_identities['scratch_root']),'QUOTA_RESOURCE')
            used,hard=observation.get('used_bytes'),observation.get('hard_bytes')
            require(type(used) is int and type(hard) is int and used>=0
                and hard==self.plan.room['resources']['disk_bytes'],'QUOTA_OBSERVATION')
            require(used+sum(r['scratch_bytes'] for r in again['outstanding'])<=hard,'QUOTA_CAPACITY')
        return True

    def close(self):
        self._closed=True  # listener custody remains with session ExitStack
