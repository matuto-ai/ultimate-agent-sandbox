"""Fixed non-root persistent Hub owner; no participant or provider launch.

Root retains this process and stdin pipe. A single startup line is followed by
silence; EOF revokes the held Hub control channel. A startup error is uncertain,
not permission to retry Docker start. stdout is a private readiness pipe.
"""
from contextlib import ExitStack
import json
import os
import secrets
import select
import socket
import sys

from .kernel_origin import _identity, probe, alive
from .native_session import HOST_UID, SessionBudget, start_hub_channel
from .docker_exec_api import DockerExecAPI
from .workstation_service import configuration
from .workstation_admission import _canonical, _unique
from .native_qualification import QualificationError


def startup_document(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 2*1048576:
        raise QualificationError('LOCAL_HUB_STARTUP_DOCUMENT')
    value=json.loads(raw,object_pairs_hook=_unique)
    if (type(value) is not dict or set(value) not in ({'version','room','resources'},{'version','room','resources','runtime'})
            or type(value['version']) is not int or value['version']!=1
            or type(value['room']) is not dict or type(value['resources']) is not dict):
        raise QualificationError('LOCAL_HUB_STARTUP_DOCUMENT')
    resources=value['resources']
    if (set(resources)!={'hub_id','instance','control_path','mapping_digest','control_fd','peer_fd'}
            or any(type(resources[k]) is not int or resources[k]<3 for k in ('control_fd','peer_fd'))
            or resources['control_fd']==resources['peer_fd']):
        raise QualificationError('LOCAL_HUB_STARTUP_RESOURCES')
    return value


def metadata(room,resources,identity,challenge):
    value={'version':1,'profile':'local-hub-v1','challenge':challenge,
           'supervisor_identity':list(identity),'mapping_digest':resources['mapping_digest'],
           'room_id':room['id'],'room_instance':resources['instance'],
           'seats':[{'participant_id':s['participant'],'actor_id':s['actor'],'profile_id':s['profile']}
                    for s in room['seats']]}
    if 'project' in room:
        # Public Project policy only, not credentials or a fabricated Run.
        value['forge']={'project_id':room['project']['id'],
                        'repository':room['project']['repository'],'host':'github.com'}
        profiles={profile['id']:profile for profile in room['profiles']}
        for source,target in zip(room['seats'],value['seats']):
            target['capabilities']=sorted(set(profiles[source['profile']]['capabilities']) | {'peer-traffic'})
    configuration(_canonical(value),persistent=True)
    return value


def retain(control,origin,parent_fd):
    """No idle deadline. Actual parent EOF or Hub loss ends ownership."""
    while True:
        if origin.revoked or not alive(origin.pidfd):
            raise QualificationError('LOCAL_HUB_OWNER_LOST')
        readable,_,failed=select.select([parent_fd,control,origin.pidfd],[],[control],1)
        if failed or control in readable or origin.pidfd in readable:
            raise QualificationError('LOCAL_HUB_OWNER_LOST')
        if parent_fd in readable:
            if os.read(parent_fd,1)==b'':return
            raise QualificationError('LOCAL_HUB_UNEXPECTED_PARENT_DATA')


def run(raw,parent_fd):
    if (os.getuid(),os.getgid())!=(HOST_UID,HOST_UID):
        raise QualificationError('LOCAL_HUB_FIXED_OWNER_REQUIRED')
    document=startup_document(raw);resources=document['resources'];probe()
    with ExitStack() as stack:
        self_fd=os.pidfd_open(os.getpid(),0);stack.callback(os.close,self_fd)
        startup=metadata(document['room'],resources,_identity(self_fd),secrets.token_hex(32))
        listener=socket.socket(fileno=resources['control_fd']);stack.callback(listener.close)
        peer=socket.socket(fileno=resources['peer_fd']);stack.callback(peer.close)
        control,origin,ready,_=start_hub_channel(DockerExecAPI('/run/docker.sock'),resources,
                                               startup,listener,stack,SessionBudget(30))
        receipt={'version':1,'status':'ready','room_id':startup['room_id'],
                 'room_instance':startup['room_instance'],'controller':ready['controller']}
        def announce(_=None):
            sys.stdout.buffer.write(_canonical(receipt)+b'\n');sys.stdout.buffer.flush()
        if 'runtime' not in document:
            announce();retain(control,origin,parent_fd)
        else:
            from io import StringIO
            from .config import load
            from .local_native import LocalNativeProfile
            from .local_runtime_plan import LocalRuntimePlan
            from .local_native_run_session import LocalNativeRunSession
            from .local_runtime_manager import serve_runtime_manager
            runtime=document['runtime']
            require_fields={'configuration','installation','installation_digest','resources',
                            'native_document','manager_reference','broker_fd','checkout_fd','git_fd'}
            if type(runtime) is not dict or set(runtime)!=require_fields:
                raise QualificationError('LOCAL_RUNTIME_STARTUP_SCHEMA')
            config=load(StringIO(runtime['configuration']))
            profile=LocalNativeProfile(config,runtime['native_document'],document['room']['id'],
                                       config['deployment']['state_root'])
            plan=LocalRuntimePlan(runtime['configuration'],runtime['installation'],
                                  installation_digest=runtime['installation_digest'],native_profile=profile)
            profile.bind_runtime(plan)
            native_resources=runtime['resources']
            if (native_resources['instance']!=resources['instance']
                    or native_resources['hub_id']!=resources['hub_id']):
                raise QualificationError('LOCAL_RUNTIME_STARTUP_SCOPE')
            owner=LocalNativeRunSession(plan,native_resources,control=control,origin=origin,
                ready=ready,metadata=startup,broker_fd=runtime['broker_fd'],
                checkout_fd=runtime['checkout_fd'],git_fd=runtime['git_fd'],parent_fd=parent_fd)
            stack.callback(owner.close)
            owner.clients()  # Authenticate retained brokers before declaring host readiness.
            def stopped():
                try:owner.current();return False
                except Exception:return True
            serve_runtime_manager(plan,native_resources,owner,runtime['manager_reference'],
                                  stopped=stopped,on_ready=announce)


def main():
    if len(sys.argv)!=1:raise QualificationError('LOCAL_HUB_FIXED_ENTRYPOINT')
    # Unbuffered reads prevent consuming parent lifetime bytes beyond newline.
    raw=bytearray()
    while len(raw)<=2*1048576:
        byte=os.read(0,1)
        if byte==b'\n':break
        if not byte:raise QualificationError('LOCAL_HUB_STARTUP_EOF')
        raw.extend(byte)
    try:run(bytes(raw),0)
    except Exception:
        sys.stdout.buffer.write(b'{"version":1,"status":"unknown","code":"LOCAL_HUB_START_OR_OWNER_UNCONFIRMED"}\n')
        sys.stdout.buffer.flush();raise


if __name__=='__main__':main()
