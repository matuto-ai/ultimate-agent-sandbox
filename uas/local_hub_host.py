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
    if (type(value) is not dict or type(value.get('version')) is not int or value['version'] not in (1,2)
            or set(value) - {'library'} not in (({'version','room','resources'}|({'host_profile'} if value['version']==2 else set())),
                                  ({'version','room','resources','runtime'}|({'host_profile'} if value['version']==2 else set())))
            or type(value['room']) is not dict or type(value['resources']) is not dict):
        raise QualificationError('LOCAL_HUB_STARTUP_DOCUMENT')
    if 'library' in value:
        selected = value['library']
        if (type(selected) is not dict or set(selected) != {'fd','root_identity','project','source_identity'}
                or type(selected['fd']) is not int or selected['fd'] < 3
                or type(selected['root_identity']) is not list or len(selected['root_identity']) != 2
                or any(type(v) is not int or v < 0 for v in selected['root_identity'])):
            raise QualificationError('LOCAL_LIBRARY_STARTUP')
        from .library import project_binding
        project_binding(selected['project'],source_identity=selected['source_identity'])
        if selected['project'] != value['room'].get('project'):
            raise QualificationError('LOCAL_LIBRARY_STARTUP')
    resources=value['resources']
    if (set(resources)!={'hub_id','instance','control_path','mapping_digest','control_fd','peer_fd'}
            or any(type(resources[k]) is not int or resources[k]<3 for k in ('control_fd','peer_fd'))
            or resources['control_fd']==resources['peer_fd']):
        raise QualificationError('LOCAL_HUB_STARTUP_RESOURCES')
    if 'library' in value:
        reserved={resources['control_fd'],resources['peer_fd']}
        runtime=value.get('runtime',{})
        if type(runtime) is dict:
            reserved.update(runtime.get(k) for k in ('broker_fd','checkout_fd','git_fd'))
        if value['library']['fd'] in reserved:
            raise QualificationError('LOCAL_LIBRARY_STARTUP_ALIAS')
    startup_engine(value)
    return value


def startup_engine(value):
    from .local_host_profile import LocalHostProfile
    if value['version']==1:
        socket_path='/run/docker.sock';selected=None
    else:
        selected=LocalHostProfile.parse(value['host_profile'])
        socket_path=selected.socket
    if 'runtime' in value:
        from .local_native import validate_document, selected_host
        runtime=value['runtime']
        if type(runtime) is not dict or 'native_document' not in runtime:
            raise QualificationError('LOCAL_RUNTIME_STARTUP_SCHEMA')
        native_host=selected_host(validate_document(runtime['native_document']))
        if ((selected is not None and native_host.document()!=selected.document())
                or (selected is None and native_host.socket!=socket_path)):
            raise QualificationError('LOCAL_RUNTIME_ENGINE_BINDING')
    return socket_path


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


FAILURE_PHASES = frozenset({'bootstrap','library-root','hub-startup','relay-start','runtime-setup','serving',
    'hub-attach','hub-start','hub-write','hub-connect','hub-origin','hub-release','hub-library-handoff','hub-ready'})
FAILURE_KINDS = frozenset({'origin-denied','origin-unavailable','qualification','permission','timeout','os-error','other'})


def failure_receipt(phase, error):
    from .kernel_origin import OriginDenied, OriginUnavailable
    kind = next((name for cls,name in ((OriginDenied,'origin-denied'),
        (OriginUnavailable,'origin-unavailable'),(QualificationError,'qualification'),
        (PermissionError,'permission'),(TimeoutError,'timeout'),(OSError,'os-error'))
        if isinstance(error,cls)), 'other')
    return {'version':1,'status':'unknown','phase':phase if phase in FAILURE_PHASES else 'bootstrap','error':kind}


def run(raw,parent_fd,*,phase=lambda _:None):
    phase('bootstrap')
    if os.getuid()==0 or os.getgid()==0:
        raise QualificationError('LOCAL_HUB_FIXED_OWNER_REQUIRED')
    document=startup_document(raw)
    from .local_host_profile import LocalHostProfile
    host_profile=LocalHostProfile.parse(document['host_profile']) if document['version']==2 else None
    owner=HOST_UID if host_profile is None else host_profile.owners['supervisor']
    if (os.getuid(),os.getgid())!=(owner,owner):
        raise QualificationError('LOCAL_HUB_FIXED_OWNER_REQUIRED')
    resources=document['resources'];probe()
    with ExitStack() as stack:
        self_fd=os.pidfd_open(os.getpid(),0);stack.callback(os.close,self_fd)
        startup=metadata(document['room'],resources,_identity(self_fd),secrets.token_hex(32))
        library_channel = None
        if 'library' in document:
            phase('library-root')
            from .kernel_origin import enable, receive, HeldOrigin
            from .local_library_transport import Relay, accept_handoff, require
            root_channel = socket.socket(fileno=document['library']['fd']); stack.callback(root_channel.close)
            enable(root_channel); root_channel.settimeout(5)
            with receive(root_channel) as record:
                require(record.credentials[1:] == (0,0)
                        and list(_identity(record.pidfd)) == document['library']['root_identity']
                        and json.loads(record.data) == {'kind':'root-ready'})
                root_origin = HeldOrigin(record)
            stack.callback(root_origin.close)
            startup['library'] = {k:document['library'][k] for k in ('project','source_identity')}
            configuration(_canonical(startup),persistent=True)
        def receive_library(control, hub_origin):
            nonlocal library_channel
            library_channel = accept_handoff(control, hub_origin)
            stack.callback(library_channel.close)
        listener=socket.socket(fileno=resources['control_fd']);stack.callback(listener.close)
        peer=socket.socket(fileno=resources['peer_fd']);stack.callback(peer.close)
        phase('hub-startup')
        control,origin,ready,_=start_hub_channel(DockerExecAPI(startup_engine(document)),resources,
                                               startup,listener,stack,SessionBudget(30),host_profile=host_profile,progress=phase,
                                               library_handoff=receive_library if 'library' in document else None)
        if library_channel is not None:
            phase('relay-start')
            relay=Relay(library_channel,origin,root_channel,root_origin)
            relay.start();stack.callback(relay.close)
        receipt={'version':1,'status':'ready','room_id':startup['room_id'],
                 'room_instance':startup['room_instance'],'controller':ready['controller']}
        def announce(_=None):
            phase('serving')
            sys.stdout.buffer.write(_canonical(receipt)+b'\n');sys.stdout.buffer.flush()
        if 'runtime' not in document:
            announce();retain(control,origin,parent_fd)
        else:
            phase('runtime-setup')
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
    phase=['bootstrap']
    try:run(bytes(raw),0,phase=lambda value:phase.__setitem__(0,value))
    except Exception as error:
        sys.stdout.buffer.write(_canonical(failure_receipt(phase[0],error))+b'\n')
        sys.stdout.buffer.flush();raise


if __name__=='__main__':main()
