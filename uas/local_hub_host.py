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
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise QualificationError('LOCAL_HUB_STARTUP_DOCUMENT')
    value=json.loads(raw,object_pairs_hook=_unique)
    if (type(value) is not dict or set(value)!={'version','room','resources'}
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
        sys.stdout.buffer.write(_canonical(receipt)+b'\n');sys.stdout.buffer.flush()
        retain(control,origin,parent_fd)


def main():
    if len(sys.argv)!=1:raise QualificationError('LOCAL_HUB_FIXED_ENTRYPOINT')
    # Unbuffered reads prevent consuming parent lifetime bytes beyond newline.
    raw=bytearray()
    while len(raw)<=65536:
        byte=os.read(0,1)
        if byte==b'\n':break
        if not byte:raise QualificationError('LOCAL_HUB_STARTUP_EOF')
        raw.extend(byte)
    try:run(bytes(raw),0)
    except Exception:
        sys.stdout.buffer.write(b'{"version":1,"status":"unknown","code":"LOCAL_HUB_START_OR_OWNER_UNCONFIRMED"}\n')
        sys.stdout.buffer.flush();raise


if __name__=='__main__':main()
