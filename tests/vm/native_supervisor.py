"""Fixed mapped nonroot Supervisor for the deliberate no-NIC native scenario."""
import base64
from contextlib import ExitStack, closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import time
import threading

from uas.docker_exec_api import DockerExecAPI
from uas.kernel_origin import HeldOrigin, ReceiverIdentity, _identity, alive, enable, probe, receive
from uas.peer import Readiness
from uas.workstation_admission import AdmissionSeat, _canonical
from uas.workstation_control import SupervisorAdmission
from uas.workstation_exec import EndpointLease, ExecLaunch, ExecSeat
from uas.workstation_service import RELEASE


def expect(value,message):
    if not value:raise RuntimeError(message)


def encoded(value):return base64.urlsafe_b64encode(_canonical(value)).decode()


def settled(native, tools):
    deadline=time.monotonic()+12
    while time.monotonic()<deadline:
        count=sum(event.get('type')=='tool_execution_end' for event in native.event_snapshot())
        if count>=tools and native.observe() is Readiness.SAFE:return
        time.sleep(.05)
    raise RuntimeError('bounded native tool exchange did not settle')


def scenario(config, peer_fd, control_fd):
    expect((os.getuid(),os.getgid())==(165533,165533),'mapped nonroot Supervisor required')
    expect('container_t' not in Path('/proc/self/attr/current').read_text(),'Supervisor must not be relabeled runtime')
    probe()
    journal=Path(config['supervisor_directory'])
    engine=DockerExecAPI('/run/docker.sock')
    peer_lease=EndpointLease(config['peer_path'],owner=165533,group=165532)
    control_lease=EndpointLease(config['control_path'],owner=165533,group=165531)
    result={'supervisor_label':Path('/proc/self/attr/current').read_text().rstrip('\0\n'),
            'supervisor_uid':os.getuid(),'seats':[]}
    with ExitStack() as stack:
        peer=stack.enter_context(closing(socket.socket(fileno=peer_fd)))
        control_listener=stack.enter_context(closing(socket.socket(fileno=control_fd)))
        enable(peer);enable(control_listener);control_listener.settimeout(12)
        self_pidfd=os.pidfd_open(os.getpid(),0);stack.callback(os.close,self_pidfd)
        challenge=secrets.token_hex(32)
        metadata={'version':1,'challenge':challenge,'supervisor_identity':list(_identity(self_pidfd)),
            'mapping_digest':config['mapping_digest'],'room_id':'alpha','room_instance':config['nonce'],
            'run_id':'native-run','seats':[
                {'participant_id':'alice','actor_id':'actor-a','profile_id':'native-pi-v1'},
                {'participant_id':'bob','actor_id':'actor-b','profile_id':'native-pi-v1'}]}
        # This exact owned container is fixed tini -> Hub child; init PID is
        # neither looked up nor used as authority for the actual Hub task.
        print('UAS_NATIVE_PHASE:hub-start',flush=True)
        stream=engine.attach_hub(config['hub_id']);stack.callback(stream.close)
        engine.start_hub(config['hub_id'])
        stream.write(_canonical(metadata)+b'\n',timeout=8)
        control,_=control_listener.accept();stack.callback(control.close)
        enable(control);control.settimeout(8)
        with receive(control) as record:
            expect(record.data==b'HUB1'+bytes.fromhex(challenge),'fixed startup channel correlation')
            expect(record.credentials[1:]==(165531,165531),'actual Hub mapped credentials')
            hub_origin=HeldOrigin(record)
        stack.callback(hub_origin.close)
        control_lease.require();peer_lease.require()
        expect(control.send(RELEASE)==len(RELEASE),'Hub release write')
        with receive(control) as record:
            hub_origin.require(record);ready=json.loads(record.data)
        expect(set(ready)=={'version','kind','controller','room_id','room_instance','observation'}
            and ready['version']==1 and ready['kind']=='HUB_READY'
            and ready['room_id']=='alpha' and ready['room_instance']==config['nonce'],'fixed Hub readiness')
        result['hub_identity']=list(hub_origin.identity)
        result['controller']=ready['controller']
        result['hub_observation']=ready['observation']
        expect(ready['observation']['uid']==65531 and ready['observation']['gid']==65531
               and ready['observation']['parent']>0,'actual Hub namespace/init identity')
        receiver=ReceiverIdentity(65532,65532,'hub-'+config['nonce'],config['mapping_digest'])
        clients=[];launches=[];control_lock=threading.Lock()
        print('UAS_NATIVE_PHASE:two-seat-start',flush=True)
        for index,(participant,actor) in enumerate((('alice','actor-a'),('bob','actor-b'))):
            launch=ExecLaunch(engine,ExecSeat('alpha',config['nonce'],participant,actor,
                'seat-a' if index==0 else 'seat-b',config['workstation_id'],165532,165532),
                peer_lease,journal/(participant+'-launch.json'))
            stack.callback(launch.close)
            launch.launch(peer)
            native=launch.attach_native(journal=journal/(participant+'-native.db'),
                scope={'room_id':'alpha','participant_id':participant,'run_id':'native-run',
                       'generation':1,'context_generation':1},profile_digest=config['profile_digest'])
            seat=AdmissionSeat('alpha',config['nonce'],participant,actor,'native-pi-v1',('peer-traffic',),receiver)
            client=SupervisorAdmission(launch,seat,control,hub_origin=hub_origin,controller=ready['controller'],control_lock=control_lock)
            client.admit(str(index+1)*32,1)
            result['seats'].append({'participant':participant,'actor':actor,'exec_id':launch.exec_id,
                'origin_identity':list(launch.origin.identity),'host_pid_diagnostic':launch.origin.credentials[0],
                'readiness':launch.native_readiness})
            clients.append(client);launches.append(launch)
        expect(launches[0].origin.identity!=launches[1].origin.identity,'two distinct kernel tasks required')
        print('UAS_NATIVE_PHASE:idle',flush=True)
        time.sleep(.5)
        print('UAS_NATIVE_PHASE:native-turns',flush=True)
        for index,launch in enumerate(launches):
            message={'id':'native-'+str(index),'run_id':'native-run','generation':1,'kind':'message',
                     'payload':{'recipient':'bob' if index==0 else 'alice','text':'fixed native peer exchange','parent_id':None}}
            forged={**message,'id':'forged-'+str(index),'actor_id':'attacker'}
            launch.native_receiver.rpc('prompt',message='/fixture-tools '+encoded([message,message,forged]))
            launch.native_receiver.rpc('prompt',message='Run the fixed account-free peer ingress test.')
            settled(launch.native_receiver,3)
            expect(clients[index].status()['installed'],'seat unexpectedly unavailable')
        # Actual Pi duplicate FD -> Python SCM_RIGHTS transfer -> different Node
        # task. Same UID/file description cannot acquire Alice kernel authority.
        print('UAS_NATIVE_PHASE:wrong-process',flush=True)
        packet={'request_id':'a'*32,'envelope':{'id':'wrong-process','run_id':'native-run','generation':1,
            'kind':'message','payload':{'recipient':'bob','text':'must fail','parent_id':None}}}
        launches[0].native_receiver.rpc('prompt',message='/fixture-peer-probe '+encoded({
            'mode':'handoff','packet':encoded(packet)}))
        deadline=time.monotonic()+8
        while clients[0].status()['installed']:
            expect(time.monotonic()<deadline,'wrong-process origin was not fenced')
            time.sleep(.05)
        result['wrong_process_fenced']=True
        expect(clients[1].status()['installed'],'sibling seat affected by wrong-process fence')
        print('UAS_NATIVE_PHASE:stop-workstation',flush=True)
        deadline=time.monotonic()+12
        while any(alive(launch.origin.pidfd) for launch in launches):
            expect(time.monotonic()<deadline,'owned Workstation stop did not exit both exact tasks')
            time.sleep(.05)
        expect(alive(hub_origin.pidfd),'outside Hub died with Workstation')
        result['hub_alive_after_workstation_stop']=True
        print('UAS_NATIVE_PHASE:control-loss',flush=True)
        clients[0].control_lost()
        deadline=time.monotonic()+8
        while alive(hub_origin.pidfd):
            expect(time.monotonic()<deadline,'Hub did not fence control EOF')
            time.sleep(.05)
        result['hub_exited_after_control_eof']=True
        result['native_tool_ends']=[sum(e.get('type')=='tool_execution_end'
            for e in launch.native_receiver.event_snapshot()) for launch in launches]
    return result


def main():
    config_path,peer_fd,control_fd=sys.argv[1:]
    config=json.loads(Path(config_path).read_text())
    expect(Path('/run/uas-vm-fixture').read_text().strip()==config['nonce'],'not owned disposable guest')
    result=scenario(config,int(peer_fd),int(control_fd))
    print('UAS_NATIVE_SUPERVISOR:'+json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':main()
