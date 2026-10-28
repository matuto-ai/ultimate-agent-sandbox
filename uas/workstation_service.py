"""Fixed qualification Hub entrypoint: tini -> this child, outside Workstation.

Only trusted Engine container-start stdin supplies configuration. This is NOT a
Participant-facing command or production launcher; no Engine access exists here.
"""
from contextlib import ExitStack, closing
import json
import hashlib
import os
from pathlib import Path
import socket
import sys
import time

from .kernel_origin import HeldOrigin, OriginDenied, ReceiverIdentity, enable, probe, receive
from .ledger import RoomLedger
from .peer import FixtureParticipant, FixturePeerHub
from .workstation_admission import AdmissionSeat, HubAdmission, _canonical, _unique
from .workstation_exec import EndpointLease
from .workstation_hub import AdmittedHubLoop
from .workstation_peer import AdmittedPeerDispatcher
from .workstation_probe import process_status

CONTROL = '/uas/control/hub.sock'
PEER = '/uas/peer/pi.sock'
STORE = Path('/uas/hub')
RELEASE = b'UAS-HUB-RELEASE-1'


def configuration(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 8192:
        raise OriginDenied('bounded trusted Hub startup required')
    value = json.loads(raw.decode(), object_pairs_hook=_unique)
    if (type(value) is not dict or set(value) - {'forge'} != {'version','challenge','supervisor_identity',
            'mapping_digest','room_id','room_instance','run_id','seats'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['challenge']) is not str or len(value['challenge']) != 64
            or any(c not in '0123456789abcdef' for c in value['challenge'])
            or type(value['supervisor_identity']) is not list
            or len(value['supervisor_identity']) != 2
            or any(type(v) is not int or v < 0 for v in value['supervisor_identity'])
            or type(value['seats']) is not list or len(value['seats']) != 2):
        raise OriginDenied('invalid trusted Hub startup')
    if 'forge' in value:
        from .forge import ForgeBinding
        from .github_read import GitHubProject
        forge = value['forge']
        if (type(forge) is not dict or set(forge) != {'project_id','repository','host'}
                or forge['host'] != 'github.com'):
            raise OriginDenied('invalid trusted Forge binding')
        from .ledger import _token
        _token(forge['project_id']); GitHubProject(forge['repository'], forge['host'])
    receiver = ReceiverIdentity(65532,65532,'hub-'+value['room_instance'],value['mapping_digest'])
    seats=[]
    for seat in value['seats']:
        if type(seat) is not dict or set(seat) not in ({'participant_id','actor_id','profile_id'}, {'participant_id','actor_id','profile_id','capabilities'}):
            raise OriginDenied('invalid fixed Hub seat')
        if 'capabilities' in seat and (type(seat['capabilities']) is not list or 'forge' not in value):
            raise OriginDenied('explicit trusted Forge capability list required')
        seats.append(AdmissionSeat(value['room_id'],value['room_instance'],
            seat['participant_id'],seat['actor_id'],seat['profile_id'],tuple(seat.get('capabilities', ('peer-traffic',))),receiver))
    if len({s.participant_id for s in seats}) != 2 or len({s.actor_id for s in seats}) != 2:
        raise OriginDenied('two distinct native seat bindings required')
    # Existing Hub validates the actual Run token; reject malformed type early.
    from .workstation_admission import _token
    if not _token(value['run_id']):
        raise OriginDenied('invalid trusted initial Run')
    return value,tuple(seats)


def report(ledger):
    data=_canonical(ledger.snapshot())
    if len(data)>1024*1024:
        raise OriginDenied('bounded qualification ledger report exceeded')
    path=STORE/'report.tmp'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.replace(path,STORE/'report.json')


def main():
    if len(sys.argv)!=1 or (os.getuid(),os.getgid())!=(65531,65531):
        raise OriginDenied('fixed unprivileged Hub entrypoint required')
    # Child of the fixed init, never unsupported PID1/parent0 or process scans.
    probe()
    kernel_status=process_status()
    if kernel_status!={'CapEff':'0000000000000000','CapBnd':'0000000000000000','NoNewPrivs':'1','Seccomp':'2'}:
        raise OriginDenied('actual Hub capabilities/NNP/seccomp profile differs')
    metadata,seats=configuration(sys.stdin.buffer.readline(8193))
    mapping={'uid_map':Path('/proc/self/uid_map').read_text(),
             'gid_map':Path('/proc/self/gid_map').read_text(),
             'overflow_uid':int(Path('/proc/sys/kernel/overflowuid').read_text()),
             'overflow_gid':int(Path('/proc/sys/kernel/overflowgid').read_text())}
    if (mapping['overflow_uid']!=65534 or mapping['overflow_gid']!=65534
            or hashlib.sha256(json.dumps(mapping,sort_keys=True).encode()).hexdigest()!=metadata['mapping_digest']):
        raise OriginDenied('actual Hub receiver namespace/overflow mapping differs')
    control_lease=EndpointLease(CONTROL,owner=65533,group=65531)
    peer_lease=EndpointLease(PEER,owner=65533,group=65532)
    with ExitStack() as stack:
        control=stack.enter_context(closing(socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)))
        enable(control);control.settimeout(8);control.connect(CONTROL)
        control_lease.require()
        if control.send(b'HUB1'+bytes.fromhex(metadata['challenge']))!=36:
            raise OriginDenied('incomplete fixed Hub bootstrap')
        with receive(control) as record:
            supervisor=HeldOrigin(record,receiver=ReceiverIdentity(65533,65533,
                'supervisor-'+metadata['room_instance'],metadata['mapping_digest']))
            stack.callback(supervisor.close)
            if (list(supervisor.identity)!=metadata['supervisor_identity'] or record.data!=RELEASE):
                raise OriginDenied('startup Supervisor kernel object not verified')
        admissions=HubAdmission(STORE/'admissions.db',seats=seats,supervisor=supervisor,endpoint=peer_lease)
        stack.callback(admissions.close)
        ledger=RoomLedger(STORE/'room.db',metadata['room_id']);stack.callback(ledger.close)
        hub=FixturePeerHub(ledger)
        hub.configure('native-integration-configure',tuple(FixtureParticipant(s.participant_id,s.actor_id) for s in seats),metadata['run_id'])
        dispatcher=AdmittedPeerDispatcher(admissions,hub)
        if 'forge' in metadata:
            from .forge import ForgeBinding
            dispatcher.attach_host_forge_binding(ForgeBinding(metadata['room_id'], **metadata['forge']))
        ready=_canonical({'version':1,'kind':'HUB_READY','controller':admissions.controller,
                          'room_id':metadata['room_id'],'room_instance':metadata['room_instance'],
                          'observation':{'uid':os.getuid(),'gid':os.getgid(),'parent':os.getppid(),'kernel_status':kernel_status,
                            'label':Path('/proc/self/attr/current').read_text().rstrip('\0\n'),
                            'uid_map':Path('/proc/self/uid_map').read_text(),
                            'gid_map':Path('/proc/self/gid_map').read_text(),
                            'overflow_uid':mapping['overflow_uid'],'overflow_gid':mapping['overflow_gid'],
                            'pid_namespace':os.readlink('/proc/self/ns/pid'),
                            'mount_namespace':os.readlink('/proc/self/ns/mnt')}})
        if control.send(ready)!=len(ready):
            raise OriginDenied('incomplete Hub startup readiness')
        loop=AdmittedHubLoop(admissions,dispatcher,control,
                            context_generations={s.participant_id:1 for s in seats})
        stack.callback(loop.close)
        through=-1;deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            control_lease.require()
            loop.step(.1)
            current=ledger.snapshot()['room_seq']
            if current!=through:
                report(ledger);through=current
        raise OriginDenied('bounded qualification service lifetime expired')


if __name__=='__main__':
    main()
