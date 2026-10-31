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
import select
import sys
import time

from .kernel_origin import HeldOrigin, OriginDenied, ReceiverIdentity, alive, enable, probe, receive
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


def configuration(raw, *, persistent=False, progress=None):
    if type(persistent) is not bool:
        raise OriginDenied('fixed Hub lifetime selection required')
    if type(raw) is not bytes or not 0 < len(raw) <= 8192:
        raise OriginDenied('bounded trusted Hub startup required')
    value = json.loads(raw.decode(), object_pairs_hook=_unique)
    if progress is not None: progress('config-decoded')
    fields = {'version','challenge','supervisor_identity','mapping_digest','room_id','room_instance','seats'}
    fields.add('profile' if persistent else 'run_id')
    if (type(value) is not dict or set(value) - {'forge','library'} != fields
            or type(value['version']) is not int or value['version'] != 1
            or type(value['challenge']) is not str or len(value['challenge']) != 64
            or any(c not in '0123456789abcdef' for c in value['challenge'])
            or type(value['supervisor_identity']) is not list
            or len(value['supervisor_identity']) != 2
            or any(type(v) is not int or v < 0 for v in value['supervisor_identity'])
            or type(value['seats']) is not list or len(value['seats']) != 2):
        raise OriginDenied('invalid trusted Hub startup')
    if 'forge' in value:
        if progress is not None: progress('forge-import')
        from .github_read import GitHubProject
        if progress is not None: progress('forge-imported')
        forge = value['forge']
        if (type(forge) is not dict or set(forge) != {'project_id','repository','host'}
                or forge['host'] != 'github.com'):
            raise OriginDenied('invalid trusted Forge binding')
        from .ledger import _token
        _token(forge['project_id']); GitHubProject(forge['repository'], forge['host'])
    if 'library' in value:
        if progress is not None: progress('library-import')
        from .library_binding import project_binding
        if progress is not None: progress('library-imported')
        selected = value['library']
        if (not persistent or type(selected) is not dict
                or set(selected) != {'project','source_identity'}):
            raise OriginDenied('invalid trusted Library binding')
        project_binding(selected['project'],source_identity=selected['source_identity'])
        if 'forge' in value and (selected['project']['id'] != value['forge']['project_id']
                or selected['project']['repository'] != value['forge']['repository']):
            raise OriginDenied('trusted Project bindings disagree')
    if progress is not None: progress('binding-validated')
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
    if persistent:
        if value['profile'] != 'local-hub-v1':
            raise OriginDenied('fixed persistent Hub profile required')
    else:
        # Qualification alone has a selected initial Run. Local startup has none.
        from .workstation_admission import _token
        if not _token(value['run_id']):
            raise OriginDenied('invalid trusted initial Run')
    if progress is not None: progress('seats-validated')
    return value,tuple(seats)


def report(ledger, *, summary=False):
    snapshot=ledger.snapshot()
    if summary:
        # Bounded observation only: do not copy unbounded Room history or invent
        # an idle Run. The canonical ledger remains the source of actual state.
        snapshot={'version':1, 'room_seq':snapshot['room_seq'],
                  'state_digest':hashlib.sha256(_canonical(snapshot['state'])).hexdigest(),
                  'configured':'peer_traffic' in snapshot['state']}
    data=_canonical(snapshot)
    if len(data)>1024*1024:
        raise OriginDenied('bounded qualification ledger report exceeded')
    path=STORE/'report.tmp'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.replace(path,STORE/'report.json')


def initialize_hub(hub, seats, metadata, *, persistent):
    if not persistent:
        hub.configure('native-integration-configure',
            tuple(FixtureParticipant(s.participant_id,s.actor_id) for s in seats),metadata['run_id'])


def serve_loop(loop, ledger, control_lease, *, persistent=False, library_client=None):
    through=-1
    deadline=None if persistent else time.monotonic()+180
    while deadline is None or time.monotonic()<deadline:
        control_lease.require()
        loop.step(.1)  # Existing loop fences control EOF and owner pidfd exit.
        if library_client is not None: library_client.poll()
        current=ledger.snapshot()['room_seq']
        if current!=through:
            report(ledger, summary=persistent);through=current
    raise OriginDenied('bounded qualification service lifetime expired')


def run_service(*, persistent=False, progress=None):
    if type(persistent) is not bool:
        raise OriginDenied('fixed Hub lifetime selection required')
    if len(sys.argv)!=1 or (os.getuid(),os.getgid())!=(65531,65531):
        raise OriginDenied('fixed unprivileged Hub entrypoint required')
    if progress is not None: progress('entrypoint-validated')
    # Only this Room ledger directory is shared with the trusted host owner.
    # Setgid directory + group-readable/writable SQLite WAL files, never world
    # access or a Supervisor-private-store mount into Hub.
    os.umask(0o007)
    # Child of the fixed init, never unsupported PID1/parent0 or process scans.
    if progress is not None: progress('probe-start')
    probe()
    if progress is not None: progress('probe-done')
    kernel_status=process_status()
    if kernel_status!={'CapEff':'0000000000000000','CapBnd':'0000000000000000','NoNewPrivs':'1','Seccomp':'2'}:
        raise OriginDenied('actual Hub capabilities/NNP/seccomp profile differs')
    if progress is not None: progress('metadata-wait')
    raw_metadata=sys.stdin.buffer.readline(8193)
    if progress is not None: progress('metadata-read')
    metadata,seats=configuration(raw_metadata, persistent=persistent, progress=progress)
    if progress is not None: progress('metadata-parsed')
    mapping={'uid_map':Path('/proc/self/uid_map').read_text(),
             'gid_map':Path('/proc/self/gid_map').read_text(),
             'overflow_uid':int(Path('/proc/sys/kernel/overflowuid').read_text()),
             'overflow_gid':int(Path('/proc/sys/kernel/overflowgid').read_text())}
    if (mapping['overflow_uid']!=65534 or mapping['overflow_gid']!=65534
            or hashlib.sha256(json.dumps(mapping,sort_keys=True).encode()).hexdigest()!=metadata['mapping_digest']):
        raise OriginDenied('actual Hub receiver namespace/overflow mapping differs')
    if progress is not None: progress('mapping-validated')
    control_lease=EndpointLease(CONTROL,owner=65533,group=65531)
    peer_lease=EndpointLease(PEER,owner=65533,group=65532)
    if progress is not None: progress('paths-validated')
    with ExitStack() as stack:
        control=stack.enter_context(closing(socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)))
        enable(control);control.settimeout(8)
        if progress is not None: progress('control-connect')
        control.connect(CONTROL)
        if progress is not None: progress('control-connected')
        control_lease.require()
        if control.send(b'HUB1'+bytes.fromhex(metadata['challenge']))!=36:
            raise OriginDenied('incomplete fixed Hub bootstrap')
        with receive(control) as record:
            supervisor=HeldOrigin(record,receiver=ReceiverIdentity(65533,65533,
                'supervisor-'+metadata['room_instance'],metadata['mapping_digest']))
            stack.callback(supervisor.close)
            if (list(supervisor.identity)!=metadata['supervisor_identity'] or record.data!=RELEASE):
                raise OriginDenied('startup Supervisor kernel object not verified')
        library_channel = None
        if 'library' in metadata:
            from .local_library_transport import offer_handoff
            library_channel=offer_handoff(control);stack.callback(library_channel.close)
        admissions=HubAdmission(STORE/'admissions.db',seats=seats,supervisor=supervisor,endpoint=peer_lease)
        stack.callback(admissions.close)
        ledger=RoomLedger(STORE/'room.db',metadata['room_id']);stack.callback(ledger.close)
        hub=FixturePeerHub(ledger)
        initialize_hub(hub,seats,metadata,persistent=persistent)
        dispatcher=AdmittedPeerDispatcher(admissions,hub)
        if 'forge' in metadata:
            from .forge import ForgeBinding
            dispatcher.attach_host_forge_binding(ForgeBinding(metadata['room_id'], **metadata['forge']))
        library_client = None
        if library_channel is not None:
            from .local_library_transport import Client
            from .library_hub import LibraryHub, DrainReports
            from .library import project_binding
            binding=metadata['library']
            project=project_binding(binding['project'],source_identity=binding['source_identity'])
            reports=DrainReports(ledger,room_id=metadata['room_id'],
                project_identity=project['project_identity'],
                authenticate=lambda: not supervisor.revoked and alive(supervisor.pidfd))
            library_client=Client(library_channel,supervisor,project,reports=reports,
                control_current=lambda: not select.select([control],[],[],0)[0])
            dispatcher.attach_library(LibraryHub(ledger,room_id=metadata['room_id'],
                project=binding['project'],source_identity=binding['source_identity'],contact=library_client))
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
                            context_generations={s.participant_id:1 for s in seats},
                            canonical_context_generations=True)
        stack.callback(loop.close)
        serve_loop(loop,ledger,control_lease,persistent=persistent,library_client=library_client)


def main():
    return run_service()


if __name__=='__main__':
    main()
