#!/usr/bin/env python3
"""Explicit artifact-only two-Room proof in this owned no-NIC disposable VM.

Never imported as production admission, never run by ordinary CI. Stock-policy
or required-kernel denial fails; no permissive policy, custom allow or fallback.
"""
import array
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
import traceback

import guest_boundary as boundary

ROOT=boundary.ROOT
PAYLOAD=boundary.PAYLOAD
STORAGE=Path('/mnt/uas-artifacts')
ROOTFS=Path('/var/lib/uas-native-rootfs')
ARCHIVE=Path('/var/lib/uas-native-rootfs.tar')
REQUIRED={'payload','confinement','committed_source','hub_adjudication','native_filter',
          'held_identity','mutation_loss','resource_limits','two_rooms','owned_cleanup','guest_cleanup'}
SCENARIOS=('present','missing','alternates','mutation','loss','malformed','resource','cleanup')
LEVELS={'alpha':'s0:c101,c102','beta':'s0:c103,c104'}
run=boundary.run
expect=boundary.expect


def emit(name,value):
    data=json.dumps({'check':name,'evidence':value},sort_keys=True,separators=(',',':'))
    expect(len(data)<=32768,'bounded artifacts checkpoint')
    print('UAS_ARTIFACT_CHECK:'+data,flush=True)


SETUP_CHILD_PHASES=('alarm','close-parent','drop-groups-gid','drop-uid','socket',
    'bind','listen','group','mode','send')
SETUP_FAILURE=struct.Struct('!4sBI')
SETUP_CREDENTIALS=struct.Struct('3i')
SETUP_MAX_RIGHTS=253


class ListenerSetupFailure(RuntimeError):
    """Bounded typed setup facts only; never raw payload, argv or environment."""
    def __init__(self,document):
        self.document=document
        data=json.dumps(document,sort_keys=True,ensure_ascii=True,separators=(',',':'))
        expect(len(data.encode())<=8192,'bounded listener diagnostics')
        super().__init__('artifact listener setup failure: '+data)


def setup_child_outcome(child,deadline):
    """Only our exact unreaped fork child; never a helper PID or adopted task."""
    while True:
        try:pid,status=os.waitpid(child,os.WNOHANG)
        except InterruptedError:
            if time.monotonic()>=deadline:return {'outcome':'unconfirmed'}
            continue
        except OSError as error:return {'outcome':'wait-error','errno':error.errno}
        if pid==child:
            if os.WIFEXITED(status):return {'outcome':'exit','exit_code':os.WEXITSTATUS(status)}
            if os.WIFSIGNALED(status):return {'outcome':'signal','signal':os.WTERMSIG(status)}
            return {'outcome':'unexpected-status','status':status}
        if pid!=0:return {'outcome':'unexpected-child'}
        if time.monotonic()>=deadline:return {'outcome':'unconfirmed'}
        time.sleep(.01)



def require_setup_reaping():
    """Fixed single-threaded Linux CPython fixture owns all child reaping.

    SIG_DFL alone is insufficient if inherited sigaction has SA_NOCLDWAIT.
    CPython PyOS_setsig uses a fresh sigaction with only SA_ONSTACK, clearing
    that flag: Python/pylifecycle.c v3.14.0 lines3365-3372. Refuse another
    disposition/interpreter; never overwrite a custom handler or repair policy.
    getsignal/return values are Python handler-state checks, not kernel flag
    observations; the successful fresh reset supplies the no-auto-reap premise.
    https://github.com/python/cpython/blob/v3.14.0/Python/pylifecycle.c
    """
    expect(sys.platform=='linux' and sys.implementation.name=='cpython',
        'fixed Linux CPython setup child ownership required')
    expect(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,
        'setup child auto-reaping or custom handler unsupported')
    expect(signal.signal(signal.SIGCHLD,signal.SIG_DFL)==signal.SIG_DFL,
        'setup child disposition changed before reset')


def receive_setup_listener(channel,child,diagnostic):
    """CLOEXEC is an allowed returned bit, not a truncation or success fact.

    SO_PASSCRED is explicitly enabled before fork. Linux may return the input
    MSG_CMSG_CLOEXEC flag: net/socket.c ____sys_recvmsg (v6.18 lines2674/2697).
    Parse installed descriptors FIRST so malformed records cannot leak them.
    """
    installed=[];result=None
    diagnostic.setdefault('cleanup_errors',[])
    raw,ancillary,flags,_=channel.recvmsg(64,
        socket.CMSG_SPACE(SETUP_CREDENTIALS.size)+socket.CMSG_SPACE(SETUP_MAX_RIGHTS*4),
        socket.MSG_CMSG_CLOEXEC)
    diagnostic['transfer']={'raw_bytes':len(raw),'flags':flags,'ancillary_count':len(ancillary),
        'ancillary':[{'level':level,'type':kind,'bytes':len(data)} for level,kind,data in ancillary[:16]]}
    credentials=[];rights=[];invalid=bool(flags & ~socket.MSG_CMSG_CLOEXEC)
    try:
        for level,kind,data in ancillary:
            if level==socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS,getattr(socket,'SCM_PIDFD',4)):
                fds=array.array('i');fds.frombytes(data[:len(data)-len(data)%4])
                installed.extend(fd for fd in fds if fd>=0)
                if kind==socket.SCM_RIGHTS:rights.extend(fds)
                else:invalid=True  # unexpected pidfds are still owned/closed
                invalid|=bool(len(data)%4 or any(fd<0 for fd in fds))
            elif level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS and len(data)==SETUP_CREDENTIALS.size:
                credentials.append(SETUP_CREDENTIALS.unpack(data))
            else:invalid=True
        expect(not invalid and len(credentials)==1 and credentials[0][0]==child,
            'exact child ancillary identity required')
        diagnostic['sender']={'pid_matches_child':True,'uid':credentials[0][1],'gid':credentials[0][2]}
        expect(all(not os.get_inheritable(fd) for fd in installed),'noninheritable received descriptors required')
        if len(raw)==SETUP_FAILURE.size and raw[:4]==b'LSF1':
            _,phase,number=SETUP_FAILURE.unpack(raw)
            expect(not rights and 1<=phase<=len(SETUP_CHILD_PHASES) and 0<=number<=4095,
                'fixed child failure packet required')
            # A failed credential drop may still be root. This is diagnostic
            # only, never a path to accept a root-created listener descriptor.
            expect(credentials[0][1:] in ((0,0),(0,165533),(165533,165533)),
                'unexpected failed child credentials')
            diagnostic['child_failure']={'phase':SETUP_CHILD_PHASES[phase-1],'errno':number or None}
            raise RuntimeError('setup child reported failure')
        expect(raw==b'LISTENER' and len(rights)==1 and len(ancillary)==2
            and credentials[0][1:]==(165533,165533),'one exact Supervisor listener required')
        result=socket.socket(fileno=rights[0]);installed.remove(rights[0])
        expect(result.family==socket.AF_UNIX
            and result.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_SEQPACKET
            and result.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,
            'received descriptor is not the expected listening seqpacket socket')
        accepted=result;result=None;return accepted
    finally:
        if result is not None:
            try:result.close()
            except BaseException as failure:
                diagnostic['cleanup_errors'].append({'phase':'received-listener-close',
                    'errno':getattr(failure,'errno',None)})
        failed=0;errnos=set()
        for descriptor in set(installed):
            try:os.close(descriptor)
            except BaseException as failure:
                failed+=1
                number=getattr(failure,'errno',None)
                errnos.add(number if type(number) is int and 1<=number<=4095 else None)
            # Attempt every other FD; uncertain cleanup remains a failed fact.
        if failed:
            diagnostic['cleanup_errors'].append({'phase':'installed-descriptor-close','count':failed,
                'errnos':sorted(errnos,key=lambda value:-1 if value is None else value)[:8],
                'errno_types_truncated':len(errnos)>8})


def labeled_listener(path,group,level):
    """Root fixture child listens as165533, transfers exact FD, then exits.

    No helper/Supervisor is privileged, no policy installed or authority adopted.
    Every received FD is closed on failure, including final label-reset failure.
    """
    diagnostic={'version':1,'phase':'fixed-profile','cleanup_errors':[]}
    left=right=result=None;child=None;child_done=False;error=None;library=None;attempted=False
    deadline=time.monotonic()+12
    try:
        expect(os.geteuid()==0 and group in (165530,165531) and level in LEVELS.values()
            and path.is_absolute() and path.name==('gate.sock' if group==165530 else 'hub.sock'),
            'fixed root fixture listener profile required')
        diagnostic['phase']='child-reaping-policy';require_setup_reaping()
        diagnostic['phase']='socket-label'
        library=ctypes.CDLL('libselinux.so.1',use_errno=True)
        library.setsockcreatecon.argtypes=[ctypes.c_char_p];library.setsockcreatecon.restype=ctypes.c_int
        context=('system_u:system_r:container_t:'+level).encode()
        attempted=True
        if library.setsockcreatecon(context):raise OSError(ctypes.get_errno(),'stock socket creation label denied')
        diagnostic['phase']='socketpair'
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        left.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        expect(left.getsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED)==1,'setup credentials unavailable')
        diagnostic['phase']='fork';child=os.fork()
        if child==0:
            phase='alarm'
            try:
                signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(10)
                phase='close-parent';left.close();right.settimeout(1)
                phase='drop-groups-gid';os.setgroups([group]);os.setgid(165533)
                phase='drop-uid';os.setuid(165533)
                phase='socket'
                with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
                    phase='bind';listener.bind(str(path))
                    phase='listen';listener.listen(4)
                    phase='group';os.chown(path,-1,group)
                    phase='mode';os.chmod(path,0o620)
                    phase='send'
                    sent=right.sendmsg([b'LISTENER'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[listener.fileno()]))])
                    if sent!=8:raise OSError(errno.EIO,'incomplete fixed listener transfer')
                os._exit(0)
            except BaseException as failure:
                number=getattr(failure,'errno',None)
                if type(number) is not int or not 1<=number<=4095:number=0
                try:right.send(SETUP_FAILURE.pack(b'LSF1',SETUP_CHILD_PHASES.index(phase)+1,number))
                except BaseException:pass
                os._exit(125)
        right.close();right=None;left.settimeout(5)
        diagnostic['phase']='receive'
        result=receive_setup_listener(left,child,diagnostic)
        diagnostic['phase']='listener-identity'
        expect(result.getsockname()==str(path),'received listener path differs')
        node=path.lstat()
        expect(stat.S_ISSOCK(node.st_mode) and node.st_uid==165533 and node.st_gid==group
            and stat.S_IMODE(node.st_mode)==0o620,'fixed socket path ownership differs')
        diagnostic['phase']='child-exit'
        diagnostic['child']=setup_child_outcome(child,deadline)
        child_done=diagnostic['child']['outcome'] in ('exit','signal')
        expect(diagnostic['child']=={'outcome':'exit','exit_code':0},'setup child did not exit successfully')
        diagnostic['phase']='path-label'
        run('chcon','-t','container_file_t','-l',level,str(path),timeout=5)
    except BaseException as failure:
        error=failure
        diagnostic['error_type']=type(failure).__name__;diagnostic['errno']=getattr(failure,'errno',None)
    finally:
        # Reset failure must NEVER bypass descriptor and exact-child cleanup.
        if attempted:
            try:
                if library.setsockcreatecon(None):raise OSError(ctypes.get_errno(),'socket label reset denied')
            except BaseException as failure:
                diagnostic['cleanup_errors'].append({'phase':'socket-label-reset','errno':getattr(failure,'errno',None)})
                if error is None:error=failure
        for value in (left,right):
            if value is not None:
                try:value.close()
                except BaseException as failure:
                    diagnostic['cleanup_errors'].append({'phase':'setup-channel-close','errno':getattr(failure,'errno',None)})
                    if error is None:error=failure
        if child is not None and child>0 and not child_done:
            outcome=setup_child_outcome(child,deadline)
            if outcome['outcome']=='unconfirmed':
                # Exact still-unreaped fork child cannot be PID-reused. This is
                # disposable setup cleanup, never helper cancellation authority.
                try:os.kill(child,signal.SIGKILL)
                except OSError as failure:outcome={'outcome':'kill-error','errno':failure.errno}
                else:outcome=setup_child_outcome(child,time.monotonic()+1)
            diagnostic['child']=outcome
            if outcome['outcome'] not in ('exit','signal'):
                diagnostic['cleanup_errors'].append({'phase':'child-exit-unconfirmed'})
                if error is None:error=RuntimeError('exact setup child exit unconfirmed')
        if error is not None and result is not None:
            try:result.close()
            except BaseException as failure:
                diagnostic['cleanup_errors'].append({'phase':'listener-close','errno':getattr(failure,'errno',None)})
            result=None
    if error is not None:raise ListenerSetupFailure(diagnostic) from None
    return result


def fixture_layout(nonce,template):
    """Pure complete fixed layout/config; no directories, mounts or Git effects.

    Runtime and tests consume this same raw configuration. The normalized
    config.load result is validation only, never serialized back as raw input.
    """
    expect(type(nonce) is str and re.fullmatch(r'[0-9a-f]{32}',nonce),
        'fixed disposable nonce required')
    config=json.loads(json.dumps(template))
    expect(type(config) is dict and type(config.get('rooms')) is list
        and len(config['rooms'])==2 and {item.get('id') for item in config['rooms']}=={'alpha','beta'},
        'exact two-Room fixture template required')
    scratch=Path('/var/lib/uas-artifacts-'+nonce)
    state=scratch/'lifecycle';configuration=scratch/'configuration.json'
    rooms={}
    for index,room in enumerate(('alpha','beta')):
        base=STORAGE/room
        paths={'room':room,'room_root':str(base),
            'room_instance':hashlib.sha256((nonce+room).encode()).hexdigest()[:32],
            'level':LEVELS[room],'state':str(state),'project':301+index*2,
            'hub':str(STORAGE/(room+'-hub')),'gate':str(scratch/(room+'-gate')),
            'control':str(scratch/(room+'-control')),'journal':str(base/'.supervisor'),
            'configuration':str(configuration)}
        for name in ('repo','checkouts','workspace','reference','scratch'):paths[name]=str(base/name)
        rooms[room]=paths
    config['deployment']['state_root']=str(state)
    for item in config['rooms']:
        paths=rooms[item['id']]
        item['state_root']=str(state/item['id'])
        for name in item['project']['roots']:item['project']['roots'][name]=paths[name]
        # Match the Workstation + Project source/target profile, not aggregate
        # whole-Room usage including its outside Hub. Hub retains its separate
        # 128MiB/.25CPU/32pids and64MiB project quota below. Never widen quotas.
        # Preserve template log_bytes: a1MiB capture/report bound is NOT an
        # aggregate Room-log enforcement claim.
        item['resources'].update(cpu=0.5,memory_bytes=256<<20,disk_bytes=256<<20,pids=64)
    return {'scratch_root':str(scratch),'state_root':str(state),
        'configuration_path':str(configuration),'rooms':rooms,'configuration':config}


def storage(nonce,ownership):
    from uas.config import load
    plan=fixture_layout(nonce,json.loads((ROOT/'tests/fixtures/two-rooms.json').read_text()))
    configuration=json.dumps(plan['configuration'])
    load(io.StringIO(configuration))  # Entire real schema/path admission BEFORE effects.
    device=Path('/dev/disk/by-id/virtio-uas-quota').resolve()
    expect(device.is_block_device() and int(run('blockdev','--getsize64',str(device)))==2*1024**3,'exact disposable quota disk')
    run('mkfs.xfs','-f',str(device));STORAGE.mkdir();ownership['mounted']=True
    run('mount','-o','prjquota,nodev,nosuid',str(device),str(STORAGE))
    scratch=Path(plan['scratch_root']);scratch.mkdir(mode=0o711);ownership['scratch']=scratch
    state=Path(plan['state_root']);state.mkdir(mode=0o700);os.chown(state,165533,165533)
    rooms=plan['rooms']
    for room,paths in rooms.items():
        level=paths['level'];base=Path(paths['room_root'])
        base.mkdir(mode=0o755);os.chown(base,165533,165533)
        project=paths['project']
        run('xfs_quota','-x','-c',f'project -s -p {base} {project}',str(STORAGE))
        run('xfs_quota','-x','-c',f'limit -p bhard=262144k ihard=8192 {project}',str(STORAGE))
        for name,mode,uid,gid in [('repo',0o755,165533,165533),('checkouts',0o755,165533,165533),
                ('workspace',0o755,165532,165532),('reference',0o755,165533,165533),('scratch',0o711,165533,165533)]:
            path=Path(paths[name]);path.mkdir(mode=mode);path.chmod(mode);os.chown(path,uid,gid)
        hub=Path(paths['hub']);hub.mkdir(mode=0o700);os.chown(hub,165531,165531)
        run('xfs_quota','-x','-c',f'project -s -p {hub} {project+1}',str(STORAGE))
        run('xfs_quota','-x','-c',f'limit -p bhard=65536k ihard=2048 {project+1}',str(STORAGE))
        for name,group,mode in [('gate',165530,0o710),('control',165531,0o710),('journal',165533,0o700)]:
            path=Path(paths[name]);path.mkdir(mode=mode);path.chmod(mode);os.chown(path,165533,group)
            if name!='journal':run('chcon','-t','container_file_t','-l',level,str(path))
        run('chcon','-R','-t','container_file_t','-l',level,str(base),str(hub))
    sentinel=Path(rooms['alpha']['scratch'])/'cross-room-sentinel'
    sentinel.write_bytes(b'fixed-no-secret-marker\n');sentinel.chmod(0o444);os.chown(sentinel,165533,165530)
    run('chcon','-t','container_file_t','-l',LEVELS['alpha'],str(sentinel))
    path=Path(plan['configuration_path']);path.write_text(configuration);path.chmod(0o444)
    return rooms


def create(image,name,paths,nonce,*,hub=False,foreign=None):
    user='65531:65531' if hub else '65532:65532'
    args=['docker','create','--name',name,'--label','uas.artifact-owner='+nonce,'--read-only','--network','none',
        '--user',user,'--cap-drop','ALL','--security-opt','no-new-privileges=true','--security-opt','label=level:'+paths['level'],
        '--memory','128m' if hub else '256m','--memory-swap','128m' if hub else '256m','--cpus','0.25' if hub else '0.5',
        '--pids-limit','32' if hub else '64','--env','PYTHONPATH=/opt/uas:/opt/uas/tests/vm','--env','PYTHONDONTWRITEBYTECODE=1',
        '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=8m,mode=0700,uid='+user.split(':')[0]+',gid='+user.split(':')[1],
        '--entrypoint','/opt/uas/bin/tini']
    if hub:
        args+=['--interactive','--mount','type=bind,src='+paths['control']+',dst=/uas/control,readonly',
            '--mount','type=bind,src='+paths['hub']+',dst=/uas/hub']
        argv=['/usr/bin/python3','/opt/uas/tests/vm/artifact_hub.py']
    else:
        args+=['--mount','type=bind,src='+paths['gate']+',dst=/uas/gate,readonly',
            '--mount','type=bind,src='+paths['scratch']+',dst=/uas/gate-targets,readonly',
            '--mount','type=bind,src='+paths['repo']+',dst=/uas/project',
            '--env','LD_PRELOAD=/nonexistent/uas-artifact-loader-poison.so']
        if foreign:args+=['--mount','type=bind,src='+foreign+',dst=/uas/foreign,readonly']
        argv=['/usr/bin/python3','/opt/uas/tests/vm/artifact_room_probe.py','idle']
    return run(*args,image,'--',*argv).strip()


def inspect(identifier):return json.loads(run('docker','inspect',identifier))[0]


def quota_mount_identity(document,device):
    """Exact mounted filesystem root/device, not a literal XFS assertion."""
    expect(type(document) is str and len(document.encode())<=65536,'bounded mount evidence')
    matches=[]
    for line in document.splitlines():
        pieces=line.split(' - ')
        if len(pieces)!=2:continue
        left,right=pieces[0].split(),pieces[1].split()
        if len(left)>=6 and left[4]==str(STORAGE):matches.append((left,right))
    expect(len(matches)==1,'one exact artifact quota mount required')
    left,right=matches[0]
    expect(len(right)>=3 and left[3]=='/' and right[0]=='xfs'
        and left[2]==str(os.major(device))+':'+str(os.minor(device)),
        'actual XFS root mount/device differs')
    return {'filesystem':right[0],'device':device,'mountpoint':left[4],'filesystem_root':left[3]}


def quota_state(document,kind):
    expect(type(document) is str and len(document.encode())<8192,'bounded quota state')
    headers=[line for line in document.splitlines() if ' quota state on ' in line]
    expect(len(headers)==1 and headers[0].startswith(kind+' quota state on '+str(STORAGE)+' ('),
        'exact mounted quota state required')
    accounting=re.findall(r'^\s*Accounting:\s+(ON|OFF)\s*$',document,re.M)
    enforcement=re.findall(r'^\s*Enforcement:\s+(ON|OFF)\s*$',document,re.M)
    expect(len(accounting)==len(enforcement)==1,'one actual quota accounting/enforcement state')
    return {'accounting':accounting[0]=='ON','enforcement':enforcement[0]=='ON'}


def quota_hard_limit(document,project):
    expect(type(document) is str and len(document.encode())<8192,'bounded quota limit report')
    rows=[line.split() for line in document.splitlines() if line.split() and line.split()[0]=='#'+str(project)]
    expect(len(rows)==1 and len(rows[0])>=4 and all(value.isdigit() for value in rows[0][1:4]),
        'one actual numeric project limit required')
    used,soft,hard=map(int,rows[0][1:4])
    expect(soft==0 and hard==262144 and used<=hard-1024,'exact project hardlimit and positive-allocation headroom required')
    return {'used_bytes':used*1024,'soft_limit_bytes':soft*1024,'hard_limit_bytes':hard*1024}


def quota_facts(room):
    from artifact_diagnostics import captured, FixtureCommandFailure, stream_facts
    expect(room in ('alpha','beta'),'fixed quota Room required')
    descriptor=os.open(STORAGE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        node=os.fstat(descriptor)
        expect(node.st_uid==0,'root-owned fixed quota mount required')
        with open('/proc/self/mountinfo','rb') as stream:raw=stream.read(65537)
        expect(len(raw)<=65536,'mount evidence output bound')
        mount=quota_mount_identity(raw.decode(),node.st_dev)
        def observe(phase,command,parse):
            result=captured(phase,['xfs_quota','-x','-c',command,str(STORAGE)],output_limit=8192,
                stdin=subprocess.DEVNULL,capture_output=True,timeout=5,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C'})
            try:return parse(result.stdout.decode('utf-8'))
            except (AssertionError,UnicodeError,ValueError):
                raise FixtureCommandFailure(phase,'schema',returncode=result.returncode,
                    stdout=stream_facts(result.stdout),stderr=stream_facts(result.stderr)) from None
        states={kind:observe('quota-state-'+kind.lower(),'state -'+flag,lambda value:quota_state(value,kind))
            for kind,flag in (('User','u'),('Group','g'),('Project','p'))}
        expect(states['Project']=={'accounting':True,'enforcement':True}
            and not states['User']['enforcement'] and not states['Group']['enforcement'],
            'project-only quota enforcement required for attribution')
        project=301 if room=='alpha' else 303
        limits=observe('quota-hard-limits','report -p -b -n -N',lambda value:quota_hard_limit(value,project))
        current=os.stat(STORAGE,follow_symlinks=False)
        expect((current.st_dev,current.st_ino)==(node.st_dev,node.st_ino),'quota mount identity changed')
        facts={'version':1,'room':room,'project_id':project,'device':node.st_dev,
            'hard_limit_bytes':limits['hard_limit_bytes'],'accounting':True,'enforcement':True,
            'filesystem':mount['filesystem'],'user_enforcement':False,'group_enforcement':False}
        return facts,{'mount':mount,'states':states,'limits':limits,'kernel_release':os.uname().release}
    finally:os.close(descriptor)


def publish_boot_marker(nonce):
    """Read access only after root-only assembly; retain exact FD for reset."""
    expect(os.geteuid()==0 and type(nonce) is str and len(nonce)==32
        and all(c in '0123456789abcdef' for c in nonce),'exact root boot marker publication')
    descriptor=os.open('/run/uas-vm-fixture',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    attempted=False
    try:
        node=os.fstat(descriptor)
        expect(stat.S_ISREG(node.st_mode) and node.st_uid==0 and node.st_nlink==1
            and stat.S_IMODE(node.st_mode)==0o600,'root-only ordinary boot marker required')
        expect(os.read(descriptor,65).decode().strip()==nonce,'exact disposable boot marker')
        # This nonce is an accidental-use guard, not a secret or authority.
        attempted=True
        os.fchmod(descriptor,0o444)
        return descriptor
    except BaseException:
        try:
            if attempted:os.fchmod(descriptor,0o600)
        finally:os.close(descriptor)
        raise


def reset_boot_marker(descriptor):
    try:os.fchmod(descriptor,0o600)
    finally:os.close(descriptor)


def scenario(nonce,manifest,checks):
    sys.path[:0]=[str(ROOT),str(ROOT/'tests/vm')]
    from artifact_diagnostics import (captured, require_file_result, decoded_json,
        FixtureCommandFailure, file_facts)
    from native_rootfs import build_rootfs
    from guest_workstation import import_image,engine_profile,NATIVE_PACKAGE_PROFILE
    owned=[];listeners=[];image=None;ownership={};children=[];marker_descriptor=None
    try:
        # Host trusted Git is signature-checked, offline, installed only in VM.
        run('dnf','-y','--setopt=reposdir=/run/uas-repositories','--disable-repo=*','--enable-repo=uas-offline',
            '--setopt=localpkg_gpgcheck=True','--setopt=install_weak_deps=False','install','git-core','util-linux',timeout=120)
        rootfs_manifest=ROOTFS.with_name(ROOTFS.name+'.manifest.json')
        expect(not ROOTFS.exists() and not ROOTFS.is_symlink() and not rootfs_manifest.exists()
            and not ARCHIVE.exists() and not ARCHIVE.is_symlink(),'fresh owned rootfs/archive paths required')
        ownership['rootfs']=True
        rootfs=build_rootfs(nonce,manifest,ROOTFS,run=run)
        boundary.start_engine();engine=engine_profile(manifest)
        ownership['archive']=True
        with tarfile.open(ARCHIVE,'x',format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(ROOTFS.iterdir()):archive.add(path,arcname=path.name,recursive=True)
        image=import_image(ARCHIVE)
        checks['payload']={'status':'passed','profile':'artifacts-v1-source','image':image,
            'rootfs_manifest_sha256':rootfs['rootfs_manifest_sha256'],'helper_sha256':manifest['native_runtime']['helper_sha256'],
            'engine':engine,'trusted_git_sha256':hashlib.sha256(Path('/usr/bin/git').read_bytes()).hexdigest(),
            'trusted_prlimit_sha256':hashlib.sha256(Path('/usr/bin/prlimit').read_bytes()).hexdigest(),
            'native_pi_qualification_reused':False,'production_enabled':False};emit('payload',checks['payload'])
        rooms=storage(nonce,ownership);containers={};quota_exhaustion={};quota_observations={}
        for room in rooms:
            facts,before=quota_facts(room)
            print('UAS_ARTIFACT_QUOTA_PREFLIGHT:'+json.dumps({'room':room,'facts':facts,'observations':before},sort_keys=True),flush=True)
            result=captured('quota-'+room,[sys.executable,str(ROOT/'tests/vm/artifact_quota_probe.py'),room],output_limit=8192,
                user=165533,group=165533,extra_groups=[],input=json.dumps(facts,sort_keys=True).encode(),capture_output=True,timeout=20,
                env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
            quota_exhaustion[room]=decoded_json('quota-'+room,result)
            after_facts,after=quota_facts(room)
            expect(after_facts==facts and quota_exhaustion[room]['quota_facts']==facts
                and quota_exhaustion[room]['project_hard_quota_enforced'] is True,
                'missing exact independently observed project quota enforcement')
            quota_observations[room]={'before':before,'after':after}
            # Preserve accepted quota facts even if a later setup phase fails.
            quota_checkpoint=json.dumps({'version':1,'room':room,'result':quota_exhaustion[room]},
                sort_keys=True,ensure_ascii=True,separators=(',',':'))
            if len(quota_checkpoint.encode())>16384:
                quota_checkpoint=json.dumps({'version':1,'room':room,'checkpoint':'overbound',
                    'accepted_child_bytes':len(result.stdout)},sort_keys=True)
            print('UAS_ARTIFACT_QUOTA_RESULT:'+quota_checkpoint,flush=True)
        rooms['beta']['foreign_scratch']=rooms['alpha']['scratch']
        for room,paths in rooms.items():
            listener=labeled_listener(Path(paths['gate'])/'gate.sock',165530,paths['level'])
            listeners.append(listener)  # Own it before the second creation can fail.
            control=labeled_listener(Path(paths['control'])/'hub.sock',165531,paths['level'])
            listeners.append(control)
            paths['listener_fds']=(listener.fileno(),control.fileno())
            ws=create(image,'uas-artifact-'+nonce+'-'+room,paths,nonce,foreign=rooms['alpha']['scratch'] if room=='beta' else None);owned.append(ws);run('docker','start',ws)
            hub=create(image,'uas-artifact-'+nonce+'-'+room+'-hub',paths,nonce,hub=True);owned.append(hub)
            containers[room]={'workstation':ws,'hub':hub}
        cross=json.loads(run('docker','exec','--user','65532:65532',containers['beta']['workstation'],
            '/usr/bin/python3','/opt/uas/tests/vm/artifact_room_probe.py','cross-room'))
        expect(cross.get('denied') is True and cross.get('errno') in (errno.EACCES,errno.EPERM),'actual cross-Room MCS access not denied')
        # build_rootfs/guest_guard above require0600. Quota probes only stat the
        # marker; publish its nonsecret contents only for mapped Supervisors.
        marker_descriptor=publish_boot_marker(nonce)
        reports={};supervisors={}
        for room,paths in rooms.items():
            facts=json.loads(run('docker','exec','--user','65532:65532',containers[room]['workstation'],
                '/usr/bin/python3','/opt/uas/tests/vm/artifact_room_probe.py','facts'))
            mapping={key:facts[key] for key in ('uid_map','gid_map','overflow_uid','overflow_gid')}
            mapping_digest=hashlib.sha256(json.dumps(mapping,sort_keys=True).encode()).hexdigest()
            profile=hashlib.sha256(json.dumps({'source':'artifacts-v1-source','image':image,'level':paths['level'],
                'mapping':mapping_digest,'helper_sha256':manifest['native_runtime']['helper_sha256'],
                'disk_bytes':256<<20,'helper_reservation':32<<20},sort_keys=True).encode()).hexdigest()
            config={**{k:v for k,v in paths.items() if k!='listener_fds'},'nonce':nonce,
                'workstation_id':containers[room]['workstation'],'hub_id':containers[room]['hub'],
                'image_digest':image.removeprefix('sha256:'),'mapping_digest':mapping_digest,'profile_digest':profile,
                'helper_sha256':manifest['native_runtime']['helper_sha256'],
                'scenarios':list(SCENARIOS if room=='alpha' else ('present','missing'))}
            file=Path(paths['journal'])/'config.json';file.write_text(json.dumps(config));os.chown(file,165533,165533);file.chmod(0o400)
            output=Path(paths['journal'])/'stdout';errors=Path(paths['journal'])/'stderr'
            with output.open('xb') as stdout,errors.open('xb') as stderr:
                try:
                    child=subprocess.Popen([sys.executable,str(ROOT/'tests/vm/artifact_supervisor.py'),str(file),
                        *map(str,paths['listener_fds'])],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
                        user=165533,group=165533,extra_groups=[165530,os.stat('/run/docker.sock').st_gid],
                        pass_fds=paths['listener_fds'],env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(ROOT)+':'+str(ROOT/'tests/vm'),
                            'PYTHONDONTWRITEBYTECODE':'1','HOME':paths['journal']})
                except OSError as error:
                    raise FixtureCommandFailure('supervisor-'+room,'launch',errno=error.errno) from None
                children.append(child);deadline=time.monotonic()+300
                while child.poll() is None:
                    outcome='timeout' if time.monotonic()>=deadline else (
                        'output' if max(output.stat().st_size,errors.stat().st_size)>1<<20 else None)
                    if outcome:
                        raise FixtureCommandFailure('supervisor-'+room,outcome,
                            stdout=file_facts(output),stderr=file_facts(errors))
                    time.sleep(.2)
            require_file_result('supervisor-'+room,child.returncode,output,errors,output_limit=1<<20)
            lines=[line.split(':',1)[1] for line in output.read_text().splitlines() if line.startswith('UAS_ARTIFACT_SUPERVISOR:')]
            expect(len(lines)==1,'exact Supervisor result required');result=json.loads(lines[0]);supervisors[room]=result
            report_path=Path(paths['hub'])/'report.json';raw=report_path.read_bytes()
            expect(len(raw)==result['terminal']['report_bytes'] and hashlib.sha256(raw).hexdigest()==result['terminal']['report_digest'],'authenticated exact Hub report bytes')
            report=json.loads(raw);reports[room]=report
            expect(report['room_id']==room and report['room_instance']==paths['room_instance'],'room report exactscope')
            expected={'present':'passed','missing':'failed',**{name:'error' for name in SCENARIOS[2:]}}
            for item in report['results']:
                expect(item['outcome']=='evaluation' and item['exact_retry_equal'] is True,'real once-only Hub evaluation')
                expect(item['evaluation']['result']['verdict']==expected[item['scenario']],'Hub outcome differs for '+item['scenario'])
            if room=='alpha':
                # End only A's already-owned Workstation. B must retain its exact
                # running container and complete fresh real-helper evaluations.
                sibling_before=inspect(containers['beta']['workstation'])
                run('docker','stop','--time','3',containers['alpha']['workstation'])
                sibling_after=inspect(containers['beta']['workstation'])
                expect(sibling_after['State']['Running'] and sibling_after['Id']==sibling_before['Id'],'sibling changed after RoomA stop')
        alpha=supervisors['alpha'];beta=supervisors['beta']
        expect(alpha['source']['head_sha']!=beta['source']['head_sha'] or rooms['alpha']['repo']!=rooms['beta']['repo'],'distinct owned repositories')
        expect(alpha['actual_hub']['pid_namespace']!=beta['actual_hub']['pid_namespace'],'two distinct Hub namespaces')
        all_admission=[record for item in supervisors.values() for record in item['admission_observations']]
        expect(all_admission and all(a['outer_socket_creation'] for a in all_admission),'actual normal Workstation network-syscall baseline')
        checks['confinement']={'status':'passed','admissions':len(all_admission),'dedicated_uid':65530,'mapped_uid':165530,
            'actual_hub_namespaces':{room:value['actual_hub']['pid_namespace'] for room,value in supervisors.items()},
            'readonly_target_checked_inside_static_bootstrap':True,'stock_policy_only':True}
        checks['committed_source']={'status':'passed','heads':{r:v['source']['head_sha'] for r,v in supervisors.items()},
            'poisoned_configuration_executed':any(v['source_config_executed'] for v in supervisors.values()),
            'dirty_readme_empty_but_committed_target_nonempty':True,'packed_git_objects':True,'alternates_rejected':True}
        probes={item['probe']:item for item in alpha['native_probes']}
        expect(set(probes)==set('NPFETMRLWCOHI') and all(p['actual_exit'] for p in probes.values()),'complete actual confinement/identity/resource attack set')
        checks['native_filter']={'status':'passed','test_payload_distinct_from_evaluator':True,
            'probes':{k:v for k,v in probes.items() if k in 'NPFETMRLWO'},'normal_workstation_socket_positive':True}
        checks['held_identity']={'status':'passed','wrong_process':probes['I'],
            'actual_direct_helper_records':sum(len(v['launches']) for v in supervisors.values())}
        checks['hub_adjudication']={'status':'passed','results':{room:[{'scenario':item['scenario'],
            'verdict':item['evaluation']['result']['verdict']} for item in report['results']] for room,report in reports.items()},
            'run_seed':'trusted-fixture-not-Run-admission','run_advanced':False,'production_enabled':False}
        checks['mutation_loss']={'status':'passed','faults':alpha['injected_faults']+reports['alpha']['injected_faults'],
            'malformed_request_not_fabricated_helper_output':True}
        state=run('xfs_quota','-x','-c','state -p',str(STORAGE))
        expect('Accounting: ON' in state and 'Enforcement: ON' in state,'actual project quota enforcement')
        quota={flag:run('xfs_quota','-x','-c','report -p -'+flag+' -n -N',str(STORAGE)) for flag in ('b','i')}
        for project,blocks,inodes in ((301,262144,8192),(302,65536,2048),(303,262144,8192),(304,65536,2048)):
            for flag,bound in (('b',blocks),('i',inodes)):
                rows=[line.split() for line in quota[flag].splitlines() if line.split() and line.split()[0]=='#'+str(project)]
                expect(len(rows)==1 and rows[0][3]==str(bound),'actual Room hard quota differs')
        checks['resource_limits']={'status':'passed','cpu':probes['C'],'wall':probes['H'],
            'memory_allocation_syscall_denied':probes['M'],'rlimit_as_checked_by_static_evaluator':128<<20,
            'room_disk_bytes':256<<20,'reservation_bytes':32<<20,'quota_reports':quota,'actual_quota_exhaustion':quota_exhaustion,
            'independent_quota_observations':quota_observations,
            'per_helper_cgroup_claimed':False,'target_host_release_defaults_measured':False}
        checks['two_rooms']={'status':'passed','distinct_hub_namespaces':True,'sibling_survived_A_stop_and_completed_real_gate':True,
            'different_MCS':LEVELS,'actual_cross_room_MCS_read_denial':cross}
        # All successful/failed-but-credible evaluations cleaned their exact
        # targets. Mutation/ownership replacement remain quarantined, not erased
        # from immutable results when final whole-VM teardown occurs.
        for room,report in reports.items():
            for item in report['results']:
                row=item['evaluation'];operational=row['operational']
                if item['scenario'] in ('present','missing'):expect(operational['cleanup'] is True,'credible evaluation not cleaned')
                if item['scenario'] in ('mutation','cleanup'):expect(operational['cleanup'] is False and operational['quarantine_ref'],'missing failure quarantine')
        checks['owned_cleanup']={'status':'passed','credible_targets_removed':True,
            'mutated_or_replaced_targets_quarantined':True,'immutable_results_not_rewritten':True}
        for name,value in checks.items():emit(name,value)
        return checks
    finally:
        original=sys.exc_info()[1];failures=[]
        if isinstance(original,ListenerSetupFailure):
            # Preserve unresolved setup ownership/reset facts. Later whole-VM
            # teardown does not prove a missing child exit or rewrite failure.
            failures.extend({'resource':'listener-setup','error':'ListenerSetupFailure','detail':dict(item)}
                for item in original.document['cleanup_errors'])
        def cleanup(name,action):
            try:action()
            except Exception as error:failures.append({'resource':name,'error':type(error).__name__})
        for child in children:
            def stop_child():
                if child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
            cleanup('owned-Supervisor',stop_child)
        if marker_descriptor is not None:
            cleanup('boot-marker-reset',lambda:reset_boot_marker(marker_descriptor))
        for listener in listeners:cleanup('listener',listener.close)
        for identifier in reversed(owned):
            def remove():
                expect(inspect(identifier)['Config']['Labels'].get('uas.artifact-owner')==nonce,'VM cleanup ownership changed')
                run('docker','rm','--force',identifier)
            cleanup('owned-container',remove)
        if ownership.get('mounted'):cleanup('quota-mount',lambda:run('umount',str(STORAGE)))
        if image:cleanup('owned-image',lambda:run('docker','image','rm',image))
        if ownership.get('rootfs'):
            if ROOTFS.exists():cleanup('owned-rootfs',lambda:shutil.rmtree(ROOTFS))
            manifest_path=ROOTFS.with_name(ROOTFS.name+'.manifest.json')
            if manifest_path.exists():cleanup('owned-rootfs-manifest',manifest_path.unlink)
        if ownership.get('archive') and ARCHIVE.exists():cleanup('owned-archive',lambda:ARCHIVE.unlink())
        if ownership.get('scratch'):cleanup('owned-scratch',lambda:shutil.rmtree(ownership['scratch']))
        checks['guest_cleanup']={'status':'passed' if not failures else 'failed','errors':failures,
            'scope':'owned-disposable-VM-resources-not-helper-result-rewrite'};emit('guest_cleanup',checks['guest_cleanup'])
        if failures and original is None:raise RuntimeError('owned VM cleanup incomplete')


def main():
    nonce,digest=sys.argv[1:];checks={};failure=None
    try:
        from guest_workstation import NATIVE_PACKAGE_PROFILE
        boundary.install(nonce,digest,exact_roots=NATIVE_PACKAGE_PROFILE,defer_engine_start=True)
        manifest=boundary.verify_payload(nonce,digest)
        expect(manifest.get('profile')=='artifacts-v1-source','explicit artifacts payload required')
        scenario(nonce,manifest,checks)
        expect(set(checks)==REQUIRED and all(x['status']=='passed' for x in checks.values()),'incomplete artifacts qualification')
    except Exception as error:
        print(traceback.format_exc()[-16384:],flush=True)
        failure={'error_type':type(error).__name__,'completed':sorted(checks)}
        for name in REQUIRED-checks.keys():checks[name]={'status':'not-run'}
    report={'version':1,'nonce':nonce,'checks':checks,'production_enabled':False}
    if failure:report['failure']=failure
    with open('/dev/ttyS0','w') as serial:
        serial.write('\nUAS_ARTIFACT_REPORT:'+nonce+':'+json.dumps(report,sort_keys=True)+'\n');serial.flush()


if __name__=='__main__':main()
