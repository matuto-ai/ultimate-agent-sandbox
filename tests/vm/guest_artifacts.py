#!/usr/bin/env python3
"""Explicit artifact-only two-Room proof in this owned no-NIC disposable VM.

Never imported as production admission, never run by ordinary CI. Stock-policy
or required-kernel denial fails; no permissive policy, custom allow or fallback.
"""
import array
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
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


def labeled_listener(path,group,level):
    """Root fixture setup child actually listens as165533 before FD transfer.

    Chown alone would leave root SO_PEERCRED and fail static bootstrap checks.
    No helper/Supervisor is made privileged, no SELinux policy is installed.
    """
    library=ctypes.CDLL('libselinux.so.1',use_errno=True)
    library.setsockcreatecon.argtypes=[ctypes.c_char_p];library.setsockcreatecon.restype=ctypes.c_int
    context=('system_u:system_r:container_t:'+level).encode()
    if library.setsockcreatecon(context):raise OSError(ctypes.get_errno(),'stock socket creation label denied')
    left=right=None;child=None
    try:
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        child=os.fork()
        if child==0:
            left.close()
            try:
                signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(10)
                os.setgroups([group]);os.setgid(165533);os.setuid(165533)
                with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
                    listener.bind(str(path));listener.listen(4)
                    os.chown(path,-1,group);os.chmod(path,0o620)
                    right.sendmsg([b'LISTENER'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[listener.fileno()]))])
                os._exit(0)
            except BaseException:os._exit(125)
        right.close();right=None;left.settimeout(5)
        raw,ancillary,flags,_=left.recvmsg(32,socket.CMSG_SPACE(4),socket.MSG_CMSG_CLOEXEC)
        expect(raw==b'LISTENER' and not flags and len(ancillary)==1,'exact setup listener transfer')
        level_,kind,data=ancillary[0];fds=array.array('i');fds.frombytes(data)
        expect(level_==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS and len(fds)==1,'one owned listener')
        _,status=os.waitpid(child,0);child=None;expect(status==0,'unprivileged listener setup failed')
        result=socket.socket(fileno=fds[0])
        run('chcon','-t','container_file_t','-l',level,str(path))
        return result
    finally:
        if library.setsockcreatecon(None):raise OSError(ctypes.get_errno(),'socket label reset denied')
        for value in (left,right):
            if value is not None:value.close()
        if child is not None:
            # This is the exact forked setup child, never a looked-up helper PID.
            os.waitpid(child,0)


def storage(nonce,ownership):
    device=Path('/dev/disk/by-id/virtio-uas-quota').resolve()
    expect(device.is_block_device() and int(run('blockdev','--getsize64',str(device)))==2*1024**3,'exact disposable quota disk')
    run('mkfs.xfs','-f',str(device));STORAGE.mkdir();ownership['mounted']=True
    run('mount','-o','prjquota,nodev,nosuid',str(device),str(STORAGE))
    scratch=Path('/run/uas-artifacts-'+nonce);scratch.mkdir(mode=0o711);ownership['scratch']=scratch
    state=scratch/'lifecycle';state.mkdir(mode=0o700);os.chown(state,165533,165533)
    rooms={}
    for index,room in enumerate(('alpha','beta')):
        level=LEVELS[room];base=STORAGE/room;base.mkdir(mode=0o755);os.chown(base,165533,165533)
        project=301+index*2
        run('xfs_quota','-x','-c',f'project -s -p {base} {project}',str(STORAGE))
        run('xfs_quota','-x','-c',f'limit -p bhard=262144k ihard=8192 {project}',str(STORAGE))
        paths={'room':room,'room_root':str(base),'room_instance':hashlib.sha256((nonce+room).encode()).hexdigest()[:32],
            'level':level,'state':str(state),'project':project}
        for name,mode,uid,gid in [('repo',0o755,165533,165533),('checkouts',0o755,165533,165533),
                ('workspace',0o755,165532,165532),('reference',0o755,165533,165533),('scratch',0o711,165533,165533)]:
            path=base/name;path.mkdir(mode=mode);path.chmod(mode);os.chown(path,uid,gid);paths[name]=str(path)
        hub=STORAGE/(room+'-hub');hub.mkdir(mode=0o700);os.chown(hub,165531,165531)
        run('xfs_quota','-x','-c',f'project -s -p {hub} {project+1}',str(STORAGE))
        run('xfs_quota','-x','-c',f'limit -p bhard=65536k ihard=2048 {project+1}',str(STORAGE));paths['hub']=str(hub)
        for name,group,mode in [('gate',165530,0o710),('control',165531,0o710),('journal',165533,0o700)]:
            path=base/'.supervisor' if name=='journal' else scratch/(room+'-'+name)
            path.mkdir(mode=mode);path.chmod(mode);os.chown(path,165533,group);paths[name]=str(path)
            if name!='journal':run('chcon','-t','container_file_t','-l',level,str(path))
        run('chcon','-R','-t','container_file_t','-l',level,str(base),str(hub));rooms[room]=paths
    sentinel=Path(rooms['alpha']['scratch'])/'cross-room-sentinel'
    sentinel.write_bytes(b'fixed-no-secret-marker\n');sentinel.chmod(0o444);os.chown(sentinel,165533,165530)
    run('chcon','-t','container_file_t','-l',LEVELS['alpha'],str(sentinel))
    config=json.loads((ROOT/'tests/fixtures/two-rooms.json').read_text())
    config['deployment']['state_root']=str(state)
    for item in config['rooms']:
        paths=rooms[item['id']]
        item['state_root']=str(state/item['id'])
        for name in item['project']['roots']:item['project']['roots'][name]=paths[name]
    path=scratch/'configuration.json';path.write_text(json.dumps(config));path.chmod(0o444)
    for paths in rooms.values():paths['configuration']=str(path)
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


def scenario(nonce,manifest,checks):
    sys.path[:0]=[str(ROOT),str(ROOT/'tests/vm')]
    from native_rootfs import build_rootfs
    from guest_workstation import import_image,engine_profile,NATIVE_PACKAGE_PROFILE
    owned=[];listeners=[];image=None;ownership={};children=[]
    try:
        # This boot nonce is an accidental-use guard, never a secret/authority.
        # Publish only this already root-validated fixed marker to mapped child.
        marker=Path('/run/uas-vm-fixture')
        expect(os.geteuid()==0 and marker.lstat().st_uid==0 and not marker.is_symlink()
            and marker.read_text().strip()==nonce,'exact disposable boot marker')
        marker.chmod(0o444)
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
        rooms=storage(nonce,ownership);containers={};quota_exhaustion={}
        for room in rooms:
            result=subprocess.run([sys.executable,str(ROOT/'tests/vm/artifact_quota_probe.py'),room],
                user=165533,group=165533,extra_groups=[],stdin=subprocess.DEVNULL,capture_output=True,timeout=20,
                env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
            expect(result.returncode==0 and len(result.stdout)+len(result.stderr)<8192,'actual nonroot project-quota excess denial')
            quota_exhaustion[room]=json.loads(result.stdout)
            expect(quota_exhaustion[room]['project_hard_quota_enforced'] is True,'missing actual quota enforcement')
        rooms['beta']['foreign_scratch']=rooms['alpha']['scratch']
        for room,paths in rooms.items():
            listener=labeled_listener(Path(paths['gate'])/'gate.sock',165530,paths['level'])
            control=labeled_listener(Path(paths['control'])/'hub.sock',165531,paths['level'])
            listeners.extend((listener,control));paths['listener_fds']=(listener.fileno(),control.fileno())
            ws=create(image,'uas-artifact-'+nonce+'-'+room,paths,nonce,foreign=rooms['alpha']['scratch'] if room=='beta' else None);owned.append(ws);run('docker','start',ws)
            hub=create(image,'uas-artifact-'+nonce+'-'+room+'-hub',paths,nonce,hub=True);owned.append(hub)
            containers[room]={'workstation':ws,'hub':hub}
        cross=json.loads(run('docker','exec','--user','65532:65532',containers['beta']['workstation'],
            '/usr/bin/python3','/opt/uas/tests/vm/artifact_room_probe.py','cross-room'))
        expect(cross.get('denied') is True and cross.get('errno') in (errno.EACCES,errno.EPERM),'actual cross-Room MCS access not denied')
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
                child=subprocess.Popen([sys.executable,str(ROOT/'tests/vm/artifact_supervisor.py'),str(file),
                    *map(str,paths['listener_fds'])],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
                    user=165533,group=165533,extra_groups=[165530,os.stat('/run/docker.sock').st_gid],
                    pass_fds=paths['listener_fds'],env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(ROOT)+':'+str(ROOT/'tests/vm'),
                        'PYTHONDONTWRITEBYTECODE':'1','HOME':paths['journal']})
                children.append(child);deadline=time.monotonic()+300
                while child.poll() is None:
                    expect(time.monotonic()<deadline,'bounded concrete Supervisor scenario')
                    expect(max(output.stat().st_size,errors.stat().st_size)<=1<<20,'Supervisor output exceeded bound')
                    time.sleep(.2)
            expect(child.returncode==0,'actual Supervisor failed: '+errors.read_text()[-8192:])
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
