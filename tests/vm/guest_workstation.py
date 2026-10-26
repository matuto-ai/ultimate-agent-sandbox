#!/usr/bin/env python3
"""Actual fixed two-Pi/outside-Hub scenario in the owned disposable no-NIC guest.

No custom policy or permissive fallback. Stock-policy failures stop before Pi.
This first native scenario is not production, real Internet or quota exhaustion.
"""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import traceback

import guest_boundary as boundary

PAYLOAD=boundary.PAYLOAD
ROOT=boundary.ROOT
STORAGE=Path('/mnt/uas-native')
LEVEL='s0:c101,c102'
SIBLING_LEVEL='s0:c103,c104'
REQUIRED={'payload','confinement','socket_policy','hub_startup','native_two_seats',
          'actor_attribution','wrong_process','control_loss','resources','guest_cleanup'}
run=boundary.run
expect=boundary.expect


def labeled_listener(path,group):
    """Trusted root setup selects only the same-Room socket-object context.

    The Supervisor process label is unchanged. Denied setsockcreatecon/connect/
    fd-use/pidfs is a failed stock-policy gate, never grounds to install policy.
    """
    label=Path('/proc/self/attr/current').read_text()
    expect('container_t' not in label,'setup must not impersonate runtime domain')
    library=ctypes.CDLL('libselinux.so.1',use_errno=True)
    library.setsockcreatecon.argtypes=[ctypes.c_char_p]
    library.setsockcreatecon.restype=ctypes.c_int
    context=('system_u:system_r:container_t:'+LEVEL).encode()
    if library.setsockcreatecon(context)!=0:
        raise OSError(ctypes.get_errno(),'stock policy denied exact trusted socket creation context')
    listener=None
    try:
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        listener.bind(str(path));listener.listen(4);listener.settimeout(3)
        os.chown(path,165533,group);os.chmod(path,0o620)
    except BaseException:
        if listener is not None:listener.close()
        raise
    finally:
        if library.setsockcreatecon(None)!=0:
            if listener is not None:listener.close()
            raise OSError(ctypes.get_errno(),'socket creation context reset failed')
    expect(Path('/proc/self/attr/current').read_text()==label,'setup process domain changed')
    run('chcon','-t','container_file_t','-l',LEVEL,str(path))
    return listener


def inspect(container):return json.loads(run('docker','inspect',container))[0]


def probe(container,mode):
    return json.loads(run('docker','exec','--user','65532:65532',container,
        '/usr/bin/python3','-m','uas.workstation_probe',mode,timeout=8))


def create(image,name,kind,paths):
    hub=kind=='hub';sibling=kind=='sibling'
    user='65531:65531' if hub else '65532:65532'
    arguments=['docker','create','--name',name,'--label','uas.native-owner='+paths['nonce'],
        '--read-only','--network','none','--user',user,'--cap-drop','ALL',
        '--security-opt','no-new-privileges=true','--security-opt','label=level:'+(SIBLING_LEVEL if sibling else LEVEL),
        '--memory','256m' if hub else ('64m' if sibling else '1024m'),
        '--memory-swap','256m' if hub else ('64m' if sibling else '1024m'),
        '--cpus','0.25' if hub else '1','--pids-limit','32' if hub else '128',
        '--env','PYTHONPATH=/opt/uas','--env','PYTHONDONTWRITEBYTECODE=1',
        '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid='+user.split(':')[0]+',gid='+user.split(':')[1],
        '--mount','type=bind,src='+str(paths['peer'])+',dst=/uas/peer,readonly',
        '--entrypoint','/opt/uas/bin/tini']
    if hub:
        arguments+=['--interactive','--group-add','65532',
            '--mount','type=bind,src='+str(paths['control'])+',dst=/uas/control,readonly',
            '--mount','type=bind,src='+str(paths['hub'])+',dst=/uas/hub']
    elif not sibling:
        arguments+=['--mount','type=bind,src='+str(paths['workstation']/'runtime')+',dst=/uas/runtime',
            '--mount','type=bind,src='+str(paths['workstation']/'workspace')+',dst=/uas/workspace']
    arguments += [image,'--','/usr/bin/python3','-m',
                  'uas.workstation_service' if hub else 'uas.workstation_probe']
    if not hub:arguments+=['idle']
    return run(*arguments).strip()


def verify_container(container,image,kind):
    info=inspect(container);host=info['HostConfig'];config=info['Config']
    expect(info['Image']==image and host['ReadonlyRootfs'] is True and host['CapDrop']==['ALL'], 'immutable confined image')
    expect(host['NetworkMode']=='none' and not host['Privileged'] and host['PidMode']=='', 'private native namespaces')
    expect(host['UsernsMode']!='host' and host['IpcMode']!='host','remapped non-host namespaces')
    expect(config['Entrypoint']==['/opt/uas/bin/tini'] and config['Tty'] is False,'fixed init/non-TTY entrypoint')
    expect('no-new-privileges=true' in host['SecurityOpt'] or 'no-new-privileges' in host['SecurityOpt'],'NNP required')
    label=info['ProcessLabel'];level=SIBLING_LEVEL if kind=='sibling' else LEVEL
    boundary.require_process_label(label,level)
    memory=(256 if kind=='hub' else (64 if kind=='sibling' else 1024))*1024**2
    expect(host['Memory']==memory and host['MemorySwap']==memory
        and host['PidsLimit']==(32 if kind=='hub' else 128)
        and host['NanoCpus']==(250000000 if kind=='hub' else 1000000000),'native resource limits drifted')
    expect(config['User']==('65531:65531' if kind=='hub' else '65532:65532'),'fixed confined user')
    mounts={item['Destination']:item for item in info['Mounts']}
    expect(mounts['/uas/peer']['RW'] is False,'peer endpoint directory writable')
    expect(all('docker.sock' not in p and '/var/lib/uas' not in p for p in mounts),'control/Engine store mounted')
    if kind!='hub':expect('/uas/hub' not in mounts and '/uas/control' not in mounts,'Hub private state exposed')
    return {'id':container,'label':label,'image':image,'memory':host['Memory'],
            'pids_limit':host['PidsLimit'],'nano_cpus':host['NanoCpus'],'mounts':sorted(mounts)}


def storage(nonce, ownership):
    device=Path('/dev/disk/by-id/virtio-uas-quota').resolve()
    expect(str(device).startswith('/dev/') and device.is_block_device(),'owned native quota disk absent')
    expect(int(run('blockdev','--getsize64',str(device)).strip())==2*1024**3,'wrong owned native quota disk size')
    run('mkfs.xfs','-f',str(device));STORAGE.mkdir()
    ownership['mount_attempted']=True
    run('mount','-o','prjquota,nodev,nosuid',str(device),str(STORAGE))
    paths={'nonce':nonce}
    for name,project,uid,block,inodes in [('workstation',201,165532,262144,8192),('hub',202,165531,65536,2048)]:
        path=STORAGE/name;path.mkdir(mode=0o700);os.chown(path,uid,uid)
        run('xfs_quota','-x','-c',f'project -s -p {path} {project}',str(STORAGE))
        run('xfs_quota','-x','-c',f'limit -p bhard={block}k ihard={inodes} {project}',str(STORAGE))
        paths[name]=path
    for name in ('workspace','runtime','runtime/seat-a','runtime/seat-b',
                 'runtime/seat-a/agent','runtime/seat-a/sessions','runtime/seat-b/agent','runtime/seat-b/sessions'):
        path=paths['workstation']/name;path.mkdir(mode=0o700);os.chown(path,165532,165532)
    run('chcon','-R','-t','container_file_t','-l',LEVEL,str(STORAGE))
    base=Path('/run/uas-native-'+nonce);base.mkdir(mode=0o711)
    ownership['scratch']=base
    for name,group,mode in [('peer',165532,0o710),('control',165531,0o710),('supervisor',165533,0o700)]:
        path=base/name;path.mkdir(mode=mode);os.chown(path,165533,group);paths[name]=path
        if name!='supervisor':run('chcon','-t','container_file_t','-l',LEVEL,str(path))
    return paths


def sample_resources(containers, samples, phase):
    for name,container in containers.items():
        if name=='sibling':continue
        # Exact owned Docker systemd scope, telemetry only, never PID authority.
        group=Path('/sys/fs/cgroup/system.slice')/('docker-'+container+'.scope')
        if not group.exists():continue  # Not yet started or already exited.
        values={}
        for field in ('memory.current','memory.peak','memory.events','pids.current','pids.events','cpu.stat'):
            raw=(group/field).read_text()
            expect(len(raw)<=16384,'native cgroup telemetry exceeded bound')
            values[field]=int(raw) if field in ('memory.current','memory.peak','pids.current') else raw
        prior=samples.setdefault(phase,{}).get(name,{})
        for field in ('memory.current','memory.peak','pids.current'):
            values[field]=max(values[field],prior.get(field,0))
        samples[phase][name]=values


NATIVE_PACKAGE_PROFILE = {'moby-engine': ('0','29.8.2','2.fc44','x86_64'),
                          'container-selinux': ('4','2.251.0','1.fc44','noarch')}


def engine_profile(manifest):
    boundary.exact_install_roots(manifest,NATIVE_PACKAGE_PROFILE)
    boundary.require_installed_roots(NATIVE_PACKAGE_PROFILE)
    packages={name:next(item for item in manifest['packages'] if item['name']==name)
              for name in NATIVE_PACKAGE_PROFILE}
    actual=run('docker','version','--format','{{.Server.Version}}').strip()
    expect(actual=='29.8.2','actual Engine version differs')
    return {'server_version':actual,'exec_api':'1.48','packages':packages,
            'dockerd_sha256':hashlib.sha256(Path('/usr/bin/dockerd').read_bytes()).hexdigest()}


def scenario(nonce,manifest):
    sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests/vm'))
    from native_rootfs import build_rootfs
    checks={};owned=[];listeners=[];child=None;image=None;ownership={}
    image_root=Path('/var/lib/uas-native-rootfs');archive=Path('/var/lib/uas-native-rootfs.tar')
    try:
        expect(not image_root.exists() and not archive.exists(),'native image workspace already exists')
        ownership['rootfs']=True
        engine=engine_profile(manifest)
        image_evidence=build_rootfs(nonce,manifest,image_root,run=run)
        ownership['archive']=True
        with tarfile.open(archive,'x',format=tarfile.PAX_FORMAT) as target:
            for path in sorted(image_root.iterdir()):target.add(path,arcname=path.name,recursive=True)
        image=run('docker','import',str(archive),timeout=120).strip()
        expect(image.startswith('sha256:') and len(image)==71,'native immutable image ID')
        checks['payload']={'status':'passed','image':image,'engine':engine,**image_evidence}
        paths=storage(nonce,ownership)
        for name,group in [('peer',165532),('control',165531)]:
            listeners.append(labeled_listener(paths[name]/('pi.sock' if name=='peer' else 'hub.sock'),group))
        containers={}
        for kind in ('workstation','hub','sibling'):
            identifier=create(image,'uas-native-'+nonce+'-'+kind,kind,paths)
            owned.append(identifier);containers[kind]=identifier
            if kind!='hub':run('docker','start',identifier)
        confinement={kind:verify_container(identifier,image,kind) for kind,identifier in containers.items()}
        actual=probe(containers['workstation'],'observe')
        expect(actual['uid']==65532 and actual['gid']==65532 and not actual['engine_mounted'],'actual confined runtime user')
        expected_status={'CapEff':'0000000000000000','CapBnd':'0000000000000000','NoNewPrivs':'1','Seccomp':'2'}
        expect(actual['kernel_status']==expected_status,'actual Workstation capabilities/NNP/seccomp differ')
        expected_map='0 100000 65536'
        expect(' '.join(actual['uid_map'].split())==expected_map and ' '.join(actual['gid_map'].split())==expected_map,'actual native remap')
        expect(actual['overflow_uid']==65534 and actual['overflow_gid']==65534,'unsupported overflow identity mapping')
        mapping_digest=hashlib.sha256(json.dumps({key:actual[key] for key in ('uid_map','gid_map','overflow_uid','overflow_gid')},sort_keys=True).encode()).hexdigest()
        checks['confinement']={'status':'passed','containers':confinement,'runtime':actual}
        expect(probe(containers['workstation'],'peer')=={'connected':True},'same-Room stock socket connection denied')
        positive,_=listeners[0].accept()
        with positive:
            expect(positive.recv(128)==b'UAS-NATIVE-PREFLIGHT','wrong fixed socket positive')
            peer_label=positive.getsockopt(socket.SOL_SOCKET,socket.SO_PEERSEC,1024).decode().rstrip('\0')
            boundary.require_process_label(peer_label,LEVEL)
        negative=probe(containers['sibling'],'peer')
        expect(negative.get('connected') is False and negative.get('errno') in (errno.EACCES,errno.EPERM),'cross-Room socket access not denied')
        private=probe(containers['workstation'],'private')
        expect(private['ledger']==errno.ENOENT and private['control']==errno.ENOENT and private['unlink'] in (errno.EROFS,errno.EACCES,errno.EPERM),'endpoint/private Hub boundary failed')
        checks['socket_policy']={'status':'passed','same_room_label':peer_label,'sibling':negative,'private':private,
                                'socket_creation_context':'system_u:system_r:container_t:'+LEVEL}
        config={'nonce':nonce,'hub_id':containers['hub'],'workstation_id':containers['workstation'],
            'mapping_digest':mapping_digest,'profile_digest':image_evidence['rootfs_manifest_sha256'],
            'supervisor_directory':str(paths['supervisor']), 'peer_path':str(paths['peer']/'pi.sock'),
            'control_path':str(paths['control']/'hub.sock')}
        config_path=paths['supervisor']/'config.json';config_path.write_text(json.dumps(config));os.chown(config_path,165533,165533);config_path.chmod(0o400)
        # Boot marker is an accidental-use guard, never a secret or authority.
        Path('/run/uas-vm-fixture').chmod(0o444)
        output=paths['supervisor']/'result.log';errors=paths['supervisor']/'errors.log'
        samples={};workstation_stopped=False
        with output.open('wb') as stdout,errors.open('wb') as stderr:
            child=subprocess.Popen([sys.executable,str(ROOT/'tests/vm/native_supervisor.py'),str(config_path),
                *[str(item.fileno()) for item in listeners]],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
                user=165533,group=165533,extra_groups=[os.stat('/run/docker.sock').st_gid],
                pass_fds=tuple(item.fileno() for item in listeners),
                env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(ROOT),'PYTHONDONTWRITEBYTECODE':'1','HOME':str(paths['supervisor'])})
            deadline=time.monotonic()+150
            while child.poll() is None:
                expect(time.monotonic()<deadline,'native Supervisor exceeded bounded scenario')
                expect(max(output.stat().st_size,errors.stat().st_size)<=1024*1024,'native output budget exceeded')
                phases=[line.split(':',1)[1] for line in output.read_text().splitlines() if line.startswith('UAS_NATIVE_PHASE:')]
                if phases and phases[-1]=='stop-workstation' and not workstation_stopped:
                    run('docker','stop','--time','3',containers['workstation'],timeout=8)
                    workstation_stopped=True
                sample_resources(containers,samples,phases[-1] if phases else 'startup')
                time.sleep(.2)
        expect(child.returncode==0,'native Supervisor failed: '+errors.read_text()[-8192:])
        lines=[line.split(':',1)[1] for line in output.read_text().splitlines() if line.startswith('UAS_NATIVE_SUPERVISOR:')]
        expect(len(lines)==1,'missing exact native Supervisor report');result=json.loads(lines[0])
        hub_observation=result['hub_observation']
        expect(hub_observation['pid_namespace']!=actual['pid_namespace']
            and hub_observation['mount_namespace']!=actual['mount_namespace']
            and hub_observation['uid_map']==actual['uid_map']
            and hub_observation['gid_map']==actual['gid_map']
            and hub_observation['overflow_uid']==65534 and hub_observation['overflow_gid']==65534,'outside Hub namespace/mapping distinction')
        expect(hub_observation['kernel_status']==expected_status,'actual Hub capabilities/NNP/seccomp differ')
        boundary.require_process_label(hub_observation['label'],LEVEL)
        checks['confinement']['hub_actual']=hub_observation
        checks['hub_startup']={'status':'passed','identity':result['hub_identity'],'controller':result['controller'],
            'supervisor_label':result['supervisor_label'],'supervisor_uid':result['supervisor_uid']}
        checks['native_two_seats']={'status':'passed','seats':result['seats'],'tool_ends':result['native_tool_ends'],
            'scope':'two native ingress paths plus recipient native history confirmation',
            'recipient_native_delivery_verified':True,'deliveries':result['native_deliveries']}
        state=json.loads((paths['hub']/'report.json').read_text())
        traffic=state['state']['peer_traffic']['traffic']
        expect(set(traffic)=={'native-0','native-1'},'native retries/forged/wrong-process mutated ledger')
        expect(traffic['native-0']['actor_id']=='actor-a' and traffic['native-1']['actor_id']=='actor-b','native Actor attribution disagrees')
        expect(len(result['native_deliveries'])==2,'missing actual recipient native acceptance')
        for index,recipient in ((0,'bob'),(1,'alice')):
            delivery=result['native_deliveries'][index]
            stored=traffic['native-'+str(index)]['deliveries']
            expect(set(stored)=={recipient} and delivery['recipient']==recipient,
                   'Hub/native recipient binding mismatch')
            receipt=delivery['hub_receipt']['result']
            expect(all(stored[recipient].get(key)==value for key,value in receipt.items()),
                   'native receipt does not match durable Hub confirmation')
            expect(delivery['native_receipt']['source']=='native-active-branch-and-session-file',
                   'native acceptance must cite active branch and session file')
        checks['actor_attribution']={'status':'passed','room_seq':state['room_seq'],'traffic':{key:value['actor_id'] for key,value in traffic.items()}}
        expect(result['wrong_process_fenced'],'real inherited descriptor wrong-process negative failed')
        checks['wrong_process']={'status':'passed','actual_pi_scm_rights_to_other_node_task':True}
        expect(result['hub_exited_after_control_eof'],'Hub control-loss monitor did not stop')
        with sqlite3.connect('file:'+str(paths['hub']/'admissions.db')+'?mode=ro',uri=True) as database:
            states=database.execute('SELECT state FROM admissions').fetchall()
        expect(states and all(row[0]=='revoked' for row in states),'control loss retained authority projection')
        checks['control_loss']={'status':'passed','all_admissions_revoked':True,'hub_survived_workstation_stop':result['hub_alive_after_workstation_stop']}
        expect('native-turns' in samples and set(samples['native-turns'])=={'hub','workstation'},'missing measured native resource phase')
        quota_state=run('xfs_quota','-x','-c','state -p',str(STORAGE))
        expect('Accounting: ON' in quota_state and 'Enforcement: ON' in quota_state,'native project quotas not enforced')
        quota_reports={flag:run('xfs_quota','-x','-c','report -p -'+flag+' -n -N',str(STORAGE)) for flag in ('b','i')}
        for project,blocks,inodes in ((201,262144,8192),(202,65536,2048)):
            for flag,limit in (('b',blocks),('i',inodes)):
                rows=[line.split() for line in quota_reports[flag].splitlines() if line.split() and line.split()[0]=='#'+str(project)]
                expect(len(rows)==1 and len(rows[0])>=4 and rows[0][3]==str(limit),'native quota limits drifted')
        checks['resources']={'status':'passed','profile':'native-pi-v1-initial-bounded-diagnostic',
            'workstation_memory_bytes':1024**3,'hub_memory_bytes':256*1024**2,
            'workstation_writable_quota_bytes':256*1024**2,'hub_writable_quota_bytes':64*1024**2,
            'phase_cgroup_observations':samples,'quota_reports':quota_reports,
            'reset_resource_profile_measured':False,'quota_exhaustion_qualified':False,'production_capacity_qualified':False}
        expect(workstation_stopped and result['hub_alive_after_workstation_stop'],'outside Hub did not survive normal Workstation stop')
        expect((paths['hub']/'room.db').is_file(),'Workstation stop removed Hub ledger')
        return checks
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        for listener in listeners:listener.close()
        cleanup=True
        for container in reversed(owned):
            try:
                info=inspect(container)
                expect(info['Config']['Labels'].get('uas.native-owner')==nonce,'cleanup ownership changed')
                run('docker','rm','--force',container)
            except Exception:cleanup=False
        if ownership.get('mount_attempted'):
            try:
                if STORAGE.is_mount():run('umount',str(STORAGE))
            except Exception:cleanup=False
        if image is not None:
            try:run('docker','image','rm',image)
            except Exception:cleanup=False
        try:
            if ownership.get('archive'):archive.unlink(missing_ok=True)
            if ownership.get('rootfs'):
                if image_root.exists():shutil.rmtree(image_root)
                image_root.with_name(image_root.name+'.manifest.json').unlink(missing_ok=True)
            if ownership.get('scratch'):shutil.rmtree(ownership['scratch'])
        except Exception:cleanup=False
        expect(cleanup,'owned native cleanup incomplete')
        checks['guest_cleanup']={'status':'passed','owned_containers_removed':True,'quota_disk_unmounted':True,'owned_image_and_build_scratch_removed':True}


def main():
    nonce,digest=sys.argv[1:];checks={}
    try:
        boundary.install(nonce,digest,exact_roots=NATIVE_PACKAGE_PROFILE)
        manifest=boundary.verify_payload(nonce,digest)
        expect(manifest.get('profile')=='native-pi-v1','not explicit native payload')
        checks=scenario(nonce,manifest)
        expect(set(checks)==REQUIRED,'incomplete native scenario')
    except Exception:
        print(traceback.format_exc()[-16384:],flush=True)
        for command in (['journalctl','-k','-b','--no-pager','-n','40','--grep=avc:.*denied'],
                        ['journalctl','-u','docker','--no-pager','-n','30']):
            try:print('Native diagnostic:',command,run(*command)[-8192:],flush=True)
            except Exception:pass
        checks={name:{'status':'failed','error':'NATIVE_SCENARIO_FAILED'} for name in REQUIRED}
    report={'version':1,'nonce':nonce,'checks':checks}
    with open('/dev/ttyS0','w') as serial:
        serial.write('\nUAS_WORKSTATION_REPORT:'+nonce+':'+json.dumps(report,sort_keys=True)+'\n');serial.flush()


if __name__=='__main__':main()
