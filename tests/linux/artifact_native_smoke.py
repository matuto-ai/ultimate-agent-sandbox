#!/usr/bin/env python3
"""Cheap explicit artifacts-native fixture; no production/Room qualification.

Uses real copied-Git ArtifactTargets, mapped identity, RO private mounts,
SCM_PIDFD, GateOffer ACK/exit and Hub reducers. Separate TEST bootstrap/probe
hashes exercise the existing exact evaluator setup/filter. Synthetic allocator,
subject and quota admission are explicit. Not Docker, SELinux, #79 or full VM
proof; the historical failed artifact VM evidence remains unchanged.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import zlib

sys.dont_write_bytecode=True
from diff_smoke import (ROOT,HOST_HELPER,HOST_SUPERVISOR,source_fixture,stage_sources,
                        wait_exit,identity,expect,emit)

GATE_CASES=('positive','missing','mutation','cleanup')
PROBES='NPFETMRLWCHO'
EXPECTED_EXIT={'N':159,'P':159,'F':159,'E':159,'T':159,'M':159,
               'R':0,'L':0,'W':0,'C':137,'H':142,'O':126}
EXTRA_SOURCES=('tests/linux/artifact_native_smoke.py',
    'runtime/workstation/artifact_bootstrap.c','runtime/workstation/artifact_evaluator.c',
    'tests/vm/artifact_confinement_probe.c')
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
DEADLINE_SECONDS=40


def artifact_source(root):
    """Append inert exact README/docs objects; retain deliberately dirty checkout."""
    supervisor,allocator,subject=source_fixture(root)
    common=allocator.repo/'.git'
    def obj(kind,data):
        raw=kind.encode()+b' '+str(len(data)).encode()+b'\0'+data
        oid=hashlib.sha1(raw).hexdigest();directory=common/'objects'/oid[:2]
        directory.mkdir(exist_ok=True);(directory/oid[2:]).write_bytes(zlib.compress(raw));return oid
    readme=obj('blob',b'committed artifact\n');guide=obj('blob',b'guide\n')
    docs=obj('tree',b'100644 guide.txt\0'+bytes.fromhex(guide))
    tree=obj('tree',b'100644 README.md\0'+bytes.fromhex(readme)+b'40000 docs\0'+bytes.fromhex(docs))
    head=obj('commit',('tree '+tree+'\nparent '+subject['head_sha']+
        '\nauthor Fixture <fixture@invalid> 0 +0000\ncommitter Fixture <fixture@invalid> 0 +0000\n\nartifacts\n').encode())
    (common/'refs/heads/main').write_text(head+'\n')
    (allocator.repo/'README.md').write_text('dirty checkout is not the artifact\n')
    return supervisor,allocator


def supervisor_case(root,case):
    sys.path.insert(0,str(ROOT))
    from uas.artifact_helper import GateOffer
    from uas.artifact_protocol import ArtifactError,PROFILE_ID,RESERVATION_BYTES,decode_record
    from uas.artifact_target import ArtifactSourceResolver,ArtifactTargets
    from uas.gate_evaluation import ArtifactGateHub
    from uas.kernel_origin import HeldOrigin,enable,receive
    expect(os.getuid()==HOST_SUPERVISOR and os.getgid()==HOST_SUPERVISOR
           and HOST_HELPER in os.getgroups(),'fixed Supervisor/group required')
    root=Path(root);supervisor,allocator=artifact_source(root)
    scratch=root/'targets';scratch.mkdir(mode=0o711)
    journal=root/'target-journal';journal.mkdir(mode=0o700)
    scope={'version':1,'evaluation_id':'artifact-'+case,'room_id':'diff-room','room_instance':'diff-instance',
        'project_id':'diff-project','repository':'fixture/repository','run_id':'diff-run','generation':1,
        'participant_id':'builder','policy_id':'fixture','policy_version':1,'policy_digest':'d'*64,
        'gate_id':'artifacts','config_digest':'e'*64}
    reservations=[]
    def reserve(value,amount):
        expect(value==scope and amount==RESERVATION_BYTES,'artifact reservation mismatch')
        reservations.append(amount);return True # explicit synthetic quota owner
    resolver=ArtifactSourceResolver(supervisor,allocator)
    source=resolver.resolve('diff-run','builder','diff-instance')
    targets=ArtifactTargets(scratch,journal,resolver,reserve_capacity=reserve)
    target=targets.prepare(scope,source);lease=targets.lease(target)
    expect((lease.path/'tree/README.md').read_bytes()==b'committed artifact\n','dirty checkout influenced target')
    endpoint=root/'gate';endpoint.mkdir(mode=0o710);os.chown(endpoint,-1,HOST_HELPER)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    listener.bind(str(endpoint/'gate.sock'));os.chmod(endpoint/'gate.sock',0o620);os.chown(endpoint/'gate.sock',-1,HOST_HELPER)
    enable(listener);listener.listen(1);listener.settimeout(5)
    challenge=hashlib.sha256(('artifact-native-'+case).encode()).digest()
    lease.recheck();lease.mark_launch_possible()
    emit({'stage':'prepared','case':case,'targets':str(scratch),'endpoint':str(endpoint),
          'challenge':challenge.hex(),'target':target,'test_payload':case in EXPECTED_EXIT})
    channel=origin=offer=None;started=time.monotonic()
    try:
        channel,_=listener.accept();enable(channel);channel.settimeout(16)
        with receive(channel) as record:
            expect(record.data==b'AGH1'+challenge and record.credentials[1:]==(HOST_HELPER,HOST_HELPER),'helper task/challenge mismatch')
            origin=HeldOrigin(record)
        release=b'AGR1'+target['target_id'].encode()
        expect(channel.send(release)==len(release),'helper release uncertain')
        if case in EXPECTED_EXIT:
            expect(channel.send(case.encode())==1,'probe selector uncertain')
            rejected=False;observed_bytes=0
            if case=='O':
                with receive(channel) as record:
                    origin.require(record);observed_bytes=len(record.data)
                    try:decode_record(record.data)
                    except ArtifactError:rejected=True
                # Preserve the over-bound record fact before any assertion.
                emit({'stage':'probe-observation','case':case,'observed_bytes':observed_bytes,
                      'receiver_rejected':rejected,'test_payload':True})
                channel.close();channel=None
            wait_exit(origin,18)
            lease.mark_exit_confirmed();post=lease.postverify()==target;clean=lease.cleanup()
            emit({'stage':'result','case':case,'test_payload':True,'actual_exit':True,
                'expected_exit':EXPECTED_EXIT[case],'elapsed_seconds':round(time.monotonic()-started,3),
                'held_identity':list(origin.identity),'post_target':post,'cleanup':clean,
                'receiver_rejected':rejected,'observed_bytes':observed_bytes,'reservations':reservations})
            return
        items=[{'path':'missing.txt' if case=='missing' else 'README.md','type':'file','nonempty':True},
               {'path':'docs','type':'directory','nonempty':True}]
        row={'evaluation_id':scope['evaluation_id'],'scope':scope,'evaluator':'artifacts','items':items}
        document={'scope':scope,'target':target,'profile':PROFILE_ID,'profile_digest':'f'*64,
                  'mapping_digest':'a'*64,'receiver_context':'fixture','origin_identity':list(origin.identity)}
        offer=GateOffer(document,channel,origin,[item['path'] for item in items]);channel=None
        reducer=object.__new__(ArtifactGateHub)
        facts,final=reducer._observations(offer,row,target)
        offer.acknowledge_final(final);offer.confirm_exit();lease.mark_exit_confirmed()
        error=None;post=False;clean=False
        if case=='mutation':
            file=lease.path/'tree/README.md';file.chmod(0o644);file.write_bytes(b'changed\n');file.chmod(0o444)
        try:post=lease.postverify()==target
        except ArtifactError as invalid:error=invalid.code
        if case=='cleanup':
            path=lease.path;path.rename(path.parent/('quarantined-'+path.name));path.mkdir(mode=0o710);os.chown(path,-1,HOST_HELPER)
        try:clean=lease.cleanup()
        except ArtifactError as invalid:error=invalid.code
        checks,verdict=ArtifactGateHub._checks(row,facts,error)
        emit({'stage':'result','case':case,'test_payload':False,'actual_exit':True,'verdict':verdict,
            'checks':checks,'error':error,'post_target':post,'cleanup':clean,'reservations':reservations,
            'head_sha':target['head_sha'],'tree_sha':target['tree_sha'],'held_identity':list(origin.identity)})
    finally:
        if offer is not None:offer.close()
        elif origin is not None:origin.close()
        if channel is not None:channel.close()
        listener.close()


def namespace_helper(rootfs,targets,endpoint,case):
    expect(case in GATE_CASES or case in EXPECTED_EXIT,'fixed case required')
    expect(os.getuid()==0 and os.getgid()==0,'mapped namespace root required')
    expect(Path('/proc/self/uid_map').read_text().split()==['0','100000','65536']
           and Path('/proc/self/gid_map').read_text().split()==['0','100000','65536'],'exact identity mapping required')
    def mount(*args):subprocess.run(['/usr/bin/mount',*args],check=True,timeout=2,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
    mount('--make-rprivate','/');rootfs=Path(rootfs)
    mount('--bind',targets,str(rootfs/'uas/gate-targets'))
    mount('-o','remount,bind,ro,nodev,nosuid,noexec',str(rootfs/'uas/gate-targets'))
    mount('--bind',endpoint,str(rootfs/'uas/gate'))
    mount('--bind','/dev/null',str(rootfs/'dev/null'))
    os.chroot(rootfs);os.chdir('/');os.setgroups([]);os.setgid(65530);os.setuid(65530)
    binary='/opt/uas/bin/artifact-test-bootstrap' if case in EXPECTED_EXIT else '/opt/uas/bin/artifact-bootstrap'
    os.execve(binary,[binary],{})


def build(root,payload):
    installed=root/'binaries';installed.mkdir(mode=0o755);digests={}
    inputs={'artifact-bootstrap':('runtime/workstation/artifact_bootstrap.c',()),
        'artifact-evaluator':('runtime/workstation/artifact_evaluator.c',()),
        'artifact-test-bootstrap':('runtime/workstation/artifact_bootstrap.c',('-DUAS_ARTIFACT_PROBE',)),
        'artifact-confinement-probe':('tests/vm/artifact_confinement_probe.c',())}
    for name,(source,extra) in inputs.items():
        output=installed/name
        subprocess.run(['/usr/bin/gcc','-std=c11','-Wall','-Wextra','-Werror','-O2',
            '-fstack-protector-strong','-static','-Wl,-z,noexecstack','-Wl,-z,relro','-Wl,-z,now',
            *extra,str(payload/source),'-o',str(output)],check=True,timeout=5)
        output.chmod(0o555);digests[name]=hashlib.sha256(output.read_bytes()).hexdigest()
    return installed,digests


def rootfs(path,installed):
    path.mkdir(mode=0o755)
    for name in ('uas','uas/gate','uas/gate-targets','opt','opt/uas','opt/uas/bin','dev'):(path/name).mkdir(mode=0o755)
    (path/'dev/null').touch(mode=0o444)
    for name in ('artifact-bootstrap','artifact-evaluator','artifact-test-bootstrap','artifact-confinement-probe'):
        shutil.copyfile(installed/name,path/'opt/uas/bin'/name);(path/'opt/uas/bin'/name).chmod(0o555)
    for directory,dirs,files in os.walk(path):
        os.chown(directory,100000,100000)
        for name in files:os.chown(Path(directory)/name,100000,100000)


def main():
    if len(sys.argv)==4 and sys.argv[1]=='--supervisor':
        expect(sys.argv[3] in GATE_CASES or sys.argv[3] in EXPECTED_EXIT,'fixed case required')
        supervisor_case(sys.argv[2],sys.argv[3]);return
    if len(sys.argv)==6 and sys.argv[1]=='--namespace-helper':
        namespace_helper(*sys.argv[2:]);return
    expect(sys.argv[1:]==['--run'],'explicit --run required')
    expect(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
           and os.environ.get('RUNNER_OS')=='Linux','owned GitHub Linux root fixture required')
    expect(signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK,()),'unblocked fatal timer required')
    def expired(*_):raise TimeoutError('artifact native fixture exceeded 40 seconds')
    signal.signal(signal.SIGALRM,expired);signal.alarm(DEADLINE_SECONDS)
    started=time.monotonic();root=Path(tempfile.mkdtemp(prefix='uas-artifact-native-',dir='/tmp'));root.chmod(0o711)
    root_identity=identity(root);processes=[];reports=[];complete=False
    try:
        payload,hashes=stage_sources(root,extra_paths=EXTRA_SOURCES)
        script=payload/'tests/linux/artifact_native_smoke.py'
        emit({'stage':'source-staged','source_sha256':hashes})
        installed,digests=build(root,payload)
        for index,case in enumerate((*GATE_CASES,*PROBES)):
            path=root/('case-'+str(index));path.mkdir(mode=0o755);os.chown(path,HOST_SUPERVISOR,HOST_SUPERVISOR)
            owner=subprocess.Popen(['/usr/bin/python3',str(script),'--supervisor',str(path),case],
                user=HOST_SUPERVISOR,group=HOST_SUPERVISOR,extra_groups=[HOST_HELPER],env=ENV,cwd=payload,
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            processes.append(owner)
            first=owner.stdout.readline()
            if not first:
                emit({'stage':'failure','case':case,'diagnostic':owner.stderr.read(8192)})
                raise AssertionError('artifact materialization failed')
            prepared=json.loads(first);image=root/('rootfs-'+str(index));rootfs(image,installed)
            helper=subprocess.Popen(['/usr/bin/unshare','--user','--map-users=0:100000:65536',
                '--map-groups=0:100000:65536','--setuid=0','--setgid=0','--mount','--fork','--kill-child=KILL','--',
                '/usr/bin/python3',str(script),'--namespace-helper',str(image),prepared['targets'],prepared['endpoint'],case],
                stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=ENV,cwd=payload)
            processes.append(helper);helper.stdin.write(bytes.fromhex(prepared['challenge']));helper.stdin.close()
            result=None
            for _ in range(3):
                line=owner.stdout.readline()
                if not line:break
                value=json.loads(line)
                if value['stage']=='result':result=value;break
                emit(value)
            if result is None:
                emit({'stage':'failure','case':case,'owner_diagnostic':owner.stderr.read(8192),
                      'helper_diagnostic':helper.stderr.read(8192).decode(errors='replace')})
                raise AssertionError('artifact terminal evidence missing')
            raw=helper.wait(timeout=2);result['helper_exit_raw']=raw;result['helper_exit']=128-raw if raw<0 else raw
            result['supervisor_exit']=owner.wait(timeout=2)
            for process,key in ((helper,'helper_diagnostic'),(owner,'supervisor_diagnostic')):
                diagnostic=process.stderr.read(8192)
                if isinstance(diagnostic,bytes):diagnostic=diagnostic.decode(errors='replace')
                if diagnostic:result[key]=diagnostic
            reports.append(result);emit(result) # decisive actual status BEFORE assertions
            expect(result['supervisor_exit']==0 and result['actual_exit'],'exact actual helper exit missing')
            if case in EXPECTED_EXIT:
                expect(result['helper_exit']==EXPECTED_EXIT[case] and result['post_target'] and result['cleanup'],
                       'native confinement probe differs from exact expected outcome')
                if case=='C':expect(result['elapsed_seconds']<15,'CPU limit did not precede wall alarm')
                if case=='H':expect(12<=result['elapsed_seconds']<=18,'fatal wall timer interval differs')
                if case=='O':expect(result['observed_bytes']==16385 and result['receiver_rejected'],'over-bound output not refused')
            else:
                expected='passed' if case=='positive' else 'failed' if case=='missing' else 'error'
                expect(result['verdict']==expected and result['helper_exit']==0,'native artifacts adjudication differs')
                if case in ('positive','missing'):expect(result['post_target'] and result['cleanup'],'valid artifacts postproof/cleanup missing')
                if case=='mutation':expect(result['error']=='ARTIFACT_TARGET_CHANGED' and not result['post_target'] and result['cleanup'],'mutation not rejected')
                if case=='cleanup':expect(result['post_target'] and not result['cleanup'],'cleanup failure not quarantined')
        complete=True
        summary={'stage':'summary','check':'artifact-native-linux-smoke','cases':len(reports),'source_sha256':hashes,
            'binary_sha256':digests,'tested_revision':os.environ.get('GITHUB_SHA'),'native_qualification':False,
            'scope':'actual artifacts/helper confinement seam; synthetic allocator/quota; no Room/SELinux/#79/fullVM proof'}
    finally:
        safe=True
        for process in reversed(processes):
            try:
                if process.poll() is None:process.kill()
                process.wait(timeout=2)
            except Exception:safe=False
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None:
                    try:stream.close()
                    except Exception:safe=False
        try:
            if complete and safe:
                expect(identity(root)==root_identity and shutil.rmtree.avoids_symlink_attacks,'fixture cleanup identity uncertain')
                shutil.rmtree(root)
            else:emit({'stage':'quarantine','path':str(root),'cleanup_claimed':False})
        finally:signal.alarm(0)
    expect(complete and safe,'fixture cleanup unconfirmed')
    summary.update(fixture_cleanup=True,seconds=round(time.monotonic()-started,3));emit(summary)


if __name__=='__main__':main()
