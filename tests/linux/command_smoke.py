#!/usr/bin/env python3
"""Explicit hosted mapped-Linux command proof; never import-time/local QA.

Exercises real copied-Git target/work leases, static provisioned test+child,
SCM_PIDFD-bound helper packets, configured limits, independent loss containment,
immutable postproof and cleanup. No Docker/SELinux/live Forge qualification.
All mounts and tasks are inside a disposable private mount/PID namespace.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import zlib

sys.dont_write_bytecode=True
from diff_smoke import ROOT, HOST_HELPER, HOST_SUPERVISOR, source_fixture, wait_exit, identity, expect, emit, stage_sources

CASES=('positive','python-test','wrong-source-root','ignored-sigchld','nonzero','timeout','output','network','group-escape',
       'async-owner','async-flags','outside-chmod','outside-utime','ioctl-denial','target-write','process-limit','memory-limit',
       'work-limit','observer-loss','guard-loss')
WORK_BYTES=8<<20
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
PYTHON_TEST=b'''import os
assert open("changed.txt", "rb").read() == b"head\\n"
temporary = os.environ["TMPDIR"]
os.mkdir(temporary + "/python-results")
with open(temporary + "/python-results/checked", "w") as output:
    output.write("immutable revision checked\\n")
child = os.fork()
if child == 0:
    os.execve("/usr/bin/uas-command-worker", ["/usr/bin/uas-command-worker", "worker"], {})
assert os.waitpid(child, 0) == (child, 0)
assert open(temporary + "/child.result", "rb").read() == b"checked\\n"
print("configured Python revision test and pinned child passed")
'''


def add_committed_python_test(repo,head):
    """Extend fixture-owned inert Git objects; never use the mutable checkout."""
    common=Path(repo)/'.git'
    def read(oid):
        return zlib.decompress((common/'objects'/oid[:2]/oid[2:]).read_bytes()).split(b'\0',1)[1]
    def write(kind,data):
        raw=kind.encode()+b' '+str(len(data)).encode()+b'\0'+data;oid=hashlib.sha1(raw).hexdigest()
        parent=common/'objects'/oid[:2];parent.mkdir(exist_ok=True)
        (parent/oid[2:]).write_bytes(zlib.compress(raw));return oid
    tree=read(head).split(b'\n',1)[0].split()[1].decode();data=read(tree);entries=[];position=0
    while position<len(data):
        stop=data.index(b'\0',position);mode,name=data[position:stop].split(b' ',1)
        entries.append((name,mode,data[stop+1:stop+21]));position=stop+21
    entries.append((b'test.py',b'100644',bytes.fromhex(write('blob',PYTHON_TEST))))
    tree=write('tree',b''.join(mode+b' '+name+b'\0'+oid for name,mode,oid in sorted(entries)))
    commit=write('commit',('tree '+tree+'\nparent '+head+'\nauthor Fixture <fixture@invalid> 0 +0000\n'
        'committer Fixture <fixture@invalid> 0 +0000\n\nconfigured Python test\n').encode())
    (common/'refs/heads/main').write_text(commit+'\n')


def mount(*args):
    subprocess.run(['/usr/bin/mount',*args],check=True,timeout=3,
                   stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)


def observed_work(path,amount):
    """Fresh exact mount inventory, not configured intent or an admission stub."""
    path=str(Path(path));records=[]
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields=line.split();separator=fields.index('-')
        if fields[4]==path or fields[4].startswith(path+'/'):
            records.append((fields,separator))
    expect(len(records)==1,'work has missing/extra nested mounts')
    fields,separator=records[0]
    expect(fields[4]==path and fields[separator+1]=='tmpfs','work is not exact tmpfs')
    expect({'rw','nosuid','nodev','noexec'}<=set(fields[5].split(',')),'work mount flags')
    fs=os.statvfs(path);node=os.stat(path)
    expect(amount==WORK_BYTES and fs.f_blocks*fs.f_frsize==WORK_BYTES
           and not fs.f_flag&os.ST_RDONLY and node.st_uid==HOST_SUPERVISOR
           and node.st_mode&0o7777==0o711,'actual work identity/bound')
    return True


def supervisor_case(root,case,digest_document):
    sys.path.insert(0,str(ROOT))
    from uas.artifact_helper import GateOffer
    from uas.artifact_target import ArtifactSourceResolver
    from uas.command_target import CommandTargets
    from uas.gate_command_hub import CommandGateHub
    from uas.gate_repository import COMMAND_PROFILE_ID, compile_repository_config, command_observations
    from uas.kernel_origin import HeldOrigin,enable,receive
    expect(os.getuid()==HOST_SUPERVISOR and os.getgid()==HOST_SUPERVISOR,'fixed Supervisor UID')
    expect(HOST_HELPER in os.getgroups(),'fixed helper group')
    digests=json.loads(digest_document);executable_digest=digests['uas-command-test']
    root=Path(root);supervisor,allocator,subject=source_fixture(root)
    add_committed_python_test(allocator.repo,subject['head_sha'])
    scratch=root/'targets';scratch.mkdir(mode=0o711)
    journal=root/'targets-journal';journal.mkdir(mode=0o700)
    (root/'command-work').mkdir(mode=0o700)
    scope={'version':1,'evaluation_id':'command-'+case,'room_id':'diff-room','room_instance':'diff-instance',
        'project_id':'diff-project','repository':'fixture/repository','run_id':'diff-run','generation':1,
        'participant_id':'builder','policy_id':'fixture','policy_version':1,'policy_digest':'d'*64,
        'gate_id':'command','config_digest':'e'*64}
    mode='positive' if case in ('ignored-sigchld','wrong-source-root') else 'loss' if case.endswith('-loss') else case
    argv=['/usr/bin/python3.12','-I','-S','-B','test.py'] if case=='python-test' else ['/usr/bin/uas-command-test',mode]
    config=compile_repository_config('command',{'argv':argv,
        'cwd':'.','timeout_seconds':2 if case=='timeout' else 5,'environment':{},
        'process_limit':8,'memory_bytes':64<<20,'output_bytes':1024 if case=='output' else 1<<20,
        'executable_sha256':digests['python3.12'] if case=='python-test' else executable_digest,
        'executables':[{'path':'/usr/bin/uas-command-worker','sha256':executable_digest}]},'fixture')
    reservations=[]
    def reserve(value,amount):
        expect(value==scope and amount==40<<20,'command target/work reservation mismatch')
        reservations.append(amount);return True # explicit fixture-owned aggregate quota token
    resolver=ArtifactSourceResolver(supervisor,allocator)
    source=resolver.resolve('diff-run','builder','diff-instance')
    targets=CommandTargets(scratch,journal,resolver,work_root=root/'work',
                           reserve_capacity=reserve,admit_work=observed_work)
    target=targets.prepare(scope,source);lease=targets.lease(target)
    expect((scratch/target['target_id']/'tree/changed.txt').read_bytes()==b'head\n','dirty checkout observed')
    row={'evaluator':'command','evaluation_id':scope['evaluation_id'],'scope':scope,'config':config}
    endpoint=root/'gate';endpoint.mkdir(mode=0o710);os.chown(endpoint,-1,HOST_HELPER)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    listener.bind(str(endpoint/'gate.sock'));os.chmod(endpoint/'gate.sock',0o620);os.chown(endpoint/'gate.sock',-1,HOST_HELPER)
    enable(listener);listener.listen(1);listener.settimeout(5)
    challenge=hashlib.sha256(('fixture-'+case).encode()).digest()
    lease.recheck();lease.mark_launch_possible()
    emit({'stage':'prepared','case':case,'targets':str(scratch),'endpoint':str(endpoint),
          'work':str(root/'work'),'challenge':challenge.hex(),'target':target})
    channel=None;origin=None;offer=None;facts=None;error=None;post=False;clean=False;normal_exit=False
    try:
        channel,_=listener.accept();enable(channel);channel.settimeout(12)
        with receive(channel) as record:
            expect(record.data==b'AGH1'+challenge,'challenge mismatch')
            expect(record.credentials[1:]==(HOST_HELPER,HOST_HELPER),'mapped helper identity mismatch')
            helper_pid=record.credentials[0];origin=HeldOrigin(record)
        release=b'AGR1'+target['target_id'].encode();expect(channel.send(release)==len(release),'release uncertain')
        requested=deepcopy(target)
        if case=='wrong-source-root':requested['inode']+=1
        document={'scope':scope,'target':requested,'profile':COMMAND_PROFILE_ID,
            'profile_digest':'f'*64,'mapping_digest':'a'*64,'receiver_context':'fixture',
            'origin_identity':list(origin.identity)}
        offer=GateOffer(document,channel,origin,config);channel=None
        try:
            records=[]
            for record in offer.records():
                records.append(record)
                if len(records)==1 and case.endswith('-loss'):
                    ready=root/'work'/target['target_id']/'ready';deadline=time.monotonic()+3
                    while not ready.exists() and time.monotonic()<deadline:time.sleep(.01)
                    values=ready.read_text().split()
                    expect(len(values)==3 and all(value.isdigit() for value in values),'tree handoff malformed')
                    pids=[int(value) for value in values]
                    expect(len(set(pids+[helper_pid]))==4 and all(pid>1 for pid in pids),'tree handoff invalid')
                    emit({'stage':'fault-ready','case':case,'observer':helper_pid,'guard':pids[0],
                          'command':pids[1],'descendant':pids[2]})
            facts,final=command_observations(records,scope,requested,config)
            offer.acknowledge_final(final);offer.confirm_exit();normal_exit=True
        except Exception as invalid:
            error=getattr(invalid,'code','FIXTURE_NATIVE_EVIDENCE_ERROR')
            wait_exit(origin)
        # The exact outer launcher confirms helper exit status before this
        # private control message. A pidfd alone does not prove tree cleanup.
        emit({'stage':'await-exit','case':case,'normal_stream':normal_exit})
        confirmation=json.loads(sys.stdin.readline())
        expect(set(confirmation)=={'exit_code'} and type(confirmation['exit_code']) is int,'missing launcher exit proof')
        if normal_exit and confirmation['exit_code']==0:
            lease.mark_exit_confirmed()
            try:post=lease.postverify()==target
            except Exception as invalid:error=getattr(invalid,'code','FIXTURE_POSTPROOF_ERROR')
            try:clean=lease.cleanup() is True
            except Exception as invalid:error=getattr(invalid,'code','FIXTURE_CLEANUP_ERROR')
        else:
            error=error or 'FIXTURE_HELPER_EXIT_FAILED'
            expect(targets.reconcile(scope['evaluation_id'])['cleanup'] is False,'uncertain tree cleanup incorrectly claimed')
        checks,verdict=CommandGateHub._checks(row,facts,error)
        emit({'stage':'result','case':case,'verdict':verdict,'error':error,'facts':facts,'checks':checks,
              'post_target':post,'cleanup':clean,'lease_phase':lease.phase,'reservations':reservations,
              'origin_identity':list(origin.identity)})
    finally:
        if offer is not None:offer.close()
        elif origin is not None:origin.close()
        if channel is not None:channel.close()
        listener.close()


def namespace_helper(rootfs,targets,endpoint,work,case):
    expect(os.getuid()==0 and os.getgid()==0,'mapped namespace root')
    expect(Path('/proc/self/uid_map').read_text().split()==['0','100000','65536'],'fixed UID map')
    expect(Path('/proc/self/gid_map').read_text().split()==['0','100000','65536'],'fixed GID map')
    rootfs=Path(rootfs);mount('--make-rprivate','/');mount('--bind',str(rootfs),str(rootfs))
    for source,destination,flags in ((targets,'uas/gate-targets','ro,nodev,nosuid,noexec'),
            (endpoint,'uas/gate','rw,nodev,nosuid,noexec'),(work,'uas/gate-work','rw,nodev,nosuid,noexec'),
            ('/dev/null','dev/null','ro,nosuid,noexec'),('/proc','proc','ro,nodev,nosuid,noexec')):
        mount('--bind',source,str(rootfs/destination));mount('-o','remount,bind,'+flags,str(rootfs/destination))
    mount('-o','remount,bind,ro,nodev,nosuid',str(rootfs))
    # No mount below the complete provisioned runtime subtree; readonly root
    # alone would not exclude a nested writable dependency mount.
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        destination=line.split()[4]
        expect(not destination.startswith(str(rootfs/'usr')+'/'),'unadmitted nested runtime mount')
    os.chroot(rootfs);os.chdir('/')
    os.setgroups([]);os.setgid(65530);os.setuid(65530)
    signal.signal(signal.SIGPIPE,signal.SIG_DFL) # Do not hide guard ordering behind Python's inherited IGN.
    if case=='ignored-sigchld':signal.signal(signal.SIGCHLD,signal.SIG_IGN)
    os.execve('/opt/uas/bin/command-bootstrap',['/opt/uas/bin/command-bootstrap'],{})


def build(root,source_root):
    installed=root/'binaries';installed.mkdir(mode=0o755);digests={}
    sources={'command-bootstrap':'runtime/workstation/command_bootstrap.c',
             'command-evaluator':'runtime/workstation/command_evaluator.c',
             'uas-command-test':'tests/linux/command_fixture.c'}
    for name,source in sources.items():
        output=installed/name
        subprocess.run(['/usr/bin/gcc','-std=c11','-Wall','-Wextra','-Werror','-O2',
            '-fstack-protector-strong','-static','-Wl,-z,noexecstack','-Wl,-z,relro','-Wl,-z,now',
            str(source_root/source),'-o',str(output)],check=True,timeout=10)
        output.chmod(0o555);digests[name]=hashlib.sha256(output.read_bytes()).hexdigest()
    runtime=installed/'runtime';runtime.mkdir()
    total=0;count=0
    def copy_runtime(source,destination,executable=False):
        nonlocal total,count
        source=Path(source).resolve(strict=True);before=source.stat()
        expect(source.is_file() and before.st_uid==0 and not before.st_mode&0o022
               and 0<before.st_size<=16<<20,'untrusted provisioned runtime file')
        data=source.read_bytes();after=source.stat()
        expect((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
               (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
               'runtime changed while provisioning')
        total+=len(data);count+=1;expect(total<=64<<20 and count<=256,'runtime image bound exceeded')
        target=runtime/destination;target.parent.mkdir(parents=True,exist_ok=True)
        expect(not target.exists(),'duplicate runtime provision')
        target.write_bytes(data);target.chmod(0o555 if executable else 0o444)
        return hashlib.sha256(data).hexdigest()
    python=Path('/usr/bin/python3.12')
    expect(python.is_file() and not python.is_symlink(),'fixed provisioned Python3.12 ELF unavailable')
    digests['python3.12']=copy_runtime(python,'usr/bin/python3.12',True)
    # Only this trusted hosted interpreter is inspected; never a target binary
    # or an untrusted caller path. The exact copied bytes enter the image hash.
    dependencies=subprocess.run(['/usr/bin/ldd',str(python)],check=True,capture_output=True,
                                timeout=3,env=ENV).stdout.decode('ascii')
    expect(len(dependencies)<16384,'dynamic dependency output bound')
    files={}
    for line in dependencies.splitlines():
        if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:[A-Za-z0-9_.+-]+ => )?(/(?:usr/)?lib(?:64|/x86_64-linux-gnu)/[A-Za-z0-9_.+-]+) \(0x[0-9a-f]+\)',line)
        expect(match is not None,'unsupported or missing dynamic runtime dependency')
        path=Path(match.group(1));expect(path.name not in files,'duplicate dynamic runtime dependency');files[path.name]=path
    expect('libc.so.6' in files and 'ld-linux-x86-64.so.2' in files,'incomplete dynamic runtime closure')
    for name,path in sorted(files.items()):
        directory='usr/lib64' if name=='ld-linux-x86-64.so.2' else 'usr/lib/x86_64-linux-gnu'
        copy_runtime(path,directory+'/'+name,name=='ld-linux-x86-64.so.2')
    standard=Path('/usr/lib/python3.12')
    copy_runtime(standard/'os.py','usr/lib/python3.12/os.py')
    encodings=sorted((standard/'encodings').glob('*.py'))
    expect(0<len(encodings)<=128,'bounded Python encoding package missing')
    for path in encodings:copy_runtime(path,'usr/lib/python3.12/encodings/'+path.name)
    return installed,digests


def make_rootfs(path,installed):
    path.mkdir(mode=0o755)
    for directory in ('uas','uas/gate','uas/gate-targets','uas/gate-work','opt','opt/uas','opt/uas/bin',
                      'usr','usr/bin','usr/lib','usr/lib64','dev','proc'):
        (path/directory).mkdir(mode=0o755)
    (path/'dev/null').touch(mode=0o444)
    for name in ('command-bootstrap','command-evaluator'):
        shutil.copyfile(installed/name,path/'opt/uas/bin'/name);(path/'opt/uas/bin'/name).chmod(0o555)
    for name in ('uas-command-test','uas-command-worker'):
        shutil.copyfile(installed/'uas-command-test',path/'usr/bin'/name);(path/'usr/bin'/name).chmod(0o555)
    for source in sorted((installed/'runtime').rglob('*')):
        target=path/source.relative_to(installed/'runtime')
        if source.is_dir():target.mkdir(mode=0o755,exist_ok=True)
        else:
            shutil.copyfile(source,target);target.chmod(source.stat().st_mode&0o777)
    (path/'lib').symlink_to('usr/lib');(path/'lib64').symlink_to('usr/lib64')
    manifest={}
    for directory,dirs,files in os.walk(path):
        os.chown(directory,100000,100000);os.chmod(directory,0o555)
        for name in dirs:
            item=Path(directory)/name
            if item.is_symlink():
                os.chown(item,100000,100000,follow_symlinks=False)
                manifest[str(item.relative_to(path))]={'symlink':os.readlink(item)}
        for name in files:
            item=Path(directory)/name;os.chown(item,100000,100000)
            manifest[str(item.relative_to(path))]=hashlib.sha256(item.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def kill_owned_tree(record):
    """Fixture root pins all four observed tasks before injecting one failure."""
    pids=[record[name] for name in ('observer','guard','command','descendant')]
    expect(len(set(pids))==4 and all(type(pid) is int and pid>1 for pid in pids),'invalid task handoff')
    held=[]
    try:
        for pid in pids:
            fd=os.pidfd_open(pid);held.append(fd)
            status=Path('/proc/'+str(pid)+'/status').read_text()
            expect(('Uid:\t'+str(HOST_HELPER)+'\t') in status,'fault task not fixture Helper UID')
        selected=0 if record['case']=='observer-loss' else 1
        signal.pidfd_send_signal(held[selected],signal.SIGKILL)
        deadline=time.monotonic()+3
        poller=select.poll()
        for fd in held:poller.register(fd,select.POLLIN)
        pending=set(held)
        while pending and time.monotonic()<deadline:
            for fd,event in poller.poll(50):
                if event&select.POLLIN:pending.discard(fd)
        expect(not pending,'injected helper loss left a live owned descendant')
        return {'pinned_tasks':4,'all_exited':True,'seconds':round(3-(deadline-time.monotonic()),3)}
    finally:
        for fd in held:os.close(fd)


def isolated():
    from mapped_namespace import mapped_popen
    expect(os.getpid()==1 and os.getppid()==0,'private PID-namespace init required')
    mount('--make-rprivate','/')
    started=time.monotonic();root=Path(tempfile.mkdtemp(prefix='uas-command-',dir='/tmp'));root.chmod(0o711)
    root_identity=identity(root);processes=[];reports=[];mounts=[];complete=False
    try:
        payload,source_hashes=stage_sources(root,extra_paths=(
            'tests/linux/command_smoke.py','tests/linux/command_fixture.c',
            'uas/command_target.py','uas/gate_command_hub.py',
            'runtime/workstation/command_bootstrap.c','runtime/workstation/command_evaluator.c',
            'runtime/workstation/artifact_bootstrap.c','runtime/workstation/artifact_evaluator.c'))
        script=payload/'tests/linux/command_smoke.py'
        emit({'stage':'staged-source','source_sha256':source_hashes,'tested_revision':os.environ.get('GITHUB_SHA')})
        installed,digests=build(root,payload)
        for index,case in enumerate(CASES):
            case_root=root/('case-'+str(index));case_root.mkdir(mode=0o755);os.chown(case_root,HOST_SUPERVISOR,HOST_SUPERVISOR)
            work=case_root/'work';work.mkdir()
            mount('-t','tmpfs','-o','rw,nosuid,nodev,noexec,size=8m,mode=0711,uid=165533,gid=165533','tmpfs',str(work));mounts.append(work)
            outside=work/'foreign';outside.mkdir(mode=0o770);os.chown(outside,HOST_HELPER,HOST_HELPER)
            sentinel=outside/'sentinel';sentinel.write_bytes(b'other Evaluation work\n');sentinel.chmod(0o640);os.chown(sentinel,HOST_HELPER,HOST_HELPER)
            before_sentinel=(sentinel.stat().st_mode,sentinel.stat().st_mtime_ns,sentinel.stat().st_ctime_ns)
            owner=subprocess.Popen(['/usr/bin/python3',str(script),'--supervisor',str(case_root),case,json.dumps(digests)],
                user=HOST_SUPERVISOR,group=HOST_SUPERVISOR,extra_groups=[HOST_HELPER],env=ENV,cwd=payload,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            processes.append(owner)
            prepared=json.loads(owner.stdout.readline())
            expect(prepared['stage']=='prepared','missing prepared target')
            rootfs=root/('rootfs-'+str(index));image_digest=make_rootfs(rootfs,installed)
            helper=mapped_popen(['/usr/bin/python3',str(script),'--namespace-helper',str(rootfs),prepared['targets'],
                prepared['endpoint'],prepared['work'],case],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,env=ENV,cwd=payload)
            processes.append(helper);helper.stdin.write(bytes.fromhex(prepared['challenge']));helper.stdin.close()
            loss=None
            while True:
                line=owner.stdout.readline()
                if not line:
                    emit({'stage':'failure','case':case,'owner_diagnostic':owner.stderr.read(8192),
                          'helper_diagnostic':helper.stderr.read(8192).decode(errors='replace')})
                    raise AssertionError('missing decisive command result')
                item=json.loads(line)
                if item['stage']=='fault-ready':loss=kill_owned_tree(item);continue
                if item['stage']=='await-exit':
                    exit_code=helper.wait(timeout=3)
                    owner.stdin.write(json.dumps({'exit_code':exit_code})+'\n');owner.stdin.flush();continue
                expect(item['stage']=='result','unexpected native stage');break
            result=item;result.update(helper_exit=helper.wait(timeout=2),supervisor_exit=owner.wait(timeout=2),
                                     loss_containment=loss,runtime_image_digest=image_digest)
            diagnostic=helper.stderr.read(8192).decode(errors='replace')
            if diagnostic:result['helper_diagnostic']=diagnostic
            diagnostic=owner.stderr.read(8192)
            if diagnostic:result['supervisor_diagnostic']=diagnostic
            result['outside_work_unchanged']=before_sentinel==(sentinel.stat().st_mode,sentinel.stat().st_mtime_ns,sentinel.stat().st_ctime_ns)
            reports.append(result);emit(result) # decisive partial evidence survives later assertion failure
            expect(result['supervisor_exit']==0,'Supervisor source fixture failed')
            expect(result['outside_work_unchanged'],'cross-Evaluation work metadata changed')
            if case.endswith('-loss'):
                expect(result['verdict']=='error' and not result['cleanup'] and loss['all_exited'],
                       'helper loss was not contained and quarantined')
            elif case=='wrong-source-root':
                expect(result['verdict']=='error' and result['helper_exit']==125 and result['facts'] is None
                       and not result['cleanup'],'wrong immutable source root was not refused')
            else:
                expect(result['helper_exit']==0 and result['post_target'] and result['cleanup'],'native lifecycle proof missing')
                expected='failed' if case in ('nonzero','timeout','output','network','group-escape','async-owner','async-flags','outside-chmod','outside-utime') else 'passed'
                if case=='work-limit':
                    bounded=(result['verdict']=='passed'
                        and bytes.fromhex(result['facts']['stdout']['tail_hex'])==b'hard work quota enforced\n')
                    expect(bounded,'work capacity not enforced')
                else:expect(result['verdict']==expected,'unexpected command adjudication')
                fact=result['facts']['exit']
                expect(fact['whole_tree_exited'] and fact['work_cleaned'],'whole-tree/work proof missing')
                if case=='timeout':expect(fact['timed_out'] and fact['descendants_terminated'],'surviving child deadline not enforced')
                if case=='output':expect(fact['output_limited'],'output bound not enforced')
                if case in ('network','group-escape','async-owner','async-flags','outside-chmod','outside-utime'):expect(fact['signal']==signal.SIGSYS,'intended syscall denial not reached')
        complete=True
    finally:
        safe=True
        for process in reversed(processes):
            try:
                if process.poll() is None:process.kill()
                process.wait(timeout=2)
            except Exception:safe=False
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None:stream.close()
        if complete and safe:
            for path in reversed(mounts):subprocess.run(['/usr/bin/umount',str(path)],check=True,timeout=2)
            expect(identity(root)==root_identity and shutil.rmtree.avoids_symlink_attacks,'fixture cleanup ownership lost')
            shutil.rmtree(root)
        else:emit({'stage':'quarantine','path':str(root),'cleanup_claimed':False})
    expect(complete and safe,'fixture cleanup unconfirmed')
    emit({'stage':'summary','check':'command-linux-smoke','cases':len(reports),
          'seconds':round(time.monotonic()-started,3),'binary_sha256':digests,'fixture_cleanup':True,
          'native_qualification':False,'tested_revision':os.environ.get('GITHUB_SHA'),
          'source_sha256':source_hashes,
          'scope':'mapped Linux configured Python revision test+static child/work/limits/loss proof; not Docker/SELinux/fullVM'})


def main():
    if len(sys.argv)==5 and sys.argv[1]=='--supervisor':
        expect(sys.argv[3] in CASES,'unknown native case');supervisor_case(*sys.argv[2:]);return
    if len(sys.argv)==7 and sys.argv[1]=='--namespace-helper':namespace_helper(*sys.argv[2:]);return
    expect(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
           and os.environ.get('RUNNER_OS')=='Linux','owned GitHub-hosted Linux root fixture required')
    if sys.argv[1:]==['--isolated']:
        isolated();return
    expect(sys.argv[1:]==['--run'],'explicit --run required')
    # Killing the private PID-namespace init also kills every remaining fixture
    # descendant; no host-wide PID/group guesses on failure or wall timeout.
    result=subprocess.run(['/usr/bin/unshare','--mount','--pid','--fork','--kill-child=KILL','--mount-proc','--',
        sys.executable,str(Path(__file__).resolve()),'--isolated'],timeout=60)
    expect(result.returncode==0,'isolated hosted command fixture failed')


if __name__=='__main__':main()
