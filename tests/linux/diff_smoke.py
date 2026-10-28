#!/usr/bin/env python3
"""Explicit <=30s GitHub-hosted exact-pair/native-diff fixture, never local QA.

Actual copied-Git materialization, mapped identity, private user/mount namespace,
RO roots, static bootstrap/evaluator, SCM_PIDFD, ACK/exit, postproof and cleanup.
Synthetic allocator/lifecycle/subject and resource admission are fixture-owned;
this is NOT Docker, SELinux, quota, live Forge or complete VM qualification.
Imports have no filesystem, process, namespace, socket or privilege effects.
"""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import zlib

ROOT=Path(__file__).resolve().parents[2]
HOST_SUPERVISOR=165533
HOST_HELPER=165530
DEADLINE_SECONDS=30
CASES=('positive','wrong-root','mutated-after-exit','cleanup-identity-loss','symlink-before-launch','missing-ack')
EXPECTED=['added.txt','changed.txt','deleted.txt','mode.txt']

# Fixed transitive Python/native closure; no runtime repository discovery.
SOURCES = (
    'uas/__main__.py',
    'uas/native_qualification.py',
    'uas/native_qualification_backend.py',
    'uas/native_session.py',
    'uas/native_run_admission.py',
    'uas/native_reviewer_recruitment.py',
    'uas/native_reviewer_reset.py',
    'uas/native_claude_retirement.py',
    'uas/native_admission_broker.py',
    'uas/native_checkout_handoff.py',
    'uas/native_image_package.py',
    'uas/guest_fixture.py',
    'uas/docker_exec_api.py',
    'uas/workstation_service.py',
    'uas/workstation_probe.py',
    'uas/workstation_hub.py',
    'uas/claude_native_admission.py',
    'uas/gate_identity.py',
    'uas/git_process.py',
    'uas/git_provenance.py',
    'uas/git_source_proof.py',
    'uas/lifecycle_scenario.py',
    'uas/native_claude_recipe.py',
    'uas/native_claude_runtime.py',
    'uas/native_helper.py',
    'uas/native_host_forge.py',
    'uas/native_review_host.py',
    'uas/workstation_admission.py',
    'uas/workstation_control.py',
    'uas/workstation_peer.py',

    'uas/manager_actions.py', 'uas/manager_lifecycle.py',
    'tests/linux/mapped_namespace.py',
    'uas/__init__.py',
    'uas/manager_owner.py', 'uas/manager_projection.py', 'uas/manager_journey.py',
    'uas/run_review.py', 'uas/gate_hub.py',
    'uas/gate_command_hub.py',
    'uas/artifact_helper.py',
    'uas/artifact_paths.py',
    'uas/artifact_protocol.py',
    'uas/artifact_target.py',
    'uas/checkout_scope.py',
    'uas/checkout_writers.py',
    'uas/checkouts.py',
    'uas/claude_fixture.py',
    'uas/claude_participant.py',
    'uas/claude_runtime.py',
    'uas/config.py',
    'uas/context.py',
    'uas/diff_protocol.py',
    'uas/diff_target.py',
    'uas/docker_fixture.py',
    'uas/forge.py',
    'uas/forge_assignment.py',
    'uas/forge_audit.py',
    'uas/forge_mutations.py',
    'uas/forge_projection_broker.py',
    'uas/forge_projections.py',
    'uas/forge_read.py',
    'uas/forge_read_provider.py',
    'uas/forge_read_service.py',
    'uas/forge_wire.py',
    'uas/gate_diff_hub.py',
    'uas/gate_evaluation.py',
    'uas/gate_forge.py',
    'uas/gate_policy.py',
    'uas/gate_repository.py',
    'uas/git_audit.py',
    'uas/git_policy.py',
    'uas/github_assignment.py',
    'uas/github_executor.py',
    'uas/github_logs.py',
    'uas/github_mutation_routes.py',
    'uas/github_mutations.py',
    'uas/github_pr.py',
    'uas/github_read.py',
    'uas/github_reconciliation.py',
    'uas/github_routes.py',
    'uas/github_surface.py',
    'uas/kernel_origin.py',
    'uas/launch.py',
    'uas/ledger.py',
    'uas/lifecycle.py',
    'uas/participant.py', 'uas/participant_recovery.py',
    'uas/peer.py',
    'uas/pi_fixture.py',
    'uas/pi_runtime.py',
    'uas/review_broker.py',
    'uas/run_admission.py',
    'uas/run_control.py',
    'uas/run_coordination.py',
    'uas/run_requests.py',
    'uas/workstation_exec.py',
    'uas/native_pi_recipe.py',
    'uas/runtime_provider.py',
    'tests/linux/diff_smoke.py',
    'runtime/workstation/diff_bootstrap.c',
    'runtime/workstation/diff_evaluator.c',
    'runtime/workstation/artifact_protocol.h',
)
MAX_SOURCE_FILES=128
MAX_SOURCE_BYTES=256<<10
MAX_SOURCE_TOTAL=2<<20


def expect(value,message):
    if not value:raise AssertionError(message)


def emit(value):
    print(json.dumps(value,sort_keys=True),flush=True)


def identity(path):
    node=Path(path).stat();return [node.st_dev,node.st_ino]


def _source_directory(path):
    """Open every absolute ancestor without following any symlink."""
    path=Path(path)
    expect(path.is_absolute() and '..' not in path.parts,'absolute ordinary source root required')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    descriptor=os.open('/',flags)
    try:
        for part in path.parts[1:]:
            child=os.open(part,flags,dir_fd=descriptor)
            previous,descriptor=descriptor,child;os.close(previous)
        result,descriptor=descriptor,-1
        return result
    finally:
        if descriptor>=0:os.close(descriptor)


def _source_bytes(root,relative):
    parts=Path(relative).parts
    expect(type(relative) is str and not Path(relative).is_absolute()
           and parts and all(part not in ('','.', '..') for part in parts)
           and '/'.join(parts)==relative,'literal source path required')
    parent=os.dup(root);descriptor=-1
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    def stamp(node):
        return (node.st_dev,node.st_ino,node.st_mode,node.st_nlink,node.st_size,node.st_mtime_ns,node.st_ctime_ns)
    try:
        for part in parts[:-1]:
            child=os.open(part,flags,dir_fd=parent)
            previous,parent=parent,child;os.close(previous)
        descriptor=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
        before=os.fstat(descriptor)
        expect(stat.S_ISREG(before.st_mode) and before.st_nlink==1
               and before.st_size<=MAX_SOURCE_BYTES,'bounded ordinary source required')
        with os.fdopen(descriptor,'rb') as stream:
            descriptor=-1;data=stream.read(MAX_SOURCE_BYTES+1);after=os.fstat(stream.fileno())
        named=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        expect(stamp(before)==stamp(after)==stamp(named) and len(data)==before.st_size,
               'source changed while staging')
        return data
    finally:
        if descriptor>=0:os.close(descriptor)
        os.close(parent)


def stage_sources(root, *, extra_paths=()):
    """Root-owned bounded exact source copies; never chmod runner paths.

    Shared only by explicit hosted fixtures. Extra paths are fixed caller-owned
    source constants, not CLI inputs. Files/ancestors are NOFOLLOW; the staged
    source root is the ROOT used by all subsequently lowered-identity children.
    """
    expect(os.geteuid()==0,'root-owned source staging required')
    expect(type(extra_paths) in (tuple,list),'fixed extra source sequence required')
    sources=tuple(dict.fromkeys((*SOURCES,*extra_paths)))
    expect(len(sources)<=MAX_SOURCE_FILES,'source file count bound exceeded')
    destination=Path(root)/'source';destination.mkdir(mode=0o755)
    source=_source_directory(ROOT);source_identity=os.fstat(source)
    total=0;hashes={};directories={destination}
    try:
        for relative in sources:
            data=_source_bytes(source,relative);total+=len(data)
            expect(total<=MAX_SOURCE_TOTAL,'source payload byte bound exceeded')
            output=destination/relative;parent=destination
            for name in Path(relative).parts[:-1]:
                parent=parent/name
                if parent not in directories:
                    parent.mkdir(mode=0o755);directories.add(parent)
            descriptor=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444)
            with os.fdopen(descriptor,'wb') as stream:
                stream.write(data);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o444)
            digest=hashlib.sha256(data).hexdigest()
            expect(hashlib.sha256(output.read_bytes()).hexdigest()==digest,'source copy differs')
            hashes[relative]=digest
        fresh=_source_directory(ROOT)
        try:
            now=os.fstat(fresh)
            expect((now.st_dev,now.st_ino)==(source_identity.st_dev,source_identity.st_ino),'source root replaced while staging')
        finally:os.close(fresh)
    finally:os.close(source)
    for directory in sorted(directories,key=lambda path:len(path.parts),reverse=True):directory.chmod(0o555)
    return destination,hashes


def source_fixture(root):
    """Write only inert synthetic Git objects; production reader verifies hashes."""
    root=Path(root)
    repo=root/'repo';repo.mkdir(mode=0o700)
    common=repo/'.git';common.mkdir(mode=0o700)
    (common/'objects').mkdir();(common/'objects/pack').mkdir();(common/'objects/info').mkdir()
    (common/'refs/heads').mkdir(parents=True)
    def obj(kind,data):
        encoded=kind.encode()+b' '+str(len(data)).encode()+b'\0'+data
        oid=hashlib.sha1(encoded).hexdigest();directory=common/'objects'/oid[:2]
        directory.mkdir(exist_ok=True);(directory/oid[2:]).write_bytes(zlib.compress(encoded))
        return oid
    def commit(files,parent=None):
        raw=b''
        for name,(mode,data) in sorted(files.items()):
            raw+=str(mode).encode()+b' '+name.encode()+b'\0'+bytes.fromhex(obj('blob',data))
        tree=obj('tree',raw)
        body=('tree '+tree+'\n'+('parent '+parent+'\n' if parent else '')+
              'author Fixture <fixture@invalid> 0 +0000\ncommitter Fixture <fixture@invalid> 0 +0000\n\nfixture\n').encode()
        return obj('commit',body)
    base=commit({'changed.txt':(100644,b'base\n'),'deleted.txt':(100644,b'remove\n'),
                 'mode.txt':(100644,b'same mode bytes\n'),'unchanged.txt':(100644,b'unchanged\n')})
    head=commit({'added.txt':(100644,b'added\n'),'changed.txt':(100644,b'head\n'),
                 'mode.txt':(100755,b'same mode bytes\n'),'unchanged.txt':(100644,b'unchanged\n')},base)
    (common/'HEAD').write_bytes(b'ref: refs/heads/main\n')
    (common/'refs/heads/main').write_text(head+'\n')
    # This dirty working copy must never become the materialized target.
    (repo/'changed.txt').write_text('dirty checkout must not be observed\n')
    slots=root/'slots';slots.mkdir(mode=0o700)
    control=root/'control';control.mkdir(mode=0o700)
    room={'id':'diff-room','project':{'id':'diff-project','repository':'fixture/repository'}}
    lifecycle={'phase':'running','instance_id':'diff-instance',
               'spec':{'project_id':'diff-project','project_paths':[str(repo),str(slots)]}}
    manifest=control/'checkouts.json'
    manifest.write_text(json.dumps({'version':1,'room_id':'diff-room','instance_id':'diff-instance',
        'project_id':'diff-project','repo':str(repo),'root':str(slots),'common':str(common),
        'filesystem':{'repo':identity(repo),'root':identity(slots),'common':identity(common)},
        'slots':{'primary':{'path':str(repo),'branch':'refs/heads/main','base':base,
            'run':'diff-run','participant':'builder','active':True,'phase':'ready',
            'identity':{'directory':identity(repo),'git_metadata':identity(common)}}}}))
    supervisor=SimpleNamespace(directory=control,_locked=lambda:nullcontext(),_read=lambda:deepcopy(lifecycle))
    allocator=SimpleNamespace(supervisor=supervisor,room=room,repo=repo,root=slots,manifest=manifest)
    subject={'repository':'fixture/repository','pull_number':1,'pull_id':101,
             'base_sha':base,'head_sha':head,'base_ref':'main'}
    return supervisor,allocator,subject


def wait_exit(origin,seconds=16):
    from uas.kernel_origin import alive,_identity
    poller=select.poll();poller.register(origin.pidfd,select.POLLIN)
    events=poller.poll(int(seconds*1000))
    expect(events and events[0][1]&select.POLLIN,'exact helper exit not observed')
    expect(_identity(origin.pidfd)==origin.identity and not alive(origin.pidfd),'helper task identity/exit unknown')


def supervisor_case(root,case):
    sys.path.insert(0,str(ROOT))
    from uas.artifact_helper import GateOffer
    from uas.artifact_protocol import ArtifactError
    from uas.artifact_target import ArtifactSourceResolver
    from uas.diff_protocol import PROFILE_ID
    from uas.diff_target import DiffSourceResolver,DiffTargets,DIFF_RESERVATION_BYTES
    from uas.gate_diff_hub import DiffGateHub
    from uas.kernel_origin import HeldOrigin,enable,receive
    expect(os.getuid()==HOST_SUPERVISOR and os.getgid()==HOST_SUPERVISOR,'fixed Supervisor UID required')
    expect(HOST_HELPER in os.getgroups(),'fixed mapped helper group required')
    root=Path(root);supervisor,allocator,subject=source_fixture(root)
    scratch=root/'targets';scratch.mkdir(mode=0o711)
    journal=root/'targets-journal';journal.mkdir(mode=0o700)
    scope={'version':1,'evaluation_id':'diff-'+case,'room_id':'diff-room','room_instance':'diff-instance',
        'project_id':'diff-project','repository':'fixture/repository','run_id':'diff-run','generation':1,
        'participant_id':'builder','policy_id':'fixture','policy_version':1,'policy_digest':'d'*64,
        'gate_id':'diff','config_digest':'e'*64}
    config={'allowed_paths':EXPECTED,'forbidden_paths':[],'require_nonempty':True}
    reservations=[]
    def reserve(value,amount):
        expect(value==scope and amount==DIFF_RESERVATION_BYTES,'pair reservation mismatch')
        reservations.append(amount);return True # explicit synthetic quota owner
    resolver=DiffSourceResolver(ArtifactSourceResolver(supervisor,allocator))
    source=resolver.resolve('diff-run','builder','diff-instance',subject)
    targets=DiffTargets(scratch,journal,resolver,reserve_capacity=reserve)
    pair=targets.prepare(scope,source);lease=targets.lease(pair)
    expect(pair['base']['head_sha']==subject['base_sha'] and pair['head']['head_sha']==subject['head_sha'],'exact pair mismatch')
    expect((scratch/pair['head']['target_id']/'tree/changed.txt').read_bytes()==b'head\n','dirty checkout influenced target')
    row={'evaluation_id':scope['evaluation_id'],'scope':scope,'config':config,'declaration':{'paths':EXPECTED}}
    facts=None;error=None;post=False;clean=False;offer=None;origin=None
    if case=='symlink-before-launch':
        file=scratch/pair['base']['target_id']/'tree/changed.txt'
        file.parent.chmod(0o755);file.unlink();file.symlink_to('/etc/passwd');file.parent.chmod(0o555)
        try:lease.recheck()
        except ArtifactError as invalid:error=invalid.code
        expect(error is not None,'symlink admitted before launch')
        try:clean=lease.cleanup()
        except ArtifactError:clean=False
        checks,verdict=DiffGateHub._checks(row,None,error)
        emit({'stage':'result','case':case,'verdict':verdict,'error':error,'native_launched':False,
              'cleanup':clean,'reservations':reservations,'checks':checks})
        return
    endpoint=root/'gate';endpoint.mkdir(mode=0o710);os.chown(endpoint,-1,HOST_HELPER)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    listener.bind(str(endpoint/'gate.sock'));os.chmod(endpoint/'gate.sock',0o620);os.chown(endpoint/'gate.sock',-1,HOST_HELPER)
    enable(listener);listener.listen(1);listener.settimeout(5)
    challenge=hashlib.sha256(('fixture-'+case).encode()).digest()
    lease.recheck();lease.mark_launch_possible()
    emit({'stage':'prepared','case':case,'targets':str(scratch),'endpoint':str(endpoint),
          'challenge':challenge.hex(),'pair':pair})
    channel=None
    try:
        channel,_=listener.accept();enable(channel);channel.settimeout(16)
        with receive(channel) as record:
            expect(record.data==b'AGH1'+challenge,'challenge mismatch')
            expect(record.credentials[1:]==(HOST_HELPER,HOST_HELPER),'helper mapped identity mismatch')
            origin=HeldOrigin(record)
        release=b'DGR1'+pair['base']['target_id'].encode()+pair['head']['target_id'].encode()
        expect(channel.send(release)==len(release),'release uncertain')
        requested=deepcopy(pair)
        if case=='wrong-root':requested['base']['inode']+=1
        document={'scope':scope,'target':requested,'profile':PROFILE_ID,
                  'profile_digest':'f'*64,'mapping_digest':'a'*64,'receiver_context':'fixture',
                  'origin_identity':list(origin.identity)}
        offer=GateOffer(document,channel,origin,config);channel=None
        reducer=object.__new__(DiffGateHub)
        try:
            facts,final=reducer._observations(offer,row,requested)
            if case=='missing-ack':
                error='FIXTURE_FINAL_ACK_WITHHELD'
                wait_exit(origin)
            else:
                offer.acknowledge_final(final);offer.confirm_exit()
        except Exception as invalid:
            error=getattr(invalid,'code','FIXTURE_NATIVE_EVIDENCE_ERROR')
            wait_exit(origin)
        lease.mark_exit_confirmed()
        if case=='mutated-after-exit':
            file=scratch/pair['base']['target_id']/'tree/changed.txt'
            file.chmod(0o644);file.write_bytes(b'mutation\n');file.chmod(0o444)
        try:post=lease.postverify()==pair
        except ArtifactError as invalid:error=invalid.code
        if case=='cleanup-identity-loss':
            base=scratch/pair['base']['target_id'];base.rename(scratch/('quarantined-'+pair['base']['target_id']))
            base.mkdir(mode=0o710);os.chown(base,-1,HOST_HELPER)
        try:clean=lease.cleanup()
        except ArtifactError as invalid:error=invalid.code
        checks,verdict=DiffGateHub._checks(row,facts,error)
        reductions={}
        if case=='positive' and facts is not None and error is None:
            # These are native-fact reducer checks, NOT new authenticated Gate
            # Evaluations or a claim that the helper ran under another config.
            # The complete observed path set is compared without relaunch.
            variants={
                'omitted-claim':{**row,'declaration':{'paths':EXPECTED[:-1]}},
                'extra-claim':{**row,'declaration':{'paths':sorted([*EXPECTED,'unobserved.txt'])}},
                'forbidden-path':{**row,'config':{**config,'forbidden_paths':['added.txt']}}}
            for name,variant in variants.items():
                reduced_checks,reduced_verdict=DiffGateHub._checks(variant,facts,None)
                reductions[name]={'verdict':reduced_verdict,'checks':reduced_checks}
        emit({'stage':'result','case':case,'verdict':verdict,'error':error,'native_launched':True,
            'post_target':post,'cleanup':clean,'actual_paths':None if facts is None else facts['paths'],
            'reservations':reservations,'checks':checks,'native_fact_reductions':reductions,
            'origin_identity':list(origin.identity),
            'child_phases':[child.phase for child in lease._leases()],
            'base_sha':subject['base_sha'],'head_sha':subject['head_sha']})
    finally:
        if offer is not None:offer.close()
        elif origin is not None:origin.close()
        if channel is not None:channel.close()
        listener.close()


def namespace_helper(rootfs,targets,endpoint):
    """Root only inside private mapped user/mount namespaces; no host mounts."""
    expect(os.getuid()==0 and os.getgid()==0,'mapped namespace root required')
    mapping=Path('/proc/self/uid_map').read_text().split()
    expect(mapping==['0','100000','65536'],'unexpected fixed UID mapping')
    expect(Path('/proc/self/gid_map').read_text().split()==mapping,'unexpected fixed GID mapping')
    def mount(*args):subprocess.run(['/usr/bin/mount',*args],check=True,timeout=2,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
    mount('--make-rprivate','/')
    rootfs=Path(rootfs)
    mount('--bind',targets,str(rootfs/'uas/gate-targets'))
    mount('-o','remount,bind,ro,nodev,nosuid,noexec',str(rootfs/'uas/gate-targets'))
    mount('--bind',endpoint,str(rootfs/'uas/gate'))
    mount('--bind','/dev/null',str(rootfs/'dev/null'))
    os.chroot(rootfs);os.chdir('/')
    os.setgroups([]);os.setgid(65530);os.setuid(65530)
    os.execve('/opt/uas/bin/diff-bootstrap',['/opt/uas/bin/diff-bootstrap'],{})


def build(root, *, source_root=ROOT):
    installed=root/'binaries';installed.mkdir(mode=0o755)
    digests={}
    for name in ('diff_bootstrap','diff_evaluator'):
        output=installed/name.replace('_','-')
        subprocess.run(['/usr/bin/gcc','-std=c11','-Wall','-Wextra','-Werror','-O2',
            '-fstack-protector-strong','-static','-Wl,-z,noexecstack','-Wl,-z,relro','-Wl,-z,now',
            str(Path(source_root)/'runtime/workstation'/(name+'.c')),'-o',str(output)],check=True,timeout=5)
        output.chmod(0o555);digests[name]=hashlib.sha256(output.read_bytes()).hexdigest()
    return installed,digests


def make_rootfs(path,installed):
    path.mkdir(mode=0o755)
    for directory in ('uas','uas/gate','uas/gate-targets','opt','opt/uas','opt/uas/bin','dev'):
        (path/directory).mkdir(mode=0o755)
    (path/'dev/null').touch(mode=0o444)
    for name in ('diff-bootstrap','diff-evaluator'):
        shutil.copyfile(installed/name,path/'opt/uas/bin'/name);(path/'opt/uas/bin'/name).chmod(0o555)
    # Namespace root is host UID100000, not host root. Only fixture files change.
    for directory,dirs,files in os.walk(path):
        os.chown(directory,100000,100000)
        for name in files:os.chown(Path(directory)/name,100000,100000)


def main():
    from mapped_namespace import mapped_popen
    if len(sys.argv)==4 and sys.argv[1]=='--supervisor':
        expect(sys.argv[3] in CASES,'unknown native case')
        supervisor_case(sys.argv[2],sys.argv[3]);return
    if len(sys.argv)==5 and sys.argv[1]=='--namespace-helper':
        namespace_helper(*sys.argv[2:]);return
    expect(sys.argv[1:]==['--run'],'explicit --run required')
    expect(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
           and os.environ.get('RUNNER_OS')=='Linux','owned GitHub-hosted Linux root fixture required')
    expect(signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK,()),'blocked fatal alarm')
    def expired(*_):raise TimeoutError('diff fixture exceeded 30 seconds')
    signal.signal(signal.SIGALRM,expired);signal.alarm(DEADLINE_SECONDS)
    started=time.monotonic();root=Path(tempfile.mkdtemp(prefix='uas-diff-',dir='/tmp'));root.chmod(0o711)
    root_identity=identity(root);processes=[];complete=False;reports=[]
    try:
        payload,source_hashes=stage_sources(root)
        script=payload/'tests/linux/diff_smoke.py'
        emit({'stage':'source-staged','source_sha256':source_hashes})
        installed,digests=build(root,source_root=payload)
        for index,case in enumerate(CASES):
            case_root=root/('case-'+str(index));case_root.mkdir(mode=0o755);os.chown(case_root,HOST_SUPERVISOR,HOST_SUPERVISOR)
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
            owner=subprocess.Popen(['/usr/bin/python3',str(script),'--supervisor',str(case_root),case],
                user=HOST_SUPERVISOR,group=HOST_SUPERVISOR,extra_groups=[HOST_HELPER],env=env,
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=payload)
            processes.append(owner)
            first=owner.stdout.readline()
            if not first:
                diagnostic=owner.stderr.read(8192)
                emit({'stage':'failure','case':case,'error':'Supervisor preparation failed','diagnostic':diagnostic})
                raise AssertionError('Supervisor preparation failed')
            prepared=json.loads(first);helper=None
            if prepared['stage']=='prepared':
                rootfs=root/('rootfs-'+str(index));make_rootfs(rootfs,installed)
                helper=mapped_popen(['/usr/bin/python3',str(script),'--namespace-helper',str(rootfs),prepared['targets'],prepared['endpoint']],
                    stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env,cwd=payload)
                processes.append(helper);helper.stdin.write(bytes.fromhex(prepared['challenge']));helper.stdin.close()
                terminal=owner.stdout.readline()
                if not terminal:
                    emit({'stage':'failure','case':case,'owner_diagnostic':owner.stderr.read(8192),
                          'helper_diagnostic':helper.stderr.read(8192).decode(errors='replace')})
                    raise AssertionError('missing terminal native evidence')
                result=json.loads(terminal)
                result['helper_exit']=helper.wait(timeout=2)
                diagnostic=helper.stderr.read(8192).decode(errors='replace')
                if diagnostic:result['helper_diagnostic']=diagnostic
            else:result=prepared
            result['supervisor_exit']=owner.wait(timeout=2)
            diagnostic=owner.stderr.read(8192)
            if diagnostic:result['supervisor_diagnostic']=diagnostic
            reports.append(result);emit(result) # preserve decisive evidence BEFORE assertions
            expect(result['supervisor_exit']==0,'Supervisor fixture failed')
            if case=='positive':
                expect(result['verdict']=='passed' and result['actual_paths']==EXPECTED and result['post_target']
                       and result['cleanup'] and result['helper_exit']==0,'native positive diff failed')
                reductions=result['native_fact_reductions']
                expect(set(reductions)=={'omitted-claim','extra-claim','forbidden-path'}
                       and all(item['verdict']=='failed' for item in reductions.values()),
                       'native-fact negative adjudication failed')
                expect(not reductions['omitted-claim']['checks'][0]['ok']
                       and not reductions['extra-claim']['checks'][0]['ok']
                       and reductions['forbidden-path']['checks'][0]['ok']
                       and not reductions['forbidden-path']['checks'][2]['ok'],
                       'native-fact negative Checks did not refute the intended claims')
            else:expect(result['verdict']=='error','negative native case unexpectedly qualified')
            if case=='wrong-root':
                expect(result['helper_exit']==125 and result['actual_paths'] is None
                       and result['post_target'] and result['cleanup'],'wrong-root case failed for an unrelated reason')
            if case=='mutated-after-exit':
                expect(result['helper_exit']==0 and result['actual_paths']==EXPECTED
                       and not result['post_target'] and result['cleanup']
                       and result['error']=='ARTIFACT_TARGET_CHANGED','mutation did not fail exact postproof')
            if case=='symlink-before-launch':
                expect(not result['native_launched'] and result['error']=='ARTIFACT_TARGET_CHANGED'
                       and not result['cleanup'],'symlink admission refusal/uncertain cleanup missing')
            if case=='missing-ack':
                expect(result['helper_exit']!=0 and result['actual_paths']==EXPECTED
                       and result['error']=='FIXTURE_FINAL_ACK_WITHHELD' and result['post_target']
                       and result['cleanup'],'missing-ACK case did not reach final then fatal exit')
            if case=='cleanup-identity-loss':
                expect(result['helper_exit']==0 and result['actual_paths']==EXPECTED and result['post_target']
                       and not result['cleanup'] and result['child_phases']==['quarantined','removed'],'two-sided cleanup evidence missing')
        complete=True
        summary={'stage':'summary','check':'diff-linux-smoke','cases':len(reports),'seconds':round(time.monotonic()-started,3),
            'binary_sha256':digests,'native_qualification':False, 'tested_revision':os.environ.get('GITHUB_SHA'),
            'source_sha256':source_hashes,'staged_sources_verified':True,
            'scope':'exact copied-Git pair + mapped Linux native source profile; no Docker/SELinux/quota/live Forge/fullVM proof'}
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
    summary['fixture_cleanup']=True
    summary['seconds']=round(time.monotonic()-started,3)
    emit(summary)


if __name__=='__main__':main()
