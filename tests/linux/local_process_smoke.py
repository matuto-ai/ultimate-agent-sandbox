#!/usr/bin/env python3
"""Hosted-only real account-free local CLI/process/socket smoke.

A disposable credential-free Library transport is selected, but no native
bindings or Manager: this proves persistent setup and the
operator transport, NOT native Room/Run/Manager operation or uncertain native
effect recovery. Importing this module starts nothing.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
WORK_SECONDS=12
CLI_SECONDS=2


def require(value,reason):
    if not value:raise AssertionError(reason)


def hosted_gate(run):
    require(run and sys.platform=='linux' and os.environ.get('GITHUB_ACTIONS')=='true'
            and os.environ.get('RUNNER_OS')=='Linux' and os.environ.get('UAS_LOCAL_PROCESS_SMOKE')=='1',
            'explicit hosted Linux local process smoke required')


class Smoke:
    def __init__(self,root):
        self.root=root;self.install=root/'install';self.children=[]
        self.started=time.monotonic();self.deadline=self.started+WORK_SECONDS
        self.environment={'PATH':'/usr/bin:/bin','PYTHONPATH':str(ROOT),'PYTHONDONTWRITEBYTECODE':'1'}

    def left(self,ceiling=CLI_SECONDS):
        remaining=self.deadline-time.monotonic()
        require(remaining>0,'bounded process smoke deadline')
        return min(ceiling,remaining)

    def spawn(self,*arguments):
        child=subprocess.Popen([sys.executable,'-m','uas','local','--root',str(self.install),*arguments],
            cwd=ROOT,env=self.environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.children.append(child)
        return child

    def command(self,*arguments,code=0):
        child=self.spawn(*arguments)
        out,error=child.communicate(timeout=self.left())
        require(child.returncode==code,'unexpected CLI exit for '+arguments[0])
        require(len(out)<=65536 and not error,'bounded clean CLI output required')
        return json.loads(out)

    def endpoint(self,host):
        endpoint=self.install/'operator.sock'
        while True:
            self.left(3);require(host.poll() is None,'owner exited before listener ready')
            try:
                node=endpoint.lstat()
                require(stat.S_ISSOCK(node.st_mode) and node.st_uid==os.geteuid(),'actual socket owner')
                with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as channel:
                    channel.settimeout(self.left(1));channel.connect(str(endpoint))
                    pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    require((pid,uid,gid)==(host.pid,os.geteuid(),os.getegid()),'actual host peer identity')
                return endpoint,(node.st_dev,node.st_ino)
            except (FileNotFoundError,ConnectionRefusedError):time.sleep(.02)

    def wire(self,endpoint,raw,*,disconnect=False):
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as channel:
            channel.settimeout(self.left(1));channel.connect(str(endpoint));channel.sendall(raw)
            if disconnect:return None
            result=channel.recv(65537);require(0<len(result)<=65536,'bounded operator reply')
            return json.loads(result)

    def stop_host(self,host):
        require(host.poll() is None,'retained owner must still be alive')
        host.terminate()  # Exact Popen owned here, never PID from external state.
        out,error=host.communicate(timeout=self.left(2))
        require(host.returncode==0 and not error and json.loads(out)=={'state':'host-stopped'},'SIGTERM orderly shutdown')
        require(not os.path.lexists(self.install/'operator.sock'),'owned endpoint removed')

    def exercise(self):
        # The installed host now requires Library selection. Keep the original
        # process/socket proof with a real disposable Git target, not a mocked
        # Library or a production credential/provider. This is not qualification.
        sys.path.insert(0,str(ROOT/'tests'))
        import library_support
        project=self.root/'project.json'
        config=json.loads((ROOT/'tests/fixtures/two-rooms.json').read_text())
        config['deployment']['state_root']=str(self.root/'state')
        for room in config['rooms']:
            room['state_root']=str(self.root/'state'/room['id'])
            for name in room['project']['roots']:
                room['project']['roots'][name]=str(self.root/'projects'/room['id']/name)
            Path(room['project']['roots']['reference']).mkdir(parents=True)
        original=json.dumps(config).encode();project.write_bytes(original)
        canonical=self.root/'canonical.git'
        subprocess.run(['/usr/bin/git','init','--bare','-q',str(canonical)],check=True,
                       timeout=self.left(),env=self.environment)
        transport=self.root/'git-transport.py'
        transport.write_text("#!/usr/bin/python3\nimport os,shlex,sys\n"
            "args=sys.argv[1:]\n"
            "if '-G' in args: raise SystemExit(1)\n"
            "command=shlex.split(args[-1])\n"
            "assert args[-2]=='git@library.invalid'\n"
            "assert len(command)==2 and command[0] in ('git-upload-pack','git-receive-pack') and command[1]=='/library.git'\n"
            "os.execv('/usr/bin/'+command[0],[command[0],"+repr(str(canonical))+"])\n")
        self.environment['GIT_SSH_COMMAND']='/usr/bin/python3 '+str(transport)
        settings=library_support.document()
        settings['repository'].update(target='ssh://git@library.invalid/library.git',credential_ref='alice-git')
        library_path=self.root/'library.json'
        library_path.write_text(json.dumps({'version':1,'settings':settings,
            'credentials':{'alice-git':{'environment':['GIT_SSH_COMMAND']}},
            'rooms':{'alpha':{'source_identity':'1001'},'beta':{'source_identity':'1002'}},
            'qualification':{'evidence':{'version':1,'target':settings['repository']['target'],
                'branch':settings['repository']['branch'],'qualified':True}},
            'model':{'profile':{'reference':'synth-local','placement':'local','provider':'fixture',
                'version':'v1','endpoint':'http://127.0.0.1:1/unused','region':'local',
                'retention':'zero','terms':'fixture-only'},'command':['/bin/false']}}))
        from fixture_library_selection import write_selection
        from uas.library import project_binding
        library_doc=json.loads(library_path.read_text())
        library_doc['model']['selection']=write_selection(self.root/'model-evidence.json',
            profile=library_doc['model']['profile'], command=library_doc['model']['command'],
            bindings=[project_binding(room['project'],source_identity=library_doc['rooms'][room['id']]['source_identity'])
                      for room in config['rooms']])
        library_path.write_text(json.dumps(library_doc))
        selection={'version':1,'project':{'path':str(project),'sha256':hashlib.sha256(original).hexdigest()},
                   'native':None,'manager':None,
                   'library':{'path':str(library_path),'sha256':hashlib.sha256(library_path.read_bytes()).hexdigest()}}
        selected=self.root/'selection.json';selected.write_text(json.dumps(selection))
        require(self.command('setup',str(selected))['status']=='installed','real setup')
        saved=(self.install/'installation.json').read_bytes()
        require(self.command('setup',str(selected))['status']=='already-installed','persistent idempotent setup')
        inspection=self.command('inspect');require(inspection['native']=='not-configured','native binding absent')
        host=self.spawn('serve');endpoint,identity=self.endpoint(host)
        collision=self.command('serve',code=3)
        require(collision['outcome']=='unknown' and collision['error']=='LOCAL_HOST_ALREADY_ACTIVE','exclusive host lock')
        require(host.poll() is None,'collision must not terminate first owner')
        for action,code in (('start',3),('status',0),('stop',3)):
            result=self.command(action,'--room','alpha',code=code)
            require(result['outcome']=='observed' and result['result']['state']=='not-configured'
                    and result['result']['missing']==['native-installation'],'truthful no-native result')
        # The caller disappears after submitting a read-only status; there is
        # deliberately no native effect whose completion could be inferred.
        self.wire(endpoint,b'{"action":"status","room_id":"alpha"}',disconnect=True)
        malformed=self.wire(endpoint,b'{')
        require(malformed['outcome']=='unknown','malformed request unknown response')
        status=self.command('status','--room','alpha')
        require(status['result']['state']=='not-configured','post-disconnect no-start observation')
        require((endpoint.stat().st_dev,endpoint.stat().st_ino)==identity,'same retained socket owner')
        self.stop_host(host)
        require(project.read_bytes()==original and (self.install/'installation.json').read_bytes()==saved,'configuration preserved')
        restarted=self.spawn('serve');self.endpoint(restarted)
        require(self.command('status','--room','alpha')['result']['state']=='not-configured','persistent restart')
        self.stop_host(restarted)
        require((self.install/'installation.json').read_bytes()==saved,'restart preserves installation')
        return {'status':'passed','scope':'account-free-cli-process-and-operator-socket',
                'native_room_run_manager':'not-exercised','native_uncertain_effect_recovery':'not-exercised',
                'elapsed_seconds':round(time.monotonic()-self.started,3)}

    def cleanup(self):
        # At most one command and one host can remain live. Fixed cleanup budget
        # stays below the15s external ceiling without process-group/PID scans.
        failures=[]
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=.5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    try:child.wait(timeout=.5)
                    except subprocess.TimeoutExpired:failures.append('owned child did not exit')
            for stream in (child.stdout,child.stderr):
                if stream is not None:stream.close()
        require(not failures,'; '.join(failures))


def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--run',action='store_true')
    args=parser.parse_args(argv);hosted_gate(args.run)
    with tempfile.TemporaryDirectory(prefix='uas-local-',dir='/tmp') as directory:
        smoke=Smoke(Path(directory))
        try:result=smoke.exercise()
        finally:smoke.cleanup()
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
