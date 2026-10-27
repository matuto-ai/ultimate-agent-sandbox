#!/usr/bin/env python3
"""Hosted-only external Broker UID/credential/executable integration; no accounts.

Uses numeric transient process identities, never creates host users or modifies
security policy. All files/ownership belong to this uniquely created temp tree.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))


def real_gh_version(root):
    """Offline evidence only: held runner executable, no provider/API request."""
    executable=shutil.which('gh',path='/usr/bin:/bin:/usr/local/bin')
    if executable is None:raise AssertionError('hosted runner has no installed gh')
    executable=Path(executable).resolve(strict=True)
    home=root/'real-gh-empty-home';home.mkdir(mode=0o700);os.chown(home,65531,65531)
    fd=os.open(executable,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        def pinned_digest():
            node=os.fstat(fd)
            # Root can maintain the runner installation; the transient UID and
            # every unprivileged group must be unable to modify the executable.
            if (not stat.S_ISREG(node.st_mode) or node.st_uid!=0 or node.st_mode&0o022
                    or not node.st_mode&0o111 or not 0<node.st_size<=128*1024*1024):
                raise AssertionError('runner gh is not a trusted root-owned executable')
            digest=hashlib.sha256();offset=0
            while True:
                block=os.pread(fd,65536,offset)
                if not block:break
                digest.update(block);offset+=len(block)
                if offset>128*1024*1024:raise AssertionError('runner gh size changed')
            if offset!=node.st_size:raise AssertionError('runner gh size changed')
            return (node.st_dev,node.st_ino,node.st_size),digest.hexdigest()
        identity,digest=pinned_digest()
        result=subprocess.run([f'/proc/self/fd/{fd}','--version'],cwd=home,
            env={'HOME':str(home),'GH_CONFIG_DIR':str(home),'GH_PROMPT_DISABLED':'1',
                 'GH_NO_UPDATE_NOTIFIER':'1','GH_NO_EXTENSION_UPDATE_NOTIFIER':'1','LC_ALL':'C'},
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            pass_fds=(fd,),user=65531,group=65531,extra_groups=(),timeout=3,check=True)
        if pinned_digest()!=(identity,digest):raise AssertionError('held runner gh bytes changed')
        if len(result.stdout)>4096 or result.stderr:raise AssertionError('unexpected gh version output')
        version=result.stdout.decode('utf-8').splitlines()[0]
        if not version.startswith('gh version '):raise AssertionError('not a GitHub CLI version response')
        print(json.dumps({'actual_gh_offline_version':version,'executable_sha256':digest,
                          'provider_requests':False}),flush=True)
    finally:
        os.close(fd)


def run():
    if os.getuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='Linux':
        raise SystemExit('requires explicit disposable hosted Linux root fixture')
    with tempfile.TemporaryDirectory(prefix='uas-forge-read-') as temporary:
        root=Path(temporary);root.chmod(0o755)
        real_gh_version(root)  # Before even the synthetic Actor credentials exist.
        code=root/'code';code.mkdir(mode=0o755);shutil.copytree(ROOT/'uas',code/'uas',ignore=shutil.ignore_patterns('__pycache__'))
        for path in (code/'uas').rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        broker_root=root/'broker';broker_root.mkdir(mode=0o700);os.chown(broker_root,65531,65531)
        supervisor_root=root/'supervisor';supervisor_root.mkdir(mode=0o700);os.chown(supervisor_root,65533,65533)
        token='fixture-only-'+os.urandom(24).hex();other_token='fixture-other-'+os.urandom(24).hex()
        credentials=broker_root/'credentials.json';credentials.write_text(json.dumps({'github.com':{'actor-a':token,'actor-b':other_token}}));credentials.chmod(0o600);os.chown(credentials,65531,65531)
        executable=root/'gh-fixture'
        # gh --include uses LF after status, CRLF after headers and the blank line:
        # https://github.com/cli/cli/blob/v2.87.3/pkg/cmd/api/api.go#L420-L424 (also L540-L555).
        executable.write_text('''#!/usr/bin/python3
import json,os,sys,pathlib
secrets=json.loads(pathlib.Path(%r).read_text())['github.com']
assert os.environ['GH_TOKEN'] in secrets.values() and os.getuid()==65531
actor=next(actor for actor,secret in secrets.items() if secret==os.environ['GH_TOKEN'])
assert set(os.environ)=={'HOME','GH_CONFIG_DIR','GH_HOST','GH_PROMPT_DISABLED','GH_NO_UPDATE_NOTIFIER','GH_NO_EXTENSION_UPDATE_NOTIFIER','GH_PAGER','LC_ALL','GH_TOKEN'}
assert sys.argv[1:7]==['api','--hostname','github.com','--method','GET','--include']
assert sys.argv[-1] in ('repos/owner/repo','repos/other/repo')
repo=sys.argv[-1].removeprefix('repos/')
if actor=='actor-b' and repo=='other/repo':
 print('HTTP/2.0 404 Not Found\\nContent-Type: application/json\\r\\n\\r\\n{}',end='');sys.exit(1)
value={'id':1,'full_name':repo,'private':True,'url':'https://api.github.com/repos/'+repo,'html_url':'https://github.com/'+repo,'default_branch':'main','description':'fixture repository'}
print('HTTP/2.0 200 OK\\nContent-Type: application/json\\r\\n\\r\\n'+json.dumps(value),end='')
''' % str(credentials))
        executable.chmod(0o555)
        from uas.kernel_origin import enable
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        enable(parent);enable(child)
        broker=None;supervisor=None
        try:
            config={'room_id':'alpha','room_instance':'instance-1','project_id':'project','repository':'owner/repo',
                'deployment_id':'deployment','audit_path':str(broker_root/'audit.db'),'result_root':str(broker_root/'results'),
                'credential_path':str(credentials),'gh_executable':str(executable),'gh_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
                'supervisor_uid':65533,'supervisor_gid':65533}
            broker=subprocess.Popen([sys.executable,'-m','uas.forge_read_service',str(child.fileno())],
                cwd=code,env={'PYTHONPATH':str(code),'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                pass_fds=(child.fileno(),),user=65531,group=65531,extra_groups=())
            broker.stdin.write(json.dumps(config)+'\n');broker.stdin.flush();broker.stdin.close();child.close()
            script='''
import json,os,socket,sys
from pathlib import Path
from types import SimpleNamespace
from uas.forge import ForgeBinding
from uas.forge_read_service import ReadBrokerClient
from uas.ledger import Origin,LedgerError
assert os.getuid()==65533
for path in %r:
 try:Path(path).read_bytes()
 except PermissionError:pass
 else:raise AssertionError('external Broker credential/cache readable')
assert 'GH_TOKEN' not in os.environ
class Supervisor:
 room_id='alpha'
 def _read(self):return {'phase':'running','instance_id':'instance-1','spec':{'project_id':'project'}}
supervisor=Supervisor()
client=ReadBrokerClient(socket.socket(fileno=int(sys.argv[1])),supervisor,ForgeBinding('alpha','project','owner/repo'),'instance-1',worker_uid=65531,worker_gid=65531)
origin=Origin('actor-a','alice','inc-1','epoch-1',('forge-read',))
for n,repo in enumerate(('owner/repo','other/repo')):
 packet=client.prepare({'id':'read-'+str(n),'kind':'forge-read','argv':['repo','view','-R',repo]},origin)
 result=client.perform(packet)
 assert result['observation']['status']=='OK',result
 assert result['observation']['data']['full_name']==repo,result
 retry=client.prepare({'id':'read-'+str(n),'kind':'forge-read','argv':['repo','view','-R',repo]},origin)
 assert client.perform(retry)==result
other=Origin('actor-b','bob','inc-b','epoch-b',('forge-read',))
packet=client.prepare({'id':'read-other-actor','kind':'forge-read','argv':['repo','view','-R','other/repo']},other)
denied=client.perform(packet)['observation']
assert denied['status']=='NOT_FOUND' and denied['completeness']=='unknown',denied
packet=client.prepare({'id':'read-1','kind':'forge-read','argv':['repo','view','-R','other/repo']},other)
try:client.perform(packet)
except LedgerError as error:assert error.code=='ID_CONFLICT',error
else:raise AssertionError('other Actor replayed first Actor result')
missing=Origin('actor-c','charlie','inc-c','epoch-c',('forge-read',))
packet=client.prepare({'id':'read-missing-actor','kind':'forge-read','argv':['repo','view','-R','other/repo']},missing)
assert client.perform(packet)['observation']['status']=='CREDENTIAL_UNAVAILABLE'
packet=client.prepare({'id':'denied','kind':'forge-read','argv':['api','user']},origin)
assert client.perform(packet)['observation']['status']=='UNSUPPORTED_ROUTE'
client.denied('WRONG_PROCESS')
client.close()
print(json.dumps({'external_broker_uid':65531,'supervisor_uid':65533,'read':'OK','same_forge_read':'OK','other_actor':'NOT_FOUND','missing_actor':'CREDENTIAL_UNAVAILABLE','cross_actor_replay':'ID_CONFLICT','private_credentials':'denied','raw_api':'denied','replay':'same-result'}))
''' % [str(credentials),str(broker_root/'audit.db')]
            supervisor=subprocess.Popen([sys.executable,'-c',script,str(parent.fileno())],cwd=code,
                env={'PYTHONPATH':str(code),'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,pass_fds=(parent.fileno(),),
                user=65533,group=65533,extra_groups=())
            parent.close();out,err=supervisor.communicate(timeout=20)
            if supervisor.returncode:raise AssertionError('Supervisor smoke failed: '+err[-4000:])
            assert all(secret not in out and secret not in err for secret in (token,other_token))
            print(out.strip(),flush=True)
            broker.wait(timeout=5)
            # Closing the owned private channel fences the worker; it cannot
            # accidentally keep a shared bearer endpoint alive for another seat.
            assert broker.poll() is not None
            for path in broker_root.glob('audit.db*'):
                assert all(secret.encode() not in path.read_bytes() for secret in (token,other_token))
        finally:
            parent.close();child.close()
            for process in (supervisor,broker):
                if process is not None:
                    if process.poll() is None:process.kill()
                    process.wait(timeout=5)
                    for stream in (process.stdout,process.stderr):
                        if stream is not None:stream.close()

if __name__=='__main__':run()
