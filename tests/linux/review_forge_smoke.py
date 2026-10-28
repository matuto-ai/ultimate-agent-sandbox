#!/usr/bin/env python3
"""Hosted-only bounded actual private Broker + Run/Review/Gate/dispatcher seam.

Participant admission and Git history are explicit controlled fixtures. Broker
and Hub are real different-UID processes using held kernel-origin transport.
No accounts, upstream network, containers, VM or native agent startup.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from forge_mutation_smoke import run_session
from gate_forge_smoke import FAKE_GH as GATE_FIXTURE

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
PHASES=('prepare','stale','outage','changes','pass','comment','repass','merged')
# Fixed observed eager/exercised-lazy closure + fixed external owner entrypoint.
# Deliberately excludes unused provider routes/runtime integrations.
SOURCES = (
    'uas/__init__.py',
    'uas/manager_owner.py',
    'uas/manager_projection.py', 'uas/manager_journey.py',
    'uas/artifact_protocol.py',
    'uas/config.py',
    'uas/context.py',
    'uas/diff_protocol.py',
    'uas/forge.py',
    'uas/forge_audit.py',
    'uas/forge_mutations.py',
    'uas/forge_projections.py',
    'uas/forge_read.py',
    'uas/forge_read_provider.py',
    'uas/forge_read_service.py',
    'uas/native_broker_audit.py',
    'uas/forge_wire.py',
    'uas/gate_command_hub.py',
    'uas/gate_diff_hub.py',
    'uas/gate_evaluation.py',
    'uas/gate_forge.py',
    'uas/gate_hub.py',
    'uas/gate_policy.py',
    'uas/gate_repository.py',
    'uas/git_audit.py',
    'uas/git_policy.py',
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
    'uas/ledger.py',
    'uas/lifecycle.py',
    'uas/peer.py',
    'uas/review_broker.py',
    'uas/run_control.py',
    'uas/run_coordination.py',
    'uas/run_review.py',
    'uas/workstation_admission.py',
    'uas/workstation_peer.py',
)
MAX_SOURCES=48
MAX_SOURCE_BYTES=8*1024*1024
FAKE_GH=GATE_FIXTURE.replace("if bare==base+'/pulls/11':value=pull",r'''
phase=state['phase']
if phase=='merged':
 pull.update(state='closed',merged=True,merge_commit_sha='c'*40,merged_by={'id':7,'login':'fixture-human','type':'User'})
 pull['base']['sha']='c'*40
if phase=='outage' and bare==base+'/pulls/11':
 state_path.write_text(json.dumps(state))
 sys.stdout.write('HTTP/2.0 503 Fixture\nContent-Type: application/json\r\n\r\n{}')
 sys.exit(0)
if bare==base+'/pulls/11':value=pull
elif bare==base+'/pulls/11/reviews':
 identifier=3 if phase in {'repass','merged'} else 2 if phase in {'pass','comment'} else 1
 value=[] if phase=='prepare' else [{'id':identifier,'html_url':'https://github.com/owner/repo/pull/11#pullrequestreview-'+str(identifier),
  'pull_request_url':api+'/pulls/11','user':{'id':8,'login':'fixture-reviewer'},
  'state':'APPROVED' if identifier>=2 else 'CHANGES_REQUESTED','submitted_at':'2026-10-27T21:00:00Z',
  'commit_id':'d'*40 if phase=='stale' else head}]
elif bare==base+'/commits/'+'c'*40:
 value={'sha':'c'*40,'url':api+'/commits/'+'c'*40,'parents':[{'sha':ancestor},{'sha':head}]}
''')
# Same pinned fixture framing as the existing mutation smoke, restricted to one
# ordinary comment. Persist it then lose its reply to exercise real reconciliation.
FAKE_GH=FAKE_GH.replace("assert args[:10]==['api','--hostname','github.com','--method','GET','--include','-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2026-03-10']\nassert len(args)==11", r'''assert args[:4]==['api','--hostname','github.com','--method']
method=args[4];assert method in {'GET','POST'}
assert args[5:10]==['--include','-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2026-03-10']
assert args[11:] in ([],['--input','-'])
body=json.loads(sys.stdin.buffer.read(32769)) if args[11:] else None
''')
FAKE_GH=FAKE_GH.replace("if bare==base+'/pulls/11':value=pull", r'''if method=='POST':
 assert bare==base+'/issues/11/comments' and body['body'].startswith('lose-fixture-comment:')
 assert state['posts']==0
 state['posts']+=1
 state['comments'].append({'id':701,'user':{'id':41,'login':'fixture-actor'},'body':body['body'],
  'url':api+'/issues/comments/701','issue_url':api+'/issues/11'})
 state_path.write_text(json.dumps(state));os._exit(13)
if bare=='user':value={'id':41,'login':'fixture-actor'}
elif bare==base:value={'id':12,'full_name':'owner/repo','html_url':'https://github.com/owner/repo'}
elif bare==base+'/issues/11':
 value={**pull,'id':100111,'repository_url':api,'pull_request':{'url':api+'/pulls/11'}}
elif bare==base+'/issues/11/comments':value=state['comments']
elif bare==base+'/pulls/11':value=pull''')
SUPERVISOR=r'''
import json,os,socket,sys
from pathlib import Path
from uas.forge import ForgeBinding
from uas.forge_read_service import ReadBrokerClient
from review_hosted_scenario import exercise
assert os.getuid()==65533 and 'GH_TOKEN' not in os.environ
for path in PRIVATE_PATHS:
 try:Path(path).read_bytes()
 except PermissionError:pass
 else:raise AssertionError('Broker private material readable by Hub')
class Supervisor:
 room_id='alpha'
 def _read(self):return {'phase':'running','instance_id':'instance-1','spec':{'project_id':'project'}}
 def _locked(self):
  from contextlib import nullcontext
  return nullcontext()
client=ReadBrokerClient(socket.socket(fileno=int(sys.argv[1])),Supervisor(),ForgeBinding('alpha','project','owner/repo'),
                       'instance-1',worker_uid=65531,worker_gid=65531)
try:print(json.dumps(exercise(client,ROOM_LEDGER,PHASE)),flush=True)
finally:client.close()
'''


def run():
    if os.getuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='Linux':
        raise SystemExit('requires explicit disposable hosted Linux root fixture')
    with tempfile.TemporaryDirectory(prefix='uas-review-forge-') as temporary:
        root=Path(temporary);root.chmod(0o755)
        code=root/'code';code.mkdir(mode=0o755)
        assert len(SOURCES)==len(set(SOURCES)) and len(SOURCES)<=MAX_SOURCES
        assert sum((ROOT/name).stat().st_size for name in SOURCES)<=MAX_SOURCE_BYTES
        for name in SOURCES:
            source=ROOT/name
            assert not source.is_symlink() and source.is_file() and name.startswith('uas/')
            destination=code/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,destination)
        shutil.copyfile(ROOT/'tests/review_hosted_scenario.py',code/'review_hosted_scenario.py')
        for path in code.rglob('*'):path.chmod(0o755 if path.is_dir() else 0o644)
        private=root/'broker';private.mkdir(mode=0o700);os.chown(private,65531,65531)
        credentials=private/'credentials.json';secret='fixture-only-'+os.urandom(24).hex()
        credentials.write_text(json.dumps({'github.com':{'actor-a':secret}}))
        state_path=private/'provider-state.json';state_path.write_text(json.dumps({'mode':'pass','phase':'prepare','calls':[],'comments':[],'posts':0}))
        for path in (credentials,state_path):path.chmod(0o600);os.chown(path,65531,65531)
        executable=root/'gh-fixture'
        executable.write_text(FAKE_GH.replace('STATE_PATH',repr(str(state_path))).replace('CREDENTIAL_PATH',repr(str(credentials))))
        executable.chmod(0o555)
        config={'room_id':'alpha','room_instance':'instance-1','project_id':'project','repository':'owner/repo',
            'deployment_id':'deployment','audit_path':str(private/'audit.db'),'result_root':str(private/'results'),
            'credential_path':str(credentials),'gh_executable':str(executable),
            'gh_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),'supervisor_uid':65533,'supervisor_gid':65533,
            'mutation_actors':{'actor-a':41},'work_labels':[],'review_actor':'actor-a'}
        room=root/'hub';room.mkdir(mode=0o700);os.chown(room,65533,65533)
        for phase in PHASES:
            state=json.loads(state_path.read_text());state['phase']=phase;state_path.write_text(json.dumps(state))
            script=SUPERVISOR.replace('PRIVATE_PATHS',repr([str(credentials),str(state_path),str(private/'audit.db')]))
            script=script.replace('ROOM_LEDGER',repr(str(room/'room.db'))).replace('PHASE',repr(phase))
            out,err=run_session(code,config,script)
            assert secret not in out and secret not in err
            print(out.strip(),flush=True)
        with sqlite3.connect(private/'audit.db') as db:
            routes=[json.loads(row[0])['route'] for row in db.execute('SELECT metadata FROM read_starts')]
            assert 'review-observe' in routes and 'review-mutation-absence' in routes
            assert db.execute('SELECT count(*) FROM mutation_starts').fetchone()[0]==1
            assert db.execute('SELECT count(*) FROM read_terminals').fetchone()[0]==len(routes)
            dump='\n'.join(db.iterdump());assert secret not in dump and str(root) not in dump
        assert json.loads(state_path.read_text())['posts']==1
        print(json.dumps({'private_broker_channel':'real different-UID kernel-authenticated processes',
                          'workflow':'submit -> stale/outage recovery -> return -> pass -> lost comment/reconcile -> repass -> human merge -> CLOSED',
                          'account_free':True,'participant_admission':'controlled fixture, not native qualification'}),flush=True)

if __name__=='__main__':run()
