#!/usr/bin/env python3
"""Hosted-only real GateHub -> private Broker process -> pinned GET fixture.

No network/account/credential/security setting changes. UIDs and fixture-only
credentials belong solely to disposable processes/files. Source Git is synthetic;
this proves the real authenticated external Forge seam, not helper confinement.
Never run locally. Reuses the existing bounded hosted Broker process launcher.
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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

FAKE_GH = r'''#!/usr/bin/python3
import json,os,pathlib,sys
state_path=pathlib.Path(STATE_PATH)
credentials=pathlib.Path(CREDENTIAL_PATH)
secret=json.loads(credentials.read_text())['github.com']['actor-a']
assert os.getuid()==65531 and os.environ['GH_TOKEN']==secret
assert set(os.environ)=={'HOME','GH_CONFIG_DIR','GH_HOST','GH_PROMPT_DISABLED','GH_NO_UPDATE_NOTIFIER','GH_NO_EXTENSION_UPDATE_NOTIFIER','GH_PAGER','LC_ALL','GH_TOKEN'}
args=sys.argv[1:]
assert args[:10]==['api','--hostname','github.com','--method','GET','--include','-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2026-03-10']
assert len(args)==11
path=args[10];bare=path.partition('?')[0]
state=json.loads(state_path.read_text());state['calls'].append(path)
api='https://api.github.com/repos/owner/repo';base='repos/owner/repo'
head='a'*40;ancestor='b'*40
branch=lambda sha,ref:{'sha':sha,'ref':ref,'repo':{'id':12,'full_name':'owner/repo'}}
pull={'id':111,'number':11,'url':api+'/pulls/11','html_url':'https://github.com/owner/repo/pull/11',
 'state':'open','draft':False,'merged':False,'user':{'id':41,'login':'fixture-actor'},
 'base':branch(ancestor,'main'),'head':branch(head,'feature'),'merge_commit_sha':None}
if bare==base+'/pulls/11':value=pull
elif bare==base+'/branches/main':value={'name':'main','protected':False,'commit':{'sha':ancestor}}
elif bare==base+'/rules/branches/main':value=[]
elif bare==base+'/compare/'+ancestor+'...'+head:
 value={'base_commit':{'sha':ancestor},'merge_base_commit':{'sha':ancestor},'status':'ahead'}
elif bare==base+'/commits/'+head+'/check-runs':
 pending=state['mode']=='pending'
 value={'total_count':1,'check_runs':[{'id':9,'url':api+'/check-runs/9','name':'suite','head_sha':head,
  'status':'in_progress' if pending else 'completed','conclusion':None if pending else 'success',
  'app':{'id':4,'slug':'fixture-ci'},'output':{'text':'PRIVATE-CI-CONTENT'}}]}
elif bare==base+'/commits/'+head+'/statuses':value=[]
elif bare==base+'/actions/runs':value={'total_count':0,'workflow_runs':[]}
else:raise AssertionError('unexpected fixed Gate GET route')
state_path.write_text(json.dumps(state))
sys.stdout.write('HTTP/2.0 200 Fixture\nContent-Type: application/json\r\n\r\n'+json.dumps(value))
'''

SUPERVISOR = r'''
from contextlib import contextmanager
from copy import deepcopy
import json,os,socket,sys,threading
from pathlib import Path
from uas.forge import ForgeBinding
from uas.forge_read_service import ReadBrokerClient,GateForgeBrokerClient
from uas.gate_evaluation import GateRoomBinding
from uas.gate_hub import GateHub,require_operation_gates
from uas.gate_policy import compile_policy
from uas.ledger import Origin,LedgerError,RoomLedger,Command,Transition,Event
assert os.getuid()==65533 and 'GH_TOKEN' not in os.environ
for path in PRIVATE_PATHS:
 try:Path(path).read_bytes()
 except PermissionError:pass
 else:raise AssertionError('private Broker material readable to Hub')
class Supervisor:
 room_id='alpha'
 def _read(self):return {'phase':'running','instance_id':'instance-1','spec':{'project_id':'project'}}
 @contextmanager
 def _locked(self):yield
client=ReadBrokerClient(socket.socket(fileno=int(sys.argv[1])),Supervisor(),ForgeBinding('alpha','project','owner/repo'),
                       'instance-1',worker_uid=65531,worker_gid=65531)
forge=GateForgeBrokerClient(client)
source={'room_instance':'instance-1','project_id':'project','repository':'owner/repo',
 'run_id':'run','participant_id':'builder','slot_id':'primary','branch':'refs/heads/feature',
 'head_sha':'a'*40,'source_digest':'c'*64}
class SourceControl:
 def resolve(self,*_):return deepcopy(source)
 def current(self,*_):return deepcopy(source)
origin=Origin('human','human','session','epoch',())
target={'repository':'owner/repo','pull_number':11,'pull_id':111,'head_sha':'a'*40,'base_sha':'b'*40,'base_ref':'main'}
ledger=RoomLedger(ROOM_LEDGER,'alpha')
hub=GateHub(ledger,GateRoomBinding('alpha','instance-1','project','owner/repo',128<<20),SourceControl(),
 authorize=lambda *_:True,authorize_target=lambda o,c:o==origin,forge=forge)
fence=threading.RLock() # Trusted fixture source/authority owner, never Participant-selected.
def consume_guard(view,operation):
 def accept(state,_):
  require_operation_gates(state,view)
  state['fixture_gate_consumed']={'evaluation_id':view['gates'][0]['evaluation_id']}
  return Transition(state,(Event('fixture.gate-consumed',{'run_id':'run'}),),{})
 return ledger.apply(Command(operation,'fixture.gate-consumed','run',1,{}),origin,
  authorize=lambda *_:fence._is_owned(),decide=accept)
if PHASE=='positive':
 policy=compile_policy({'id':'default','version':1,'gates':[{'id':'ci','kind':'mechanical','evaluator':'forge-state',
  'config':{'ci':[{'id':'suite','kind':'check-run','producer_id':4,'context':'suite','coverage':'head','purpose':'complete-suite'}]}}],
  'protected_operations':{'submit-for-review':['ci'],'complete':['ci']},'review_return_cap':5,
  'queue_timeout_seconds':30,'response_timeout_seconds':30},'policy')
 def seed(state,_):
  state['runs']={'run':{'run_id':'run','generation':1,'status':'ACTIVE','project_id':'project','repository':'owner/repo',
   'actor_id':'builder-actor','participant_id':'builder','policy':policy,'checkout':{'slot':'primary','branch':'refs/heads/feature'}}}
  return Transition(state,(Event('fixture.seeded',{}),),{})
 ledger.apply(Command('seed','fixture.seed','run',None,{}),origin,authorize=lambda *_:True,decide=seed)
 bound=hub.bind_target('bind','run',1,target,origin=origin)
 assert bound['status']=='BOUND',bound
 first=hub.evaluate('passing','run',1,'ci',origin=origin)
 assert first['result']['verdict']=='passed',first
 assert hub.evaluate('passing','run',1,'ci',origin=origin)==first
 with fence:
  view=hub.operation_gates('run',1,'complete',origin=origin)
  assert view['gates_satisfied'],view
  consume_guard(view,'consume-positive')
 # Even a real authenticated Supervisor cannot convert a Participant Origin
 # with a forged capability name into the exact Hub-only Broker authority.
 forged=Origin('actor-a','builder','inc','epoch',('forge-read','forge-gate'))
 packet=client.prepare({'id':'forged','kind':'gate-target','target':target},forged,authorize=lambda:True)
 try:client.perform(packet)
 except LedgerError as error:assert error.code=='FORBIDDEN',error
 else:raise AssertionError('Participant forged Gate authority')
 print(json.dumps({'gate_bind':'BOUND','immutable_checks':'passed','exact_retry':'same-evaluation',
  'protected_operation':'canonical-transaction-marker-not-Run-closed','participant_gate_authority':'FORBIDDEN'}))
else:
 old=hub.evaluate('passing','run',1,'ci',origin=origin)
 assert old['result']['verdict']=='passed',old
 pending=hub.evaluate('pending','run',1,'ci',origin=origin)
 assert pending['result']['verdict']=='failed',pending
 with fence:
  view=hub.operation_gates('run',1,'complete',origin=origin)
  assert not view['gates_satisfied'],view
  before=ledger.snapshot()
  try:consume_guard(view,'consume-pending')
  except LedgerError as error:assert error.code=='GATE_OPERATION_BLOCKED',error
  else:raise AssertionError('pending CI advanced operation')
  assert ledger.snapshot()==before,'blocked transaction changed canonical state'
 print(json.dumps({'restart':'old-immutable-pass-retained','new-pending-CI':'failed',
  'protected_operation':'BLOCKED','run':'ACTIVE'}))
assert ledger.snapshot()['state']['runs']['run']['status']=='ACTIVE'
ledger.close();client.close()
'''


def run():
    if os.getuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux':
        raise SystemExit('requires explicit disposable hosted Linux root fixture')
    with tempfile.TemporaryDirectory(prefix='uas-gate-forge-') as temporary:
        root = Path(temporary); root.chmod(0o755)
        code = root / 'code'; code.mkdir(mode=0o755)
        shutil.copytree(ROOT / 'uas', code / 'uas', ignore=shutil.ignore_patterns('__pycache__'))
        for path in (code / 'uas').rglob('*'): path.chmod(0o755 if path.is_dir() else 0o644)
        private = root / 'broker'; private.mkdir(mode=0o700); os.chown(private, 65531, 65531)
        credentials = private / 'credentials.json'
        secret = 'fixture-only-' + os.urandom(24).hex()
        credentials.write_text(json.dumps({'github.com': {'actor-a': secret}}))
        state_path = private / 'provider-state.json'; state_path.write_text(json.dumps({'mode': 'pass', 'calls': []}))
        for path in (credentials, state_path): path.chmod(0o600); os.chown(path, 65531, 65531)
        executable = root / 'gh-fixture'
        executable.write_text(FAKE_GH.replace('STATE_PATH', repr(str(state_path)))
                              .replace('CREDENTIAL_PATH', repr(str(credentials))))
        executable.chmod(0o555)
        config = {'room_id': 'alpha', 'room_instance': 'instance-1', 'project_id': 'project',
            'repository': 'owner/repo', 'deployment_id': 'deployment', 'audit_path': str(private / 'audit.db'),
            'result_root': str(private / 'results'), 'credential_path': str(credentials),
            'gh_executable': str(executable), 'gh_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'supervisor_uid': 65533, 'supervisor_gid': 65533, 'gate_actor': 'actor-a'}
        room = root / 'hub'; room.mkdir(mode=0o700); os.chown(room, 65533, 65533)
        for phase in ('positive', 'pending'):
            state = json.loads(state_path.read_text()); state['mode'] = 'pending' if phase == 'pending' else 'pass'
            state_path.write_text(json.dumps(state))
            script = SUPERVISOR.replace('PRIVATE_PATHS', repr([str(credentials), str(state_path), str(private / 'audit.db')]))
            script = script.replace('PHASE', repr(phase)).replace('ROOM_LEDGER', repr(str(room / 'room.db')))
            out, err = run_session(code, config, script)
            assert secret not in out and secret not in err
            print(out.strip(), flush=True)
        with sqlite3.connect(private / 'audit.db') as db:
            rows = db.execute('SELECT metadata FROM read_starts').fetchall()
            assert sum(json.loads(row[0])['route'] == 'gate-target' for row in rows) == 1
            assert sum(json.loads(row[0])['route'] == 'gate-forge' for row in rows) == 3
            assert db.execute('SELECT count(*) FROM read_terminals').fetchone()[0] == len(rows)
            dump = '\n'.join(db.iterdump())
            assert secret not in dump and 'PRIVATE-CI-CONTENT' not in dump and str(root) not in dump
        print(json.dumps({'gate_forge_channel': 'real-process-bound', 'broker_uid': 65531,
            'hub_uid': 65533, 'credentials': 'fixture-private', 'account_free': True,
            'helper_confinement': 'not-tested'}), flush=True)


if __name__ == '__main__':
    run()
