#!/usr/bin/env python3
"""Hosted-only process-bound mutation integration against a private gh fixture.

No GitHub account, network provider, host user or security policy is changed.
Numeric UIDs and ownership apply only to this disposable fixture's processes and
files. The pinned executable implements the documented gh api framing, not a
claim of live GitHub credential/scope qualification. Never run this locally.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


FAKE_GH = r'''#!/usr/bin/python3
import hashlib,json,os,pathlib,sys
from urllib.parse import unquote,parse_qs
credentials=pathlib.Path(CREDENTIAL_PATH)
state_path=pathlib.Path(STATE_PATH)
late_flag=pathlib.Path(LATE_PATH)
secrets=json.loads(credentials.read_text())['github.com']
assert os.getuid()==65531 and os.environ['GH_TOKEN']==secrets['actor-a']
assert set(os.environ)=={'HOME','GH_CONFIG_DIR','GH_HOST','GH_PROMPT_DISABLED','GH_NO_UPDATE_NOTIFIER','GH_NO_EXTENSION_UPDATE_NOTIFIER','GH_PAGER','LC_ALL','GH_TOKEN'}
args=sys.argv[1:]
assert args[:4]==['api','--hostname','github.com','--method']
method=args[4]
assert args[5:10]==['--include','-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2026-03-10']
path=args[10]
bare,_,query=path.partition('?')
assert args[11:] in ([],['--input','-'])
raw=sys.stdin.buffer.read(1114113) if args[11:] else b''
assert len(raw)<=1114112
body=json.loads(raw) if raw else None
assert method in {'GET','POST','PATCH','DELETE'}
assert path=='user' or path=='repos/owner/repo' or path.startswith('repos/owner/repo/')
state=json.loads(state_path.read_text())
state['calls'].append({'method':method,'path':path,'body_bytes':len(raw),'body_sha256':hashlib.sha256(raw).hexdigest()})
api='https://api.github.com/repos/owner/repo'
web='https://github.com/owner/repo'

def save():state_path.write_text(json.dumps(state))
def emit(status,value):
 save()
 if method!='GET' and type(body) is dict and str(body.get('body','')).startswith('lose-create-comment-review:'):
  os._exit(13)
 if method=='POST' and bare.endswith('/labels') and state.get('lose_projection_once'):
  state['lose_projection_once']=False;save();os._exit(13)
 text=json.dumps(value,separators=(',',':'))
 sys.stdout.write('HTTP/2.0 '+str(status)+' Fixture\nContent-Type: application/json\r\n\r\n'+text)
 sys.exit(0 if status<400 else 1)
def issue(number):
 return state['issues'][str(number)] if str(number) in state['issues'] else state['pulls'][str(number)]
def issue_facade(number):
 value=dict(issue(number))
 if str(number) in state['pulls']:
  value['id']+=100000
  value['pull_request']={'url':api+'/pulls/'+str(number)}
 return value
if method=='GET':
 if path=='user':emit(200,{'id':41,'login':'fixture-actor'})
 if path=='repos/owner/repo':emit(200,{'id':12,'full_name':'owner/repo','html_url':web,'url':api,'private':True,'default_branch':'main','description':'fixture'})
 bits=bare.split('/')
 if query:
  page=int(parse_qs(query)['page'][0])
  if bare=='repos/owner/repo/issues':values=list(state['issues'].values())
  elif bare=='repos/owner/repo/pulls':values=list(state['pulls'].values())
  elif bare.endswith('/labels'):values=[{'id':10000+i,'name':v} for i,v in enumerate(state['labels'].get(bits[4],[]))]
  elif bare.endswith('/comments'):values=[v for v in state['comments'] if v.get('pull_request_url' if bits[3]=='pulls' else 'issue_url')==api+'/'+bits[3]+'/'+bits[4]]
  elif bare.endswith('/reviews'):values=[v for v in state['reviews'] if v['pull_request_url']==api+'/pulls/'+bits[4]]
  elif bare.endswith('/dependencies/blocked_by'):values=[v for v in state['issues'].values() if v['id'] in state['dependencies'].get(bits[4],[])]
  else:raise AssertionError('unsupported collection')
  emit(200,values[(page-1)*100:page*100])
 if bits[3]=='issues' and len(bits)==5:emit(200,issue_facade(int(bits[4])))
 if bits[3]=='pulls' and len(bits)==5:emit(200,state['pulls'][bits[4]])
 if bits[3:5]==['pulls','comments'] and len(bits)==6:emit(200,{'id':int(bits[5]),'pull_request_url':api+'/pulls/11'})
 raise AssertionError('unsupported fixture GET')
bits=path.split('/')
if method=='POST' and path in ('repos/owner/repo/issues','repos/owner/repo/pulls'):
 pull=bits[3]=='pulls';key='next_pull' if pull else 'next_issue'
 state[key]+=1;number=state[key]
 value={'id':1000+number,'number':number,'html_url':web+('/pull/' if pull else '/issues/')+str(number),
        'repository_url':api,'user':{'id':41},'state':'open','title':body['title'],'body':body['body'],'assignees':[]}
 if pull:value.update(base={'repo':{'full_name':'owner/repo'},'ref':body['base']},head={'sha':'a'*40,'ref':body['head'],'repo':{'full_name':'owner/repo'}},draft=body.get('draft',False))
 state['pulls' if pull else 'issues'][str(number)]=value
 emit(201,value)
number=int(bits[4]);current=issue(number)
if method=='PATCH' and len(bits)==5:
 if body.get('body')=='reject-403':emit(403,{'message':'PRIVATE-PROVIDER-ERROR'})
 for key,value in body.items():
  if key=='base':current['base']['ref']=value
  else:current[key]=value
 if body.get('title')=='late-revocation':late_flag.write_text('1')
 if body.get('title')=='external-drift':state['labels'][str(number)]=['type:bug','run:paused']
 if body.get('title')=='arm-projection-loss':
  state['labels'][str(number)]=['type:bug','run:paused'];state['lose_projection_once']=True
 if body.get('body','').startswith('lost-after-contact:'):save();os._exit(13)
 emit(200,current)
if bits[5:] == ['assignees']:
 assert body=={'assignees':['fixture-actor']}
 current['assignees']=[{'id':41,'login':'fixture-actor'}] if method=='POST' else []
 emit(201 if method=='POST' else 200,issue_facade(number))
if len(bits)>=6 and bits[5]=='labels':
 labels=state['labels'].setdefault(str(number),[])
 if method=='POST':
  assert len(body['labels'])==1
  if body['labels'][0] not in labels:labels.append(body['labels'][0])
 else:labels.remove(unquote(bits[6]))
 emit(200,[{'name':label} for label in labels])
if bits[5:7]==['dependencies','blocked_by']:
 dependency_id=body['issue_id'] if method=='POST' else int(bits[7])
 target=next(item for item in state['issues'].values() if item['id']==dependency_id)
 state['dependencies'][str(number)]=[dependency_id] if method=='POST' else []
 emit(201 if method=='POST' else 200,target)
if bits[5:]==['comments'] or (len(bits)==8 and bits[5]=='comments' and bits[7]=='replies'):
 state['next_comment']+=1
 value={'id':state['next_comment'],'body':body['body'],'user':{'id':41}}
 if len(bits)==8:value['in_reply_to_id']=int(bits[6])
 value['pull_request_url' if len(bits)==8 else 'issue_url']=api+('/pulls/' if len(bits)==8 else '/issues/')+str(number)
 state['comments'].append(value)
 emit(201,value)
if bits[5:]==['reviews']:
 state['next_review']+=1
 value={'id':state['next_review'],'user':{'id':41},'body':body['body'],'commit_id':body['commit_id'],
        'state':{'APPROVE':'APPROVED','REQUEST_CHANGES':'CHANGES_REQUESTED','COMMENT':'COMMENTED'}[body['event']],
        'submitted_at':'2026-10-27T00:00:00Z','pull_request_url':api+'/pulls/'+str(number)}
 state['reviews'].append(value)
 emit(200,value)
raise AssertionError('unsupported fixture mutation')
'''

SUPERVISOR = r'''
from contextlib import contextmanager
import json,os,socket,sys
from pathlib import Path
from uas.forge import ForgeBinding
from uas.forge_read_service import ReadBrokerClient
from uas.ledger import Origin,LedgerError
assert os.getuid()==65533 and 'GH_TOKEN' not in os.environ
for path in PRIVATE_PATHS:
 try:Path(path).read_bytes()
 except PermissionError:pass
 else:raise AssertionError('private Broker material readable to Supervisor')
class Supervisor:
 room_id='alpha'
 def _read(self):return {'phase':'running','instance_id':'instance-1','spec':{'project_id':'project'}}
 @contextmanager
 def _locked(self):yield
supervisor=Supervisor()
client=ReadBrokerClient(socket.socket(fileno=int(sys.argv[1])),supervisor,ForgeBinding('alpha','project','owner/repo'),
                       'instance-1',worker_uid=65531,worker_gid=65531)
origin=Origin('actor-a','alice','inc-1','epoch-1',('forge-read','forge-write'))
allow=True;deny_late=False

def authority():return allow and not (deny_late and Path(LATE_PATH).read_text()=='1')
def envelope(operation,argv,body=None):
 value={'id':operation,'kind':'forge-write','argv':['gh',*argv]}
 if body is not None:value['body']=body
 return value
def invoke(operation,argv,body=None,selected=origin):
 packet=client.prepare(envelope(operation,argv,body),selected,authorize=authority)
 return client.perform(packet)
def status(receipt,expected,fields=None):
 assert receipt['mutation']['status']==expected,receipt
 assert bool(receipt['audit_reference'])
 assert receipt['exit_code']==(0 if expected=='OK' else 1),receipt
 if fields is not None:assert receipt['mutation']['confirmed_fields']==fields,receipt
 return receipt
lost_argv=['issue','edit','1','--body-file','-']
lost_body='lost-after-contact:'+('x'*(512*1024-len('lost-after-contact:')))
if PHASE=='restart':
 unknown=status(invoke('lost',lost_argv,lost_body),'UNKNOWN_OUTCOME',[])
 try:invoke('fenced-after-restart',['issue','edit','1','--title','must-not-execute'])
 except LedgerError as error:assert error.code=='FORGE_RECONCILIATION_REQUIRED',error
 else:raise AssertionError('restart bypassed unknown write fence')
 print(json.dumps({'phase':'restart','unknown_receipt':'retained','duplicate_write':'blocked'}))
 client.close();sys.exit(0)


def reconcile(operation,original,receipt):
 request={'id':operation,'kind':'forge-reconcile','audit_reference':receipt['audit_reference'],'mutation':original}
 result=client.perform(client.prepare(request,origin,authorize=authority))
 assert result['reconciliation']['status']=='MATCHED',result
 assert result['reconciliation']['attribution']=='observed-only'
 assert client.perform(client.prepare(request,origin,authorize=authority))==result
 return result

if PHASE=='reconcile':
 unknown=status(invoke('lost',lost_argv,lost_body),'UNKNOWN_OUTCOME',[])
 reconcile('resolve-original',envelope('lost',lost_argv,lost_body),unknown)
 status(invoke('shrink-one',['issue','edit','1','--body','bounded-after-recovery']),'OK')
 status(invoke('shrink-seven',['issue','edit','7','--body','bounded-after-quota-test']),'OK')
 lost_commands=[
  ['issue','create','--title','lost-created-object','--body','lose-create-comment-review:create'],
  ['issue','comment','1','--body','lose-create-comment-review:comment'],
  ['pr','review','11','--approve','--commit','a'*40,'--body','lose-create-comment-review:review']]
 for index,argv in enumerate(lost_commands):
  operation='lost-object-'+str(index)
  receipt=status(invoke(operation,argv),'UNKNOWN_OUTCOME',[])
  reconcile('resolve-object-'+str(index),envelope(operation,argv),receipt)
  assert invoke(operation,argv)==receipt
 partial_args=['issue','edit','1','--title','partial-title','--body','lost-after-contact:partial']
 partial=status(invoke('lost-multifield',partial_args),'UNKNOWN_OUTCOME',['title'])
 reconcile('resolve-multifield',envelope('lost-multifield',partial_args),partial)
 status(invoke('assign-hub-target',['issue','edit','1','--add-assignee','@me']),'OK')
 status(invoke('work-label',['issue','edit','1','--add-label','type:bug']),'OK')
 from uas.forge_read_service import ProjectionBrokerClient
 from uas.forge_projections import ProjectionOutbox,enqueue_run_projection
 from uas.ledger import RoomLedger,Command,Event,Transition
 from uas.forge_projection_broker import hub_origin
 ledger=RoomLedger(ROOM_LEDGER,'alpha')
 hub=hub_origin('instance-1')
 def seed(state,_):
  state['runs']={'run-fixture':{'run_id':'run-fixture','status':'ACTIVE','generation':1,'project_id':'project',
    'repository':'owner/repo','issue_number':1,'issue_id':101,'github_user_id':41}}
  event=enqueue_run_projection(state,'alpha','run-fixture')
  return Transition(state,(event,),{})
 ledger.apply(Command('seed-run','fixture.seed','run-fixture',None,{}),hub,authorize=lambda *_:True,decide=seed)
 outbox=ProjectionOutbox(ledger,ForgeBinding('alpha','project','owner/repo'),ProjectionBrokerClient(client))
 first=outbox.advance('initial-sync','run-fixture',origin=hub,authorize=authority)
 assert first['state']=='repaired',first
 assert outbox.advance('initial-sync','run-fixture',origin=hub,authorize=authority)==first
 status(invoke('external-label-drift',['issue','edit','1','--title','external-drift']),'OK')
 repaired=outbox.advance('drift-sync','run-fixture',origin=hub,authorize=authority)
 assert repaired['state']=='repaired',repaired
 status(invoke('arm-label-loss',['issue','edit','1','--title','arm-projection-loss']),'OK')
 uncertain=outbox.advance('lost-projection','run-fixture',origin=hub,authorize=authority)
 assert uncertain['state']=='unknown',uncertain
 assert outbox.advance('lost-projection','run-fixture',origin=hub,authorize=authority)==uncertain
 ledger.close();ledger=RoomLedger(ROOM_LEDGER,'alpha')
 outbox=ProjectionOutbox(ledger,ForgeBinding('alpha','project','owner/repo'),ProjectionBrokerClient(client))
 final=outbox.advance('recover-projection','run-fixture',origin=hub,authorize=authority)
 assert final['state']=='repaired',final
 assert ledger.snapshot()['state']['runs']['run-fixture']['status']=='ACTIVE'
 assert any(e['kind']=='forge.projection-drifted' for e in ledger.replay(0))
 ledger.close();client.close()
 print(json.dumps({'phase':'reconcile','lost_create_comment_review_multifield':'MATCHED-observed-only',
  'duplicate_writes':'none','hub_outbox_restart':'repaired','external_label_drift':'repaired','run_truth':'ACTIVE'}))
 sys.exit(0)

created_argv=['issue','create','--title','private-issue-title','--body','PRIVATE-CREATE-BODY',
              '--repo','OWNER/REPO','--label','type:bug,type:bug','--assignee','@me']
created=status(invoke('create',created_argv),'OK',['create','title','body','add-assignee','add-label'])
assert created['warnings'],created
assert invoke('create',created_argv)==created
status(invoke('comment',['issue','comment','1','--body','PRIVATE-COMMENT-BODY']),'OK',['comment'])
status(invoke('label-add',['issue','edit','1','--add-label','type:bug']),'OK',['add-label'])
status(invoke('label-remove',['issue','edit','1','--remove-label','type:bug']),'OK',['remove-label'])
status(invoke('dependency-add',['issue','dependency','add','1','--blocked-by','2']),'OK',['dependency'])
status(invoke('dependency-remove',['issue','dependency','remove','1','--blocked-by','2']),'OK',['remove-dependency'])
status(invoke('pull-create',['pr','create','--title','private-pull-title','--body','PRIVATE-PULL-BODY',
              '--head','feature','--base','main','--draft']),'OK',['create','title','body','base','head','draft'])
status(invoke('pull-assign',['pr','edit','11','--add-assignee','@me']),'OK',['add-assignee'])
status(invoke('pull-unassign',['pr','edit','11','--remove-assignee','@me']),'OK',['remove-assignee'])
status(invoke('reply',['pr','reply','11','--comment-id','700','--body','PRIVATE-REPLY-BODY']),'OK',['reply'])
status(invoke('review',['pr','review','11','--approve','--commit','a'*40,'--body','PRIVATE-REVIEW-BODY']),'OK',['review'])
partial_argv=['issue','edit','1','--title','confirmed-before-403','--body','reject-403']
partial=status(invoke('partial',partial_argv),'PARTIAL_MUTATION',['title'])
assert partial['mutation']['failed_field']=='body',partial
assert invoke('partial',partial_argv)==partial
status(invoke('after-definite-rejection',['issue','edit','1','--title','after-403']),'OK',['title'])

large='PRIVATE-LARGE-BODY:'+('\"'*1024)+('x'*(512*1024-len('PRIVATE-LARGE-BODY:')-1024))
status(invoke('body-limit',['issue','edit','7','--body-file','-'],large),'OK',['body'])
rejected=status(invoke('too-large',['issue','edit','1','--body-file','-'],large+'x'),'DENIED',[])
assert rejected['diagnostic']['code']=='BODY_LIMIT',rejected
for operation,argv,code in (
 ('cross-project',['issue','edit','1','--title','x','--repo','other/repo'],'PROJECT_MISMATCH'),
 ('raw-api',['api','user'],'UNSUPPORTED_ROUTE'),
 ('binary-attachment',['issue','comment','1','--body','x','--attach','secret-file'],'UNSUPPORTED_ROUTE'),
 ('lifecycle-label',['issue','edit','1','--add-label','agent:claimed'],'LABEL_AUTHORITY_DENIED')):
 denied=status(invoke(operation,argv),'DENIED',[])
 assert denied['diagnostic']['code']==code,denied
 assert set(denied['diagnostic'])=={'code','token_index','token','correction'},denied
owned=status(invoke('foreign-owner',['issue','edit','8','--title','forbidden-owner']),'DENIED',[])
assert owned['mutation']['error_code']=='OWNERSHIP_DENIED',owned
missing=Origin('actor-missing','bob','inc-b','epoch-b',('forge-read','forge-write'))
try:invoke('missing-actor',['issue','edit','1','--title','x'],selected=missing)
except LedgerError as error:assert error.code=='FORBIDDEN',error
else:raise AssertionError('unknown Actor acquired write authority')

packet=client.prepare(envelope('revoked-before-dispatch',['issue','edit','1','--title','must-not-execute']),origin,authorize=authority)
allow=False
try:client.perform(packet)
except LedgerError as error:assert error.code=='FORBIDDEN',error
else:raise AssertionError('pre-dispatch revocation allowed write')
allow=True;deny_late=True
late_argv=['issue','edit','1','--title','late-revocation']
try:invoke('late',late_argv)
except LedgerError as error:assert error.code=='FORBIDDEN',error
else:raise AssertionError('post-contact revoked authority received success')
deny_late=False
status(invoke('late',late_argv),'OK',['title'])  # Exact committed receipt, no second PATCH.
unknown=status(invoke('lost',lost_argv,lost_body),'UNKNOWN_OUTCOME',[])
assert invoke('lost',lost_argv,lost_body)==unknown
try:invoke('fenced',['issue','edit','1','--title','must-not-execute'])
except LedgerError as error:assert error.code=='FORGE_RECONCILIATION_REQUIRED',error
else:raise AssertionError('new operation ID bypassed unknown write fence')
client.close()
print(json.dumps({'phase':'initial','external_broker_uid':65531,'supervisor_uid':65533,
 'issue_comment_label_dependency_pull_review':'OK','warning_exit_code':0,'partial':'confirmed-title-only',
 'body_bytes':512*1024,'framed_write_body_bytes':512*1024,'oversize':'DENIED','late_authority':'FORBIDDEN',
 'lost_response':'UNKNOWN_OUTCOME','exact_replay':'no-provider-contact','private_credentials':'denied'}))
'''


def initial_state():
    api = 'https://api.github.com/repos/owner/repo'
    web = 'https://github.com/owner/repo'
    def issue(number, owner=41):
        return {'id': 100 + number, 'number': number, 'repository_url': api,
            'html_url': web + '/issues/' + str(number), 'user': {'id': owner},
            'state': 'open', 'title': 'fixture', 'body': 'initial', 'assignees': []}
    pull = {**issue(11), 'html_url': web + '/pull/11',
        'base': {'repo': {'full_name': 'owner/repo'}, 'ref': 'main'},
        'head': {'sha': 'a' * 40, 'ref': 'feature', 'repo': {'full_name': 'owner/repo'}}, 'draft': False}
    return {'issues': {str(n): issue(n, 99 if n == 8 else 41) for n in (1, 2, 7, 8)},
        'pulls': {'11': pull}, 'labels': {}, 'dependencies': {}, 'comments': [], 'reviews': [],
        'next_issue': 20, 'next_pull': 30, 'next_comment': 800, 'next_review': 900, 'calls': []}


def run_session(code, config, script):
    from uas.kernel_origin import enable
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    enable(parent); enable(child)
    broker = supervisor = None
    try:
        environment = {'PYTHONPATH': str(code), 'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}
        broker = subprocess.Popen([sys.executable, '-m', 'uas.forge_read_service', str(child.fileno())],
            cwd=code, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, pass_fds=(child.fileno(),), user=65531, group=65531, extra_groups=())
        broker.stdin.write(json.dumps(config) + '\n'); broker.stdin.flush(); broker.stdin.close(); child.close()
        supervisor = subprocess.Popen([sys.executable, '-c', script, str(parent.fileno())],
            cwd=code, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, pass_fds=(parent.fileno(),), user=65533, group=65533, extra_groups=())
        parent.close()
        out, err = supervisor.communicate(timeout=20)
        if supervisor.returncode:
            # The fixture itself has no real secrets; error text still avoids
            # Broker stderr and credential material, which never belong here.
            raise AssertionError('mutation Supervisor smoke failed: ' + err[-5000:])
        broker.wait(timeout=5)
        assert broker.poll() is not None
        return out, err
    finally:
        parent.close(); child.close()
        for process in (supervisor, broker):
            if process is not None:
                if process.poll() is None: process.kill()
                process.wait(timeout=5)
                for stream in (process.stdout, process.stderr):
                    if stream is not None: stream.close()


def run():
    if os.getuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux':
        raise SystemExit('requires explicit disposable hosted Linux root fixture')
    with tempfile.TemporaryDirectory(prefix='uas-forge-mutation-') as temporary:
        root = Path(temporary); root.chmod(0o755)
        code = root / 'code'; code.mkdir(mode=0o755)
        shutil.copytree(ROOT / 'uas', code / 'uas', ignore=shutil.ignore_patterns('__pycache__'))
        for path in (code / 'uas').rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        private = root / 'broker'; private.mkdir(mode=0o700); os.chown(private, 65531, 65531)
        secret = 'fixture-only-' + os.urandom(24).hex()
        credentials = private / 'credentials.json'
        credentials.write_text(json.dumps({'github.com': {'actor-a': secret}}))
        state_path = private / 'provider-state.json'; state_path.write_text(json.dumps(initial_state()))
        for path in (credentials, state_path):
            path.chmod(0o600); os.chown(path, 65531, 65531)
        late_path = root / 'late-flag'; late_path.write_text('0'); late_path.chmod(0o644); os.chown(late_path, 65531, 65531)
        executable = root / 'gh-fixture'
        executable.write_text(FAKE_GH.replace('CREDENTIAL_PATH', repr(str(credentials)))
                              .replace('STATE_PATH', repr(str(state_path))).replace('LATE_PATH', repr(str(late_path))))
        executable.chmod(0o555)
        config = {'room_id': 'alpha', 'room_instance': 'instance-1', 'project_id': 'project',
            'repository': 'owner/repo', 'deployment_id': 'deployment', 'audit_path': str(private / 'audit.db'),
            'result_root': str(private / 'results'), 'credential_path': str(credentials),
            'gh_executable': str(executable), 'gh_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'supervisor_uid': 65533, 'supervisor_gid': 65533, 'mutation_actors': {'actor-a': 41},
            'work_labels': ['type:bug'], 'projection_actor':'actor-a'}
        outputs = []
        call_count = None
        room_store=root/'hub';room_store.mkdir(mode=0o700);os.chown(room_store,65533,65533)
        for phase in ('initial', 'restart', 'reconcile'):
            script = SUPERVISOR.replace('PRIVATE_PATHS', repr([str(credentials), str(state_path), str(private / 'audit.db')]))
            script = script.replace('LATE_PATH', repr(str(late_path))).replace('PHASE', repr(phase)).replace('ROOM_LEDGER',repr(str(room_store/'room.db')))
            out, err = run_session(code, config, script)
            assert secret not in out and secret not in err
            outputs.append(out.strip())
            current = json.loads(state_path.read_text())
            if phase == 'initial': call_count = len(current['calls'])
            elif phase=='restart': assert len(current['calls']) == call_count, 'restart replay contacted provider'
            elif phase=='reconcile': assert len(current['calls'])>call_count
        state = json.loads(state_path.read_text())
        assert state['next_issue'] == 22 and state['next_pull'] == 31
        assert len(state['comments']) == 3 and len(state['reviews']) == 2
        assert state['issues']['1']['title'] == 'arm-projection-loss'
        assert state['issues']['1']['body'].startswith('lost-after-contact:')
        assert state['issues']['1']['body']=='lost-after-contact:partial'
        assert any(call['body_bytes']>512*1024 for call in state['calls'])
        assert state['issues']['8']['title'] == 'fixture'
        assert state['issues']['7']['body']=='bounded-after-quota-test'
        assert set(state['labels']['1'])=={'type:bug','lifecycle:active','run:active'}
        assert state['dependencies']['1'] == []
        with sqlite3.connect(private / 'audit.db') as db:
            starts = db.execute('SELECT metadata FROM mutation_starts').fetchall()
            terminals = db.execute('SELECT result FROM mutation_terminals').fetchall()
            audit_text = '\n'.join(db.iterdump())
            assert len(starts) == len(terminals), 'unexpected unfinished mutation'
            dependency = db.execute("SELECT target FROM mutation_prepared WHERE target LIKE '%related_id%'").fetchall()
            assert len(dependency) == 2
            assert all(json.loads(row[0])['related_id'] == 102 for row in dependency)
            partial = [json.loads(row[0]) for row in terminals if json.loads(row[0])['status'] == 'PARTIAL_MUTATION']
            assert len(partial) == 1 and partial[0]['confirmed_fields'] == ['title']
            assert sum(json.loads(row[0])['status'] == 'UNKNOWN_OUTCOME' for row in terminals) == 6
            assert db.execute('SELECT count(*) FROM mutation_observations').fetchone()[0]>=6
        forbidden = (secret, 'PRIVATE-CREATE-BODY', 'PRIVATE-COMMENT-BODY', 'PRIVATE-PULL-BODY',
                     'PRIVATE-REPLY-BODY', 'PRIVATE-REVIEW-BODY', 'PRIVATE-LARGE-BODY',
                     'PRIVATE-PROVIDER-ERROR', 'private-issue-title', 'private-pull-title', str(root))
        assert all(value not in audit_text for value in forbidden), 'audit retained raw content or secret'
        for output in outputs: print(output, flush=True)
        print(json.dumps({'mutation_audit': 'metadata-only', 'dependency_identity': 'both-issues-bound',
                          'provider_calls': len(state['calls']), 'account_free': True}), flush=True)


if __name__ == '__main__':
    run()
