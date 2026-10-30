"""Pinned official Claude SDK/CLI -> native MCP -> held helper origin -> Git.

Account-free loopback protocol replies are scripted, not model reasoning. The
fixture substitutes paths and bootstrap only; production profile, MCP server,
current Hub admission and Library service are real. Same-UID fixture is not a
container/credential-isolation or production host qualification claim.
"""
from collections import deque
import http.server
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

import library_support as support
import test_library_enqueue as service_tests
from test_library_git import git
from test_workstation_peer import Endpoint
from uas import library
from uas.claude_runtime import require_loopback_namespace, _dispose_sdk_process
from uas.context import FixtureRunTerminal
from uas.kernel_origin import HeldOrigin, ReceiverIdentity, enable, receive
from uas.ledger import RoomLedger
from uas.library_enqueue import EnqueueEndpoint
from uas.library_hub import LibraryHub
from uas.library_registration import Registrar
from uas.peer import FixtureParticipant, FixturePeerHub
from uas.workstation_admission import AdmissionSeat, HubAdmission, send_admit
from uas.workstation_exec import ExecLaunch, ExecSeat
from uas.workstation_peer import AdmittedPeerDispatcher

ROOT=Path(__file__).resolve().parents[1]
INSTALL=os.environ.get('UAS_CLAUDE_INSTALL')
SDK=os.environ.get('UAS_CLAUDE_SDK_INSTALL')
NODE=os.environ.get('UAS_CLAUDE_NODE')

class Gateway(http.server.ThreadingHTTPServer):
    daemon_threads=True

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_POST(self):
        if self.headers.get('x-api-key')!=self.server.key:
            return self.send_error(401)
        length=int(self.headers.get('Content-Length','0'))
        if not 0<length<2*1024*1024:return self.send_error(413)
        request=json.loads(self.rfile.read(length))
        self.server.requests.append(request)
        if self.path.split('?')[0]=='/v1/messages/count_tokens':
            body=b'{"input_tokens":10}';self.send_response(200)
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
            self.end_headers();self.wfile.write(body);return
        if self.path.split('?')[0]!='/v1/messages':return self.send_error(404)
        with self.server.lock:
            call=self.server.capture if not self.server.emitted else None
            self.server.emitted=True
        block=({'type':'tool_use','id':'tool_'+uuid.uuid4().hex,'name':'mcp__uas__library_enqueue','input':{}}
               if call is not None else {'type':'text','text':''})
        delta=({'type':'input_json_delta','partial_json':json.dumps(call)} if call is not None
               else {'type':'text_delta','text':'fixture turn completed'})
        self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
        events=[('message_start',{'type':'message_start','message':{'id':'msg_'+uuid.uuid4().hex,'type':'message',
          'role':'assistant','model':request['model'],'content':[],'stop_reason':None,'stop_sequence':None,
          'usage':{'input_tokens':10,'output_tokens':0}}}),
          ('content_block_start',{'type':'content_block_start','index':0,'content_block':block}),
          ('content_block_delta',{'type':'content_block_delta','index':0,'delta':delta}),
          ('content_block_stop',{'type':'content_block_stop','index':0}),
          ('message_delta',{'type':'message_delta','delta':{'stop_reason':'tool_use' if call is not None else 'end_turn',
             'stop_sequence':None},'usage':{'output_tokens':1}}),('message_stop',{'type':'message_stop'})]
        for event,data in events:self.wfile.write(('event: '+event+'\ndata: '+json.dumps(data)+'\n\n').encode())
        self.wfile.flush()


class NativeSession:
    def __init__(self,test,project,service,capability=True):
        self.test=test;self.project=project;self.service=service
        self.root=test.root/(project+'-'+uuid.uuid4().hex[:8]);self.root.mkdir();self.home=self.root/'home';self.home.mkdir()
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);enable(self.listener)
        self.endpoint=self.root/'peer';self.listener.bind(str(self.endpoint));self.listener.listen(1)
        self.gateway=Gateway(('127.0.0.1',0),Handler);self.gateway.key='fixture-only-'+uuid.uuid4().hex
        self.gateway.requests=[];self.gateway.capture=None;self.gateway.emitted=False;self.gateway.lock=threading.Lock()
        self.thread=threading.Thread(target=lambda:self.gateway.serve_forever(poll_interval=.02),daemon=True);self.thread.start()
        self.events=deque(maxlen=256);self.errors=deque(maxlen=8);self.condition=threading.Condition()
        self.session=str(uuid.uuid4());self.process=None;self.hostfd=None;self.origin=None;self.channel=None
        self.admissions=None;self.ledger=None;self.control=None;self.sender=None;self.supervisor=None
        test.addCleanup(self.close)
        binary=Path(INSTALL)/'node_modules/@anthropic-ai/claude-code-linux-x64/claude'
        self.process=subprocess.Popen([NODE,str(ROOT/'tests/claude/library/host.mjs'),SDK,str(binary),str(self.root),
            str(self.home),f'http://127.0.0.1:{self.gateway.server_port}',self.gateway.key,self.session,
            str(self.endpoint),sys.executable,NODE,str(ROOT)],cwd=ROOT,
            env={'PATH':'/usr/bin:/bin','HOME':str(self.home)},start_new_session=True,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.hostfd=os.pidfd_open(self.process.pid,0)
        def read():
            try:
                for line in iter(lambda:self.process.stdout.readline(256*1024+1),b''):
                    if len(line)>256*1024 or not line.endswith(b'\n'):raise ValueError('fixture frame limit')
                    event=json.loads(line)
                    with self.condition:self.events.append(event);self.condition.notify_all()
            except Exception as error:self.errors.append(type(error).__name__)
        def errors():
            for line in iter(lambda:self.process.stderr.readline(4096),b''):self.errors.append(line.decode(errors='replace'))
        self.readers=[threading.Thread(target=read,daemon=True),threading.Thread(target=errors,daemon=True)]
        for thread in self.readers:thread.start()
        test.assertTrue(select.select([self.listener],[],[],10)[0],
            {'errors':list(self.errors),'startup':list(self.events)})
        self.channel,_=self.listener.accept();enable(self.channel);self.channel.settimeout(3)
        with receive(self.channel) as record:
            test.assertEqual(record.data,b'CLAUDE-LIBRARY-FIXTURE')
            self.origin=HeldOrigin(record)
        self.ledger=RoomLedger(self.root/'room.db',project);self.hub=FixturePeerHub(self.ledger)
        self.hub.configure('configure',(FixtureParticipant('claude','actor-'+project),
            FixtureParticipant('observer','observer-'+project)),'run-1')
        self.control,self.sender=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);enable(self.control)
        self.sender.send(b'trusted-supervisor')
        with receive(self.control) as record:self.supervisor=HeldOrigin(record)
        seat=AdmissionSeat(project,'instance','claude','actor-'+project,'library-profile',
            ('library:enqueue',) if capability else (),ReceiverIdentity(os.getuid(),os.getgid(),'hub-'+project,'a'*64))
        self.admissions=HubAdmission(self.root/'admission.db',seats=[seat],supervisor=self.supervisor,endpoint=Endpoint())
        launch=ExecLaunch(None,ExecSeat(project,'instance','claude','actor-'+project,'seat-a','b'*64,os.getuid(),os.getgid()),Endpoint(),self.root/'launch')
        launch.state='active';launch.origin=self.origin;launch.channel=self.channel;self.operation='a'*32
        send_admit(self.sender,launch=launch,seat=seat,operation_id=self.operation,epoch=1,readiness_digest='c'*64)
        self.admissions.admit(self.control)
        connection=self.hub.connect('capture-attach','claude',launch.incarnation,object())
        self.dispatcher=AdmittedPeerDispatcher(self.admissions,self.hub);self.dispatcher.attach(self.operation,connection)
        self.contact=EnqueueEndpoint(service.publisher,settings=lambda:service.settings).contact
        self.observed=[]
        def contact(**kw):self.observed.append(kw);return self.contact(**kw)
        self.owner=LibraryHub(self.ledger,room_id=project,project={'id':project,'repository':'acme/'+project,
            'roots':{'reference':'/srv/'+project+'/reference'}},source_identity='1001' if project=='alpha' else '1002',
            contact=contact,clock=lambda:support.AT)
        self.dispatcher.attach_library(self.owner)
        self.channel.sendall(b'UAS-HELPER-ACTIVE-1\n')
        ready=self.wait(lambda e:e.get('type')=='ready')
        test.assertEqual(ready['allowedTools'],['mcp__uas__library_enqueue']);test.assertEqual(ready['tools'],[])
        self.native_pid=ready['pid'];test.assertNotEqual(self.origin.credentials[0],self.native_pid)
        test.assertNotEqual(self.native_pid,self.process.pid)
        # The SDK owns the real native process, whose child launched the MCP helper.
        test.assertEqual(Path(f'/proc/{self.native_pid}/stat').read_text().rsplit(')',1)[1].split()[1],str(self.process.pid))
        test.assertEqual(self.gateway.requests,[],'initialization must not call the fixture model')

    def wait(self,predicate,timeout=10):
        until=time.monotonic()+timeout
        with self.condition:
            while True:
                found=next((e for e in self.events if predicate(e)),None)
                if found:return found
                if time.monotonic()>=until or select.select([self.hostfd],[],[],0)[0]:
                    self.test.fail(f'no native evidence; errors={list(self.errors)} events={list(self.events)}')
                self.condition.wait(.02)

    def invoke(self,request='request-1',capture=None,*,ordinary=False,dispatch=True,revoke=False):
        with self.gateway.lock:
            self.gateway.capture=None if ordinary else {'request_id':request,'capture':capture or support.value()}
            self.gateway.emitted=False
        start=len(self.events);identity=str(uuid.uuid4())
        wire=json.dumps({'op':'send','uuid':identity,'content':'Explicit capture fixture.' if not ordinary else 'Ordinary work.'})+'\n'
        self.process.stdin.write(wire.encode());self.process.stdin.flush()
        if not ordinary and dispatch:
            self.test.assertTrue(select.select([self.channel],[],[],10)[0],'native tool did not reach admitted Hub')
            if revoke:
                self.admissions.revoke(self.operation)
                # Close the fixture's extra bootstrap reference as the real
                # owner does on revocation; it carries no current authority.
                self.channel.shutdown(socket.SHUT_RDWR)
            else:self.dispatcher.receive(self.operation)
        result=self.wait(lambda e:e.get('type')=='native' and e['event'].get('type')=='result'
                         and e['event'].get('user_message_uuid')==identity)
        self.test.assertIsNone(result['fence']);self.test.assertFalse(result['event']['is_error'])
        events=list(self.events)[start:]
        init=[e['event'] for e in self.events if e.get('type')=='native' and e['event'].get('subtype')=='init']
        self.test.assertTrue(init,'actual native initialization event required')
        self.test.assertEqual(init[0]['tools'],['mcp__uas__library_enqueue'])
        blocks=[block for e in events if e.get('type')=='native' and e['event'].get('type')=='user'
          and isinstance(e['event'].get('message',{}).get('content'),list)
          for block in e['event']['message']['content'] if block.get('type')=='tool_result']
        if ordinary:
            self.test.assertEqual(blocks,[]);return None
        self.test.assertEqual(len(blocks),1,events)
        content=blocks[0]['content']
        if isinstance(content,list):content=''.join(b.get('text','') for b in content)
        return json.loads(content)

    def close(self):
        if self.process is not None:
            _dispose_sdk_process(self.process,self.hostfd,None,grace=.3)
            for thread in self.readers:thread.join(timeout=1)
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):stream.close()
            self.process=None
        if self.hostfd is not None:os.close(self.hostfd);self.hostfd=None
        for value in (self.admissions,self.ledger,self.origin,self.supervisor,self.channel,self.listener,self.control,self.sender):
            if value is not None:
                try:value.close()
                except OSError:pass
        self.gateway.shutdown();self.gateway.server_close();self.thread.join(timeout=1)


@unittest.skipUnless(INSTALL and SDK and NODE,'Official Claude native gate required')
class ClaudeLibraryNativeTests(unittest.TestCase):
    def test_exact_native_profile_capture_two_projects_and_failure_recovery(self):
        require_loopback_namespace()
        temp=tempfile.TemporaryDirectory(prefix='uas-clib-');self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        service=service_tests.EnqueueTests();service.setUp();self.addCleanup(service.doCleanups)
        beta_scope=service.make_scope('beta','acme/beta','1002')
        Registrar(service.publisher,current_scope=lambda:beta_scope).register(library.action(beta_scope,service.settings,
          kind='register',operation_id='register-beta',request_id='register-beta',payload={},at=support.AT),service.settings)
        alpha=NativeSession(self,'alpha',service)
        alpha.invoke(ordinary=True);self.assertEqual(alpha.observed,[])
        capture=support.value(title='Native_Claude_title',body='Exact Alpha **body**\n')
        first=alpha.invoke(capture=capture);self.assertEqual(first['outcome'],'DURABLY_QUEUED',first)
        self.assertEqual(alpha.observed[-1]['value'],capture)
        retry=alpha.invoke(capture=capture);self.assertEqual(retry['queue_id'],first['queue_id'])
        self.assertNotEqual(retry['command_id'],first['command_id'])
        conflict=alpha.invoke(capture=support.value(body='changed'))
        self.assertEqual((conflict['outcome'],conflict['reason']),('REJECTED','ID_CONFLICT'))
        original=alpha.contact
        def lost(**kw):original(**kw);raise OSError('PRIVATE_SERVICE_ERROR')
        alpha.contact=lost
        lost_result=alpha.invoke('lost',capture);self.assertEqual(lost_result['outcome'],'NOT_DURABLE')
        self.assertNotIn('PRIVATE_SERVICE_ERROR',json.dumps(lost_result))
        alpha.hub.contexts.close_run('closed','run-1',FixtureRunTerminal.COMPLETED)
        alpha.contact=original
        recovered=alpha.invoke('lost',capture);self.assertEqual(recovered['outcome'],'DURABLY_QUEUED')
        self.assertNotEqual(recovered['command_id'],lost_result['command_id'])
        large=support.value(body='L'*70000)
        large_result=alpha.invoke('large',large)
        self.assertEqual(large_result['outcome'],'DURABLY_QUEUED')
        self.assertEqual(alpha.observed[-1]['value'],large)
        alpha.dispatcher.library=None
        outage=alpha.invoke('outage',capture);self.assertEqual(outage['status'],'HUB_REFUSED')
        self.assertNotIn('outcome',outage);self.assertEqual(outage['reason'],'LIBRARY_UNAVAILABLE')
        alpha.invoke(ordinary=True)
        before=service.head()
        missing=NativeSession(self,'alpha',service,capability=False)
        refusal=missing.invoke(capture=capture)
        self.assertEqual((refusal['status'],refusal['reason']),('HUB_REFUSED','FORBIDDEN'))
        self.assertNotIn('outcome',refusal);self.assertEqual(missing.observed,[])
        self.assertEqual(service.head(),before)
        missing.invoke(ordinary=True)
        revoked=alpha.invoke('revoked',capture,revoke=True)
        self.assertEqual(revoked['status'],'TRANSPORT_UNAVAILABLE');self.assertNotIn('outcome',revoked)
        self.assertEqual(alpha.admissions.status(alpha.operation)['state'],'revoked')
        self.assertEqual(service.head(),before)
        beta=NativeSession(self,'beta',service)
        other=beta.invoke(capture=support.value(body='Distinct Beta body'))
        self.assertEqual(other['outcome'],'DURABLY_QUEUED');self.assertNotEqual(other['queue_id'],first['queue_id'])
        first_text=service.contents(first['path']);self.assertIn('Exact Alpha',first_text);self.assertNotIn('Distinct Beta',first_text)
        beta_text=git(service.target,'show',service.head()+':projects/'+beta_scope.project_path+'/'+other['path'])
        self.assertIn('Distinct Beta',beta_text);self.assertNotIn('Exact Alpha',beta_text)
        self.assertIn('Submission Actor: actor-alpha',first_text);self.assertIn('Submission Actor: actor-beta',beta_text)
        # Losing the Hub transport cannot invent a Library outcome or gate native completion.
        beta.channel.shutdown(socket.SHUT_RDWR)
        unavailable=beta.invoke('unavailable',capture,dispatch=False)
        self.assertEqual(unavailable['status'],'TRANSPORT_UNAVAILABLE');self.assertNotIn('outcome',unavailable)
        print(json.dumps({'proof':'actual Claude Library profile','cli':'2.1.310','sdk':'0.3.310',
          'projects':2,'native_profile':'library-capture-v1','provider':'loopback scripted fixture only',
          'actual_helper_kernel_origins':[alpha.origin.credentials[0],beta.origin.credentials[0]],
          'actual_native_pids':[alpha.native_pid,beta.native_pid]}))
