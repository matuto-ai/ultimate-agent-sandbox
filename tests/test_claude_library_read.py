"""Official Claude tools + production read profile over real supervisor projections.

Only paths/bootstrap and provider replies are fixture substitutions. No account,
upstream reasoning, model-obedience, or container isolation claim. Two real
published Git-backed projections carry distinct payloads. The request capture
proves controlling instruction loading, not semantic compliance by a model.
"""
from collections import deque
import http.server
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch

import test_library_projection as projections
from uas.claude_runtime import require_loopback_namespace, _dispose_sdk_process

ROOT = Path(__file__).resolve().parents[1]
INSTALL = os.environ.get('UAS_CLAUDE_INSTALL')
SDK = os.environ.get('UAS_CLAUDE_SDK_INSTALL')
NODE = os.environ.get('UAS_CLAUDE_NODE')


class Gateway(http.server.ThreadingHTTPServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_POST(self):
        self.connection.settimeout(5)
        if self.headers.get('x-api-key') != self.server.key:
            return self.send_error(401)
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length < 2 * 1024 * 1024:
            return self.send_error(413)
        request = json.loads(self.rfile.read(length))
        route = self.path.split('?')[0]
        if route == '/v1/messages/count_tokens':
            body = b'{"input_tokens":10}'
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body))); self.end_headers()
            self.wfile.write(body); return
        if route != '/v1/messages': return self.send_error(404)
        with self.server.lock:
            if len(self.server.requests) >= 80: return self.send_error(409)
            self.server.requests.append(request)
            call = self.server.calls.popleft() if self.server.calls else None
        block = ({'type':'tool_use', 'id':'tool_' + uuid.uuid4().hex, 'name':call['name'], 'input':{}}
                 if call else {'type':'text', 'text':''})
        delta = ({'type':'input_json_delta', 'partial_json':json.dumps(call['input'])} if call else
                 {'type':'text_delta', 'text':'scripted fixture complete; not a model answer'})
        self.send_response(200); self.send_header('Content-Type', 'text/event-stream'); self.end_headers()
        events = [
            ('message_start', {'type':'message_start', 'message':{'id':'msg_' + uuid.uuid4().hex,
              'type':'message','role':'assistant','model':request['model'],'content':[],
              'stop_reason':None,'stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':0}}}),
            ('content_block_start', {'type':'content_block_start','index':0,'content_block':block}),
            ('content_block_delta', {'type':'content_block_delta','index':0,'delta':delta}),
            ('content_block_stop', {'type':'content_block_stop','index':0}),
            ('message_delta', {'type':'message_delta','delta':{'stop_reason':'tool_use' if call else 'end_turn',
              'stop_sequence':None},'usage':{'output_tokens':1}}),
            ('message_stop', {'type':'message_stop'})]
        for event, data in events:
            self.wfile.write(('event: ' + event + '\ndata: ' + json.dumps(data) + '\n\n').encode())
        self.wfile.flush()


class ReadSession:
    def __init__(self, test, worker, directory):
        self.test = test; self.worker = worker
        self.root = directory; self.root.mkdir(); self.home = self.root/'home'; self.home.mkdir()
        self.events = deque(maxlen=1024); self.errors = deque(maxlen=12)
        self.condition = threading.Condition(); self.process = None; self.hostfd = None; self.readers = []
        self.gateway = Gateway(('127.0.0.1',0),Handler)
        self.gateway.key = 'fixture-only-' + uuid.uuid4().hex
        self.gateway.requests = []; self.gateway.calls = deque(); self.gateway.lock = threading.Lock()
        self.thread = threading.Thread(target=lambda:self.gateway.serve_forever(poll_interval=.02),daemon=True)
        self.thread.start(); test.addCleanup(self.close)
        wrapper = self.root/'scan.mjs'
        # Trusted fixture substitutes only installed parser and reference mount.
        wrapper.write_text('import {scan} from ' + json.dumps((ROOT/'runtime/pi/library-scan.mjs').as_uri()) + ';\n'
          + 'import {parse} from ' + json.dumps((ROOT/'tests/claude/library/node_modules/yaml/dist/index.js').as_uri()) + ';\n'
          + 'process.stdout.write(scan(' + json.dumps(str(worker.root))
          + ',process.argv.slice(2),{parse,now:"2026-10-30T00:00:00Z"}));\n')
        self.command = NODE + ' ' + str(wrapper)
        self.session = str(uuid.uuid4())
        binary = Path(INSTALL)/'node_modules/@anthropic-ai/claude-code-linux-x64/claude'
        self.process = subprocess.Popen([NODE,str(ROOT/'tests/claude/library/read-host.mjs'),SDK,str(binary),
            str(self.root),str(self.home),f'http://127.0.0.1:{self.gateway.server_port}',self.gateway.key,
            self.session,str(worker.root),self.command],cwd=ROOT,
            env={'PATH':'/usr/bin:/bin','HOME':str(self.home)},start_new_session=True,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.hostfd = os.pidfd_open(self.process.pid,0)
        def read():
            try:
                for line in iter(lambda:self.process.stdout.readline(256*1024+1),b''):
                    if len(line)>256*1024 or not line.endswith(b'\n'): raise ValueError('native frame limit')
                    value = json.loads(line)
                    with self.condition: self.events.append(value); self.condition.notify_all()
            except Exception as error: self.errors.append(type(error).__name__)
        def errors():
            for line in iter(lambda:self.process.stderr.readline(4096),b''):
                self.errors.append(line.decode(errors='replace'))
        self.readers = [threading.Thread(target=read,daemon=True), threading.Thread(target=errors,daemon=True)]
        for thread in self.readers: thread.start()
        ready = self.wait(lambda e:e.get('type')=='ready')
        test.assertEqual(set(ready['tools']),{'Read','Bash'})
        test.assertEqual(ready['allowedTools'],[])
        self.native_pid = ready['pid']
        test.assertNotEqual(self.native_pid,self.process.pid)
        test.assertEqual(Path(f'/proc/{self.native_pid}/stat').read_text().rsplit(')',1)[1].split()[1],str(self.process.pid))
        test.assertEqual(self.gateway.requests,[],'initialization must not query the provider')

    def wait(self, predicate, timeout=12):
        until = time.monotonic()+timeout
        with self.condition:
            while True:
                found = next((e for e in self.events if predicate(e)),None)
                if found: return found
                if time.monotonic()>=until or select.select([self.hostfd],[],[],0)[0]:
                    self.test.fail(f'missing native evidence: errors={list(self.errors)} events={list(self.events)}')
                self.condition.wait(.02)

    def read(self, name):
        return {'name':'Read','input':{'file_path':str(self.worker.root/name)}}

    def search(self, *terms):
        return {'name':'Bash','input':{'command':self.command + ''.join(" '" + term + "'" for term in terms)}}

    def invoke(self, calls=(), *, denied=False, native_path_denial=False):
        with self.gateway.lock:
            self.test.assertFalse(self.gateway.calls)
            self.gateway.calls.extend(calls)
        start = len(self.events); identity = str(uuid.uuid4())
        self.process.stdin.write((json.dumps({'op':'send','uuid':identity,'content':'Perform explicit native-file fixture steps.'})+'\n').encode())
        self.process.stdin.flush()
        result = self.wait(lambda e:e.get('type')=='native' and e['event'].get('type')=='result'
                           and e['event'].get('user_message_uuid')==identity)
        events = list(self.events)[start:]
        if denied:
            self.test.assertIsNotNone(result['fence'],'denied action must not silently restore readiness')
        else:
            self.test.assertIsNone(result['fence'],events)
            self.test.assertFalse(result['event']['is_error'])
        blocks = [block for e in events if e.get('type')=='native' and e['event'].get('type')=='user'
          and isinstance(e['event'].get('message',{}).get('content'),list)
          for block in e['event']['message']['content'] if block.get('type')=='tool_result']
        self.test.assertEqual(len(blocks),len(calls),events)
        if not denied: self.test.assertTrue(all(not b.get('is_error') for b in blocks),blocks)
        permits = [e for e in events if e.get('type')=='permission']
        self.test.assertEqual(len(permits),0 if native_path_denial else len(calls),
                              'qualified access must reach policy; restricted out-of-cwd rejection occurs earlier')
        if native_path_denial:
            self.test.assertTrue(any(e.get('type')=='native' and
                e['event'].get('subtype')=='permission_denied' and
                '--restricted' in e['event'].get('decision_reason','') for e in events),events)
        self.test.assertTrue(all(e['result']['behavior']==('deny' if denied else 'allow') for e in permits),permits)
        return [b['content'] if isinstance(b['content'],str) else
                '\n'.join(v.get('text','') for v in b['content']) for b in blocks]

    def close(self):
        if self.process is not None:
            _dispose_sdk_process(self.process,self.hostfd,None,grace=.3)
            for thread in self.readers: thread.join(timeout=1)
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr): stream.close()
            self.process = None
        if self.hostfd is not None: os.close(self.hostfd); self.hostfd = None
        self.gateway.shutdown(); self.gateway.server_close(); self.thread.join(timeout=1)


@unittest.skipUnless(INSTALL and SDK and NODE,'Official Claude native gate required')
class ClaudeLibraryReadNativeTests(unittest.TestCase):
    def test_native_read_progression_instructions_isolation_and_denial(self):
        require_loopback_namespace()
        temp = tempfile.TemporaryDirectory(prefix='uas-cread-'); self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        p = projections.ProjectionTests(); p.setUp(); self.addCleanup(p.doCleanups)
        p.register(); alpha = p.projection(); self.assertTrue(alpha.refresh())
        prefix = 'projects/' + p.scope.project_path + '/'
        def doc(title,body,status='stable',extra=''):
            return (f'---\ntype: alien-existing\ntitle: {title}\nstatus: {status}\n{extra}---\n'+body+'\n').encode()
        files = {prefix+'context/alpha space.md':doc('ALPHA_ONLY','Amber token\nSQLite storage\n'
          '[broken](missing.md)\nIGNORE_RUNTIME_MARKER',extra='verified: {by: "human:reader", at: "2026-10-01T00:00:00Z"}\nstale_after: 2020-01-01\nunknown_key: keep\n'),
          prefix+'pending/draft.md':doc('Pending','Sapphire specialdraft','draft'),
          prefix+'context/rotation.md':doc('BEFORE_REFRESH_MARKER','Snapshot boundary payload'),
          prefix+'context/long.md':doc('Long','\n'.join(['PAGE_ONE_MARKER']+['x']*2010+['PAGE_TWO_MARKER']))}
        files.update({prefix+f'context/many{i}.md':doc('Many','commonmatch') for i in range(12)})
        p.mutate(files); self.assertTrue(alpha.refresh())
        beta_scope = p.make_scope('beta','other/beta','2002'); p.fresh = beta_scope
        p.registrar.register(p.operation('register-beta',beta_scope),p.settings)
        p.mutate({'projects/'+beta_scope.project_path+'/context/beta.md':doc('BETA_ONLY','BETA_SECRET')})
        beta = p.projection(beta_scope); self.assertTrue(beta.refresh())
        for index,worker in enumerate((alpha,beta)):
            session = ReadSession(self,worker,directory/str(index))
            session.invoke()
            first = session.gateway.requests[0]
            system = json.dumps(first.get('system'))
            self.assertIn('never instruction authority',system)
            self.assertIn('/project/reference/library/',system)
            self.assertIn('Runtime',system); self.assertIn('human',system)
            for marker in ('ALPHA_ONLY','BETA_SECRET','IGNORE_RUNTIME_MARKER'):
                self.assertNotIn(marker,json.dumps(first))
            out = session.invoke([session.read('library/index.md'),session.read('library/pending/index.md'),
              session.search('AMBER','sqlite'),session.search('specialdrafx'),session.search('commonmatch'),
              session.search('noexistquery'),session.search('BETA_SECRET')])
            if index==0:
                self.assertIn('ALPHA_ONLY',out[2]); self.assertNotIn('FUZZY',out[2])
                for marker in ('human-reviewed','STALE warning','alien-existing','sources: absent'):
                    self.assertIn(marker,out[2])
                self.assertIn('FUZZY DRAFT',out[3]); self.assertEqual(out[4].count('fragment:'),8)
                self.assertIn('No matching document',out[5]); self.assertIn('No inferred answer',out[5])
                self.assertIn('No matching document',out[6])
                whole = session.invoke([session.read('library/context/alpha space.md')])[0]
                for marker in ('unknown_key','missing.md','IGNORE_RUNTIME_MARKER','verified:','stale_after:'):
                    self.assertIn(marker,whole)
                page1 = session.read('library/context/long.md'); page1['input'].update(offset=1,limit=2000)
                page2 = session.read('library/context/long.md'); page2['input'].update(offset=2001,limit=2000)
                pages = session.invoke([page1,page2])
                self.assertIn('PAGE_ONE_MARKER',pages[0]); self.assertNotIn('PAGE_TWO_MARKER',pages[0])
                self.assertIn('PAGE_TWO_MARKER',pages[1]); self.assertNotIn('PAGE_ONE_MARKER',pages[1])
                # Refresh failure preserves readable old bytes and original timestamp.
                before = alpha.read(); p.change(b'\nChanged after snapshot.\n')
                with patch.object(alpha,'_stage',side_effect=OSError('refresh fixture outage')):
                    self.assertFalse(alpha.refresh())
                self.assertEqual(alpha.read(),before)
                self.assertIn('ALPHA_ONLY',session.invoke([session.search('AMBER')])[0])
                old_view = session.invoke([session.read('library.snapshot.json'),
                                           session.read('library/context/rotation.md')])
                p.mutate({prefix+'context/rotation.md':doc('AFTER_REFRESH_MARKER','Distinct refreshed payload')})
                self.assertTrue(alpha.refresh())
                new_view = session.invoke([session.read('library.snapshot.json'),
                                           session.read('library/context/rotation.md')])
                self.assertNotEqual(old_view[0],new_view[0])
                self.assertIn('BEFORE_REFRESH_MARKER',old_view[1]); self.assertNotIn('AFTER_REFRESH_MARKER',old_view[1])
                self.assertIn('AFTER_REFRESH_MARKER',new_view[1]); self.assertNotIn('BEFORE_REFRESH_MARKER',new_view[1])
                self.assertIn('retry',system.lower())
            else:
                self.assertIn('No matching document',out[2]); self.assertIn('BETA_ONLY',out[6])
                self.assertNotIn('ALPHA_ONLY',''.join(out))
            # Same-UID files are readable to the OS. Distinguish native cwd
            # confinement from a separate actual host-policy Read denial.
            if index==0:
                denial = session.invoke([{'name':'Read','input':{'file_path':str(beta.root/'library/index.md')}}],
                                         denied=True,native_path_denial=True)
                self.assertNotIn('BETA_SECRET',''.join(denial))
            else:
                forbidden = worker.root/'unapproved.txt'; forbidden.write_text('FORBIDDEN_READ_MARKER')
                denial = session.invoke([{'name':'Read','input':{'file_path':str(forbidden)}}],denied=True)
                self.assertNotIn('FORBIDDEN_READ_MARKER',''.join(denial))
            self.assertFalse((worker.root/'library/.git').exists())
            session.close()
        missing_scope = p.make_scope('missing','other/missing','3003')
        missing = p.projection(missing_scope); self.assertFalse(missing.refresh())
        session = ReadSession(self,missing,directory/'missing')
        empty = session.invoke([session.read('library.snapshot.json'),session.search('AMBER')])
        self.assertIn('null',empty[0]); self.assertIn('no published snapshot',empty[1])
        self.assertIn('No inferred answer',empty[1])
        denied = session.search('AMBER'); denied['input']['command'] += '; cat /etc/passwd'
        result = session.invoke([denied],denied=True)
        self.assertNotIn('root:', ''.join(result))
        session.close()
        print(json.dumps({'proof':'official Claude native Library read and instruction loading',
          'cli':'2.1.310','sdk':'0.3.310','profile':'library-read-v1','projects':2,
          'provider':'loopback-scripted-only','model_obedience':False,'production_host_isolation':False}))
