"""Finite local Manager HTTPS hosting over existing human mTLS grants.

No credential provisioning or new authority. The installation owner supplies an
already-bound loopback listener, server TLS context, explicit HumanActionBindings,
and fixed per-session document/action owners. Serve on their common owner thread;
SQLite and live grants are deliberately not transferred to worker threads.
"""
import json
import html as html_encoding
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from .human_mtls import HumanActionBindings, PATH
from .ledger import LedgerError, _json
from .manager_action_host import FieldNotesActionHost
from .manager_action_protocol import MAX_ACTION_BYTES
from .manager_transport import MAX_HEADERS, TIMEOUT, _pairs, _read_exact
from .manager_ui import FieldNotesDocument, MAX_DOCUMENT_BYTES


LOADER = b'''<!doctype html><html><meta charset="utf-8"><title>Ultimate Agent Sandbox</title>
<body><p id="status">Loading authenticated Field Notes...</p><script>
fetch('/uas/human-action/v1',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({version:1,action:'observe',payload:{kind:'document'}}),cache:'no-store'})
.then(async r=>{if(!r.ok)throw Error('Authentication or Room view unavailable');return r.json()})
.then(v=>{if(v.status!=='available'||typeof v.html!=='string')throw Error('Room view unavailable');
document.open();document.write(v.html);document.close()})
.catch(()=>{document.getElementById('status').textContent='Manager unavailable. Check the existing client certificate and Room grant. No actions were sent.'});
</script></body></html>'''

# Constant source, not supplied by a request or projection. Only the preselected
# one-Room owner is attached; the existing UI enforces stale-view/receipt fences.
ACTION_CLIENT = '''<script>
(function(){
const call=async(action,payload)=>{const r=await fetch('/uas/human-action/v1',{
method:'POST',headers:{'Content-Type':'application/json'},cache:'no-store',
body:JSON.stringify({version:1,action,payload})});if(!r.ok)throw Error('Manager request unavailable');return r.json();};
const packet=(kind,request)=>{if(!['request-changes','reconcile-changes'].includes(request.action))
throw Error('Action not granted by this transport');return call(request.action,{kind,request});};
for(const item of live.rooms)installActionHost(projectKey(item),{
view:run_id=>call('observe',{kind:'run',run_id}), lifecycle:()=>call('observe',{kind:'lifecycle'}),
replacement:participant_id=>call('observe',{kind:'replacement',participant_id}),
execute:request=>packet('execute',request), inspect:request=>packet('inspect',request)});
})();</script>'''


# A manual submission, never an automatic admission retry. The correlation stays
# fixed after any error; the user explicitly clears it for a different request.
OPEN_CLIENT = """<script>
(function(){
const form=document.createElement('form');form.id='native-open-run';
form.innerHTML='<h2>Open native Run</h2><p>Open one explicit issue. Admitted work continues after this page closes.</p><label>Issue number <input name="issue" type="number" min="1" max="9999999999" required></label> <button type="submit">Open Run</button> <button type="button" name="clear">New request</button><p role="status"></p>';
const issue=form.elements.issue,send=form.querySelector('[type=submit]'),clear=form.elements.clear,status=form.querySelector('[role=status]');
let operation=null,selected=null,busy=false;
clear.onclick=()=>{if(busy)return;operation=null;selected=null;issue.disabled=false;status.textContent='New request. No action sent.';};
form.onsubmit=async(event)=>{event.preventDefault();if(busy)return;
const number=Number(issue.value);if(!Number.isSafeInteger(number)||number<1||number>9999999999)return;
if(operation===null){operation=crypto.randomUUID();selected=number;}
if(selected!==number){status.textContent='Use New request to change the issue.';return;}
busy=true;send.disabled=true;clear.disabled=true;issue.disabled=true;
status.textContent='Submitting explicit Run admission. Operation '+operation;
try{const response=await fetch('/uas/human-action/v1',{method:'POST',headers:{'Content-Type':'application/json'},cache:'no-store',body:JSON.stringify({version:1,action:'open-run',payload:{operation_id:operation,issue_number:selected}})});
const result=await response.json();if(!response.ok)throw Error('unconfirmed');
status.textContent='Operation '+operation+': '+result.status+'; Run '+result.run_id+'; generation '+result.generation+(result.outcome?'; outcome '+result.outcome:'');
}catch(_){status.textContent='Outcome unconfirmed. Operation '+operation+'. No automatic retry. Inspect the Run before explicitly retrying this same request.';}
finally{busy=false;send.disabled=false;clear.disabled=false;}};
document.body.appendChild(form);
})();</script>"""


TERMINAL_CLIENT = """<script>
(function(){
const data=JSON.parse(document.getElementById('native-runtime-status').dataset.runtime);
if(!data.interrupted)return;
const button=document.createElement('button'),status=document.createElement('p');
button.textContent='End interrupted Run (keep files)';let operation=null,busy=false;
button.onclick=async()=>{if(busy)return;if(!confirm('End this interrupted Run before starting new work? Files are preserved; this does not mark the issue completed.'))return;
if(operation===null)operation=crypto.randomUUID();busy=true;button.disabled=true;
try{const response=await fetch('/uas/human-action/v1',{method:'POST',headers:{'Content-Type':'application/json'},cache:'no-store',body:JSON.stringify({version:1,action:'terminal-stop',payload:{operation_id:operation,run_id:data.run_id,generation:data.generation,control_revision:data.control_revision,reason:'operator-ended-interrupted-run'}})});
const value=await response.json();if(!response.ok)throw Error('unknown');
status.textContent='Run '+value.run_id+' ended as '+value.outcome+'. Refresh to open a new Run. Files remain preserved.';button.hidden=true;
}catch(_){status.textContent='Outcome unconfirmed. Operation '+operation+'. No automatic retry; inspect the Run before explicitly retrying.';}
finally{busy=false;button.disabled=false;}};
document.body.append(button,status);
})();</script>"""


class LocalManager:
    """Use `serve(listener, tls_context, stopped)` on the trusted owner thread.

    document_for(session) returns FieldNotesDocument for that exact single Room;
    action_host_for(session), if supplied, returns a fixed FieldNotesActionHost
    whose authenticate callback consumes the provided HumanSession context.
    There is no default grant and no browser-selected owner or filesystem path.
    """
    def __init__(self, bindings, document_for, *, authority, action_host_for=None, run_actions=None, current=None):
        if type(bindings) is not HumanActionBindings or not callable(document_for):
            raise LedgerError('LOCAL_MANAGER_BINDINGS_REQUIRED')
        if action_host_for is not None and not callable(action_host_for):
            raise LedgerError('LOCAL_MANAGER_ACTION_HOST_REQUIRED')
        if (type(authority) is not str or
                not re.fullmatch(r'(?:127\.0\.0\.1|localhost|\[::1\]):[0-9]{1,5}', authority) or
                not 1 <= int(authority.rsplit(':',1)[1]) <= 65535):
            raise LedgerError('LOCAL_MANAGER_AUTHORITY_REQUIRED')
        if run_actions is not None:
            from .local_manager_actions import LocalNativeRunActions
            if type(run_actions) is not LocalNativeRunActions:
                raise LedgerError('LOCAL_NATIVE_RUN_ACTIONS_REQUIRED')
        if current is not None and not callable(current):
            raise LedgerError('LOCAL_MANAGER_CURRENT_REQUIRED')
        self.current = current
        self.run_actions = run_actions
        self.bindings, self.document_for = bindings, document_for
        self.authority, self.action_host_for = authority, action_host_for
        self._thread = threading.get_ident()

    def _owner(self):
        if threading.get_ident() != self._thread:
            raise LedgerError('LOCAL_MANAGER_OWNER_REQUIRED')

    def _read(self, channel):
        deadline = time.monotonic() + TIMEOUT
        header = bytearray()
        while not header.endswith(b'\r\n\r\n'):
            if len(header) >= MAX_HEADERS: raise LedgerError('LOCAL_HTTP_HEADER_LIMIT')
            header.extend(_read_exact(channel, 1, deadline))
        lines = header[:-4].decode('ascii').split('\r\n')
        if len(lines[0]) > 2048: raise LedgerError('LOCAL_HTTP_ROUTE_DENIED')
        parts = lines[0].split(' ')
        if len(parts) != 3 or parts[2] != 'HTTP/1.1': raise LedgerError('LOCAL_HTTP_ROUTE_DENIED')
        method, target, _ = parts
        headers = {}
        for line in lines[1:]:
            name, colon, value = line.partition(':'); name = name.lower()
            if (not colon or not re.fullmatch('[a-z0-9-]+',name) or name in headers
                    or any(ord(c)<32 or ord(c)==127 for c in value)):
                raise LedgerError('LOCAL_HTTP_HEADERS_INVALID')
            headers[name] = value.strip()
        if (headers.get('host') != self.authority or
                any(k in headers for k in ('transfer-encoding','content-encoding','expect')) or
                headers.get('origin', 'https://'+self.authority) != 'https://'+self.authority):
            raise LedgerError('LOCAL_HTTP_ORIGIN_DENIED')
        if method == 'GET':
            url = urlsplit(target)
            if (url.scheme or url.netloc or url.path != '/' or url.fragment or
                    headers.get('content-length','0') != '0'):
                raise LedgerError('LOCAL_HTTP_ROUTE_DENIED')
            return None
        if (method != 'POST' or target != PATH or headers.get('content-type') != 'application/json'
                or not re.fullmatch('[0-9]{1,6}',headers.get('content-length',''))):
            raise LedgerError('LOCAL_HTTP_ROUTE_DENIED')
        length = int(headers['content-length'])
        if not 0 < length <= MAX_ACTION_BYTES: raise LedgerError('LOCAL_HTTP_BODY_LIMIT')
        return json.loads(_read_exact(channel,length,deadline).decode('utf-8'),object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))

    @staticmethod
    def _send(channel, status, content, mime='application/json'):
        if type(content) is not bytes or len(content)>MAX_DOCUMENT_BYTES+65536:
            raise LedgerError('LOCAL_HTTP_RESPONSE_LIMIT')
        head = (f'HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {len(content)}\r\n'
                'Cache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n'
                "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'\r\n\r\n")
        channel.settimeout(TIMEOUT); channel.sendall(head.encode('ascii')+content)

    def handle(self, channel):
        """Handle one request on an established TLS socket; caller closes it."""
        self._owner(); connection = None; action_attempted = False
        try:
            # Even the public loader requires a registered client certificate;
            # its actual data request separately receives request-scoped authority.
            if self.current is not None: self.current()
            connection = self.bindings.accept(channel)
            value = self._read(channel)
            if value is None:
                self._send(channel,'200 OK',LOADER,'text/html; charset=utf-8'); return
            with connection.request(value) as (frame, session):
                payload = frame['payload']
                if frame['action']=='observe' and payload=={'kind':'document'}:
                    document=self.document_for(session)
                    if type(document) is not FieldNotesDocument:
                        raise LedgerError('LOCAL_MANAGER_DOCUMENT_REQUIRED')
                    bindings=document._bindings
                    if (len(bindings)!=1 or bindings[0].identity.deployment_id!=session.deployment_id or
                            bindings[0].identity.room_id!=session.room_id):
                        raise LedgerError('LOCAL_MANAGER_SCOPE_MISMATCH')
                    html=document.render()
                    if self.run_actions is not None:
                        status=self.run_actions.status(session)
                        notice='<p id="native-runtime-status" data-runtime="'+html_encoding.escape(_json(status),quote=True)+'">Native runtime: '+html_encoding.escape(_json(status))+'</p>'
                        html=html.replace('</body>',notice+'</body>')
                        if status.get('interrupted') and 'terminal-stop' in connection._grant.actions:
                            html=html.replace('</body>',TERMINAL_CLIENT+'</body>')
                    if self.action_host_for is not None or self.run_actions is not None:
                        html=html.replace('</body>',ACTION_CLIENT+'</body>')
                    # Rendering availability is not action authority: an observe
                    # session cannot authorize open-run. The later POST must
                    # obtain its own exact request scope from the same binding.
                    connection._current()
                    if (self.run_actions is not None and
                            {'open-run','authorize-run-request'}.issubset(connection._grant.actions)):
                        html=html.replace('</body>',OPEN_CLIENT+'</body>')
                    result={'status':'available','html':html}
                elif frame['action']=='open-run' and self.run_actions is not None:
                    action_attempted = True
                    result=self.run_actions.open(payload,session,grant=connection.run_admission_lease(
                        session,payload.get('operation_id'),payload.get('issue_number')))
                elif frame['action']=='terminal-stop' and self.run_actions is not None:
                    action_attempted=True
                    result=self.run_actions.terminal(payload,session)
                elif self.run_actions is not None and self.action_host_for is None:
                    connection._current()
                    action_attempted=payload.get('kind')=='execute'
                    result=self.run_actions.control(frame,payload,session,
                        available_actions=tuple(connection._grant.actions))
                elif self.action_host_for is not None:
                    host=self.action_host_for(session)
                    if type(host) is not FieldNotesActionHost:
                        raise LedgerError('LOCAL_MANAGER_ACTION_HOST_REQUIRED')
                    if (payload.get('kind') in {'execute','inspect'} and
                            (type(payload.get('request')) is not dict or
                             payload['request'].get('action') != frame['action'])):
                        raise LedgerError('LOCAL_MANAGER_ACTION_MISMATCH')
                    result=host.handle(_json(payload).encode(),context=session)
                else:
                    raise LedgerError('LOCAL_MANAGER_ACTIONS_UNAVAILABLE')
                if self.current is not None: self.current()
                if not session.allowed(frame['action']): raise LedgerError('LOCAL_MANAGER_AUTHENTICATION_REVOKED')
                self._send(channel,'200 OK',_json(result).encode())
        except (LedgerError,ValueError,UnicodeError,OSError):
            if action_attempted:
                self._send(channel,'503 Service Unavailable',b'{"status":"unavailable","outcome":"unknown"}')
            else:
                self._send(channel,'403 Forbidden',b'{"status":"unavailable"}')
        except Exception:
            # No owner details or blind retry after an uncertain action outcome.
            self._send(channel,'503 Service Unavailable',b'{"status":"unavailable","outcome":"unknown"}')
        finally:
            if connection is not None: connection.close()

    def serve(self, listener, tls_context, stopped, *, idle=None):
        """Borrow an existing loopback listener; stop never destroys Room data."""
        self._owner()
        if (type(tls_context) is not ssl.SSLContext or tls_context.verify_mode!=ssl.CERT_REQUIRED
                or tls_context.minimum_version<ssl.TLSVersion.TLSv1_3 or not callable(stopped)
                or idle is not None and not callable(idle)):
            raise LedgerError('LOCAL_MANAGER_TLS_REQUIRED')
        address=listener.getsockname()
        if address[0] not in ('127.0.0.1','::1') or int(address[1])!=int(self.authority.rsplit(':',1)[1]):
            raise LedgerError('LOCAL_MANAGER_LOOPBACK_REQUIRED')
        previous=listener.gettimeout();listener.settimeout(0.25)
        try:
            while not stopped():
                if idle is not None:idle()
                try: raw,_=listener.accept()
                except socket.timeout: continue
                with raw:
                    raw.settimeout(TIMEOUT)
                    try:
                        with tls_context.wrap_socket(raw,server_side=True) as channel:
                            self.handle(channel)
                    except (OSError,ValueError):
                        # No automatic mutation retry; one connection failed.
                        continue
        finally:
            listener.settimeout(previous)


# This descriptor is selected by the trusted installation, never by HTTP input.
# It carries existing grants and TLS paths only; no key material or provisioning.
from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import stat
from .human_mtls import HumanActionGrant
from .ledger import Origin
from .native_pi_recipe import path, read_manifest
from .manager_transport import server_tls_context


def _require(value, code='LOCAL_MANAGER_SELECTION_INVALID'):
    if not value: raise LedgerError(code)


def _tls_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def _held_tls(filename, *, private, stack):
    filename = Path(path(filename))
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in filename.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory); directory = child
            info = os.fstat(directory)
            _require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
                     'LOCAL_MANAGER_TLS_REFERENCE_UNAVAILABLE')
        fd = os.open(filename.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
    finally:
        os.close(directory)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid()) and info.st_nlink == 1
        and 0 < info.st_size <= 1048576 and not info.st_mode & (0o077 if private else 0o022),
        'LOCAL_MANAGER_TLS_REFERENCE_UNAVAILABLE')
    return fd, _tls_identity(info)


@dataclass(frozen=True)
class ManagerSelection:
    """Validated existing single-Room grant; TLS files open only at runtime.

    read(ref, **scope) consumes {path,sha256} selected by the installation.
    scope is deployment_id, room_id, instance_id, configuration_sha256. A new
    Room instance requires a matching explicit grant, not automatic rebinding.
    Document/action owners remain trusted constructor injections.
    """
    authority: str
    fingerprint: str
    grant: HumanActionGrant
    tls: tuple
    configuration_sha256: str

    @classmethod
    def read(cls, reference, **scope):
        _require(type(reference) is dict and set(reference) == {'path','sha256'})
        path(reference['path'])
        return cls.parse(read_manifest(reference['path'], reference['sha256']), **scope)

    @classmethod
    def parse(cls, value, *, deployment_id, room_id, instance_id, configuration_sha256):
        fields = {'version','purpose','deployment_id','room_id','instance_id','configuration_sha256',
                  'authority','manager_id','client_certificate_sha256','human_origin','actions','tls'}
        _require(type(value) is dict and set(value) == fields and type(value['version']) is int
                 and value['version'] == 1 and value['purpose'] == 'local-manager-v1')
        _require((value['deployment_id'],value['room_id'],value['instance_id'],value['configuration_sha256'])
                 == (deployment_id,room_id,instance_id,configuration_sha256), 'LOCAL_MANAGER_SCOPE_MISMATCH')
        for digest in (configuration_sha256,value['client_certificate_sha256']):
            _require(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest))
        authority=value['authority']
        _require(type(authority) is str and re.fullmatch(r'(?:127\.0\.0\.1|localhost|\[::1\]):[0-9]{1,5}',authority)
                 and 1 <= int(authority.rsplit(':',1)[1]) <= 65535)
        origin=value['human_origin']
        _require(type(origin) is dict and set(origin)=={'actor_id','participant_id','incarnation_id',
                  'authority_version','capabilities'} and type(origin['capabilities']) is list)
        human=Origin(**{**origin,'capabilities':tuple(origin['capabilities'])})
        _require(human.canonical()==origin)
        _require(type(value['actions']) is list and 'observe' in value['actions'])
        grant=HumanActionGrant(deployment_id,room_id,instance_id,value['manager_id'],human,tuple(value['actions']))
        if {'open-run','authorize-run-request'}.intersection(grant.actions):
            _require({'open-run','authorize-run-request'}.issubset(grant.actions)
                     and 'human-open-run' in human.capabilities)
        if {'request-changes','reconcile-changes'}.intersection(grant.actions):
            _require('human-control-run' in human.capabilities)
        tls=value['tls']
        _require(type(tls) is dict and set(tls)=={'trust_file','certificate_file','private_key_file'})
        for filename in tls.values(): path(filename)
        return cls(authority,value['client_certificate_sha256'],grant,tuple(sorted(tls.items())),configuration_sha256)

    def manager(self, document_for, *, action_host_for=None, run_actions=None, current=None):
        return LocalManager(HumanActionBindings({self.fingerprint:self.grant}),document_for,
                            authority=self.authority,action_host_for=action_host_for,run_actions=run_actions,current=current)

    def require_unchanged(self, reference):
        """Revalidate only this existing selected descriptor, not root installation."""
        observed=type(self).read(reference,deployment_id=self.grant.deployment_id,
            room_id=self.grant.room_id,instance_id=self.grant.instance_id,
            configuration_sha256=self.configuration_sha256)
        _require(observed==self,'LOCAL_MANAGER_SELECTION_CHANGED')

    def tls_context(self):
        """Load existing credentials by held nofollow FD, never return their bytes."""
        with ExitStack() as stack:
            held={key:_held_tls(filename,private=key=='private_key_file',stack=stack)
                  for key,filename in self.tls}
            context=server_tls_context(**{key:'/proc/self/fd/'+str(item[0]) for key,item in held.items()})
            for fd,identity in held.values():
                _require(_tls_identity(os.fstat(fd))==identity,'LOCAL_MANAGER_TLS_REFERENCE_CHANGED')
            return context
