"""Native SDK control receiver over the concrete Supervisor-owned child root.

Uses the existing Claude handoff journal/receipt algorithm, not fixture startup,
credentials, PID adoption or a second workflow store. Kernel ownership remains
in NativeClaudeRoot; stream claims alone never admit a Participant.
"""
import fcntl
import json
import os
from pathlib import Path
import select
import sqlite3
import stat
import time
import threading
import uuid

from .claude_runtime import _ClaudeJournal, _ack_matches, ClaudeUnavailable, ClaudeNotApplied
from .ledger import LedgerError
from .peer import Readiness


class NativeClaudeReceiver(_ClaudeJournal):
    MAX_FRAME=262144
    def __init__(self, root, *, journal, timeout=8):
        from .claude_native_admission import NativeClaudeRoot
        if type(root) is not NativeClaudeRoot or type(timeout) not in (int,float) or not 0<timeout<=30:
            raise ClaudeUnavailable('typed live Claude root required')
        self._serial=threading.RLock()
        self.root=root; root.current()
        self.recipe=root.recipe; self.scope=self.recipe.scope
        self.session_id=self.recipe.session_id; self.incarnation_id=root.incarnation
        self.timeout=timeout; self.owner=self.db=self.io=None
        self.closed=False; self.fenced=None; self.ready=False; self._stderr_eof=False
        self.native_spawned=False; self.revision=0; self.ack=None; self.pending=None
        self.buffer=bytearray(); self.reply=None; self.reply_id=None
        try:
            self._open_native_journal(journal)
            self.io=root.host_launch.transport.rpc_io()
            for stream in (self.io.stdin,self.io.stdout,self.io.stderr): os.set_blocking(stream.fileno(),False)
            deadline=time.monotonic()+timeout
            while not self.ready: self._pump(deadline)
        except BaseException:
            self.close(); raise

    def _open_native_journal(self,journal):
        selected=Path(journal)
        parent=selected.parent
        info=parent.stat()
        if (not selected.is_absolute() or parent.resolve()!=parent or not stat.S_ISDIR(info.st_mode)
                or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700):
            raise ClaudeUnavailable('private Supervisor journal directory required')
        owner_fd=os.open(str(selected)+'.owner',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        self.owner=os.fdopen(owner_fd,'r+b',buffering=0)
        node=os.fstat(owner_fd)
        if not stat.S_ISREG(node.st_mode) or node.st_uid!=os.getuid() or node.st_mode & 0o077:
            raise ClaudeUnavailable('private journal owner required')
        fcntl.flock(owner_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        fd=os.open(selected,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK | (0 if self.recipe.resume else os.O_CREAT|os.O_EXCL),0o600)
        try:
            node=os.fstat(fd)
            if not stat.S_ISREG(node.st_mode) or node.st_uid!=os.getuid() or node.st_mode & 0o077:
                raise ClaudeUnavailable('private journal required')
        finally: os.close(fd)
        self.db=sqlite3.connect(selected)
        self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), scope TEXT, session_id TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS handoffs (logical_digest TEXT PRIMARY KEY, logical TEXT, message_id TEXT, receipt TEXT, retryable INTEGER NOT NULL DEFAULT 0 CHECK(retryable IN (0,1)))')
        previous=self.db.execute('SELECT scope,session_id FROM binding WHERE singleton=1').fetchone()
        if bool(previous)!=self.recipe.resume or (previous and (json.loads(previous[0])!=self.scope or previous[1]!=self.session_id)):
            raise ClaudeUnavailable('native scope/session restore mismatch')
        if not previous:
            with self.db: self.db.execute('INSERT INTO binding VALUES (1,?,?)',(json.dumps(self.scope),self.session_id))

    def _current(self):
        if self.closed or self.fenced: raise ClaudeUnavailable('native receiver fenced')
        self.root.current()

    def _frame(self,frame):
        if type(frame) is not dict: raise ClaudeUnavailable('invalid native frame')
        kind=frame.get('type')
        if kind=='native-spawned':
            if (self.native_spawned or frame.get('native_pid')!=self.root.native_namespace_pid
                    or frame.get('session_id')!=self.session_id): raise ClaudeUnavailable('native child mismatch')
            self.native_spawned=True
        elif kind=='host-ready':
            if (self.ready or not self.native_spawned or frame.get('native_pid')!=self.root.native_namespace_pid
                    or frame.get('session_id')!=self.session_id or frame.get('sdk_version')!='0.3.310'
                    or frame.get('cli_version')!='2.1.310' or frame.get('authority')!='native-child-awaits-supervisor-admission'
                    or frame.get('fresh_context')!='exclusive-new-home-explicit-session-no-input'):
                raise ClaudeUnavailable('unsupported native ready frame')
            self.ready=True
        elif kind=='native':
            self.revision+=1
            if frame.get('fence'): raise ClaudeUnavailable('native policy fenced')
            event=frame.get('event')
            if type(event) is not dict or event.get('session_id')!=self.session_id: raise ClaudeUnavailable('native event scope')
            if self.pending and _ack_matches(event,self.session_id,*self.pending): self.ack=event
        elif kind=='reply':
            if frame.get('id')!=self.reply_id or self.reply is not None: raise ClaudeUnavailable('uncorrelated native reply')
            self.reply={**frame,'_seen_revision':self.revision}
        else: raise ClaudeUnavailable('native channel unavailable')

    def _pump(self,deadline):
        self._current()
        while b'\n' not in self.buffer:
            remaining=deadline-time.monotonic()
            if remaining<=0: raise ClaudeUnavailable('native response timeout')
            streams=[self.io.stdout.fileno()] + ([] if self._stderr_eof else [self.io.stderr.fileno()])
            readable,_,_=select.select(streams,[],[],remaining)
            for fd in readable:
                try: data=os.read(fd,self.MAX_FRAME+1)
                except BlockingIOError: continue
                if not data:
                    if fd==streams[0]: raise ClaudeUnavailable('native control EOF')
                    self._stderr_eof=True; continue
                if fd==streams[0]: self.buffer.extend(data)
                # Bounded stderr is discarded, never passed into diagnostics.
            if len(self.buffer)>2*self.MAX_FRAME: raise ClaudeUnavailable('native input capacity')
        line,_,rest=self.buffer.partition(b'\n'); self.buffer=bytearray(rest)
        if len(line)>self.MAX_FRAME: raise ClaudeUnavailable('oversized native frame')
        try: self._frame(json.loads(line))
        except (ValueError,TypeError,KeyError): raise ClaudeUnavailable('invalid native JSON') from None
        self._current()

    def _command(self,op,**data):
        with self._serial: return self._command_locked(op,**data)

    def _command_locked(self,op,**data):
        self._current()
        if self.reply_id is not None: raise ClaudeNotApplied('native command already pending')
        request_id=str(uuid.uuid4()); wire=(json.dumps({'id':request_id,'op':op,**data})+'\n').encode()
        if len(wire)>self.MAX_FRAME: raise ClaudeNotApplied('native input limit before write')
        deadline=time.monotonic()+self.timeout; offset=0; self.reply_id=request_id; self.reply=None
        try:
            while offset<len(wire):
                self._current(); remaining=deadline-time.monotonic()
                if remaining<=0: raise ClaudeUnavailable('native write timeout')
                try:
                    count=os.write(self.io.stdin.fileno(),wire[offset:])
                    if count<=0: raise ClaudeUnavailable('native write unavailable')
                    offset+=count
                except BlockingIOError: select.select([],[self.io.stdin.fileno()],[],remaining)
            while self.reply is None: self._pump(deadline)
            result=self.reply
            # Consume already buffered policy events before returning SAFE.
            while b'\n' in self.buffer: self._pump(deadline)
            self._current(); return result
        except BaseException as error:
            self.fenced='native-command-uncertain' if offset else 'native-command-unavailable'
            if not offset: raise ClaudeNotApplied('no native command bytes written') from error
            raise ClaudeUnavailable('native command outcome unknown') from error
        finally: self.reply_id=None; self.reply=None

    def observe(self):
        with self._serial: return self._observe_locked()

    def _observe_locked(self):
        try:
            self._current()
            if self._unknown(): return Readiness.AMBIGUOUS
            reply=self._command('probe')
            if (reply.get('pid')!=self.root.native_namespace_pid or reply.get('session_id')!=self.session_id
                    or reply.get('liveness')!='fresh-public-mcpServerStatus'
                    or reply.get('_seen_revision')!=self.revision): return Readiness.AMBIGUOUS
            if reply.get('state')=='busy': return Readiness.BUSY
            return (Readiness.SAFE if reply.get('state')=='safe' and reply.get('reason')=='native-listing-idle'
                and reply.get('native_state') in (None,'idle') else Readiness.AMBIGUOUS)
        except (ClaudeUnavailable,OSError): return Readiness.LOST

    def _write(self,message_id,content,peer=True):
        self.pending=(message_id,content); self.ack=None
        reply=self._command('send',uuid=message_id,content=content,session_id=self.session_id)
        if reply.get('not_applied') is True: self.pending=None; raise ClaudeNotApplied('native send refused before input')
        if reply.get('released') is not True: raise ClaudeUnavailable('native send outcome unknown')

    def _wait_ack(self,message_id,content):
        deadline=time.monotonic()+self.timeout
        while not _ack_matches(self.ack,self.session_id,message_id,content): self._pump(deadline)
        return self.ack

    def accept(self,envelope):
        with self._serial:
            self._current()
            receipt=super().accept(envelope)
            self._current(); return receipt

    def prove_fresh_context(self,root):
        if root is not self.root or self.recipe.resume or self.db.execute('SELECT count(*) FROM handoffs').fetchone()[0]:
            raise ClaudeUnavailable('fresh context unavailable')
        if self.observe() is not Readiness.SAFE: raise ClaudeUnavailable('native context not safe')
        return {'runtime':'Claude','runtime_version':'2.1.310','sdk_version':'0.3.310',
            'native_pid':root.native_namespace_pid,'session_id':self.session_id,'scope':self.scope,
            'source':'fresh-home-explicit-session-native-idle-no-input','readiness':'safe'}

    def close(self):
        self.closed=True
        try:
            if self.io is not None: self.io.close()
        finally: self._close_journal()
