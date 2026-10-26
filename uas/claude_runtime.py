"""Fixed account-free Claude SDK fixture; NOT production seat authority.

The SDK default uses fresh non-model liveness plus independent native idle.
The old direct-CLI implementation is diagnostic-only, never a fallback.
"""
from collections import deque
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import subprocess
import threading
import time
from urllib.parse import urlsplit
import uuid

from uas.ledger import LedgerError
from uas.peer import Readiness, digest


VERSION = '2.1.310'
BINARY_SHA256 = 'b73676430af12f97316a798b8371f81d640f90a58bdcb8f3ce56a835bb47df56'


class ClaudeUnavailable(RuntimeError):
    pass


class ClaudeNotApplied(ClaudeUnavailable):
    """This attempt provably wrote no native input bytes; not an ACK."""


def _ack_matches(event, session_id, message_id, content):
    try:
        valid_id = type(message_id) is str and str(uuid.UUID(message_id)) == message_id.lower()
    except (ValueError, AttributeError):
        valid_id = False
    return (valid_id and type(content) is str and type(event) is dict and event.get('type') == 'user'
            and event.get('session_id') == session_id and event.get('uuid') == message_id
            and event.get('isReplay') is True and 'parent_tool_use_id' in event
            and event['parent_tool_use_id'] is None
            and event.get('message') == {'role': 'user', 'content': content})


def require_loopback_namespace():
    """Defense in depth; CI's unshare --net is the actual boundary."""
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise ClaudeUnavailable('fixture requires a loopback-only network namespace')
    for path, field in (('/proc/net/route', 0), ('/proc/net/ipv6_route', -1)):
        lines = Path(path).read_text().splitlines()
        if path.endswith('/route'):
            lines = lines[1:]
        if any(line.split()[field] != 'lo' for line in lines):
            raise ClaudeUnavailable('fixture namespace has an external route')


class ClaudeSignals:
    """Bounded signal reducer. No signal, init, or connection authorizes work."""
    def __init__(self, session_id, *, safe_for=2.0):
        self.session_id = session_id
        self.safe_for = safe_for
        self.pending = None
        self.command_id = None
        self.completed_id = None
        self.ack = None
        self.initialized = False
        self.fenced = False
        self.state = 'unknown'
        self.safe_at = None

    def begin(self, message_id, content):
        if self.fenced or self.pending is not None:
            raise ClaudeUnavailable('Claude has no available invocation slot')
        self.pending = (message_id, content)
        self.command_id = message_id
        self.ack = None
        self.safe_at = None
        self.state = 'working'

    def hold(self, state):
        self.state = state
        self.fenced = True
        self.safe_at = None

    def event(self, event):
        if self.fenced:
            return
        if type(event) is not dict or event.get('session_id') != self.session_id:
            self.hold('replacement-or-unknown')
            return
        kind = event.get('type')
        if kind == 'system' and event.get('subtype') == 'init':
            if (event.get('claude_code_version') != VERSION or event.get('tools') != []
                    or event.get('mcp_servers') != [] or event.get('mcp_server_errors')
                    or event.get('plugin_errors')):
                self.hold('unsupported-session')
            else:
                self.initialized = True
        elif kind == 'control_request' or (kind == 'system' and event.get('subtype') == 'permission_denied'):
            self.hold('needs-input')  # Conservative attention inference, not auto-approval.
        elif kind == 'user':
            if not self.pending or not _ack_matches(event, self.session_id, *self.pending):
                self.hold('unmatched-acknowledgment')
            else:
                self.ack = event
        elif kind == 'result':
            if (not self.initialized or not self.pending or self.ack is None
                    or event.get('user_message_uuid') != self.pending[0]
                    or event.get('subtype') != 'success' or event.get('is_error') is not False
                    or event.get('permission_denials') != [] or event.get('queued_turn_count') != 0
                    or event.get('terminal_reason') != 'completed' or event.get('stop_reason') != 'end_turn'):
                self.hold('needs-input' if event.get('permission_denials') else 'unknown-result')
            else:
                self.completed_id = self.command_id
                self.pending = None
                self.state = 'idle-inferred'
                self.safe_at = time.monotonic()
        elif kind == 'assistant':
            if (self.pending is None or event.get('user_message_uuid') != self.command_id
                    or 'parent_tool_use_id' not in event or event['parent_tool_use_id'] is not None):
                self.hold('unexpected-active-turn')
        elif kind == 'command_lifecycle':
            state = event.get('state')
            if state == 'completed' and self.completed_id is not None and event.get('command_uuid') == self.completed_id:
                return  # The previous result can precede its trailing lifecycle event.
            if (self.pending is None or event.get('command_uuid') != self.command_id
                    or state not in ('queued', 'started', 'completed')):
                self.hold('unexpected-active-turn')
        elif not (kind == 'system' and event.get('subtype') == 'ui_invalidate'):
            self.hold('unknown-signal')

    def readiness(self):
        if self.fenced:
            return Readiness.AMBIGUOUS
        if self.pending:
            return Readiness.BUSY
        if self.safe_at is not None and time.monotonic() - self.safe_at <= self.safe_for:
            return Readiness.SAFE
        return Readiness.AMBIGUOUS


class _ClaudeJournal:
    """Only fixed Claude scope binding and immutable intent/receipt semantics."""
    def _open_journal(self, binary, gateway_url, fixture_key, journal, scope, resume, timeout):
        require_loopback_namespace()
        parsed = urlsplit(gateway_url)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
                or not fixture_key.startswith('fixture-only-')):
            raise ClaudeUnavailable('only an isolated loopback fixture endpoint is supported')
        if (type(scope) is not dict or set(scope) != {'room_id', 'participant_id', 'run_id', 'generation', 'context_generation'}
                or any(type(scope[k]) is not str or not scope[k] for k in ('room_id', 'participant_id', 'run_id'))
                or any(type(scope[k]) is not int or scope[k] != 1 for k in ('generation', 'context_generation'))):
            raise ClaudeUnavailable('only fixed fixture Run/context generation 1 is supported')
        with open(binary, 'rb') as handle:
            if hashlib.file_digest(handle, 'sha256').hexdigest() != BINARY_SHA256:
                raise ClaudeUnavailable('unqualified Claude binary')
        self.scope = dict(scope)
        self.timeout = timeout
        self.incarnation_id = uuid.uuid4().hex
        self.owner = open(str(journal) + '.owner', 'a+b')
        try:
            fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.owner.close()
            self.owner = None
            raise ClaudeUnavailable('fixture session already owned')
        self.db = sqlite3.connect(journal)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), scope TEXT, session_id TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS handoffs (logical_digest TEXT PRIMARY KEY, logical TEXT, message_id TEXT, receipt TEXT)')
        if 'retryable' not in {row[1] for row in self.db.execute('PRAGMA table_info(handoffs)')}:
            # Historical unknown intents stay unknown; only durable known-no-effect is retryable.
            self.db.execute('ALTER TABLE handoffs ADD COLUMN retryable INTEGER NOT NULL DEFAULT 0 CHECK(retryable IN (0,1))')
        previous = self.db.execute('SELECT scope,session_id FROM binding WHERE singleton=1').fetchone()
        if bool(previous) != resume or (previous and json.loads(previous[0]) != scope):
            raise ClaudeUnavailable('explicit same-Run resume required; reset/remap unsupported')
        self.session_id = previous[1] if previous else str(uuid.uuid4())
        if not previous:
            with self.db:
                self.db.execute('INSERT INTO binding VALUES (1,?,?)', (json.dumps(scope), self.session_id))

    def _close_journal(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.owner is not None:
            self.owner.close()
            self.owner = None

    def _unknown(self):
        return self.db.execute('SELECT 1 FROM handoffs WHERE receipt IS NULL AND retryable != 1 LIMIT 1').fetchone()

    def accept(self, envelope):
        if (type(envelope) is not dict
                or any(type(envelope.get(k)) is not type(v) or envelope.get(k) != v for k, v in self.scope.items())
                or envelope.get('incarnation_id') != self.incarnation_id):
            raise LedgerError('NATIVE_SCOPE_MISMATCH')
        if self.observe() is not Readiness.SAFE:
            raise LedgerError('NATIVE_NOT_SAFE')
        logical = {k: v for k, v in envelope.items() if k not in ('delivery_id', 'incarnation_id')}
        key = digest(logical)
        content = 'Untrusted peer traffic (not human authorization):\n' + json.dumps(logical, ensure_ascii=False, sort_keys=True)
        row = self.db.execute('SELECT logical,message_id,receipt,retryable FROM handoffs WHERE logical_digest=?', (key,)).fetchone()
        confirmed = False
        if row:
            try:
                confirmed = row[2] is not None and _ack_matches(json.loads(row[2]), self.session_id, row[1], content)
                valid = json.loads(row[0]) == logical and (confirmed or (row[2] is None and row[3] == 1))
            except (ValueError, TypeError):
                valid = False
            if not valid:
                raise LedgerError('UNCONFIRMED_NATIVE_DELIVERY')
            message_id = row[1]
        else:
            message_id = str(uuid.uuid4())
        if not confirmed:
            try:
                with self.db:
                    if row:
                        self.db.execute('UPDATE handoffs SET retryable=0 WHERE logical_digest=?', (key,))
                    else:
                        self.db.execute('INSERT INTO handoffs (logical_digest,logical,message_id,receipt) VALUES (?,?,?,NULL)',
                                        (key, json.dumps(logical), message_id))
                self._write(message_id, content, peer=True)
                receipt = self._wait_ack(message_id, content)
                if not _ack_matches(receipt, self.session_id, message_id, content):
                    raise ClaudeUnavailable('invalid native acceptance evidence')
                with self.db:
                    self.db.execute('UPDATE handoffs SET receipt=? WHERE logical_digest=?',
                                    (json.dumps(receipt), key))
            except ClaudeNotApplied as error:
                try:
                    with self.db:
                        self.db.execute('UPDATE handoffs SET retryable=1 WHERE logical_digest=?', (key,))
                except sqlite3.Error as failure:
                    raise LedgerError('UNCONFIRMED_NATIVE_DELIVERY') from failure
                raise LedgerError('NATIVE_NOT_APPLIED') from error
            except (ClaudeUnavailable, sqlite3.Error) as error:
                raise LedgerError('UNCONFIRMED_NATIVE_DELIVERY') from error
        return {'delivery_id': envelope['delivery_id'], 'digest': digest(envelope),
                'participant_id': envelope['participant_id'], 'incarnation_id': envelope['incarnation_id'],
                'context_generation': envelope['context_generation']}

class DirectClaudeDiagnosticReceiver(_ClaudeJournal):
    """One explicit fixture Run/session, durable intent and native replay ACK.

    Unknown handoffs never reinject, even after same-session restoration. A
    durable confirmed ACK can reconcile to a new Hub attachment only after fresh
    readiness. Native ACK is input acceptance, never work completion or replay
    durability of Claude's own session store.
    """
    def __init__(self, binary, *, cwd, home, gateway_url, fixture_key, journal,
                 scope, resume=False, timeout=8, safe_for=2):
        self.db = self.owner = self.process = None
        self.reader = self.stderr = None
        try:
            self._open_journal(binary, gateway_url, fixture_key, journal, scope, resume, timeout)
            self.signals = ClaudeSignals(self.session_id, safe_for=safe_for)
            self.condition = threading.Condition()
            self.write_lock = threading.Lock()
            self.events = deque(maxlen=128)
            self.errors = deque(maxlen=16)
            self.ended = False
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'CLAUDE_CONFIG_DIR': str(Path(home) / 'config'),
                   'ANTHROPIC_BASE_URL': gateway_url, 'ANTHROPIC_API_KEY': fixture_key,
                   'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1'}
            argv = [str(binary), '--bare', '--restricted', '-p', '--input-format', 'stream-json',
                    '--output-format', 'stream-json', '--verbose', '--replay-user-messages',
                    '--tools', '', '--disallowedTools', 'mcp__*', '--strict-mcp-config',
                    '--mcp-config', '{"mcpServers":{}}', '--setting-sources', '',
                    '--model', 'claude-sonnet-4-6', '--resume' if resume else '--session-id', self.session_id]
            self.process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            os.set_blocking(self.process.stdin.fileno(), False)
            self.reader = threading.Thread(target=self._read, daemon=True)
            self.stderr = threading.Thread(target=self._errors, daemon=True)
            self.reader.start()
            self.stderr.start()
            # Explicit non-peer bootstrap. Spawn/resume/init alone stay held.
            self.refresh()
        except BaseException:
            self.close()
            raise

    def _read(self):
        try:
            while line := self.process.stdout.readline(1024 * 1024 + 1):
                if len(line) > 1024 * 1024 or not line.endswith(b'\n'):
                    raise ValueError('oversized/incomplete native frame')
                event = json.loads(line)
                with self.condition:
                    self.events.append(event)
                    self.signals.event(event)
                    self.condition.notify_all()
        except (OSError, ValueError) as error:
            self.errors.append(str(error))
        finally:
            with self.condition:
                self.ended = True
                self.signals.hold('transport-loss')
                self.condition.notify_all()

    def _errors(self):
        for line in iter(lambda: self.process.stderr.readline(4096), b''):
            self.errors.append(line.decode('utf8', errors='replace'))

    def _write(self, message_id, content, *, peer=False):
        wire = (json.dumps({'type': 'user', 'uuid': message_id, 'session_id': self.session_id,
                            'message': {'role': 'user', 'content': content}}, ensure_ascii=False) + '\n').encode()
        deadline = time.monotonic() + self.timeout
        offset = 0
        if not self.write_lock.acquire(timeout=self.timeout):
            with self.condition:
                self.signals.safe_at = None
            raise ClaudeNotApplied('native write lock deadline exceeded before handoff')
        begun = False
        try:
            with self.condition:
                # Journal I/O and write-lock contention may outlive the sampled
                # safe point. Bootstrap is explicit control, never peer traffic.
                if peer and self.signals.readiness() is not Readiness.SAFE:
                    raise ClaudeNotApplied('safe evidence expired before peer handoff')
                try:
                    self.signals.begin(message_id, content)
                except ClaudeUnavailable as error:
                    raise ClaudeNotApplied('no invocation slot before handoff') from error
                begun = True
            try:
                try:
                    fd = self.process.stdin.fileno()
                except (OSError, ValueError) as error:
                    with self.condition:
                        if not self.signals.fenced:
                            self.signals.hold('transport-loss')
                    raise ClaudeNotApplied('native input unavailable before handoff') from error
                while offset < len(wire):
                    try:
                        # Serialize each nonblocking syscall with the reader's
                        # signal reducer, never a whole blocking/select wait.
                        # A newly observed attention/unknown fence stops all
                        # remaining bytes; a partial frame is never retryable.
                        with self.condition:
                            remaining = deadline - time.monotonic()
                            if (self.signals.fenced or self.ended
                                    or self.process.poll() is not None or remaining <= 0):
                                if not self.signals.fenced:
                                    self.signals.hold('transport-loss')
                                error = ClaudeNotApplied if offset == 0 else ClaudeUnavailable
                                raise error('native session held before remaining input bytes')
                            written = os.write(fd, wire[offset:])
                            if written <= 0:
                                raise OSError('native pipe made no progress')
                            offset += written
                    except BlockingIOError:
                        select.select([], [fd], [], min(remaining, .05))
            except ClaudeNotApplied:
                raise
            except (OSError, ValueError, ClaudeUnavailable) as error:
                with self.condition:
                    if not self.signals.fenced:
                        self.signals.hold('transport-loss')
                raise ClaudeUnavailable('unconfirmed native write; replacement required') from error
        except ClaudeNotApplied:
            with self.condition:
                if begun:
                    self.signals.pending = None
                    self.signals.command_id = None
                    self.signals.ack = None
                self.signals.safe_at = None
                if self.signals.pending is None and not self.signals.fenced:
                    self.signals.state = 'unknown'
            raise
        finally:
            self.write_lock.release()

    def refresh(self):
        """Explicit fixture control turn, never silent readiness polling."""
        if self.process.poll() is not None or self.ended:
            raise ClaudeUnavailable('native process absent')
        self._write(str(uuid.uuid4()), 'Fixture control: establish a fresh completed tool-less turn.')

    def _wait(self, predicate):
        deadline = time.monotonic() + self.timeout
        with self.condition:
            while True:
                if self.ended or self.process.poll() is not None or self.signals.fenced:
                    raise ClaudeUnavailable('native session held: ' + self.signals.state)
                value = predicate()
                if value:
                    return value
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.signals.hold('unresponsive-inferred')
                    raise ClaudeUnavailable('missing native evidence; no reinjection')
                self.condition.wait(remaining)

    def wait_safe(self):
        self._wait(lambda: self.signals.readiness() is Readiness.SAFE)

    def _wait_ack(self, message_id, content):
        return self._wait(lambda: self.signals.ack if _ack_matches(
            self.signals.ack, self.session_id, message_id, content) else None)

    def observe(self):
        with self.condition:
            if self.process.poll() is not None or self.ended:
                return Readiness.LOST
            # Ambiguous responsibility holds the whole receiver, not just a
            # selected envelope; a caller cannot route around an unknown head.
            if self._unknown():
                return Readiness.AMBIGUOUS
            return self.signals.readiness()

    def evidence(self):
        return {'runtime': 'Claude Code', 'version': VERSION, 'binary_sha256': BINARY_SHA256,
                'authority': 'trusted-fixture-only', 'session_id': self.session_id,
                'incarnation_id': self.incarnation_id, 'process_alive': self.process.poll() is None,
                'readiness': self.observe().value, 'state': self.signals.state,
                'safe_source': 'adapter-inferred-fresh-correlated-tool-less-terminal-result',
                'receipt_source': 'native-replay-user-message', 'transport_fenced': self.signals.fenced,
                'native_receipts': self.db.execute('SELECT count(*) FROM handoffs WHERE receipt IS NOT NULL').fetchone()[0],
                'unknown_intents': self.db.execute('SELECT count(*) FROM handoffs WHERE receipt IS NULL AND retryable != 1').fetchone()[0],
                'retryable_intents': self.db.execute('SELECT count(*) FROM handoffs WHERE receipt IS NULL AND retryable = 1').fetchone()[0],
                'provider': 'no-upstream-loopback-protocol-fixture', 'inference_health': 'not-qualified',
                'image_digest': 'not-qualified', 'native_reset': 'not-qualified', 'mcp_reconnect': 'not-qualified'}

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            for thread in (self.reader, self.stderr):
                if thread is not None and thread.ident is not None:
                    thread.join(timeout=1)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()
        self._close_journal()


class FixtureClaudeReceiver(_ClaudeJournal):
    """Qualified tool-less SDK fixture, not a Supervisor-owned native badge.

    The fixed SDK host owns the native CLI. Every observation and send performs
    a fresh non-model public control/listing check; no synthetic bootstrap or
    refresh turn exists. A durable unknown intent still holds the whole receiver.
    """
    MAX_FRAME = 256 * 1024

    def __init__(self, binary, *, sdk_install, node, cwd, home, gateway_url, fixture_key,
                 journal, scope, resume=False, timeout=8):
        self.db = self.owner = self.process = None
        self.reader = self.stderr = None
        self.condition = threading.Condition()
        self.command_lock = threading.Lock()
        self.events = deque(maxlen=128)
        self.errors = deque(maxlen=16)
        self.ended = False
        self.ready = False
        self.native_pid = self.native_start = None
        self.reply_id = self.reply = None
        self.event_revision = 0
        try:
            self._open_journal(binary, gateway_url, fixture_key, journal, scope, resume, timeout)
            self.signals = ClaudeSignals(self.session_id, safe_for=0)
            host = Path(__file__).resolve().parents[1] / 'runtime/claude/sdk-host.mjs'
            argv = [str(node), str(host), str(sdk_install), str(binary), str(cwd), str(home),
                    gateway_url, fixture_key, self.session_id, '1' if resume else '0']
            self.process = subprocess.Popen(argv, cwd=cwd,
                env={'PATH': '/usr/bin:/bin', 'HOME': str(home)}, start_new_session=True,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            os.set_blocking(self.process.stdin.fileno(), False)
            self.reader = threading.Thread(target=self._read, daemon=True)
            self.stderr = threading.Thread(target=self._errors, daemon=True)
            self.reader.start()
            self.stderr.start()
            self._wait(lambda: self.ready)
            # Initialization is not readiness and makes no model request.
        except BaseException:
            self.close()
            raise

    def _kernel(self):
        if not self.ready or self.process.poll() is not None or self.ended:
            raise ClaudeUnavailable('SDK host/native absent')
        try:
            fields = Path(f'/proc/{self.native_pid}/stat').read_text().rsplit(')', 1)[1].split()
            if fields[1] != str(self.process.pid) or fields[19] != self.native_start:
                raise ValueError('native process identity changed')
            return fields[0]
        except (OSError, ValueError, IndexError) as error:
            raise ClaudeUnavailable('SDK-owned native identity lost') from error

    def _read(self):
        try:
            while line := self.process.stdout.readline(self.MAX_FRAME + 1):
                if len(line) > self.MAX_FRAME or not line.endswith(b'\n'):
                    raise ValueError('oversized/incomplete SDK host frame')
                frame = json.loads(line)
                if type(frame) is not dict:
                    raise ValueError('invalid SDK host frame')
                with self.condition:
                    kind = frame.get('type')
                    if kind == 'host-ready':
                        if (self.ready or frame.get('host_pid') != self.process.pid
                                or type(frame.get('native_pid')) is not int or frame['native_pid'] <= 0
                                or frame['native_pid'] == self.process.pid
                                or frame.get('session_id') != self.session_id
                                or frame.get('sdk_version') != '0.3.310' or frame.get('cli_version') != VERSION
                                or frame.get('authority') != 'sdk-host-owned-fixture-only'):
                            raise ValueError('invalid SDK host/native binding')
                        self.native_pid = frame['native_pid']
                        fields = Path(f'/proc/{self.native_pid}/stat').read_text().rsplit(')', 1)[1].split()
                        if fields[1] != str(self.process.pid):
                            raise ValueError('SDK host does not own native process')
                        self.native_start = fields[19]
                        self.ready = True
                    elif kind == 'native':
                        event = frame.get('event')
                        if (type(event) is not dict or 'fence' not in frame
                                or (frame['fence'] is not None and type(frame['fence']) is not str)):
                            raise ValueError('invalid native SDK event')
                        if frame['fence'] is not None:
                            self.signals.hold('host-native-policy:' + frame['fence'])
                        self.events.append(event)
                        self.event_revision += 1
                        if event.get('type') == 'system' and event.get('subtype') == 'session_state_changed':
                            if event.get('session_id') != self.session_id:
                                self.signals.hold('native-identity')
                            elif event.get('state') == 'requires_action':
                                self.signals.hold('needs-input')
                            elif event.get('state') not in ('idle', 'running'):
                                self.signals.hold('unknown-native-state')
                            # Idle event alone never authorizes receipt or delivery.
                        else:
                            self.signals.event(event)
                    elif kind == 'reply':
                        if frame.get('id') != self.reply_id or self.reply is not None:
                            raise ValueError('uncorrelated/duplicate SDK host reply')
                        self.reply = {**frame, '_seen_revision': self.event_revision}
                    else:
                        raise ValueError('SDK host/native lost or unknown frame')
                    self.condition.notify_all()
        except (OSError, ValueError, IndexError) as error:
            self.errors.append(str(error))
        finally:
            with self.condition:
                self.ended = True
                self.signals.hold('transport-loss')
                self.condition.notify_all()
            self._terminate_host()

    def _errors(self):
        for line in iter(lambda: self.process.stderr.readline(4096), b''):
            self.errors.append(line.decode('utf8', errors='replace'))

    def _terminate_host(self):
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.terminate()
            except ProcessLookupError:
                pass

    def _wait(self, predicate):
        deadline = time.monotonic() + self.timeout
        with self.condition:
            while True:
                if self.ended or self.process.poll() is not None or self.signals.fenced:
                    raise ClaudeUnavailable('SDK/native session held: ' + self.signals.state)
                value = predicate()
                if value:
                    return value
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.signals.hold('unresponsive-inferred')
                    self._terminate_host()
                    raise ClaudeUnavailable('missing SDK/native evidence; no reinjection')
                self.condition.wait(remaining)

    def _command(self, op, **data):
        request_id = str(uuid.uuid4())
        wire = (json.dumps({'id': request_id, 'op': op, **data}, ensure_ascii=False) + '\n').encode()
        if len(wire) > self.MAX_FRAME:
            raise ClaudeNotApplied('fixed host input limit before any write')
        if not self.command_lock.acquire(timeout=self.timeout):
            raise ClaudeNotApplied('fixed host command lock unavailable before any write')
        offset = 0
        deadline = time.monotonic() + self.timeout
        try:
            with self.condition:
                if self.reply_id is not None:
                    raise ClaudeNotApplied('fixed host command slot unavailable')
                self.reply_id, self.reply = request_id, None
            fd = self.process.stdin.fileno()
            while offset < len(wire):
                try:
                    with self.condition:
                        remaining = deadline - time.monotonic()
                        if self.ended or self.signals.fenced or self.process.poll() is not None or remaining <= 0:
                            raise ClaudeUnavailable('fixed host held before remaining command bytes')
                        count = os.write(fd, wire[offset:])
                        if count <= 0:
                            raise OSError('fixed host pipe made no progress')
                        offset += count
                except BlockingIOError:
                    select.select([], [fd], [], min(remaining, .05))
            return self._wait(lambda: self.reply)
        except (OSError, ValueError, ClaudeUnavailable) as error:
            if offset:
                with self.condition:
                    self.signals.hold('unconfirmed-host-command')
                self._terminate_host()
                raise ClaudeUnavailable('host command outcome unknown') from error
            raise ClaudeNotApplied('host command provably not written') from error
        finally:
            with self.condition:
                self.reply_id = self.reply = None
            self.command_lock.release()

    def _probe(self):
        self._kernel()
        reply = self._command('probe')
        with self.condition:
            if self.signals.fenced or self.ended:
                return Readiness.AMBIGUOUS
            state = reply.get('state')
            if state not in ('safe', 'busy', 'ambiguous'):
                self.signals.hold('invalid-host-observation')
                return Readiness.AMBIGUOUS
            if state != 'safe':
                return Readiness.BUSY if state == 'busy' else Readiness.AMBIGUOUS
            if (reply.get('pid') != self.native_pid or reply.get('session_id') != self.session_id
                    or reply.get('liveness') != 'fresh-public-mcpServerStatus'
                    or reply.get('reason') != 'native-listing-idle'
                    or reply.get('native_state') not in (None, 'idle')
                    or type(reply.get('revision')) is not int or reply['revision'] < 0
                    or reply['_seen_revision'] != self.event_revision):
                return Readiness.AMBIGUOUS
            if self.signals.pending:
                return Readiness.BUSY
            return Readiness.AMBIGUOUS if self._kernel() in ('T', 't', 'Z', 'X', 'D') else Readiness.SAFE

    def observe(self):
        if self.process.poll() is not None or self.ended:
            return Readiness.LOST
        if self._unknown() or self.signals.fenced:
            return Readiness.AMBIGUOUS
        try:
            return self._probe()
        except ClaudeUnavailable:
            return Readiness.AMBIGUOUS

    def wait_safe(self):
        """Bounded test/controller wait using non-model checks, never clears intents."""
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self._probe() is Readiness.SAFE:
                return
            with self.condition:
                if self.signals.fenced or self.ended:
                    raise ClaudeUnavailable('SDK/native held')
                self.condition.wait(.02)
        self.signals.hold('unresponsive-inferred')
        self._terminate_host()
        raise ClaudeUnavailable('native idle evidence unavailable')

    def _write(self, message_id, content, *, peer=False):
        if not peer:
            raise ClaudeNotApplied('SDK receiver has no synthetic control turns')
        with self.condition:
            try:
                self.signals.begin(message_id, content)
            except ClaudeUnavailable as error:
                raise ClaudeNotApplied('no input slot before host handoff') from error
        try:
            reply = self._command('send', uuid=message_id, session_id=self.session_id, content=content)
            if reply.get('not_applied') is True and reply.get('released') is not True:
                raise ClaudeNotApplied('host verified no native input release')
            if reply.get('released') is not True or 'not_applied' in reply:
                raise ClaudeUnavailable('unconfirmed SDK input release')
            # Release is not acceptance: only the exact native replay may commit.
        except ClaudeNotApplied:
            with self.condition:
                self.signals.pending = self.signals.command_id = self.signals.ack = None
                self.signals.safe_at = None
            raise

    def _wait_ack(self, message_id, content):
        return self._wait(lambda: self.signals.ack if _ack_matches(
            self.signals.ack, self.session_id, message_id, content) else None)

    def evidence(self):
        return {'runtime': 'Claude Code', 'version': VERSION, 'sdk_version': '0.3.310',
                'binary_sha256': BINARY_SHA256, 'authority': 'sdk-host-owned-fixture-only',
                'host_pid': self.process.pid, 'native_pid': self.native_pid,
                'session_id': self.session_id, 'incarnation_id': self.incarnation_id,
                'process_alive': self.process.poll() is None, 'readiness': self.observe().value,
                'safe_source': 'fresh-public-SDK-control-plus-exact-native-idle-listing-and-state-holds',
                'receipt_source': 'exact-native-replay-user-message', 'transport_fenced': self.signals.fenced,
                'native_receipts': self.db.execute('SELECT count(*) FROM handoffs WHERE receipt IS NOT NULL').fetchone()[0],
                'unknown_intents': self.db.execute('SELECT count(*) FROM handoffs WHERE receipt IS NULL AND retryable != 1').fetchone()[0],
                'retryable_intents': self.db.execute('SELECT count(*) FROM handoffs WHERE receipt IS NULL AND retryable=1').fetchone()[0],
                'provider': 'no-upstream-loopback-protocol-fixture', 'inference_health': 'not-qualified',
                'image_digest': 'not-qualified', 'native_reset': 'not-qualified', 'mcp_reconnect': 'not-qualified'}

    def close(self):
        if self.process is not None:
            self._terminate_host()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, 9)
                self.process.wait(timeout=3)
            # Only this receiver's own newly-created process group; includes a
            # SIGSTOPped native child if the host exited before its close timer.
            try:
                os.killpg(self.process.pid, 9)
            except ProcessLookupError:
                pass
            for thread in (self.reader, self.stderr):
                if thread is not None and thread.ident is not None:
                    thread.join(timeout=1)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()
            self.process = None
        self._close_journal()
