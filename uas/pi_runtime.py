"""Real Pi RPC receiver with a deliberately fixture-only authority boundary.

Native session state is Pi-specific here, never in the Hub domain. This module
neither mints process badges nor launches a qualified Workstation Participant.
"""
import base64
from collections import deque
import json
import os
import select
import sqlite3
import subprocess
import threading
import time
import uuid

from uas.ledger import LedgerError
from uas.peer import Readiness, digest


class NativeUnavailable(RuntimeError):
    pass


class FixturePiRpcReceiver:
    """Harness-owned or controller-attached RPC + durable handoff intent.

    Native transcript evidence, not RPC dispatch, is Runtime acceptance.

    Same journal and same Pi session are required for same-Run restoration. An
    intent with no native receipt never automatically injects again. Therefore
    crash-before-handoff may require explicit recovery; it cannot duplicate work.
    """
    def __init__(self, argv, *, cwd, env, journal, runtime_version, scope, timeout=8):
        self._initialize(argv=argv, cwd=cwd, env=env, journal=journal,
                         runtime_version=runtime_version, scope=scope, timeout=timeout)

    @classmethod
    def attach(cls, process, *, journal, runtime_version, scope, incarnation_id, timeout=8):
        """Trusted controller seam, not PID adoption or a public authority API.

        The controller already owns the direct child, held pidfd and kernel
        credential channel. This object owns only RPC observation and its journal.
        """
        if type(incarnation_id) is not str or not incarnation_id:
            raise NativeUnavailable('missing supervisor incarnation')
        receiver = cls.__new__(cls)
        receiver._initialize(process=process, journal=journal, runtime_version=runtime_version,
                             scope=scope, incarnation_id=incarnation_id, timeout=timeout)
        return receiver

    def _initialize(self, *, journal, runtime_version, scope, timeout,
                    process=None, argv=None, cwd=None, env=None, incarnation_id=None):
        self._closed = False
        self._owns_process = process is None
        self.incarnation_id = incarnation_id
        self.db = None
        self.process = process
        self._reader = self._stderr = None
        self._condition = threading.Condition()
        self._write_lock = threading.Lock()
        self._transport_fenced = False
        try:
            if runtime_version != '1.4.0':
                raise NativeUnavailable('unsupported Pi version')
            if (type(scope) is not dict or set(scope) != {'room_id', 'participant_id', 'run_id', 'generation', 'context_generation'}
                    or any(type(scope[key]) is not str or not scope[key] for key in ('room_id', 'participant_id', 'run_id'))
                    or any(type(scope[key]) is not int or not 1 <= scope[key] <= 2**53 - 1 for key in ('generation', 'context_generation'))):
                raise NativeUnavailable('explicit bounded fixture Run/context scope is required')
            self.scope = dict(scope)
            self.runtime_version = runtime_version
            self.timeout = timeout
            self.db = sqlite3.connect(journal)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS handoffs ('
                            'logical_digest TEXT PRIMARY KEY, logical TEXT NOT NULL, '
                            'session_id TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT)')
            self.db.execute('CREATE TABLE IF NOT EXISTS binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), scope TEXT NOT NULL)')
            previous = self.db.execute('SELECT scope FROM binding WHERE singleton=1').fetchone()
            if previous and json.loads(previous[0]) != self.scope:
                raise NativeUnavailable('fixture scope cannot change without qualified native reset')
            self.db.execute('INSERT OR IGNORE INTO binding VALUES (1,?)', (json.dumps(self.scope),))
            self.db.commit()
            self.process = process if process is not None else subprocess.Popen(
                argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0)
            os.set_blocking(self.process.stdin.fileno(), False)
            self._transport_fenced = False
            self._responses = {}
            self._notifications = {}
            self._rpc_pending = set()
            self._native_pending = set()
            self.events = deque(maxlen=512)
            self.errors = deque(maxlen=64)
            self._ended = False
            self._binding = None
            self._reader = threading.Thread(target=self._read, daemon=True)
            self._stderr = threading.Thread(target=self._read_errors, daemon=True)
            self._reader.start()
            self._stderr.start()
            state = self._native('state', {})['state']
            if state.get('api_baseline') != runtime_version or state.get('readiness') not in {r.value for r in Readiness}:
                raise NativeUnavailable('unsupported or absent native observation')
            self._binding = {key: state[key] for key in ('runtime_id', 'session_id')}
            if self.incarnation_id is None:
                self.incarnation_id = state['runtime_id']
            self.initial_state = state
            self.last_observation = state
            self.readiness = Readiness(state['readiness'])
        except BaseException:
            self.close()
            raise

    def _read(self):
        try:
            while line := self.process.stdout.readline(1024 * 1024 + 1):
                if len(line) > 1024 * 1024 or not line.endswith(b'\n'):
                    raise ValueError('oversized or incomplete native record')
                event = json.loads(line)
                if type(event) is not dict:
                    raise ValueError('invalid native record')
                with self._condition:
                    self.events.append(event)
                    event_id = event.get('id')
                    if event.get('type') == 'response' and type(event_id) is str and event_id in self._rpc_pending:
                        self._responses[event_id] = event
                    elif event.get('type') == 'extension_ui_request' and event.get('method') == 'notify':
                        try:
                            value = json.loads(event.get('message', ''))
                            if (type(value) is dict and value.get('uas') == 1
                                    and type(value.get('request_id')) is str
                                    and value['request_id'] in self._native_pending):
                                self._notifications[value['request_id']] = value
                        except (ValueError, TypeError):
                            pass
                    self._condition.notify_all()
        except (ValueError, OSError) as error:
            self.errors.append(str(error))
        finally:
            with self._condition:
                self._ended = True
                self._condition.notify_all()

    def _read_errors(self):
        try:
            for line in iter(lambda: self.process.stderr.readline(4096), b''):
                self.errors.append(line[:4096].decode('utf8', errors='replace'))
        except (OSError, ValueError):
            pass  # Controller may close streams after reaping its owned process.

    def _wait(self, values, request_id, timeout=None):
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        with self._condition:
            while request_id not in values:
                if self._transport_fenced:
                    raise NativeUnavailable('native transport fenced after incomplete write')
                if self._ended or self.process.poll() is not None:
                    raise NativeUnavailable('native process lost')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NativeUnavailable('missing native response; hold without reinjection')
                self._condition.wait(remaining)
            return values.pop(request_id)

    def _write(self, wire, deadline):
        remaining = max(0, deadline - time.monotonic())
        if not self._write_lock.acquire(timeout=remaining):
            raise NativeUnavailable('native transport write deadline exceeded')
        offset = 0
        try:
            if self._transport_fenced:
                raise NativeUnavailable('native transport fenced; process replacement required')
            fd = self.process.stdin.fileno()
            while offset < len(wire):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Even zero progress is conservatively fenced. A partial
                    # JSON frame MUST NOT be followed by another command.
                    self._transport_fenced = True
                    raise NativeUnavailable('native transport write deadline exceeded; fenced')
                try:
                    count = os.write(fd, wire[offset:])
                    if count <= 0:
                        raise OSError('native pipe made no progress')
                    offset += count
                except BlockingIOError:
                    select.select([], [fd], [], remaining)
        except (OSError, ValueError) as error:
            self._transport_fenced = True
            raise NativeUnavailable('native transport lost; fenced') from error
        finally:
            if offset < len(wire):
                self._transport_fenced = True
            self._write_lock.release()

    def rpc(self, command, *, timeout=None, **fields):
        budget = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + budget
        request_id = uuid.uuid4().hex
        wire = json.dumps({'id': request_id, 'type': command, **fields}, ensure_ascii=False).encode() + b'\n'
        with self._condition:
            self._rpc_pending.add(request_id)
        try:
            self._write(wire, deadline)
            result = self._wait(self._responses, request_id, max(0, deadline - time.monotonic()))
            if result.get('success') is not True:
                raise NativeUnavailable('native command rejected: ' + str(result.get('error', 'unknown')))
            return result
        finally:
            with self._condition:
                self._rpc_pending.discard(request_id)
                self._responses.pop(request_id, None)

    def _native(self, command, payload):
        request_id = uuid.uuid4().hex
        message = base64.urlsafe_b64encode(json.dumps({**payload, 'request_id': request_id},
                                                      ensure_ascii=False).encode()).decode()
        with self._condition:
            self._native_pending.add(request_id)
        try:
            # "handled" only means extension dispatch completed, NEVER delivery.
            self.rpc('prompt', message=f'/uas-{command} {message}')
            return self._wait(self._notifications, request_id)
        finally:
            with self._condition:
                self._native_pending.discard(request_id)
                self._notifications.pop(request_id, None)

    def observe(self):
        if self._transport_fenced:
            self.readiness = Readiness.AMBIGUOUS
            return self.readiness
        if self.process.poll() is not None or self._ended:
            self.readiness = Readiness.LOST
            return self.readiness
        try:
            state = self._native('state', {})['state']
            self.last_observation = state
            if any(state.get(key) != value for key, value in self._binding.items()):
                self.readiness = Readiness.LOST
                return self.readiness
            # A fresh matching native sample restores observation after a lost
            # response. Journaled intents still permit reconciliation only.
            self.readiness = Readiness(state['readiness'])
            return self.readiness
        except (NativeUnavailable, KeyError, ValueError, TypeError, AttributeError):
            self.readiness = Readiness.AMBIGUOUS
            return self.readiness

    @staticmethod
    def _logical(envelope):
        return {key: value for key, value in envelope.items() if key not in ('delivery_id', 'incarnation_id')}

    def accept(self, envelope):
        if (type(envelope) is not dict
                or any(type(envelope.get(key)) is not type(value) or envelope.get(key) != value for key, value in self.scope.items())
                or envelope.get('incarnation_id') != self.incarnation_id):
            raise LedgerError('NATIVE_SCOPE_MISMATCH')
        logical = self._logical(envelope)
        logical_digest = digest(logical)
        row = self.db.execute('SELECT logical,session_id,state FROM handoffs WHERE logical_digest=?',
                              (logical_digest,)).fetchone()
        if row and (json.loads(row[0]) != logical or row[1] != self._binding['session_id']):
            raise LedgerError('NATIVE_SESSION_MISMATCH')
        if self.observe() is not Readiness.SAFE:
            raise LedgerError('NATIVE_NOT_SAFE')
        inject = not row or row[2] == 'NOT_APPLIED'
        if inject:
            # A fresh, explicit pre-effect refusal can permit retry. Unknown or
            # pending handoffs cannot. Commit each intent BEFORE touching Pi.
            with self.db:
                self.db.execute('INSERT INTO handoffs VALUES (?,?,?, ?,NULL) '
                                'ON CONFLICT(logical_digest) DO UPDATE SET state=excluded.state,receipt=NULL',
                                (logical_digest, json.dumps(logical, ensure_ascii=False),
                                 self._binding['session_id'], 'INTENT'))
        action = 'inject' if inject else 'reconcile'
        payload = {**self._binding, 'logical': logical, 'action': action}
        try:
            result = self._native('delivery', payload)
            refused = result.get('not_applied')
            if (inject and type(refused) is dict
                    and refused.get('source') == 'native-pre-effect-refusal'
                    and refused.get('logical_digest') == logical_digest
                    and refused.get('session_id') == self._binding['session_id']
                    and refused.get('runtime_id') == self._binding['runtime_id']
                    and refused.get('pending') is False
                    and refused.get('readiness') in ('busy', 'compacting', 'ambiguous')):
                try:
                    with self.db:
                        self.db.execute("UPDATE handoffs SET state='NOT_APPLIED' WHERE logical_digest=? AND state='INTENT'",
                                        (logical_digest,))
                except sqlite3.Error as error:
                    # Failure to persist NOT_APPLIED leaves INTENT and prohibits
                    # reinjection, even though this caller saw a refusal.
                    raise LedgerError('UNCONFIRMED_NATIVE_DELIVERY') from error
                raise LedgerError('NATIVE_NOT_SAFE')
            deadline = time.monotonic() + self.timeout
            while not result.get('receipt') and action == 'inject' and result.get('handoff') == 'started':
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
                result = self._native('delivery', {**payload, 'action': 'reconcile'})
                # An asynchronous first turn may not yet have persisted the
                # custom-message. Continue read-only, never repeat injection.
                if not result.get('receipt'):
                    result['handoff'] = 'started'
            native = result.get('receipt')
            if (type(native) is not dict or native.get('logical_digest') != logical_digest
                    or native.get('session_id') != self._binding['session_id']
                    or native.get('source') != 'native-active-branch-and-session-file'
                    or type(native.get('entry_id')) is not str):
                raise LedgerError('UNCONFIRMED_NATIVE_DELIVERY')
            with self.db:
                self.db.execute('UPDATE handoffs SET state=?,receipt=? WHERE logical_digest=?',
                                ('CONFIRMED', json.dumps(native), logical_digest))
            # Hub receipt has no Pi-specific state. Hub alone starts its clock.
            return {'delivery_id': envelope['delivery_id'], 'digest': digest(envelope),
                    'participant_id': envelope['participant_id'], 'incarnation_id': envelope['incarnation_id'],
                    'context_generation': envelope['context_generation']}
        except NativeUnavailable as error:
            raise LedgerError('UNCONFIRMED_NATIVE_DELIVERY') from error

    def prove_fresh_context(self, *, preceding_session=None):
        """Private native evidence for a controller's pending reset, not a badge.

        The caller has spawned a fresh CLI without resume/parent arguments and
        keeps its process authority pending. No priming prompt or JSONL write.
        """
        state = self._native('state', {})['state']
        actual = self.rpc('get_state')['data']
        entries = self.rpc('get_entries')['data']['entries']
        if (state.get('readiness') != 'safe' or any(state.get(k) != v for k, v in self._binding.items())
                or state.get('session_id') == preceding_session
                or actual.get('sessionId') != state.get('session_id')
                or type(actual.get('messageCount')) is not int or actual['messageCount'] != 0
                or type(actual.get('pendingMessageCount')) is not int or actual['pendingMessageCount'] != 0
                or actual.get('isStreaming') is not False or actual.get('isCompacting') is not False
                or type(entries) is not list
                or any(type(entry) is not dict or entry.get('type') not in {'model_change', 'thinking_level_change'}
                       for entry in entries)
                or self.db.execute('SELECT count(*) FROM handoffs').fetchone()[0]):
            raise NativeUnavailable('fresh native context not proven')
        return {**self._binding, 'session_file': state['session_file'],
                'source': 'native-empty-session-and-no-pending-messages'}

    def event_snapshot(self):
        with self._condition:
            return tuple(self.events)

    def evidence(self):
        return {'runtime': 'Pi', 'version': self.runtime_version,
                'authority': 'trusted-fixture-only', 'session_id': self._binding['session_id'],
                'runtime_id': self._binding['runtime_id'],
                'supervisor_incarnation': self.incarnation_id if not self._owns_process else None,
                'process_alive': self.process.poll() is None,
                'adapter_readiness': self.readiness.value,
                'transport_fenced': self._transport_fenced,
                'signal_source': self.last_observation['source'],
                'last_native_readiness': self.last_observation['readiness'],
                'receipt_source': 'native-active-branch-and-session-file',
                'native_receipts': self.db.execute("SELECT count(*) FROM handoffs WHERE state='CONFIRMED'").fetchone()[0],
                'retryable_pre_effect_refusals': self.db.execute("SELECT count(*) FROM handoffs WHERE state='NOT_APPLIED'").fetchone()[0],
                'unknown_intents': self.db.execute("SELECT count(*) FROM handoffs WHERE state='INTENT'").fetchone()[0],
                'provider_configuration': 'separate-not-qualified', 'inference_health': 'separate-not-qualified',
                'hang_uncertainty': 'no-native-hang-signal', 'image_digest': 'not-qualified'}

    def close(self):
        # Every resource slot exists before initialization can fail. Retrying
        # close may join readers after an attached owner has subsequently reaped.
        self._closed = True
        self._transport_fenced = True
        with self._condition:
            self._condition.notify_all()
        try:
            if self.process is not None:
                if self._owns_process and self.process.poll() is None:
                    try:
                        self.process.stdin.close()
                        self.process.wait(timeout=3)
                    except (OSError, ValueError, subprocess.TimeoutExpired):
                        self.process.kill()
                        self.process.wait(timeout=3)
                # An attached receiver never kills/closes controller resources.
                # Its owner reaps on failure; started readers then observe EOF.
                if self.process.poll() is not None:
                    for thread in (self._reader, self._stderr):
                        if thread is not None and thread.ident is not None:
                            thread.join(timeout=1)
                if self._owns_process:
                    for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                        if stream is not None and not stream.closed:
                            try:
                                stream.close()
                            except OSError:
                                pass
        finally:
            if self.db is not None:
                database, self.db = self.db, None
                database.close()
