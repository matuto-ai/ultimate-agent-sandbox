"""Real Pi RPC receiver with a deliberately fixture-only authority boundary.

Native session state is Pi-specific here, never in the Hub domain. This module
neither mints process badges nor launches a qualified Workstation Participant.
"""
import base64
from collections import deque
import hashlib
import json
import math
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

    @classmethod
    def attach_workstation(cls, launch, *, journal, scope, timeout=8, startup_observer=None,
                           initial_state_timeout=None):
        """Attach native I/O separately from the Supervisor's held task object.

        Source integration seam only: it does not qualify image, mounts or
        SELinux. The launch gate remains released (not active) until its owner
        verifies this receiver's fresh native state. No Popen/CLI PID adoption.
        """
        from .workstation_exec import ExecLaunch
        from .kernel_origin import alive
        if type(launch) is not ExecLaunch or launch.state != 'released':
            raise NativeUnavailable('verified released exec required')
        if startup_observer is not None and not callable(startup_observer):
            raise NativeUnavailable('trusted startup observer must be callable')
        cls._validate_initial_state_timeout(initial_state_timeout)
        receiver = cls.__new__(cls)
        receiver._initialize(transport=launch.transport.rpc_io(),
            task_alive=lambda: (launch.state in {'released', 'active'}
                                and not launch.origin.revoked and alive(launch.origin.pidfd)),
            journal=journal, runtime_version='1.4.0', scope=scope,
            incarnation_id=launch.incarnation, timeout=timeout, startup_observer=startup_observer,
            initial_state_timeout=initial_state_timeout)
        return receiver

    @staticmethod
    def _validate_initial_state_timeout(value):
        if value is not None and (type(value) not in (int, float)
                or not 0 < value <= 30 or not math.isfinite(value)):
            raise NativeUnavailable('initial state timeout must be finite and within 30 seconds')

    @staticmethod
    def _require_initial_deadline(deadline):
        if time.monotonic() >= deadline:
            raise NativeUnavailable('initial native state deadline exceeded; hold without reinjection')

    def _initialize(self, *, journal, runtime_version, scope, timeout,
                    process=None, argv=None, cwd=None, env=None, incarnation_id=None,
                    transport=None, task_alive=None, startup_observer=None, initial_state_timeout=None):
        self._closed = False
        self._owns_process = process is None and transport is None
        self._task_alive = task_alive
        self.incarnation_id = incarnation_id
        self.db = None
        self.process = transport if transport is not None else process
        self._reader = self._stderr = None
        self._condition = threading.Condition()
        self._write_lock = threading.Lock()
        self._scope_lock = threading.RLock()
        self._transport_fenced = False
        self._initial_state_timeout = initial_state_timeout
        self._initial_state_started = None
        # Only an explicit trusted owner opts in. No general receiver output,
        # event/command content capture or liveness/authority decision is added.
        self._startup_lock = threading.Lock()
        self._startup_capture = None
        if callable(startup_observer):
            self._startup_capture = {'active': True, 'stage': 'setup',
                'started': time.monotonic(), 'finished': None, 'bytes': 0,
                'hash': hashlib.sha256(), 'head': bytearray(), 'tail': bytearray()}
        try:
            self._validate_initial_state_timeout(initial_state_timeout)
            if startup_observer is not None and not callable(startup_observer):
                raise NativeUnavailable('trusted startup observer must be callable')
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
            self.process = (transport if transport is not None else process) if not self._owns_process else subprocess.Popen(
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
            self._reader_error_type = None
            self._binding = None
            self._reader = threading.Thread(target=self._read, daemon=True)
            self._stderr = threading.Thread(target=self._read_errors, daemon=True)
            self._reader.start()
            self._stderr.start()
            self._startup_stage('state-rpc')
            initial_deadline = None
            if initial_state_timeout is None:
                state = self._native('state', {})['state']
            else:
                # The explicit owner-only cold-start allowance is one fixed
                # deadline, not a new timeout for each initialization stage.
                self._initial_state_started = time.monotonic()
                initial_deadline = self._initial_state_started + initial_state_timeout
                state = self._native('state', {}, deadline=initial_deadline)['state']
                self._require_initial_deadline(initial_deadline)
            self._startup_stage('validation')
            if state.get('api_baseline') != runtime_version or state.get('readiness') not in {r.value for r in Readiness}:
                raise NativeUnavailable('unsupported or absent native observation')
            binding = {key: state[key] for key in ('runtime_id', 'session_id')}
            readiness = Readiness(state['readiness'])
            if initial_deadline is not None:
                self._require_initial_deadline(initial_deadline)
            self._binding = binding
            if self.incarnation_id is None:
                self.incarnation_id = binding['runtime_id']
            self.initial_state = state
            self.last_observation = state
            self.readiness = readiness
            self._startup_stage('complete')
            try:
                self._finish_startup_capture()
            except BaseException:
                pass
        except BaseException as error:
            try:
                self._finish_startup_capture()
                if callable(startup_observer):
                    # Observe before close/fencing, while the owner still holds
                    # the unrevised task identity and exact exec operation.
                    startup_observer(self, error)
            except BaseException:
                pass  # A diagnostic hook cannot replace the original error.
            self.close()
            raise

    def _startup_stage(self, stage):
        if self._startup_capture is None:
            return
        with self._startup_lock:
            if self._startup_capture is not None and self._startup_capture['active']:
                self._startup_capture['stage'] = stage

    def _finish_startup_capture(self):
        if self._startup_capture is None:
            return
        with self._startup_lock:
            if self._startup_capture is not None and self._startup_capture['active']:
                self._startup_capture['active'] = False
                self._startup_capture['finished'] = time.monotonic()

    def _capture_startup_stderr(self, raw):
        if self._startup_capture is None:
            return
        with self._startup_lock:
            value = self._startup_capture
            if value is not None and value['active']:
                value['bytes'] += len(raw)
                value['hash'].update(raw)
                value['head'].extend(raw[:max(0, 512 - len(value['head']))])
                value['tail'].extend(raw)
                del value['tail'][:-1536]

    def startup_diagnostic(self, *, include_stderr=False):
        """Owner-only observation; raw stderr requires an explicit fixture opt-in.

        The optional observer is the sole consumer. No event, command, response,
        scope or exception contents are included. Snapshot values grant nothing.
        """
        if type(include_stderr) is not bool:
            raise ValueError('stderr diagnostic option must be boolean')
        with self._startup_lock:
            value = self._startup_capture
            if value is None:
                return {'version': 1, 'enabled': False}
            count = value['bytes']
            head = bytes(value['head'])
            remaining = count - len(head)
            tail = bytes(value['tail'][-remaining:]) if 0 < remaining <= 1536 else (
                bytes(value['tail']) if remaining > 1536 else b'')
            stderr = {'bytes': count, 'sha256': value['hash'].hexdigest(),
                      'retained_bytes': len(head) + len(tail),
                      'truncated': count > len(head) + len(tail)}
            if include_stderr:
                # UTF-8 replacement itself can expand invalid bytes. Bound the
                # emitted UTF-8 text separately, not just its source buffers.
                head_text = head.decode('utf-8', errors='replace').encode('utf-8')
                tail_text = tail.decode('utf-8', errors='replace').encode('utf-8')
                stderr.update(head=head_text[:512].decode('utf-8', errors='ignore'),
                              tail=tail_text[:1536].decode('utf-8', errors='ignore'),
                              text_encoding='utf-8-replacement',
                              text_decode_truncated=len(head_text) > 512 or len(tail_text) > 1536)
            now = value['finished'] if value['finished'] is not None else time.monotonic()
            result = {'version': 1, 'enabled': True, 'authority': 'observation-only',
                      'stage': value['stage'], 'elapsed_seconds': round(max(0, now - value['started']), 6),
                      'capture_active': value['active'], 'stderr': stderr}
        timeout = getattr(self, 'timeout', None)
        ordinary = timeout if type(timeout) in (int, float) and 0 < timeout <= 3600 else None
        initial = self._initial_state_timeout
        initial = initial if type(initial) in (int, float) and 0 < initial <= 30 else None
        result['ordinary_timeout_seconds'] = ordinary
        result['initial_state_timeout_seconds'] = initial
        result['budget_seconds'] = initial if initial is not None else ordinary
        result['initial_state_elapsed_seconds'] = (None if self._initial_state_started is None else
            round(max(0, now - self._initial_state_started), 6))
        try:
            result['held_task_alive'] = bool(self._alive())
        except Exception as error:
            result['held_task_alive'] = None
            result['liveness_error_type'] = type(error).__name__[:64]
        with self._condition:
            result.update(reader_ended=getattr(self, '_ended', None),
                reader_error_type=getattr(self, '_reader_error_type', None),
                transport_fenced=self._transport_fenced,
                retained_event_count=len(getattr(self, 'events', ())),
                retained_error_count=len(getattr(self, 'errors', ())),
                buffered_response_count=len(getattr(self, '_responses', ())),
                buffered_notification_count=len(getattr(self, '_notifications', ())),
                pending_rpc_count=len(getattr(self, '_rpc_pending', ())),
                pending_native_count=len(getattr(self, '_native_pending', ())))
        result['reader_alive'] = self._reader.is_alive() if self._reader is not None else None
        result['stderr_reader_alive'] = self._stderr.is_alive() if self._stderr is not None else None
        result['io_error_present'] = getattr(self.process, 'error', None) is not None
        stop = getattr(self.process, '_stop', None)
        result['io_stopped'] = stop.is_set() if stop is not None else None
        result['streams_closed'] = {name: closed if type(closed) is bool else None
            for name in ('stdin', 'stdout', 'stderr')
            for closed in (getattr(getattr(self.process, name, None), 'closed', None),)}
        return result

    def _alive(self):
        # Transport EOF is separately observed; it is not proof of task exit.
        return self._task_alive() if self._task_alive is not None else self.process.poll() is None

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
            self._reader_error_type = type(error).__name__
            self.errors.append(str(error))
        finally:
            with self._condition:
                self._ended = True
                self._condition.notify_all()

    def _read_errors(self):
        try:
            for line in iter(lambda: self.process.stderr.readline(4096), b''):
                self._capture_startup_stderr(line)
                self.errors.append(line[:4096].decode('utf8', errors='replace'))
        except (OSError, ValueError):
            pass  # Controller may close streams after reaping its owned process.

    def _wait(self, values, request_id, timeout=None, *, deadline=None):
        initial_deadline = deadline is not None
        if deadline is None:
            deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        with self._condition:
            if initial_deadline:
                self._require_initial_deadline(deadline)
            while request_id not in values:
                if self._transport_fenced:
                    raise NativeUnavailable('native transport fenced after incomplete write')
                if self._ended or not self._alive():
                    raise NativeUnavailable('native process lost')
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if initial_deadline:
                        self._require_initial_deadline(deadline)
                    raise NativeUnavailable('missing native response; hold without reinjection')
                self._condition.wait(remaining)
            if initial_deadline:
                self._require_initial_deadline(deadline)
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

    def rpc(self, command, *, timeout=None, _deadline=None, **fields):
        budget = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + budget if _deadline is None else _deadline
        if _deadline is not None:
            self._require_initial_deadline(deadline)
        request_id = uuid.uuid4().hex
        wire = json.dumps({'id': request_id, 'type': command, **fields}, ensure_ascii=False).encode() + b'\n'
        with self._condition:
            self._rpc_pending.add(request_id)
        try:
            self._write(wire, deadline)
            if _deadline is None:
                result = self._wait(self._responses, request_id, max(0, deadline - time.monotonic()))
            else:
                result = self._wait(self._responses, request_id, deadline=deadline)
                self._require_initial_deadline(deadline)
            if result.get('success') is not True:
                raise NativeUnavailable('native command rejected: ' + str(result.get('error', 'unknown')))
            return result
        finally:
            with self._condition:
                self._rpc_pending.discard(request_id)
                self._responses.pop(request_id, None)

    def _native(self, command, payload, *, deadline=None):
        request_id = uuid.uuid4().hex
        message = base64.urlsafe_b64encode(json.dumps({**payload, 'request_id': request_id},
                                                      ensure_ascii=False).encode()).decode()
        with self._condition:
            self._native_pending.add(request_id)
        try:
            # "handled" only means extension dispatch completed, NEVER delivery.
            if deadline is None:
                self.rpc('prompt', message=f'/uas-{command} {message}')
            else:
                self._require_initial_deadline(deadline)
                self.rpc('prompt', message=f'/uas-{command} {message}', _deadline=deadline)
            if command == 'state':
                self._startup_stage('state-notification')
            if deadline is None:
                return self._wait(self._notifications, request_id)
            result = self._wait(self._notifications, request_id, deadline=deadline)
            self._require_initial_deadline(deadline)
            return result
        finally:
            with self._condition:
                self._native_pending.discard(request_id)
                self._notifications.pop(request_id, None)

    def observe(self):
        if self._transport_fenced:
            self.readiness = Readiness.AMBIGUOUS
            return self.readiness
        if not self._alive() or self._ended:
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
        # A handoff and an owner generation CAS cannot interleave between the
        # scope check and native injection. An already prepared old offer loses.
        with self._scope_lock:
            return self._accept(envelope)

    def _accept(self, envelope):
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
                'process_alive': self._alive(),
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

    def advance_run_generation(self, expected_scope, target_scope, *, authorize):
        """Owner-only CAS after canonical policy fencing; never a context reset.

        The Run and native session stay identical. Old handoffs remain immutable
        history and cannot be reinjected in the new generation. Authorization
        must verify the canonical paused migration and exact owned incarnation.
        """
        with self._scope_lock:
            return self._advance_run_generation(expected_scope, target_scope, authorize=authorize)

    def _advance_run_generation(self, expected_scope, target_scope, *, authorize):
        if (not callable(authorize) or authorize() is not True or self._closed
                or type(expected_scope) is not dict or type(target_scope) is not dict
                or set(expected_scope) != set(self.scope) or set(target_scope) != set(self.scope)
                or any(type(target_scope[k]) is not type(expected_scope[k])
                       or target_scope[k] != expected_scope[k] for k in self.scope if k != 'generation')
                or any(type(expected_scope[k]) is not str or not expected_scope[k]
                       for k in ('room_id', 'participant_id', 'run_id'))
                or type(expected_scope.get('context_generation')) is not int
                or not 1 <= expected_scope['context_generation'] <= 2**53 - 1
                or type(expected_scope.get('generation')) is not int
                or not 1 <= expected_scope['generation'] < 2**53 - 1
                or type(target_scope.get('generation')) is not int
                or target_scope['generation'] != expected_scope['generation'] + 1
                or target_scope['generation'] > 2**53 - 1):
            raise NativeUnavailable('invalid same-context generation migration')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT scope FROM binding WHERE singleton=1').fetchone()
            current = json.loads(row[0]) if row else None
            if (type(current) is not dict or set(current) != set(expected_scope)
                    or any(type(current[k]) is not type(expected_scope[k]) for k in expected_scope)
                    or current not in (expected_scope, target_scope)
                    or self.scope not in (expected_scope, target_scope)):
                raise NativeUnavailable('native generation binding conflict')
            if authorize() is not True:
                raise NativeUnavailable('native generation authority revoked')
            self.db.execute('UPDATE binding SET scope=? WHERE singleton=1', (json.dumps(target_scope),))
            self.db.commit()
            self.scope = dict(target_scope)
        except BaseException:
            self.db.rollback()
            raise
        return dict(self.scope)

    def close(self):
        # Every resource slot exists before initialization can fail. Retrying
        # close may join readers after an attached owner has subsequently reaped.
        self._closed = True
        self._transport_fenced = True
        with self._condition:
            self._condition.notify_all()
        try:
            if self.process is not None:
                if self._owns_process and self._alive():
                    try:
                        self.process.stdin.close()
                        self.process.wait(timeout=3)
                    except (OSError, ValueError, subprocess.TimeoutExpired):
                        self.process.kill()
                        self.process.wait(timeout=3)
                # An attached receiver never kills/closes controller resources.
                # Its owner reaps on failure; started readers then observe EOF.
                if not self._alive():
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
