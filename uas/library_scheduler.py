"""T20 fair bounded turns. Trusted service API, not a Participant command.

A caller pumps tick(); enqueue mailboxes and explicit controls never execute
inference on the publication path. T21 owns the host startup/report loop.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import threading

from . import library, library_bundle as bundle, library_gate as gate
from .library_attempts import Attempts
from .library_records import LibraryRecords
from .library_registration import project_state

BACKOFF = (5, 30, 120, 600, 1800)
MODEL_FAILURES = frozenset({'MODEL_TIMEOUT', 'MODEL_OUTPUT_INVALID', 'MODEL_JSON_INVALID',
                            'MODEL_RESPONSE_BOUND'})


def fail(code):
    raise library.LibraryError(code, 'scheduler')


def instant(value):
    if not isinstance(value, datetime) or value.tzinfo is None: fail('SCHEDULER_CLOCK_INVALID')
    return value.astimezone(timezone.utc)


class Scheduler:
    """One service scheduler per leased publisher. Threads may signal during a turn."""
    def __init__(self, publisher, *, now=lambda: datetime.now(timezone.utc)):
        self.publisher, self.now = publisher, now
        self._lock = threading.RLock()
        self._turn = threading.Lock()
        self._entries = {}
        self._failed = self._closed = False
        # The publisher already owns the host-local exclusive service lease.
        with publisher._subscriptions_lock:
            if getattr(publisher, '_scheduler', None) is not None: fail('SCHEDULER_ALREADY_ACTIVE')
            publisher._scheduler = self

    def _check(self):
        if self._closed: fail('SCHEDULER_CLOSED')
        if self._failed: fail('SCHEDULER_RECOVERY_REQUIRED')

    def _records(self):
        return LibraryRecords(self.publisher.records_path, self.publisher.deployment_id)

    def _authority(self, entry):
        scope = entry['runner'].assembler._scope()
        if type(scope) is not library.LibraryScope or scope.canonical() != entry['scope'].canonical(): fail('LIBRARY_AUTHENTICATION_REQUIRED')
        library._require_scope(scope, 'participant', library.ENQUEUE_CAPABILITY)
        settings = entry['runner'].assembler._settings()
        if settings['repository']['target'] != self.publisher.target or settings['repository']['branch'] != self.publisher.branch:
            fail('SCHEDULER_TARGET_MISMATCH')
        entry['settings'] = deepcopy(settings)
        return scope, settings

    def _save(self, entry, value, at, *, transition=None, control=None):
        # Service-owned operational evidence must survive Project revocation.
        # This does not read or publish Project content under stale authority.
        scope, settings = entry['scope'], entry['settings']
        value = {**deepcopy(value), 'sequence': entry['state']['sequence'] + 1}
        value.pop('transition', None)
        phase = transition
        if phase is None:
            if value['state'] == 'ACTIVE' and value['drain_id'] and value['attempt'] > entry['state']['attempt']: phase = {'phase':'STARTED'}
            elif value['state'] in ('BACKOFF','BLOCKED') and any(value[k] != entry['state'][k] for k in ('state','attempt','failures','reason')):
                phase = {'phase':'RETRY_SCHEDULED' if value['state']=='BACKOFF' else 'BLOCKED'}
        if phase is not None:
            old = entry['state']
            value['transition'] = library.drain_transition(dict(
                drain_id=phase.get('drain_id', value['drain_id'] or old['drain_id'] or 'validation-'+library._digest(entry['scope'].project_identity)),
                sequence=value['sequence'], phase=phase['phase'],
                attempt=phase.get('attempt', value['attempt'] or old['attempt']),
                outcomes=phase.get('outcomes', []), resulting_sha=phase.get('resulting_sha'),
                reason=value['reason'], due=value['due'] if phase['phase']=='RETRY_SCHEDULED' else None))
        library.scheduler_manifest(value)
        identity = 'scheduler-' + library._digest(scope.project_identity) + '-' + str(value['sequence'])
        operation = library._operation('scheduler-state', scope, settings, identity, identity,
            {'manifest_sha256': library._digest(value)}, at.isoformat())
        operation = replace(operation, manifest=value)
        try:
            with self._records() as records:
                schedule_receipt = library.receipt(operation, 'ACKNOWLEDGED', at=at.isoformat(),
                    acknowledgement=library._digest(value), reason='SCHEDULE_RECORDED')
                if control is None:
                    records.begin(operation); records.finish(operation, schedule_receipt)
                else:
                    response = library.receipt(control, 'ACKNOWLEDGED', at=at.isoformat(),
                        acknowledgement=library._digest(value), reason='SCHEDULE_RECORDED')
                    records.schedule_control(control, response, operation, schedule_receipt)
        except BaseException:
            self._failed = True  # reopen/read durable intent before any other turn
            raise
        entry['state'] = value
        return response if control is not None else None

    def register(self, runner, *, context=lambda selected: ((), ()), recovery=False, binding_scope=None):
        """Register a trusted current Project composition; reconnect restores durable state."""
        with self._lock:
            self._check()
            if type(runner) is not Attempts or runner.publisher is not self.publisher or not callable(context):
                fail('SCHEDULER_DEPENDENCY_REQUIRED')
            scope = binding_scope if recovery and binding_scope is not None else runner.assembler._scope()
            if not recovery: library._require_scope(scope, 'participant', library.ENQUEUE_CAPABILITY)
            if type(scope) is not library.LibraryScope: fail('LIBRARY_AUTHENTICATION_REQUIRED')
            key = scope.project_identity
            if key in self._entries: fail('PROJECT_ALREADY_REGISTERED')
            with self._records() as records: saved = records.latest_schedule(key)
            state = deepcopy(saved['manifest']) if saved else dict(sequence=0, served=0, state='IDLE',
                due=None, drain_id=None, selected=[], attempt=0, failures=0, model_failures=0,
                wake=False, reason=None)
            entry = dict(scope=scope, runner=runner, context=context, state=state,
                         subscription=self.publisher.subscribe(scope), version=0)
            self._entries[key] = entry
            if state['state'] == 'DISPOSED':
                entry['settings'] = runner.assembler._settings()
                return key
            try:
                self._authority(entry)
            except library.LibraryError as error:
                if not recovery: self._entries.pop(key); self.publisher.unsubscribe(entry['subscription']); raise
                entry['settings'] = runner.assembler._settings()
                self._save(entry,{**state,'state':'BLOCKED','due':None,'reason':error.code},instant(self.now()))
                return key
            # Startup reconciliation does not bypass backoff or model blocking.
            if state['state'] not in ('BACKOFF', 'BLOCKED', 'DISPOSED'):
                self._save(entry, {**state, 'state':'READY', 'due':instant(self.now()).isoformat()}, instant(self.now()))
            return key

    def state(self, key):
        with self._lock:
            self._check(); entry = self._entries[key]; self._authority(entry)
            return deepcopy(entry['state'])

    def request(self, key, *, retry=False, control=None):
        """Trusted operator-service request; caller-facing authorization is owned by T22.

        retry is the distinct explicit action releasing the original blocked batch.
        Neither action executes work or changes fair priority/preempts a turn.
        """
        with self._lock:
            self._check(); entry = self._entries[key]
            if control is None:
                self._authority(entry)
            else:
                library._require_scope(control.scope, 'human', 'library-' + ('retry' if retry else 'drain'))
                if control.scope.project_identity != key: fail('FORBIDDEN')
                settings = library.admit_settings_value(entry['runner'].assembler._settings())
                if settings['settings_id'] != control.settings_id: fail('STALE_CONTROL_STATE')
                entry['settings'] = settings
            old = entry['state']; now = instant(self.now())
            if old['state'] == 'DISPOSED': fail('DRAIN_DISPOSED')
            if old['state'] == 'BLOCKED' and not retry: fail('PROJECT_BLOCKED')
            if retry and old['state'] != 'BLOCKED': fail('PROJECT_NOT_BLOCKED')
            state = {**old, 'wake':True}
            if old['state'] != 'ACTIVE':
                state.update(state='READY', due=now.isoformat(), reason=None)
            if retry: state.update(model_failures=0, failures=0)
            return self._save(entry, state, now, control=control)

    def reconcile(self, key):
        """T21 startup/reconnect signal, deliberately not an implicit operator retry."""
        with self._lock:
            self._check(); entry = self._entries[key]; old = entry['state']
            if old['state'] in ('BLOCKED', 'BACKOFF', 'ACTIVE', 'DISPOSED'): return
            now = instant(self.now())
            self._save(entry, {**old, 'state':'READY', 'due':now.isoformat()}, now)

    def _signals(self):
        for entry in self._entries.values():
            version, publication, closed = entry['subscription'].wait(entry['version'], timeout=0)
            if closed or version == entry['version']: continue
            entry['version'] = version
            old = entry['state']; now = instant(self.now())
            if old['state'] == 'DISPOSED': continue
            try:
                _, settings = self._authority(entry)
            except library.LibraryError as error:
                self._save(entry, {**old, 'state':'BLOCKED', 'due':None, 'reason':error.code}, now)
                continue
            state = {**old, 'wake':True}
            if old['state'] == 'IDLE':
                state.update(state='READY', due=(now + timedelta(seconds=settings['limits']['coalesce_seconds'])).isoformat())
            # Repeated enqueues never postpone the first wake, clear retry delay,
            # replace a fixed batch, or bypass a blocked Project.
            self._save(entry, state, now)

    def _batch(self, entry):
        scope, settings = self._authority(entry)
        current = lambda: self._authority(entry)
        try:
            head, tree = self.publisher.project_snapshot(scope, settings, current=current)
        except library.LibraryError as error:
            if error.code in ('UNSUPPORTED_PROJECT_ENTRY','INVALID_PROJECT_TREE','TOO_MANY_DOCUMENTS','BUNDLE_TOO_LARGE'):
                raise library.LibraryError('PROJECT_QUEUE_INVALID', 'scheduler') from error
            raise
        try:
            gate.validate(scope, settings, proposed=tree, current=tree)
        except library.LibraryError as error:
            raise library.LibraryError('PROJECT_QUEUE_INVALID', 'scheduler') from error
        prefix = bundle._prefix(scope)
        if project_state(tree, prefix) != 'active': fail('PROJECT_ARCHIVED')
        pending = tree.files[prefix + '/pending/index.md'].decode('utf-8')
        queues = {}
        for path, data in tree.files.items():
            if not path.startswith(prefix + '/pending/') or path.endswith('/index.md'): continue
            queue = path[len(prefix + '/pending/'):-3]
            library._digest_value(queue, 'queue_id')
            if any(queue + '.md)' in line and 'DRAFT PARKED:' in line for line in pending.splitlines()): continue
            queues[queue] = len(data)
        ordered = self.publisher.queue_order(scope, settings, head, queues, current=current) if queues else ()
        selected, size = [], 0
        for queue in ordered:
            if len(selected) == settings['limits']['batch_drafts']: break
            if size + queues[queue] > settings['limits']['batch_bytes']:
                if not selected: fail('BATCH_TOO_LARGE')
                break
            selected.append(queue); size += queues[queue]
        return selected

    def tick(self):
        """Perform at most one fair bounded unit, then return/yield to the caller."""
        if not self._turn.acquire(blocking=False): fail('SCHEDULER_BUSY')
        try:
            with self._lock:
                self._check(); self._signals(); now = instant(self.now())
                eligible = [(entry['state']['served'], key, entry) for key, entry in self._entries.items()
                    if entry['state']['state'] in ('READY','BACKOFF')
                    and entry['state']['due'] is not None
                    and datetime.fromisoformat(entry['state']['due']) <= now]
                if not eligible: return None
                _, key, entry = min(eligible, key=lambda item: item[:2])
                state = deepcopy(entry['state'])
                state['served'] = max(int(now.timestamp() * 1000000),
                    max(e['state']['served'] for e in self._entries.values()) + 1)
                state.update(state='ACTIVE', due=None, wake=False, reason=None)
                # Turn reservation and fairness survive a crash before inference.
                self._save(entry, state, now)
            try:
                if not state['selected']:
                    selected = self._batch(entry)
                    with self._lock:
                        state = deepcopy(entry['state'])
                        if not selected:
                            self._save(entry, {**state, 'state':'IDLE', 'due':None}, instant(self.now()))
                            return dict(project_identity=key, state='EMPTY')
                        state.update(selected=selected, drain_id='drain-' + library._digest([key,state['sequence']]), attempt=0)
                        self._save(entry, state, instant(self.now()))
                with self._lock:
                    state = deepcopy(entry['state']); state['attempt'] += 1
                    at = instant(self.now()); self._save(entry, state, at)
                accepted, indexes = entry['context'](tuple(state['selected']))
                result = entry['runner'].run(drain_id=state['drain_id'], attempt=state['attempt'],
                    selected=state['selected'], accepted=accepted, indexes=indexes, at=at.isoformat())
            except library.LibraryError as error:
                if (error.code.startswith(('RECORD_', 'STORE_', 'GIT_', 'REMOTE_', 'LEASE_', 'CLONE_', 'PIN_')) or error.code in ('PUBLICATION_UNAVAILABLE','INVALID_STORE','INVALID_RECORD')):
                    self._failed = True
                    raise
                with self._lock:
                    old = entry['state']; now = instant(self.now())
                    failures = old['failures'] + 1
                    model_failures = old['model_failures'] + int(error.code in MODEL_FAILURES)
                    blocked = model_failures >= 3 or error.code in ('BATCH_TOO_LARGE','PROJECT_ARCHIVED',
                        'LIBRARY_AUTHENTICATION_REQUIRED','CONFIGURATION_CHANGED','SCHEDULER_TARGET_MISMATCH',
                        'PROJECT_QUEUE_INVALID','QUEUE_HISTORY_INCOMPLETE')
                    self._save(entry, {**old, 'state':'BLOCKED' if blocked else 'BACKOFF',
                        'due':None if blocked else (now + timedelta(seconds=BACKOFF[min(failures-1,4)])).isoformat(),
                        'failures':failures, 'model_failures':model_failures, 'reason':error.code}, now)
                return dict(project_identity=key, state=entry['state']['state'], reason=error.code)
            except BaseException:
                self._failed = True
                raise
            with self._lock:
                old = entry['state']; now = instant(self.now())
                self._save(entry, {**old, 'state':'READY', 'due':now.isoformat(),
                    'drain_id':None, 'selected':[], 'attempt':0, 'failures':0, 'model_failures':0,
                    'reason':None}, now, transition=dict(phase='COMMITTED', drain_id=result.drain_id,
                        attempt=result.attempt, resulting_sha=result.resulting_sha,
                        outcomes=[dict(queue_id=q,kind='parked',reason=r) for q,r in result.outcomes]
                            if result.state=='SOURCE_PARKED' else list(result.outcomes)))
            return dict(project_identity=key, state=result.state, drain_id=result.drain_id,
                        attempt=result.attempt, resulting_sha=result.resulting_sha)
        finally: self._turn.release()

    def recover(self, key):
        """Startup only: validate canonical Project, recover commits without model contact."""
        with self._lock:
            self._check(); entry = self._entries[key]
            try:
                old = entry['state']
                if old['state'] == 'DISPOSED': return
                if old['selected']:
                    result = entry['runner'].recover(old['drain_id'])
                    if result is not None:
                        now = instant(self.now())
                        self._save(entry, {**old, 'state':'READY', 'due':now.isoformat(),
                            'drain_id':None,'selected':[],'attempt':0,'failures':0,'model_failures':0,'reason':None}, now,
                            transition=dict(phase='COMMITTED',drain_id=result.drain_id,attempt=result.attempt,
                                resulting_sha=result.resulting_sha,outcomes=list(result.outcomes)))
                self._batch(entry)  # validate next eligible bundle only after committed recovery
            except library.LibraryError as error:
                if (error.code.startswith(('RECORD_', 'STORE_', 'GIT_', 'REMOTE_', 'LEASE_', 'CLONE_', 'PIN_')) or error.code in ('PUBLICATION_UNAVAILABLE','INVALID_STORE','INVALID_RECORD')): raise
                old = entry['state']
                self._save(entry, {**old,'state':'BLOCKED','due':None,'reason':error.code},instant(self.now()),
                    transition={'phase':'BLOCKED','drain_id':old['drain_id'] or 'validation-'+library._digest(key),
                        'attempt':old['attempt']})

    def close(self):
        if not self._turn.acquire(blocking=False): fail('SCHEDULER_BUSY')
        try:
            with self._lock:
                for entry in self._entries.values(): self.publisher.unsubscribe(entry['subscription'])
                self._closed = True
                with self.publisher._subscriptions_lock:
                    if self.publisher._scheduler is self: self.publisher._scheduler = None
        finally: self._turn.release()
