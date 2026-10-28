"""Bounded human Run controls over the existing ledger and owned fixture Runtime.

Intent/fencing commits before native effects. Unknown stop or generation rebind
retains the exact intent and resources for an explicit retry; it is never success.
There is no timer, background retry, completion adjudication, or PID adoption.
"""
from copy import deepcopy
import hashlib
import os
import select

from .context import MAX_CONTEXT_GENERATION
from .forge_projections import enqueue_run_projection
from .ledger import Command, Event, LedgerError, Transition, _token, _json
from .peer import FixturePeerHub, TERMINAL, _now


def reserve_run_control_capacity(state):
    """Model bounded future lifecycle metadata on a disposable projection copy.

    Native targets are exactly the existing context owners, not 32 invented
    owners per Run. Recruiting another context must reserve its own growth.
    """
    wide = 'x' * 256
    maximum = MAX_CONTEXT_GENERATION
    def targets(run_id, previous=()):
        participants = {target['participant_id'] for target in previous}
        for participant, context in state.get('fixture_context', {}).get('participants', {}).items():
            scope = context.get('bound_run') or context.get('reserved_run')
            if scope is not None and scope['run_id'] == run_id:
                participants.add(participant)
        return [{'participant_id': participant, 'incarnation_id': wide,
                 'actor_id':wide,'attachment_id':wide,
                 'scope': {'room_id': wide, 'participant_id': participant,
                    'run_id': run_id, 'generation': maximum, 'context_generation': maximum}}
                for participant in sorted(participants)]
    release = {'status': 'RELEASED', 'reason': wide, 'path': 'x' * 4096, 'disposition': 'retained'}
    for run_id, row in state.get('runs', {}).items():
        owners = targets(run_id, (row.get('control_pending') or {}).get('targets', ()))
        row.update(generation=maximum, control_revision=maximum, control_reason=wide,
            stop_reason=wide, outcome='stopped', successor_run=wide,
            checkout_release=deepcopy(release), coordinator_attention=wide, coordinator_nomination=wide,
            native_stop={'operation_id': wide, 'status': 'VERIFIED', 'generation': maximum,
                         'restored': False, 'restore_attention': wide},
            coordinator={'participant_id': wide, 'incarnation_id': wide, 'generation': maximum,
                'expires_at': maximum, 'request_budget': 16, 'requests_used': 16, 'appointment': wide},
            control_pending={'operation_id': wide, 'kind': 'policy-migrate',
                'control_revision': maximum, 'completion_digest': 'f' * 64,
                'source_generation': maximum, 'target_generation': maximum,
                'targets': owners, 'reason': wide, 'attention': wide,
                'policy_id': wide, 'policy_version': maximum, 'successor_run': wide})
    for run_id, row in state.get('run_admissions', {}).items():
        row.update(withdrawal={'operation_id': wide,
                'targets': targets(run_id, (row.get('withdrawal') or {}).get('targets', ())), 'reason': wide},
            checkout_release=deepcopy(release), stop_reason=wide, native_stop='VERIFIED')


class RunControl:
    """Mixin for the Room's existing RunAdmission owner, not another store."""

    @staticmethod
    def _run_revision(state, run_id, generation, revision, *, allow_pending=False):
        if (type(generation) is not int or not 1 <= generation <= MAX_CONTEXT_GENERATION
                or type(revision) is not int or not 0 <= revision <= MAX_CONTEXT_GENERATION):
            raise LedgerError('INVALID_RUN_CONTROL')
        row = state.get('runs', {}).get(run_id)
        if row is None:
            raise LedgerError('UNKNOWN_RUN')
        if row['generation'] != generation:
            raise LedgerError('STALE_RUN_GENERATION')
        if row.get('control_revision', 0) != revision:
            raise LedgerError('STALE_RUN_CONTROL')
        if row['status'] == 'CLOSED':
            raise LedgerError('INVALID_RUN_TRANSITION')
        if row.get('control_pending') is not None and not allow_pending:
            raise LedgerError('RUN_CONTROL_PENDING')
        if revision == MAX_CONTEXT_GENERATION:
            raise LedgerError('RUN_CONTROL_REVISION_EXHAUSTED')
        return row

    @staticmethod
    def _cancel_generation(state, run_id, generation, reason):
        cancelled = []
        for item in state['peer_traffic']['traffic'].values():
            if (item['run_id'] == run_id and item['generation'] == generation
                    and item.get('status') not in TERMINAL):
                item.update(status='CANCELLED', reason=reason, attention=None)
                cancelled.append(item['id'])
        # Offers and native delivery receipts remain immutable evidence. In
        # particular, an unconfirmed handoff does not become NOT_APPLIED.
        return cancelled

    def _control_contexts(self, state, run_id, *, admission=None):
        targets = []
        for participant, context in state['fixture_context']['participants'].items():
            scope = context['bound_run'] or context['reserved_run']
            reset = context.get('reset')
            withdrawing_reset = (admission is not None and participant == admission['participant_id']
                and reset is not None and reset.get('target_run', {}).get('run_id') == run_id)
            withdrawing_preceding = (admission is not None and participant == admission['participant_id']
                and scope is not None and admission.get('preceding_run') == scope
                and state['fixture_context']['runs'].get(scope['run_id'], {}).get('status') == 'CLOSED')
            if scope is None or not (scope['run_id'] == run_id or withdrawing_reset or withdrawing_preceding):
                continue
            if not withdrawing_reset and (context['status'] != 'READY'
                    or reset is not None and reset['status'] != 'SUCCEEDED'):
                raise LedgerError('CONTEXT_UNAVAILABLE')
            targets.append({'participant_id': participant,
                'scope': {'room_id': self.ledger.room_id, 'participant_id': participant,
                    **scope, 'context_generation': context['context_generation']}})
        if not targets or len(targets) > 32:
            raise LedgerError('RUN_CONTEXT_OWNERSHIP_UNKNOWN')
        return targets

    def _control_targets(self, state, run_id, document, *, admission=None):
        targets=self._control_contexts(state,run_id,admission=admission)
        for target in targets:
            record=document['seats'].get(target['participant_id'])
            target['incarnation_id']=record['incarnation_id'] if record else None
        return targets

    @staticmethod
    def _fence_generation(state, row, targets):
        generation = row['generation']
        if generation == MAX_CONTEXT_GENERATION:
            raise LedgerError('RUN_GENERATION_EXHAUSTED')
        domain = state['fixture_context']
        context_run = domain['runs'].get(row['run_id'])
        if not context_run or context_run['generation'] != generation or context_run['status'] != 'OPEN':
            raise LedgerError('RUN_CONTEXT_OWNERSHIP_UNKNOWN')
        for target in targets:
            context = domain['participants'][target['participant_id']]
            key = 'bound_run' if context['bound_run'] is not None else 'reserved_run'
            if context[key] != {'run_id': row['run_id'], 'generation': generation}:
                raise LedgerError('CONTEXT_MISMATCH')
            context[key] = {'run_id': row['run_id'], 'generation': generation + 1}
        context_run['generation'] = generation + 1
        row.update(generation=generation + 1, status='PAUSED', coordinator=None)

    def _control_finish(self, state, row, kind, result, extra_events=()):
        projection = enqueue_run_projection(state, self.ledger.room_id, row['run_id']) if 'issue_id' in row else None
        FixturePeerHub._reserve_capacity(state)
        events = (Event(kind, result),) + extra_events + ((projection,) if projection else ())
        return Transition(state, events, result)

    @staticmethod
    def _finish_id(operation_id):
        return 'run-control-result-' + hashlib.sha256(operation_id.encode()).hexdigest()

    def _rebind_generation(self, pending, human, command):
        """Native adapter owns its durable scope CAS; context/session is retained."""
        with self.supervisor._locked():
            self._rebind_generation_locked(pending, human, command)

    def _rebind_generation_locked(self, pending, human, command):
        for target in pending['targets']:
            if not self._control_authorized(pending, human, command):
                raise LedgerError('FORBIDDEN')
            handle = self.controller.handles.get(target['participant_id'])
            if handle is None or handle.badge.incarnation_id != target['incarnation_id']:
                raise LedgerError('NATIVE_GENERATION_REBIND_REQUIRED')
            self._authority(handle)
            receiver = handle.connection.receiver
            advance = getattr(receiver, 'advance_run_generation', None)
            if not callable(advance):
                raise LedgerError('NATIVE_GENERATION_REBIND_REQUIRED')
            target_scope = {**target['scope'], 'generation': pending['target_generation']}
            authorize = lambda: self._control_authorized(pending, human, command) and self._authority(handle)
            if getattr(handle, 'protocol', None) == 'pi':
                self.controller._advance_pi_generation_locked(handle, target['scope'], target_scope, authorize=authorize)
            else:
                advance(target['scope'], target_scope, authorize=authorize)
            if receiver.scope != target_scope:
                raise LedgerError('NATIVE_GENERATION_REBIND_REQUIRED')

    def _control_authorized(self, pending, human, command):
        if not self._human(human, command):
            return False
        state = self.ledger.snapshot()['state']
        current = (state.get('run_admissions', {}).get(command.target, {}).get('withdrawal')
                   if command.kind == 'run.human-withdraw' else
                   state.get('runs', {}).get(command.target, {}).get('control_pending'))
        return current == pending

    @staticmethod
    def _absent_pid(pid):
        """Absence check only. A persisted numeric PID never grants kill authority."""
        try:
            descriptor = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            return True
        try:
            return bool(select.select([descriptor], [], [], 0)[0])
        finally:
            os.close(descriptor)

    def _stop_owned(self, pending, human, command):
        for target in pending['targets']:
            with self.supervisor._locked():
                if not self._control_authorized(pending, human, command):
                    raise LedgerError('FORBIDDEN')
                participant = target['participant_id']
                record, handle = self._target_owner(target)
            if handle is not None:
                # revoke uses only the controller's held child and native
                # identities. It cannot target a PID supplied in this command.
                self.controller.revoke(participant, expected_incarnation=target['incarnation_id'],
                    authorize=lambda: self._control_authorized(pending, human, command))
        with self.supervisor._locked():
            self._verify_control_effect(pending, 'stop')

    def _target_owner(self, target):
        record = self.controller._read()['seats'].get(target['participant_id'])
        handle = self.controller.handles.get(target['participant_id'])
        if ((record is None) != (target['incarnation_id'] is None)
                or record is not None and record['incarnation_id'] != target['incarnation_id']
                or handle is not None and handle.badge.incarnation_id != target['incarnation_id']):
            raise LedgerError('NATIVE_OWNERSHIP_CHANGED')
        return record, handle

    def _verify_control_effect(self, pending, kind):
        """Fresh exact ownership check under the caller's lifecycle lock."""
        for target in pending['targets']:
            record, handle = self._target_owner(target)
            if kind == 'policy-migrate':
                if (handle is None or handle.connection is None or handle.connection.receiver.scope !=
                        {**target['scope'], 'generation': pending['target_generation']}):
                    raise LedgerError('NATIVE_GENERATION_REBIND_REQUIRED')
                self._authority(handle)
            elif handle is not None:
                if (self.controller._alive(handle) or handle.process.poll() is None
                        or handle.protocol == 'claude' and not handle.cleanup_verified):
                    raise LedgerError('NATIVE_STOP_UNVERIFIED')
            elif record is not None:
                if record.get('cleanup_pending'):
                    raise LedgerError('NATIVE_STOP_UNVERIFIED')
                if any(not self._absent_pid(pid) for pid in
                       (record.get('pid'), record.get('host_pid')) if pid is not None):
                    raise LedgerError('NATIVE_STOP_UNVERIFIED')
        # Reconstructed owners retain possible writers but never adopt them.
        if kind != 'policy-migrate' and any(not self._absent_pid(pid)
                for pid in self.controller._read()['retired_pids']):
            raise LedgerError('RETIRED_PROCESSES_UNVERIFIED')

    def _release_checkout(self, run_id, participant, *, authorize=None):
        """Release ownership through its authoritative allocator, never delete."""
        from .lifecycle import LifecycleError
        try:
            slots = [slot for slot in self.allocator.status() if slot['run'] == run_id]
            if not slots:
                return {'status': 'ABSENT', 'reason': 'NO_OWNED_CHECKOUT'}
            if len(slots) != 1 or slots[0]['participant'] != participant:
                raise LedgerError('CHECKOUT_BINDING_CONFLICT')
            slot = self.allocator.release(run_id, participant, authorize=authorize)
            return {'status': 'RELEASED', 'reason': slot['reason'],
                    'path': slot['path'], 'disposition': slot['disposition']}
        except LifecycleError as error:
            if error.code == 'ADMISSION_REVOKED':
                raise LedgerError('FORBIDDEN') from error
            # The exact slot remains owned. A closed Run does not authorize
            # deleting/adopting unknown paths or overwriting retained files.
            return {'status': 'RETAINED', 'reason': error.code}

    def _assignment_settled(self, run_id):
        service = self.broker.assignments
        if service is None:
            return
        record = service.audit.get(service._key('admit-assignment-' + run_id))
        if record is None:
            return
        result = record.get('result')
        if result is None:
            raise LedgerError('ADMISSION_ASSIGNMENT_PENDING')
        if result['status'] == 'UNKNOWN_OUTCOME':
            observations = record.get('reconciliations', [])
            latest = observations[-1].get('observation') if observations else None
            if not latest or latest['status'] not in {'MATCHED', 'ABSENT', 'CONFLICT'}:
                raise LedgerError('ADMISSION_ASSIGNMENT_PENDING')

    def _migration_request(self, state, row, operation_id, human):
        request_id = 'implementation-migration-' + hashlib.sha256(operation_id.encode()).hexdigest()
        if request_id in state['peer_traffic']['traffic']:
            raise LedgerError('ID_CONFLICT')
        state['peer_traffic']['traffic'][request_id] = {
            'id': request_id, 'kind': 'peer.work-request', 'sender': 'run-hub', 'actor_id': human.actor_id,
            'run_id': row['run_id'], 'generation': row['generation'], 'recipients': [row['participant_id']],
            'text': self._request_text(row['issue_number'], row['policy'], row['checkout']['path']),
            'parent_id': None, 'correlation_id': request_id, 'submitted_at': _now(),
            'submitted_seq': self.ledger.snapshot()['room_seq'] + 1, 'deliveries': {}, 'status': 'QUEUED',
            'response_started_at': None, 'reason': None, 'attention': None}
        row['implementation_request'] = request_id
        return Event('peer.submitted', {'traffic_id': request_id, 'recipients': [row['participant_id']]})

    def migrate_policy(self, operation_id, run_id, generation, revision,
                       policy_id, policy_version, reason, *, human):
        _token(policy_id)
        if type(policy_version) is not int or not 1 <= policy_version <= MAX_CONTEXT_GENERATION:
            raise LedgerError('INVALID_POLICY_VERSION')
        return self._generation_control(operation_id, run_id, generation, revision,
            reason, human, 'policy-migrate', {'policy_id': policy_id, 'policy_version': policy_version})

    def force_stop(self, operation_id, run_id, generation, revision, reason, *, human):
        return self._generation_control(operation_id, run_id, generation, revision,
                                        reason, human, 'force-stop', {})

    def terminal_stop(self, operation_id, run_id, generation, revision, reason, *, human, successor_run=None):
        if successor_run is not None:
            _token(successor_run)
            if successor_run == run_id:
                raise LedgerError('INVALID_SUCCESSOR_RUN')
        return self._generation_control(operation_id, run_id, generation, revision,
            reason, human, 'terminal-stop', {'successor_run': successor_run})

    def _generation_control(self, operation_id, run_id, generation, revision, reason, human, kind, extra):
        command = Command(operation_id, 'run.human-' + kind, _token(run_id), generation,
                          {'expected_revision': revision, 'reason': _token(reason), **extra})
        terminal = Command(self._finish_id(operation_id), 'run.human-' + kind + '-result',
                           run_id, generation, {'operation_id': operation_id})
        with self.supervisor._locked():
            document = self.controller._read()
            def prepare(state, _):
                # An explicit newer human stop can fence an interrupted
                # migration/stop. Its old exact retry cannot finish this one.
                row = self._run_revision(state, run_id, generation, revision,
                                         allow_pending=kind != 'policy-migrate')
                targets = self._control_targets(state, run_id, document)
                policy = None
                if kind == 'policy-migrate':
                    policy = next((p for p in self.room['policies'] if p['id'] == extra['policy_id']
                                   and p['version'] == extra['policy_version']), None)
                    if policy is None:
                        raise LedgerError('UNKNOWN_RUN_POLICY')
                    if row['policy'] == policy:
                        raise LedgerError('POLICY_ALREADY_CURRENT')
                    if (row['policy']['id'], row['policy']['version']) == (policy['id'], policy['version']):
                        raise LedgerError('POLICY_VERSION_CONFLICT')
                    # Same bounded evidence contract as new admission.
                    from .peer import _text
                    _text(self._request_text(row['issue_number'], policy, row['checkout']['path']))
                successor = extra.get('successor_run')
                if successor is not None and successor in state.get('runs', {}):
                    if state['runs'][successor]['project_id'] != row['project_id']:
                        raise LedgerError('INVALID_SUCCESSOR_RUN')
                superseded = (row.get('control_pending') or {}).get('operation_id')
                self._fence_generation(state, row, targets)
                cancelled = self._cancel_generation(state, run_id, generation, reason)
                row.update(control_revision=revision + 1, control_reason=reason,
                    control_pending={'operation_id': operation_id, 'kind': kind,
                        'source_generation': generation, 'target_generation': generation + 1,
                        'targets': targets, 'reason': reason,
                        'attention': 'NATIVE_RECONCILIATION_REQUIRED', **extra})
                request_events = ()
                if policy is not None:
                    row['policy'] = deepcopy(policy)
                    # Reserve/queue the new exact evidence contract in this
                    # fence transaction, before native scope effects. PAUSED
                    # and control_pending prevent delivery until explicit resume.
                    request_events = (self._migration_request(state, row, operation_id, human),)
                return self._control_finish(state, row, 'run.generation-fenced', {
                    'run_id': run_id, 'generation': generation + 1, 'status': 'PAUSED',
                    'control_revision': revision + 1, 'control_pending': kind,
                    'cancelled_traffic': cancelled, 'superseded_control': superseded}, request_events)
            self._apply(command, human, prepare)
            completed = self.ledger.operation_receipt(terminal.id, human,
                authorize=lambda: self._human(human, command))
            if completed is not None:
                return completed['result']
            row = self.ledger.snapshot()['state']['runs'][run_id]
            pending = row.get('control_pending')
            if pending is None or pending['operation_id'] != operation_id:
                raise LedgerError('RUN_CONTROL_CONFLICT')
        restore_attention = None
        if kind == 'policy-migrate':
            self._rebind_generation(pending, human, command)
        else:
            if kind == 'force-stop':
                try:
                    self._rebind_generation(pending, human, command)
                except Exception as error:
                    # A stop may not depend on a responsive Runtime/checkpoint.
                    # Verification below still gates stop success; failed native
                    # restoration metadata remains explicit, never resume proof.
                    restore_attention = 'NATIVE_CONTEXT_RESTORE_UNVERIFIED'
            self._stop_owned(pending, human, command)
        checkout = (self._release_checkout(run_id, row['participant_id'],
                        authorize=lambda: self._control_authorized(pending, human, command))
                    if kind == 'terminal-stop' else None)
        with self.supervisor._locked():
            self._verify_control_effect(pending, kind)
            def finish(state, _):
                current = state['runs'][run_id]
                if current.get('control_pending') != pending:
                    raise LedgerError('RUN_CONTROL_CONFLICT')
                current['control_pending'] = None
                if kind != 'policy-migrate':
                    current['native_stop'] = {'operation_id': operation_id, 'status': 'VERIFIED',
                                              'generation': current['generation'], 'restored': False,
                                              'restore_attention': restore_attention}
                if kind == 'terminal-stop':
                    current.update(status='CLOSED', outcome='stopped', stop_reason=reason,
                                   successor_run=extra['successor_run'], checkout_release=checkout)
                    state['fixture_context']['runs'][run_id].update(status='CLOSED', terminal_fact='CANCELLED')
                    if run_id in state.get('run_admissions', {}):
                        state['run_admissions'][run_id]['status'] = 'CLOSED'
                result = {'run_id': run_id, 'generation': current['generation'],
                    'status': current['status'], 'control_revision': current['control_revision'],
                    'reason': reason, 'outcome': current.get('outcome'),
                    'native_stop': current.get('native_stop')}
                return self._control_finish(state, current, 'run.' + kind + '-completed', result)
            return self._apply(terminal, human, finish)['result']

    def withdraw(self, operation_id, run_id, reason, *, human):
        """Fence pending intake, reconcile exact native/checkout owners, then close.

        An in-flight funded Forge read must settle first. Closing this intent
        does not reset its context or authorize another target; new admission
        must use the ordinary native-reset and clean-checkout rules.
        """
        command = Command(operation_id, 'run.human-withdraw', _token(run_id), None,
                          {'reason': _token(reason)})
        terminal = Command(self._finish_id(operation_id), 'run.human-withdraw-result',
                           run_id, None, {'operation_id': operation_id})
        with self.supervisor._locked():
            document = self.controller._read()
            def prepare(state, _):
                row = state.get('run_admissions', {}).get(run_id)
                if row is None:
                    raise LedgerError('UNKNOWN_ADMISSION')
                if row['status'] != 'PREPARING' or run_id in state.get('runs', {}):
                    raise LedgerError('INVALID_RUN_TRANSITION')
                targets = self._control_targets(state, run_id, document, admission=row)
                row.update(status='WITHDRAWING', attention='WITHDRAWAL_PENDING',
                    withdrawal={'operation_id': operation_id, 'targets': targets, 'reason': reason})
                FixturePeerHub._reserve_capacity(state)
                return Transition(state, (Event('run.admission-withdrawing', {'run_id': run_id}),),
                                  {'run_id': run_id, 'status': 'WITHDRAWING'})
            self._apply(command, human, prepare)
            completed = self.ledger.operation_receipt(terminal.id, human,
                authorize=lambda: self._human(human, command))
            if completed is not None:
                return completed['result']
            state = self.ledger.snapshot()['state']
            row = state['run_admissions'][run_id]
            if row['status'] != 'WITHDRAWING' or row['withdrawal']['operation_id'] != operation_id:
                raise LedgerError('RUN_CONTROL_CONFLICT')
            if any(p.get('admission_funding', {}).get('run_id') == run_id
                   for p in state.get('forge_pending', {}).values()):
                raise LedgerError('ADMISSION_EFFECT_PENDING')
            self._assignment_settled(run_id)
        self._stop_owned(row['withdrawal'], human, command)
        checkout = self._release_checkout(run_id, row['participant_id'],
            authorize=lambda: self._control_authorized(row['withdrawal'], human, command))
        with self.supervisor._locked():
            self._verify_control_effect(row['withdrawal'], 'withdraw')
            self._assignment_settled(run_id)
            def finish(current, _):
                item = current['run_admissions'][run_id]
                if item.get('withdrawal') != row['withdrawal'] or item['status'] != 'WITHDRAWING':
                    raise LedgerError('RUN_CONTROL_CONFLICT')
                item.update(status='CLOSED', attention=None, checkout_release=checkout,
                            stop_reason=reason, native_stop='VERIFIED')
                item.pop('reservation', None)
                grant = current.get('run_requests', {}).get(item.get('request_id'))
                if grant is not None and grant['status'] == 'UNUSED' and grant.get('reserved_run') == run_id:
                    grant['reserved_run'] = None
                current['fixture_context']['runs'][run_id].update(status='CLOSED', terminal_fact='CANCELLED')
                FixturePeerHub._reserve_capacity(current)
                result = {'run_id': run_id, 'status': 'CLOSED', 'reason': reason,
                          'authorization_consumed': False, 'checkout_release': checkout}
                return Transition(current, (Event('run.admission-withdrawn', result),), result)
            return self._apply(terminal, human, finish)['result']


    @staticmethod
    def _completion_digest(row):
        pin={key:row.get(key) for key in ('run_id','generation','status','outcome','completion',
            'review_stage','participant_id','actor_id','checkout','policy')}
        return hashlib.sha256(_json(pin).encode()).hexdigest()

    def _retire_completed(self, operation_id, run_id, generation, revision, *, human):
        """Annotate owned native retirement without rewriting completed Run truth."""
        command=Command(_token(operation_id),'run.human-retire-completed',_token(run_id),generation,
                        {'expected_revision':revision})
        terminal=Command(self._finish_id(operation_id),'run.human-retire-completed-result',run_id,generation,
                         {'operation_id':operation_id,'expected_revision':revision})
        with self.supervisor._locked():
            self._room()
            cached=self.ledger.exact_receipt(terminal,human,authorize=lambda *_:self._human(human,command))
            if cached is not None:return cached['result']
            def prepare(state,_):
                row=state.get('runs',{}).get(run_id)
                if (type(generation) is not int or type(revision) is not int
                        or not 1<=generation<=MAX_CONTEXT_GENERATION or not 0<=revision<MAX_CONTEXT_GENERATION
                        or not row or row['status']!='CLOSED' or row.get('outcome')!='completed'
                        or row['generation']!=generation or row.get('control_revision',0)!=revision
                        or row.get('control_pending') is not None or type(row.get('completion')) is not dict):
                    raise LedgerError('COMPLETED_RETIREMENT_SCOPE_CHANGED')
                targets=self._completed_retirement_targets(state,run_id)
                row.update(control_revision=revision+1,control_pending={
                    'operation_id':operation_id,'kind':'retire-completed','control_revision':revision+1,'source_generation':generation,
                    'target_generation':generation,'targets':targets,'completion_digest':self._completion_digest(row),
                    'attention':'NATIVE_RECONCILIATION_REQUIRED'})
                return self._control_finish(state,row,'run.completed-retirement-requested',{
                    'run_id':run_id,'generation':generation,'control_revision':revision+1,'status':'CLOSED'})
            self._apply(command,human,prepare)
            pending=self.ledger.snapshot()['state']['runs'][run_id].get('control_pending')
            if pending is None or pending['operation_id']!=operation_id:
                raise LedgerError('RUN_CONTROL_CONFLICT')
        self._stop_completed_owned(pending,human,command)
        checkout=self._release_completed_checkout(run_id,pending,human,command)
        with self.supervisor._locked():
            self._verify_completed_retirement(pending)
            def finish(state,_):
                row=state['runs'][run_id]
                if (row.get('control_pending')!=pending or row['control_revision']!=pending['control_revision']
                        or self._completion_digest(row)!=pending['completion_digest']):
                    raise LedgerError('COMPLETED_RETIREMENT_SCOPE_CHANGED')
                self._verify_completed_targets(state,pending)
                row.update(native_stop={'operation_id':operation_id,'status':'VERIFIED',
                    'generation':generation,'restored':False,'restore_attention':None},
                    checkout_release=deepcopy(checkout),control_pending=None)
                return self._control_finish(state,row,'run.completed-retirement-recorded',{
                    'run_id':run_id,'generation':generation,'status':'CLOSED','outcome':row['outcome'],
                    'control_revision':row['control_revision'],'native_stop':row['native_stop'],
                    'checkout_release':deepcopy(checkout)})
            return self._apply(terminal,human,finish)['result']
