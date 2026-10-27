"""Canonical bounded Run admission over existing account-free fixture seams.

Trusted human authority callback is NOT a Manager authentication implementation.
Already-exact assignment or opt-in audited self-assignment is eligible.
Canonical transitions enqueue lifecycle projections atomically; projection failure
never rewrites Run truth. No completion, automatic intake or recovery scheduler
exists here. Explicit repeats reconcile the same durable intent and owned checkout;
they never consume another human grant. Explicit authenticated Run Requests reuse this exact admission transaction.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import select
import time

from .config import load
from .forge_projections import enqueue_run_projection
from .context import FixtureRun, MAX_RUNS, MAX_CONTEXT_GENERATION
from .ledger import Command, Event, LedgerError, Origin, Transition, _json, _token
from .peer import FixturePeerHub, Readiness, _now, _text
from .pi_fixture import FixturePiRecipe
from .pi_runtime import NativeUnavailable
from .lifecycle import LifecycleError
from .run_requests import RunRequests
from .run_control import RunControl
from .run_coordination import RunCoordination


class RunAdmission(RunRequests, RunControl, RunCoordination):
    """Bounded fixture Run admission and control; no automatic intake or merge."""
    def __init__(self, controller, broker, allocator, source, *, seats, install,
                 runtime_root, authorize_human):
        self.controller, self.hub = controller, controller.hub
        self.ledger, self.supervisor = self.hub.ledger, controller.supervisor
        if (controller.forge_broker is not broker or broker.ledger is not self.ledger
                or allocator.supervisor.directory != self.supervisor.directory
                or not callable(authorize_human)):
            raise LedgerError('ADMISSION_BINDING_MISMATCH')
        config = load(source)
        self.room = next((r for r in config['rooms'] if r['id'] == self.ledger.room_id), None)
        if (self.room is None or self.room['project']['id'] != broker.binding.project_id
                or self.room['project']['repository'] != broker.binding.repository
                or self.room['project'] != allocator.room['project']):
            raise LedgerError('ADMISSION_BINDING_MISMATCH')
        self.actors = {a['id']: a for a in config['deployment']['actors']}
        self.seats = dict(seats)
        for participant, seat in self.seats.items():
            configured = next((s for s in self.room['seats'] if s['participant'] == participant), None)
            profile = next((p for p in self.room['profiles']
                            if configured is not None and p['id'] == configured['profile']), None)
            if (configured is None or configured['actor'] != seat.actor_id
                    or configured['runtime'] != 'pi' or seat.runtime != 'pi-fixture'
                    or profile is None or seat.profile_id != profile['id']
                    or 'implement' not in profile['capabilities'] or 'implement' not in seat.capabilities
                    or set(seat.capabilities) - {'peer-traffic'} - set(profile['capabilities'])
                    or seat.participant_id != participant or 'forge-read' not in seat.capabilities
                    or 'peer-traffic' not in seat.capabilities):
                raise LedgerError('ADMISSION_BINDING_MISMATCH')
        if broker.assignments is not None:
            # Deployment identity comes only from trusted installation config,
            # never a Participant envelope or the Room-local binding.
            if broker.assignments.audit.deployment_id != config['deployment']['id']:
                raise LedgerError('ADMISSION_BINDING_MISMATCH')
            for seat in self.seats.values():
                if ('forge-write' in seat.capabilities and
                        broker.assignments.actor_user_ids.get(seat.actor_id) != self.actors[seat.actor_id].get('github_user_id')):
                    raise LedgerError('ADMISSION_BINDING_MISMATCH')
        self.broker, self.allocator = broker, allocator
        self.install, self.runtime_root = install, Path(runtime_root)
        self.authorize_human = authorize_human

    @staticmethod
    def run_id(operation_id):
        return 'run-' + hashlib.sha256(_token(operation_id).encode()).hexdigest()

    def _human(self, origin, command):
        capability = ('human-open-run' if command.kind in {'run.human-open',
            'run.human-request', 'run.human-approve-proposal', 'run.admission-attempt',
            'run.admission-attempt-result'} else 'human-control-run')
        return (type(origin) is Origin and capability in origin.capabilities
                and self.authorize_human(origin, command) is True)

    def _apply(self, command, origin, decide, *, authorize=None):
        return self.ledger.apply(command, origin,
            authorize=authorize or (lambda o, c: self._human(o, c)), decide=decide)

    def pause(self, operation_id, run_id, generation, expected_revision, reason, *, human):
        """Hold Hub traffic, not native inference or arbitrary Project writes."""
        return self._control_run(operation_id, run_id, generation, expected_revision,
                                 reason, human, 'ACTIVE', 'PAUSED')

    def resume(self, operation_id, run_id, generation, expected_revision, reason, *, human):
        """Resume the same binding; never reset, relaunch, migrate or re-admit."""
        return self._control_run(operation_id, run_id, generation, expected_revision,
                                 reason, human, 'PAUSED', 'ACTIVE')

    def _control_run(self, operation_id, run_id, generation, expected_revision,
                     reason, human, preceding, target):
        if (type(generation) is not int or not 1 <= generation <= MAX_CONTEXT_GENERATION
                or type(expected_revision) is not int
                or not 0 <= expected_revision <= MAX_CONTEXT_GENERATION):
            raise LedgerError('INVALID_RUN_CONTROL')
        command = Command(operation_id, 'run.human-' + ('pause' if target == 'PAUSED' else 'resume'),
            _token(run_id), generation, {'expected_revision': expected_revision, 'reason': _token(reason)})
        def decide(state, _):
            row = state.get('runs', {}).get(run_id)
            if row is None:
                raise LedgerError('UNKNOWN_RUN')
            if row['generation'] != generation:
                raise LedgerError('STALE_RUN_GENERATION')
            revision = row.get('control_revision', 0)
            if revision != expected_revision:
                raise LedgerError('STALE_RUN_CONTROL')
            if row.get('control_pending') is not None:
                raise LedgerError('RUN_CONTROL_PENDING')
            if row['status'] != preceding:
                raise LedgerError('INVALID_RUN_TRANSITION')
            restoring_stop = target == 'ACTIVE' and row.get('native_stop') and not row['native_stop'].get('restored', False)
            if restoring_stop:
                # Force-stop is not pause. A stopped/old-generation native
                # owner cannot be made live by flipping canonical status.
                handle = self.controller.handles.get(row['participant_id'])
                if (handle is None or not self.controller._alive(handle) or handle.connection is None
                        or handle.connection.receiver.scope != self.hub.contexts.scope(row['participant_id'])):
                    raise LedgerError('NATIVE_RESTORE_REQUIRED')
                self._authority(handle)
                if Path('/proc', str(handle.process.pid), 'cwd').resolve() != Path(row['checkout']['path']):
                    raise LedgerError('NATIVE_CHECKOUT_MISMATCH')
            if revision == MAX_CONTEXT_GENERATION:
                raise LedgerError('RUN_CONTROL_REVISION_EXHAUSTED')
            row.update(status=target, control_revision=revision + 1,
                       control_reason=reason)
            replacement = None
            if restoring_stop:
                replacement = self._migration_request(state, row, operation_id, human)
                row['native_stop'].update(restored=True, restore_attention=None)
            # Admission remains consumed/ACTIVE; canonical Run alone controls
            # traffic. No native ACK, request, context or checkout is rewritten.
            projection = (enqueue_run_projection(state, self.ledger.room_id, run_id)
                if 'issue_id' in row else None)  # Unbound source-only fixtures have no Forge target.
            FixturePeerHub._reserve_capacity(state)
            result = {'run_id': run_id, 'generation': generation, 'status': target,
                      'control_revision': revision + 1, 'reason': reason}
            events = (Event('run.paused' if target == 'PAUSED' else 'run.resumed', result),)
            return Transition(state, events + ((replacement,) if replacement else ())
                              + ((projection,) if projection else ()), result)
        # Ledger authorizes every retry inside its transaction, then looks up
        # the exact immutable receipt before evaluating current revision/state.
        with self.supervisor._locked():
            return self._apply(command, human, decide)['result']

    def _pending(self, run):
        return self.ledger.snapshot()['state'].get('run_admissions', {}).get(run)

    def _seat_binding(self, participant):
        configured = next(s for s in self.room['seats'] if s['participant'] == participant)
        profile = next(p for p in self.room['profiles'] if p['id'] == configured['profile'])
        return {'seat': self.seats[participant].document(),
                'configured_seat': {k: configured[k] for k in
                    ('id', 'participant', 'actor', 'profile', 'runtime', 'arguments', 'provider')},
                'configured_capabilities': list(profile['capabilities'])}

    def _prepare(self, operation_id, number, participant, human, *, request_id=None, authorize=None):
        if (type(number) is not int or not 1 <= number <= 9_999_999_999
                or type(participant) is not str or participant not in self.seats):
            raise LedgerError('INVALID_RUN_REQUEST')
        run = self.run_id(operation_id)
        payload = {'issue_number': number, 'participant_id': participant}
        if request_id is not None:
            payload['request_id'] = _token(request_id)
        command = Command(operation_id, 'run.human-open' if request_id is None else 'run.participant-open',
                          self.room['project']['id'], None, payload)
        seat = self.seats[participant]
        actor_id = self.actors[seat.actor_id].get('github_user_id')
        policy = next(p for p in self.room['policies'] if p['id'] == self.room['default_policy'])
        with self.supervisor._locked():
            self.controller._room()
            def prepare(state, _):
                if actor_id is None:
                    raise LedgerError('GITHUB_ACTOR_ID_UNKNOWN')
                # Exact authorized retries precede new-policy validation. New
                # requests deliver their complete bounded evidence contract.
                _text(self._request_text(number, policy, 'x' * 4096))
                admissions, runs = state.setdefault('run_admissions', {}), state.setdefault('runs', {})
                state.setdefault('forge_pending', {})
                if len(admissions) >= 8 or len(runs) >= 32:
                    raise LedgerError('RUN_CAPACITY')
                if run in state['fixture_context']['runs']:
                    raise LedgerError('RUN_CONTEXT_ALREADY_EXISTS')
                if len(state['fixture_context']['runs']) >= MAX_RUNS:
                    raise LedgerError('RUN_CONTEXT_CAPACITY')
                for row in list(admissions.values()) + list(runs.values()):
                    if row['status'] != 'CLOSED' and (row['issue_number'] == number
                            or row['participant_id'] == participant):
                        raise LedgerError('RUN_CAPACITY_OR_DUPLICATE')
                # A new target never relabels old native context. Only a
                # verified terminal predecessor can enter native reset below.
                context = state['fixture_context']['participants'].get(participant)
                peer = state['peer_traffic']
                if context is None or context['status'] != 'READY':
                    raise LedgerError('UNUSED_NATIVE_CONTEXT_REQUIRED')
                assigned = context['bound_run'] or context['reserved_run']
                old_run = state.get('runs', {}).get(assigned['run_id'])
                old_admission = admissions.get(assigned['run_id'])
                closed = (old_run if old_run and old_run['status'] == 'CLOSED' else
                          old_admission if old_admission and old_admission['status'] == 'CLOSED' else None)
                preceding = None
                if closed is not None:
                    stopped = closed.get('native_stop')
                    if stopped != 'VERIFIED' and (not isinstance(stopped, dict) or stopped.get('status') != 'VERIFIED'):
                        raise LedgerError('NATIVE_STOP_UNVERIFIED')
                    if context['context_generation'] == MAX_CONTEXT_GENERATION:
                        raise LedgerError('CONTEXT_GENERATION_EXHAUSTED')
                    if context['reset'] and context['reset']['status'] != 'SUCCEEDED':
                        raise LedgerError('CONTEXT_UNAVAILABLE')
                    preceding = deepcopy(assigned)
                elif (context['context_generation'] != 1 or context['bound_run'] is not None
                        or context['reset'] is not None or participant in peer['connections']
                        or participant in self.controller._read()['seats']
                        or any(participant == t['sender'] or participant in t['recipients']
                               for t in peer['traffic'].values())):
                    raise LedgerError('UNUSED_NATIVE_CONTEXT_REQUIRED')
                if peer['definition']['participants'][participant]['actor_id'] != seat.actor_id:
                    raise LedgerError('ADMISSION_BINDING_MISMATCH')
                if request_id is not None:
                    grant = state.get('run_requests', {}).get(request_id)
                    if (grant is None or grant['status'] != 'UNUSED'
                            or grant['issue_number'] != number or grant['participant_id'] != participant
                            or grant['reserved_run'] not in (None, run)):
                        raise LedgerError('FORBIDDEN_RUN_REQUEST')
                    grant['reserved_run'] = run
                admissions[run] = {'status': 'PREPARING', 'issue_number': number,
                    'request_id': request_id, 'preceding_run': preceding,
                    'context_generation': context['context_generation'] + (1 if preceding else 0),
                    'participant_id': participant, 'actor_id': seat.actor_id,
                    'github_user_id': actor_id, 'policy': deepcopy(policy),
                    'seat_binding': self._seat_binding(participant),
                    'admission_origin': human.canonical(), 'admission_operation': operation_id,
                    'human_operation': operation_id if request_id is None else grant['human_operation'],
                    'human_origin': human.canonical() if request_id is None else deepcopy(grant['human_origin']),
                    'authorization_consumed': False, 'attention': None,
                    # Complete policy is bounded by the request above. Reserve
                    # its duplicate plus slot (16KiB), request text and maximal
                    # future peer receipt/reason, not just the QUEUED record.
                    'reservation': 'x' * (len(_json(policy).encode()) + 131072)}
                # Context namespace is delivery plumbing only, never Run truth.
                state['fixture_context']['runs'][run] = {
                    'generation': 1, 'status': 'OPEN', 'terminal_fact': None}
                if preceding is None:
                    context['reserved_run'] = {'run_id': run, 'generation': 1}
                FixturePeerHub._reserve_capacity(state)
                return Transition(state, (Event('run.admission-reserved', {
                    'run_id': run, 'issue_number': number, 'participant_id': participant}),),
                    {'run_id': run, 'authorization_consumed': False})
            self._apply(command, human, prepare, authorize=authorize)
        return run, command

    def _authority(self, handle):
        # Trusted supervisor examination of its exact owned child, not a client
        # identity claim or a replacement for SCM_CREDENTIALS on native traffic.
        return self.controller._authority(handle, (handle.process.pid, os.getuid(), os.getgid()))

    def _slot(self, run, participant, *, authorize=None):
        # Inspect authoritative owned manifest/Git before repeat allocation.
        existing = [s for s in self.allocator.status() if s['run'] == run]
        if len(existing) > 1 or (existing and existing[0]['participant'] != participant):
            raise LedgerError('CHECKOUT_BINDING_CONFLICT')
        slot = self.allocator.allocate(run, participant, authorize=authorize)
        if (slot['phase'] != 'ready' or slot['reason'] != 'ACTIVE'
                or slot['observed_dirty'] is not False or slot['observed_head'] != slot['base']):
            raise LedgerError('CHECKOUT_NOT_READY')
        if len(_json(slot).encode()) > 16384:
            raise LedgerError('CHECKOUT_OBSERVATION_LIMIT')
        return slot

    def _fresh_read(self, run, number, handle, attempt_id):
        # Stable ID within one explicit attempt: interrupted contact is reconciled,
        # never repeated. A NEW human refresh attempt gets a new observation.
        envelope = {'id': 'admit-read-' + hashlib.sha256(attempt_id.encode()).hexdigest(), 'kind': 'forge-read',
                    'argv': ['issue', 'view', str(number)]}
        with self.supervisor._locked():
            intent = self.broker.prepare(envelope, origin=handle.badge.origin(),
                authorize=lambda: self._authority(handle), admission=True, admission_reservation=run)
        outcome = self.broker.perform(intent)
        try:
            with self.supervisor._locked():
                receipt = self.broker.complete(intent, outcome, authorize=lambda: self._authority(handle))
        except LedgerError as error:
            if error.code in {'AUTHORITY_REVOKED', 'PROCESS_EXITED', 'MISSING_ACTOR_CREDENTIAL',
                    'ROOM_NOT_RUNNING', 'ROOM_REPLACED', 'CONTROLLER_REPLACED'}:
                with self.supervisor._locked():
                    self.broker.abandon(intent, error.code)
            raise
        return receipt, intent['started']

    def _assign_or_reconcile(self, run, number, handle, attempt_id, human, command, authorize):
        service = self.broker.assignments
        def authorized():
            return (self._authority(handle) and authorize(human, command)
                    and self._pending(run)['status'] == 'PREPARING')
        operation = 'admit-assignment-' + run
        with self.supervisor._locked():
            self._authority(handle)
            record = service.audit.get(service._key(operation))
            if record is None:
                intent = self.broker.prepare({'id': operation, 'kind': 'forge-write',
                    'argv': ['issue', 'edit', str(number), '--add-assignee', '@me']},
                    origin=handle.badge.origin(), authorize=authorized)
            else:
                service._authorize(handle.badge.origin(), authorized)
                if (record.get('result') or {}).get('status') == 'NOT_EXECUTED':
                    # Original process was proven fenced before any POST. A new
                    # explicit native write may repair assignment; never silently
                    # turn human refresh into another mutation attempt.
                    return
                intent = None
        if intent is not None:
            outcome = self.broker.perform(intent)
            with self.supervisor._locked():
                receipt = self.broker.complete(intent, outcome, authorize=authorized)
            status = receipt['assignment']['status']
            if status not in {'ASSIGNED', 'ALREADY_ASSIGNED'}:
                raise LedgerError('ASSIGNMENT_' + ('CONFLICT' if status == 'ASSIGNMENT_CONFLICT' else 'UNKNOWN'))
        else:
            receipt = service.reconcile(operation, 'admission-' + hashlib.sha256(attempt_id.encode()).hexdigest(),
                origin=handle.badge.origin(), authorize=authorized)
            status = receipt['assignment']['status']
            if status != 'MATCHED':
                raise LedgerError('ASSIGNMENT_' + ('CONFLICT' if status == 'CONFLICT' else 'UNKNOWN'))

    def _request_text(self, number, policy, path):
        return ('Implement exactly https://github.com/' + self.broker.binding.repository
            + '/issues/' + str(number) + '. Checkout: ' + path
            + '. Snapshotted Run Policy and evidence contract: ' + _json(policy)
            + '. No merge authority; completion of this request does not complete the Run.')

    def _attention(self, run, human, reason, terminal_command, authorize):
        """Durable refusal, not a queued retry or a canonical PAUSED Run."""
        _token(reason)
        def note(state, _):
            row = state['run_admissions'][run]
            if row['status'] != 'PREPARING':
                raise LedgerError('ADMISSION_CONFLICT')
            row['attention'] = reason
            FixturePeerHub._reserve_capacity(state)
            return Transition(state, (Event('run.admission-held', {
                'run_id': run, 'reason': reason, 'authorization_consumed': False}),),
                {'status': 'HELD', 'reason': reason})
        return self._apply(terminal_command, human, note, authorize=authorize)['result']

    @staticmethod
    def _eligible(observation, pending):
        if observation.get('status') != 'OK' or observation.get('completeness') != 'complete':
            raise LedgerError('FORGE_FACTS_UNKNOWN')
        issue = observation['issue']
        if issue['number'] != pending['issue_number'] or issue['state'] != 'open':
            raise LedgerError('ISSUE_NOT_ELIGIBLE')
        if any(d['state'] != 'closed' for d in observation['dependencies']):
            raise LedgerError('DEPENDENCY_BLOCKED')
        if not issue['assignees']:
            raise LedgerError('ASSIGNMENT_REQUIRED_NO_WRITE_SUPPORT')
        if [a['id'] for a in issue['assignees']] != [pending['github_user_id']]:
            raise LedgerError('ASSIGNMENT_CONFLICT')
        classification = observation.get('delivery_class', {})
        if classification.get('status') != 'known':
            raise LedgerError('DELIVERY_CLASS_UNKNOWN')
        return classification['value']

    def open(self, operation_id, issue_number, participant_id, *, human, attempt_id=None):
        """Explicit human invocation only; exceptions never queue a retry.

        A pending reservation is NOT a Run or consumed authorization. If Git or
        native startup happened, errors preserve their exact ownership for human
        inspection/explicit retry, never delete work or silently activate it.
        """
        return self._open(operation_id, issue_number, participant_id, human, attempt_id=attempt_id)

    def _open(self, operation_id, issue_number, participant_id, human, *, attempt_id=None,
              request_id=None, authorize=None):
        authorize = authorize or self._human
        run, command = self._prepare(operation_id, issue_number, participant_id, human,
                                     request_id=request_id, authorize=authorize)
        pending = self._pending(run)
        attempt_id = _token(('initial-' + run) if attempt_id is None else attempt_id)
        attempt = Command(attempt_id, 'run.admission-attempt', run, 1,
                          {'human_operation': operation_id})
        terminal = Command('attempt-result-' + hashlib.sha256(attempt_id.encode()).hexdigest(),
                           'run.admission-attempt-result', run, 1, {'human_operation': operation_id})
        with self.supervisor._locked():
            self._apply(attempt, human, lambda state, _: Transition(state,
                (Event('run.admission-attempt-started', {'run_id': run, 'attempt_id': attempt_id}),),
                {'status': 'STARTED'}), authorize=authorize)
        completed = self.ledger.operation_receipt(terminal.id, human,
            authorize=lambda: authorize(human, attempt))
        if completed is not None:
            result = completed['result']
            if result.get('status') == 'HELD':
                raise LedgerError(result['reason'])
            return result
        if pending['status'] == 'ACTIVE':
            # A new attempt cannot reopen, retarget or queue a second request.
            raise LedgerError('RUN_ALREADY_ACTIVE')
        try:
            return self._advance(run, command, pending, attempt_id, terminal,
                                 issue_number, participant_id, human, authorize)
        except (LedgerError, LifecycleError, NativeUnavailable) as error:
            code = error.code if isinstance(error, (LedgerError, LifecycleError)) else 'NATIVE_ADMISSION_UNAVAILABLE'
            # Never downgrade a possibly committed activation. Reconcile the
            # immutable terminal first; storage uncertainty remains uncertainty.
            completed = self.ledger.operation_receipt(terminal.id, human,
                authorize=lambda: authorize(human, attempt))
            if completed is not None:
                result = completed['result']
                if result.get('status') == 'HELD':
                    raise LedgerError(result['reason']) from None
                return result
            if completed is None and code not in {'STORAGE_ERROR', 'AUDIT_UNAVAILABLE', 'CLOSED'}:
                with self.supervisor._locked():
                    result = self._attention(run, human, code, terminal, authorize)
                if result.get('status') == 'HELD':
                    raise LedgerError(result['reason']) from None
                return result
            raise

    def _advance(self, run, command, pending, attempt_id, terminal,
                 issue_number, participant_id, human, authorize):
        current_actor = self.seats[participant_id].actor_id
        if (current_actor != pending['actor_id']
                or self.actors[current_actor].get('github_user_id') != pending['github_user_id']
                or self._seat_binding(participant_id) != pending['seat_binding']):
            raise LedgerError('ACTOR_BINDING_CHANGED')
        with self.supervisor._locked():
            self.controller._room()
            if not authorize(human, command):
                raise LedgerError('FORBIDDEN')
        def stage_authorized():
            if not authorize(human, command) or self._pending(run)['status'] != 'PREPARING':
                raise LedgerError('ADMISSION_REVOKED')
            return True
        slot = self._slot(run, participant_id, authorize=stage_authorized)
        handle = self.controller.handles.get(participant_id)
        target_scope = {'room_id': self.ledger.room_id, 'participant_id': participant_id,
                        'run_id': run, 'generation': 1, 'context_generation': pending.get('context_generation', 1)}
        needs_reset = pending.get('preceding_run') is not None
        if needs_reset and (handle is None or not self.controller._alive(handle)
                or handle.connection is None or handle.connection.receiver.scope != target_scope):
            recipe = FixturePiRecipe(self.install, self.runtime_root / run,
                                     scope=target_scope, checkout=slot['path'])
            handle = self.controller.reset_pi('admission-reset-' + run, self.seats[participant_id], recipe,
                expected_context_generation=pending.get('context_generation', 1) - 1,
                target_run=FixtureRun(run), authorize=stage_authorized)
        elif handle is None or not self.controller._alive(handle):
            # Reconstructed controllers do not adopt/kill a stored PID. Any
            # still-live retired writer must be reconciled by its owner first.
            with self.supervisor._locked():
                for pid in self.controller._read()['retired_pids']:
                    try:
                        descriptor = os.pidfd_open(pid, 0)
                    except ProcessLookupError:
                        continue
                    try:
                        if not select.select([descriptor], [], [], 0)[0]:
                            raise LedgerError('RETIRED_PROCESSES_UNVERIFIED')
                    finally:
                        os.close(descriptor)
            recipe = FixturePiRecipe(self.install, self.runtime_root / run,
                scope=self.hub.contexts.scope(participant_id), checkout=slot['path'])
            handle = self.controller.launch_pi(self.seats[participant_id], recipe, authorize=stage_authorized)
        native = handle.connection.receiver
        if native.scope != self.hub.contexts.scope(participant_id):
            raise LedgerError('NATIVE_SCOPE_MISMATCH')
        if Path('/proc', str(handle.process.pid), 'cwd').resolve() != Path(slot['path']):
            raise LedgerError('NATIVE_CHECKOUT_MISMATCH')
        native_proof = native.prove_fresh_context()
        with self.supervisor._locked():
            stage_authorized()
            self._authority(handle)
            if native.scope != self.hub.contexts.scope(participant_id):
                raise LedgerError('NATIVE_SCOPE_MISMATCH')
            recipe = getattr(handle, 'pi_recipe', None)
            if recipe is not None:
                reset = self.hub.contexts._row(participant_id).get('reset')
                self.controller._save_pi_checkpoint(participant_id, recipe,
                    reset['id'] if reset is not None and reset['status'] == 'SUCCEEDED' else None, native_proof)
        self.hub.observe(handle.connection, native.observe())
        receipt, fresh = self._fresh_read(run, issue_number, handle, attempt_id)
        observed = time.monotonic()
        if not fresh:
            raise LedgerError('FORGE_FACTS_EXPIRED')
        assignment_service = self.broker.assignments
        assignment_operation = 'admit-assignment-' + run
        prior_assignment = (assignment_service.audit.get(assignment_service._key(assignment_operation))
                            if assignment_service is not None else None)
        if prior_assignment is not None:
            self._assign_or_reconcile(run, issue_number, handle, attempt_id, human, command, authorize)
        if (receipt['observation'].get('status') == 'OK'
                and receipt['observation'].get('completeness') == 'complete'
                and not receipt['observation']['issue']['assignees']
                and self.broker.assignments is not None and prior_assignment is None):
            # Validate all other eligibility facts before even requesting a write.
            eligible = deepcopy(receipt['observation'])
            eligible['issue']['assignees'] = [{'id': pending['github_user_id'], 'login': 'validation-only'}]
            self._eligible(eligible, pending)
            self._assign_or_reconcile(run, issue_number, handle, attempt_id, human, command, authorize)
            # Neither response success nor reconciliation replaces fresh native
            # dependencies, classification and assignment at activation.
            receipt, fresh = self._fresh_read(run, issue_number, handle, 'post-assignment-' + attempt_id)
            observed = time.monotonic()
            if not fresh:
                raise LedgerError('FORGE_FACTS_EXPIRED')
        if (prior_assignment is not None and not (receipt['observation'].get('issue') or {}).get('assignees')
                and (prior_assignment.get('result') or {}).get('status') == 'NOT_EXECUTED'):
            raise LedgerError('ASSIGNMENT_EXPLICIT_RETRY_REQUIRED')
        delivery_class = self._eligible(receipt['observation'], pending)
        # Read-side snapshot is bounded/fresh, not an atomic GitHub lock. Git is
        # observed again after provider I/O, before the one activation transaction.
        slot = self._slot(run, participant_id, authorize=stage_authorized)
        assignment_audit = (assignment_service._key(assignment_operation)
            if assignment_service is not None and assignment_service.audit.get(
                assignment_service._key(assignment_operation)) is not None else None)
        with self.supervisor._locked():
            self._authority(handle)
            if native.observe() is not Readiness.SAFE:
                raise LedgerError('NATIVE_NOT_SAFE')
            def activate(state, _):
                if time.monotonic() - observed > 5:
                    raise LedgerError('FORGE_FACTS_EXPIRED')
                current = state['run_admissions'][run]
                if (current['status'] != 'PREPARING'
                        or current.get('admission_origin', current['human_origin']) != human.canonical()):
                    raise LedgerError('ADMISSION_CONFLICT')
                if not self.hub._current(handle.connection, safe=True):
                    raise LedgerError('NATIVE_NOT_SAFE')
                scope = self.hub.contexts.scope(participant_id)
                if scope != native.scope or scope['run_id'] != run or scope['context_generation'] != pending.get('context_generation', 1):
                    raise LedgerError('CONTEXT_MISMATCH')
                # Refresh configured policy at activation, not at an earlier held attempt.
                policy = next(p for p in self.room['policies'] if p['id'] == self.room['default_policy'])
                request_id = 'implementation-' + run
                request_text = self._request_text(issue_number, policy, slot['path'])
                _text(request_text)
                record = {'id': request_id, 'kind': 'peer.work-request', 'sender': 'run-hub',
                    'actor_id': human.actor_id, 'run_id': run, 'generation': 1,
                    'recipients': [participant_id], 'text': request_text, 'parent_id': None,
                    'correlation_id': request_id, 'submitted_at': _now(),
                    'submitted_seq': self.ledger.snapshot()['room_seq'] + 1,
                    'deliveries': {}, 'status': 'QUEUED', 'response_started_at': None,
                    'reason': None, 'attention': None}
                row = {'run_id': run, 'generation': 1, 'status': 'ACTIVE', 'outcome': None,
                    'issue_number': issue_number, 'issue_id': receipt['observation']['issue']['id'],
                    'repository': self.broker.binding.repository, 'project_id': self.broker.binding.project_id,
                    'participant_id': participant_id, 'actor_id': current['actor_id'],
                    'github_user_id': current['github_user_id'], 'delivery_class': delivery_class,
                    'policy': deepcopy(policy), 'checkout': deepcopy(slot),
                    'context_generation': pending.get('context_generation', 1), 'implementation_request': request_id,
                    'forge_observation': receipt['operation_id'], 'human_operation': current['human_operation'],
                    'admission_operation': command.id, 'admission_origin': human.canonical(),
                    'authorization_consumed': True, 'control_revision': 0, 'control_reason': None,
                    'projection': 'pending',
                    'assignment_audit': assignment_audit}
                grant_id = current.get('request_id')
                if grant_id is not None:
                    grant = state['run_requests'][grant_id]
                    if grant['status'] != 'UNUSED' or grant['reserved_run'] != run:
                        raise LedgerError('FORBIDDEN_RUN_REQUEST')
                    grant.update(status='CONSUMED', consumed_run=run)
                    row['run_request'] = grant_id
                current['policy'] = deepcopy(policy)
                current.pop('reservation')
                current.update(status='ACTIVE', authorization_consumed=True, attention=None)
                state['runs'][run] = row
                state['peer_traffic']['traffic'][request_id] = record
                projection = enqueue_run_projection(state, self.ledger.room_id, run)
                FixturePeerHub._reserve_capacity(state)
                return Transition(state, (Event('run.activated', row),
                    Event('peer.submitted', {'traffic_id': request_id, 'recipients': [participant_id]}), projection), row)
            result = self._apply(terminal, human, activate, authorize=authorize)
        if result['result'].get('status') == 'HELD':
            raise LedgerError(result['result']['reason'])
        return result['result']
