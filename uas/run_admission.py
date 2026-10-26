"""Restricted canonical first-Run admission over existing account-free seams.

Trusted human authority callback is NOT a Manager authentication implementation.
Only already-exact GitHub assignment is eligible. No Forge mutation, projection,
completion, automatic intake or recovery scheduler exists here. Explicit repeats
reconcile the same durable intent and owned checkout; they never consume another
human grant. This does not satisfy #69 or complete #72.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import select
import time

from .config import load
from .context import MAX_RUNS
from .ledger import Command, Event, LedgerError, Origin, Transition, _json, _token
from .peer import FixturePeerHub, Readiness, _now, _text
from .pi_fixture import FixturePiRecipe


class RunAdmission:
    """One trusted, source-only human command, restricted to unused Pi contexts."""
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
        self.broker, self.allocator = broker, allocator
        self.install, self.runtime_root = install, Path(runtime_root)
        self.authorize_human = authorize_human

    @staticmethod
    def run_id(operation_id):
        return 'run-' + hashlib.sha256(_token(operation_id).encode()).hexdigest()

    def _human(self, origin, command):
        return (type(origin) is Origin and 'human-open-run' in origin.capabilities
                and self.authorize_human(origin, command) is True)

    def _apply(self, command, origin, decide):
        return self.ledger.apply(command, origin,
            authorize=lambda o, c: self._human(o, c), decide=decide)

    def _pending(self, run):
        return self.ledger.snapshot()['state'].get('run_admissions', {}).get(run)

    def _seat_binding(self, participant):
        configured = next(s for s in self.room['seats'] if s['participant'] == participant)
        profile = next(p for p in self.room['profiles'] if p['id'] == configured['profile'])
        return {'seat': self.seats[participant].document(),
                'configured_seat': {k: configured[k] for k in
                    ('id', 'participant', 'actor', 'profile', 'runtime', 'arguments', 'provider')},
                'configured_capabilities': list(profile['capabilities'])}

    def _prepare(self, operation_id, number, participant, human):
        if type(number) is not int or not 1 <= number <= 9_999_999_999 or participant not in self.seats:
            raise LedgerError('INVALID_RUN_REQUEST')
        run = self.run_id(operation_id)
        command = Command(operation_id, 'run.human-open', self.room['project']['id'], None,
                          {'issue_number': number, 'participant_id': participant})
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
                # First native context only. No relabel of a surviving process,
                # prior delivery, reserved unknown delivery, or previous Run.
                context = state['fixture_context']['participants'].get(participant)
                peer = state['peer_traffic']
                if (context is None or context['status'] != 'READY' or context['context_generation'] != 1
                        or context['bound_run'] is not None or context['reset'] is not None
                        or participant in peer['connections']
                        or participant in self.controller._read()['seats']
                        or any(participant == t['sender'] or participant in t['recipients']
                               for t in peer['traffic'].values())):
                    raise LedgerError('UNUSED_NATIVE_CONTEXT_REQUIRED')
                if peer['definition']['participants'][participant]['actor_id'] != seat.actor_id:
                    raise LedgerError('ADMISSION_BINDING_MISMATCH')
                admissions[run] = {'status': 'PREPARING', 'issue_number': number,
                    'participant_id': participant, 'actor_id': seat.actor_id,
                    'github_user_id': actor_id, 'policy': deepcopy(policy),
                    'seat_binding': self._seat_binding(participant),
                    'human_operation': operation_id, 'human_origin': human.canonical(),
                    'authorization_consumed': False, 'attention': None,
                    # Complete policy is bounded by the request above. Reserve
                    # its duplicate plus slot (16KiB), request text and maximal
                    # future peer receipt/reason, not just the QUEUED record.
                    'reservation': 'x' * (len(_json(policy).encode()) + 131072)}
                # Context namespace is delivery plumbing only, never Run truth.
                state['fixture_context']['runs'][run] = {
                    'generation': 1, 'status': 'OPEN', 'terminal_fact': None}
                context['reserved_run'] = {'run_id': run, 'generation': 1}
                FixturePeerHub._reserve_capacity(state)
                return Transition(state, (Event('run.admission-reserved', {
                    'run_id': run, 'issue_number': number, 'participant_id': participant}),),
                    {'run_id': run, 'authorization_consumed': False})
            self._apply(command, human, prepare)
        return run, command

    def _authority(self, handle):
        # Trusted supervisor examination of its exact owned child, not a client
        # identity claim or a replacement for SCM_CREDENTIALS on native traffic.
        return self.controller._authority(handle, (handle.process.pid, os.getuid(), os.getgid()))

    def _slot(self, run, participant):
        # Inspect authoritative owned manifest/Git before repeat allocation.
        existing = [s for s in self.allocator.status() if s['run'] == run]
        if len(existing) > 1 or (existing and existing[0]['participant'] != participant):
            raise LedgerError('CHECKOUT_BINDING_CONFLICT')
        slot = self.allocator.allocate(run, participant)
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

    def _request_text(self, number, policy, path):
        return ('Implement exactly https://github.com/' + self.broker.binding.repository
            + '/issues/' + str(number) + '. Checkout: ' + path
            + '. Snapshotted Run Policy and evidence contract: ' + _json(policy)
            + '. No merge authority; completion of this request does not complete the Run.')

    def _attention(self, run, human, reason, terminal_command):
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
        return self._apply(terminal_command, human, note)['result']

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
        run, command = self._prepare(operation_id, issue_number, participant_id, human)
        pending = self._pending(run)
        attempt_id = _token(('initial-' + run) if attempt_id is None else attempt_id)
        attempt = Command(attempt_id, 'run.admission-attempt', run, 1,
                          {'human_operation': operation_id})
        terminal = Command('attempt-result-' + hashlib.sha256(attempt_id.encode()).hexdigest(),
                           'run.admission-attempt-result', run, 1, {'human_operation': operation_id})
        self._apply(attempt, human, lambda state, _: Transition(state,
            (Event('run.admission-attempt-started', {'run_id': run, 'attempt_id': attempt_id}),),
            {'status': 'STARTED'}))
        completed = self.ledger.operation_receipt(terminal.id, human,
            authorize=lambda: self._human(human, attempt))
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
                                 issue_number, participant_id, human)
        except LedgerError as error:
            # Never downgrade a possibly committed activation. Reconcile the
            # immutable terminal first; storage uncertainty remains uncertainty.
            completed = self.ledger.operation_receipt(terminal.id, human,
                authorize=lambda: self._human(human, attempt))
            if completed is not None:
                result = completed['result']
                if result.get('status') == 'HELD':
                    raise LedgerError(result['reason']) from None
                return result
            if completed is None and error.code not in {'STORAGE_ERROR', 'AUDIT_UNAVAILABLE', 'CLOSED'}:
                result = self._attention(run, human, error.code, terminal)
                if result.get('status') == 'HELD':
                    raise LedgerError(result['reason']) from None
                return result
            raise

    def _advance(self, run, command, pending, attempt_id, terminal,
                 issue_number, participant_id, human):
        current_actor = self.seats[participant_id].actor_id
        if (current_actor != pending['actor_id']
                or self.actors[current_actor].get('github_user_id') != pending['github_user_id']
                or self._seat_binding(participant_id) != pending['seat_binding']):
            raise LedgerError('ACTOR_BINDING_CHANGED')
        with self.supervisor._locked():
            self.controller._room()
            if not self._human(human, command):
                raise LedgerError('FORBIDDEN')
        slot = self._slot(run, participant_id)
        handle = self.controller.handles.get(participant_id)
        if handle is None or not self.controller._alive(handle):
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
            handle = self.controller.launch_pi(self.seats[participant_id], recipe)
        native = handle.connection.receiver
        if native.scope != self.hub.contexts.scope(participant_id):
            raise LedgerError('NATIVE_SCOPE_MISMATCH')
        if Path('/proc', str(handle.process.pid), 'cwd').resolve() != Path(slot['path']):
            raise LedgerError('NATIVE_CHECKOUT_MISMATCH')
        native.prove_fresh_context()
        self.hub.observe(handle.connection, native.observe())
        receipt, fresh = self._fresh_read(run, issue_number, handle, attempt_id)
        observed = time.monotonic()
        if not fresh:
            raise LedgerError('FORGE_FACTS_EXPIRED')
        delivery_class = self._eligible(receipt['observation'], pending)
        # Read-side snapshot is bounded/fresh, not an atomic GitHub lock. Git is
        # observed again after provider I/O, before the one activation transaction.
        slot = self._slot(run, participant_id)
        with self.supervisor._locked():
            self._authority(handle)
            if native.observe() is not Readiness.SAFE:
                raise LedgerError('NATIVE_NOT_SAFE')
            def activate(state, _):
                if time.monotonic() - observed > 5:
                    raise LedgerError('FORGE_FACTS_EXPIRED')
                current = state['run_admissions'][run]
                if current['status'] != 'PREPARING' or current['human_origin'] != human.canonical():
                    raise LedgerError('ADMISSION_CONFLICT')
                if not self.hub._current(handle.connection, safe=True):
                    raise LedgerError('NATIVE_NOT_SAFE')
                scope = self.hub.contexts.scope(participant_id)
                if scope != native.scope or scope['run_id'] != run or scope['context_generation'] != 1:
                    raise LedgerError('CONTEXT_MISMATCH')
                request_id = 'implementation-' + run
                request_text = self._request_text(issue_number, current['policy'], slot['path'])
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
                    'policy': deepcopy(current['policy']), 'checkout': deepcopy(slot),
                    'context_generation': 1, 'implementation_request': request_id,
                    'forge_observation': receipt['operation_id'], 'human_operation': command.id,
                    'authorization_consumed': True, 'projection': 'unavailable-no-write-support'}
                current.pop('reservation')
                current.update(status='ACTIVE', authorization_consumed=True, attention=None)
                state['runs'][run] = row
                state['peer_traffic']['traffic'][request_id] = record
                FixturePeerHub._reserve_capacity(state)
                return Transition(state, (Event('run.activated', row),
                    Event('peer.submitted', {'traffic_id': request_id, 'recipients': [participant_id]})), row)
            result = self._apply(terminal, human, activate)
        if result['result'].get('status') == 'HELD':
            raise LedgerError(result['result']['reason'])
        return result['result']
