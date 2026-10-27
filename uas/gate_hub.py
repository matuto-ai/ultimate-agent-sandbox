"""Typed identity evidence and protected-operation adjudication in the Room Hub.

Identity facts come from the trusted authority owner, never the submitted note.
This module neither launches a Participant nor grants merge/completion authority.
"""
from copy import deepcopy
import re
import uuid

from .gate_evaluation import ArtifactGateHub, MAX_EVALUATIONS, PROJECTION_RESERVATION, _capacity, _digest, _now
from .ledger import Command, Event, LedgerError, Origin, Transition, _token, _json

_SHA = re.compile(r'[0-9a-f]{40}\Z')
_AUTHORITY_KEYS = {'actor_id', 'kind', 'active', 'authority_epoch', 'capabilities',
                   'contributors', 'contribution_version', 'complete'}
_NOT_READ = object()


def identity_fact(value, actor_id):
    if (type(value) is not dict or set(value) != _AUTHORITY_KEYS
            or value['actor_id'] != actor_id or value['kind'] not in ('human', 'participant')
            or type(value['active']) is not bool or value['complete'] is not True
            or type(value['capabilities']) is not list or len(value['capabilities']) > 32
            or type(value['contributors']) is not list or len(value['contributors']) > 128):
        raise LedgerError('GATE_IDENTITY_UNVERIFIABLE')
    for key in ('actor_id', 'authority_epoch', 'contribution_version'):
        _token(value[key])
    for key in ('capabilities', 'contributors'):
        if value[key] != sorted(set(value[key])):
            raise LedgerError('GATE_IDENTITY_UNVERIFIABLE')
        for item in value[key]:
            _token(item)
    return deepcopy(value)


def eligible(gate, run, identity):
    config = gate['config']
    actor = identity['actor_id']
    if not identity['active'] or actor not in config['eligible_actors']:
        return False
    capability = config['required_capability']
    if capability is not None and capability not in identity['capabilities']:
        return False
    implementer = run.get('actor_id')
    if implementer is None:
        raise LedgerError('GATE_IMPLEMENTER_UNVERIFIABLE')
    if not config['allow_self'] and actor == implementer:
        return False
    relationship = config['relationship']
    if relationship in ('human', 'participant'):
        return identity['kind'] == relationship
    if relationship == 'implementer':
        return actor == implementer
    return (identity['kind'] == 'participant' and actor != implementer
            and actor not in identity['contributors'])


class GateHub(ArtifactGateHub):
    """The same ledger owner, with fixed Gate kinds rather than evaluator plugins.

    ``identity`` is a trusted authority read ``(run, actor_id, head_sha) -> fact``.
    Its contribution set is the durable Actor history for that exact revision,
    not seat/session/runtime separation. Unavailable evidence always blocks.
    """
    def __init__(self, ledger, binding, control, *, authorize, identity=None, forge=None,
                 repository=None, authorize_target=None, diff=None):
        super().__init__(ledger, binding, control, authorize=authorize)
        if identity is not None and not callable(identity):
            raise LedgerError('INVALID_GATE_BINDING')
        if authorize_target is not None and not callable(authorize_target):
            raise LedgerError('INVALID_GATE_BINDING')
        self.authorize_target = authorize_target or (lambda *_: False)
        self.identity, self.forge, self.repository = identity, forge, repository
        from .gate_command_hub import CommandGateHub
        self.repository_hub = (CommandGateHub(ledger, binding, repository, authorize=authorize)
                               if repository is not None else None)
        from .gate_diff_hub import DiffGateHub
        self.diff_hub = DiffGateHub(ledger, binding, diff, authorize=authorize, forge=forge) if diff is not None else None

    def bind_target(self, operation_id, run_id, generation, target, *, origin, expected_binding=None):
        """Trusted #74 owner only: verify then durably CAS the exact PR subject.

        Ordinary evaluation/Participant authority does not permit this operation.
        Broker/source observations establish identity; target fields alone do not.
        An uncertain read is never silently repeated by an exact operation retry.
        """
        from .gate_forge import validate_forge_target, validate_target_observation
        self._require_owner()
        target = validate_forge_target(target)
        if expected_binding is not None:
            if type(expected_binding) is not str or not re.fullmatch(r'[0-9a-f]{64}', expected_binding):
                raise LedgerError('INVALID_GATE_TARGET_BINDING')
        command = Command(_token(operation_id), 'gate.bind-target', _token(run_id), generation,
                          {'target': target, 'expected_binding': expected_binding})
        if type(generation) is not int or not 1 <= generation < 2**53:
            raise LedgerError('INVALID_GATE_TARGET_BINDING')
        receipt = self.ledger.exact_receipt(command, origin, authorize=self.authorize_target)
        if receipt is not None:
            return deepcopy(self.ledger.snapshot()['state']['gate_target_bindings'][command.id]['result'])
        if self.forge is None: raise LedgerError('GATE_FORGE_UNAVAILABLE')
        def scope(state):
            run = state.get('runs', {}).get(run_id)
            if run is None: raise LedgerError('UNKNOWN_RUN')
            if run['generation'] != generation: raise LedgerError('STALE_RUN_GENERATION')
            if run['status'] != 'ACTIVE': raise LedgerError('RUN_NOT_ACTIVE')
            if (run['repository'] != self.binding.repository or run['project_id'] != self.binding.project_id
                    or target['repository'] != self.binding.repository):
                raise LedgerError('GATE_BINDING_MISMATCH')
            # Verify the complete immutable policy using the existing compiler.
            gate_id = run['policy']['gates'][0]['id']
            self._definition(state, self._command('gate-target-policy', run_id, generation, gate_id))
            actual = _digest(run['gate_target']) if 'gate_target' in run else None
            if actual != expected_binding: raise LedgerError('GATE_TARGET_BINDING_CONFLICT')
            return run, _run_dependency_digest(run)
        state = self.ledger.snapshot()['state']; run, dependency = scope(state)
        source = self._source(self.control.resolve(run_id, run['participant_id'], self.binding.room_instance), run)
        if source['head_sha'] != target['head_sha']: raise LedgerError('GATE_TARGET_MISMATCH')
        def current(state, source_now=_NOT_READ):
            run, fresh = scope(state)
            if fresh != dependency or source_now is not _NOT_READ and self._source(source_now, run) != source:
                raise LedgerError('GATE_DEPENDENCY_CHANGED')
            return run
        created = False
        def reserve(state, _):
            nonlocal created
            current(state)
            rows = state.setdefault('gate_target_bindings', {})
            if len(rows) >= MAX_EVALUATIONS: raise LedgerError('GATE_HISTORY_CAPACITY')
            if any(row['run_id'] == run_id and row['phase'] == 'STARTED' for row in rows.values()):
                raise LedgerError('GATE_TARGET_BINDING_IN_FLIGHT')
            rows[command.id] = {'run_id': run_id, 'generation': generation, 'phase': 'STARTED',
                'target': target, 'source': source, 'dependency_digest': dependency,
                'origin': origin.canonical(), 'result': {'status': 'PENDING', 'operation_id': command.id},
                'reservation': 'x' * 65536}
            _capacity(state); created = True
            return Transition(state, (Event('gate.target-binding-started', {'operation_id': command.id,
                'run_id': run_id, 'generation': generation, 'target': target, 'source': source,
                'dependency_digest': dependency}),), {'operation_id': command.id})
        self.ledger.apply(command, origin, authorize=self.authorize_target, decide=reserve)
        if not created:
            return deepcopy(self.ledger.snapshot()['state']['gate_target_bindings'][command.id]['result'])
        def authorized():
            try:
                return self.authorize_target(origin, command) is True and bool(current(self.ledger.snapshot()['state'], self.control.current(source)))
            except Exception:
                return False
        observation = None; audit_reference = None; reason = None
        try:
            reply = self.forge.observe_target(target, 'gate-target-' + _digest(command.canonical()), authorize=authorized)
            if type(reply) is not dict or set(reply) != {'observation', 'audit_reference'}:
                raise LedgerError('INVALID_FORGE_OBSERVATION')
            audit_reference = _token(reply['audit_reference'])
            observation = validate_target_observation(reply['observation'], target)
            if observation['status'] != 'OK' or observation['completeness'] != 'complete':
                raise LedgerError('GATE_FORGE_UNAVAILABLE')
            pull = observation['pull']
            if pull['state'] != 'open' or pull['merged']:
                raise LedgerError('GATE_TARGET_NOT_OPEN')
        except Exception as error:
            reason = self._error_code(error)
        try:
            fresh_source = self.control.current(source)
        except Exception as invalid:
            fresh_source = None
            reason = reason or self._error_code(invalid)
        terminal = Command('gate-target-result-' + _digest(command.canonical()), 'gate.target-bound', run_id, generation, {})
        def finish(state, _):
            error = reason
            try:
                row = current(state, fresh_source)
                if self.authorize_target(origin, command) is not True:
                    raise LedgerError('GATE_AUTHORITY_REVOKED')
            except Exception as invalid:
                error = self._error_code(invalid)
            result = {'operation_id': command.id, 'status': 'ERROR' if error else 'BOUND',
                'target': target, 'binding_digest': _digest(target), 'reason': error,
                'audit_reference': audit_reference, 'observation': observation}
            intent = state['gate_target_bindings'][command.id]
            intent.update(phase='TERMINAL', result=result, reservation='')
            if error is None:
                row['gate_target'] = deepcopy(target)
                row['gate_target_binding'] = {'operation_id': command.id, 'digest': _digest(target),
                    'source': source, 'policy_digest': _digest(row['policy']), 'generation': generation, 'audit_reference': audit_reference}
            _capacity(state)
            return Transition(state, (Event('gate.target-bound' if error is None else 'gate.target-binding-error', result),), result)
        return self.ledger.apply(terminal, origin, authorize=lambda *_: True, decide=finish)['result']

    def recover_target_binding(self, operation_id):
        """After old Hub fencing, retire uncertain binding without provider replay."""
        self._require_owner(); _token(operation_id)
        existing = self.ledger.snapshot()['state'].get('gate_target_bindings', {}).get(operation_id)
        if existing is not None and existing['phase'] == 'TERMINAL': return deepcopy(existing['result'])
        command = Command('gate-target-interrupted-' + _digest(operation_id), 'gate.target-interrupted', operation_id, None, {})
        def decide(state, _):
            row = state.get('gate_target_bindings', {}).get(operation_id)
            if row is None: raise LedgerError('UNKNOWN_GATE_TARGET_BINDING')
            if row['phase'] == 'TERMINAL': raise LedgerError('GATE_BINDING_ALREADY_TERMINAL')
            row.update(phase='TERMINAL', reservation='', result={'operation_id': operation_id,
                'status': 'ERROR', 'reason': 'GATE_INTERRUPTED_UNKNOWN'})
            return Transition(state, (Event('gate.target-binding-error', row['result']),), row['result'])
        from .gate_evaluation import _CONTROL
        return self.ledger.apply(command, _CONTROL, authorize=lambda *_: True, decide=decide)['result']

    def evaluate(self, operation_id, run_id, generation, gate_id, *, origin):
        self._require_owner()
        command = self._command(operation_id, run_id, generation, gate_id)
        receipt = self.ledger.exact_receipt(command, origin, authorize=self.authorize)
        if receipt is not None:
            return self._view(self._row(receipt['result']['evaluation_id']))
        _, _, gate = self._definition(self.ledger.snapshot()['state'], command)
        if gate.get('evaluator') == 'artifacts':
            return super().evaluate(operation_id, run_id, generation, gate_id, origin=origin)
        if gate.get('evaluator') == 'command':
            if self.repository_hub is None: raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
            return self.repository_hub.evaluate(operation_id, run_id, generation, gate_id, origin=origin)
        if gate.get('evaluator') == 'diff-claims':
            if self.diff_hub is None: raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
            return self.diff_hub.evaluate(operation_id, run_id, generation, gate_id, origin=origin)
        if gate['kind'] != 'mechanical':
            raise LedgerError('GATE_TYPED_SUBMISSION_REQUIRED')
        return self._evaluate_external(command, origin, gate)

    def declare_diff(self, operation_id, run_id, generation, gate_id, paths, *, origin):
        """Untrusted changed-file declaration; no target, command or verdict input."""
        from .artifact_protocol import validate_path
        self._require_owner()
        if type(paths) is not list or len(paths) > 128:
            raise LedgerError('INVALID_GATE_DIFF_DECLARATION')
        try:
            for path in paths: validate_path(path)
            if len(set(paths)) != len(paths): raise ValueError()
        except Exception:
            raise LedgerError('INVALID_GATE_DIFF_DECLARATION') from None
        ordered = sorted(paths, key=lambda path: path.encode())
        command = Command(_token(operation_id), 'gate.declare-diff', _token(run_id), generation,
                          {'gate_id': _token(gate_id), 'paths': ordered})
        self._command(operation_id, run_id, generation, gate_id)
        receipt = self.ledger.exact_receipt(command, origin, authorize=self.authorize)
        if receipt is not None: return receipt['result']
        def decide(state, _):
            run, policy, gate = self._definition(state, command)
            if (gate.get('evaluator') != 'diff-claims' or origin.actor_id != run.get('actor_id')
                    or 'implement' not in origin.capabilities):
                raise LedgerError('FORBIDDEN_GATE_DECLARATION')
            target = self._external_target(run, gate)
            declaration = {'paths': ordered, 'subject': target, 'actor_id': origin.actor_id,
                           'generation': generation}
            run.setdefault('gate_declarations', {})[gate_id] = declaration
            _capacity(state)
            return Transition(state, (Event('gate.diff-declared', {'run_id': run_id,
                'generation': generation, 'gate_id': gate_id, 'declaration': declaration}),), declaration)
        return self.ledger.apply(command, origin, authorize=self.authorize, decide=decide)['result']

    def _refresh_diff_projection(self, projection, command, origin):
        from .gate_forge import validate_target_observation
        row = self._row(projection['evaluation_id']); subject = row['source']['subject']
        operation = 'gate-diff-refresh-' + uuid.uuid4().hex
        result = deepcopy(projection)
        def authorized():
            try:
                state = self.ledger.snapshot()['state']
                run, policy, gate = self._definition(state, command)
                return (self.authorize(origin, command) is True
                    and self._external_target(run, gate) == subject
                    and self.diff_hub._scope(Command(**row['command']), run, policy, gate) == row['scope']
                    and self.diff_hub.control.current(row['source']) == row['source'])
            except Exception:
                return False
        def reserve(state, _):
            current = state['gate_evaluations'][row['evaluation_id']]
            if current.get('refresh', {}).get('phase') == 'STARTED':
                raise LedgerError('GATE_FORGE_REFRESH_UNRESOLVED')
            current['refresh'] = {'operation_id': operation, 'phase': 'STARTED'}
            return Transition(state, (Event('gate.refresh-started', {'evaluation_id': row['evaluation_id'],
                'operation_id': operation}),), {})
        self.ledger.apply(Command(operation, 'gate.refresh', row['evaluation_id'], None, {}), origin,
            authorize=lambda *_: self.authorize(origin, command), decide=reserve)
        proof = None; reference = None; fresh_source = None
        try:
            if self.forge is None: raise LedgerError('GATE_FORGE_UNAVAILABLE')
            reply = self.forge.observe_target(subject, operation, authorize=authorized)
            if type(reply) is not dict or set(reply) != {'observation', 'audit_reference'}:
                raise LedgerError('INVALID_FORGE_OBSERVATION')
            reference = _token(reply['audit_reference'])
            proof = validate_target_observation(reply['observation'], subject)
            if proof['status'] != 'OK': raise LedgerError('GATE_DIFF_SUBJECT_CHANGED')
            if not authorized(): raise LedgerError('GATE_DEPENDENCY_CHANGED')
            fresh_source = self.diff_hub.control.current(row['source'])
            result['dependency_digest'] = _digest(subject)
        except Exception as error:
            result.update(state='stale', changed_dependencies=[self._error_code(error)])
        def finish(state, _):
            try:
                run, policy, gate = self._definition(state, command)
                if (self._external_target(run, gate) != subject or fresh_source != row['source']
                        or self.diff_hub._scope(Command(**row['command']), run, policy, gate) != row['scope']):
                    raise LedgerError('GATE_DEPENDENCY_CHANGED')
                candidates = [r for r in state['gate_evaluations'].values()
                    if r['scope']['run_id'] == command.target and r['scope']['gate_id'] == gate['id']]
                if max(candidates, key=lambda r: r['started']['sequence'])['evaluation_id'] != row['evaluation_id']:
                    raise LedgerError('GATE_EVALUATION_SUPERSEDED')
                if self.authorize(origin, command) is not True: raise LedgerError('GATE_AUTHORITY_REVOKED')
            except Exception as error:
                result.update(state='stale', changed_dependencies=[self._error_code(error)])
            state['gate_evaluations'][row['evaluation_id']]['refresh'] = {
                'operation_id': operation, 'phase': 'TERMINAL', 'projection': result, 'audit_reference': reference}
            return Transition(state, (Event('gate.refreshed', {**result, 'audit_reference': reference,
                'subject_observation': proof}),), result)
        terminal = Command(operation + '-done', 'gate.refreshed', row['evaluation_id'], None, {})
        return self.ledger.apply(terminal, origin, authorize=lambda *_: True, decide=finish)['result']

    def _external_target(self, run, gate):
        if gate['evaluator'] not in ('forge-state', 'diff-claims'):
            raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
        from .gate_forge import validate_forge_target
        if 'gate_target' not in run:
            raise LedgerError('GATE_TARGET_UNBOUND')
        target = validate_forge_target(run['gate_target'])
        binding = run.get('gate_target_binding')
        if (type(binding) is not dict or binding.get('digest') != _digest(target)
                or binding.get('generation') != run['generation']
                or binding.get('policy_digest') != _digest(run['policy'])):
            raise LedgerError('GATE_TARGET_BINDING_STALE')
        if target['repository'] != self.binding.repository:
            raise LedgerError('GATE_TARGET_MISMATCH')
        return target

    def _external_scope(self, command, run, policy, gate, target):
        scope = self._scope(command, run, policy, gate)
        scope.update(evaluator=gate['evaluator'], target_digest=_digest(target))
        return scope

    def _external_current(self, state, command, expected, *, require_active=True, current_source=_NOT_READ):
        run, policy, gate = self._definition(state, command, require_active=require_active)
        target = self._external_target(run, gate)
        scope = self._external_scope(command, run, policy, gate, target)
        if scope != expected['scope'] or target != expected['target']:
            raise LedgerError('GATE_DEPENDENCY_CHANGED')
        if self._checkout_digest(run) != expected['checkout_digest']:
            raise LedgerError('GATE_SOURCE_MISMATCH')
        if current_source is not _NOT_READ:
            current = self._source(current_source, run)
            if current != expected['source'] or current['head_sha'] != target['head_sha']:
                raise LedgerError('GATE_SOURCE_MISMATCH')
        return run, policy, gate

    def _evaluate_external(self, command, origin, gate):
        from .gate_forge import adjudicate_forge_state, validate_forge_observation
        if gate['evaluator'] != 'forge-state':
            raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
        if self.forge is None:
            raise LedgerError('GATE_FORGE_UNAVAILABLE')
        run, policy, gate = self._definition(self.ledger.snapshot()['state'], command)
        target = self._external_target(run, gate)
        source = self._source(self.control.resolve(run['run_id'], run['participant_id'],
                                                  self.binding.room_instance), run)
        if source['head_sha'] != target['head_sha']:
            raise LedgerError('GATE_TARGET_MISMATCH')
        scope = self._external_scope(command, run, policy, gate, target)
        evaluation_id = scope['evaluation_id']
        created = False
        def reserve(state, _):
            nonlocal created
            rows = state.setdefault('gate_evaluations', {})
            if len(rows) >= MAX_EVALUATIONS:
                raise LedgerError('GATE_HISTORY_CAPACITY')
            if any(row['result'] is None and row['scope']['run_id'] == command.target
                   and row['scope']['gate_id'] == gate['id'] for row in rows.values()):
                raise LedgerError('GATE_EVALUATION_IN_FLIGHT')
            row = {'evaluation_id': evaluation_id, 'scope': scope, 'source': source,
                'target': target, 'checkout_digest': self._checkout_digest(run),
                'config': deepcopy(gate['config']), 'phase': 'STARTED',
                'started': {'sequence': self.ledger.snapshot()['room_seq'] + 1, 'time': _now()},
                'origin': origin.canonical(), 'command': command.canonical(), 'result': None,
                'operational': {'cleanup': True, 'quarantine_ref': None, 'attention': None},
                'reservation': {'scratch_bytes': 0, 'projection': 'x' * PROJECTION_RESERVATION}}
            self._external_current(state, command, row)
            rows[evaluation_id] = row; _capacity(state); created = True
            return Transition(state, (Event('gate.started', {key: row[key] for key in
                ('evaluation_id', 'scope', 'source', 'target', 'started')}),), {'evaluation_id': evaluation_id})
        self.ledger.apply(command, origin, authorize=self.authorize, decide=reserve)
        if not created: return self._view(self._row(evaluation_id))
        observation = None; audit_reference = None; reason = None
        def authorized():
            if self.authorize(origin, command) is not True: return False
            try:
                self._external_current(self.ledger.snapshot()['state'], command, self._row(evaluation_id),
                    current_source=self.control.current(source))
                return True
            except Exception:
                return False
        try:
            response = self.forge.observe(target, gate['config'], evaluation_id, authorize=authorized)
            if type(response) is not dict or set(response) != {'observation', 'audit_reference'}:
                raise LedgerError('INVALID_FORGE_OBSERVATION')
            audit_reference = _token(response['audit_reference'])
            observation = validate_forge_observation(response['observation'], target)
        except Exception as error:
            reason = self._error_code(error)
        return self._complete_external(evaluation_id, command, origin, observation, audit_reference, reason)

    def _complete_external(self, evaluation_id, command, origin, observation, audit_reference, reason):
        from .gate_forge import adjudicate_forge_state
        terminal = Command('gate-terminal-' + evaluation_id, 'gate.completed', evaluation_id, None, {})
        try:
            fresh_source = self.control.current(self._row(evaluation_id)['source'])
            from .artifact_protocol import validate_source
            validate_source(fresh_source)
        except Exception as invalid:
            fresh_source = None
            reason = reason or self._error_code(invalid)
        def decide(state, _):
            row = state['gate_evaluations'][evaluation_id]
            if row['result'] is not None: raise LedgerError('EVALUATION_ALREADY_TERMINAL')
            changed = []; error = reason
            try: self._external_current(state, command, row, current_source=fresh_source)
            except Exception as invalid: changed.append(self._error_code(invalid))
            try:
                if self.authorize(origin, command) is not True: error = 'GATE_AUTHORITY_REVOKED'
            except Exception:
                error = 'GATE_AUTHORITY_REVOKED'
            reduced = (adjudicate_forge_state(observation, row['target'], row['config'])
                       if observation is not None and error is None else
                       {'checks': [{'item': 'forge-state', 'ok': False, 'note': 'verification-incomplete',
                                    'evidence_refs': [audit_reference] if audit_reference else []}],
                        'verdict': 'error', 'reason': error or 'GATE_SOURCE_UNVERIFIED', 'dependencies': {}})
            result = {'evaluation_id': evaluation_id, 'scope': deepcopy(row['scope']),
                'source': deepcopy(row['source']), 'target': deepcopy(row['target']),
                'checkout_digest': row['checkout_digest'], 'started': row['started'],
                'completed': {'sequence': self.ledger.snapshot()['room_seq'] + 1, 'time': _now()},
                'checks': reduced['checks'], 'verdict': reduced['verdict'], 'reason': reduced['reason'],
                'dependencies': reduced['dependencies'], 'observation': observation,
                'audit_reference': audit_reference, 'provenance': 'external-forge-broker / verified',
                'freshness_at_completion': {'state': 'stale' if changed else 'current',
                                            'changed_dependencies': changed}}
            row.update(result=result, phase='TERMINAL'); row['reservation']['projection'] = ''
            _capacity(state)
            return Transition(state, (Event('gate.completed', result),), {'evaluation_id': evaluation_id})
        self.ledger.apply(terminal, origin, authorize=lambda *_: True, decide=decide)
        return self._view(self._row(evaluation_id))

    def _external_projection(self, state, command, run, policy, gate, origin):
        rows = [row for row in state.get('gate_evaluations', {}).values()
                if row['scope']['run_id'] == run['run_id'] and row['scope']['gate_id'] == gate['id']]
        if not rows: return {'gate_id': gate['id'], 'state': 'missing', 'evaluation_id': None}
        row = max(rows, key=lambda row: row['started']['sequence'])
        result = {'gate_id': gate['id'], 'evaluation_id': row['evaluation_id'], 'changed_dependencies': []}
        original = Command(**row['command'])
        try:
            if original.generation != command.generation:
                raise LedgerError('STALE_RUN_GENERATION')
            self._external_current(state, original, row, current_source=self.control.current(row['source']))
        except Exception as error:
            result.update(state='stale', changed_dependencies=[self._error_code(error)])
            return result
        if row['result'] is None: result['state'] = 'in-flight'; return result
        result['state'] = row['result']['verdict']
        # Failed/error immutable attempts already block; never re-run them on read.
        if result['state'] != 'passed': return result
        from .gate_forge import adjudicate_forge_state
        operation = 'gate-refresh-' + uuid.uuid4().hex
        refresh = Command(operation, 'gate.refresh', row['evaluation_id'], None, {})
        def reserve(current, _):
            active = current['gate_evaluations'][row['evaluation_id']]
            if active.get('refresh', {}).get('phase') == 'STARTED':
                raise LedgerError('GATE_FORGE_REFRESH_UNRESOLVED')
            active['refresh'] = {'operation_id': operation, 'phase': 'STARTED'}
            return Transition(current, (Event('gate.refresh-started', {'evaluation_id': row['evaluation_id'],
                'operation_id': operation}),), {})
        self.ledger.apply(refresh, origin, authorize=lambda *_: self.authorize(origin, command), decide=reserve)
        audit_reference = None
        def authorized():
            try:
                return (self.authorize(origin, command) is True and
                    bool(self._external_current(self.ledger.snapshot()['state'], original, row,
                        current_source=self.control.current(row['source']))))
            except Exception:
                return False
        try:
            if self.forge is None: raise LedgerError('GATE_FORGE_UNAVAILABLE')
            current = self.forge.observe(row['target'], gate['config'], operation, authorize=authorized)
            if type(current) is not dict or set(current) != {'observation', 'audit_reference'}:
                raise LedgerError('INVALID_FORGE_OBSERVATION')
            audit_reference = _token(current['audit_reference'])
            reduced = adjudicate_forge_state(current['observation'], row['target'], gate['config'])
            result['dependency_digest'] = reduced['dependencies'].get('dependency_digest')
            if reduced['verdict'] != 'passed' or reduced['dependencies'] != row['result']['dependencies']:
                result.update(state='stale', changed_dependencies=['forge-state'])
        except Exception:
            result.update(state='stale', changed_dependencies=['forge-state-unverifiable'])
        try:
            fresh_source = self.control.current(row['source'])
        except Exception:
            fresh_source = None
            result.update(state='stale', changed_dependencies=['source-unverifiable'])
        terminal = Command(operation + '-done', 'gate.refreshed', row['evaluation_id'], None, result)
        def finish(current, _):
            try:
                self._external_current(current, original, row, current_source=fresh_source)
                candidates = [r for r in current['gate_evaluations'].values()
                    if r['scope']['run_id'] == run['run_id'] and r['scope']['gate_id'] == gate['id']]
                if max(candidates, key=lambda r: r['started']['sequence'])['evaluation_id'] != row['evaluation_id']:
                    raise LedgerError('GATE_EVALUATION_SUPERSEDED')
                if self.authorize(origin, command) is not True:
                    raise LedgerError('GATE_AUTHORITY_REVOKED')
            except Exception as error:
                result.update(state='stale', changed_dependencies=[self._error_code(error)])
            current['gate_evaluations'][row['evaluation_id']]['refresh'] = {
                'operation_id': operation, 'phase': 'TERMINAL', 'projection': result,
                'audit_reference': audit_reference}
            return Transition(current, (Event('gate.refreshed', {**result,
                'audit_reference': audit_reference}),), result)
        self.ledger.apply(terminal, origin, authorize=lambda *_: True, decide=finish)
        return result

    def recover_interrupted(self, evaluation_id):
        self._require_owner()
        row = self._row(_token(evaluation_id))
        if row['result'] is not None:
            pending = row.get('refresh')
            if pending is not None and pending['phase'] == 'STARTED':
                command = Command(pending['operation_id'] + '-interrupted', 'gate.refresh-interrupted',
                                  evaluation_id, None, {})
                def reconcile(state, _):
                    state['gate_evaluations'][evaluation_id]['refresh'] = {
                        'operation_id': pending['operation_id'], 'phase': 'TERMINAL',
                        'projection': {'state': 'stale', 'changed_dependencies': ['GATE_INTERRUPTED_UNKNOWN']}}
                    return Transition(state, (Event('gate.refresh-interrupted', {'evaluation_id': evaluation_id}),), {})
                from .gate_evaluation import _CONTROL
                self.ledger.apply(command, _CONTROL, authorize=lambda *_: True, decide=reconcile)
            return self._view(self._row(evaluation_id))
        if row['scope'].get('scope_kind') in ('run', 'head'):
            return self._complete_identity(evaluation_id, None, False, 'GATE_INTERRUPTED_UNKNOWN', [])
        if row['scope'].get('evaluator') == 'forge-state':
            origin = Origin(**{**row['origin'], 'capabilities': tuple(row['origin']['capabilities'])})
            return self._complete_external(evaluation_id, Command(**row['command']), origin,
                                           None, None, 'GATE_INTERRUPTED_UNKNOWN')
        if row.get('evaluator') == 'command':
            if self.repository_hub is None: raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
            return self.repository_hub.recover_interrupted(evaluation_id)
        if row.get('evaluator') == 'diff-claims':
            if self.diff_hub is None: raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
            return self.diff_hub.recover_interrupted(evaluation_id)
        return super().recover_interrupted(evaluation_id)

    def reconcile_cleanup(self, evaluation_id):
        self._require_owner()
        row = self._row(_token(evaluation_id))
        if row.get('evaluator') == 'command':
            if self.repository_hub is None: raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
            return self.repository_hub.reconcile_cleanup(evaluation_id)
        if row.get('evaluator') == 'diff-claims':
            if self.diff_hub is None: raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
            return self.diff_hub.reconcile_cleanup(evaluation_id)
        return super().reconcile_cleanup(evaluation_id)

    def _identity_scope(self, command, run, policy, gate):
        scope = {'room_id': self.binding.room_id, 'room_instance': self.binding.room_instance,
            'project_id': self.binding.project_id, 'repository': self.binding.repository,
            'run_id': run['run_id'], 'generation': run['generation'], 'gate_id': gate['id'],
            'policy_id': policy['id'], 'policy_version': policy['version'],
            'policy_digest': _digest(policy), 'config_digest': _digest(gate['config']),
            'scope_kind': gate['scope']}
        if gate['scope'] == 'head':
            source = self._source(self.control.resolve(run['run_id'], run['participant_id'],
                                                      self.binding.room_instance), run)
            scope['head_sha'] = source['head_sha']
        return scope

    def _identity(self, run, actor_id, scope):
        if self.identity is None:
            raise LedgerError('GATE_IDENTITY_UNAVAILABLE')
        return identity_fact(self.identity(deepcopy(run), actor_id, scope.get('head_sha')), actor_id)

    @staticmethod
    def _submission(payload):
        keys = {'gate_id', 'action', 'statement_id', 'note', 'evidence_refs'}
        if type(payload) is not dict or set(payload) != keys:
            raise LedgerError('INVALID_GATE_SUBMISSION')
        _token(payload['gate_id']); _token(payload['statement_id'])
        try:
            note_bytes = payload['note'].encode('utf-8') if type(payload['note']) is str else None
        except UnicodeError:
            raise LedgerError('INVALID_GATE_SUBMISSION') from None
        if (payload['action'] not in ('assert', 'approve', 'reject', 'withdraw')
                or note_bytes is None or len(note_bytes) > 4096
                or any(ord(c) < 32 and c not in '\n\t' for c in payload['note'])
                or type(payload['evidence_refs']) is not list or len(payload['evidence_refs']) > 16):
            raise LedgerError('INVALID_GATE_SUBMISSION')
        if any(type(reference) is not str for reference in payload['evidence_refs']):
            raise LedgerError('INVALID_GATE_SUBMISSION')
        for reference in payload['evidence_refs']:
            try: _token(reference)
            except LedgerError: raise LedgerError('INVALID_GATE_SUBMISSION') from None
        if payload['evidence_refs'] != sorted(set(payload['evidence_refs'])):
            raise LedgerError('INVALID_GATE_SUBMISSION')
        return deepcopy(payload)

    def submit(self, operation_id, run_id, generation, payload, *, origin):
        """Reserve once, then record one typed assertion/decision and its scope."""
        self._require_owner(); payload = self._submission(payload)
        command = Command(_token(operation_id), 'gate.submit', _token(run_id), generation, payload)
        self._command(operation_id, run_id, generation, payload['gate_id'])
        receipt = self.ledger.exact_receipt(command, origin, authorize=self.authorize)
        if receipt is not None: return self._view(self._row(receipt['result']['evaluation_id']))
        run, policy, gate = self._definition(self.ledger.snapshot()['state'], command)
        if (gate['kind'] not in ('attestation', 'decision')
                or payload['statement_id'] != gate['config']['statement_id']
                or payload['action'] not in (('assert', 'withdraw') if gate['kind'] == 'attestation'
                                             else ('approve', 'reject', 'withdraw'))):
            raise LedgerError('INVALID_GATE_SUBMISSION')
        captured = self._identity_scope(command, run, policy, gate)
        evaluation_id = self.evaluation_id(command.id); created = False
        def reserve(state, _):
            nonlocal created
            current_run, current_policy, current_gate = self._definition(state, command)
            if (_digest(current_policy) != captured['policy_digest']
                    or _digest(current_gate['config']) != captured['config_digest']):
                raise LedgerError('GATE_DEPENDENCY_CHANGED')
            rows = state.setdefault('gate_evaluations', {})
            if len(rows) >= MAX_EVALUATIONS: raise LedgerError('GATE_HISTORY_CAPACITY')
            if any(row['result'] is None and row['scope']['run_id'] == run_id
                   and row['scope']['gate_id'] == gate['id'] for row in rows.values()):
                raise LedgerError('GATE_EVALUATION_IN_FLIGHT')
            target = {'head_sha': captured['head_sha']} if 'head_sha' in captured else {'run_id': run_id}
            started = {'sequence': self.ledger.snapshot()['room_seq'] + 1, 'time': _now()}
            rows[evaluation_id] = {'evaluation_id': evaluation_id, 'scope': captured,
                'source': {'actor_id': origin.actor_id, 'authenticated_origin': origin.canonical()},
                'target': target, 'started': started, 'phase': 'STARTED', 'result': None,
                'origin': origin.canonical(), 'command': command.canonical(),
                'submission': payload, 'config': deepcopy(gate['config']), 'kind': gate['kind'],
                'operational': {'cleanup': True, 'quarantine_ref': None, 'attention': None},
                'reservation': {'scratch_bytes': 0, 'projection': 'x' * 32768}}
            _capacity(state); created = True
            return Transition(state, (Event('gate.submission-started', {'evaluation_id': evaluation_id,
                'scope': captured, 'source': rows[evaluation_id]['source'], 'submission': payload,
                'started': started}),), {'evaluation_id': evaluation_id})
        self.ledger.apply(command, origin, authorize=self.authorize, decide=reserve)
        if not created: return self._view(self._row(evaluation_id))
        fact, admitted, error, changed = None, False, None, []
        try:
            fact = self._identity(run, origin.actor_id, captured)
            admitted = fact['authority_epoch'] == origin.authority_version and eligible(gate, run, fact)
        except Exception as invalid:
            error = self._error_code(invalid)
        # All external source/identity reads occur outside the pure ledger
        # callback. Closing read makes a concurrent revision change explicit.
        try:
            closing_run, closing_policy, closing_gate = self._definition(self.ledger.snapshot()['state'], command)
            closing = self._identity_scope(command, closing_run, closing_policy, closing_gate)
            changed = sorted(key for key in set(captured) | set(closing) if captured.get(key) != closing.get(key))
        except Exception as invalid:
            changed.append(self._error_code(invalid))
        return self._complete_identity(evaluation_id, fact, admitted, error, changed)

    def _complete_identity(self, evaluation_id, fact, admitted, error, changed):
        saved = self._row(evaluation_id)
        command = Command(**saved['command'])
        origin = Origin(**{**saved['origin'], 'capabilities': tuple(saved['origin']['capabilities'])})
        terminal = Command('gate-terminal-' + evaluation_id, 'gate.submitted', evaluation_id, None, {})
        def decide(state, _):
            row = state['gate_evaluations'][evaluation_id]
            if row['result'] is not None: raise LedgerError('EVALUATION_ALREADY_TERMINAL')
            reason = error; stale = list(changed)
            try:
                run, policy, gate = self._definition(state, command)
                if _digest(policy) != row['scope']['policy_digest']: stale.append('policy')
                if _digest(gate['config']) != row['scope']['config_digest']: stale.append('configuration')
                if self.authorize(origin, command) is not True: reason = 'GATE_AUTHORITY_REVOKED'
            except Exception as invalid:
                reason = self._error_code(invalid)
            payload = row['submission']; positive = payload['action'] in ('approve', 'assert')
            ok = admitted and positive and reason is None
            note = ('identity-unverifiable' if reason else 'identity-ineligible' if not admitted
                    else 'asserted' if payload['action'] == 'assert' else payload['action'])
            source = {**row['source'], 'authority': fact}
            result = {'evaluation_id': evaluation_id, 'scope': row['scope'], 'target': row['target'],
                'source': source, 'started': row['started'],
                'completed': {'sequence': self.ledger.snapshot()['room_seq'] + 1, 'time': _now()},
                'checks': [{'item': payload['statement_id'], 'ok': ok, 'note': note,
                            'evidence_refs': deepcopy(payload['evidence_refs'])}],
                'verdict': 'error' if reason else 'passed' if ok else 'failed', 'reason': reason,
                'submission': payload, 'provenance': 'attested' if row['kind'] == 'attestation' else 'decided',
                'freshness_at_completion': {'state': 'stale' if stale else 'current',
                                            'changed_dependencies': sorted(set(stale))}}
            row.update(result=result, phase='TERMINAL', source=source)
            row['reservation']['projection'] = ''; _capacity(state)
            return Transition(state, (Event('gate.submitted', result),), {'evaluation_id': evaluation_id})
        from .gate_evaluation import _CONTROL
        self.ledger.apply(terminal, _CONTROL, authorize=lambda *_: True, decide=decide)
        return self._view(self._row(evaluation_id))

    def _identity_projection(self, state, command, run, policy, gate, origin):
        current = self._identity_scope(command, run, policy, gate)
        rows = [row for row in state.get('gate_evaluations', {}).values()
                if row['scope']['run_id'] == run['run_id'] and row['scope']['gate_id'] == gate['id']]
        latest = {}
        for row in sorted(rows, key=lambda row: row['started']['sequence']):
            latest[row['origin']['actor_id']] = row
        outcomes = []
        for actor, row in latest.items():
            changed = sorted(key for key in set(current) | set(row['scope'])
                             if current.get(key) != row['scope'].get(key))
            if run['status'] != 'ACTIVE': changed.append('run-status')
            result = row['result']
            if result is not None and gate['config']['continuing_authority'] and not changed:
                try:
                    fresh = self._identity(run, actor, current)
                    old = row['source']['authority']
                    if (old is None or fresh['authority_epoch'] != old['authority_epoch']
                            or not eligible(gate, run, fresh)):
                        changed.append('eligibility')
                except Exception:
                    changed.append('identity-unverifiable')
            outcomes.append({'evaluation_id': row['evaluation_id'], 'actor_id': actor,
                'state': 'stale' if changed else 'in-flight' if result is None else result['verdict'],
                'changed_dependencies': changed})
        try:
            closing_state = self.ledger.snapshot()['state']
            closing_run, closing_policy, closing_gate = self._definition(closing_state, command, require_active=False)
            closing_scope = self._identity_scope(command, closing_run, closing_policy, closing_gate)
            closing_rows = [row for row in closing_state.get('gate_evaluations', {}).values()
                if row['scope']['run_id'] == run['run_id'] and row['scope']['gate_id'] == gate['id']]
            if (self.authorize(origin, command) is not True
                    or _run_dependency_digest(closing_run) != _run_dependency_digest(run)
                    or closing_scope != current
                    or [r['evaluation_id'] for r in closing_rows] != [r['evaluation_id'] for r in rows]):
                raise LedgerError('GATE_DEPENDENCY_CHANGED')
        except Exception as invalid:
            for item in outcomes:
                item['state'] = 'stale'
                item['changed_dependencies'].append(self._error_code(invalid))
        passing = [row for row in outcomes if row['state'] == 'passed']
        # Per-identity withdrawal/rejection removes only that identity's approval.
        state_name = ('in-flight' if any(r['state'] == 'in-flight' for r in outcomes) else
                      'passed' if passing else 'missing' if not outcomes else
                      'stale' if any(r['state'] == 'stale' for r in outcomes) else
                      'error' if any(r['state'] == 'error' for r in outcomes) else 'failed')
        return {'gate_id': gate['id'], 'state': state_name,
            'evaluation_id': min((r['evaluation_id'] for r in passing), default=None) if state_name == 'passed' else None,
            'evaluations': outcomes, 'provenance': 'attested' if gate['kind'] == 'attestation' else 'decided'}

    def projection(self, run_id, generation, gate_id, *, origin):
        self._require_owner()
        command = self._command('gate-projection', run_id, generation, gate_id)
        if self.authorize(origin, command) is not True:
            raise LedgerError('FORBIDDEN')
        state = self.ledger.snapshot()['state']
        run, policy, gate = self._definition(state, command, require_active=False)
        if gate['kind'] != 'mechanical':
            return self._identity_projection(state, command, run, policy, gate, origin)
        if gate['evaluator'] == 'artifacts':
            return super().projection(run_id, generation, gate_id, origin=origin)
        if gate['evaluator'] == 'command':
            if self.repository_hub is None: raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
            return self.repository_hub.projection(run_id, generation, gate_id, origin=origin)
        if gate['evaluator'] == 'diff-claims':
            if self.diff_hub is None: raise LedgerError('GATE_REPOSITORY_PROFILE_UNAVAILABLE')
            projected = self.diff_hub.projection(run_id, generation, gate_id, origin=origin)
            return self._refresh_diff_projection(projected, command, origin) if projected['state'] == 'passed' else projected
        return self._external_projection(state, command, run, policy, gate, origin)

    def operation_gates(self, run_id, generation, operation, *, origin):
        """Fresh blocking facts only; never a reusable authorization/merge token.

        The actual Run transition owner must compare this dependency-bound view
        in its own atomic acceptance transaction; this read cannot close a Run.
        No evaluator is launched implicitly by a protected-operation request.
        """
        self._require_owner()
        state = self.ledger.snapshot()['state']
        run = state.get('runs', {}).get(run_id)
        if run is None: raise LedgerError('UNKNOWN_RUN')
        if run['generation'] != generation: raise LedgerError('STALE_RUN_GENERATION')
        if operation not in ('submit-for-review', 'complete'):
            raise LedgerError('INVALID_PROTECTED_OPERATION')
        gate_ids = run['policy'].get('protected_operations', {}).get(operation)
        if type(gate_ids) is not list or not gate_ids:
            raise LedgerError('INVALID_GATE_POLICY')
        projections = [self.projection(run_id, generation, gate, origin=origin) for gate in gate_ids]
        blockers = [projection for projection in projections if projection['state'] != 'passed']
        return {'operation': operation, 'run_id': run_id, 'generation': generation,
                'gates_satisfied': not blockers, 'blockers': blockers, 'gates': projections,
                'policy_digest': _digest(run['policy']), 'run_dependency_digest': _run_dependency_digest(run)}


def require_operation_gates(state, view):
    """Inside the canonical transition: reject a stale/missing observation cut.

    The trusted caller must still hold its external target/identity authority
    fence while supplying ``view``; a view is not a transferable capability.
    This function performs no I/O or implicit evaluation and cannot close a Run.
    """
    if type(view) is not dict or set(view) != {'operation', 'run_id', 'generation',
            'gates_satisfied', 'blockers', 'gates', 'policy_digest', 'run_dependency_digest'}:
        raise LedgerError('INVALID_GATE_OPERATION_VIEW')
    run = state.get('runs', {}).get(view['run_id'])
    if run is None or run['generation'] != view['generation'] or run['status'] != 'ACTIVE':
        raise LedgerError('GATE_OPERATION_STALE')
    if (_digest(run['policy']) != view['policy_digest']
            or _run_dependency_digest(run) != view['run_dependency_digest']):
        raise LedgerError('GATE_OPERATION_STALE')
    required = run['policy'].get('protected_operations', {}).get(view['operation'])
    if (not required or [item.get('gate_id') for item in view['gates']] != required
            or view['gates_satisfied'] is not True or view['blockers']
            or any(item.get('state') != 'passed' for item in view['gates'])):
        raise LedgerError('GATE_OPERATION_BLOCKED')
    rows = state.get('gate_evaluations', {})
    for projection in view['gates']:
        candidates = [row for row in rows.values() if row['scope']['run_id'] == view['run_id']
                      and row['scope']['gate_id'] == projection['gate_id']]
        identities = {row['origin']['actor_id']: row for row in sorted(candidates,
                       key=lambda row: row['started']['sequence'])}
        selected = rows.get(projection.get('evaluation_id'))
        if selected is None or selected['result'] is None or selected['result']['verdict'] != 'passed':
            raise LedgerError('GATE_OPERATION_STALE')
        if selected['scope'].get('evaluator') == 'forge-state' or selected.get('evaluator') == 'diff-claims':
            refresh = selected.get('refresh', {})
            if (refresh.get('phase') != 'TERMINAL' or refresh.get('projection', {}).get('state') != 'passed'
                    or refresh['projection'].get('dependency_digest') != projection.get('dependency_digest')
                    or (selected['source']['subject'] if selected.get('evaluator') == 'diff-claims' else selected['target']) != run.get('gate_target')):
                raise LedgerError('GATE_OPERATION_STALE')
        if 'evaluations' in projection:
            expected = sorted((row['evaluation_id'] for row in identities.values()))
            observed = sorted(row['evaluation_id'] for row in projection['evaluations'])
            if expected != observed: raise LedgerError('GATE_OPERATION_STALE')
        elif not candidates or max(candidates, key=lambda row: row['started']['sequence']) != selected:
            raise LedgerError('GATE_OPERATION_STALE')
    return deepcopy(view)


def _run_dependency_digest(run):
    return _digest({'run_id': run['run_id'], 'generation': run['generation'],
        'status': run['status'], 'policy': run['policy'],
        'checkout': ArtifactGateHub._checkout_digest(run), 'gate_target': run.get('gate_target'),
        'target_binding': run.get('gate_target_binding'), 'declarations': run.get('gate_declarations')})
