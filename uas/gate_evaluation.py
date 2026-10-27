"""Hub-owned repository adjudication over the private Supervisor control seam.

No filesystem/Git, Engine, Participant tool, protected-operation advancement or
helper launch authority lives here. The control adapter supplies authenticated
GATE_BIND objects; mocks of that adapter are policy tests, never boundary proof.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import threading

from .gate_policy import compile_policy
from .ledger import Command, Event, LedgerError, Origin, Transition, _json, _token
from .artifact_protocol import (RESERVATION_BYTES, MAX_OUTPUT_BYTES, MAX_BLOB_BYTES,
    PROFILE_ID, scope_digest, profile_scope_digest, expected_header, path_digest, validate_scope,
    validate_source, validate_target)


MAX_EVALUATIONS = 16
MAX_OUTSTANDING = 2
SCRATCH_BYTES = RESERVATION_BYTES
PROJECTION_RESERVATION = 196608
MAX_OBSERVATION_BYTES = MAX_OUTPUT_BYTES
PROVENANCE = 'workstation-local / tamper-evident'
_CONTROL = Origin('gate-hub', 'gate-hub', 'gate-control', 'artifacts-v1', ())
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def _digest(value):
    return hashlib.sha256(_json(value).encode('utf-8')).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _unknown_cleanup(evaluation_id):
    return {'launch_state': 'unknown', 'exit_confirmed': False, 'cleanup': False,
            'post_target': None, 'quarantine_ref': 'gate-' + evaluation_id}


def _capacity(state):
    # Preserve reservations made by the existing peer/context/Forge owners.
    if 'peer_traffic' in state:
        from .peer import FixturePeerHub
        FixturePeerHub._reserve_capacity(state)
    else:
        _json(state)


@dataclass(frozen=True)
class GateRoomBinding:
    room_id: str
    room_instance: str
    project_id: str
    repository: str
    disk_bytes: int

    def __post_init__(self):
        for key in ('room_id', 'room_instance', 'project_id', 'repository'):
            _token(getattr(self, key))
        if type(self.disk_bytes) is not int or self.disk_bytes < 1:
            raise LedgerError('INVALID_GATE_BINDING')


class ArtifactGateHub:
    """One trusted Hub owner; all effects occur after a RoomLedger reservation.

    ``control`` is the gate-specific authenticated Supervisor client, not a
    resolver/Engine inside the Hub. ``authorize`` is the existing trusted control
    authority check, evaluated on every request/retry and before acceptance.
    Neither an Origin nor these dependencies is accepted from request payloads.
    """
    scratch_bytes = SCRATCH_BYTES

    def __init__(self, ledger, binding, control, *, authorize):
        if (type(binding) is not GateRoomBinding or binding.room_id != ledger.room_id
                or not callable(authorize)):
            raise LedgerError('INVALID_GATE_BINDING')
        self.ledger, self.binding, self.control = ledger, binding, control
        self.authorize = authorize
        self._owner = threading.get_ident()

    def _require_owner(self):
        if threading.get_ident() != self._owner:
            raise LedgerError('GATE_OWNER_MISMATCH')

    @staticmethod
    def evaluation_id(operation_id):
        return 'evaluation-' + hashlib.sha256(_token(operation_id).encode()).hexdigest()

    def _command(self, operation_id, run_id, generation, gate_id):
        if type(generation) is not int or not 1 <= generation < 2**53:
            raise LedgerError('INVALID_GATE_REQUEST')
        return Command(_token(operation_id), 'gate.evaluate', _token(run_id), generation,
                       {'gate_id': _token(gate_id)})

    def _definition(self, state, command, *, require_active=True):
        run = state.get('runs', {}).get(command.target)
        if run is None:
            raise LedgerError('UNKNOWN_RUN')
        if run['generation'] != command.generation:
            raise LedgerError('STALE_RUN_GENERATION')
        if require_active and run['status'] != 'ACTIVE':
            raise LedgerError('RUN_NOT_ACTIVE')
        if (run['project_id'] != self.binding.project_id
                or run['repository'] != self.binding.repository):
            raise LedgerError('GATE_BINDING_MISMATCH')
        # Recompile the persisted snapshot, not current installation config.
        # Derived fields are removed before compilation, then compared exactly;
        # corrupt/unsupported snapshots can never degrade to fewer Checks.
        policy = deepcopy(run['policy'])
        for gate in policy.get('gates', []):
            for key in ('source', 'scope', 'freshness', 'dependencies', 'guarded_operations'):
                gate.pop(key, None)
        try:
            compiled = compile_policy(policy, 'run.policy')
        except (ValueError, KeyError, TypeError) as error:
            raise LedgerError('INVALID_GATE_POLICY') from error
        if compiled != run['policy']:
            raise LedgerError('INVALID_GATE_POLICY')
        gate = next((g for g in compiled['gates'] if g['id'] == command.payload['gate_id']), None)
        if gate is None:
            raise LedgerError('UNKNOWN_GATE')
        return run, compiled, gate

    def _source_dependencies(self, run):
        return {'room_instance': self.binding.room_instance,
                'project_id': self.binding.project_id, 'repository': self.binding.repository,
                'run_id': run['run_id'], 'participant_id': run['participant_id'],
                'branch': run['checkout']['branch'], 'slot_id': run['checkout']['slot']}

    @staticmethod
    def _checkout_digest(run):
        # Canonical ownership binding, not mutable worktree observations. Dirty
        # files and observed_head are never revision evidence or dependencies.
        return _digest({k: run['checkout'][k] for k in (
            'slot', 'path', 'branch', 'base', 'run', 'participant', 'active', 'phase', 'identity')
            if k in run['checkout']})

    def _source(self, source, run):
        validate_source(source)
        expected = self._source_dependencies(run)
        if any(source[k] != v for k, v in expected.items()):
            raise LedgerError('GATE_SOURCE_MISMATCH')
        return deepcopy(source)

    def _scope(self, command, run, policy, gate):
        return validate_scope({'version': 1, 'evaluation_id': self.evaluation_id(command.id), 'room_id': self.binding.room_id,
            'room_instance': self.binding.room_instance, 'project_id': self.binding.project_id,
            'repository': self.binding.repository, 'run_id': command.target,
            'generation': command.generation, 'participant_id': run['participant_id'],
            'policy_id': policy['id'], 'policy_version': policy['version'],
            'policy_digest': _digest(policy), 'gate_id': gate['id'],
            'config_digest': _digest(gate['config'])})

    def _row(self, evaluation_id):
        row = self.ledger.snapshot()['state'].get('gate_evaluations', {}).get(evaluation_id)
        if row is None:
            raise LedgerError('UNKNOWN_EVALUATION')
        return row

    @staticmethod
    def _view(row):
        # Historical attempt only; current eligibility requires projection().
        return deepcopy({k: row[k] for k in ('evaluation_id', 'scope', 'source', 'target',
            'phase', 'started', 'result', 'operational')})

    def _progress(self, evaluation_id, phase, payload, *, validate=None):
        command = Command('gate-' + phase.lower() + '-' + evaluation_id, 'gate.progress',
                          evaluation_id, None, payload)
        def decide(state, _):
            row = state['gate_evaluations'][evaluation_id]
            if row['result'] is not None:
                raise LedgerError('EVALUATION_ALREADY_TERMINAL')
            if validate is not None:
                validate(state, row)
            row['phase'] = phase
            if phase == 'TARGET_BOUND':
                row['target'] = deepcopy(payload['target'])
            elif phase == 'OBSERVED':
                row['observations'] = deepcopy(payload['observations'])
            elif phase == 'SOURCE_BOUND':
                row['helper_source'] = deepcopy(payload['helper_source'])
            elif phase == 'SUBJECT_VERIFIED':
                row['subject_observation'] = deepcopy(payload)
            # Padding was reserved before effects. Transfer space rather than
            # requiring newly available ledger capacity after the helper ran.
            padding = row['reservation'].get('projection', '')
            used = len(_json(payload).encode()) + 4096
            if used > len(padding):
                raise LedgerError('GATE_EVIDENCE_LIMIT')
            row['reservation']['projection'] = padding[:-used]
            _capacity(state)
            return Transition(state, (Event('gate.' + phase.lower().replace('_', '-'),
                {'evaluation_id': evaluation_id, **payload}),), {'evaluation_id': evaluation_id})
        self.ledger.apply(command, _CONTROL, authorize=lambda *_: True, decide=decide)

    def evaluate(self, operation_id, run_id, generation, gate_id, *, origin):
        """Evaluate once; exact retries read the original attempt, never relaunch."""
        self._require_owner()
        command = self._command(operation_id, run_id, generation, gate_id)
        receipt = self.ledger.exact_receipt(command, origin, authorize=self.authorize)
        if receipt is not None:
            return self._view(self._row(receipt['result']['evaluation_id']))
        run, policy, gate = self._definition(self.ledger.snapshot()['state'], command)
        if gate.get('evaluator') not in ('artifacts', 'command', 'diff-claims'):
            raise LedgerError('UNSUPPORTED_REPOSITORY_GATE')
        expected_profile = {'artifacts': PROFILE_ID, 'command': 'command-v1-source',
                            'diff-claims': 'diff-claims-v1-source'}[gate['evaluator']]
        if getattr(self.control, 'profile', PROFILE_ID) != expected_profile:
            raise LedgerError('GATE_PROFILE_UNAVAILABLE')
        # This is an inert bounded ownership/ref read, not source Git execution.
        source = self._source(self.control.resolve(run_id, run['participant_id'], self.binding.room_instance,
                            run['gate_target']) if gate['evaluator'] == 'diff-claims' else
                            self.control.resolve(run_id, run['participant_id'], self.binding.room_instance), run)
        scope = self._scope(command, run, policy, gate)
        checkout_digest = self._checkout_digest(run)
        created = False
        def reserve(state, _):
            nonlocal created
            fresh_run, fresh_policy, fresh_gate = self._definition(state, command)
            if self._scope(command, fresh_run, fresh_policy, fresh_gate) != scope:
                raise LedgerError('GATE_DEPENDENCY_CHANGED')
            if self._checkout_digest(fresh_run) != checkout_digest:
                raise LedgerError('GATE_SOURCE_MISMATCH')
            if self._source(source, fresh_run) != source:
                raise LedgerError('GATE_SOURCE_MISMATCH')
            evaluations = state.setdefault('gate_evaluations', {})
            if len(evaluations) >= MAX_EVALUATIONS:
                raise LedgerError('GATE_HISTORY_CAPACITY')
            outstanding = [r for r in evaluations.values()
                           if r['reservation']['scratch_bytes']]
            if (len(outstanding) >= MAX_OUTSTANDING
                    or sum(r['reservation']['scratch_bytes'] for r in outstanding) + self.scratch_bytes
                    > self.binding.disk_bytes):
                raise LedgerError('GATE_RESOURCE_CAPACITY')
            if any(r['result'] is None and r['scope']['run_id'] == run_id
                   and r['scope']['generation'] == generation and r['scope']['gate_id'] == gate_id
                   for r in evaluations.values()):
                raise LedgerError('GATE_EVALUATION_IN_FLIGHT')
            row = {'evaluation_id': scope['evaluation_id'], 'scope': scope, 'source': source,
                'checkout_digest': checkout_digest,
                'items': deepcopy(gate['config'].get('items', [])),
                'evaluator': gate['evaluator'], 'config': deepcopy(gate['config']),
                'declaration': deepcopy(run.get('gate_declarations', {}).get(gate_id)) if gate['evaluator'] == 'diff-claims' else None,
                'target': None, 'phase': 'STARTED',
                'started': {'sequence': self.ledger.snapshot()['room_seq'] + 1, 'time': _now()},
                'origin': origin.canonical(), 'command': command.canonical(), 'result': None,
                'observations': None, 'helper_source': None,
                'operational': {'cleanup': False, 'quarantine_ref': None,
                                                     'attention': None},
                'reservation': {'scratch_bytes': self.scratch_bytes,
                                'projection': 'x' * PROJECTION_RESERVATION}}
            evaluations[scope['evaluation_id']] = row
            _capacity(state)
            created = True
            return Transition(state, (Event('gate.started', {k: row[k] for k in
                ('evaluation_id', 'scope', 'source', 'checkout_digest', 'items', 'evaluator', 'config', 'declaration', 'started')}),),
                {'evaluation_id': scope['evaluation_id']})
        receipt = self.ledger.apply(command, origin, authorize=self.authorize, decide=reserve)
        if not created:
            return self._view(self._row(receipt['result']['evaluation_id']))
        return self._execute(scope['evaluation_id'], command, origin)

    def _execute(self, evaluation_id, command, origin):
        row = self._row(evaluation_id)
        target, offer, observations, final = None, None, None, None
        cleanup = _unknown_cleanup(evaluation_id)
        fresh, reason = None, None
        finish_attempted = False
        try:
            target = self.control.prepare(row['scope'], row['source'])
            self._validate_target(target, row['source'])
            self._progress(evaluation_id, 'TARGET_BOUND', {'target': target})
            if self.control.current(row['source']) != row['source']:
                raise LedgerError('GATE_SOURCE_CHANGED_BEFORE_LAUNCH')
            def validate_launch(state, persisted):
                # Preparation can outlive a pause, generation fence, policy or
                # checkout change. Recheck under the same transaction that
                # reserves this launch; an authorization callback alone does
                # not establish current Run/source applicability.
                if self.authorize(origin, command) is not True:
                    raise LedgerError('FORBIDDEN')
                run, policy, gate = self._definition(state, command)
                if self._scope(command, run, policy, gate) != persisted['scope']:
                    raise LedgerError('GATE_DEPENDENCY_CHANGED')
                self._source(persisted['source'], run)
                if self._checkout_digest(run) != persisted['checkout_digest']:
                    raise LedgerError('GATE_SOURCE_MISMATCH')
            self._progress(evaluation_id, 'LAUNCH_RESERVED', {}, validate=validate_launch)
            offer = self.control.start(row['scope'], target, row['config'] if row.get('evaluator') in ('command', 'diff-claims')
                                       else [i['path'] for i in row['items']])
            helper_source = offer.document()
            self._validate_helper_source(helper_source, row['scope'], target,
                profile={'command': 'command-v1-source', 'diff-claims': 'diff-claims-v1-source'}.get(row.get('evaluator'), PROFILE_ID))
            self._progress(evaluation_id, 'SOURCE_BOUND', {'helper_source': helper_source})
            observations, final = self._observations(offer, row, target)
            self._progress(evaluation_id, 'OBSERVED', {'observations': observations})
            offer.acknowledge_final(final)
            if offer.confirm_exit() is not True:
                raise LedgerError('GATE_HELPER_EXIT_UNCONFIRMED')
            finish_attempted = True
            candidate = self.control.finish(target, offer)
            self._validate_cleanup(candidate)
            if candidate['launch_state'] != 'exited':
                raise LedgerError('GATE_HELPER_EXIT_UNCONFIRMED')
            cleanup = candidate
            if cleanup['cleanup'] is not True:
                raise LedgerError('GATE_CLEANUP_FAILED')
            if cleanup.get('post_target') != target:
                raise LedgerError('GATE_TARGET_CHANGED')
            fresh = self.control.current(row['source'])
            self._source(fresh, {'run_id': row['scope']['run_id'],
                'participant_id': row['scope']['participant_id'],
                'checkout': {'branch': row['source']['branch'], 'slot': row['source']['slot_id']}})
        except Exception as error:
            reason = self._error_code(error)
            # No blind retry, including a start whose outcome is unknown. The
            # Supervisor can remove only never-launched or exact-exited leases.
            if not finish_attempted:
                try:
                    candidate = self.control.abort(evaluation_id, target, offer)
                    self._validate_cleanup(candidate)
                    if offer is not None and candidate['launch_state'] == 'never-launched':
                        raise LedgerError('INVALID_GATE_CLEANUP')
                    cleanup = candidate
                except Exception:
                    cleanup = _unknown_cleanup(evaluation_id)
            elif cleanup.get('cleanup') is not True and cleanup.get('quarantine_ref') is None:
                # A failed/uncertain finish is quarantined, not an implicit
                # second cleanup attempt. Explicit recovery owns reconciliation.
                cleanup = _unknown_cleanup(evaluation_id)
        finally:
            if offer is not None:
                try:
                    offer.close()
                except Exception:
                    reason = reason or 'GATE_CHANNEL_CLOSE_FAILED'
        return self._complete(evaluation_id, command, origin, observations, cleanup, fresh, reason)

    @staticmethod
    def _error_code(error):
        code = getattr(error, 'code', '')
        return code if isinstance(code, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', code) else 'GATE_BOUNDARY_ERROR'

    @staticmethod
    def _validate_target(target, source):
        validate_target(target)
        if target['head_sha'] != source['head_sha'] or target['source_digest'] != source['source_digest']:
            raise LedgerError('GATE_TARGET_MISMATCH')
        for key in ('device', 'inode', 'entries', 'expanded_bytes'):
            if type(target[key]) is not int or not 0 <= target[key] < 2**63:
                raise LedgerError('INVALID_GATE_TARGET')

    @staticmethod
    def _validate_helper_source(value, scope, target, *, profile=PROFILE_ID):
        if (type(value) is not dict or set(value) != {'source', 'provenance', 'profile',
                'profile_digest', 'binding_digest', 'scope_digest'}
                or value['source'] != 'supervisor-one-shot-helper'
                or value['provenance'] != PROVENANCE or value['profile'] != profile
                or value['scope_digest'] != profile_scope_digest(profile, scope, target)
                or any(type(value[k]) is not str or not _HEX64.fullmatch(value[k])
                       for k in ('profile_digest', 'binding_digest'))):
            raise LedgerError('GATE_HELPER_BINDING_MISMATCH')

    @staticmethod
    def _validate_cleanup(proof, *, target_validator=validate_target):
        if (type(proof) is not dict or set(proof) != {'post_target', 'cleanup',
                'quarantine_ref', 'exit_confirmed', 'launch_state'}
                or type(proof['cleanup']) is not bool or type(proof['exit_confirmed']) is not bool
                or proof['launch_state'] not in ('never-launched', 'exited', 'unknown')
                or proof['exit_confirmed'] != (proof['launch_state'] == 'exited')
                or (proof['cleanup'] and proof['launch_state'] == 'unknown')):
            raise LedgerError('INVALID_GATE_CLEANUP')
        reference = proof.get('quarantine_ref')
        if reference is not None:
            _token(reference)
        if proof['cleanup'] is False and reference is None:
            raise LedgerError('INVALID_GATE_CLEANUP')
        if proof['cleanup'] is True and reference is not None:
            raise LedgerError('INVALID_GATE_CLEANUP')
        if proof['post_target'] is not None:
            target_validator(proof['post_target'])

    def _observations(self, offer, row, target):
        if row.get('evaluator') == 'command':
            from .gate_repository import command_observations
            records, size = [], 0
            for record in offer.records():
                size += len(_json(record).encode('utf-8'))
                if len(records) >= 9 or size > MAX_OBSERVATION_BYTES:
                    raise LedgerError('GATE_EVIDENCE_LIMIT')
                records.append(deepcopy(record))
            return command_observations(records, row['scope'], target, row['config'])
        # The offer checks the exact held kernel sender for every packet. This
        # independent reducer still rejects malformed facts, wrong correlation,
        # missing/duplicate/out-of-order/extra items and helper verdict claims.
        paths = [i['path'] for i in row['items']]
        records, size = [], 0
        for record in offer.records():
            size += len(_json(record).encode('utf-8'))
            if size > MAX_OBSERVATION_BYTES or len(records) >= len(paths) + 2:
                raise LedgerError('GATE_EVIDENCE_LIMIT')
            records.append(deepcopy(record))
        if len(records) != len(paths) + 2:
            raise LedgerError('GATE_INCOMPLETE_OBSERVATIONS')
        if (_json(records[0]) != _json(expected_header(row['scope'], target, paths))
                or _json(records[-1]) != _json(expected_header(row['scope'], target, paths, kind='final'))):
            raise LedgerError('GATE_CORRELATION_MISMATCH')
        for index, fact in enumerate(records[1:-1]):
            if (type(fact) is not dict or set(fact) != {'kind', 'index', 'path_digest',
                    'observed_type', 'length', 'nonempty', 'error'}
                    or fact['kind'] != 'item' or type(fact['index']) is not int
                    or fact['index'] != index or fact['path_digest'] != path_digest(paths[index])
                    or fact['observed_type'] not in ('file', 'directory', 'missing', 'error')
                    or type(fact['length']) is not int or not 0 <= fact['length'] <= MAX_BLOB_BYTES
                    or type(fact['nonempty']) is not bool or type(fact['error']) is not int):
                raise LedgerError('GATE_INVALID_OBSERVATION')
            kind = fact['observed_type']
            if ((kind != 'file' and fact['length'] != 0)
                    or (kind != 'directory' and fact['nonempty'] is not False)
                    or (kind != 'error' and fact['error'] != 0)
                    or (kind == 'error' and not 1 <= fact['error'] <= 4095)):
                raise LedgerError('GATE_INVALID_OBSERVATION')
        return records[1:-1], records[-1]

    def _complete(self, evaluation_id, command, origin, observations, cleanup, fresh, reason):
        terminal = Command('gate-terminal-' + evaluation_id, 'gate.completed', evaluation_id, None, {})
        def decide(state, _):
            row = state['gate_evaluations'][evaluation_id]
            if row['result'] is not None:
                raise LedgerError('EVALUATION_ALREADY_TERMINAL')
            changed = []
            error = reason
            if error is None and (_json(cleanup.get('post_target')) != _json(row['target'])
                                  or cleanup['cleanup'] is not True
                                  or cleanup['launch_state'] != 'exited'):
                error = 'GATE_TERMINAL_PROOF_MISMATCH'
            try:
                authorized = self.authorize(origin, command) is True
            except Exception:
                authorized = False
            if not authorized:
                error = 'GATE_AUTHORITY_REVOKED'
            try:
                run, policy, gate = self._definition(state, command)
                current_scope = self._scope(command, run, policy, gate)
                changed.extend(k for k, value in row['scope'].items() if current_scope[k] != value)
                # The canonical Run's checkout is a dependency too. A fresh
                # resolver response bound to the original slot cannot make an
                # independently changed Run checkout current at completion.
                source_now = fresh if fresh is not None else row['source']
                changed.extend(k for k, value in self._source_dependencies(run).items()
                               if source_now[k] != value)
                if self._checkout_digest(run) != row['checkout_digest']:
                    changed.append('checkout-binding')
            except LedgerError as invalid:
                changed.append(invalid.code)
            if fresh is not None:
                changed.extend(k for k in row['source'] if fresh[k] != row['source'][k])
            elif error is None:
                error = 'GATE_SOURCE_UNVERIFIED'
            checks, verdict = self._checks(row, observations, error)
            complete = {'sequence': self.ledger.snapshot()['room_seq'] + 1, 'time': _now()}
            result = {'evaluation_id': evaluation_id, 'scope': deepcopy(row['scope']),
                'target': deepcopy(row['target']), 'source': deepcopy(row['source']),
                'checkout_digest': row['checkout_digest'],
                'started': deepcopy(row['started']), 'completed': complete,
                'checks': checks, 'verdict': verdict, 'reason': error,
                'helper_source': deepcopy(row['helper_source']),
                'provenance': PROVENANCE, 'freshness_at_completion': {
                    'state': 'unknown' if fresh is None else 'stale' if changed else 'current',
                    'changed_dependencies': sorted(set(changed))},
                'cleanup': deepcopy(cleanup)}
            if 'subject_observation' in row:
                result['subject_observation'] = deepcopy(row['subject_observation'])
            row['result'], row['phase'] = result, 'TERMINAL'
            row['operational'] = {'cleanup': cleanup['cleanup'],
                'quarantine_ref': cleanup.get('quarantine_ref'),
                'attention': None if cleanup['cleanup'] else 'GATE_TARGET_QUARANTINED'}
            row['reservation']['projection'] = ''
            if cleanup['cleanup']:
                row['reservation']['scratch_bytes'] = 0
            _capacity(state)
            return Transition(state, (Event('gate.completed', result),), {'evaluation_id': evaluation_id})
        self.ledger.apply(terminal, _CONTROL, authorize=lambda *_: True, decide=decide)
        return self._view(self._row(evaluation_id))

    @staticmethod
    def _checks(row, observations, error):
        if row.get('evaluator') == 'command':
            fact = observations.get('exit') if type(observations) is dict else None
            if error is not None or fact is None:
                note, verdict = 'verification-incomplete', 'error'
            elif (fact['exit_code'] == 0 and fact['signal'] == 0 and not fact['timed_out']
                    and not fact['output_limited'] and not fact['descendants_terminated']):
                note, verdict = 'command-exit-zero', 'passed'
            else:
                note = ('command-timeout' if fact['timed_out'] else
                        'command-output-limit' if fact['output_limited'] else
                        'command-descendants-survived' if fact['descendants_terminated'] else
                        'command-signal' if fact['signal'] else 'command-nonzero-exit')
                verdict = 'failed'
            return [{'item': {'argv_digest': _digest(row['config']['argv']), 'cwd': row['config']['cwd']},
                'ok': verdict == 'passed', 'note': note,
                'evidence_refs': [row['evaluation_id'] + '/' + key for key in ('stdout', 'stderr', 'exit')]
                                 if observations is not None else []}], verdict
        checks, failed, errored = [], False, error is not None
        for index, item in enumerate(row['items']):
            fact = observations[index] if observations is not None else None
            note, ok = 'verification-incomplete', False
            if error is None and fact is not None:
                if fact['observed_type'] == 'error':
                    note, errored = 'artifact-read-error-' + str(fact['error']), True
                elif fact['observed_type'] == 'missing':
                    note, failed = 'artifact-missing', True
                elif fact['observed_type'] != item['type']:
                    note, failed = 'artifact-wrong-type', True
                elif item['nonempty'] and not (fact['length'] > 0 if item['type'] == 'file' else fact['nonempty']):
                    note, failed = 'artifact-empty', True
                else:
                    note, ok = 'artifact-present', True
            checks.append({'item': {'index': index, 'path_digest': hashlib.sha256(item['path'].encode()).hexdigest()},
                'ok': ok, 'note': note,
                'evidence_refs': [row['evaluation_id'] + '/item/' + str(index)] if fact is not None else []})
        return checks, 'error' if errored else 'failed' if failed else 'passed'

    def recover_interrupted(self, evaluation_id):
        """Trusted startup reconciliation after old Hub ownership is fenced.

        Never resumes helper launch or reuses provisional facts as an immutable
        pass. Unknown launched tasks retain their scratch reservation.
        """
        self._require_owner()
        row = self._row(_token(evaluation_id))
        if row['result'] is not None:
            return self._view(row)
        try:
            cleanup = self.control.abort(evaluation_id, row['target'], None)
            self._validate_cleanup(cleanup)
        except Exception:
            cleanup = _unknown_cleanup(evaluation_id)
        return self._complete(evaluation_id, Command(**row['command']), Origin(**{
            **row['origin'], 'capabilities': tuple(row['origin']['capabilities'])}),
            None, cleanup, None, 'GATE_INTERRUPTED_UNKNOWN')

    def reconcile_cleanup(self, evaluation_id):
        """Targeted trusted recovery; append cleanup fact, never rewrite verdict."""
        self._require_owner()
        row = self._row(_token(evaluation_id))
        if row['result'] is None:
            raise LedgerError('GATE_EVALUATION_IN_FLIGHT')
        if row['operational']['cleanup']:
            return self._view(row)
        proof = self.control.abort(evaluation_id, row['target'], None)
        self._validate_cleanup(proof)
        if not proof['cleanup']:
            return self._view(row)
        command = Command('gate-cleaned-' + evaluation_id, 'gate.cleaned', evaluation_id, None, {})
        def decide(state, _):
            current = state['gate_evaluations'][evaluation_id]
            current['operational'] = {'cleanup': True, 'quarantine_ref': None, 'attention': None}
            current['reservation']['scratch_bytes'] = 0
            return Transition(state, (Event('gate.cleaned', {'evaluation_id': evaluation_id}),), {})
        self.ledger.apply(command, _CONTROL, authorize=lambda *_: True, decide=decide)
        return self._view(self._row(evaluation_id))

    def projection(self, run_id, generation, gate_id, *, origin):
        """Read current dependencies; no evaluation or protected action starts."""
        self._require_owner()
        command = self._command('gate-projection', run_id, generation, gate_id)
        if self.authorize(origin, command) is not True:
            raise LedgerError('FORBIDDEN')
        state = self.ledger.snapshot()['state']
        run, policy, gate = self._definition(state, command, require_active=False)
        rows = [r for r in state.get('gate_evaluations', {}).values()
                if r['scope']['run_id'] == run_id and r['scope']['gate_id'] == gate_id]
        if not rows:
            return {'gate_id': gate_id, 'state': 'missing', 'evaluation_id': None}
        row = max(rows, key=lambda r: r['started']['sequence'])
        expected = self._scope(Command(row['command']['id'], command.kind, run_id,
                                      generation, command.payload), run, policy, gate)
        changed = [k for k in expected if expected[k] != row['scope'][k]]
        if self._checkout_digest(run) != row['checkout_digest']:
            changed.append('checkout-binding')
        if run['status'] != 'ACTIVE':
            changed.append('run-status')
        if row['result'] is None:
            return {'gate_id': gate_id, 'state': 'stale' if changed else 'in-flight',
                    'evaluation_id': row['evaluation_id'], 'changed_dependencies': sorted(set(changed))}
        try:
            current = self.control.current(row['source'])
            self._source(current, run)
            changed.extend(k for k in current if current[k] != row['source'][k])
        except Exception:
            changed.append('source-unverifiable')
        return {'gate_id': gate_id, 'state': 'stale' if changed else row['result']['verdict'],
                'evaluation_id': row['evaluation_id'], 'changed_dependencies': sorted(set(changed)),
                'provenance': PROVENANCE}
