"""Exact-base/head diff Checks over the existing one-shot Evaluation lifecycle."""
from copy import deepcopy
import hashlib

from .artifact_protocol import validate_path
from .diff_protocol import (PROFILE_ID, artifact_source, validate_diff_source,
                            validate_diff_target, diff_correlation)
from .gate_evaluation import ArtifactGateHub, SCRATCH_BYTES, _digest
from .ledger import LedgerError, _json, _token


class DiffGateHub(ArtifactGateHub):
    scratch_bytes = 2 * SCRATCH_BYTES

    def __init__(self, ledger, binding, control, *, authorize, forge):
        super().__init__(ledger, binding, control, authorize=authorize)
        self.forge = forge

    def _source(self, source, run):
        validate_diff_source(source)
        super()._source(artifact_source(source), run)
        if (source['subject']['repository'] != self.binding.repository
                or 'gate_target' in run and source['subject'] != run['gate_target']):
            raise LedgerError('GATE_SOURCE_MISMATCH')
        return deepcopy(source)

    def _scope(self, command, run, policy, gate):
        scope = super()._scope(command, run, policy, gate)
        binding = run.get('gate_target_binding')
        if (type(binding) is not dict or binding.get('digest') != _digest(run.get('gate_target'))
                or binding.get('generation') != run['generation']
                or binding.get('policy_digest') != _digest(policy)):
            raise LedgerError('GATE_TARGET_BINDING_STALE')
        declaration = run.get('gate_declarations', {}).get(gate['id'])
        if (type(declaration) is not dict or set(declaration) != {'paths', 'subject', 'actor_id', 'generation'}
                or declaration['subject'] != run.get('gate_target')
                or declaration['generation'] != run['generation']
                or declaration['actor_id'] != run.get('actor_id')
                or type(declaration['paths']) is not list or len(declaration['paths']) > 128):
            raise LedgerError('GATE_DIFF_DECLARATION_MISSING_OR_STALE')
        for path in declaration['paths']: validate_path(path)
        if declaration['paths'] != sorted(set(declaration['paths']), key=lambda path: path.encode()):
            raise LedgerError('INVALID_GATE_DIFF_DECLARATION')
        scope['config_digest'] = _digest({'config': gate['config'], 'declaration': declaration})
        return scope

    @staticmethod
    def _validate_target(target, source):
        validate_diff_target(target); validate_diff_source(source, require_head=True)
        if (target['source_digest'] != source['binding_digest'] or target['subject'] != source['subject']
                or target['head']['head_sha'] != source['head_sha']
                or any(target[side]['source_digest'] != source['source_digest'] for side in ('base','head'))):
            raise LedgerError('GATE_TARGET_MISMATCH')
        if any(not 0 <= target[side][key] < 2**63 for side in ('base','head')
               for key in ('device','inode','entries','expanded_bytes')):
            raise LedgerError('INVALID_GATE_TARGET')

    @staticmethod
    def _validate_cleanup(proof):
        ArtifactGateHub._validate_cleanup(proof, target_validator=validate_diff_target)

    def _observations(self, offer, row, target):
        correlation = diff_correlation(row['scope'], target, row['config'])
        records, size = [], 0
        for record in offer.records():
            size += len(_json(record).encode())
            if size > 128 << 10 or len(records) >= 130:
                raise LedgerError('GATE_EVIDENCE_LIMIT')
            records.append(deepcopy(record))
        if (len(records) < 2 or records[0] != {'kind': 'header', 'correlation': correlation}
                or type(records[-1]) is not dict or set(records[-1]) != {'kind', 'correlation', 'count'}
                or records[-1]['kind'] != 'final' or records[-1]['correlation'] != correlation
                or type(records[-1]['count']) is not int or records[-1]['count'] != len(records) - 2):
            raise LedgerError('GATE_INCOMPLETE_OBSERVATIONS')
        paths = []
        for index, record in enumerate(records[1:-1]):
            if (type(record) is not dict or set(record) != {'kind', 'index', 'path'}
                    or record['kind'] != 'path' or type(record['index']) is not int or record['index'] != index):
                raise LedgerError('GATE_INVALID_OBSERVATION')
            validate_path(record['path']); paths.append(record['path'])
        if paths != sorted(set(paths), key=lambda path: path.encode()):
            raise LedgerError('GATE_INVALID_OBSERVATION')
        return {'paths': paths, 'correlation': correlation}, records[-1]

    @staticmethod
    def _checks(row, observations, error):
        if error is not None or observations is None:
            return [{'item': 'diff-claims', 'ok': False, 'note': 'verification-incomplete', 'evidence_refs': []}], 'error'
        actual, claimed = observations['paths'], row['declaration']['paths']
        ref = row['evaluation_id'] + '/diff-paths'
        checks = [{'item': 'declared-file-set', 'ok': actual == claimed,
            'note': 'exact-set-equality' if actual == claimed else 'declared-diff-mismatch', 'evidence_refs': [ref, row['evaluation_id'] + '/subject']}]
        config = row['config']
        if config['require_nonempty']:
            checks.append({'item': 'nonempty-declaration', 'ok': bool(claimed),
                           'note': 'required-nonempty-declaration', 'evidence_refs': [ref]})
        for path in actual:
            permitted = ((not config['allowed_paths'] or path in config['allowed_paths'])
                         and path not in config['forbidden_paths'])
            checks.append({'item': {'path_digest': hashlib.sha256(path.encode()).hexdigest()},
                'ok': permitted, 'note': 'allowed-diff-path' if permitted else 'forbidden-diff-path',
                'evidence_refs': [ref]})
        return checks, 'passed' if all(check['ok'] for check in checks) else 'failed'

    def _complete(self, evaluation_id, command, origin, observations, cleanup, fresh, reason):
        # This is outside the RoomLedger transaction. A fresh Broker re-read
        # follows the helper wait; a cached target binding never authorizes pass.
        row = self._row(evaluation_id)
        if reason is None:
            try:
                from .gate_forge import validate_target_observation
                if self.forge is None: raise LedgerError('GATE_FORGE_UNAVAILABLE')
                def authorized():
                    try:
                        run, policy, gate = self._definition(self.ledger.snapshot()['state'], command)
                        return (self.authorize(origin, command) is True
                            and self._scope(command, run, policy, gate) == row['scope']
                            and self._source(self.control.current(row['source']), run) == row['source'])
                    except Exception:
                        return False
                response = self.forge.observe_target(row['source']['subject'],
                    'diff-final-' + evaluation_id, authorize=authorized)
                if type(response) is not dict or set(response) != {'observation', 'audit_reference'}:
                    raise LedgerError('INVALID_FORGE_OBSERVATION')
                _token(response['audit_reference'])
                proof = validate_target_observation(response['observation'], row['source']['subject'])
                if proof['status'] != 'OK': raise LedgerError('GATE_DIFF_SUBJECT_CHANGED')
                # Preserve Broker provenance in raw evidence before terminal
                # reduction; no standalone JSON fact is an authenticated source.
                self._progress(evaluation_id, 'SUBJECT_VERIFIED', {
                    'audit_reference': response['audit_reference'], 'observation': proof})
                fresh = self.control.current(row['source'])
            except Exception as error:
                reason = self._error_code(error)
        return super()._complete(evaluation_id, command, origin, observations, cleanup, fresh, reason)
