"""Passive, allowlisted Manager facts; never an authority or a refresh request.

Every section is a fact envelope. Its provenance applies to every value beneath
it; collections from different owners are never combined under one envelope.
Missing owners are unavailable, not an empty collection or a successful check.
No Project text, instructions, config, command output, credentials, raw
Forge responses, or native session identifiers are copied to this read model.
The explicitly required checkout host path is metadata, never a diagnostic.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import json
import re


SCHEMA_VERSION = 1
MAX_PROJECTION_BYTES = 524_288
MAX_ROWS = 1024
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z')


class ProjectionError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def token(value):
    if type(value) is not str or not TOKEN.fullmatch(value):
        raise ProjectionError('INVALID_IDENTIFIER')
    return value


def timestamp(value):
    if type(value) is not str or len(value) > 40:
        raise ProjectionError('INVALID_TIMESTAMP')
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() is None:
            raise ValueError()
    except ValueError:
        raise ProjectionError('INVALID_TIMESTAMP') from None
    return value


def canonical(value):
    try:
        result = json.dumps(value, sort_keys=True, separators=(',', ':'),
                            ensure_ascii=False, allow_nan=False)
        if len(result.encode()) > MAX_PROJECTION_BYTES:
            raise ProjectionError('PROJECTION_LIMIT')
        return result
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ProjectionError('INVALID_PROJECTION') from None


def _scalar(value):
    if value is None or type(value) is bool:
        return value
    if type(value) is int and 0 <= value < 2**63:
        return value
    if type(value) is str:
        return token(value)
    raise ProjectionError('INVALID_SOURCE_FACT')


def _fields(row, fields):
    if type(row) is not dict:
        raise ProjectionError('INVALID_SOURCE_FACT')
    result = {}
    for key in fields:
        if key not in row:
            continue
        if key == 'path':
            value = row[key]
            if (type(value) is not str or not value.startswith('/') or len(value) > 4096
                    or '..' in value.split('/') or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise ProjectionError('INVALID_CHECKOUT_PATH')
            result[key] = value
        elif key in {'working_tree_observed_at', 'observation_time', 'updated_at'}:
            result[key] = None if row[key] is None else timestamp(row[key])
        elif key == 'review_reference':
            value = row[key]
            if value is not None and (type(value) is not str or len(value) > 1024 or not re.fullmatch(
                    r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[1-9][0-9]*#pullrequestreview-[1-9][0-9]*', value)):
                raise ProjectionError('INVALID_REVIEW_REFERENCE')
            result[key] = value
        else:
            result[key] = _scalar(row[key])
    return result


def _rows(rows, fields):
    if type(rows) is not dict or len(rows) > MAX_ROWS:
        raise ProjectionError('INVALID_SOURCE_FACT')
    return {token(key): _fields(row, fields) for key, row in sorted(rows.items())}


def fact(owner, version, *, value=None, observed_at=None, source_committed_at=None, status='known',
         freshness='unknown', reason=None):
    token(owner)
    if version is not None and (type(version) is not int or not 0 <= version < 2**63):
        raise ProjectionError('INVALID_SOURCE_VERSION')
    if observed_at is not None:
        timestamp(observed_at)
    if source_committed_at is not None:
        timestamp(source_committed_at)
    if status not in {'known', 'unknown', 'unavailable', 'failed'}:
        raise ProjectionError('INVALID_FACT_STATUS')
    if freshness not in {'current', 'stale', 'unknown'}:
        raise ProjectionError('INVALID_FRESHNESS')
    if reason is not None:
        token(reason)
    if status != 'known' and value is not None:
        raise ProjectionError('UNKNOWN_FACT_HAS_VALUE')
    return {'source_owner': owner, 'observed_version': version,
            'observed_at': observed_at, 'source_committed_at': source_committed_at,
            'status': status, 'freshness': freshness,
            'reason': reason, 'value': deepcopy(value)}


# These owners have no universal versioned passive snapshot API in the current
# source. This is a finite extension seam, not a caller-defined owner registry.
EXTERNAL_FIELDS = {
    'room_lifecycle': ('supervisor', ('phase', 'desired', 'authority', 'error')),
    'seats': ('supervisor', ('participant_id', 'actor_id', 'profile_id', 'runtime', 'enabled')),
    'processes': ('supervisor', ('participant_id', 'incarnation_id', 'epoch', 'state', 'reason')),
    'checkout_slots': ('supervisor', ('slot', 'run_id', 'participant_id', 'branch', 'path',
                                     'state', 'working_tree_state', 'working_tree_observed_at', 'reason')),
    'capabilities': ('supervisor', ('participant_id', 'implement', 'review', 'forge_read', 'forge_write')),
    'image_profile_drift': ('supervisor', ('expected_image_digest', 'expected_profile_digest',
        'actual_image_digest', 'actual_profile_digest', 'pending_image_digest',
        'pending_profile_digest', 'staged_update', 'state')),
    'provider_configuration': ('runtime-adapter', ('participant_id', 'provider_id', 'validity', 'reason')),
    'inference': ('runtime-adapter', ('participant_id', 'state', 'reason')),
    'quota': ('runtime-adapter', ('participant_id', 'source', 'account_ref', 'semantics', 'amount',
                                   'unit', 'state', 'reason')),
    'context_observations': ('runtime-adapter', ('participant_id', 'context_generation', 'used',
                                                   'limit', 'unit', 'state', 'reason')),
    'review': ('hub-review', ('run_id', 'generation', 'candidate_sha', 'submission_id', 'review_reference', 'reviewer_id',
                               'verdict', 'round', 'state', 'reason', 'updated_at')),
    'gate_truth': ('hub-gate', ('run_id', 'generation', 'gate_id', 'evaluation_id', 'state', 'reason',
        'observed_state', 'observed_generation', 'observation_version', 'observation_time',
        'last_refresh_state', 'owner', 'checkpoint')),
    'pending_ci': ('hub-gate', ('run_id', 'generation', 'gate_id', 'evaluation_id', 'candidate_sha',
                               'owner', 'checkpoint', 'state', 'reason')),
    'dependencies': ('forge-broker', ('issue_id', 'issue_number', 'state', 'completeness',
        'repository', 'run_id', 'kind', 'blocked_issue_id', 'blocked_issue_number',
        'dependency_count', 'observation_version')),
    'forge_diagnostics': ('forge-broker', ('operation_id', 'state', 'error_code', 'contact',
                                          'completeness', 'audit_reference')),
}


@dataclass(frozen=True)
class SourceObservation:
    """Trusted owner capture, never accepted from a Manager or Participant frame.

    An integration must provide its own monotonic version and actual source
    observation timestamp. Polling time or a content hash is not that version.
    """
    section: str
    source_owner: str
    observed_version: int | None
    observed_at: str | None
    rows: dict | None
    status: str = 'known'
    freshness: str = 'unknown'
    reason: str | None = None
    source_committed_at: str | None = None

    def document(self):
        definition = EXTERNAL_FIELDS.get(self.section)
        if definition is None or definition[0] != self.source_owner:
            raise ProjectionError('SOURCE_OWNER_MISMATCH')
        if self.observed_version is not None and (type(self.observed_version) is not int or self.observed_version < 0):
            raise ProjectionError('INVALID_SOURCE_VERSION')
        if self.observed_at is not None:
            timestamp(self.observed_at)
        if self.observed_version is None and self.status == 'known':
            raise ProjectionError('KNOWN_FACT_WITHOUT_SOURCE_VERSION')
        rows = _rows(self.rows, definition[1]) if self.status == 'known' else None
        if self.status != 'known' and self.rows is not None:
            raise ProjectionError('UNKNOWN_FACT_HAS_VALUE')
        # Quota semantics are not inferred from a number or native readiness.
        if self.section == 'quota' and rows is not None:
            for row in rows.values():
                if row.get('semantics') not in {'consumed', 'remaining', 'unknown'}:
                    raise ProjectionError('QUOTA_SEMANTICS_REQUIRED')
        return fact(self.source_owner, self.observed_version, value=rows,
                    observed_at=self.observed_at, source_committed_at=self.source_committed_at, status=self.status,
                    freshness=self.freshness, reason=self.reason)


def project_hub(snapshot, *, captured_at, observations=()):
    """One already-atomic Hub cut, plus independently versioned owner captures.

    No calls to Gate.projection, Supervisor.status, native evidence(), Broker,
    filesystem, or network occur here. External captures are NOT an atomic cut
    with the Hub and are deliberately labeled separately.
    """
    if type(snapshot) is not dict or set(snapshot) != {'room_id', 'room_seq', 'state'}:
        raise ProjectionError('INVALID_HUB_SNAPSHOT')
    token(snapshot['room_id']); timestamp(captured_at)
    seq, state = snapshot['room_seq'], snapshot['state']
    if type(seq) is not int or not 0 <= seq < 2**63 or type(state) is not dict:
        raise ProjectionError('INVALID_HUB_SNAPSHOT')
    sections = {name: fact(owner, None, status='unavailable', reason='SOURCE_NOT_CONNECTED')
                for name, (owner, _) in EXTERNAL_FIELDS.items()}
    seen = set()
    for observation in observations:
        if type(observation) is not SourceObservation:
            raise ProjectionError('INVALID_OWNER_OBSERVATION')
        document = observation.document()
        if observation.section in seen:
            raise ProjectionError('DUPLICATE_OWNER_OBSERVATION')
        seen.add(observation.section)
        sections[observation.section] = document

    def hub(name, value, *, freshness='current'):
        sections[name] = fact('hub', seq, value=value, freshness=freshness)

    def missing(name, owner='hub'):
        sections[name] = fact(owner, seq, status='unavailable', reason='SOURCE_NOT_INITIALIZED')

    if 'runs' in state:
        hub('runs', _rows(state['runs'], ('run_id', 'generation', 'status', 'outcome', 'issue_number',
            'issue_id', 'repository', 'project_id', 'participant_id', 'actor_id', 'delivery_class',
            'context_generation', 'control_revision', 'control_reason', 'projection')))
        from .run_review import snapshot_review_run
        from .gate_evaluation import snapshot_gate_state
        retained_gates = snapshot_gate_state(snapshot, snapshot['room_id'])
        candidates, reviews, review_attention = retained_gates['candidates'], {}, {}
        for run_id, run in state['runs'].items():
            retained = snapshot_review_run(snapshot, snapshot['room_id'], run_id)
            review = retained['review']
            current = None if review is None else review['current']
            if current is None:
                continue
            target = current['target']
            stale = current['generation'] != run['generation'] or target != run.get('gate_target')
            if run_id not in candidates:
                candidates[run_id] = {'candidate_sha': target['head_sha'], 'pull_number': target['pull_number'],
                    'generation': current['generation'], 'state': 'stale' if stale else 'recorded'}
            reviewer = current['reviewer']
            reviews[run_id] = {'run_id': run_id, 'generation': current['generation'],
                'candidate_sha': target['head_sha'], 'submission_id': current['submission_id'],
                'review_reference': current['review_reference'],
                'reviewer_id': None if reviewer is None else reviewer['actor_id'],
                'verdict': current['result'], 'round': current['round'],
                'state': 'STALE' if stale else current['stage'],
                'reason': 'CANDIDATE_BINDING_CHANGED' if stale else current['reason'],
                'updated_at': current.get('updated_at')}
            if current['stage'] == 'ATTENTION' and not stale:
                review_attention[run_id] = {'review_state': current['stage'], 'review_reason': current['reason']}
        hub('candidate', _rows(candidates, ('candidate_sha', 'pull_number', 'generation', 'state')), freshness='unknown')
        if 'review' not in seen:
            sections['review'] = SourceObservation('review', 'hub-review', seq, None, reviews).document()
        hub('attention', {token(key): _fields(row, ('coordinator_attention', 'control_reason', 'status'))
                          for key, row in state['runs'].items()})
        for run_id, attention in review_attention.items():
            sections['attention']['value'][run_id].update(attention)
    else:
        for name in ('runs', 'candidate', 'attention'):
            missing(name)

    peer = state.get('peer_traffic')
    if type(peer) is dict:
        # Recorded attachment != a fresh process/connection health probe.
        hub('adapter_connections', _rows(peer.get('connections', {}),
            ('participant_id', 'incarnation_id', 'context_generation', 'attachment_id')),
            freshness='unknown')
        hub('readiness', _rows(peer.get('connections', {}), ('readiness',)), freshness='unknown')
        hub('last_observation', _rows(peer.get('connections', {}), ('observation_id',)), freshness='unknown')
        hub('work_requests', _rows({key: row for key, row in peer.get('traffic', {}).items()
            if row.get('kind') == 'peer.work-request'}, ('id', 'run_id', 'generation', 'sender',
                'status', 'attention', 'submitted_seq')))
    else:
        for name in ('adapter_connections', 'readiness', 'last_observation', 'work_requests'):
            missing(name)
    contexts = state.get('fixture_context', {}).get('participants')
    if contexts is not None:
        rows = {}
        for key, row in contexts.items():
            rows[token(key)] = {**_fields(row, ('context_generation', 'status')),
                'bound_run': None if row.get('bound_run') is None else
                    _fields(row['bound_run'], ('run_id', 'generation')),
                'reserved_run': None if row.get('reserved_run') is None else
                    _fields(row['reserved_run'], ('run_id', 'generation'))}
        hub('context_binding', rows)
    else:
        missing('context_binding')

    if 'gate_evaluations' in state:
        rows = {}
        for key, row in state['gate_evaluations'].items():
            result = row.get('result')
            rows[token(key)] = {**_fields(row, ('evaluation_id', 'phase')),
                'scope': _fields(row['scope'], ('run_id', 'generation', 'gate_id', 'participant_id')),
                'recorded_result': None if result is None else _fields(result, ('verdict', 'reason')),
                'operational': _fields(row.get('operational', {}), ('cleanup', 'attention')),
                'current_gate_truth': 'unknown'}
        hub('gate_history', rows, freshness='unknown')
    else:
        missing('gate_history')
    # A past immutable result cannot be relabeled as a currently passing Gate.
    if any('gates' in run.get('policy', {}) for run in state.get('runs', {}).values()):
        if 'gate_truth' not in seen:
            sections['gate_truth'] = SourceObservation('gate_truth', 'hub-gate', seq, None, retained_gates['gates']).document()
        if 'pending_ci' not in seen:
            sections['pending_ci'] = SourceObservation('pending_ci', 'hub-gate', seq, None, retained_gates['pending_ci']).document()
    if sections['gate_truth']['observed_version'] is None:
        sections['gate_truth'] = fact('hub-gate', None, status='unknown', reason='FRESH_OWNER_OBSERVATION_REQUIRED')

    if 'forge_projections' in state:
        rows = {}
        for key, row in state['forge_projections'].items():
            desired, observed = row['desired'], row.get('observed')
            rows[token(key)] = {**_fields(row, ('state', 'reason', 'attribution', 'audit_reference')),
                'desired_version': _scalar(desired['version']),
                'observed_status': None if observed is None else _scalar(observed['status']),
                'observed_completeness': None if observed is None else _scalar(observed['completeness'])}
        hub('lifecycle_label_drift', rows, freshness='unknown')
    else:
        missing('lifecycle_label_drift')
    result = {'schema_version': SCHEMA_VERSION, 'room_id': snapshot['room_id'],
              'room_seq': seq, 'captured_at': captured_at, 'sections': sections}
    canonical(result)
    return result


HUB_FIELDS = {
    'runs': ('run_id', 'generation', 'status', 'outcome', 'issue_number', 'issue_id', 'repository',
             'project_id', 'participant_id', 'actor_id', 'delivery_class', 'context_generation',
             'control_revision', 'control_reason', 'projection'),
    'candidate': ('candidate_sha', 'pull_number', 'generation', 'state'),
    'attention': ('coordinator_attention', 'control_reason', 'status', 'review_state', 'review_reason'),
    'adapter_connections': ('participant_id', 'incarnation_id', 'context_generation', 'attachment_id'),
    'readiness': ('readiness',), 'last_observation': ('observation_id',),
    'work_requests': ('id', 'run_id', 'generation', 'sender', 'status', 'attention', 'submitted_seq'),
    'lifecycle_label_drift': ('state', 'reason', 'attribution', 'audit_reference', 'desired_version',
                            'observed_status', 'observed_completeness'),
}


def validate_section_value(section, value):
    """Also enforce the disclosure allowlist on the receiving side."""
    if section in EXTERNAL_FIELDS or section in HUB_FIELDS:
        fields = EXTERNAL_FIELDS[section][1] if section in EXTERNAL_FIELDS else HUB_FIELDS[section]
        if _rows(value, fields) != value:
            raise ProjectionError('UNSUPPORTED_PROJECTED_FIELD')
        if section == 'quota' and any(row.get('semantics') not in {'consumed', 'remaining', 'unknown'}
                                      for row in value.values()):
            raise ProjectionError('QUOTA_SEMANTICS_REQUIRED')
        return
    if type(value) is not dict or len(value) > MAX_ROWS:
        raise ProjectionError('INVALID_SOURCE_FACT')
    for key, row in value.items():
        token(key)
        if section == 'context_binding':
            if type(row) is not dict or set(row) - {'context_generation', 'status', 'bound_run', 'reserved_run'}:
                raise ProjectionError('UNSUPPORTED_PROJECTED_FIELD')
            _fields(row, ('context_generation', 'status'))
            for field in ('bound_run', 'reserved_run'):
                nested = row.get(field)
                if nested is not None and _fields(nested, ('run_id', 'generation')) != nested:
                    raise ProjectionError('UNSUPPORTED_PROJECTED_FIELD')
        elif section == 'gate_history':
            if type(row) is not dict or set(row) != {'evaluation_id', 'phase', 'scope',
                    'recorded_result', 'operational', 'current_gate_truth'} or row['current_gate_truth'] != 'unknown':
                raise ProjectionError('UNSUPPORTED_PROJECTED_FIELD')
            _fields(row, ('evaluation_id', 'phase'))
            for field, allowed in (('scope', ('run_id', 'generation', 'gate_id', 'participant_id')),
                                   ('operational', ('cleanup', 'attention')),
                                   ('recorded_result', ('verdict', 'reason'))):
                nested = row[field]
                if nested is not None and _fields(nested, allowed) != nested:
                    raise ProjectionError('UNSUPPORTED_PROJECTED_FIELD')
        else:
            raise ProjectionError('UNSUPPORTED_PROJECTED_SECTION')
