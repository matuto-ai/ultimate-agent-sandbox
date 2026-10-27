"""Finite passive exports of facts held by existing authoritative owners.

The two optional metadata fields are written with the owner's existing atomic
manifest save. They version persisted facts; they are NOT process observation
times. No fallback version is minted for an old manifest or a failed read.
"""
from datetime import datetime, timezone

from .manager_projection import ProjectionError, SourceObservation, timestamp


REVISION_FIELDS = frozenset({'observation_revision', 'observation_committed_at'})


def validate_revision(state):
    present = REVISION_FIELDS & state.keys()
    if present and present != REVISION_FIELDS:
        raise ValueError('incomplete source revision')
    if present:
        if type(state['observation_revision']) is not int or not 1 <= state['observation_revision'] < 2**63:
            raise ValueError('invalid source revision')
        try:
            timestamp(state['observation_committed_at'])
        except ProjectionError:
            raise ValueError('invalid source commit timestamp') from None


def advance_revision(state):
    validate_revision(state)
    revision = state.get('observation_revision', 0)
    if revision == 2**63 - 1:
        raise ValueError('source revision exhausted')
    state.update(observation_revision=revision + 1,
                 observation_committed_at=datetime.now(timezone.utc).isoformat())


def _owned(section, state, rows):
    validate_revision(state)
    revision = state.get('observation_revision')
    return SourceObservation(section, 'supervisor', revision, None,
        rows if revision is not None else None,
        status='known' if revision is not None else 'unknown', freshness='unknown',
        reason=None if revision is not None else 'OWNER_REVISION_UNAVAILABLE',
        source_committed_at=state.get('observation_committed_at'))


def lifecycle_observations(state):
    if state is None:
        return tuple(SourceObservation(section, 'supervisor', None, None, None,
                status='unknown', reason='OWNER_REVISION_UNAVAILABLE')
                for section in ('room_lifecycle', 'image_profile_drift'))
    spec, pending = state['spec'], state.get('pending_spec')
    return (
        _owned('room_lifecycle', state, {state['room_id']: {
            'phase': state['phase'], 'desired': state['desired'], 'authority': state['authority']}}),
        _owned('image_profile_drift', state, {state['room_id']: {
            'expected_image_digest': spec['image_id'], 'expected_profile_digest': spec['profile_digest'],
            'actual_image_digest': None, 'actual_profile_digest': None,
            'pending_image_digest': None if pending is None else pending['image_id'],
            'pending_profile_digest': None if pending is None else pending['profile_digest'],
            'staged_update': pending is not None, 'state': 'actual-image-profile-unknown'}}),
    )


def participant_observations(state):
    seats, processes, capabilities = {}, {}, {}
    for participant, row in state['seats'].items():
        seat = row['seat']
        seats[participant] = {key: seat[key] for key in ('participant_id', 'actor_id', 'profile_id', 'runtime')}
        # This is the persisted authority/lifecycle state, NOT a PID liveness
        # assertion. No PID, native session identifier or startup argv escapes.
        processes[participant] = {'participant_id': participant, 'incarnation_id': row['incarnation_id'],
                                  'epoch': row['epoch'], 'state': row['status'], 'reason': row['reason']}
        declared = seat['capabilities']
        capabilities[participant] = {'participant_id': participant, 'implement': 'implement' in declared,
            'review': 'review' in declared, 'forge_read': 'forge-read' in declared,
            'forge_write': 'forge-write' in declared}
    return (_owned('seats', state, seats), _owned('processes', state, processes),
            _owned('capabilities', state, capabilities))


def checkout_observations(state):
    rows = {key: {'slot': key, 'run_id': row['run'], 'participant_id': row['participant'],
                   'branch': row['branch'], 'path': row['path'], 'state': row['phase'],
                   'working_tree_state': 'unknown', 'reason': 'WORKING_TREE_NOT_OBSERVED'}
            for key, row in state['slots'].items()}
    return (_owned('checkout_slots', state, rows),)
