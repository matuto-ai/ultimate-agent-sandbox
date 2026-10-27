"""Bounded original workflow observations for the passive Manager projection.

Attribution follows only the named Run/Review owner event contracts. Arbitrary
command targets, peer payloads and event bodies are never displayed or inferred.
This is a chronological observation window, not intermediate state replay.
"""
from .manager_projection import ProjectionError, fact, timestamp, token


JOURNEY_WINDOW = 200
RUN_EVENTS = frozenset({'run.activated', 'run.paused', 'run.resumed', 'run.generation-fenced'})
REVIEW_EVENTS = frozenset({'review.submitted', 'review.result', 'review.human-control',
                           'review.completed', 'review.merge-observed',
                           'review.comment-requested', 'review.comment-settled',
                           'review.request-observed'})
VERDICTS = frozenset({'pass', 'changes-requested', 'human-needed'})
STAGES = frozenset({'REVIEWING', 'ATTENTION', 'IMPLEMENTING', 'READY_FOR_HUMAN',
                    'SUPERSEDED', 'COMPLETED'})


def project_journey(snapshot, events):
    cut = snapshot['room_seq']
    first = max(0, cut - JOURNEY_WINDOW)
    if type(events) is not list or len(events) != cut - first:
        raise ProjectionError('JOURNEY_RANGE_INCOMPLETE')
    runs = snapshot['state'].get('runs', {})
    rows = {}
    for sequence, event in enumerate(events, first + 1):
        if (type(event) is not dict or event.get('room_id') != snapshot['room_id']
                or event.get('room_seq') != sequence):
            raise ProjectionError('JOURNEY_RANGE_INCOMPLETE')
        kind = event['kind']
        if kind not in RUN_EVENTS | REVIEW_EVENTS:
            continue
        payload = event.get('payload')
        if type(payload) is not dict:
            raise ProjectionError('INVALID_JOURNEY_EVENT')
        if kind in RUN_EVENTS:
            # These owner events explicitly carry their resulting Run binding;
            # admission commands may target the Project, not the new Run.
            run_id, generation = payload.get('run_id'), payload.get('generation')
            detail = payload
        else:
            # RunReview dispatch constructs these exact event envelopes with
            # target=run_id and command generation. No other target is relabeled.
            run_id, generation = event.get('target'), event.get('generation')
            detail = payload.get('review') if kind == 'review.human-control' else payload
        if run_id not in runs:
            continue  # Admission failures/unretained Runs are not live Run facts.
        if (type(generation) is not int or not 0 <= generation <= runs[run_id]['generation']
                or type(detail) is not dict):
            raise ProjectionError('INVALID_JOURNEY_EVENT')
        if kind in REVIEW_EVENTS and detail.get('generation', generation) != generation:
            raise ProjectionError('INVALID_JOURNEY_EVENT')
        row = {'run_id': token(run_id), 'generation': generation, 'kind': token(kind),
               'observed_version': sequence, 'observed_at': timestamp(event['timestamp'])}
        # A later human control/merge observation may retain the previous
        # aggregate result. Only the result event is a new review return.
        if kind == 'review.result' and detail.get('result') in VERDICTS:
            row['verdict'] = detail['result']
        if detail.get('stage') in STAGES:
            row['stage'] = detail['stage']
        rows[str(sequence)] = row
    return fact('hub', cut, value={'from_seq': first + 1, 'through_seq': cut,
        'completeness': 'complete-supported-window' if first == 0 else 'partial-supported-window',
        'events': rows}, freshness='unknown', reason='SUPPORTED_WORKFLOW_EVENTS_ONLY')


def validate_journey(value):
    if (type(value) is not dict or set(value) != {'from_seq', 'through_seq', 'completeness', 'events'}
            or type(value['from_seq']) is not int or type(value['through_seq']) is not int
            or not 0 <= value['through_seq'] < 2**63
            or value['from_seq'] != max(0, value['through_seq'] - JOURNEY_WINDOW) + 1
            or value['completeness'] != ('complete-supported-window' if value['from_seq'] == 1 else 'partial-supported-window')
            or type(value['events']) is not dict or len(value['events']) > JOURNEY_WINDOW):
        raise ProjectionError('INVALID_JOURNEY_WINDOW')
    previous = 0
    # JSON canonicalization sorts string keys lexically, so explicitly order by
    # their validated sequence rather than trusting object insertion order.
    for key in value['events']:
        if type(key) is not str or not key.isascii() or not key.isdigit() or str(int(key)) != key:
            raise ProjectionError('INVALID_JOURNEY_EVENT')
    for key in sorted(value['events'], key=int):
        row = value['events'][key]
        if (type(row) is not dict or set(row) - {'run_id', 'generation', 'kind', 'observed_version', 'observed_at', 'verdict', 'stage'}
                or not {'run_id', 'generation', 'kind', 'observed_version', 'observed_at'} <= row.keys()
                or type(row['generation']) is not int or not 0 <= row['generation'] < 2**63
                or type(row['observed_version']) is not int or row['observed_version'] != int(key)
                or not max(previous, value['from_seq'] - 1) < int(key) <= value['through_seq']
                or type(row['kind']) is not str or row['kind'] not in RUN_EVENTS | REVIEW_EVENTS
                or 'verdict' in row and (row['kind'] != 'review.result'
                                        or type(row['verdict']) is not str or row['verdict'] not in VERDICTS)
                or 'stage' in row and (type(row['stage']) is not str or row['stage'] not in STAGES)):
            raise ProjectionError('INVALID_JOURNEY_EVENT')
        token(row['run_id']); timestamp(row['observed_at'])
        previous = int(key)
