"""Pure/file/SQLite read-model → Field Notes fixtures; no process or browser.

The existing check.cjs consumes documents produced here. Hub event inputs are
controlled fixtures, not a claim of live GitHub, native Runtime or login proof.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from uas.ledger import Command, Event, Origin, RoomLedger, Transition
from uas.manager_journey import JOURNEY_WINDOW, project_journey
from uas.manager_projection import ProjectionError, SourceObservation, LIBRARY_FIELDS
from uas.manager_stream import ManagerReadModel, RoomIdentity, RoomStream, StreamError, validate_projection
from uas.manager_transport import ManagerSession
from uas.manager_ui import BOOTSTRAP, FieldNotesDocument, ProjectBinding


ROOT = Path(__file__).resolve().parents[1]
ORIGIN = Origin('actor', 'participant', 'incarnation', 'epoch', ())
TIME = '2026-10-27T20:00:00+00:00'


def install(stream, session, cursor, now):
    transfer = stream.capture(cursor, captured_at=now)
    session.handle({'kind': 'begin', 'transfer': transfer.begin()})
    while cursor is not None and cursor < transfer.cut:
        response = session.handle({'kind': 'events', 'page': transfer.page(cursor)})
        cursor = response['room_seq']
    session.handle({'kind': 'finish', 'transfer_id': transfer.transfer_id})
    return transfer


def append(ledger, kind, payload, *, run_id='run-alpha', generation=1, state=None):
    sequence = ledger.snapshot()['room_seq'] + 1
    ledger.apply(Command('fixture-' + str(sequence), 'fixture.owner-event', run_id, generation, {}),
        ORIGIN, authorize=lambda *_: True, decide=lambda previous, _: Transition(
            deepcopy(previous if state is None else state), (Event(kind, deepcopy(payload)),), {}))


def initial_state():
    target = {'head_sha': 'a' * 40, 'pull_number': 123, 'repository': 'example/alpha'}
    run = {'run_id': 'run-alpha', 'generation': 1, 'status': 'PAUSED', 'project_id': 'alpha',
           'repository': 'example/alpha', 'issue_number': 76, 'issue_id': 176,
           'participant_id': 'alice', 'actor_id': 'alice', 'gate_target': target,
           'policy': {'gates': [{'id': 'mechanical', 'evaluator': 'artifacts'},
                                {'id': 'ci', 'evaluator': 'forge-state'}]}}
    review = {'generation': 1, 'target': target, 'submission_id': 'review-submission',
              'review_reference': 'https://github.com/example/alpha/pull/123#pullrequestreview-123',
              'reviewer': {'actor_id': 'bob'}, 'result': 'human-needed', 'round': 1,
              'stage': 'ATTENTION', 'reason': 'REVIEW_HUMAN_NEEDED', 'updated_at': TIME}
    evaluations = {
        'evaluation': {'evaluation_id': 'evaluation', 'scope': {'run_id': 'run-alpha',
            'generation': 1, 'gate_id': 'mechanical', 'participant_id': 'alice'},
            'phase': 'TERMINAL', 'started': {'sequence': 1},
            'result': {'verdict': 'pass', 'reason': 'EVIDENCE_RECORDED',
                       'completed': {'sequence': 1, 'time': TIME}}, 'operational': {}},
        'ci-evaluation': {'evaluation_id': 'ci-evaluation', 'scope': {'run_id': 'run-alpha',
            'generation': 1, 'gate_id': 'ci', 'participant_id': 'alice'},
            'phase': 'STARTED', 'started': {'sequence': 2}, 'result': None,
            'target': target, 'operational': {}}}
    return {'runs': {'run-alpha': run}, 'run_reviews': {'run-alpha': {'current': review}},
            'gate_evaluations': evaluations}


def library_observation(now, *, freshness='unknown', status='known', project='github.com/1001'):
    """Validated Library-owned metadata fixture, through real stream/cache/render.

    Owner generation, Git and authenticated Hub binding are separately covered by
    test_library_observations; no content or source fetch enters this UI fixture.
    """
    if status != 'known':
        return SourceObservation('library', 'library-service', None, None, None,
                                 status=status, reason='SOURCE_NOT_OBSERVED')
    row = dict.fromkeys(LIBRARY_FIELDS)
    row.update(project_identity=project, active_depth=2, parked_depth=1,
        oldest_age_seconds=120, adjudication_wait_seconds=60, published_drafts=3,
        completed_outcomes=None, drain_state='BLOCKED', drain_id='drain-alpha', attempt=1,
        retry_count=0, queue_status='known', projection_state='current',
        canonical_sha='c' * 40, projected_sha='c' * 40, projected_at=now, replay_lag=0,
        window_start=now, window_end=now, coverage='complete', provider_state='unknown',
        provider_mode='unknown', effectiveness='unmeasured', feedback='unmeasured',
        capture_failures=0, source_failures=1, model_failures=0, validation_failures=0,
        transport_failures=0, audit_failures=0, recovery_failures=0)
    return SourceObservation('library', 'library-service', 1, now, {project: row},
                             freshness=freshness)


def observations(now):
    values = {
        'seats': ('supervisor', {'alice': {'participant_id': 'alice', 'actor_id': 'alice',
            'profile_id': 'implementer', 'runtime': 'pi', 'enabled': True}}),
        'processes': ('supervisor', {'alice': {'participant_id': 'alice', 'state': 'ACTIVE', 'epoch': 3}}),
        'capabilities': ('supervisor', {'alice': {'participant_id': 'alice', 'implement': True, 'review': False}}),
        'checkout_slots': ('supervisor', {'primary': {'slot': 'primary', 'run_id': 'run-alpha',
            'participant_id': 'alice', 'branch': 'refs/heads/work', 'path': '/srv/project/alpha',
            'working_tree_state': 'unknown', 'working_tree_observed_at': None}}),
        'image_profile_drift': ('supervisor', {'alpha': {'state': 'drifted', 'staged_update': True}}),
        'forge_diagnostics': ('forge-broker', {'operation': {'operation_id': 'operation',
            'state': 'PARTIAL_MUTATION', 'completeness': 'partial', 'contact': 'possible',
            'audit_reference': 'audit/operation'}}),
        'quota': ('runtime-adapter', {'alice': {'participant_id': 'alice', 'source': 'provider-quota',
            'semantics': 'remaining', 'amount': 0, 'unit': 'requests', 'state': 'known'}}),
    }
    return tuple(SourceObservation(section, owner, 1, now, rows, freshness='unknown')
                 for section, (owner, rows) in values.items()) + (library_observation(now),)


def browser_documents(root, now):
    """Actual passive projection/transport/cache/document seam, account-free."""
    identity = RoomIdentity('deployment', 'alpha', 'stream-alpha')
    with RoomLedger(root / 'room.sqlite3', 'alpha') as ledger:
        model = ManagerReadModel(root / 'manager.sqlite3', stale_after_seconds=30)
        session = ManagerSession(model, identity)
        stream = RoomStream(ledger, identity)
        binding = ProjectBinding(identity, 'alpha', 'example/alpha')
        idle = ProjectBinding(RoomIdentity('deployment', 'beta', 'stream-beta'), 'beta', 'example/beta')
        ui = FieldNotesDocument(model, (binding, idle))
        try:
            state = initial_state()
            append(ledger, 'run.activated', state['runs']['run-alpha'], state=state)
            append(ledger, 'review.submitted', {**state['run_reviews']['run-alpha']['current'], 'result': None, 'stage': 'REVIEWING'})
            append(ledger, 'review.result', {**state['run_reviews']['run-alpha']['current'], 'result': 'changes-requested', 'stage': 'IMPLEMENTING'})
            append(ledger, 'review.human-control', {'review': {
                **state['run_reviews']['run-alpha']['current'], 'result': 'changes-requested', 'stage': 'IMPLEMENTING'}})
            append(ledger, 'review.result', state['run_reviews']['run-alpha']['current'])
            # Finite typed owner fixture observations enter through RoomStream,
            # never through HTML globals or a synthetic frontend scenario.
            transfer = stream.capture(None, captured_at=now, observations=observations(now))
            session.handle({'kind': 'begin', 'transfer': transfer.begin()})
            session.handle({'kind': 'finish', 'transfer_id': transfer.transfer_id})
            connected = ui.render(now=now)
            connected_data = ui.capture(now=now)
            # A fresh Hub cut never renews the older Library owner's sample.
            later = (datetime.fromisoformat(now) + timedelta(seconds=60)).isoformat()
            # Explicit producer freshness is distinct from current transport.
            current_observations = tuple(item for item in observations(now) if item.section != 'library') + (library_observation(now, freshness='current'),)
            current_stream = RoomStream(ledger, identity)
            current_transfer = current_stream.capture(None, captured_at=now, observations=current_observations)
            # Separate cache/stream to avoid changing a same-version observation.
            current_model = ManagerReadModel(root / 'current.sqlite3', stale_after_seconds=30)
            current_session = ManagerSession(current_model, identity)
            try:
                current_session.handle({'kind':'begin','transfer':current_transfer.begin()})
                current_session.handle({'kind':'finish','transfer_id':current_transfer.transfer_id})
                current_ui = FieldNotesDocument(current_model, (binding, idle))
                library_current = current_ui.render(now=now)
                # A later Hub capture carries the unchanged owner observation.
                current_session.close(); current_model.close()
                current_model = ManagerReadModel(root / 'stale.sqlite3', stale_after_seconds=30)
                current_session = ManagerSession(current_model, identity)
                current_ui = FieldNotesDocument(current_model, (binding, idle))
                older = current_stream.capture(None, captured_at=later, observations=current_observations)
                current_session.handle({'kind':'begin','transfer':older.begin()})
                current_session.handle({'kind':'finish','transfer_id':older.transfer_id})
                library_stale = current_ui.render(now=later)
                older = current_stream.capture(5, captured_at=later, observations=current_observations)
                current_session.close()
                current_session = ManagerSession(current_model, identity)
                current_session.handle({'kind':'begin','transfer':older.begin()})
                current_session.handle({'kind':'finish','transfer_id':older.transfer_id})
                library_stale_reconnected = current_ui.render(now=later)
            finally:
                current_session.close(); current_model.close()

            session.close()
            disconnected = ui.render(now=now)
            append(ledger, 'run.resumed', {'run_id': 'run-alpha', 'generation': 1, 'status': 'ACTIVE'})
            session = ManagerSession(model, identity)
            resumed = stream.capture(5, captured_at=now, observations=observations(now))
            session.handle({'kind': 'begin', 'transfer': resumed.begin()})
            catching_up = ui.render(now=now)
            session.handle({'kind': 'events', 'page': resumed.page(5)})
            session.handle({'kind': 'finish', 'transfer_id': resumed.transfer_id})
            reconnected = ui.render(now=now)
            return {'connected': connected, 'disconnected': disconnected, 'catching-up': catching_up,
                    'reconnected': reconnected, 'library-current': library_current, 'library-stale': library_stale, 'library-stale-reconnected': library_stale_reconnected}, connected_data
        finally:
            session.close(); model.close()


class ManagerUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.identity = RoomIdentity('deployment', 'alpha', 'stream-alpha')
        self.ledger = RoomLedger(self.root / 'room.sqlite3', 'alpha')
        self.model = ManagerReadModel(self.root / 'manager.sqlite3')
        self.session = ManagerSession(self.model, self.identity)
        self.addCleanup(self.model.close); self.addCleanup(self.session.close); self.addCleanup(self.ledger.close)

    def test_document_crosses_source_cache_renderer_and_never_invents_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            documents, data = browser_documents(Path(directory), TIME)
        self.assertIn('"journey"', documents['connected'])
        self.assertNotIn(BOOTSTRAP, documents['connected'])
        self.assertNotIn('Request confirmed', documents['connected'])
        self.assertNotIn('Approve candidate', documents['connected'])
        self.assertNotIn('Math.random', documents['connected'])
        self.assertEqual('unknown', next(iter(data['rooms'][0]['view']['projection']['sections']['gate_truth']['value'].values()))['state'])
        self.assertIn('"status":"disconnected"', documents['disconnected'])
        self.assertIn('"catching_up":true', documents['catching-up'])

    def test_library_fixture_is_strict_metadata_and_keeps_own_source_time(self):
        with tempfile.TemporaryDirectory() as directory:
            documents, data = browser_documents(Path(directory), TIME)
        source = data['rooms'][0]['view']['projection']['sections']['library']
        self.assertEqual(source['source_owner'], 'library-service')
        self.assertEqual(source['freshness'], 'unknown')
        self.assertEqual(source['observed_at'], TIME)
        self.assertEqual(source['value']['github.com/1001']['drain_state'], 'BLOCKED')
        self.assertIn('"freshness":"stale"', documents['library-stale'])
        for marker in ('PRIVATE_TITLE', 'PRIVATE_BODY', 'RAW_PROMPT', 'SECRET_MATCH'):
            self.assertNotIn(marker, json.dumps(data))
        bad = library_observation(TIME)
        bad.rows['github.com/1001']['title'] = 'PRIVATE_TITLE'
        with self.assertRaises(ProjectionError):
            bad.document()

    def test_v1_upgrade_same_cut_restart_and_replay_keep_old_event_shape(self):
        old = RoomStream(self.ledger, self.identity, schema_version=1)
        append(self.ledger, 'run.activated', {'run_id': 'run-alpha', 'generation': 1}, state=initial_state())
        install(old, self.session, None, TIME)
        self.assertNotIn('journey', self.model.view(self.identity, now=TIME)['projection']['sections'])
        new = RoomStream(self.ledger, self.identity)
        install(new, self.session, 1, TIME)
        self.assertEqual(2, self.model.view(self.identity, now=TIME)['projection']['schema_version'])
        with self.assertRaisesRegex(StreamError, 'PROJECTION_SCHEMA_REGRESSION'):
            install(old, self.session, 1, TIME)
        append(self.ledger, 'review.result', {'generation': 1, 'result': 'changes-requested'})
        transfer = install(new, self.session, 1, TIME)
        self.assertEqual({'source_owner', 'observed_version', 'kind', 'observed_at'}, set(transfer.page(1)['events'][0]))
        # Same captured projection and exact event retry remain idempotent.
        self.session.close(); self.model.close()
        self.model = ManagerReadModel(self.root / 'manager.sqlite3')
        self.session = ManagerSession(self.model, self.identity)
        self.addCleanup(self.model.close); self.addCleanup(self.session.close)
        install(new, self.session, 2, TIME)
        self.assertEqual(2, self.model.cursor(self.identity))

    def test_v1_mode_preserves_older_consumer_wire_and_v2_is_explicit(self):
        old = RoomStream(self.ledger, self.identity, schema_version=1).capture(None, captured_at=TIME).begin()
        new = RoomStream(self.ledger, self.identity).capture(None, captured_at=TIME).begin()
        self.assertEqual(1, old['schema_version']); self.assertEqual(2, new['schema_version'])
        self.assertEqual(set(new['projection']['sections']) - {'journey'}, set(old['projection']['sections']))
        # A v1 receiver's unchanged equality guard rejects v2, never silently
        # drops the new section. Upgrade consumer first, then producer.
        self.assertNotEqual(1, new['schema_version'])
        broken = deepcopy(new); broken['schema_version'] = 1
        with self.assertRaisesRegex(StreamError, 'PROJECTION_SCHEMA_MISMATCH'):
            self.session.handle({'kind': 'begin', 'transfer': broken})

    def test_journey_is_bounded_same_cut_scoped_and_payload_redacted(self):
        append(self.ledger, 'run.activated', {'run_id': 'run-alpha', 'generation': 1}, state=initial_state())
        for _ in range(JOURNEY_WINDOW + 2):
            append(self.ledger, 'peer.submitted', {'secret': 'NOT_DISPLAYED', 'run_id': 'run-alpha'})
        append(self.ledger, 'review.result', {'generation': 1, 'result': 'changes-requested', 'secret': 'NOT_DISPLAYED'})
        stream = RoomStream(self.ledger, self.identity)
        transfer = stream.capture(None, captured_at=TIME)
        append(self.ledger, 'review.result', {'generation': 1, 'result': 'pass'})
        journey = transfer.begin()['projection']['sections']['journey']['value']
        self.assertEqual('partial-supported-window', journey['completeness'])
        self.assertEqual(transfer.cut, journey['through_seq'])
        self.assertEqual(1, len(journey['events']))
        self.assertNotIn('NOT_DISPLAYED', json.dumps(journey))
        self.assertNotIn('"pass"', json.dumps(journey))
        self.assertEqual('run-alpha', next(iter(journey['events'].values()))['run_id'])

    def test_arbitrary_target_does_not_create_run_history(self):
        append(self.ledger, 'fixture.anything', {'run_id': 'run-alpha'}, state=initial_state())
        captured = RoomStream(self.ledger, self.identity).capture(None, captured_at=TIME)
        self.assertEqual({}, captured.begin()['projection']['sections']['journey']['value']['events'])

    def test_human_control_does_not_relabel_an_old_verdict_as_a_new_return(self):
        state = initial_state()
        append(self.ledger, 'review.result', {'generation': 1, 'result': 'changes-requested'}, state=state)
        append(self.ledger, 'review.human-control', {'review': {
            'generation': 1, 'result': 'changes-requested', 'stage': 'IMPLEMENTING'}})
        projection = RoomStream(self.ledger, self.identity).capture(None, captured_at=TIME).begin()['projection']
        events = projection['sections']['journey']['value']['events']
        self.assertEqual('changes-requested', events['1']['verdict'])
        self.assertNotIn('verdict', events['2'])
        self.assertEqual('IMPLEMENTING', events['2']['stage'])
        events['2']['verdict'] = 'changes-requested'
        with self.assertRaisesRegex(ProjectionError, 'INVALID_JOURNEY_EVENT'):
            validate_projection(projection, 'alpha')

    def test_journey_receiver_rejects_mismatched_cut_and_cross_run(self):
        append(self.ledger, 'run.activated', {'run_id': 'run-alpha', 'generation': 1}, state=initial_state())
        projection = RoomStream(self.ledger, self.identity).capture(None, captured_at=TIME).begin()['projection']
        bad = deepcopy(projection); bad['sections']['journey']['value']['events']['1']['run_id'] = 'another-run'
        with self.assertRaisesRegex(StreamError, 'JOURNEY_CUT_MISMATCH'):
            validate_projection(bad, 'alpha')
        bad = deepcopy(projection); bad['sections']['journey']['observed_version'] = 0
        with self.assertRaisesRegex(StreamError, 'JOURNEY_CUT_MISMATCH'):
            validate_projection(bad, 'alpha')

    def test_same_version_journey_change_fails_closed(self):
        append(self.ledger, 'run.activated', {'run_id': 'run-alpha', 'generation': 1}, state=initial_state())
        stream = RoomStream(self.ledger, self.identity)
        install(stream, self.session, None, TIME)
        from uas.manager_stream import SnapshotTransfer
        altered = stream.capture(1, captured_at=TIME).begin()['projection']
        altered['sections']['journey']['value']['events']['1']['kind'] = 'run.paused'
        transfer = SnapshotTransfer(self.ledger, self.identity, 1, altered)
        with self.assertRaisesRegex(StreamError, 'HUB_SNAPSHOT_CONFLICT'):
            self.session.handle({'kind': 'begin', 'transfer': transfer.begin()})

    def test_events_accessor_is_scoped_bounded_and_excludes_pending_cut(self):
        stream = RoomStream(self.ledger, self.identity)
        install(stream, self.session, None, TIME)
        for _ in range(3): append(self.ledger, 'fixture.event', {})
        transfer = stream.capture(0, captured_at=TIME)
        self.session.handle({'kind': 'begin', 'transfer': transfer.begin()})
        self.session.handle({'kind': 'events', 'page': transfer.page(0)})
        self.assertEqual([], self.model.events(self.identity)['events'])
        self.session.handle({'kind': 'finish', 'transfer_id': transfer.transfer_id})
        first = self.model.events(self.identity, limit=2)
        self.assertTrue(first['has_more']); self.assertFalse(first['complete'])
        self.assertEqual([1, 2], [event['observed_version'] for event in first['events']])
        last = self.model.events(self.identity, after_seq=first['next_after_seq'], limit=2)
        self.assertEqual([3], [event['observed_version'] for event in last['events']])
        self.assertTrue(self.model.events(self.identity)['complete'])
        with self.assertRaisesRegex(StreamError, 'INVALID_EVENT_LIMIT'): self.model.events(self.identity, limit=1001)
        with self.assertRaisesRegex(StreamError, 'ROOM_STREAM_CONFLICT'):
            self.model.events(RoomIdentity('deployment', 'alpha', 'other'))

    def test_config_binding_works_without_run_and_cannot_disclose_config_roots(self):
        identity = RoomIdentity('demo', 'alpha', 'epoch')
        with (ROOT / 'tests/fixtures/two-rooms.json').open() as source:
            binding = ProjectBinding.from_configuration(source, identity)
        self.assertEqual('alpha', binding.project_id)
        document = FieldNotesDocument(self.model, (binding,)).capture(now=TIME)
        self.assertEqual('unknown', document['rooms'][0]['view']['status'])
        self.assertNotIn('/srv/', json.dumps(document))
        with self.assertRaisesRegex(StreamError, 'DUPLICATE_UI_ROOM'):
            FieldNotesDocument(self.model, (binding, binding))

    def test_host_scope_does_not_enumerate_unauthorized_rooms(self):
        bindings = (ProjectBinding(self.identity, 'alpha', 'example/alpha'),)
        install(RoomStream(self.ledger, self.identity), self.session, None, TIME)
        with patch.object(self.model, 'deployments', side_effect=AssertionError('broad enumeration')):
            document = FieldNotesDocument(self.model, bindings).capture(now=TIME)
        self.assertEqual(1, len(document['rooms']))
        self.assertEqual('alpha', document['rooms'][0]['view']['identity']['room_id'])


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--write-browser-fixtures':
        output = Path(sys.argv[2])
        output.mkdir(parents=True, exist_ok=False)
        with tempfile.TemporaryDirectory() as directory:
            documents, data = browser_documents(Path(directory), datetime.now(timezone.utc).isoformat())
        for name, content in documents.items():
            (output / (name + '.html')).write_text(content, encoding='utf-8')
        (output / 'receipt.json').write_text(json.dumps({'schema_version': 1,
            'source': 'RoomLedger-RoomStream-ManagerReadModel-FieldNotesDocument',
            'generated_at': data['generated_at'], 'rooms': len(data['rooms']),
            'documents': list(documents)}, indent=2), encoding='utf-8')
    else:
        unittest.main()
