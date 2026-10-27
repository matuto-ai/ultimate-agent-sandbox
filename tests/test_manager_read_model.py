"""Explicit pure/filesystem checks: no network, subprocess, or native discovery."""
from copy import deepcopy
from pathlib import Path
import json
import tempfile
import unittest

from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.manager_projection import (ProjectionError, SourceObservation, project_hub,
                                    validate_section_value)
from uas.manager_stream import ManagerReadModel, RoomIdentity, RoomStream, StreamError
from uas.manager_transport import ManagerSession, receive_frame, send_frame
from uas.peer import FixtureParticipant, FixturePeerHub, Readiness, WorkRequest


TIME = '2026-10-27T20:00:00+00:00'
LATER = '2026-10-27T20:00:10+00:00'
ORIGIN = Origin('actor', 'participant', 'incarnation', 'authority', ('observe',))


class MemoryChannel:
    def __init__(self, data=b''):
        self.data = data
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def recv(self, size):
        value, self.data = self.data[:size], self.data[size:]
        return value

    def sendall(self, value):
        self.data += value

    def close(self):
        self.data = b''


class ManagerReadModelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.model = ManagerReadModel(self.root / 'manager.sqlite3')
        self.addCleanup(lambda: self.model.close())
        self.identity = RoomIdentity('deployment', 'alpha', 'stream-alpha')
        self.ledger = RoomLedger(self.root / 'alpha.sqlite3', 'alpha')
        self.addCleanup(self.ledger.close)
        self.stream = RoomStream(self.ledger, self.identity)
        self.session = ManagerSession(self.model, self.identity)
        self.addCleanup(self.session.close)

    def error(self, code, call):
        with self.assertRaises((StreamError, ProjectionError)) as caught:
            call()
        self.assertEqual(code, caught.exception.code)

    def append(self, count=1):
        for _ in range(count):
            number = self.ledger.snapshot()['room_seq'] + 1
            self.ledger.apply(Command('operation-' + str(number), 'counter', 'counter', None, {}), ORIGIN,
                authorize=lambda *_: True,
                decide=lambda state, _: Transition({'counter': number},
                    (Event('counter.changed', {'private_project_text': 'DO_NOT_DISCLOSE'}),), {}))

    def install(self, transfer, session=None):
        session = session or self.session
        session.handle({'kind': 'begin', 'transfer': transfer.begin()})
        cursor = transfer.after_seq
        while cursor is not None and cursor < transfer.cut:
            page = transfer.page(cursor, limit=2)
            reply = session.handle({'kind': 'events', 'page': page})
            cursor = reply['room_seq']
        return session.handle({'kind': 'finish', 'transfer_id': transfer.transfer_id})

    def test_initial_snapshot_has_all_named_unavailable_sources_not_empty_success(self):
        transfer = self.stream.capture(None, captured_at=TIME)
        self.install(transfer)
        sections = self.model.view(self.identity, now=TIME)['projection']['sections']
        for key in ('seats', 'processes', 'provider_configuration', 'inference', 'quota',
                    'review', 'pending_ci', 'dependencies', 'forge_diagnostics', 'checkout_slots'):
            self.assertEqual('unavailable', sections[key]['status'])
            self.assertIsNone(sections[key]['observed_version'])
            self.assertIsNone(sections[key]['value'])
        self.assertEqual('unknown', sections['gate_truth']['status'])

    def test_two_rooms_group_by_deployment_without_cross_room_authority(self):
        self.install(self.stream.capture(None, captured_at=TIME))
        other = RoomIdentity('deployment', 'beta', 'stream-beta')
        with RoomLedger(self.root / 'beta.sqlite3', 'beta') as ledger:
            stream = RoomStream(ledger, other)
            session = ManagerSession(self.model, other)
            self.addCleanup(session.close)
            self.install(stream.capture(None, captured_at=TIME), session)
        rooms = self.model.deployments()['deployment']
        self.assertEqual(['alpha', 'beta'], [r['identity']['room_id'] for r in rooms])
        self.error('CERTIFICATE_ROOM_MISMATCH', lambda: self.session.handle(
            {'kind': 'hello', 'identity': other.document()}))
        self.error('INVALID_BEGIN', lambda: session.handle({'kind': 'begin',
            'transfer': self.stream.capture(0, captured_at=TIME).begin()}))

    def test_disconnect_does_not_stop_hub_and_reconnect_replays_every_event(self):
        self.install(self.stream.capture(None, captured_at=TIME))
        self.session.close()
        self.append(7)
        self.assertEqual(7, self.ledger.snapshot()['room_seq'])
        view = self.model.view(self.identity, now=TIME)
        self.assertEqual('disconnected', view['status'])
        self.assertTrue(view['projection_stale'])
        reconnected = ManagerSession(self.model, self.identity)
        self.addCleanup(reconnected.close)
        transfer = self.stream.capture(0, captured_at=LATER)
        self.install(transfer, reconnected)
        self.assertEqual(7, self.model.cursor(self.identity))
        events = self.model._db.execute('SELECT seq,event FROM manager_events ORDER BY seq').fetchall()
        self.assertEqual(list(range(1, 8)), [row['seq'] for row in events])
        self.assertNotIn('DO_NOT_DISCLOSE', json.dumps([row['event'] for row in events]))
        self.assertEqual(transfer.begin()['projection'], self.model.view(self.identity, now=LATER)['projection'])

    def test_events_after_atomic_cut_are_not_included_or_lost(self):
        self.install(self.stream.capture(None, captured_at=TIME))
        self.append(2)
        transfer = self.stream.capture(0, captured_at=LATER)
        self.append(3)
        self.install(transfer)
        self.assertEqual(2, self.model.cursor(self.identity))
        self.assertEqual([1, 2], [r[0] for r in self.model._db.execute('SELECT seq FROM manager_events ORDER BY seq')])
        self.install(self.stream.capture(2, captured_at=LATER))
        self.assertEqual(5, self.model.cursor(self.identity))
        self.assertEqual([1, 2, 3, 4, 5], [r[0] for r in self.model._db.execute('SELECT seq FROM manager_events ORDER BY seq')])

    def test_partial_replay_stays_stale_and_cannot_install_snapshot(self):
        self.install(self.stream.capture(None, captured_at=TIME)); self.append(3)
        transfer = self.stream.capture(0, captured_at=LATER)
        self.session.handle({'kind': 'begin', 'transfer': transfer.begin()})
        self.session.handle({'kind': 'events', 'page': transfer.page(0, limit=1)})
        self.error('REPLAY_INCOMPLETE', lambda: self.session.handle({'kind': 'finish', 'transfer_id': transfer.transfer_id}))
        view = self.model.view(self.identity, now=LATER)
        self.assertEqual(0, view['projection']['room_seq'])
        self.assertTrue(view['catching_up']); self.assertTrue(view['projection_stale'])

    def test_exact_page_retry_is_idempotent_but_changed_event_is_not(self):
        self.install(self.stream.capture(None, captured_at=TIME)); self.append(2)
        transfer = self.stream.capture(0, captured_at=LATER)
        self.session.handle({'kind': 'begin', 'transfer': transfer.begin()})
        page = transfer.page(0)
        reply = self.session.handle({'kind': 'events', 'page': page})
        self.assertEqual(reply, self.session.handle({'kind': 'events', 'page': page}))
        page['events'][0]['kind'] = 'counter.forged'
        self.error('SOURCE_EVENT_CONFLICT', lambda: self.session.handle({'kind': 'events', 'page': page}))
        self.assertEqual(2, self.model._db.execute('SELECT count(*) FROM manager_events').fetchone()[0])

    def test_reordered_or_gapped_page_is_rejected_without_partial_persistence(self):
        self.install(self.stream.capture(None, captured_at=TIME)); self.append(3)
        transfer = self.stream.capture(0, captured_at=LATER)
        self.session.handle({'kind': 'begin', 'transfer': transfer.begin()})
        page = transfer.page(0)
        page['events'][1]['observed_version'] = 90
        self.error('INVALID_REPLAY_EVENT', lambda: self.session.handle({'kind': 'events', 'page': page}))
        self.assertEqual(0, self.model._db.execute('SELECT count(*) FROM manager_events').fetchone()[0])
        self.error('REPLAY_GAP', lambda: self.session.handle({'kind': 'events', 'page': transfer.page(1)}))

    def test_new_connection_fences_old_session_without_disconnecting_replacement(self):
        replacement = ManagerSession(self.model, self.identity)
        self.addCleanup(replacement.close)
        self.error('STALE_MANAGER_CONNECTION', lambda: self.session.handle(
            {'kind': 'hello', 'identity': self.identity.document()}))
        self.session.close()
        self.install(self.stream.capture(None, captured_at=TIME), replacement)
        self.assertEqual('connected', self.model.view(self.identity, now=TIME)['status'])

    def test_source_epoch_or_cursor_regression_cannot_replace_existing_room(self):
        self.install(self.stream.capture(None, captured_at=TIME)); self.append(2)
        self.install(self.stream.capture(0, captured_at=LATER))
        self.error('ROOM_STREAM_CONFLICT', lambda: ManagerSession(self.model,
            RoomIdentity('deployment', 'alpha', 'other-stream')))
        self.error('SOURCE_CURSOR_REGRESSION', lambda: self.stream.capture(3, captured_at=TIME))
        self.error('CURSOR_CONFLICT', lambda: self.session.handle({'kind': 'begin',
            'transfer': self.stream.capture(None, captured_at=TIME).begin()}))

    def test_final_commit_survives_reopen_and_lost_ack_reconciles_by_cursor(self):
        self.append(2)
        self.install(self.stream.capture(None, captured_at=TIME))
        before = self.model.view(self.identity, now=TIME)['projection']
        self.session.close(); self.model.close()
        self.model = ManagerReadModel(self.root / 'manager.sqlite3')
        view = self.model.view(self.identity, now=TIME)
        self.assertEqual('disconnected', view['status'])
        self.assertEqual(before, view['projection'])
        session = ManagerSession(self.model, self.identity); self.addCleanup(session.close)
        reply = session.handle({'kind': 'hello', 'identity': self.identity.document()})
        self.assertEqual(2, reply['room_seq'])

    def test_partial_transfer_survives_reopen_and_exact_replay(self):
        self.install(self.stream.capture(None, captured_at=TIME)); self.append(3)
        transfer = self.stream.capture(0, captured_at=LATER)
        self.session.handle({'kind': 'begin', 'transfer': transfer.begin()})
        self.session.handle({'kind': 'events', 'page': transfer.page(0, limit=1)})
        self.session.close(); self.model.close()
        self.model = ManagerReadModel(self.root / 'manager.sqlite3')
        session = ManagerSession(self.model, self.identity); self.addCleanup(session.close)
        self.install(transfer, session)
        self.assertEqual(3, self.model.cursor(self.identity))
        self.assertEqual(3, self.model._db.execute('SELECT count(*) FROM manager_events').fetchone()[0])

    def test_presence_dimensions_are_literal_from_real_peer_domain(self):
        hub = FixturePeerHub(self.ledger)
        hub.configure('configure', (FixtureParticipant('alice', 'actor-a'),
                                   FixtureParticipant('bob', 'actor-b')), 'fixture-run')
        alice = hub.connect('attach-a', 'alice', 'process-a', lambda *_: None)
        hub.observe(alice, Readiness.BUSY)
        projection = self.stream.capture(None, captured_at=TIME).begin()['projection']
        sections = projection['sections']
        self.assertEqual('busy', sections['readiness']['value']['alice']['readiness'])
        self.assertEqual('unknown', sections['readiness']['freshness'])
        self.assertEqual('process-a', sections['adapter_connections']['value']['alice']['incarnation_id'])
        self.assertIsNone(sections['context_binding']['value']['alice']['bound_run'])
        self.assertEqual('fixture-run', sections['context_binding']['value']['alice']['reserved_run']['run_id'])
        self.assertEqual('unavailable', sections['seats']['status'])
        self.assertEqual('unavailable', sections['processes']['status'])
        self.assertIsNotNone(sections['last_observation']['value']['alice']['observation_id'])

    def test_owner_facts_do_not_turn_quota_or_inference_into_readiness(self):
        quota = SourceObservation('quota', 'runtime-adapter', 12, TIME,
            {'alice': {'participant_id': 'alice', 'source': 'provider', 'account_ref': 'account-a',
                       'semantics': 'remaining', 'amount': 0, 'unit': 'tokens', 'state': 'exhausted'}})
        inference = SourceObservation('inference', 'runtime-adapter', 4, TIME,
                                      None, status='failed', reason='PROVIDER_UNAVAILABLE')
        projection = self.stream.capture(None, captured_at=TIME, observations=(quota, inference)).begin()['projection']
        self.assertEqual('remaining', projection['sections']['quota']['value']['alice']['semantics'])
        self.assertEqual('failed', projection['sections']['inference']['status'])
        self.assertEqual('unavailable', projection['sections']['readiness']['status'])
        self.install(self.stream.capture(None, captured_at=TIME, observations=(quota, inference)))
        self.assertEqual(12, self.model.view(self.identity, now=TIME)['projection']['sections']['quota']['observed_version'])

    def test_owner_observations_require_owner_version_time_and_quota_semantics(self):
        self.error('SOURCE_OWNER_MISMATCH', lambda: SourceObservation('quota', 'hub', 1, TIME, {}).document())
        self.error('QUOTA_SEMANTICS_REQUIRED', lambda: SourceObservation('quota', 'runtime-adapter', 1, TIME,
            {'alice': {'amount': 20}}).document())
        self.error('INVALID_SOURCE_VERSION', lambda: SourceObservation('quota', 'runtime-adapter', True, TIME, {}).document())
        self.error('INVALID_TIMESTAMP', lambda: SourceObservation('quota', 'runtime-adapter', 1, 'now', {}).document())

    def test_source_version_regression_or_conflicting_same_version_is_refused(self):
        def observation(version, state):
            return SourceObservation('inference', 'runtime-adapter', version, TIME,
                                      {'alice': {'state': state}})
        self.install(self.stream.capture(None, captured_at=TIME, observations=(observation(2, 'healthy'),)))
        for version, state in ((1, 'healthy'), (2, 'failed')):
            transfer = self.stream.capture(0, captured_at=LATER, observations=(observation(version, state),))
            self.error('SOURCE_OBSERVATION_CONFLICT', lambda: self.session.handle({'kind': 'begin', 'transfer': transfer.begin()}))

    def test_raw_project_data_and_forge_diagnostics_are_never_serialized(self):
        source = {'room_id': 'alpha', 'room_seq': 8, 'state': {
            'raw_provider': {'authorization': 'SECRET'},
            'peer_traffic': {'connections': {}, 'traffic': {'request': {'kind': 'peer.work-request',
                'id': 'request', 'status': 'QUEUED', 'text': 'SECRET', 'instructions': 'SECRET'}}},
            'gate_evaluations': {'evaluation': {'evaluation_id': 'evaluation', 'phase': 'TERMINAL',
                'scope': {'run_id': 'run', 'generation': 1, 'gate_id': 'gate', 'participant_id': 'alice'},
                'result': {'verdict': 'passed', 'reason': None, 'stdout': 'SECRET'},
                'operational': {'cleanup': True, 'attention': None, 'quarantine_ref': 'SECRET'}}}}}
        projection = project_hub(source, captured_at=TIME)
        self.assertNotIn('SECRET', json.dumps(projection))
        self.assertEqual('passed', projection['sections']['gate_history']['value']['evaluation']['recorded_result']['verdict'])
        self.assertEqual('unknown', projection['sections']['gate_truth']['status'])

    def test_receiver_refuses_extra_project_bearing_fields_even_from_source(self):
        self.error('UNSUPPORTED_PROJECTED_FIELD', lambda: validate_section_value('forge_diagnostics',
            {'operation': {'operation_id': 'operation', 'stdout': 'SECRET'}}))
        self.error('UNSUPPORTED_PROJECTED_FIELD', lambda: validate_section_value('context_binding',
            {'alice': {'context_generation': 1, 'transcript': 'SECRET'}}))

    def test_read_only_protocol_rejects_actions_and_arbitrary_identity_switch(self):
        before = self.ledger.snapshot()
        for kind in ('command', 'gate-refresh', 'run-close', 'shell', 'forge-write', 'switch-room'):
            self.error('UNSUPPORTED_MANAGER_OPERATION', lambda: self.session.handle({'kind': kind}))
        self.assertEqual(before, self.ledger.snapshot())

    def test_connected_but_aged_or_future_snapshot_is_stale_not_healthy(self):
        self.install(self.stream.capture(None, captured_at=TIME))
        self.assertFalse(self.model.view(self.identity, now=LATER)['projection_stale'])
        self.assertTrue(self.model.view(self.identity, now='2026-10-27T20:00:31+00:00')['projection_stale'])
        self.assertTrue(self.model.view(self.identity, now='2026-10-27T19:59:59+00:00')['projection_stale'])

    def test_wire_framing_is_bounded_duplicate_free_and_exact(self):
        channel = MemoryChannel()
        send_frame(channel, {'kind': 'hello', 'identity': self.identity.document()})
        self.assertEqual({'kind': 'hello', 'identity': self.identity.document()}, receive_frame(channel))
        self.error('MANAGER_DISCONNECTED', lambda: receive_frame(channel))
        headers = b'POST /v1/room-stream HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\nContent-Length: '
        self.error('WIRE_FRAME_LIMIT', lambda: receive_frame(MemoryChannel(headers + b'1048577\r\n\r\n')))
        content = b'{"kind":"hello","kind":"command"}'
        self.error('INVALID_WIRE_JSON', lambda: receive_frame(MemoryChannel(headers +
            str(len(content)).encode() + b'\r\n\r\n' + content)))

    def test_https_url_path_host_framing_and_redirects_follow_real_configuration(self):
        from uas.manager_transport import ManagerAddress
        address = ManagerAddress.from_url('https://manager.example.test:8443/custom-stream')
        self.assertEqual(('manager.example.test', 8443, '/custom-stream'),
                         (address.hostname, address.port, address.path))
        self.assertEqual('/v1/room-stream', ManagerAddress.from_url('https://manager.example.test/').path)
        for url in ('http://manager.example.test', 'https://secret@manager.example.test',
                    'https://localhost', 'https://manager.example.test/../secret',
                    'https://manager.example.test/path?token=secret'):
            self.error('INVALID_MANAGER_URL', lambda: ManagerAddress.from_url(url))
        channel = MemoryChannel()
        send_frame(channel, {'kind': 'hello'}, path='/custom-stream', host='manager.example.test:8443')
        self.assertIn(b'POST /custom-stream HTTP/1.1\r\n', channel.data)
        self.assertIn(b'Host: manager.example.test:8443\r\n', channel.data)
        self.assertEqual({'kind': 'hello'}, receive_frame(channel, path='/custom-stream'))
        self.error('UNSUPPORTED_HTTP_MESSAGE', lambda: receive_frame(MemoryChannel(
            b'HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example.test\r\n\r\n'), response=True))
        self.error('UNSUPPORTED_HTTP_FRAMING', lambda: receive_frame(MemoryChannel(
            b'POST /v1/room-stream HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\n'
            b'Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}')))

    def test_real_supervisor_passive_export_never_calls_backend_or_refreshes_liveness(self):
        from unittest.mock import patch
        from lifecycle_support import FileFixtureBackend
        from uas.lifecycle import FixtureSpec, Supervisor
        project = self.root / 'project'; project.mkdir()
        backend = FileFixtureBackend(self.root / 'resources')
        supervisor = Supervisor(self.root / 'control', 'alpha', backend,
            authorize=lambda *_: True, revoke=backend.revoke)
        spec = FixtureSpec('alpha', 'project', (str(project),), 'sha256:' + 'a' * 64,
                           'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        supervisor.start(spec)
        stream = RoomStream(self.ledger, self.identity, supervisor=supervisor)
        with patch.object(backend, 'inspect', side_effect=AssertionError('passive export probed backend')):
            sections = stream.capture(None, captured_at=TIME).begin()['projection']['sections']
        lifecycle = sections['room_lifecycle']
        self.assertEqual('running', lifecycle['value']['alpha']['phase'])
        self.assertGreater(lifecycle['observed_version'], 0)
        self.assertIsNone(lifecycle['observed_at'])
        self.assertIsNotNone(lifecycle['source_committed_at'])
        self.assertEqual('unknown', lifecycle['freshness'])
        self.assertEqual('unavailable', sections['processes']['status'])

    def test_destroyed_recreated_owner_cannot_silently_reuse_room_stream(self):
        # Accepted Destroy deletes Hub state. The file fixture allows retaining
        # a separately supplied ledger; this must not silently reset Manager.
        from lifecycle_support import FileFixtureBackend
        from uas.lifecycle import FixtureSpec, Supervisor
        project = self.root / 'project'; project.mkdir()
        backend = FileFixtureBackend(self.root / 'resources')
        supervisor = Supervisor(self.root / 'control', 'alpha', backend,
            authorize=lambda *_: True, revoke=backend.revoke)
        spec = FixtureSpec('alpha', 'project', (str(project),), 'sha256:' + 'a' * 64,
                           'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        original = supervisor.start(spec)['instance_id']
        stream = RoomStream(self.ledger, self.identity, supervisor=supervisor)
        self.install(stream.capture(None, captured_at=TIME))
        supervisor.stop()
        self.install(stream.capture(0, captured_at=LATER))
        self.assertEqual(original, supervisor.start(spec)['instance_id'])
        self.install(stream.capture(0, captured_at=LATER))
        supervisor.destroy()
        self.install(stream.capture(0, captured_at=LATER))
        destroyed = self.model.view(self.identity, now=LATER)['projection']
        self.assertNotEqual(original, supervisor.start(spec)['instance_id'])
        self.error('SOURCE_OBSERVATION_CONFLICT', lambda:
            self.install(stream.capture(0, captured_at=LATER)))
        self.assertEqual(destroyed, self.model.view(self.identity, now=LATER)['projection'])
        replacement = RoomIdentity('deployment', 'alpha', 'replacement-stream')
        self.error('ROOM_STREAM_CONFLICT', lambda: self.model.connect(replacement))
        self.assertEqual(0, self.model.cursor(self.identity))

    def test_legacy_manifest_has_unknown_revision_until_real_owner_save(self):
        from lifecycle_support import FileFixtureBackend
        from uas.lifecycle import FixtureSpec, Supervisor
        project = self.root / 'project'; project.mkdir()
        backend = FileFixtureBackend(self.root / 'resources')
        supervisor = Supervisor(self.root / 'control', 'alpha', backend,
            authorize=lambda *_: True, revoke=backend.revoke)
        spec = FixtureSpec('alpha', 'project', (str(project),), 'sha256:' + 'a' * 64,
                           'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        supervisor.start(spec)
        state = json.loads(supervisor._manifest.read_text())
        state.pop('observation_revision'); state.pop('observation_committed_at')
        supervisor._manifest.write_text(json.dumps(state))
        observation = supervisor.manager_observations()[0].document()
        self.assertEqual('unknown', observation['status'])
        self.assertIsNone(observation['observed_version'])
        supervisor.stop()
        observation = supervisor.manager_observations()[0].document()
        self.assertEqual('known', observation['status'])
        self.assertGreater(observation['observed_version'], 0)
        self.assertIsNone(observation['observed_at'])

    def test_real_broker_audit_export_is_room_scoped_sanitized_and_read_only(self):
        from uas.forge_audit import ForgeAudit
        from uas.forge import ForgeBinding
        from uas.forge_read import ExternalReadBroker
        from test_forge_read import Provider
        with ForgeAudit(self.root / 'audit.sqlite3', 'deployment') as audit:
            provider = Provider()
            broker = ExternalReadBroker(ForgeBinding('alpha', 'project', 'owner/repo'), 'instance',
                audit, lambda _: provider, self.root / 'receipts')
            origin = Origin('actor', 'alice', 'incarnation', 'epoch', ('forge-read',))
            broker.execute({'id': 'read-1', 'kind': 'forge-read', 'argv': ['issue', 'view', '1']},
                           origin=origin, authorize=lambda: True)
            calls = len(provider.calls)
            observation = audit.manager_observations('alpha')[0].document()
            self.assertEqual(2, observation['observed_version'])
            self.assertEqual(1, len(observation['value']))
            self.assertEqual('OK', next(iter(observation['value'].values()))['state'])
            self.assertNotIn('PRIVATE_SOURCE_BODY', json.dumps(observation))
            self.assertEqual({}, audit.manager_observations('beta')[0].document()['value'])
            stream = RoomStream(self.ledger, self.identity, audit=audit)
            self.install(stream.capture(None, captured_at=TIME))
            self.assertEqual(calls, len(provider.calls))
            self.assertEqual(observation, self.model.view(self.identity, now=TIME)['projection']['sections']['forge_diagnostics'])

    def test_source_watermark_survives_unavailable_interval(self):
        source = SourceObservation('inference', 'runtime-adapter', 7, TIME, {'alice': {'state': 'failed'}})
        self.install(self.stream.capture(None, captured_at=TIME, observations=(source,)))
        self.install(self.stream.capture(0, captured_at=LATER))
        old = SourceObservation('inference', 'runtime-adapter', 2, TIME, {'alice': {'state': 'healthy'}})
        transfer = self.stream.capture(0, captured_at=LATER, observations=(old,))
        self.error('SOURCE_OBSERVATION_CONFLICT', lambda: self.session.handle({'kind': 'begin', 'transfer': transfer.begin()}))

    def test_inert_participant_store_export_preserves_seat_process_distinction_without_probes(self):
        from unittest.mock import patch
        from lifecycle_support import FileFixtureBackend
        from uas.lifecycle import FixtureSpec, Supervisor
        from uas.participant import FixtureParticipantController, FixtureSeat
        project = self.root / 'project'; project.mkdir()
        backend = FileFixtureBackend(self.root / 'resources')
        supervisor = Supervisor(self.root / 'control', 'alpha', backend,
            authorize=lambda *_: True, revoke=backend.revoke)
        spec = FixtureSpec('alpha', 'project', (str(project),), 'sha256:' + 'a' * 64,
                           'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        result = supervisor.start(spec)
        # Inert store fixture only: deliberately do not invoke the controller's
        # native capability admission or start any process.
        controller = FixtureParticipantController.__new__(FixtureParticipantController)
        controller.supervisor, controller.instance = supervisor, result['instance_id']
        controller.controller_id = 'controller'
        controller.path = supervisor.directory / 'participants-fixture.json'
        controller.store_failed = False
        state = {'version': 1, 'room_id': 'alpha', 'instance_id': result['instance_id'],
            'controller_id': 'controller', 'retired_pids': [], 'seats': {'alice': {
                'seat': FixtureSeat('alice', 'actor', 'profile', ('implement', 'forge-read')).document(),
                'epoch': 3, 'incarnation_id': 'process-3', 'status': 'revoked',
                'reason': 'controller-replaced', 'pid': None}}}
        controller._save(state)
        with patch.object(controller, '_alive', side_effect=AssertionError('native liveness probe')):
            stream = RoomStream(self.ledger, self.identity, supervisor=supervisor, participants=controller)
            projection = stream.capture(None, captured_at=TIME).begin()['projection']
        sections = projection['sections']
        self.assertEqual('actor', sections['seats']['value']['alice']['actor_id'])
        self.assertEqual('revoked', sections['processes']['value']['alice']['state'])
        self.assertEqual('unknown', sections['processes']['freshness'])
        self.assertIsNone(sections['processes']['observed_at'])
        self.assertTrue(sections['capabilities']['value']['alice']['implement'])
        self.assertFalse(sections['capabilities']['value']['alice']['review'])
        self.assertNotIn('pid', json.dumps(projection))

    def test_inert_checkout_manifest_export_does_not_run_git_or_infer_cleanliness(self):
        from unittest.mock import patch
        from lifecycle_support import FileFixtureBackend
        from uas.lifecycle import FixtureSpec, Supervisor
        from uas.checkouts import CheckoutAllocator, _identity
        repo = self.root / 'project'; repo.mkdir()
        common = repo / '.git'; common.mkdir()
        slots = self.root / 'slots'; slots.mkdir()
        backend = FileFixtureBackend(self.root / 'resources')
        supervisor = Supervisor(self.root / 'control', 'alpha', backend,
            authorize=lambda *_: True, revoke=backend.revoke)
        spec = FixtureSpec('alpha', 'project', (str(repo), str(slots)), 'sha256:' + 'a' * 64,
                           'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        result = supervisor.start(spec)
        allocator = CheckoutAllocator.__new__(CheckoutAllocator)
        allocator.supervisor = supervisor
        allocator.room = {'id': 'alpha', 'project': {'id': 'project'}}
        allocator.repo, allocator.root = repo, slots
        allocator.manifest = supervisor.directory / 'checkouts.json'
        state = {'version': 1, 'room_id': 'alpha', 'instance_id': result['instance_id'],
            'project_id': 'project', 'repo': str(repo), 'root': str(slots), 'common': str(common),
            'filesystem': {'repo': _identity(repo), 'root': _identity(slots), 'common': _identity(common)},
            'slots': {'primary': {'path': str(repo), 'branch': 'refs/heads/main', 'base': 'a' * 40,
                'run': 'run', 'participant': 'alice', 'active': False, 'phase': 'ready',
                'identity': {'directory': _identity(repo), 'git_metadata': _identity(common)}}}}
        allocator._save(state)
        with patch.object(allocator, '_git', side_effect=AssertionError('Git probe')):
            stream = RoomStream(self.ledger, self.identity, supervisor=supervisor, checkouts=allocator)
            fact = stream.capture(None, captured_at=TIME).begin()['projection']['sections']['checkout_slots']
        self.assertEqual('ready', fact['value']['primary']['state'])
        self.assertEqual('WORKING_TREE_NOT_OBSERVED', fact['value']['primary']['reason'])
        self.assertEqual('unknown', fact['freshness'])
        self.assertEqual(str(repo), fact['value']['primary']['path'])
        self.assertEqual('unknown', fact['value']['primary']['working_tree_state'])

    def test_manager_store_refuses_unrelated_database_and_in_memory_claim(self):
        import sqlite3
        path = self.root / 'unrelated.sqlite3'
        db = sqlite3.connect(path); db.execute('CREATE TABLE human_data(value TEXT)'); db.commit(); db.close()
        self.error('INVALID_MANAGER_STORE', lambda: ManagerReadModel(path))
        db = sqlite3.connect(path)
        self.assertEqual(['human_data'], [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")])
        db.close()
        self.error('DURABLE_MANAGER_STORE_REQUIRED', lambda: ManagerReadModel(':memory:'))

    def test_composed_export_iteration_reconciles_cursor_and_outage_does_not_stop_hub(self):
        from uas.manager_transport import RoomTLSClient, export_once
        # Exact client protocol, inert byte transport: no TLS/network claim.
        client = RoomTLSClient.__new__(RoomTLSClient)
        client.identity = self.identity
        client._channel = MemoryChannel()
        client._exchange = self.session.handle
        self.assertEqual({'status': 'synchronized', 'room_seq': 0},
                         export_once(self.stream, client, captured_at=TIME))
        self.append(2)
        self.assertEqual({'status': 'synchronized', 'room_seq': 2},
                         export_once(self.stream, client, captured_at=LATER))
        client._channel = None
        client.connect = lambda: (_ for _ in ()).throw(OSError('PRIVATE_NETWORK_DETAIL'))
        result = export_once(self.stream, client, captured_at=LATER)
        self.assertEqual('disconnected', result['status'])
        self.assertNotIn('PRIVATE_NETWORK_DETAIL', json.dumps(result))
        self.append()
        self.assertEqual(3, self.ledger.snapshot()['room_seq'])

    def test_dependency_export_reads_exact_canonical_run_receipt_without_new_provider_call(self):
        from uas.forge import ForgeBinding, ReadOnlyForgeBroker
        from uas.github_read import GitHubProject, GitHubReadProvider, ProviderResponse
        from test_forge import ForgeTests
        issue = ForgeTests.issue(None, 66)
        dependency = ForgeTests.issue(None, 7)
        calls = []
        def transport(path):
            calls.append(path)
            return ProviderResponse(200, json.dumps([dependency] if '/dependencies/' in path else issue).encode(), {})
        provider = GitHubReadProvider(GitHubProject('owner/repo'), transport)
        broker = ReadOnlyForgeBroker(self.ledger, ForgeBinding('alpha', 'project', 'owner/repo'), lambda _: provider)
        origin = Origin('actor', 'alice', 'incarnation', 'epoch', ('forge-read',))
        receipt = broker.submit({'id': 'read-source', 'kind': 'forge-read', 'argv': ['issue', 'view', '66']},
                                origin=origin, authorize=lambda: True)
        run = {'run_id': 'run', 'generation': 1, 'status': 'ACTIVE', 'project_id': 'project',
               'repository': 'owner/repo', 'issue_number': 66, 'issue_id': 166,
               'forge_observation': receipt['operation_id']}
        self.ledger.apply(Command('run-fixture', 'fixture.run', 'run', 1, {}), ORIGIN,
            authorize=lambda *_: True, decide=lambda state, _: Transition({**state, 'runs': {'run': run}},
                (Event('fixture.run', {}),), {}))
        cut = self.ledger.snapshot(); count = len(calls)
        observation = broker.manager_observations(cut)[0].document()
        self.assertEqual(2, observation['observed_version'])
        self.assertEqual(1, observation['value']['run:work-item']['dependency_count'])
        self.assertEqual('open', observation['value']['run:dependency:107']['state'])
        self.assertEqual('unknown', observation['freshness'])
        self.assertIsNone(observation['observed_at'])
        stream = RoomStream(self.ledger, self.identity, forge=broker)
        self.install(stream.capture(None, captured_at=TIME))
        self.assertEqual(count, len(calls))
        self.assertNotIn('SECRET_RAW_BODY', json.dumps(self.model.view(self.identity, now=TIME)))
        corrupted = deepcopy(cut); corrupted['state']['runs']['run']['issue_id'] = 999
        with self.assertRaisesRegex(LedgerError, 'OBSERVATION_UNAVAILABLE'):
            broker.manager_observations(corrupted)
        future_cut = deepcopy(cut); future_cut['room_seq'] = 1
        with self.assertRaisesRegex(LedgerError, 'INVALID_PROVIDER_OBSERVATION'):
            broker.manager_observations(future_cut)


if __name__ == '__main__':
    unittest.main()
