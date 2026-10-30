"""Real T29 observation, T38 attention owner, Manager replay, inert Gotify, socket snooze."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
import json
import threading
import time
import unittest

import library_support as support
import test_library_enqueue as enqueue_fixture
import test_library_registration as registration
import test_library_service as service_fixture
from uas import library, library_attention, manager_attention, manager_projection
from uas.library_attention import Owner
from uas.library_controls import Controls, canonical, request, serve
from uas.library_observations import HubObservations, Owner as ObservationOwner
from uas.library_records import LibraryRecords
from uas.ledger import RoomLedger, LedgerError
from uas.manager_stream import ManagerReadModel, RoomIdentity, RoomStream, validate_projection
from uas.manager_transport import ManagerSession

AT = support.AT
NOW = datetime.fromisoformat(AT)
START = '2026-10-28T00:00:00+00:00'
FAILURES = ('capture', 'source', 'model', 'validation', 'transport', 'audit', 'recovery')


def response(body=b'{"id":7}'):
    return ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
            + str(len(body)) + '\r\n\r\n').encode() + body


class InertConnection:
    """Inert HTTPS transport: records the exact bytes, never opens a socket."""
    sent = []
    wire = response()

    def __init__(self, host, port, timeout, context):
        self.sock = self.Channel(self.wire)
        self.sent.append({'host': host, 'port': port})

    class Channel:
        def __init__(self, data): self.data = bytearray(data)
        def settimeout(self, value): pass
        def recv(self, count):
            value = bytes(self.data[:count]); del self.data[:count]; return value

    def request(self, method, path, body, headers):
        self.sent[-1].update(method=method, path=path, body=body, headers=headers)
    def close(self): pass


class Recorder:
    """Inert explicit delivery; the host decision is the only preference input."""
    def __init__(self, outcome='confirmed', raises=False):
        self.outcome, self.notices, self.raises = outcome, [], raises
    def deliver_payload(self, payload):
        self.notices.append(payload)
        if self.raises: raise RuntimeError('transport construction failed')
        return {'outcome': self.outcome, 'message_id': 7} if self.outcome == 'confirmed' \
            else {'outcome': self.outcome, 'reason': 'GOTIFY_UNCREDENTIALED'}

    def attempts(self):
        return [item['notice_sha256'] for item in self.notices]


class DerivationTests(unittest.TestCase):
    setUp = enqueue_fixture.EnqueueTests.setUp
    make_scope = registration.RegistrationTests.make_scope
    make_publisher = registration.RegistrationTests.make_publisher
    head = registration.RegistrationTests.head
    count = registration.RegistrationTests.count

    def owner(self, now=None):
        return Owner(self.publisher, current_scope=lambda: self.fresh,
                     settings=lambda: self.settings, now=lambda: now or NOW)

    def observe(self, **updates):
        """Write one real T29 library-observation record; the row is its contract."""
        row = {key: None for key in manager_projection.library_FIELDS}
        row.update(project_identity=self.scope.project_identity, window_start=START,
                   window_end=AT, active_depth=0, parked_depth=0, queue_status='known',
                   canonical_sha=self.head(), coverage='complete', drain_state='IDLE',
                   projection_state='unknown', provider_state='unknown',
                   provider_mode='unknown', effectiveness='unmeasured', feedback='unmeasured')
        for name in FAILURES: row[name + '_failures'] = 0
        row.update(updates)
        with LibraryRecords(self.records, 'deployment-1') as records:
            prior = records.latest_observation(self.scope.project_identity)
        sequence = 1 if prior is None else prior['manifest']['sequence'] + 1
        value = manager_projection.library_observation(
            {'sequence': sequence, 'observed_at': AT, 'row': row})
        ident = 'observation-' + library._digest([self.scope.project_identity, sequence])
        operation = library._operation('library-observation', self.scope, self.settings, ident,
            ident, {'manifest_sha256': library._digest(value)}, AT)
        operation = replace(operation, manifest=value)
        with LibraryRecords(self.records, 'deployment-1') as records:
            records.begin(operation)
            records.finish(operation, library.receipt(operation, 'ACKNOWLEDGED', at=AT,
                acknowledgement=library._digest(value), reason='OBSERVATION_RECORDED'))
        return value

    def test_blocked_notice_is_one_per_episode_and_retries_do_not_repeat(self):
        self.observe(drain_state='BLOCKED', drain_id='drain-a', retry_count=3)
        delivery = Recorder()
        sample = self.owner().sample(notify=delivery)
        self.assertEqual({'project-blocked'}, set(sample['rows']))
        self.assertEqual(['A Library Project is blocked and needs human attention.'
                          '\nProject: https://github.com/acme/alpha\nObserved: ' + AT + '\nItems: 1'],
                         [item['message'] for item in delivery.notices])
        self.assertEqual(1, len(delivery.notices))
        # Same blocked state, a retry with more attempts, and a later sample: one notice.
        self.owner().sample(notify=delivery)
        self.observe(drain_state='BLOCKED', drain_id='drain-a', retry_count=9, attempt=4)
        self.owner().sample(notify=delivery)
        self.assertEqual(1, len(delivery.notices))
        # A different drain is a new blocked episode, not a retry of the old batch.
        self.observe(drain_state='BLOCKED', drain_id='drain-b')
        self.owner().sample(notify=delivery)
        self.assertEqual(2, len(delivery.notices))
        for notice in delivery.notices:
            self.assertEqual('text/plain', notice['extras']['client::display']['contentType'])
            self.assertIn('https://github.com/' + self.scope.project_path[len('github.com/'):],
                          notice['message'])
            self.assertLessEqual(len(json.dumps(notice).encode()), manager_attention.MAX_NOTICE_BYTES)

    def test_failure_categories_are_manager_only_or_one_notice_each(self):
        self.observe(parked_depth=2, adjudication_wait_seconds=120, audit_failures=1,
                     recovery_failures=1, model_failures=4)
        recorder = Recorder()
        sample = self.owner().sample(notify=recorder)
        self.assertEqual({'parked-conflict', 'audit-failure', 'recovery-failure'}, set(sample['rows']))
        # Model failures remain Manager facts; parked conflicts never notify externally.
        self.assertEqual(2, len(recorder.notices))
        self.assertIn('audit or storage failure', recorder.notices[0]['message'])
        self.assertIn('recovery failure', recorder.notices[1]['message'])
        self.observe(parked_depth=3, adjudication_wait_seconds=60, audit_failures=7,
                     recovery_failures=1, model_failures=9)
        self.owner().sample(notify=recorder)
        self.assertEqual(2, len(recorder.notices))
        self.assertEqual(1, sample['rows']['audit-failure']['count'])
        raw = repr([record for record in [sample, recorder.notices]])
        self.assertNotIn('Draft first', raw)

    def test_unknown_partial_and_absent_observation_stay_literal(self):
        owner = self.owner()
        sample = owner.sample(notify=Recorder())
        self.assertEqual(('unknown', {}), (sample['state'], sample['rows']))
        self.assertIsNone(sample['observed_at'])
        self.observe(coverage='partial')
        self.assertEqual('unknown', owner.sample()['state'])
        self.observe(active_depth=None, parked_depth=None, oldest_age_seconds=None,
                     adjudication_wait_seconds=None, queue_status='unknown')
        self.assertEqual('unknown', owner.sample()['state'])
        empty = manager_projection.attention_sample({'sequence': 1, 'observed_at': None,
            'state': 'unknown', 'rows': {}, 'snooze': None, 'episodes': {},
            'project_identity': 'acme/alpha'})
        self.assertEqual('unknown', empty['state'])
        with self.assertRaises(manager_projection.ProjectionError):
            manager_projection.attention_sample({'sequence': 1, 'observed_at': None,
                'state': 'unknown', 'snooze': None, 'episodes': {},
                'project_identity': 'acme/alpha',
                'rows': {'parked-conflict': {'kind': 'PARKED_CONFLICT',
                    'count': 1, 'age_seconds': 0, 'snoozed_until': None}}})
        with self.assertRaises(manager_projection.ProjectionError):
            manager_projection.attention_sample({'sequence': 1, 'observed_at': AT,
                'state': 'known', 'episodes': {}, 'project_identity': 'acme/alpha',
                'snooze': {'until': AT, 'kinds': ['PROJECT_BLOCKED']},
                'rows': {'parked-conflict': {
                        'kind': 'PARKED_CONFLICT', 'count': 1, 'age_seconds': 0,
                        'snoozed_until': AT}}})
        with self.assertRaises(manager_projection.ProjectionError):
            manager_projection.attention_sample({'sequence': 1, 'observed_at': AT,
                'state': 'known', 'snooze': None, 'episodes': {'AUDIT_FAILURE': 0},
                'project_identity': 'acme/alpha',
                'rows': {'audit-failure': {'kind': 'AUDIT_FAILURE', 'count': 1,
                    'age_seconds': True, 'snoozed_until': None}}})

    def test_known_empty_attention_stays_literal_and_never_claims_health(self):
        self.observe()
        recorder = Recorder()
        sample = self.owner().sample(notify=recorder)
        self.assertEqual(('known', {}), (sample['state'], sample['rows']))
        self.assertEqual([], recorder.notices)
        text = json.dumps(sample)
        for claim in ('healthy', 'captured', 'success'):
            self.assertNotIn(claim, text.lower())

    def test_recovered_then_new_failure_or_block_notifies_again(self):
        recorder = Recorder()
        self.observe(audit_failures=1)
        self.owner().sample(notify=recorder)
        self.observe()  # the failure clears: this episode is over
        self.assertEqual({}, self.owner().sample(notify=recorder)['rows'])
        self.observe(audit_failures=1)  # a new episode, not the same state
        sample = self.owner().sample(notify=recorder)
        self.assertEqual(2, sample['episodes']['AUDIT_FAILURE'])
        self.assertEqual(2, len(recorder.notices))
        # A Project blocked before any batch exists has no drain identity; the
        # episode number still separates two blocked states.
        self.observe(drain_state='BLOCKED')
        self.owner().sample(notify=recorder)
        self.observe()
        self.owner().sample(notify=recorder)
        self.observe(drain_state='BLOCKED')
        sample = self.owner().sample(notify=recorder)
        self.assertEqual(2, sample['episodes']['PROJECT_BLOCKED'])
        self.assertEqual(4, len(recorder.notices))

    def test_delivery_outcomes_settle_once_and_only_undeliverable_retries(self):
        self.observe(audit_failures=1)
        absent = Recorder('not-sent')
        self.owner().sample(notify=absent)
        with LibraryRecords(self.records, 'deployment-1') as records:
            attempts = records.notice_attempts('attention-notice-' + library._digest([
                self.scope.project_identity, 'audit-failure',
                ['AUDIT_FAILURE', 1]]))
        self.assertEqual(1, attempts['count'])
        self.assertEqual(['NOT_DURABLE'],
            [item['receipt']['outcome'] for item in attempts['items']])
        self.assertTrue(attempts['items'][0]['receipt']['retryable'])
        for _ in range(17):  # more attempts than one bounded dedupe page holds
            self.owner().sample(notify=Recorder('not-sent'))
        confirmed = Recorder()
        self.owner().sample(notify=confirmed)
        self.assertEqual(1, len(confirmed.notices))  # restored credentials still deliver once
        # An uncertain response is never automatically retried, even if it clears.
        self.observe(recovery_failures=1)
        uncertain = Recorder('unknown')
        self.owner().sample(notify=uncertain)
        self.owner().sample(notify=confirmed)
        self.assertEqual(1, len(uncertain.notices))
        self.assertEqual(1, len(confirmed.notices))
        # A raising transport settles as unknown instead of suppressing forever.
        self.observe(parked_depth=1, adjudication_wait_seconds=1)
        raised = Recorder(raises=True)
        self.owner().sample(notify=raised)  # parked is Manager-only, so nothing is sent
        self.observe(audit_failures=1)
        raised = Recorder(raises=True)
        self.assertEqual(2, self.owner().sample(notify=raised)['episodes']['AUDIT_FAILURE'])
        self.assertEqual(1, len(raised.notices))
        self.owner().sample(notify=confirmed)  # settled unknown: no automatic retry
        self.assertEqual(1, len(confirmed.notices))

    def test_hub_replay_restart_and_manager_fact_keep_owner_time_and_stale_state(self):
        self.observe(parked_depth=1, adjudication_wait_seconds=30)
        sample = self.owner().sample()
        base = self.base
        with RoomLedger(base / 'hub.db', 'alpha') as ledger:
            hub = HubObservations(ledger, project_identity=self.scope.project_identity,
                                  authenticate=lambda: True)
            hub.receive_attention(sample)
            cut = ledger.snapshot()['room_seq']
            # A cut derived for one Project cannot be recorded as another's.
            with RoomLedger(base / 'other.db', 'alpha') as other:
                stranger = HubObservations(other, project_identity='beta/beta',
                                           authenticate=lambda: True)
                with self.assertRaises(LedgerError):
                    stranger.receive_attention(sample)
                self.assertNotIn('library_attention', other.snapshot()['state'])
            hub.receive_attention(sample)
            self.assertEqual(cut, ledger.snapshot()['room_seq'])
            hub.receive_attention({**sample, 'sequence': sample['sequence'] + 1})
            with self.assertRaises(LedgerError):
                hub.receive_attention({**sample, 'rows': {}})
            identity = RoomIdentity('deployment-1', 'alpha', 'stream-alpha')
            model = ManagerReadModel(base / 'manager.db'); self.addCleanup(model.close)
            session = ManagerSession(model, identity)
            transfer = RoomStream(ledger, identity).capture(None, captured_at=AT,
                observations=hub.manager_observations())
            frame = json.loads(transfer._projection)
            del frame['sections']['library_attention']
            validate_projection(frame, 'alpha')  # older source frames stay readable
            session.handle({'kind': 'begin', 'transfer': transfer.begin()})
            session.handle({'kind': 'finish', 'transfer_id': transfer.transfer_id})
            session.close()  # disconnected Manager keeps the fact but marks it stale
            fact = model.view(identity, now=AT)['projection']['sections']['library_attention']
        self.assertEqual('library-service', fact['source_owner'])
        self.assertEqual('known', fact['status'])
        self.assertEqual(AT, fact['observed_at'])
        self.assertEqual('stale', fact['freshness'])
        self.assertEqual({'parked-conflict'}, set(fact['value']))
        self.assertEqual(sample, self.owner().latest())

    def test_real_gotify_transport_receives_only_bounded_metadata(self):
        self.observe(drain_state='BLOCKED', drain_id='drain-a')
        sender = manager_attention.GotifyDelivery('https://gotify.fixture.invalid/message',
            'gotify-ref', lambda reference: 'fixed_token')
        original = manager_attention.http.client.HTTPSConnection
        manager_attention.http.client.HTTPSConnection = InertConnection
        InertConnection.sent = []
        self.addCleanup(setattr, manager_attention.http.client, 'HTTPSConnection', original)
        sample = self.owner().sample(notify=sender)
        self.assertEqual('known', sample['state'])
        self.assertEqual(1, len(InertConnection.sent))
        sent = InertConnection.sent[0]
        self.assertEqual(('/message', 'fixed_token'),
                         (sent['path'], sent['headers']['X-Gotify-Key']))
        self.assertNotIn(b'fixed_token', sent['body'])
        payload = json.loads(sent['body'])
        self.assertEqual(['extras', 'message', 'priority', 'title'], sorted(payload))
        self.assertNotIn(self.scope.project_identity, sent['body'].decode())


class ServiceAttentionTests(unittest.TestCase):
    """Real service, canonical Git, durable records, Hub and Manager fixtures."""

    def setUp(self):
        self.fx = service_fixture.ServiceTests('test_commit_reports_survive_hub_outage_and_deduplicate')
        self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.source = self.fx.source

    def observation(self, **kwargs):
        owner = ObservationOwner(self.fx.service.publisher,
            current_scope=lambda: self.source.fresh, settings=lambda: self.source.settings)
        return owner.capture(observed_at=self.fx.now.isoformat(),
            window_start=(self.fx.now - timedelta(hours=1)).isoformat(), **kwargs)

    def attention(self, now=None):
        return Owner(self.fx.service.publisher, current_scope=lambda: self.source.fresh,
            settings=lambda: self.source.settings, now=lambda: now or self.fx.now)

    def test_parked_conflict_is_manager_attention_and_never_external(self):
        self.assertEqual(self.fx.service.tick()['state'], 'COMMITTED')
        self.observation()
        delivery = Recorder()
        sample = self.attention().sample(notify=delivery)
        self.assertEqual({'parked-conflict'}, set(sample['rows']))
        self.assertEqual(1, sample['rows']['parked-conflict']['count'])
        self.assertEqual([], delivery.notices)
        self.assertEqual(sample, self.attention().latest())

    def test_blocked_snooze_expiry_real_socket_and_unchanged_work(self):
        self.fx.mode = 'oversize'
        for delay in (5, 30, 120):
            self.fx.service.tick(); self.fx.now += timedelta(seconds=delay)
        state = deepcopy(self.fx.service.scheduler.state(self.source.scope.project_identity))
        self.assertEqual('BLOCKED', state['state'])
        self.observation()
        head, count = self.source.head(), self.source.count()
        delivery = Recorder()
        first = self.attention().sample()
        # The published 24-hour default warning is literal, from the observed age.
        self.assertEqual({'project-blocked', 'oldest-draft-warning'}, set(first['rows']))
        self.assertGreater(first['rows']['oldest-draft-warning']['age_seconds'],
                           self.source.settings['limits']['warning_seconds'])
        self.assertEqual([], delivery.notices)  # no preference handed over: nothing is sent
        self.attention().sample(notify=delivery)
        self.assertEqual(1, len(delivery.notices))

        # A real host-local Unix socket carries the receipted snooze, with only
        # the defer grant; the same authenticated human performs both calls.
        controls = Controls(self.fx.service)
        principal = library.LocalHuman('bruno', 'human-actor', 'grant-1',
            lambda project, key, action: key == self.source.scope.project_identity
                and action == 'library-defer', lambda: True)
        root = self.source.base / 'operator'; root.mkdir(mode=0o700)
        stop = threading.Event(); errors = []
        def run():
            try: serve(root, controls, authenticate=lambda uid: principal, stopped=stop.is_set)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=run); thread.start()
        try:
            deadline = time.monotonic() + 3
            while not (root / 'library-operator.sock').exists():
                if time.monotonic() > deadline: self.fail('operator endpoint did not start')
                time.sleep(.005)
            observed = request(root, {'version': 1, 'action': 'observe', 'project_id': 'alpha',
                                      'for_action': 'defer'})
            self.assertEqual('observed', observed['outcome'])
            value = {'version': 1, 'action': 'defer', 'project_id': 'alpha',
                     'request_id': 'snooze-1', 'settings_id': observed['result']['settings_id'],
                     'observed_version': observed['result']['observed_version']}
            # A stale configuration identity cannot authorize a new snooze.
            self.assertEqual('STALE_CONTROL_STATE', request(root,
                {**value, 'request_id': 'snooze-0', 'settings_id': '0' * 64})['error'])
            receipt = request(root, value)
            self.assertEqual('observed', receipt['outcome'])
            self.assertEqual('ACKNOWLEDGED', receipt['result']['outcome'])
            self.assertIsNone(receipt['result']['publication'])
            self.assertEqual(receipt, request(root, value))
            again = request(root, {'version': 1, 'action': 'observe', 'project_id': 'alpha',
                                   'for_action': 'defer'})['result']
            self.assertEqual('ATTENTION_ALREADY_SNOOZED', request(root,
                {**value, 'request_id': 'snooze-2',
                 'observed_version': again['observed_version']})['error'])
            # Defer changed only attention: same canonical Git, schedule and observation.
            self.assertEqual((head, count, state),
                (self.source.head(), self.source.count(),
                 self.fx.service.scheduler.state(self.source.scope.project_identity)))
            snoozed = self.attention().sample(notify=delivery)
            self.assertIsNotNone(snoozed['rows']['project-blocked']['snoozed_until'])
            self.assertEqual(1, len(delivery.notices))
            # A partial observation cannot derive attention, but it cannot drop
            # the receipted snooze window either.
            self.assertEqual('partial', self.observation(max_records=1)['row']['coverage'])
            gap = self.attention().sample(notify=delivery)
            self.assertEqual(('unknown', {}), (gap['state'], gap['rows']))
            self.assertIsNotNone(gap['snooze'])
            self.observation()
            restored = self.attention().sample(notify=delivery)
            self.assertIsNotNone(restored['rows']['project-blocked']['snoozed_until'])
            self.assertEqual(1, len(delivery.notices))
            # Expiry restores Manager attention without resolving the blocked work
            # and does not repeat the already deduplicated notification.
            later = self.fx.now + timedelta(seconds=library_attention.SNOOZE_SECONDS + 1)
            expired = self.attention(now=later).sample(notify=delivery)
            self.assertIsNone(expired['rows']['project-blocked']['snoozed_until'])
            self.assertEqual(1, len(delivery.notices))
            self.assertEqual('BLOCKED',
                self.fx.service.scheduler.state(self.source.scope.project_identity)['state'])
        finally:
            stop.set(); thread.join(3)
        self.assertFalse(errors)
        self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
