"""Pure protocol/temporary SQLite; no exporter thread, network or native launch."""
from io import StringIO
import json
from pathlib import Path
import sqlite3
import ssl
import tempfile
import unittest

from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.manager_host import RoomManagerExport
from uas.manager_stream import ManagerReadModel, RoomIdentity, RoomStream, StreamError
from uas.manager_transport import ManagerSession, RoomTLSClient


TIME = '2026-10-27T20:00:00+00:00'


class HostExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'room.sqlite3'
        self.writer = RoomLedger(self.path, 'alpha'); self.addCleanup(self.writer.close)
        self.reader = RoomLedger.open_reader(self.path, 'alpha'); self.addCleanup(self.reader.close)
        self.identity = RoomIdentity('demo', 'alpha', 'retained-room-epoch')
        self.source = RoomStream(self.reader, self.identity)
        self.model = ManagerReadModel(self.root / 'manager.sqlite3'); self.addCleanup(self.model.close)
        self.session = ManagerSession(self.model, self.identity); self.addCleanup(self.session.close)
        self.client = RoomTLSClient.__new__(RoomTLSClient)
        self.client.identity = self.identity
        class InertChannel:
            def close(self): pass
        self.client._channel = InertChannel()
        self.client._exchange = self.session.handle
        self.exporter = RoomManagerExport(self.source, self.client, interval_seconds=10, retry_limit_seconds=4)
        self.addCleanup(self.exporter.close)

    def write(self):
        number = self.writer.snapshot()['room_seq'] + 1
        return self.writer.apply(Command(str(number), 'counter', 'counter', None, {}),
            Origin('actor', 'participant', 'incarnation', 'authority', ('observe',)),
            authorize=lambda *_: True,
            decide=lambda *_: Transition({'counter': number}, (Event('counter.changed', {}),), {}))

    def test_separate_reader_observes_commits_and_cannot_write(self):
        self.write()
        self.assertEqual(1, self.reader.snapshot()['room_seq'])
        self.assertEqual(1, len(self.reader.replay(0)))
        with self.assertRaises(sqlite3.OperationalError):
            self.reader._connection().execute("UPDATE room SET seq=99")
        self.assertEqual(1, self.writer.snapshot()['room_seq'])
        missing = self.root / 'missing.sqlite3'
        with self.assertRaises(LedgerError): RoomLedger.open_reader(missing, 'alpha')
        self.assertFalse(missing.exists())
        with self.assertRaises(LedgerError) as caught: RoomLedger.open_reader(self.path, 'beta')
        self.assertEqual('ROOM_MISMATCH', caught.exception.code)

    def test_scheduled_step_has_no_hidden_loop_and_reader_replays_writer_progress(self):
        self.assertEqual('synchronized', self.exporter.step(now=0, captured_at=TIME)['status'])
        self.write()
        self.assertEqual({'status': 'waiting', 'next_attempt': 10}, self.exporter.step(now=9, captured_at=TIME))
        result = self.exporter.step(now=10, captured_at=TIME)
        self.assertEqual('synchronized', result['status']); self.assertEqual(1, result['room_seq'])
        self.assertEqual(20, result['next_attempt'])
        self.assertEqual(1, self.model.view(self.identity, now=TIME)['projection']['room_seq'])

    def test_outage_backoff_is_capped_and_never_controls_hub(self):
        calls = []
        def fail():
            calls.append(1); raise OSError('PRIVATE_TRANSPORT_DETAIL')
        self.client.close(); self.client.connect = fail
        for now, next_attempt in ((0, 1), (1, 3), (3, 7), (7, 11)):
            result = self.exporter.step(now=now, captured_at=TIME)
            self.assertEqual('disconnected', result['status'])
            self.assertEqual(next_attempt, result['next_attempt'])
            self.assertNotIn('PRIVATE', json.dumps(result))
            self.write()
        self.assertEqual(4, len(calls)); self.assertEqual(4, self.writer.snapshot()['room_seq'])
        self.exporter.close()
        self.assertEqual({'status': 'closed', 'next_attempt': None}, self.exporter.step(now=12, captured_at=TIME))
        self.assertEqual(4, len(calls))

    def test_fixed_configuration_resolves_existing_references_once_and_redacts_failure(self):
        config = json.loads((Path(__file__).parent / 'fixtures/two-rooms.json').read_text())
        calls = []
        def resolve(**kwargs):
            calls.append(kwargs)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            return context
        exporter = RoomManagerExport.from_configuration(self.source, StringIO(json.dumps(config)), resolve)
        self.addCleanup(exporter.close)
        self.assertEqual([{'client_credential_ref': 'manager-client', 'server_trust_ref': 'manager-trust',
                          'identity': self.identity}], calls)
        self.assertEqual('manager.example.com', exporter.client.address.hostname)
        self.assertEqual(self.identity, exporter.client.identity)
        def fail(**kwargs): raise ValueError('SECRET_KEY_CONTENT')
        with self.assertRaises(StreamError) as caught:
            RoomManagerExport.from_configuration(self.source, StringIO(json.dumps(config)), fail)
        self.assertEqual('MANAGER_CREDENTIALS_UNAVAILABLE', str(caught.exception))

    def test_wrong_room_configuration_and_regressing_clock_fail_before_effects(self):
        config = json.loads((Path(__file__).parent / 'fixtures/two-rooms.json').read_text())
        config['deployment']['id'] = 'other'
        def forbidden(**kwargs): self.fail('wrong-identity resolver invoked')
        with self.assertRaises(StreamError):
            RoomManagerExport.from_configuration(self.source, StringIO(json.dumps(config)), forbidden)
        self.exporter.step(now=1, captured_at=TIME)
        for value in (True, -1, float('inf'), 0):
            with self.subTest(value=value), self.assertRaises(StreamError):
                self.exporter.step(now=value, captured_at=TIME)
