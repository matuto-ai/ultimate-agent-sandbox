"""Explicit synchronous worker-body tests; never start a local thread/network."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.ledger import LedgerError, RoomLedger
from uas.manager_host import RoomManagerWorker
from uas.manager_stream import RoomIdentity, RoomStream, StreamError


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'room.sqlite3'
        self.writer = RoomLedger(self.path, 'alpha'); self.addCleanup(self.writer.close)
        self.identity = RoomIdentity('deployment', 'alpha', 'stream')
        self.readers = []
        @contextmanager
        def open_source(reader, identity):
            self.readers.append(reader)
            yield RoomStream(reader, identity)
        self.worker = RoomManagerWorker(self.path, self.identity, '{}', lambda **_: None, open_source=open_source)

    def test_interrupted_construction_is_terminal_and_closes_owned_reader(self):
        with patch('uas.manager_host.RoomManagerExport.from_configuration', side_effect=ValueError('SECRET')):
            self.worker._run()
        status = self.worker.status()
        self.assertTrue(status['terminated']); self.assertEqual('failed', status['phase'])
        self.assertEqual('MANAGER_WORKER_FAILED', status['error'])
        self.assertNotIn('SECRET', str(status))
        with self.assertRaises(LedgerError): self.readers[0].snapshot()
        self.assertEqual(0, self.writer.snapshot()['room_seq'])

    def test_outage_iteration_and_stop_close_only_owned_export_resources(self):
        worker = self.worker
        class Export:
            closed = False
            def step(self, **kwargs):
                worker.request_stop()
                return {'status': 'disconnected', 'room_seq': None,
                        'reason': 'MANAGER_TRANSFER_UNCONFIRMED', 'next_attempt': kwargs['now'] + 1}
            def close(self): self.closed = True
        exporter = Export()
        with patch('uas.manager_host.RoomManagerExport.from_configuration', return_value=exporter):
            worker._run()
        self.assertTrue(exporter.closed)
        self.assertTrue(worker.join(0)); self.assertTrue(worker.status()['terminated'])
        self.assertEqual('disconnected', worker.status()['last_export']['status'])
        with self.assertRaises(LedgerError): self.readers[0].snapshot()
        self.assertEqual(0, self.writer.snapshot()['room_seq'])

    def test_stop_before_start_never_constructs_source_and_cannot_restart(self):
        self.worker.request_stop()
        self.assertTrue(self.worker.join(0))
        with self.assertRaises(StreamError): self.worker.start()
        self.assertEqual([], self.readers)

    def test_join_timeout_retains_exact_owned_worker_without_false_termination(self):
        class Thread:
            ident = 12
            def __init__(self): self.alive = True; self.waits = []
            def join(self, timeout): self.waits.append(timeout)
            def is_alive(self): return self.alive
        thread = Thread(); self.worker._thread = thread; self.worker._phase = 'running'
        self.worker.request_stop()
        self.assertFalse(self.worker.join(.1)); self.assertIs(thread, self.worker._thread)
        self.assertFalse(self.worker.status()['terminated'])
        with self.assertRaises(StreamError): self.worker.start()
        thread.alive = False; self.worker._done.set()
        self.assertTrue(self.worker.join(0))
        self.assertEqual([.1, 0], thread.waits)

    def test_wrong_source_identity_fails_without_resolver_or_export(self):
        @contextmanager
        def wrong(reader, identity):
            source = RoomStream(reader, identity)
            source.identity = RoomIdentity('deployment', 'alpha', 'other-stream')
            yield source
        self.worker._open_source = wrong
        with patch('uas.manager_host.RoomManagerExport.from_configuration', side_effect=AssertionError('called')) as factory:
            self.worker._run()
        factory.assert_not_called(); self.assertTrue(self.worker.status()['terminated'])
        self.assertEqual('failed', self.worker.status()['phase'])

    def test_thread_construction_failure_has_no_owned_live_worker(self):
        with patch('uas.manager_host.threading.Thread', side_effect=RuntimeError('PRIVATE')):
            with self.assertRaises(StreamError): self.worker.start()
        self.assertTrue(self.worker.join(0)); self.assertTrue(self.worker.status()['terminated'])
        self.assertNotIn('PRIVATE', str(self.worker.status()))

    def test_same_room_epoch_new_worker_cannot_replace_old_lifetime_identity(self):
        other = RoomManagerWorker(self.path, self.identity, '{}', lambda **_: None)
        self.assertNotEqual(self.worker.worker_id, other.worker_id)
        self.assertEqual(self.worker.worker_id, self.worker.status()['worker_id'])
        with self.assertRaises(AttributeError): self.worker.worker_id = other.worker_id

    def test_uncertain_start_retains_thread_until_terminal_body(self):
        class Thread:
            ident = 12
            def __init__(self, **kwargs): self.alive = True
            def start(self): raise RuntimeError('after-start failure')
            def is_alive(self): return self.alive
            def join(self, timeout): pass
        with patch('uas.manager_host.threading.Thread', Thread):
            with self.assertRaises(StreamError): self.worker.start()
        self.assertFalse(self.worker.join(0))
        self.assertTrue(self.worker.status()['stop_requested'])
        self.assertFalse(self.worker.status()['terminated'])
        self.worker._run()  # Synchronous completion sees the retained stop signal.
        self.worker._thread.alive = False
        self.assertTrue(self.worker.join(0))
