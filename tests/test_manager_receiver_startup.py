"""Receiver initialization ordering: ordinary SQLite only, never threads/TLS."""
import ast
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from test_manager_tls import initialize_receiver_model
from uas.manager_stream import ManagerReadModel, StreamError


class ManagerReceiverStartupTests(unittest.TestCase):
    def test_competing_initial_reader_reproduces_wal_conversion_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manager.sqlite3'
            reader = sqlite3.connect(path, isolation_level=None)
            try:
                reader.execute('BEGIN')
                reader.execute('SELECT * FROM sqlite_master').fetchall()
                connect = sqlite3.connect
                # Deterministic contention, not a retry or a five-second sleep.
                with patch('uas.manager_stream.sqlite3.connect',
                           side_effect=lambda *a, **kw: connect(*a, **dict(kw, timeout=0))):
                    with self.assertRaisesRegex(StreamError, 'MANAGER_STORAGE_UNAVAILABLE') as caught:
                        ManagerReadModel(path)
                self.assertIsInstance(caught.exception.__cause__, sqlite3.OperationalError)
                self.assertIn('locked', str(caught.exception.__cause__))
            finally:
                reader.close()

    def test_ready_is_published_only_after_durable_schema_allows_observer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manager.sqlite3'
            observations, errors = [], []
            class Ready:
                def set(self):
                    observer = ManagerReadModel(path)
                    try:
                        observations.append(observer.deployments())
                    finally:
                        observer.close()
            model = initialize_receiver_model(path, Ready(), errors)
            try:
                self.assertIsInstance(model, ManagerReadModel)
                self.assertEqual(errors, [])
                self.assertEqual(len(observations), 1)
            finally:
                model.close()

    def test_initialization_failure_is_signaled_without_false_ready_owner(self):
        signals, errors = [], []
        class Ready:
            def set(self):
                signals.append(list(errors))
        with patch('uas.manager_stream.ManagerReadModel',
                   side_effect=StreamError('MANAGER_STORAGE_UNAVAILABLE')):
            model = initialize_receiver_model('unused', Ready(), errors)
        self.assertIsNone(model)
        self.assertEqual(signals, [['MANAGER_STORAGE_UNAVAILABLE']])

    def test_hosted_setup_waits_for_owner_and_checks_failure_before_return(self):
        tree = ast.parse((Path(__file__).with_name('test_manager_tls.py')).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                     and node.name == 'HostedManagerTLSTests')
        setup = next(node for node in owner.body if isinstance(node, ast.FunctionDef)
                     and node.name == 'setUp')
        tail = [ast.unparse(node) for node in setup.body[-4:]]
        self.assertEqual(tail[0], 'self.thread.start()')
        self.assertEqual(tail[1], 'self.addCleanup(self.shutdown)')
        self.assertIn('self.ready.wait(3)', tail[2])
        self.assertIn('self.assertFalse(self.startup_errors', tail[3])

    def test_helper_retains_one_owned_observer_and_polling_only_reads(self):
        tree = ast.parse((Path(__file__).with_name('manager_worker_fixture.py')).read_text())
        helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'hosted_manager_worker')
        constructors = [node for node in ast.walk(helper) if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name) and node.func.id == 'ManagerReadModel']
        self.assertEqual(len(constructors), 1)
        reader = next(node for node in helper.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'read_projection')
        self.assertEqual(len(reader.body), 1)
        self.assertIn('observer.view(', ast.unparse(reader.body[0]))
        owned = next(node for node in helper.body if isinstance(node, ast.With))
        scope = owned.body[0]
        self.assertIsInstance(scope, ast.Try)
        self.assertIn('observer = ManagerReadModel', ast.unparse(scope.body[0]))
        self.assertIn('observer.close()', ast.unparse(scope.finalbody[0]))

    def test_observer_close_failure_still_stops_owned_worker_and_receiver(self):
        tree = ast.parse((Path(__file__).with_name('manager_worker_fixture.py')).read_text())
        helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'hosted_manager_worker')
        owned = next(node for node in helper.body if isinstance(node, ast.With))
        # Execute only the reviewed cleanup statements with inert owners, not
        # the hosted helper, any sockets, or any thread lifecycle operation.
        statements = owned.body[0].finalbody
        actions = []
        class Observer:
            def close(self):
                actions.append('observer-close')
                raise RuntimeError('controlled observer close failure')
        class Worker:
            def request_stop(self):
                actions.append('worker-stop')
            def join(self, timeout):
                actions.append(('worker-join', timeout))
                return True
        class Receiver:
            def doCleanups(self):
                actions.append('receiver-cleanup')
                return True
        code = compile(ast.Module(body=statements, type_ignores=[]), '<inert-cleanup>', 'exec')
        with self.assertRaisesRegex(RuntimeError, 'controlled observer close failure'):
            exec(code, {'observer': Observer(), 'workers': [Worker()], 'case': Receiver()})
        self.assertEqual(actions, ['observer-close', 'worker-stop', ('worker-join', 3), 'receiver-cleanup'])
