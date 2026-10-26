"""Resource-fault tests around real disposable official Pi subprocesses.

These assert cleanup ownership, not a successful native handshake or acceptance.
"""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from uas.pi_runtime import FixturePiRpcReceiver

ROOT = Path(__file__).resolve().parents[1]
INSTALL = os.environ.get('UAS_PI_INSTALL')


@unittest.skipUnless(INSTALL, 'Set UAS_PI_INSTALL for real Pi initialization fault tests')
class PiInitializationTests(unittest.TestCase):
    def check_fault(self, fault, attached):
        with tempfile.TemporaryDirectory(prefix='uas-pi-init-') as directory:
            root = Path(directory)
            home = root / 'home'
            home.mkdir()
            package = Path(INSTALL).resolve() / 'node_modules/@earendil-works/pi-coding-agent'
            self.assertEqual('1.4.0', json.loads((package / 'package.json').read_text())['version'])
            argv = [shutil.which('node'), str(package / 'dist/cli.js'), '--mode', 'rpc',
                    '--no-tools', '--no-extensions', '--no-skills', '--no-prompt-templates', '--no-themes']
            env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'PI_OFFLINE': '1',
                   'PI_CODING_AGENT_DIR': str(home / 'agent'),
                   'NODE_OPTIONS': '--import=' + str(ROOT / 'tests/pi/network-guard.mjs')}
            processes, databases, threads = [], [], []
            original_popen, original_connect, original_start = subprocess.Popen, sqlite3.connect, threading.Thread.start
            def spawn(*args, **kwargs):
                process = original_popen(*args, **kwargs)
                processes.append(process)
                return process
            class Database(sqlite3.Connection):
                def execute(db, query, *args, **kwargs):
                    if fault == 'pragma' and query.startswith('PRAGMA'):
                        raise sqlite3.OperationalError('injected PRAGMA failure')
                    return super().execute(query, *args, **kwargs)
            def connect(*args, **kwargs):
                if fault == 'connect':
                    raise sqlite3.OperationalError('injected connection failure')
                db = original_connect(*args, **kwargs, factory=Database)
                databases.append(db)
                return db
            def start(thread):
                threads.append(thread)
                if len(threads) == (1 if fault == 'first-thread' else 2):
                    raise RuntimeError('injected thread start failure')
                original_start(thread)
            kwargs = {'journal': root / 'intent.db', 'runtime_version': '1.4.0',
                      'scope': {'room_id': 'alpha', 'participant_id': 'pi', 'run_id': 'run-1',
                                'generation': 1, 'context_generation': 1}}
            # Attached setup is already owned by a controller-like caller. The
            # receiver must leave it alive, including on its own setup failure.
            external = spawn(argv, cwd=root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0) if attached else None
            try:
                with patch('uas.pi_runtime.sqlite3.connect', connect), \
                     patch('uas.pi_runtime.subprocess.Popen', spawn), \
                     patch.object(threading.Thread, 'start', start):
                    with self.assertRaises((sqlite3.OperationalError, RuntimeError)):
                        if attached:
                            FixturePiRpcReceiver.attach(external, incarnation_id='supervisor-test', **kwargs)
                        else:
                            FixturePiRpcReceiver(argv, cwd=root, env=env, **kwargs)
                if attached:
                    self.assertIsNone(external.poll(), 'attached receiver killed its owner process')
                    self.assertTrue(all(not stream.closed for stream in (external.stdin, external.stdout, external.stderr)))
                elif fault in ('connect', 'pragma'):
                    self.assertEqual([], processes, 'database failure should precede spawn')
                else:
                    self.assertEqual(1, len(processes))
                    self.assertIsNotNone(processes[0].poll(), 'standalone receiver leaked its child')
                    self.assertTrue(all(stream.closed for stream in (processes[0].stdin, processes[0].stdout, processes[0].stderr)))
                for db in databases:
                    with self.assertRaises(sqlite3.ProgrammingError):
                        db.execute('SELECT 1')
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=3)
                    for thread in threads:
                        if thread.ident is not None:
                            thread.join(timeout=2)
                            self.assertFalse(thread.is_alive())
                    for stream in (process.stdin, process.stdout, process.stderr):
                        stream.close()

    def test_connect_failure_never_leaks_or_kills_attached_owner(self):
        for attached in (False, True):
            with self.subTest(attached=attached):
                self.check_fault('connect', attached)

    def test_pragma_failure_closes_open_journal_without_killing_attached_owner(self):
        for attached in (False, True):
            with self.subTest(attached=attached):
                self.check_fault('pragma', attached)

    def test_first_reader_start_failure_cleans_only_owned_resources(self):
        for attached in (False, True):
            with self.subTest(attached=attached):
                self.check_fault('first-thread', attached)

    def test_second_reader_start_failure_closes_journal_and_joins_started_thread(self):
        for attached in (False, True):
            with self.subTest(attached=attached):
                self.check_fault('second-thread', attached)
