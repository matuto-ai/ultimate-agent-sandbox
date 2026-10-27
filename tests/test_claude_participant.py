"""Actual Claude process authority, same-Run restore and cross-Run reset.

These two bounded integration cases run only in the existing account-free,
loopback-only Claude native gate. Imports do not probe sockets or the kernel.
The Run completion/cancellation inputs are explicit trusted fixture facts, not
native work acceptance, production approval or GitHub completion evidence.
"""
import json
import os
from pathlib import Path
import select
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid

from lifecycle_support import FileFixtureBackend
from uas.claude_fixture import FixtureClaudeRecipe
from uas.claude_runtime import require_loopback_namespace
from uas.context import FixtureRun, FixtureRunTerminal
from uas.fixture_peer import FixtureReceiver
from uas.ledger import LedgerError, RoomLedger
from uas.lifecycle import FixtureSpec, Supervisor
from uas.participant import FixtureCredentials, FixtureSeat
from uas.peer import FixtureParticipant, FixturePeerHub, Message, Readiness, WorkRequest


INSTALL = os.environ.get('UAS_CLAUDE_INSTALL')
SDK_INSTALL = os.environ.get('UAS_CLAUDE_SDK_INSTALL')
NODE = os.environ.get('UAS_CLAUDE_NODE')


@unittest.skipUnless(INSTALL and SDK_INSTALL and NODE,
                     'Actual Claude Participant requires the isolated pinned-package native gate')
class ClaudeParticipantNativeTests(unittest.TestCase):
    def setUp(self):
        from claude.probe import Gateway, Handler

        class ObservedHandler(Handler):
            def parse_request(self):
                parsed = super().parse_request()
                if parsed:
                    self.server.all_requests.append({'method': self.command, 'path': self.path})
                return parsed

        require_loopback_namespace()
        self.started = time.monotonic()
        self.cleanup_receipts = []
        self.temp = tempfile.TemporaryDirectory(prefix='uas-claude-participant-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        project = self.root / 'project'
        project.mkdir()
        self.project_file = project / 'dirty.txt'
        self.project_file.write_text('Uncommitted Project bytes survive native reset.\n')
        self.backend = FileFixtureBackend(self.root / 'resources')
        self.supervisor = Supervisor(self.root / 'control', 'alpha', self.backend,
                                     authorize=lambda *_: True, revoke=self.backend.revoke)
        # These are file-backend fixture identities, explicitly not a built image.
        self.supervisor.start(FixtureSpec('alpha', 'fixture', (str(project),),
                                         *['sha256:' + c * 64 for c in 'abc']))
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', tuple(FixtureParticipant(p, 'actor-' + p)
                           for p in ('claude', 'sender-a', 'sender-b', 'sibling')), 'run-a',
                           initial_runs={'sender-b': FixtureRun('run-b'), 'sibling': FixtureRun('run-c')})
        self.senders = {p: self.hub.connect(p, p, p + '-inc', object())
                        for p in ('sender-a', 'sender-b')}
        self.gateway = Gateway(('127.0.0.1', 0), ObservedHandler)
        self.gateway.key = 'fixture-only-' + uuid.uuid4().hex
        self.gateway.requests = []
        self.gateway.all_requests = []
        self.gateway.release = threading.Event()
        self.gateway.release.set()
        self.gateway.entered = threading.Event()
        self.thread = threading.Thread(target=lambda: self.gateway.serve_forever(poll_interval=.05), daemon=True)
        self.thread.start()
        self.addCleanup(self.close_gateway)
        self.controller = self.supervisor.participants(self.hub, FixtureCredentials())
        self.addCleanup(self.controller.close)
        self.seat = FixtureSeat('claude', 'actor-claude', 'claude-fixture-profile',
                                ('peer-traffic',), runtime='claude-fixture')
        self.active_recipe = self.recipe(self.hub.contexts.scope('claude'))
        self.select(self.controller.launch_claude(self.seat, self.active_recipe))
        self.native.wait_safe()
        self.workspace_file = self.active_recipe.workdir / 'dirty.txt'
        self.workspace_file.write_text('Retained fixture workspace bytes.\n')
        self.sibling_receiver = FixtureReceiver(self.root / 'sibling.db', 'alpha', 'sibling', 'unused')
        self.addCleanup(self.sibling_receiver.close)
        self.sibling = self.controller.launch(
            FixtureSeat('sibling', 'actor-sibling', 'profile', ('peer-traffic',)), self.sibling_receiver)
        self.assertTrue(select.select([self.sibling.process.stdout], [], [], 3)[0])
        self.assertTrue(json.loads(self.sibling.process.stdout.readline())['ready'])

    def close_gateway(self):
        self.gateway.release.set()
        self.gateway.shutdown()
        self.gateway.server_close()
        self.thread.join(timeout=2)

    def recipe(self, scope):
        binary = Path(INSTALL) / 'node_modules/@anthropic-ai/claude-code-linux-x64/claude'
        return FixtureClaudeRecipe(binary, sdk_install=SDK_INSTALL, node=NODE,
            directory=self.root / 'native', scope=scope,
            gateway_url=f'http://127.0.0.1:{self.gateway.server_port}',
            fixture_key=self.gateway.key, timeout=8)

    def select(self, handle):
        self.handle = handle
        self.native = handle.managed_receiver
        return handle

    def restore(self):
        self.active_recipe = self.recipe(self.hub.contexts.scope('claude'))
        self.select(self.controller.restore_claude(self.seat, self.active_recipe))
        self.native.wait_safe()

    def target_recipe(self):
        return self.recipe({'room_id': 'alpha', 'participant_id': 'claude', 'run_id': 'run-b',
                            'generation': 1, 'context_generation': 2})

    def reset(self):
        preceding = self.handle
        self.active_recipe = self.target_recipe()
        handle = self.controller.reset_claude('reset-a-b', self.seat, self.active_recipe,
            expected_context_generation=1, target_run=FixtureRun('run-b'))
        if handle is not preceding:
            self.assertTrue(preceding.cleanup_verified)
            self.cleanup_receipts.append({'host_reaped': preceding.process.returncode is not None,
                                          'held_native_exit_verified': preceding.cleanup_verified})
        self.select(handle)
        self.native.wait_safe()
        return handle

    def submit(self, identifier, text, *, run='a'):
        self.hub.submit(self.senders['sender-' + run],
                        WorkRequest(identifier, 'run-' + run, 1, 'claude', text))

    def request(self, identifier):
        return self.hub._state()['traffic'][identifier]

    def deliver(self):
        self.hub.observe(self.handle.connection, self.handle.connection.receiver.observe())
        return self.hub.deliver(self.handle.connection, limit=1)

    def close_a(self, *requests):
        for identifier in requests:
            self.hub.cancel('cancel-' + identifier, identifier, 'Trusted fixture cancellation before reset.')
        self.hub.contexts.close_run('close-a', 'run-a', FixtureRunTerminal.COMPLETED)

    def history(self):
        request = next(item['request'] for item in reversed(self.gateway.requests)
                       if item['path'].split('?')[0] == '/v1/messages')
        return json.dumps(request['messages'])

    def journal_rows(self, path):
        db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
        try:
            return db.execute('SELECT logical_digest,message_id,receipt,retryable FROM handoffs ORDER BY logical_digest').fetchall()
        finally:
            db.close()

    def tearDown(self):
        row = self.hub.contexts._row('claude')
        print(json.dumps({'case': self.id(), 'elapsed_seconds': round(time.monotonic() - self.started, 3),
            'runtime': 'Claude Code', 'version': '2.1.310', 'sdk_version': '0.3.310',
            'authority': 'supervisor-owned-native-pidfd-account-free-fixture',
            'sdk_host_is_native_authority': False,
            'context_generation': row['context_generation'], 'context_status': row['status'],
            'bound_run': row['bound_run'], 'reserved_run': row['reserved_run'],
            'reset_status': row['reset']['status'] if row['reset'] else None,
            'reset_events': [event['kind'] for event in self.ledger.replay(0)
                             if event['kind'].startswith('context.reset.')],
            'gateway_requests': len(self.gateway.requests),
            'prior_cleanup_receipts': self.cleanup_receipts,
            'canonical_github_run_completion': 'not-qualified',
            'workstation_image': 'not-qualified'}, sort_keys=True))

    def test_actual_native_authority_restore_and_fresh_cross_run_context(self):
        initial = self.handle
        initial_pid = initial.native_pid
        session = self.native.session_id
        self.assertNotEqual(initial.process.pid, initial_pid)
        self.assertEqual(initial.badge.incarnation_id, self.native.incarnation_id)
        with self.supervisor._locked():
            self.assertTrue(self.controller._authority(initial, (initial_pid, os.getuid(), os.getgid())))
            with self.assertRaisesRegex(LedgerError, 'WRONG_PROCESS'):
                self.controller._authority(initial, (initial.process.pid, os.getuid(), os.getgid()))
        self.assertEqual([], self.gateway.all_requests, 'start/readiness never primes the model')
        marker = 'OLD-RUN-' + uuid.uuid4().hex
        self.submit('work-a', marker)
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.native.wait_safe()
        started = self.request('work-a')['response_started_at']
        self.assertIsNotNone(started, 'only a persisted native replay ACK starts the clock')
        self.submit('work-pending', 'SAME-RUN-PENDING-' + marker)
        self.assertIsNone(self.request('work-pending')['response_started_at'])
        before = len(self.gateway.all_requests)
        self.controller.revoke('claude')
        self.assertTrue(self.handle.cleanup_verified)
        self.cleanup_receipts.append({'host_reaped': self.handle.process.returncode is not None,
                                      'held_native_exit_verified': self.handle.cleanup_verified})
        self.assertIsNotNone(initial.process.returncode, 'owned SDK host must be reaped by close')
        self.assertEqual('HELD', self.hub.deliver(initial.connection)['outcome'])
        self.restore()
        self.assertEqual(session, self.native.session_id)
        self.assertNotEqual(initial_pid, self.handle.native_pid)
        self.assertNotEqual(initial.badge.incarnation_id, self.handle.badge.incarnation_id)
        self.assertGreater(self.handle.badge.epoch, initial.badge.epoch)
        self.assertEqual(1, self.handle.connection.context_generation)
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.assertEqual(before, len(self.gateway.all_requests), 'same logical ACK reconciles without reinjection')
        self.assertEqual(started, self.request('work-a')['response_started_at'])
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.native.wait_safe()
        self.assertEqual(2, self.history().count(marker), 'old first turn plus the new pending turn, once each')
        self.assertIsNotNone(self.request('work-pending')['response_started_at'])
        with self.supervisor._locked():
            with self.assertRaisesRegex(LedgerError, 'AUTHORITY_REVOKED'):
                self.controller._authority(initial, (initial_pid, os.getuid(), os.getgid()))

        self.hub.submit(self.senders['sender-a'], Message('old-queued', 'run-a', 1, 'claude', marker))
        self.submit('work-b', 'NEW-RUN-ONLY', run='b')
        self.assertNotIn('work-b', [item['id'] for item in self.hub._pending(self.handle.connection)])
        old = self.handle
        old_journal = self.active_recipe.journal
        sibling_scope = self.hub.contexts.scope('sibling')
        with self.assertRaisesRegex(LedgerError, 'PRECEDING_RUN_OPEN'):
            self.reset()
        self.assertTrue(self.controller._alive(old))
        self.close_a('work-a', 'work-pending')
        old_rows = self.journal_rows(old_journal)
        before = len(self.gateway.all_requests)
        self.reset()
        self.assertIsNotNone(old.process.returncode)
        self.assertEqual(before, len(self.gateway.all_requests), 'fresh proof must not inject a priming turn')
        self.assertNotEqual(session, self.native.session_id)
        self.assertNotEqual(old.native_pid, self.handle.native_pid)
        self.assertEqual(2, self.handle.connection.context_generation)
        self.assertEqual('actor-claude', self.handle.badge.actor_id)
        self.assertIsNone(self.hub.contexts._row('claude')['bound_run'])
        self.assertEqual('run-b', self.hub.contexts.scope('claude')['run_id'])
        self.assertEqual(sibling_scope, self.hub.contexts.scope('sibling'))
        self.assertTrue(self.controller._alive(self.sibling))
        self.assertEqual('Retained fixture workspace bytes.\n', self.workspace_file.read_text())
        self.assertEqual('Uncommitted Project bytes survive native reset.\n', self.project_file.read_text())
        self.assertEqual(old_rows, self.journal_rows(old_journal))
        self.assertFalse(self.request('old-queued')['deliveries'])
        self.assertEqual('HELD', self.hub.deliver(old.connection)['outcome'])
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.native.wait_safe()
        self.assertNotIn(marker, self.history(), 'native request itself proves old context was not resumed')
        self.assertEqual(1, self.history().count('NEW-RUN-ONLY'))
        self.assertEqual({'run_id': 'run-b', 'generation': 1}, self.hub.contexts._row('claude')['bound_run'])
        current = self.handle
        self.assertIs(current, self.reset())
        self.assertEqual(2, self.hub.contexts._row('claude')['context_generation'])
        self.assertEqual(1, len([event for event in self.ledger.replay(0)
                               if event['kind'] == 'context.reset.succeeded']))

    def test_unknown_old_receipt_stays_unknown_after_restore_and_explicit_reset(self):
        marker = 'UNCERTAIN-OLD-RUN-' + uuid.uuid4().hex
        self.submit('work-unknown', marker)
        self.native.db.execute("CREATE TRIGGER fail_receipt BEFORE UPDATE ON handoffs "
            "WHEN NEW.receipt IS NOT NULL BEGIN SELECT RAISE(ABORT, 'fixture receipt failure'); END")
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.native.wait_safe()
        self.assertIsNone(self.request('work-unknown')['response_started_at'])
        self.assertEqual(1, self.native.evidence()['unknown_intents'])
        self.native.db.execute('DROP TRIGGER fail_receipt')
        self.native.db.commit()
        session = self.native.session_id
        self.controller.revoke('claude')
        self.assertTrue(self.handle.cleanup_verified)
        self.cleanup_receipts.append({'host_reaped': self.handle.process.returncode is not None,
                                      'held_native_exit_verified': self.handle.cleanup_verified})
        self.restore()
        self.assertEqual(session, self.native.session_id)
        self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
        old_journal = self.active_recipe.journal
        old_rows = self.journal_rows(old_journal)
        self.submit('work-held', 'Cannot bypass the unresolved first handoff.')
        before = len(self.gateway.all_requests)
        self.assertEqual('HELD', self.deliver()['outcome'])
        self.assertEqual(before, len(self.gateway.all_requests))
        self.assertIsNone(self.request('work-held')['response_started_at'])
        self.close_a('work-unknown', 'work-held')
        self.reset()
        self.submit('work-b', 'NEW-CONTEXT-AFTER-EXPLICIT-TERMINAL', run='b')
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.native.wait_safe()
        self.assertNotIn(marker, self.history())
        self.assertEqual(old_rows, self.journal_rows(old_journal))
        self.assertIsNone(self.request('work-unknown')['response_started_at'])
        self.assertEqual('UNCONFIRMED', self.hub._state()['offers']['work-unknown']['claude']['outcome'])
        self.assertEqual(1, len([row for row in old_rows if row[2] is None and row[3] != 1]))
        self.assertEqual(0, self.native.evidence()['unknown_intents'])

