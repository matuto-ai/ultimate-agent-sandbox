"""Durable cross-Run barrier with actual official Pi and trusted fixture Run facts."""
import base64
import json
import os
from pathlib import Path
import select
import tempfile
import time
import unittest
from unittest.mock import patch

from lifecycle_support import FileFixtureBackend
from uas.context import FixtureRun, FixtureRunTerminal
from uas.fixture_peer import FixtureReceiver
from uas.ledger import LedgerError, RoomLedger
from uas.lifecycle import FixtureSpec, Supervisor
from uas.participant import FixtureCredentials, FixtureSeat
from uas.peer import FixtureParticipant, FixturePeerHub, Message, Readiness, WorkRequest
from uas.pi_fixture import FixturePiRecipe
from uas.pi_runtime import FixturePiRpcReceiver, NativeUnavailable

INSTALL = os.environ.get('UAS_PI_INSTALL')


@unittest.skipUnless(INSTALL, 'Set UAS_PI_INSTALL for actual Pi cross-Run reset gate')
class PiResetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='uas-pi-reset-')
        self.root = Path(self.temp.name)
        project = self.root / 'project'
        project.mkdir()
        self.project_file = project / 'preserved.txt'
        self.project_file.write_text('Uncommitted Project bytes must survive reset.\n')
        self.backend = FileFixtureBackend(self.root / 'resources')
        self.supervisor = Supervisor(self.root / 'control', 'alpha', self.backend,
                                     authorize=lambda *_: True, revoke=self.backend.revoke)
        self.supervisor.start(FixtureSpec('alpha', 'fixture', (str(project),), *['sha256:' + c * 64 for c in 'abc']))
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', tuple(FixtureParticipant(p, 'actor-' + p)
                           for p in ('pi', 'sender-a', 'sender-b', 'sibling')), 'run-a',
                           initial_runs={'sender-b': FixtureRun('run-b'), 'sibling': FixtureRun('run-c')})
        self.senders = {p: self.hub.connect(p, p, p + '-inc', object()) for p in ('sender-a', 'sender-b')}
        self.controller = self.supervisor.participants(self.hub, FixtureCredentials())
        self.seat = FixtureSeat('pi', 'actor-pi', 'pi-fixture-profile', ('peer-traffic',), runtime='pi-fixture')
        self.handle = self.controller.launch_pi(self.seat, self.recipe(self.hub.contexts.scope('pi')))
        self.native = self.handle.connection.receiver
        self.workspace_file = self.root / 'native/workspace/dirty.txt'
        self.workspace_file.write_text('Retained fixture workspace bytes.\n')
        self.sibling_receiver = FixtureReceiver(self.root / 'sibling.db', 'alpha', 'sibling', 'unused')
        self.sibling = self.controller.launch(FixtureSeat('sibling', 'actor-sibling', 'profile', ('peer-traffic',)), self.sibling_receiver)
        self.assertTrue(select.select([self.sibling.process.stdout], [], [], 3)[0])
        self.assertTrue(json.loads(self.sibling.process.stdout.readline())['ready'])

    def recipe(self, scope):
        return FixturePiRecipe(INSTALL, self.root / 'native', scope=scope)

    def target_recipe(self):
        scope = {**self.hub.contexts.scope('pi'), 'run_id': 'run-b', 'context_generation': 2}
        return self.recipe(scope)

    def tearDown(self):
        if os.environ.get('UAS_PI_EVIDENCE'):
            row = self.hub.contexts._row('pi')
            current = self.controller.handles.get('pi')
            evidence = {'case': self.id(), 'runtime': 'Pi', 'version': '1.4.0',
                        'authority': 'linux-same-uid-fixture-only',
                        'context_generation': row['context_generation'], 'context_status': row['status'],
                        'bound_run': row['bound_run'], 'reserved_run': row['reserved_run'],
                        'reset_status': row['reset']['status'] if row['reset'] else None,
                        'process_alive': current is not None and current.process.poll() is None,
                        'reset_events': [e['kind'] for e in self.ledger.replay(0) if e['kind'].startswith('context.reset.')],
                        'canonical_github_run_completion': 'not-qualified'}
            with open(os.environ['UAS_PI_EVIDENCE'], 'a') as output:
                output.write(json.dumps(evidence, sort_keys=True) + '\n')
        self.controller.close()
        self.sibling_receiver.close()
        self.ledger.close()
        self.temp.cleanup()

    def deliver(self, handle=None):
        handle = handle or self.handle
        self.hub.observe(handle.connection, handle.connection.receiver.observe())
        return self.hub.deliver(handle.connection)

    def idle(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.native.observe() is Readiness.SAFE:
                return
            time.sleep(.01)
        self.fail('native did not settle')

    def script(self, commands):
        payload = base64.urlsafe_b64encode(json.dumps(commands).encode()).decode()
        self.native.rpc('prompt', message='/fixture-tools ' + payload)

    def command(self, id, action):
        return {'id': id, 'run_id': 'run-b', 'generation': 1, 'kind': 'command',
                'payload': {'request_id': 'work-b', 'action': action, 'reason': None}}

    def receive(self):
        self.assertTrue(select.select([self.handle.channel], [], [], 5)[0])
        result = self.controller.receive(self.handle)
        self.assertTrue(result['ok'], result)
        return result

    def old_context(self):
        self.hub.submit(self.senders['sender-a'], Message('message-a', 'run-a', 1, 'pi', 'OLD_RUN_SECRET_MARKER'))
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.idle()
        self.hub.submit(self.senders['sender-a'], Message('old-queued', 'run-a', 1, 'pi', 'Must stay old ledger history.'))
        self.assertEqual('run-a', self.hub.contexts._row('pi')['bound_run']['run_id'])

    def close_a(self):
        self.hub.contexts.close_run('close-a', 'run-a', FixtureRunTerminal.COMPLETED)

    def reset(self, recipe=None):
        if recipe is None:
            recipe = self.recipe({'room_id': 'alpha', 'participant_id': 'pi', 'run_id': 'run-b',
                                  'generation': 1, 'context_generation': 2})
        self.handle = self.controller.reset_pi('reset-a-b', self.seat, recipe,
                         expected_context_generation=1, target_run=FixtureRun('run-b'))
        self.native = self.handle.connection.receiver
        return self.handle

    def test_actual_reset_replaces_only_target_and_first_new_delivery_binds_new_generation(self):
        self.old_context()
        old, old_native = self.handle, self.native
        old_file = Path(old_native.initial_state['session_file'])
        before_file = old_file.read_bytes()
        sibling = self.hub.contexts.scope('sibling')
        # New Run may queue, but cannot reach an old native context.
        self.hub.submit(self.senders['sender-b'], WorkRequest('work-b', 'run-b', 1, 'pi', 'New Run work.'))
        self.assertNotIn('work-b', [item['id'] for item in self.hub._pending(self.handle.connection)])
        self.assertIsNone(self.hub._state()['traffic']['work-b']['response_started_at'])
        with self.assertRaisesRegex(LedgerError, 'PRECEDING_RUN_OPEN'):
            self.reset()
        self.assertIsNone(old.process.poll())
        self.close_a()
        self.reset()
        self.assertIsNotNone(old.process.poll())
        self.assertNotEqual(old.badge.incarnation_id, self.handle.badge.incarnation_id)
        self.assertNotEqual(old_native.initial_state['session_id'], self.native.initial_state['session_id'])
        self.assertEqual('actor-pi', self.handle.badge.actor_id)
        self.assertEqual('Retained fixture workspace bytes.\n', self.workspace_file.read_text())
        self.assertEqual(self.root / 'native/workspace', Path(os.readlink(f'/proc/{self.handle.process.pid}/cwd')))
        self.assertEqual(2, self.handle.connection.context_generation)
        self.assertEqual('run-b', self.hub.contexts.scope('pi')['run_id'])
        self.assertIsNone(self.hub.contexts._row('pi')['bound_run'])
        self.assertEqual(sibling, self.hub.contexts.scope('sibling'))
        self.assertIsNone(self.sibling.process.poll())
        self.assertEqual(before_file, old_file.read_bytes())
        self.assertEqual('Uncommitted Project bytes must survive reset.\n', self.project_file.read_text())
        self.assertNotIn('OLD_RUN_SECRET_MARKER', str(self.native.rpc('get_entries')))
        self.assertEqual('HELD', self.hub.deliver(old.connection)['outcome'])
        self.script([self.command('accept-b', 'accept'), self.command('complete-b', 'complete')])
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.receive(); self.receive(); self.idle()
        self.assertEqual({'run_id': 'run-b', 'generation': 1}, self.hub.contexts._row('pi')['bound_run'])
        self.assertEqual('COMPLETED', self.hub._state()['traffic']['work-b']['status'])
        self.assertIn('old-queued', self.hub._state()['traffic'])
        self.assertFalse(self.hub._state()['traffic']['old-queued']['deliveries'])
        handle = self.handle
        self.assertIs(handle, self.reset())
        self.assertEqual(2, self.hub.contexts._row('pi')['context_generation'])
        successes = [e for e in self.ledger.replay(0) if e['kind'] == 'context.reset.succeeded']
        self.assertEqual(1, len(successes))

    def test_failed_actual_native_proof_leaves_closed_run_unavailable_then_same_id_retry_succeeds(self):
        self.old_context(); self.close_a()
        old = self.handle
        with patch.object(FixturePiRpcReceiver, 'prove_fresh_context', side_effect=NativeUnavailable('lost fresh observation')):
            with self.assertRaises(NativeUnavailable):
                self.reset()
        self.assertIsNotNone(old.process.poll())
        self.assertFalse('pi' in self.controller.handles)
        self.assertEqual('FAILED', self.hub.contexts.reset_status('reset-a-b')['status'])
        self.assertEqual(1, self.hub.contexts._row('pi')['context_generation'])
        self.assertEqual('CLOSED', self.hub.contexts._domain()['runs']['run-a']['status'])
        self.reset()
        self.assertEqual(2, self.hub.contexts._row('pi')['context_generation'])
        self.assertEqual('SUCCEEDED', self.hub.contexts.reset_status('reset-a-b')['status'])

    def test_lost_success_ack_reconciles_once_and_restores_unflushed_fresh_context_without_priming(self):
        self.old_context(); self.close_a()
        original = self.hub.contexts.succeed_reset
        def lose_ack(*args, **kwargs):
            original(*args, **kwargs)
            raise LedgerError('LOST_SUCCESS_ACK')
        with patch.object(self.hub.contexts, 'succeed_reset', side_effect=lose_ack):
            with self.assertRaisesRegex(LedgerError, 'LOST_SUCCESS_ACK'):
                self.reset()
        self.assertEqual('SUCCEEDED', self.hub.contexts.reset_status('reset-a-b')['status'])
        self.assertEqual(2, self.hub.contexts._row('pi')['context_generation'])
        self.assertNotIn('pi', self.controller.handles)
        with self.assertRaisesRegex(LedgerError, 'RESTORE_REQUIRED'):
            self.reset()
        self.handle = self.controller.restore_pi(self.seat, self.recipe(self.hub.contexts.scope('pi')))
        self.native = self.handle.connection.receiver
        self.assertEqual(2, self.handle.connection.context_generation)
        self.assertFalse(Path(self.native.initial_state['session_file']).exists())
        self.hub.submit(self.senders['sender-b'], WorkRequest('work-b', 'run-b', 1, 'pi', 'First work after restored reset.'))
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.assertEqual('DELIVERED', self.hub._state()['traffic']['work-b']['status'])
        self.assertEqual(1, len([e for e in self.ledger.replay(0) if e['kind'] == 'context.reset.succeeded']))

    def test_unknown_first_flush_after_reset_cannot_use_empty_session_restore_exception(self):
        self.old_context(); self.close_a(); self.reset()
        self.native.rpc('prompt', message='/fixture-delay 2000')
        self.native.timeout = .15
        self.hub.submit(self.senders['sender-b'], WorkRequest('work-b', 'run-b', 1, 'pi', 'Unknown first handoff.'))
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertEqual(1, self.native.evidence()['unknown_intents'])
        self.assertFalse(Path(self.native.initial_state['session_file']).exists())
        self.controller.revoke('pi')
        with patch.object(FixturePiRecipe, 'spawn', side_effect=AssertionError('must not spawn')):
            with self.assertRaisesRegex(LedgerError, 'NATIVE_CONTEXT_RESTORE_UNVERIFIED'):
                self.controller.restore_pi(self.seat, self.recipe(self.hub.contexts.scope('pi')))
        self.assertEqual(2, self.hub.contexts._row('pi')['context_generation'])
        self.assertIsNone(self.hub._state()['traffic']['work-b']['response_started_at'])

    def test_actual_pending_reset_stopped_before_publication_cannot_advance_generation(self):
        self.old_context(); self.close_a()
        original = FixturePiRpcReceiver.prove_fresh_context
        observed = []
        def stop_after_proof(receiver, **kwargs):
            proof = original(receiver, **kwargs)
            observed.append(receiver.process)
            self.assertEqual('stopped', self.supervisor.stop()['phase'])
            return proof
        with patch.object(FixturePiRpcReceiver, 'prove_fresh_context', stop_after_proof):
            with self.assertRaises(Exception):
                self.reset()
        self.assertEqual(1, self.hub.contexts._row('pi')['context_generation'])
        self.assertEqual('FAILED', self.hub.contexts.reset_status('reset-a-b')['status'])
        self.assertTrue(all(p.poll() is not None for p in observed))
        self.assertNotIn('pi', self.controller.handles)
        self.assertEqual('CLOSED', self.hub.contexts._domain()['runs']['run-a']['status'])

    def test_private_native_checkpoint_failure_reaps_pending_child_and_retry_uses_fresh_session(self):
        self.old_context(); self.close_a()
        observed = []
        original = FixturePiRpcReceiver.prove_fresh_context
        def observe(receiver, **kwargs):
            observed.append((receiver.process, receiver.initial_state['session_id']))
            return original(receiver, **kwargs)
        with patch.object(FixturePiRpcReceiver, 'prove_fresh_context', observe), \
             patch.object(self.controller, '_save_pi_checkpoint', side_effect=OSError('checkpoint fsync failed')):
            with self.assertRaises(OSError):
                self.reset()
        self.assertEqual(1, self.hub.contexts._row('pi')['context_generation'])
        self.assertEqual('FAILED', self.hub.contexts.reset_status('reset-a-b')['status'])
        self.assertIsNotNone(observed[0][0].poll())
        self.assertIsNone(self.sibling.process.poll())
        self.reset()
        self.assertNotEqual(observed[0][1], self.native.initial_state['session_id'])
        self.assertEqual(2, self.handle.connection.context_generation)

    def test_compaction_is_not_fresh_native_context_or_cross_run_permission(self):
        self.old_context()
        for text in ('First native conversation ', 'Second native conversation '):
            self.native.rpc('prompt', message=text * 300)
            self.idle()
        self.native.rpc('compact', timeout=12)
        self.idle()
        with self.assertRaisesRegex(NativeUnavailable, 'fresh native context not proven'):
            self.native.prove_fresh_context()
        self.assertEqual(1, self.hub.contexts._row('pi')['context_generation'])
        self.hub.submit(self.senders['sender-b'], WorkRequest('work-b', 'run-b', 1, 'pi', 'Held across compaction.'))
        self.assertNotIn('work-b', [item['id'] for item in self.hub._pending(self.handle.connection)])
        self.assertIsNone(self.hub._state()['traffic']['work-b']['response_started_at'])
        self.close_a(); self.reset()
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])

    def test_success_then_active_manifest_failure_recovers_context_without_repeating_reset(self):
        self.old_context(); self.close_a()
        original = os.replace
        def fail_active(source, target):
            if Path(target) == self.controller.path:
                record = json.loads(Path(source).read_text())['seats'].get('pi')
                if record and record['reason'] in ('launched', 'launch-failed'):
                    raise OSError('active and compensating manifest persistence failed')
            return original(source, target)
        with patch('uas.participant.os.replace', side_effect=fail_active):
            with self.assertRaises(OSError):
                self.reset()
        self.assertTrue(self.controller.store_failed)
        self.assertNotIn('pi', self.controller.handles)
        self.assertEqual('SUCCEEDED', self.hub.contexts.reset_status('reset-a-b')['status'])
        self.assertEqual(2, self.hub.contexts._row('pi')['context_generation'])
        self.assertIsNone(self.sibling.process.poll())
        # Explicit reconstruction, not implicit authority repair or PID adoption.
        self.controller.close()
        self.supervisor = Supervisor(self.root / 'control', 'alpha', self.backend,
                                     authorize=lambda *_: True, revoke=self.backend.revoke)
        self.controller = self.supervisor.participants(self.hub, FixtureCredentials())
        self.handle = self.controller.restore_pi(self.seat, self.recipe(self.hub.contexts.scope('pi')))
        self.native = self.handle.connection.receiver
        self.assertEqual(2, self.handle.connection.context_generation)
        self.assertIs(self.handle, self.reset())
        self.assertEqual(1, len([e for e in self.ledger.replay(0) if e['kind'] == 'context.reset.succeeded']))
        self.assertNotIn('OLD_RUN_SECRET_MARKER', str(self.native.rpc('get_entries')))

    def test_duplicate_success_still_requires_current_manifest_authority(self):
        self.old_context(); self.close_a(); self.reset()
        before = self.ledger.snapshot()
        self.controller.store_failed = True
        with self.assertRaisesRegex(LedgerError, 'AUTHORITY_STORE_UNAVAILABLE'):
            self.reset()
        self.assertEqual(before, self.ledger.snapshot())
        self.assertEqual(2, self.hub.contexts._row('pi')['context_generation'])

    def test_replacement_wins_pending_reset_race_without_killing_new_owner_or_advancing_twice(self):
        self.old_context(); self.close_a()
        original = FixturePiRpcReceiver.prove_fresh_context
        first = []
        replacement = []
        def replace_after_proof(receiver, **kwargs):
            proof = original(receiver, **kwargs)
            if not first:
                first.append(receiver.process)
                replacement.append(self.reset())
            return proof
        with patch.object(FixturePiRpcReceiver, 'prove_fresh_context', replace_after_proof):
            with self.assertRaisesRegex(LedgerError, 'AUTHORITY_REVOKED'):
                self.reset()
        self.assertIsNotNone(first[0].poll())
        self.assertIsNone(replacement[0].process.poll())
        self.assertIs(replacement[0], self.controller.handles['pi'])
        self.assertEqual(2, self.hub.contexts._row('pi')['context_generation'])
        self.assertEqual(1, len([e for e in self.ledger.replay(0) if e['kind'] == 'context.reset.succeeded']))
        checkpoint = json.loads(self.controller._pi_checkpoint_path('pi').read_text())
        self.assertEqual(replacement[0].connection.receiver.initial_state['session_id'], checkpoint['native']['session_id'])

    def test_terminal_old_run_retains_unknown_native_handoff_without_redelivery_to_new_context(self):
        self.native.rpc('prompt', message='/fixture-delay 2000')
        self.native.timeout = .15
        self.hub.submit(self.senders['sender-a'], WorkRequest('unknown-old', 'run-a', 1, 'pi', 'Unknown old native handoff.'))
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertEqual(1, self.native.evidence()['unknown_intents'])
        self.hub.cancel('cancel-unknown-old', 'unknown-old', 'Explicit trusted fixture cancellation before terminal Run fact')
        self.hub.contexts.close_run('close-a', 'run-a', FixtureRunTerminal.CANCELLED)
        retained_offer = self.hub._state()['offers']['unknown-old'].copy()
        self.reset()
        import sqlite3
        database = sqlite3.connect((self.root / 'native/intent.db').as_uri() + '?mode=ro', uri=True)
        try:
            self.assertEqual(1, database.execute("SELECT count(*) FROM handoffs WHERE state='INTENT'").fetchone()[0])
        finally:
            database.close()
        self.assertEqual(retained_offer, self.hub._state()['offers']['unknown-old'])
        self.assertEqual('CANCELLED', self.hub._state()['traffic']['unknown-old']['status'])
        self.assertIsNone(self.hub._state()['traffic']['unknown-old']['response_started_at'])
        self.hub.submit(self.senders['sender-b'], Message('new-b', 'run-b', 1, 'pi', 'Only this new Run payload.'))
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        entries = self.native.rpc('get_entries')['data']['entries']
        self.assertNotIn('Unknown old native handoff.', str(entries))
        self.assertEqual(1, sum(e.get('customType') == 'uas-peer-v1' for e in entries))
