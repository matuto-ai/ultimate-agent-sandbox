"""Pure Claude controller fault tests: real ledger/files, synthetic processes.

No native runtime, child, socket, pidfd, signal, /proc probe or thread is used.
The controller constructor is deliberately bypassed; its manifest/ledger state
machine runs with explicit synthetic process identities and tripwires. These
tests establish source ordering only, never native reset or kernel authority.
"""
from contextlib import nullcontext
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from uas import claude_participant
from uas.claude_fixture import FixtureClaudeRecipe
from uas.context import FixtureRun, FixtureRunTerminal
from uas.ledger import LedgerError, RoomLedger
from uas.participant import FixtureCredentials, FixtureParticipantController, FixtureSeat
from uas.peer import FixtureParticipant, FixturePeerHub


class ClaudeParticipantSourceTests(unittest.TestCase):
    def setUp(self):
        # Defense in depth, not a claim that an unreviewed suite is pure. All
        # imports/setup/test bodies in this file are included in its audit.
        for target in ('subprocess.Popen', 'os.pidfd_open', 'os.kill', 'os.killpg',
                       'os.waitid', 'os.waitpid', 'select.select', 'socket.socket',
                       'socket.socketpair', 'threading.Thread.start',
                       'signal.pidfd_send_signal'):
            guard = patch(target, side_effect=AssertionError('forbidden native operation: ' + target))
            guard.start()
            self.addCleanup(guard.stop)
        for target, value in (('os.getuid', 1000), ('os.getgid', 1000)):
            guard = patch(target, return_value=value)
            guard.start()
            self.addCleanup(guard.stop)
        self.synthetic_fds = set()
        self.closed_fds = []

        def duplicate(_):
            descriptor = 901 + len(self.synthetic_fds)
            self.synthetic_fds.add(descriptor)
            return descriptor

        dup_guard = patch('os.dup', side_effect=duplicate)
        dup_guard.start()
        self.addCleanup(dup_guard.stop)
        real_close = os.close

        def close_descriptor(fd):
            if fd in self.synthetic_fds:
                self.closed_fds.append(fd)
            else:
                real_close(fd)

        close_guard = patch('os.close', side_effect=close_descriptor)
        close_guard.start()
        self.addCleanup(close_guard.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='uas-claude-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('claude', 'actor-claude'),
                           FixtureParticipant('sender-b', 'actor-b')), 'run-a',
                           initial_runs={'sender-b': FixtureRun('run-b')})
        self.room = {'instance_id': 'fixture-instance', 'phase': 'running',
                     'desired': 'running', 'spec': {'project_id': 'fixture'}}
        supervisor = SimpleNamespace(room_id='alpha', _read=lambda: self.room,
            _locked=lambda: nullcontext(), _allowed=Mock(), _sync_directory=Mock())
        self.controller = FixtureParticipantController.__new__(FixtureParticipantController)
        self.controller.supervisor = supervisor
        self.controller.hub = self.hub
        self.controller.credentials = FixtureCredentials()
        self.controller.instance = 'fixture-instance'
        self.controller.project_id = 'fixture'
        self.controller.controller_id = 'source-controller'
        self.controller.path = self.root / 'participants.json'
        self.controller.handles = {}
        self.controller.fenced = set()
        self.controller.store_failed = False
        self.controller.forge_broker = self.controller.read_service = None
        self.controller._alive = lambda handle: handle.pidfd >= 0 and handle.process.returncode is None
        self.controller._dispose = self.dispose
        self.controller._save({'version': 1, 'room_id': 'alpha', 'instance_id': 'fixture-instance',
            'controller_id': 'source-controller', 'seats': {}, 'retired_pids': []})
        self.seat = FixtureSeat('claude', 'actor-claude', 'profile', ('peer-traffic',), runtime='claude-fixture')
        self.receivers = []
        self.sessions = {}

    def dispose(self, handle):
        handle.cleanup_started = True
        handle.managed_receiver.close()
        handle.pidfd = -1
        handle.host_pidfd = None
        handle.cleanup_verified = True
        document = self.controller._read()
        record = document['seats'].get(handle.badge.participant_id)
        if record and record['incarnation_id'] == handle.badge.incarnation_id:
            record['cleanup_pending'] = False
            self.controller._save(document)

    def recipe(self, scope=None):
        recipe = FixtureClaudeRecipe.__new__(FixtureClaudeRecipe)
        recipe.directory = self.root / 'native'
        recipe.scope = scope or self.hub.contexts.scope('claude')
        recipe.context_directory = None
        recipe.workdir = recipe.directory / 'workspace'

        def start(incarnation, *, resume=False, context_directory=None, defer_ready=False):
            generation = recipe.scope['context_generation']
            directory = Path(context_directory) if resume else (
                recipe.directory / 'contexts' / str(generation) / ('attempt-' + uuid.uuid4().hex))
            directory.mkdir(parents=True, exist_ok=True)
            recipe.context_directory = directory
            recipe.home = directory / 'home'
            recipe.journal = directory / 'intent.db'
            if not resume:
                self.sessions[str(directory)] = str(uuid.uuid4())
            session = self.sessions[str(directory)]
            process = SimpleNamespace(pid=100 + len(self.receivers), returncode=None)
            receiver = SimpleNamespace(incarnation_id=incarnation, scope=dict(recipe.scope),
                session_id=session, process=process, native_pid=1000 + len(self.receivers),
                native_pidfd=900, host_pidfd=899, authorize=None,
                condition=nullcontext(), startup_error=None, startup_cleanup_succeeded=None,
                _kernel=Mock(return_value='S'), wait_ready=Mock(), wait_safe=Mock())
            receiver.prove_fresh_context = Mock(return_value={'session_id': session,
                'source': 'fresh-home-explicit-session-native-idle-no-input'})
            receiver.close = Mock(side_effect=lambda: setattr(process, 'returncode', 0))
            self.receivers.append(receiver)
            return receiver

        recipe.start = Mock(side_effect=start)
        return recipe

    def initial(self):
        return self.controller.launch_claude(self.seat, self.recipe())

    def close_a(self):
        self.hub.contexts.close_run('close-a', 'run-a', FixtureRunTerminal.COMPLETED)

    def target_recipe(self):
        return self.recipe({'room_id': 'alpha', 'participant_id': 'claude', 'run_id': 'run-b',
                            'generation': 1, 'context_generation': 2})

    def reset(self, recipe=None):
        return self.controller.reset_claude('reset-a-b', self.seat, recipe or self.target_recipe(),
            expected_context_generation=1, target_run=FixtureRun('run-b'))

    def events(self, kind):
        return [event for event in self.ledger.replay(0) if event['kind'] == kind]

    def checkpoint(self):
        return claude_participant._checkpoint_path(self.controller, 'claude')

    def test_checkpoint_failure_keeps_generation_and_closes_pending_receiver(self):
        old = self.initial()
        before = self.checkpoint().read_bytes()
        self.close_a()
        with patch.object(claude_participant, '_checkpoint', side_effect=OSError('synthetic fsync failure')):
            with self.assertRaisesRegex(OSError, 'fsync failure'):
                self.reset()
        self.assertIsNotNone(old.process.returncode)
        self.assertIsNotNone(self.receivers[-1].process.returncode)
        self.assertNotIn('claude', self.controller.handles)
        self.assertEqual(1, self.hub.contexts._row('claude')['context_generation'])
        self.assertEqual('FAILED', self.hub.contexts.reset_status('reset-a-b')['status'])
        self.assertEqual([], self.events('context.reset.succeeded'))
        self.assertEqual(before, self.checkpoint().read_bytes())

    def test_lost_success_ack_keeps_approved_checkpoint_and_restores_once(self):
        self.initial()
        self.close_a()
        succeed = self.hub.contexts.succeed_reset

        def lose_ack(*args, **kwargs):
            succeed(*args, **kwargs)
            raise LedgerError('LOST_SUCCESS_ACK')

        with patch.object(self.hub.contexts, 'succeed_reset', side_effect=lose_ack):
            with self.assertRaisesRegex(LedgerError, 'LOST_SUCCESS_ACK'):
                self.reset()
        native_session = self.receivers[-1].session_id
        self.assertEqual('SUCCEEDED', self.hub.contexts.reset_status('reset-a-b')['status'])
        self.assertEqual(2, self.hub.contexts._row('claude')['context_generation'])
        self.assertNotIn('claude', self.controller.handles)
        saved = json.loads(self.checkpoint().read_text())
        self.assertEqual(native_session, saved['native']['session_id'])
        retry = self.target_recipe()
        with self.assertRaisesRegex(LedgerError, 'RESET_SUCCEEDED_RESTORE_REQUIRED'):
            self.reset(retry)
        retry.start.assert_not_called()
        restore_recipe = self.recipe()
        handle = self.controller.restore_claude(self.seat, restore_recipe)
        self.assertEqual(native_session, handle.managed_receiver.session_id)
        self.assertEqual(2, handle.connection.context_generation)
        self.assertTrue(restore_recipe.start.call_args.kwargs['resume'])
        self.assertEqual(saved['context_directory'], restore_recipe.start.call_args.kwargs['context_directory'])
        self.assertEqual(1, len(self.events('context.reset.succeeded')))

    def test_late_pending_authority_revocation_never_attaches_or_advances(self):
        self.initial()
        self.close_a()
        recipe = self.target_recipe()
        start = recipe.start.side_effect

        def revoke_after_start(*args, **kwargs):
            receiver = start(*args, **kwargs)
            receiver.wait_safe.side_effect = lambda: self.controller._fence(
                self.controller._read(), 'claude', 'revoked', 'source-late-revocation')
            return receiver

        recipe.start.side_effect = revoke_after_start
        with self.assertRaisesRegex(LedgerError, 'AUTHORITY_REVOKED'):
            self.reset(recipe)
        self.assertIsNotNone(self.receivers[-1].process.returncode)
        self.assertNotIn('claude', self.controller.handles)
        self.assertEqual(1, len(self.events('peer.attached')), 'only the initial old context ever attached')
        self.assertEqual(1, self.hub.contexts._row('claude')['context_generation'])
        self.assertEqual('FAILED', self.hub.contexts.reset_status('reset-a-b')['status'])

    def test_exact_success_retry_uses_current_authority_without_native_spawn(self):
        self.initial()
        self.close_a()
        handle = self.reset()
        retry = self.target_recipe()
        self.assertIs(handle, self.reset(retry))
        retry.start.assert_not_called()
        self.assertEqual(1, len(self.events('context.reset.succeeded')))
        self.controller.store_failed = True
        with self.assertRaisesRegex(LedgerError, 'AUTHORITY_STORE_UNAVAILABLE'):
            self.reset(retry)
        retry.start.assert_not_called()

    def test_stale_checkpoint_is_rejected_before_native_effects(self):
        self.initial()
        self.controller.revoke('claude')
        original = json.loads(self.checkpoint().read_text())
        for name, changes in (
                ('generation', {'scope': {**original['scope'], 'context_generation': 2}}),
                ('room', {'room_instance': 'different-room-instance'}),
                ('participant', {'participant': 'different-participant'}),
                ('directory', {'directory': str(self.root / 'other')}),
                ('native-source', {'native': {**original['native'], 'source': 'unproved'}})):
            with self.subTest(name=name):
                self.checkpoint().write_text(json.dumps({**original, **changes}))
                recipe = self.recipe()
                with self.assertRaisesRegex(LedgerError, 'NATIVE_CONTEXT_RESTORE_UNVERIFIED'):
                    self.controller.restore_claude(self.seat, recipe)
                recipe.start.assert_not_called()
        self.assertEqual(1, len(self.receivers))

    def test_initial_attachment_is_published_only_after_pending_guard(self):
        recipe = self.recipe()
        with patch.object(self.controller, '_pending_pi_authority', side_effect=LedgerError('AUTHORITY_REVOKED')):
            with self.assertRaisesRegex(LedgerError, 'AUTHORITY_REVOKED'):
                self.controller.launch_claude(self.seat, recipe)
        self.assertEqual([], self.events('peer.attached'))
        self.assertFalse(self.checkpoint().exists())
        self.assertNotIn('claude', self.controller.handles)
        self.assertIsNotNone(self.receivers[0].process.returncode)

    def test_pending_sdk_host_is_owned_before_wait_and_stop_prevents_native_attachment(self):
        recipe = self.recipe()
        start = recipe.start.side_effect

        def own_then_wait(*args, **kwargs):
            self.assertTrue(kwargs['defer_ready'])
            receiver = start(*args, **kwargs)

            def stop_at_wait():
                handle = self.controller.handles['claude']
                self.assertIs(receiver, handle.managed_receiver)
                self.assertIsNone(handle.native_pid, 'initial SDK host is cleanup ownership only')
                record = self.controller._read()['seats']['claude']
                self.assertEqual('starting', record['status'])
                self.assertEqual(receiver.process.pid, record['pid'])
                self.assertTrue(record['cleanup_pending'], 'host-only startup must retain durable cleanup uncertainty')
                with self.assertRaisesRegex(LedgerError, 'AUTHORITY_REVOKED'):
                    self.controller._authority(handle, (receiver.process.pid, 1000, 1000))
                self.assertTrue(self.controller._revoke_all_locked(self.room))
                self.room.update(phase='stopped', desired='stopped')
                self.assertIsNotNone(receiver.process.returncode)

            receiver.wait_ready.side_effect = stop_at_wait
            return receiver

        recipe.start.side_effect = own_then_wait
        with self.assertRaisesRegex(LedgerError, 'ROOM_NOT_RUNNING'):
            self.controller.launch_claude(self.seat, recipe)
        self.assertEqual([], self.events('peer.attached'))
        self.assertFalse(self.checkpoint().exists())
        self.assertNotIn('claude', self.controller.handles)

    def test_active_manifest_failure_never_downgrades_durable_reset_success(self):
        self.initial()
        self.close_a()
        save = self.controller._save

        def fail_active(document):
            record = document['seats'].get('claude')
            if record and record['status'] == 'active':
                # Match _save's fail-closed classification after an uncertain
                # real manifest write, without invoking a native lifecycle.
                self.controller.store_failed = True
                raise OSError('synthetic active-manifest failure')
            return save(document)

        with patch.object(self.controller, '_save', side_effect=fail_active):
            with self.assertRaisesRegex(OSError, 'active-manifest failure'):
                self.reset()
        self.assertTrue(self.controller.store_failed)
        self.assertEqual('SUCCEEDED', self.hub.contexts.reset_status('reset-a-b')['status'])
        self.assertEqual(2, self.hub.contexts._row('claude')['context_generation'])
        self.assertEqual(1, len(self.events('context.reset.succeeded')))
        self.assertEqual([], self.events('context.reset.failed'))
        self.assertEqual(2, json.loads(self.checkpoint().read_text())['scope']['context_generation'])
        self.assertNotIn('claude', self.controller.handles)
        self.assertIsNotNone(self.receivers[-1].process.returncode)
        recipe = self.recipe()
        with self.assertRaisesRegex(LedgerError, 'AUTHORITY_STORE_UNAVAILABLE'):
            self.controller.restore_claude(self.seat, recipe)
        recipe.start.assert_not_called()

    def real_controller_disposer(self):
        # This calls the real disposal state machine. Its native effects are
        # mocked per test, while the default suite's native tripwires stay on.
        self.controller._dispose = FixtureParticipantController._dispose.__get__(self.controller)

    def test_failed_receiver_cleanup_retains_independent_fds_until_native_exit_and_host_reap(self):
        handle = self.initial()
        receiver = handle.managed_receiver
        held_native, held_host = handle.pidfd, handle.host_pidfd
        already_closed = list(self.closed_fds)
        self.real_controller_disposer()

        def lose_receiver_copies():
            receiver.process = receiver.native_pidfd = receiver.host_pidfd = None
            raise OSError('synthetic receiver cleanup failure after field release')

        receiver.close.side_effect = lose_receiver_copies
        native_exited = False

        def observed_exit(read, *_):
            self.assertEqual([held_native], read)
            return (list(read) if native_exited else [], [], [])

        with patch('uas.claude_runtime._dispose_sdk_process') as retry, \
             patch('uas.participant.select.select', side_effect=observed_exit):
            self.assertFalse(self.controller._revoke_all_locked(self.room))
            self.assertIs(handle, self.controller.handles['claude'])
            self.assertEqual((held_native, held_host), (handle.pidfd, handle.host_pidfd))
            self.assertTrue(handle.cleanup_started)
            self.assertFalse(handle.cleanup_verified)
            self.assertTrue(self.controller._read()['seats']['claude']['cleanup_pending'])
            self.assertEqual(already_closed, self.closed_fds, 'failed cleanup must not discard independent handles')
            retry.assert_not_called()
            # A successful disposal call alone is not process-exit evidence.
            self.assertFalse(self.controller._revoke_all_locked(self.room))
            retry.assert_called_with(handle.process, held_host, held_native)
            self.assertTrue(self.controller._read()['seats']['claude']['cleanup_pending'])
            handle.process.returncode = 0  # Synthetic independent host reap.
            self.assertFalse(self.controller._revoke_all_locked(self.room), 'reaped host is not native exit')
            self.assertEqual((held_native, held_host), (handle.pidfd, handle.host_pidfd))
            native_exited = True  # Only the held native pidfd's exit observation finishes cleanup.
            self.assertTrue(self.controller._revoke_all_locked(self.room))
            self.assertTrue(handle.cleanup_verified)
            self.assertEqual((-1, None), (handle.pidfd, handle.host_pidfd))
            self.assertFalse(self.controller._read()['seats']['claude']['cleanup_pending'])
            receiver.close.assert_called_once()
            self.assertEqual(already_closed + [held_native, held_host], self.closed_fds)
            before = retry.call_count
            self.assertTrue(self.controller._revoke_all_locked(self.room))
            self.assertEqual(before, retry.call_count, 'verified cleanup is idempotent')

    def test_constructor_uncertainty_without_handle_blocks_stop_and_all_relaunch_paths(self):
        recipe = self.recipe()
        recipe.start.side_effect = OSError('synthetic constructor failed before returning ownership')
        with self.assertRaisesRegex(OSError, 'constructor failed'):
            self.controller.launch_claude(self.seat, recipe)
        record = self.controller._read()['seats']['claude']
        self.assertTrue(record['cleanup_pending'])
        self.assertIsNone(record['pid'])
        self.assertIsNone(record['host_pid'])
        self.assertNotIn('claude', self.controller.handles)
        self.assertFalse(self.controller._revoke_all_locked(self.room))
        self.assertFalse(self.controller._revoke_all_locked(self.room))
        fresh = self.recipe()
        with self.assertRaisesRegex(LedgerError, 'NATIVE_STOP_UNVERIFIED'):
            self.controller.launch_claude(self.seat, fresh)
        fresh.start.assert_not_called()
        with self.assertRaisesRegex(LedgerError, 'NATIVE_CONTEXT_RESTORE_UNVERIFIED'):
            self.controller.restore_claude(self.seat, fresh)
        fresh.start.assert_not_called()
        self.close_a()
        target = self.target_recipe()
        with self.assertRaisesRegex(LedgerError, 'NATIVE_STOP_UNVERIFIED'):
            self.reset(target)
        target.start.assert_not_called()
        self.assertEqual(1, self.hub.contexts._row('claude')['context_generation'])
        self.assertFalse(self.controller._revoke_all_locked(self.room))
        self.assertTrue(self.controller._read()['seats']['claude']['cleanup_pending'])

    def test_launch_exception_preserves_handle_when_owned_cleanup_is_unverified(self):
        self.real_controller_disposer()
        recipe = self.recipe()
        start = recipe.start.side_effect

        def failed_ready(*args, **kwargs):
            receiver = start(*args, **kwargs)
            receiver.wait_ready.side_effect = LedgerError('SYNTHETIC_INITIALIZATION_FAILED')
            receiver.close.side_effect = OSError('synthetic cleanup outcome unknown')
            return receiver

        recipe.start.side_effect = failed_ready
        with self.assertRaisesRegex(LedgerError, 'NATIVE_STOP_UNVERIFIED'):
            self.controller.launch_claude(self.seat, recipe)
        handle = self.controller.handles['claude']
        self.assertIs(self.receivers[0], handle.managed_receiver)
        self.assertTrue(handle.cleanup_started)
        self.assertFalse(handle.cleanup_verified)
        self.assertGreaterEqual(handle.pidfd, 0)
        self.assertIsNotNone(handle.host_pidfd)
        self.assertTrue(self.controller._read()['seats']['claude']['cleanup_pending'])
        self.assertEqual([], self.events('peer.attached'))
        with patch('uas.claude_runtime._dispose_sdk_process') as retry:
            self.assertFalse(self.controller._revoke_all_locked(self.room))
            retry.assert_called_once_with(handle.process, handle.host_pidfd, handle.pidfd)
        self.assertIs(handle, self.controller.handles['claude'])

    def test_missing_credential_has_no_cleanup_uncertainty_and_explicit_recovery_can_launch(self):
        self.seat = FixtureSeat('claude', 'actor-claude', 'profile', ('peer-traffic',),
                               required_credentials=('forge',), runtime='claude-fixture')
        recipe = self.recipe()
        with self.assertRaisesRegex(LedgerError, 'MISSING_ACTOR_CREDENTIAL'):
            self.controller.launch_claude(self.seat, recipe)
        recipe.start.assert_not_called()
        self.assertFalse(self.controller._read()['seats']['claude']['cleanup_pending'])
        self.assertTrue(self.controller._revoke_all_locked(self.room))
        self.controller.credentials = FixtureCredentials(
            (('actor-claude', 'forge.fixture.invalid', 'forge', 'fixture-forge'),), ('fixture-forge',))
        handle = self.controller.launch_claude(self.seat, recipe)
        self.assertIs(handle, self.controller.handles['claude'])
        self.assertEqual('active', self.controller._read()['seats']['claude']['status'])

    def test_pending_startup_without_held_handle_cannot_claim_stop_or_launch_replacement(self):
        recipe = self.recipe()
        start = recipe.start.side_effect

        def lose_pending_handle(*args, **kwargs):
            receiver = start(*args, **kwargs)

            def missing_ownership_during_wait():
                held = self.controller.handles
                self.assertTrue(self.controller._read()['seats']['claude']['cleanup_pending'])
                self.controller.handles = {}
                try:
                    self.assertFalse(self.controller._revoke_all_locked(self.room))
                    self.assertIsNone(receiver.process.returncode)
                    fresh = self.recipe()
                    with self.assertRaisesRegex(LedgerError, 'NATIVE_STOP_UNVERIFIED'):
                        self.controller.launch_claude(self.seat, fresh)
                    fresh.start.assert_not_called()
                    self.assertTrue(self.controller._read()['seats']['claude']['cleanup_pending'])
                finally:
                    # The old stack still owns the synthetic handle and must
                    # perform its own cleanup; no replacement adopts its PID.
                    self.controller.handles = held

            receiver.wait_ready.side_effect = missing_ownership_during_wait
            return receiver

        recipe.start.side_effect = lose_pending_handle
        with self.assertRaisesRegex(LedgerError, 'AUTHORITY_REVOKED'):
            self.controller.launch_claude(self.seat, recipe)
        self.assertEqual([], self.events('peer.attached'))

