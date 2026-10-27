"""Pure controller composition: no proc, socket, native Git or process effects."""
import base64
from contextlib import nullcontext
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from uas.forge import ForgeBinding
from uas.git_controller import GitCheckout, GitCoordinator
from uas.git_policy import GitIdentity
from uas.git_provenance import GitProvenance, parse_commit
from uas.git_worker import TrustedGitWorker
from uas.ledger import LedgerError, Origin

A = Origin('alice', 'seat-a', 'inc-a', 'epoch1', ('git-read', 'git-push'))
B = Origin('bob', 'seat-b', 'inc-b', 'epoch2', ('git-read', 'git-push'))
OLD = 'a' * 40

def commit(parent=OLD, *, author='Alice <alice@example.test> 1 +0000', message=b'new\n'):
    return (b'tree ' + b'1' * 40 + b'\n' + (b'parent ' + parent.encode() + b'\n' if parent else b'')
            + b'author ' + author.encode() + b'\ncommitter Alice <alice@example.test> 2 +0000\n\n' + message)


def blob(name, data):
    return [{'kind': 'blob', 'name': name, 'bytes': len(data), 'count': 1,
             'sha256': hashlib.sha256(data).hexdigest()},
            {'kind': 'blob-part', 'name': name, 'index': 0, 'data': base64.b64encode(data).decode()}]


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = GitProvenance(Path(self.tmp.name) / 'provenance.db', 'room', 'project')
        self.addCleanup(self.store.close)
        self.binding = ForgeBinding('room', 'project', 'org/repo', 'github.com')
        self.checkout = GitCheckout('checkout', '/project', '/project/.git', '/project/.git',
                                    '/project/.git/config', '/helpers', 1000)
        self.origin = A
        self.authority = SimpleNamespace(origin=A, current=Mock(return_value=True))
        self.worker = object.__new__(TrustedGitWorker)
        self.worker.launch = SimpleNamespace(seat=SimpleNamespace(room_id='room', room_instance='instance',
            participant_id='seat-a', actor_id='alice'), endpoint=SimpleNamespace(require=Mock()),
            origin=SimpleNamespace(revoked=False, pidfd=55), state='active', close=Mock(), channel=Mock())
        self.worker.configure, self.worker.reply, self.worker.require = Mock(), Mock(), Mock()
        self.worker.finish = Mock(return_value={'worker_identity': [7, 8], 'quiescent': True, 'exited': True})
        self.broker = SimpleNamespace(relay=Mock())
        self.coordinator = GitCoordinator(self.binding, 'instance', {'alice': GitIdentity('alice', 'Alice', 'alice@example.test')},
            (self.checkout,), self.store, self.broker, lambda origin: self.worker,
            backend_fd=19, backend_sha256='f' * 64, lifecycle_lock=nullcontext,
            run_scope=lambda origin, checkout: {'run_id': 'run1', 'generation': 1})
        self.alive = patch('uas.git_controller.alive', return_value=True).start()
        self.addCleanup(patch.stopall)
        # Any accidentally introduced native effects fail the pure suite.
        for target in ('os.fork', 'os.pidfd_open', 'socket.socket', 'socket.socketpair', 'subprocess.Popen'):
            patch(target, side_effect=AssertionError('native effect forbidden')).start()

    def frames(self, *, source=None, raw=None, result=None, prefix=()):
        preflight = {'kind': 'preflight', 'head': OLD, 'parent': OLD, 'head_ref': 'refs/heads/main',
                     'source_oid': parse_commit(source).oid if source else None}
        frames = [preflight] + (blob('source', source) if source else []) + list(prefix)
        frames += [result or {'kind': 'result', 'returncode': 0, 'conflict': False,
            'commit_oid': parse_commit(raw).oid if raw else None}]
        frames += blob('stdout', b'native output\n') + blob('stderr', b'') + blob('commit', raw or b'')
        self.worker.receive = Mock(side_effect=frames)
        return frames

    def request(self, argv, **changes):
        value = {'kind': 'git', 'id': 'op1', 'invoked_as': 'git', 'argv': argv, 'cwd': '/project'}
        value.update(changes)
        return self.coordinator.request(value, self.authority)

    def test_canonical_commit_from_exact_worker(self):
        raw = commit(); self.frames(raw=raw)
        result = self.request(['commit', '-m', 'new'])
        self.assertEqual(result['status'], 'COMMITTED')
        self.assertEqual(result['receipt']['commit_oid'], parse_commit(raw).oid)
        self.assertEqual(result['receipt']['contributors'], ['alice'])
        self.worker.configure.assert_called_once()
        self.worker.launch.close.assert_called_once()

    def test_public_identity_fields_rejected(self):
        with self.assertRaisesRegex(LedgerError, 'INVALID_GIT_REQUEST'):
            self.request(['status'], actor_id='bob')
        self.worker.configure.assert_not_called()

    def test_cwd_not_configured_root_rejected(self):
        with self.assertRaisesRegex(LedgerError, 'GIT_CHECKOUT_ROOT_REQUIRED'):
            self.request(['status'], cwd='/project/subdir')

    def test_wrong_worker_actor_never_configures(self):
        self.worker.launch.seat.actor_id = 'bob'
        with self.assertRaises(Exception): self.request(['status'])
        self.worker.configure.assert_not_called()

    def test_public_raw_author_claim_cannot_finish(self):
        raw = commit(author='Mallory <evil@example.test> 1 +0000'); self.frames(raw=raw)
        with self.assertRaisesRegex(LedgerError, 'GIT_AUTHOR_MISMATCH'):
            self.request(['commit', '-m', 'new'])
        self.assertEqual(self.store.pending_checkout('checkout')['status'], 'UNKNOWN')

    def test_repeated_commit_never_gets_go(self):
        raw = commit(); self.frames(raw=raw); self.request(['commit', '-m', 'new'])
        self.worker.reply.reset_mock(); self.frames(raw=raw)
        with self.assertRaisesRegex(LedgerError, 'GIT_COMMAND_ALREADY_CONSUMED'):
            self.request(['commit', '-m', 'new'])
        self.assertNotIn({'kind': 'go', 'operation_id': 'op1'}, [call.args[0] for call in self.worker.reply.call_args_list])

    def test_channel_loss_after_go_fences_checkout(self):
        self.frames(raw=commit())
        self.worker.receive.side_effect = [self.worker.receive.side_effect.__next__(), OSError('lost')]
        with self.assertRaises(OSError): self.request(['commit', '-m', 'new'])
        self.assertEqual(self.store.pending_checkout('checkout')['status'], 'UNKNOWN')

    def test_unknown_never_runs_second_mutation(self):
        self.frames(result={'kind': 'result', 'returncode': 1, 'conflict': False, 'commit_oid': None})
        self.assertEqual(self.request(['commit', '-m', 'new'])['status'], 'UNKNOWN')
        self.frames()
        with self.assertRaisesRegex(LedgerError, 'GIT_CHECKOUT_FENCED'):
            self.request(['add', '-A'], id='op2')

    def test_cherry_requires_authenticated_advertisement(self):
        source = commit(parent=None); self.frames(source=source)
        with self.assertRaisesRegex(LedgerError, 'GIT_SOURCE_UNANCHORED'):
            self.request(['cherry-pick', parse_commit(source).oid])
        self.assertIsNone(self.store.pending_checkout('checkout'))

    def test_cherry_conflict_remains_source_bound(self):
        source = commit(parent=None); oid = parse_commit(source).oid
        self.store.record_advertisements('other/repo', [oid])
        self.frames(source=source, result={'kind': 'result', 'returncode': 1, 'conflict': True, 'commit_oid': None})
        receipt = self.request(['cherry-pick', oid])['receipt']
        self.assertEqual((receipt['status'], receipt['source_oid']), ('CONFLICT', oid))
        wrong = commit(parent=None, message=b'wrong\n'); self.frames(source=wrong)
        with self.assertRaisesRegex(LedgerError, 'GIT_CONFLICT_STATE_MISMATCH'):
            self.request(['cherry-pick', '--continue'], id='op2')

    def test_cherry_finish_inherits_source_taint(self):
        source = commit(parent=None); oid = parse_commit(source).oid
        self.store.record_advertisements('other/repo', [oid])
        self.store.anchor_source('other/repo', oid, source, contributors=('bob',))
        raw = commit(message=b'new\n\n(cherry picked from commit ' + oid.encode() + b')\n')
        self.frames(source=source, raw=raw)
        result = self.request(['cherry-pick', oid])
        self.assertEqual(result['receipt']['contributors'], ['alice', 'bob'])

    def test_read_cannot_open_push_stream(self):
        self.frames(prefix=({'kind': 'ssh-open', 'argv': ['git@github.com', "git-receive-pack 'org/repo.git'"]},))
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.request(['fetch'])
        self.broker.relay.assert_not_called()

    def test_advertisements_only_from_trusted_completed_read(self):
        oid = 'b' * 40
        self.frames(prefix=({'kind': 'ssh-open', 'argv': ['git@github.com', "git-upload-pack 'org/repo.git'"]},))
        self.broker.relay.return_value = {'kind': 'exit', 'status': 'OK', 'advertised': [oid]}
        self.request(['fetch'])
        self.assertTrue(self.store.was_advertised('org/repo', oid))

    def test_nonzero_signal_is_not_reported_success(self):
        self.frames(result={'kind': 'result', 'returncode': -15, 'conflict': False, 'commit_oid': None})
        result = self.request(['status'])
        self.assertEqual(result['code'], 128)

    def test_revocation_before_dispatch_never_gets_go(self):
        self.authority.current.side_effect = [True, True, True, False]
        # current contracts raise on revocation; false must not be accepted either.
        self.authority.current.side_effect = LedgerError('REVOKED')
        with self.assertRaisesRegex(LedgerError, 'REVOKED'): self.request(['status'])
        self.worker.configure.assert_not_called()

    def become_bob(self):
        self.authority.origin = B
        self.worker.launch.seat.actor_id, self.worker.launch.seat.participant_id = 'bob', 'seat-b'
        self.coordinator.identities['bob'] = GitIdentity('bob', 'Bob', 'bob@example.test')

    def test_current_run_required_only_for_mutations(self):
        self.coordinator.run_scope = lambda *_: None
        self.frames()
        self.assertEqual(self.request(['status'])['status'], 'OK')
        self.worker.configure.reset_mock()
        with self.assertRaisesRegex(LedgerError, 'GIT_RUN_SCOPE_UNAVAILABLE'):
            self.request(['add', '-A'])
        self.worker.configure.assert_not_called()

    def test_staging_actor_retained_on_other_actor_commit(self):
        self.frames(); self.request(['add', '-A'])
        self.become_bob()
        raw = commit().replace(b'Alice <alice@example.test>', b'Bob <bob@example.test>')
        self.frames(raw=raw)
        result = self.request(['commit', '-m', 'new'], id='op2')
        self.assertEqual(result['receipt']['contributors'], ['alice', 'bob'])
        self.assertEqual(self.store.scope_contributors({'run_id': 'run1', 'generation': 1}), ['alice', 'bob'])

    def test_explicit_new_run_does_not_erase_or_inherit_unrelated_history(self):
        self.frames(); self.request(['add', '-A'])
        self.become_bob()
        self.coordinator.run_scope = lambda *_: {'run_id': 'run2', 'generation': 1}
        raw = commit().replace(b'Alice <alice@example.test>', b'Bob <bob@example.test>')
        self.frames(raw=raw)
        result = self.request(['commit', '-m', 'new'], id='op2')
        self.assertEqual(result['receipt']['contributors'], ['bob'])
        self.assertEqual(self.store.scope_contributors({'run_id': 'run1', 'generation': 1}), ['alice'])

    def test_run_generation_change_fences_before_go(self):
        calls = [0]
        def scope(*_):
            calls[0] += 1
            return {'run_id': 'run1', 'generation': 1 if calls[0] < 3 else 2}
        self.coordinator.run_scope = scope
        self.frames(raw=commit())
        with self.assertRaises(Exception): self.request(['commit', '-m', 'new'])
        self.assertNotIn({'kind': 'go', 'operation_id': 'op1'}, [call.args[0] for call in self.worker.reply.call_args_list])

    def test_historical_source_proof_bound_to_advertised_tip(self):
        import json
        from uas.git_source_proof import build
        source = commit(parent=None); source_oid = parse_commit(source).oid
        tip = commit(parent=source_oid, message=b'tip\n'); tip_oid = parse_commit(tip).oid
        self.store.record_advertisements('other/repo', [tip_oid])
        proof = build(source_oid, [tip_oid], {source_oid: source, tip_oid: tip}.get)
        raw = commit(message=b'new\n\n(cherry picked from commit ' + source_oid.encode() + b')\n')
        frames = self.frames(source=source, raw=raw)
        frames[3:3] = blob('source-proof', json.dumps(proof).encode())
        self.worker.receive = Mock(side_effect=frames)
        result = self.request(['cherry-pick', source_oid])
        self.assertEqual(result['status'], 'COMMITTED')
        self.assertFalse(self.store.was_advertised('other/repo', source_oid))
        event = [event for event in self.store.audit_events() if event['kind'] == 'source-anchored'][0]
        self.assertEqual(event['metadata']['advertised_tip'], tip_oid)

    def test_local_write_lost_worker_fences_checkout_across_reopen(self):
        self.frames()
        self.worker.receive.side_effect = [next(self.worker.receive.side_effect), OSError('lost')]
        with self.assertRaises(OSError): self.request(['add', '-A'])
        self.assertEqual(self.store.pending_worker('checkout'), 'op1')
        self.store.close()
        self.store = GitProvenance(Path(self.tmp.name) / 'provenance.db', 'room', 'project')
        self.addCleanup(self.store.close)
        self.coordinator.provenance = self.store
        self.frames(); self.worker.configure.reset_mock()
        with self.assertRaisesRegex(LedgerError, 'GIT_WORKER_QUIESCENCE_UNKNOWN'):
            self.request(['status'], id='op2')
        self.worker.configure.assert_not_called()

    def test_cleanup_exit_uncertainty_retains_all_command_lease(self):
        self.frames()
        self.worker.finish.side_effect = OSError('not exited')
        with self.assertRaises(OSError): self.request(['status'])
        self.assertEqual(self.store.pending_worker('checkout'), 'op1')
        self.worker.launch.close.assert_called_once()

    def test_verified_cleanup_releases_but_never_replays_original_id(self):
        self.frames(); self.request(['add', '-A'])
        self.assertIsNone(self.store.pending_worker('checkout'))
        self.worker.configure.reset_mock()
        with self.assertRaisesRegex(LedgerError, 'GIT_COMMAND_ALREADY_CONSUMED'):
            self.request(['add', '-A'])
        self.worker.configure.assert_not_called()
        self.frames(); self.request(['status'], id='op2')

    def test_launch_exception_leaves_durable_worker_reservation(self):
        self.coordinator.worker_factory = Mock(side_effect=OSError('launch unknown'))
        with self.assertRaises(OSError): self.request(['status'])
        self.assertEqual(self.store.pending_worker('checkout'), 'op1')

    def test_authenticated_worker_failure_can_prove_cleanup_without_actor_authority(self):
        self.worker.receive = Mock(return_value={'kind': 'worker-failed', 'code': 'GIT_WORKER_COMMAND_FAILED'})
        with self.assertRaisesRegex(LedgerError, 'GIT_WORKER_COMMAND_FAILED'):
            self.request(['add', '-A'])
        self.assertIsNone(self.store.pending_worker('checkout'))
        self.worker.finish.assert_called_once_with('op1')

    def test_amend_in_new_run_inherits_replaced_controlled_commit(self):
        raw = commit(); old = parse_commit(raw).oid
        self.frames(raw=raw); self.request(['commit', '-m', 'new'])
        self.become_bob()
        self.coordinator.run_scope = lambda *_: {'run_id': 'run2', 'generation': 1}
        amended = commit().replace(b'Alice <alice@example.test>', b'Bob <bob@example.test>')
        frames = self.frames(raw=amended); frames[0]['head'] = old
        self.worker.receive = Mock(side_effect=frames)
        receipt = self.request(['commit', '--amend', '-m', 'new'], id='op2')['receipt']
        self.assertEqual(receipt['contributors'], ['alice', 'bob'])
        self.assertEqual(receipt['replaced_oid'], old)
