"""Pure receipt state and mocked process/socket observations; no native runs."""
from contextlib import ExitStack, nullcontext
import hashlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.git_transaction import (GitTransactionError, MAX_INPUT, ReferenceTransaction,
    TransactionSequence, ZERO, _decode, _wire, hook_main, parse_updates)

OLD, NEW = 'a' * 40, 'b' * 40
REF = 'refs/heads/main'
NONCE = 'c' * 64


def updates(old=OLD, new=NEW, ref=REF):
    return f'{old} {new} {ref}\n'.encode('ascii')


def sequence(*, kind='commit', old=OLD, ref=REF):
    return TransactionSequence(expected_old=old, expected_ref=ref, kind=kind)


class SequenceTests(unittest.TestCase):
    def test_exact_prepared_then_committed_is_required_not_stdout_or_head(self):
        proof = sequence()
        proof.accept('prepared', updates())
        with self.assertRaises(GitTransactionError):
            proof.committed_oid(required=True)
        proof.accept('committed', updates())
        self.assertEqual(NEW, proof.committed_oid(required=True))
        self.assertEqual(NEW, proof.committed_oid(required=True))
        with self.assertRaises(GitTransactionError):
            proof.committed_oid(required=False)  # Effects plus failed native result are unknown.

    def test_unborn_and_detached_target_transactions(self):
        for old, ref in ((None, REF), (OLD, 'HEAD')):
            proof = sequence(old=old, ref=ref)
            raw = updates(old or ZERO, ref=ref)
            proof.accept('prepared', raw)
            proof.accept('committed', raw)
            self.assertEqual(NEW, proof.committed_oid(required=True))

    def test_newer_preparing_head_can_resolve_to_exact_branch_only(self):
        proof = sequence()
        proof.accept('preparing', updates(ref='HEAD'))
        proof.accept('prepared', updates())
        proof.accept('committed', updates())
        self.assertEqual(NEW, proof.committed_oid(required=True))

    def test_identical_optional_head_row_is_allowed_but_not_other_branch(self):
        raw = updates() + updates(ref='HEAD')
        proof = sequence()
        proof.accept('prepared', raw)
        proof.accept('committed', updates(ref='HEAD') + updates())
        self.assertEqual(NEW, proof.committed_oid(required=True))
        for bad in (updates(ref='HEAD'), updates(ref='refs/heads/other'),
                    updates() + updates(new='c' * 40, ref='HEAD')):
            with self.subTest(raw=bad), self.assertRaises(GitTransactionError):
                sequence().accept('prepared', bad)

    def test_wrong_old_value_deletion_duplicate_commit_and_unpaired_states_fail_closed(self):
        for phases in ([('committed', updates())], [('aborted', updates())],
                       [('prepared', updates(old=ZERO))], [('prepared', updates(new=ZERO))],
                       [('prepared', updates()), ('prepared', updates())],
                       [('prepared', updates()), ('committed', updates(new='d' * 40))],
                       [('prepared', updates()), ('committed', updates()), ('prepared', updates())],
                       [('preparing', updates()), ('prepared', updates(new='d' * 40))]):
            proof = sequence()
            with self.subTest(phases=phases), self.assertRaises(GitTransactionError):
                for phase, raw in phases:
                    proof.accept(phase, raw)
            self.assertTrue(proof.failed)
            with self.assertRaises(GitTransactionError):
                proof.committed_oid(required=False)

    def test_cherry_auxiliary_phases_never_count_as_created_commit(self):
        proof = sequence(kind='cherry-pick')
        for ref in ('AUTO_MERGE', 'CHERRY_PICK_HEAD'):
            raw = updates(old=ZERO, ref=ref)
            proof.accept('prepared', raw)
            proof.accept('committed', raw)
        self.assertIsNone(proof.committed_oid(required=False))
        with self.assertRaises(GitTransactionError):
            proof.committed_oid(required=True)
        proof.accept('prepared', updates())
        proof.accept('committed', updates())
        raw = updates(old=ZERO, new=ZERO, ref='CHERRY_PICK_HEAD')
        proof.accept('prepared', raw)
        proof.accept('committed', raw)
        self.assertEqual(NEW, proof.committed_oid(required=True))

    def test_native_commit_cleanup_follows_complete_target_without_changing_created_oid(self):
        for preparing in (False, True):
            proof = sequence()
            if preparing:
                proof.accept('preparing', updates(ref='HEAD'))
            proof.accept('prepared', updates())
            proof.accept('committed', updates())
            cleanup = updates(old=ZERO, new=ZERO, ref='AUTO_MERGE')
            if preparing:
                proof.accept('preparing', cleanup)
            proof.accept('prepared', cleanup)
            with self.assertRaises(GitTransactionError):
                proof.committed_oid(required=True)
            proof.accept('committed', cleanup)
            self.assertEqual(NEW, proof.committed_oid(required=True))
            self.assertEqual(1, proof.target_count)

    def test_commit_cleanup_wrong_order_creation_other_refs_and_mixed_target_refuse(self):
        cleanup = updates(old=ZERO, new=ZERO, ref='AUTO_MERGE')
        for prior in ([], [('preparing', updates(ref='HEAD'))], [('prepared', updates())]):
            proof = sequence()
            for phase, raw in prior:
                proof.accept(phase, raw)
            with self.subTest(prior=prior), self.assertRaises(GitTransactionError):
                proof.accept('preparing', cleanup)
            self.assertTrue(proof.failed)
        for raw in (updates(old=ZERO, ref='AUTO_MERGE'), updates(new=ZERO, ref='AUTO_MERGE'),
                    updates(old=ZERO, new=ZERO, ref='CHERRY_PICK_HEAD'),
                    updates(old=ZERO, new=ZERO, ref='ORIG_HEAD'),
                    updates(old=ZERO, new=ZERO, ref='refs/heads/other'), cleanup + updates()):
            proof = sequence()
            proof.accept('prepared', updates())
            proof.accept('committed', updates())
            with self.subTest(raw=raw), self.assertRaises(GitTransactionError):
                proof.accept('prepared', raw)
            self.assertTrue(proof.failed)

    def test_commit_cleanup_requires_complete_matching_phases_and_never_rewrites_target(self):
        cleanup = updates(old=ZERO, new=ZERO, ref='AUTO_MERGE')
        cases = [[('preparing', cleanup)], [('prepared', cleanup)],
                 [('committed', cleanup)], [('prepared', cleanup), ('aborted', cleanup)],
                 [('prepared', cleanup), ('committed', updates(new=ZERO, ref='AUTO_MERGE'))],
                 [('prepared', cleanup), ('committed', cleanup), ('prepared', updates())]]
        for phases in cases:
            proof = sequence()
            proof.accept('prepared', updates())
            proof.accept('committed', updates())
            with self.subTest(phases=phases), self.assertRaises(GitTransactionError):
                for phase, raw in phases:
                    proof.accept(phase, raw)
                proof.committed_oid(required=True)
            self.assertEqual(NEW, proof.created)
            self.assertEqual(1, proof.target_count)

    def test_abort_complete_reset_is_not_created_commit_proof_and_keeps_partial_unknown(self):
        proof = sequence(kind='abort')
        for raw in (updates(ref='ORIG_HEAD'), updates(old='d' * 40)):
            proof.accept('prepared', raw)
            proof.accept('committed', raw)
        self.assertIsNone(proof.committed_oid(required=False))
        with self.assertRaises(GitTransactionError):
            proof.committed_oid(required=True)
        proof.accept('prepared', updates(new=ZERO, ref='AUTO_MERGE'))
        with self.assertRaises(GitTransactionError):
            proof.committed_oid(required=False)

    def test_auxiliary_ref_mixed_target_notes_stash_or_generic_ref_is_refused(self):
        for kind, raw in (('commit', updates(ref='AUTO_MERGE')),
                          ('cherry-pick', updates() + updates(ref='CHERRY_PICK_HEAD')),
                          ('cherry-pick', updates(ref='ORIG_HEAD')),
                          ('commit', updates(ref='refs/notes/commits')),
                          ('commit', updates(ref='refs/stash'))):
            with self.subTest(kind=kind, raw=raw), self.assertRaises(GitTransactionError):
                sequence(kind=kind).accept('prepared', raw)

    def test_parser_rejects_filename_style_injection_symbolic_values_and_bounds(self):
        for raw in (b'', updates()[:-1], updates().replace(b' ', b'  ', 1), updates() + updates(),
                    updates(ref='refs/heads/a\nb'), updates(ref='refs/heads/a\rb'),
                    updates(ref='refs/heads/a..b'), updates(ref='refs/heads/a.lock'),
                    updates(ref='refs/heads/.hidden'), updates(ref='refs/heads/a//b'),
                    updates().replace(OLD.encode(), b'ref:refs/heads/main'), b'x' * (MAX_INPUT + 1),
                    updates(ref='refs/heads/a[spoof]'), updates(ref='refs/heads/a\x00b')):
            with self.subTest(raw=raw[:100]), self.assertRaises(GitTransactionError):
                parse_updates(raw)
        self.assertEqual(((OLD, NEW, REF),), parse_updates(updates()))

    def test_phase_count_and_empty_success_are_bounded(self):
        proof = sequence(kind='cherry-pick')
        raw = updates(ref='AUTO_MERGE')
        for _ in range(32):
            proof.accept('prepared', raw)
            proof.accept('committed', raw)
        with self.assertRaises(GitTransactionError):
            proof.accept('prepared', raw)
        with self.assertRaises(GitTransactionError):
            sequence().committed_oid(required=True)
        self.assertIsNone(sequence().committed_oid(required=False))


class ReceiptProtocolTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (('getuid', 65530), ('geteuid', 65530), ('getgid', 65532), ('getegid', 65532), ('getpid', 456)):
            self.stack.enter_context(patch('uas.git_transaction.os.' + name, return_value=value))
        self.left, self.right = Mock(), Mock()
        self.right.fileno.return_value = 30
        self.left.send.side_effect = lambda raw: len(raw)
        self.pair = self.stack.enter_context(patch('uas.git_transaction.socket.socketpair', return_value=(self.left, self.right)))
        self.enable = self.stack.enter_context(patch('uas.git_transaction.enable'))
        self.stack.enter_context(patch('uas.git_transaction.secrets.token_hex', return_value=NONCE))
        self.alive = self.stack.enter_context(patch('uas.git_transaction.alive', return_value=True))
        self.sid = self.stack.enter_context(patch('uas.git_transaction.os.getsid', return_value=123))
        self.pgid = self.stack.enter_context(patch('uas.git_transaction.os.getpgid', return_value=123))
        self.proof = ReferenceTransaction('operation-1', expected_old=OLD, expected_ref=REF, kind='commit')
        self.addCleanup(self.proof.close)
        self.proof.native_pid = 123

    def packet(self, phase='prepared', raw=None):
        return {'kind': 'reference-transaction', 'operation': 'operation-1', 'nonce': NONCE,
                'phase': phase, 'updates': (updates() if raw is None else raw).decode('ascii')}

    def record(self, value=None, *, credentials=(789, 65530, 65532)):
        return SimpleNamespace(credentials=credentials, pidfd=99, data=_wire(self.packet() if value is None else value))

    def test_private_per_run_environment_and_kernel_bound_phases(self):
        self.assertEqual({'UAS_GIT_TX_FD': '30', 'UAS_GIT_TX_NONCE': NONCE,
            'UAS_GIT_TX_OPERATION': 'operation-1', 'UAS_GIT_TX_WORKER_PID': '456'}, self.proof.environment)
        self.proof._record(self.record())
        self.proof._record(self.record(self.packet('committed')))
        self.assertEqual(NEW, self.proof.sequence.committed_oid(required=True))
        self.assertEqual(2, self.left.send.call_count)
        self.assertEqual('ack', _decode(self.left.send.call_args.args[0])['kind'])
        self.alive.assert_called_with(99)

    def test_participant_other_worker_session_dead_sender_and_identity_reuse_refuse(self):
        for credentials in ((789, 65532, 65532), (789, 65530, 1), (0, 65530, 65532)):
            with self.subTest(credentials=credentials), self.assertRaises(GitTransactionError):
                self.proof._record(self.record(credentials=credentials))
        self.sid.return_value = 999
        with self.assertRaises(GitTransactionError):
            self.proof._record(self.record())
        self.sid.return_value = 123
        self.pgid.return_value = 999
        with self.assertRaises(GitTransactionError):
            self.proof._record(self.record())
        self.pgid.return_value = 123
        self.alive.side_effect = [True, False]
        with self.assertRaises(GitTransactionError):
            self.proof._record(self.record())
        self.left.send.assert_not_called()

    def test_wrong_nonce_operation_or_shape_cannot_acknowledge(self):
        for name, value in (('nonce', 'd' * 64), ('operation', 'other'), ('kind', 'stdout'), ('extra', 'x')):
            packet = self.packet()
            packet[name] = value
            with self.subTest(name=name), self.assertRaises(GitTransactionError):
                self.proof._record(self.record(packet))
        self.left.send.assert_not_called()

    def test_started_native_session_is_fixed_and_collection_must_stop_before_result(self):
        self.proof.native_pid = None
        fake = Mock()
        fake.is_alive.return_value = False
        with patch('uas.git_transaction.threading.Thread', return_value=fake):
            self.proof.start(123)
        fake.start.assert_called_once_with()
        with self.assertRaises(GitTransactionError):
            self.proof.committed_oid(required=False)
        with self.assertRaises(GitTransactionError):
            self.proof.start(123)
        self.proof.stop()
        self.assertIsNone(self.proof.committed_oid(required=False))
        fake.join.assert_called_once_with(timeout=1)

    def test_missing_or_wrong_native_session_never_starts_collector(self):
        self.proof.native_pid = None
        self.sid.return_value = 999
        with patch('uas.git_transaction.threading.Thread') as thread, self.assertRaises(GitTransactionError):
            self.proof.start(123)
        thread.assert_not_called()

    def test_used_or_stopped_receipt_cannot_be_reused_for_another_native_invocation(self):
        with self.assertRaises(GitTransactionError):
            self.proof.require_fresh()
        self.proof.native_pid = None
        self.proof.require_fresh()
        self.proof.stop()
        with self.assertRaises(GitTransactionError):
            self.proof.require_fresh()

    def test_hook_rejects_ambient_malformed_context_before_socket_contact(self):
        for field, value in (('UAS_GIT_TX_FD', '030'), ('UAS_GIT_TX_FD', '-1'),
                             ('UAS_GIT_TX_FD', 30), ('UAS_GIT_TX_WORKER_PID', '9' * 100),
                             ('UAS_GIT_TX_NONCE', 'x' * 64)):
            env = self.proof.environment
            env[field] = value
            with self.subTest(field=field, value=value), patch('uas.git_transaction.socket.socket') as socket_ctor, self.assertRaises(GitTransactionError):
                hook_main(['prepared'], environ=env, stdin=io.BytesIO(updates()))
            socket_ctor.assert_not_called()

    def test_receipt_collection_failure_and_incomplete_thread_are_sticky(self):
        with patch('uas.git_transaction.receive', side_effect=RuntimeError('private detail')):
            self.proof._collect()
        with self.assertRaises(GitTransactionError):
            self.proof.require()
        self.proof.thread = Mock()
        self.proof.thread.is_alive.return_value = True
        self.proof.stop()
        with self.assertRaises(GitTransactionError):
            self.proof.committed_oid(required=False)

    def test_canonical_wire_disallows_duplicate_keys_and_unbounded_unparsed_text(self):
        for raw in (b'{"kind":"one","kind":"two"}', b'[]', b'{ "x": 1 }', b'not json'):
            with self.subTest(raw=raw), self.assertRaises(GitTransactionError):
                _decode(raw)

    def test_hook_requires_exact_worker_ack_for_bounded_native_stdin(self):
        raw = updates()
        ack = {'kind': 'ack', 'operation': 'operation-1', 'nonce': NONCE,
               'phase': 'prepared', 'digest': hashlib.sha256(raw).hexdigest()}
        channel = Mock()
        channel.__enter__ = Mock(return_value=channel)
        channel.__exit__ = Mock(return_value=False)
        channel.send.side_effect = lambda data: len(data)
        record = self.record(ack, credentials=(456, 65530, 65532))
        with patch('uas.git_transaction.socket.socket', return_value=channel), patch('uas.git_transaction.receive', return_value=nullcontext(record)):
            self.assertEqual(0, hook_main(['prepared'], environ=self.proof.environment, stdin=io.BytesIO(raw)))
        self.assertEqual(self.packet(), _decode(channel.send.call_args.args[0]))
        record.credentials = (456, 65532, 65532)
        with patch('uas.git_transaction.socket.socket', return_value=channel), patch('uas.git_transaction.receive', return_value=nullcontext(record)), self.assertRaises(GitTransactionError):
            hook_main(['prepared'], environ=self.proof.environment, stdin=io.BytesIO(raw))

    def test_nonattributed_hook_is_noop_but_partial_context_and_bad_stdin_refuse(self):
        with patch('uas.git_transaction.socket.socket') as socket_ctor:
            self.assertEqual(0, hook_main(['prepared'], environ={}, stdin=io.BytesIO(b'arbitrary')))
            with self.assertRaises(GitTransactionError):
                hook_main(['prepared'], environ={'UAS_GIT_TX_FD': '30'}, stdin=io.BytesIO(updates()))
            with self.assertRaises(GitTransactionError):
                hook_main(['prepared'], environ=self.proof.environment, stdin=io.BytesIO(b'bad\n'))
        socket_ctor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
