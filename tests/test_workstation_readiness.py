"""Concrete readiness orchestration with injected native responses, real origins.

No listener, Pi, Engine, namespace or SELinux qualification is supplied here.
"""
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import test_exec_state
from uas.pi_runtime import FixturePiRpcReceiver, NativeUnavailable
from uas.workstation_exec import ExecUnavailable


class WorkstationReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_exec_state.ExecStateTests.setUpClass()

    launch = test_exec_state.ExecStateTests.launch

    def setUp(self):
        test_exec_state.ExecStateTests.setUp(self)
        self.launch()
        self.right.recv(64)
        self.scope = {'room_id': 'alpha', 'participant_id': 'alice', 'run_id': 'run-1',
                      'generation': 1, 'context_generation': 1}
        self.proof = {'runtime_id': 'runtime-1', 'session_id': 'session-1',
                      'session_file': '/uas/runtime/seat-a/sessions/session-1.jsonl',
                      'source': 'native-empty-session-and-no-pending-messages'}
        self.receiver = Mock(spec=FixturePiRpcReceiver)
        self.receiver.scope = dict(self.scope)
        self.receiver.incarnation_id = self.attempt.incarnation
        self.receiver.runtime_version = '1.4.0'
        self.receiver.prove_fresh_context.return_value = dict(self.proof)
        self.attach = patch.object(FixturePiRpcReceiver, 'attach_workstation', return_value=self.receiver).start()
        self.addCleanup(patch.stopall)

    def ready(self):
        return self.attempt.attach_native(journal=Path(self.temp.name)/'native.db',
                                         scope=self.scope, profile_digest='d'*64)

    def test_fresh_proof_is_bound_and_durable_before_active_return(self):
        self.assertIs(self.ready(), self.receiver)
        self.assertEqual(self.attempt.state, 'active')
        metadata = self.attempt.native_readiness
        digest = metadata.pop('digest')
        self.assertEqual(digest, hashlib.sha256(json.dumps(metadata, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode()).hexdigest())
        self.assertEqual(metadata['origin_identity'], list(self.attempt.origin.identity))
        self.assertEqual(metadata['native'], self.proof)
        self.assertEqual(metadata['scope'], self.scope)
        stored = json.loads(self.attempt.journal.read_text())
        self.assertEqual(stored['native_readiness'], self.attempt.native_readiness)
        self.assertIsNone(stored['admission'])
        self.attach.assert_called_once()
        self.receiver.prove_fresh_context.assert_called_once_with()
        metadata['scope']['room_id'] = 'forged'
        self.assertEqual(self.attempt.native_readiness['scope']['room_id'], 'alpha')
        self.right.send(b'queued peer not consumed by readiness')
        self.assertEqual(self.left.recv(128), b'queued peer not consumed by readiness')

    def test_false_proof_fences_and_disposes(self):
        self.receiver.prove_fresh_context.return_value = False
        with self.assertRaises(ExecUnavailable):
            self.ready()
        self.assert_failed()

    def test_lost_fresh_response_fences_and_disposes(self):
        self.receiver.prove_fresh_context.side_effect = NativeUnavailable('response lost')
        with self.assertRaises(NativeUnavailable):
            self.ready()
        self.assert_failed()

    def test_wrong_context_session_path_fences(self):
        self.receiver.prove_fresh_context.return_value = {**self.proof,
            'session_file': '/uas/runtime/seat-b/sessions/other.jsonl'}
        with self.assertRaises(ExecUnavailable):
            self.ready()
        self.assert_failed()

    def test_receiver_scope_mismatch_fences_before_proof(self):
        self.receiver.scope = {**self.scope, 'run_id': 'other'}
        with self.assertRaises(ExecUnavailable):
            self.ready()
        self.receiver.prove_fresh_context.assert_not_called()
        self.assert_failed()

    def test_endpoint_loss_after_proof_fences(self):
        def proof():
            self.endpoint.replaced = True
            return self.proof
        self.receiver.prove_fresh_context.side_effect = proof
        with self.assertRaises(ExecUnavailable):
            self.ready()
        self.assert_failed()

    def test_readiness_audit_failure_never_returns_active(self):
        with patch.object(self.attempt, '_save', side_effect=OSError('full')):
            with self.assertRaises(OSError):
                self.ready()
        self.assert_failed()
        self.assertEqual(json.loads(self.attempt.journal.read_text())['state'], 'released')

    def test_attach_error_without_receiver_still_closes_transport(self):
        self.attach.side_effect = NativeUnavailable('partial attach')
        with self.assertRaises(NativeUnavailable):
            self.ready()
        self.assert_failed(receiver=False)

    def test_revocation_during_proof_cannot_activate(self):
        def proof():
            self.attempt.origin.revoke()
            return self.proof
        self.receiver.prove_fresh_context.side_effect = proof
        with self.assertRaises(ExecUnavailable):
            self.ready()
        self.assert_failed()

    def test_one_shot_attachment_does_not_reuse_rpc_or_journal(self):
        self.ready()
        before = self.attempt.journal.read_bytes()
        with self.assertRaises(ExecUnavailable):
            self.ready()
        self.attach.assert_called_once()
        self.assertEqual(self.attempt.journal.read_bytes(), before)

    def test_invalid_scope_fences_before_native_contact(self):
        self.scope['generation'] = True
        with self.assertRaises(ExecUnavailable):
            self.ready()
        self.attach.assert_not_called()
        self.assert_failed(receiver=False)

    def test_cleanup_closes_transport_and_receiver_even_if_peer_close_fails(self):
        self.receiver.prove_fresh_context.return_value = False
        peer = self.attempt.channel
        self.attempt.channel = Mock()
        self.attempt.channel.close.side_effect = OSError('peer close uncertain')
        transport = self.attempt.transport
        transport.close = Mock()
        with self.assertRaises(OSError):
            self.ready()
        transport.close.assert_called_once()
        self.assert_failed()
        peer.close()  # Real socket remains owned by this fixture, not the Mock.

    def test_native_metadata_and_admission_are_in_same_existing_journal(self):
        self.ready()
        self.attempt.admission = {'operation_id': 'a'*32, 'state': 'sending'}
        self.attempt._save()
        document = json.loads(self.attempt.journal.read_text())
        self.assertEqual(document['admission'], self.attempt.admission)
        self.assertEqual(document['native_readiness'], self.attempt.native_readiness)

    def assert_failed(self, receiver=True):
        self.assertEqual(self.attempt.state, 'uncertain')
        self.assertTrue(self.attempt.origin.revoked)
        self.assertIsNone(self.attempt.native_readiness)
        self.assertIsNone(self.attempt.native_receiver)
        self.assertIsNone(self.attempt.channel)
        self.assertIsNone(self.attempt.transport)
        self.assertIsNone(self.attempt.admission)
        if receiver:
            self.receiver.close.assert_called_once()

