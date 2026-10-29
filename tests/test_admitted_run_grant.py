"""Controlled authenticated frames; no actual TLS, provider or native execution."""
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import pickle
import unittest
from unittest.mock import patch

from uas import human_mtls as subject
from uas.ledger import LedgerError, Origin
from uas.manager_actions import HumanSession
import test_human_mtls_source as support


class AdmittedRunGrantTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subject.ssl, 'SSLSocket', support.TLS).start()
        self.channel = support.TLS()
        self.human = Origin('operator', 'human', 'human-session', 'human-authority',
                            ('human-open-run', 'human-control-run'))
        self.grant = subject.HumanActionGrant('deployment', 'room', 'instance', 'manager',
            self.human, tuple(sorted(subject.ACTIONS)))
        self.fingerprint = hashlib.sha256(self.channel.certificate).hexdigest()
        self.bindings = subject.HumanActionBindings({self.fingerprint: self.grant})
        self.connection = self.bindings.accept(self.channel)
        self.frame = {'version': 1, 'action': 'open-run',
                      'payload': {'operation_id': 'open-one', 'issue_number': 12}}

    def mint(self):
        with self.connection.request(self.frame) as (_, session):
            lease = self.connection.run_admission_lease(session, 'open-one', 12)
        return lease, session

    def test_close_ends_human_session_not_one_run_revocation_handle(self):
        lease, session = self.mint()
        self.assertFalse(session.allowed('open-run'))
        self.connection.close()
        self.channel.fd = -1
        self.assertTrue(lease.require_current())
        self.assertEqual((lease.operation_id, lease.issue_number, lease.deployment_id,
            lease.room_id, lease.instance_id, lease.manager_id, lease.human),
            ('open-one', 12, 'deployment', 'room', 'instance', 'manager', self.human))
        self.assertFalse(hasattr(lease, 'allowed'))
        self.assertFalse(hasattr(lease, 'session'))
        self.assertFalse(hasattr(lease, '_channel'))
        self.assertFalse(hasattr(lease, '_connection'))
        self.assertIsNone(self.connection._active_session)
        self.assertIsNone(self.connection._active_open)
        self.assertFalse(any(isinstance(value, (HumanSession, subject.HumanActionConnection, support.TLS))
                             for value in vars(lease).values()))

    def test_revoke_and_rebind_cannot_revive_existing_handle(self):
        lease, _ = self.mint()
        self.bindings.revoke(self.fingerprint)
        with self.assertRaisesRegex(LedgerError, 'ADMITTED_RUN_GRANT_REVOKED'):
            lease.require_current()
        self.bindings.bind(self.fingerprint, self.grant)
        with self.assertRaisesRegex(LedgerError, 'ADMITTED_RUN_GRANT_REVOKED'):
            lease.require_current()
        self.connection = self.bindings.accept(self.channel)
        fresh, _ = self.mint()
        self.assertTrue(fresh.require_current())

    def test_equal_rebinding_revokes_and_other_identity_binding_does_not(self):
        lease, _ = self.mint()
        self.bindings.bind('a' * 64, self.grant)
        self.assertTrue(lease.require_current())
        self.bindings.bind(self.fingerprint, replace(self.grant))
        with self.assertRaisesRegex(LedgerError, 'ADMITTED_RUN_GRANT_REVOKED'):
            lease.require_current()

    def test_constructor_serialization_and_field_changes_are_denied(self):
        with self.assertRaisesRegex(LedgerError, 'AUTHENTICATED_RUN_FRAME_REQUIRED'):
            subject.AdmittedRunGrant()
        lease, _ = self.mint()
        with self.assertRaises(FrozenInstanceError):
            lease.issue_number = 13
        with self.assertRaises(TypeError):
            pickle.dumps(lease)
        self.assertIs(copy(lease), lease)
        self.assertIs(deepcopy(lease), lease)

    def test_mint_requires_original_live_session_not_equivalent_or_previous(self):
        _, previous = self.mint()
        with self.connection.request(self.frame) as (_, session):
            for wrong in (previous, replace(session), None):
                with self.subTest(wrong=type(wrong)), self.assertRaisesRegex(LedgerError, 'AUTHENTICATED_RUN_FRAME_REQUIRED'):
                    self.connection.run_admission_lease(wrong, 'open-one', 12)
        with self.assertRaisesRegex(LedgerError, 'AUTHENTICATED_RUN_FRAME_REQUIRED'):
            self.connection.run_admission_lease(session, 'open-one', 12)

    def test_mint_exact_request_snapshot_survives_mutation_of_handler_payload(self):
        with self.connection.request(self.frame) as (frame, session):
            frame['payload']['operation_id'] = 'different'
            frame['payload']['issue_number'] = 13
            with self.assertRaisesRegex(LedgerError, 'AUTHENTICATED_RUN_FRAME_REQUIRED'):
                self.connection.run_admission_lease(session, 'different', 13)
            lease = self.connection.run_admission_lease(session, 'open-one', 12)
            self.assertEqual((lease.operation_id, lease.issue_number), ('open-one', 12))

    def test_mint_denies_other_frame_scope_and_missing_human_capability(self):
        for action in ('observe', 'authorize-run-request', 'request-changes'):
            with self.connection.request({**self.frame, 'action': action}) as (_, session):
                with self.subTest(action=action), self.assertRaisesRegex(LedgerError, 'AUTHENTICATED_RUN_FRAME_REQUIRED'):
                    self.connection.run_admission_lease(session, 'open-one', 12)
        human = Origin('operator', 'human', 'human-session', 'human-authority', ())
        self.bindings.bind(self.fingerprint, replace(self.grant, human=human))
        self.connection = self.bindings.accept(self.channel)
        with self.connection.request(self.frame) as (_, session):
            with self.assertRaisesRegex(LedgerError, 'AUTHENTICATED_RUN_FRAME_REQUIRED'):
                self.connection.run_admission_lease(session, 'open-one', 12)

    def test_mint_denies_changed_scope_untyped_issue_and_revoke_during_frame(self):
        with self.connection.request(self.frame) as (_, session):
            for operation, issue in [('other', 12), ('open-one', 13), ('open-one', True), ('open-one', 0)]:
                with self.subTest(operation=operation, issue=issue), self.assertRaisesRegex(LedgerError, 'AUTHENTICATED_RUN_FRAME_REQUIRED'):
                    self.connection.run_admission_lease(session, operation, issue)
            self.bindings.revoke(self.fingerprint)
            with self.assertRaisesRegex(LedgerError, 'HUMAN_AUTHENTICATION_REVOKED'):
                self.connection.run_admission_lease(session, 'open-one', 12)

    def test_other_owner_thread_is_rejected_without_mutating_registry(self):
        lease, _ = self.mint()
        with patch.object(subject.threading, 'get_ident', return_value=-1):
            with self.assertRaisesRegex(LedgerError, 'HUMAN_AUTHENTICATION_OWNER_REQUIRED'):
                lease.require_current()
        self.assertTrue(lease.require_current())

    def test_exception_clears_original_session_and_frame(self):
        with self.assertRaisesRegex(RuntimeError, 'controlled'):
            with self.connection.request(self.frame) as (_, session):
                raise RuntimeError('controlled')
        self.assertIsNone(self.connection._active_session)
        self.assertIsNone(self.connection._active_open)
        self.assertFalse(session.allowed('open-run'))


if __name__ == '__main__': unittest.main()
