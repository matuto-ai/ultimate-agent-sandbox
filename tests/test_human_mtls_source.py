"""Controlled TLS seam only: no real connection, certificate or action execution."""
from dataclasses import FrozenInstanceError, replace
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from uas import human_mtls as subject
from uas.ledger import LedgerError, Origin, _json
from uas.manager_actions import HumanSession
from uas.manager_transport import RoomCertificateBindings
from uas.room_remote_start import StartCertificateBindings


class TLS:
    def __init__(self):
        self.context = SimpleNamespace(verify_mode=subject.ssl.CERT_REQUIRED,
            minimum_version=subject.ssl.TLSVersion.TLSv1_3)
        self.server_side = True
        self.fd, self.protocol, self.certificate = 7, 'TLSv1.3', b'controlled-client-certificate'

    def fileno(self):
        return self.fd

    def version(self):
        return self.protocol

    def getpeercert(self, *, binary_form):
        if binary_form is not True:
            raise AssertionError('exact DER fingerprint required')
        return self.certificate


class HumanMTLSSourceTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subject.ssl, 'SSLSocket', TLS).start()
        self.human = Origin('operator', 'human', 'operator-session', 'operator-authority',
                            ('human-control-run', 'human-open-run', 'human-approve-run'))
        self.grant = self.make_grant(actions=tuple(sorted(subject.ACTIONS)))
        self.channel = TLS()
        self.fingerprint = hashlib.sha256(self.channel.certificate).hexdigest()
        self.bindings = subject.HumanActionBindings({self.fingerprint: self.grant})
        self.connection = self.bindings.accept(self.channel)
        self.frame = {'version': 1, 'action': 'open-run', 'payload': {'operation_id': 'original'}}
        self.receive = patch.object(subject, 'receive_frame', return_value=self.frame).start()

    def make_grant(self, **changes):
        fields = dict(deployment_id='deployment', room_id='room', instance_id='exact-instance',
                      manager_id='manager', human=self.human)
        return subject.HumanActionGrant(**(fields | changes))

    def test_exact_grant_and_origin_create_only_frame_scoped_session(self):
        with self.connection.receive() as (frame, session):
            self.assertIs(frame, self.frame)
            self.assertIs(type(session), HumanSession)
            self.assertIs(session.human, self.human)
            self.assertEqual(session.metadata(), {'deployment_id': 'deployment', 'room_id': 'room',
                'instance_id': 'exact-instance', 'manager_id': 'manager', 'human_origin': self.human.canonical()})
            self.assertTrue(session.allowed('open-run'))
            self.assertFalse(session.allowed('stop'))
        self.assertFalse(session.allowed('open-run'))
        self.receive.assert_called_once_with(self.channel, path=subject.PATH)

    def test_empty_scope_default_denies_even_with_capable_origin(self):
        self.bindings.bind(self.fingerprint, self.make_grant())
        connection = self.bindings.accept(self.channel)
        with self.assertRaisesRegex(LedgerError, 'HUMAN_ACTION_DENIED'):
            with connection.receive():
                self.fail('no session for empty action grant')

    def test_required_action_pairs_must_be_individually_granted_before_session(self):
        for action, dependency in (('open-run', 'authorize-run-request'),
                                   ('request-changes', 'observe'), ('reconcile-changes', 'observe')):
            for actions in ((action,), (dependency,)):
                self.bindings.bind(self.fingerprint, self.make_grant(actions=actions))
                self.receive.return_value = {**self.frame, 'action': action}
                connection = self.bindings.accept(self.channel)
                with self.subTest(action=action, actions=actions), self.assertRaisesRegex(LedgerError, 'HUMAN_ACTION_DENIED'):
                    with connection.receive():
                        self.fail('missing dependency must not expose a partial session')

    def test_frame_action_bundles_do_not_bleed_other_granted_scopes(self):
        expected = {'observe': {'observe'}, 'authorize-run-request': {'authorize-run-request'},
            'open-run': {'open-run', 'authorize-run-request'},
            'request-changes': {'request-changes', 'observe'}, 'reconcile-changes': {'reconcile-changes', 'observe'}}
        for action, permitted in expected.items():
            self.receive.return_value = {**self.frame, 'action': action}
            with self.connection.receive() as (_, session):
                for selected in subject.ACTIONS:
                    self.assertEqual(session.allowed(selected), selected in permitted, (action, selected))

    def test_unknown_duplicate_or_untyped_scopes_rejected(self):
        for actions in (('start',), ('merge',), ('open-run', 'open-run'), ['observe'], (True,)):
            with self.subTest(actions=actions), self.assertRaises(LedgerError):
                self.make_grant(actions=actions)

    def test_grant_is_frozen_and_exact_origin_type_required(self):
        with self.assertRaises(FrozenInstanceError):
            self.grant.manager_id = 'other'
        for human in ({'actor_id': 'operator'}, SimpleNamespace(**self.human.__dict__)):
            with self.assertRaises(LedgerError):
                self.make_grant(human=human)
        for field in ('deployment_id', 'room_id', 'instance_id', 'manager_id'):
            with self.subTest(field=field), self.assertRaises(LedgerError):
                self.make_grant(**{field: ''})

    def test_empty_registry_denies_certificate(self):
        with self.assertRaisesRegex(LedgerError, 'UNREGISTERED_HUMAN_CERTIFICATE'):
            subject.HumanActionBindings().accept(self.channel)

    def test_start_and_room_bindings_cannot_supply_human_authority(self):
        for bindings in (StartCertificateBindings.__new__(StartCertificateBindings),
                         RoomCertificateBindings.__new__(RoomCertificateBindings)):
            with self.subTest(bindings=type(bindings)), self.assertRaises(LedgerError):
                subject.HumanActionConnection(bindings, self.channel)
            with self.assertRaises(LedgerError):
                subject.HumanActionBindings(bindings)

    def test_grant_and_registry_subclasses_are_not_inherited_authority(self):
        class Grant(subject.HumanActionGrant):
            pass
        class Bindings(subject.HumanActionBindings):
            pass
        with self.assertRaises(LedgerError):
            self.bindings.bind(self.fingerprint, Grant(**self.grant.__dict__))
        with self.assertRaises(LedgerError):
            Bindings({self.fingerprint: self.grant}).accept(self.channel)

    def test_invalid_fingerprint_and_grant_rejected(self):
        for fingerprint in ('a' * 63, 'A' * 64, True):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(LedgerError):
                self.bindings.bind(fingerprint, self.grant)
        with self.assertRaises(LedgerError):
            self.bindings.bind(self.fingerprint, self.grant.__dict__)

    def test_exact_server_socket_required(self):
        class Child(TLS):
            pass
        for channel in (object(), Child()):
            with self.subTest(channel=type(channel)), self.assertRaises(LedgerError):
                self.bindings.accept(channel)
        self.channel.server_side = False
        with self.assertRaises(LedgerError):
            self.bindings.accept(self.channel)

    def test_tls13_cert_required_and_open_local_descriptor_required(self):
        changes = (('protocol', 'TLSv1.2'), ('fd', -1))
        for key, value in changes:
            channel = TLS(); setattr(channel, key, value)
            with self.subTest(key=key), self.assertRaises(LedgerError):
                self.bindings.accept(channel)
        for key, value in (('verify_mode', subject.ssl.CERT_NONE),
                           ('minimum_version', subject.ssl.TLSVersion.TLSv1_2)):
            channel = TLS(); setattr(channel.context, key, value)
            with self.subTest(key=key), self.assertRaises(LedgerError):
                self.bindings.accept(channel)

    def test_nonempty_exact_der_certificate_is_required(self):
        for certificate in (None, b'', 'controlled-client-certificate', b'another-certificate'):
            channel = TLS(); channel.certificate = certificate
            with self.subTest(certificate=certificate), self.assertRaises(LedgerError):
                self.bindings.accept(channel)

    def test_grant_revocation_denies_active_session_and_readdition_never_revives(self):
        with self.connection.receive() as (_, session):
            self.bindings.revoke(self.fingerprint)
            self.bindings.bind(self.fingerprint, self.grant)
            self.assertFalse(session.allowed('open-run'))
        with self.assertRaises(LedgerError):
            with self.connection.receive():
                self.fail('old connection must not revive')
        fresh = self.bindings.accept(self.channel)
        with fresh.receive() as (_, new_session):
            self.assertTrue(new_session.allowed('open-run'))
            self.assertFalse(session.allowed('open-run'))

    def test_equal_replacement_and_same_object_rebinding_rotate_generation(self):
        for replacement in (replace(self.grant), self.grant):
            connection = self.bindings.accept(self.channel)
            with connection.receive() as (_, session):
                self.bindings.bind(self.fingerprint, replacement)
                self.assertFalse(session.allowed('open-run'))

    def test_generation_exhaustion_cannot_wrap_and_revocation_still_works(self):
        self.bindings._generation = 2**63 - 1
        with self.assertRaisesRegex(LedgerError, 'HUMAN_GRANT_GENERATION_EXHAUSTED'):
            self.bindings.bind(self.fingerprint, self.grant)
        self.bindings.revoke(self.fingerprint)
        with self.assertRaises(LedgerError):
            self.bindings.accept(self.channel)

    def test_registry_or_peer_change_during_receive_is_rechecked(self):
        def read(*_args, **_kwargs):
            self.bindings.revoke(self.fingerprint)
            return self.frame
        self.receive.side_effect = read
        with self.assertRaises(LedgerError):
            with self.connection.receive():
                self.fail('revoked during receive')

    def test_local_close_and_peer_change_deny_active_session(self):
        for key, value in (('fd', -1), ('certificate', b'another-certificate'), ('protocol', 'TLSv1.2')):
            channel = TLS(); connection = self.bindings.accept(channel)
            with connection.receive() as (_, session):
                setattr(channel, key, value)
                self.assertFalse(session.allowed('open-run'))

    def test_explicit_close_and_processing_error_invalidate_session(self):
        with self.connection.receive() as (_, session):
            self.connection.close()
            self.assertFalse(session.allowed('open-run'))
        connection = self.bindings.accept(self.channel)
        with self.assertRaisesRegex(RuntimeError, 'controlled'):
            with connection.receive() as (_, errored):
                raise RuntimeError('controlled')
        self.assertFalse(errored.allowed('open-run'))
        with self.assertRaises(LedgerError):
            with connection.receive():
                self.fail('error closed authentication')

    def test_eof_and_receive_error_yield_no_session_and_latch_closed(self):
        for error in (EOFError(), OSError('controlled transport error')):
            connection = self.bindings.accept(self.channel)
            self.receive.side_effect = error
            with self.assertRaises(type(error)):
                with connection.receive():
                    self.fail('no session for failed frame')
            self.receive.side_effect = None
            with self.assertRaises(LedgerError):
                with connection.receive():
                    self.fail('EOF/error cannot reconnect implicitly')

    def test_previous_frame_session_cannot_revive_in_next_frame(self):
        with self.connection.receive() as (_, first):
            self.assertTrue(first.allowed('open-run'))
        with self.connection.receive() as (_, second):
            self.assertFalse(first.allowed('open-run'))
            self.assertTrue(second.allowed('open-run'))

    def test_copying_session_or_changing_frame_action_does_not_grant_authority(self):
        with self.connection.receive() as (frame, session):
            self.assertFalse(replace(session).allowed('open-run'))
            frame['action'] = 'request-changes'
            self.assertFalse(session.allowed('request-changes'))
            self.assertFalse(session.allowed(['open-run']))

    def test_nested_processing_fails_closed(self):
        with self.connection.receive() as (_, session):
            with self.assertRaisesRegex(LedgerError, 'HUMAN_FRAME_ALREADY_ACTIVE'):
                with self.connection.receive():
                    self.fail('nested frame')
            self.assertFalse(session.allowed('open-run'))

    def test_wire_authority_fields_denied_even_when_nested(self):
        for field in subject._AUTHORITY_FIELDS:
            for payload in ({field: 'claimed'}, {'nested': [{field: 'claimed'}]}):
                self.receive.return_value = {'version': 1, 'action': 'open-run', 'payload': payload}
                connection = self.bindings.accept(self.channel)
                with self.subTest(field=field), self.assertRaisesRegex(LedgerError, 'JSON_HUMAN_AUTHORITY_DENIED'):
                    with connection.receive():
                        self.fail('JSON authority')

    def test_existing_manager_packet_scope_is_preserved_unchanged_not_authority(self):
        packet = {'version': 1, 'operation_id': 'original', 'action': 'request-changes',
            'deployment_id': 'deployment', 'room_id': 'room', 'instance_id': 'exact-instance',
            'run_id': 'run', 'generation': 1, 'object_id': 'submission',
            'observed_version': 'a' * 64, 'payload': {'body': 'please revise'}}
        before = _json(packet)
        self.receive.return_value = {'version': 1, 'action': 'request-changes', 'payload': packet}
        with self.connection.receive() as (frame, session):
            self.assertIs(frame['payload'], packet)
            self.assertEqual(_json(frame['payload']), before)
            self.assertTrue(session.allowed('request-changes'))
            self.assertIs(session.human, self.human)

    def test_wrong_scope_correlations_refused_without_rewriting_packet(self):
        for key in ('deployment_id', 'room_id', 'instance_id', 'manager_id'):
            for value in ('other', True):
                self.receive.return_value = {**self.frame, 'payload': {'nested': [{key: value}]}}
                connection = self.bindings.accept(self.channel)
                with self.subTest(key=key, value=value), self.assertRaisesRegex(LedgerError, 'HUMAN_ACTION_SCOPE_MISMATCH'):
                    with connection.receive():
                        self.fail('wrong scope')

    def test_optional_manager_correlation_matches_grant_without_granting(self):
        self.receive.return_value = {**self.frame, 'payload': {'manager_id': 'manager'}}
        with self.connection.receive() as (frame, session):
            self.assertEqual(frame['payload'], {'manager_id': 'manager'})
            self.assertEqual(session.manager_id, 'manager')
            self.assertFalse(session.allowed('request-changes'))

    def test_creator_thread_confinement_precedes_mutation_receive_or_authority(self):
        with self.connection.receive() as (_, session):
            generation = self.bindings._generation
            with patch.object(subject.threading, 'get_ident', return_value=self.bindings._owner_thread + 1):
                operations = (lambda: self.bindings.bind(self.fingerprint, self.grant),
                    lambda: self.bindings.revoke(self.fingerprint), lambda: self.bindings.accept(self.channel),
                    lambda: subject.HumanActionConnection(self.bindings, self.channel),
                    self.connection._current, self.connection.close)
                for operation in operations:
                    with self.assertRaisesRegex(LedgerError, 'HUMAN_AUTHENTICATION_OWNER_REQUIRED'):
                        operation()
                with self.assertRaises(LedgerError):
                    with self.connection.receive():
                        self.fail('wrong thread')
                self.assertFalse(session.allowed('open-run'))
            self.assertEqual(self.bindings._generation, generation)
            self.assertTrue(session.allowed('open-run'))

    def test_wrong_thread_context_exit_still_invalidates_saved_session(self):
        context = self.connection.receive()
        _, session = context.__enter__()
        with patch.object(subject.threading, 'get_ident', return_value=self.bindings._owner_thread + 1):
            with self.assertRaisesRegex(LedgerError, 'HUMAN_AUTHENTICATION_OWNER_REQUIRED'):
                context.__exit__(None, None, None)
        self.assertFalse(session.allowed('open-run'))
        with self.assertRaises(LedgerError):
            with self.connection.receive():
                self.fail('wrong-thread exit cannot retain connection authority')

    def test_wire_envelope_unknown_actions_and_size_are_bounded(self):
        bad = ({**self.frame, 'principal': 'operator'}, {**self.frame, 'version': True},
               {**self.frame, 'action': 'start'}, {**self.frame, 'payload': []},
               {**self.frame, 'payload': {'note': 'x' * subject.MAX_ACTION_BYTES}})
        for frame in bad:
            self.receive.return_value = frame
            connection = self.bindings.accept(self.channel)
            with self.subTest(frame=list(frame)), self.assertRaises(LedgerError):
                with connection.receive():
                    self.fail('invalid frame')

    def test_connection_construction_performs_no_receive_or_credential_creation(self):
        self.receive.assert_not_called()
        self.assertFalse(hasattr(self.connection, 'session'))
