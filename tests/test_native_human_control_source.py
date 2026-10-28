"""Finite scripted TLS/thread seams; no real transport, thread or native effects."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from uas import human_mtls as auth
from uas import native_human_control as subject
from uas.ledger import LedgerError, Origin, _json
from uas.manager_actions import HumanSession


class TLS:
    def __init__(self):
        self.context = SimpleNamespace(verify_mode=auth.ssl.CERT_REQUIRED,
            minimum_version=auth.ssl.TLSVersion.TLSv1_3)
        self.server_side, self.fd, self.protocol = True, 7, 'TLSv1.3'
        self.certificate, self.calls, self.closes = b'public-test-certificate', [], 0

    def fileno(self):
        self.calls.append('fileno'); return self.fd

    def version(self):
        self.calls.append('version'); return self.protocol

    def getpeercert(self, *, binary_form):
        if binary_form is not True: raise AssertionError('DER required')
        self.calls.append('getpeercert'); return self.certificate

    def close(self):
        self.closes += 1


class NativeHumanControlSourceTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.now, self.identity = 10., 101
        self.frames, self.responses, self.on_send = [], [], None
        self.human = Origin('operator', 'human', 'incarnation', 'authority',
                            ('human-open-run', 'human-control-run'))
        self.grant = auth.HumanActionGrant('deployment', 'room', 'instance', 'manager',
                                          self.human, tuple(sorted(auth.ACTIONS)))
        self.channel = TLS()
        self.fingerprint = hashlib.sha256(self.channel.certificate).hexdigest()
        patch.object(auth.ssl, 'SSLSocket', TLS).start()
        patch.object(subject.threading, 'get_ident', side_effect=lambda: self.identity).start()
        test = self
        class ScriptedThread:
            def __init__(self, *, target, name, daemon):
                test.assertEqual(name, 'uas-native-human'); test.assertFalse(daemon)
                self.target, self.ident, self.alive = target, None, False
                self.started, self.joins, self.stuck = 0, [], False
            def start(self):
                self.started += 1; self.ident, self.alive = 202, True
            def run(self):
                with test.thread(202):
                    try: self.target()
                    finally: self.alive = False
            def join(self, *, timeout):
                self.joins.append(timeout)
                if self.alive and not self.stuck: self.run()
            def is_alive(self): return self.alive
        self.thread_type = ScriptedThread
        patch.object(subject.threading, 'Thread', ScriptedThread).start()
        self.receive = patch.object(subject, 'receive_frame', side_effect=self.received).start()
        self.send = patch.object(subject, 'send_frame', side_effect=self.sent).start()
        self.bindings = auth.HumanActionBindings({self.fingerprint: self.grant})
        self.control = self.make_control()

    @contextmanager
    def thread(self, identity):
        previous, self.identity = self.identity, identity
        try: yield
        finally: self.identity = previous

    def make_control(self, **changes):
        fields = dict(instance_id='instance', deadline=100., freshness=5., clock=lambda: self.now)
        return subject.NativeHumanControl(self.bindings, self.channel, **(fields | changes))

    def opened(self, **changes):
        return {'version': 1, 'action': 'open-run', 'payload': {'operation_id': 'open', 'issue_number': 78} | changes}

    def command(self, operation='comment', action='request-changes', **changes):
        payload = {'version': 1, 'operation_id': operation, 'action': action,
            'deployment_id': 'deployment', 'room_id': 'room', 'instance_id': 'instance',
            'run_id': 'run-one', 'generation': 1, 'object_id': 'run-one',
            'observed_version': 'a' * 64, 'payload': {'body': 'private comment'} if action == 'request-changes' else {}}
        return {'version': 1, 'action': action, 'payload': payload | changes}

    def view(self, **changes):
        return {'run_id': 'run-one', 'generation': 1, 'status': 'ACTIVE', 'observed_version': 'a' * 64,
                'review_stage': 'READY_FOR_HUMAN', 'submission_id': 'submission-one',
                'forge_uncertain': False} | changes

    def received(self, channel, *, path):
        self.assertIs(channel, self.channel); self.assertEqual(path, auth.PATH)
        self.assertEqual(self.identity, 202)
        if not self.frames: raise EOFError('private transport detail')
        value = self.frames.pop(0)
        if callable(value): value = value()
        if isinstance(value, BaseException): raise value
        return value

    def sent(self, channel, value, *, response, path):
        self.assertIs(channel, self.channel); self.assertTrue(response); self.assertEqual(path, auth.PATH)
        self.assertEqual(self.identity, 202)
        self.responses.append(deepcopy(value))
        if self.on_send is not None: self.on_send(value)

    def accept(self, value):
        if not self.control._started: self.control.start()
        self.control._worker_thread = 202
        with self.thread(202): return self.control._accept(value)

    def pump(self, *values):
        self.frames = list(values)
        if not self.control._started: self.control.start()
        self.control._thread.run()

    def assert_dead(self):
        self.assertFalse(self.control.session.connected())
        for action in auth.ACTIONS: self.assertFalse(self.control.session.allowed(action))

    def test_constructor_authenticates_without_starting_or_io(self):
        self.assertIsNone(self.control._thread)
        self.assertIs(type(self.control.session), HumanSession)
        self.assertIs(self.control.session.human, self.human)
        self.assertFalse(self.control.session.allowed('open-run'))
        self.receive.assert_not_called(); self.send.assert_not_called()

    def test_open_data_is_frozen_and_cannot_select_participant_or_authority(self):
        for changes in ({'issue_number': True}, {'issue_number': 0}, {'operation_id': ''},
                        {'participant_id': 'pi'}, {'session': {}}, {'origin': {}}):
            with self.subTest(changes=changes), self.assertRaises(LedgerError): self.accept(self.opened(**changes))
        self.accept(self.opened())
        request = self.control.first_request()
        self.assertIs(type(request), subject.NativeHumanOpen)
        self.assertEqual((request.operation_id, request.issue_number), ('open', 78))
        with self.assertRaises(FrozenInstanceError): request.issue_number = 1

    def test_first_request_exact_once_and_duplicate_never_creates_second_run(self):
        self.control.start(); self.assertIsNone(self.control.first_request())
        self.accept(self.opened()); session = self.control.session
        first = self.control.first_request()
        self.accept(self.opened())
        with self.assertRaisesRegex(LedgerError, 'OPEN_ALREADY_TAKEN'): self.control.first_request()
        self.assertIs(session, self.control.session)
        self.assertEqual(first.issue_number, 78)
        for value in (self.opened(operation_id='new'), self.opened(issue_number=79)):
            with self.assertRaisesRegex(LedgerError, 'SECOND_RUN_DENIED'): self.accept(value)

    def test_initial_grant_not_usable_until_complete_open(self):
        self.control.start()
        self.assert_dead()
        self.accept(self.opened())
        self.assertTrue(self.control.session.allowed('open-run'))
        self.assertTrue(self.control.session.allowed('authorize-run-request'))
        self.assertFalse(self.control.session.allowed('stop'))
        self.assertFalse(replace(self.control.session).allowed('open-run'))
        with self.assertRaises(AttributeError): self.control.session = replace(self.control.session)

    def test_expire_before_first_and_late_frame_never_revives(self):
        self.control.start(); self.now = 15.
        self.pump(self.opened())
        self.assert_dead(); self.assertIsNone(self.control._first)
        self.assertFalse(self.responses)

    def test_expire_before_refresh_is_terminal_even_without_main_check(self):
        self.accept(self.opened()); self.now = 15.
        self.pump({'version': 1, 'action': 'observe', 'payload': {}})
        self.assert_dead(); self.assertEqual(self.control._expires, 15.)
        self.now = 14.
        self.assert_dead()

    def test_complete_valid_frame_refreshes_but_never_extends_absolute_deadline(self):
        self.control = self.make_control(deadline=16.)
        self.accept(self.opened()); self.now = 14.
        self.accept({'version': 1, 'action': 'observe', 'payload': {}})
        self.assertEqual(self.control._expires, 16.)
        self.now = 16.; self.assert_dead()

    def test_incomplete_or_invalid_frame_does_not_refresh(self):
        for failure in (EOFError(), TimeoutError(), OSError('private'), {'version': 1, 'action': 'unknown', 'payload': {}}):
            self.control = self.make_control(); self.accept(self.opened()); self.now += 1
            expires = self.control._expires
            self.pump(failure)
            self.assert_dead(); self.assertEqual(self.control._expires, expires)

    def test_valid_reply_then_immediate_eof_denies_saved_session(self):
        checked = []
        def observe(_):
            with self.thread(101): checked.append(self.control.session.allowed('open-run'))
        self.on_send = observe
        self.pump(self.opened(), EOFError())
        self.assertEqual(checked, [True]); self.assertEqual(len(self.responses), 1)
        self.assert_dead(); self.assertEqual(self.channel.closes, 1)
        with self.assertRaises(LedgerError): self.control.first_request()

    def test_send_failure_invalidates_and_never_resends(self):
        self.send.side_effect = OSError('private body')
        self.pump(self.opened(), self.opened())
        self.assert_dead(); self.assertEqual(self.send.call_count, 1)
        self.assertEqual(len(self.frames), 1)

    def test_worker_stop_without_more_frames_invalidates(self):
        self.pump(self.opened())
        self.assert_dead(); self.assertTrue(self.control._closed)

    def test_registry_removal_readd_same_or_equal_grant_never_revives(self):
        for same in (True, False):
            self.control = self.make_control(); self.accept(self.opened())
            self.bindings.revoke(self.fingerprint)
            self.bindings.bind(self.fingerprint, self.grant if same else replace(self.grant))
            self.assert_dead()
            with self.assertRaises(LedgerError): self.control.drain_commands()

    def test_main_revocation_latch_prevents_later_worker_frame_or_projection(self):
        self.accept(self.opened())
        self.control.publish(self.view())
        self.bindings.revoke(self.fingerprint)
        self.assert_dead()
        self.pump({'version': 1, 'action': 'observe', 'payload': {}})
        self.assertFalse(self.responses)

    def test_original_instance_mismatch_or_replacement_denied(self):
        with self.assertRaises(LedgerError): self.make_control(instance_id='other-instance')
        self.accept(self.opened())
        self.bindings.bind(self.fingerprint, replace(self.grant, instance_id='other-instance'))
        self.assert_dead()

    def test_exact_registry_socket_and_grant_types_only(self):
        class Registry(auth.HumanActionBindings): pass
        class Socket(TLS): pass
        for bindings, channel in (({}, self.channel), (Registry({}), self.channel), (self.bindings, Socket())):
            with self.assertRaises(LedgerError):
                subject.NativeHumanControl(bindings, channel, instance_id='instance', deadline=100, clock=lambda: 10)
        self.bindings._bindings[self.fingerprint] = ({'actions': ['open-run']}, 1)
        with self.assertRaises(LedgerError): self.make_control()

    def test_tls_version_certificate_and_local_close_rechecked_only_by_worker(self):
        for field, value in (('protocol', 'TLSv1.2'), ('certificate', b'different'), ('fd', -1)):
            self.channel = TLS(); self.control = self.make_control()
            self.accept(self.opened()); setattr(self.channel, field, value)
            self.pump({'version': 1, 'action': 'observe', 'payload': {}})
            self.assert_dead(); self.assertFalse(self.responses)

    def test_missing_explicit_scope_bundle_and_capability_refused(self):
        for actions, human in ((('open-run',), self.human), (('authorize-run-request',), self.human),
                              (self.grant.actions, replace(self.human, capabilities=()))):
            self.bindings.bind(self.fingerprint, replace(self.grant, actions=actions, human=human))
            self.control = self.make_control(); self.pump(self.opened())
            self.assert_dead(); self.assertIsNone(self.control._first)

    def test_control_requires_explicit_observe_and_human_control_capability(self):
        for grant in (replace(self.grant, actions=('open-run', 'authorize-run-request', 'request-changes')),
                      replace(self.grant, human=replace(self.human, capabilities=('human-open-run',)))):
            self.bindings.bind(self.fingerprint, grant); self.control = self.make_control()
            self.accept(self.opened())
            self.assertFalse(self.control.session.allowed('request-changes'))
            self.pump(self.command())
            self.assert_dead(); self.assertFalse(self.control._items)

    def test_non_open_first_and_standalone_authorize_denied(self):
        for value in ({'version': 1, 'action': 'observe', 'payload': {}}, self.command(),
                      {'version': 1, 'action': 'authorize-run-request', 'payload': {}}):
            self.control = self.make_control(); self.pump(value)
            self.assert_dead(); self.assertIsNone(self.control._first)

    def test_exact_manager_packet_preserved_and_drained_once(self):
        value = self.command(); original = _json(value['payload'])
        self.accept(self.opened()); self.accept(value)
        value['payload']['payload']['body'] = 'changed outside'
        drained = self.control.drain_commands()
        self.assertEqual(len(drained), 1); self.assertEqual(_json(drained[0]), original)
        drained[0]['payload']['body'] = 'changed after handoff'
        self.assertEqual(self.control.drain_commands(), ())
        self.accept(self.command())  # Exact duplicate remains tracked, never requeued.
        self.assertEqual(self.control.drain_commands(), ())

    def test_unknown_status_duplicate_does_not_retry_or_allocate_new_operation(self):
        self.accept(self.opened()); self.accept(self.command())
        self.control.drain_commands()
        self.control.publish(None, ({'operation_id': 'comment', 'status': 'unknown'},))
        answer = self.accept(self.command())
        self.assertEqual(answer['actions'], [{'operation_id': 'comment', 'status': 'unknown'}])
        self.assertEqual(self.control.drain_commands(), ())

    def test_duplicate_conflict_and_first_operation_collision_denied(self):
        self.accept(self.opened()); self.accept(self.command())
        for value in (self.command(payload={'body': 'different'}), self.command(operation='open')):
            with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'): self.accept(value)

    def test_eight_lifetime_actions_not_eight_simultaneous(self):
        self.accept(self.opened())
        for number in range(8):
            self.accept(self.command(operation='comment-' + str(number)))
            self.control.drain_commands()
        self.pump(self.command(operation='ninth'))
        self.assert_dead(); self.assertEqual(len(self.control._items), 8)

    def test_unknown_authority_scope_cross_action_and_oversize_refused(self):
        values = [self.command(instance_id='wrong'), self.command(action='reconcile-changes')]
        values[1]['payload']['action'] = 'request-changes'
        values += [self.command(payload={'body': 'x' * 20000}), self.command(origin={}),
                   self.command(payload={'body': 'x', 'callback': {}}),
                   {'version': 1, 'action': 'observe', 'payload': {'principal': 'claimed'}}]
        for value in values:
            self.control = self.make_control(); self.accept(self.opened()); self.pump(value)
            self.assert_dead(); self.assertFalse(self.control._items)

    def test_observe_latch_coalesces_and_responses_are_stale_bounded_projections(self):
        self.accept(self.opened()); self.assertFalse(self.control.take_observation_request())
        observe = {'version': 1, 'action': 'observe', 'payload': {}}
        self.accept(observe); self.accept(observe)
        self.assertTrue(self.control.take_observation_request()); self.assertFalse(self.control.take_observation_request())
        view = self.view()
        self.control.publish(view); view['run_id'] = 'not-published'
        answer = self.accept(observe)
        self.assertEqual(answer['view_kind'], 'last-published-not-live')
        self.assertEqual(answer['current']['run_id'], 'run-one')
        self.assertEqual(answer['current']['submission_id'], 'submission-one')
        self.assertEqual(answer['receipt'], 'observed')
        self.assertNotIn('private', _json(answer)); self.assertNotIn('human', _json(answer))

    def test_arbitrary_views_statuses_and_raw_secrets_cannot_be_published(self):
        self.accept(self.opened())
        for value in ({'secret': 'raw'}, self.view(generation=True), self.view(review_stage='invented'),
                      self.view(submission_id='bad token'), self.view(forge_uncertain=1), self.view(secret='raw')):
            with self.assertRaises(LedgerError): self.control.publish(value)
        for statuses in ([{'operation_id': 'x', 'status': 'unknown'}], ({'operation_id': 'x', 'status': 'unknown'},),
                         ({'operation_id': 'x', 'status': 'unknown', 'body': 'secret'},)):
            with self.assertRaises(LedgerError): self.control.publish(None, statuses)

    def test_nullable_review_projection_preserves_exact_canonical_fields(self):
        self.accept(self.opened())
        view = self.view(review_stage=None, submission_id=None, forge_uncertain=True)
        self.control.publish(view)
        answer = self.accept({'version': 1, 'action': 'observe', 'payload': {}})
        self.assertEqual(answer['current'], view)

    def test_view_publication_requires_explicit_observe_and_first_request(self):
        self.control.start()
        with self.assertRaises(LedgerError): self.control.publish(self.view())
        self.bindings.bind(self.fingerprint, replace(self.grant, actions=('open-run', 'authorize-run-request')))
        self.control = self.make_control(); self.accept(self.opened())
        with self.assertRaises(LedgerError): self.control.publish(self.view())

    def test_wrong_thread_methods_refuse_and_callbacks_do_not_mutate(self):
        self.accept(self.opened()); before = (self.control._closed, self.control._expires)
        with self.thread(303):
            self.assertFalse(self.control.session.connected()); self.assertFalse(self.control.session.allowed('open-run'))
            for call in (self.control.start, self.control.close, self.control.first_request,
                         self.control.drain_commands, self.control.take_observation_request,
                         lambda: self.control.publish(None)):
                with self.assertRaisesRegex(LedgerError, 'OWNER_REQUIRED'): call()
        self.assertEqual((self.control._closed, self.control._expires), before)
        self.assertTrue(self.control.session.allowed('open-run'))

    def test_callbacks_use_no_transport_or_certificate_getters(self):
        self.accept(self.opened()); self.channel.calls.clear()
        self.receive.reset_mock(); self.send.reset_mock()
        for _ in range(3): self.assertTrue(self.control.session.allowed('open-run'))
        self.assertEqual(self.channel.calls, [])
        self.receive.assert_not_called(); self.send.assert_not_called()

    def test_close_before_consumption_discards_authority_not_replay_state(self):
        self.accept(self.opened()); self.accept(self.command())
        self.control.close(); self.assert_dead()
        for call in (self.control.first_request, self.control.drain_commands, self.control.take_observation_request):
            with self.assertRaises(LedgerError): call()
        self.assertEqual(len(self.control._items), 1); self.assertEqual(self.channel.closes, 1)

    def test_close_before_start_and_repeated_close_are_idempotent(self):
        self.control.close(); self.control.close()
        self.assertEqual(self.channel.closes, 1)
        with self.assertRaises(LedgerError): self.control.start()
        self.receive.assert_not_called()

    def test_stuck_worker_is_terminal_and_reported_not_replaced(self):
        self.control.start(); self.control._thread.stuck = True
        with self.assertRaisesRegex(LedgerError, 'STOP_PENDING'): self.control.close()
        self.assert_dead(); self.assertEqual(self.channel.closes, 0)
        with self.assertRaises(LedgerError): self.control.start()

    def test_start_once_and_start_failure_are_terminal(self):
        with patch.object(self.thread_type, 'start', side_effect=RuntimeError('start failed')):
            with self.assertRaises(RuntimeError): self.control.start()
        self.assert_dead(); self.assertEqual(self.channel.closes, 1)
        self.control.close(); self.assertEqual(self.channel.closes, 1)
        with self.assertRaises(LedgerError): self.control.start()

    def test_thread_construction_failure_is_terminal_and_closes_untransferred_socket(self):
        with patch.object(subject.threading, 'Thread', side_effect=RuntimeError('construction failed')):
            with self.assertRaises(RuntimeError): self.control.start()
        self.assert_dead(); self.assertEqual(self.channel.closes, 1)
        self.control.close(); self.assertEqual(self.channel.closes, 1)

    def test_invalid_deadline_freshness_and_clock_are_refused(self):
        for fields in ({'deadline': 10}, {'deadline': float('inf')}, {'deadline': True},
                       {'freshness': 6}, {'freshness': 0}, {'freshness': float('nan')}, {'clock': None}):
            with self.subTest(fields=fields), self.assertRaises(LedgerError): self.make_control(**fields)
