"""Hosted-only real TLS/thread proof of the retained human transport checkpoint.

Never execute this module's fixtures in local source-only checks. Independent
review precedes hosted enablement. Only existing temporary fixture certificates
and loopback are used; this is not native Run, provider or account qualification.
"""
import os
import unittest


_HOSTED = (os.environ.get('UAS_MANAGER_TLS_TEST') == '1'
           and os.environ.get('GITHUB_ACTIONS') == 'true'
           and os.environ.get('RUNNER_OS') == 'Linux')


@unittest.skipUnless(_HOSTED, 'real native human mTLS is an explicit hosted-only gate')
class HostedNativeHumanTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HOSTED:
            raise unittest.SkipTest('real native human mTLS is an explicit hosted-only gate')
        # Reuse only certificate setup, not its server fixtures or inherited tests.
        from test_manager_tls import HostedManagerTLSTests
        HostedManagerTLSTests.setUpClass.__func__(cls)

    def setUp(self):
        import hashlib
        import socket
        import ssl
        import time
        from uas.human_mtls import HumanActionBindings, HumanActionGrant, ACTIONS
        from uas.ledger import Origin
        from uas.manager_transport import server_tls_context
        self.deadline = time.monotonic() + 15
        self.controls, self.untransferred, self.clients, self.releases, self.errors = [], [], [], [], []
        self.context = server_tls_context(trust_file=str(self.certroot / 'ca.crt'),
            certificate_file=str(self.certroot / 'manager.crt'),
            private_key_file=str(self.certroot / 'manager.key'))
        self.human = Origin('operator', 'human', 'operator-session', 'operator-authority',
                            ('human-open-run', 'human-control-run'))
        self.grant = HumanActionGrant('deployment', 'room', 'instance', 'manager',
                                      self.human, tuple(sorted(ACTIONS)))
        der = ssl.PEM_cert_to_DER_cert((self.certroot / 'alpha.crt').read_text())
        self.fingerprint = hashlib.sha256(der).hexdigest()
        self.bindings = HumanActionBindings({self.fingerprint: self.grant})
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(self.shutdown)
        self.listener.bind(('127.0.0.1', 0)); self.listener.listen(1); self.listener.settimeout(2)
        self.port = self.listener.getsockname()[1]

    def shutdown(self):
        # Release scripted client waits first. No main-thread I/O on transferred TLS.
        for event in self.releases:
            event.set()
        failures = []
        for control in self.controls:
            try:
                control.close()  # Immediate denial, worker-owned close, bounded join.
            except Exception as error:
                failures.append(type(error).__name__)
        for secure in self.untransferred:
            secure.close()
        self.listener.close()
        for worker in self.clients:
            worker.join(6)
            if worker.is_alive(): failures.append('client thread still active')
        for control in self.controls:
            if control._thread is not None and control._thread.is_alive():
                failures.append('TLS owner thread still active')
        self.assertFalse(failures, repr(failures))
        self.assertFalse(self.errors, repr(self.errors))

    def event(self):
        import threading
        event = threading.Event()
        self.releases.append(event)
        return event

    def wait(self, event):
        import time
        remaining = min(2, self.deadline - time.monotonic())
        self.assertGreater(remaining, 0, 'hosted fixture deadline expired')
        self.assertTrue(event.wait(remaining), 'hosted fixture phase timed out')
        self.assertFalse(self.errors, repr(self.errors))

    def accept_client(self, certificate, conversation):
        import socket
        import threading
        from uas.manager_transport import client_tls_context
        context = client_tls_context(trust_file=str(self.certroot / 'ca.crt'),
            certificate_file=str(self.certroot / (certificate + '.crt')),
            private_key_file=str(self.certroot / (certificate + '.key')))

        def client():
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=2) as raw:
                    with context.wrap_socket(raw, server_hostname='localhost') as secure:
                        conversation(secure)
            except Exception as error:
                self.errors.append(type(error).__name__ + ': ' + str(error))

        worker = threading.Thread(target=client, name='uas-human-tls-test-client', daemon=False)
        self.clients.append(worker)
        worker.start()
        raw, _ = self.listener.accept()
        try:
            raw.settimeout(2)
            secure = self.context.wrap_socket(raw, server_side=True)
        except BaseException:
            raw.close()
            raise
        self.untransferred.append(secure)
        return secure

    def control(self, secure):
        from uas.native_human_control import NativeHumanControl
        control = NativeHumanControl(self.bindings, secure, instance_id='instance', deadline=self.deadline)
        self.controls.append(control)
        self.untransferred.remove(secure)
        control.start()
        return control

    def exchange(self, channel, frame):
        import time
        from uas.human_mtls import PATH
        from uas.manager_transport import receive_frame, send_frame
        self.assertLess(time.monotonic(), self.deadline, 'hosted fixture deadline expired')
        send_frame(channel, frame, path=PATH, host='localhost')
        return receive_frame(channel, response=True, path=PATH)

    @staticmethod
    def open_frame():
        return {'version': 1, 'action': 'open-run', 'payload': {'operation_id': 'open-78', 'issue_number': 78}}

    def test_real_open_observe_exact_manager_queue_and_eof_terminal(self):
        from uas.ledger import LedgerError, _json
        from uas.manager_actions import HumanSession
        from uas.native_human_control import NativeHumanOpen
        opened, allow_observe, observed, projection_ready, queued, finish = [self.event() for _ in range(6)]
        replies = []
        observe = {'version': 1, 'action': 'observe', 'payload': {}}
        packet = {'version': 1, 'operation_id': 'comment-78', 'action': 'request-changes',
            'deployment_id': 'deployment', 'room_id': 'room', 'instance_id': 'instance',
            'run_id': 'run-78', 'generation': 1, 'object_id': 'submission-78',
            'observed_version': 'a' * 64, 'payload': {'body': 'PRIVATE_FIXTURE_COMMENT'}}
        original = _json(packet)
        view = {'run_id': 'run-78', 'generation': 1, 'status': 'ACTIVE',
            'observed_version': 'a' * 64, 'review_stage': 'READY_FOR_HUMAN',
            'submission_id': 'submission-78', 'forge_uncertain': False}

        def conversation(channel):
            replies.append(self.exchange(channel, self.open_frame())); opened.set()
            self.wait(allow_observe)
            replies.append(self.exchange(channel, observe)); observed.set()
            self.wait(projection_ready)
            replies.append(self.exchange(channel, observe))  # Explicit heartbeat, last-published view.
            replies.append(self.exchange(channel, {'version': 1, 'action': 'request-changes', 'payload': packet}))
            queued.set(); self.wait(finish)
            # Exiting the client TLS context produces actual transport EOF.

        control = self.control(self.accept_client('alpha', conversation))
        session = control.session
        self.wait(opened)
        self.assertIs(type(session), HumanSession)
        self.assertIs(session.human, self.human)
        self.assertTrue(session.allowed('open-run')); self.assertTrue(session.allowed('authorize-run-request'))
        request = control.first_request()
        self.assertIs(type(request), NativeHumanOpen)
        self.assertEqual((request.operation_id, request.issue_number), ('open-78', 78))
        with self.assertRaisesRegex(LedgerError, 'OPEN_ALREADY_TAKEN'): control.first_request()
        allow_observe.set(); self.wait(observed)
        self.assertTrue(control.take_observation_request())
        control.publish(view)  # Fixed fixture projection, not a real owner/provider observation.
        projection_ready.set(); self.wait(queued)
        self.assertIs(control.session, session)
        self.assertTrue(session.allowed('request-changes'))
        commands = control.drain_commands()
        self.assertEqual(len(commands), 1); self.assertEqual(_json(commands[0]), original)
        self.assertEqual(control.drain_commands(), ())
        self.assertEqual(replies[0]['receipt'], 'queued')
        self.assertIsNone(replies[1]['current'])
        self.assertEqual(replies[2]['current'], view)
        self.assertEqual(replies[2]['view_kind'], 'last-published-not-live')
        self.assertEqual(replies[3]['actions'], [{'operation_id': 'comment-78', 'status': 'queued'}])
        self.assertNotIn('PRIVATE_FIXTURE_COMMENT', _json(replies))
        self.assertNotIn('human_origin', _json(replies))
        finish.set()
        self.clients[0].join(2); self.assertFalse(self.clients[0].is_alive())
        control._thread.join(2); self.assertFalse(control._thread.is_alive())
        self.assertFalse(session.connected()); self.assertFalse(session.allowed('open-run'))
        with self.assertRaises(LedgerError): control.drain_commands()

    def test_ca_valid_unregistered_client_certificate_cannot_create_control(self):
        from uas.ledger import LedgerError
        from uas.manager_stream import StreamError
        from uas.native_human_control import NativeHumanControl
        denied = self.event()

        def conversation(channel):
            with self.assertRaises((OSError, StreamError)):
                self.exchange(channel, self.open_frame())
            denied.set()

        secure = self.accept_client('unregistered', conversation)
        with self.assertRaisesRegex(LedgerError, 'UNREGISTERED_HUMAN_CERTIFICATE'):
            NativeHumanControl(self.bindings, secure, instance_id='instance', deadline=self.deadline)
        secure.close(); self.untransferred.remove(secure)
        self.wait(denied)
        self.assertFalse(self.controls)

    def test_registered_certificate_empty_scope_cannot_inherit_origin_capabilities(self):
        from dataclasses import replace
        from uas.ledger import LedgerError
        from uas.manager_stream import StreamError
        denied = self.event()
        self.bindings.bind(self.fingerprint, replace(self.grant, actions=()))

        def conversation(channel):
            with self.assertRaises((OSError, StreamError)):
                self.exchange(channel, self.open_frame())
            denied.set()

        control = self.control(self.accept_client('alpha', conversation))
        self.wait(denied)
        control._thread.join(2); self.assertFalse(control._thread.is_alive())
        self.assertFalse(control.session.allowed('open-run'))
        self.assertFalse(control.session.allowed('request-changes'))
        with self.assertRaises(LedgerError): control.first_request()
        with self.assertRaises(LedgerError): control.drain_commands()


if __name__ == '__main__':
    unittest.main()
