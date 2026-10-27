"""Hosted-only account-free mTLS proof; never enable in local restricted checks.

Source must be independently reviewed before root publishes/enables this test.
Only temporary test certificates, loopback sockets and temporary SQLite stores
are used. No production credential, system trust, account or host setting.
"""
import os
import unittest


def initialize_receiver_model(path, ready, startup_errors):
    """One receiver owns initial WAL/schema setup before observers may open it."""
    from uas.manager_stream import ManagerReadModel
    try:
        model = ManagerReadModel(path)
    except Exception as error:
        startup_errors.append(getattr(error, 'code', type(error).__name__))
        ready.set()
        return None
    ready.set()
    return model


@unittest.skipUnless(os.environ.get('UAS_MANAGER_TLS_TEST') == '1'
                     and os.environ.get('GITHUB_ACTIONS') == 'true'
                     and os.environ.get('RUNNER_OS') == 'Linux',
                     'real Manager mTLS is an explicit hosted-only gate')
class HostedManagerTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pathlib import Path
        import subprocess
        import tempfile
        cls.certificates = tempfile.TemporaryDirectory(prefix='uas-manager-certificates-')
        cls.addClassCleanup(cls.certificates.cleanup)
        cls.certroot = Path(cls.certificates.name)

        def command(*args):
            subprocess.run(['openssl', *args], check=True, cwd=cls.certroot,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

        command('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=UAS Fixture CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        for index, name in enumerate(('manager', 'alpha', 'beta', 'unregistered'), 1):
            command('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-keyout', name + '.key', '-out', name + '.csr', '-subj', '/CN=' + name)
            extension = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
            extension += ('extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:manager.fixture.invalid\n'
                          if name == 'manager' else 'extendedKeyUsage=clientAuth\n')
            (cls.certroot / (name + '.ext')).write_text(extension)
            command('x509', '-req', '-in', name + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
                '-set_serial', str(index), '-days', '1', '-extfile', name + '.ext', '-out', name + '.crt')

    def setUp(self):
        from pathlib import Path
        import hashlib
        import socket
        import ssl
        import tempfile
        import threading
        from uas.manager_stream import ManagerReadModel, RoomIdentity, StreamError
        from uas.manager_transport import (RoomCertificateBindings, accept_session,
                                           serve_once, server_tls_context)
        self.directory = tempfile.TemporaryDirectory(prefix='uas-manager-hosted-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.alpha = getattr(self, 'fixture_alpha', RoomIdentity('deployment', 'alpha', 'stream-alpha'))
        self.beta = RoomIdentity('deployment', 'beta', 'stream-beta')
        self.errors, self.snapshots = [], []
        bindings = {}
        for name, identity in (('alpha', self.alpha), ('beta', self.beta)):
            der = ssl.PEM_cert_to_DER_cert((self.certroot / (name + '.crt')).read_text())
            bindings[hashlib.sha256(der).hexdigest()] = identity
        certificates = RoomCertificateBindings(bindings)
        context = server_tls_context(trust_file=str(self.certroot / 'ca.crt'),
            certificate_file=str(self.certroot / 'manager.crt'),
            private_key_file=str(self.certroot / 'manager.key'))
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0)); self.listener.listen(8); self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.startup_errors = []
        self.channel_lock = threading.Lock()
        self.active_channels, self.connection_count = set(), 0

        def server():
            model = initialize_receiver_model(self.root / 'manager.sqlite3', self.ready, self.startup_errors)
            if model is None:
                return
            try:
                while not self.stop.is_set():
                    try:
                        channel, _ = self.listener.accept()
                    except socket.timeout:
                        continue
                    session, secure = None, None
                    try:
                        channel.settimeout(2)
                        secure = context.wrap_socket(channel, server_side=True)
                        session = accept_session(secure, model, certificates)
                        with self.channel_lock:
                            self.active_channels.add(secure)
                            self.connection_count += 1
                        while not self.stop.is_set():
                            serve_once(secure, session)
                    except (OSError, StreamError) as error:
                        self.errors.append(getattr(error, 'code', type(error).__name__))
                    finally:
                        if session is not None:
                            session.close()
                        if secure is not None:
                            with self.channel_lock:
                                self.active_channels.discard(secure)
                            secure.close()
                        channel.close()
                        self.snapshots.append(model.deployments())
            finally:
                model.close()

        self.thread = threading.Thread(target=server, daemon=True)
        self.thread.start()
        self.addCleanup(self.shutdown)
        self.assertTrue(self.ready.wait(3), 'Manager receiver initialization timed out')
        self.assertFalse(self.startup_errors, 'Manager receiver initialization failed: ' + repr(self.startup_errors))

    def shutdown(self):
        self.stop.set()
        self.thread.join(3)
        self.listener.close()
        self.assertFalse(self.thread.is_alive(), 'fixture left Manager thread active')

    def client(self, identity, certificate):
        from uas.manager_transport import ManagerAddress, RoomTLSClient, client_tls_context
        context = client_tls_context(trust_file=str(self.certroot / 'ca.crt'),
            certificate_file=str(self.certroot / (certificate + '.crt')),
            private_key_file=str(self.certroot / (certificate + '.key')))
        client = RoomTLSClient(identity, ManagerAddress('localhost', self.port), context)
        self.addCleanup(client.close)
        return client

    def test_two_authenticated_room_streams_disconnect_replay_and_restart(self):
        from uas.ledger import Command, Event, Origin, RoomLedger, Transition
        from uas.manager_stream import ManagerReadModel, RoomStream
        from uas.manager_transport import export_once
        origin = Origin('actor', 'participant', 'incarnation', 'authority', ('observe',))
        with RoomLedger(self.root / 'alpha.sqlite3', 'alpha') as alpha, \
             RoomLedger(self.root / 'beta.sqlite3', 'beta') as beta:
            for identity, ledger, name in ((self.alpha, alpha, 'alpha'), (self.beta, beta, 'beta')):
                client = self.client(identity, name)
                self.assertEqual({'status': 'synchronized', 'room_seq': 0}, export_once(
                    RoomStream(ledger, identity), client, captured_at='2026-10-27T20:00:00+00:00'))
                client.close()
            # The Hub continues committing while neither Room is connected.
            for number in range(3):
                alpha.apply(Command('op-' + str(number), 'counter', 'target', None, {}), origin,
                    authorize=lambda *_: True, decide=lambda state, _: Transition(state,
                        (Event('source.changed', {'project_text': 'MUST_NOT_ESCAPE'}),), {}))
            reconnected = self.client(self.alpha, 'alpha')
            self.assertEqual({'status': 'synchronized', 'room_seq': 3}, export_once(
                RoomStream(alpha, self.alpha), reconnected, captured_at='2026-10-27T20:00:10+00:00'))
            reconnected.close()
        # Separate SQLite reader observes the committed snapshot, not queued I/O.
        with_read = ManagerReadModel(self.root / 'manager.sqlite3')
        try:
            rooms = with_read.deployments()['deployment']
            self.assertEqual(['alpha', 'beta'], [r['identity']['room_id'] for r in rooms])
            self.assertEqual([3, 0], [r['projection']['room_seq'] for r in rooms])
            self.assertEqual(3, with_read._db.execute('SELECT count(*) FROM manager_events').fetchone()[0])
            self.assertNotIn('MUST_NOT_ESCAPE', str(rooms))
        finally:
            with_read.close()

    def test_certificate_cannot_select_another_room_or_gain_workflow_actions(self):
        from uas.manager_stream import StreamError
        attacker = self.client(self.beta, 'alpha')
        with self.assertRaises((StreamError, OSError)):
            attacker.connect()
        attacker.close()
        legitimate = self.client(self.alpha, 'alpha')
        self.assertIsNone(legitimate.connect())
        with self.assertRaises((StreamError, OSError)):
            legitimate._exchange({'kind': 'run-close', 'room_id': 'beta'})
        legitimate.close()

    def test_missing_unregistered_client_and_untrusted_server_certificates_fail_closed(self):
        import ssl
        from uas.manager_transport import ManagerAddress, RoomTLSClient
        from uas.manager_stream import StreamError
        missing = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        missing.minimum_version = ssl.TLSVersion.TLSv1_3
        missing.load_verify_locations(cafile=str(self.certroot / 'ca.crt'))
        no_certificate = RoomTLSClient(self.alpha, ManagerAddress('localhost', self.port), missing)
        self.addCleanup(no_certificate.close)
        with self.assertRaises((OSError, StreamError)):
            no_certificate.connect()
        no_certificate.close()
        unregistered = self.client(self.alpha, 'unregistered')
        with self.assertRaises((OSError, StreamError)):
            unregistered.connect()
        unregistered.close()
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        untrusted.minimum_version = ssl.TLSVersion.TLSv1_3
        untrusted.load_cert_chain(str(self.certroot / 'alpha.crt'), str(self.certroot / 'alpha.key'))
        wrong_trust = RoomTLSClient(self.alpha, ManagerAddress('localhost', self.port), untrusted)
        self.addCleanup(wrong_trust.close)
        with self.assertRaises(ssl.SSLCertVerificationError):
            wrong_trust.connect()

    def test_owned_exporter_worker_survives_stop_reopens_same_stream_and_terminates_before_destroy(self):
        import json
        from pathlib import Path
        from lifecycle_support import FileFixtureBackend
        from manager_worker_fixture import hosted_manager_worker
        from uas.ledger import Command, Event, Origin, RoomLedger, Transition
        from uas.lifecycle import FixtureSpec, Supervisor
        config = json.loads((Path(__file__).parent / 'fixtures/two-rooms.json').read_text())
        config['deployment']['id'] = self.alpha.deployment_id
        config['deployment']['state_root'] = str(self.root / 'control')
        for room in config['rooms']:
            room['state_root'] = str(self.root / 'control' / room['id'])
            for role in room['project']['roots']:
                path = self.root / room['id'] / role; path.mkdir(parents=True)
                room['project']['roots'][role] = str(path)
        room = config['rooms'][0]
        backend = FileFixtureBackend(self.root / 'resources')
        supervisor = Supervisor(self.root / 'control', 'alpha', backend,
                                authorize=lambda *_: True, revoke=backend.revoke)
        spec = FixtureSpec('alpha', room['project']['id'], tuple(room['project']['roots'].values()),
            'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        supervisor.start(spec)
        ledger_path = self.root / 'worker-room.sqlite3'
        ledger = RoomLedger(ledger_path, 'alpha'); self.addCleanup(ledger.close)
        origin = Origin('actor', 'participant', 'incarnation', 'authority', ('observe',))
        def advance(number):
            ledger.apply(Command('worker-event-' + str(number), 'counter', 'target', None, {}), origin,
                authorize=lambda *_: True, decide=lambda state, _: Transition(state,
                    (Event('source.changed', {}),), {}))
        def received(sequence, phase):
            return lambda projection: (projection['room_seq'] == sequence and
                projection['sections']['room_lifecycle']['value']['alpha']['phase'] == phase)
        with hosted_manager_worker(supervisor, ledger_path, self.alpha, config, self.certroot) as fixture:
            worker = fixture.worker; worker.start()
            fixture.wait_projection(received(0, 'running'))
            supervisor.stop()
            fixture.wait_projection(received(0, 'stopped'))  # No Hub event hides lifecycle propagation.
            self.assertFalse(worker.status()['terminated'])
            owned_id = worker.worker_id
            connections = fixture.disconnect_receiver()
            advance(1)
            fixture.wait_projection(received(1, 'stopped'))
            self.assertGreater(fixture.connection_count(), connections)
            self.assertEqual(owned_id, worker.worker_id)  # Same live worker reconnects automatically.
            self.assertFalse(worker.status()['terminated'])
            worker.request_stop(); self.assertTrue(worker.join(3))
            advance(2)  # Hub progress while the exporter is offline.
            restarted = fixture.new_worker(); self.assertNotEqual(worker.worker_id, restarted.worker_id)
            restarted.start()
            fixture.wait_projection(received(2, 'stopped'))
            supervisor.start(spec)
            fixture.wait_projection(received(2, 'running'))  # Quiet-Hub resume also propagates.
            with supervisor._locked():
                restarted.request_stop()  # Never join while this owner lock is held.
            self.assertTrue(restarted.join(3))
            self.assertTrue(restarted.status()['terminated'])
            supervisor.destroy()


if __name__ == '__main__':
    unittest.main()
