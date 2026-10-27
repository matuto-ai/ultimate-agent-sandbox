"""Real external Broker process and Linux per-record origin integration.

No live accounts, network provider, native agent or container is used. The
credential is a synthetic sentinel passed only to the Broker environment. These
same-UID tests prove non-inheritance, NOT filesystem/ptrace credential isolation.
Kernel checks happen in setUpClass, never while a pure test imports this module.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from lifecycle_support import FileFixtureBackend
from uas.fixture_peer import FixtureReceiver
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read_service import ReadBrokerClient, receive_result
from uas.kernel_origin import OriginDenied, OriginUnavailable, enable, probe
from uas.ledger import LedgerError, Origin, RoomLedger, _json
from uas.lifecycle import FixtureSpec, Supervisor
from uas.participant import FixtureCredentials, FixtureSeat
from uas.peer import FixtureParticipant, FixturePeerHub


_REPOSITORY = Path(__file__).resolve().parents[1]
_CREDENTIAL_NAME = 'UAS_TEST_READ_BROKER_CREDENTIAL'
_CREDENTIAL = 'synthetic-broker-only-not-an-account-key'
_WORKER_SOURCE = r'''
import json, os, socket, sys
from pathlib import Path
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read import ExternalReadBroker
from uas.forge_read_service import serve
from uas.kernel_origin import OriginDenied
from uas.ledger import LedgerError
channel = socket.socket(fileno=int(sys.argv[1]))
root, instance, mode = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
credential = os.environ.pop('UAS_TEST_READ_BROKER_CREDENTIAL', None)
class Provider:
    host = 'github.com'
    def __init__(self, actor): self.actor = actor
    def read(self, route):
        if credential != 'synthetic-broker-only-not-an-account-key':
            raise LedgerError('CREDENTIAL_UNAVAILABLE')
        print(json.dumps({'event':'CONTACT', 'actor':self.actor,
                          'credential_available':bool(credential)}), flush=True)
        if mode == 'gate' and sys.stdin.readline().strip() != 'release':
            raise LedgerError('PROVIDER_FAILURE')
        return {'status':'OK', 'completeness':'complete', 'data':{
            'repository':route.repository, 'actor':self.actor,
            'payload':'x' * (180000 if mode == 'large' else 8)}}
def provider(actor):
    if actor != 'actor-a': raise LedgerError('CREDENTIAL_UNAVAILABLE')
    return Provider(actor)
try:
    with ForgeAudit(root/'audit.db', 'deployment-a') as audit:
        broker = ExternalReadBroker(ForgeBinding('alpha','fixture','owner/repo'),
                                    instance, audit, provider, root/'results')
        serve(channel, broker, supervisor_uid=int(sys.argv[5]), supervisor_gid=int(sys.argv[6]))
except (OriginDenied, OSError, LedgerError) as error:
    print(json.dumps({'event':'FENCED', 'kind':type(error).__name__}), flush=True)
    sys.exit(3)
'''
_ATTACK_SOURCE = r'''
import json, os, socket, sys
channel=socket.socket(fileno=int(sys.argv[1]))
packet=json.loads(sys.argv[2])
channel.send(json.dumps(packet).encode())
print(json.dumps({'pid':os.getpid(), 'sent':True}),flush=True)
'''


class ExternalReadProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe()
            if os.getuid() == 0:
                raise OriginUnavailable('unprivileged fixture required')
        except OriginUnavailable as error:
            if os.environ.get('UAS_REQUIRE_PARTICIPANT_PROCESS_TESTS') == '1':
                raise RuntimeError('Required external Broker process tests unavailable') from error
            raise unittest.SkipTest(str(error))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='uas-forge-read-process-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root/'project'
        self.project.mkdir()
        self.backend = FileFixtureBackend(self.root/'resources')
        self.spec = FixtureSpec('alpha', 'fixture', (str(self.project),),
                                *['sha256:' + c * 64 for c in 'abc'])
        self.supervisor = Supervisor(self.root/'control', 'alpha', self.backend,
                                    authorize=lambda *_: True, revoke=self.backend.revoke)
        self.instance = self.supervisor.start(self.spec)['instance_id']
        self.binding = ForgeBinding('alpha', 'fixture', 'owner/repo')
        self.origin = Origin('actor-a', 'alice', 'incarnation-a', 'epoch-1', ('forge-read',))
        self.worker = self.client = None

    @staticmethod
    def stop_child(process):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def start_broker(self, mode='normal', *, client_binding=None):
        self.assertIsNone(self.worker)
        local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(local.close)
        self.addCleanup(remote.close)
        # Ancillary capture must be enabled before bootstrap can be queued.
        enable(remote)
        environment = {'LANG':'C.UTF-8', 'PYTHONPATH':str(_REPOSITORY),
                       _CREDENTIAL_NAME:_CREDENTIAL}
        self.worker = subprocess.Popen([sys.executable, '-u', '-c', _WORKER_SOURCE,
            str(remote.fileno()), str(self.root), self.instance, mode,
            str(os.getuid()), str(os.getgid())], pass_fds=(remote.fileno(),),
            cwd=str(_REPOSITORY), env=environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.addCleanup(self.stop_child, self.worker)
        remote.close()
        self.client = ReadBrokerClient(local, self.supervisor, client_binding or self.binding, self.instance,
                                       worker_uid=os.getuid(), worker_gid=os.getgid())
        self.addCleanup(self.client.close)
        self.client.channel.settimeout(2)
        self.assertEqual(self.worker.pid, self.client.worker.credentials[0])
        self.assertNotEqual(os.getpid(), self.worker.pid)
        return self.client

    def line(self, process, timeout=2):
        self.assertTrue(select.select([process.stdout], [], [], timeout)[0],
                        'bounded fixture stdout event missing')
        line = process.stdout.readline()
        self.assertTrue(line, 'fixture exited before expected event')
        return json.loads(line)

    def packet(self, operation='read-1', *, argv=None, origin=None):
        with self.supervisor._locked():
            return self.client.prepare({'id':operation, 'kind':'forge-read',
                'argv':['repo','view'] if argv is None else argv}, origin or self.origin)

    def record(self, operation='read-1'):
        key = 'read-' + hashlib.sha256(_json([
            self.binding.room_id, self.instance, operation]).encode()).hexdigest()
        with ForgeAudit(self.root/'audit.db', 'deployment-a') as audit:
            return audit.read_record(key)

    def raw_request(self, packet):
        # Deliberately bypass the client's immutable prepared-packet guard to
        # test service validation of a malformed authenticated Supervisor record.
        raw = _json(packet).encode()
        self.assertEqual(len(raw), self.client.channel.send(raw))
        return receive_result(self.client.channel, self.client.worker, packet['request_id'])

    def denial_codes(self):
        with ForgeAudit(self.root/'audit.db', 'deployment-a') as audit:
            rows = audit._db.execute('SELECT id FROM read_starts ORDER BY rowid').fetchall()
            records = [audit.read_record(row['id']) for row in rows]
        denied = [r for r in records if r['metadata']['route'] == 'denied'
                  and r['metadata']['actor_id'] == 'unauthenticated']
        self.assertTrue(all(r['result']['contact'] == 'none' for r in denied))
        return {r['result']['status'] for r in denied}

    def error(self, code, function):
        with self.assertRaises(LedgerError) as raised:
            function()
        self.assertEqual(code, raised.exception.code)

    def participant(self):
        ledger = RoomLedger(self.root/'room.db', 'alpha')
        self.addCleanup(ledger.close)
        hub = FixturePeerHub(ledger)
        hub.configure('configure', (FixtureParticipant('alice','actor-a'),
                                    FixtureParticipant('bob','actor-b')), 'run-1')
        credentials = FixtureCredentials((('actor-a','forge.fixture.invalid','forge','fixture-a'),),
                                          ('fixture-a',))
        controller = self.supervisor.participants(hub, credentials)
        self.addCleanup(controller.close)
        controller.bind_read_service(self.client)
        receiver = FixtureReceiver(self.root/'receiver.db', 'alpha', 'alice', 'synthetic-inbox')
        self.addCleanup(receiver.close)
        seat = FixtureSeat('alice','actor-a','peer-profile',('peer-traffic','forge-read'),
                           required_credentials=('forge',))
        handle = controller.launch(seat, receiver)
        self.assertEqual({'ready':True,'pid':handle.process.pid,'uid':os.getuid()}, self.line(handle.process))
        return controller, handle

    def send(self, handle, operation='read-1', *, mode=None, argv=None):
        command = {'message':{'id':operation, 'kind':'forge-read',
                             'argv':['repo','view'] if argv is None else argv}}
        if mode is not None:
            command['mode'] = mode
        handle.process.stdin.write(json.dumps(command)+'\n')
        handle.process.stdin.flush()
        self.assertTrue(self.line(handle.process)['sent'])

    def test_actual_participant_external_broker_and_metadata_only_audit(self):
        self.start_broker()
        controller, handle = self.participant()
        self.assertNotIn(_CREDENTIAL_NAME, os.environ)
        participant_environment = Path(f'/proc/{handle.process.pid}/environ').read_bytes()
        self.assertNotIn(_CREDENTIAL_NAME.encode(), participant_environment)
        self.assertNotIn(_CREDENTIAL.encode(), participant_environment)
        self.send(handle)
        response = controller.receive(handle)
        self.assertEqual(response, self.line(handle.process))
        self.assertTrue(response['ok'])
        self.assertEqual('actor-a', response['receipt']['observation']['data']['actor'])
        self.assertEqual({'event':'CONTACT','actor':'actor-a','credential_available':True}, self.line(self.worker))
        audited = self.record()
        self.assertEqual(handle.badge.incarnation_id, audited['metadata']['incarnation_id'])
        self.assertEqual('OK', audited['result']['status'])
        self.assertNotIn('payload', json.dumps(audited))
        self.assertNotIn(_CREDENTIAL, json.dumps(audited))
        ledger = controller.hub.ledger
        row = ledger._connection().execute(
            'SELECT canonical, receipt FROM operations WHERE id=?', ('read-1',)).fetchone()
        stored, reserved = json.loads(row['canonical']), json.loads(row['receipt'])
        metadata = {'request_digest':hashlib.sha256(_json({
            'id':'read-1','kind':'forge-read','argv':['repo','view']}).encode()).hexdigest(),
            'host':'github.com','repository':'owner/repo'}
        self.assertEqual('forge-read-external', stored['command']['kind'])
        self.assertEqual(metadata, stored['command']['payload'])
        self.assertEqual({'status':'RESERVED'}, reserved['result'])
        events = [event for event in ledger.replay(0) if event['operation_id'] == 'read-1']
        self.assertEqual(1, len(events))
        self.assertEqual('forge-read-reserved', events[0]['kind'])
        self.assertEqual(metadata, events[0]['payload'])
        room_evidence = json.dumps([stored, reserved, events])
        for absent in ('"argv"', '"observation"', '"rawresult"', 'xxxxxxxx', _CREDENTIAL):
            self.assertNotIn(absent, room_evidence)
        self.send(handle)
        self.assertEqual(response, controller.receive(handle))
        self.assertEqual(response, self.line(handle.process))
        # An exact retry discloses its original cached receipt without a contact.
        self.assertFalse(select.select([self.worker.stdout], [], [], 0)[0])

    def test_forked_participant_cannot_acquire_parent_actor_authority(self):
        self.start_broker()
        controller, handle = self.participant()
        self.send(handle, mode='fork')
        response = controller.receive(handle)
        self.assertEqual({'ok':False,'error':'WRONG_PROCESS'}, response)
        self.assertEqual(response, self.line(handle.process))
        self.assertIsNone(self.record())
        self.assertIn('WRONG_PROCESS', self.denial_codes())
        self.assertFalse(select.select([self.worker.stdout], [], [], 0)[0])

    def test_inherited_supervisor_descriptor_is_not_supervisor_process_authority(self):
        self.start_broker()
        packet = self.packet()
        attacker = subprocess.Popen([sys.executable, '-u', '-c', _ATTACK_SOURCE,
            str(self.client.channel.fileno()), json.dumps(packet)],
            pass_fds=(self.client.channel.fileno(),), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={'LANG':'C.UTF-8'})
        self.addCleanup(self.stop_child, attacker)
        self.assertNotEqual(os.getpid(), self.line(attacker)['pid'])
        attacker.wait(timeout=2)
        self.assertEqual(3, self.worker.wait(timeout=2))
        self.assertEqual('FENCED', self.line(self.worker)['event'])
        self.assertIsNone(self.record())
        self.assertTrue(self.denial_codes() & {'WRONG_PROCESS', 'INVALID_PROCESS_RECORD'})
        self.error('BROKER_UNAVAILABLE', lambda: self.client.perform(packet))

    def test_invalid_origin_cross_room_and_raw_route_do_not_contact_provider(self):
        self.start_broker()
        invalid = self.packet()
        invalid['origin']['attacker_identity'] = 'actor-b'
        self.assertEqual({'ok':False,'error':'FORBIDDEN'}, self.raw_request(invalid))
        self.assertIn('FORBIDDEN', self.denial_codes())
        denied = self.client.perform(self.packet('raw-api', argv=['api','user']))
        self.assertEqual('UNSUPPORTED_ROUTE', denied['observation']['status'])
        self.assertEqual('none', self.record('raw-api')['result']['contact'])
        self.assertFalse(select.select([self.worker.stdout], [], [], 0)[0])
        cross = self.packet('cross-room')
        cross['room_id'] = 'beta'
        with self.assertRaises(OriginDenied):
            self.raw_request(cross)
        self.assertEqual(3, self.worker.wait(timeout=2))
        self.assertIsNone(self.record('cross-room'))
        self.assertTrue(self.denial_codes() & {'PROJECT_MISMATCH', 'INVALID_PROCESS_RECORD'})

    def test_bootstrap_same_room_and_instance_wrong_repository_is_denied(self):
        wrong_repository = ForgeBinding('alpha', 'fixture', 'owner/other')
        with self.assertRaises(OriginDenied):
            self.start_broker(client_binding=wrong_repository)
        self.assertEqual(3, self.worker.wait(timeout=2))
        self.assertEqual('FENCED', self.line(self.worker)['event'])
        self.assertIsNone(self.client)
        self.assertIsNone(self.record())
        self.assertIn('PROJECT_MISMATCH', self.denial_codes())

    def test_large_response_crosses_real_authenticated_chunk_transport(self):
        self.start_broker('large')
        observed = self.client.perform(self.packet())['observation']
        self.assertEqual('OK', observed['status'])
        self.assertEqual('x' * 180000, observed['data']['payload'])
        self.assertGreater(self.record()['result']['output_bytes'], 65536)
        self.assertEqual('CONTACT', self.line(self.worker)['event'])

    def test_broker_exit_prevents_send_and_no_same_uid_pid_claim_restores_it(self):
        self.start_broker()
        packet = self.packet()
        self.worker.terminate()
        self.worker.wait(timeout=2)
        self.error('BROKER_UNAVAILABLE', lambda: self.client.perform(packet))
        self.assertIsNone(self.record())

    def gate_thread(self, action):
        errors = []
        def work():
            try:
                self.assertEqual('CONTACT', self.line(self.worker)['event'])
                action()
                self.worker.stdin.write('release\n')
                self.worker.stdin.flush()
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=work)
        thread.start()
        def finish():
            thread.join(3)
            self.assertFalse(thread.is_alive(), 'bounded provider release thread stuck')
            if errors:
                raise errors[0]
        self.addCleanup(finish)
        return finish

    def test_participant_exit_during_contact_blocks_late_receipt_disclosure(self):
        self.start_broker('gate')
        controller, handle = self.participant()
        self.send(handle)
        def exit_participant():
            handle.process.terminate()
            handle.process.wait(timeout=2)
        finish = self.gate_thread(exit_participant)
        response = controller.receive(handle)
        finish()
        self.assertEqual({'ok':False,'error':'PROCESS_EXITED'}, response)
        # Provider work already in flight may finish, but cannot regrant authority.
        self.assertEqual('OK', self.record()['result']['status'])
        self.error('PROCESS_EXITED', lambda: controller._authority(handle,
                    (handle.process.pid,os.getuid(),os.getgid())))

    def test_prepare_then_actual_revoke_blocks_dispatch_before_provider_contact(self):
        self.start_broker()
        controller, handle = self.participant()
        credentials = (handle.process.pid, os.getuid(), os.getgid())
        with self.supervisor._locked():
            packet = self.client.prepare({'id':'read-1', 'kind':'forge-read',
                'argv':['repo','view']}, handle.badge.origin(),
                authorize=lambda: controller._authority(handle, credentials))
        controller.revoke('alice')
        self.error('AUTHORITY_REVOKED', lambda: self.client.perform(packet))
        self.assertIsNotNone(handle.process.poll())
        self.assertIsNone(self.record())
        self.assertFalse(select.select([self.worker.stdout], [], [], 0)[0])
        # Prepared packets are one-shot even when authorization denied them.
        self.error('FORBIDDEN', lambda: self.client.perform(packet))

    def test_revoked_epoch_rejects_already_queued_packet_before_provider_contact(self):
        self.start_broker()
        controller, handle = self.participant()
        self.send(handle)
        # The real controller persists the same epoch fence used by revoke;
        # leave the task alive briefly to exercise a queued stale record.
        with self.supervisor._locked():
            controller._fence(controller._read(), 'alice', 'revoked', 'explicit-revocation')
        response = controller.receive(handle)
        self.assertEqual({'ok':False,'error':'AUTHORITY_REVOKED'}, response)
        self.assertEqual(response, self.line(handle.process))
        self.assertIsNone(self.record())
        self.assertIn('AUTHORITY_REVOKED', self.denial_codes())
        self.assertFalse(select.select([self.worker.stdout], [], [], 0)[0])

    def test_disconnect_during_contact_rejects_late_reply_without_recontact(self):
        self.start_broker('gate')
        packet = self.packet()
        def disconnect():
            self.client.channel.shutdown(socket.SHUT_RDWR)
        finish = self.gate_thread(disconnect)
        self.error('BROKER_UNAVAILABLE', lambda: self.client.perform(packet))
        finish()
        self.assertEqual(3, self.worker.wait(timeout=2))
        self.assertTrue(self.client.closed)
        self.assertEqual('OK', self.record()['result']['status'])
        self.error('BROKER_UNAVAILABLE', lambda: self.client.perform(packet))


if __name__ == '__main__':
    unittest.main()
