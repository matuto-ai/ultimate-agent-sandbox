"""Two distinct owned child task origins -> existing Hub/RoomLedger decisions.

Real socketpair/kernel attribution; Python children and native-readiness inputs
are fixtures, NOT Pi, container namespaces, SELinux or production qualification.
"""
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from uas.kernel_origin import HeldOrigin, OriginDenied, OriginUnavailable, ReceiverIdentity, enable, probe, receive
from uas.ledger import RoomLedger
from uas.peer import FixtureParticipant, FixturePeerHub
from uas.workstation_admission import AdmissionSeat, HubAdmission, send_admit
from uas.workstation_exec import ExecLaunch, ExecSeat
from uas.workstation_peer import AdmittedPeerDispatcher


class Endpoint:
    def require(self):
        pass


class OwnedChild:
    def __init__(self):
        self.channel, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        enable(self.channel)
        self.channel.settimeout(2)
        code = '''import socket,sys,json
peer=socket.socket(fileno=int(sys.argv[1]))
peer.send(b'owned-child-bootstrap')
for line in sys.stdin:
 message=json.loads(line)
 if message['op']=='send':
  peer.send(json.dumps(message['packet']).encode())
  print(json.dumps({'sent':True}),flush=True)
 elif message['op']=='read':
  print(json.dumps({'reply':json.loads(peer.recv(65536))}),flush=True)
'''
        self.process = subprocess.Popen([sys.executable, '-u', '-c', code, str(peer.fileno())],
            pass_fds=(peer.fileno(),), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        peer.close()
        with receive(self.channel) as record:
            self.origin = HeldOrigin(record)
        if self.origin.credentials[0] != self.process.pid:
            raise AssertionError('owned child is not received kernel sender')

    def command(self, value):
        self.process.stdin.write(json.dumps(value)+'\n'); self.process.stdin.flush()
        if not select.select([self.process.stdout], [], [], 2)[0]:
            raise AssertionError('owned child command timed out')
        return json.loads(self.process.stdout.readline())

    def send(self, packet):
        return self.command({'op': 'send', 'packet': packet})

    def reply(self):
        return self.command({'op': 'read'})['reply']

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=2)

    def close(self):
        self.stop()
        self.channel.close(); self.origin.close()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


class AdmittedPeerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe()
        except OriginUnavailable as error:
            raise unittest.SkipTest(str(error))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.control, self.sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        enable(self.control)
        self.addCleanup(self.control.close); self.addCleanup(self.sender.close)
        self.sender.send(b'trusted-supervisor')
        with receive(self.control) as record:
            self.supervisor = HeldOrigin(record)
        self.addCleanup(self.supervisor.close)
        self.children = []
        for _ in range(2):
            child = OwnedChild()
            self.addCleanup(child.close)
            self.children.append(child)
        self.assertNotEqual(self.children[0].origin.identity, self.children[1].origin.identity)
        self.assertNotEqual(self.children[0].process.pid, self.children[1].process.pid)
        receiver = ReceiverIdentity(os.getuid(), os.getgid(), 'hub-alpha', 'a'*64)
        self.seats = [AdmissionSeat('alpha', 'instance', name, actor, 'peer', ('peer-traffic',), receiver)
                      for name, actor in (('alice', 'actor-a'), ('bob', 'actor-b'))]
        self.admissions = HubAdmission(self.root/'admissions.db', seats=self.seats,
                                      supervisor=self.supervisor, endpoint=Endpoint())
        self.addCleanup(self.admissions.close)
        self.ledger = RoomLedger(self.root/'room.db', 'alpha'); self.addCleanup(self.ledger.close)
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', tuple(FixtureParticipant(s.participant_id, s.actor_id) for s in self.seats), 'run-1')
        self.dispatcher = AdmittedPeerDispatcher(self.admissions, self.hub)
        self.operations, self.launches = [], []
        for index, (seat, child) in enumerate(zip(self.seats, self.children)):
            operation = str(index+1)*32
            launch = ExecLaunch(None, ExecSeat('alpha', 'instance', seat.participant_id, seat.actor_id,
                'seat-a' if index==0 else 'seat-b', 'b'*64, os.getuid(), os.getgid()), Endpoint(), self.root/f'launch-{index}')
            launch.state = 'active'  # Synthetic readiness, not native Pi proof.
            launch.origin, launch.channel = child.origin, child.channel
            send_admit(self.sender, launch=launch, seat=seat, operation_id=operation,
                       epoch=1, readiness_digest='c'*64)
            self.admissions.admit(self.control)
            # This source test covers inbound dispatch only. No fake safe-point
            # or outbound delivery is supplied by this placeholder receiver.
            connection = self.hub.connect(f'attach-{index}', seat.participant_id, launch.incarnation, object())
            self.dispatcher.attach(operation, connection)
            self.operations.append(operation); self.launches.append(launch)

    def packet(self, index=0, *, identity='message-1', request='a'*32):
        return {'request_id': request, 'envelope': {'id': identity, 'run_id': 'run-1', 'generation': 1,
            'kind': 'message', 'payload': {'recipient': 'bob' if index==0 else 'alice', 'text': 'hello', 'parent_id': None}}}

    def exchange(self, index, packet):
        self.children[index].send(packet)
        result = self.dispatcher.receive(self.operations[index])
        self.assertEqual(self.children[index].reply(), result)
        return result

    def test_two_distinct_kernel_children_get_exact_actor_ledger_attribution(self):
        for index in (0, 1):
            self.assertTrue(self.exchange(index, self.packet(index, identity=f'message-{index}'))['ok'])
        traffic = self.ledger.snapshot()['state']['peer_traffic']['traffic']
        self.assertEqual(traffic['message-0']['actor_id'], 'actor-a')
        self.assertEqual(traffic['message-1']['actor_id'], 'actor-b')
        events = [row for row in self.ledger.replay(0, limit=1000) if row['kind']=='peer.submitted']
        self.assertEqual([event['origin']['actor_id'] for event in events], ['actor-a', 'actor-b'])

    def test_attach_rejects_mismatched_hub_actor_without_mutation(self):
        ledger = RoomLedger(self.root/'mismatched-room.db', 'alpha')
        self.addCleanup(ledger.close)
        hub = FixturePeerHub(ledger)
        hub.configure('configure', (FixtureParticipant('alice', 'wrong-actor'),
                                   FixtureParticipant('bob', 'actor-b')), 'run-1')
        operation = self.operations[0]
        binding = self.admissions.binding(operation)
        self.assertEqual(binding.seat.actor_id, 'actor-a')
        connection = hub.connect('attach', 'alice', binding.incarnation, object())
        # A dispatcher owns one admission controller. Use a separate real
        # admission fixture for the intentionally mismatched local Hub.
        admissions = HubAdmission(self.root/'mismatched-admissions.db', seats=self.seats,
                                  supervisor=self.supervisor, endpoint=Endpoint())
        self.addCleanup(admissions.close)
        send_admit(self.sender, launch=self.launches[0], seat=self.seats[0],
                   operation_id=operation, epoch=1, readiness_digest='c'*64)
        admissions.admit(self.control)
        self.assertEqual(admissions.binding(operation), binding)
        dispatcher = AdmittedPeerDispatcher(admissions, hub)
        before = ledger.snapshot()
        with self.assertRaisesRegex(OriginDenied, 'Hub Actor'):
            dispatcher.attach(operation, connection)
        self.assertEqual(dispatcher._connections, {})
        self.assertEqual(ledger.snapshot(), before)
        # Existing submit also rejects this mismatch; the early attachment
        # guard adds fail-fast consistency rather than a second reducer.
        from uas.ledger import LedgerError
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            hub.submit(connection, self.packet()['envelope'],
                       origin=dispatcher._origin(binding), authorize=lambda: True)
        self.assertEqual(ledger.snapshot(), before)

    def test_exact_retry_uses_existing_receipt_and_changed_payload_conflicts(self):
        packet = self.packet()
        first = self.exchange(0, packet)
        sequence = self.ledger.snapshot()['room_seq']
        packet['request_id'] = 'b'*32
        second = self.exchange(0, packet)
        self.assertEqual(first['receipt'], second['receipt'])
        self.assertEqual(self.ledger.snapshot()['room_seq'], sequence)
        packet['envelope']['payload']['text'] = 'changed'
        self.assertEqual(self.exchange(0, packet)['error'], 'ID_CONFLICT')
        self.assertEqual(self.ledger.snapshot()['room_seq'], sequence)

    def test_forged_actor_capability_and_room_fields_never_reach_ledger(self):
        sequence = self.ledger.snapshot()['room_seq']
        for field in ('actor_id', 'capabilities', 'room_id'):
            packet = self.packet(identity='forged-'+field)
            packet['envelope'][field] = 'forged'
            self.assertEqual(self.exchange(0, packet)['error'], 'INVALID_ENVELOPE')
        self.assertEqual(self.ledger.snapshot()['room_seq'], sequence)

    def test_forge_stays_unavailable_without_broker_and_does_not_mutate(self):
        packet = {'request_id': 'a'*32, 'envelope': {'id': 'forge-1', 'kind': 'forge-read', 'argv': ['issue', 'view', '1']}}
        sequence = self.ledger.snapshot()['room_seq']
        self.assertEqual(self.exchange(0, packet)['error'], 'FORGE_UNAVAILABLE')
        self.assertEqual(self.ledger.snapshot()['room_seq'], sequence)

    def assert_only_lost_since(self, sequence, participant='alice'):
        events=self.ledger.replay(sequence)
        self.assertEqual([event['kind'] for event in events],['peer.observed'])
        self.assertEqual(events[0]['payload']['participant_id'],participant)
        self.assertEqual(events[0]['payload']['readiness'],'lost')

    def test_other_live_child_record_cannot_use_alice_admission(self):
        self.children[1].send(self.packet(1))
        with receive(self.admissions.peer_channel(self.operations[1])) as wrong_record:
            sequence = self.ledger.snapshot()['room_seq']
            with patch('uas.workstation_peer.receive', return_value=wrong_record):
                result = self.dispatcher.receive(self.operations[0])
            self.assertEqual(result['error'], 'AUTHORITY_REVOKED')
            self.assert_only_lost_since(sequence)
            self.assertTrue(self.admissions.status(self.operations[1])['installed'])

    def test_late_revoke_after_receive_prevents_ledger_mutation(self):
        self.children[0].send(self.packet())
        original = receive
        def late_revoke(channel):
            record = original(channel)
            self.admissions.revoke(self.operations[0])
            return record
        sequence = self.ledger.snapshot()['room_seq']
        with patch('uas.workstation_peer.receive', side_effect=late_revoke):
            self.assertEqual(self.dispatcher.receive(self.operations[0])['error'], 'AUTHORITY_REVOKED')
        self.assert_only_lost_since(sequence)

    def test_exit_after_ledger_begin_is_pure_recheck_then_fence_after_rollback(self):
        original = self.ledger.apply
        authority_sql = []
        self.admissions.db.set_trace_callback(lambda sql: authority_sql.append((sql, self.ledger._connection().in_transaction)))
        def apply(command, origin, *, authorize, decide):
            def inside(origin, operation):
                self.assertTrue(self.ledger._connection().in_transaction)
                self.children[0].stop()
                return authorize(origin, operation)
            return original(command, origin, authorize=inside, decide=decide)
        self.children[0].send(self.packet())
        sequence = self.ledger.snapshot()['room_seq']
        with patch.object(self.ledger, 'apply', side_effect=apply):
            result = self.dispatcher.receive(self.operations[0])
        self.assertEqual(result['error'], 'AUTHORITY_REVOKED')
        self.assert_only_lost_since(sequence)
        self.assertTrue(authority_sql)
        self.assertFalse(any(in_transaction for _, in_transaction in authority_sql))
        self.assertTrue(self.admissions.status(self.operations[1])['installed'])

    def test_recheck_outside_authorization_context_is_forbidden(self):
        self.children[0].send(self.packet())
        with receive(self.admissions.peer_channel(self.operations[0])) as record:
            with self.assertRaises(OriginDenied):
                self.admissions.recheck(self.operations[0], record)

    def test_work_request_and_stale_generation_use_existing_hub_decisions(self):
        packet = self.packet(identity='work-1')
        packet['envelope']['kind'] = 'work-request'
        del packet['envelope']['payload']['parent_id']
        self.assertTrue(self.exchange(0, packet)['ok'])
        item = self.ledger.snapshot()['state']['peer_traffic']['traffic']['work-1']
        self.assertEqual(item['status'], 'QUEUED')
        self.assertIsNone(item['response_started_at'])
        packet = self.packet(identity='stale-1')
        packet['envelope']['generation'] = 999
        self.assertEqual(self.exchange(0, packet)['error'], 'STALE_GENERATION')

    def test_blocked_peer_read_does_not_hold_revocation_lock(self):
        import threading
        entered, release, fenced = threading.Event(), threading.Event(), threading.Event()
        results, failures = [], []
        original = receive
        def stalled(channel):
            entered.set()
            if not release.wait(2):
                raise AssertionError('stalled receive not released')
            return original(channel)
        def dispatch():
            try:
                results.append(self.dispatcher.receive(self.operations[0]))
            except BaseException as error:
                failures.append(error)
        def revoke():
            try:
                self.admissions.revoke(self.operations[0])
            finally:
                fenced.set()
        reader = threading.Thread(target=dispatch)
        revoker = threading.Thread(target=revoke)
        with patch('uas.workstation_peer.receive', side_effect=stalled):
            reader.start()
            try:
                self.assertTrue(entered.wait(1))
                revoker.start()
                self.assertTrue(fenced.wait(1), 'peer recv held authority lock')
            finally:
                release.set()
                reader.join(timeout=2)
                if revoker.ident is not None:
                    revoker.join(timeout=2)
        self.assertFalse(failures)
        self.assertFalse(reader.is_alive())
        self.assertEqual(results[0]['error'], 'AUTHORITY_REVOKED')

    def test_reply_io_allows_revoke_and_lost_reply_preserves_receipt(self):
        import threading
        offer = self.admissions._active[self.operations[0]][0]
        actual = offer.channel
        admissions, operation = self.admissions, self.operations[0]
        self.children[0].send(self.packet())
        class ReplyProbe:
            def __getattr__(self, name):
                return getattr(actual, name)
            def send(self, data):
                done = threading.Event()
                def revoke():
                    try:
                        admissions.revoke(operation)
                    finally:
                        done.set()
                thread = threading.Thread(target=revoke)
                thread.start()
                if not done.wait(1):
                    raise AssertionError('reply held authority lock')
                thread.join(timeout=1)
                return actual.send(data)  # Closed by revoke: intentionally lost.
        offer.channel = ReplyProbe()
        result = self.dispatcher.receive(operation)
        self.assertTrue(result['ok'])
        self.assertIn('message-1', self.ledger.snapshot()['state']['peer_traffic']['traffic'])
        self.assertFalse(admissions.status(operation)['installed'])


class ColdPeerParsingTests(unittest.TestCase):
    def test_cold_import_defers_lifecycle_until_exact_duplicate_rejecting_parser(self):
        code="""import sys,json
sys.path.insert(0,sys.argv[1])
from uas.workstation_peer import AdmittedPeerDispatcher
from uas.ledger import LedgerError
assert 'uas.lifecycle' not in sys.modules
assert 'uas.manager_owner' not in sys.modules
raw=b'{"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","envelope":{"kind":"one","kind":"two"}}'
try:AdmittedPeerDispatcher._decode(raw)
except LedgerError as error:
 assert error.code=='INVALID_NATIVE_FRAME'
 assert type(error.__cause__) is ValueError
 assert str(error.__cause__)=='duplicate manifest field'
else:raise AssertionError('duplicate key accepted')
assert 'uas.lifecycle' in sys.modules
from uas.lifecycle import _unique_object
from unittest.mock import patch
with patch('uas.lifecycle._unique_object',wraps=_unique_object) as exact:
 value=AdmittedPeerDispatcher._decode(b'{"request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","envelope":{}}')
 assert value['envelope']=={} and exact.call_count==2
from types import SimpleNamespace
instance=object.__new__(AdmittedPeerDispatcher)
try:instance._library_frame('operation',SimpleNamespace(data=raw),object())
except LedgerError as error:assert error.code=='INVALID_NATIVE_FRAME'
else:raise AssertionError('duplicate Library frame accepted')
"""
        result=subprocess.run([sys.executable,'-I','-S','-B','-c',code,
            str(Path(__file__).resolve().parents[1])],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
