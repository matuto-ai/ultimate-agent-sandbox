"""One-thread Hub loop with two distinct real Python task origins, not Docker/Pi."""
import json
from pathlib import Path
import threading
import unittest

import test_workstation_peer as peer_fixture
from uas.kernel_origin import OriginDenied, enable, receive
from uas.workstation_admission import HubAdmission, _canonical, send_admit
from uas.workstation_hub import AdmittedHubLoop
from uas.workstation_peer import AdmittedPeerDispatcher


class HubLoopTests(unittest.TestCase):
    setUpClass=classmethod(peer_fixture.AdmittedPeerTests.setUpClass.__func__)
    packet=peer_fixture.AdmittedPeerTests.packet

    def setUp(self):
        peer_fixture.AdmittedPeerTests.setUp(self)
        enable(self.sender)
        self.loop=AdmittedHubLoop(self.admissions,self.dispatcher,self.control,
                                  context_generations={'alice':1,'bob':1})
        self.addCleanup(self.loop.close)

    def test_two_distinct_children_dispatch_on_existing_owner_thread(self):
        for index,child in enumerate(self.children):
            child.send(self.packet(index,identity='message-'+str(index)))
        results=self.loop.step(1)
        self.assertEqual(len(results),2)
        self.assertTrue(all(result['ok'] for result in results))
        for child in self.children:self.assertTrue(child.reply()['ok'])
        traffic=self.ledger.snapshot()['state']['peer_traffic']['traffic']
        self.assertEqual(traffic['message-0']['actor_id'],'actor-a')
        self.assertEqual(traffic['message-1']['actor_id'],'actor-b')

    def test_control_eof_precedes_already_queued_peer_packet(self):
        before=self.ledger.snapshot()['room_seq']
        self.children[0].send(self.packet())
        self.sender.close()
        with self.assertRaises(OriginDenied):self.loop.step(1)
        self.assertEqual(self.ledger.snapshot()['room_seq'],before)
        self.assertFalse(self.admissions._active)

    def test_control_revoke_wins_over_queued_peer_and_sibling_survives(self):
        self.children[0].send(self.packet())
        self.children[1].send(self.packet(1,identity='sibling'))
        self.sender.send(_canonical({'version':1,'kind':'REVOKE','exchange_id':'e'*32,
            'operation_id':self.operations[0],'controller':self.admissions.controller}))
        results=self.loop.step(1)
        self.assertEqual(len(results),1)
        self.assertTrue(results[0]['ok'])
        with receive(self.sender) as record:
            self.assertFalse(json.loads(record.data)['result']['installed'])
        traffic=self.ledger.snapshot()['state']['peer_traffic']['traffic']
        self.assertNotIn('message-1',traffic)
        self.assertEqual(traffic['sibling']['actor_id'],'actor-b')
        self.assertTrue(self.admissions.status(self.operations[1])['installed'])

    def test_held_task_exit_fences_only_that_seat_without_pid_lookup(self):
        self.children[0].stop()
        self.children[1].send(self.packet(1,identity='sibling'))
        results=self.loop.step(1)
        self.assertEqual(len(results),1)
        self.assertTrue(results[0]['ok'])
        self.assertFalse(self.admissions.status(self.operations[0])['installed'])
        self.assertTrue(self.admissions.status(self.operations[1])['installed'])

    def test_other_thread_cannot_consume_ledger_or_control(self):
        errors=[]
        def run():
            try:self.loop.step(0)
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=run);thread.start();thread.join(2)
        self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],OriginDenied)
        self.assertFalse(self.loop._closed)

    def test_idle_poll_is_bounded_and_checks_endpoint(self):
        self.assertEqual(self.loop.step(0),[])
        with self.assertRaises(OriginDenied):self.loop.step(2)
        self.assertFalse(self.loop._closed)

    def test_single_admit_attaches_before_ack_then_processes_queued_child_data(self):
        import socket
        self.loop.close()
        control,sender=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.addCleanup(sender.close);self.addCleanup(control.close)
        enable(control);enable(sender)
        admissions=HubAdmission(self.root/'fresh-admissions.db',seats=self.seats,
                                supervisor=self.supervisor,endpoint=peer_fixture.Endpoint())
        self.addCleanup(admissions.close)
        dispatcher=AdmittedPeerDispatcher(admissions,self.hub)
        loop=AdmittedHubLoop(admissions,dispatcher,control,
                            context_generations={'alice':1,'bob':1})
        self.addCleanup(loop.close)
        operation='f'*32
        self.children[0].send(self.packet(identity='after-admit'))
        send_admit(sender,launch=self.launches[0],seat=self.seats[0],
                   operation_id=operation,epoch=1,readiness_digest='c'*64)
        self.assertEqual(loop.step(1),[])
        with receive(sender) as record:
            self.assertEqual(json.loads(record.data)['result']['status'],'ADMITTED')
        self.assertIn(operation,dispatcher._connections)
        self.assertNotIn('after-admit',self.ledger.snapshot()['state']['peer_traffic']['traffic'])
        self.assertTrue(loop.step(1)[0]['ok'])
        self.assertTrue(self.children[0].reply()['ok'])
