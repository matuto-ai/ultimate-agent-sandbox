"""Official Pi tool -> held kernel origin -> existing Hub -> real disposable Git.

Same-UID account-free fixture, not host/credential isolation or model obedience.
"""
import json
import os
import select
import socket
import unittest
from unittest.mock import patch

import library_support as support
import test_library_enqueue as service_tests
import test_pi_participant as native_tests
from test_workstation_peer import Endpoint
from uas.kernel_origin import HeldOrigin, ReceiverIdentity, enable, receive
from uas.workstation_admission import AdmissionSeat, HubAdmission, send_admit
from uas.workstation_exec import ExecLaunch, ExecSeat
from uas.workstation_peer import AdmittedPeerDispatcher
from uas.library_hub import LibraryHub
from uas.library_enqueue import EnqueueEndpoint
from uas.context import FixtureRunTerminal

@unittest.skipUnless(native_tests.INSTALL,'Official Pi native capture suite required')
class PiCaptureTests(unittest.TestCase):
    recipe=native_tests.PiParticipantTests.recipe
    idle=native_tests.PiParticipantTests.idle
    def tearDown(self):
        if hasattr(self,'admissions'): self.admissions.close()
        native_tests.PiParticipantTests.tearDown(self)

    def setUp(self):
        native_tests.PiParticipantTests.setUp(self)
        self.service=service_tests.EnqueueTests()
        document=support.document()
        if self._testMethodName=='test_large_configured_capture_authenticated_framing_preserves_payload':
            document['limits'].update(body_bytes=100000,payload_bytes=150000,document_bytes=150000,batch_bytes=200000,projection_bytes=200000)
        with patch('library_support.document',return_value=document):self.service.setUp()
        self.addCleanup(self.service.doCleanups)
        self.contact=EnqueueEndpoint(self.service.publisher,settings=lambda:self.service.settings).contact
        self.observed=[]
        def contact(**kwargs):
            self.observed.append(kwargs)
            return self.contact(**kwargs)
        self.owner=LibraryHub(self.ledger,room_id='alpha',project={'id':'alpha','repository':'acme/alpha',
            'roots':{'reference':'/srv/alpha/reference'}},source_identity='1001',contact=contact,clock=lambda:support.AT)

    def start(self, capability=True):
        native_tests.PiParticipantTests.start(self)
        enable(self.handle.channel)
        # A record from the actual Pi process establishes held kernel identity.
        self.native.rpc('prompt',message='/fixture-peer-probe '+native_tests.encoded({'mode':'raw','packet':native_tests.encoded('bootstrap')}))
        self.assertTrue(select.select([self.handle.channel],[],[],10)[0], 'native Pi capture channel was not ready')
        with receive(self.handle.channel) as record: origin=HeldOrigin(record)
        self.addCleanup(origin.close)
        self.assertEqual(origin.credentials[0],self.native.process.pid)
        control,sender=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        enable(control);self.addCleanup(control.close);self.addCleanup(sender.close)
        sender.send(b'trusted-supervisor')
        with receive(control) as record: supervisor=HeldOrigin(record)
        self.addCleanup(supervisor.close)
        seat=AdmissionSeat('alpha','instance','pi','actor-p','profile',
            ('peer-traffic','library:enqueue') if capability else ('peer-traffic',),
            ReceiverIdentity(os.getuid(),os.getgid(),'hub-alpha','a'*64))
        self.admissions=HubAdmission(self.root/'admission.db',seats=[seat],supervisor=supervisor,endpoint=Endpoint())
        self.addCleanup(self.admissions.close)
        launch=ExecLaunch(None,ExecSeat('alpha','instance','pi','actor-p','seat-a','b'*64,os.getuid(),os.getgid()),Endpoint(),self.root/'launch')
        launch.state='active';launch.origin=origin;launch.channel=self.handle.channel
        self.operation='a'*32
        send_admit(sender,launch=launch,seat=seat,operation_id=self.operation,epoch=1,readiness_digest='c'*64)
        self.admissions.admit(control)
        connection=self.hub.connect('capture-attach','pi',launch.incarnation,self.native)
        self.dispatcher=AdmittedPeerDispatcher(self.admissions,self.hub)
        self.dispatcher.attach(self.operation,connection);self.dispatcher.attach_library(self.owner)

    def invoke(self,request='request-1',capture=None,receive_reply=True):
        value={'request_id':request,'capture':capture or support.value(title='Exact_title',body='Exact explicit body\n')}
        self.native.rpc('prompt',message='/fixture-library-tools '+native_tests.encoded([value]))
        start=len(self.native.event_snapshot())
        self.native.rpc('prompt',message='Perform the explicit capture fixture call.')
        if receive_reply:
            self.assertTrue(select.select([self.handle.channel],[],[],10)[0], 'native Pi capture channel was not ready')
            self.dispatcher.receive(self.operation)
        self.idle()
        results=[e for e in self.native.event_snapshot()[start:] if e.get('type')=='tool_execution_end']
        self.assertEqual(len(results),1,results)
        return results[0]['result']['details']

    def test_actual_capture_exact_payload_distinct_ids_and_retry_no_duplicate(self):
        self.start();payload=dict(support.value(title='Exact_title',body='**Exact** explicit body\n'),hints=['hint'])
        one=self.invoke(capture=payload);self.assertEqual(one['outcome'],'DURABLY_QUEUED')
        self.assertEqual(self.observed[0]['value'],payload)
        two=self.invoke(capture=payload)
        self.assertNotEqual(one['command_id'],two['command_id'])
        self.assertEqual(one['queue_id'],two['queue_id']);self.assertEqual(self.service.count(),2)
        three=self.invoke('request-2',payload)
        self.assertNotEqual(one['queue_id'],three['queue_id']);self.assertEqual(self.service.count(),3)
        self.assertIn('Submission Actor: actor-p',self.service.contents(one['path']))
        changed=self.invoke(capture=support.value(body='changed'))
        self.assertEqual(changed['outcome'],'REJECTED');self.assertEqual(changed['reason'],'ID_CONFLICT')
        self.assertFalse(changed['retryable'])

    def test_uncertain_response_retains_request_new_command_recovers_after_close(self):
        self.start();contact=self.contact
        def lost(**kwargs): contact(**kwargs);raise OSError('PRIVATE_ERROR')
        self.contact=lost
        one=self.invoke();self.assertEqual(one['outcome'],'NOT_DURABLE');self.assertTrue(one['retryable'])
        self.assertEqual(one['request_id'],'request-1');self.assertNotIn('PRIVATE_ERROR',json.dumps(one))
        self.hub.contexts.close_run('close','run-1',FixtureRunTerminal.COMPLETED)
        self.contact=contact
        two=self.invoke();self.assertEqual(two['outcome'],'DURABLY_QUEUED')
        self.assertNotEqual(one['command_id'],two['command_id']);self.assertEqual(self.service.count(),2)

    def test_missing_capability_is_safe_hub_refusal_and_no_content(self):
        self.start(False);result=self.invoke()
        self.assertEqual(result['status'],'HUB_REFUSED');self.assertEqual(result['reason'],'FORBIDDEN')
        self.assertNotIn('outcome',result);self.assertFalse(result['retryable']);self.assertEqual(self.observed,[])

    def test_no_automatic_capture_and_missing_library_does_not_gate_run(self):
        self.start();self.dispatcher.library=None
        self.native.rpc('prompt',message='Ordinary work mentioning valuable knowledge.');self.idle()
        self.assertFalse(select.select([self.handle.channel],[],[],.05)[0]);self.assertEqual(self.observed,[])
        result=self.invoke();self.assertEqual(result['status'],'HUB_REFUSED')
        self.assertEqual(result['reason'],'LIBRARY_UNAVAILABLE');self.assertNotIn('outcome',result)
        self.hub.contexts.close_run('ordinary-completion','run-1',FixtureRunTerminal.COMPLETED)
        self.native.rpc('prompt',message='Continue ordinary work.');self.idle()
        self.assertEqual(self.observed,[])

    def test_large_configured_capture_authenticated_framing_preserves_payload(self):
        self.start()
        payload=support.value(body='A'*70000)
        result=self.invoke(capture=payload)
        self.assertEqual(result['outcome'],'DURABLY_QUEUED',result)
        self.assertEqual(self.observed[0]['value'],payload)

    def test_lost_hub_channel_has_no_librarian_outcome_and_pi_still_finishes(self):
        self.start();self.handle.channel.shutdown(socket.SHUT_RDWR)
        result=self.invoke(receive_reply=False)
        self.assertEqual(result['status'],'TRANSPORT_UNAVAILABLE');self.assertNotIn('outcome',result)
        self.assertEqual(result['request_id'],'request-1');self.assertTrue(result['retryable'])
        self.assertEqual(self.observed,[])
        self.native.rpc('prompt',message='Ordinary work after unavailable capture.');self.idle()
