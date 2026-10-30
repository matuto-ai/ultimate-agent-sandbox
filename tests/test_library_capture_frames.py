"""Bounded authenticated transient capture framing; no native tool substitution."""
import base64
import hashlib
import json
import unittest
from unittest.mock import patch
import test_library_hub as fixtures

class CaptureFrameTests(fixtures.ServiceFixture,unittest.TestCase):
    setUpClass=fixtures.AuthenticatedHubTests.setUpClass
    setUp=fixtures.AuthenticatedHubTests.setUp

    def frames(self, packet=None):
        packet=packet or {'request_id':'a'*32,'envelope':self.envelope()}
        packet['envelope']['capture']['body']='A'*70000
        raw=json.dumps(packet).encode()
        return [{'kind':'library.enqueue','request_id':'a'*32,'index':i,'count':2,
            'sha256':hashlib.sha256(raw).hexdigest(),'data':base64.b64encode(raw[i*40000:(i+1)*40000]).decode()}
            for i in range(2)]

    def send(self,frames):
        for frame in frames:self.children[0].send(frame)
        return self.dispatcher.receive(self.operations[0])

    def test_invalid_correlation_order_size_digest_and_shape_no_contact(self):
        for mutate in (lambda f:f[1].update(index=0),lambda f:f[1].update(request_id='b'*32),
            lambda f:f[1].update(sha256='b'*64),lambda f:f[1].update(count=3),
            lambda f:f[1].update(kind='message'),lambda f:f[0].update(count=29),
            lambda f:f[0].update(data='!'),lambda f:f[0].update(extra='no')):
            # Each invalid stream owns a fresh fixture: leftover untrusted frames
            # must never be silently treated as a continuation of another attempt.
            frames=self.frames();mutate(frames)
            self.assertFalse(self.send(frames)['ok'])
            self.assertEqual(self.calls,0)
            # Consume refused trailing records, without dispatching any content.
            import select
            channel=self.admissions.peer_channel(self.operations[0])
            from uas.kernel_origin import receive
            while select.select([channel],[],[],0)[0]:
                with receive(channel):pass

    def test_other_operation_cannot_use_library_frame_namespace(self):
        packet={'request_id':'a'*32,'envelope':self.envelope()};packet['envelope']['kind']='message'
        result=self.send(self.frames(packet))
        self.assertFalse(result['ok']);self.assertEqual(self.calls,0)

    def test_incomplete_request_is_bounded_no_content_contact(self):
        self.children[0].send(self.frames()[0])
        with patch('uas.workstation_peer.select.select',return_value=([],[],[])):
            result=self.dispatcher.receive(self.operations[0])
        self.assertFalse(result['ok']);self.assertEqual(self.calls,0)

    def test_valid_large_request_still_applies_service_limits(self):
        result=self.send(self.frames())
        self.assertTrue(result['ok'],result)
        self.assertEqual(result['receipt']['outcome'],'REJECTED')
        self.assertEqual(result['receipt']['reason'],'CAPTURE_TOO_LARGE')
        self.assertEqual(self.calls,1)

    def test_revocation_during_wait_fails_closed_without_escaping(self):
        import select
        original=select.select
        self.children[0].send(self.frames()[0])
        def revoke(*args):
            self.admissions.revoke(self.operations[0])
            return original(*args)
        with patch('uas.workstation_peer.select.select',side_effect=revoke):
            result=self.dispatcher.receive(self.operations[0])
        self.assertFalse(result['ok']);self.assertEqual(self.calls,0)

    def test_second_record_wrong_real_kernel_origin_refused(self):
        from uas.kernel_origin import receive
        from contextlib import contextmanager
        first,second=self.frames()
        self.children[0].send(first);self.children[1].send(second)
        calls=0
        @contextmanager
        def switched(channel):
            nonlocal calls
            calls+=1
            # Controlled transport switch, actual independently held child sender.
            with receive(channel if calls==1 else self.children[1].channel) as record:yield record
        with patch('uas.workstation_peer.receive',side_effect=switched), \
             patch('uas.workstation_peer.select.select',return_value=([self.children[1].channel],[],[])):
            result=self.dispatcher.receive(self.operations[0])
        self.assertFalse(result['ok']);self.assertEqual(self.calls,0)
