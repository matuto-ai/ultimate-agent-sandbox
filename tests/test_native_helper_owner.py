from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch
import json, unittest
import test_run_review as fixture
from test_native_helper_admission import HelperAdmissionTests
from uas import workstation_admission as admission, workstation_peer as transport
from uas.kernel_origin import ReceiverIdentity

class CombinedSeamTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.RunReviewTests('test_submission_uses_real_peer_outbox_and_exact_retry'); self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.live=patch.object(admission,'alive',return_value=True);self.live.start();self.addCleanup(self.live.stop)
        self.hub,self.offer=HelperAdmissionTests().make()
        root,binding=self.hub._active['a'*32]
        seat=admission.AdmissionSeat('room','instance','builder-seat','builder','profile',('peer-traffic','implement'),ReceiverIdentity(1000,1000,'hub','0'*64))
        self.binding=replace(binding,seat=seat)
        self.hub._active['a'*32]=(root,self.binding)
        self.hub.seats={'builder-seat':seat}
        self.offer.origin.require=lambda r: self.assertEqual(r.identity,(5,6))
        self.hub._admit_helper(self.offer)
        self.dispatcher=transport.AdmittedPeerDispatcher(self.hub,self.f.peer)
        connection=self.f.peer.connect('native-builder','builder-seat',self.binding.incarnation,object())
        self.dispatcher.attach('a'*32,connection)
        self.dispatcher.reviews=self.f.owner
        self.envelope={'id':'native-submit','kind':'submit-for-review','run_id':'run','generation':1,'payload':{'target':deepcopy(fixture.TARGET),'evidence':['evidence:tests']}}
    def send(self,envelope):
        record=SimpleNamespace(identity=(5,6),data=json.dumps({'request_id':'1'*32,'envelope':envelope}).encode())
        @contextmanager
        def receive(channel):
            self.assertIs(channel,self.offer.channel);yield record
        with patch.object(transport,'receive',receive):
            return self.dispatcher.receive_helper('f'*32)
    def test_actual_helper_dispatch_review_ledger_replay_and_revocation(self):
        first=self.send(self.envelope)
        self.assertTrue(first['ok'],first)
        self.assertEqual(first['receipt']['stage'],'REVIEWING')
        traffic=deepcopy(self.f.state()['peer_traffic'])
        self.assertEqual(self.send(self.envelope),first)
        self.assertEqual(self.f.state()['peer_traffic'],traffic)
        self.assertEqual(len(self.f.broker.calls),1)
        stored=self.f.state()['run_reviews']['run']['current']
        self.assertEqual(stored['target']['head_sha'],'a'*40)
        self.hub._active['a'*32][0].origin.revoke()
        before=self.f.state()
        # Revoked lease rejects before decoding or performing any new transition.
        with self.assertRaises(admission.OriginDenied):self.send({**self.envelope,'id':'forbidden-next'})
        self.assertEqual(self.f.state(),before)
    def test_helper_submission_then_real_owner_unknown_reconciliation(self):
        self.assertTrue(self.send(self.envelope)['ok'])
        self.f.result(submission='native-submit')
        self.f.broker.comment_status='unknown'
        args=dict(human=fixture.HUMAN,authorize=lambda:True,admission_operation='human-admission')
        payload={'submission_id':'native-submit','target':deepcopy(fixture.TARGET),'body':'Controlled human return'}
        first=self.f.owner.request_changes('native-return','run',1,payload,**args)
        self.assertEqual(first['status'],'unknown')
        self.assertEqual(self.f.owner.request_changes('native-return','run',1,payload,**args),first)
        self.f.broker.comment_status='confirmed'
        result=self.f.owner.reconcile_changes('native-return',reconciliation_id='native-read',**args)
        self.assertEqual(result['status'],'confirmed')
        self.assertEqual(len([c for c in self.f.broker.calls if c[0]=='comment']),1)
    def test_helper_authority_cannot_follow_root_epoch_change(self):
        root,binding=self.hub._active['a'*32]
        self.hub._active['a'*32]=(root,replace(binding,epoch=3))
        before=self.f.state()
        with self.assertRaises(admission.OriginDenied):self.send(self.envelope)
        self.assertEqual(self.f.state(),before)
