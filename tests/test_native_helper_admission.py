"""Pure canonical Hub helper authority transitions; no sockets/processes."""
from types import SimpleNamespace
from unittest.mock import patch
import unittest
from uas import workstation_admission as m

class Lock:
    def __enter__(self): return self
    def __exit__(self,*_): pass

class Origin:
    def __init__(self, identity): self.identity=identity;self.pidfd=identity[1];self.revoked=False;self.closed=False
    def require(self,record):
        if record != self.identity: raise m.OriginDenied('substitution')
    def revoke(self): self.revoked=True
    def close(self): self.closed=True

class Channel:
    def __init__(self): self.sent=[];self.closed=False
    def send(self,data): self.sent.append(data);return len(data)
    def close(self): self.closed=True

class HelperAdmissionTests(unittest.TestCase):
    def make(self):
        hub=object.__new__(m.HubAdmission)
        hub._lock=Lock();hub._authorization=SimpleNamespace(depth=0)
        hub._closed=hub._fenced=False;hub.controller='c'*32
        hub.supervisor=Origin((1,2));hub.endpoint=SimpleNamespace(require=lambda:True)
        root=m._Offer({},Channel(),Origin((3,4)))
        binding=m.AdmittedBinding(None,'a'*32,'b'*32,2,'e'*64,'d'*64)
        hub._active={'a'*32:(root,binding)};hub._helpers={};hub._helper_history={}
        doc={'version':1,'kind':'ADMIT_NATIVE_HELPER','operation_id':'f'*32,'exchange_id':'1'*32,
            'controller':hub.controller,'root_operation':'a'*32,'root_incarnation':'b'*32,
            'root_epoch':2,'root_identity':[3,4],'helper_identity':[5,6],'helper_payload_digest':'d'*64}
        offer=m._HelperOffer(doc,Channel(),Origin((5,6)))
        return hub,offer
    @patch.object(m,'alive',return_value=True)
    def test_install_activation_and_exact_record(self,_):
        hub,offer=self.make();m._validate_helper_document(offer.document)
        receipt=hub._admit_helper(offer)
        self.assertEqual(receipt['state'],'active')
        self.assertEqual(offer.channel.sent,[b'UAS-HELPER-ACTIVE-1\n'])
        with hub.authorize_descendant('f'*32,(5,6)) as binding:
            self.assertEqual(binding.operation_id,'a'*32)
            self.assertTrue(hub.recheck_descendant('f'*32,(5,6)))
            with self.assertRaises(m.OriginDenied):hub.recheck_descendant('f'*32,(3,4))
        with self.assertRaises(m.OriginDenied):hub.recheck_descendant('f'*32,(5,6))
    @patch.object(m,'alive',return_value=True)
    def test_changed_root_epoch_or_payload_blocks(self,_):
        for key,value in [('root_epoch',3),('root_identity',[3,9]),('helper_payload_digest','e'*64),('controller','e'*32)]:
            hub,offer=self.make();offer.document[key]=value
            with self.assertRaises(m.OriginDenied):hub._admit_helper(offer)
            self.assertTrue(offer.channel.closed);self.assertFalse(hub._helpers)
    @patch.object(m,'alive',return_value=True)
    def test_root_revocation_fences_helper(self,_):
        hub,offer=self.make();hub._admit_helper(offer)
        hub._active['a'*32][0].origin.revoke()
        with self.assertRaises(m.OriginDenied):
            with hub.authorize_descendant('f'*32,(5,6)):pass
        self.assertEqual(hub.helper_status('f'*32)['state'],'revoked')
    @patch.object(m,'alive',return_value=True)
    def test_revoke_cannot_restore_from_receipt(self,_):
        hub,offer=self.make();hub._admit_helper(offer);hub.revoke_helper('f'*32)
        self.assertTrue(offer.origin.closed)
        self.assertEqual(hub.helper_status('f'*32)['state'],'revoked')
        with self.assertRaises(m.OriginDenied):hub._admit_helper(offer)
    @patch.object(m,'alive',return_value=True)
    def test_capacity_and_ordinary_root_reject(self,_):
        hub,offer=self.make();hub._helper_history={str(i):'x' for i in range(128)}
        with self.assertRaises(m.OriginDenied):hub._admit_helper(offer)
        hub,offer=self.make();root,b=hub._active['a'*32]
        hub._active['a'*32]=(root,m.AdmittedBinding(None,b.operation_id,b.incarnation,b.epoch,b.readiness_digest))
        with self.assertRaises(m.OriginDenied):hub._admit_helper(offer)

    def test_native_live_host_dead_revokes_effects(self):
        hub,offer=self.make()
        root,_=hub._active['a'*32]; root.host_origin=Origin((8,9))
        with patch.object(m,'alive',return_value=True):hub._admit_helper(offer)
        with patch.object(m,'alive',side_effect=lambda fd:fd!=9):
            with self.assertRaises(m.OriginDenied):
                with hub.authorize_descendant('f'*32,(5,6)):pass
            self.assertEqual(hub.helper_status('f'*32)['state'],'revoked')
