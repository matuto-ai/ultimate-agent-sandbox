"""Pure state/packet contracts with inert doubles; no native/socket execution."""
import ast
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uas import native_helper as m
from uas.kernel_origin import OriginDenied

class Lock:
    def __enter__(self): return self
    def __exit__(self,*args): pass

class Channel:
    def __init__(self, queued=None): self.queued=queued; self.sent=[]; self.closed=False
    def recv(self,*args):
        if self.queued is None: raise BlockingIOError()
        return self.queued
    def send(self,data): self.sent.append(data); return len(data)
    def sendmsg(self,data,rights): self.sent.append((data,rights)); return len(data[0])
    def fileno(self): return 10
    def close(self): self.closed=True

class Admission:
    def __init__(self,root):
        self.launch=root; self.controller='c'*32; self._io=Lock(); self._authority=Lock()
        self.control=Channel(); self.hub_origin=SimpleNamespace(require=lambda record:None)
        self.lost=False
    def _current(self): pass
    def control_lost(self): self.lost=True

class NativeHelperTests(unittest.TestCase):
    def make(self):
        lease=object.__new__(m.NativeDescendantLease)
        root=SimpleNamespace(origin=SimpleNamespace(identity=(1,2)),incarnation='i'*32,
            recipe=SimpleNamespace(manifest_digest='d'*64),current=lambda:True,state='active',
            native_readiness={'digest':'x'},admission={'state':'admitted','controller':'c'*32,
            'operation_id':'r'*32,'epoch':3})
        lease.root=root; lease.origin=SimpleNamespace(identity=(4,5),pidfd=20,revoked=False,close=lambda:None)
        lease.channel=Channel(); lease.forge_channel=Channel(); lease.state='released'; lease.operation_id='h'*32
        lease._root_identity=(1,2); lease._root_incarnation=root.incarnation
        lease._manifest_digest='d'*64; lease._lineage=SimpleNamespace(current=lambda:True,close=lambda:None)
        lease._authority=None; lease._document=lease._digest=lease._admission=None
        return lease,Admission(root)
    def test_queue_and_eof_refuse(self):
        for value in (b'call',b''):
            lease,_=self.make(); lease.channel.queued=value
            with self.assertRaises(OriginDenied): lease._empty_channel()
    def test_empty_queue_allowed(self): self.make()[0]._empty_channel()
    def test_transfer_exact_document_and_no_second_send(self):
        lease,admission=self.make()
        with patch.object(m,'NativeClaudeSupervisorAdmission',Admission),patch.object(m,'alive',return_value=True),patch.object(lease,'_receive',return_value={'state':'active'}):
            lease.admit(admission)
            packet=json.loads(admission.control.sent[0][0][0])
            self.assertEqual(set(packet),{'version','kind','operation_id','exchange_id','controller',
                'root_operation','root_incarnation','root_epoch','root_identity','helper_identity','helper_payload_digest'})
            self.assertEqual(packet['root_identity'],[1,2]); self.assertEqual(packet['helper_identity'],[4,5])
            self.assertEqual(packet['helper_payload_digest'],'d'*64)
            with self.assertRaises(OriginDenied): lease.admit(admission)
            self.assertEqual(len(admission.control.sent),1)
    def test_root_epoch_change_refuses_status(self):
        lease,admission=self.make()
        with patch.object(m,'NativeClaudeSupervisorAdmission',Admission),patch.object(m,'alive',return_value=True),patch.object(lease,'_receive',return_value={'state':'active'}):
            lease.admit(admission)
            lease.root.admission['epoch']=4
            with self.assertRaises(OriginDenied): lease.status()
            self.assertEqual(len(admission.control.sent),1)
    def test_partial_transfer_becomes_unknown(self):
        lease,admission=self.make(); admission.control.sendmsg=lambda *args:0
        with patch.object(m,'NativeClaudeSupervisorAdmission',Admission),patch.object(m,'alive',return_value=True):
            with self.assertRaises(OriginDenied): lease.admit(admission)
            self.assertEqual(lease.state,'unknown')
            with self.assertRaises(OriginDenied): lease.admit(admission)
    def test_provisional_cannot_transfer(self):
        for state,proof,ack in [('released',None,'admitted'),('active',None,'admitted'),('active',{},'unknown')]:
            lease,admission=self.make(); lease.root.state=state; lease.root.native_readiness=proof
            lease.root.admission['state']=ack
            with patch.object(m,'NativeClaudeSupervisorAdmission',Admission),patch.object(m,'alive',return_value=True):
                with self.assertRaises(OriginDenied): lease.admit(admission)
            self.assertFalse(admission.control.sent)
    def test_changed_root_or_manifest_refuses(self):
        for attr,value in [('incarnation','changed'),('origin',None),('origin',SimpleNamespace(identity=(9,9))),('recipe',SimpleNamespace(manifest_digest='e'*64))]:
            lease,_=self.make(); setattr(lease.root,attr,value)
            with patch.object(m,'alive',return_value=True):
                with self.assertRaises(OriginDenied): lease.current()
    def test_cleanup_fences_possible_transferred_authority(self):
        lease,admission=self.make(); lease._admission=admission; lease.state='unknown'
        lease.close(); self.assertTrue(admission.lost); self.assertEqual(lease.state,'revoked')
    def reply(self,lease,admission,**changes):
        body={'version':1,'kind':'REPLY','operation_id':lease.operation_id,
            'controller':admission.controller,'exchange_id':'e'*32,
            'result':{'state':'active','helper_digest':lease._digest},**changes}
        class Context:
            def __enter__(self): return SimpleNamespace(data=json.dumps(body).encode())
            def __exit__(self,*args): pass
        return Context()
    def test_authenticated_matching_receipt_closes_local_channel(self):
        lease,admission=self.make(); lease._admission=admission; lease._digest='f'*64; lease.state='unknown'
        channel=lease.channel
        with patch.object(m,'NativeClaudeSupervisorAdmission',Admission),patch.object(m,'alive',return_value=True),patch.object(m,'receive',return_value=self.reply(lease,admission)):
            self.assertEqual(lease._receive('e'*32)['state'],'active')
        self.assertEqual(lease.state,'admitted'); self.assertTrue(channel.closed)
    def test_mismatched_receipt_fences_controller(self):
        lease,admission=self.make(); lease._admission=admission; lease._digest='f'*64; lease.state='unknown'
        with patch.object(m,'NativeClaudeSupervisorAdmission',Admission),patch.object(m,'alive',return_value=True),patch.object(m,'receive',return_value=self.reply(lease,admission,operation_id='wrong')):
            with self.assertRaises(OriginDenied): lease._receive('e'*32)
        self.assertTrue(admission.lost); self.assertEqual(lease.state,'revoked')
    def test_timeout_preserves_identity_for_status_not_resend(self):
        lease,admission=self.make(); lease._admission=admission; lease.state='intent'
        with patch.object(m,'receive',side_effect=TimeoutError):
            with self.assertRaises(TimeoutError): lease._receive('e'*32)
        self.assertEqual(lease.state,'unknown'); self.assertFalse(admission.lost)
        self.assertEqual(lease.operation_id,'h'*32)
    def test_uncertain_revoke_fences_controller(self):
        lease,admission=self.make(); lease._admission=admission; lease.state='admitted'
        with patch.object(m,'NativeClaudeSupervisorAdmission',Admission),patch.object(m,'alive',return_value=True),patch.object(lease,'_receive',side_effect=TimeoutError):
            with self.assertRaises(TimeoutError): lease.revoke()
        self.assertTrue(admission.lost); self.assertEqual(lease.state,'revoked')
        self.assertEqual(json.loads(admission.control.sent[0])['kind'],'REVOKE_NATIVE_HELPER')
    def test_source_retains_immediate_lineage_and_exact_types(self):
        source=Path(m.__file__).read_text(); ast.parse(source)
        self.assertIn('len(self._lineage.tasks) != 2',source)
        self.assertIn('self._lineage.require(record)',source)
        self.assertIn('type(root) is not NativeClaudeRoot',source)
        self.assertNotIn('pidfd_open(',source)
        self.assertNotIn('ProcView(',source)

if __name__=='__main__': unittest.main()
