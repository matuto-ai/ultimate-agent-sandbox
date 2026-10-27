"""Pure framing/authority checks; no sockets, processes or kernel probes."""
import base64
from contextlib import contextmanager, nullcontext
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from uas.participant import FixtureParticipantController
from uas.ledger import LedgerError


class MutationFrameTests(unittest.TestCase):
    def setUp(self):
        self.controller=object.__new__(FixtureParticipantController)
        self.controller.supervisor=SimpleNamespace(_locked=nullcontext)
        self.controller._authority=Mock(return_value=True)
        self.handle=SimpleNamespace(protocol='pi',channel=object())
        self.credentials=(123,1000,1000)

    def frames(self,body='x'*524288,kind='forge-write'):
        packet={'request_id':'a'*32,'envelope':{'id':'op','kind':kind,
            'argv':['issue','comment','1','--body-file','-'],'body':body}}
        raw=json.dumps(packet,separators=(',',':')).encode();count=(len(raw)+39999)//40000
        return [json.dumps({'request_id':'a'*32,'index':index,'count':count,
            'sha256':hashlib.sha256(raw).hexdigest(),'data':base64.b64encode(raw[index*40000:(index+1)*40000]).decode()}).encode()
            for index in range(count)],raw

    def assemble(self,frames):
        self.controller._record=Mock(side_effect=[(x,self.credentials) for x in frames[1:]])
        with patch('uas.participant.select.select',return_value=([self.handle.channel],[],[])):
            return self.controller._forge_packet(self.handle,frames[0],self.credentials)

    def test_read_only_external_owner_retains_explicit_legacy_write_dispatch(self):
        self.controller.read_service=SimpleNamespace(write_enabled=False)
        self.assertTrue(self.controller._external_forge({'kind':'forge-read'}))
        self.assertFalse(self.controller._external_forge({'kind':'forge-write'}))
        self.controller.read_service.write_enabled=True
        self.assertTrue(self.controller._external_forge({'kind':'forge-write'}))
        self.assertTrue(self.controller._external_forge({'kind':'forge-reconcile'}))
        self.assertFalse(self.controller._external_forge({'kind':'forge-projection'}))
        self.assertFalse(self.controller._external_forge({'kind':'message'}))
        self.controller.read_service=None
        self.assertFalse(self.controller._external_forge({'kind':'forge-write'}))

    def test_full_512k_body_each_record_authenticated_and_no_identity_fields(self):
        frames,raw=self.frames()
        data,credentials=self.assemble(frames)
        self.assertEqual(raw,data);self.assertEqual(self.credentials,credentials)
        self.assertEqual(len(frames),self.controller._authority.call_count)
        self.assertNotIn('actor_id',json.loads(data)['envelope'])

    def test_full_escaped_body_uses_request_bound_not_output_bound(self):
        from uas.forge_wire import request_json,MAX_REQUEST
        for char in ('"','\\','\n'):
            frames,raw=self.frames(body=char*524288)
            self.assertGreater(len(raw),1048576)
            self.assertLess(len(raw),MAX_REQUEST)
            self.assertEqual(raw,self.assemble(frames)[0])
            self.assertEqual(json.loads(raw),json.loads(request_json(json.loads(raw))))

    def test_reconciliation_uses_authenticated_large_body_channel_but_projection_does_not(self):
        frames,raw=self.frames(kind='forge-reconcile')
        self.assertEqual(raw,self.assemble(frames)[0])
        frames,_=self.frames(kind='forge-projection')
        with self.assertRaisesRegex(LedgerError,'INVALID_NATIVE_FRAME'):self.assemble(frames)

    def test_changed_process_mid_body_never_assembles(self):
        frames,_=self.frames()
        self.controller._authority.side_effect=[True,LedgerError('WRONG_PROCESS')]
        with self.assertRaisesRegex(LedgerError,'WRONG_PROCESS'):self.assemble(frames)
        self.assertEqual(1,self.controller._record.call_count)

    def test_truncated_changed_digest_or_nonwrite_chunks_are_denied(self):
        frames,_=self.frames()
        modified=list(frames);part=json.loads(modified[1]);part['sha256']='0'*64;modified[1]=json.dumps(part).encode()
        with self.assertRaisesRegex(LedgerError,'INVALID_NATIVE_FRAME'):self.assemble(modified)
        frames,_=self.frames(kind='message')
        with self.assertRaisesRegex(LedgerError,'INVALID_NATIVE_FRAME'):self.assemble(frames)
        frames,_=self.frames()
        self.controller._record=Mock()
        with patch('uas.participant.select.select',return_value=([],[],[])),self.assertRaisesRegex(LedgerError,'INVALID_NATIVE_FRAME'):
            self.controller._forge_packet(self.handle,frames[0],self.credentials)
        self.controller._record.assert_not_called()

    def test_ordinary_small_packet_preserves_legacy_protocol(self):
        raw=b'{"kind":"message"}'
        self.assertEqual((raw,self.credentials),self.controller._forge_packet(self.handle,raw,self.credentials))

    def test_non_pi_packet_defers_authentication_and_decoding_to_dispatch_lock(self):
        self.handle.protocol='fixture'
        raw=b'{"kind":"message"}'
        with patch.object(self.controller,'_decode_packet') as decode:
            self.assertEqual((raw,self.credentials),self.controller._forge_packet(self.handle,raw,self.credentials))
        self.controller._authority.assert_not_called()
        decode.assert_not_called()


class ReceiveAuthorityBoundaryTests(unittest.TestCase):
    """Mocked receive only: preserve native transaction semantics without I/O."""
    def setUp(self):
        self.controller=object.__new__(FixtureParticipantController)
        self.locked=False
        self.lock_entries=0
        self.before_lock=None
        self.in_transaction=False
        self.authority_states=[]
        self.fail_at=None
        self.code='MISSING_ACTOR_CREDENTIAL'
        self.document={'seats':{'alice':{'incarnation_id':'incarnation-1','status':'active','epoch':1}}}
        self.handle=SimpleNamespace(protocol='fixture',channel=Mock(),connection=object(),
            badge=SimpleNamespace(participant_id='alice',incarnation_id='incarnation-1',epoch=1,origin=lambda:object()))
        self.controller.handles={'alice':self.handle}
        self.controller.supervisor=SimpleNamespace(_locked=self.lock)
        self.controller.read_service=None
        self.controller.forge_broker=None
        self.controller._record=Mock(return_value=(b'{"kind":"message"}',(123,1000,1000)))
        self.controller._authority=Mock(side_effect=self.authorize)
        self.controller._read=Mock(return_value=self.document)
        self.controller._fence=Mock(side_effect=self.fence)
        self.controller.hub=SimpleNamespace(submit=Mock(side_effect=self.submit))

    @contextmanager
    def lock(self):
        self.assertFalse(self.locked)
        self.lock_entries+=1
        if self.before_lock is not None: self.before_lock(self.lock_entries)
        self.locked=True
        try: yield
        finally: self.locked=False

    def authorize(self,*_):
        self.assertTrue(self.locked)
        self.authority_states.append(self.in_transaction)
        if len(self.authority_states)==self.fail_at:
            raise LedgerError(self.code)
        return True

    def submit(self,*_,authorize,**__):
        self.assertTrue(self.locked)
        self.in_transaction=True
        try:
            authorize()
            return {'status':'accepted'}
        finally:
            self.in_transaction=False

    def fence(self,*_):
        self.assertTrue(self.locked)
        self.assertFalse(self.in_transaction)

    def test_legacy_admission_and_fresh_transaction_authority_are_unchanged(self):
        self.assertTrue(self.controller.receive(self.handle)['ok'])
        self.assertEqual([False,True],self.authority_states)
        self.controller._fence.assert_not_called()

    def test_initial_credential_loss_fences_without_dispatch(self):
        self.fail_at=1
        self.assertEqual(self.code,self.controller.receive(self.handle)['error'])
        self.controller.hub.submit.assert_not_called()
        self.assertEqual('disabled',self.controller._fence.call_args.args[2])

    def test_fresh_credential_or_exit_race_fences_only_after_rollback(self):
        for code,status in [('MISSING_ACTOR_CREDENTIAL','disabled'),('PROCESS_EXITED','exited')]:
            with self.subTest(code=code):
                self.code=code;self.fail_at=2;self.authority_states=[]
                self.controller._fence.reset_mock()
                self.assertEqual(code,self.controller.receive(self.handle)['error'])
                self.assertEqual([False,True],self.authority_states)
                self.assertFalse(self.in_transaction)
                self.assertEqual(status,self.controller._fence.call_args.args[2])

    def test_initial_and_mid_chunk_authority_loss_fence_pi_incarnation(self):
        frame_case=MutationFrameTests();frame_case.setUp()
        frames,_=frame_case.frames()
        self.handle.protocol='pi'
        for fail_at in (1,2):
            with self.subTest(fail_at=fail_at):
                self.fail_at=fail_at;self.authority_states=[]
                self.controller._fence.reset_mock()
                self.controller._record.side_effect=[(frame,(123,1000,1000)) for frame in frames]
                with patch('uas.participant.select.select',return_value=([self.handle.channel],[],[])):
                    self.assertEqual(self.code,self.controller.receive(self.handle)['error'])
                self.assertEqual([False]*fail_at,self.authority_states)
                self.assertEqual('disabled',self.controller._fence.call_args.args[2])
                self.controller.hub.submit.assert_not_called()

    def test_authority_failure_cannot_fence_replacement_incarnation(self):
        self.fail_at=1
        self.document['seats']['alice']['incarnation_id']='replacement'
        self.assertEqual(self.code,self.controller.receive(self.handle)['error'])
        self.controller._fence.assert_not_called()

    def test_delayed_authority_fence_preserves_close_revoke_and_changed_epoch(self):
        for status,epoch in [('closed',2),('revoked',2),('active',2)]:
            with self.subTest(status=status,epoch=epoch):
                self.fail_at=1;self.authority_states=[];self.lock_entries=0
                record=self.document['seats']['alice']
                record.update(status='active',epoch=1)
                self.controller._fence.reset_mock()
                def interleave(entry):
                    if entry==2: record.update(status=status,epoch=epoch)
                self.before_lock=interleave
                self.assertEqual(self.code,self.controller.receive(self.handle)['error'])
                self.assertEqual(2,self.lock_entries)
                self.assertEqual((status,epoch),(record['status'],record['epoch']))
                self.controller._fence.assert_not_called()
