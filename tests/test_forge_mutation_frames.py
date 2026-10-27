"""Pure framing/authority checks; no sockets, processes or kernel probes."""
import base64
from contextlib import nullcontext
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
