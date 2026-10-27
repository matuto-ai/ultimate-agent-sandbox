"""Pure bounded binary schemas, independent of any kernel/helper claim."""
import struct
import unittest
from uas.artifact_protocol import (ArtifactError, decode_record, decode_observation,
    encode_request, encode_final_ack, expected_header, path_digest, scope_digest,
    validate_path, validate_scope, validate_source, validate_target, MAX_ENTRIES)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.scope={'version':1,'evaluation_id':'evaluation-a','room_id':'room-a','room_instance':'a'*32,
            'project_id':'project-a','repository':'owner/repo','run_id':'run-a','generation':1,
            'participant_id':'alice','policy_id':'policy-a','policy_version':1,'policy_digest':'b'*64,
            'gate_id':'gate-a','config_digest':'c'*64}
        self.target={'target_id':'d'*32,'head_sha':'e'*40,'tree_sha':'f'*40,'manifest_sha256':'a'*64,
            'source_digest':'b'*64,'device':1,'inode':2,'entries':1,'expanded_bytes':10}
        self.paths=['résumé.txt']

    def test_header_and_final_exact_target_roundtrip(self):
        packets=encode_request(self.scope,self.target,self.paths)
        self.assertEqual(104,len(packets[0]));self.assertEqual(2,len(packets))
        for tag,kind in ((b'AGS1','header'),(b'AGF1','final')):
            self.assertEqual(expected_header(self.scope,self.target,self.paths,kind=kind),
                decode_observation(tag+packets[0][4:],self.scope,self.target,self.paths))
        self.assertEqual(b'AGA1'+bytes.fromhex(scope_digest(self.scope,self.target)),encode_final_ack(self.scope,self.target))

    def test_raw_item_has_no_verdict_check_or_contents(self):
        raw=struct.pack('!4sI32sIQII',b'AGI1',0,bytes.fromhex(path_digest(self.paths[0])),1,10,0,0)
        item=decode_observation(raw,self.scope,self.target,self.paths)
        self.assertEqual({'kind','index','path_digest','observed_type','length','nonempty','error'},set(item))
        self.assertEqual('file',item['observed_type']);self.assertEqual(60,len(raw))

    def test_wrong_path_digest_index_target_and_extra_bytes_rejected(self):
        raw=struct.pack('!4sI32sIQII',b'AGI1',0,bytes(32),1,10,0,0)
        with self.assertRaises(ArtifactError):decode_observation(raw,self.scope,self.target,self.paths)
        packet=encode_request(self.scope,self.target,self.paths)[0]
        with self.assertRaises(ArtifactError):decode_record(b'AGS1'+packet[4:]+b'x')
        other=dict(self.target,inode=3)
        with self.assertRaises(ArtifactError):decode_observation(b'AGS1'+packet[4:],self.scope,other,self.paths)

    def test_paths_canonical_utf8_components_total_bytes_and_depth(self):
        for path in ('../escape','a//b','a/.git/b','a/.GiT','/absolute','x\\y','x*','x\x00','x\u0080',
                     '\ud800','é'*128,'/'.join(['x']*33),'a'*1025):
            with self.subTest(path=repr(path)),self.assertRaises(ArtifactError):validate_path(path)
        self.assertEqual('é'*127,validate_path('é'*127).decode())

    def test_empty_duplicate_and_excessive_paths_fail(self):
        for paths in ([],['x','x'],['x'+str(i) for i in range(129)]):
            with self.assertRaises(ArtifactError):encode_request(self.scope,self.target,paths)

    def test_bool_numbers_wrong_hashes_and_extra_fields_fail(self):
        for scope in (dict(self.scope,generation=True),dict(self.scope,version=True),dict(self.scope,extra='x')):
            with self.assertRaises(ArtifactError):validate_scope(scope)
        for target in (dict(self.target,device=True),dict(self.target,head_sha='a'*64),dict(self.target,entries=MAX_ENTRIES+1)):
            with self.assertRaises(ArtifactError):validate_target(target)

    def test_item_fact_invariants_reject_nonfacts(self):
        for kind,length,nonempty,error in ((2,1,0,0),(3,0,1,0),(1,1,0,1),(4,0,0,0),(99,0,0,0)):
            raw=struct.pack('!4sI32sIQII',b'AGI1',0,bytes(32),kind,length,nonempty,error)
            with self.assertRaises(ArtifactError):decode_record(raw)


if __name__ == '__main__':unittest.main()
