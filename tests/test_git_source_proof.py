"""Inert source hash/parent proof tests; no native object reads."""
import base64
import unittest
from unittest.mock import patch
from uas.git_provenance import parse_commit
from uas.git_source_proof import build, verify
from uas.ledger import LedgerError


def commit(parent=None, message=b'root'):
    raw = (b'tree ' + b'1' * 40 + b'\n' + (b'parent ' + parent.encode() + b'\n' if parent else b'')
        + b'author A <a@example.test> 1 +0000\ncommitter A <a@example.test> 1 +0000\n\n' + message + b'\n')
    return parse_commit(raw).oid, raw


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.source, source = commit()
        self.middle, middle = commit(self.source, b'middle')
        self.tip, tip = commit(self.middle, b'tip')
        self.objects = {self.source: source, self.middle: middle, self.tip: tip}

    def test_historical_reachable_positive(self):
        proof = build(self.source, [self.tip], self.objects.get)
        self.assertEqual(verify(proof, source_oid=self.source, tips=[self.tip]), self.objects[self.source])
        self.assertEqual(len(proof['commits']), 3)

    def test_exact_advertised_tip(self):
        proof = build(self.tip, [self.tip], self.objects.get)
        self.assertEqual(len(proof['commits']), 1)
        verify(proof, source_oid=self.tip, tips=[self.tip])

    def test_unrelated_or_missing_refuses(self):
        other, raw = commit(message=b'other'); self.objects[other] = raw
        with self.assertRaisesRegex(LedgerError, 'GIT_SOURCE_UNANCHORED'):
            build(other, [self.tip], self.objects.get)
        with self.assertRaises(LedgerError): build(self.source, ['a' * 40], self.objects.get)

    def test_mutable_object_different_bytes_not_authority(self):
        self.objects[self.middle] = self.objects[self.source]
        with self.assertRaisesRegex(LedgerError, 'GIT_SOURCE_PROOF_MISMATCH'):
            build(self.source, [self.tip], self.objects.get)

    def test_external_verifier_rejects_omitted_link_and_wrong_tip(self):
        proof = build(self.source, [self.tip], self.objects.get)
        for changed in ({**proof, 'commits': [proof['commits'][0], proof['commits'][2]]},
                        {**proof, 'tip_oid': self.middle}, {**proof, 'source_oid': self.tip}):
            with self.subTest(changed=changed), self.assertRaises(LedgerError):
                verify(changed, source_oid=self.source, tips=[self.tip])

    def test_node_and_byte_bound(self):
        with patch('uas.git_source_proof.MAX_NODES', 2), self.assertRaisesRegex(LedgerError, 'GIT_SOURCE_PROOF_BOUND'):
            build(self.source, [self.tip], self.objects.get)
        with patch('uas.git_source_proof.MAX_RAW_BYTES', 4), self.assertRaisesRegex(LedgerError, 'GIT_SOURCE_PROOF_BOUND'):
            build(self.source, [self.tip], self.objects.get)

    def test_post_observation_deadline_no_reset(self):
        clock = [0]
        def read(oid):
            clock[0] = 6
            return self.objects[oid]
        with patch('uas.git_source_proof.time.monotonic', side_effect=lambda: clock[0]), self.assertRaisesRegex(LedgerError, 'GIT_SOURCE_PROOF_BOUND'):
            build(self.tip, [self.tip], read)

    def test_authority_revoked_and_noncanonical_encoding(self):
        with self.assertRaises(LedgerError): build(self.source, [self.tip], self.objects.get, current=lambda: False)
        proof = build(self.source, [self.tip], self.objects.get)
        proof['commits'][0] += '\n'
        with self.assertRaises(LedgerError): verify(proof, source_oid=self.source, tips=[self.tip])
