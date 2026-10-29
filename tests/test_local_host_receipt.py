import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.local_host_profile import HostProfileError
from uas.local_host_receipt import PreparationReceipt, HostReceiptUncertain
from tests.test_local_host_plan import selected


class PreparationReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.plan = selected()
        self.evidence = {'identity': [3, 44], 'observed_sha256': 'c'*64}

    def open(self):
        return PreparationReceipt(self.root, self.plan, owner_uid=os.getuid())

    def test_resume_never_reauthorizes_unknown_effect(self):
        with self.open() as receipt:
            self.assertEqual(receipt.state(0), {'state': 'not-started'})
            self.assertTrue(receipt.intent(0))
        with self.open() as receipt:
            self.assertEqual(receipt.state(0), {'state': 'unknown'})
            self.assertFalse(receipt.intent(0))
            with self.assertRaisesRegex(HostProfileError, 'PREVIOUS_UNKNOWN'): receipt.intent(1)
            receipt.confirm(0, self.evidence)
            self.assertTrue(receipt.intent(1))
        with self.open() as receipt:
            self.assertEqual(receipt.state(0), {'state':'confirmed', 'evidence':self.evidence})
            self.assertFalse(receipt.intent(0))
            self.assertEqual(receipt.state(1), {'state':'unknown'})

    def test_conflict_never_overwrites(self):
        with self.open() as receipt:
            receipt.intent(0); receipt.confirm(0, self.evidence)
            before = (self.root/'0.confirmed.json').read_bytes()
            with self.assertRaisesRegex(HostProfileError, 'CONFLICT'):
                receipt.confirm(0, dict(self.evidence, identity=[3, 45]))
            self.assertEqual((self.root/'0.confirmed.json').read_bytes(), before)

    def test_no_confirmation_without_intent(self):
        with self.open() as receipt:
            with self.assertRaisesRegex(HostProfileError, 'INTENT_REQUIRED'): receipt.confirm(0, self.evidence)

    def test_uncertain_receipt_requires_reopen_reconciliation(self):
        with self.open() as receipt:
            with patch('os.fsync', side_effect=OSError('lost acknowledgement')):
                with self.assertRaises(HostReceiptUncertain): receipt.intent(0)
            with self.assertRaisesRegex(HostProfileError, 'UNAVAILABLE'): receipt.state(0)
        with self.open() as receipt:
            self.assertFalse(receipt.intent(0))
            self.assertEqual(receipt.state(0), {'state':'unknown'})

    def test_foreign_file_and_symlink_preserved(self):
        foreign = self.root/'human.txt'; foreign.write_text('keep')
        with self.open() as receipt:
            (self.root/'0.intent.json').symlink_to(foreign)
            with self.assertRaises(OSError): receipt.intent(0)
        self.assertEqual(foreign.read_text(), 'keep')

    def test_no_arbitrary_evidence_content(self):
        with self.open() as receipt:
            receipt.intent(0)
            with self.assertRaisesRegex(HostProfileError, 'EVIDENCE'):
                receipt.confirm(0, dict(self.evidence, token='not persisted'))
        self.assertNotIn('not persisted', ''.join(p.read_text() for p in self.root.iterdir()))

    def test_two_owners_only_first_intent_is_actionable(self):
        with self.open() as first, self.open() as second:
            self.assertTrue(first.intent(0))
            self.assertFalse(second.intent(0))

    def test_directory_permissions_and_replacement(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(HostProfileError, 'DIRECTORY'): self.open()
        self.root.chmod(0o700)
        with self.open() as receipt:
            self.root.chmod(0o755)
            with self.assertRaisesRegex(HostProfileError, 'DIRECTORY_CHANGED'): receipt.intent(0)


if __name__ == '__main__': unittest.main()
