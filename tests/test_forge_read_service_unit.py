"""Pure file/config checks; no sockets, locks, child or kernel probes execute."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.forge_read_service import ReadOwner
from uas.ledger import LedgerError


class ReadOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_exact_private_scope_lock_retained_until_owner_exit(self):
        with patch('fcntl.flock') as lock:
            owner=ReadOwner(self.root/'audit.db','room','instance')
            with owner:
                fd=owner.fd
                self.assertFalse(os.get_inheritable(fd))
                self.assertEqual(0o600,owner.path.stat().st_mode & 0o777)
                lock.assert_called_once()
                self.assertEqual(fd,lock.call_args.args[0])
            self.assertEqual(-1,owner.fd)
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertEqual(owner.path,ReadOwner(self.root/'audit.db','room','instance').path)
        self.assertNotEqual(owner.path,ReadOwner(self.root/'audit.db','room','new-instance').path)

    def test_concurrent_or_unsafe_owner_refuses_and_closes_without_recovery(self):
        owner=ReadOwner(self.root/'audit.db','room','instance')
        with patch('fcntl.flock',side_effect=BlockingIOError()):
            with self.assertRaisesRegex(LedgerError,'BROKER_OWNER_UNAVAILABLE'):owner.__enter__()
        self.assertEqual(-1,owner.fd)
        owner.path.chmod(0o666)
        with patch('fcntl.flock') as lock:
            with self.assertRaisesRegex(LedgerError,'BROKER_OWNER_UNAVAILABLE'):owner.__enter__()
            lock.assert_not_called()
        self.assertEqual(-1,owner.fd)
