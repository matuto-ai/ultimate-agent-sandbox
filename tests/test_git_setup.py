"""Pure owned-file setup tests: never invokes Git, mounts or a kernel endpoint."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uas.git_setup import GitPrimarySetup
from uas.ledger import LedgerError


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.gitdir = self.root / 'project.git'; self.gitdir.mkdir()
        self.private = self.root / 'private'; self.private.mkdir(mode=0o700)
        self.fd = os.open(self.gitdir, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        node = os.fstat(self.fd)
        self.identity = (node.st_dev, node.st_ino)
        self.setup = GitPrimarySetup(self.private / 'setup.json', room_id='room', project_id='project')
        self.addCleanup(self.setup.close)
        self.args = {'expected_identity': self.identity, 'project_owner': os.getuid(),
                     'authorize': lambda: True, 'quiescent': lambda: True}

    def prepare(self, **changes): return self.setup.prepare(self.fd, **{**self.args, **changes})

    def test_explicit_absent_marker_creation_exact_retry_no_rewrite(self):
        first = self.prepare()
        self.assertEqual((self.gitdir / 'commondir').read_bytes(), b'.\n')
        self.assertEqual(first['phase'], 'owned')
        self.assertEqual(self.prepare(), first)
        self.assertEqual((self.gitdir / 'commondir').stat().st_mode & 0o777, 0o444)

    def test_existing_human_marker_is_never_adopted_even_identical(self):
        for raw in (b'.\n', b'../../human\n'):
            with self.subTest(raw=raw):
                if (self.gitdir / 'commondir').exists(): (self.gitdir / 'commondir').unlink()
                (self.gitdir / 'commondir').write_bytes(raw)
                if self.setup.journal.exists(): self.setup.journal.unlink()
                self.setup.failed = False
                with self.assertRaisesRegex(LedgerError, 'GIT_SETUP_COLLISION'): self.prepare()
                self.assertEqual((self.gitdir / 'commondir').read_bytes(), raw)
                self.assertEqual(json.loads(self.setup.journal.read_text())['phase'], 'intent')

    def test_symlink_collision_preserves_link_and_target(self):
        target = self.root / 'human'; target.write_text('keep')
        (self.gitdir / 'commondir').symlink_to(target)
        with self.assertRaisesRegex(LedgerError, 'GIT_SETUP_COLLISION'): self.prepare()
        self.assertTrue((self.gitdir / 'commondir').is_symlink())
        self.assertEqual(target.read_text(), 'keep')

    def test_authority_and_quiescence_before_any_write(self):
        for value in (False, None, 1):
            with self.subTest(value=value), self.assertRaises(LedgerError):
                self.prepare(quiescent=lambda: value)
        self.assertFalse(self.setup.journal.exists()); self.assertFalse((self.gitdir / 'commondir').exists())

    def test_wrong_project_identity_or_owner_preserves_everything(self):
        for changes in ({'expected_identity': (0, 0)}, {'project_owner': os.getuid() + 1}):
            with self.assertRaisesRegex(LedgerError, 'GIT_SETUP_PROJECT_MISMATCH'): self.prepare(**changes)
        self.assertEqual(list(self.gitdir.iterdir()), [])

    def test_interrupted_after_creation_never_adopts_on_restart(self):
        original = self.setup._save
        def save(value, **options):
            if not options.get('first'): raise OSError('disk')
            return original(value, **options)
        with patch.object(self.setup, '_save', side_effect=save), self.assertRaises(OSError): self.prepare()
        self.assertEqual((self.gitdir / 'commondir').read_bytes(), b'.\n')
        restarted = GitPrimarySetup(self.setup.journal, room_id='room', project_id='project')
        self.addCleanup(restarted.close)
        with self.assertRaisesRegex(LedgerError, 'GIT_SETUP_INTERRUPTED'):
            restarted.prepare(self.fd, **self.args)
        self.assertEqual((self.gitdir / 'commondir').read_bytes(), b'.\n')

    def test_replaced_owned_marker_never_overwritten(self):
        self.prepare()
        marker = self.gitdir / 'commondir'; marker.unlink(); marker.write_text('human\n')
        with self.assertRaisesRegex(LedgerError, 'GIT_SETUP_MARKER_CHANGED'): self.prepare()
        self.assertEqual(marker.read_text(), 'human\n')

    def test_storage_failure_before_intent_cannot_touch_project(self):
        with patch.object(self.setup, '_save', side_effect=OSError('disk')), self.assertRaises(OSError): self.prepare()
        self.assertFalse((self.gitdir / 'commondir').exists())

    def test_parent_replacement_cannot_adopt_journal(self):
        moved = self.root / 'moved'; self.private.rename(moved); self.private.mkdir(mode=0o700)
        with self.assertRaisesRegex(LedgerError, 'GIT_SETUP_UNAVAILABLE'): self.prepare()
        self.assertFalse((self.gitdir / 'commondir').exists())
