"""Pure offline image staging checks. No compiler, native Git, mount or chown."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from uas.git_policy import ROUTES, GitPolicyError, parse_git
from uas.git_transaction import HOOK_SCRIPT

ROOT = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
native = module('git_native_payload', ROOT / 'tests/vm/prepare_native_payload.py')
rootfs = module('git_native_rootfs', ROOT / 'tests/vm/native_rootfs.py')


class GitPayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.image = self.root / 'source', self.root / 'image'
        self.source.mkdir(); (self.image / 'opt/uas/bin').mkdir(parents=True)
        self.base = self.image / 'opt/uas'
        self.calls = []
        def compile_(argv, **options):
            self.calls.append((argv, options))
            Path(argv[argv.index('-o') + 1]).write_bytes(b'not-executed-ELF-fixture')
        self.compile = compile_

    def sources(self):
        shutil.copytree(ROOT / 'uas', self.source / 'uas', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT / 'runtime/git', self.source / 'runtime/git')
        (self.source / 'runtime/workstation').mkdir()
        shutil.copyfile(ROOT / 'runtime/workstation/git_worker_connector.c', self.source / 'runtime/workstation/git_worker_connector.c')

    def test_old_profile_absent_git_assets_unchanged(self):
        self.assertIsNone(native.stage_git(self.source, self.base, self.compile))
        self.assertEqual(self.calls, [])
        self.assertEqual(native.RPM_ROOTS, ('python3', 'tini', 'glibc', 'libstdc++'))

    def test_complete_fixed_manifest_and_no_native_backend_or_credential(self):
        self.sources()
        value = native.stage_git(self.source, self.base, self.compile)
        self.assertEqual(value['version'], 1)
        self.assertEqual(value['entries'], json.loads((ROOT / 'runtime/git/public-entries.json').read_text()))
        self.assertEqual((self.base / 'git-hooks/reference-transaction').read_bytes(), HOOK_SCRIPT)
        self.assertEqual(self.calls[0][0][-1], str(self.source / 'runtime/workstation/git_worker_connector.c'))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(sorted(p.name for p in (self.base / 'bin').iterdir()), ['git', 'git-ssh-shim', 'git-worker-connector'])

    def test_partial_git_asset_selection_rejected(self):
        (self.source / 'runtime/git').mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'complete controlled Git'):
            native.stage_git(self.source, self.base, self.compile)
        self.assertEqual(self.calls, [])

    def test_missing_python_dependency_rejects_before_compiler_or_public_install(self):
        self.sources()
        (self.source / 'uas/git_runtime.py').unlink()
        with self.assertRaisesRegex(ValueError, 'complete controlled Git Python'):
            native.stage_git(self.source, self.base, self.compile)
        self.assertEqual(self.calls, [])
        self.assertFalse((self.base / 'bin/git').exists())

    def test_all_installed_routes_and_helper_bypasses_use_same_launcher(self):
        entries = json.loads((ROOT / 'runtime/git/public-entries.json').read_text())
        self.assertTrue({'git-' + row.command for row in ROUTES} <= set(entries))
        for name in ('git-am', 'git-upload-pack', 'git-receive-pack', 'git-shell', 'git-remote-ext', 'git-credential', 'scalar'):
            with self.subTest(name=name), self.assertRaises(GitPolicyError): parse_git(name, [])

    def test_offline_install_exclusive_entries_and_hook_directory_only(self):
        self.sources(); value = native.stage_git(self.source, self.base, self.compile)
        with patch.object(rootfs.os, 'chown') as chown:
            rootfs.install_git_entries(self.image, value)
        chown.assert_called_once_with(self.base / 'git-hooks', 65530, 65532)
        expected = (self.base / 'bin/git').read_bytes()
        for prefix in ('usr/bin', 'usr/lib/git-core', 'usr/libexec/git-core'):
            for name in value['entries']:
                self.assertEqual((self.image / prefix / name).read_bytes(), expected)
        self.assertEqual((self.base / 'git-hooks').stat().st_mode & 0o777, 0o500)
        self.assertTrue((self.base / 'git-views').is_dir())

    def test_existing_native_or_human_entry_never_overwritten(self):
        self.sources(); value = native.stage_git(self.source, self.base, self.compile)
        (self.image / 'usr/bin').mkdir(parents=True)
        existing = self.image / 'usr/bin/git'; existing.write_bytes(b'preserve')
        with patch.object(rootfs.os, 'chown') as chown, self.assertRaises(FileExistsError):
            rootfs.install_git_entries(self.image, value)
        self.assertEqual(existing.read_bytes(), b'preserve'); chown.assert_not_called()
