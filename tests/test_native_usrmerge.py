"""Pure fresh-root usrmerge seeding; package execution is always mocked."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('usrmerge_rootfs', Path(__file__).parent / 'vm/native_rootfs.py')
rootfs = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(rootfs)


class NativeUsrmergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / 'root'; self.root.mkdir()

    def test_empty_root_seed_is_relative_minimal_and_valid(self):
        rootfs.seed_usrmerge(self.root)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['bin', 'lib', 'lib64', 'sbin', 'usr'])
        expected = {'bin': 'usr/bin', 'sbin': 'usr/sbin', 'lib': 'usr/lib',
                    'lib64': 'usr/lib64', 'usr/sbin': 'bin', 'usr/local/sbin': 'bin'}
        for name, target in expected.items():
            self.assertEqual(os.readlink(self.root / name), target)
            self.assertTrue((self.root / name).resolve().is_relative_to(self.root))
        for name in ('usr', 'usr/bin', 'usr/lib', 'usr/lib64', 'usr/local', 'usr/local/bin'):
            self.assertTrue(stat.S_ISDIR((self.root / name).lstat().st_mode))
        self.assertEqual(os.readlink(self.root / 'lib64'), 'usr/lib64')
        self.assertTrue(stat.S_ISDIR((self.root / 'usr/lib64').lstat().st_mode))
        rootfs.require_usrmerge(self.root)

    def test_existing_file_directory_or_link_refused_unchanged(self):
        for kind in ('file', 'directory', 'link'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                root = Path(temporary); existing = root / 'lib64'
                if kind == 'file': existing.write_bytes(b'preserve')
                elif kind == 'directory': existing.mkdir(); (existing / 'preserve').touch()
                else: existing.symlink_to('absent')
                before = existing.lstat()
                with self.assertRaises(ValueError): rootfs.seed_usrmerge(root)
                self.assertEqual(list(root.iterdir()), [existing])
                self.assertEqual(existing.lstat(), before)
                if kind == 'file': self.assertEqual(existing.read_bytes(), b'preserve')
                if kind == 'link': self.assertEqual(os.readlink(existing), 'absent')
                if kind == 'directory': self.assertTrue((existing / 'preserve').exists())

    def test_wrong_owner_and_root_symlink_refused_without_writes(self):
        with patch.object(rootfs.os, 'geteuid', return_value=self.root.stat().st_uid + 1):
            with self.assertRaises(ValueError): rootfs.seed_usrmerge(self.root)
        self.assertEqual(list(self.root.iterdir()), [])
        alias = self.directory / 'alias'; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): rootfs.seed_usrmerge(alias)
        self.assertTrue(alias.is_symlink()); self.assertEqual(list(self.root.iterdir()), [])

    def test_postinstall_malformed_usrmerge_rejected(self):
        for change in ('lib64_directory', 'lib64_wrong_link', 'usr_link', 'usr_lib64_link'):
            with self.subTest(change=change), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                root = Path(temporary); rootfs.seed_usrmerge(root)
                if change.startswith('lib64'):
                    (root / 'lib64').unlink()
                    if change == 'lib64_directory': (root / 'lib64').mkdir()
                    else: (root / 'lib64').symlink_to('/usr/lib64')
                elif change == 'usr_link':
                    (root / 'usr').rename(root / 'elsewhere'); (root / 'usr').symlink_to('elsewhere')
                else:
                    (root / 'usr/lib64').rmdir(); (root / 'usr/lib64').symlink_to('../elsewhere')
                with self.assertRaises(ValueError): rootfs.require_usrmerge(root)

    def test_every_seeded_link_is_required_exactly(self):
        links = {'bin': 'usr/bin', 'sbin': 'usr/sbin', 'lib': 'usr/lib',
                 'lib64': 'usr/lib64', 'usr/sbin': 'bin', 'usr/local/sbin': 'bin'}
        for name, target in links.items():
            for mutation in ('missing', 'absolute', 'directory'):
                with self.subTest(name=name, mutation=mutation), tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                    root = Path(temporary); rootfs.seed_usrmerge(root)
                    link = root / name; link.unlink()
                    if mutation == 'absolute': link.symlink_to('/' + target)
                    elif mutation == 'directory': link.mkdir()
                    with self.assertRaises((ValueError, OSError)): rootfs.require_usrmerge(root)

    def test_build_seeds_before_dnf_and_shape_failure_prevents_runtime(self):
        self.root.rmdir(); events = []
        tools = 'rpm-0:observed-base-version.noarch\ndnf5-0:another-observed-version.x86_64\n'
        def run(*arguments, **kwargs):
            rootfs.require_usrmerge(self.root)
            events.append(arguments[0])
            if arguments[0] == 'rpm': return tools
            self.assertEqual(arguments[0], 'dnf')
            self.assertIn('--setopt=tsflags=noscripts', arguments)
            (self.root / 'lib64').unlink(); (self.root / 'lib64').mkdir()
            return ''
        with patch.object(rootfs, 'guest_guard'), patch.object(rootfs, 'verify_runtime', return_value=('archive', [])), \
             patch.object(rootfs, 'extract_runtime') as extract, patch('builtins.print') as output:
            with self.assertRaisesRegex(ValueError, 'usrmerge shape'):
                rootfs.build_rootfs('a' * 32, {'native_runtime': {}}, self.root, run=run)
            extract.assert_not_called()
            self.assertIn('observed-base-version', output.call_args.args[1])
            self.assertIn('another-observed-version', output.call_args.args[1])
        self.assertEqual(events, ['rpm', 'dnf'])

    def test_diagnostic_queries_installed_tools_and_rejects_oversize_before_dnf(self):
        self.root.rmdir(); commands = []
        def run(*arguments, **kwargs):
            commands.append(arguments)
            return 'é' * 2049
        with patch.object(rootfs, 'guest_guard'), patch.object(rootfs, 'verify_runtime', return_value=('archive', [])), \
             patch.object(rootfs, 'extract_runtime') as extract:
            with self.assertRaisesRegex(ValueError, 'oversized package tool identity'):
                rootfs.build_rootfs('a' * 32, {'native_runtime': {}}, self.root, run=run)
            extract.assert_not_called()
        self.assertEqual(commands, [('rpm', '-q', '--qf',
            '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n', 'rpm', 'rpm-libs', 'dnf5', 'libdnf5')])

    def filesystem_fixture(self):
        rows = ['filesystem\tx86_64']
        for name, target in rootfs.USRMERGE_LINKS.items():
            ghost = name in rootfs.USRMERGE_GHOSTS
            rows.append('/' + name + '\t' + str(0 if ghost else stat.S_IFLNK | 0o777)
                        + '\t' + ('' if ghost else target) + '\t' + ('64' if ghost else '0'))
        pretrans = 'posix.symlink("bin", "/usr/sbin")\nposix.symlink("bin", "/usr/local/sbin")\n'
        return '\n'.join(rows) + '\n', pretrans

    def verify_fixture(self, metadata, pretrans):
        with patch('builtins.print'):
            commands = []
            def run(*args, **kwargs):
                commands.append(args)
                self.assertEqual(args[:4], ('rpm', '--root', str(self.root), '-q'))
                self.assertEqual(args[-1], 'filesystem')
                return pretrans if args[-2] == '%{PRETRANS}' else metadata
            value = rootfs.verify_filesystem_layout(self.root, run=run)
            self.assertEqual(len(commands), 2)
            return value

    def test_signed_header_and_pretrans_verify_ghost_targets_not_header_guess(self):
        rootfs.seed_usrmerge(self.root)
        metadata, pretrans = self.filesystem_fixture()
        metadata = metadata.replace('/usr/sbin\t0\t\t64', '/usr/sbin\t33188\tobserved-not-authoritative\t64')
        value = self.verify_fixture(metadata, pretrans)
        self.assertEqual(value['aliases'], rootfs.USRMERGE_LINKS)
        self.assertEqual(value['observed_ghost_metadata']['usr/sbin'],
                         {'mode': 33188, 'link_target': 'observed-not-authoritative', 'flags': 64})
        self.assertEqual(value['ghost_target_source'], 'installed-signed-package-pretrans-not-executed')
        self.assertEqual(len(value['metadata_sha256']), 64)
        self.assertEqual(len(value['pretrans_sha256']), 64)

    def test_wrong_missing_pretrans_creation_rejected(self):
        rootfs.seed_usrmerge(self.root); metadata, pretrans = self.filesystem_fixture()
        for invalid in ('', pretrans.replace('"bin"', '"sbin"'),
                        pretrans.replace('/usr/sbin', '/other/sbin'), pretrans.splitlines()[0]):
            with self.subTest(pretrans=invalid), self.assertRaises(ValueError):
                self.verify_fixture(metadata, invalid)

    def test_wrong_arch_payload_type_flags_target_duplicate_missing_rejected(self):
        rootfs.seed_usrmerge(self.root); metadata, pretrans = self.filesystem_fixture()
        row = metadata.splitlines()[1]
        invalid = [metadata.replace('x86_64', 'aarch64'),
                   metadata.replace('/bin\t41471', '/bin\t16877'),
                   metadata.replace('/bin\t41471\tusr/bin\t0', '/bin\t41471\tusr/bin\t64'),
                   metadata.replace('\tusr/bin\t', '\telsewhere\t'),
                   metadata + row + '\n', metadata.replace(row + '\n', ''),
                   metadata.replace('/usr/sbin\t0\t\t64', '/usr/sbin\t0\t\t0'),
                   metadata + 'malformed\n']
        for value in invalid:
            with self.subTest(metadata=value), self.assertRaises(ValueError):
                self.verify_fixture(value, pretrans)

    def test_metadata_and_pretrans_byte_bounds(self):
        rootfs.seed_usrmerge(self.root); metadata, pretrans = self.filesystem_fixture()
        for first, second in [('é' * (2 * 1024 * 1024 + 1), pretrans), (metadata, 'é' * 32769)]:
            with self.assertRaisesRegex(ValueError, 'exceeds bound'):
                self.verify_fixture(first, second)

    def test_signed_metadata_cannot_authorize_changed_actual_shape(self):
        rootfs.seed_usrmerge(self.root); metadata, pretrans = self.filesystem_fixture()
        (self.root / 'sbin').unlink(); (self.root / 'sbin').symlink_to('usr/bin')
        with self.assertRaisesRegex(ValueError, 'shape changed: sbin'):
            self.verify_fixture(metadata, pretrans)

    def test_fingerprint_missing_target_reports_originating_link(self):
        rootfs.seed_usrmerge(self.root)
        (self.root / 'usr/bin/broken-tool').symlink_to('../absent/tool')
        with self.assertRaises(FileNotFoundError) as caught:
            rootfs.fingerprint(self.root)
        message = str(caught.exception)
        self.assertIn('"link": "usr/bin/broken-tool"', message)
        self.assertIn('"target": "../absent/tool"', message)
        self.assertIn('"missing": "usr/absent"', message)
        self.assertNotIn(str(self.root), message)
        self.assertLess(len(message), 4096)


if __name__ == '__main__': unittest.main()
