"""Pure native staging contracts: no download, native runtime or VM launch."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('native_payload', Path(__file__).parent / 'vm/prepare_native_payload.py')
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class NativePayloadTests(unittest.TestCase):
    def test_reviewed_lock_and_rejects_foreign_or_mutable_dependencies(self):
        root = Path(__file__).parent / 'pi'
        package = json.loads((root / 'package.json').read_text())
        lock = json.loads((root / 'package-lock.json').read_text())
        native.validate_lock(package, lock)
        key = next(key for key in lock['packages'] if key)
        for field, value in [('resolved', 'https://evil.invalid/package.tgz'), ('integrity', 'sha256-no'),
                             ('link', True)]:
            modified = json.loads(json.dumps(lock))
            modified['packages'][key][field] = value
            with self.assertRaises(ValueError): native.validate_lock(package, modified)
        package['dependencies']['@earendil-works/pi-ai'] = '^1.4.0'
        with self.assertRaises(ValueError): native.validate_lock(package, lock)

    def test_archive_exact_hashes_modes_and_determinism(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'root'; root.mkdir()
            (root / 'opt/uas').mkdir(parents=True)
            source = root / 'opt/uas/file'; source.write_bytes(b'exact'); source.chmod(0o755)
            a = Path(temp) / 'a.tar'; b = Path(temp) / 'b.tar'
            first = native.archive_tree(root, a); second = native.archive_tree(root, b)
            self.assertEqual(first['sha256'], second['sha256'])
            self.assertEqual(first['unpacked_bytes'], 5)
            self.assertEqual(first['files'], [{'file': 'opt/uas/file', 'bytes': 5,
                             'sha256': hashlib.sha256(b'exact').hexdigest(), 'mode': 0o555}])
            with tarfile.open(a) as archive:
                entry = archive.getmembers()[0]
                self.assertEqual((entry.uid, entry.gid, entry.mtime, entry.mode), (0, 0, 0, 0o555))

    def test_archive_rejects_links_and_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'root'; root.mkdir()
            source = root / 'file'; source.write_bytes(b'exact')
            alias = root / 'link'; alias.symlink_to(source)
            with self.assertRaises(ValueError): native.archive_tree(root, Path(temp) / 'link.tar')
            alias.unlink()
            with patch.object(native, 'MAX_RUNTIME_BYTES', 4), self.assertRaises(ValueError):
                native.archive_tree(root, Path(temp) / 'size.tar')
            with patch.object(native, 'MAX_FILES', 0), self.assertRaises(ValueError):
                native.archive_tree(root, Path(temp) / 'count.tar')

    def test_profile_is_explicit_and_old_budgets_stay_small(self):
        text = (Path(__file__).parent / 'vm/prepare_payload.py').read_text()
        self.assertIn('profile="static-go-v1"', text)
        self.assertIn('MAX_WORK_BYTES = 2 * 1024 * 1024 * 1024', text)
        self.assertIn('BUILD_TIMEOUT = 900', text)
        self.assertEqual(native.RPM_ROOTS, ('python3', 'tini', 'glibc', 'libstdc++'))

    def test_stage_is_manifest_bound_and_install_scripts_disabled(self):
        import io
        import shutil
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); payload = work / 'payload'; payload.mkdir()
            source = payload / 'repo'
            (source / 'tests/pi').mkdir(parents=True)
            for name in ('package.json', 'package-lock.json'):
                shutil.copyfile(Path(__file__).parent / 'pi' / name, source / 'tests/pi' / name)
            (source / 'runtime/workstation').mkdir(parents=True)
            (source / 'runtime/workstation/pi_connector.c').write_text('synthetic C')
            archive = work / 'node-source.tar.xz'
            with tarfile.open(archive, 'w:xz') as tar:
                entry = tarfile.TarInfo('node-v24.22.1-linux-x64/bin/node'); entry.size = 4
                tar.addfile(entry, io.BytesIO(b'node'))
                entry = tarfile.TarInfo('node-v24.22.1-linux-x64/LICENSE'); entry.size = 7
                tar.addfile(entry, io.BytesIO(b'license'))
            calls = []
            def fetch(url, target, maximum):
                self.assertEqual(url, native.NODE_URL)
                shutil.copyfile(archive, target)
            def run(args, **options):
                calls.append((args, options))
                if '--version' in args: return 'v24.22.1\n'
                if args[0] == 'cc':
                    target = Path(args[args.index('-o') + 1]); target.write_bytes(b'ELF fixture'); target.chmod(0o755)
                return ''
            with patch.object(native, 'NODE_SHA256', native.sha256(archive)), \
                    patch.object(native.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name):
                result = native.stage_native(work, payload, run, fetch)
            npm = next(args for args, _ in calls if args[0].endswith('/npm'))
            self.assertIn('--ignore-scripts', npm)
            self.assertIn('--no-audit', npm)
            self.assertIn('--registry=https://registry.npmjs.org', npm)
            self.assertNotIn('files', result)
            details = result['file_manifest']
            self.assertEqual(details['sha256'], native.sha256(payload / details['file']))
            files = json.loads((payload / details['file']).read_text())['files']
            self.assertIn('opt/uas/bin/pi-connector', [entry['file'] for entry in files])
            self.assertEqual(result['rpm_scriptlets'], False)
