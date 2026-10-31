"""Cheap warm-VM adapter contracts. Never launches QEMU or prepares a host."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
import run_library_installation as runner
import guest_library_installation as guest


class LibraryVMAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_explicit_approval_before_prepared_image_or_process(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(runner.prepared_room, 'select') as select:
            with self.assertRaisesRegex(ValueError, 'explicit'):
                runner.main()
        select.assert_not_called()

    def test_payload_still_within_existing_reviewed_source_bounds(self):
        self.assertLessEqual(len(runner.run_room.SOURCES) + 3, 64)
        self.assertEqual(runner.prepared_room.BASE_SOURCES,
            ('tests/vm/prepared_room.py', 'tests/vm/guest_boundary.py',
             'tests/vm/room_profile.py', 'tests/vm/fedora-image.json'))

    def test_rootfs_uses_existing_fixed_native_trust_installroot(self):
        import native_trust
        self.assertEqual(guest.ROOTFS, Path('/var/lib/uas-native-rootfs'))
        streams = {'stdout': {'output': 'fixed trust result'}}
        with patch.object(guest.boundary, 'native_command', return_value=(0, streams)) as command:
            for argv in native_trust.fixed_commands(guest.ROOTFS):
                self.assertEqual(guest.run(*argv, timeout=90, native_trust_context=True),
                                 'fixed trust result')
            count = command.call_count
            for argv in native_trust.fixed_commands(Path('/var/lib/uas-library-rootfs')):
                with self.assertRaisesRegex(ValueError, 'fixed offline installroot'):
                    guest.run(*argv, timeout=90, native_trust_context=True)
            self.assertEqual(command.call_count, count)

    def test_report_requires_actual_two_room_and_negative_observations(self):
        nonce = 'a' * 32
        value = {'version': 1, 'nonce': nonce, 'profile': runner.PROFILE, 'production_enabled': False,
            'status': 'passed', 'proof': {'status': 'passed', 'rooms': ['alpha', 'beta'],
                'stopped_room_operator': 'observed', 'sibling': 'running',
                'project_content_isolation': 'own-marker-present-sibling-markers-absent',
                'projection_identities': {'alpha': 'a'*64, 'beta': 'b'*64}},
            'absent_configuration': 'refused', 'unsafe_configuration': 'refused', 'cleanup': 'confirmed'}
        def parse(doc):
            return runner.parse_report('UAS_LIBRARY_REPORT:' + nonce + ':' + json.dumps(doc), nonce)
        self.assertEqual(parse(value), value)
        for key in ('unsafe_configuration', 'absent_configuration', 'cleanup', 'proof'):
            changed = dict(value); changed.pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError): parse(changed)
        with self.assertRaises(ValueError): parse({**value, 'version': True})
        with self.assertRaises(ValueError): parse({**value, 'failure': {}})

    def test_negative_startup_consumes_actual_cli_stdout_receipt(self):
        from contextlib import redirect_stdout
        from uas import local_cli, library
        for code in ('LIBRARY_NOT_CONFIGURED', 'INVALID_DEPLOYMENT_STATE'):
            stream = io.StringIO()
            with patch.object(local_cli, 'Installation'), patch.object(local_cli, 'run_host',
                    side_effect=library.LibraryError(code)), redirect_stdout(stream):
                status = local_cli.main(['--root', str(self.base), 'serve'])
            result = subprocess.CompletedProcess([], status, stream.getvalue().encode(), b'')
            guest.startup_refusal(result, code)
            with self.assertRaises(AssertionError):
                guest.startup_refusal(result, 'WRONG_ERROR')
            with self.assertRaises(AssertionError):
                guest.startup_refusal(subprocess.CompletedProcess([], status, b'', result.stdout), code)

    def test_archive_producer_pins_clean_candidate_and_exact_wheels(self):
        root = self.base / 'repo'; root.mkdir()
        for name in ('uas/__init__.py', *runner.EXTRA_SOURCES):
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('# source\n')
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
        git('init', '-q'); git('add', '.')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'Fixture')
        commit = git('rev-parse', 'HEAD')
        wheels = self.base / 'wheels'; wheels.mkdir()
        wheel = wheels / 'fixture.whl'; wheel.write_bytes(b'fixture wheel bytes')
        selected = {'fixture.whl': hashlib.sha256(wheel.read_bytes()).hexdigest()}
        with patch.object(runner, 'WHEELS', selected):
            path = self.base / 'candidate.zip'
            digest = runner.candidate_archive(root, path, wheels, commit)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            with zipfile.ZipFile(path) as archive:
                manifest = json.loads(archive.read('candidate.json'))
                self.assertEqual(manifest['commit'], commit)
                self.assertIn('uas/__init__.py', {row['file'] for row in manifest['files']})
            (root / 'uas/__init__.py').write_text('# changed\n')
            with self.assertRaisesRegex(ValueError, 'tracked candidate'):
                runner.candidate_archive(root, self.base / 'changed.zip', wheels, commit)

    def test_archive_rejects_path_escape_before_creating_root(self):
        raw = b'bad'; name = '../escape'
        descriptor = {'version': 1, 'commit': 'a'*40, 'files': [
            {'file': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}]}
        archive = self.base / 'bad.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('candidate.json', json.dumps(descriptor)); output.writestr(name, raw)
        destination = self.base / 'unpacked'
        with self.assertRaisesRegex(AssertionError, 'relative path'):
            guest.unpack_candidate(archive, destination)
        self.assertFalse(destination.exists())
        self.assertFalse((self.base / 'escape').exists())
