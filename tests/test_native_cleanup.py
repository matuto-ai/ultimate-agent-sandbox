"""SQLite and mocked owned cleanup; no guest, mount, listener or Engine I/O."""
from contextlib import ExitStack, closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).parent / 'vm'))
import guest_boundary as boundary
import guest_workstation as guest
import native_rootfs

NONCE = 'a' * 32
IMAGE = 'sha256:' + 'b' * 64
CONTAINER = 'c' * 64
MOUNT = '/mnt/uas-native'


class AdmissionConnectionTests(unittest.TestCase):
    def database(self, directory, *, table=True):
        path = Path(directory) / 'admissions.db'
        with closing(sqlite3.connect(path)) as database:
            if table:
                database.execute('CREATE TABLE admissions (state TEXT NOT NULL)')
                database.executemany('INSERT INTO admissions VALUES (?)', [('revoked',), ('revoked',)])
                database.commit()
        return path

    def test_readonly_uri_returns_rows_and_really_closes_connection(self):
        connect = sqlite3.connect
        opened = []
        with tempfile.TemporaryDirectory() as directory:
            path = self.database(directory)
            def capture(*args, **kwargs):
                database = connect(*args, **kwargs)
                opened.append(database)
                with self.assertRaisesRegex(sqlite3.OperationalError, 'readonly'):
                    database.execute("INSERT INTO admissions VALUES ('active')")
                return database
            with patch.object(guest.sqlite3, 'connect', side_effect=capture) as factory:
                states = guest.read_admission_states(path)
            factory.assert_called_once_with('file:' + str(path) + '?mode=ro', uri=True)
            self.assertEqual(states, [('revoked',), ('revoked',)])
            self.assertEqual(len(opened), 1)
            with self.assertRaisesRegex(sqlite3.ProgrammingError, 'closed'):
                opened[0].execute('SELECT state FROM admissions')
            with closing(connect(path)) as database:
                self.assertEqual(database.execute('SELECT state FROM admissions').fetchall(), states)

    def test_actual_query_failure_still_closes_connection(self):
        connect = sqlite3.connect
        opened = []
        with tempfile.TemporaryDirectory() as directory:
            path = self.database(directory, table=False)
            def capture(*args, **kwargs):
                database = connect(*args, **kwargs)
                opened.append(database)
                return database
            with patch.object(guest.sqlite3, 'connect', side_effect=capture):
                with self.assertRaisesRegex(sqlite3.OperationalError, 'no such table: admissions'):
                    guest.read_admission_states(path)
            self.assertEqual(len(opened), 1)
            with self.assertRaisesRegex(sqlite3.ProgrammingError, 'closed'):
                opened[0].execute('SELECT 1')

    def test_readonly_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'missing.db'
            with self.assertRaises(sqlite3.OperationalError):
                guest.read_admission_states(path)
            self.assertFalse(path.exists())


class NativeOwnedCleanupTests(unittest.TestCase):
    def scenario_failure(self, *, umount_error=None, mount_error=None, mounted=True,
                         container_error=None, image_error=None, scratch_error=None,
                         listener_error=None, before_failure=None, before_umount=None):
        """Reach real finally after one owned container, without native setup."""
        original = ValueError('original scenario failure')
        checks = {}
        progress = {}
        image_root = MagicMock(spec=Path)
        image_root.exists.side_effect = [False, True]
        image_root.iterdir.return_value = []
        image_root.name = 'uas-native-rootfs'
        archive = MagicMock(spec=Path)
        archive.exists.return_value = False
        source = archive.open.return_value.__enter__.return_value
        source.read.return_value = b''
        source.fileno.return_value = 33
        storage = Mock()
        storage.__str__ = Mock(return_value=MOUNT)
        storage.is_mount.return_value = mounted
        storage.is_mount.side_effect = mount_error
        listeners = [Mock(), Mock()]
        listeners[0].close.side_effect = listener_error
        events = []

        def prepare_storage(nonce, ownership):
            self.assertEqual(nonce, NONCE)
            ownership['mount_attempted'] = True
            return {'peer': Path('/unused/peer'), 'control': Path('/unused/control')}

        def create(image, name, kind, paths):
            self.assertEqual(image, IMAGE)
            if kind == 'workstation':
                return CONTAINER
            self.assertEqual(kind, 'hub')
            if before_failure is not None:
                before_failure()
            raise original

        def run(*arguments, **options):
            self.assertEqual(options, {})
            events.append(arguments)
            if arguments == ('docker', 'start', CONTAINER):
                return ''
            if arguments == ('docker', 'rm', '--force', CONTAINER):
                if container_error is not None:
                    raise container_error
                return ''
            if arguments == ('umount', MOUNT):
                if before_umount is not None:
                    before_umount()
                if umount_error is not None:
                    raise umount_error
                return ''
            if arguments == ('docker', 'image', 'rm', IMAGE):
                if image_error is not None:
                    raise image_error
                return ''
            raise AssertionError('unexpected command: ' + repr(arguments))

        with ExitStack() as stack:
            stack.enter_context(patch.object(sys, 'path', sys.path.copy()))
            stack.enter_context(patch.object(guest, 'Path', side_effect=lambda path: {
                '/var/lib/uas-native-rootfs': image_root,
                '/var/lib/uas-native-rootfs.tar': archive}[path]))
            stack.enter_context(patch.object(guest, 'STORAGE', storage))
            stack.enter_context(patch.object(native_rootfs, 'build_rootfs', return_value={
                'rootfs_manifest_sha256': 'd' * 64}))
            stack.enter_context(patch.object(boundary, 'start_engine'))
            stack.enter_context(patch.object(guest, 'engine_profile', return_value={}))
            stack.enter_context(patch.object(guest.tarfile, 'open'))
            stack.enter_context(patch.object(guest.os, 'fstat', return_value=SimpleNamespace(st_size=0)))
            stack.enter_context(patch.object(guest, 'import_image', return_value=IMAGE))
            stack.enter_context(patch.object(guest, 'storage', side_effect=prepare_storage))
            stack.enter_context(patch.object(guest, 'labeled_listener', side_effect=listeners))
            stack.enter_context(patch.object(guest, 'create', side_effect=create))
            stack.enter_context(patch.object(guest, 'inspect', return_value={
                'Config': {'Labels': {'uas.native-owner': NONCE}}}))
            commands = stack.enter_context(patch.object(guest, 'run', side_effect=run))
            scratch = stack.enter_context(patch.object(guest.shutil, 'rmtree', side_effect=scratch_error))
            stack.enter_context(patch.object(guest.subprocess, 'Popen', side_effect=AssertionError('no process')))
            stack.enter_context(patch.object(guest, 'emit_evidence'))
            emit = stack.enter_context(patch.object(guest, 'emit_check'))
            stack.enter_context(patch('builtins.print'))
            with self.assertRaises(ValueError) as caught:
                guest.scenario(NONCE, {}, checks=checks, progress=progress)
            self.assertIs(caught.exception, original)
        self.assertEqual(checks['payload']['status'], 'passed')
        self.assertEqual(checks['payload']['image'], IMAGE)
        self.assertEqual(progress, {'check': 'confinement', 'stage': 'container-confinement'})
        self.assertEqual(emit.call_args.args, (checks, 'guest_cleanup'))
        for listener in listeners:
            listener.close.assert_called_once_with()
        scratch.assert_called_once_with(image_root)
        archive.unlink.assert_called_once_with(missing_ok=True)
        self.assertEqual([item.args for item in commands.call_args_list], events)
        return checks['guest_cleanup'], original, events, storage

    def test_actual_admission_connection_closed_before_mocked_unmount(self):
        connect = sqlite3.connect
        opened = []
        with tempfile.TemporaryDirectory() as directory:
            path = AdmissionConnectionTests().database(directory)
            def capture(*args, **kwargs):
                database = connect(*args, **kwargs)
                opened.append(database)
                return database
            def read_states():
                self.assertEqual(guest.read_admission_states(path), [('revoked',), ('revoked',)])
            def assert_closed():
                self.assertEqual(len(opened), 1)
                with self.assertRaisesRegex(sqlite3.ProgrammingError, 'closed'):
                    opened[0].execute('SELECT 1')
            with patch.object(guest.sqlite3, 'connect', side_effect=capture):
                cleanup, original, commands, storage = self.scenario_failure(
                    before_failure=read_states, before_umount=assert_closed)
        self.assertEqual(cleanup, {'status': 'passed', 'cleanup_errors': [],
            'owned_containers_removed': True, 'quota_disk_unmounted': True,
            'owned_image_and_build_scratch_removed': True})
        self.assertFalse(hasattr(original, '__notes__'))
        self.assertEqual(commands, [('docker', 'start', CONTAINER),
            ('docker', 'rm', '--force', CONTAINER), ('umount', MOUNT), ('docker', 'image', 'rm', IMAGE)])
        storage.is_mount.assert_called_once_with()

    def test_fixed_umount_error_is_byte_bounded_hashed_and_never_retried(self):
        for text in ('umount: target is busy', 'x' * 2048, 'x' * 2047 + '\u20ac' * 1000):
            with self.subTest(bytes=len(text.encode('utf-8'))):
                cleanup, original, commands, storage = self.scenario_failure(umount_error=RuntimeError(text))
                raw = text.encode('utf-8')
                error, = cleanup['cleanup_errors']
                self.assertEqual(error['resource'], 'quota-mount')
                self.assertEqual(error['error'], 'RuntimeError')
                self.assertEqual(error['fixed_umount_diagnostic'], {
                    'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                    'text': raw[:2048].decode('utf-8', errors='ignore'), 'truncated': len(raw) > 2048})
                self.assertLessEqual(len(error['fixed_umount_diagnostic']['text'].encode('utf-8')), 2048)
                self.assertEqual([command for command in commands if command[0] == 'umount'], [('umount', MOUNT)])
                self.assertTrue(cleanup['owned_containers_removed'])
                self.assertFalse(cleanup['quota_disk_unmounted'])
                self.assertTrue(cleanup['owned_image_and_build_scratch_removed'])
                self.assertEqual(cleanup['status'], 'failed')
                self.assertIn('Native cleanup failures:', original.__notes__[0])
                storage.is_mount.assert_called_once_with()

    def test_only_fixed_umount_runtime_error_retains_content(self):
        for options, resource, error_type in (
                ({'mount_error': RuntimeError('PRIVATE mount inspection')}, 'quota-mount', 'RuntimeError'),
                ({'umount_error': OSError('PRIVATE generic error')}, 'quota-mount', 'OSError'),
                ({'container_error': RuntimeError('PRIVATE container')}, 'container', 'RuntimeError'),
                ({'image_error': RuntimeError('PRIVATE image')}, 'image', 'RuntimeError'),
                ({'scratch_error': RuntimeError('PRIVATE scratch')}, 'build-scratch', 'RuntimeError'),
                ({'listener_error': RuntimeError('PRIVATE listener')}, 'listener', 'RuntimeError')):
            with self.subTest(resource=resource, options=tuple(options)):
                cleanup, original, commands, _ = self.scenario_failure(**options)
                self.assertEqual(cleanup['cleanup_errors'], [{'resource': resource, 'error': error_type}])
                self.assertNotIn('PRIVATE', json.dumps(cleanup))
                self.assertNotIn('PRIVATE', ''.join(original.__notes__))
                self.assertEqual(cleanup['owned_containers_removed'], resource != 'container')
                self.assertEqual(cleanup['quota_disk_unmounted'], resource != 'quota-mount')
                self.assertEqual(cleanup['owned_image_and_build_scratch_removed'], resource not in {'image', 'build-scratch'})
                umounts = [command for command in commands if command[0] == 'umount']
                self.assertEqual(umounts, [] if 'mount_error' in options else [('umount', MOUNT)])

    def test_multiple_cleanup_failures_do_not_skip_later_resources_or_replace_original(self):
        cleanup, original, commands, _ = self.scenario_failure(
            container_error=OSError('PRIVATE container'), umount_error=RuntimeError('fixed umount failure'),
            image_error=OSError('PRIVATE image'), scratch_error=OSError('PRIVATE scratch'))
        self.assertEqual([error['resource'] for error in cleanup['cleanup_errors']],
                         ['container', 'quota-mount', 'image', 'build-scratch'])
        self.assertFalse(cleanup['owned_containers_removed'])
        self.assertFalse(cleanup['quota_disk_unmounted'])
        self.assertFalse(cleanup['owned_image_and_build_scratch_removed'])
        self.assertEqual(cleanup['status'], 'failed')
        self.assertEqual(commands[-1], ('docker', 'image', 'rm', IMAGE))
        self.assertNotIn('PRIVATE', json.dumps(cleanup))
        self.assertNotIn('PRIVATE', ''.join(original.__notes__))

    def test_diagnostic_encoding_failure_still_records_real_cleanup_failure(self):
        class BrokenText(RuntimeError):
            def __str__(self):
                raise LookupError('PRIVATE diagnostic failure')
        cleanup, original, commands, _ = self.scenario_failure(umount_error=BrokenText())
        self.assertEqual(cleanup['cleanup_errors'], [{'resource': 'quota-mount', 'error': 'BrokenText',
            'fixed_umount_diagnostic': {'unavailable': 'LookupError'}}])
        self.assertFalse(cleanup['quota_disk_unmounted'])
        self.assertNotIn('PRIVATE', json.dumps(cleanup))
        self.assertEqual([command for command in commands if command[0] == 'umount'], [('umount', MOUNT)])
        self.assertIn('Native cleanup failures:', original.__notes__[0])

    def test_already_unmounted_owned_disk_never_calls_umount(self):
        cleanup, _, commands, storage = self.scenario_failure(mounted=False)
        self.assertEqual(cleanup['status'], 'passed')
        self.assertTrue(cleanup['quota_disk_unmounted'])
        self.assertFalse(any(command[0] == 'umount' for command in commands))
        storage.is_mount.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
