"""Mocked descriptor traversal contracts; no permission or native probe."""
import errno
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from uas.artifact_protocol import ArtifactError
from uas import artifact_target as target
from uas import artifact_helper as helper
from uas import artifact_paths as paths


class ArtifactTraversalTests(unittest.TestCase):
    def test_search_only_ancestors_keep_readable_leaf_and_nofollow_everywhere(self):
        search = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        with patch.object(target.os, 'open', side_effect=[41, 42, 43, 44]) as opened, \
                patch.object(target.os, 'close') as closed:
            self.assertEqual(target._open_dir('/private/control/room'), 44)
        self.assertEqual(opened.call_args_list, [call('/', search),
            call('private', search, dir_fd=41), call('control', search, dir_fd=42),
            call('room', target._DIR, dir_fd=43)])
        self.assertEqual(closed.call_args_list, [call(41), call(42), call(43)])
        self.assertFalse(target._DIR & os.O_PATH)
        for item in opened.call_args_list:
            flags = item.args[1]
            self.assertEqual(flags & (os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC),
                os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    def test_execute_only_ancestor_model_does_not_require_directory_read(self):
        # This is a permissions model, not a local uid/chmod/kernel proof.
        def opened(name, flags, **kwargs):
            if name in ('/', 'private'):
                if not flags & os.O_PATH:
                    raise PermissionError(errno.EACCES, 'simulated unreadable ancestor')
            else:
                self.assertEqual(name, 'leaf')
                self.assertEqual(flags, target._DIR)
            return {'/': 41, 'private': 42, 'leaf': 43}[name]
        with patch.object(target.os, 'open', side_effect=opened), patch.object(target.os, 'close'):
            self.assertEqual(target._open_dir('/private/leaf'), 43)

    def test_single_component_leaf_still_opened_readonly_from_held_root(self):
        with patch.object(target.os, 'open', side_effect=[41, 42]) as opened, \
                patch.object(target.os, 'close') as closed:
            self.assertEqual(target._open_dir('/leaf'), 42)
        self.assertEqual(opened.call_args_list[-1], call('leaf', target._DIR, dir_fd=41))
        closed.assert_called_once_with(41)

    def test_root_relative_and_traversal_paths_rejected_before_open(self):
        for path in ('/', '//', '//.', '/.', 'relative', '/allowed/../escape'):
            with self.subTest(path=path), patch.object(target.os, 'open') as opened:
                with self.assertRaises(ArtifactError): target._open_dir(path)
                opened.assert_not_called()

    def test_missing_or_invalid_search_flag_fails_closed_without_read_fallback(self):
        for flag in (None, 0, False, 'O_PATH'):
            with self.subTest(flag=flag), patch.object(target.os, 'O_PATH', flag), \
                    patch.object(target.os, 'open') as opened:
                with self.assertRaises(ArtifactError) as failure: target._open_dir('/leaf')
                self.assertEqual(str(failure.exception), 'ARTIFACT_PATH_TRAVERSAL_UNAVAILABLE')
                opened.assert_not_called()

    def test_each_acquisition_failure_closes_only_owned_descriptors(self):
        for fail_at in range(4):
            sequence = list(range(41, 41 + fail_at)) + [PermissionError(errno.EACCES, 'denied')]
            with self.subTest(fail_at=fail_at), patch.object(target.os, 'open', side_effect=sequence), \
                    patch.object(target.os, 'close') as closed:
                with self.assertRaises(PermissionError): target._open_dir('/a/b/c')
            self.assertEqual(closed.call_args_list, [call(fd) for fd in range(41, 41 + fail_at)])

    def test_symlink_nondirectory_and_denied_search_errors_never_retry_or_fallback(self):
        for number in (errno.ELOOP, errno.ENOTDIR, errno.EACCES):
            with self.subTest(errno=number), patch.object(target.os, 'open',
                    side_effect=[41, OSError(number, 'fixed denial')]) as opened, \
                    patch.object(target.os, 'close') as closed:
                with self.assertRaises(OSError) as failure: target._open_dir('/a/leaf')
                self.assertEqual(failure.exception.errno, number)
                self.assertEqual(opened.call_count, 2)
                closed.assert_called_once_with(41)

    def test_close_failure_releases_new_child_without_retrying_retired_fd(self):
        with patch.object(target.os, 'open', side_effect=[41, 42]), \
                patch.object(target.os, 'close', side_effect=[OSError(errno.EIO, 'close'), None]) as closed:
            with self.assertRaises(OSError): target._open_dir('/a/leaf')
        self.assertEqual(closed.call_args_list, [call(41), call(42)])


class ArtifactDirectoryConsumerCleanupTests(unittest.TestCase):
    def lease(self):
        owner = SimpleNamespace(root=Path('/owned'), root_identity=[2, 3])
        return target.ArtifactTargetLease(owner, 'evaluation', {}, 'target', [2, 4])

    def test_observe_initial_fstat_failure_releases_returned_leaf(self):
        for failure in (OSError(errno.EIO, 'fstat'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(target, '_open_dir', return_value=41), \
                    patch.object(target.os, 'fstat', side_effect=failure), \
                    patch.object(target.os, 'close') as closed:
                with self.assertRaises(type(failure)): target.observe_target('/owned/tree', 1)
                closed.assert_called_once_with(41)

    def test_parent_root_fstat_or_child_open_failure_releases_root(self):
        for point in ('fstat', 'open'):
            with self.subTest(point=point), patch.object(target, '_open_dir', return_value=41), \
                    patch.object(target.os, 'fstat', return_value=SimpleNamespace(st_dev=2, st_ino=3)) as fs, \
                    patch.object(target.os, 'open') as opened, \
                    patch.object(target.os, 'close') as closed:
                (fs if point == 'fstat' else opened).side_effect = OSError(errno.EIO, point)
                with self.assertRaises(OSError): self.lease()._parent()
                closed.assert_called_once_with(41)

    def test_parent_root_close_failure_still_releases_child_without_retry(self):
        for failure in (OSError(errno.EIO, 'close'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(target, '_open_dir', return_value=41), \
                    patch.object(target.os, 'fstat', return_value=SimpleNamespace(st_dev=2, st_ino=3)), \
                    patch.object(target.os, 'open', return_value=42), \
                    patch.object(target.os, 'close', side_effect=[failure, None]) as closed:
                with self.assertRaises(type(failure)): self.lease()._parent()
                self.assertEqual(closed.call_args_list, [call(41), call(42)])

    def test_parent_child_fstat_failure_releases_child(self):
        with patch.object(target, '_open_dir', return_value=41), \
                patch.object(target.os, 'fstat', side_effect=[SimpleNamespace(st_dev=2, st_ino=3),
                    OSError(errno.EIO, 'fstat')]), patch.object(target.os, 'open', return_value=42), \
                patch.object(target.os, 'close') as closed:
            with self.assertRaises(OSError): self.lease()._parent()
        self.assertEqual(closed.call_args_list, [call(41), call(42)])

    def test_parent_identity_uid_and_mode_validation_still_fail_closed(self):
        good = dict(st_dev=2, st_ino=4, st_uid=65533, st_mode=0o40700)
        for change in ({'st_ino': 5}, {'st_uid': 65532}, {'st_mode': 0o40755}):
            with self.subTest(change=change), patch.object(target, '_open_dir', return_value=41), \
                    patch.object(target.os, 'fstat', side_effect=[SimpleNamespace(st_dev=2, st_ino=3),
                        SimpleNamespace(**(good | change))]), patch.object(target.os, 'getuid', return_value=65533), \
                    patch.object(target.os, 'open', return_value=42), patch.object(target.os, 'close') as closed:
                with self.assertRaisesRegex(ArtifactError, 'ARTIFACT_TARGET_OWNERSHIP_LOST'):
                    self.lease()._parent()
                self.assertEqual(closed.call_args_list, [call(41), call(42)])

    def test_parent_success_transfers_exact_readable_leaf(self):
        with patch.object(target, '_open_dir', return_value=41), \
                patch.object(target.os, 'fstat', side_effect=[SimpleNamespace(st_dev=2, st_ino=3),
                    SimpleNamespace(st_dev=2, st_ino=4, st_uid=65533, st_mode=0o40710)]), \
                patch.object(target.os, 'getuid', return_value=65533), \
                patch.object(target.os, 'open', return_value=42) as opened, \
                patch.object(target.os, 'close') as closed:
            self.assertEqual(self.lease()._parent(), 42)
        opened.assert_called_once_with('target', target._DIR, dir_fd=41)
        closed.assert_called_once_with(41)

    def test_object_directory_close_failure_still_closes_common_without_retry(self):
        for failure in (OSError(errno.EIO, 'close'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(target, '_open_dir', return_value=41), \
                    patch.object(target.os, 'open', side_effect=[42, FileNotFoundError()]), \
                    patch.object(target, '_names', return_value=[]), \
                    patch.object(target.os, 'close', side_effect=[failure, None]) as closed:
                with self.assertRaises(type(failure)): target.copy_objects('/common', Mock(), 1)
                self.assertEqual(closed.call_args_list, [call(42), call(41)])


class ConnectedGateTraversalTests(unittest.TestCase):
    def test_target_and_helper_wrappers_use_the_same_primitive(self):
        self.assertIs(target.open_directory, paths.open_directory)
        self.assertIs(helper.open_directory, paths.open_directory)
        for module, name, invalid, unavailable in ((target, '_open_dir', 'UNSAFE_ARTIFACT_PATH',
                'ARTIFACT_PATH_TRAVERSAL_UNAVAILABLE'), (helper, '_directory',
                'INVALID_GATE_RESOURCE_PATH', 'GATE_PATH_TRAVERSAL_UNAVAILABLE')):
            with self.subTest(caller=name), patch.object(module, 'open_directory', return_value=41) as opened:
                self.assertEqual(getattr(module, name)('/owned/leaf'), 41)
                opened.assert_called_once_with('/owned/leaf', invalid_code=invalid, unsupported_code=unavailable)

    def test_helper_searches_nonce_ancestor_but_returns_readable_leaf(self):
        search = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        with patch.object(paths.os, 'open', side_effect=[41, 42, 43, 44, 45]) as opened, \
                patch.object(paths.os, 'close') as closed:
            self.assertEqual(helper._directory('/var/lib/nonce/gate'), 45)
        self.assertEqual(opened.call_args_list, [call('/', search), call('var', search, dir_fd=41),
            call('lib', search, dir_fd=42), call('nonce', search, dir_fd=43),
            call('gate', target._DIR, dir_fd=44)])
        self.assertEqual(closed.call_args_list, [call(41), call(42), call(43), call(44)])

    def test_helper_root_and_missing_search_support_fail_closed(self):
        for value in ('/', '//', '//.', '/.', 'relative', '/one/../two'):
            with self.subTest(path=value), patch.object(paths.os, 'open') as opened:
                with self.assertRaisesRegex(ArtifactError, 'INVALID_GATE_RESOURCE_PATH'):
                    helper._directory(value)
                opened.assert_not_called()
        with patch.object(paths.os, 'O_PATH', None), patch.object(paths.os, 'open') as opened:
            with self.assertRaisesRegex(ArtifactError, 'GATE_PATH_TRAVERSAL_UNAVAILABLE'):
                helper._directory('/owned/leaf')
            opened.assert_not_called()

    def test_helper_acquisition_errors_and_interruption_close_owned_fds_once(self):
        for number in (errno.EACCES, errno.ENOTDIR, errno.ELOOP):
            for fail_at in range(4):
                with self.subTest(errno=number, fail_at=fail_at), \
                        patch.object(paths.os, 'open', side_effect=list(range(41,41+fail_at))+[OSError(number,'denied')]), \
                        patch.object(paths.os, 'close') as closed:
                    with self.assertRaises(OSError): helper._directory('/nonce/gate/leaf')
                    self.assertEqual(closed.call_args_list,[call(fd) for fd in range(41,41+fail_at)])
        with patch.object(paths.os, 'open', side_effect=[41,42]), \
                patch.object(paths.os, 'close', side_effect=[KeyboardInterrupt(),None]) as closed:
            with self.assertRaises(KeyboardInterrupt): helper._directory('/nonce/gate')
            self.assertEqual(closed.call_args_list,[call(41),call(42)])

    def test_relative_ref_walk_close_failure_releases_new_child_without_retry(self):
        for failure in (OSError(errno.EIO, 'close'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), patch.object(target.os, 'dup', return_value=41), \
                    patch.object(target.os, 'open', return_value=42), \
                    patch.object(target.os, 'close', side_effect=[failure,None]) as closed, \
                    patch.object(target, '_read_at') as read:
                with self.assertRaises(type(failure)): target._read_path(40,'refs/heads/main')
                self.assertEqual(closed.call_args_list,[call(41),call(42)])
                read.assert_not_called()

    def test_trusted_binary_walk_close_failure_releases_new_child_without_retry(self):
        for failure in (OSError(errno.EIO, 'close'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(target.os, 'open', side_effect=[41,42]), \
                    patch.object(target.os, 'fstat', return_value=SimpleNamespace(st_uid=0,st_mode=0o40755)), \
                    patch.object(target.os, 'close', side_effect=[failure,None]) as closed:
                with self.assertRaises(type(failure)): target._trusted_executable('/usr/bin/git')
                self.assertEqual(closed.call_args_list,[call(41),call(42)])

    def test_launch_journal_close_attempts_both_descriptors_once_on_failure(self):
        for failure in (OSError(errno.EIO, 'close'), KeyboardInterrupt(), SystemExit()):
            journal=object.__new__(helper._LaunchJournal);journal.fd=41;journal.parent=42
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(helper.os,'close',side_effect=[failure,None]) as closed:
                with self.assertRaises(type(failure)): journal.close()
                self.assertEqual((journal.fd,journal.parent),(-1,-1))
                journal.close()
                self.assertEqual(closed.call_args_list,[call(41),call(42)])

    def test_launch_journal_parent_close_error_is_not_retried(self):
        journal=object.__new__(helper._LaunchJournal);journal.fd=41;journal.parent=42
        with patch.object(helper.os,'close',side_effect=[None,OSError(errno.EIO,'close')]) as closed:
            with self.assertRaises(OSError):journal.close()
            journal.close()
            self.assertEqual((journal.fd,journal.parent),(-1,-1))
            self.assertEqual(closed.call_args_list,[call(41),call(42)])


if __name__ == '__main__': unittest.main()
