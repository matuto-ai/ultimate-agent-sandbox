"""Inert held-lock/source tests: ordinary files only, no native runtime."""
from copy import deepcopy
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from uas.lifecycle import Supervisor, LifecycleError, _HeldLifecycleScope
from uas.artifact_target import ArtifactSourceResolver
from uas.artifact_protocol import ArtifactError
import test_artifact_target as source_fixture


class HeldLifecycleTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.owner = self.make_owner('one')

    def make_owner(self, name):
        return Supervisor(self.root, name, object(), authorize=lambda *a: True,
                          revoke=lambda *a: True)

    def test_exact_active_owner_and_distinct_scopes(self):
        other = self.make_owner('two')
        with self.owner._locked() as scope:
            scope.require(self.owner)
            with self.assertRaises(LifecycleError): scope.require(other)
            for forged in (None, True, object(), _HeldLifecycleScope(self.owner)):
                with self.assertRaises(LifecycleError): self.owner._require_lifecycle_scope(forged)
        with self.assertRaises(LifecycleError): scope.require(self.owner)
        with self.owner._locked() as fresh:
            fresh.require(self.owner)
            with self.assertRaises(LifecycleError): scope.require(self.owner)
            self.assertIsNot(scope, fresh)

    def test_scope_bound_to_process_and_thread_without_starting_either(self):
        with self.owner._locked() as scope:
            with patch('uas.lifecycle.threading.get_ident', return_value=-1):
                with self.assertRaises(LifecycleError): scope.require(self.owner)
            with patch('uas.lifecycle.os.getpid', return_value=-1):
                with self.assertRaises(LifecycleError): scope.require(self.owner)
            scope.require(self.owner)

    def test_exception_expires_scope_before_descriptor_close(self):
        actual_close = os.close
        def checked_close(fd):
            self.assertFalse(self.owner._lifecycle_scopes)
            actual_close(fd)
        with patch('uas.lifecycle.os.close', side_effect=checked_close):
            with self.assertRaisesRegex(RuntimeError, 'abort'):
                with self.owner._locked() as scope:
                    scope.require(self.owner)
                    raise RuntimeError('abort')
        with self.assertRaises(LifecycleError): scope.require(self.owner)

    def test_flock_failure_never_mints_scope(self):
        with patch('uas.lifecycle.fcntl.flock', side_effect=OSError('unavailable')):
            with self.assertRaises(OSError):
                with self.owner._locked(): self.fail('entered without lock')
        self.assertFalse(self.owner._lifecycle_scopes)


class LockedSourceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = source_fixture.TargetTests()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.owner = Supervisor(self.fixture.root / 'owners', 'room-a', object(),
                               authorize=lambda *a: True, revoke=lambda *a: True)
        self.owner._read = lambda: deepcopy(self.fixture.lifecycle)
        self.fixture.allocator.supervisor = self.owner
        self.resolver = ArtifactSourceResolver(self.owner, self.fixture.allocator)

    def resolve(self):
        return self.resolver.resolve('run-a', 'alice', 'a' * 32)

    def locked(self, scope):
        return self.resolver.resolve_locked(scope, 'run-a', 'alice', 'a' * 32)

    def test_public_and_locked_results_identical_without_reacquisition(self):
        expected = self.resolve()
        with self.owner._locked() as scope:
            with patch.object(self.owner, '_locked', side_effect=AssertionError('nested lock')):
                self.assertEqual(self.locked(scope), expected)
        with self.assertRaises(LifecycleError): self.locked(scope)

    def test_forged_or_other_owner_scope_refused_before_read(self):
        other = Supervisor(self.fixture.root / 'owners', 'other', object(),
                           authorize=lambda *a: True, revoke=lambda *a: True)
        with other._locked() as wrong:
            with patch.object(self.owner, '_read', side_effect=AssertionError('read before validation')):
                for scope in (wrong, None, True, _HeldLifecycleScope(self.owner)):
                    with self.assertRaises(LifecycleError): self.locked(scope)

    def test_head_remains_in_full_result_for_consuming_equality(self):
        captured = self.resolve()
        with self.owner._locked() as scope:
            (self.fixture.common / 'refs/heads/main').write_text('b' * 40 + '\n')
            changed = self.locked(scope)
            self.assertEqual(changed['head_sha'], 'b' * 40)
            self.assertNotEqual(changed, captured)
            self.assertEqual(changed['source_digest'], captured['source_digest'])

    def test_changed_binding_and_stopped_room_fail_locked(self):
        with self.owner._locked() as scope:
            self.fixture.state['slots']['primary']['participant'] = 'other'
            self.fixture.save()
            with self.assertRaises(ArtifactError): self.locked(scope)
            self.fixture.lifecycle['phase'] = 'stopped'
            with self.assertRaises(ArtifactError): self.locked(scope)

    def test_public_fixture_contract_and_lock_error_normalization_unchanged(self):
        self.assertEqual(self.fixture.resolve(), self.resolve())
        with patch.object(self.owner, '_locked', side_effect=OSError('lock unavailable')):
            with self.assertRaises(ArtifactError) as caught: self.resolve()
        self.assertEqual(caught.exception.code, 'ARTIFACT_SOURCE_UNVERIFIABLE')
