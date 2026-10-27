"""Real local Git through the existing fixture supervisor; no remote or accounts."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lifecycle_support import FileFixtureBackend
from uas.lifecycle import FixtureSpec, LifecycleError, Supervisor


class CheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads(Path('tests/fixtures/two-rooms.json').read_text())
        self.config['deployment']['state_root'] = str(self.root / 'control')
        for room in self.config['rooms']:
            room['state_root'] = str(self.root / 'control' / room['id'])
            for role in room['project']['roots']:
                path = self.root / room['id'] / role
                path.mkdir(parents=True)
                room['project']['roots'][role] = str(path)
        self.room = self.config['rooms'][0]
        self.repo = Path(self.room['project']['roots']['repo'])
        self.slots = Path(self.room['project']['roots']['checkouts'])
        self.git(self.repo, 'init', '-b', 'main')
        self.git(self.repo, 'config', 'user.name', 'Fixture')
        self.git(self.repo, 'config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'source.txt').write_text('original\n')
        (self.repo / '.gitignore').write_text('ignored.txt\n')
        self.git(self.repo, 'add', '.')
        self.git(self.repo, 'commit', '-m', 'fixture baseline')
        self.backend = FileFixtureBackend(self.root / 'resources')
        self.allowed = True
        self.quiescent = True
        self.supervisor = self.reopen_supervisor()
        self.spec = FixtureSpec(self.room['id'], self.room['project']['id'],
            tuple(self.room['project']['roots'].values()), 'sha256:' + 'a' * 64,
            'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
        self.supervisor.start(self.spec)
        self.allocator = self.reopen()

    def git(self, path, *args):
        result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(path), *args],
            capture_output=True, text=True, timeout=10,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'GIT_CONFIG_NOSYSTEM': '1',
                 'GIT_CONFIG_GLOBAL': '/dev/null', 'LC_ALL': 'C'})
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.strip()

    def reopen_supervisor(self):
        return Supervisor(self.root / 'control', self.room['id'], self.backend,
                          authorize=lambda *_: self.allowed, revoke=self.backend.revoke)

    def reopen(self):
        return self.reopen_supervisor().checkouts(io.StringIO(json.dumps(self.config)),
            writer_quiescent=lambda *_: self.quiescent)

    def pair(self):
        first = self.allocator.allocate('run-1', 'alice')
        second = self.allocator.allocate('run-2', 'bob')
        return first, second, Path(second['path'])

    def secondary(self, results):
        return next(item for item in results if item['slot'] != 'primary')

    def error(self, code, action):
        with self.assertRaises(LifecycleError) as raised:
            action()
        self.assertEqual(code, raised.exception.code)

    def test_supervisor_primary_concurrent_host_work_restart_and_cleanup(self):
        first, second, path = self.pair()
        self.assertEqual(str(self.repo), first['path'])
        self.assertEqual(self.slots, path.parent)
        self.assertEqual(second['base'], self.git(path, 'rev-parse', 'HEAD'))
        self.assertEqual('original\n', (path / 'source.txt').read_text())
        self.assertEqual(second, self.reopen().allocate('run-2', 'bob'))
        # The ordinary host Git CLI sees and can work in the returned path.
        (path / 'source.txt').write_text('human work\n')
        self.assertIn('source.txt', self.git(path, 'status', '--porcelain'))
        self.supervisor.stop()
        self.error('ROOM_NOT_RUNNING', lambda: self.reopen().allocate('run-3', 'alice'))
        self.assertTrue(self.secondary(self.reopen().status())['observed_dirty'])
        self.supervisor.start(self.spec)
        self.allocator.release('run-2', 'bob')
        self.assertEqual('retained', self.secondary(self.allocator.reconcile())['disposition'])
        self.assertEqual('human work\n', (path / 'source.txt').read_text())
        self.git(path, 'restore', 'source.txt')  # Explicit fixture-human repair.
        self.assertEqual('removed', self.secondary(self.allocator.reconcile())['disposition'])
        self.assertFalse(path.exists())
        self.assertTrue(self.repo.exists())
        self.allocator.release('run-1', 'alice')
        self.assertEqual('primary', self.allocator.allocate('run-3', 'bob')['slot'])

    def test_concurrent_allocation_serializes_one_primary_and_distinct_slots(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda n: self.reopen().allocate('run-' + str(n), 'alice'), range(6)))
        self.assertEqual(1, sum(r['slot'] == 'primary' for r in results))
        self.assertEqual(6, len({r['path'] for r in results}))
        self.assertEqual(6, len(self.allocator.status()))

    def test_retained_manager_probe_uses_real_git_and_survives_owner_restart(self):
        self.allocator.allocate('run-1', 'alice')
        self.assertFalse(self.allocator.refresh_observation('primary')['observed_dirty'])
        (self.repo / 'ignored.txt').write_text('preserve ignored human bytes')
        self.assertTrue(self.reopen().refresh_observation('primary')['observed_dirty'])
        reopened = self.reopen()
        with patch.object(reopened, '_git', side_effect=AssertionError('passive Manager export invoked Git')):
            fact = reopened.manager_observations()[0].document()
        self.assertEqual('dirty', fact['value']['primary']['working_tree_state'])
        self.assertEqual('unknown', fact['freshness'])
        self.assertIsNone(fact['observed_at'])
        self.assertNotIn('ignored.txt', json.dumps(fact))
        self.assertEqual('preserve ignored human bytes', (self.repo / 'ignored.txt').read_text())
        self.allowed = False
        self.error('FORBIDDEN', lambda: self.reopen().refresh_observation('primary'))

    def test_dirty_untracked_and_ignored_paths_survive(self):
        _, _, path = self.pair()
        self.allocator.release('run-2', 'bob')
        for name in ['source.txt', 'untracked.txt', 'ignored.txt']:
            with self.subTest(name=name):
                target = path / name; original = target.read_bytes() if target.exists() else None
                target.write_text('retain me')
                result = self.secondary(self.allocator.reconcile())
                self.assertEqual('DIRTY_OR_UNTRACKED_OR_IGNORED', result['reason'])
                self.assertEqual('retain me', target.read_text())
                if original is None: target.unlink()
                else: target.write_bytes(original)

    def test_unmerged_commits_remain_until_explicit_merge(self):
        _, _, path = self.pair()
        (path / 'source.txt').write_text('committed work\n')
        self.git(path, 'add', '.'); self.git(path, 'commit', '-m', 'participant change')
        self.allocator.release('run-2', 'bob')
        self.assertEqual('UNMERGED', self.secondary(self.allocator.reconcile())['reason'])
        self.assertTrue(path.exists())
        self.git(self.repo, 'merge', '--ff-only', self.git(path, 'rev-parse', 'HEAD'))
        self.assertEqual('removed', self.secondary(self.allocator.reconcile())['disposition'])

    def test_unregistered_mismatched_and_locked_paths_are_not_deleted(self):
        _, second, path = self.pair()
        unregistered = self.slots / 'human-owned'; unregistered.mkdir()
        (unregistered / 'sentinel').write_text('human')
        self.allocator.release('run-2', 'bob')
        self.git(self.repo, 'worktree', 'lock', str(path))
        self.assertEqual('retained', self.secondary(self.allocator.reconcile())['disposition'])
        self.git(self.repo, 'worktree', 'unlock', str(path))
        self.git(path, 'switch', '-c', 'human-branch')
        self.assertEqual('METADATA_MISMATCH', self.secondary(self.allocator.reconcile())['reason'])
        self.assertTrue(path.exists()); self.assertEqual('human', (unregistered / 'sentinel').read_text())

    def test_interrupted_creation_recovers_exact_registered_worktree(self):
        self.allocator.allocate('run-1', 'alice')
        original = self.allocator._git
        def interrupted(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if args[:2] == ('worktree', 'add'): raise RuntimeError('simulated interruption after Git add')
            return result
        with patch.object(self.allocator, '_git', interrupted):
            with self.assertRaises(RuntimeError): self.allocator.allocate('run-2', 'bob')
        result = self.reopen().allocate('run-2', 'bob')
        self.assertEqual('ready', result['phase'])
        self.assertEqual(1, len(list(self.slots.iterdir())))
        self.assertEqual('run-2', result['run'])

    def test_interrupted_removal_recovers_without_global_pruning(self):
        _, _, path = self.pair(); self.allocator.release('run-2', 'bob')
        original = self.allocator._git
        def interrupted(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if args[:2] == ('worktree', 'remove'): raise RuntimeError('simulated interruption after Git remove')
            return result
        with patch.object(self.allocator, '_git', interrupted):
            with self.assertRaises(RuntimeError): self.allocator.reconcile()
        self.assertFalse(path.exists())
        self.assertEqual('removed', self.secondary(self.reopen().reconcile())['disposition'])
        self.assertTrue(self.repo.exists())

    def test_authority_and_binding_fail_before_git_effects(self):
        self.allocator.allocate('run-1', 'alice')
        self.error('CHECKOUT_BINDING_CONFLICT', lambda: self.allocator.allocate('run-1', 'bob'))
        self.allowed = False
        with patch.object(self.allocator, '_git', side_effect=AssertionError('must not run Git')):
            self.error('FORBIDDEN', lambda: self.allocator.allocate('run-2', 'bob'))
        self.assertEqual([], list(self.slots.iterdir()))

    def test_dirty_primary_and_replaced_paths_cannot_be_adopted(self):
        (self.repo / 'ignored.txt').write_text('human ignored work')
        self.error('PRIMARY_NOT_CLEAN', lambda: self.allocator.allocate('run-1', 'alice'))
        (self.repo / 'ignored.txt').unlink()
        self.pair(); self.allocator.release('run-2', 'bob')
        state = json.loads(self.allocator.manifest.read_text())
        key = next(k for k in state['slots'] if k != 'primary')
        path = Path(state['slots'][key]['path']); moved = self.slots / 'retained-original'
        path.rename(moved); path.symlink_to(moved, target_is_directory=True)
        self.assertEqual('retained', self.secondary(self.allocator.reconcile())['disposition'])
        self.assertTrue(path.is_symlink()); self.assertTrue(moved.exists())

    def test_malformed_store_is_rejected_before_mutation(self):
        self.pair()
        original = json.loads(self.allocator.manifest.read_text())
        for value in [[], {'version': 1}, {**original, 'slots': {'evil': {}}}]:
            self.allocator.manifest.write_text(json.dumps(value))
            self.error('INVALID_CHECKOUT_STORE', self.allocator.reconcile)
        self.assertEqual(1, len(list(self.slots.iterdir())))

    def test_filter_processes_unsupported_and_hooks_never_executed(self):
        hooks = self.repo / '.git/hooks'; hook = hooks / 'post-checkout'
        sentinel = self.root / 'hook-ran'
        hook.write_text('#!/bin/sh\ntouch ' + str(sentinel) + '\n'); hook.chmod(0o700)
        self.pair(); self.assertFalse(sentinel.exists())
        self.git(self.repo, 'config', 'filter.custom.smudge', 'false')
        self.error('UNSUPPORTED_GIT_FILTER', lambda: self.allocator.allocate('run-3', 'alice'))
        self.assertEqual(1, len(list(self.slots.iterdir())))

    def test_wrong_project_and_room_store_are_not_adopted(self):
        changed = deepcopy(self.config)
        changed['rooms'][0]['project']['id'] = 'other-project'
        allocator = self.supervisor.checkouts(io.StringIO(json.dumps(changed)))
        self.error('PROJECT_BINDING_CONFLICT', lambda: allocator.allocate('run-1', 'alice'))
        changed = deepcopy(self.config)
        changed['rooms'][0]['state_root'] += '-other'
        self.error('ROOM_MISMATCH', lambda: self.supervisor.checkouts(io.StringIO(json.dumps(changed))))
        self.assertEqual([], list(self.slots.iterdir()))

    def test_failed_creation_never_adopts_partial_or_foreign_content(self):
        self.allocator.allocate('run-1', 'alice')
        original = self.allocator._git
        def fail(path, *args, **kwargs):
            if args[:2] == ('worktree', 'add'):
                target = Path(args[-2]); target.mkdir(); (target / 'human').write_text('retain')
                raise LifecycleError('GIT_OBSERVATION_UNKNOWN')
            return original(path, *args, **kwargs)
        with patch.object(self.allocator, '_git', fail):
            self.error('GIT_OBSERVATION_UNKNOWN', lambda: self.allocator.allocate('run-2', 'bob'))
        self.error('CHECKOUT_RECONCILIATION_REQUIRED', lambda: self.reopen().allocate('run-2', 'bob'))
        self.assertEqual('retain', next(self.slots.iterdir()).joinpath('human').read_text())

    def test_git_observation_failure_retains_released_checkout(self):
        _, _, path = self.pair(); self.allocator.release('run-2', 'bob')
        original = self.allocator._git
        def fail(target, *args, **kwargs):
            if args[0] == 'status': raise LifecycleError('GIT_OBSERVATION_UNKNOWN')
            return original(target, *args, **kwargs)
        with patch.object(self.allocator, '_git', fail):
            self.assertEqual('retained', self.secondary(self.allocator.reconcile())['disposition'])
        self.assertTrue(path.exists())

    def test_primary_branch_change_requires_explicit_reconciliation(self):
        self.allocator.allocate('run-1', 'alice'); self.allocator.release('run-1', 'alice')
        self.git(self.repo, 'switch', '-c', 'human-changed-primary')
        self.error('PRIMARY_NOT_RECONCILED', lambda: self.allocator.allocate('run-2', 'bob'))
        self.assertEqual('human-changed-primary', self.git(self.repo, 'branch', '--show-current'))

    def test_actual_process_kill_after_git_effect_recovers_saved_intent(self):
        self.allocator.allocate('run-1', 'alice')
        program = '''import io,json,os,signal,sys
from uas.lifecycle import Supervisor
config=json.loads(sys.stdin.read())
s=Supervisor(config['deployment']['state_root'],'alpha',None,authorize=lambda *_:True,revoke=lambda *_:True)
a=s.checkouts(io.StringIO(json.dumps(config)),writer_quiescent=lambda *_:True)
original=a._git
operation=sys.argv[1]
def interrupted(path,*args,**kwargs):
 result=original(path,*args,**kwargs)
 if args[:2]==('worktree',operation): os.kill(os.getpid(),signal.SIGKILL)
 return result
a._git=interrupted
if operation=='add': a.allocate('run-2','bob')
else: a.reconcile()
'''
        for operation in ('add', 'remove'):
            if operation == 'remove': self.allocator.release('run-2', 'bob')
            result = subprocess.run(['/usr/bin/python3', '-c', program, operation],
                input=json.dumps(self.config), text=True, capture_output=True, timeout=10,
                env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root)})
            self.assertEqual(-9, result.returncode, result.stderr)
            if operation == 'add':
                restored = self.reopen().allocate('run-2', 'bob')
                self.assertEqual('ready', restored['phase'])
                self.assertEqual(1, len(list(self.slots.iterdir())))
            else:
                self.assertEqual('removed', self.secondary(self.reopen().reconcile())['disposition'])
                self.assertEqual([], list(self.slots.iterdir()))

    def test_registered_same_path_directory_replacement_is_retained(self):
        _, _, path = self.pair(); self.allocator.release('run-2', 'bob')
        original = self.slots / 'original-retained'; path.rename(original)
        # Same .git registration, branch and common-dir, but a different directory.
        import shutil
        shutil.copytree(original, path)
        self.assertEqual(self.git(original, 'rev-parse', '--git-common-dir'),
                         self.git(path, 'rev-parse', '--git-common-dir'))
        result = self.secondary(self.allocator.reconcile())
        self.assertEqual('FILESYSTEM_IDENTITY_MISMATCH', result['reason'])
        self.assertTrue(path.exists()); self.assertTrue(original.exists())

    def test_repository_metadata_same_path_replacement_fails_closed(self):
        self.pair()
        import shutil
        metadata = self.repo / '.git'; original = self.root / 'retained-git-metadata'
        metadata.rename(original); shutil.copytree(original, metadata)
        self.error('INVALID_CHECKOUT_STORE', self.allocator.reconcile)
        self.assertEqual(1, len(list(self.slots.iterdir())))

    def test_symlinked_git_metadata_is_not_ownership_evidence(self):
        _, _, path = self.pair(); self.allocator.release('run-2', 'bob')
        metadata = path / '.git'; original = self.root / 'git-pointer'
        metadata.rename(original); metadata.symlink_to(original)
        self.assertEqual('retained', self.secondary(self.allocator.reconcile())['disposition'])
        self.assertTrue(metadata.is_symlink()); self.assertTrue(path.exists())
        primary_metadata = self.repo / '.git'; saved = self.root / 'primary-git'
        primary_metadata.rename(saved); primary_metadata.symlink_to(saved, target_is_directory=True)
        self.error('INVALID_PATH', self.allocator.reconcile)

    def test_release_and_cleanup_require_fresh_trusted_quiescence(self):
        _, _, path = self.pair()
        self.quiescent = False
        self.error('WRITER_NOT_QUIESCENT', lambda: self.allocator.release('run-2', 'bob'))
        self.quiescent = True; self.allocator.release('run-2', 'bob')
        self.quiescent = False
        self.assertEqual('WRITER_NOT_QUIESCENT', self.secondary(self.allocator.reconcile())['reason'])
        self.assertTrue(path.exists())
        no_observer = self.supervisor.checkouts(io.StringIO(json.dumps(self.config)))
        self.assertEqual('WRITER_NOT_QUIESCENT', self.secondary(no_observer.reconcile())['reason'])

    def test_primary_reuse_requires_fresh_quiescence_and_stopped_reservation(self):
        self.allocator.allocate('run-1', 'alice')
        self.allocator.release('run-1', 'alice')
        before = self.allocator.manifest.read_bytes()
        self.quiescent = False
        self.error('WRITER_NOT_QUIESCENT', lambda: self.allocator.allocate('run-2', 'bob'))
        self.assertEqual(before, self.allocator.manifest.read_bytes())
        self.error('ROOM_NOT_STOPPED', lambda: self.allocator.reserve('run-2', 'bob'))
        self.supervisor.stop()
        self.error('WRITER_NOT_QUIESCENT', lambda: self.allocator.reserve('run-2', 'bob'))
        self.quiescent = True
        reserved = self.allocator.reserve('run-2', 'bob')
        self.assertEqual('primary', reserved['slot'])
        self.assertTrue(reserved['active'])
        self.assertEqual(reserved, self.reopen().reserve('run-2', 'bob'))
        self.supervisor.start(self.spec)
        self.assertEqual(reserved, self.reopen().allocate('run-2', 'bob'))

    def test_observer_failure_retains_and_does_not_release(self):
        _, _, path = self.pair()
        self.allocator.writer_quiescent = lambda *_: (_ for _ in ()).throw(OSError('unknown'))
        before = self.allocator.manifest.read_bytes()
        self.error('WRITER_NOT_QUIESCENT', lambda: self.allocator.release('run-2', 'bob'))
        self.assertEqual(before, self.allocator.manifest.read_bytes())
        self.assertTrue(path.exists())

    def test_final_writer_change_before_quiescence_is_reobserved_before_cleanup_or_reuse(self):
        _, _, path = self.pair()
        self.allocator.release('run-2', 'bob')
        def final_write(*_):
            (path / 'ignored.txt').write_text('last writer data before stopped')
            return True
        self.allocator.writer_quiescent = final_write
        self.assertEqual('DIRTY_OR_UNTRACKED_OR_IGNORED', self.secondary(self.allocator.reconcile())['reason'])
        self.assertEqual('last writer data before stopped', (path / 'ignored.txt').read_text())
        self.allocator.writer_quiescent = lambda *_: True
        self.allocator.release('run-1', 'alice')
        def final_primary_write(*_):
            (self.repo / 'ignored.txt').write_text('last primary writer data')
            return True
        self.allocator.writer_quiescent = final_primary_write
        self.error('PRIMARY_NOT_RECONCILED', lambda: self.allocator.allocate('run-3', 'alice'))
        self.assertEqual('last primary writer data', (self.repo / 'ignored.txt').read_text())

    def test_writable_backend_requires_durable_guard_and_cannot_downgrade_on_restart(self):
        from uas.checkout_writers import DockerCheckoutBackend, DockerCheckoutWriters
        backend = DockerCheckoutBackend(self.repo, self.slots)
        supervisor = Supervisor(self.root / 'control', self.room['id'], backend,
                                authorize=lambda *_: True, revoke=lambda *_: True)
        source = lambda: io.StringIO(json.dumps(self.config))
        self.error('INVALID_WRITER_GUARD', lambda: supervisor.checkouts(source(), writer_quiescent=lambda *_: True))
        allocator = supervisor.checkouts(source())  # Concrete guard is automatic.
        self.assertIsInstance(allocator.writer_guard, DockerCheckoutWriters)
        running = {'Id': 'a' * 64, 'State': {'Running': True, 'Status': 'running', 'Pid': 123,
            'Paused': False, 'Restarting': False, 'Dead': False,
            'StartedAt': '2026-10-27T14:00:00Z', 'FinishedAt': '0001-01-01T00:00:00Z'}}
        with patch.object(backend, 'admit', return_value=running):
            primary = allocator.allocate('run-1', 'alice')
            secondary = allocator.allocate('run-2', 'bob')
            self.assertEqual(primary, allocator.allocate('run-1', 'alice'))
        self.assertEqual('a' * 64, secondary['writer_scope']['container'])
        before = allocator.manifest.read_bytes()
        with patch.object(backend, '_inspect_object', return_value=running):
            self.error('WRITER_NOT_QUIESCENT', lambda: allocator.release('run-2', 'bob'))
        self.assertEqual(before, allocator.manifest.read_bytes())
        changed = deepcopy(running); changed['Id'] = 'b' * 64
        with patch.object(backend, 'admit', return_value=changed):
            self.error('WRITER_OBSERVATION_UNKNOWN', lambda: allocator.allocate('run-2', 'bob'))
        self.assertEqual(before, allocator.manifest.read_bytes())
        stopped = deepcopy(running)
        stopped['State'].update(Running=False, Status='exited', Pid=0, FinishedAt='2026-10-27T14:01:00Z')
        with patch.object(backend, '_inspect_object', return_value=stopped):
            supervisor.checkouts(source()).release('run-2', 'bob')
        # Reopening with the old synthetic callback cannot erase the guard.
        legacy = self.reopen()
        self.assertEqual('WRITER_NOT_QUIESCENT', self.secondary(legacy.reconcile())['reason'])
        self.assertTrue(Path(secondary['path']).is_dir())
        with patch.object(backend, '_inspect_object', return_value=stopped):
            self.assertEqual('removed', self.secondary(supervisor.checkouts(source()).reconcile())['disposition'])

    def test_guard_does_not_adopt_legacy_unscoped_allocation(self):
        from uas.checkout_writers import DockerCheckoutBackend
        self.pair()
        supervisor = Supervisor(self.root / 'control', self.room['id'], DockerCheckoutBackend(self.repo, self.slots),
                                authorize=lambda *_: True, revoke=lambda *_: True)
        allocator = supervisor.checkouts(io.StringIO(json.dumps(self.config)))
        with patch.object(supervisor.backend, '_inspect_object', side_effect=AssertionError('must not infer ownership')):
            self.error('WRITER_NOT_QUIESCENT', lambda: allocator.release('run-2', 'bob'))
        self.assertTrue(self.secondary(allocator.status())['active'])

    def test_store_capacity_rejects_before_store_or_git_effects(self):
        self.pair()
        before = self.allocator.manifest.read_bytes()
        worktrees = self.git(self.repo, 'worktree', 'list', '--porcelain')
        for limits in ({'MAX_SLOTS': 2}, {'MAX_STORE_BYTES': len(before) + 1}):
            with self.subTest(limits=limits), patch.multiple('uas.checkouts', **limits):
                self.error('CHECKOUT_CAPACITY_EXCEEDED', lambda: self.allocator.allocate('run-3', 'alice'))
                self.assertEqual(before, self.allocator.manifest.read_bytes())
                self.assertEqual(worktrees, self.git(self.repo, 'worktree', 'list', '--porcelain'))
                self.assertEqual(2, len(self.allocator.status()))
        # Capacity failure does not destroy or erase ownership tombstones/state.
        self.assertEqual(2, len(self.reopen().status()))

    def test_capacity_reserves_post_create_identity_before_git_add(self):
        self.allocator.allocate('run-1', 'alice')
        before = self.allocator.manifest.read_bytes()
        save = self.allocator._save
        def narrow_capacity(state):
            from uas.lifecycle import _canonical
            # Enough for raw creating/null identity but not the completed record.
            with patch('uas.checkouts.MAX_STORE_BYTES', len(_canonical(state).encode('utf-8')) + 1):
                save(state)
        with patch.object(self.allocator, '_save', narrow_capacity):
            self.error('CHECKOUT_CAPACITY_EXCEEDED', lambda: self.allocator.allocate('run-2', 'bob'))
        self.assertEqual(before, self.allocator.manifest.read_bytes())
        self.assertEqual([], list(self.slots.iterdir()))
