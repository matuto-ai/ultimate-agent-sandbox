"""Real disposable Git registration, refusal, retry and recovery checks."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import library_support as support
from test_library_git import git, Interrupted
from uas import library, library_bundle, library_gate
from uas.library_git import LibraryGit
from uas.library_records import LibraryRecords
from uas.library_registration import Registrar, skeleton


class LocalTransport(LibraryGit):
    """Map the admitted SSH name to disposable local Git; no network/auth proof."""
    def _environment(self):
        env = super()._environment()
        env.update({'GIT_ALLOW_PROTOCOL': 'file', 'GIT_CONFIG_COUNT': '1',
                    'GIT_CONFIG_KEY_0': 'url.'+str(self.records_path.parent/'canonical.git')+'.insteadOf',
                    'GIT_CONFIG_VALUE_0': self.target})
        return env


class LostAckTransport(Interrupted, LocalTransport):
    pass


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.target = self.base / 'canonical.git'
        git(self.base, 'init', '--bare', '-q', str(self.target))
        self.records = self.base / 'records.db'
        LibraryRecords(self.records, 'deployment-1').close()
        document = support.document()
        document['repository']['target'] = 'ssh://git@example.test/library.git'
        document['repository']['branch'] = 'main'
        self.settings = support.settings(document)
        self.scope = self.make_scope()
        self.fresh = self.scope
        self.publisher = self.make_publisher()
        self.publisher.startup()
        self.addCleanup(self.publisher.close)
        self.registrar = Registrar(self.publisher, current_scope=lambda: self.fresh)

    def make_scope(self, project='alpha', repository='acme/alpha', source='1001'):
        return library.human_scope(support.session(('library-register',)),
                                   binding=support.binding(project, repository, source), kind='register')

    def make_publisher(self, cls=LocalTransport, **kwargs):
        return cls(self.base / 'service', records_path=self.records, deployment_id='deployment-1',
                   target=self.settings['repository']['target'], branch='main', **kwargs)

    def operation(self, identity='op-1', scope=None, at=support.AT):
        return library.action(scope or self.scope, self.settings, kind='register',
                              operation_id=identity, request_id='request-'+identity, payload={}, at=at)

    def register(self, operation=None):
        return self.registrar.register(operation or self.operation(), self.settings)

    def head(self):
        return git(self.target, 'rev-parse', 'refs/heads/main').strip()

    def count(self):
        return len(git(self.target, 'rev-list', 'refs/heads/main').split())

    def files(self):
        return git(self.target, 'ls-tree', '-r', '--name-only', self.head()).splitlines()

    def mutate(self, files):
        """Trusted fixture producer; arbitrary canonical corruption is intentional."""
        work = self.base / 'fixture'
        if not work.exists():
            git(self.base, 'clone', '-q', '-b', 'main', str(self.target), str(work))
        else:
            git(work, 'pull', '-q', '--ff-only')
        for path, data in files.items():
            file = work / path
            file.parent.mkdir(parents=True, exist_ok=True)
            if data is None:
                file.unlink()
            else:
                file.write_bytes(data)
        git(work, 'add', '-A')
        git(work, 'commit', '-q', '-m', 'fixture')
        git(work, 'push', '-q', 'origin', 'main')

    def root(self):
        return 'projects/' + self.scope.project_path + '/index.md'

    def root_bytes(self):
        return git(self.target, 'show', self.head()+':'+self.root()).encode()

    def refusal(self, code, operation=None):
        before = self.head()
        with self.assertRaises(library.LibraryError) as raised:
            self.register(operation)
        self.assertEqual(code, raised.exception.code)
        self.assertEqual(before, self.head())

    def test_initial_tree_exact_six_files_content_and_published_receipt(self):
        result = self.register()
        prefix = 'projects/' + self.scope.project_path
        self.assertEqual(set(self.files()), {prefix+'/'+name for name in library_bundle.REQUIRED})
        self.assertTrue(result.created)
        self.assertEqual(result.commit_sha, self.head())
        self.assertEqual(result.state, 'active')
        self.assertIsNone(result.receipt['projection'])
        self.assertEqual(result.receipt['publication']['commit_sha'], self.head())
        self.assertEqual(self.count(), 1)
        for name in library_bundle.REQUIRED:
            data = git(self.target, 'show', self.head()+':'+prefix+'/'+name)
            if name.endswith('index.md'):
                self.assertIn(library_gate.NOTICE, data)
            if name == 'log.md':
                self.assertEqual(data.count('**Initialization**'), 1)
                self.assertIn('## 2026-10-28', data)
        self.assertIn('Source identity: github.com/1001', self.root_bytes().decode())
        with LibraryRecords(self.records, 'deployment-1') as records:
            self.assertIsNotNone(records.record('op-1', project_identity=self.scope.project_identity)['receipt'])

    def test_exact_and_new_request_retries_leave_commit_and_log_unchanged(self):
        first = self.register()
        for operation in (self.operation(), self.operation('op-2', at='2026-11-01T00:00:00+00:00')):
            again = self.register(operation)
            self.assertFalse(again.created)
            self.assertEqual(again.commit_sha, first.commit_sha)
        self.assertEqual(self.count(), 1)

    def test_other_project_isolation_and_unrelated_data_preserved(self):
        first = self.register()
        self.mutate({'README.md': b'operational docs\n'})
        beta = self.make_scope('beta', 'other/beta', '2002')
        self.fresh = beta
        result = self.register(self.operation('op-beta', beta))
        self.assertNotEqual(result.commit_sha, first.commit_sha)
        self.assertEqual(len(self.files()), 13)
        self.assertEqual(git(self.target, 'show', self.head()+':README.md'), 'operational docs\n')
        self.fresh = self.scope
        again = self.register()
        self.assertEqual(again.commit_sha, first.commit_sha)
        self.assertEqual(again.observed_sha, self.head())
        self.assertEqual(self.count(), 3)

    def test_conflicting_identity_is_not_overwritten(self):
        self.register()
        other = self.make_scope(source='different')
        self.fresh = other
        self.refusal('MISSING_SOURCE_IDENTITY', self.operation('other', other))

    def test_partial_bundle_is_not_repaired(self):
        self.register()
        self.mutate({self.root().replace('index.md','log.md'): None})
        self.refusal('MALFORMED_EXISTING_BUNDLE')

    def test_malformed_bundle_is_not_repaired(self):
        self.register()
        self.mutate({self.root(): b'broken\n'})
        with self.assertRaises(library.LibraryError): self.register()
        self.assertEqual(self.root_bytes(), b'broken\n')

    def test_archived_matching_registration_does_not_restore_or_commit(self):
        self.register()
        self.mutate({self.root(): self.root_bytes()+b'\nLibrary state: archived\n'})
        before = self.head()
        for operation in (self.operation(), self.operation('archive-retry')):
            result = self.register(operation)
            self.assertEqual(result.state, 'archived')
            self.assertFalse(result.created)
            self.assertEqual(result.observed_sha, before)
        self.assertEqual(self.head(), before)
        self.assertEqual(self.count(), 2)

    def test_invalid_or_duplicate_lifecycle_state_fails_closed(self):
        self.register()
        root = self.root_bytes()
        for line in (b'Library state: unknown\n', b'Library state: active\nLibrary state: archived\n'):
            self.mutate({self.root(): root+b'\n'+line})
            self.refusal('INVALID_PROJECT_STATE')

    def test_tolerated_reader_bytes_unchanged_on_retry(self):
        self.register()
        self.mutate({self.root(): self.root_bytes()+b'\nUnknown reader note.\n'})
        before = self.root_bytes()
        result = self.register(self.operation('retry'))
        self.assertFalse(result.created)
        self.assertEqual(before, self.root_bytes())
        self.assertEqual(self.count(), 2)

    def test_gate_rejection_leaves_no_canonical_commit(self):
        with patch('uas.library_registration.library_gate.validate', side_effect=library.LibraryError('POLICY_REFUSED')):
            with self.assertRaises(library.LibraryError) as raised: self.register()
        self.assertEqual(raised.exception.code, 'POLICY_REFUSED')
        self.assertEqual(git(self.target, 'for-each-ref', '--format=%(refname)'), '')

    def test_current_authority_required_before_reads(self):
        self.register()
        self.fresh = None
        with patch.object(self.publisher, 'project_snapshot', wraps=self.publisher.project_snapshot) as read:
            self.refusal('LIBRARY_AUTHENTICATION_REQUIRED')
        read.assert_not_called()

    def test_revocation_after_snapshot_prevents_publication(self):
        snapshot = self.publisher.project_snapshot
        def revoked(*args, **kwargs):
            result = snapshot(*args, **kwargs)
            self.fresh = None
            return result
        with patch.object(self.publisher, 'project_snapshot', side_effect=revoked):
            with self.assertRaises(library.LibraryError) as raised: self.register()
        self.assertEqual(raised.exception.code, 'LIBRARY_AUTHENTICATION_REQUIRED')
        self.assertEqual(git(self.target, 'for-each-ref', '--format=%(refname)'), '')

    def test_participant_or_changed_payload_cannot_register(self):
        with self.assertRaises(library.LibraryError): self.register(support.capture())
        with self.assertRaises(library.LibraryError): self.register(replace(self.operation(), payload={'path':'x'}))
        self.assertEqual(git(self.target, 'for-each-ref', '--format=%(refname)'), '')

    def test_operation_id_reuse_conflict_even_when_bundle_exists(self):
        self.register()
        self.refusal('ID_CONFLICT', self.operation(at='2026-11-01T00:00:00+00:00'))

    def test_parent_file_collision_is_not_replaced(self):
        self.register()
        self.mutate({'projects/github.com/other': b'valuable parent content\n'})
        other = self.make_scope('beta', 'other/beta', '2002')
        self.fresh = other
        self.refusal('UNSUPPORTED_PROJECT_ENTRY', self.operation('other', other))
        self.assertEqual(git(self.target, 'show', self.head()+':projects/github.com/other'),
                         'valuable parent content\n')

    def test_revoked_during_publication_fetch_cannot_commit(self):
        fetch = self.publisher._fetch
        calls = []
        def revoked():
            result = fetch()
            calls.append(1)
            if len(calls) == 2:
                self.fresh = None
            return result
        with patch.object(self.publisher, '_fetch', side_effect=revoked):
            with self.assertRaises(library.LibraryError) as raised: self.register()
        self.assertEqual(raised.exception.code, 'LIBRARY_AUTHENTICATION_REQUIRED')
        self.assertEqual(git(self.target, 'for-each-ref', '--format=%(refname)'), '')

    def test_immutable_identity_cannot_be_registered_at_second_coordinates(self):
        self.register()
        moved = self.make_scope('alpha', 'other/alpha', '1001')
        self.fresh = moved
        self.refusal('PROJECT_COORDINATE_CONFLICT', self.operation('move', moved))
        self.assertEqual(self.count(), 1)

    def test_parent_file_collision_after_snapshot_cannot_be_destroyed(self):
        self.register()
        other = self.make_scope('beta', 'other/beta', '2002')
        self.fresh = other
        snapshot = self.publisher.project_snapshot
        def raced(*args, **kwargs):
            result = snapshot(*args, **kwargs)
            self.mutate({'projects/github.com/other': b'valuable\n'})
            return result
        with patch.object(self.publisher, 'project_snapshot', side_effect=raced):
            with self.assertRaises(library.LibraryError) as raised:
                self.register(self.operation('other', other))
        self.assertEqual(raised.exception.code, 'UNSUPPORTED_PROJECT_ENTRY')
        self.assertEqual(git(self.target, 'show', self.head()+':projects/github.com/other'), 'valuable\n')

    def test_missing_bundle_after_lost_receipt_is_not_historical_success(self):
        with patch.object(LibraryRecords, 'finish', side_effect=OSError('crash')):
            with self.assertRaises(OSError): self.register()
        self.mutate({**{path: None for path in self.files()}, 'README.md': b'valuable\n'})
        self.refusal('REGISTRATION_MISSING')
        self.assertEqual(self.files(), ['README.md'])

    def test_definite_refusals_finish_and_do_not_exhaust_pending_capacity(self):
        with patch('uas.library_records.MAX_PENDING', 2):
            for number in range(4):
                with patch('uas.library_registration.library_gate.validate',
                           side_effect=library.LibraryError('POLICY_REFUSED')):
                    with self.assertRaises(library.LibraryError) as raised:
                        self.register(self.operation('refused-'+str(number)))
                self.assertEqual(raised.exception.code, 'POLICY_REFUSED')
            with LibraryRecords(self.records, 'deployment-1') as records:
                self.assertEqual(records.pending(), [])
            # Exact retry retains the same refusal, rather than re-executing
            # corrected input under an already terminal identity.
            with self.assertRaises(library.LibraryError) as raised:
                self.register(self.operation('refused-0'))
            self.assertEqual(raised.exception.code, 'POLICY_REFUSED')
            self.assertTrue(self.register(self.operation('new')).created)

    def test_transient_read_failure_does_not_terminalize_uncertain_publication(self):
        with patch.object(LibraryRecords, 'finish', side_effect=OSError('crash')):
            with self.assertRaises(OSError): self.register()
        sha = self.head()
        with patch.object(self.publisher, 'project_snapshot',
                          side_effect=library.LibraryError('PUBLICATION_UNAVAILABLE')):
            with self.assertRaises(library.LibraryError): self.register()
        with LibraryRecords(self.records, 'deployment-1') as records:
            self.assertIsNone(records.record('op-1', project_identity=self.scope.project_identity)['receipt'])
        self.assertEqual(self.register().commit_sha, sha)
        self.assertEqual(self.count(), 1)

    def test_concurrent_same_request_uses_one_commit_and_receipt(self):
        import threading
        outcomes, failures = [], []
        def run():
            try: outcomes.append(self.register())
            except Exception as error: failures.append(error)
        workers = [threading.Thread(target=run) for _ in range(4)]
        for worker in workers: worker.start()
        for worker in workers: worker.join(10)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(failures, [])
        self.assertEqual(len(outcomes), 4)
        self.assertEqual({result.commit_sha for result in outcomes}, {self.head()})
        self.assertEqual(self.count(), 1)

    def test_target_mismatch_rejected(self):
        self.register()
        self.publisher.target = '/elsewhere'
        with self.assertRaises(library.LibraryError) as raised: self.register()
        self.assertEqual(raised.exception.code, 'TARGET_MISMATCH')

    def test_lost_push_ack_reconciles_and_retry_does_not_duplicate(self):
        self.publisher.close()
        publisher = self.make_publisher(LostAckTransport, lose_push=True)
        publisher.startup()
        self.addCleanup(publisher.close)
        self.registrar = Registrar(publisher, current_scope=lambda:self.fresh)
        result = self.register()
        self.assertEqual(result.commit_sha, self.head())
        self.assertEqual(self.register().commit_sha, result.commit_sha)
        self.assertEqual(self.count(), 1)

    def test_receipt_loss_after_publication_recovers_without_new_commit(self):
        with patch.object(LibraryRecords, 'finish', side_effect=OSError('crash')):
            with self.assertRaises(OSError): self.register()
        sha = self.head()
        self.publisher.close()
        self.publisher = self.make_publisher()
        self.publisher.startup()
        self.addCleanup(self.publisher.close)
        self.registrar = Registrar(self.publisher, current_scope=lambda:self.fresh)
        result = self.register()
        self.assertEqual(result.commit_sha, sha)
        self.assertFalse(result.created)
        self.assertEqual(self.count(), 1)

    def test_oversized_snapshot_fails_without_overwrite(self):
        self.register()
        self.mutate({self.root(): self.root_bytes()+b'x'*65537})
        self.refusal('BUNDLE_TOO_LARGE')

    def test_symlink_entry_fails_without_dereference(self):
        self.register()
        self.mutate({'README.md':b'docs'})
        work = self.base / 'fixture'
        (work / 'projects/github.com/acme/alpha/evil').symlink_to('/etc/passwd')
        git(work,'add','-A');git(work,'commit','-qm','symlink');git(work,'push','-q','origin','main')
        self.refusal('UNSUPPORTED_PROJECT_ENTRY')


if __name__ == '__main__': unittest.main()
