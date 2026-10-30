"""Real disposable Library Git/service with the owning file-backed Room supervisor.

Room resources are simulated, not Docker/VM qualification. Library publication,
records, provider subprocess and host-local control owners are real.
"""
import unittest
import test_library_controls as fixture
from lifecycle_support import FileFixtureBackend
from uas import library
from uas.lifecycle import FixtureSpec, Supervisor
from uas.library_controls import Controls


class ArchiveFixture:
    def setup_archive(self):
        self.fx = fixture.ControlsTests('test_operational_ack_no_git_or_model_and_exact_retry')
        self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.fx.principal = library.LocalHuman('bruno','human-actor','grant-archive',
            lambda p,key,action:self.fx.allowed and key == self.fx.source.scope.project_identity
                and action in ('library-archive','library-restore'), lambda:self.fx.connected)

    def roundtrip(self):
        source = self.fx.source
        before = source.contents('pending/index.md')
        identity, path = source.scope.project_identity, source.scope.project_path
        value = self.fx.value('archive','archive-roundtrip')
        first = self.fx.send(value)
        self.assertEqual(first['outcome'],'observed',first)
        self.assertEqual(first['result']['outcome'],'COMMITTED')
        self.assertEqual(first['result']['publication']['commit_sha'],source.head())
        self.assertIn('Library state: archived',source.contents('index.md'))
        marker = self.fx.fx.fixture.marker
        self.assertTrue(marker.exists()); marker.unlink()
        count = source.count()
        self.assertEqual(self.fx.send(value),first)
        self.assertEqual(source.count(),count); self.assertFalse(marker.exists())
        self.assertIn(self.fx.fx.fixture.q,source.contents('pending/index.md'))
        restore = self.fx.send(self.fx.value('restore','restore-roundtrip'))
        self.assertEqual(restore['outcome'],'observed',restore)
        self.assertEqual(restore['result']['publication']['commit_sha'],source.head())
        self.assertIn('Library state: active',source.contents('index.md'))
        self.assertFalse(marker.exists())
        self.assertEqual((source.scope.project_identity,source.scope.project_path),(identity,path))
        self.assertIn(self.fx.fx.fixture.q,source.contents('pending/index.md'))
        self.assertNotEqual(before,source.contents('pending/index.md'))  # retained, now parked by final attempt

    def failed_final(self):
        self.fx.fx.mode = 'error'
        value = self.fx.value('archive','archive-failed-final')
        first = self.fx.send(value)
        self.assertEqual(first['outcome'],'observed',first)
        self.assertEqual(first['result']['outcome'],'COMMITTED')
        marker = self.fx.fx.fixture.marker
        self.assertTrue(marker.exists());marker.unlink()
        count = self.fx.source.count()
        self.assertIn(self.fx.fx.fixture.q,self.fx.source.contents('pending/index.md'))
        self.assertEqual(self.fx.send(value),first)
        self.assertFalse(marker.exists());self.assertEqual(self.fx.source.count(),count)
        return value, first

    def authority(self):
        value = self.fx.value('archive','archive-authority')
        head = self.fx.source.head()
        self.fx.allowed = False
        self.assertEqual(self.fx.send(value)['error'],'FORBIDDEN')
        self.assertEqual(self.fx.source.head(),head)
        self.fx.allowed = True
        first = self.fx.send(value)
        self.assertEqual(first['outcome'],'observed',first)
        self.fx.allowed = False
        self.assertEqual(self.fx.send(value)['error'],'FORBIDDEN')
        self.assertEqual(self.fx.source.head(),first['result']['publication']['commit_sha'])


class ArchiveIntegrationTests(ArchiveFixture, unittest.TestCase):
    def setUp(self): self.setup_archive()
    def test_service_archive_restore_exact_retry(self): self.roundtrip()
    def test_current_human_authority_for_action_and_receipt(self): self.authority()
    def test_failed_final_stays_archived_across_service_restart(self):
        value, first = self.failed_final()
        self.fx.fx.mode = 'success'
        self.fx.fx.restart()
        self.fx.service = self.fx.fx.service
        self.fx.controls = Controls(self.fx.service)
        self.assertEqual(self.fx.send(value),first)
        self.assertIsNone(self.fx.service.tick())
        self.assertFalse(self.fx.fx.fixture.marker.exists())
        self.assertIn('Library state: archived',self.fx.source.contents('index.md'))

    def test_room_stop_destroy_preserves_canonical_and_local_library_bytes(self):
        source = self.fx.source
        root = source.base/'room-control'
        backend = FileFixtureBackend(source.base/'room-resources')
        supervisor = Supervisor(root,'alpha',backend,authorize=lambda *_:True,revoke=backend.revoke)
        workspace = source.base/'project-workspace';workspace.mkdir()
        spec = FixtureSpec('alpha','project',(str(workspace),),'sha256:'+'a'*64,
            'sha256:'+'b'*64,'sha256:'+'c'*64)
        self.assertEqual(supervisor.start(spec)['phase'],'running')
        def snapshot():
            return ({str(p.relative_to(source.target)):p.read_bytes()
                for p in source.target.rglob('*') if p.is_file()},source.records.read_bytes())
        before = snapshot()
        self.assertEqual(supervisor.stop()['phase'],'stopped')
        self.assertEqual(snapshot(),before)
        self.assertEqual(supervisor.destroy()['phase'],'destroyed')
        self.assertEqual(snapshot(),before)
        self.fx.fx.available = False  # destroyed Room Hub unavailable; separate owner still works
        result = self.fx.send(self.fx.value('archive','absent-room'))
        self.assertEqual(result['outcome'],'observed',result)
        self.assertIn('Library state: archived',source.contents('index.md'))
