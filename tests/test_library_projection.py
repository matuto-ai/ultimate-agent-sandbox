"""T07 actual disposable Git, supervisor projection and pinned filesystem reads."""
from pathlib import Path
import json
import os
import stat
import threading
import unittest
from unittest.mock import patch

import library_support as support
import test_library_registration as registration_tests
from uas import library, library_bundle, library_gate
from uas.library_projection import ProjectProjection, read_projection, STATE, CURRENT, MANIFEST
from uas.library_registration import Registrar


class ProjectionTests(unittest.TestCase):
    # Reuse fixture helpers, not imported unittest cases (no duplicate inventory).
    setUp = registration_tests.RegistrationTests.setUp
    make_publisher = registration_tests.RegistrationTests.make_publisher
    operation = registration_tests.RegistrationTests.operation
    register = registration_tests.RegistrationTests.register
    head = registration_tests.RegistrationTests.head
    count = registration_tests.RegistrationTests.count
    mutate = registration_tests.RegistrationTests.mutate
    root = registration_tests.RegistrationTests.root
    root_bytes = registration_tests.RegistrationTests.root_bytes

    def make_scope(self, project='alpha', repository='acme/alpha', source='1001'):
        reference = self.base / project / 'reference'
        reference.mkdir(mode=0o755, parents=True, exist_ok=True)
        binding = library.project_binding({'id': project, 'repository': repository,
                                          'roots': {'reference': str(reference)}}, source_identity=source)
        return library.human_scope(support.session(('library-register',)), binding=binding, kind='register')

    def projection(self, scope=None, start=False, clock=None):
        scope = scope or self.scope
        worker = ProjectProjection(self.publisher, scope, self.settings,
                                   current_scope=lambda: scope, clock=clock or (lambda: support.AT))
        self.addCleanup(worker.close)
        if start:
            worker.start()
            self.assertTrue(worker.wait_idle())
        return worker

    def change(self, suffix=b'\nA new observation.\n'):
        self.mutate({self.root(): self.root_bytes() + suffix})
        return self.head()

    def test_first_absent_bundle_and_null_manifest_no_fabricated_freshness(self):
        worker = self.projection(start=True)
        view = worker.read()
        self.assertEqual(dict(view.manifest), {'version': 1, 'project_id': 'alpha',
            'project_identity': 'github.com/1001', 'commit_sha': None, 'published_at': None})
        self.assertEqual(dict(view.files), {})
        self.assertFalse(Path(self.scope.reference_root).exists())
        self.assertEqual(json.loads((worker.root / MANIFEST).read_text()), dict(view.manifest))
        self.assertEqual(worker.last_error, 'PROJECT_NOT_REGISTERED')
        self.assertEqual(worker.visibility(), {'commit_sha': None, 'visible': False})

    def test_registration_refresh_hook_exact_bytes_and_fixed_native_paths(self):
        worker = self.projection(start=True)
        result = self.register()
        self.assertTrue(worker.wait_idle())
        view = worker.read()
        self.assertEqual(view.manifest['commit_sha'], result.commit_sha)
        _, tree = self.publisher.project_snapshot(self.scope, self.settings, current=lambda: None)
        prefix = 'projects/' + self.scope.project_path + '/'
        self.assertEqual(dict(view.files), {path[len(prefix):]:data for path,data in tree.files.items()})
        for name, data in view.files.items():
            self.assertEqual((Path(self.scope.reference_root) / name).read_bytes(), data)
        self.assertEqual(worker.visibility(result.commit_sha), {'commit_sha': result.commit_sha,'visible':True})
        self.assertIsNone(result.receipt['projection'])

    def test_startup_and_transport_reconnect_refresh_current_canonical_head(self):
        first = self.register()
        worker = self.projection(start=True)
        self.assertEqual(worker.read().manifest['commit_sha'], first.commit_sha)
        second = self.change()
        self.publisher.reconnect()
        self.assertTrue(worker.wait_idle())
        self.assertEqual(worker.read().manifest['commit_sha'], second)
        worker.close()
        third = self.change(b'\nRestart observation.\n')
        restored = self.projection(start=True)
        self.assertEqual(restored.read().manifest['commit_sha'], third)

    def test_failed_refresh_preserves_content_manifest_and_original_timestamp(self):
        self.register()
        times = iter([support.AT, '2026-10-30T03:00:00+00:00'])
        worker = self.projection(clock=lambda: next(times))
        self.assertTrue(worker.refresh())
        before = worker.read()
        self.change()
        with patch.object(worker, '_stage', side_effect=OSError('disk full, secret not emitted')):
            self.assertFalse(worker.refresh())
        after = worker.read()
        self.assertEqual(after, before)
        self.assertEqual(worker.last_error, 'PROJECTION_UNAVAILABLE')
        self.assertEqual(len(list((worker.root / STATE).glob('?' * 32))), 1)

    def test_failed_first_refresh_does_not_install_partial_or_empty_bundle(self):
        worker = self.projection()
        self.register()
        with patch('uas.library_projection._write', side_effect=OSError('full')):
            self.assertFalse(worker.refresh())
        self.assertIsNone(worker.read().manifest['commit_sha'])
        self.assertFalse(Path(self.scope.reference_root).exists())

    def test_rename_failure_keeps_last_pair_and_reclaims_staging(self):
        self.register()
        worker = self.projection(); self.assertTrue(worker.refresh())
        before = worker.read(); self.change()
        with patch('uas.library_projection.os.replace', side_effect=OSError('rename failed')):
            self.assertFalse(worker.refresh())
        self.assertEqual(worker.read(), before)
        self.assertEqual(len(list((worker.root / STATE).glob('?' * 32))), 1)

    def test_no_timestamp_renewal_for_same_commit(self):
        self.register()
        worker = self.projection(); worker.refresh()
        before = worker.read()
        worker.clock = lambda: '2026-12-01T00:00:00+00:00'
        self.assertTrue(worker.refresh())
        self.assertEqual(worker.read(), before)

    def test_project_binding_and_two_distinguishable_projections(self):
        alpha = self.projection(start=True)
        self.register(); self.assertTrue(alpha.wait_idle())
        before = alpha.read()
        beta = self.make_scope('beta','other/beta','2002')
        other = self.projection(beta, start=True)
        self.fresh = beta
        result = self.registrar.register(self.operation('op-beta', beta), self.settings)
        self.assertTrue(other.wait_idle())
        self.assertEqual(other.read().manifest['commit_sha'], result.commit_sha)
        self.assertIn(b'github.com/2002', other.read().files['index.md'])
        self.assertEqual(alpha.read(), before)
        self.assertNotIn(b'github.com/2002', b''.join(alpha.read().files.values()))
        # A malicious trusted-binding mix cannot read or repin another Project.
        wrong = library.human_scope(support.session(('library-register',)), binding={
            'project_id': beta.project_id, 'project_identity': beta.project_identity,
            'project_path': beta.project_path, 'reference_root': self.scope.reference_root}, kind='register')
        with self.assertRaises(library.LibraryError): read_projection(wrong,self.settings)

    def test_caller_source_or_destination_payload_is_not_admitted(self):
        for payload in ({'reference_root':'/tmp/other'}, {'source':'projects/other'}, {'snapshot_path':'/tmp/x'}):
            with self.assertRaises(library.LibraryError):
                library.action(self.scope,self.settings,kind='register', operation_id='bad',request_id='bad',
                               payload=payload,at=support.AT)

    def test_projection_files_are_nonwritable_and_contain_no_git_or_service_paths(self):
        self.register(); worker = self.projection(); worker.refresh()
        for path in Path(self.scope.reference_root).rglob('*'):
            self.assertFalse(path.stat().st_mode & 0o222, path)
        self.assertFalse((Path(self.scope.reference_root)/'.git').exists())
        self.assertFalse((worker.root/'clone.git').exists())
        self.assertFalse((worker.root/'canonical.json').exists())
        with self.assertRaises(TypeError): worker.read().files['x'] = b'x'

    def test_unapproved_existing_public_path_is_preserved_not_overwritten(self):
        path = Path(self.scope.reference_root)
        path.mkdir(); (path/'human.txt').write_text('preserve')
        with self.assertRaises(library.LibraryError): self.projection()
        self.assertEqual((path/'human.txt').read_text(), 'preserve')

    def test_unsafe_reference_symlink_or_writable_root_refused(self):
        reference = Path(self.scope.reference_root).parent
        reference.chmod(0o777)
        with self.assertRaises(library.LibraryError): self.projection()
        reference.chmod(0o755)
        os.symlink(self.base/'service', reference/STATE)
        with self.assertRaises(library.LibraryError): self.projection()

    def test_revocation_before_switch_preserves_previous_generation(self):
        self.register(); worker = self.projection(); worker.refresh()
        before = worker.read(); self.change()
        real = worker._stage
        def stage(*args):
            result = real(*args)
            worker.current_scope = lambda: None
            return result
        with patch.object(worker,'_stage',side_effect=stage): self.assertFalse(worker.refresh())
        self.assertEqual(before,worker.read())
        self.assertEqual(worker.last_error,'LIBRARY_AUTHENTICATION_REQUIRED')

    def test_snapshot_source_path_metadata_symlink_and_bounds_refuse(self):
        self.register(); worker = self.projection(); worker.refresh()
        before = worker.read()
        prefix = 'projects/'+self.scope.project_path+'/'
        for bad in (library_bundle.Tree({prefix+'.git/config':b'secret'}),
                    library_bundle.Tree({prefix+'../escape':b'secret'}),
                    library_bundle.Tree({'projects/other/index.md':b'secret'}),
                    library_bundle.Tree(dict((prefix+k,v) for k,v in before.files.items()), (prefix+'link',))):
            with self.subTest(tree=tuple(bad.files)), patch.object(self.publisher,'projection_snapshot',return_value=('a'*40,bad)):
                self.assertFalse(worker.refresh()); self.assertEqual(before,worker.read())
        large = dict((prefix+k,v) for k,v in before.files.items())
        large[prefix+'research/large.md'] = b'x'*(self.settings['limits']['document_bytes']+1)
        with patch.object(self.publisher,'projection_snapshot',return_value=('a'*40,library_bundle.Tree(large))):
            self.assertFalse(worker.refresh()); self.assertEqual(before,worker.read())

    def test_canonical_missing_or_identity_changed_retains_old_readable_snapshot(self):
        self.register(); worker = self.projection(); worker.refresh(); before=worker.read()
        self.mutate({self.root():self.root_bytes().replace(b'github.com/1001',b'github.com/9999')})
        self.assertFalse(worker.refresh()); self.assertEqual(before,worker.read())

    def test_existing_unknown_content_remains_readable_without_write_gate(self):
        self.register()
        self.mutate({'projects/'+self.scope.project_path+'/research/unknown.md':
                     b'---\ntype: future-type\n---\n\nUnrecognized but readable.\n'})
        worker=self.projection()
        with patch('uas.library_gate.validate',side_effect=AssertionError('no write gate for reads')):
            self.assertTrue(worker.refresh())
        self.assertIn('research/unknown.md',worker.read().files)

    def test_slow_projection_does_not_block_publication_or_change_durable_result(self):
        worker=self.projection(start=True)
        entered, release = threading.Event(), threading.Event()
        original=worker._stage
        def slow(*args):
            entered.set(); release.wait(5); return original(*args)
        with patch.object(worker,'_stage',side_effect=slow):
            result=self.register()
            self.assertTrue(entered.wait(2))
            self.assertEqual(result.receipt['outcome'],'COMMITTED')
            self.assertEqual(worker.visibility(result.commit_sha),{'commit_sha':None,'visible':False})
            release.set(); self.assertTrue(worker.wait_idle())
        self.assertTrue(worker.visibility(result.commit_sha)['visible'])

    def test_failed_notification_refresh_leaves_registration_success_and_recovers(self):
        worker=self.projection(start=True)
        with patch.object(worker,'_stage',side_effect=OSError('full')):
            result=self.register(); self.assertTrue(worker.wait_idle())
            self.assertEqual(result.receipt['outcome'],'COMMITTED')
            self.assertFalse(worker.visibility(result.commit_sha)['visible'])
        worker.reconcile(); self.assertTrue(worker.wait_idle())
        self.assertTrue(worker.visibility(result.commit_sha)['visible'])

    def test_coherent_consumer_racing_atomic_switch_never_mixes_commit_and_bytes(self):
        first=self.register(); worker=self.projection(); worker.refresh()
        old=worker.read(); new_sha=self.change(b'\nDistinct second generation.\n')
        started, finish=threading.Event(),threading.Event(); views=[]; failures=[]
        def read_loop():
            started.set()
            try:
                while not finish.is_set(): views.append(read_projection(self.scope,self.settings))
            except BaseException as error: failures.append(error)
        thread=threading.Thread(target=read_loop); thread.start(); started.wait(2)
        try:
            self.assertTrue(worker.refresh())
            views.append(worker.read())
        finally:
            finish.set();thread.join(3)
        self.assertFalse(failures);self.assertFalse(thread.is_alive())
        self.assertTrue(views)
        for view in views:
            if view.manifest['commit_sha']==first.commit_sha:self.assertEqual(view.files,old.files)
            else:
                self.assertEqual(view.manifest['commit_sha'],new_sha)
                self.assertIn(b'Distinct second generation',view.files['index.md'])

    def test_sync_error_after_switch_reports_visible_not_false_failed_refresh(self):
        self.register();worker=self.projection()
        from uas import library_projection as module
        original=module._sync
        def sync(path):
            if path==worker.root:raise OSError('sync failed')
            return original(path)
        with patch.object(module,'_sync',side_effect=sync):self.assertTrue(worker.refresh())
        self.assertEqual(worker.read().manifest['commit_sha'],self.head())
        self.assertEqual(worker.last_error,'PROJECTION_SYNC_UNCERTAIN')

    def test_bounded_latest_identity_mailbox_and_recovered_publication_signal(self):
        subscription=self.publisher.subscribe(self.scope);self.addCleanup(lambda:self.publisher.unsubscribe(subscription))
        initial=subscription.wait(0,0)[0]
        first=self.register();version,publication,closed=subscription.wait(initial,0)
        self.assertFalse(closed);self.assertEqual(publication.resulting_sha,first.commit_sha)
        _,tree=self.publisher.project_snapshot(self.scope,self.settings,current=lambda:None)
        bundle=library_gate.validate(self.scope,self.settings,proposed=tree,current=tree).bundle
        result=self.publisher.publish(self.operation(),bundle,input_sha=first.commit_sha)
        newest,publication,closed=subscription.wait(version,0)
        self.assertGreater(newest,version);self.assertFalse(result.created)
        self.assertEqual(publication.resulting_sha,first.commit_sha)
        self.publisher.unsubscribe(subscription)
        self.assertTrue(subscription.wait(newest,0)[2])

    def test_unreadable_subtree_and_traversal_error_never_return_partial_success(self):
        self.register();worker=self.projection();worker.refresh()
        directory = (worker.root / CURRENT).resolve() / 'library/context'
        directory.chmod(0o000)
        try:
            with self.assertRaises(OSError): worker.read()
        finally:
            directory.chmod(0o555)
        self.assertEqual(len(worker.read().files), 6)

    def test_partial_stage_is_under_private_nonparticipant_traversable_parent(self):
        self.register();worker=self.projection()
        from uas import library_projection as module
        original=module._write
        observed=[]
        def inspect(path, data, *args):
            if 'staging' in path.parts:
                private=worker.root / STATE / 'staging'
                self.assertEqual(stat.S_IMODE(private.stat().st_mode),0o700)
                self.assertIn(private,path.parents)
                self.assertIsNone(worker.read().manifest['commit_sha'])
                self.assertFalse(Path(self.scope.reference_root).exists())
                observed.append(path)
            return original(path,data,*args)
        with patch.object(module,'_write',side_effect=inspect):self.assertTrue(worker.refresh())
        self.assertEqual(len(observed),7)
        self.assertFalse(list((worker.root/STATE/'staging').iterdir()))

    def test_stalled_projection_git_read_does_not_hold_canonical_write_lock(self):
        first=self.register();worker=self.projection()
        entered,release,done=threading.Event(),threading.Event(),threading.Event()
        real=self.publisher._git
        result=[];failures=[]
        def stalled(*args,**kwargs):
            if args[:2]==('-c','gc.auto=0'):
                entered.set();release.wait(5)
            return real(*args,**kwargs)
        beta=self.make_scope('beta','other/beta','2002')
        def publish():
            try:
                result.append(Registrar(self.publisher,current_scope=lambda:beta).register(
                    self.operation('beta',beta),self.settings))
            except BaseException as error:failures.append(error)
            finally:done.set()
        with patch.object(self.publisher,'_git',side_effect=stalled):
            worker.start()
            self.assertTrue(entered.wait(2))
            thread=threading.Thread(target=publish);thread.start()
            try:
                self.assertTrue(done.wait(2), 'canonical writer blocked by projection')
            finally:
                release.set();thread.join(5)
            self.assertTrue(worker.wait_idle())
        self.assertFalse(failures);self.assertEqual(len(result),1)
        self.assertEqual(self.publisher.head(),result[0].commit_sha)
        self.assertEqual(worker.read().manifest['commit_sha'],first.commit_sha)

    def test_moved_generation_sync_failure_preserves_previous_pair(self):
        self.register();worker=self.projection();worker.refresh();before=worker.read();self.change()
        from uas import library_projection as module
        original=module._sync
        def fail_after_move(path):
            if path.parent == worker.root/STATE and len(path.name)==32:
                raise OSError('directory sync failure')
            return original(path)
        with patch.object(module,'_sync',side_effect=fail_after_move):
            self.assertFalse(worker.refresh())
        self.assertEqual(worker.read(),before)
        self.assertEqual(len(list((worker.root/STATE).glob('?'*32))),1)

    def test_restart_reclaims_only_owned_orphan_generations(self):
        self.register();worker=self.projection();worker.refresh();before=worker.read()
        stage=worker._stage(dict(before.manifest),dict(before.files))
        orphan=worker.root/STATE/('f'*32);orphan.mkdir();(orphan/'partial').write_text('old')
        human=worker.root/STATE/'human-note';human.write_text('preserve')
        worker.close();new=self.projection()
        self.assertEqual(new.read(),before)
        self.assertFalse(stage.exists());self.assertFalse(orphan.exists())
        self.assertEqual(human.read_text(),'preserve')

    def test_revocation_while_waiting_for_reader_lock_prevents_switch(self):
        from contextlib import contextmanager
        from uas import library_projection as module
        self.register();worker=self.projection();worker.refresh();before=worker.read();self.change()
        real=module._guard;waiting=threading.Event();out=[]
        @contextmanager
        def guard(root,exclusive=False):
            if exclusive:waiting.set()
            with real(root,exclusive):yield
        with patch.object(module,'_guard',side_effect=guard):
            with real(worker.root):
                thread=threading.Thread(target=lambda:out.append(worker.refresh()));thread.start()
                self.assertTrue(waiting.wait(2));worker.current_scope=lambda:None
            thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(out,[False])
        self.assertEqual(worker.read(),before)

    def test_second_supervisor_refused_and_close_stops_background_worker(self):
        worker=self.projection(start=True)
        with self.assertRaises(OSError): self.projection()
        thread=worker._thread
        worker.close();self.assertFalse(thread.is_alive())
        again=self.projection();self.assertIsNone(again.read().manifest['commit_sha'])



