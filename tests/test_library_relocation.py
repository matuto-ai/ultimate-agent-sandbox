"""Atomic public relocation with real canonical Git and fixed projection reads."""
from pathlib import Path
import unittest
from unittest.mock import patch

import library_support as support
import test_library_registration as fixtures
from test_library_git import git
from uas import library, library_bundle as bundle, library_gate as gate
from uas.library_relocation import Relocator
from uas.library_projection import ProjectProjection


class RelocationTests(unittest.TestCase):
    setUp = fixtures.RegistrationTests.setUp
    make_publisher = fixtures.RegistrationTests.make_publisher
    operation = fixtures.RegistrationTests.operation
    register = fixtures.RegistrationTests.register
    head = fixtures.RegistrationTests.head
    count = fixtures.RegistrationTests.count
    files = fixtures.RegistrationTests.files
    mutate = fixtures.RegistrationTests.mutate
    root = fixtures.RegistrationTests.root
    root_bytes = fixtures.RegistrationTests.root_bytes

    def make_scope(self, project='alpha', repository='acme/alpha', source='1001', kind='register'):
        reference = self.base / project / 'reference'
        reference.mkdir(mode=0o755, parents=True, exist_ok=True)
        b = library.project_binding({'id':project,'repository':repository,
            'roots':{'reference':str(reference)}}, source_identity=source)
        return library.human_scope(support.session(('library-'+kind,)), binding=b, kind=kind)

    def setup_move(self, repository='new-owner/new-name', source='1001', project='alpha'):
        self.register()
        self.old = self.scope
        self.new = self.make_scope(project, repository, source, 'relocate')
        self.current = self.new
        self.mover = Relocator(self.publisher, previous_scope=self.old, current_scope=lambda:self.current)
        return self.new

    def move(self, identity='move-1', payload=None):
        op = library.action(self.new, self.settings, kind='relocate', operation_id=identity,
            request_id='request-'+identity,payload=payload or {},at=support.AT)
        return self.mover.move(op,self.settings)

    def refuse(self, code, action=None):
        head=self.head()
        with self.assertRaises(library.LibraryError) as caught: (action or self.move)()
        self.assertEqual(caught.exception.code,code)
        self.assertEqual(head,self.head())

    def test_atomic_transfer_preserves_identity_history_pending_and_other_project(self):
        self.setup_move()
        other=self.make_scope('beta','acme/beta','2002')
        self.fresh=other
        self.register(self.operation('other',other))
        self.fresh=self.old
        prefix='projects/'+self.old.project_path
        index=git(self.target,'show',self.head()+':'+prefix+'/context/index.md').encode()
        self.mutate({prefix+'/context/authored.md':b'---\ntype: context\ntitle: Authored\n---\nBody.\n',
                     prefix+'/context/index.md':index+b'\n* [Authored](authored.md)\n'})
        head,before=self.publisher.project_snapshot(self.old,self.settings,current=lambda:None)
        result=self.move()
        self.assertTrue(result.created)
        self.assertEqual(result.project_identity,self.old.project_identity)
        self.assertFalse(any(p.startswith(prefix+'/') for p in self.files()))
        self.assertIn('projects/github.com/acme/beta/index.md',self.files())
        _,after=self.publisher.project_snapshot(self.new,self.settings,current=lambda:None)
        for path,data in before.files.items():
            relative=path[len(prefix):]
            if relative not in ('/index.md','/log.md'):
                self.assertEqual(data,after.files['projects/'+self.new.project_path+relative])
        self.assertIn(head,git(self.target,'rev-list',self.head()))
        self.assertIn(b'Source identity: github.com/1001',after.files['projects/'+self.new.project_path+'/index.md'])
        self.assertEqual(self.move().commit_sha,result.commit_sha)
        self.assertFalse(self.move().created)

    def test_no_payload_path_allowed(self):
        self.setup_move();self.refuse('UNKNOWN_FIELD',lambda:self.move(payload={'path':'evil'}))

    def test_wrong_identity_refused(self):
        self.setup_move(source='2002');self.refuse('PROJECT_MISMATCH')

    def test_wrong_project_refused(self):
        self.setup_move(project='beta');self.refuse('PROJECT_MISMATCH')

    def test_unchanged_coordinate_refused(self):
        self.setup_move(repository='acme/alpha');self.refuse('PROJECT_MISMATCH')

    def test_destination_collision_keeps_both_bundles(self):
        self.setup_move()
        self.mutate({'projects/'+self.new.project_path+'/occupied':b'owned'})
        self.refuse('INCOMPATIBLE_HEAD')

    def test_destination_parent_file_refused(self):
        self.setup_move();self.mutate({'projects/github.com/new-owner':b'owned'})
        self.refuse('UNSUPPORTED_PROJECT_ENTRY')

    def test_archived_frozen(self):
        self.setup_move();self.mutate({self.root():self.root_bytes()+b'\nLibrary state: archived\n'})
        self.refuse('PROJECT_ARCHIVED')

    def test_revoked_current_authority(self):
        self.setup_move();self.current=self.old
        self.refuse('LIBRARY_AUTHENTICATION_REQUIRED')

    def test_gate_failure_keeps_canonical(self):
        self.setup_move()
        with patch('uas.library_relocation.gate.validate', side_effect=library.LibraryError('TEST_GATE','gate')):
            self.refuse('TEST_GATE')

    def test_old_prepared_publication_cannot_restore_old_path(self):
        self.setup_move()
        oldhead,tree=self.publisher.project_snapshot(self.old,self.settings,current=lambda:None)
        checked=gate.validate(self.old,self.settings,proposed=tree,current=tree)
        self.move()
        stale=self.operation('stale',self.old)
        self.refuse('PROJECT_COORDINATE_CONFLICT',lambda:self.publisher.publish(stale,checked.bundle,input_sha=oldhead))

    def test_ambiguous_push_reconciles_no_second_move(self):
        self.setup_move();original=self.publisher._push
        def lost(*args):
            original(*args)
            raise library.LibraryError('PUBLICATION_UNCERTAIN','push')
        with patch.object(self.publisher,'_push',side_effect=lost):
            with self.assertRaises(library.LibraryError):self.move()
        commit=self.head();count=self.count()
        result=self.move()
        self.assertEqual(result.commit_sha,commit);self.assertFalse(result.created)
        self.assertEqual(self.count(),count)

    def test_fixed_projection_old_generation_survives_until_new_refresh(self):
        self.setup_move()
        worker=ProjectProjection(self.publisher,self.old,self.settings,current_scope=lambda:self.old)
        self.addCleanup(worker.close);worker.refresh()
        before=worker.read();worker.close()
        result=self.move()
        changed=ProjectProjection(self.publisher,self.new,self.settings,current_scope=lambda:self.current)
        self.addCleanup(changed.close)
        self.assertEqual(changed.read().manifest['commit_sha'],before.manifest['commit_sha'])
        changed.refresh()
        self.assertEqual(changed.read().manifest['commit_sha'],result.commit_sha)
        self.assertEqual(self.old.reference_root,self.new.reference_root)

    def test_pending_capture_survives_and_same_request_stays_deduplicated(self):
        from uas.library_enqueue import Enqueuer
        self.setup_move()
        def participant(scope):
            return library.participant_scope(support.ORIGIN,binding={
                'project_id':scope.project_id,'project_identity':scope.project_identity,
                'project_path':scope.project_path,'reference_root':scope.reference_root})
        active=[participant(self.old)]
        enqueue=Enqueuer(self.publisher,current_scope=lambda:active[0])
        args=dict(operation_id='capture',request_id='capture-request',value=support.value(),at=support.AT)
        before=enqueue.enqueue(self.settings,**args)
        self.assertEqual(before.outcome,'DURABLY_QUEUED')
        original=git(self.target,'show',self.head()+':projects/'+self.old.project_path+'/'+before.path)
        self.move();active[0]=participant(self.new)
        after=enqueue.enqueue(self.settings,**args)
        self.assertEqual(before.queue_id,after.queue_id)
        self.assertEqual(before.published_sha,after.published_sha)
        self.assertEqual(original,git(self.target,'show',self.head()+':projects/'+self.new.project_path+'/'+before.path))
        later=enqueue.enqueue(self.settings,**{**args,'operation_id':'later','request_id':'later'})
        self.assertEqual(later.outcome,'DURABLY_QUEUED')

    def test_concurrent_source_change_fences_move(self):
        self.setup_move(); original=self.publisher.move
        changed=[]
        def race(*args,**kwargs):
            self.mutate({self.root():self.root_bytes()+b'\nNew authored note.\n'})
            changed.append(self.head())
            return original(*args,**kwargs)
        with patch.object(self.publisher,'move',side_effect=race):
            with self.assertRaisesRegex(library.LibraryError,'INCOMPATIBLE_HEAD'):self.move()
        self.assertEqual(self.head(),changed[0]);self.assertIn(self.root(),self.files())

    def test_third_bundle_duplicate_identity_refused(self):
        self.setup_move()
        other='projects/github.com/duplicate/repo/index.md'
        self.mutate({other:self.root_bytes().replace(b'acme/alpha',b'duplicate/repo')})
        self.refuse('PROJECT_COORDINATE_CONFLICT')

    def test_receipt_failure_restart_recovers_current_move(self):
        from uas.library_records import LibraryRecords
        self.setup_move();original=LibraryRecords.finish
        def fail(records,operation,*args,**kwargs):
            if operation.kind=='relocate-publication':raise OSError('receipt disk failed')
            return original(records,operation,*args,**kwargs)
        with patch.object(LibraryRecords,'finish',new=fail):
            with self.assertRaises(OSError):self.move()
        head=self.head();self.publisher.close()
        self.publisher=self.make_publisher();self.publisher.startup();self.addCleanup(self.publisher.close)
        self.mover=Relocator(self.publisher,previous_scope=self.old,current_scope=lambda:self.current)
        result=self.move();self.assertEqual(head,result.commit_sha);self.assertFalse(result.created)

    def test_revoke_before_push_preserves_canonical(self):
        self.setup_move();original=self.publisher._commit
        def revoke(*args,**kwargs):
            commit=original(*args,**kwargs);self.current=self.old;return commit
        with patch.object(self.publisher,'_commit',side_effect=revoke):
            self.refuse('LIBRARY_AUTHENTICATION_REQUIRED')

    def test_projection_disk_failure_retains_previous_coherent_generation(self):
        self.setup_move()
        old=ProjectProjection(self.publisher,self.old,self.settings,current_scope=lambda:self.old)
        old.refresh();view=old.read();old.close()
        self.move()
        new=ProjectProjection(self.publisher,self.new,self.settings,current_scope=lambda:self.current)
        self.addCleanup(new.close)
        with patch.object(new,'_stage',side_effect=OSError('disk full')):
            self.assertFalse(new.refresh())
        self.assertEqual(new.read(),view)
        self.assertTrue(new.refresh())
        self.assertNotEqual(new.read().manifest['commit_sha'],view.manifest['commit_sha'])

    def test_failed_preparation_records_safe_terminal_refusal(self):
        from uas.library_records import LibraryRecords
        self.setup_move();self.mutate({self.root():self.root_bytes()+b'\nLibrary state: archived\n'})
        self.refuse('PROJECT_ARCHIVED')
        with LibraryRecords(self.records,'deployment-1') as records:
            record=records.record('move-1',project_identity=self.old.project_identity)
            self.assertEqual(record['receipt']['outcome'],'REFUSED')
            self.assertEqual(record['receipt']['reason'],'PROJECT_ARCHIVED')
        self.refuse('PROJECT_ARCHIVED')

    def test_intent_storage_failure_never_publishes(self):
        from uas.library_records import LibraryRecords
        self.setup_move();head=self.head()
        with patch.object(LibraryRecords,'begin',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):self.move()
        self.assertEqual(self.head(),head)

class AttemptRelocationTests(unittest.TestCase):
    def setup_attempt(self):
        from test_library_attempts import AttemptTests
        test = AttemptTests('test_parking_commit_has_durable_inputs_before_contact_and_recovery_outcomes')
        test.setUp(); self.addCleanup(test.doCleanups)
        source = test.source
        old = source.scope
        binding = support.binding(repository='new-owner/new-name')
        new = library.human_scope(support.session(('library-relocate',)), binding=binding, kind='relocate')
        op = library.action(new,source.settings,kind='relocate',operation_id='move',request_id='move',payload={},at=support.AT)
        mover = Relocator(source.publisher,previous_scope=old,current_scope=lambda:new)
        participant = library.participant_scope(support.ORIGIN,binding=binding)
        return test, mover, op, participant

    def test_committed_attempt_recovers_after_move_without_model_contact(self):
        test,mover,op,participant = self.setup_attempt()
        result = test.run_attempt()
        mover.move(op,test.source.settings)
        test.source.scope=test.source.fresh=participant
        test.marker.unlink(); count=test.source.count()
        recovered=test.run_attempt()
        self.assertEqual(result,recovered)
        self.assertFalse(test.marker.exists())
        self.assertEqual(count,test.source.count())

    def test_move_after_model_output_invalidates_old_coordinates(self):
        test,mover,op,participant = self.setup_attempt()
        test.integrate(); moved=[]
        def audit(event):
            if event['state']=='returned':
                moved.append(mover.move(op,test.source.settings))
                test.source.fresh=participant
        test.hook=audit
        with self.assertRaisesRegex(library.LibraryError,'LIBRARY_AUTHENTICATION_REQUIRED'):
            test.run_attempt()
        self.assertEqual(len(moved),1)
        self.assertEqual(test.source.head(),moved[0].commit_sha)
        self.assertNotIn('/context/accepted-note.md','\n'.join(git(test.source.target,'ls-tree','-r','--name-only',test.source.head()).splitlines()))

if __name__=='__main__':unittest.main()
