"""Explicit preview/confirm through real disposable source and canonical Git."""
from dataclasses import replace
import json
from unittest.mock import patch
import unittest

import library_support as support
import test_library_enqueue as enqueue_support
from test_library_git import git
from uas import library, library_bundle
from uas.library_import import Importer
from uas.library_sources import GitSource, Resolver
from uas.library_records import LibraryRecords


class ImportTests(unittest.TestCase):
    make_scope = enqueue_support.EnqueueTests.make_scope
    make_publisher = enqueue_support.EnqueueTests.make_publisher
    head = enqueue_support.EnqueueTests.head
    count = enqueue_support.EnqueueTests.count
    contents = enqueue_support.EnqueueTests.contents
    # Reuse setup helpers, not unrelated inherited enqueue test cases.
    def setUp(self):
        enqueue_support.EnqueueTests.setUp(self)
        self.work = self.base/'source-work'
        self.work.mkdir()
        git(self.work, 'init', '-q')
        git(self.work, 'config', 'user.name', 'fixture')
        git(self.work, 'config', 'user.email', 'source@example.test')
        for name, text in {'one.md':'# First_title\n\nOriginal text.\n',
                           'two.md':'# Second\n\nOther text.\n',
                           'secret.md':'# Secret\nsk-proj-'+'x'*40+'\n'}.items():
            (self.work/name).write_text(text)
        git(self.work, 'add', '.')
        git(self.work, 'commit', '-qm', 'sources')
        self.commit = git(self.work, 'rev-parse', 'HEAD').strip()
        self.bare = self.base/'source.git'
        git(self.base, 'clone', '-q', '--bare', str(self.work), str(self.bare))
        self.bare.chmod(0o700)
        self.kind = 'import-preview'
        self.allowed = True
        self.human = True
        self.binding = support.binding()
        self.source = GitSource(self.bare, project_identity=self.scope.project_identity,
                                repository='github.com/acme/alpha')
        self.resolver = Resolver(source=self.source, current_scope=lambda: self.hscope(self.kind),
                                 source_allowed=lambda scope,resource: self.allowed)
        self.importer = Importer(self.publisher, resolver=self.resolver,
                                 current_scope=lambda kind:self.hscope(kind))

    def hscope(self, kind):
        if not self.human: return None
        return library.human_scope(support.session(('library-'+kind,)), binding=self.binding, kind=kind)

    def op(self, kind, payload, name='op', at=support.AT):
        self.kind=kind
        return library.action(self.hscope(kind), self.settings, kind=kind,
                              operation_id=name, request_id='request-'+name, payload=payload, at=at)

    def preview(self, paths=None, name='preview', types=None):
        value={'source_commit':self.commit, 'paths':paths or ['one.md','two.md']}
        if types is not None:value['types']=types
        return self.importer.preview(self.op('import-preview',value,name), self.settings)

    def confirm(self, preview=None, paths=None, name='confirm', types=None, **overrides):
        preview=preview or self.preview()
        value={'source_commit':preview.source_commit,'paths':paths or [i['path'] for i in preview.files],
               'preview_id':preview.preview_id,'observed_version':preview.observed_version}
        if types is not None:value['types']=types
        value.update(overrides)
        return self.importer.confirm(self.op('import-confirm',value,name),self.settings)

    def test_preview_has_exact_metadata_no_content_or_git_write(self):
        head=self.head(); result=self.preview()
        self.assertEqual(self.head(),head);self.assertEqual(self.count(),1)
        self.assertEqual([i['path'] for i in result.files],['one.md','two.md'])
        self.assertEqual(result.repository,'github.com/acme/alpha')
        self.assertEqual(result.source_commit,self.commit)
        self.assertEqual(result.files[0]['author'],'fixture')
        self.assertNotIn('Original text',str(result.files))
        with LibraryRecords(self.records,'deployment-1') as records:
            stored=str(records.submission(self.scope.project_identity,'preview-manifest:'+result.preview_id))
        self.assertNotIn('First_title',stored);self.assertNotIn('one.md',stored)

    def test_confirm_atomic_pending_provenance_no_acceptance(self):
        preview=self.preview(types=['decision','research'])
        result=self.confirm(preview,types=['decision','research'])
        self.assertEqual(self.count(),2)
        self.assertEqual(result.receipt['outcome'],'COMMITTED')
        for q,t in zip(result.queue_ids,['decision','research']):
            meta,body=library_bundle.frontmatter(self.contents('pending/'+q+'.md'),'pending')
            self.assertEqual(meta['type'],t);self.assertEqual(meta['status'],'draft')
            self.assertNotIn('verified',meta);self.assertNotIn('expires',meta)
            self.assertIn('Source author: fixture',body)
            self.assertIn(self.commit,meta['sources'][0]['resource'])
        self.assertIn('Original text',self.contents('pending/'+result.queue_ids[0]+'.md'))

    def test_manifest_repetition_new_preview_command_deduplicates(self):
        p=self.preview();one=self.confirm(p)
        p2=self.preview(['two.md','one.md'],name='preview2')
        self.assertEqual(p.preview_id,p2.preview_id)
        two=self.confirm(p2,name='confirm2')
        self.assertEqual(one.queue_ids,two.queue_ids);self.assertEqual(self.count(),2)
        self.assertEqual(one.receipt['publication'],two.receipt['publication'])
        three=self.confirm(self.preview(['one.md'],name='preview3'),name='confirm3')
        self.assertNotEqual(one.manifest_id,three.manifest_id);self.assertEqual(self.count(),3)

    def test_changed_paths_commit_type_version_refused_no_write(self):
        p=self.preview();head=self.head()
        for overrides in ({'paths':['one.md']},{'source_commit':'f'*40},{'types':['research','context']},
                          {'preview_id':'a'*64},{'observed_version':'b'*64}):
            with self.subTest(overrides=overrides),self.assertRaises(library.LibraryError):
                self.confirm(p,**overrides)
            self.assertEqual(head,self.head())

    def test_no_preview_cannot_confirm_even_computed_digest(self):
        p=self.preview()
        # Separate metadata store means no preview receipt, same source/canonical.
        import sqlite3
        db=sqlite3.connect(self.records);db.execute("DELETE FROM attempts")
        db.execute("DELETE FROM submissions WHERE request_id=?",('preview-manifest:'+p.preview_id,));db.commit();db.close()
        with self.assertRaisesRegex(library.LibraryError,'IMPORT_PREVIEW_REQUIRED'):self.confirm(p)
        self.assertEqual(self.count(),1)

    def test_source_and_human_revoked_before_read(self):
        p=self.preview();self.allowed=False
        with patch.object(self.source,'read',side_effect=AssertionError('read')):
            with self.assertRaisesRegex(library.LibraryError,'SOURCE_AUTHORITY_REVOKED'):self.confirm(p)
        self.allowed=True
        op=self.op('import-confirm',{'source_commit':p.source_commit,'paths':['one.md','two.md'],
            'preview_id':p.preview_id,'observed_version':p.preview_id})
        self.human=False
        with patch.object(self.source,'read',side_effect=AssertionError('read')):
            with self.assertRaisesRegex(library.LibraryError,'LIBRARY_AUTHENTICATION_REQUIRED'):
                self.importer.confirm(op,self.settings)

    def test_secret_in_any_file_no_partial_write(self):
        with self.assertRaises(library.LibraryError):self.preview(['one.md','secret.md'])
        self.assertEqual(self.count(),1)

    def test_source_branch_advances_old_pin_stays_valid(self):
        p=self.preview();(self.work/'one.md').write_text('new branch text')
        git(self.work,'add','.');git(self.work,'commit','-qm','later')
        git(self.work,'push','-q',str(self.bare),'HEAD:refs/heads/main')
        self.assertEqual(self.confirm(p).receipt['outcome'],'COMMITTED')

    def test_duplicate_path_and_unsafe_binary_bounds_refused(self):
        with self.assertRaisesRegex(library.LibraryError,'DUPLICATE_IMPORT_PATH'):self.preview(['one.md','one.md'])
        with self.assertRaises(library.LibraryError):self.preview(['../one.md'])
        with self.assertRaises(library.LibraryError):self.preview(types=['unknown','context'])

    def test_lost_publication_response_reconciles_once(self):
        p=self.preview();real=self.publisher.publish
        def lost(*args,**kwargs):
            real(*args,**kwargs);raise library.LibraryError('PUBLICATION_UNAVAILABLE')
        with patch.object(self.publisher,'publish',side_effect=lost):
            with self.assertRaises(library.LibraryError):self.confirm(p)
        self.assertEqual(self.count(),2)
        result=self.confirm(p,name='retry')
        self.assertEqual(result.receipt['outcome'],'COMMITTED');self.assertEqual(self.count(),2)

    def test_revocation_at_publication_has_no_partial_write(self):
        p=self.preview();real=self.publisher.publish
        def revoke(*args,**kwargs):
            self.allowed=False;return real(*args,**kwargs)
        with patch.object(self.publisher,'publish',side_effect=revoke):
            with self.assertRaises(library.LibraryError):self.confirm(p)
        self.assertEqual(self.count(),1)

    def test_exact_command_identity_not_silently_normalized(self):
        p=self.preview();self.confirm(p)
        payload={'source_commit':p.source_commit,'paths':['one.md','two.md'],
                 'preview_id':p.preview_id,'observed_version':p.preview_id}
        op=self.op('import-confirm',payload,'confirm')
        with self.assertRaisesRegex(library.LibraryError,'ID_CONFLICT'):
            self.importer.confirm(library.action(op.scope,self.settings,kind=op.kind,operation_id=op.operation_id,request_id='other-request',payload=op.payload,at=op.at),self.settings)
        with self.assertRaisesRegex(library.LibraryError,'ID_CONFLICT'):
            self.confirm(p,paths=['two.md','one.md'])
        self.assertEqual(self.count(),2)

    def test_callback_mutation_cannot_change_admitted_selection(self):
        p=self.preview()
        payload={'source_commit':p.source_commit,'paths':['one.md','two.md'],
                 'preview_id':p.preview_id,'observed_version':p.preview_id}
        op=self.op('import-confirm',payload,'confirm')
        def mutate(scope, resource):
            payload['paths'][:]=['secret.md'];payload['source_commit']='f'*40
            return True
        self.resolver.source_allowed=mutate
        result=self.importer.confirm(op,self.settings)
        self.assertEqual(len(result.queue_ids),2)
        self.assertEqual(self.count(),2)

    def test_current_policy_rechecked_after_preview(self):
        doc=support.document();doc['repository'].update(self.settings['repository'])
        doc['filters']['high_confidence']='observe';self.settings=support.settings(doc)
        (self.work/'one.md').write_text('# First\nsk-proj-'+'x'*40+'\n')
        git(self.work,'add','.');git(self.work,'commit','-qm','policy fixture')
        self.commit=git(self.work,'rev-parse','HEAD').strip()
        git(self.work,'push','-q',str(self.bare),'HEAD:refs/heads/main')
        p=self.preview(['one.md'])
        doc=support.document();doc['repository'].update(self.settings['repository'])
        doc['filters']['high_confidence']='block';self.settings=support.settings(doc)
        with self.assertRaises(library.LibraryError):self.confirm(p)
        self.assertEqual(self.count(),1)

    def test_wrong_project_and_participant_refused(self):
        p=self.preview();op=self.op('import-confirm',{'source_commit':p.source_commit,
          'paths':['one.md','two.md'],'preview_id':p.preview_id,'observed_version':p.preview_id})
        with self.assertRaises(library.LibraryError):
            self.importer.confirm(replace(op,scope=self.scope),self.settings)
        self.binding=support.binding('beta','acme/beta','1002')
        with self.assertRaises(library.LibraryError):self.confirm(p)
        self.assertEqual(self.count(),1)

    def test_lost_receipt_recovery_new_attempt_does_not_duplicate(self):
        p=self.preview();real=LibraryRecords.finish
        def lost(records,op,receipt):
            real(records,op,receipt)
            if op.kind=='import-publication':raise library.LibraryError('RECORD_UNCERTAIN')
        with patch.object(LibraryRecords,'finish',lost):
            with self.assertRaises(library.LibraryError):self.confirm(p)
        self.assertEqual(self.count(),2)
        self.assertEqual(self.confirm(p,name='retry').receipt['outcome'],'COMMITTED')
        self.assertEqual(self.count(),2)

    def test_bound_and_complete_tree_refusal_leave_no_drafts(self):
        p=self.preview()
        doc=support.document();doc['repository'].update(self.settings['repository'])
        doc['limits']['batch_drafts']=1;self.settings=support.settings(doc)
        with self.assertRaisesRegex(library.LibraryError,'IMPORT_TOO_LARGE'):self.confirm(p)
        self.assertEqual(self.count(),1)

    def test_observe_evidence_and_refusal_records_omit_source_content(self):
        doc=support.document();doc['repository'].update(self.settings['repository'])
        doc['filters']['high_confidence']='observe';self.settings=support.settings(doc)
        p=self.preview(['secret.md']);result=self.confirm(p)
        self.assertTrue(result.receipt['evidence'])
        self.assertEqual(result.receipt['evidence'][0]['rule'],'provider-secret')
        with LibraryRecords(self.records,'deployment-1') as records:
            encoded=json.dumps(records.record('confirm',project_identity=self.scope.project_identity))
        self.assertNotIn('sk-proj-',encoded);self.assertNotIn('secret.md',encoded)
        doc['filters']['high_confidence']='block';self.settings=support.settings(doc)
        with self.assertRaises(library.LibraryError):self.preview(['secret.md'],name='refused')
        with LibraryRecords(self.records,'deployment-1') as records:
            receipt=records.record('refused',project_identity=self.scope.project_identity)['receipt']
        self.assertEqual(receipt['outcome'],'REFUSED');self.assertEqual(receipt['reason'],'SECRET_DETECTED')

    def test_uncertain_publication_is_retryable_not_refused(self):
        p=self.preview();real=self.publisher.publish
        def uncertain(*args,**kwargs):
            real(*args,**kwargs);raise library.LibraryError('PUBLICATION_UNCERTAIN')
        with patch.object(self.publisher,'publish',side_effect=uncertain):
            with self.assertRaisesRegex(library.LibraryError,'PUBLICATION_UNCERTAIN'):self.confirm(p)
        with LibraryRecords(self.records,'deployment-1') as records:
            receipt=records.record('confirm',project_identity=self.scope.project_identity)['receipt']
        self.assertEqual(receipt['outcome'],'NOT_DURABLE')
        self.assertEqual(self.confirm(p,name='retry').receipt['outcome'],'COMMITTED')
        self.assertEqual(self.count(),2)

    def test_dependency_exception_is_safe_and_receipted(self):
        with patch.object(self.source,'read',side_effect=RuntimeError('PRIVATE_MARKER')):
            with self.assertRaisesRegex(library.LibraryError,'SERVICE_UNAVAILABLE') as error:self.preview()
        self.assertNotIn('PRIVATE_MARKER',str(error.exception))
        with LibraryRecords(self.records,'deployment-1') as records:
            receipt=records.record('preview',project_identity=self.scope.project_identity)['receipt']
        self.assertEqual(receipt['outcome'],'NOT_DURABLE')

    def test_known_gate_failure_terminalizes_internal_intent(self):
        p=self.preview()
        with patch('uas.library_import.library_gate.validate',side_effect=library.LibraryError('INVALID_BUNDLE')):
            with self.assertRaisesRegex(library.LibraryError,'INVALID_BUNDLE'):self.confirm(p)
        with LibraryRecords(self.records,'deployment-1') as records:
            public=records.record('confirm',project_identity=self.scope.project_identity)
            internal=records.record('manifest:'+library._digest('confirm'),project_identity=self.scope.project_identity)
        self.assertEqual(public['receipt']['outcome'],'REFUSED')
        self.assertEqual(internal['receipt']['outcome'],'REFUSED')
        self.assertEqual(self.count(),1)

    def test_raw_author_policy_before_markdown_escape(self):
        real=self.source._git
        marker='ghp_'+'A'*36
        def author(args,limit,current):
            value=real(args,limit,current)
            return (marker+'\0'+'2026-10-30T00:00:00+00:00\n').encode() if 'log' in args else value
        with patch.object(self.source,'_git',side_effect=author):
            with self.assertRaisesRegex(library.LibraryError,'SECRET_DETECTED'):self.preview()
            self.assertEqual(self.count(),1)
            doc=support.document();doc['repository'].update(self.settings['repository'])
            doc['filters']['high_confidence']='observe';self.settings=support.settings(doc)
            p=self.preview(name='allowed-preview');result=self.confirm(p)
        self.assertTrue(any(e['rule']=='github-token' for e in result.receipt['evidence']))
        self.assertNotIn(marker,json.dumps(result.receipt))

if __name__=='__main__':unittest.main()
