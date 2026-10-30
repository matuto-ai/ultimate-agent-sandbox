"""Explicit service enqueue through real disposable canonical Git and records."""
from dataclasses import replace
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

import library_support as support
from test_library_git import git
import test_library_registration as registration
from uas import library, library_bundle
from uas.library_enqueue import Enqueuer
from uas.library_records import LibraryRecords
from uas.library_registration import Registrar
from uas.library_projection import ProjectProjection


class EnqueueTests(unittest.TestCase):
    make_scope = registration.RegistrationTests.make_scope
    make_publisher = registration.RegistrationTests.make_publisher
    head = registration.RegistrationTests.head
    count = registration.RegistrationTests.count
    mutate = registration.RegistrationTests.mutate
    root = registration.RegistrationTests.root
    root_bytes = registration.RegistrationTests.root_bytes

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.target = self.base/'canonical.git'
        git(self.base, 'init', '--bare', '-q', str(self.target))
        self.records = self.base/'records.db'
        LibraryRecords(self.records, 'deployment-1').close()
        doc = support.document()
        doc['repository'].update(target='ssh://git@example.test/library.git', branch='main')
        self.settings = support.settings(doc)
        human = self.make_scope()
        self.publisher = self.make_publisher()
        self.publisher.startup()
        self.addCleanup(self.publisher.close)
        Registrar(self.publisher, current_scope=lambda: human).register(
            library.action(human, self.settings, kind='register', operation_id='register',
                           request_id='register', payload={}, at=support.AT), self.settings)
        self.scope = library.participant_scope(support.ORIGIN, binding=support.binding())
        self.fresh = self.scope
        self.run = 'closed-run-1'
        self.service = Enqueuer(self.publisher, current_scope=lambda: self.fresh,
                                current_run=lambda: self.run)

    def enqueue(self, command='command-1', request='request-1', value=None, at=support.AT):
        return self.service.enqueue(self.settings, operation_id=command, request_id=request,
                                    value=support.value() if value is None else value, at=at)

    def contents(self, path, sha=None):
        return git(self.target, 'show', (sha or self.head())+':projects/'+self.scope.project_path+'/'+path)

    def test_escaped_markdown_title_publishes_through_real_gate(self):
        for index, title in enumerate(('PRIVATE_TITLE_MARKER', 'A [nested] title', r'A \ path', 'Use *stars* and `code`')):
            with self.subTest(title=title):
                result = self.enqueue('title-op-'+str(index), 'title-request-'+str(index), support.value(title=title))
                self.assertEqual(result.outcome, 'DURABLY_QUEUED', result)
                meta, _ = library_bundle.frontmatter(self.contents(result.path), result.path)
                self.assertEqual(meta['title'], title)

    def test_real_publication_metadata_and_separate_visibility(self):
        result = self.enqueue()
        self.assertEqual(result.outcome, 'DURABLY_QUEUED', result)
        self.assertEqual(result.published_sha, self.head())
        self.assertEqual(result.path, 'pending/'+result.queue_id+'.md')
        self.assertFalse(result.visible)
        self.assertIsNone(result.projection_sha)
        text = self.contents(result.path)
        meta, body = library_bundle.frontmatter(text, result.path)
        self.assertEqual(meta['status'], 'draft')
        self.assertEqual(str(meta['generated']), 'true')
        self.assertIn('Submission Actor: actor-alpha', body)
        self.assertIn('Originating Run: closed-run-1', body)
        self.assertIn(support.AT, body)
        self.assertIn(support.value()['body'], body)
        self.assertEqual(self.count(), 2)
        with LibraryRecords(self.records, 'deployment-1') as records:
            record = records.record('command-1', project_identity=self.scope.project_identity)
            self.assertEqual(record['receipt']['publication']['commit_sha'], self.head())

    def test_exact_and_new_actor_retry_preserve_original_commit_log_provenance(self):
        first = self.enqueue()
        self.assertEqual(self.enqueue(), first)
        log = self.contents('log.md')
        self.fresh = library.participant_scope(support.OTHER, binding=support.binding())
        self.run = 'other-run'
        again = self.enqueue('command-2', at='2026-10-30T00:00:00+00:00')
        self.assertEqual(again, first)
        self.assertEqual(self.count(), 2)
        self.assertEqual(log, self.contents('log.md'))
        with LibraryRecords(self.records, 'deployment-1') as records:
            submission = records.submission(self.scope.project_identity, 'request-1')
        self.assertEqual(submission['origin']['actor_id'], 'actor-alpha')
        self.assertEqual(submission['origin']['run_id'], 'closed-run-1')
        self.assertEqual(submission['attempts'][1]['scope']['actor_id'], 'actor-beta')
        self.assertEqual(submission['attempts'][1]['provenance'], submission['origin'])

    def test_changed_id_payload_conflicts_different_ids_distinct(self):
        first = self.enqueue()
        conflict = self.enqueue('other', value=support.value(body='Changed'))
        self.assertEqual((conflict.outcome,conflict.reason), ('REJECTED','ID_CONFLICT'))
        other = self.enqueue('third','request-2')
        self.assertEqual(other.outcome, 'DURABLY_QUEUED')
        self.assertNotEqual(other.queue_id,first.queue_id)
        self.assertEqual(self.count(),3)

    def test_exact_command_reuse_different_actor_is_conflict(self):
        self.enqueue()
        self.fresh = library.participant_scope(support.OTHER, binding=support.binding())
        result = self.enqueue()
        self.assertEqual(result.reason, 'ID_CONFLICT')
        self.assertEqual(self.count(),2)

    def test_revoked_authority_retry_does_not_disclose_success(self):
        self.enqueue()
        self.fresh = None
        result = self.enqueue('retry')
        self.assertEqual(result.outcome, 'REJECTED')
        self.assertIsNone(result.published_sha)
        self.assertEqual(self.count(),2)

    def test_forbidden_scope_and_payload_cannot_forge_authority(self):
        for key in ('project_id','actor_id','generated','status','frontmatter','queue_id','path'):
            value = support.value(); value[key] = 'forged'
            result = self.enqueue(value=value)
            self.assertEqual(result.outcome,'REJECTED',result)
        self.fresh = self.make_scope()
        self.assertEqual(self.enqueue().outcome,'REJECTED')
        self.assertEqual(self.count(),1)

    def test_research_source_and_input_bounds(self):
        for value in ({'type':'research','title':'Research','body':'Text'},
                      support.value(title='x'*201),support.value(body='x'*16385),
                      support.value(body=' '),support.value(body='---\nstatus: stable\n---\nHi')):
            result = self.enqueue(command='c-'+str(len(value['body'])),request='r-'+str(len(value['body'])),value=value)
            self.assertEqual(result.outcome,'REJECTED',result)
        self.assertEqual(self.count(),1)

    def test_gate_refusal_is_permanent_for_request(self):
        value = support.value(body='![image](https://example.test/image)')
        result = self.enqueue(value=value)
        self.assertEqual(result.outcome,'REJECTED')
        self.assertEqual(result.reason,'IMAGE_NOT_ALLOWED')
        self.assertEqual(self.enqueue('again',value=value).reason,result.reason)
        self.assertEqual(self.enqueue('corrected',value=support.value()).reason,'ID_CONFLICT')
        self.assertEqual(self.enqueue('new','new',value=support.value()).outcome,'DURABLY_QUEUED')

    def test_archived_project_does_not_enqueue_or_restore(self):
        self.mutate({self.root():self.root_bytes()+b'\nLibrary state: archived\n'})
        before=self.head()
        result=self.enqueue()
        self.assertEqual(result.reason,'PROJECT_ARCHIVED')
        self.assertEqual(result.outcome,'REJECTED')
        self.assertEqual(self.head(),before)

    def test_unregistered_project_no_hidden_initialization(self):
        self.fresh = library.participant_scope(support.OTHER,binding=support.binding('beta','acme/beta','2002'))
        result=self.enqueue()
        self.assertEqual(result.reason,'PROJECT_NOT_REGISTERED')
        self.assertEqual(self.count(),1)

    def test_failure_before_publication_retry_uses_original_provenance(self):
        with patch.object(self.publisher,'publication_for',side_effect=library.LibraryError('PUBLICATION_UNAVAILABLE')):
            result=self.enqueue()
        self.assertEqual((result.outcome,result.retryable),('NOT_DURABLE',True))
        self.assertEqual(self.count(),1)
        self.fresh=library.participant_scope(support.OTHER,binding=support.binding())
        self.run=None
        again=self.enqueue('retry')
        self.assertEqual(again.outcome,'DURABLY_QUEUED',again)
        self.assertIn('Submission Actor: actor-alpha',self.contents(again.path))
        self.assertIn('Originating Run: closed-run-1',self.contents(again.path))

    def test_lost_publication_response_is_reconciled_without_duplicate(self):
        publish=self.publisher.publish
        def lost(*args,**kwargs):
            publish(*args,**kwargs)
            raise library.LibraryError('PUBLICATION_UNCERTAIN')
        with patch.object(self.publisher,'publish',side_effect=lost):
            result=self.enqueue()
        self.assertEqual(result.outcome,'NOT_DURABLE')
        before=self.head()
        result=self.enqueue('retry')
        self.assertEqual(result.outcome,'DURABLY_QUEUED',result)
        self.assertEqual(result.published_sha,before)
        self.assertEqual(self.count(),2)

    def test_crash_after_publication_before_receipt_recovers(self):
        finish=LibraryRecords.finish
        def crash(*args,**kwargs): raise KeyboardInterrupt()
        with patch.object(LibraryRecords,'finish',side_effect=crash):
            with self.assertRaises(KeyboardInterrupt): self.enqueue()
        before=self.head()
        self.publisher.close()
        self.publisher=self.make_publisher();self.publisher.startup()
        self.addCleanup(self.publisher.close)
        self.service=Enqueuer(self.publisher,current_scope=lambda:self.fresh,current_run=lambda:self.run)
        result=self.enqueue()
        self.assertEqual(result.outcome,'DURABLY_QUEUED',result)
        self.assertEqual(result.published_sha,before)
        self.assertEqual(self.count(),2)

    def test_receipt_storage_failure_never_claims_success(self):
        with patch.object(LibraryRecords,'finish',side_effect=library.LibraryError('RECORD_UNCERTAIN')):
            result=self.enqueue()
        self.assertEqual(result.outcome,'NOT_DURABLE')
        self.assertEqual(self.enqueue('retry').outcome,'DURABLY_QUEUED')
        self.assertEqual(self.count(),2)

    def test_current_authority_rechecked_before_commit(self):
        original=self.publisher.project_snapshot
        def revoked(*a,**kw):
            result=original(*a,**kw);self.fresh=None;return result
        with patch.object(self.publisher,'project_snapshot',side_effect=revoked): result=self.enqueue()
        self.assertEqual(result.outcome,'REJECTED')
        self.assertEqual(self.count(),1)

    def test_stale_basis_is_retryable_and_does_not_overwrite(self):
        with patch.object(self.publisher,'publish',side_effect=library.LibraryError('INCOMPATIBLE_HEAD')):
            result=self.enqueue()
        self.assertEqual(result.outcome,'NOT_DURABLE')
        self.assertEqual(self.enqueue('retry').outcome,'DURABLY_QUEUED')

    def test_safe_records_and_errors_do_not_contain_submitted_marker(self):
        marker='CONFIDENTIAL_BODY_MARKER_abc'
        result=self.enqueue(value=support.value(body=marker))
        self.assertEqual(result.outcome,'DURABLY_QUEUED')
        with LibraryRecords(self.records,'deployment-1') as records:
            stored=records.submission(self.scope.project_identity,'request-1')
        self.assertNotIn(marker,json.dumps(stored))
        self.assertNotIn(marker,str(result))
        for path in self.base.glob('records.db*'):
            self.assertNotIn(marker.encode(),path.read_bytes())
        with patch.object(self.publisher,'publication_for',side_effect=RuntimeError(marker)):
            failed=self.enqueue('other','other',value=support.value(body=marker))
        self.assertEqual(failed.reason,'SERVICE_UNAVAILABLE')
        self.assertNotIn(marker,str(failed))

    def test_projection_advance_and_lag_are_independent(self):
        root=self.base/'reference';root.mkdir()
        binding=support.binding();binding['reference_root']=str(root/'library')
        self.scope=library.participant_scope(support.ORIGIN,binding=binding);self.fresh=self.scope
        projection=ProjectProjection(self.publisher,self.scope,self.settings,current_scope=lambda:self.fresh)
        self.addCleanup(projection.close)
        self.service.projection=projection
        first=self.enqueue()
        self.assertEqual(first.outcome,'DURABLY_QUEUED',first)
        self.assertFalse(first.visible)
        projection.refresh()
        retry=self.enqueue('retry')
        self.assertTrue(retry.visible,retry)
        self.assertEqual(retry.projection_sha,first.published_sha)
        second=self.enqueue('next','next')
        projection.refresh()
        visible=self.enqueue('retry2')
        self.assertTrue(visible.visible)
        self.assertEqual(visible.projection_sha,second.published_sha)
        self.assertEqual(visible.published_sha,first.published_sha)

    def test_no_run_is_required(self):
        self.run=None
        result=self.enqueue()
        self.assertEqual(result.outcome,'DURABLY_QUEUED',result)
        self.assertNotIn('Originating Run:',self.contents(result.path))

    def test_concurrent_exact_service_attempt_creates_one_commit(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:self.enqueue(),range(2)))
        self.assertEqual(results[0],results[1])
        self.assertEqual(results[0].outcome,'DURABLY_QUEUED')
        self.assertEqual(self.count(),2)

    def test_actual_git_lost_ack_reconciles(self):
        self.publisher.close()
        self.publisher=self.make_publisher(registration.LostAckTransport,lose_push=True)
        self.publisher.startup();self.addCleanup(self.publisher.close)
        self.service=Enqueuer(self.publisher,current_scope=lambda:self.fresh)
        result=self.enqueue()
        self.assertEqual(result.outcome,'DURABLY_QUEUED',result)
        self.assertEqual(self.count(),2)

    def test_new_authorized_retry_after_postpublication_revocation_reconciles(self):
        original=self.publisher.publish
        def revoked(*args,**kwargs):
            result=original(*args,**kwargs);self.fresh=None;return result
        with patch.object(self.publisher,'publish',side_effect=revoked): failed=self.enqueue()
        self.assertEqual(failed.outcome,'REJECTED')
        self.assertEqual(self.count(),2)
        self.fresh=self.scope
        recovered=self.enqueue('retry')
        self.assertEqual(recovered.outcome,'DURABLY_QUEUED',recovered)
        self.assertEqual(self.count(),2)

    def test_projection_failure_does_not_change_durability(self):
        class Broken:
            def read(self): raise OSError('not visible')
        self.service.projection=Broken()
        result=self.enqueue()
        self.assertEqual(result.outcome,'DURABLY_QUEUED')
        self.assertFalse(result.visible)
        self.assertEqual(result.published_sha,self.head())

    def test_wrong_project_projection_does_not_disclose_commit(self):
        class Other:
            def read(self):
                from types import SimpleNamespace
                return SimpleNamespace(manifest={'project_id':'other','project_identity':'other'},files={})
        self.service.projection=Other()
        result=self.enqueue()
        self.assertEqual(result.outcome,'DURABLY_QUEUED')
        self.assertIsNone(result.projection_sha)

    def test_recovery_does_not_reenqueue_historically_integrated_draft(self):
        first=self.enqueue()
        prefix='projects/'+self.scope.project_path+'/'
        index=self.contents('pending/index.md')
        self.mutate({prefix+first.path:None,prefix+'pending/index.md':index.split('\n* [')[0].encode()})
        before=self.head()
        again=self.enqueue('retry')
        self.assertEqual(again.published_sha,first.published_sha)
        self.assertEqual(self.head(),before)
        self.assertFalse(again.visible)

    def test_no_current_capability_no_content_or_record(self):
        from uas.ledger import Origin
        origin=Origin('actor-alpha','seat-a','inc-1','epoch-1',('implement',))
        self.service.current_scope=lambda: library.participant_scope(origin,binding=support.binding())
        result=self.enqueue()
        self.assertEqual(result.outcome,'REJECTED')
        self.assertEqual(self.count(),1)

    def test_trusted_authority_outage_is_retryable_not_input_refusal(self):
        def unavailable(): raise library.LibraryError('AUTHORITY_UNAVAILABLE')
        self.service.current_scope=unavailable
        result=self.enqueue()
        self.assertEqual((result.outcome,result.reason,result.retryable),
                         ('NOT_DURABLE','AUTHORITY_UNAVAILABLE',True))
        self.assertEqual(self.count(),1)

    def test_missing_settings_is_not_a_permanent_capture_refusal(self):
        self.settings=None
        result=self.enqueue()
        self.assertEqual(result.outcome,'NOT_DURABLE')
        self.assertEqual(self.count(),1)

    def test_safe_credential_evidence_is_durable_without_match_bytes(self):
        secret='ghp_'+'A'*36
        result=self.enqueue(value=support.value(body=secret))
        self.assertEqual(result.outcome,'REJECTED')
        self.assertEqual(result.reason,'SECRET_DETECTED')
        with LibraryRecords(self.records,'deployment-1') as records:
            record=records.record('command-1',project_identity=self.scope.project_identity)
        evidence=record['receipt']['evidence']
        self.assertEqual(evidence[0]['rule'],'github-token')
        self.assertIn('path',evidence[0]);self.assertIn('sha256',evidence[0])
        self.assertNotIn(secret,json.dumps(record))
        observed=self.enqueue('observe','observe',value=support.value(body='password: arbitrarysuspiciousvalue012345'))
        self.assertEqual(observed.outcome,'DURABLY_QUEUED',observed)
        with LibraryRecords(self.records,'deployment-1') as records:
            record=records.record('observe',project_identity=self.scope.project_identity)
        self.assertEqual(record['receipt']['evidence'][0]['rule'],'assigned-secret')

    def test_ordinary_horizontal_rule_and_fenced_yaml_are_allowed(self):
        for number,body in enumerate(('---\nAn ordinary rule then prose.', '```yaml\nstatus: stable\n```')):
            result=self.enqueue('markdown-'+str(number),'markdown-'+str(number),value=support.value(body=body))
            self.assertEqual(result.outcome,'DURABLY_QUEUED',result)

    def test_safe_findings_survive_lost_ack_and_receipt_crash(self):
        value=support.value(body='password: suspiciouscapturevalue987654321')
        original=self.publisher.publish
        def lost(*a,**kw):
            original(*a,**kw);raise library.LibraryError('PUBLICATION_UNCERTAIN')
        with patch.object(self.publisher,'publish',side_effect=lost):
            failed=self.enqueue(value=value)
        with LibraryRecords(self.records,'deployment-1') as records:
            first=records.record('command-1',project_identity=self.scope.project_identity)
        self.assertTrue(first['receipt']['evidence'])
        again=self.enqueue('retry',value=value)
        self.assertEqual(again.outcome,'DURABLY_QUEUED')
        with LibraryRecords(self.records,'deployment-1') as records:
            retried=records.record('retry',project_identity=self.scope.project_identity)
        self.assertEqual(first['receipt']['evidence'],retried['receipt']['evidence'])
        with patch.object(LibraryRecords,'finish',side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):self.enqueue('crash','crash',value=value)
        recovered=self.enqueue('recover','crash',value=value)
        self.assertEqual(recovered.outcome,'DURABLY_QUEUED')
        with LibraryRecords(self.records,'deployment-1') as records:
            record=records.record('recover',project_identity=self.scope.project_identity)
        self.assertTrue(record['receipt']['evidence'])

    def test_two_registered_projects_same_request_stay_distinct(self):
        first=self.enqueue()
        human=self.make_scope('beta','acme/beta','2002')
        Registrar(self.publisher,current_scope=lambda:human).register(
            library.action(human,self.settings,kind='register',operation_id='register-beta',
                           request_id='register-beta',payload={},at=support.AT),self.settings)
        self.fresh=library.participant_scope(support.OTHER,binding=support.binding('beta','acme/beta','2002'))
        second=self.enqueue('beta-command')
        self.assertEqual(second.outcome,'DURABLY_QUEUED',second)
        self.assertNotEqual(first.queue_id,second.queue_id)
        alpha=self.contents(first.path)
        beta=git(self.target,'show',self.head()+':projects/'+self.fresh.project_path+'/'+second.path)
        self.assertIn('Submission Actor: actor-alpha',alpha)
        self.assertIn('Submission Actor: actor-beta',beta)
        with LibraryRecords(self.records,'deployment-1') as records:
            a=records.submission(self.scope.project_identity,'request-1')
            b=records.submission(self.fresh.project_identity,'request-1')
            self.assertIsNone(records.record('command-1',project_identity=self.fresh.project_identity))
        self.assertNotEqual(a['origin']['actor_id'],b['origin']['actor_id'])
        self.fresh=self.scope
        self.assertEqual(self.enqueue('alpha-retry').published_sha,first.published_sha)
        self.assertEqual(self.count(),4)

    def test_receipt_evidence_bounds_and_tamper_rejected(self):
        operation=library.capture(self.scope,self.settings,operation_id='test',request_id='test',
                                  value=support.value(),at=support.AT)
        fact={'rule':'assigned-secret','path':'pending/example.md','line':1,'sha256':'a'*64}
        receipt=library.receipt(operation,'REJECTED',at=support.AT,reason='SECRET_DETECTED',evidence=[fact])
        self.assertEqual(library.admit_receipt(receipt),receipt)
        for evidence in ([fact]*65,[dict(fact,body='sensitive')],[dict(fact,sha256='bad')],
                         [dict(fact,line=0)],[dict(fact,path='x'*1025)]):
            with self.assertRaises(library.LibraryError):
                library.receipt(operation,'REJECTED',at=support.AT,reason='SECRET_DETECTED',evidence=evidence)

    def test_invalid_id_not_reflected_and_no_fallback_files(self):
        result=self.enqueue(request='../secret\ntext')
        self.assertEqual(result.outcome,'REJECTED')
        self.assertIsNone(result.request_id)
        self.assertEqual(self.count(),1)

if __name__=='__main__': unittest.main()
