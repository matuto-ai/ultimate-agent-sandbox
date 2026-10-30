"""T23 committed inspection: real service/Git and hosted private Unix socket."""
from copy import deepcopy
import errno
import json
import os
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest.mock import patch

import library_support as support
import test_library_controls as controls_fixture
from uas import library, library_bundle as bundle, library_gate as gate
from uas.library_controls import Controls, canonical, request, serve, MAX_RESPONSE
from uas.library_compiler import compile_proposal


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.fx = controls_fixture.ControlsTests('test_operational_ack_no_git_or_model_and_exact_retry')
        self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.source, self.service = self.fx.source, self.fx.service
        self.controls = self.fx.controls
        self.root = self.fx.root
        self.q = self.fx.fx.fixture.q
        self.allowed = True; self.connected = True; self.open_counter = 0
        self.principal = library.LocalHuman('human','actor','authority-1',
            lambda p,key,action:self.allowed and key == self.source.scope.project_identity
                and action == 'library-inspect',lambda:self.connected)
    def send(self, value):
        try: return {'outcome':'observed','result':self.controls.handle(canonical(value),self.principal)}
        except library.LibraryError as e:return {'outcome':'unknown','error':e.code}
    def observe(self, q=None):
        response=self.send(dict(version=1,action='observe',for_action='inspect',project_id='alpha',queue_id=q or self.q))
        self.assertEqual(response['outcome'],'observed',response)
        return response['result']
    def opening(self, q=None):
        evidence=self.observe(q);self.open_counter+=1
        return dict(version=1,action='inspect',project_id='alpha',queue_id=evidence['queue_id'],
            request_id='open-'+str(self.open_counter),settings_id=evidence['settings_id'],observed_version=evidence['observed_version'])
    def limit(self, key, value):
        document=support.document();document['repository']=deepcopy(self.source.settings['repository'])
        document['limits'][key]=value
        self.source.settings=support.settings(document)
    def replace_draft(self, body):
        path='projects/'+self.source.scope.project_path+'/pending/'+self.q+'.md'
        text=self.source.contents('pending/'+self.q+'.md').replace('Selected draft data.',body)
        self.source.mutate({path:text.encode()})
    def concept(self, title='Context one', body='CONTEXT_PRIVATE_MARKER'):
        q=self.source.capture('concept-'+title.replace(' ','-'))
        scope=self.source.scope; settings=self.source.settings
        head,tree=self.source.publisher.project_snapshot(scope,settings,current=lambda:None)
        proposal=dict(version=1,drain_id='make-concept',attempt=1,
            operations=[dict(id='one',op='create',drafts=[q],type='context',title=title,description='Required context',body=body)],
            outcomes=[dict(queue_id=q,kind='integrated',targets=['one'])])
        result=compile_proposal(scope,settings,current=tree,selected=[q],input_sha=head,
            drain_id='make-concept',attempt=1,at=support.AT,proposal=proposal)
        changes={p:data for p,data in result.tree.files.items() if tree.files.get(p)!=data}
        for path in tree.files:
            if path not in result.tree.files: changes[path]=None
        self.source.mutate(changes)
        return result.paths['one']
    def test_exact_committed_item_provenance_and_version_evidence_no_content_write(self):
        value=self.opening();before=self.source.count();response=self.send(value)
        self.assertEqual(response['outcome'],'observed',response);result=response['result']
        self.assertEqual(result['item']['text'],self.source.contents('pending/'+self.q+'.md'))
        self.assertIn('Submission Actor: actor-alpha',result['item']['text'])
        self.assertIn('Originating Run:',result['item']['text'])
        for key in ('commit_sha','target_version','content_version','settings_id','observed_version'):
            self.assertTrue(result[key])
        self.assertEqual(result['commit_sha'],self.source.head());self.assertEqual(self.source.count(),before)
        self.assertEqual(result['context'],[]);self.assertEqual(result['media_type'],'text/plain')
    def test_observation_has_no_content_and_no_unselected_item(self):
        self.source.capture('other',body='UNSELECTED_PRIVATE_MARKER')
        result=self.observe();self.assertNotIn('Selected draft data.',canonical(result).decode())
        opened=self.send(self.opening())
        self.assertNotIn('UNSELECTED_PRIVATE_MARKER',canonical(opened).decode())
    def test_direct_context_only_and_no_recursive_expansion(self):
        two=self.concept('Context two','SECOND_HOP_PRIVATE_MARKER')
        one=self.concept(body='CONTEXT_PRIVATE_MARKER\n[More](/'+two+')')
        self.replace_draft('Selected draft data.\n[Required](/'+one+')')
        result=self.send(self.opening())['result']
        self.assertEqual([x['reference'] for x in result['context']],[one])
        self.assertIn('CONTEXT_PRIVATE_MARKER',canonical(result).decode())
        self.assertNotIn('SECOND_HOP_PRIVATE_MARKER',canonical(result).decode())
        self.assertTrue(result['insufficient_context']);self.assertIn('RECURSION_NOT_EXPANDED',result['reasons'])
    def test_provenance_source_selects_exact_local_context_without_fetch(self):
        concept=self.concept()
        q=self.source.capture('with-source',sources=[{'resource':concept}])
        result=self.send(self.opening(q))['result']
        self.assertEqual([x['reference'] for x in result['context']],[concept])
        self.assertFalse(result['remote_resources'])
    def test_external_image_html_are_inert_and_never_fetched(self):
        # Historical unchanged reader data remains inert, not new writer output.
        self.replace_draft('<img src="https://never-fetch.test/pixel">\n![remote](https://never-fetch.test/img)\n[external](https://never-fetch.test/doc)')
        result=self.send(self.opening())['result']
        self.assertIn('<img',result['item']['text']);self.assertEqual(result['context'],[])
        self.assertTrue(result['insufficient_context']);self.assertFalse(result['remote_resources'])
    def test_cross_project_and_other_pending_links_are_not_context(self):
        other=self.source.capture('other',body='OTHER_PENDING_MARKER')
        self.replace_draft('[Sibling](/projects/other/context/secret.md)\n[Other]('+other+'.md)')
        result=self.send(self.opening())['result']
        self.assertEqual(result['context'],[]);self.assertTrue(result['insufficient_context'])
        self.assertNotIn('OTHER_PENDING_MARKER',canonical(result).decode())
        import test_library_scheduler as scheduler_tests
        fixture=self.fx.fx
        fixture.scheduler=self.service.scheduler;fixture.runner=fixture.fixture.runner();fixture.replies=[]
        fixture.register=lambda runner:scheduler_tests.SchedulerTests.register(fixture,runner)
        _,queue=scheduler_tests.SchedulerTests.second(fixture)
        refused=self.send(dict(version=1,action='observe',for_action='inspect',project_id='beta',queue_id=queue))
        self.assertEqual(refused['error'],'FORBIDDEN');self.assertNotIn('Beta data',canonical(refused).decode())
    def test_paths_recursive_context_and_authority_cannot_be_requested(self):
        value=self.opening()
        for field in ('path','context','recursive','actor_id','human_id','scope','sources'):
            self.assertEqual(self.send({**value,field:'forged'})['error'],'INVALID_CONTROL_REQUEST')
        for q in ('../secret','pending/x.md','a'*63):
            self.assertNotEqual(self.send({**value,'queue_id':q})['outcome'],'observed')
    def test_revocation_reconnect_and_reusing_request_id_require_fresh_open(self):
        value=self.opening();self.assertEqual(self.send(value)['outcome'],'observed')
        self.allowed=False;self.assertEqual(self.send(value)['error'],'FORBIDDEN')
        self.allowed=True;self.connected=False;self.assertEqual(self.send(value)['error'],'FORBIDDEN')
        self.connected=True;self.assertEqual(self.send(value)['outcome'],'observed')
        self.principal=library.LocalHuman('settings','actor','v2',lambda p,k,a:k is None,lambda:True)
        self.assertEqual(self.send(value)['error'],'FORBIDDEN')
    def test_new_human_or_authority_version_requires_new_observation(self):
        value=self.opening()
        self.principal=library.LocalHuman('other-human','other-actor','authority-2',lambda *args:True,lambda:True)
        self.assertEqual(self.send(value)['error'],'STALE_INSPECTION')
        self.assertEqual(self.send(self.opening())['outcome'],'observed')
    def test_changed_request_payload_conflicts_but_exact_read_is_fresh(self):
        value=self.opening();self.assertEqual(self.send(value)['outcome'],'observed')
        self.assertEqual(self.send(value)['outcome'],'observed')
        q=self.source.capture('later')
        changed=self.opening(q);changed['request_id']=value['request_id']
        self.assertEqual(self.send(changed)['error'],'ID_CONFLICT')
        self.assertEqual(self.send(value)['error'],'STALE_INSPECTION')
    def test_retention_preserves_read_identity_without_body_replay(self):
        from test_library_retention import AUDIT,FUTURE
        value=self.opening();self.assertEqual(self.send(value)['outcome'],'observed')
        with self.service.scheduler._records() as records:
            records.configure_retention(AUDIT);records.compact(now=FUTURE)
        self.assertEqual(self.send(value)['outcome'],'observed')
        q=self.source.capture('after-compaction')
        changed=self.opening(q);changed['request_id']=value['request_id']
        self.assertEqual(self.send(changed)['error'],'ID_CONFLICT')
    def test_identity_capacity_failure_discloses_no_body(self):
        from uas.library_records import LibraryRecords
        value=self.opening()
        with patch.object(LibraryRecords,'inspection_identity',side_effect=library.LibraryError('RECORD_CAPACITY')):
            result=self.send(value)
        self.assertEqual(result['error'],'RECORD_CAPACITY');self.assertNotIn('result',result)
    def test_configuration_changed_during_snapshot_discloses_nothing(self):
        value=self.opening();original=self.source.publisher.project_snapshot
        def snapshot(*args,**kwargs):
            result=original(*args,**kwargs);self.limit('inspection_bytes',8000);return result
        with patch.object(self.source.publisher,'project_snapshot',snapshot):
            result=self.send(value)
        self.assertEqual(result['error'],'STALE_INSPECTION');self.assertNotIn('result',result)
    def test_restart_retains_identity_but_not_response(self):
        value=self.opening();self.assertEqual(self.send(value)['outcome'],'observed')
        self.fx.fx.restart();self.service=self.fx.fx.service
        self.controls.service=self.service
        self.allowed=False;self.assertEqual(self.send(value)['error'],'FORBIDDEN')
        self.allowed=True;self.assertEqual(self.send(value)['outcome'],'observed')
        self.replace_draft('POST_RESTART_NEW_BODY')
        changed=self.opening();changed['request_id']=value['request_id']
        self.assertEqual(self.send(changed)['error'],'ID_CONFLICT')
        self.assertEqual(self.send(value)['error'],'STALE_INSPECTION')
    def test_required_total_context_limit_never_defaults(self):
        document=support.document();del document['limits']['inspection_context_bytes']
        with self.assertRaises(library.LibraryError):support.settings(document)
        for bad in (0,-1,True,1048577):
            document=support.document();document['limits']['inspection_context_bytes']=bad
            with self.assertRaises(library.LibraryError):support.settings(document)
    def test_current_authority_revoked_during_snapshot_discloses_nothing(self):
        value=self.opening();original=self.source.publisher.project_snapshot
        def snapshot(*args,**kwargs):
            result=original(*args,**kwargs);self.allowed=False;return result
        with patch.object(self.source.publisher,'project_snapshot',snapshot):
            result=self.send(value)
        self.assertEqual(result['error'],'FORBIDDEN');self.assertNotIn('result',result)
    def test_configuration_target_and_any_project_content_change_stales_open(self):
        value=self.opening();self.replace_draft('NEW_BODY')
        self.assertEqual(self.send(value)['error'],'STALE_INSPECTION')
        value=self.opening();self.source.capture('later')
        self.assertEqual(self.send(value)['error'],'STALE_INSPECTION')
        value=self.opening();self.limit('inspection_bytes',8000)
        self.assertEqual(self.send(value)['error'],'STALE_INSPECTION')
    def test_item_and_context_have_distinct_byte_bounds(self):
        context=self.concept(body='CONTEXT_PRIVATE_MARKER'*30)
        self.replace_draft('[Context](/'+context+')')
        size=len(self.source.contents('pending/'+self.q+'.md').encode())
        self.limit('inspection_context_bytes',size+10)
        result=self.send(self.opening())['result']
        self.assertEqual(result['context'],[]);self.assertEqual(result['context_bytes'],size)
        self.assertTrue(result['insufficient_context']);self.assertIn('CONTEXT_LIMIT',result['reasons'])
        self.limit('inspection_context_bytes',size-1)
        self.assertEqual(self.send(self.opening())['error'],'INSPECTION_CONTEXT_LIMIT')
    def test_complete_encoded_response_limit_and_context_omission(self):
        concept=self.concept(body='More text '*90)
        self.replace_draft('[Context](/'+concept+')')
        self.limit('inspection_bytes',1600)
        result=self.send(self.opening())
        self.assertEqual(result['outcome'],'observed',result)
        self.assertLessEqual(len(canonical(result)),1600)
        self.assertTrue(result['result']['insufficient_context'])
        self.limit('inspection_bytes',100)
        self.assertEqual(self.send(self.opening())['error'],'INSPECTION_RESPONSE_LIMIT')
    def test_missing_item_context_and_queue_removed_by_publication(self):
        self.assertEqual(self.send(dict(version=1,action='observe',for_action='inspect',project_id='alpha',queue_id='a'*64))['error'],'PENDING_ITEM_UNAVAILABLE')
        self.replace_draft('[Missing](/context/missing.md)')
        result=self.send(self.opening())['result'];self.assertIn('MISSING_CONTEXT',result['reasons'])
        value=self.opening()
        self.source.mutate({'projects/'+self.source.scope.project_path+'/pending/'+self.q+'.md':None})
        self.assertEqual(self.send(value)['error'],'PENDING_ITEM_UNAVAILABLE')
    def test_response_bodies_absent_from_records_hub_logs_and_replay(self):
        self.replace_draft('UNIQUE_INSPECTION_BODY_MARKER')
        value=self.opening();before=self.source.records.read_bytes();count=self.source.count()
        result=self.send(value);self.assertIn('UNIQUE_INSPECTION_BODY_MARKER',canonical(result).decode())
        self.assertNotEqual(self.source.records.read_bytes(),before);self.assertEqual(self.source.count(),count)
        self.assertFalse(self.fx.fx.path.exists())
        for path in self.source.base.glob('*.db*'):
            self.assertNotIn(b'UNIQUE_INSPECTION_BODY_MARKER',path.read_bytes())
    def test_archived_project_refuses(self):
        value=self.opening()
        path='projects/'+self.source.scope.project_path+'/index.md'
        self.source.mutate({path:self.source.root_bytes()+b'\nLibrary state: archived\n'})
        self.assertEqual(self.send(value)['error'],'PROJECT_ARCHIVED')
    def test_closed_service_refuses(self):
        value=self.opening();self.fx.fx.service.shutdown()
        self.assertEqual(self.send(value)['error'],'SERVICE_NOT_AVAILABLE')


class NativeInspectionTests(InspectionTests):
    def setUp(self):
        # CI must run real sockets; sandbox-only skips are explicit, not proof.
        probe=None
        try:
            probe=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);probe.bind('')
        except OSError as error:
            if error.errno==errno.EPERM and os.environ.get('GITHUB_ACTIONS')!='true':
                self.skipTest('environment denies Unix socket bind')
            raise
        finally:
            if probe is not None:probe.close()
        super().setUp()
        self.stop=threading.Event();self.errors=[]
        def run():
            try:serve(self.root,self.controls,authenticate=lambda uid:self.principal,stopped=self.stop.is_set)
            except BaseException as error:self.errors.append(error)
        self.thread=threading.Thread(target=run);self.thread.start();self.addCleanup(self.close)
        deadline=time.monotonic()+2
        while not (self.root/'library-operator.sock').exists() and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue((self.root/'library-operator.sock').exists())
    def send(self,value):
        try:return request(self.root,value)
        except library.LibraryError as e:return {'outcome':'unknown','error':e.code}
    def close(self):
        self.stop.set();self.thread.join(3);self.assertFalse(self.thread.is_alive());self.assertFalse(self.errors)
