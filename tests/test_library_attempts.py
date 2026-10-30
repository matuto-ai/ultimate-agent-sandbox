"""Real service attempts: disposable Git, durable records and controlled adapter."""
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
import library_support as support
import test_library_assembly as assembly_tests
from test_library_git import git
from uas import library
from uas.library_attempts import Attempts
from uas.library_dispatch import Dispatcher, Gateway, Profile, Evidence, Selection
from uas.library_records import LibraryRecords

class AttemptTests(unittest.TestCase):
    def setUp(self):
        self.source=assembly_tests.AssemblyTests('test_exact_request_separate_typed_data_and_no_unselected_content')
        self.source.setUp();self.addCleanup(self.source.doCleanups)
        self.q=self.source.capture(); self.selected=[self.q]
        self.marker=self.source.base/'contact'; self.audit=[]; self.hook=lambda e:None
        self.profile=Profile('synth-local','local','provider-one','v1','http://127.0.0.1:1234/selected','local','zero','terms-v1')
        def proof(ref):return Evidence(ref,self.profile.identity(),self.source.scope.project_identity,'2030-01-01T00:00:00+00:00')
        self.selection=Selection(self.profile,proof('synth-qualification'),proof('synth-local'))
        self.mode='success';self.number=1;self.reply=None
    def runner(self):
        reply=self.reply or dict(version=1,drain_id='drain-1',attempt=self.number,operations=[],
             outcomes=[dict(queue_id=q,kind='parked',reason='NEEDS_EVIDENCE') for q in self.selected])
        gateway=Gateway({self.profile.identity():(sys.executable,str(Path(__file__).with_name('fixture_library_provider.py')),
            str(self.marker),self.mode,json.dumps(reply))},interactive=lambda:False)
        def audit(e):self.audit.append(e);self.hook(e)
        dispatcher=Dispatcher(gateway,current_scope=lambda:self.source.fresh,settings=lambda:self.source.settings,
            selection=lambda s:self.selection,current=lambda r:True,token_count=lambda p,b:len(b),audit=audit,
            records_path=self.source.publisher.records_path,deployment_id=self.source.publisher.deployment_id,
            now=lambda:datetime(2026,10,30,tzinfo=timezone.utc))
        return Attempts(self.source.assembler(),dispatcher)
    def run_attempt(self,**kwargs):
        return self.runner().run(drain_id='drain-1',attempt=kwargs.pop('attempt',self.number),
            selected=kwargs.pop('selected',self.selected),at=kwargs.pop('at',support.AT),**kwargs)
    def operation_id(self,number=1):return 'attempt-'+library._digest([self.source.scope.project_identity,'drain-1',number])
    def records(self):return LibraryRecords(self.source.records,'deployment-1')
    def test_parking_commit_has_durable_inputs_before_contact_and_recovery_outcomes(self):
        before=self.source.head()
        def audit(e):
            if e['state']=='admitted':
                with self.records() as r:
                    saved=r.record(self.operation_id(),project_identity=self.source.scope.project_identity)
                    self.assertEqual(saved['manifest']['selected'],[self.q]);self.assertEqual(saved['manifest']['input_sha'],before)
                    self.assertEqual(saved['manifest']['request_sha256'],e['request_sha256'])
        self.hook=audit
        result=self.run_attempt(); self.assertEqual(result.state,'COMMITTED');self.assertEqual(result.input_sha,before)
        self.assertEqual(result.previous_sha,before);self.assertEqual(result.outcomes[0]['kind'],'parked')
        count=self.source.count();self.marker.unlink()
        self.assertEqual(result,self.run_attempt());self.assertFalse(self.marker.exists());self.assertEqual(count,self.source.count())
    def integrate(self):
        self.reply=dict(version=1,drain_id='drain-1',attempt=self.number,
            operations=[dict(id='one',op='create',drafts=[self.q],type='context',title='Accepted note',description='A fact.',body='Accepted body.')],
            outcomes=[dict(queue_id=self.q,kind='integrated',targets=['one'])])
    def test_atomic_integration_retains_later_draft_and_latest_parent(self):
        self.integrate(); original=self.source.head();later=[]
        def audit(e):
            if e['state']=='admitted':later.append(self.source.capture('later'))
        self.hook=audit;result=self.run_attempt()
        self.assertEqual(result.input_sha,original);self.assertNotEqual(result.previous_sha,original)
        self.assertIn(later[0],self.source.contents('pending/index.md'));self.assertNotIn(self.q+'.md',self.source.contents('pending/index.md'))
        message=git(self.source.target,'show','-s','--format=%B',result.resulting_sha)
        self.assertIn('Library-Input: '+original,message);self.assertIn('Library-Parent: '+result.previous_sha,message)
    def test_git_lock_is_free_during_provider_latency(self):
        import time
        self.integrate();self.mode='release';results=[];errors=[]
        def attempt():
            try:results.append(self.run_attempt())
            except Exception as error:errors.append(error)
        worker=threading.Thread(target=attempt);worker.start()
        try:
            deadline=time.monotonic()+3
            while not self.marker.exists() and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(self.marker.exists());self.assertTrue(worker.is_alive())
            enqueue=threading.Thread(target=lambda:self.source.capture('parallel'))
            enqueue.start();enqueue.join(2);self.assertFalse(enqueue.is_alive())
        finally:
            Path(str(self.marker)+'.release').touch();worker.join(5)
        self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
        self.assertEqual(results[0].state,'COMMITTED')
    def test_same_attempt_never_calls_again_after_model_failure(self):
        self.mode='error'
        with self.assertRaisesRegex(library.LibraryError,'MODEL_UNAVAILABLE'):self.run_attempt()
        self.assertTrue(self.marker.exists());self.marker.unlink();self.mode='success'
        with self.assertRaisesRegex(library.LibraryError,'NEW_ATTEMPT_REQUIRED'):self.run_attempt()
        self.assertFalse(self.marker.exists());self.number=2
        self.assertEqual(self.run_attempt().state,'COMMITTED')
    def test_fixed_batch_cannot_change_on_numbered_retry(self):
        self.mode='error'
        with self.assertRaises(library.LibraryError):self.run_attempt()
        other=self.source.capture('other');self.number=2
        with self.assertRaisesRegex(library.LibraryError,'ID_CONFLICT'):self.run_attempt(selected=[other])
    def test_changed_selected_input_discards_output_requires_new_attempt(self):
        prefix='projects/'+self.source.scope.project_path
        def audit(e):
            if e['state']=='returned':
                text=self.source.contents('pending/'+self.q+'.md').replace('Selected draft data.','Changed draft data.')
                self.source.mutate({prefix+'/pending/'+self.q+'.md':text.encode()})
        self.hook=audit
        with self.assertRaisesRegex(library.LibraryError,'ATTEMPT_INPUT_CHANGED'):self.run_attempt()
        self.assertIn(self.q,self.source.contents('pending/index.md'));self.hook=lambda e:None;self.number=2
        self.assertEqual(self.run_attempt().state,'COMMITTED')
    def test_invalid_output_publishes_nothing(self):
        self.integrate();self.reply['outcomes']=[];before=self.source.head()
        with self.assertRaises(library.LibraryError):self.run_attempt()
        self.assertEqual(before,self.source.head());self.assertIn(self.q,self.source.contents('pending/index.md'))
    def test_record_failure_before_contact_never_calls_model(self):
        original=LibraryRecords.begin
        def begin(r,op,**kw):
            if op.kind=='synthesis-attempt':raise library.LibraryError('RECORD_UNAVAILABLE')
            return original(r,op,**kw)
        with patch.object(LibraryRecords,'begin',begin),self.assertRaisesRegex(library.LibraryError,'RECORD_UNAVAILABLE'):self.run_attempt()
        self.assertFalse(self.marker.exists())
    def test_lost_receipt_recovers_from_canonical_history_without_model(self):
        original=LibraryRecords.finish
        def finish(r,op,receipt):
            if op.kind=='synthesis-attempt':raise library.LibraryError('RECORD_UNCERTAIN')
            return original(r,op,receipt)
        with patch.object(LibraryRecords,'finish',finish),self.assertRaisesRegex(library.LibraryError,'RECORD_UNCERTAIN'):self.run_attempt()
        sha=self.source.head();count=self.source.count();self.marker.unlink()
        result=self.run_attempt();self.assertEqual(result.resulting_sha,sha);self.assertEqual(count,self.source.count());self.assertFalse(self.marker.exists())
    def test_lost_push_response_recovers_before_retry(self):
        original=self.source.publisher._push
        def push(*args):original(*args);raise library.LibraryError('PUBLICATION_UNCERTAIN')
        with patch.object(self.source.publisher,'_push',push),self.assertRaisesRegex(library.LibraryError,'PUBLICATION_UNCERTAIN'):self.run_attempt()
        sha=self.source.head();self.marker.unlink();self.assertEqual(self.run_attempt().resulting_sha,sha);self.assertFalse(self.marker.exists())
    def test_new_attempt_reconciles_previous_canonical_commit(self):
        original=LibraryRecords.finish
        def finish(r,op,receipt):
            if op.kind=='synthesis-attempt':raise library.LibraryError('RECORD_UNCERTAIN')
            return original(r,op,receipt)
        with patch.object(LibraryRecords,'finish',finish),self.assertRaises(library.LibraryError):self.run_attempt()
        self.number=2;self.marker.unlink();result=self.run_attempt()
        self.assertEqual(result.attempt,1);self.assertFalse(self.marker.exists())
    def test_metadata_has_no_prompt_output_or_body(self):
        self.integrate();self.run_attempt()
        with self.records() as r:value=r.drain('drain-1',project_identity=self.source.scope.project_identity)
        data=json.dumps(value);self.assertNotIn('Selected draft data',data);self.assertNotIn('Accepted body',data)
        self.assertNotIn('instructions',data)
    def test_authority_revocation_during_response_no_publication(self):
        before=self.source.head()
        def audit(e):
            if e['state']=='returned':self.source.fresh=None
        self.hook=audit
        with self.assertRaisesRegex(library.LibraryError,'LIBRARY_AUTHENTICATION_REQUIRED'):self.run_attempt()
        self.assertEqual(before,self.source.head())
    def test_contact_audit_failure_does_not_allow_second_call(self):
        self.hook=lambda e:(_ for _ in ()).throw(OSError('PRIVATE'))
        with self.assertRaisesRegex(library.LibraryError,'DISPATCH_AUDIT_UNAVAILABLE'):self.run_attempt()
        self.hook=lambda e:None
        with self.assertRaisesRegex(library.LibraryError,'NEW_ATTEMPT_REQUIRED'):self.run_attempt()
        self.assertFalse(self.marker.exists())
    def test_batch_bounds_enforced_before_provider(self):
        self.source.limit('batch_drafts',1);self.selected.append(self.source.capture('two'))
        with self.assertRaises(library.LibraryError):self.run_attempt()
        self.assertFalse(self.marker.exists())

    def test_compatible_race_at_publish_recompiles_without_new_call(self):
        original=self.source.publisher.publish; later=[]
        def publish(op,*args,**kw):
            if op.kind=='synthesis-attempt' and not later:
                later.append(self.source.capture('last-moment'))
            return original(op,*args,**kw)
        with patch.object(self.source.publisher,'publish',publish):result=self.run_attempt()
        self.assertEqual(result.state,'COMMITTED');self.assertIn(later[0],self.source.contents('pending/index.md'))
        self.assertEqual(len([e for e in self.audit if e['state']=='admitted']),1)
    def test_source_parking_cannot_change_fixed_batch(self):
        declaration,_=self.source.source();q=self.source.capture('bad-source',sources=[declaration])
        result=self.run_attempt(selected=[q]);self.assertEqual(result.state,'SOURCE_PARKED')
        with self.assertRaisesRegex(library.LibraryError,'ID_CONFLICT'):self.run_attempt(attempt=2)
        self.assertFalse(self.marker.exists())
    def test_same_completed_attempt_changed_arguments_refused(self):
        self.run_attempt()
        for kw in ({'at':'2026-10-31T00:00:00+00:00'},{'indexes':['index.md']},{'accepted':['other']}):
            with self.assertRaisesRegex(library.LibraryError,'ID_CONFLICT'):self.run_attempt(**kw)
    def test_source_revocation_at_final_publication_does_not_commit(self):
        declaration,resolver=self.source.source();q=self.source.capture('with-source',sources=[declaration])
        runner=self.runner();runner.assembler.resolve_source=lambda s,d:resolver
        self.selected=[q]
        runner=self.runner();runner.assembler.resolve_source=lambda s,d:resolver
        original=self.source.publisher.publish;before=self.source.head()
        def publish(op,*args,**kwargs):
            if op.kind=='synthesis-attempt':resolver.source_allowed=lambda s,r:False
            return original(op,*args,**kwargs)
        with patch.object(self.source.publisher,'publish',publish),self.assertRaisesRegex(library.LibraryError,'SOURCE_AUTHORITY_REVOKED'):
            runner.run(drain_id='drain-1',attempt=1,selected=[q],at=support.AT)
        self.assertEqual(before,self.source.head())
    def test_whole_attempt_deadline_includes_assembly(self):
        runner=self.runner();ticks=iter([0,0,121]);runner.clock=lambda:next(ticks,121)
        with self.assertRaisesRegex(library.LibraryError,'ATTEMPT_TIMEOUT'):
            runner.run(drain_id='drain-1',attempt=1,selected=self.selected,at=support.AT)
        self.assertFalse(self.marker.exists())
    def test_shared_publisher_serializes_attempt_not_capture(self):
        other=self.runner()
        def audit(e):
            if e['state']=='admitted':
                with self.assertRaisesRegex(library.LibraryError,'ATTEMPT_BUSY'):
                    other.run(drain_id='drain-2',attempt=1,selected=self.selected,at=support.AT)
        self.hook=audit;self.run_attempt()
    def test_attempt_manifest_supports_configured_batch_capacity(self):
        value=dict(attempt=1,input_sha='a'*40,selected=[format(i,'064x') for i in range(64)],accepted=[],indexes=[],
            request_sha256='b'*64,request_bytes=10000,request_files=64,request_tokens=10000,
            inputs=[{'name_sha256':format(i,'064x'),'bytes_sha256':'c'*64} for i in range(64)],
            batch_drafts=64,batch_bytes=262144,attempt_seconds=120)
        op=self.runner().operation(self.source.scope,self.source.settings,'large',1,support.AT,value)
        with self.records() as records:
            records.begin(op)
            self.assertEqual(records.record(op.operation_id,project_identity=self.source.scope.project_identity)['manifest'],value)

    def test_inflight_limits_keep_starting_snapshot(self):
        original_settings=self.source.settings['settings_id']
        def audit(e):
            if e['state']=='admitted':self.source.limit('request_tokens',1)
        self.hook=audit;result=self.run_attempt();self.assertEqual(result.state,'COMMITTED')
        with self.records() as r:
            self.assertEqual(r.record(self.operation_id(),project_identity=self.source.scope.project_identity)['settings_id'],original_settings)
    def test_mixed_integration_and_parking_is_one_atomic_commit(self):
        other=self.source.capture('other');self.selected.append(other);self.integrate()
        self.reply['outcomes'].append(dict(queue_id=other,kind='parked',reason='NEEDS_EVIDENCE'))
        before=self.source.count();result=self.run_attempt()
        self.assertEqual(self.source.count(),before+1);self.assertEqual({v['kind'] for v in result.outcomes},{'integrated','parked'})
        self.assertIn(other,self.source.contents('pending/index.md'))
    def crash_restart(self, boundary):
        import subprocess, shutil
        state=self.source.base/'child-state.json'
        code = """
import os, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from test_library_attempts import AttemptTests
from uas.library_records import LibraryRecords
case=AttemptTests();case.setUp()
Path(sys.argv[1]).write_text(json.dumps({'base':str(case.source.base),'settings':case.source.settings,'queue':case.q}))
boundary=sys.argv[2]
if boundary in ('admitted','returned'):
    case.hook=lambda event: os._exit(91) if event['state']==boundary else None
elif boundary=='intent':
    original=LibraryRecords.begin
    def begin(records,operation,**kwargs):
        result=original(records,operation,**kwargs)
        if operation.kind=='synthesis-attempt':os._exit(91)
        return result
    LibraryRecords.begin=begin
elif boundary=='push':
    original=case.source.publisher._push
    def push(*args):
        original(*args);os._exit(91)
    case.source.publisher._push=push
case.run_attempt()
raise AssertionError('crash boundary not reached')
"""
        process=subprocess.run([sys.executable,'-c',code,str(state),boundary,str(Path(__file__).resolve().parent)],capture_output=True,timeout=20)
        self.assertEqual(process.returncode,91,process.stderr.decode())
        data=json.loads(state.read_text());self.addCleanup(lambda:shutil.rmtree(data['base']))
        recovered=AttemptTests();source=assembly_tests.AssemblyTests()
        source.base=Path(data['base']);source.target=source.base/'canonical.git';source.records=source.base/'records.db'
        source.settings=data['settings'];source.scope=library.participant_scope(support.ORIGIN,binding=support.binding());source.fresh=source.scope
        source.publisher=source.make_publisher();source.publisher.startup();self.addCleanup(source.publisher.close)
        recovered.source=source;recovered.q=data['queue'];recovered.selected=[recovered.q];recovered.marker=source.base/'contact'
        recovered.audit=[];recovered.hook=lambda e:None;recovered.profile=self.profile;recovered.selection=self.selection
        recovered.mode='success';recovered.number=1;recovered.reply=None
        if boundary=='push':
            before=source.count();recovered.marker.unlink()
            result=recovered.run_attempt();self.assertEqual(result.state,'COMMITTED');self.assertEqual(before,source.count())
            self.assertFalse(recovered.marker.exists())
        elif boundary=='intent':
            self.assertFalse(recovered.marker.exists());self.assertEqual(recovered.run_attempt().state,'COMMITTED')
        else:
            if recovered.marker.exists():recovered.marker.unlink()
            with self.assertRaisesRegex(library.LibraryError,'NEW_ATTEMPT_REQUIRED'):recovered.run_attempt()
            self.assertFalse(recovered.marker.exists())
    def test_process_death_after_intent_retries_without_duplicate_contact(self):self.crash_restart('intent')
    def test_process_death_after_contact_reservation_never_redispatches(self):self.crash_restart('admitted')
    def test_process_death_after_model_output_never_persists_or_replays_it(self):self.crash_restart('returned')
    def test_process_death_after_push_recovers_canonical_result(self):self.crash_restart('push')

    def test_native_io_deadline_and_thread_scope(self):
        import time
        from uas import library_deadline
        with library_deadline.bounded(.01):
            self.assertLessEqual(library_deadline.remaining(120),.01)
            unrelated=[]
            thread=threading.Thread(target=lambda:unrelated.append(library_deadline.remaining(120)))
            thread.start();thread.join();self.assertEqual(unrelated,[120])
            time.sleep(.02)
            with self.assertRaisesRegex(library.LibraryError,'ATTEMPT_TIMEOUT'):self.source.publisher.project_snapshot(self.source.scope,self.source.settings,current=lambda:None)
        self.assertEqual(library_deadline.remaining(120),120)
    def test_expired_admitted_audit_does_not_spawn_provider(self):
        import time
        from uas import library_deadline
        runner=self.runner()
        with library_deadline.bounded(.01):
            with self.assertRaisesRegex(library.LibraryError,'ATTEMPT_TIMEOUT'):
                runner.dispatcher.gateway.call(self.profile,b'{}',response_limit=100,seconds=120,
                    before_contact=lambda:time.sleep(.02))
        self.assertFalse(self.marker.exists())

if __name__=='__main__':unittest.main()
