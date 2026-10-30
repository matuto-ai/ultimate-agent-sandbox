"""Fair service turns with actual Git/records/assembly/controlled provider execution."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch
import library_support as support
import test_library_attempts as attempt_tests
from uas import library
from uas.library_attempts import Attempts
from uas.library_scheduler import Scheduler, BACKOFF
from uas.library_records import LibraryRecords

class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = attempt_tests.AttemptTests('test_invalid_output_publishes_nothing')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.source = self.fixture.source
        self.now = datetime(2026,10,30,tzinfo=timezone.utc)
        self.runner = self.fixture.runner()
        self.scheduler = Scheduler(self.source.publisher, now=lambda:self.now)
        self.addCleanup(lambda: self.scheduler.close())
        self.key = self.source.scope.project_identity
        self.mode = 'success'; self.replies=[]
        self.register(self.runner)
    def register(self, runner):
        def context(selected):
            state = self.scheduler.state(runner.assembler._scope().project_identity)
            reply=dict(version=1,drain_id=state['drain_id'],attempt=state['attempt'],operations=[],
                outcomes=[dict(queue_id=q,kind='parked',reason='NEEDS_EVIDENCE') for q in selected])
            if self.mode=='invalid': reply['outcomes']=[]
            self.replies.append(deepcopy(reply))
            runner.dispatcher.gateway.routes[self.fixture.profile.identity()] = (
                sys.executable,str(Path(__file__).with_name('fixture_library_provider.py')),
                str(self.fixture.marker),'success' if self.mode=='invalid' else self.mode,json.dumps(reply))
            return (),()
        return self.scheduler.register(runner, context=context)
    def advance(self, seconds): self.now += timedelta(seconds=seconds)
    def second(self):
        from copy import copy
        from uas.library_registration import Registrar
        from uas.library_enqueue import Enqueuer
        from uas.library_dispatch import Evidence, Selection
        human=self.source.make_scope('beta','acme/beta','2002')
        Registrar(self.source.publisher,current_scope=lambda:human).register(
            library.action(human,self.source.settings,kind='register',operation_id='register-beta',
                request_id='register-beta',payload={},at=support.AT),self.source.settings)
        scope=library.participant_scope(support.ORIGIN,binding=support.binding('beta','acme/beta','2002'))
        enqueuer=Enqueuer(self.source.publisher,current_scope=lambda:scope)
        result=enqueuer.enqueue(self.source.settings,operation_id='beta-capture',request_id='beta-capture',
            value={'type':'context','title':'Beta','body':'Beta data','sources':[]},at=support.AT)
        self.assertEqual(result.outcome,'DURABLY_QUEUED')
        assembler=copy(self.runner.assembler);assembler.current_scope=lambda:scope
        dispatcher=copy(self.runner.dispatcher);dispatcher.current_scope=lambda:scope
        def proof(ref):return Evidence(ref,self.fixture.profile.identity(),scope.project_identity,'2030-01-01T00:00:00+00:00')
        selection=Selection(self.fixture.profile,proof('synth-qualification'),proof('synth-local'))
        dispatcher.selection=lambda s:selection
        runner=Attempts(assembler,dispatcher);self.register(runner)
        return scope.project_identity,result.queue_id
    def test_two_projects_fair_tie_and_explicit_no_jump_after_failure(self):
        other,_=self.second();first=min(self.key,other);last=max(self.key,other)
        self.mode='error';result=self.scheduler.tick();self.assertEqual(result['project_identity'],first)
        self.scheduler.request(first)
        result=self.scheduler.tick();self.assertEqual(result['project_identity'],last)
        self.scheduler.request(last)
        self.assertEqual(self.scheduler.tick()['project_identity'],first)
    def test_independent_project_runs_while_another_is_backing_off(self):
        other,_=self.second();first=min(self.key,other);last=max(self.key,other)
        self.mode='error';self.assertEqual(self.scheduler.tick()['project_identity'],first)
        self.mode='success';result=self.scheduler.tick()
        self.assertEqual(result['project_identity'],last);self.assertEqual(result['state'],'COMMITTED')
    def test_retry_history_is_paged_past_old_256_limit(self):
        from dataclasses import replace
        with self.scheduler._records() as records:
            for number in range(260):
                ident='history-'+str(number)
                op=library._operation('history',self.source.scope,self.source.settings,ident,ident,{},support.AT,drain_id='long-drain')
                records.begin(op)
                records.finish(op,library.receipt(op,'REFUSED',at=support.AT,reason='SETTLED'))
            self.assertEqual(len(list(records.iter_drain('long-drain',project_identity=self.key))),260)
    def test_original_order_survives_coordinate_move(self):
        from uas.library_relocation import Relocator
        second=self.source.capture('second')
        binding=support.binding(repository='new-owner/new-name')
        human=library.human_scope(support.session(('library-relocate',)),binding=binding,kind='relocate')
        mover=Relocator(self.source.publisher,previous_scope=self.source.scope,current_scope=lambda:human)
        mover.move(library.action(human,self.source.settings,kind='relocate',operation_id='move-order',
            request_id='move-order',payload={},at=support.AT),self.source.settings)
        moved=library.participant_scope(support.ORIGIN,binding=binding)
        order=self.source.publisher.queue_order(moved,self.source.settings,
            self.source.head(),[second,self.fixture.q],current=lambda:None)
        self.assertEqual(order,(self.fixture.q,second))
    def test_real_turn_parks_then_yields_and_excludes_parked(self):
        result=self.scheduler.tick();self.assertEqual(result['state'],'COMMITTED')
        self.assertEqual(self.scheduler.tick()['state'],'EMPTY')
        self.assertIsNone(self.scheduler.tick());self.assertEqual(len(self.replies),1)
    def test_coalesces_publications_without_postponing(self):
        self.scheduler.tick();self.scheduler.tick()
        self.source.capture('later');self.assertIsNone(self.scheduler.tick())
        due=self.scheduler.state(self.key)['due'];self.advance(5)
        self.source.capture('third');self.assertIsNone(self.scheduler.tick())
        self.assertEqual(due,self.scheduler.state(self.key)['due'])
        self.advance(5);self.assertEqual(self.scheduler.tick()['state'],'COMMITTED')
        self.assertEqual(len(self.replies[-1]['outcomes']),2)
    def test_explicit_request_clears_delay_and_does_not_execute(self):
        self.scheduler.tick();self.scheduler.tick();self.source.capture('later')
        self.assertIsNone(self.scheduler.tick());self.scheduler.request(self.key)
        self.assertEqual(len(self.replies),1);self.assertEqual(self.scheduler.tick()['state'],'COMMITTED')
    def test_fixed_batch_survives_backoff_later_capture_and_explicit_retry(self):
        self.mode='invalid'
        for i, delay in enumerate((5,30,120)):
            result=self.scheduler.tick()
            self.assertEqual(result['state'],'BLOCKED' if i==2 else 'BACKOFF')
            if i==0:self.source.capture('later')
            self.advance(delay)
        states=self.scheduler.state(self.key);selected=states['selected'];drain=states['drain_id']
        self.assertEqual(selected,[self.fixture.q])
        with self.assertRaisesRegex(library.LibraryError,'PROJECT_BLOCKED'):self.scheduler.request(self.key)
        self.scheduler.reconcile(self.key);self.assertIsNone(self.scheduler.tick())
        self.scheduler.request(self.key,retry=True);self.mode='success'
        result=self.scheduler.tick();self.assertEqual(result['drain_id'],drain);self.assertEqual(result['attempt'],4)
        self.assertEqual(self.replies[-1]['outcomes'][0]['queue_id'],self.fixture.q)
        self.assertEqual(len(self.replies[-1]['outcomes']),1)
        self.assertEqual(self.scheduler.tick()['state'],'COMMITTED')
        self.assertEqual(len(self.replies[-1]['outcomes']),1)
    def test_backoff_sequence_transport_never_hits_model_threshold(self):
        self.mode='error'
        for index in range(7):
            old=self.now;self.assertEqual(self.scheduler.tick()['state'],'BACKOFF')
            state=self.scheduler.state(self.key)
            self.assertEqual(datetime.fromisoformat(state['due'])-old,timedelta(seconds=BACKOFF[min(index,4)]))
            self.assertEqual(state['model_failures'],0)
            self.assertIsNone(self.scheduler.tick());self.advance(BACKOFF[min(index,4)])
    def test_enqueues_cannot_clear_backoff(self):
        self.mode='error';self.scheduler.tick();due=self.scheduler.state(self.key)['due']
        self.source.capture('later');self.assertIsNone(self.scheduler.tick())
        self.assertEqual(self.scheduler.state(self.key)['due'],due)
    def test_configurable_batch_count_and_creation_order(self):
        self.source.limit('batch_drafts',2)
        second=self.source.capture('second');self.source.capture('third')
        self.scheduler.tick()
        self.assertEqual([v['queue_id'] for v in self.replies[0]['outcomes']],[self.fixture.q,second])
        self.scheduler.tick();self.assertEqual(len(self.replies[1]['outcomes']),1)
    def test_batch_bytes_are_full_canonical_draft_bytes(self):
        first=len(self.source.contents('pending/'+self.fixture.q+'.md').encode())
        # limit helper reconstructs settings, set both together below
        doc=support.document();doc['repository'].update(target=self.source.publisher.target,branch='main')
        doc['limits']['body_bytes']=100;doc['limits']['batch_bytes']=first+1
        self.source.settings=support.settings(doc)
        self.source.capture('second');self.scheduler.tick()
        self.assertEqual(len(self.replies[0]['outcomes']),1)
    def test_restart_preserves_blocked_batch_and_turn(self):
        self.mode='invalid'
        for delay in (5,30,120):self.scheduler.tick();self.advance(delay)
        state=self.scheduler.state(self.key);self.scheduler.close()
        self.scheduler=Scheduler(self.source.publisher,now=lambda:self.now);self.register(self.runner)
        self.assertEqual(self.scheduler.state(self.key),state)
        self.assertIsNone(self.scheduler.tick())
        self.scheduler.request(self.key,retry=True);self.mode='success'
        self.assertEqual(self.scheduler.tick()['attempt'],4)
    def test_no_second_scheduler_or_overlapping_turn_and_no_git_lock(self):
        with self.assertRaisesRegex(library.LibraryError,'SCHEDULER_ALREADY_ACTIVE'):
            Scheduler(self.source.publisher)
        self.mode='release';results=[]
        worker=threading.Thread(target=lambda:results.append(self.scheduler.tick()));worker.start()
        try:
            deadline=time.monotonic()+4
            while not self.fixture.marker.exists() and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(worker.is_alive())
            with self.assertRaisesRegex(library.LibraryError,'SCHEDULER_BUSY'):self.scheduler.tick()
            self.scheduler.request(self.key)
            later=self.source.capture('concurrent')
        finally:
            Path(str(self.fixture.marker)+'.release').touch();worker.join(5)
        self.assertFalse(worker.is_alive());self.assertEqual(results[0]['state'],'COMMITTED')
        self.assertIn(later,self.source.contents('pending/index.md'))
    def test_uncertain_schedule_write_fences_until_reopened(self):
        original=LibraryRecords.finish
        def finish(store,operation,*args):
            if operation.kind=='scheduler-state':raise library.LibraryError('RECORD_UNCERTAIN')
            return original(store,operation,*args)
        with patch.object(LibraryRecords,'finish',finish), self.assertRaises(library.LibraryError):
            self.scheduler.request(self.key)
        with self.assertRaisesRegex(library.LibraryError,'SCHEDULER_RECOVERY_REQUIRED'):self.scheduler.tick()
        self.scheduler.close();self.scheduler=Scheduler(self.source.publisher,now=lambda:self.now)
        self.register(self.runner);self.assertEqual(self.scheduler.tick()['state'],'COMMITTED')
    def test_persisted_metadata_has_no_content(self):
        self.scheduler.tick()
        with self.scheduler._records() as records:state=records.latest_schedule(self.key)
        self.assertNotIn('Selected draft data',json.dumps(state))
        self.assertNotIn('instructions',json.dumps(state))
    def test_revoked_project_does_not_block_independent_project(self):
        other,_=self.second();self.source.fresh=None
        result=self.scheduler.tick()
        self.assertEqual(result['project_identity'],other)
        self.assertEqual(result['state'],'COMMITTED')
        self.assertEqual(self.scheduler._entries[self.key]['state']['state'],'BLOCKED')
    def test_revocation_during_provider_return_blocks_only_project(self):
        other,_=self.second()
        original=self.runner.dispatcher.audit
        def audit(event):
            original(event)
            if event['state']=='returned':self.source.fresh=None
        self.runner.dispatcher.audit=audit
        # Force alpha to be first without disturbing its fair counter.
        self.scheduler._entries[other]['state']['due']=(self.now+timedelta(seconds=1)).isoformat()
        result=self.scheduler.tick();self.assertEqual(result['state'],'BLOCKED')
        self.advance(1);self.assertEqual(self.scheduler.tick()['project_identity'],other)
    def test_malformed_model_operation_counts_not_global_crash(self):
        original=self.runner.dispatcher.dispatch
        from dataclasses import replace
        def dispatch(*args,**kwargs):
            result=original(*args,**kwargs);value=json.loads(result.proposal)
            value['operations']=[None]
            return replace(result,proposal=json.dumps(value).encode())
        with patch.object(self.runner.dispatcher,'dispatch',dispatch):
            self.assertEqual(self.scheduler.tick()['reason'],'MODEL_OUTPUT_INVALID')
        self.assertFalse(self.scheduler._failed)
    def test_prior_failed_intents_settled_before_retry(self):
        self.mode='error';self.scheduler.tick();self.advance(5);self.scheduler.tick()
        state=self.scheduler.state(self.key)
        with self.scheduler._records() as records:
            attempts=[r for r in records.iter_drain(state['drain_id'],project_identity=self.key) if r['kind']=='synthesis-attempt']
        self.assertEqual(attempts[0]['receipt']['reason'],'RECONCILED_NOT_PUBLISHED')
        self.assertIsNone(attempts[1]['receipt'])
    def test_more_than_256_settled_attempts_do_not_rescan_or_limit_retry(self):
        from dataclasses import replace
        self.mode='error';self.scheduler.tick()
        state=self.scheduler.state(self.key);drain=state['drain_id']
        with self.scheduler._records() as records:
            first=next(r for r in records.iter_drain(drain,project_identity=self.key) if r['kind']=='synthesis-attempt')
            for number in range(1,261):
                manifest={**first['manifest'],'attempt':number}
                op=self.runner.operation(self.source.scope,self.source.settings,drain,number,first['at'],manifest)
                records.begin(op)
                records.finish(op,library.receipt(op,'REFUSED',at=support.AT,reason='RECONCILED_NOT_PUBLISHED'))
        original=self.source.publisher.publication_for;calls=[]
        def lookup(*args,**kwargs):calls.append(args[0].operation_id);return original(*args,**kwargs)
        self.scheduler._entries[self.key]['state']['attempt']=260
        self.scheduler.request(self.key);self.mode='success'
        with patch.object(self.source.publisher,'publication_for',lookup): result=self.scheduler.tick()
        self.assertEqual(result['attempt'],261);self.assertLess(len(calls),5)
    def test_lost_push_reconciles_before_new_model_call(self):
        original=self.source.publisher._push
        def push(*args):original(*args);raise library.LibraryError('PUBLICATION_UNCERTAIN')
        with patch.object(self.source.publisher,'_push',push):self.assertEqual(self.scheduler.tick()['state'],'BACKOFF')
        count=self.source.count();self.fixture.marker.unlink();self.advance(5)
        self.assertEqual(self.scheduler.tick()['state'],'COMMITTED')
        self.assertEqual(self.source.count(),count);self.assertFalse(self.fixture.marker.exists())
    def test_process_exit_after_fixed_selection_restores_same_batch(self):
        import subprocess, shutil
        import test_library_assembly as assembly_tests
        statefile=self.source.base/'child-state.json'
        code = r"""
import sys, json, os
sys.path.insert(0,sys.argv[2])
from test_library_scheduler import SchedulerTests
case=SchedulerTests();case.setUp()
original=case.scheduler._save
def save(entry,state,at):
    original(entry,state,at)
    if state['attempt']==1:
        with open(sys.argv[1],'w') as f:
            json.dump({'base':str(case.source.base),'settings':case.source.settings,'queue':case.fixture.q,
                       'drain':entry['state']['drain_id']},f)
        os._exit(91)
case.scheduler._save=save
case.scheduler.tick()
"""
        child=subprocess.run([sys.executable,'-c',code,str(statefile),str(Path(__file__).resolve().parent)],
            capture_output=True,timeout=15)
        self.assertEqual(child.returncode,91,child.stderr.decode())
        saved=json.loads(statefile.read_text());self.addCleanup(lambda:shutil.rmtree(saved['base']))
        source=assembly_tests.AssemblyTests();source.base=Path(saved['base'])
        source.target=source.base/'canonical.git';source.records=source.base/'records.db'
        source.settings=saved['settings'];source.scope=self.source.scope;source.fresh=source.scope
        source.publisher=source.make_publisher();source.publisher.startup();self.addCleanup(source.publisher.close)
        self.scheduler.close();self.source=source;self.fixture.source=source
        self.fixture.marker=source.base/'contact';self.fixture.q=saved['queue'];self.fixture.selected=[saved['queue']]
        self.runner=self.fixture.runner();self.scheduler=Scheduler(source.publisher,now=lambda:self.now)
        self.register(self.runner);result=self.scheduler.tick()
        self.assertEqual(result['drain_id'],saved['drain']);self.assertEqual(result['attempt'],2)
        self.assertEqual(result['state'],'COMMITTED')

    def test_clock_must_be_aware(self):
        self.now=datetime(2026,10,30)
        with self.assertRaisesRegex(library.LibraryError,'SCHEDULER_CLOCK_INVALID'):self.scheduler.tick()

if __name__=='__main__':unittest.main()
