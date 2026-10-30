"""T35 complete lifecycle acceptance using disposable real Git/service/SQLite."""
from copy import deepcopy
import threading
import time
import unittest
from unittest.mock import patch
import test_library_controls as fixture
import library_support as support
from uas import library, library_bundle as bundle, library_gate as gate
from uas.library_controls import canonical
from uas.library_registration import Registrar, project_state
from uas.library_records import LibraryRecords


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixture.ControlsTests('test_operational_ack_no_git_or_model_and_exact_retry')
        self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.source=self.fx.source;self.service=self.fx.service;self.controls=self.fx.controls
        self.allowed=True
        self.principal=library.LocalHuman('human','actor','grant',lambda p,key,action:self.allowed
            and key==self.source.scope.project_identity and action in ('library-archive','library-restore','library-register'),lambda:True)
        self.prefix='projects/'+self.source.scope.project_path
    def send(self,value):return self.controls.handle(canonical(value),self.principal)
    def value(self,kind='archive',request='archive-one'):
        observed=self.send(dict(version=1,action='observe',for_action=kind,project_id='alpha'))
        return dict(version=1,action=kind,project_id='alpha',request_id=request,
            settings_id=observed['settings_id'],observed_version=observed['observed_version'])
    def tree(self):return self.source.publisher.project_snapshot(self.source.scope,self.source.settings,current=lambda:None)[1]
    def state(self):return project_state(self.tree(),self.prefix)
    def refused(self,value,code):
        with self.assertRaises(library.LibraryError) as e:self.send(value)
        self.assertEqual(e.exception.code,code)
    def restart(self):
        self.fx.fx.restart();self.service=self.fx.fx.service;self.controls.service=self.service
    def test_archive_restore_canonical_commits_same_identity_and_retained_drafts(self):
        before=self.tree();value=self.value();result=self.send(value)
        self.assertEqual(result['outcome'],'COMMITTED');self.assertEqual(result['publication']['commit_sha'],self.source.head())
        self.assertEqual(self.state(),'archived');count=self.source.count()
        self.assertEqual(self.send(value),result);self.assertEqual(self.source.count(),count)
        q=self.fx.fx.fixture.q
        self.assertEqual(before.files[self.prefix+'/pending/'+q+'.md'],self.tree().files[self.prefix+'/pending/'+q+'.md'])
        self.assertIn(b'DRAFT PARKED:',self.tree().files[self.prefix+'/pending/index.md'])
        restored=self.send(self.value('restore','restore-one'))
        self.assertEqual(restored['outcome'],'COMMITTED');self.assertEqual(self.state(),'active')
        self.assertEqual(restored['publication']['commit_sha'],self.source.head())
        self.assertIn(b'Source identity: '+self.source.scope.project_identity.encode(),self.tree().files[self.prefix+'/index.md'])
        self.assertEqual(set(before.files),set(self.tree().files))
    def test_failed_final_model_runs_once_across_push_failure_and_restart(self):
        self.fx.fx.mode='oversize';value=self.value();publisher=self.source.publisher;original=publisher.publish
        calls=[]
        def failed(operation,*a,**kw):
            if operation.kind=='archive':calls.append(operation.kind);raise OSError('before archive push')
            return original(operation,*a,**kw)
        with patch.object(publisher,'publish',failed):
            with self.assertRaises(OSError):self.send(value)
        marker=self.fx.fx.fixture.marker.read_bytes();self.assertTrue(marker)
        self.assertEqual(self.state(),'active');self.restart();self.assertIsNone(self.service.tick())
        result=self.send(value);self.assertEqual(result['outcome'],'COMMITTED')
        self.assertEqual(self.fx.fx.fixture.marker.read_bytes(),marker);self.assertEqual(self.state(),'archived')
    def test_lost_archive_ack_reconciles_without_second_content_commit(self):
        value=self.value();original=self.source.publisher.publish
        def lost(operation,*a,**kw):
            result=original(operation,*a,**kw)
            if operation.kind=='archive':raise OSError('lost acknowledgement')
            return result
        with patch.object(self.source.publisher,'publish',lost):
            with self.assertRaises(OSError):self.send(value)
        count=self.source.count();self.restart();result=self.send(value)
        self.assertEqual(result['outcome'],'COMMITTED');self.assertEqual(self.source.count(),count)
    def test_capture_refused_after_durable_admission_while_global_turn_waits(self):
        value=self.value();turn=self.service.scheduler._turn;turn.acquire();out=[];errors=[]
        def archive():
            try:out.append(self.send(value))
            except BaseException as e:errors.append(e)
        worker=threading.Thread(target=archive);worker.start()
        from uas.library_lifecycle import frozen
        deadline=time.monotonic()+3
        while not frozen(self.source.publisher,self.source.scope.project_identity) and time.monotonic()<deadline:time.sleep(.005)
        try:
            self.assertTrue(frozen(self.source.publisher,self.source.scope.project_identity))
            result=self.source.enqueue('capture-during-archive','during-archive',
                {'type':'context','title':'During archive','body':'Must not be captured.','sources':[]})
            self.assertEqual(result.outcome,'REJECTED');self.assertEqual(result.reason,'PROJECT_ARCHIVING')
            self.assertFalse(out)
        finally:turn.release();worker.join(5)
        self.assertFalse(worker.is_alive());self.assertFalse(errors);self.assertEqual(out[0]['outcome'],'COMMITTED')
    def test_archive_waits_active_attempt_without_deadlock_or_repeat(self):
        started=threading.Event();release=threading.Event();entry=self.controls._entry('alpha');original=entry['runner'].run
        calls=[]
        def active(**kw):started.set();release.wait(3);calls.append(kw);return original(**kw)
        tick=[];arch=[]
        with patch.object(entry['runner'],'run',active):
            worker=threading.Thread(target=lambda:tick.append(self.service.tick()));worker.start();self.assertTrue(started.wait(2))
            value=self.value();other=threading.Thread(target=lambda:arch.append(self.send(value)));other.start()
            time.sleep(.05);self.assertFalse(arch);release.set();worker.join(5);other.join(5)
        self.assertFalse(worker.is_alive());self.assertFalse(other.is_alive());self.assertEqual(len(calls),1)
        self.assertEqual(arch[0]['outcome'],'COMMITTED')
    def test_archived_common_gate_refuses_writes_but_read_checks_and_registration_work(self):
        self.send(self.value());tree=self.tree();gate.validate(self.source.scope,self.source.settings,proposed=tree,current=tree)
        for path in ('log.md','pending/index.md','index.md'):
            files=dict(tree.files);files[self.prefix+'/'+path]+=b'\nUnexpected write.\n'
            with self.assertRaises(library.LibraryError) as e:gate.validate(self.source.scope,self.source.settings,proposed=bundle.Tree(files),current=tree)
            self.assertEqual(e.exception.code,'PROJECT_ARCHIVED')
        scope=library.local_human_scope(self.principal,binding=self.source.scope.canonical(),kind='register')
        op=library.action(scope,self.source.settings,kind='register',operation_id='register-archive',request_id='register-archive',payload={},at=self.service.scheduler.now().isoformat())
        count=self.source.count();result=Registrar(self.source.publisher,current_scope=lambda:scope).register(op,self.source.settings)
        self.assertEqual(result.state,'archived');self.assertEqual(self.source.count(),count)
        self.assertIsNone(self.service.tick())
    def test_restore_requires_authority_fresh_observation_and_same_payload(self):
        self.refused(self.value('restore','premature'),'PROJECT_NOT_ARCHIVED')
        value=self.value();self.allowed=False;self.refused(value,'FORBIDDEN');self.allowed=True
        self.source.capture('change');self.refused(value,'STALE_CONTROL_STATE')
        value=self.value();self.send(value)
        self.refused({**value,'observed_version':'a'*64},'ID_CONFLICT')
        self.refused({**value,'actor_id':'forged'},'INVALID_CONTROL_REQUEST')
        restore=self.value('restore','restore');self.allowed=False;self.refused(restore,'FORBIDDEN')
    def test_reconcile_is_read_only_and_never_admits_or_repeats_final_work(self):
        value=self.value()
        with self.assertRaises(library.LibraryError) as e:self.controls.reconcile(canonical(value),self.principal)
        self.assertEqual(e.exception.code,'CONTROL_OUTCOME_UNKNOWN');self.assertFalse(self.fx.fx.fixture.marker.exists())
        with patch.object(self.source.publisher,'publish',side_effect=OSError('before publication')):
            with self.assertRaises(OSError):self.send(value)
        count=self.source.count()
        with self.assertRaises(library.LibraryError):self.controls.reconcile(canonical(value),self.principal)
        self.assertEqual(self.source.count(),count)
    def test_prior_failed_batch_is_not_implicitly_retried_by_archive(self):
        self.fx.fx.mode='oversize';self.service.tick();marker=self.fx.fx.fixture.marker.read_bytes()
        self.send(self.value());self.assertEqual(self.fx.fx.fixture.marker.read_bytes(),marker)
        self.assertEqual(self.state(),'archived')
    def test_malformed_existing_content_prevents_admission_and_archive_publication(self):
        self.source.mutate({self.prefix+'/log.md':b'# No required dated history\n'})
        with self.assertRaises(library.LibraryError):self.value()
        from uas.library_lifecycle import frozen
        self.assertFalse(frozen(self.source.publisher,self.source.scope.project_identity))
    def test_crashed_final_schedule_settles_before_restore_and_next_tick(self):
        value=self.value();from uas import library_lifecycle as lifecycle
        original=lifecycle._settle_final_schedule
        with patch.object(lifecycle,'_settle_final_schedule',side_effect=OSError('process ended before schedule settlement')):
            with self.assertRaises(OSError):self.send(value)
        old=self.controls._entry('alpha')['state'];self.assertEqual(old['state'],'ACTIVE')
        self.assertTrue(old['drain_id'].startswith('archive-final-'));marker=self.fx.fx.fixture.marker.read_bytes()
        self.restart();self.assertIsNone(self.service.tick());self.send(value)
        self.assertNotEqual(self.controls._entry('alpha')['state']['state'],'ACTIVE')
        self.send(self.value('restore','restore-crash'));self.assertEqual(self.service.tick()['state'],'EMPTY')
        self.assertEqual(self.fx.fx.fixture.marker.read_bytes(),marker)
        self.service.flush();phases=[x['phase'] for x in self.fx.fx.transitions()]
        self.assertEqual(phases,['STARTED','COMMITTED'])
    def test_final_failure_reports_terminal_blocked_without_retry(self):
        self.fx.fx.mode='oversize';self.send(self.value());self.service.flush()
        transitions=self.fx.fx.transitions()
        self.assertEqual([x['phase'] for x in transitions],['STARTED','BLOCKED'])
        self.assertIsNotNone(transitions[-1]['reason']);self.restart();self.assertIsNone(self.service.tick())
    def test_ordinary_gate_cannot_change_lifecycle_even_from_active(self):
        tree=self.tree();files=dict(tree.files);files[self.prefix+'/index.md']+=b'\nLibrary state: archived\n'
        with self.assertRaises(library.LibraryError) as e:gate.validate(self.source.scope,self.source.settings,proposed=bundle.Tree(files),current=tree)
        self.assertEqual(e.exception.code,'LIFECYCLE_AUTHORITY_REQUIRED')
    def test_lifecycle_gate_cannot_smuggle_other_content_changes(self):
        from uas.library_lifecycle import proposed_state
        tree=self.tree();scope=library.local_human_scope(self.principal,binding=self.source.scope.canonical(),kind='archive')
        op=library.action(scope,self.source.settings,kind='archive',operation_id='test-archive',request_id='test-archive',
            payload={'observed_version':'a'*64},at=self.service.scheduler.now().isoformat())
        files=dict(proposed_state(op,tree).files);files[self.prefix+'/pending/index.md']+=b'\nInjected content\n'
        with self.assertRaises(library.LibraryError) as e:gate.validate(scope,self.source.settings,proposed=bundle.Tree(files),current=tree,lifecycle=op)
        self.assertEqual(e.exception.code,'INVALID_LIFECYCLE')
    def test_renewed_human_grant_reconciles_original_identity(self):
        value=self.value();original=self.source.publisher.publish
        def lost(op,*a,**kw):
            result=original(op,*a,**kw)
            if op.kind=='archive':raise OSError('lost')
            return result
        with patch.object(self.source.publisher,'publish',lost):
            with self.assertRaises(OSError):self.send(value)
        count=self.source.count()
        self.principal=library.LocalHuman('human','actor','renewed-grant',lambda *args:True,lambda:True)
        self.assertEqual(self.send(value)['outcome'],'COMMITTED');self.assertEqual(self.source.count(),count)
    def test_lost_final_attempt_ack_recovers_commit_before_terminal_report(self):
        value=self.value();original=self.source.publisher.publish
        def lost(op,*a,**kw):
            result=original(op,*a,**kw)
            if op.kind=='synthesis-attempt':raise OSError('final attempt committed, ack lost')
            return result
        with patch.object(self.source.publisher,'publish',lost):
            with self.assertRaises(OSError):self.send(value)
        marker=self.fx.fx.fixture.marker.read_bytes();self.assertEqual(self.controls._entry('alpha')['state']['state'],'ACTIVE')
        self.restart();self.send(value);self.service.flush()
        self.assertEqual([x['phase'] for x in self.fx.fx.transitions()],['STARTED','COMMITTED'])
        self.assertEqual(self.fx.fx.fixture.marker.read_bytes(),marker)
        self.send(self.value('restore','restore-final-ack'));self.assertEqual(self.service.tick()['state'],'EMPTY')
    def test_lost_started_schedule_ack_cannot_publish_archive_or_leak_active(self):
        value=self.value();scheduler=self.service.scheduler;original=scheduler._save
        def lost(entry,state,at,**kw):
            result=original(entry,state,at,**kw)
            if state['state']=='ACTIVE':raise library.LibraryError('RECORD_UNCERTAIN')
            return result
        with patch.object(scheduler,'_save',lost):self.refused(value,'RECORD_UNCERTAIN')
        self.assertEqual(self.state(),'active');self.assertFalse(self.fx.fx.fixture.marker.exists())
        self.restart();self.send(value);self.send(self.value('restore','restore-started-loss'))
        self.assertNotEqual(self.controls._entry('alpha')['state']['state'],'ACTIVE')
        self.assertFalse(self.fx.fx.fixture.marker.exists())
    def test_restore_lost_ack_reconciles(self):
        self.send(self.value());value=self.value('restore','restore-one');original=self.source.publisher.publish
        def lost(op,*a,**kw):original(op,*a,**kw);raise OSError('lost')
        with patch.object(self.source.publisher,'publish',lost):
            with self.assertRaises(OSError):self.send(value)
        count=self.source.count();self.restart();result=self.send(value)
        self.assertEqual(result['outcome'],'COMMITTED');self.assertEqual(self.source.count(),count);self.assertEqual(self.state(),'active')


if __name__=='__main__':unittest.main()
