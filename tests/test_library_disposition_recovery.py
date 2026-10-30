"""Canonical rejection recovery, operational honesty and real process death."""
from copy import deepcopy
from unittest.mock import patch

import test_library_disposition as fixture
from uas import library
from uas import library_disposition as disposition


class RecoveryTests(fixture.DispositionBase):
    def test_push_before_schedule_interrupt_recovers_without_resurrection(self):
        self.blocked();value=self.value();before=self.source.count()
        with patch.object(disposition,'apply_schedule',side_effect=RuntimeError('crash')):
            with self.assertRaises(RuntimeError):self.send(value)
        self.assertEqual(self.source.count(),before+1)
        self.restart();state=self.entry()['state'];self.assertEqual(state['state'],'DISPOSED')
        self.assertEqual(self.send(value)['publication']['commit_sha'],self.source.head())
        self.assertEqual(self.source.count(),before+1)
    def test_schedule_before_receipt_interrupt_exact_reconcile(self):
        self.blocked();value=self.value();before=self.source.count()
        with patch.object(disposition,'finish',side_effect=RuntimeError('crash')):
            with self.assertRaises(RuntimeError):self.send(value)
        self.restart();self.assertEqual(self.send(value)['outcome'],'COMMITTED')
        self.assertEqual(self.source.count(),before+1)
    def test_unknown_pre_push_never_reapplies(self):
        value=self.value();original=self.source.publisher.publish;before=self.source.count()
        def publish(operation,*a,**kw):
            with self.service.scheduler._records() as records:records.begin(operation)
            raise library.LibraryError('PUBLICATION_UNCERTAIN')
        with patch.object(self.source.publisher,'publish',publish):self.refused(value,'PUBLICATION_UNCERTAIN')
        self.refused(value,'CONTROL_OUTCOME_UNKNOWN');self.assertEqual(self.source.count(),before)
    def test_direct_attempt_run_and_recover_old_drain_refused(self):
        self.blocked();self.send(self.value());runner=self.entry()['runner']
        for call in (lambda:runner.recover('original-drain'),lambda:runner.run(drain_id='original-drain',attempt=2,selected=(self.q,),at='2026-10-30T00:00:00+00:00')):
            with self.assertRaises(library.LibraryError) as error:call()
            self.assertEqual(error.exception.code,'DRAIN_DISPOSED')
        self.assertFalse(self.fx.fx.fixture.marker.exists())
    def test_reason_is_canonical_only_and_report_is_truthful(self):
        self.blocked();self.send(self.value());self.service.flush()
        for path in self.source.base.glob('*.db*'):self.assertNotIn(b'PRIVATE_HUMAN_REASON',path.read_bytes())
        text=self.fx.fx.path.read_bytes();self.assertNotIn(b'PRIVATE_HUMAN_REASON',text)
        self.assertIn(b'OPERATOR_DISPOSED',text)
    def test_wire_scope_and_cross_project_forgery_refused(self):
        value=self.value()
        for key in ('scope','actor_id','path','selected'):
            self.refused({**value,key:'forged'},'INVALID_CONTROL_REQUEST')
        self.refused({**value,'project_id':'beta'},'PROJECT_UNAVAILABLE')
        import test_library_scheduler as scheduler_tests
        fx=self.fx.fx;fx.scheduler=self.service.scheduler;fx.runner=fx.fixture.runner();fx.replies=[]
        fx.register=lambda runner:scheduler_tests.SchedulerTests.register(fx,runner)
        _,queue=scheduler_tests.SchedulerTests.second(fx)
        self.refused({**value,'project_id':'beta','queue_id':queue},'FORBIDDEN')
    def test_postpush_revoked_restart_then_authority_restore_uses_new_report_slot(self):
        self.blocked();value=self.value()
        with patch.object(disposition,'apply_schedule',side_effect=RuntimeError('crash')):
            with self.assertRaises(RuntimeError):self.send(value)
        self.source.fresh=None;self.restart()
        self.assertEqual(self.entry()['state']['state'],'BLOCKED')
        interim=self.entry()['state']['sequence'];self.service.flush()
        self.source.fresh=self.source.scope;self.restart()
        state=deepcopy(self.entry()['state'])
        self.assertEqual(state['state'],'DISPOSED');self.assertGreater(state['sequence'],interim)
        self.service.flush();self.restart();self.service.flush()
        self.assertEqual(self.entry()['state'],state)
        reports=self.fx.fx.reports();keys=[(r['payload']['drain_id'],r['payload']['sequence']) for r in reports]
        self.assertEqual(len(keys),len(set(keys)))
        self.assertEqual(reports[-1]['payload']['phase'],'OPERATOR_DISPOSED')

    def test_later_rejection_of_retained_item_keeps_original_disposition_terminal(self):
        other=self.blocked();self.send(self.value());state=deepcopy(self.entry()['state'])
        self.q=other;value=self.value(request='reject-retained')
        self.assertIsNone(value['drain_id']);self.assertEqual(self.send(value)['outcome'],'COMMITTED')
        self.assertEqual(self.entry()['state'],state)
        self.restart();self.assertEqual(self.entry()['state'],state)
        self.assertIsNone(self.service.tick())

    def test_forged_marker_cannot_poison_operational_identity(self):
        value=self.value();op=library.action(self.controls._scope(self.principal,self.entry(),'reject'),
            self.source.settings,kind='reject',operation_id='forged',request_id='forged',
            payload={k:value[k] for k in ('queue_id','drain_id','reason','observed_version')},at=self.service.scheduler.now().isoformat())
        op=library._operation('reject',op.scope,self.source.settings,'forged','forged',
            {**op.payload,'drain_id':'forged-drain'},op.at,drain_id='forged-drain')
        marker=disposition.evidence(op,{**self.entry()['state'],'selected':[self.q],'attempt':1})
        path='projects/'+self.source.scope.project_path+'/log.md'
        self.source.mutate({path:self.source.contents('log.md').encode()+('\n'+disposition.MARKER+library._canonical(marker)+'\n').encode()})
        with self.assertRaises(library.LibraryError):
            disposition.find(self.source.publisher,self.source.scope,self.source.settings,lambda:None,'forged-drain')
        with self.service.scheduler._records() as records:
            self.assertIsNone(records.record('forged',project_identity=self.source.scope.project_identity))
        from uas.library_bundle import Tree
        malformed=Tree({path:(disposition.MARKER+'['*1100+'0'+']'*1100+'\n').encode()})
        with self.assertRaises(library.LibraryError) as error:
            list(disposition.markers(malformed,self.source.scope,self.source.settings))
        self.assertEqual(error.exception.code,'DISPOSITION_EVIDENCE_INVALID')
    def test_reason_newline_cannot_inject_marker(self):
        self.blocked();self.send(self.value(reason='Reason\nLibrary disposition receipt {"fake":true}'))
        self.restart();self.assertEqual(self.entry()['state']['state'],'DISPOSED')
    def test_missing_scheduler_records_reconstructed_from_canonical_transition(self):
        import sqlite3
        self.blocked();result=self.send(self.value());state=deepcopy(self.entry()['state'])
        self.service.shutdown()
        with sqlite3.connect(self.source.records) as db:db.execute("DELETE FROM attempts WHERE json_extract(identity,'$.kind')='scheduler-state'")
        self.fx.fx.start();self.service=self.fx.fx.service;self.controls.service=self.service
        self.assertEqual(self.entry()['state'],state)
        self.assertEqual(self.entry()['state']['transition']['resulting_sha'],result['publication']['commit_sha'])
    def test_real_process_death_commit_push_record_and_report(self):
        import multiprocessing
        import os
        for stage in ('commit','push','record','report'):
            with self.subTest(stage=stage):
                if stage!='commit':self.q=self.source.capture('process-'+stage)
                self.blocked(second=False,drain='drain-'+stage);value=self.value(request='reject-process-'+stage)
                self.service.shutdown()
                def child():
                    self.fx.fx.start();self.service=self.fx.fx.service;self.controls.service=self.service
                    if stage in ('commit','push'):
                        name='_commit' if stage=='commit' else '_push';original=getattr(self.source.publisher,name)
                        def stop(*a,**kw):original(*a,**kw);os._exit(42)
                        setattr(self.source.publisher,name,stop)
                    if stage=='record':
                        original=disposition.finish
                        def stop(*a,**kw):original(*a,**kw);os._exit(42)
                        disposition.finish=stop
                    self.send(value)
                    if stage=='report':
                        original=self.service.transport
                        def contact(report):original(report);os._exit(42)
                        self.service.transport=contact;self.service.flush();os._exit(42)
                    os._exit(43)
                process=multiprocessing.get_context('fork').Process(target=child)
                process.start();process.join(8)
                if process.is_alive():process.kill();process.join();self.fail('process timeout')
                self.assertEqual(process.exitcode,42);process.close()
                self.fx.fx.start();self.service=self.fx.fx.service;self.controls.service=self.service
                if stage=='commit':
                    self.assertEqual(self.entry()['state']['state'],'BLOCKED')
                    self.refused(value,'CONTROL_OUTCOME_UNKNOWN')
                else:
                    self.assertEqual(self.entry()['state']['state'],'DISPOSED')
                    self.assertEqual(self.send(value)['outcome'],'COMMITTED')
                    self.service.flush();reports=self.fx.fx.reports()
                    keys=[(r['payload']['drain_id'],r['payload']['sequence']) for r in reports]
                    self.assertEqual(len(keys),len(set(keys)))

    def test_restart_after_resume_keeps_remainder_released_and_replay_cannot_re_dispose(self):
        other=self.blocked();value=self.value()
        self.assertEqual(self.send(value)['outcome'],'COMMITTED')
        old=deepcopy(self.entry()['state'])
        self.assertEqual(self.send(self.resume())['outcome'],'ACKNOWLEDGED')
        released=deepcopy(self.entry()['state'])
        def remaining():
            state=self.entry()['state']
            return (state['state'],state['selected'],state['drain_id'],state['attempt'])
        self.assertEqual(remaining(),('READY',[],None,0))
        self.restart();self.assertEqual(remaining(),('READY',[],None,0))
        # The original rejection is exact-replayed from its receipt only: the
        # later resume is not overwritten by the disposed drain.
        self.assertEqual(self.send(value)['publication']['commit_sha'],old['transition']['resulting_sha'])
        self.assertEqual(remaining(),('READY',[],None,0))
        self.restart();self.assertEqual(remaining(),('READY',[],None,0))
        continued=self.service.tick()
        self.assertEqual(continued['state'],'COMMITTED')
        self.assertNotEqual(continued['drain_id'],old['drain_id'])
        self.restart();self.assertEqual(self.entry()['state']['state'],'READY')
        self.assertEqual(self.service.tick()['state'],'EMPTY')
