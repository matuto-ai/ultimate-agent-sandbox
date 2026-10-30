"""T21 real Git, service restart, external SQLite and actual Hub metadata replay."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sys
import threading
import time
import unittest
from unittest.mock import patch
import library_support as support
import test_library_attempts as attempts
from uas import library
from uas.ledger import RoomLedger, LedgerError
from uas.library_hub import DrainReports
from uas.library_service import Service, Project, bounded_report
from uas.library_records import LibraryRecords


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = attempts.AttemptTests('test_invalid_output_publishes_nothing')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.source=self.fixture.source; self.source.publisher.close()
        self.path=self.source.base/'hub.db'; self.available=True
        self.mode='success'; self.service=None; self.now=datetime(2026,10,30,tzinfo=timezone.utc)
        self.start()
    def contact(self, report):
        if not self.available: raise OSError('offline')
        with RoomLedger(self.path,'alpha') as ledger:
            return DrainReports(ledger,room_id='alpha',project_identity=self.source.scope.project_identity,
                authenticate=lambda:True).receive(report)
    def projects(self, publisher):
        self.source.publisher=publisher
        self.source.service.publisher=publisher
        runner=self.fixture.runner()
        def context(selected):
            state=self.service.scheduler.state(self.source.scope.project_identity)
            reply=dict(version=1,drain_id=state['drain_id'],attempt=state['attempt'],operations=[],
                outcomes=[dict(queue_id=q,kind='parked',reason='NEEDS_EVIDENCE') for q in selected])
            runner.dispatcher.gateway.routes[self.fixture.profile.identity()]=(
                sys.executable,str(Path(__file__).with_name('fixture_library_provider.py')),
                str(self.fixture.marker),self.mode,json.dumps(reply))
            return (),()
        return [Project(self.source.scope,runner,context)]
    def start(self):
        self.service=Service(self.source.make_publisher(),self.projects,transport=self.contact,
            room_for=lambda scope:'alpha',now=lambda:self.now)
        self.service.startup(); self.addCleanup(self.service.shutdown)
    def restart(self):
        self.service.shutdown(); self.start()
    def reports(self):
        if not self.path.exists(): return []
        with RoomLedger(self.path,'alpha') as ledger:
            return [e for e in ledger.replay(0,limit=1000) if e['kind']=='library.drain.reported']
    def transitions(self):
        with LibraryRecords(self.source.records,'deployment-1') as r:
            return [x['manifest']['transition'] for x in r.iter_schedules(self.source.scope.project_identity)
                    if x['manifest'].get('transition')]
    def test_commit_reports_survive_hub_outage_and_deduplicate(self):
        self.available=False
        result=self.service.tick(); self.assertEqual(result['state'],'COMMITTED')
        self.assertEqual(self.reports(),[])
        self.available=True;self.service.flush()
        self.assertEqual([x['phase'] for x in self.transitions()],['STARTED','COMMITTED'])
        self.assertEqual(len(self.reports()),2)
        self.restart();self.service.flush();self.assertEqual(len(self.reports()),2)
        self.assertEqual(self.service.tick()['state'],'EMPTY')
    def test_backoff_restored_and_report_replayed_without_contact(self):
        self.mode='error';self.available=False
        self.assertEqual(self.service.tick()['state'],'BACKOFF')
        state=self.service.scheduler.state(self.source.scope.project_identity)
        self.restart();self.assertEqual(self.service.scheduler.state(self.source.scope.project_identity)['due'],state['due'])
        self.fixture.marker.unlink();self.assertIsNone(self.service.tick());self.assertFalse(self.fixture.marker.exists())
        self.available=True;self.service.flush();self.assertEqual(len(self.reports()),2)
        self.assertEqual(self.transitions()[-1]['phase'],'RETRY_SCHEDULED')
    def test_push_before_state_clear_recovers_without_second_model(self):
        self.available=False
        original=self.service.scheduler._save
        def save(entry,value,at,**kwargs):
            if kwargs.get('transition',{}).get('phase')=='COMMITTED': raise OSError('process dies after push')
            return original(entry,value,at,**kwargs)
        with patch.object(self.service.scheduler,'_save',save):
            with self.assertRaises(OSError):self.service.tick()
        count=self.source.count();self.fixture.marker.unlink();self.restart()
        self.assertEqual(self.source.count(),count);self.assertFalse(self.fixture.marker.exists())
        self.assertEqual(self.transitions()[-1]['phase'],'COMMITTED')
        self.available=True;self.service.flush();self.assertEqual(len(self.reports()),2)
    def test_lost_hub_ack_replays_same_metadata_once(self):
        def lost(report):self.contact(report);raise OSError('ack lost')
        self.service.transport=lost;self.service.tick()
        self.assertEqual(len(self.reports()),1)
        self.service.transport=self.contact;self.service.flush();self.assertEqual(len(self.reports()),2)
    def test_receiver_auth_scope_and_same_key_changed_payload_refused(self):
        self.service.tick();value=self.transitions()[0]
        report={'room_id':'alpha','project_identity':self.source.scope.project_identity,**value}
        with RoomLedger(self.path,'alpha') as ledger:
            owner=DrainReports(ledger,room_id='alpha',project_identity=self.source.scope.project_identity,authenticate=lambda:True)
            self.assertTrue(owner.receive(report))
            with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):owner.receive({**report,'reason':'CHANGED'})
            with self.assertRaisesRegex(LedgerError,'INVALID_LIBRARY_BINDING'):owner.receive({**report,'room_id':'beta'})
            owner.authenticate=lambda:False
            with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):owner.receive(report)
    def test_second_process_cannot_touch_clone_before_lease(self):
        receiver,sender=multiprocessing.get_context('fork').Pipe(duplex=False)
        def child():
            os.close(self.service.publisher._lease)
            p=self.source.make_publisher()
            try:
                with patch.object(p,'_clone_state',side_effect=AssertionError('clone touched')):p.startup()
            except library.LibraryError as error:sender.send(error.code)
            finally:sender.close()
        process=multiprocessing.get_context('fork').Process(target=child);process.start();sender.close()
        try:
            self.assertTrue(receiver.poll(2));self.assertEqual(receiver.recv(),'LEASE_BUSY')
        finally:
            process.join(2)
            if process.is_alive():process.kill();process.join()
            receiver.close();process.close()
    def test_hung_report_bounded_and_releases_child_lease(self):
        start=time.monotonic()
        self.assertFalse(bounded_report(lambda _:time.sleep(10),{},.05,self.service.publisher._lease))
        self.assertLess(time.monotonic()-start,1)
        self.restart()
    def test_shutdown_during_attempt_waits_no_new_selection_and_flushes(self):
        self.mode='release';out=[]
        thread=threading.Thread(target=lambda:out.append(self.service.tick()));thread.start()
        deadline=time.monotonic()+3
        while not self.fixture.marker.exists() and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(self.fixture.marker.exists())
        self.service.request_stop();self.assertIsNone(self.service.tick())
        Path(str(self.fixture.marker)+'.release').touch();thread.join(5)
        self.assertFalse(thread.is_alive());self.service.shutdown()
        self.assertEqual(out[0]['state'],'COMMITTED');self.assertEqual(len(self.reports()),2)
    def test_metadata_outbox_contains_no_model_or_draft_content(self):
        self.service.tick()
        raw=self.source.records.read_bytes()
        self.assertNotIn(b'Selected draft data.',raw)
        self.assertNotIn(b'"operations"',raw)
        self.assertEqual(len(self.reports()),2)

    def test_actual_process_death_at_intent_return_push_and_report_boundaries(self):
        # Independent actual processes reopen the same lease/clone/store. No
        # exception mock stands in for a dead process at these boundaries.
        for stage in ('intent','returned','push','report'):
            with self.subTest(stage=stage):
                if self.service._closed: self.start()
                queue=self.source.capture('process-'+stage)
                self.service.shutdown()
                def child():
                    self.start()
                    if stage=='returned':
                        self.fixture.hook=lambda event: os._exit(42) if event['state']=='returned' else None
                    if stage=='push':
                        original=self.service.publisher._push
                        def push(*args,**kw):original(*args,**kw);os._exit(42)
                        self.service.publisher._push=push
                    if stage=='intent':
                        original=self.service.scheduler._save
                        def save(entry,value,at,**kw):
                            result=original(entry,value,at,**kw)
                            if entry['state'].get('transition',{}).get('phase')=='STARTED':os._exit(42)
                            return result
                        self.service.scheduler._save=save
                    if stage=='report':
                        self.service.transport=lambda report: (self.contact(report),os.kill(os.getppid(),signal.SIGKILL))[0]
                    self.service.tick();os._exit(43)
                process=multiprocessing.get_context('fork').Process(target=child);process.start();process.join(8)
                if process.is_alive():process.kill();process.join();self.fail('child exceeded bound')
                self.assertIn(process.exitcode,(42,-signal.SIGKILL));process.close()
                self.start();before=self.source.count()
                if stage in ('push','report'):
                    self.assertTrue(any(x['phase']=='COMMITTED' for x in self.transitions()))
                    result=self.service.tick();self.assertIn(result['state'],('EMPTY','COMMITTED'))
                    if result['state']=='EMPTY':self.assertEqual(self.source.count(),before)
                else:
                    self.assertEqual(self.service.tick()['state'],'COMMITTED')
                self.service.shutdown()

    def test_source_park_push_before_state_recovers_exact_outcomes(self):
        declaration,_=self.source.source()
        queue=self.source.capture('bad-source',sources=[declaration])
        original=self.service.scheduler._save
        def save(entry,value,at,**kwargs):
            if kwargs.get('transition',{}).get('phase')=='COMMITTED':raise OSError('after source park')
            return original(entry,value,at,**kwargs)
        with patch.object(self.service.scheduler,'_save',save):
            with self.assertRaises(OSError):self.service.tick()
        before=self.source.count();self.restart()
        committed=[x for x in self.transitions() if x['phase']=='COMMITTED'][-1]
        self.assertEqual(committed['outcomes'],[dict(queue_id=queue,kind='parked',reason='SOURCE_UNRESOLVED')])
        self.assertEqual(self.source.count(),before)
        # The unrelated good queue survives and is considered in a fresh drain.
        self.assertEqual(self.service.tick()['state'],'COMMITTED')

    def test_operator_disposed_persisted_terminal_survives_revocation_and_replay(self):
        self.mode='error';self.service.tick()
        entry=self.service.scheduler._entries[self.source.scope.project_identity]
        state=entry['state']
        self.service.scheduler._save(entry,{**state,'state':'DISPOSED','due':None,'reason':'HUMAN_DISPOSITION'},self.now,
            transition=dict(phase='OPERATOR_DISPOSED',resulting_sha=self.source.head(),outcomes=[dict(queue_id=self.fixture.q,kind='rejected',reason='HUMAN_REJECTED')]))
        self.restart()
        self.assertEqual(self.service.scheduler.state(self.source.scope.project_identity)['state'],'DISPOSED')
        self.source.fresh=None
        self.service.scheduler._signals()
        self.service.scheduler.recover(self.source.scope.project_identity)
        self.assertEqual(self.service.scheduler._entries[self.source.scope.project_identity]['state']['state'],'DISPOSED')
        self.source.fresh=self.source.scope
        with self.assertRaisesRegex(library.LibraryError,'DRAIN_DISPOSED'):
            self.service.scheduler.request(self.source.scope.project_identity,retry=True)
        self.assertEqual(self.transitions()[-1]['phase'],'OPERATOR_DISPOSED')

    def test_recovered_commit_precedes_new_oversized_queue_validation(self):
        original=self.service.scheduler._save
        def save(entry,value,at,**kw):
            if kw.get('transition',{}).get('phase')=='COMMITTED':raise OSError('after push')
            return original(entry,value,at,**kw)
        with patch.object(self.service.scheduler,'_save',save):
            with self.assertRaises(OSError):self.service.tick()
        self.source.capture('later-large')
        doc=support.document();doc['repository'].update(target=self.source.publisher.target,branch=self.source.publisher.branch)
        doc['limits'].update(body_bytes=1,batch_bytes=1)
        self.source.settings=support.settings(doc)
        self.restart()
        phases=[x['phase'] for x in self.transitions()]
        self.assertEqual(phases[-2:],['COMMITTED','BLOCKED'])

    def test_shared_store_corruption_stops_startup_before_draining(self):
        self.service.shutdown()
        import sqlite3
        with sqlite3.connect(self.source.records) as db:db.execute('CREATE TABLE unexpected(x)')
        with self.assertRaisesRegex(library.LibraryError,'RECORD_|INVALID_STORE'):self.start()

    def test_outbox_validation_rejects_content_and_unbound_outcomes(self):
        self.service.tick();value=self.transitions()[-1]
        for bad in ({**value,'body':'private'}, {**value,'phase':'STARTED'},
                    {**value,'outcomes':[{'queue_id':self.fixture.q,'kind':'parked','reason':'bad words'}]}):
            with self.assertRaises(library.LibraryError):library.drain_transition(bad)

    def test_two_projects_local_invalidity_does_not_block_unrelated_drain(self):
        import test_library_scheduler as scheduler_tests
        self.scheduler=self.service.scheduler;self.runner=self.fixture.runner();self.replies=[]
        self.register=lambda runner:scheduler_tests.SchedulerTests.register(self,runner)
        other,queue=scheduler_tests.SchedulerTests.second(self)
        # Malformed first Project's canonical bundle is local, not a store failure.
        self.source.mutate({'projects/'+self.source.scope.project_path+'/context/index.md':b'\xffinvalid'})
        self.service.scheduler.recover(self.source.scope.project_identity)
        self.assertEqual(self.service.scheduler.state(self.source.scope.project_identity)['state'],'BLOCKED')
        result=self.service.tick();self.assertEqual(result['project_identity'],other)
        self.assertEqual(result['state'],'COMMITTED')

    def test_revoked_live_scope_keeps_trusted_binding_and_reports_blocked(self):
        self.service.shutdown();self.source.fresh=None
        self.start()
        entry=self.service.scheduler._entries[self.source.scope.project_identity]
        self.assertEqual(entry['state']['state'],'BLOCKED')
        self.assertEqual(self.reports()[-1]['payload']['phase'],'BLOCKED')

    def test_live_oversized_project_is_blocked_not_invalid_transition(self):
        path='projects/'+self.source.scope.project_path+'/context/large.md'
        self.source.mutate({path:b'x'*(self.source.settings['limits']['document_bytes']+1)})
        result=self.service.tick()
        self.assertEqual(result['state'],'BLOCKED')
        self.assertEqual(self.transitions()[-1]['phase'],'BLOCKED')

    def test_flush_sqlite_wait_is_bounded_and_store_failure_is_not_hub_outage(self):
        import sqlite3
        self.available=False;self.service.tick();self.available=True
        self.service.flush_seconds=.05
        db=sqlite3.connect(self.source.records,isolation_level=None)
        db.execute('BEGIN IMMEDIATE')
        start=time.monotonic()
        try:
            with self.assertRaises(library.LibraryError):self.service.flush()
            self.assertLess(time.monotonic()-start,.7)
        finally:db.rollback();db.close()

    def test_normal_flush_deadline_yields_without_failing_drains(self):
        self.available=False;self.service.tick();self.available=True
        with patch('uas.library_service.bounded_report',side_effect=library.LibraryError('ATTEMPT_TIMEOUT','deadline')):
            self.assertEqual(self.service.flush(),0)
        self.service.flush()
        self.assertEqual([e['payload']['phase'] for e in self.reports()],['STARTED','COMMITTED'])

    def test_bounded_replay_progresses_past_large_acknowledged_prefix(self):
        entry=self.service.scheduler._entries[self.source.scope.project_identity]
        for _ in range(100):self.service.scheduler._save(entry,entry['state'],self.now)
        self.available=False;self.service.tick();self.available=True
        self.service.flush_seconds=.03
        for _ in range(200):
            self.service.flush()
            if len(self.reports())==2:break
        self.assertEqual(len(self.reports()),2)
        self.assertGreater(self.service._cursors[self.source.scope.project_identity],100)

if __name__=='__main__':unittest.main()
