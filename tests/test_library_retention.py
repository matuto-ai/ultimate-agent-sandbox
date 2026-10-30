"""T39 real SQLite bounds and canonical capture/recovery, no canonical pruning."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
import fcntl
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import library_support as support
import test_library_records as records_fixture
import test_library_enqueue as enqueue_fixture
import test_library_service as service_fixture
import test_library_import as import_fixture
import test_library_controls as controls_fixture
from uas import library, library_deadline
from uas.library_records import LibraryRecords
from uas.library_observations import Owner

AUDIT={'retention_days':1,'max_bytes':4*1024*1024}
FUTURE=datetime.now(timezone.utc)+timedelta(days=3)

class RetentionRecordsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'records.db'
        self.records=LibraryRecords(self.path,'deployment-1');self.addCleanup(self.records.close)
        self.records.configure_retention(AUDIT)
    def reopen(self):
        self.records.close();self.records=LibraryRecords(self.path,'deployment-1');self.addCleanup(self.records.close)
    def op(self,n=1):return support.capture(operation_id='op-'+str(n),request_id='req-'+str(n))
    def terminal(self,n=1):
        op=self.op(n);self.records.begin(op)
        proof=records_fixture.durable(op)
        proof['evidence']=[dict(rule='safe',path='file'+str(i),line=1,sha256='a'*64) for i in range(30)]
        self.records.finish(op,proof);return op,proof
    def total(self):return sum(p.stat().st_size for p in self.path.parent.glob(self.path.name+'*') if p.is_file())
    def test_expiry_preserves_identity_conflicts_and_finish_reconciliation(self):
        op,receipt=self.terminal();self.records.compact(now=FUTURE);self.reopen()
        record=self.records.begin(op)['record']
        self.assertEqual(record['state'],'DETAIL_EXPIRED');self.assertNotIn('evidence',record['receipt'])
        self.assertTrue(record['receipt']['detail_expired'])
        self.assertEqual(self.records.finish(op,receipt),record)
        with self.assertRaises(library.LibraryError) as caught:self.records.begin(support.capture(operation_id=op.operation_id,request_id=op.request_id,payload=support.value(body='different')))
        self.assertEqual(caught.exception.code,'ID_CONFLICT')
        with self.assertRaises(library.LibraryError) as caught:self.records.begin(replace(op,operation_id='new-command'))
        self.assertEqual(caught.exception.code,'DETAIL_EXPIRED')
    def test_pending_and_uncertain_never_expire(self):
        first=self.op();self.records.begin(first)
        second=self.op(2);self.records.begin(second);self.records.finish(second,library.receipt(second,'NOT_DURABLE',at=support.AT,reason='GIT_UNKNOWN'))
        self.records.compact(now=FUTURE);self.reopen()
        self.assertEqual(self.records.record(first.operation_id,project_identity=first.scope.project_identity)['state'],'PENDING')
        self.assertEqual(self.records.record(second.operation_id,project_identity=first.scope.project_identity)['state'],'RECORDED')
    def test_current_details_not_expired_by_age_and_statistics_mark_partial(self):
        op,_=self.terminal();self.records.compact()
        self.assertEqual(self.records.record(op.operation_id,project_identity=op.scope.project_identity)['state'],'RECORDED')
        self.records.compact(now=FUTURE)
        rows,complete=self.records.project_history(op.scope.project_identity,limit=100)
        self.assertFalse(complete);self.assertEqual(len(rows),1)
    def test_policy_persists_and_actual_files_stay_bounded_until_safe_refusal(self):
        cap=262144
        self.records.configure_retention({'retention_days':1,'max_bytes':cap});self.reopen()
        completed=[]
        for n in range(300):
            try:self.terminal(n);completed.append(n)
            except library.LibraryError as error:
                self.assertEqual(error.code,'RECORD_CAPACITY');break
            self.assertLessEqual(self.total(),cap)
        else:self.fail('expected bounded capacity')
        self.assertTrue(completed);self.assertLessEqual(self.total(),cap)
        self.reopen()
        for n in completed:self.assertIsNotNone(self.records.record(self.op(n).operation_id,project_identity=self.op(n).scope.project_identity)['receipt'])
    def test_compaction_reclaims_real_storage_and_cannot_erase_tombstones(self):
        for n in range(20):self.terminal(n)
        before=self.total();self.records.compact(now=FUTURE);after=self.total()
        self.assertLess(after,before);self.assertLessEqual(after,AUDIT['max_bytes'])
        self.reopen()
        self.assertTrue(all(self.records.begin(self.op(n))['state']=='DETAIL_EXPIRED' for n in range(20)))
    def test_reader_prevents_wal_accumulation_safe_refusal(self):
        self.terminal()
        reader=sqlite3.connect(self.path,isolation_level=None);self.addCleanup(reader.close)
        reader.execute('BEGIN');reader.execute('SELECT * FROM attempts').fetchall()
        # The writer first checkpoints. A live snapshot can prevent truncation.
        with self.assertRaises(library.LibraryError) as caught:self.records.begin(self.op(2))
        self.assertEqual(caught.exception.code,'RECORD_CAPACITY')
        self.assertLessEqual(self.total(),AUDIT['max_bytes'])
        reader.rollback();self.records.begin(self.op(2))
    def test_small_cap_installs_durable_block_without_deleting_required_state(self):
        op=self.op();self.records.begin(op)
        with self.assertRaises(library.LibraryError) as caught:self.records.configure_retention({'retention_days':1,'max_bytes':1})
        self.assertEqual(caught.exception.code,'RECORD_CAPACITY');self.reopen()
        with self.assertRaises(library.LibraryError):self.records.begin(self.op(2))
        self.assertEqual(self.records.record(op.operation_id,project_identity=op.scope.project_identity)['state'],'PENDING')
    def test_atomic_compaction_lost_commit_reopens_same_expired_identity(self):
        op,_=self.terminal();commit=self.records._commit
        def lost():commit();raise sqlite3.OperationalError('lost')
        with patch.object(self.records,'_commit',lost):
            with self.assertRaises(library.LibraryError) as caught:self.records.compact(now=FUTURE)
        self.assertEqual(caught.exception.code,'RECORD_UNCERTAIN');self.reopen()
        self.assertEqual(self.records.begin(op)['state'],'DETAIL_EXPIRED')
    def test_capacity_reserves_vacuum_copy_and_full_wal(self):
        page=self.records._connection().execute('PRAGMA page_size').fetchone()[0]
        limit=self.records._page_limit(AUDIT)
        self.assertLessEqual(limit*(3*page+24)+32768+4096,AUDIT['max_bytes'])
    def test_writer_lock_rejects_unsafe_mode_and_respects_operation_deadline(self):
        lock=Path(str(self.path)+'.writer');lock.chmod(0o644)
        with self.assertRaises(library.LibraryError) as caught:self.records.begin(self.op())
        self.assertEqual(caught.exception.code,'INVALID_STORE');lock.chmod(0o600)
        fd=os.open(lock,os.O_RDWR);self.addCleanup(os.close,fd);fcntl.flock(fd,fcntl.LOCK_EX)
        with library_deadline.bounded(0.02):
            with self.assertRaises(library.LibraryError) as caught:self.records.begin(self.op())
        self.assertEqual(caught.exception.code,'ATTEMPT_TIMEOUT')
        fcntl.flock(fd,fcntl.LOCK_UN);self.records.begin(self.op())
    def test_exact_legacy_schema_upgrade_preserves_pending(self):
        op=self.op();self.records.begin(op);self.records.close()
        with sqlite3.connect(self.path) as db:db.execute('DROP TABLE retention')
        self.reopen();self.assertEqual(self.records.begin(op)['state'],'PENDING')
    def test_arbitrary_extra_schema_not_accepted(self):
        self.records.close()
        with sqlite3.connect(self.path) as db:db.execute('CREATE TABLE alien(value)')
        with self.assertRaises(library.LibraryError) as caught:LibraryRecords(self.path,'deployment-1')
        self.assertEqual(caught.exception.code,'INVALID_STORE')

class RetentionCaptureTests(unittest.TestCase):
    def setUp(self):
        self.f=enqueue_fixture.EnqueueTests('test_real_publication_metadata_and_separate_visibility');self.f.setUp();self.addCleanup(self.f.doCleanups)
    def compact(self):
        with LibraryRecords(self.f.records,'deployment-1') as records:
            records.configure_retention(AUDIT);records.compact(now=FUTURE)
    def test_expired_public_capture_does_not_republish_and_auth_still_required(self):
        result=self.f.enqueue();head=self.f.head();count=self.f.count();self.compact()
        for command in ('command-1','fresh-command'):
            repeat=self.f.enqueue(command=command)
            self.assertEqual(repeat.outcome,'DURABLY_QUEUED');self.assertEqual(repeat.reason,'DETAIL_EXPIRED')
            self.assertEqual(repeat.published_sha,result.published_sha)
        self.assertEqual(self.f.head(),head);self.assertEqual(self.f.count(),count)
        self.assertEqual(self.f.enqueue(command='conflict',value=support.value(body='changed')).reason,'ID_CONFLICT')
        self.f.fresh=None;denied=self.f.enqueue(command='denied')
        self.assertEqual(denied.outcome,'REJECTED');self.assertEqual(self.f.head(),head)
    def test_expired_request_still_refuses_other_command_identity(self):
        self.f.enqueue()
        self.f.enqueue(command='other-command',request='other-request',value=support.value(body='different'))
        self.compact()
        self.assertEqual(self.f.enqueue(command='other-command').reason,'ID_CONFLICT')

    def test_expiry_observation_coverage_is_partial_not_zero_success(self):
        self.f.enqueue();self.compact()
        owner=Owner(self.f.publisher,current_scope=lambda:self.f.scope,settings=lambda:self.f.settings)
        result=owner.capture(observed_at=FUTURE.isoformat(),window_start=support.AT)
        self.assertEqual(result['row']['coverage'],'partial');self.assertIsNone(result['row']['published_drafts'])
    def test_publisher_applies_deployment_audit_before_operations(self):
        self.f.publisher.close();self.f.publisher=self.f.make_publisher();self.addCleanup(self.f.publisher.close)
        self.f.publisher.audit=AUDIT;self.f.publisher.startup()
        with LibraryRecords(self.f.records,'deployment-1') as records:self.assertEqual(records._policy(records._connection()),AUDIT)

class RetentionRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f=service_fixture.ServiceTests('test_commit_reports_survive_hub_outage_and_deduplicate');self.f.setUp();self.addCleanup(self.f.doCleanups)
    def compact(self):
        with LibraryRecords(self.f.source.records,'deployment-1') as records:
            records.configure_retention(AUDIT);return records.compact(now=FUTURE)
    def test_unacknowledged_reports_and_fixed_batch_survive_compact_restart(self):
        self.f.available=False;self.assertEqual(self.f.service.tick()['state'],'COMMITTED')
        self.compact();self.f.restart();self.assertEqual(self.f.reports(),[])
        self.f.available=True;self.f.service.flush();self.assertEqual(len(self.f.reports()),2)
        self.compact();self.f.restart();self.f.service.flush();self.assertEqual(len(self.f.reports()),2)
    def test_completed_old_drain_tombstone_refuses_inference_after_new_state(self):
        self.assertEqual(self.f.service.tick()['state'],'COMMITTED')
        drain=self.f.transitions()[-1]['drain_id']
        self.f.service.tick() # EMPTY state still preserves latest drain; start a new one below.
        self.f.source.enqueue('new-command','new-request',support.value(body='second'))
        self.f.service.scheduler.request(self.f.source.scope.project_identity)
        self.f.service.tick();self.f.service.flush();self.compact()
        with self.assertRaises(library.LibraryError) as caught:self.f.fixture.runner().recover(drain)
        self.assertEqual(caught.exception.code,'DETAIL_EXPIRED')


class RetentionOwnerTests(unittest.TestCase):
    def test_human_control_exact_ack_conflict_and_revocation_after_expiry(self):
        f=controls_fixture.ControlsTests('test_operational_ack_no_git_or_model_and_exact_retry')
        f.setUp();self.addCleanup(f.doCleanups)
        value=f.value();before=f.send(value);state=f.state()
        with LibraryRecords(f.source.records,'deployment-1') as records:
            records.configure_retention(AUDIT);records.compact(now=FUTURE)
        repeat=f.send(value)['result']
        self.assertTrue(repeat['detail_expired']);self.assertEqual(repeat['acknowledgement'],before['result']['acknowledgement'])
        self.assertEqual(f.state(),state)
        self.assertEqual(f.send({**value,'observed_version':'0'*64})['error'],'ID_CONFLICT')
        f.allowed=False;self.assertNotEqual(f.send(value)['outcome'],'observed')
        self.assertEqual(f.state(),state)
    def test_import_exact_and_new_command_expiry_cannot_repeat_publication(self):
        f=import_fixture.ImportTests('test_confirm_atomic_pending_provenance_no_acceptance')
        f.setUp();self.addCleanup(f.doCleanups)
        preview=f.preview();f.confirm(preview);head=f.head();count=f.count()
        with LibraryRecords(f.records,'deployment-1') as records:
            records.configure_retention(AUDIT);records.compact(now=FUTURE)
        for name in ('confirm','new-confirm'):
            with self.assertRaises(library.LibraryError) as caught:f.confirm(preview,name=name)
            self.assertEqual(caught.exception.code,'DETAIL_EXPIRED')
        f.human=False
        with self.assertRaises(library.LibraryError) as caught:f.confirm(preview)
        self.assertNotEqual(caught.exception.code,'DETAIL_EXPIRED')
        self.assertEqual(f.head(),head);self.assertEqual(f.count(),count)
