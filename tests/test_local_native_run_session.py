"""Persistent native request lifetime and exactly-once boundary, no native effects."""
import io
import threading
import unittest
from unittest.mock import Mock,patch
from uas.local_native_run_session import LocalNativeRunSession
from uas.local_runtime_plan import LocalRuntimePlan
from uas.ledger import LedgerError
from test_native_run_admission import fixture

class LocalNativeRunSessionTests(unittest.TestCase):
    def make(self):
        f=fixture(self);plan=object.__new__(LocalRuntimePlan)
        plan.room=f.plan.room;plan.seats={'pi':{'participant':f.participant}};plan.require_unchanged=Mock()
        origin=Mock();origin.revoked=False;origin.pidfd=50
        resources={'instance':f.session.instance_id,'room_id':plan.room['id']}
        ready={'room_id':plan.room['id'],'room_instance':resources['instance']}
        with patch('uas.local_native_run_session.readonly_local_supervisor',return_value=f.supervisor), \
             patch('uas.local_native_run_session.alive',return_value=True), \
             patch('uas.local_native_run_session.select.select',return_value=([],[],[])):
            owner=LocalNativeRunSession(plan,resources,control=object(),origin=origin,ready=ready,
                metadata={},broker_fd=10,checkout_fd=11,parent_fd=12)
        owner.current=Mock();return f,owner

    def test_operation_uses_original_session_and_observed_result_without_retry(self):
        f,owner=self.make()
        observed={'run_id':'run-one','session':{'outcome':'attention','last_observed_run':{'generation':1}}}
        with patch('uas.native_session.run',return_value=observed) as run:
            result=owner.open_human('op-one',1,session=f.session)
            self.assertEqual(result,{'status':'finished','run_id':'run-one','generation':1,'outcome':'attention'})
            self.assertIs(run.call_args.kwargs['human_request'].session,f.session)
            self.assertIs(run.call_args.kwargs['local_host'],owner)
            self.assertEqual(owner.open_human('op-one',1,session=f.session),result)
            self.assertEqual(run.call_count,1)
            self.assertTrue(owner._cleanup_confirmed)
        self.assertNotIn('session',owner._attempts['op-one'])

    def test_unknown_operation_never_retries_or_claims_cleanup(self):
        f,owner=self.make()
        with patch('uas.native_session.run',side_effect=OSError('uncertain')) as run:
            with self.assertRaises(OSError):owner.open_human('op-one',1,session=f.session)
            self.assertFalse(owner._cleanup_confirmed)
            with self.assertRaisesRegex(LedgerError,'OUTCOME_UNKNOWN'):
                owner.open_human('op-one',1,session=f.session)
            with self.assertRaisesRegex(LedgerError,'CLEANUP_UNKNOWN'):
                owner.open_human('different-operation',2,session=f.session)
            self.assertEqual(run.call_count,1)
            self.assertFalse(owner._cleanup_confirmed)

    def test_preselected_successor_keeps_original_request_and_budget(self):
        f,owner=self.make()
        observed={'run_id':'run-two','session':{'outcome':'completed','last_observed_run':{'generation':1}}}
        with patch('uas.native_session.run',return_value=observed) as run:
            owner.open_human('op-one',1,session=f.session,next_operation_id='op-two',next_issue_number=2)
            successor=run.call_args.kwargs['next_request']
            self.assertIs(successor.session,f.session)
            self.assertEqual((successor.operation_id,successor.issue_number),('op-two',2))
            with self.assertRaisesRegex(LedgerError,'NEW_EPOCH_UNSUPPORTED'):
                owner.open_human('op-three',3,session=f.session)
            self.assertEqual(run.call_count,1)
        f,owner=self.make()
        with self.assertRaisesRegex(LedgerError,'SUCCESSOR'):
            owner.open_human('op-one',1,session=f.session,next_operation_id='op-one',next_issue_number=2)

    def test_pause_before_operation_denies_without_launch(self):
        f,owner=self.make();owner._paused=True
        with patch('uas.native_session.run') as run:
            with self.assertRaisesRegex(LedgerError,'PAUSED'):
                owner.open_human('op-one',1,session=f.session)
            run.assert_not_called()

    def test_parent_pause_ack_only_after_confirmed_cleanup(self):
        _,owner=self.make();del owner.current
        output=io.BytesIO();stdout=Mock();stdout.buffer=output
        with patch('uas.local_native_run_session.alive',return_value=True), \
             patch('uas.local_native_run_session.select.select',return_value=([12],[],[])), \
             patch('uas.local_native_run_session.os.read',return_value=b'P'), \
             patch('uas.local_native_run_session.sys.stdout',stdout):
            owner._busy=True;owner._cleanup_confirmed=False;owner.current()
            self.assertEqual(output.getvalue(),b'')
            owner._busy=False;owner.current();self.assertEqual(output.getvalue(),b'')
            owner._cleanup_confirmed=True;owner.current()
            self.assertIn(b'participants-revoked',output.getvalue())

if __name__=='__main__':unittest.main()
