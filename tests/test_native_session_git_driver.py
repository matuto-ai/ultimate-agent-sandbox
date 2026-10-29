"""Actual finite driver/native Git dispatch; only transport service is controlled."""
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch
from uas.ledger import LedgerError
from uas.native_git_operations import NativeGitOperations
from uas.native_run_admission import NativeHumanRunRequest
from uas.native_session_driver import NativeSessionDriver
import test_native_session_driver as fixture


class NativeSessionGitDriverTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.NativeSessionDriverTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        c=self.case.c
        self.operations=object.__new__(NativeGitOperations)
        self.operations.owner=c.admission;self.operations.reviewer=c.recruitment
        self.operations.closed=False
        self.listener=object()
        self.operations.resources=N(request_listener=self.listener)
        self.operations.service=N(serve_next=Mock(),close=Mock())
        self.driver=NativeSessionDriver(c.admission,c.recruitment,self.case.request,self.case.budget,
                                        git_operations=self.operations)

    def test_readable_git_listener_consumed_by_actual_serve_next(self):
        self.case.readable=[self.listener]
        self.operations.service.serve_next.side_effect=lambda **kwargs:self.case.close_run()
        result=self.driver.run()
        self.assertEqual(result['outcome'],'completed');self.assertEqual(result['counts']['git_requests'],1)
        self.operations.service.serve_next.assert_called_once_with(timeout=1)
        self.assertIn(self.listener,self.case.polls[0][0])
        self.case.c.pi.forge_service.receive_once.assert_not_called()
        self.case.root.forge_service.receive_once.assert_not_called()

    def test_idle_listener_does_not_complete_or_consume_unread_request(self):
        before=self.case.c.ledger.snapshot()
        result=self.driver.run()
        self.assertEqual(result['outcome'],'inconclusive');self.assertEqual(result['counts']['git_requests'],0)
        self.assertGreater(len(self.case.polls),1)
        self.assertTrue(all(self.listener in watched for watched,_ in self.case.polls))
        self.operations.service.serve_next.assert_not_called()
        self.assertEqual(self.case.c.ledger.snapshot(),before)

    def test_wrong_owner_reviewer_or_untyped_operations_rejected(self):
        c=self.case.c
        for field,value in (('owner',object()),('reviewer',object())):
            old=getattr(self.operations,field);setattr(self.operations,field,value)
            with self.assertRaisesRegex(LedgerError,'NATIVE_GIT_OWNER_REQUIRED'):
                NativeSessionDriver(c.admission,c.recruitment,self.case.request,self.case.budget,
                                    git_operations=self.operations)
            setattr(self.operations,field,old)
        with self.assertRaises(LedgerError):
            NativeSessionDriver(c.admission,c.recruitment,self.case.request,self.case.budget,
                                git_operations=N(owner=c.admission,reviewer=c.recruitment))

    def test_primary_only_successor_refuses_before_retirement_or_new_allocation(self):
        self.case.close_run();c=self.case.c
        request=NativeHumanRunRequest('next-git',2,c.participant,c.session)
        driver=NativeSessionDriver(c.admission,c.recruitment,self.case.request,self.case.budget,
                                  next_request=request,git_operations=self.operations)
        before=c.ledger.snapshot();counts=(len(c.allocations),len(c.launches))
        with patch.object(c.admission,'retire_completed',side_effect=AssertionError('must refuse before retirement')) as retire:
            result=driver.run()
        self.assertEqual(result['reason'],'NATIVE_SUCCESSOR_GIT_VIEW_UNAVAILABLE')
        self.assertEqual(result['outcome'],'attention');retire.assert_not_called()
        self.assertEqual(c.ledger.snapshot(),before);self.assertEqual(counts,(len(c.allocations),len(c.launches)))
        self.assertIs(driver.recruitment,c.recruitment);self.assertIs(driver.request,self.case.request)

    def test_unknown_git_request_is_not_replayed(self):
        self.case.readable=[self.listener]
        self.operations.service.serve_next.side_effect=TimeoutError('uncertain Git outcome')
        result=self.driver.run()
        self.assertEqual(result['outcome'],'unknown');self.assertIn('reconcile',result['reason'])
        self.operations.service.serve_next.assert_called_once_with(timeout=1)
        self.assertEqual(result['counts']['git_requests'],0)
        self.assertIs(self.operations.owner,self.case.c.admission)
