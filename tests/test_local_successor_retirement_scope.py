"""Fresh genuine Open frame scopes only its exact completed predecessor cleanup."""
from contextlib import contextmanager
import hashlib,unittest
from unittest.mock import patch
from uas import human_mtls
from uas.local_runtime_plan import LocalRuntimePlan
from uas.native_run_admission import NativeHumanRunRequest
from uas.ledger import LedgerError,Command
import test_local_manager as transport
import test_native_completed_retirement as native

class SuccessorScopeTests(unittest.TestCase):
    def setUp(self):
        self.c=native.CompletedRetirementTests();self.c.setUp();self.addCleanup(self.c.doCleanups)
        old=self.c.launcher.plan;plan=object.__new__(LocalRuntimePlan)
        plan.__dict__.update(vars(old));self.c.launcher.plan=plan
    @contextmanager
    def request(self):
        c=self.c;s=c.session
        grant=human_mtls.HumanActionGrant(s.deployment_id,s.room_id,s.instance_id,s.manager_id,s.human,
            ('open-run','authorize-run-request'))
        binding=human_mtls.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():grant})
        with patch.object(human_mtls.ssl,'SSLSocket',transport.TLS):
            channel=binding.accept(transport.TLS())
            with channel.request({'version':1,'action':'open-run','payload':{'operation_id':'next','issue_number':2}}) as (_,session):
                request=NativeHumanRunRequest('next',2,c.participant,session)
                yield request,channel.run_admission_lease(session,'next',2)
            channel.close()
    def test_completed_retirement_works_without_lending_stop_scope(self):
        c=self.c
        with self.request() as (request,grant):
            self.assertFalse(request.session.allowed('stop'))
            row=c.ledger.snapshot()['state']['runs'][c.run_id]
            result=c.admission.retire_for_successor(request,grant,c.run_id,row['generation'],
                row['control_revision'],reviewer=c.recruitment)
            self.assertEqual(result['native_stop']['status'],'VERIFIED')
            self.assertFalse(request.session.allowed('stop'))
        self.assertIsNone(c.admission._local_retirement_intent)
        self.assertIsNone(c.admission._session)
    def test_closed_scope_cannot_retire_after_http_expiry(self):
        c=self.c
        with self.request() as (request,grant):pass
        before=c.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'INTENT_REQUIRED'):
            c.admission.retire_for_successor(request,grant,c.run_id,1,0,reviewer=c.recruitment)
        self.assertEqual(c.ledger.snapshot(),before)
    def test_wrong_predecessor_and_active_run_cannot_borrow_open(self):
        c=self.c
        with self.request() as (request,grant):
            before=c.ledger.snapshot()
            with self.assertRaisesRegex(LedgerError,'PREDECESSOR_CHANGED'):
                c.admission.retire_for_successor(request,grant,'foreign',1,0,reviewer=c.recruitment)
            self.assertEqual(c.ledger.snapshot(),before)
            c.seed(lambda state:state['runs'][c.run_id].update(status='ACTIVE',outcome=None))
            with self.assertRaisesRegex(LedgerError,'PREDECESSOR_CHANGED'):
                c.admission.retire_for_successor(request,grant,c.run_id,1,0,reviewer=c.recruitment)
    def test_failure_clears_intent_and_does_not_authorize_other_stop(self):
        c=self.c
        with self.request() as (request,grant):
            with patch.object(c.admission,'retire_completed',side_effect=LedgerError('UNKNOWN')):
                row=c.ledger.snapshot()['state']['runs'][c.run_id]
                with self.assertRaisesRegex(LedgerError,'UNKNOWN'):
                    c.admission.retire_for_successor(request,grant,c.run_id,row['generation'],
                        row['control_revision'],reviewer=c.recruitment)
            self.assertIsNone(c.admission._local_retirement_intent)
            with c.admission.human_scope(request.session):
                self.assertFalse(c.admission._session_authorized(request.session.human,
                    Command('foreign','run.human-retire-completed',c.run_id,1,{'expected_revision':0})))
