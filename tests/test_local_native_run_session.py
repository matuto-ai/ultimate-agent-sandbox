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
        plan.config=f.plan.config;plan.room=f.plan.room;plan.seats={'pi':{'participant':f.participant}};plan.require_unchanged=Mock()
        origin=Mock();origin.revoked=False;origin.pidfd=50
        resources={'instance':f.session.instance_id,'room_id':plan.room['id']}
        ready={'room_id':plan.room['id'],'room_instance':resources['instance']}
        with patch('uas.local_native_run_session.readonly_local_supervisor',return_value=f.supervisor), \
             patch('uas.local_native_run_session.alive',return_value=True), \
             patch('uas.local_native_run_session.select.select',return_value=([],[],[])):
            owner=LocalNativeRunSession(plan,resources,control=object(),origin=origin,ready=ready,
                metadata={},broker_fd=10,checkout_fd=11,parent_fd=12)
        owner.current=Mock();return f,owner

    def authenticated(self,f,operation='op-one',issue=1):
        from uas import human_mtls
        import hashlib
        from test_local_manager import TLS
        from contextlib import contextmanager
        @contextmanager
        def request():
            grant=human_mtls.HumanActionGrant(f.session.deployment_id,f.session.room_id,
                f.session.instance_id,f.session.manager_id,f.session.human,
                ('open-run','authorize-run-request'))
            bindings=human_mtls.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():grant})
            with patch.object(human_mtls.ssl,'SSLSocket',TLS):
                connection=bindings.accept(TLS())
                with connection.request({'version':1,'action':'open-run','payload':{
                        'operation_id':operation,'issue_number':issue}}) as (_,session):
                    yield session,connection.run_admission_lease(session,operation,issue)
                connection.close()
        return request()

    def test_admission_returns_active_and_retains_graph_without_session(self):
        f,owner=self.make();graph=Mock();graph.open.return_value={'status':'ACTIVE','run_id':'run-one','generation':1}
        with patch('uas.local_native_graph.LocalNativeGraph',return_value=graph) as factory:
            with self.authenticated(f) as (session,grant):
                result=owner.open_human('op-one',1,session=session,grant=grant)
                self.assertEqual(result,{'status':'ACTIVE','run_id':'run-one','generation':1})
                self.assertIs(graph.open.call_args.args[0].session,session)
            self.assertFalse(session.allowed('open-run'))
            graph.closed=False;owner.step();graph.step.assert_called_once()
            with self.authenticated(f) as (fresh,lease):
                self.assertEqual(owner.open_human('op-one',1,session=fresh,grant=lease),result)
            factory.assert_called_once_with(owner);graph.open.assert_called_once()
            graph.close.assert_not_called()
        self.assertNotIn('session',owner._attempts['op-one'])

    def test_unknown_operation_never_retries_or_claims_cleanup(self):
        f,owner=self.make();graph=Mock();graph.open.side_effect=OSError('uncertain');graph.close.side_effect=OSError('unknown')
        with patch('uas.local_native_graph.LocalNativeGraph',return_value=graph):
            with self.authenticated(f) as (session,grant):
                with self.assertRaises(OSError):owner.open_human('op-one',1,session=session,grant=grant)
            self.assertFalse(owner._cleanup_confirmed)
            with self.authenticated(f) as (session,grant):
                with self.assertRaisesRegex(LedgerError,'OUTCOME_UNKNOWN'):
                    owner.open_human('op-one',1,session=session,grant=grant)
            with self.authenticated(f,'different-operation',2) as (session,grant):
                with self.assertRaisesRegex(LedgerError,'CLEANUP_UNKNOWN'):
                    owner.open_human('different-operation',2,session=session,grant=grant)
            graph.open.assert_called_once()

    def test_new_operation_cannot_interrupt_active_graph(self):
        f,owner=self.make();owner._graph=graph=Mock()
        graph.preflight.side_effect=LedgerError('LOCAL_PREVIOUS_RUN_NOT_COMPLETED')
        with self.authenticated(f) as (session,grant):
            with self.assertRaisesRegex(LedgerError,'PREVIOUS_RUN_NOT_COMPLETED'):
                owner.open_human('op-one',1,session=session,grant=grant)
        graph.close.assert_not_called();graph.open.assert_not_called()
        self.assertNotIn('op-one',owner._attempts)

    def test_preselected_successor_denied_without_launch(self):
        f,owner=self.make()
        with self.authenticated(f) as (session,grant):
            with self.assertRaisesRegex(LedgerError,'EXPLICIT_SEPARATE_RUN_REQUIRED'):
                owner.open_human('op-one',1,session=session,grant=grant,
                                next_operation_id='op-two',next_issue_number=2)
        self.assertIsNone(owner._graph)

    def test_admission_requires_lease_and_live_human_request(self):
        f,owner=self.make()
        with self.assertRaisesRegex(LedgerError,'GRANT_REQUIRED'):
            owner.open_human('op-one',1,session=f.session)
        with self.authenticated(f) as (session,grant):pass
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
            owner.open_human('op-one',1,session=session,grant=grant)

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

    def test_successor_pause_receipt_requires_exact_retirement_and_preserves_graph(self):
        _,owner=self.make();del owner.current
        owner._busy=True;owner._cleanup_confirmed=False
        owner._graph=graph=Mock();graph.transition_retirement=object()
        output=io.BytesIO();stdout=Mock();stdout.buffer=output
        with patch('uas.local_native_run_session.alive',return_value=True), \
             patch('uas.local_native_run_session.select.select',return_value=([12],[],[])), \
             patch('uas.local_native_run_session.os.read',side_effect=[b'P',b'R']), \
             patch('uas.local_native_run_session.sys.stdout',stdout):
            owner.current()
            self.assertTrue(owner._paused);self.assertTrue(owner._transition_paused)
            graph.require_retired.assert_called_once();graph.close.assert_not_called()
            self.assertIn(b'participants-revoked',output.getvalue())
            owner.current()
            self.assertFalse(owner._paused);self.assertFalse(owner._transition_paused)
            self.assertIn(b'runtime-resumed',output.getvalue())
        self.assertIs(owner._graph,graph)

    def test_successor_unverified_retirement_never_acknowledges_pause(self):
        _,owner=self.make();del owner.current
        owner._busy=True;owner._graph=graph=Mock();graph.transition_retirement=object()
        graph.require_retired.side_effect=LedgerError('NATIVE_RETIREMENT_UNVERIFIED')
        output=io.BytesIO();stdout=Mock();stdout.buffer=output
        with patch('uas.local_native_run_session.alive',return_value=True), \
             patch('uas.local_native_run_session.select.select',return_value=([12],[],[])), \
             patch('uas.local_native_run_session.os.read',return_value=b'P'), \
             patch('uas.local_native_run_session.sys.stdout',stdout):
            with self.assertRaisesRegex(LedgerError,'UNVERIFIED'):owner.current()
        self.assertEqual(output.getvalue(),b'');self.assertFalse(owner._cleanup_confirmed)
        graph.close.assert_not_called()

    def test_real_graph_uncertain_close_stays_unknown_on_parent_pause(self):
        from contextlib import ExitStack
        from uas.local_native_graph import LocalNativeGraph
        _,owner=self.make();del owner.current
        graph=object.__new__(LocalNativeGraph);graph.closed=False
        graph.transition_retirement=None;graph.stack=ExitStack()
        revoked=Mock();revoked.revoke.side_effect=OSError('uncertain native revocation')
        graph.admissions=[revoked];released=Mock();graph.stack.callback(released)
        owner._graph=graph
        with self.assertRaisesRegex(Exception,'ADMISSION_REVOCATION_UNKNOWN'):
            owner.close()
        self.assertFalse(owner._cleanup_confirmed);released.assert_called_once()
        output=io.BytesIO();stdout=Mock();stdout.buffer=output
        with patch('uas.local_native_run_session.alive',return_value=True), \
             patch('uas.local_native_run_session.select.select',return_value=([12],[],[])), \
             patch('uas.local_native_run_session.os.read',return_value=b'P'), \
             patch('uas.local_native_run_session.sys.stdout',stdout):
            with self.assertRaisesRegex(LedgerError,'CLEANUP_UNKNOWN'):owner.current()
        self.assertFalse(owner._cleanup_confirmed);self.assertEqual(output.getvalue(),b'')
        revoked.revoke.assert_called_once();released.assert_called_once()
        with self.assertRaisesRegex(LedgerError,'CLEANUP_UNKNOWN'):graph.close()

    def test_stopped_service_and_unknown_cleanup_are_not_reported_as_active_work(self):
        from uas.local_manager_actions import LocalNativeRunActions
        f,owner=self.make();graph=Mock();graph.closed=True;graph._cleanup_unknown=False
        graph.activity.status.return_value={'run_id':'run-one','generation':1,'status':'ACTIVE'}
        owner._graph=graph
        # A fresh observe session may see stopped runtime without borrowing
        # the old admission grant or changing the canonical Run status.
        from dataclasses import replace
        human=replace(f.session,authorized=lambda _,action:action=='observe')
        result=LocalNativeRunActions(owner).status(human)
        self.assertEqual(result['service'],'stopped');self.assertEqual(result['status'],'ACTIVE')
        graph._cleanup_unknown=True
        self.assertEqual(LocalNativeRunActions(owner).status(human)['service'],'cleanup-unknown')

if __name__=='__main__':unittest.main()
