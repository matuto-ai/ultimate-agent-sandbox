"""Actual Manager dispatch into typed persistent owner with inert native boundary."""
import hashlib,json,threading
from pathlib import Path
from unittest.mock import Mock,patch
import unittest
from uas import local_runtime_manager as runtime
from uas.local_runtime_plan import LocalRuntimePlan
from uas.local_native_run_session import LocalNativeRunSession
from uas.local_manager import ManagerSelection,LocalManager
from uas.local_manager_actions import LocalNativeRunActions
from uas import human_mtls as human
from uas.ledger import LedgerError
from test_local_manager import TLS,wire
from test_native_run_admission import fixture


class LocalRuntimeManagerTests(unittest.TestCase):
    def setup_owner(self):
        f=fixture(self)
        plan=object.__new__(LocalRuntimePlan);plan.config=f.plan.config;plan.room=f.plan.room
        plan.require_unchanged=Mock()
        resources={'instance':f.session.instance_id,'hub_ledger_path':str(f.ledger.writer_binding()[0]),
                   'supervisor_directory':str(f.supervisor.root.parent)}
        owner=object.__new__(LocalNativeRunSession);owner.plan=plan;owner.resources=resources
        owner.supervisor=f.supervisor;owner.participant_id=f.participant;owner._thread=threading.get_ident()
        owner.current=Mock()
        grant=human.HumanActionGrant(f.session.deployment_id,f.session.room_id,f.session.instance_id,
            'manager',f.session.human,('observe','open-run','authorize-run-request'))
        selection=ManagerSelection('localhost:8765',hashlib.sha256(b'test-client').hexdigest(),grant,(),'a'*64)
        return f,plan,resources,owner,selection
    def test_live_request_scope_typed_session_complete_result_and_cleanup(self):
        f,plan,resources,owner,selection=self.setup_owner();seen=[]
        def open_human(op,number,*,session,attempt_id):
            seen.append(session);self.assertTrue(session.allowed('open-run'))
            return {'status':'finished','run_id':'run-one','generation':1,'outcome':'attention','internal':'PRIVATE'}
        owner.open_human=Mock(side_effect=open_human)
        def serve(manager,*_):
            from uas.lifecycle import LifecycleError
            with patch.object(f.supervisor,'manager_observations',side_effect=LifecycleError('UNAVAILABLE')):
                observed=TLS(wire());manager.handle(observed)
            self.assertIn(b'200 OK',observed.output)
            html=json.loads(observed.output.split(b'\r\n\r\n',1)[1])['html']
            self.assertIn('native-open-run',html);self.assertIn('manager-data',html)
            channel=TLS(wire({'version':1,'action':'open-run','payload':{'operation_id':'open','issue_number':1}}))
            manager.handle(channel);self.assertIn(b'200 OK',channel.output)
            result=json.loads(channel.output.split(b'\r\n\r\n',1)[1])
            self.assertEqual(result,{'status':'finished','run_id':'run-one','generation':1,'outcome':'attention'})
            self.assertFalse(seen[0].allowed('open-run'))
        with patch.object(runtime.ManagerSelection,'read',return_value=selection), \
             patch.object(ManagerSelection,'tls_context',return_value=object()), \
             patch.object(runtime.socket,'socket') as socket,patch.object(LocalManager,'serve',serve), \
             patch.object(human.ssl,'SSLSocket',TLS):
            ready=Mock();runtime.serve_runtime_manager(plan,resources,owner,{},stopped=lambda:True,on_ready=ready)
            self.assertEqual(ready.call_args.args[0]['mode'],'bounded-native-run')
            socket.return_value.bind.assert_called_once_with(('127.0.0.1',8765))
            socket.return_value.close.assert_called_once();owner.open_human.assert_called_once()
    def test_scope_wrong_owner_and_invalid_finished_receipt_refused(self):
        _,plan,resources,owner,_=self.setup_owner()
        with self.assertRaisesRegex(LedgerError,'SCOPE'):
            runtime.serve_runtime_manager(plan,{**resources,'instance':'other'},owner,{},stopped=lambda:True)
        with self.assertRaisesRegex(LedgerError,'OWNER'):
            runtime.serve_runtime_manager(plan,resources,object(),{},stopped=lambda:True)
        f=fixture(self);owner.open_human=Mock(return_value={'status':'finished','run_id':'run-one','generation':1,'outcome':'invented'})
        actions=LocalNativeRunActions(owner)
        with self.assertRaisesRegex(LedgerError,'UNCONFIRMED'):
            actions.open({'operation_id':'open','issue_number':1},f.session)
    def test_selection_revalidation_requires_same_grant_and_paths(self):
        from dataclasses import replace
        _,_,_,_,selection=self.setup_owner()
        reference={'path':'/selected/manager.json','sha256':'a'*64}
        with patch.object(ManagerSelection,'read',return_value=selection) as read:
            selection.require_unchanged(reference)
            self.assertEqual(read.call_args.kwargs['instance_id'],selection.grant.instance_id)
        with patch.object(ManagerSelection,'read',return_value=replace(selection,authority='localhost:9999')):
            with self.assertRaisesRegex(LedgerError,'SELECTION_CHANGED'):selection.require_unchanged(reference)
