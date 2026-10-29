"""Native admission dispatch with real request scopes, inert native boundaries."""
import unittest
from unittest.mock import patch
from uas.local_manager_actions import LocalNativeRunActions
from uas.ledger import LedgerError
from uas.manager_actions import HumanSession
from test_native_run_admission import fixture


class LocalManagerActionsTests(unittest.TestCase):
    def test_exact_native_owner_fixed_participant_and_original_session(self):
        f=fixture(self);actions=LocalNativeRunActions(f.owner)
        receipt={'status':'ACTIVE','run_id':'run-one','generation':1,'private_path':'DO_NOT_RETURN'}
        with patch.object(f.owner,'open_human',return_value=receipt) as open_run:
            result=actions.open({'operation_id':'open','issue_number':1},f.session)
            open_run.assert_called_once_with('open',1,f.participant,session=f.session,attempt_id=None)
            self.assertEqual(result,{'status':'ACTIVE','run_id':'run-one','generation':1})
        self.assertFalse(hasattr(actions,'session'))
    def test_real_canonical_prepare_under_exact_request_session(self):
        f=fixture(self);actions=LocalNativeRunActions(f.owner)
        # Only post-reservation native activation is doubled. The real owner
        # enters human_scope and reserves via canonical ledger reducers.
        def open_run(operation,issue,participant,*,session,attempt_id):
            with f.owner.human_scope(session):
                run,_=f.owner._prepare(operation,issue,participant,session.human)
            return {'status':'ACTIVE','run_id':run,'generation':1}
        with patch.object(f.owner,'open_human',side_effect=open_run):
            actions.open({'operation_id':'open','issue_number':1},f.session)
        rows=f.ledger.snapshot()['state']['run_admissions']
        self.assertEqual(len(rows),1);self.assertEqual(next(iter(rows.values()))['status'],'PREPARING')
        self.assertIsNone(f.owner._session);f.checkout.allocate.assert_not_called()
    def test_untrusted_fields_missing_grants_and_thread_refused_before_effect(self):
        f=fixture(self);actions=LocalNativeRunActions(f.owner)
        with patch.object(f.owner,'open_human') as open_run:
            for payload in ({'operation_id':'open','issue_number':True},
                            {'operation_id':'open','issue_number':0},
                            {'operation_id':'open','issue_number':1,'participant_id':'other'},
                            {'operation_id':'open','issue_number':1,'session':{}},
                            {'operation_id':'open','issue_number':1,'attempt_id':12}):
                with self.assertRaises((LedgerError,ValueError,TypeError)):actions.open(payload,f.session)
            revoked=HumanSession(f.session.deployment_id,f.session.room_id,f.session.instance_id,'manager',
                f.session.human,lambda _,action:action=='open-run',lambda:True)
            with self.assertRaisesRegex(LedgerError,'DENIED'):
                actions.open({'operation_id':'open','issue_number':1},revoked)
            with patch('uas.local_manager_actions.threading.get_ident',return_value=-1):
                with self.assertRaisesRegex(LedgerError,'THREAD'):actions.open({},f.session)
            open_run.assert_not_called()
    def test_unknown_outcome_never_retries_and_unconfirmed_receipt_refused(self):
        f=fixture(self);actions=LocalNativeRunActions(f.owner)
        with patch.object(f.owner,'open_human',side_effect=OSError('uncertain')) as open_run:
            with self.assertRaises(OSError):actions.open({'operation_id':'open','issue_number':1},f.session)
            open_run.assert_called_once()
        with patch.object(f.owner,'open_human',return_value={'status':'QUEUED'}):
            with self.assertRaisesRegex(LedgerError,'UNCONFIRMED'):
                actions.open({'operation_id':'open','issue_number':1},f.session)
        with self.assertRaisesRegex(LedgerError,'EXACT_NATIVE'):LocalNativeRunActions(object())
    def test_http_authentication_to_exact_owner_and_expired_session(self):
        import hashlib,json
        from uas import human_mtls as human
        from uas.local_manager import LocalManager,OPEN_CLIENT
        from test_local_manager import TLS,wire
        f=fixture(self);actions=LocalNativeRunActions(f.owner)
        grant=human.HumanActionGrant(f.session.deployment_id,f.session.room_id,f.session.instance_id,
            'manager',f.session.human,('observe','open-run','authorize-run-request'))
        bindings=human.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():grant})
        manager=LocalManager(bindings,lambda _:None,authority='localhost:8765',run_actions=actions)
        seen=[]
        def open_run(op,number,participant,*,session,attempt_id):
            seen.append(session);self.assertTrue(session.allowed('open-run'))
            self.assertEqual(participant,f.participant)
            return {'status':'ACTIVE','run_id':'run-one','generation':1}
        with patch.object(human.ssl,'SSLSocket',TLS),patch.object(f.owner,'open_human',side_effect=open_run) as opened:
            channel=TLS(wire({'version':1,'action':'open-run','payload':{'operation_id':'open','issue_number':1}}))
            manager.handle(channel);self.assertIn(b'200 OK',channel.output);opened.assert_called_once()
            self.assertFalse(seen[0].allowed('open-run'))
            denied=TLS(wire({'version':1,'action':'authorize-run-request','payload':{}}))
            manager.handle(denied);self.assertIn(b'403',denied.output);self.assertEqual(opened.call_count,1)
        self.assertIn('crypto.randomUUID()',OPEN_CLIENT);self.assertIn('No automatic retry',OPEN_CLIENT)
    def test_http_unknown_action_effect_is_not_retried_or_reported_rejected(self):
        import hashlib
        from uas import human_mtls as human
        from uas.local_manager import LocalManager
        from test_local_manager import TLS,wire
        f=fixture(self);actions=LocalNativeRunActions(f.owner)
        grant=human.HumanActionGrant(f.session.deployment_id,f.session.room_id,f.session.instance_id,
            'manager',f.session.human,('observe','open-run','authorize-run-request'))
        bindings=human.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():grant})
        manager=LocalManager(bindings,lambda _:None,authority='localhost:8765',run_actions=actions)
        with patch.object(human.ssl,'SSLSocket',TLS),patch.object(f.owner,'open_human',side_effect=OSError('PRIVATE')) as opened:
            channel=TLS(wire({'version':1,'action':'open-run','payload':{'operation_id':'open','issue_number':1}}))
            manager.handle(channel);opened.assert_called_once()
            self.assertIn(b'503',channel.output);self.assertIn(b'unknown',channel.output);self.assertNotIn(b'PRIVATE',channel.output)
    def test_observe_form_is_hint_and_only_present_for_existing_open_grant(self):
        import hashlib,tempfile,json
        from pathlib import Path
        from uas import human_mtls as human
        from uas.local_manager import LocalManager
        from uas.manager_stream import ManagerReadModel,RoomIdentity
        from uas.manager_ui import FieldNotesDocument,ProjectBinding
        from test_local_manager import TLS,wire
        f=fixture(self);actions=LocalNativeRunActions(f.owner)
        with tempfile.TemporaryDirectory() as root:
            model=ManagerReadModel(Path(root)/'manager.db');self.addCleanup(model.close)
            identity=RoomIdentity(f.session.deployment_id,f.session.room_id,f.session.instance_id)
            doc=FieldNotesDocument(model,(ProjectBinding(identity,'project','owner/repo'),))
            for enabled in (False,True):
                grants=('observe','open-run','authorize-run-request') if enabled else ('observe',)
                grant=human.HumanActionGrant(f.session.deployment_id,f.session.room_id,f.session.instance_id,
                    'manager',f.session.human,grants)
                bindings=human.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():grant})
                manager=LocalManager(bindings,lambda _:doc,authority='localhost:8765',run_actions=actions)
                with patch.object(human.ssl,'SSLSocket',TLS),patch.object(f.owner,'open_human') as opened:
                    channel=TLS(wire());manager.handle(channel)
                    self.assertIn(b'200 OK',channel.output)
                    html=json.loads(channel.output.split(b'\r\n\r\n',1)[1])['html']
                    self.assertEqual('native-open-run' in html,enabled);opened.assert_not_called()
            model.close()
    def test_current_descriptor_guard_refuses_before_native_dispatch(self):
        import hashlib
        from uas import human_mtls as human
        from uas.local_manager import LocalManager
        from test_local_manager import TLS,wire
        f=fixture(self);actions=LocalNativeRunActions(f.owner)
        grant=human.HumanActionGrant(f.session.deployment_id,f.session.room_id,f.session.instance_id,
            'manager',f.session.human,('observe','open-run','authorize-run-request'))
        bindings=human.HumanActionBindings({hashlib.sha256(b'test-client').hexdigest():grant})
        def changed():raise LedgerError('SELECTED_DESCRIPTOR_CHANGED')
        manager=LocalManager(bindings,lambda _:None,authority='localhost:8765',run_actions=actions,current=changed)
        with patch.object(human.ssl,'SSLSocket',TLS),patch.object(f.owner,'open_human') as opened:
            channel=TLS(wire({'version':1,'action':'open-run','payload':{'operation_id':'open','issue_number':1}}))
            manager.handle(channel);self.assertIn(b'403',channel.output);opened.assert_not_called()
