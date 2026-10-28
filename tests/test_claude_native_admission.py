"""Inert ownership/state tests. No process, socket or live native evidence."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uas import claude_native_admission as m
from uas.kernel_origin import HeldOrigin, Record, ReceiverIdentity, OriginDenied
from uas.workstation_exec import ExecSeat
from uas.workstation_admission import AdmissionSeat


def held(pid, identity):
    result=object.__new__(HeldOrigin)
    result.credentials=(pid,65532,65532); result.identity=identity
    result.pidfd=100; result.revoked=False; result._receiver=None
    return result


def fixture():
    host=object.__new__(m.NativeClaudeHostLaunch)
    host.seat=ExecSeat('room','instance','participant','actor','seat-a','a'*64,65532,65532)
    host.origin=held(101,(1,101)); host.state='released'; host._native_child=None
    host.incarnation='b'*32; host.exec_id='c'*64
    host.recipe=SimpleNamespace(scope={'run_id':'run','generation':1},
        session_id='session',manifest_digest='d'*64,identity={'runtime':'claude'})
    host.endpoint=SimpleNamespace(require=Mock(),path='/endpoint')
    host._save=Mock(); host.inspect_current=Mock(return_value=True)
    seat=AdmissionSeat('room','instance','participant','actor','profile',(),
        ReceiverIdentity(65532,65532,'context','e'*64))
    with patch.object(m,'alive',return_value=True):
        root=m.NativeClaudeRoot(host,seat)
    return root


class NativeClaudeAdmissionTests(unittest.TestCase):
    def test_host_cannot_become_participant(self):
        host=object.__new__(m.NativeClaudeHostLaunch)
        with self.assertRaises(OriginDenied):host.activate({})
        with self.assertRaises(OriginDenied):host.attach_native()

    def test_host_inspection_cannot_adopt_native_pid(self):
        root=fixture();host=root.host_launch
        del host.inspect_current
        host.recipe.validate_container=Mock()
        host.engine=SimpleNamespace(inspect=Mock(return_value={
            'ID':host.exec_id,'ContainerID':host.seat.container_id,'Running':True,'Pid':102}))
        with patch.object(m,'alive',return_value=True):
            with self.assertRaises(OriginDenied):host.inspect_current()
            host.engine.inspect.return_value['Pid']=101
            self.assertTrue(host.inspect_current())
        host.recipe.validate_container.assert_called_once()

    def test_exact_host_required(self):
        with self.assertRaises(OriginDenied):m.NativeClaudeRoot(SimpleNamespace(),None)

    def test_host_can_only_have_one_root(self):
        root=fixture()
        with self.assertRaises(OriginDenied):m.NativeClaudeRoot(root.host_launch,root.admission_seat)

    def test_bad_challenge_does_not_inspect_processes(self):
        root=fixture()
        with patch.object(m,'ProcView') as proc:
            with self.assertRaises(OriginDenied):root._bind_child(Record(b'UAS1'+b'x'*32,(102,65532,65532),-1),b'y'*32)
            proc.assert_not_called()

    def test_child_uses_kernel_namespace_pid_and_distinct_held_identity(self):
        root=fixture(); native=held(102,(1,102))
        host_task=SimpleNamespace(namespace=((1,2),(3,4)),status={'NSpid':(101,2)},close=Mock())
        child_task=SimpleNamespace(identity=(1,102),namespace=((1,2),(3,4)),status={'NSpid':(102,7)})
        binding=SimpleNamespace(tasks=[child_task,SimpleNamespace(identity=(1,101))],current=Mock(return_value=True))
        def bind_origin(self,record):
            self.__dict__.update(native.__dict__);record.pidfd=-1
        with patch.object(m,'alive',return_value=True), patch.object(m,'ProcView') as view, \
             patch.object(m,'_Task',return_value=host_task),patch.object(m,'GitChildAuthority') as authority, \
             patch.object(HeldOrigin,'__init__',bind_origin):
            authority.return_value.bind.return_value=binding
            root._bind_child(Record(b'UAS1'+b'x'*32,(102,65532,65532),200),b'x'*32)
        self.assertEqual(root.native_namespace_pid,7)
        self.assertEqual(root.native_namespace,((1,2),(3,4)))
        self.assertEqual(root.native_pid_depth,2)
        self.assertEqual(root.origin.identity,(1,102))
        self.assertEqual(root.host_origin.identity,(1,101))
        self.assertIsNot(root.origin,root.host_origin)
        host_task.close.assert_called_once();view.return_value.close.assert_called_once()

    def test_non_immediate_child_rejected(self):
        root=fixture()
        task=SimpleNamespace(namespace=((1,2),(3,4)),status={'NSpid':(101,2)},close=Mock())
        binding=SimpleNamespace(tasks=[SimpleNamespace(identity=(1,102)),SimpleNamespace(identity=(1,103)),SimpleNamespace(identity=(1,101))])
        with patch.object(m,'alive',return_value=True),patch.object(m,'ProcView'), \
             patch.object(m,'_Task',return_value=task),patch.object(m,'GitChildAuthority') as authority:
            authority.return_value.bind.return_value=binding
            with self.assertRaises(OriginDenied):root._bind_child(Record(b'UAS1'+b'x'*32,(102,65532,65532),200),b'x'*32)
        self.assertIsNone(root.origin)

    def test_current_checks_host_native_and_lineage(self):
        root=fixture();root.origin=held(102,(1,102));root.state='released'
        root._lineage=SimpleNamespace(tasks=[SimpleNamespace(identity=(1,102))],current=Mock(return_value=True))
        with patch.object(m,'alive',return_value=True):
            self.assertTrue(root.current())
            root.host_origin.revoked=True
            with self.assertRaises(OriginDenied):root.current()
            root.host_origin.revoked=False;root.origin.revoked=True
            with self.assertRaises(OriginDenied):root.current()
        root._lineage.current.assert_called_once()

    def test_shared_journal_serializer_keeps_host_and_child_separate(self):
        root=fixture();host=root.host_launch
        host._native_readiness=None;host.admission=None
        document=host._journal_document()
        self.assertEqual(document['incarnation'],host.incarnation)
        self.assertEqual(document['native_child']['incarnation'],root.incarnation)
        self.assertEqual(document['native_child']['host_identity'],[1,101])
        self.assertEqual(document['native_host_recipe'],{'runtime':'claude'})
        self.assertIsNone(document['native_child']['native_identity'])

    def test_shared_admit_document_uses_native_child_not_sdk_host(self):
        from uas.workstation_admission import _admission_document
        root=fixture();root.state='active';root.origin=held(102,(1,102));root.current=Mock(return_value=True)
        with patch('uas.workstation_admission.alive',return_value=True):
            document=_admission_document(root,root.admission_seat,'a'*32,1,'b'*64)
        self.assertEqual(document['kind'],'ADMIT_NATIVE_CLAUDE')
        self.assertEqual(document['origin_identity'],[1,102])
        self.assertEqual(document['native_payload_digest'],root.recipe.manifest_digest)

    def test_replaced_native_identity_is_not_current(self):
        root=fixture();root.origin=held(102,(1,102));root.state="released"
        root._lineage=SimpleNamespace(tasks=[SimpleNamespace(identity=(1,999))],current=Mock(return_value=True))
        with patch.object(m,"alive",return_value=True):
            with self.assertRaises(OriginDenied):root.current()

    def test_journal_is_metadata_not_challenge_or_reconstruction(self):
        root=fixture();root.origin=held(102,(1,102));root.native_namespace_pid=7
        doc=root.document()
        self.assertEqual(doc['host_identity'],[1,101]);self.assertEqual(doc['native_identity'],[1,102])
        self.assertNotIn('challenge',json.dumps(doc))
        self.assertIsNone(doc['native_readiness'])
        root._save();root.host_launch._save.assert_called_once()

    def test_concrete_initializer_orders_owners_and_does_not_retry(self):
        root=fixture();events=[]
        root.launch=Mock(side_effect=lambda *a,**k:events.append('native-release'))
        root.helper_lease=Mock()
        root.helper_lease.admit.side_effect=lambda *a:events.append('helper-admit')
        root._receive_helper=Mock(side_effect=lambda *a:events.append('helper-release'))
        root._receive_forge_helper=Mock(side_effect=lambda *a:events.append('forge-release'))
        root.attach_native=Mock(side_effect=lambda **k:events.append('native-proof'))
        with patch.object(m,'NativeClaudeSupervisorAdmission') as admission:
            admission.return_value.admit.side_effect=lambda *a:events.append('root-admit')
            args=dict(journal='/unused',control=None,hub_origin=None,controller='f'*32,
                control_lock=None,operation_id='a'*32,epoch=1)
            self.assertIs(root.initialize_helper(None,**args),root)
            self.assertEqual(events,['native-release','helper-release','forge-release','native-proof','root-admit','helper-admit'])
            with self.assertRaises(OriginDenied):root.initialize_helper(None,**args)
            admission.return_value.admit.assert_called_once_with('a'*32,1)

    def test_initializer_has_one_deadline(self):
        root=fixture();root.launch=Mock();root._receive_helper=Mock();root._receive_forge_helper=Mock();root._fail=Mock()
        with patch.object(m.time,'monotonic',side_effect=[0,0,9]):
            with self.assertRaises(TimeoutError):root.initialize_helper(None,journal='/unused',
                control=None,hub_origin=None,controller='f'*32,control_lock=None,
                operation_id='a'*32,epoch=1,timeout=8)
        root._receive_helper.assert_not_called();root._fail.assert_called_once()

    def test_rejected_helper_hello_closes_accepted_channel(self):
        from contextlib import nullcontext
        root=fixture();root.current=Mock(return_value=True)
        channel=Mock();listener=Mock();listener.accept.return_value=(channel,None)
        with patch.object(m,'enable'),patch.object(m,'receive',return_value=nullcontext(Record(b'bad',(102,65532,65532),-1))), \
             patch('uas.native_helper.NativeDescendantLease',side_effect=OriginDenied('bad hello')):
            with self.assertRaises(OriginDenied):root._receive_helper(listener,1)
        channel.close.assert_called_once()

    def test_initializer_unknown_transfer_preserves_owner_for_status(self):
        root=fixture();root.launch=Mock();root._receive_helper=Mock();root._receive_forge_helper=Mock();root.attach_native=Mock()
        root._fail=Mock();root.helper_lease=Mock()
        with patch.object(m,'NativeClaudeSupervisorAdmission') as admission:
            admission.return_value.admit.side_effect=TimeoutError('unknown')
            with self.assertRaises(TimeoutError):root.initialize_helper(None,journal='/unused',
                control=None,hub_origin=None,controller='f'*32,control_lock=None,
                operation_id='a'*32,epoch=1)
            root._fail.assert_not_called();root.helper_lease.admit.assert_not_called()
            self.assertIs(root.native_admission,admission.return_value)

    def test_initializer_proof_failure_never_transfers(self):
        root=fixture();root.launch=Mock();root._receive_helper=Mock();root._receive_forge_helper=Mock()
        root.attach_native=Mock(side_effect=OriginDenied('not fresh'));root._fail=Mock()
        with patch.object(m,'NativeClaudeSupervisorAdmission') as admission:
            with self.assertRaises(OriginDenied):root.initialize_helper(None,journal='/unused',
                control=None,hub_origin=None,controller='f'*32,control_lock=None,
                operation_id='a'*32,epoch=1)
            admission.assert_not_called();root._fail.assert_called_once()

    def test_failure_cleanup_does_not_replace_original_error(self):
        root=fixture()
        root.close_resources=Mock(side_effect=RuntimeError('cleanup'))
        root._fail()
        self.assertEqual(root.state,'uncertain')
        self.assertTrue(root.cleanup_incomplete)
        self.assertIsNotNone(root.host_launch)

    def test_fresh_proof_exact_child_or_fences(self):
        from uas.native_claude_runtime import NativeClaudeReceiver
        for wrong_pid in (False,True):
            with self.subTest(wrong_pid=wrong_pid):
                root=fixture();root.origin=held(102,(1,102));root.state='released';root.native_namespace_pid=7
                root.current=Mock(return_value=True);root._fail=Mock()
                receiver=object.__new__(NativeClaudeReceiver)
                receiver.scope=root.scope;receiver.incarnation_id=root.incarnation
                proof={'runtime':'Claude','runtime_version':'2.1.310','sdk_version':'0.3.310',
                    'native_pid':8 if wrong_pid else 7,'session_id':root.recipe.session_id,
                    'scope':root.scope,'source':'fresh-home-explicit-session-native-idle-no-input','readiness':'safe'}
                with patch.object(NativeClaudeReceiver,'__init__',return_value=None), \
                     patch.object(NativeClaudeReceiver,'prove_fresh_context',return_value=proof), \
                     patch.object(NativeClaudeReceiver,'scope',create=True,new=root.scope), \
                     patch.object(NativeClaudeReceiver,'incarnation_id',create=True,new=root.incarnation):
                    if wrong_pid:
                        with self.assertRaises(OriginDenied):root.attach_native(journal='/unused')
                        root._fail.assert_called_once();self.assertIsNone(root.native_readiness)
                    else:
                        root.attach_native(journal='/unused')
                        self.assertEqual(root.state,'active')
                        self.assertEqual(root.native_readiness['origin_identity'],[1,102])
                        self.assertEqual(root.native_readiness['host_origin_identity'],[1,101])
                        value=root.native_readiness;value['native']['native_pid']=999
                        self.assertEqual(root.native_readiness['native']['native_pid'],7)

if __name__=='__main__':unittest.main()
