"""Controlled root transition checks: no process, Docker, socket or host effects."""
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import hashlib
import threading
import unittest
from unittest.mock import Mock, patch
from uas import local_successor_checkout as local
from uas.local_services import LocalServices
from uas.local_host import LocalController
from uas.lifecycle import LifecycleError
from uas.native_checkout_handoff import reservation, request_value, NativeCheckoutClient
import test_native_checkout_successor as predecessor


class LocalSuccessorCheckoutTests(unittest.TestCase):
    def test_general_context_generation_is_local_only_and_exactly_successive(self):
        request, room, actors, state, _ = predecessor.fixture()
        state['run_admissions']['previous-run']={'participant_id':'pi','actor_id':'developer','context_generation':2}
        state['run_admissions'][request['run_id']]['context_generation']=3
        context=state['fixture_context']['participants']['pi'];context['context_generation']=2
        context['reset'].update(expected_context_generation=2,next_context_generation=3)
        reservation(state,request,room,actors,initial=True,local_reuse=True)
        with self.assertRaises(LifecycleError):reservation(state,request,room,actors,initial=True)
        state['run_admissions']['previous-run']['context_generation']=1
        with self.assertRaises(LifecycleError):reservation(state,request,room,actors,initial=True,local_reuse=True)

    def fixture(self):
        request,room,actors,ledger,slot=predecessor.fixture();request['kind']='REUSE_PRIMARY'
        run=request['run_id'];slot={**slot,'path':'/project/repo'}
        pinned=ledger['run_admissions'][run]
        state={'phase':'running','instance_id':'instance','spec':{'config_digest':'sha256:digest'}}
        owner=SimpleNamespace(_locked=lambda **k:nullcontext(),_read=lambda:state)
        owner.backend=SimpleNamespace(admit=lambda s:{'Id':'container','State':{'Running':s['phase']=='running'}})
        calls=[]
        def stop(): calls.append('stop');state['phase']='stopped';row['runtime_phase']='paused'
        def start(spec):calls.append('start');state['phase']='running'
        owner.stop=Mock(side_effect=stop);owner.start=Mock(side_effect=start)
        primary={'run':'previous-run','participant':'pi','active':True,'phase':'ready'}
        slots={'slots':{'primary':primary}}
        allocator=SimpleNamespace(repo=Path('/project/repo'),_locked=lambda action:nullcontext(slots),
          _quiescent=Mock(return_value=True),_observe=Mock(return_value={'disposition':'clean'}))
        def release(*a,authorize):
            authorize();calls.append('release');return {'disposition':'clean','active':False}
        def reserve(*a,authorize):authorize();calls.append('reserve');return slot
        allocator.release=Mock(side_effect=release);allocator.reserve=Mock(side_effect=reserve)
        services=object.__new__(LocalServices);services.operation_lock=threading.RLock()
        resources=SimpleNamespace(services=services,backend=SimpleNamespace(profile=SimpleNamespace(spec=lambda:'spec')),state=state)
        child=object();row={'runtime_owner':resources,'process':child,'instance':'instance','runtime_phase':'active'}
        services._rooms={'alpha':row}
        def ensure(*args):calls.append('resume');row['runtime_phase']='active'
        services.ensure=Mock(side_effect=ensure)
        handoff=SimpleNamespace(local_resources=resources,attempted=set(),owner=owner,child=child,
            allocator=allocator,deadline=9999999999,pins={},pin=(run,'pi',pinned),
            plan=SimpleNamespace(room={'id':'alpha'}))
        return handoff,request,calls,primary,row

    def test_stop_clean_release_reserve_start_then_resume_in_order(self):
        handoff,request,calls,_,_=self.fixture()
        with patch.object(local,'authorize_local',return_value=True):
            slot=local.reuse_primary(handoff,request)
            self.assertEqual(slot['run'],request['run_id'])
            self.assertEqual(calls,['stop','release','reserve','start','resume'])
            with self.assertRaisesRegex(LifecycleError,'RECONCILE_ONLY'):local.reuse_primary(handoff,request)
        self.assertEqual(handoff.reused_primary,request['run_id'])

    def test_dirty_or_unquiescent_preserved_without_release_start_or_retry(self):
        for dirty in (False,True):
            handoff,request,calls,primary,_=self.fixture();before=deepcopy(primary)
            if dirty:handoff.allocator._observe.return_value={'disposition':'retained'}
            else:handoff.allocator._quiescent.return_value=False
            with patch.object(local,'authorize_local',return_value=True):
                with self.assertRaises(LifecycleError):local.reuse_primary(handoff,request)
                with self.assertRaisesRegex(LifecycleError,'RECONCILE_ONLY'):local.reuse_primary(handoff,request)
            self.assertEqual(calls,['stop']);self.assertEqual(primary,before)
            handoff.allocator.release.assert_not_called();handoff.owner.start.assert_not_called()

    def test_stop_failure_cannot_release_or_start(self):
        handoff,request,calls,_,_=self.fixture();handoff.owner.stop.side_effect=LifecycleError('UNKNOWN')
        with patch.object(local,'authorize_local',return_value=True):
            with self.assertRaisesRegex(LifecycleError,'UNKNOWN'):local.reuse_primary(handoff,request)
        handoff.allocator.release.assert_not_called();handoff.owner.start.assert_not_called()
        self.assertIn(request['run_id'],handoff.attempted)

    def test_foreign_service_owner_rejected_before_effect(self):
        handoff,request,calls,_,row=self.fixture();row['process']=object()
        with patch.object(local,'authorize_local',return_value=True):
            with self.assertRaisesRegex(LifecycleError,'OWNER_CHANGED'):local.reuse_primary(handoff,request)
        self.assertEqual(calls,[]);self.assertEqual(handoff.attempted,set())

    def test_local_only_packet_exact_fields_and_operation_identity(self):
        _,request,_,_,_=self.fixture();self.assertEqual(local.local_request(request),request)
        with self.assertRaises(LifecycleError):request_value(request)
        for changed in ({**request,'path':'/etc'},{**request,'operation_id':'different'}):
            with self.assertRaises(LifecycleError):local.local_request(changed)

    def test_controller_internal_checkout_actions_are_root_and_room_bound(self):
        owner=object.__new__(LocalController);owner.rooms={'alpha'}
        with patch('uas.local_host.os.geteuid',return_value=0):
            self.assertTrue(owner.authorize('checkout.reserve','alpha','instance'))
            self.assertFalse(owner.authorize('checkout.reserve','foreign','instance'))
            self.assertFalse(owner.authorize('checkout.reconcile','alpha','instance'))
        with patch('uas.local_host.os.geteuid',return_value=1000):
            self.assertFalse(owner.authorize('checkout.reserve','alpha','instance'))

    def test_wait_services_parent_control_with_bounded_poll(self):
        client=object.__new__(local.LocalNativeCheckoutClient);client.deadline=100
        client.current=Mock();client.channel=Mock();client.channel.recvmsg.return_value=(b'{}',[],0,None)
        with patch.object(local,'remaining',return_value=3),patch.object(local.select,'select',side_effect=[([],[],[]),([client.channel],[],[])]) as poll:
            self.assertEqual(client._receive()[0],b'{}')
        self.assertEqual(client.current.call_count,2)
        self.assertTrue(all(c.args[3]==.05 for c in poll.call_args_list))

    def test_transition_uses_real_canonical_reservation_at_each_phase(self):
        handoff,request,calls,_,_=self.fixture()
        original,room,actors,state,_=predecessor.fixture()
        state['run_admissions']['previous-run']={'participant_id':'pi','actor_id':'developer','context_generation':1}
        room['id']='alpha'
        handoff._held=Mock();handoff._snapshot=lambda:state
        handoff.actors=actors;handoff.plan=SimpleNamespace(room=room,config_digest='digest',require_unchanged=Mock())
        handoff.resources=SimpleNamespace(data={'instance':'instance'})
        result=local.reuse_primary(handoff,request)
        self.assertEqual(result['run'],request['run_id'])
        self.assertEqual(calls,['stop','release','reserve','start','resume'])
        self.assertGreaterEqual(handoff._held.call_count,6)

    def test_after_reuse_rebuild_runs_only_after_confirmed_reply_and_fences_failure(self):
        _,_,_,_,slot=predecessor.fixture()
        client=object.__new__(local.LocalNativeCheckoutClient);client.close=Mock()
        client._call=Mock(return_value=slot);client.after_reuse=Mock(side_effect=LifecycleError('REBUILD_UNKNOWN'))
        with self.assertRaisesRegex(LifecycleError,'REBUILD_UNKNOWN'):
            client.reuse_primary(slot['run'],'operation')
        client.close.assert_called_once();client.after_reuse.assert_called_once()
        client.after_reuse.reset_mock();client._call.side_effect=LifecycleError('ROOT_UNKNOWN')
        with self.assertRaisesRegex(LifecycleError,'ROOT_UNKNOWN'):
            client.reuse_primary(slot['run'],'operation')
        client.after_reuse.assert_not_called()

    def test_client_preserves_supplied_deadline_instead_of_renewing_request(self):
        self.assertIs(local.LocalNativeCheckoutClient._call,NativeCheckoutClient._call)
