"""Controlled first-reuse tests; no native execution or permission effects."""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import test_native_checkout_handoff as base
from uas.native_checkout_handoff import reservation, RootCheckoutHandoff
from uas.checkouts import CheckoutAllocator
from uas.lifecycle import LifecycleError


def fixture():
    request, room, actors, state, slot = base.fixture()
    old = 'previous-run'
    predecessor = {'run_id': old, 'generation': 2}
    row = state['run_admissions'][request['run_id']]
    row.update(context_generation=2, preceding_run=predecessor)
    state['runs'] = {old: {'status': 'CLOSED', 'participant_id': 'pi', 'actor_id': 'developer',
        'generation': 2, 'native_stop': {'status': 'VERIFIED', 'generation': 2, 'operation_id': 'stop'}}}
    context = state['fixture_context']['participants']['pi']
    context.update(status='RESETTING', bound_run=predecessor, reserved_run=None,
        reset={'id': 'native-pi-reset-'+hashlib.sha256(request['operation_id'].encode()).hexdigest(),
            'participant_id': 'pi', 'expected_context_generation': 1, 'next_context_generation': 2,
            'preceding_run': predecessor, 'target_run': {'run_id': request['run_id'], 'generation': 1},
            'reason_code': None, 'status': 'REQUESTED'})
    state['fixture_context']['runs'][old] = {'generation': 2, 'status': 'CLOSED', 'terminal_fact': 'CANCELLED'}
    return request, room, actors, state, slot


class SuccessorTests(unittest.TestCase):
    def test_requested_then_succeeded_pin_stable_and_allocate_denied_after_success(self):
        request, room, actors, state, _ = fixture()
        before = reservation(state, request, room, actors, initial=True)
        self.assertEqual(reservation(state, request, room, actors, initial=False), before)
        context = state['fixture_context']['participants']['pi']
        context.update(status='READY', context_generation=2, bound_run=None,
                       reserved_run=context['reset']['target_run'])
        context['reset']['status'] = 'SUCCEEDED'
        self.assertEqual(reservation(state, request, room, actors, initial=False), before)
        context['bound_run'], context['reserved_run'] = context['reserved_run'], None
        self.assertEqual(reservation(state, request, room, actors, initial=False), before)
        with self.assertRaises(LifecycleError): reservation(state, request, room, actors, initial=True)

    def test_changed_reset_or_predecessor_denied(self):
        request, room, actors, state, _ = fixture()
        changes = [
            ('reset', 'id', 'different'), ('reset', 'participant_id', 'other'),
            ('reset', 'status', 'FAILED'), ('reset', 'target_run', {'run_id':'other','generation':1}),
            ('reset', 'preceding_run', {'run_id':'other','generation':2}),
            ('reset', 'next_context_generation', 3), ('reset','reason_code','failure'),
            ('context','status','READY'), ('context','context_generation',2),
            ('old','status','ACTIVE'), ('old','participant_id','other'), ('old','actor_id','other'),
            ('old','native_stop',{'status':'UNKNOWN','generation':2}),
            ('old','native_stop',{'status':'VERIFIED','generation':1}),
            ('old_context','status','OPEN'), ('old_context','generation',1),
            ('admission','context_generation',3)]
        for target, key, value in changes:
            with self.subTest(target=target, key=key, value=value):
                current=deepcopy(state);context=current['fixture_context']['participants']['pi']
                obj={'reset':context['reset'],'context':context,'old':current['runs']['previous-run'],
                     'old_context':current['fixture_context']['runs']['previous-run'],
                     'admission':current['run_admissions'][request['run_id']]}[target]
                obj[key]=value
                with self.assertRaises(LifecycleError):reservation(current,request,room,actors,initial=False)

    def test_retained_slot_guard_runs_inside_lock_before_reconcile_or_effects(self):
        predecessor={'run':'old','participant':'pi','active':True,'phase':'ready'}
        successor={'run':'new','participant':'pi','active':True,'phase':'creating'}
        for change in ({'active':False},{'phase':'removing'},{'participant':'other'},None):
            owner=CheckoutAllocator.__new__(CheckoutAllocator)
            slots={'new':deepcopy(successor)}
            if change is not None:slots['old']={**predecessor,**change}
            owner._locked=Mock(return_value=nullcontext({'slots':slots}))
            owner._recover_creation=Mock();owner._observe=Mock();owner._save=Mock();owner._git=Mock()
            with self.assertRaises(LifecycleError):
                owner.allocate('new','pi',retained_predecessor=('old','pi'))
            owner._locked.assert_called_once_with('allocate')
            for effect in (owner._recover_creation,owner._observe,owner._save,owner._git):effect.assert_not_called()

    def test_retained_dirty_slot_not_observed_or_changed_on_successor_reconcile(self):
        old={'run':'old','participant':'pi','active':True,'phase':'ready','dirty':True}
        new={'run':'new','participant':'pi','active':True,'phase':'creating'}
        state={'slots':{'old':old,'new':new}};before=deepcopy(old)
        owner=CheckoutAllocator.__new__(CheckoutAllocator);owner.writer_guard=None
        owner._locked=lambda action:nullcontext(state)
        owner._recover_creation=Mock();owner._observe=Mock(return_value={'reason':'ACTIVE'})
        owner._remaining=Mock()
        owner.allocate('new','pi',retained_predecessor=('old','pi'))
        owner._recover_creation.assert_called_once_with(state,'new')
        owner._observe.assert_called_once_with(state,'new');self.assertEqual(old,before)

    def test_exact_predecessor_identity_required(self):
        state={'slots':{'old':{'run':'old','participant':'pi','active':True,'phase':'ready'}}}
        for preceding in (('new','pi'),('old','other'),['old','pi'],('absent','pi')):
            with self.assertRaises(LifecycleError):CheckoutAllocator._retained_predecessor(state,'new','pi',preceding)
        CheckoutAllocator._retained_predecessor(state,'new','pi',('old','pi'))

    def test_root_passes_derived_guard_and_observe_never_allocates(self):
        request,_,_,state,slot=fixture();row=state['run_admissions'][request['run_id']]
        owner=RootCheckoutHandoff.__new__(RootCheckoutHandoff)
        owner.deadline=100;owner.pin=(request['run_id'],'pi',row);owner.attempted=set()
        owner.owner=SimpleNamespace(_locked=lambda **k:nullcontext());owner._authorized=Mock(return_value=True)
        old={'run':'previous-run','participant':'pi','active':True,'phase':'ready'}
        owner.allocator=SimpleNamespace(allocate=Mock(return_value=slot),
            _locked=lambda action:nullcontext({'slots':{'old':old,'new':slot}}),
            _observe=Mock(return_value=slot),_retained_predecessor=CheckoutAllocator._retained_predecessor)
        with patch('uas.native_checkout_handoff.time.monotonic',return_value=1):
            self.assertEqual(owner.operation(request),slot)
            self.assertEqual(owner.allocator.allocate.call_args.kwargs['retained_predecessor'],('previous-run','pi'))
            owner.operation({**request,'kind':'OBSERVE'})
            old['active']=False
            with self.assertRaises(LifecycleError):owner.operation({**request,'kind':'OBSERVE'})
            with self.assertRaises(LifecycleError):owner.operation(request)
        self.assertEqual(owner.allocator.allocate.call_count,1)

    def test_bounded_root_pins_preserve_origin_and_stop_evidence(self):
        request,room,actors,state,_=fixture()
        owner=RootCheckoutHandoff.__new__(RootCheckoutHandoff);owner.pin=None;owner.pins={}
        owner._held=lambda:None;owner.actors=actors
        owner.plan=SimpleNamespace(room=room,config_digest='digest')
        owner.resources=SimpleNamespace(data={'instance':'instance'})
        owner.owner=SimpleNamespace(_read=lambda:{'phase':'running','instance_id':'instance',
            'spec':{'config_digest':'sha256:digest'}})
        owner._snapshot=lambda:state
        owner._authorized(request,initial=True)
        state['runs']['previous-run']['native_stop']['operation_id']='different'
        with self.assertRaises(LifecycleError):owner._authorized(request,initial=True)
        owner.pins={'one':(), 'two':()}
        with self.assertRaises(LifecycleError) as error:owner._authorized(request,initial=True)
        self.assertEqual(error.exception.code,'CHECKOUT_RUN_LIMIT')

    def test_new_allocation_forces_unique_worktree_without_touching_retained_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            old={'run':'old','participant':'pi','active':True,'phase':'ready','dirty':True}
            state={'slots':{'primary':deepcopy(old)}}
            owner=CheckoutAllocator.__new__(CheckoutAllocator);owner.writer_guard=None
            owner.repo=Path(directory)/'repo';owner.root=Path(directory)/'slots'
            owner._locked=lambda action:nullcontext(state)
            owner._quiescent=Mock(side_effect=AssertionError('must not reuse primary'))
            owner._git=Mock(return_value='a'*40);owner._save=Mock();owner._remaining=Mock()
            owner._recover_creation=Mock()
            owner._observe=lambda state,key:{**state['slots'][key],'reason':'ACTIVE'}
            with patch('uas.checkouts.uuid.uuid4',return_value=SimpleNamespace(hex='b'*32)):
                slot=owner.allocate('new','pi',retained_predecessor=('old','pi'))
            self.assertEqual(slot['path'],str(owner.root/('b'*32)))
            self.assertEqual(slot['branch'],'refs/heads/uas-slot/'+'b'*32)
            self.assertEqual(state['slots']['primary'],old)
            owner._quiescent.assert_not_called()
            owner._git.assert_called_once_with(owner.repo,'rev-parse','HEAD')
            owner._recover_creation.assert_called_once_with(state,'b'*32)

    def test_same_host_initial_then_successor_has_distinct_stable_pins(self):
        first,room,actors,state,_=base.fixture()
        owner=RootCheckoutHandoff.__new__(RootCheckoutHandoff);owner.pin=None;owner.pins={}
        owner._held=lambda:None;owner.actors=actors
        owner.plan=SimpleNamespace(room=room,config_digest='digest')
        owner.resources=SimpleNamespace(data={'instance':'instance'})
        owner.owner=SimpleNamespace(_read=lambda:{'phase':'running','instance_id':'instance',
            'spec':{'config_digest':'sha256:digest'}})
        owner._snapshot=lambda:state
        owner._authorized(first,initial=True);first_pin=deepcopy(owner.pin)
        second,_,_,next_state,_=fixture()
        operation='second-open';new='run-'+hashlib.sha256(operation.encode()).hexdigest()
        pending=next_state['run_admissions'].pop(second['run_id'])
        pending['admission_operation']=operation
        pending['preceding_run']['run_id']=first['run_id']
        next_state['run_admissions'][new]=pending
        next_state['runs'][first['run_id']]=next_state['runs'].pop('previous-run')
        domain=next_state['fixture_context']
        domain['runs'][first['run_id']]=domain['runs'].pop('previous-run')
        domain['runs'][new]={'generation':1,'status':'OPEN','terminal_fact':None}
        reset=domain['participants']['pi']['reset']
        reset['id']='native-pi-reset-'+hashlib.sha256(operation.encode()).hexdigest()
        reset['target_run']={'run_id':new,'generation':1}
        second={**second,'run_id':new,'operation_id':operation}
        state=next_state
        owner._authorized(second,initial=True)
        self.assertEqual(len(owner.pins),2);self.assertEqual(owner.pins[first['run_id']],first_pin)
        self.assertEqual(owner.pin[0],new)
        owner._authorized(second,initial=False)

    def test_domain_and_context_predecessor_generations_cannot_diverge(self):
        request,room,actors,state,_=fixture()
        old=state['runs']['previous-run']
        old['generation']=3;old['native_stop']['generation']=3
        with self.assertRaises(LifecycleError):reservation(state,request,room,actors,initial=True)
