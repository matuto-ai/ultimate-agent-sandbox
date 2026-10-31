"""T31 actual authenticated host/Hub/service, SQLite and real Git; no provider."""
from dataclasses import replace
import json
import unittest
from unittest.mock import patch

import test_library_disposition as fixture
from uas import library
from uas.ledger import RoomLedger, Origin
from uas.library_controls import canonical
from uas.manager_actions import HumanSession
from uas.manager_library_transport import FieldNotesLibraryHost, ManagerLibraryHub, LibraryServiceContact


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixture.DispositionBase('runTest')
        self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.source, self.controls = self.fx.source, self.fx.controls
        self.path = self.source.base/'manager-private.db'
        self.ledger = RoomLedger(self.path, 'room'); self.addCleanup(self.ledger.close)
        self.connected = True; self.allowed = True; self.context = object(); self.auth_calls = 0
        self.session = HumanSession('deployment-1','room','instance','human',
            Origin('actor','human','inc','grant',()), lambda _,a:self.allowed,
            lambda:self.connected)
        self.contact = LibraryServiceContact(self.controls, lambda _:self.fx.principal)
        self.hub = ManagerLibraryHub(self.ledger, deployment_id='deployment-1', room_id='room',
            instance_id='instance', project_id='alpha', project_identity=self.source.scope.project_identity,
            contact=self.contact)
        def authenticate(context):
            self.auth_calls += 1
            if context is not self.context: raise ValueError('private diagnostic')
            return self.session
        self.host = FieldNotesLibraryHost(self.hub, authenticate)
    def invoke(self, request, ident='one', mode='execute'):
        return self.host.handle(canonical(dict(version=1,operation_id=ident,mode=mode,request=request)),self.context)
    def opening(self):
        evidence = self.invoke(dict(version=1,action='observe',for_action='inspect',project_id='alpha',
            queue_id=self.fx.q),'observe')['result']
        return dict(version=1,action='inspect',project_id='alpha',queue_id=self.fx.q,request_id='open',
            settings_id=evidence['settings_id'],observed_version=evidence['observed_version'])
    def assert_private(self, *markers):
        retained = canonical(self.ledger.snapshot()) + canonical(self.ledger.replay(0,limit=1000))
        # Include on-disk DB/WAL, not just the selected visible projection.
        for base in (self.path, self.source.records):
            for path in base.parent.glob(base.name+'*'):
                if path.is_file(): retained += path.read_bytes()
        for marker in markers:self.assertNotIn(marker.encode(),retained)
    def test_actual_inspect_reject_metadata_replay_and_fresh_open(self):
        value=self.opening(); result=self.invoke(value,'open')
        self.assertEqual(result['outcome'],'OBSERVED',result)
        self.assertIn('Selected draft data.',result['result']['item']['text'])
        self.assertFalse(result['result']['remote_resources']); self.assertFalse(result['result']['recursive'])
        self.assertEqual(self.invoke(value,'open','reconcile'),{'outcome':'FRESH_OPEN_REQUIRED'})
        reason='PRIVATE_REASON_T31 requires a human rejection.'
        rejection=self.fx.value(reason=reason);before=self.source.count()
        result=self.invoke(rejection,'reject')
        self.assertEqual(result['outcome'],'COMMITTED',result)
        self.assertEqual(self.source.count(),before+1)
        self.assertEqual(self.invoke(rejection,'reject'),result)
        self.assertEqual(self.source.count(),before+1)
        self.assert_private('Selected draft data.',reason)
        self.assertNotIn('runs',self.ledger.snapshot()['state'])
        self.assertGreater(self.auth_calls,3)
    def test_lost_response_duplicate_reconciles_without_second_write(self):
        value=self.fx.value(); before=self.source.count()
        def lost(*a,**kw):
            self.contact(*a,**kw)
            raise OSError(value['reason'])
        self.hub.contact=lost
        self.assertEqual(self.invoke(value)['reason'],'LIBRARY_UNAVAILABLE')
        self.assertEqual(self.source.count(),before+1)
        self.hub.contact=self.contact
        self.assertEqual(self.invoke(value)['outcome'],'COMMITTED')
        self.assertEqual(self.source.count(),before+1)
        self.assert_private(value['reason'])
    def test_reserved_without_service_contact_never_replays_write(self):
        value=self.fx.value(); before=self.source.count()
        self.hub.contact=lambda *a,**k:(_ for _ in ()).throw(OSError('lost before service'))
        self.invoke(value);self.hub.contact=self.contact
        self.assertEqual(self.invoke(value)['reason'],'CONTROL_OUTCOME_UNKNOWN')
        self.assertEqual(self.invoke(value,mode='reconcile')['reason'],'CONTROL_OUTCOME_UNKNOWN')
        self.assertEqual(self.source.count(),before)
    def test_current_grants_host_and_service_even_after_confirmed_receipt(self):
        value=self.fx.value();self.assertEqual(self.invoke(value)['outcome'],'COMMITTED')
        self.fx.allowed=False;self.assertEqual(self.invoke(value)['reason'],'FORBIDDEN')
        self.fx.allowed=True;self.connected=False
        self.assertEqual(self.invoke(value)['reason'],'FORBIDDEN')
        self.connected=True;self.session=replace(self.session,room_id='other')
        self.assertEqual(self.invoke(value)['reason'],'FORBIDDEN')
    def test_conflicting_body_origin_and_stale_inspection(self):
        value=self.fx.value();self.invoke(value)
        self.assertEqual(self.invoke({**value,'reason':'different'})['reason'],'ID_CONFLICT')
        self.session=replace(self.session,human=Origin('actor','human','inc','new-grant',()))
        self.assertEqual(self.invoke(value)['reason'],'ID_CONFLICT')
    def test_stale_prepublication_does_not_write(self):
        value=self.fx.value();self.source.capture('other');before=self.source.count()
        self.assertEqual(self.invoke(value)['reason'],'STALE_INSPECTION')
        self.assertEqual(self.source.count(),before)
    def test_settings_authority_does_not_grant_project(self):
        self.fx.principal=library.LocalHuman('human','actor','grant',
            lambda _,p,a:p is None and a==library.SETTINGS_CAPABILITY,lambda:True)
        self.assertEqual(self.invoke(dict(version=1,action='observe',for_action='inspect',
            project_id='alpha',queue_id=self.fx.q))['reason'],'FORBIDDEN')
    def test_two_real_projects_no_cross_project_read_or_pending_context(self):
        import test_library_scheduler as sched
        fx=self.fx.fx.fx;fx.scheduler=self.fx.service.scheduler
        fx.runner=fx.fixture.runner();fx.replies=[]
        fx.register=lambda runner:sched.SchedulerTests.register(fx,runner)
        _,queue=sched.SchedulerTests.second(fx)
        result=self.invoke(dict(version=1,action='observe',for_action='inspect',project_id='beta',queue_id=queue))
        self.assertEqual(result['reason'],'FORBIDDEN')
        value=self.opening();result=self.invoke(value,'open')
        self.assertNotIn('Beta data',canonical(result).decode())
        self.assert_private('Beta data','Selected draft data.')
    def test_strict_wire_and_untrusted_context_have_no_side_effects(self):
        before=self.ledger.snapshot()
        for raw in (b'[]',b'NaN',b'{"version":1,"version":1}',b'x'*10000):
            self.assertEqual(self.host.handle(raw,self.context)['outcome'],'UNCONFIRMED')
        self.assertEqual(self.host.handle(b'{}',object())['outcome'],'UNCONFIRMED')
        self.assertEqual(self.ledger.snapshot(),before)
    def test_revocation_during_service_response_suppresses_body(self):
        value=self.opening()
        def revoke(*a,**kw):
            result=self.contact(*a,**kw);self.allowed=False;return result
        self.hub.contact=revoke
        result=self.invoke(value,'open')
        self.assertEqual(result['reason'],'FORBIDDEN')
        self.assertNotIn('Selected draft data.',canonical(result).decode())
        self.assert_private('Selected draft data.')

    def test_composed_adjudication_conclusion_rationale_ephemeral_and_loss_safe(self):
        self.fx.principal=library.LocalHuman('human','actor','grant',
            lambda _,p,a:self.fx.allowed and p==self.source.scope.project_identity
                and a in ('library-inspect','library-adjudicate'),lambda:True)
        value=self.fx.value();value.pop('reason')
        value.update(action='adjudicate',conclusion='T31_PRIVATE_CONCLUSION Keep policy.',
            rationale='T31_PRIVATE_RATIONALE Human judgement.')
        before=self.source.count()
        def lost(*a,**kw):
            self.contact(*a,**kw);raise OSError(value['conclusion'])
        self.hub.contact=lost;self.assertEqual(self.invoke(value)['reason'],'LIBRARY_UNAVAILABLE')
        self.hub.contact=self.contact
        self.assertEqual(self.invoke(value)['outcome'],'COMMITTED')
        self.assertEqual(self.source.count(),before+1)
        self.assert_private(value['conclusion'],value['rationale'])

    def test_same_project_id_wrong_immutable_binding_denies_before_effects(self):
        value=self.fx.value();before=self.source.count()
        self.hub.project_identity='github.com/999999'
        self.assertEqual(self.invoke(value)['reason'],'FORBIDDEN')
        self.assertEqual(self.source.count(),before)
        self.assertEqual(self.invoke(dict(version=1,action='observe',for_action='inspect',
            project_id='alpha',queue_id=self.fx.q),'read')['reason'],'FORBIDDEN')
    def test_service_grant_revoked_after_read_suppresses_body(self):
        value=self.opening();original=self.controls.handle
        def revoke(*a,**kw):
            result=original(*a,**kw);self.fx.allowed=False;return result
        with patch.object(self.controls,'handle',revoke):
            result=self.invoke(value,'open')
        self.assertEqual(result['reason'],'FORBIDDEN')
        self.assertNotIn('Selected draft data.',canonical(result).decode())
    def test_duplicate_while_reservation_winner_inflight_only_reconciles(self):
        import threading
        entered=threading.Event();release=threading.Event();results=[];modes=[]
        value=self.fx.value();before=self.source.count()
        def contact(*a,**kw):
            modes.append(kw['reconcile'])
            if not kw['reconcile']:
                entered.set()
                if not release.wait(5):raise RuntimeError('test deadline')
            return self.contact(*a,**kw)
        self.hub.contact=contact
        def winning_request():
            with RoomLedger(self.path,'room') as ledger:
                hub=ManagerLibraryHub(ledger,deployment_id='deployment-1',room_id='room',
                    instance_id='instance',project_id='alpha',project_identity=self.source.scope.project_identity,
                    contact=contact)
                host=FieldNotesLibraryHost(hub,lambda _:self.session)
                raw=canonical(dict(version=1,operation_id='one',mode='execute',request=value))
                results.append(host.handle(raw,self.context))
        worker=threading.Thread(target=winning_request)
        worker.start()
        try:
            self.assertTrue(entered.wait(5))
            duplicate=self.invoke(value)
            self.assertEqual(duplicate['reason'],'CONTROL_OUTCOME_UNKNOWN')
        finally:
            release.set();worker.join(5)
        self.assertFalse(worker.is_alive());self.assertEqual(modes,[False,True])
        self.assertEqual(results[0]['outcome'],'COMMITTED')
        self.assertEqual(self.source.count(),before+1)
    def test_restart_and_actual_manager_cache_replay_never_restore_bodies(self):
        from uas.manager_stream import RoomIdentity,RoomStream,ManagerReadModel
        from uas.manager_transport import ManagerSession
        identity=RoomIdentity('deployment-1','room','stream')
        cache=self.source.base/'manager-cache.db'
        model=ManagerReadModel(cache);session=ManagerSession(model,identity)
        self.addCleanup(model.close);self.addCleanup(session.close)
        initial=RoomStream(self.ledger,identity).capture(None,captured_at='2026-10-30T00:00:00+00:00')
        session.handle({'kind':'begin','transfer':initial.begin()})
        session.handle({'kind':'finish','transfer_id':initial.transfer_id})
        value=self.opening();self.invoke(value,'open')
        rejection=self.fx.value();self.invoke(rejection,'reject')
        self.ledger.close();self.ledger=RoomLedger(self.path,'room')
        self.addCleanup(self.ledger.close);self.hub.ledger=self.ledger
        self.fx.restart();self.controls=self.fx.controls
        self.assertEqual(self.invoke(rejection,'reject')['outcome'],'COMMITTED')
        self.assertEqual(self.invoke(value,'open','reconcile'),{'outcome':'FRESH_OPEN_REQUIRED'})
        transfer=RoomStream(self.ledger,identity).capture(0,captured_at='2026-10-30T00:00:00+00:00')
        frames=[{'kind':'begin','transfer':transfer.begin()}]
        session.handle(frames[0]);cursor=0
        while cursor<transfer.cut:
            frame={'kind':'events','page':transfer.page(cursor,limit=2)}
            frames.append(frame);cursor=session.handle(frame)['room_seq']
        frames.append({'kind':'finish','transfer_id':transfer.transfer_id})
        session.handle(frames[-1]);self.assertEqual(cursor,transfer.cut)
        events=model.events(identity);self.assertTrue(events['events'])
        view=model.view(identity,now='2026-10-30T00:00:00+00:00')
        retained=canonical(frames)+canonical(view)+canonical(events)
        for path in cache.parent.glob(cache.name+'*'):
            if path.is_file():retained+=path.read_bytes()
        for marker in ('Selected draft data.',rejection['reason']):
            self.assertNotIn(marker.encode(),retained)
        self.assert_private('Selected draft data.',rejection['reason'])

    def all_project_grants(self):
        self.fx.principal=library.LocalHuman('human','actor','grant',
            lambda _, project, action:self.fx.allowed and project==self.source.scope.project_identity
                and action in ('library-inspect','library-reject','library-adjudicate',
                    'library-drain','library-retry','library-defer','library-requeue','library-resume'),
            lambda:True)

    def scheduling(self, kind, ident):
        observed=self.invoke(dict(version=1,action='observe',project_id='alpha',for_action=kind),
                             ident+'-observe')['result']
        value=dict(version=1,action=kind,project_id='alpha',request_id=ident,
                   settings_id=observed['settings_id'],observed_version=observed['observed_version'])
        if kind in ('retry','resume','requeue'):value['drain_id']=observed['drain_id']
        return value

    def receipt_query(self, kind, ident):
        return self.invoke(dict(version=1,action='receipt',project_id='alpha',for_action=kind),
                           ident,mode='reconcile')

    def test_scheduling_distinct_retry_disposition_and_separate_resume(self):
        self.all_project_grants(); before=self.source.count()
        drain=self.scheduling('drain','drain-new')
        acknowledged=self.invoke(drain,'drain-new')
        self.assertEqual(acknowledged['outcome'],'ACKNOWLEDGED',acknowledged)
        self.assertEqual(acknowledged['kind'],'drain')
        state=json.loads(canonical(self.fx.entry()['state']))
        self.assertEqual(self.invoke(drain,'drain-new'),acknowledged)
        self.assertEqual(self.receipt_query('drain','drain-new'),acknowledged)
        self.assertEqual(self.fx.entry()['state'],state)
        self.assertEqual(self.source.count(),before)
        self.fx.blocked()
        retry=self.scheduling('retry','retry-same')
        self.assertEqual(self.invoke(retry,'retry-same')['kind'],'retry')
        self.assertEqual(self.fx.entry()['state']['drain_id'],'original-drain')
        self.fx.blocked()
        rejection=self.fx.value(request='disposition')
        receipt=self.invoke(rejection,'disposition')
        self.assertEqual(receipt['outcome'],'COMMITTED')
        self.assertEqual(self.fx.entry()['state']['state'],'DISPOSED')
        bad=self.scheduling('drain','cannot-drain')
        self.assertEqual(self.invoke(bad,'cannot-drain'),{'outcome':'REFUSED','reason':'DRAIN_DISPOSED'})
        resume=self.scheduling('resume','new-remainder')
        accepted=self.invoke(resume,'new-remainder')
        self.assertEqual(accepted['kind'],'resume')
        self.assertEqual(accepted['outcome'],'ACKNOWLEDGED')
        self.assertIsNone(self.fx.entry()['state']['drain_id'])
        self.assertEqual(self.fx.entry()['state']['selected'],[])
        self.assertEqual(self.receipt_query('reject','disposition'),receipt)
        self.assertEqual(self.fx.entry()['state']['state'],'READY')
        self.assertFalse(self.fx.fx.fx.fixture.marker.exists())

    def test_defer_and_requeue_keep_schedule_and_reconcile_without_new_writes(self):
        from uas.library_observations import Owner as Observations
        from uas.library_attention import Owner as Attention
        import test_library_requeue as requeue_fixture
        from datetime import timedelta
        self.all_project_grants();self.fx.blocked()
        now=self.fx.fx.fx.now
        Observations(self.controls.service.publisher,current_scope=lambda:self.source.fresh,
            settings=lambda:self.source.settings).capture(observed_at=now.isoformat(),
                window_start=(now-timedelta(hours=1)).isoformat())
        Attention(self.controls.service.publisher,current_scope=lambda:self.source.fresh,
            settings=lambda:self.source.settings,now=lambda:now).sample()
        state=json.loads(canonical(self.fx.entry()['state']));before=self.source.count()
        defer=self.scheduling('defer','snooze')
        result=self.invoke(defer,'snooze')
        self.assertEqual(result['outcome'],'ACKNOWLEDGED',result)
        self.assertEqual(result['reason'],'ATTENTION_SNOOZED')
        self.assertEqual(self.receipt_query('defer','snooze'),result)
        self.assertEqual(self.fx.entry()['state'],state);self.assertEqual(self.source.count(),before)
        _,_,parked_drain=requeue_fixture.RequeueTests.parked(self.fx)
        value=self.scheduling('requeue','release');value['drain_id']=parked_drain
        before=self.source.count();result=self.invoke(value,'release')
        self.assertEqual(result['outcome'],'COMMITTED',result)
        self.assertEqual(self.fx.entry()['state'],state)
        self.assertEqual(self.receipt_query('requeue','release'),result)
        self.assertEqual(self.invoke(value,'release'),result)
        self.assertEqual(self.source.count(),before+1)

    def test_body_free_receipt_after_lost_private_response_and_current_fences(self):
        self.all_project_grants();value=self.fx.value(reason='T32_EPHEMERAL_PRIVATE_REASON')
        before=self.source.count()
        def lost(*a,**kw):
            self.contact(*a,**kw)
            raise OSError('private response lost')
        self.hub.contact=lost
        self.assertEqual(self.invoke(value,'private-write')['outcome'],'UNCONFIRMED')
        self.hub.contact=self.contact
        receipt=self.receipt_query('reject','private-write')
        self.assertEqual(receipt['outcome'],'COMMITTED',receipt)
        self.assertEqual(self.source.count(),before+1)
        self.assertEqual(self.receipt_query('reject','private-write'),receipt)
        self.assertEqual(self.receipt_query('adjudicate','private-write')['reason'],'FORBIDDEN')
        self.fx.allowed=False
        self.assertEqual(self.receipt_query('reject','private-write')['reason'],'FORBIDDEN')
        self.fx.allowed=True
        self.session=replace(self.session,human=Origin('actor','human','inc','different-grant',()))
        self.assertEqual(self.receipt_query('reject','private-write')['reason'],'ID_CONFLICT')
        self.assert_private('T32_EPHEMERAL_PRIVATE_REASON')

    def test_absent_pending_receipts_and_untrusted_receipt_fields_never_write(self):
        self.all_project_grants();value=self.fx.value();before=self.source.count()
        self.hub.contact=lambda *a,**kw:(_ for _ in ()).throw(OSError('before service'))
        self.invoke(value,'unreached');self.hub.contact=self.contact
        self.assertEqual(self.receipt_query('reject','unreached')['reason'],'CONTROL_OUTCOME_UNKNOWN')
        self.assertEqual(self.receipt_query('reject','never-reserved')['reason'],'CONTROL_OUTCOME_UNKNOWN')
        raw=dict(version=1,action='receipt',project_id='alpha',for_action='reject')
        for extra in ({'service_operation_id':'forged'}, {'reason':'private'}, {'path':'/tmp'}):
            self.assertEqual(self.invoke({**raw,**extra},'unreached','reconcile')['reason'],'INVALID_CONTROL_REQUEST')
        self.assertEqual(self.invoke(raw,'unreached')['reason'],'INVALID_CONTROL_REQUEST')
        self.assertEqual(self.source.count(),before)

    def test_stale_definite_refusal_refresh_and_postpublication_failure_stays_unknown(self):
        self.all_project_grants();value=self.fx.value(request='stale')
        self.source.capture('newer');before=self.source.count()
        self.assertEqual(self.invoke(value,'stale'),{'outcome':'REFUSED','reason':'STALE_INSPECTION'})
        self.assertEqual(self.source.count(),before)
        # Lost/duplicate refusal never becomes permission to apply a new write.
        self.assertEqual(self.receipt_query('reject','stale')['reason'],'CONTROL_OUTCOME_UNKNOWN')
        self.assertEqual(self.invoke(value,'stale')['reason'],'CONTROL_OUTCOME_UNKNOWN')
        fresh=self.fx.value(request='fresh');publish=self.source.publisher.publish
        def uncertain(*a,**kw):
            publish(*a,**kw)
            raise library.LibraryError('STALE_CONTROL_STATE')
        with patch.object(self.source.publisher,'publish',side_effect=uncertain):
            result=self.invoke(fresh,'fresh')
        self.assertEqual(result['outcome'],'UNCONFIRMED',result)
        self.assertEqual(self.source.count(),before+1)
        self.assertEqual(self.receipt_query('reject','fresh')['reason'],'CONTROL_OUTCOME_UNKNOWN')
        self.assertEqual(self.invoke(fresh,'fresh')['outcome'],'COMMITTED')
        self.assertEqual(self.receipt_query('reject','fresh')['outcome'],'COMMITTED')
        self.assertEqual(self.source.count(),before+1)

    def test_inspection_service_selects_batch_identity_and_versions_batch_changes(self):
        opening=self.opening();first=self.invoke(opening,'open-a')['result']
        self.assertIsNone(first['drain_id'])
        self.fx.blocked()
        self.assertEqual(self.invoke(opening,'open-b')['reason'],'STALE_INSPECTION')
        opening=self.opening();opening['request_id']='open-new-version'
        second=self.invoke(opening,'open-c')['result']
        self.assertEqual(second['drain_id'],'original-drain')
        self.assertNotEqual(first['observed_version'],second['observed_version'])

    def test_upgrade_preserves_original_t31_reservation_canonical_identity(self):
        import hashlib
        from uas.ledger import Command, Event, Transition
        value=self.fx.value(request='old-format')
        metadata={'request_sha256':hashlib.sha256(canonical(value)).hexdigest(),
            'project_identity':self.source.scope.project_identity,'session':self.session.metadata(),
            'service_operation_id':'human-control-'+library._digest(
                [self.source.scope.project_identity,value['request_id']])}
        self.ledger.apply(Command('old-operation','library.private','alpha',None,metadata),
            self.session.human,authorize=lambda *_:True,
            decide=lambda state,_:Transition(state,(Event('library.private.reserved',metadata),),metadata))
        self.controls.handle(canonical(value),self.fx.principal)
        before=self.source.count()
        receipt=self.receipt_query('reject','old-operation')
        self.assertEqual(receipt['outcome'],'COMMITTED',receipt)
        self.assertEqual(self.invoke(value,'old-operation'),receipt)
        self.assertEqual(self.source.count(),before)

if __name__ == '__main__': unittest.main()
