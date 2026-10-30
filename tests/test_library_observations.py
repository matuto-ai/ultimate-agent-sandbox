"""Actual Library owner, canonical Git, durable Hub and Manager replay fixtures."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_library_service as service_tests
import library_support as support
from uas import library
from uas.library_records import LibraryRecords
from uas.library_observations import Owner, HubObservations, ProviderObservation
from uas.library_observation_schema import observation, ObservationError
from uas.ledger import RoomLedger, LedgerError
from uas.manager_projection import SourceObservation, ProjectionError
from uas.manager_stream import RoomIdentity, RoomStream, ManagerReadModel, SnapshotTransfer, StreamError
from uas.manager_transport import ManagerSession

AT='2026-10-30T00:00:00+00:00'
START='2026-10-28T00:00:00+00:00'

class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.f=service_tests.ServiceTests('test_commit_reports_survive_hub_outage_and_deduplicate')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.source=self.f.source;self.project=self.source.scope.project_identity
        self.owner=Owner(self.f.service.publisher,current_scope=lambda:self.source.fresh,settings=lambda:self.source.settings)
        self.ledger=RoomLedger(self.source.base/'observation-hub.db','alpha');self.addCleanup(self.ledger.close)
        self.hub=HubObservations(self.ledger,project_identity=self.project,authenticate=lambda:True)
        self.identity=RoomIdentity('deployment-1','alpha','stream-alpha')
        self.stream=RoomStream(self.ledger,self.identity,library=self.hub)
        self.path=self.source.base/'manager.db';self.model=ManagerReadModel(self.path);self.addCleanup(self.model.close)
        self.session=ManagerSession(self.model,self.identity);self.addCleanup(self.session.close)
    def capture(self,**kwargs):return self.owner.capture(observed_at=AT,window_start=START,**kwargs)
    def install(self,at=AT):
        t=self.stream.capture(self.model.cursor(self.identity),captured_at=at)
        self.session.handle({'kind':'begin','transfer':t.begin()});cursor=t.after_seq
        while cursor is not None and cursor<t.cut:
            page=t.page(cursor,limit=2);cursor=self.session.handle({'kind':'events','page':page})['room_seq']
        self.session.handle({'kind':'finish','transfer_id':t.transfer_id})
        return self.model.view(self.identity,now=at)
    def row(self,view):return view['projection']['sections']['library']['value'][self.project]
    def test_actual_owner_hub_manager_provenance_and_no_content(self):
        value=self.capture();self.assertEqual(value['row']['active_depth'],1)
        self.hub.receive(value);view=self.install();row=self.row(view)
        self.assertEqual(row['provider_state'],'unknown');self.assertEqual(row['feedback'],'unmeasured')
        self.assertEqual(row['canonical_sha'],self.source.head())
        fact=view['projection']['sections']['library'];self.assertEqual(fact['observed_at'],AT)
        self.assertEqual(fact['source_owner'],'library-service');self.assertEqual(fact['freshness'],'unknown')
        stores=repr(value)+repr(self.ledger.snapshot())+repr(list(self.model.events(self.identity)))+repr(view)
        for marker in ('We picked SQLite','Pick SQLite','PRIVATE_TITLE','prompt','raw_output'):
            self.assertNotIn(marker,stores)
        with LibraryRecords(self.source.records,'deployment-1') as records:
            saved=records.latest_observation(self.project);self.assertEqual(saved['manifest'],value)
    def test_restart_recovers_version_and_same_hub_report_deduplicates(self):
        one=self.capture();self.hub.receive(one);seq=self.ledger.snapshot()['room_seq']
        self.hub.receive(one);self.assertEqual(self.ledger.snapshot()['room_seq'],seq)
        other=Owner(self.f.service.publisher,current_scope=lambda:self.source.fresh,settings=lambda:self.source.settings)
        self.assertEqual(other.latest(),one)
        two=other.capture(observed_at=AT,window_start=START);self.assertEqual(two['sequence'],2)
        self.hub.receive(two);self.install()
        self.session.close();self.model.close();self.model=ManagerReadModel(self.path);self.addCleanup(self.model.close)
        view=self.model.view(self.identity,now=AT);self.assertEqual(view['status'],'disconnected')
        self.assertEqual(view['projection']['sections']['library']['freshness'],'stale')
    def test_hub_capture_does_not_refresh_old_external_observation(self):
        self.hub.receive(self.capture());later='2026-10-30T01:00:00+00:00';view=self.install(later)
        fact=view['projection']['sections']['library'];self.assertEqual(fact['observed_at'],AT)
        self.assertEqual(fact['freshness'],'stale');self.assertFalse(view['projection_stale'])
    def test_outage_replay_and_unattempted_reports_count_as_lag(self):
        self.f.available=False;self.f.service.tick();value=self.capture()
        self.assertEqual(value['row']['replay_lag'],2);self.assertEqual(value['row']['parked_depth'],1)
        self.assertEqual(value['row']['active_depth'],0);self.assertEqual(value['row']['completed_outcomes'],1)
        self.assertEqual(value['row']['duplicate_merges'],0)
        self.f.available=True;self.f.service.flush()
        self.assertEqual(self.capture()['row']['replay_lag'],0)
        self.hub.receive(value);self.install();self.assertEqual(self.row(self.model.view(self.identity,now=AT))['replay_lag'],2)
    def test_empty_queue_not_quality_capture_or_feedback_success(self):
        self.f.service.tick();value=self.capture()['row']
        self.assertEqual(value['active_depth'],0);self.assertEqual(value['feedback'],'unmeasured')
        self.assertIsNone(value['human_corrections']);self.assertNotIn('quality',value)
    def test_bounded_history_partial_never_complete_statistics(self):
        value=self.capture(max_records=1)['row'];self.assertEqual(value['coverage'],'partial')
        for key in ('oldest_age_seconds','replay_lag','published_drafts','capture_failures','completed_outcomes'):
            self.assertIsNone(value[key])
        self.assertEqual(value['active_depth'],1)
    def test_two_project_binding_refuses_cross_project_report(self):
        value=self.capture();other=HubObservations(self.ledger,project_identity='different-project',authenticate=lambda:True)
        with self.assertRaisesRegex(LedgerError,'INVALID_LIBRARY_BINDING'):other.receive(value)
        self.assertEqual(self.ledger.snapshot()['room_seq'],0)
    def test_two_real_projects_export_and_replay_without_cross_content(self):
        from uas.library_registration import Registrar
        alpha=self.capture()
        human=self.source.make_scope('beta','acme/beta','2002')
        Registrar(self.f.service.publisher,current_scope=lambda:human).register(
            library.action(human,self.source.settings,kind='register',operation_id='register-beta',
                request_id='register-beta',payload={},at=support.AT),self.source.settings)
        beta_scope=library.participant_scope(support.OTHER,binding=support.binding('beta','acme/beta','2002'))
        self.source.fresh=beta_scope
        self.source.enqueue('beta-command','beta-request',support.value(title='BETA_PRIVATE_MARKER',body='BETA_PRIVATE_BODY'))
        beta_owner=Owner(self.f.service.publisher,current_scope=lambda:beta_scope,settings=lambda:self.source.settings)
        beta=beta_owner.capture(observed_at=AT,window_start=START)
        with RoomLedger(self.source.base/'beta.db','beta') as ledger:
            hub=HubObservations(ledger,project_identity=beta_scope.project_identity,authenticate=lambda:True)
            hub.receive(beta);identity=RoomIdentity('deployment-1','beta','stream-beta')
            stream=RoomStream(ledger,identity,library=hub)
            session=ManagerSession(self.model,identity)
            try:
                t=stream.capture(None,captured_at=AT)
                session.handle({'kind':'begin','transfer':t.begin()})
                session.handle({'kind':'finish','transfer_id':t.transfer_id})
                beta_view=self.model.view(identity,now=AT)
            finally:session.close()
        self.source.fresh=self.source.scope
        self.hub.receive(alpha);alpha_view=self.install()
        self.assertEqual(set(beta_view['projection']['sections']['library']['value']),{beta_scope.project_identity})
        self.assertEqual(set(alpha_view['projection']['sections']['library']['value']),{self.project})
        self.assertNotIn('BETA_PRIVATE',repr(beta_view)+repr(alpha_view)+repr(self.model.deployments()))
        self.assertNotIn(beta_scope.project_identity,repr(alpha_view))
        self.assertNotIn(self.project,repr(beta_view))

    def test_old_schema_frame_without_optional_section_still_installs(self):
        t=self.stream.capture(None,captured_at=AT)
        projection=json.loads(t._projection)
        del projection['sections']['library']
        t=SnapshotTransfer(self.ledger,self.identity,None,projection)
        self.session.handle({'kind':'begin','transfer':t.begin()})
        self.session.handle({'kind':'finish','transfer_id':t.transfer_id})
        self.assertNotIn('library',self.model.view(self.identity,now=AT)['projection']['sections'])

    def test_participant_cannot_preempt_observation_record_identity(self):
        ident='observation-'+library._digest(self.project)+'-1'
        result=self.source.enqueue(ident,'preempt')
        self.assertEqual(result.outcome,'DURABLY_QUEUED')
        value=self.capture()
        self.assertEqual(value['sequence'],1)
        self.assertEqual(self.owner.latest(),value)

    def test_invalid_library_metadata_and_false_fresh_envelope_refused_before_storage(self):
        self.hub.receive(self.capture())
        for mutation,expected in (
            (lambda p:p['sections']['library']['value'][self.project].update(active_depth=-1),ProjectionError),
            (lambda p:p['sections']['library'].update(observed_at='2026-10-31T00:00:00+00:00'),StreamError)):
            projection=json.loads(self.stream.capture(None,captured_at=AT)._projection)
            mutation(projection)
            transfer=SnapshotTransfer(self.ledger,self.identity,None,projection)
            with self.assertRaises(expected):self.session.handle({'kind':'begin','transfer':transfer.begin()})
            self.assertIsNone(self.model.cursor(self.identity))

    def test_adjudication_wait_starts_at_parking_not_enqueue(self):
        self.f.service.tick()
        later='2026-10-30T00:01:00+00:00'
        row=self.owner.capture(observed_at=later,window_start=START)['row']
        self.assertEqual(row['parked_depth'],1)
        self.assertEqual(row['adjudication_wait_seconds'],60)
        self.assertIsNone(row['oldest_age_seconds'])

    def test_authenticated_receiver_and_replay_conflict(self):
        value=self.capture();self.hub.authenticate=lambda:False
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):self.hub.receive(value)
        self.hub.authenticate=lambda:True;self.hub.receive(value)
        changed=deepcopy(value);changed['row']['active_depth']=99
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'):self.hub.receive(changed)
    def test_unknown_source_without_sample_is_not_empty(self):
        view=self.install();fact=view['projection']['sections']['library']
        self.assertEqual(fact['status'],'unknown');self.assertIsNone(fact['value'])
    def test_current_authority_rechecked_and_no_observation_after_revocation(self):
        self.source.fresh=None
        with self.assertRaisesRegex(library.LibraryError,'LIBRARY_AUTHENTICATION_REQUIRED'):self.capture()
        with LibraryRecords(self.source.records,'deployment-1') as records:self.assertIsNone(records.latest_observation(self.project))
    def test_projection_exact_sha_and_unavailable_are_literal(self):
        from uas.library_projection import ProjectProjection
        reference=self.source.base/'reference';reference.mkdir(mode=0o700)
        binding=library.project_binding({'id':'alpha','repository':'acme/alpha','roots':{'reference':str(reference)}},source_identity='1001')
        scope=library.participant_scope(support.ORIGIN,binding=binding)
        projection=ProjectProjection(self.f.service.publisher,scope,self.source.settings,current_scope=lambda:scope)
        self.addCleanup(projection.close);projection.refresh()
        self.owner.projection=projection;row=self.capture()['row'];self.assertEqual(row['projection_state'],'current')
        self.source.capture('later');self.assertEqual(self.capture()['row']['projection_state'],'stale')
        with patch.object(projection,'read',side_effect=library.LibraryError('PROJECTION_UNAVAILABLE')):
            self.assertEqual(self.capture()['row']['projection_state'],'unavailable')
    def test_literal_provider_observation_not_inferred(self):
        p=ProviderObservation(self.project,AT,'f'*64,'local','unavailable',7)
        row=self.capture(provider=p)['row'];self.assertEqual(row['provider_state'],'unavailable')
        with self.assertRaises(ObservationError):self.capture(provider=replace(p,project_identity='other'))
        with self.assertRaises(ObservationError):self.capture(provider=replace(p,state='secret-title'))
    def test_unknown_fields_and_raw_payload_refused_on_all_surfaces(self):
        value=self.capture()
        for key in ('title','body','prompt','raw_output','secret','quality_score'):
            bad=deepcopy(value);bad['row'][key]='PRIVATE_MARKER'
            with self.assertRaises(ObservationError):self.hub.receive(bad)
            with self.assertRaises(ObservationError):observation(bad)
            with self.assertRaises(ProjectionError):SourceObservation('library','library-service',1,AT,{self.project:bad['row']}).document()
        self.assertEqual(self.ledger.snapshot()['room_seq'],0)
    def test_schema_negative_types_denominators_timestamps_and_sha(self):
        value=self.capture()
        for key,bad in [('active_depth',True),('canonical_sha','secret'),('window_end','bad'),('completed_outcomes',3),('provider_mode','hosted')]:
            v=deepcopy(value);v['row'][key]=bad
            with self.assertRaises(ObservationError):observation(v)
