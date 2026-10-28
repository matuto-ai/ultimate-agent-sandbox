"""Independent canonical recruitment cuts; controlled native launch only."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as N
import tempfile
import unittest

from uas.artifact_target import ArtifactSourceResolver
from uas.claude_native_admission import NativeClaudeRoot
from uas.gate_evaluation import GateRoomBinding
from uas.git_provenance import GitProvenance
from uas.ledger import LedgerError, Origin
from uas.native_host_forge import NativeHostForge
from uas.native_review_host import NativeReviewIdentity
from uas.native_reviewer_recruitment import NativeReviewerRecruitment
import test_native_run_admission_adversarial as run_fixture


class RecruitmentAdversarialTests(unittest.TestCase):
    seed=run_fixture.NativeRunAdversarialTests.seed
    open=run_fixture.NativeRunAdversarialTests.open

    def setUp(self):
        run_fixture.NativeRunAdversarialTests.setUp(self)
        self.run=self.open();self.run_id=self.run['run_id']
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name)
        self.launcher.resources['supervisor_directory']=str(root)
        git=GitProvenance(root/'git.db',self.room['id'],self.room['project']['id']);self.addCleanup(git.close)
        resolver=object.__new__(ArtifactSourceResolver);resolver.supervisor=self.supervisor
        self.source={'run_id':self.run_id,'participant_id':self.participant,'room_instance':'instance',
                     'head_sha':'a'*40,'source_digest':'b'*64,'checkout':'original'}
        def resolve(capability,*args):
            capability.require(self.supervisor)
            return deepcopy(self.source)
        resolver.resolve_locked=resolve
        self.pi=self.launcher.started[self.participant]
        self.owner_client=self.admission.broker.client
        self.recruitment=NativeReviewerRecruitment(self.admission,self.pi,git,resolver,
            GateRoomBinding(self.room['id'],'instance',self.room['project']['id'],self.room['project']['repository'],128<<20))
        self.reviewer=self.recruitment.selected['participant'];self.starts=[];self.after_reserve=lambda:None
        self.current_checks=[]
        def launch(operation,run,generation):
            self.after_reserve()
            self.recruitment._allowed()
            self.starts.append((operation,run,generation))
            root=object.__new__(NativeClaudeRoot)
            ingress=object.__new__(NativeHostForge);ingress.client=self.owner_client
            ingress.origin=Origin(self.recruitment.selected['actor'],self.reviewer,'reviewer-incarnation','reviewer-authority',('forge-read','review'))
            ingress.binding=N(operation_id='reviewer-operation')
            ingress._current=lambda:self.current_checks.append('current')
            self.hub.connect('admit-reviewer-operation',self.reviewer,'reviewer-incarnation',object())
            root.forge_service=ingress
            root.review_host=N(identity=NativeReviewIdentity((self.pi.forge_service,ingress),self.ledger,git,resolver,self.recruitment.binding))
            self.recruitment.root=root
            return root
        self.recruitment._launch=launch

    def recruit(self,operation='recruit',session=None):
        return self.recruitment.recruit(operation,self.run_id,1,session=self.session if session is None else session)

    def test_exact_stable_retry_returns_same_held_root_without_second_launch(self):
        first=self.recruit();snapshot=self.ledger.snapshot()
        self.assertIs(first,self.recruit());self.assertEqual(snapshot,self.ledger.snapshot())
        self.assertEqual(1,len(self.starts));self.assertTrue(self.current_checks)
        with self.assertRaisesRegex(LedgerError,'OPERATION_CONFLICT'):self.recruit('other')
        self.assertEqual(1,len(self.starts))

    def test_unknown_launch_is_retained_and_never_reissued(self):
        attempts=[]
        def unknown(*args):attempts.append(args);raise TimeoutError('controlled uncertain startup')
        self.recruitment._launch=unknown
        with self.assertRaises(TimeoutError):self.recruit()
        before=self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'RECONCILIATION_REQUIRED'):self.recruit()
        self.assertEqual(1,len(attempts));self.assertEqual(before,self.ledger.snapshot())
        self.assertIsNone(self.recruitment._session);self.assertFalse(self.recruitment._busy)

    def test_paused_closed_or_revised_run_after_reservation_prevents_launch(self):
        for field,value in [('status','PAUSED'),('status','CLOSED'),('control_revision',1)]:
            with self.subTest(field=field,value=value):
                case=RecruitmentAdversarialTests();case.setUp();self.addCleanup(case.doCleanups)
                case.after_reserve=lambda:case.seed(lambda state:state['runs'][case.run_id].update({field:value}))
                with self.assertRaisesRegex(LedgerError,'RUN_CHANGED'):case.recruit()
                self.assertFalse(case.starts)

    def test_full_checkout_source_change_after_reservation_is_not_just_head(self):
        self.after_reserve=lambda:self.source.update(checkout='different-worktree')
        with self.assertRaisesRegex(LedgerError,'SOURCE_CHANGED'):self.recruit()
        self.assertFalse(self.starts)

    def test_human_disconnect_after_reservation_refuses(self):
        self.after_reserve=lambda:setattr(self,'connected',False)
        with self.assertRaisesRegex(LedgerError,'AUTHORIZATION_REVOKED'):self.recruit()
        self.assertFalse(self.starts)

    def test_pi_lost_after_reservation_refuses(self):
        self.after_reserve=lambda:self.seed(lambda state:state['peer_traffic']['connections'][self.participant].update(readiness='lost'))
        with self.assertRaisesRegex(LedgerError,'STALE_CONNECTION'):self.recruit()
        self.assertFalse(self.starts)

    def test_wrong_human_origin_and_changed_reviewer_actor_deny(self):
        before=self.ledger.snapshot()
        other=replace(self.session,human=replace(self.human,actor_id='different-human'))
        with self.assertRaisesRegex(LedgerError,'RUN_CHANGED'):self.recruit(session=other)
        self.assertEqual(before,self.ledger.snapshot())
        self.seed(lambda state:state['peer_traffic']['definition']['participants'][self.reviewer].update(actor_id='different-reviewer'))
        before=self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'NATIVE_REVIEWER_BINDING'):self.recruit()
        self.assertEqual(before,self.ledger.snapshot());self.assertFalse(self.starts)

    def test_existing_connection_or_delivered_traffic_never_relabels_context(self):
        before=deepcopy(self.ledger.snapshot()['state'])
        self.hub.connect('reviewer-existing',self.reviewer,'old-reviewer',object())
        snapshot=self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'RESET_REQUIRED'):self.recruit()
        self.assertEqual(snapshot,self.ledger.snapshot());self.assertFalse(self.starts)
        self.seed(lambda state:state.update(deepcopy(before)))
        self.seed(lambda state:state['peer_traffic']['traffic'].update(previous={
            'sender':self.participant,'recipients':[self.reviewer],'status':'DELIVERED'}))
        snapshot=self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'RESET_REQUIRED'):self.recruit()
        self.assertEqual(snapshot,self.ledger.snapshot());self.assertFalse(self.starts)

    def test_changed_reserved_context_or_existing_journal_prevents_create(self):
        self.recruitment.journal.write_text('owned startup evidence')
        before=self.ledger.snapshot()
        with self.assertRaisesRegex(LedgerError,'RESET_REQUIRED'):self.recruit()
        self.assertEqual(before,self.ledger.snapshot());self.assertFalse(self.starts)
        self.recruitment.journal.unlink()
        self.after_reserve=lambda:self.seed(lambda state:state['fixture_context']['participants'][self.reviewer].update(context_generation=2))
        with self.assertRaisesRegex(LedgerError,'CONTEXT_CHANGED'):self.recruit()
        self.assertFalse(self.starts)

    def test_existing_root_with_lost_or_replaced_reviewer_is_not_returned_as_current(self):
        for field,value in [('readiness','lost'),('attachment_id','replacement'),('incarnation_id','replacement')]:
            with self.subTest(field=field):
                case=RecruitmentAdversarialTests();case.setUp();self.addCleanup(case.doCleanups)
                case.recruit()
                case.seed(lambda state:state['peer_traffic']['connections'][case.reviewer].update({field:value}))
                before=case.ledger.snapshot()
                with self.assertRaisesRegex(LedgerError,'STALE_CONNECTION'):case.recruit()
                self.assertEqual(1,len(case.starts));self.assertEqual(before,case.ledger.snapshot())
