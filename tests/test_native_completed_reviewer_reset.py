"""Reuse exact completed retirement across canonical Pi and Claude reset.

Target Run activation is a controlled prerequisite; native effects are inert.
No arbitrary descendants or checkout quiescence is inferred.
"""
from copy import copy,deepcopy
from dataclasses import replace
from types import SimpleNamespace as N
import json
import time
import unittest
from unittest.mock import patch
from uas.ledger import LedgerError, Origin
from uas.kernel_origin import OriginDenied
from uas.native_reviewer_recruitment import NativeReviewerRecruitment
from uas.native_claude_retirement import NativeClaudeRetirement
from uas.claude_native_admission import NativeClaudeRoot, NativeClaudeSupervisorAdmission
from uas.native_helper import NativeDescendantLease
from uas.native_host_forge import NativeHostForge
from uas.native_review_host import NativeReviewIdentity
import test_native_pi_reset_adversarial as fixture

class CompletedReviewerResetTests(unittest.TestCase):
    def setUp(self):
        self.c=fixture.NativePiResetAdversarialTests();self.c.setUp();self.addCleanup(self.c.doCleanups);c=self.c
        c.root.recipe.session_id='old-reviewer-session';c.root.forge_service.binding.epoch=1
        c.launcher.control=object();reset=c.prepare();c.request(reset);self.pi=c.fresh(reset);c.complete(reset,self.pi)
        self.pi.seat.actor_id=c.actor;self.pi.launch.incarnation='new-pi';self.pi.forge_service=copy(c.pi.forge_service)
        self.pi.forge_service.origin=replace(c.pi.forge_service.origin,incarnation_id='new-pi')
        self.pi.forge_service.binding=N(operation_id='new-pi',epoch=2)
        c.launcher.started[c.participant]=self.pi
        def active(state):
            row=deepcopy(state['runs'][c.run_id]);row.update(run_id=c.newrun,status='ACTIVE',outcome=None,
                completion=None,admission_origin=c.human.canonical(),control_pending=None,control_revision=0,native_stop=None,admission_operation='next')
            state['runs'][c.newrun]=row;state['run_admissions'][c.newrun]['status']='ACTIVE'
            state['peer_traffic']['connections'][c.participant].update(incarnation_id='new-pi',attachment_id='admit-new-pi',context_generation=2,readiness='safe')
            state['peer_traffic']['connections'][c.reviewer]['readiness']='lost'
        c.seed(active);c.source['run_id']=c.newrun
        self.owner=NativeReviewerRecruitment(c.admission,self.pi,c.recruitment.provenance,c.recruitment.resolver,c.recruitment.binding)
        self.launches=[];self.after_request=lambda:None;self.check_after_root_admit=False;self.mutate_admission=lambda root:None
        def launch(op,run,generation):
            self.after_request();self.owner._allowed();self.launches.append(run)
            root=object.__new__(NativeClaudeRoot);scope=self.owner._reset.contexts.pending_scope(self.owner._reset.reset_id)
            root.recipe=N(scope=scope,session_id='new-reviewer-session')
            root.admission=None;root.incarnation='new-reviewer'
            root._prepared_initialization={'deadline':time.monotonic()+20,'epoch':2,'operation_id':'new-reviewer'};root._prepared_admit_started=False
            root._native_readiness_json=json.dumps({'scope':scope,'native':{'session_id':'new-reviewer-session','source':'fresh-home-explicit-session-native-idle-no-input'}})
            root.current=lambda:True;root.helper_lease=object.__new__(NativeDescendantLease);root.helper_lease.root=root
            root.helper_lease.state='released';root.helper_lease.current=lambda:True;root.helper_lease._lineage=N(current=lambda:True)
            root.forge_service=root.review_host=None;self.owner.root=root;self.owner._reset.complete(root)
            ingress=object.__new__(NativeHostForge);ingress.client=c.owner_client
            ingress.origin=Origin(c.recruitment.selected['actor'],c.reviewer,'new-reviewer','new-authority',('forge-read','review'))
            ingress.binding=N(operation_id='new-reviewer',epoch=2);ingress._current=lambda:True
            c.hub.connect('admit-new-reviewer',c.reviewer,'new-reviewer',object(),context_generation=2)
            root.native_admission=object.__new__(NativeClaudeSupervisorAdmission)
            root.native_admission.launch=root;root.native_admission.controller='controller';root.native_admission._current=lambda:True
            receipt={'version':1,'operation_id':'new-reviewer','epoch':2,'controller':'controller','admission_digest':'digest'}
            root.admission={**receipt,'state':'admitted','receipt':receipt}
            self.mutate_admission(root)
            if self.check_after_root_admit:self.owner._allowed()
            root.forge_service=ingress;root.review_host=N(identity=NativeReviewIdentity((self.pi.forge_service,ingress),c.ledger,c.recruitment.provenance,c.recruitment.resolver,c.recruitment.binding))
            return root
        self.owner._launch=launch
    def recruit(self):return self.owner.recruit('successor-reviewer',self.c.newrun,1,session=self.c.session,reset_from=self.c.recruitment)
    def test_completed_retirement_reused_without_recapture_or_second_stop(self):
        captured=len(self.c.captured);stopped=len(self.c.stopped)
        with patch.object(NativeClaudeRetirement,'__init__',side_effect=AssertionError('no recapture')),patch.object(NativeClaudeRetirement,'retire',side_effect=AssertionError('no restop')):
            root=self.recruit()
        row=self.c.ledger.snapshot()['state']['fixture_context']['participants'][self.c.reviewer]
        self.assertEqual(2,row['context_generation']);self.assertEqual('SUCCEEDED',row['reset']['status'])
        self.assertIs(self.owner._reset.completed,self.c.retirement)
        self.assertIs(self.owner._reset.retirement,self.c.retirement.retirements[self.c.reviewer])
        self.assertEqual((captured,stopped),(len(self.c.captured),len(self.c.stopped)));self.assertIs(root,self.owner.root)
    def test_wrong_retirement_registry_denies_not_adopts_receipt(self):
        self.c.admission._completed_retirements['retire']=object()
        with self.assertRaisesRegex(LedgerError,'OWNERS_REQUIRED'):self.recruit()
        self.assertFalse(self.launches)
    def test_same_lost_row_but_replaced_identity_or_actor_denies(self):
        for field in ('attachment_id','incarnation_id','actor_id'):
            case=CompletedReviewerResetTests();case.setUp();self.addCleanup(case.doCleanups)
            def change(state):
                if field=='actor_id':state['peer_traffic']['definition']['participants'][case.c.reviewer][field]='replacement'
                else:state['peer_traffic']['connections'][case.c.reviewer][field]='replacement'
            case.c.seed(change)
            with self.assertRaises(LedgerError):case.recruit()
            self.assertFalse(case.launches)
    def test_lost_retained_exit_after_request_prevents_new_launch(self):
        self.after_request=lambda:self.c.proven.discard(id(self.c.root))
        with self.assertRaises(OriginDenied):self.recruit()
        self.assertFalse(self.launches)
        row=self.c.ledger.snapshot()['state']['fixture_context']['participants'][self.c.reviewer]
        self.assertEqual(1,row['context_generation']);self.assertEqual('REQUESTED',row['reset']['status'])

    def test_attachment_replacement_after_request_prevents_new_launch(self):
        self.after_request=lambda:self.c.seed(lambda state:state['peer_traffic']['connections'][self.c.reviewer].update(attachment_id='late-replacement'))
        with self.assertRaises(LedgerError):self.recruit()
        self.assertFalse(self.launches)

    def test_actual_canonical_root_admit_before_review_host_construction(self):
        self.check_after_root_admit=True
        self.recruit()
        self.assertEqual([self.c.newrun],self.launches)

    def test_root_admit_unknown_or_mismatched_receipt_cannot_enable_helper_phase(self):
        for field,value in (('receipt',None),('epoch',9),('controller','wrong'),('state','unknown')):
            case=CompletedReviewerResetTests();case.setUp();self.addCleanup(case.doCleanups)
            case.check_after_root_admit=True
            case.mutate_admission=lambda root:root.admission.update({field:value})
            with self.assertRaises(LedgerError):case.recruit()
            self.assertIsNone(case.owner.root.review_host)
