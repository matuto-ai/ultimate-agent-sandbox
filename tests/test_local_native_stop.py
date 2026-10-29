"""Canonical completed reducers, controlled native effects; no host execution."""
from contextlib import ExitStack
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

from uas.local_native_graph import LocalNativeGraph
from uas.local_native_stop import LocalNativeStopObservations
from uas.local_runtime_plan import LocalRuntimePlan
from uas.ledger import LedgerError
from uas.native_completed_retirement import NativeCompletedRetirement
import test_native_completed_retirement as fixture


class LocalStopTests(unittest.TestCase):
    seed=fixture.CompletedRetirementTests.seed
    open=fixture.CompletedRetirementTests.open
    recruit=fixture.CompletedRetirementTests.recruit
    row=fixture.CompletedRetirementTests.row
    unchanged_completion=fixture.CompletedRetirementTests.unchanged_completion
    def setUp(self):
        fixture.CompletedRetirementTests.setUp(self)
        plan=object.__new__(LocalRuntimePlan)
        plan.__dict__.update(vars(self.launcher.plan))
        self.launcher.plan=plan
        self.stack.enter_context(patch.object(LocalRuntimePlan,'require_unchanged',lambda s:None))
        graph=object.__new__(LocalNativeGraph)
        graph.host=N(plan=plan);graph.closed=False;graph.owner=self.admission
        graph.launcher=self.launcher;graph.recruitment=self.recruitment
        graph.stack=ExitStack();self.addCleanup(graph.stack.close)
        self.graph=graph
    def bundle(self):return LocalNativeStopObservations(self.graph)
    def adopt(self,bundle,operation='retire'):
        held=bundle.adopt_completed(self.admission,self.recruitment,operation,self.run_id)
        self.admission._completed_retirements[operation]=held
        return held
    def test_all_captured_before_effects_then_fresh_canonical_retirement(self):
        snapshot=self.ledger.snapshot()
        bundle=self.bundle();self.assertEqual(2,len(self.captured));self.assertFalse(self.stopped)
        bundle.retire();self.assertTrue(bundle.require_exited())
        self.assertEqual(snapshot,self.ledger.snapshot())
        held=self.adopt(bundle);self.assertIs(type(held),NativeCompletedRetirement)
        count=len(self.stopped)
        result=self.admission.retire_completed('retire',self.run_id,1,0,session=self.session,reviewer=self.recruitment)
        self.assertEqual('VERIFIED',result['native_stop']['status']);self.assertTrue(held.require_completed())
        self.assertEqual(count,len(self.stopped));self.unchanged_completion()
    def test_unknown_is_sticky_and_never_retried(self):
        bundle=self.bundle();self.fail=self.root
        with self.assertRaises(TimeoutError):bundle.retire()
        count=len(self.stopped);self.fail=None
        with self.assertRaisesRegex(LedgerError,'CLEANUP_UNKNOWN'):bundle.retire()
        with self.assertRaisesRegex(LedgerError,'CLEANUP_UNKNOWN'):self.adopt(bundle)
        self.assertEqual(count,len(self.stopped))
    def test_noncompleted_refused_before_any_capture(self):
        self.seed(lambda state:state['runs'][self.run_id].update(status='PREPARING'))
        with self.assertRaisesRegex(LedgerError,'COMPLETED_RUN_REQUIRED'):self.bundle()
        self.assertFalse(self.captured)
    def test_changed_attachment_between_captures_blocks_effects(self):
        self.after_capture=lambda:self.seed(lambda state:state['peer_traffic']['connections'][self.reviewer].update(attachment_id='other'))
        with self.assertRaises(LedgerError):self.bundle()
        self.assertFalse(self.stopped)
    def test_closed_graph_and_replaced_native_owner_fence(self):
        bundle=self.bundle();bundle.retire();self.graph.closed=True
        with self.assertRaisesRegex(LedgerError,'OWNER_CHANGED'):self.adopt(bundle)
        self.graph.closed=False;self.recruitment.root=object()
        with self.assertRaisesRegex(LedgerError,'OWNERSHIP_CHANGED'):self.adopt(bundle)
    def test_fresh_human_still_required_after_stop(self):
        bundle=self.bundle();bundle.retire();self.adopt(bundle)
        self.connected=False
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
            self.admission.retire_completed('retire',self.run_id,1,0,session=self.session,reviewer=self.recruitment)
        self.assertIsNone(self.row().get('native_stop'));self.unchanged_completion()
    def test_adoption_cannot_switch_operation_or_run(self):
        bundle=self.bundle();bundle.retire();held=self.adopt(bundle)
        self.assertIs(held,self.adopt(bundle))
        with self.assertRaisesRegex(LedgerError,'ALREADY_ADOPTED'):self.adopt(bundle,'other')
        with self.assertRaisesRegex(LedgerError,'OWNER_REQUIRED'):
            bundle.adopt_completed(self.admission,self.recruitment,'retire','another-run')
    def test_changed_completion_or_revision_refuses_adoption(self):
        bundle=self.bundle();bundle.retire()
        self.seed(lambda state:state['runs'][self.run_id].update(control_revision=1))
        with self.assertRaisesRegex(LedgerError,'SCOPE_CHANGED'):self.adopt(bundle)
    def test_no_observation_adoption_before_verified_exit(self):
        bundle=self.bundle()
        with self.assertRaisesRegex(LedgerError,'CLEANUP_UNKNOWN'):self.adopt(bundle)
    def test_closed_observations_cannot_be_adopted(self):
        bundle=self.bundle();bundle.retire();bundle.close();bundle.close()
        with self.assertRaisesRegex(LedgerError,'OWNER_CHANGED'):self.adopt(bundle)
