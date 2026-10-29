"""Real ledger/RunReview delegation, controlled identity/Gates/Broker facts.

Run in ordinary repository CI. This is not native/provider integration. Reuse
existing review fixtures rather than duplicate the review state machine here.
"""
from copy import deepcopy
from types import SimpleNamespace
import unittest
import test_run_review as fixture
from uas.lifecycle_scenario import LifecycleScenario
from uas.workstation_peer import AdmittedPeerDispatcher


class LifecycleScenarioOwnerTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.RunReviewTests('test_submission_uses_real_peer_outbox_and_exact_retry')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        f = self.f
        dispatcher = object.__new__(AdmittedPeerDispatcher)
        dispatcher.hub = f.peer
        dispatcher.reviews = f.owner
        # Explicit controlled identity; no fabricated live admission claim.
        dispatcher.reviewer_authority = f.identity.dispatcher.reviewer_authority
        f.identity.dispatcher = dispatcher
        f.gates.binding = SimpleNamespace(room_id='room', project_id='project', repository='owner/repo')
        self.scenario = LifecycleScenario(f.owner, dispatcher, 'run', 1)
        self.auth = {'human': fixture.HUMAN, 'authorize': lambda: f.allowed, 'admission_operation': 'admission'}

    def test_real_owner_unknown_comment_reconciles_without_duplicate(self):
        f = self.f
        f.submit(); f.result(); f.broker.comment_status = 'unknown'
        payload = {'submission_id': 'submit', 'target': deepcopy(fixture.TARGET), 'body': 'Human return'}
        first = self.scenario.request_changes('changes', payload, **self.auth)
        self.assertEqual(first['status'], 'unknown')
        self.assertEqual(self.scenario.request_changes('changes', payload, **self.auth), first)
        f.broker.comment_status = 'confirmed'
        result = self.scenario.reconcile_changes('changes', 'read1', **self.auth)
        self.assertEqual(result['status'], 'confirmed')
        count = len(f.state()['peer_traffic']['traffic'])
        self.assertEqual(self.scenario.reconcile_changes('changes', 'read1', **self.auth), result)
        self.assertEqual(len(f.state()['peer_traffic']['traffic']), count)
        self.assertEqual(len([x for x in f.broker.calls if x[0] == 'comment']), 1)
        self.assertFalse(self.scenario.report()['real_lifecycle_qualified'])

    def test_real_owner_merge_observation_preserves_candidate_and_terminal_retry(self):
        f = self.f
        f.submit(); f.result(); f.broker.merged = True
        result = self.scenario.observe_completion('finish', 'submit', **self.auth)
        self.assertEqual(result['stage'], 'COMPLETED')
        self.assertEqual(self.scenario.observe_completion('finish', 'submit', **self.auth), result)
        report = self.scenario.report()
        self.assertEqual(report['run_status'], 'CLOSED')
        self.assertEqual(report['completion']['candidate_sha'], 'a'*40)
        self.assertEqual(report['completion']['integration_sha'], 'c'*40)
        self.assertEqual(report['completion']['merger_id'], 7)
        self.assertEqual(report['status'], 'blocked')
