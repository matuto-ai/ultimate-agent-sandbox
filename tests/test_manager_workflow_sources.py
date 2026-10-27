"""Real canonical reducers with controlled authority/providers; no native I/O."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from uas.gate_evaluation import snapshot_gate_state
from uas.ledger import LedgerError
from uas.manager_projection import project_hub
from uas.manager_stream import ManagerReadModel, RoomIdentity, RoomStream
from uas.manager_transport import ManagerSession

TIME = '2026-10-27T20:00:00+00:00'


class WorkflowSourceTests(unittest.TestCase):
    def fixture(self, cls):
        fixture = cls(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        return fixture

    def gate_fixture(self):
        from test_gate_decisions import GateDecisionTests
        return self.fixture(GateDecisionTests)

    def test_real_positive_gate_is_retained_not_current_authorization(self):
        fixture = self.gate_fixture()
        fixture.submit()
        snapshot = fixture.ledger.snapshot()
        with patch.object(fixture.hub, 'projection', side_effect=AssertionError('effectful Gate projection')):
            projected = project_hub(snapshot, captured_at=TIME)
        fact = projected['sections']['gate_truth']
        row = next(iter(fact['value'].values()))
        self.assertEqual('passed', row['observed_state'])
        self.assertEqual('unknown', row['state'])
        self.assertEqual('unknown', fact['freshness'])
        self.assertIsNone(fact['observed_at'])
        result = next(iter(snapshot['state']['gate_evaluations'].values()))['result']
        self.assertEqual(result['completed']['sequence'], row['observation_version'])
        self.assertEqual(result['completed']['time'], row['observation_time'])
        self.assertNotIn('Typed evidence', json.dumps(projected))
        self.assertNotIn('gates_satisfied', json.dumps(projected))

    def test_gate_missing_stale_and_supplied_cut_are_literal(self):
        fixture = self.gate_fixture()
        missing = snapshot_gate_state(fixture.ledger.snapshot(), 'alpha')
        self.assertEqual('missing', next(iter(missing['gates'].values()))['state'])
        fixture.submit(); old = fixture.ledger.snapshot()
        fixture.seed(lambda state: state['runs']['run-one'].update(generation=2))
        self.assertEqual('unknown', next(iter(snapshot_gate_state(old, 'alpha')['gates'].values()))['state'])
        current = snapshot_gate_state(fixture.ledger.snapshot(), 'alpha')
        row = next(iter(current['gates'].values()))
        self.assertEqual('stale', row['state']); self.assertEqual('RUN_GENERATION_CHANGED', row['reason'])
        with self.assertRaises(LedgerError): snapshot_gate_state(old, 'other-room')

    def test_actual_pending_forge_evaluation_and_refresh_checkpoint_do_not_claim_remote_ci(self):
        from test_gate_forge_hub import ForgeGateHubTests
        fixture = self.fixture(ForgeGateHubTests)
        cuts = []; fixture.client.before = lambda: cuts.append(fixture.ledger.snapshot())
        fixture.evaluate()
        pending = snapshot_gate_state(cuts[-1], 'alpha')['pending_ci']
        row = next(iter(pending.values()))
        self.assertEqual('evaluation', row['checkpoint']); self.assertEqual('owner-pending', row['state'])
        self.assertEqual('REMOTE_CI_STATE_NOT_OBSERVED', row['reason'])
        self.assertEqual('hub-gate', row['owner'])
        self.assertEqual({}, snapshot_gate_state(fixture.ledger.snapshot(), 'alpha')['pending_ci'])
        fixture.projection()
        row = next(iter(snapshot_gate_state(cuts[-1], 'alpha')['pending_ci'].values()))
        self.assertEqual('refresh', row['checkpoint'])
        before = len(fixture.client.calls)
        snapshot = fixture.ledger.snapshot()
        project_hub(snapshot, captured_at=TIME)
        self.assertEqual(before, len(fixture.client.calls))
        self.assertEqual(snapshot, fixture.ledger.snapshot())

    def test_real_review_submission_and_same_cut_candidate_export_without_broker_calls(self):
        from test_run_review import RunReviewTests
        fixture = self.fixture(RunReviewTests)
        fixture.submit()
        snapshot = fixture.ledger.snapshot()
        before = len(fixture.broker.calls)
        projected = project_hub(snapshot, captured_at=TIME)
        self.assertEqual(before, len(fixture.broker.calls))
        review = projected['sections']['review']['value']['run']
        current = snapshot['state']['run_reviews']['run']['current']
        self.assertEqual(current['submission_id'], review['submission_id'])
        self.assertIsNone(review['review_reference'])
        self.assertEqual('REVIEWING', review['state'])
        self.assertEqual(current['updated_at'], review['updated_at'])
        self.assertEqual(current['target']['head_sha'], projected['sections']['candidate']['value']['run']['candidate_sha'])
        self.assertNotIn('Independent review:', json.dumps(projected))
        fixture.seed(lambda state: state['runs']['run'].update(generation=2))
        self.assertEqual('REVIEWING', project_hub(snapshot, captured_at=TIME)['sections']['review']['value']['run']['state'])
        fresh = project_hub(fixture.ledger.snapshot(), captured_at=TIME)
        self.assertEqual('STALE', fresh['sections']['review']['value']['run']['state'])
        self.assertEqual('stale', fresh['sections']['candidate']['value']['run']['state'])

    def test_review_result_preserves_exact_provider_reference_separate_from_submission(self):
        from test_run_review import RunReviewTests, URL
        fixture = self.fixture(RunReviewTests); fixture.submit()
        fixture.result()
        projected = project_hub(fixture.ledger.snapshot(), captured_at=TIME)
        row = projected['sections']['review']['value']['run']
        self.assertEqual('submit', row['submission_id'])
        self.assertEqual(URL + '1', row['review_reference'])
        self.assertEqual('pass', row['verdict'])
        self.assertEqual('READY_FOR_HUMAN', row['state'])
        self.assertNotIn('review_id', row)

    def test_bound_candidate_is_visible_before_review_and_stale_review_cannot_replace_it(self):
        from test_gate_forge_hub import ForgeGateHubTests
        fixture = self.fixture(ForgeGateHubTests)
        snapshot = fixture.ledger.snapshot()
        projected = project_hub(snapshot, captured_at=TIME)
        candidate = projected['sections']['candidate']['value']['run-one']
        self.assertEqual('bound', candidate['state'])
        self.assertEqual(snapshot['state']['runs']['run-one']['gate_target']['head_sha'], candidate['candidate_sha'])
        self.assertEqual({}, projected['sections']['review']['value'])
        snapshot['state']['run_reviews'] = {'run-one': {'current': {
            'submission_id': 'old-submission', 'generation': 1, 'target': {
                'head_sha': 'f' * 40, 'pull_number': 3}, 'reviewer': None,
            'review_reference': None, 'result': None, 'round': 1,
            'stage': 'REVIEWING', 'reason': None}}}
        changed = project_hub(snapshot, captured_at=TIME)
        self.assertEqual(candidate, changed['sections']['candidate']['value']['run-one'])
        self.assertEqual('STALE', changed['sections']['review']['value']['run-one']['state'])

    def test_gate_projection_replay_and_manager_restart_preserve_unknown_currentness(self):
        fixture = self.gate_fixture(); fixture.submit()
        identity = RoomIdentity('deployment', 'alpha', 'stream')
        source = RoomStream(fixture.ledger, identity)
        path = Path(fixture.temp.name) / 'manager.db'
        model = ManagerReadModel(path); session = ManagerSession(model, identity)
        transfer = source.capture(None, captured_at=TIME)
        session.handle({'kind': 'begin', 'transfer': transfer.begin()})
        session.handle({'kind': 'finish', 'transfer_id': transfer.transfer_id})
        self.assertEqual('unknown', next(iter(model.view(identity, now=TIME)['projection']['sections']['gate_truth']['value'].values()))['state'])
        prior = transfer.cut
        fixture.seed(lambda state: state['runs']['run-one'].update(generation=2))
        transfer = source.capture(prior, captured_at=TIME)
        session.handle({'kind': 'begin', 'transfer': transfer.begin()})
        while prior < transfer.cut:
            page = transfer.page(prior)
            prior = session.handle({'kind': 'events', 'page': page})['room_seq']
        session.handle({'kind': 'finish', 'transfer_id': transfer.transfer_id})
        expected = model.view(identity, now=TIME)['projection']['sections']['gate_truth']
        session.close(); model.close()
        reopened = ManagerReadModel(path); self.addCleanup(reopened.close)
        actual = reopened.view(identity, now=TIME)['projection']['sections']['gate_truth']
        self.assertEqual(expected, actual)
        self.assertEqual('stale', next(iter(actual['value'].values()))['state'])

    def test_review_attention_is_owner_defined_and_does_not_disclose_request_body(self):
        from test_run_review import RunReviewTests
        fixture = self.fixture(RunReviewTests)
        fixture.owner.reviewers = []
        fixture.submit()
        projected = project_hub(fixture.ledger.snapshot(), captured_at=TIME)
        attention = projected['sections']['attention']['value']['run']
        self.assertEqual('ATTENTION', attention['review_state'])
        self.assertEqual('NO_ELIGIBLE_REVIEWER', attention['review_reason'])
        self.assertNotIn('evidence:tests', json.dumps(projected))
