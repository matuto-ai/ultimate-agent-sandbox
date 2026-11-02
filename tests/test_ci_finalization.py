"""Exclude only pre/post-step intervals, not setup, cleanup or execution gaps."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

import ci_runtime_budget as budget


EPOCH = datetime(2026, 11, 2, tzinfo=timezone.utc)


def stamp(seconds):
    return (EPOCH + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


def fixture(name='official-claude-fixture-0', *, finalization=29, offset=0):
    def step(number, name, start, end):
        return {'number': number, 'name': name, 'status': 'completed',
                'conclusion': 'success', 'started_at': stamp(offset + start),
                'completed_at': stamp(offset + end)}
    return {'name': name, 'status': 'completed', 'conclusion': 'success',
            'started_at': stamp(offset), 'completed_at': stamp(offset + 31 + finalization),
            'steps': [step(1, 'Set up job', 5, 6), step(2, 'Run actual tests', 6, 26),
                      step(7, 'Post Run actions/checkout', 26, 30),
                      step(8, 'Complete job', 30, 31)]}


class CIFinalizationTests(unittest.TestCase):
    def test_pre_and_post_step_intervals_are_separate_from_all_our_work(self):
        timing = budget.job_timing(fixture())
        self.assertEqual(26, timing['execution'])
        self.assertEqual(60, timing['wall'])
        self.assertEqual(29, timing['finalization'])
        # Five seconds before setup are separate; four seconds of our cleanup count.
        self.assertEqual(5, timing['provisioning'])
        self.assertEqual(timing['wall'], timing['provisioning'] + timing['execution'] + timing['finalization'])

    def test_longer_pre_step_delay_never_changes_work_or_historical_comparison(self):
        job = fixture()
        job['started_at'] = stamp(-15)
        timing = budget.job_timing(job)
        self.assertEqual(20, timing['provisioning'])
        self.assertEqual(26, timing['execution'])
        self.assertEqual(29, timing['finalization'])
        self.assertEqual(75, timing['wall'])

    def test_no_finalization_and_zero_duration_steps_are_valid(self):
        job = fixture(finalization=0)
        job['steps'][0]['completed_at'] = job['steps'][0]['started_at']
        job['steps'][-1]['started_at'] = job['steps'][-1]['completed_at']
        timing = budget.job_timing(job)
        self.assertEqual(26, timing['execution'])
        self.assertEqual(31, timing['wall'])
        self.assertEqual(0, timing['finalization'])

    def test_real_step_gaps_and_cleanup_are_not_subtracted(self):
        job = fixture()
        job['steps'][1]['completed_at'] = stamp(21)
        job['steps'][2]['started_at'] = stamp(26)  # Five-second inter-step gap stays counted.
        self.assertEqual(26, budget.job_timing(job)['execution'])
        job['steps'][2]['completed_at'] = stamp(40)
        job['steps'][3]['started_at'] = stamp(40)
        job['steps'][3]['completed_at'] = stamp(41)
        self.assertEqual(36, budget.job_timing(job)['execution'])

    def test_current_and_historical_graphs_use_the_same_execution_metric(self):
        lane = 'claude-native.yml'
        current = [fixture(name) for name in sorted(budget.STAGES[lane][0])]
        historic = [fixture('official-claude-fixture')]
        self.assertEqual(26, budget.critical_path(lane, current))
        self.assertEqual(26, budget.critical_path(lane, historic, historical=True))
        # Longer real execution still exceeds the identical historical growth limit.
        slow = deepcopy(current)
        for step in slow[0]['steps'][1:]:
            step['started_at'] = stamp(10 + (datetime.fromisoformat(step['started_at'].replace('Z', '+00:00')) - EPOCH).total_seconds())
            step['completed_at'] = stamp(10 + (datetime.fromisoformat(step['completed_at'].replace('Z', '+00:00')) - EPOCH).total_seconds())
        self.assertGreater(budget.critical_path(lane, slow),
                           budget.allowed_seconds(budget.critical_path(lane, historic, historical=True)))
        # GitHub finalization alone does not make either baseline or candidate slower.
        for job in current + historic:
            job['completed_at'] = stamp(300)
        self.assertEqual(26, budget.critical_path(lane, current))
        self.assertEqual(26, budget.critical_path(lane, historic, historical=True))

    def test_failed_or_cancelled_work_cannot_receive_runtime_acceptance(self):
        lane = 'claude-native.yml'
        for status, conclusion in [('completed', 'failure'), ('completed', 'cancelled'),
                                   ('in_progress', None), ('completed', 'skipped')]:
            jobs = [fixture(name) for name in sorted(budget.STAGES[lane][0])]
            jobs[0].update(status=status, conclusion=conclusion)
            with self.subTest(status=status, conclusion=conclusion), self.assertRaises(budget.BudgetError):
                budget.critical_path(lane, jobs)

    def test_missing_or_invalid_step_inventory_fails_closed(self):
        changes = {
            'missing steps': lambda j: j.pop('steps'),
            'empty steps': lambda j: j.update(steps=[]),
            'null steps': lambda j: j.update(steps=None),
            'missing setup': lambda j: j['steps'].pop(0),
            'missing complete': lambda j: j['steps'].pop(),
            'step after complete': lambda j: j['steps'].append(dict(j['steps'][-1], number=9, name='Later cleanup')),
            'setup not successful': lambda j: j['steps'][0].update(conclusion='skipped'),
            'complete not successful': lambda j: j['steps'][-1].update(conclusion='skipped'),
            'failed step': lambda j: j['steps'][1].update(conclusion='failure'),
            'cancelled step': lambda j: j['steps'][1].update(conclusion='cancelled'),
            'unfinished step': lambda j: j['steps'][1].update(status='in_progress'),
            'missing step status': lambda j: j['steps'][1].pop('status'),
            'duplicate step number': lambda j: j['steps'][1].update(number=1),
            'descending step number': lambda j: j['steps'][2].update(number=1),
            'missing step number': lambda j: j['steps'][1].pop('number'),
            'boolean step number': lambda j: j['steps'][0].update(number=True),
            'string step number': lambda j: j['steps'][1].update(number='2'),
            'null step': lambda j: j['steps'].__setitem__(1, None),
            'non-object boundary': lambda j: j['steps'].__setitem__(0, 'Set up job'),
        }
        for name, change in changes.items():
            job = fixture()
            change(job)
            with self.subTest(name=name), self.assertRaises(budget.BudgetError):
                budget.job_timing(job)

    def test_missing_invalid_naive_or_out_of_range_timestamps_fail_closed(self):
        changes = {
            'missing start': lambda j: j.pop('started_at'),
            'missing end': lambda j: j.pop('completed_at'),
            'null start': lambda j: j.update(started_at=None),
            'bad end': lambda j: j.update(completed_at='not-a-time'),
            'naive job start': lambda j: j.update(started_at='2026-11-02T00:00:00'),
            'naive step start': lambda j: j['steps'][1].update(started_at='2026-11-02T00:00:06'),
            'naive step end': lambda j: j['steps'][1].update(completed_at='2026-11-02T00:00:26'),
            'missing step start': lambda j: j['steps'][1].pop('started_at'),
            'missing step end': lambda j: j['steps'][1].pop('completed_at'),
            'step before job': lambda j: j['steps'][0].update(started_at=stamp(-1)),
            'step after job': lambda j: j['steps'][-1].update(completed_at=stamp(61)),
            'inverted step': lambda j: j['steps'][1].update(completed_at=stamp(5)),
            'overlapping steps': lambda j: j['steps'][2].update(started_at=stamp(25)),
            'inverted job': lambda j: j.update(completed_at=stamp(-1)),
            'zero execution': lambda j: j.update(started_at=stamp(31)),
        }
        for name, change in changes.items():
            job = fixture()
            change(job)
            with self.subTest(name=name), self.assertRaises(budget.BudgetError):
                budget.job_timing(job)

    def test_skipped_non_boundary_step_is_valid_with_explicit_timestamps(self):
        job = fixture()
        job['steps'][1].update(conclusion='skipped', completed_at=stamp(6))
        self.assertEqual(26, budget.job_timing(job)['execution'])

    def test_diagnostics_retain_wall_path_span_and_each_finalization_gap(self):
        lane = 'claude-native.yml'
        jobs = [fixture(name, offset=index * 10)
                for index, name in enumerate(sorted(budget.STAGES[lane][0]))]
        diagnostics = {}
        self.assertEqual(26, budget.critical_path(lane, jobs, diagnostics=diagnostics))
        self.assertEqual(60, diagnostics['wall_path'])
        self.assertEqual(70, diagnostics['span'])
        self.assertEqual({job['name'] for job in jobs}, set(diagnostics['jobs']))
        for values in diagnostics['jobs'].values():
            self.assertEqual({'provisioning': 5, 'execution': 26, 'wall': 60, 'finalization': 29}, values)

    def test_two_stage_path_keeps_cleanup_for_each_stage_without_finalization(self):
        lane = 'validate.yml'
        jobs = [fixture(name, offset=index * 40)
                for index, stage in enumerate(budget.STAGES[lane]) for name in stage]
        diagnostics = {}
        self.assertEqual(52, budget.critical_path(lane, jobs, diagnostics=diagnostics))
        self.assertEqual(120, diagnostics['wall_path'])
        self.assertEqual(100, diagnostics['span'])


class CIFirstAttemptTests(unittest.TestCase):
    def test_only_first_attempt_jobs_are_requested(self):
        row = dict(run_id=123, run_attempt=1)
        with patch.object(budget, 'api', return_value=dict(total_count=1, jobs=[row])) as api:
            self.assertEqual([row], budget.run_jobs('owner/repo', 123))
        api.assert_called_once_with('owner/repo', 'actions/runs/123/attempts/1/jobs?per_page=100')

    def test_second_attempt_and_coercible_identities_are_rejected(self):
        for run_id, attempt in [(123, 2), (123, True), ('123', 1), (True, 1)]:
            with self.subTest(run_id=run_id, attempt=attempt):
                with patch.object(budget, 'api', return_value=dict(
                        total_count=1, jobs=[dict(run_id=run_id, run_attempt=attempt)])):
                    with self.assertRaises(budget.BudgetError):
                        budget.run_jobs('owner/repo', 123)

    def test_rerun_and_legacy_variable_cannot_override_cancelled_first_attempt(self):
        lane = 'claude-native.yml'
        jobs = [fixture(name) for name in sorted(budget.STAGES[lane][0])]
        for job in jobs:
            job.update(run_id=123, run_attempt=1)
        jobs[0]['conclusion'] = 'cancelled'
        def api(repo, path):
            if path == 'actions/runs/123':
                return dict(path='.github/workflows/claude-native.yml', event='push', run_attempt=2)
            self.assertEqual('actions/runs/123/attempts/1/jobs?per_page=100', path)
            return dict(total_count=len(jobs), jobs=jobs)
        with patch.dict('os.environ', {'CI_RUNTIME_RECOVERY_APPROVAL': '{"attempt":2}'}):
            with patch.object(budget, 'api', side_effect=api), patch.object(budget, 'baseline') as baseline:
                with self.assertRaisesRegex(budget.BudgetError, 'did not complete successfully'):
                    budget.check('owner/repo', lane, 'main', 'a' * 40, 123)
                baseline.assert_not_called()
