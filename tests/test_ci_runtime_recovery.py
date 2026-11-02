"""Explicit recovery is bounded to one approved second attempt, never a baseline."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import ci_runtime_budget as budget


REPO = 'matuto-ai/ultimate-agent-sandbox'
SHA = 'a' * 40
RUN = 999


def job(name, identity, attempt=1, seconds=10):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stamp = lambda value: (start + timedelta(seconds=value)).isoformat()
    return dict(id=identity, name=name, run_id=RUN, run_attempt=attempt,
                head_sha=SHA, status='completed', conclusion='success',
                started_at=stamp(0), completed_at=stamp(seconds + 2), steps=[
        dict(name='Set up job', number=1, status='completed', conclusion='success',
             started_at=stamp(0), completed_at=stamp(1)),
        dict(name='Actual tests and cleanup', number=2, status='completed', conclusion='success',
             started_at=stamp(1), completed_at=stamp(seconds)),
        dict(name='Complete job', number=3, status='completed', conclusion='success',
             started_at=stamp(seconds), completed_at=stamp(seconds))])


def evidence():
    names = sorted(budget.recovery_functional_names() | budget.RECOVERY_ACCOUNTING | {'verify'})
    original = [job(name, number) for number, name in enumerate(names, 1)]
    original.append(dict(id=100, name='pi-durable-fit', run_id=RUN, run_attempt=1,
                         head_sha=SHA, status='completed', conclusion='skipped', steps=[]))
    cancelled = []
    for value in original:
        if value['name'] in ('forge-broker-smoke', 'manager-field-notes'):
            value['conclusion'] = 'cancelled'
            cancelled.append(value['id'])
        if value['name'] in ('validate runtime budget', 'verify'):
            value['conclusion'] = 'failure'
    approval = dict(version=1, repository=REPO, run_id=RUN, head_sha=SHA, attempt=2,
                    cancelled_job_ids=cancelled, approval_reference='Sentinel_explicit_permission')
    replacement = deepcopy(original)
    for value in replacement:
        value['run_attempt'] = 2
        value['id'] += 1000
        if value['name'] != 'pi-durable-fit':
            value['conclusion'] = 'success'
    current = dict(id=RUN, head_sha=SHA, run_attempt=2, path='.github/workflows/verify.yaml',
                   event='pull_request', head_branch='feature', status='in_progress', conclusion=None)
    old_run = dict(current, run_attempt=1, status='completed', conclusion='failure')
    return approval, original, replacement, current, old_run


class RuntimeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.approval, self.original, self.replacement, self.current, self.old_run = evidence()

    def api(self, repo, path):
        self.assertEqual(repo, REPO)
        responses = {
            f'actions/runs/{RUN}': self.current,
            f'actions/runs/{RUN}/attempts/1': self.old_run,
            f'actions/runs/{RUN}/attempts/1/jobs?per_page=100':
                dict(total_count=len(self.original), jobs=self.original),
            f'actions/runs/{RUN}/attempts/2/jobs?per_page=100':
                dict(total_count=len(self.replacement), jobs=self.replacement)}
        self.assertIn(path, responses)
        return deepcopy(responses[path])

    def check(self, workflow='validate.yml', approval=True):
        with patch.object(budget, 'api', side_effect=self.api), patch.object(
                budget, 'baseline', return_value=(100, [(1, 'b' * 40, 100)])):
            return budget.check(REPO, workflow, 'main', 'b' * 40, RUN,
                                recovery_approval=self.approval if approval else None)

    def test_strict_record_and_default(self):
        self.assertIsNone(budget.parse_recovery_approval(''))
        self.assertEqual(budget.parse_recovery_approval(json.dumps(self.approval)), self.approval)
        for raw in ('{}', '[]', 'null', '{', 'x' * 4097,
                    '{"version":1,"version":1}', json.dumps(dict(self.approval, extra=True))):
            with self.subTest(raw=raw[:40]), self.assertRaises(budget.BudgetError):
                budget.parse_recovery_approval(raw)
        invalid = dict(version=True, attempt=3, repository='../wrong', head_sha='short',
                       run_id=True, cancelled_job_ids=[1, 1], approval_reference='')
        for key, value in invalid.items():
            with self.subTest(key=key), self.assertRaises(budget.BudgetError):
                budget.parse_recovery_approval(json.dumps(dict(self.approval, **{key: value})))
        for value in ([], [1], [1, 2, 3], [True, 2], [0, 2]):
            with self.subTest(ids=value), self.assertRaises(budget.BudgetError):
                budget.parse_recovery_approval(json.dumps(dict(self.approval, cancelled_job_ids=value)))

    def test_approved_complete_second_attempt_and_original_not_mutated(self):
        original = deepcopy(self.original)
        for workflow in budget.STAGES:
            with self.subTest(workflow=workflow):
                self.assertIn('explicitly approved attempt 2', self.check(workflow))
        self.assertEqual(self.original, original)
        self.assertIn('Original GitHub conclusions remain unchanged', self.check())

    def test_absent_approval_does_not_use_green_second_attempt(self):
        with self.assertRaises(budget.BudgetError):
            self.check(approval=False)

    def test_wrong_scope_or_attempt_is_rejected(self):
        for key, value in dict(repository='other/repo', run_id=RUN+1, head_sha='c'*40).items():
            saved = deepcopy(self.approval)
            self.approval[key] = value
            with self.subTest(key=key), self.assertRaises(budget.BudgetError):
                self.check()
            self.approval = saved
        for key, value in dict(run_attempt=3, path='.github/workflows/other.yml',
                               event='push', head_branch='other').items():
            saved = deepcopy(self.current)
            self.current[key] = value
            with self.subTest(key=key), self.assertRaises(budget.BudgetError):
                self.check()
            self.current = saved

    def test_original_cancellation_requires_all_successful_steps_and_positive_finalization(self):
        index = next(i for i, value in enumerate(self.original)
                     if value['name'] == 'forge-broker-smoke')
        mutations = (
            lambda value: value['steps'][1].update(conclusion='failure'),
            lambda value: value['steps'][1].update(conclusion='skipped'),
            lambda value: value['steps'].pop(),
            lambda value: value.update(completed_at=value['steps'][-1]['completed_at']),
            lambda value: value.update(status='in_progress'),
            lambda value: value['steps'][-1].update(completed_at='invalid'),
            lambda value: value.update(conclusion='success'))
        for mutate in mutations:
            saved = deepcopy(self.original)
            mutate(self.original[index])
            with self.subTest(mutation=mutate), self.assertRaises(budget.BudgetError):
                self.check()
            self.original = saved

    def test_other_original_failure_or_cancellation_cannot_be_hidden(self):
        index = next(i for i, value in enumerate(self.original) if value['name'] == 'unit-slow')
        for conclusion in ('failure', 'cancelled', 'skipped'):
            saved = deepcopy(self.original)
            self.original[index]['conclusion'] = conclusion
            with self.subTest(conclusion=conclusion), self.assertRaises(budget.BudgetError):
                self.check()
            self.original = saved
        self.approval['cancelled_job_ids'][0] = 999999
        with self.assertRaises(budget.BudgetError):
            self.check()

    def test_missing_duplicate_extra_and_mixed_replacement_jobs_fail_closed(self):
        mutations = (
            lambda rows: rows.pop(0),
            lambda rows: rows.append(deepcopy(rows[0])),
            lambda rows: rows.append(job('unexpected', 9000, attempt=2)),
            lambda rows: rows[0].update(run_attempt=1),
            lambda rows: rows[0].update(head_sha='c'*40),
            lambda rows: rows[0].update(run_id=RUN+1),
            lambda rows: rows[0].update(conclusion='failure'))
        for mutate in mutations:
            saved = deepcopy(self.replacement)
            mutate(self.replacement)
            with self.subTest(mutation=mutate), self.assertRaises(budget.BudgetError):
                self.check()
            self.replacement = saved
        self.replacement = [row for row in self.replacement
                            if row['name'] in ('forge-broker-smoke', 'manager-field-notes')]
        with self.assertRaises(budget.BudgetError):
            self.check()

    def test_original_slowdown_and_replacement_slowdown_each_fail(self):
        for attribute in ('original', 'replacement'):
            rows = getattr(self, attribute)
            saved = deepcopy(rows)
            index = next(i for i, value in enumerate(rows) if value['name'] == 'unit-slow')
            previous = rows[index]
            rows[index] = job('unit-slow', previous['id'], previous['run_attempt'], seconds=120)
            with self.subTest(attribute=attribute), self.assertRaises(budget.BudgetError):
                self.check()
            setattr(self, attribute, saved)

    def test_early_native_gate_checks_own_lane_but_final_main_requires_all(self):
        sibling = next(value for value in self.replacement if value['name'] == 'manager-field-notes')
        sibling.update(status='in_progress', conclusion=None)
        self.assertIn('explicitly approved attempt 2', self.check('pi-native.yml'))
        with self.assertRaises(budget.BudgetError):
            self.check()
        native = next(value for value in self.replacement
                      if value['name'] == 'pi-native / official-pi-native-0')
        native.update(status='in_progress', conclusion=None)
        with self.assertRaises(budget.BudgetError):
            self.check('pi-native.yml')

    def test_native_accounting_and_durable_applicability_cannot_be_skipped(self):
        native = next(value for value in self.replacement
                      if value['name'] == 'pi-native / pi-native runtime budget')
        native['conclusion'] = 'failure'
        with self.assertRaises(budget.BudgetError):
            self.check()
        native['conclusion'] = 'success'
        index = next(i for i, value in enumerate(self.replacement)
                     if value['name'] == 'pi-durable-fit')
        self.replacement[index] = job(budget.RECOVERY_DURABLE, 5000, attempt=2)
        with self.assertRaises(budget.BudgetError):
            self.check()

    def test_historical_baselines_still_fetch_first_attempt_only(self):
        runs = [dict(id=number, head_sha=f'{number:040x}', run_attempt=2,
                     path='.github/workflows/verify.yaml', event='push', head_branch='main',
                     status='completed', conclusion='success') for number in range(1, 6)]
        calls = []
        def historical_api(repo, path):
            calls.append(path)
            if path.startswith('actions/runs?'):
                return {'workflow_runs': runs}
            number = int(path.split('/')[2])
            self.assertIn('/attempts/1', path)
            if path.endswith('/jobs?per_page=100'):
                value = job('unit-slow', number)
                value['run_id'] = number
                return dict(total_count=1, jobs=[value])
            return dict(runs[number-1], run_attempt=1)
        with patch.object(budget, 'api', side_effect=historical_api), patch.object(
                budget, 'ancestor', return_value=True), patch.object(
                budget, 'critical_path', return_value=100):
            value, samples = budget.baseline(REPO, 'validate.yml', 'main', SHA, RUN)
        self.assertEqual(value, 100)
        self.assertEqual(len(samples), 5)
        self.assertFalse(any('/attempts/2' in path for path in calls))
        self.assertEqual(sum('/attempts/1/jobs' in path for path in calls), 5)

    def test_recovery_wiring_is_optional_and_final_accounting_waits_all_lanes(self):
        root = Path(__file__).resolve().parents[1]
        for workflow in ('verify.yaml', 'pi-native.yml', 'claude-native.yml'):
            source = (root / '.github/workflows' / workflow).read_text()
            self.assertIn('CI_RUNTIME_RECOVERY_APPROVAL:', source)
            self.assertIn('vars.CI_RUNTIME_RECOVERY_APPROVAL', source)
        source = (root / '.github/workflows/verify.yaml').read_text()
        accounting = source.split('  runtime-budget:', 1)[1].split('  pi-native:', 1)[0]
        needs = next(line for line in accounting.splitlines() if line.strip().startswith('needs:'))
        for name in ('pi-native', 'claude-native', 'pi-durable-fit'):
            self.assertIn(name, needs)


if __name__ == '__main__':
    unittest.main()
