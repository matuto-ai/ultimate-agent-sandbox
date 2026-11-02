"""Finite nonfunctional skip evidence, never a functional-test exemption."""
from copy import deepcopy
from pathlib import Path
import unittest

import ci_runtime_budget as budget
from test_ci_runtime_recovery import job


def steps_job(name, results):
    value = job(name, 7)
    middle = value['steps'][1]
    value['steps'] = [value['steps'][0]] + [dict(middle, name=step, number=number,
        conclusion=result, started_at=middle['started_at'], completed_at=middle['started_at'])
        for number, (step, result) in enumerate(results, 2)] + [dict(value['steps'][-1], number=len(results)+2)]
    return value


def cache_job(hit=True):
    results = [(name, 'success') for name in sorted(budget.RECOVERY_CACHE_PREREQUISITES)]
    results += [(budget.RECOVERY_CACHE_PROOF, 'success' if hit else 'skipped'),
                (budget.RECOVERY_CACHE_SAVE, 'skipped' if hit else 'success')]
    return steps_job('claude-native / official-claude-fixture-1', results)


def unit_job(name):
    test = ('Validate successor interfaces' if name == 'validate' else
            'Validate measured slow unit partition' if name == 'unit-slow' else
            'Validate measured integration unit partition')
    results = [(step, 'success') for step in ('Detect test applicability',
               'Install pinned Python dependencies', test)]
    if name == 'validate':
        results += [('Check account-free local CLI process lifecycle', 'success')]
    return steps_job(name, results + [('Report tests not applicable', 'skipped')])


class RecoveryStepProofTests(unittest.TestCase):
    def test_warm_and_cold_cache_require_affirmative_branch(self):
        for hit in (True, False):
            for partition in (0, 1):
                value = cache_job(hit)
                value['name'] = f'claude-native / official-claude-fixture-{partition}'
                budget.job_timing(value)
                budget.require_successful_recovery_steps(value)

    def test_missing_failed_duplicate_or_skipped_cache_evidence_rejected(self):
        for hit in (True, False):
            good = cache_job(hit)
            required = budget.RECOVERY_CACHE_PREREQUISITES | {budget.RECOVERY_CACHE_PROOF, budget.RECOVERY_CACHE_SAVE}
            for name in required:
                for mutation in ('missing', 'failure', 'duplicate'):
                    value = deepcopy(good)
                    step = next(step for step in value['steps'] if step['name'] == name)
                    if mutation == 'missing': value['steps'].remove(step)
                    elif mutation == 'failure': step['conclusion'] = 'failure'
                    else: value['steps'].append(deepcopy(step))
                    with self.subTest(hit=hit, name=name, mutation=mutation), self.assertRaises(budget.BudgetError):
                        budget.require_successful_recovery_steps(value)
            for name in budget.RECOVERY_CACHE_PREREQUISITES | {budget.RECOVERY_CACHE_PROOF, budget.RECOVERY_CACHE_SAVE}:
                value = deepcopy(good)
                step = next(step for step in value['steps'] if step['name'] == name)
                if step['conclusion'] == 'skipped': continue
                step['conclusion'] = 'skipped'
                with self.subTest(hit=hit, skipped=name), self.assertRaises(budget.BudgetError):
                    budget.require_successful_recovery_steps(value)

    def test_cache_branch_must_be_mutually_exclusive(self):
        for result in ('success', 'skipped'):
            value = cache_job()
            for step in value['steps']:
                if step['name'] in {budget.RECOVERY_CACHE_PROOF, budget.RECOVERY_CACHE_SAVE}:
                    step['conclusion'] = result
            with self.subTest(result=result), self.assertRaises(budget.BudgetError):
                budget.require_successful_recovery_steps(value)

    def test_cache_exemption_not_available_to_other_jobs_or_unknown_steps(self):
        for name in ('official-claude-fixture-1', 'claude-native / official-claude-fixture-2', 'validate'):
            value = cache_job(); value['name'] = name
            with self.subTest(name=name), self.assertRaises(budget.BudgetError):
                budget.require_successful_recovery_steps(value)
        value = cache_job()
        value['steps'].insert(-1, dict(value['steps'][1], name='Unreviewed optional step', conclusion='skipped'))
        with self.assertRaises(budget.BudgetError): budget.require_successful_recovery_steps(value)

    def test_each_unit_report_skip_requires_actual_matching_tests_and_install(self):
        for name in budget.UNIT_JOBS:
            value = unit_job(name)
            budget.require_successful_recovery_steps(value)
            for index in range(1, len(value['steps'])-2):
                broken = deepcopy(value); broken['steps'][index]['conclusion'] = 'skipped'
                with self.subTest(name=name, skipped=broken['steps'][index]['name']), self.assertRaises(budget.BudgetError):
                    budget.require_successful_recovery_steps(broken)
        value = unit_job('unit-slow'); value['name'] = 'unit-archive'
        with self.assertRaises(budget.BudgetError): budget.require_successful_recovery_steps(value)

    def test_original_normalization_accepts_proof_but_preserves_original(self):
        value = cache_job(); value['conclusion'] = 'cancelled'
        original = deepcopy(value)
        approval = dict(cancelled_job_ids=[7], run_id=value['run_id'], head_sha=value['head_sha'])
        copied = budget.normalize_original_cancellations([value], approval)
        self.assertEqual(copied[0]['conclusion'], 'success')
        self.assertEqual(value, original)
        value['steps'][-1]['conclusion'] = 'skipped'
        with self.assertRaises(budget.BudgetError): budget.normalize_original_cancellations([value], approval)

    def test_workflow_cache_hit_proof_checks_actual_output_and_does_not_replace_tests(self):
        source = (Path(__file__).resolve().parents[1]/'.github/workflows/claude-native.yml').read_text()
        proof = source.split('      - name: '+budget.RECOVERY_CACHE_PROOF+'\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn("if: ${{ steps.claude-npm-cache.outputs.cache-hit == 'true' }}", proof)
        self.assertIn('CACHE_HIT: ${{ steps.claude-npm-cache.outputs.cache-hit }}', proof)
        self.assertIn('test "$CACHE_HIT" = true', proof)
        self.assertIn('Actual Claude CLI against loopback protocol fixture, never upstream', source)
