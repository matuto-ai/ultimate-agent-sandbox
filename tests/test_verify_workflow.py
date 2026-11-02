"""The single required check includes every automatic lane, not just unit tests."""
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import ci_runtime_budget as budget
import test_vm_ci_policy

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github/workflows/verify.yaml').read_text()


class VerifyWorkflowTests(unittest.TestCase):
    def gate(self, jobs):
        block = WORKFLOW.split('          python3 - <<\'PYTHON\'\n', 1)[1].split('          PYTHON', 1)[0]
        code = '\n'.join(line[10:] for line in block.splitlines())
        return subprocess.run([sys.executable, '-c', code], env={**os.environ, 'RESULTS': json.dumps(jobs)},
                              capture_output=True, text=True).returncode

    def results(self, applicable='true'):
        jobs = {name: {'result': 'success'} for name in
                ('validate', 'runtime-budget', 'pi-native', 'claude-native', 'pi-durable-fit')}
        jobs['validate']['outputs'] = {'durable_fit': applicable}
        if applicable == 'false':
            jobs['pi-durable-fit']['result'] = 'skipped'
        return jobs

    def test_final_gate_is_fail_closed_with_one_explicit_path_exemption(self):
        self.assertEqual(0, self.gate(self.results()))
        self.assertEqual(0, self.gate(self.results('false')))
        for name in self.results():
            for result in ('failure', 'cancelled', 'skipped', 'unknown'):
                jobs = self.results()
                jobs[name]['result'] = result
                self.assertNotEqual(0, self.gate(jobs), (name, result))
        for defect in ('missing', 'unexpected', 'missing-applicability', 'unexplained-success'):
            jobs = self.results('false')
            if defect == 'missing': del jobs['runtime-budget']
            elif defect == 'unexpected': jobs['other'] = {'result': 'success'}
            elif defect == 'missing-applicability': jobs['validate']['outputs'] = {}
            else: jobs['pi-durable-fit']['result'] = 'success'
            self.assertNotEqual(0, self.gate(jobs), defect)

    def test_durable_fit_applicability_handles_source_docs_workflow_and_unknown_diff(self):
        start = WORKFLOW.index('          set -euo pipefail')
        end = WORKFLOW.index('\n      # Give every', start)
        code = '\n'.join(line[10:] for line in WORKFLOW[start:end].splitlines())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], text=True).strip()
            git('init', '-q')
            git('config', 'user.name', 'CI fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (root / 'seed').write_text('base')
            git('add', '.')
            git('commit', '-qm', 'base')
            for path, expected in [('docs/help.md', 'false'), ('uas/other.py', 'false'),
                                   ('uas/ledger.py', 'true'), ('spike/pi-durable-fit/test.js', 'true'),
                                   ('.github/workflows/verify.yaml', 'true')]:
                base = git('rev-parse', 'HEAD')
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('changed')
                git('add', '.')
                git('commit', '-qm', 'change')
                output = root / 'outputs'
                output.write_text('')
                result = subprocess.run(['bash', '-c', code], cwd=root, capture_output=True, text=True,
                                        env={**os.environ, 'EVENT_NAME': 'pull_request', 'PR_BASE_SHA': base,
                                             'GITHUB_OUTPUT': str(output)})
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn('durable_fit=' + expected, output.read_text())
            output.write_text('')
            result = subprocess.run(['bash', '-c', code], cwd=root, capture_output=True, text=True,
                                    env={**os.environ, 'EVENT_NAME': 'push', 'PUSH_BEFORE_SHA': '0' * 40,
                                         'GITHUB_OUTPUT': str(output)})
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('durable_fit=true', output.read_text())

    def test_all_automatic_workflows_feed_verify_without_duplicate_triggers(self):
        self.assertFalse((ROOT / '.github/workflows/validate.yml').exists())
        self.assertIn('\n  verify:\n', WORKFLOW)
        gate = WORKFLOW.split('\n  verify:\n', 1)[1]
        self.assertIn('always()', gate)
        self.assertNotIn('continue-on-error', gate)
        for name in ('pi-native', 'claude-native', 'pi-durable-fit'):
            text = (ROOT / f'.github/workflows/{name}.yml').read_text()
            self.assertEqual('  workflow_call:', text.split('\non:\n', 1)[1].split('\npermissions:', 1)[0].strip('\n'))
            self.assertNotIn('\nconcurrency:', text)  # no self-cancellation of the caller
            self.assertIn(f'uses: ./.github/workflows/{name}.yml', WORKFLOW)
        self.assertIn("if: ${{ needs.validate.outputs.durable_fit == 'true' }}", WORKFLOW)

    def test_unified_runtime_scopes_preserve_exact_lane_inventory(self):
        helper = test_vm_ci_policy.RuntimeBudgetTests()
        jobs = helper.jobs('validate.yml')
        for lane in ('pi-native.yml', 'claude-native.yml'):
            prefix = lane.removesuffix('.yml') + ' / '
            jobs.extend(dict(job, name=prefix + job['name']) for job in helper.jobs(lane))
            jobs.append({'name': prefix + lane.removesuffix('.yml') + ' runtime budget'})
        jobs.extend([{'name': 'verify'}, {'name': 'pi-durable-fit / model-free-fit'},
                     {'name': 'validate runtime budget'}])
        for lane in budget.STAGES:
            selected = budget.scoped_jobs(lane, jobs, '.github/workflows/verify.yaml')
            self.assertEqual(80 if lane == 'validate.yml' else 40, budget.critical_path(lane, selected))
            broken = [dict(job) for job in jobs]
            target = 'validate' if lane == 'validate.yml' else lane.removesuffix('.yml') + ' / ' + next(iter(budget.STAGES[lane][0]))
            next(job for job in broken if job['name'] == target)['conclusion'] = 'failure'
            with self.assertRaises(budget.BudgetError):
                budget.critical_path(lane, budget.scoped_jobs(lane, broken, '.github/workflows/verify.yaml'))
        with self.assertRaises(budget.BudgetError):
            budget.critical_path('validate.yml', budget.scoped_jobs('validate.yml', jobs + [{'name': 'unmeasured'}], '.github/workflows/verify.yaml'))

    def test_native_repartition_keeps_only_complete_historical_graphs(self):
        helper = test_vm_ci_policy.RuntimeBudgetTests()
        for lane, names in (
                ('pi-native.yml', ['official-pi-native-0', 'official-pi-native-1', 'official-pi-native-2']),
                ('claude-native.yml', ['official-claude-fixture'])):
            template = helper.jobs(lane)[0]
            old = [dict(template, name=name) for name in names]
            self.assertEqual(40, budget.critical_path(lane, old, historical=True))
            with self.assertRaises(budget.BudgetError):
                budget.critical_path(lane, old)
            for invalid in (old + old[:1], old + [dict(template, name='unexpected')], old[:-1]):
                with self.assertRaises(budget.BudgetError):
                    budget.critical_path(lane, invalid, historical=True)

    def test_rename_keeps_old_baseline_and_new_current_workflow_identity(self):
        helper = test_vm_ci_policy.RuntimeBudgetTests()
        for lane in budget.STAGES:
            routes = helper.evidence(workflow=lane, current=40, previous=40)
            routes['actions/runs/30']['path'] = '.github/workflows/verify.yaml'
            if lane != 'validate.yml':
                prefix = lane.removesuffix('.yml') + ' / '
                jobs = routes['actions/runs/30/attempts/1/jobs?per_page=100']['jobs']
                for job in jobs: job['name'] = prefix + job['name']
            self.assertIn('baseline median:', helper.check(routes, lane))
            # New unified main evidence also contributes, without a baseline reset.
            row = routes['actions/runs?event=push&branch=main&per_page=100']['workflow_runs'][0]
            row['path'] = '.github/workflows/verify.yaml'
            if lane != 'validate.yml':
                for job in routes['actions/runs/20/attempts/1/jobs?per_page=100']['jobs']:
                    job['name'] = prefix + job['name']
            self.assertIn('run 20', helper.check(routes, lane))
