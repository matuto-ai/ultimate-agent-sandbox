"""Accounting recovery accepts typed, immutable evidence, never arbitrary failure."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
import os
import subprocess
import unittest
from unittest.mock import patch

import ci_runtime_budget as budget
from test_ci_runtime_recovery import evidence, REPO, RUN, SHA


class AccountingReceiptTests(unittest.TestCase):
    def setUp(self):
        self.approval, self.jobs, _, _, _ = evidence()
        self.job = next(row for row in self.jobs if row['name'] == 'validate runtime budget')
        self.receipt = dict(version=1, repository=REPO, run_id=RUN, head_sha=SHA,
                            attempt=1, workflow='validate.yml', reason='functional_cancellation',
                            cancelled_job_ids=self.approval['cancelled_job_ids'])

    def verify(self, raw=None):
        if raw is None:
            raw = '2026-11-02T19:00:00.000Z ' + budget.RECEIPT_PREFIX + json.dumps(self.receipt)
        with patch.object(budget, 'accounting_log', return_value=raw):
            budget.verify_original_accounting(REPO, self.jobs, self.approval)

    def test_exact_receipts_and_original_conclusions_remain_unchanged(self):
        before = deepcopy(self.jobs)
        self.verify()
        self.assertEqual(before, self.jobs)
        self.receipt.update(reason='evidence_unavailable', cancelled_job_ids=[])
        self.job['conclusion'] = 'cancelled'
        self.verify()
        self.receipt['reason'] = 'passed'
        self.job['steps'][1]['conclusion'] = 'success'
        self.verify()

    def test_untrusted_or_ambiguous_receipt_text_rejected(self):
        valid = budget.RECEIPT_PREFIX + json.dumps(self.receipt)
        for raw in ('', 'echo ' + valid, valid + '\n' + valid,
                    budget.RECEIPT_PREFIX + '{', budget.RECEIPT_PREFIX + 'null',
                    budget.RECEIPT_PREFIX + 'x' * 1025,
                    valid + '\n' + budget.RECEIPT_PREFIX + 'x' * 1025,
                    budget.RECEIPT_PREFIX + json.dumps(self.receipt)[:-1] + ',"version":1}'):
            with self.subTest(raw=raw[:50]), self.assertRaises(budget.BudgetError):
                self.verify(raw)

    def test_identity_reason_and_cancelled_scope_must_match(self):
        for key, value in dict(repository='other/repo', run_id=RUN+1, head_sha='b'*40,
                               attempt=2, workflow='pi-native.yml', version=True,
                               reason='runtime_growth', cancelled_job_ids=[], extra=True).items():
            saved = deepcopy(self.receipt)
            self.receipt[key] = value
            with self.subTest(key=key), self.assertRaises(budget.BudgetError):
                self.verify()
            self.receipt = saved
        for ids in ([True], [999], self.approval['cancelled_job_ids'][:1]):
            self.receipt['cancelled_job_ids'] = ids
            with self.subTest(ids=ids), self.assertRaises(budget.BudgetError):
                self.verify()

    def test_failed_receipt_cannot_hide_cleanup_or_missing_boundary(self):
        mutations = (lambda j: j['steps'].pop(),
                     lambda j: j['steps'][0].update(conclusion='failure'),
                     lambda j: j['steps'][0].update(conclusion='skipped'),
                     lambda j: j['steps'][1].update(conclusion='success'),
                     lambda j: j['steps'][-1].update(completed_at='invalid'),
                     lambda j: j['steps'].append(deepcopy(j['steps'][1])))
        for mutate in mutations:
            saved = deepcopy(self.job)
            mutate(self.job)
            with self.subTest(mutate=mutate), self.assertRaises(budget.BudgetError):
                self.verify()
            self.job.clear(); self.job.update(saved)

    def test_passed_receipt_cannot_cover_failed_budget_or_early_cancel(self):
        self.receipt.update(reason='passed', cancelled_job_ids=[])
        with self.assertRaises(budget.BudgetError):
            self.verify()
        self.job['conclusion'] = 'cancelled'
        self.job['steps'][1]['conclusion'] = 'success'
        self.job['completed_at'] = self.job['steps'][-1]['completed_at']
        with self.assertRaises(budget.BudgetError):
            self.verify()

    def test_digest_binds_full_original_inventory_not_order(self):
        digest = budget.conclusion_digest(self.jobs)
        self.assertEqual(digest, budget.conclusion_digest(list(reversed(self.jobs))))
        self.job['conclusion'] = 'cancelled'
        self.assertNotEqual(digest, budget.conclusion_digest(self.jobs))
        for field, value in (('id', True), ('status', 'in_progress'), ('conclusion', None)):
            saved = deepcopy(self.job)
            self.job[field] = value
            with self.subTest(field=field), self.assertRaises(budget.BudgetError):
                budget.conclusion_digest(self.jobs)
            self.job.clear(); self.job.update(saved)
        with self.assertRaises(budget.BudgetError):
            budget.conclusion_digest(self.jobs + [deepcopy(self.jobs[0])])

    def test_only_api_request_timeout_is_typed_as_evidence_unavailable(self):
        with patch.object(budget.subprocess, 'run', side_effect=subprocess.TimeoutExpired('gh', 30)):
            with self.assertRaises(budget.EvidenceUnavailable):
                budget.api(REPO, 'actions/runs/999')
            with self.assertRaises(subprocess.TimeoutExpired):
                budget.accounting_log(REPO, self.job['id'])
        with patch.object(budget.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'not-json')):
            with self.assertRaises(ValueError):
                budget.api(REPO, 'actions/runs/999')

    def test_emission_is_pinned_and_unavailable_identity_is_not_invented(self):
        env = dict(GITHUB_REPOSITORY=REPO, GITHUB_RUN_ID=str(RUN), CI_RUNTIME_HEAD_SHA=SHA,
                   GITHUB_RUN_ATTEMPT='1')
        with patch.dict(os.environ, env, clear=True), redirect_stdout(io.StringIO()) as output:
            budget.emit_accounting_receipt('validate.yml', 'evidence_unavailable')
        receipt = json.loads(output.getvalue().strip().removeprefix(budget.RECEIPT_PREFIX))
        self.assertEqual(receipt['head_sha'], SHA)
        self.assertEqual(receipt['run_id'], RUN)
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(io.StringIO()) as output:
            budget.emit_accounting_receipt('validate.yml', 'evidence_unavailable')
        self.assertEqual(output.getvalue(), '')

    def test_main_does_not_emit_receipt_for_arbitrary_validation_failure(self):
        env = dict(GITHUB_REPOSITORY=REPO, GITHUB_RUN_ID=str(RUN), CI_RUNTIME_HEAD_SHA=SHA,
                   GITHUB_RUN_ATTEMPT='1', DEFAULT_BRANCH='main')
        for error, emitted in ((budget.BudgetError('Runtime growth exceeds allowance'), False),
                               (budget.EvidenceUnavailable('API unavailable'), True),
                               (budget.CancelledFunctionalJob('cancelled', [1]), True)):
            with patch.dict(os.environ, env, clear=True), patch.object(budget, 'check', side_effect=error), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(budget.main(['validate.yml', '--base', SHA]), 1)
            self.assertEqual(budget.RECEIPT_PREFIX in output.getvalue(), emitted)
