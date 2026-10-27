"""Cheap contracts: expensive VM qualification must be a deliberate action."""
from pathlib import Path
import re
import unittest


class VMCITriggerTests(unittest.TestCase):
    def test_automatic_execution_budgets_do_not_exceed_three_minutes(self):
        workflows = Path(__file__).parents[1] / '.github/workflows'
        budgets = {'validate.yml': [1, 1, 1, 2, 1], 'claude-native.yml': [2],
                   'pi-native.yml': [3], 'pi-durable-fit.yml': [2]}
        for name, expected in budgets.items():
            with self.subTest(workflow=name):
                text = (workflows / name).read_text()
                actual = list(map(int, re.findall(r'^    timeout-minutes: (\d+)$', text, re.MULTILINE)))
                self.assertEqual(expected, actual)
                if name == 'validate.yml':
                    # Every integration job depends only on validate and runs
                    # in parallel; never sum parallel wall-clock budgets.
                    jobs = dict(re.findall(
                        r'^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)',
                        text.split('\njobs:\n', 1)[1], re.MULTILINE | re.DOTALL))
                    integrations = {'forge-broker-smoke', 'artifact-linux-smoke', 'docker-lifecycle', 'git-native-seams'}
                    self.assertEqual(set(jobs), {'validate'} | integrations)
                    self.assertEqual(re.findall(r'^    needs: (.+)$', jobs['validate'], re.MULTILINE), [])
                    for job in integrations:
                        self.assertEqual(re.findall(r'^    needs: (.+)$', jobs[job], re.MULTILINE), ['validate'])
                        self.assertEqual(re.findall(r'^    if: (.+)$', jobs[job], re.MULTILINE), [
                            "${{ needs.validate.outputs.skip_tests != 'true' && (github.event_name == 'pull_request' || github.ref == format('refs/heads/{0}', github.event.repository.default_branch)) }}"])
                    forge = jobs['forge-broker-smoke']
                    self.assertNotIn('continue-on-error:', forge)
                    self.assertEqual(re.findall(r'^        if: (.+)$', forge, re.MULTILINE), [])
                    for script in ('forge_read_smoke.py', 'forge_mutation_smoke.py'):
                        command = ('        run: timeout --signal=TERM --kill-after=2s 25s sudo -n '
                                   '--preserve-env=GITHUB_ACTIONS,RUNNER_OS /usr/bin/python3 tests/linux/' + script + '\n')
                        self.assertEqual(text.count(command), 1)
                        self.assertIn(command, forge)
                    self.assertLessEqual(actual[0] + max(actual[1:]), 3)
                else:
                    self.assertLessEqual(sum(actual), 3)

    def test_feasibility_has_only_manual_or_exact_review_label_triggers(self):
        workflow = (Path(__file__).parents[1] / '.github/workflows/vm-feasibility.yml').read_text()
        triggers = workflow.split('\non:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertEqual('  workflow_dispatch:\n  pull_request:\n    types: [labeled]', triggers.strip('\n'))
        self.assertIn("github.event_name == 'workflow_dispatch' || (github.event.label.name == 'qualify-vm-feasibility' && github.event.sender.login == 'puglab-reviewer' && github.event.pull_request.head.repo.full_name == github.repository)", workflow)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha || github.sha }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('permissions:\n  contents: read', workflow)
        self.assertNotIn('pull_request_target', workflow)
        self.assertNotIn('secrets.', workflow)
