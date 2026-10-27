"""Cheap contracts: expensive VM qualification must be a deliberate action."""
from pathlib import Path
import re
import unittest


class VMCITriggerTests(unittest.TestCase):
    def test_automatic_execution_budgets_do_not_exceed_three_minutes(self):
        workflows = Path(__file__).parents[1] / '.github/workflows'
        budgets = {'validate.yml': [1, 1, 2], 'claude-native.yml': [2],
                   'pi-native.yml': [3], 'pi-durable-fit.yml': [2]}
        for name, expected in budgets.items():
            with self.subTest(workflow=name):
                text = (workflows / name).read_text()
                actual = list(map(int, re.findall(r'^    timeout-minutes: (\d+)$', text, re.MULTILINE)))
                self.assertEqual(expected, actual)
                if name == 'validate.yml':
                    # Both narrow integration jobs depend only on validate and
                    # run in parallel; never sum parallel wall-clock budgets.
                    smoke = text.split('  artifact-linux-smoke:\n', 1)[1].split('  docker-lifecycle:\n', 1)[0]
                    docker = text.split('  docker-lifecycle:\n', 1)[1]
                    self.assertEqual(re.findall(r'^    needs: (.+)$', smoke, re.MULTILINE), ['validate'])
                    self.assertEqual(re.findall(r'^    needs: (.+)$', docker, re.MULTILINE), ['validate'])
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
