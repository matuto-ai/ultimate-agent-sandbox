"""Cheap contracts: expensive VM qualification must be a deliberate action."""
from pathlib import Path
import unittest


class VMCITriggerTests(unittest.TestCase):
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
