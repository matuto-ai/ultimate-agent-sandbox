"""Cheap contracts: expensive VM qualification must be a deliberate action."""
from pathlib import Path
import re
import unittest


class VMCITriggerTests(unittest.TestCase):
    def test_automatic_execution_budgets_do_not_exceed_three_minutes(self):
        workflows = Path(__file__).parents[1] / '.github/workflows'
        budgets = {'validate.yml': [1, 1, 1, 1, 2, 1, 1, 2, 1, 1], 'claude-native.yml': [2],
                   'pi-native.yml': [3], 'pi-durable-fit.yml': [2]}
        for name, expected in budgets.items():
            with self.subTest(workflow=name):
                text = (workflows / name).read_text()
                actual = list(map(int, re.findall(r'^    timeout-minutes: (\d+)$', text, re.MULTILINE)))
                self.assertEqual(expected, actual)
                if name == 'validate.yml':
                    # Both disjoint unit roots must pass before any integration.
                    # Never sum sibling wall-clock budgets or weaken failures.
                    jobs = dict(re.findall(
                        r'^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)',
                        text.split('\njobs:\n', 1)[1], re.MULTILINE | re.DOTALL))
                    integrations = {'forge-broker-smoke', 'artifact-linux-smoke', 'docker-lifecycle', 'git-native-seams', 'gate-linux-smoke', 'gate-command-native', 'gate-artifact-native', 'manager-mtls'}
                    roots = {'validate', 'unit-slow'}
                    self.assertEqual(set(jobs), roots | integrations)
                    for root in roots:
                        self.assertEqual(re.findall(r'^    needs: (.+)$', jobs[root], re.MULTILINE), [])
                        self.assertNotIn('continue-on-error:', jobs[root])
                        self.assertEqual(re.findall(r'^    if: (.+)$', jobs[root], re.MULTILINE), [
                            "${{ github.event_name == 'pull_request' || github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}"])
                    # Same source diff, docs exemption and mandatory test env;
                    # only the root's label and selected complementary shard differ.
                    self.assertEqual(jobs['validate'].replace('Validate successor interfaces', 'UNIT')
                                     .replace('./validate.sh remainder', './validate.sh PARTITION'),
                                     jobs['unit-slow'].replace('Validate measured slow unit partition', 'UNIT')
                                     .replace('./validate.sh slow', './validate.sh PARTITION'))
                    self.assertEqual(text.count('run: ./validate.sh remainder\n'), 1)
                    self.assertEqual(text.count('run: ./validate.sh slow\n'), 1)
                    for job in integrations:
                        self.assertEqual(re.findall(r'^    needs: (.+)$', jobs[job], re.MULTILINE), ['[validate, unit-slow]'])
                        self.assertNotIn('continue-on-error:', jobs[job])
                        self.assertEqual(re.findall(r'^    if: (.+)$', jobs[job], re.MULTILINE), [
                            "${{ needs.validate.outputs.skip_tests != 'true' && needs.unit-slow.outputs.skip_tests != 'true' && (github.event_name == 'pull_request' || github.ref == format('refs/heads/{0}', github.event.repository.default_branch)) }}"])
                    forge = jobs['forge-broker-smoke']
                    self.assertNotIn('continue-on-error:', forge)
                    self.assertEqual(re.findall(r'^        if: (.+)$', forge, re.MULTILINE), [])
                    for script in ('forge_read_smoke.py', 'forge_mutation_smoke.py'):
                        command = ('        run: timeout --signal=TERM --kill-after=2s 25s sudo -n '
                                   '--preserve-env=GITHUB_ACTIONS,RUNNER_OS /usr/bin/python3 tests/linux/' + script + '\n')
                        self.assertEqual(text.count(command), 1)
                        self.assertIn(command, forge)
                    gates = jobs['gate-linux-smoke']
                    self.assertEqual(re.findall(r'^        if: (.+)$', gates, re.MULTILINE), [])
                    self.assertIn('40s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS,GITHUB_SHA /usr/bin/python3 tests/linux/diff_smoke.py --run & diff=$!', gates)
                    self.assertIn('15s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS /usr/bin/python3 tests/linux/gate_forge_smoke.py & broker=$!', gates)
                    self.assertIn('30s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS /usr/bin/python3 tests/linux/review_forge_smoke.py & review=$!', gates)
                    self.assertIn('for child in "$diff" "$broker" "$review"; do', gates)
                    self.assertIn('wait "$child" || status=1', gates)
                    self.assertIn('exit "$status"', gates)
                    for job, script, seconds in (
                            ('gate-command-native', 'command_smoke.py', 65),
                            ('gate-artifact-native', 'artifact_native_smoke.py', 43)):
                        self.assertEqual(re.findall(r'^        if: (.+)$', jobs[job], re.MULTILINE), [])
                        self.assertIn('persist-credentials: false', jobs[job])
                        self.assertIn(f'{seconds}s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS,GITHUB_SHA /usr/bin/python3 tests/linux/{script} --run', jobs[job])
                        self.assertNotIn('tests/vm/', jobs[job])
                    manager = jobs['manager-mtls']
                    self.assertIn('UAS_MANAGER_TLS_TEST: "1"', manager)
                    self.assertIn('timeout --signal=TERM --kill-after=2s 40s python3 -m unittest discover -s tests -p test_manager_tls.py -v', manager)
                    self.assertNotIn('sudo', manager)
                    self.assertLessEqual(max(actual[:2]) + max(actual[2:]), 3)
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
