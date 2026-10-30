"""Cheap contracts: expensive VM qualification must be a deliberate action."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import ci_runtime_budget as budget


class VMCITriggerTests(unittest.TestCase):
    def test_automatic_job_watchdogs_and_measured_budget_are_required(self):
        workflows = Path(__file__).parents[1] / '.github/workflows'
        budgets = {'validate.yml': [3, 3, 3, 1, 1, 2, 1, 1, 2, 1, 2, 1, 1, 1], 'claude-native.yml': [3, 1],
                   'pi-native.yml': [3, 1], 'pi-durable-fit.yml': [2]}
        for name, expected in budgets.items():
            with self.subTest(workflow=name):
                text = (workflows / name).read_text()
                actual = list(map(int, re.findall(r'^    timeout-minutes: (\d+)$', text, re.MULTILINE)))
                self.assertEqual(expected, actual)
                if name in budget.STAGES:
                    self.assertIn('  actions: read\n', text)
                    gate = text.split('\n  runtime-budget:\n', 1)[1]
                    self.assertIn('always()', gate)
                    self.assertIn('name: ${{ github.workflow }} runtime budget', gate)
                    self.assertNotIn('continue-on-error:', gate)
                    self.assertIn('fetch-depth: 0', gate)
                    self.assertIn('persist-credentials: false', gate)
                    self.assertIn(f'python3 -B tests/ci_runtime_budget.py {name} --base "$BASE_SHA"', gate)
                    self.assertNotIn('write', text.split('\npermissions:\n')[1].split('\n\n')[0])
                if name == 'validate.yml':
                    # All disjoint unit shards must pass before any integration.
                    # The matrix shares the same measured first stage as the other roots.
                    jobs = dict(re.findall(
                        r'^  ([a-z][a-z0-9-]*):\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)',
                        text.split('\njobs:\n', 1)[1], re.MULTILINE | re.DOTALL))
                    integrations = {'forge-broker-smoke', 'artifact-linux-smoke', 'docker-lifecycle', 'git-native-seams', 'gate-linux-smoke', 'gate-command-native', 'gate-artifact-native', 'room-control-plane', 'manager-mtls', 'manager-field-notes'}
                    roots = {'validate', 'unit-slow', 'unit-integration'}
                    self.assertEqual(set(jobs), roots | integrations | {'runtime-budget'})
                    dependencies = re.search(r'^    needs: \[(.+)\]$', jobs['runtime-budget'], re.MULTILINE)
                    self.assertEqual(set(dependencies[1].split(', ')), roots | integrations)
                    self.assertEqual(budget.STAGES['validate.yml'][1], integrations)
                    matrix_names = set(re.findall(r'partition: \w+, name: ([\w-]+)', text))
                    self.assertEqual(budget.STAGES['validate.yml'][0], {'validate', 'unit-slow'} | matrix_names)
                    for root in roots:
                        self.assertEqual(re.findall(r'^    needs: (.+)$', jobs[root], re.MULTILINE), [])
                        self.assertNotIn('continue-on-error:', jobs[root])
                        self.assertEqual(re.findall(r'^    if: (.+)$', jobs[root], re.MULTILINE), [
                            "${{ github.event_name == 'pull_request' || github.ref == format('refs/heads/{0}', github.event.repository.default_branch) }}"])
                    # The remainder lane also owns the explicit account-free
                    # process smoke. Validate that exact bounded step once before
                    # comparing the otherwise identical root/shard definitions.
                    smoke = """      - name: Check account-free local CLI process lifecycle
        if: steps.changes.outputs.skip_tests != 'true'
        env:
          UAS_LOCAL_PROCESS_SMOKE: "1"
        # Keep the bounded process smoke in the measured remainder lane.
        run: timeout --signal=TERM --kill-after=1s 15s python3 tests/linux/local_process_smoke.py --run

"""
                    self.assertEqual(text.count(smoke), 1)
                    self.assertEqual(jobs['validate'].count(smoke), 1)
                    self.assertEqual(text.count('python3 tests/linux/local_process_smoke.py --run'), 1)
                    remainder = jobs['validate'].replace(smoke, '', 1)
                    # Same source diff, docs exemption and mandatory test env;
                    # only the root's label and selected complementary shard differ.
                    self.assertEqual(remainder.replace('Validate successor interfaces', 'UNIT')
                                     .replace('./validate.sh remainder', './validate.sh PARTITION'),
                                     jobs['unit-slow'].replace('Validate measured slow unit partition', 'UNIT')
                                     .replace('./validate.sh slow', './validate.sh PARTITION'))
                    matrix = """    name: ${{ matrix.name }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - {partition: integration, name: unit-integration}
          - {partition: additional, name: unit-additional}
          - {partition: synthesis, name: unit-synthesis}
          - {partition: scheduler, name: unit-scheduler}
          - {partition: operator, name: unit-operator}
"""
                    self.assertEqual(jobs['unit-integration'].count(matrix), 1)
                    self.assertEqual(jobs['unit-integration'].replace(matrix, '', 1)
                                     .replace('Validate measured integration unit partition', 'UNIT')
                                     .replace('./validate.sh ${{ matrix.partition }}', './validate.sh PARTITION'),
                                     jobs['unit-slow'].replace('Validate measured slow unit partition', 'UNIT')
                                     .replace('./validate.sh slow', './validate.sh PARTITION'))
                    self.assertEqual(text.count('run: ./validate.sh ${{ matrix.partition }}\n'), 1)
                    self.assertEqual(text.count('run: ./validate.sh remainder\n'), 1)
                    self.assertEqual(text.count('run: ./validate.sh slow\n'), 1)
                    for job in integrations:
                        self.assertEqual(re.findall(r'^    needs: (.+)$', jobs[job], re.MULTILINE), ['[validate, unit-slow, unit-integration]'])
                        self.assertNotIn('continue-on-error:', jobs[job])
                        self.assertEqual(re.findall(r'^    if: (.+)$', jobs[job], re.MULTILINE), [
                            "${{ needs.validate.outputs.skip_tests != 'true' && needs.unit-slow.outputs.skip_tests != 'true' && needs.unit-integration.outputs.skip_tests != 'true' && (github.event_name == 'pull_request' || github.ref == format('refs/heads/{0}', github.event.repository.default_branch)) }}"])
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
                    self.assertIn('40s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS,GITHUB_SHA /usr/bin/python3 tests/linux/diff_smoke.py --run >"$log" 2>&1 & diff=$!', gates)
                    self.assertIn('15s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS /usr/bin/python3 tests/linux/gate_forge_smoke.py & broker=$!', gates)
                    self.assertIn('30s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS /usr/bin/python3 tests/linux/review_forge_smoke.py & review=$!', gates)
                    self.assertIn('log=$(mktemp) || exit 1', gates)
                    self.assertIn('deadline=$((SECONDS + 15))', gates)
                    self.assertIn('while (( SECONDS < deadline )); do', gates)
                    self.assertIn('ready=false', gates)
                    self.assertLess(gates.index('grep -Fxq'), gates.index('kill -0 "$diff"'))
                    self.assertIn('children=("$diff")', gates)
                    ready = gates.split('          if "$ready"; then\n', 1)[1].split('          fi\n', 1)[0]
                    success, failure = ready.split('          else\n')
                    for name in ('broker', 'review'):
                        self.assertIn(f'children+=("${name}")', success)
                    self.assertNotIn('timeout ', failure)
                    self.assertIn('status=1', failure)
                    self.assertIn('for child in "${children[@]}"; do', gates)
                    self.assertIn('cat "$log" || status=1', gates)
                    self.assertIn('rm -f "$log" || status=1', gates)
                    self.assertNotIn('| tee', gates)
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
                    self.assertEqual(re.findall(r'^        run: (.+)$', manager, re.MULTILINE), [
                        'PYTHONPATH=tests timeout --signal=TERM --kill-after=2s 40s python3 -m unittest test_manager_tls test_native_human_tls -v'])
                    self.assertNotIn('sudo', manager)
                    room = jobs['room-control-plane']
                    self.assertIn("UAS_ROOM_CONTROL_TEST: '1'", room)
                    self.assertIn('75s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS,UAS_ROOM_CONTROL_TEST,UAS_MANAGER_TLS_TEST /usr/bin/python3 tests/linux/room_control_smoke.py', room)
                    self.assertIn('persist-credentials: false', room)
                    self.assertNotIn('tests/vm/', room)
                    browser = jobs['manager-field-notes']
                    self.assertIn('UAS_MANAGER_BROWSER_TEST: "1"', browser)
                    self.assertIn('timeout --signal=TERM --kill-after=2s 40s node spike/manager-ui/check.cjs', browser)
                    self.assertIn('--browser', browser)
                    self.assertNotIn('sudo', browser)
                    self.assertNotIn('npm ', browser)
                    self.assertNotIn('--no-sandbox', browser)
                self.assertLessEqual(max(actual), 3)

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


class RuntimeBudgetTests(unittest.TestCase):
    def jobs(self, workflow='validate.yml', seconds=40, run_id=30):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        return [dict(name=name, run_id=run_id, status='completed', conclusion='success', steps=[],
                     started_at=start.isoformat(), completed_at=(start + timedelta(seconds=seconds)).isoformat())
                for stage in budget.STAGES[workflow] for name in sorted(stage)]

    def evidence(self, *, current=110, previous=100, workflow='pi-native.yml'):
        # Different run payloads expose accidental self-baselining or PR promotion.
        current_jobs = self.jobs(workflow, current, 30)
        old_jobs = self.jobs(workflow, previous, 20)
        row = dict(id=20, path=f'.github/workflows/{workflow}', event='push', head_branch='main',
                   head_sha='a' * 40, status='completed', conclusion='success')
        routes = {
            'actions/runs/30': dict(path=f'.github/workflows/{workflow}', event='pull_request'),
            'actions/runs/30/jobs?filter=latest&per_page=100': dict(total_count=len(current_jobs), jobs=current_jobs),
            'actions/runs/20/jobs?filter=latest&per_page=100': dict(total_count=len(old_jobs), jobs=old_jobs),
            f'actions/workflows/{workflow}/runs?event=push&status=success&branch=main&per_page=100':
                dict(workflow_runs=[row]),
        }
        return routes

    def check(self, routes, workflow='pi-native.yml'):
        with patch.object(budget, 'api', side_effect=lambda repo, path: routes[path]), \
                patch.object(budget, 'ancestor', return_value=True):
            return budget.check('owner/repo', workflow, 'main', 'b' * 40, 30)

    def test_parallel_path_counts_setup_cleanup_but_not_queue_delay(self):
        jobs = self.jobs()
        next(job for job in jobs if job['name'] == 'unit-synthesis')['completed_at'] = '2026-01-01T00:01:00+00:00'
        # Moving an entire downstream stage later must not add queue time.
        for job in jobs:
            if job['name'] in budget.SEAM_JOBS:
                job['started_at'] = '2026-01-01T01:00:00+00:00'
                job['completed_at'] = '2026-01-01T01:00:45+00:00'
        jobs.append(dict(name='validate runtime budget', status='in_progress'))
        self.assertEqual(105, budget.critical_path('validate.yml', jobs))

    def test_growth_boundary_and_absolute_ceiling_through_check(self):
        self.assertIn('limit: 120.0s', self.check(self.evidence(current=120)))
        with self.assertRaisesRegex(budget.BudgetError, 'growth exceeds'):
            self.check(self.evidence(current=121))
        self.assertIn('limit: 150.0s', self.check(self.evidence(current=150, previous=140)))
        with self.assertRaisesRegex(budget.BudgetError, 'absolute 150'):
            self.check(self.evidence(current=151, previous=140))
        self.assertIn('limit: 96.0s', self.check(self.evidence(current=90, previous=80)))

    def test_failed_skipped_missing_duplicate_or_unexpected_jobs_cannot_pass(self):
        for defect in ('failure', 'cancelled', 'skipped', 'missing', 'duplicate', 'unexpected', 'zero'):
            with self.subTest(defect=defect), self.assertRaises(budget.BudgetError):
                jobs = self.jobs()
                if defect == 'missing':
                    jobs.pop()
                elif defect == 'duplicate':
                    jobs.append(dict(jobs[0]))
                elif defect == 'unexpected':
                    jobs.append(dict(jobs[0], name='new-unmeasured-job'))
                elif defect == 'zero':
                    jobs[0]['completed_at'] = jobs[0]['started_at']
                else:
                    jobs[0]['conclusion'] = defect
                budget.critical_path('validate.yml', jobs)

    def test_docs_only_runs_neither_fail_growth_nor_become_a_full_baseline(self):
        jobs = self.jobs()
        for job in jobs:
            if job['name'] in budget.UNIT_JOBS:
                job['steps'] = [dict(name='Report tests not applicable', conclusion='success')]
            else:
                job['conclusion'] = 'skipped'
        self.assertIsNone(budget.critical_path('validate.yml', jobs))
        routes = self.evidence(workflow='validate.yml')
        routes['actions/runs/30/jobs?filter=latest&per_page=100']['jobs'] = jobs
        self.assertIn('Documentation-only', self.check(routes, 'validate.yml'))
        key = 'actions/workflows/validate.yml/runs?event=push&status=success&branch=main&per_page=100'
        rows = routes[key]['workflow_runs']
        rows.append(dict(rows[0], id=25))
        routes['actions/runs/25/jobs?filter=latest&per_page=100'] = dict(total_count=len(jobs),
                                                                     jobs=[dict(j, run_id=25) for j in jobs])
        routes['actions/runs/30/jobs?filter=latest&per_page=100']['jobs'] = self.jobs(seconds=50)
        routes['actions/runs/20/jobs?filter=latest&per_page=100']['jobs'] = self.jobs(seconds=50, run_id=20)
        self.assertIn('run 20', self.check(routes, 'validate.yml'))

    def test_baseline_is_last_successful_ancestor_main_run_not_current_or_pr(self):
        routes = self.evidence()
        key = 'actions/workflows/pi-native.yml/runs?event=push&status=success&branch=main&per_page=100'
        row = routes[key]['workflow_runs'][0]
        routes[key]['workflow_runs'] = [dict(row, id=10), dict(row, id=30), row]
        self.assertIn('run 20', self.check(routes))
        routes[key]['workflow_runs'] = [dict(row, event='pull_request')]
        with self.assertRaisesRegex(budget.BudgetError, 'identity mismatch'):
            self.check(routes)
        routes[key]['workflow_runs'] = [row]
        with patch.object(budget, 'api', side_effect=lambda repo, path: routes[path]), \
                patch.object(budget, 'ancestor', return_value=False), \
                self.assertRaisesRegex(budget.BudgetError, 'No successful full main baseline'):
            budget.check('owner/repo', 'pi-native.yml', 'main', 'b' * 40, 30)

    def test_missing_baseline_partial_inventory_and_invalid_baseline_fail_closed(self):
        routes = self.evidence()
        key = 'actions/workflows/pi-native.yml/runs?event=push&status=success&branch=main&per_page=100'
        routes[key]['workflow_runs'] = []
        with self.assertRaisesRegex(budget.BudgetError, 'No successful full main baseline'):
            self.check(routes)
        routes = self.evidence()
        routes['actions/runs/30/jobs?filter=latest&per_page=100']['total_count'] = 2
        with self.assertRaisesRegex(budget.BudgetError, 'Incomplete job inventory'):
            self.check(routes)
        with self.assertRaisesRegex(budget.BudgetError, 'Baseline is outside'):
            self.check(self.evidence(previous=151))

    def test_unavailable_or_malformed_evidence_makes_cli_fail_without_leaking_it(self):
        from contextlib import redirect_stderr
        import io
        environment = dict(GITHUB_REPOSITORY='owner/repo', DEFAULT_BRANCH='main', GITHUB_RUN_ID='30')
        for error in (OSError('private response'), ValueError('private response'), KeyError('private response')):
            with self.subTest(error=type(error).__name__), patch.dict(budget.os.environ, environment), \
                    patch.object(budget, 'api', side_effect=error), redirect_stderr(io.StringIO()) as output:
                self.assertEqual(1, budget.main(['pi-native.yml', '--base', 'b' * 40]))
                self.assertNotIn('private response', output.getvalue())
