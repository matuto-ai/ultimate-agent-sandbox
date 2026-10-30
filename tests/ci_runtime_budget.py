"""Gate the measured CI critical path against the last successful main run."""
import argparse
from datetime import datetime
import json
import os
import re
import subprocess
import sys


ABSOLUTE_SECONDS = 150
GROWTH_PERCENT = 20
UNIT_JOBS = frozenset(('validate', 'unit-slow', 'unit-integration', 'unit-additional',
                       'unit-synthesis', 'unit-scheduler', 'unit-operator', 'unit-inspection'))
SEAM_JOBS = frozenset(('forge-broker-smoke', 'artifact-linux-smoke', 'docker-lifecycle',
                       'git-native-seams', 'gate-linux-smoke', 'gate-command-native',
                       'gate-artifact-native', 'room-control-plane', 'manager-mtls',
                       'manager-field-notes'))
STAGES = {
    'validate.yml': (UNIT_JOBS, SEAM_JOBS),
    'pi-native.yml': (frozenset(('official-pi-native',)),),
    'claude-native.yml': (frozenset(('official-claude-fixture',)),),
}


class BudgetError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise BudgetError(message)


def critical_path(workflow, jobs):
    """Include job setup/cleanup, not queue time or this accounting job."""
    accounting = workflow.removesuffix('.yml') + ' runtime budget'
    measured = [job for job in jobs if job['name'] != accounting]
    require(len(jobs) - len(measured) <= 1, 'Duplicate runtime accounting job')
    names = [job['name'] for job in measured]
    expected = set().union(*STAGES[workflow])
    require(len(names) == len(set(names)) and set(names) == expected,
            'Missing, duplicate or unexpected validation jobs; update the measured graph')
    by_name = {job['name']: job for job in measured}
    # A docs-only run is not a faster full-suite baseline.
    if workflow == 'validate.yml' and all(
            by_name[name]['conclusion'] == 'success' and any(
                step['name'] == 'Report tests not applicable' and step['conclusion'] == 'success'
                for step in by_name[name]['steps']) for name in UNIT_JOBS):
        require(all(by_name[name]['conclusion'] == 'skipped' for name in SEAM_JOBS),
                'Inconsistent documentation-only execution')
        return None
    durations = {}
    for name, job in by_name.items():
        require(job['status'] == 'completed' and job['conclusion'] == 'success',
                f'{name} did not complete successfully; no runtime acceptance')
        start = datetime.fromisoformat(job['started_at'].replace('Z', '+00:00'))
        end = datetime.fromisoformat(job['completed_at'].replace('Z', '+00:00'))
        seconds = (end - start).total_seconds()
        require(seconds > 0, f'{name} has invalid timing evidence')
        durations[name] = seconds
    return sum(max(durations[name] for name in stage) for stage in STAGES[workflow])


def allowed_seconds(baseline):
    require(0 < baseline <= ABSOLUTE_SECONDS, 'Baseline is outside the 150-second ceiling')
    return min(ABSOLUTE_SECONDS, baseline * (100 + GROWTH_PERCENT) / 100)


def api(repo, path):
    # gh owns token handling; never print API bodies or command stderr.
    result = subprocess.run(['gh', 'api', f'repos/{repo}/{path}'],
                            capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, 'GitHub evidence unavailable; check actions:read permission and retry')
    return json.loads(result.stdout)


def run_jobs(repo, run_id):
    response = api(repo, f'actions/runs/{run_id}/jobs?filter=latest&per_page=100')
    require(response['total_count'] == len(response['jobs']) <= 100,
            'Incomplete job inventory')
    require(all(job['run_id'] == run_id for job in response['jobs']), 'Job/run identity mismatch')
    return response['jobs']


def ancestor(commit, base):
    require(isinstance(commit, str) and re.fullmatch(r'[0-9a-f]{40}', commit),
            'Invalid baseline commit')
    result = subprocess.run(['git', 'merge-base', '--is-ancestor', commit, base],
                            capture_output=True, timeout=10)
    require(result.returncode in (0, 1), 'Baseline history unavailable; checkout with fetch-depth: 0')
    return result.returncode == 0


def baseline(repo, workflow, branch, base, current_id):
    from urllib.parse import quote
    response = api(repo, f'actions/workflows/{workflow}/runs?event=push&status=success'
                   f'&branch={quote(branch, safe="")}&per_page=100')
    for run in sorted(response['workflow_runs'], key=lambda row: row['id'], reverse=True):
        if run['id'] >= current_id:
            continue
        require(run['path'] == f'.github/workflows/{workflow}' and run['event'] == 'push'
                and run['head_branch'] == branch and run['status'] == 'completed'
                and run['conclusion'] == 'success', 'Baseline run identity mismatch')
        if not ancestor(run['head_sha'], base):
            continue
        seconds = critical_path(workflow, run_jobs(repo, run['id']))
        if seconds is not None:
            return seconds, run['id'], run['head_sha']
    raise BudgetError('No successful full main baseline among the last 100 runs; restore baseline evidence')


def check(repo, workflow, branch, base, run_id):
    require(re.fullmatch(r'[\w.-]+/[\w.-]+', repo) and re.fullmatch(r'[0-9a-f]{40}', base)
            and run_id > 0, 'Invalid repository, base or run identity')
    current = api(repo, f'actions/runs/{run_id}')
    require(current['path'] == f'.github/workflows/{workflow}'
            and current['event'] in ('push', 'pull_request'), 'Current workflow identity mismatch')
    elapsed = critical_path(workflow, run_jobs(repo, run_id))
    if elapsed is None:
        return 'Documentation-only run: runtime unchanged; no new full-suite baseline.'
    require(elapsed <= ABSOLUTE_SECONDS,
            f'CI critical path {elapsed:.1f}s exceeds the absolute 150-second ceiling')
    previous, source_id, source_sha = baseline(repo, workflow, branch, base, run_id)
    limit = allowed_seconds(previous)
    summary = (f'CI critical path: {elapsed:.1f}s; baseline: {previous:.1f}s '
               f'(run {source_id}, commit {source_sha}); limit: {limit:.1f}s '
               f'(+{GROWTH_PERCENT}%, absolute {ABSOLUTE_SECONDS}s).')
    require(elapsed <= limit, summary + ' Runtime growth exceeds the allowance.')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workflow', choices=STAGES)
    parser.add_argument('--base', required=True)
    args = parser.parse_args(argv)
    try:
        message = check(os.environ['GITHUB_REPOSITORY'], args.workflow,
                        os.environ['DEFAULT_BRANCH'], args.base, int(os.environ['GITHUB_RUN_ID']))
        print(message)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
                output.write(message + '\n')
        return 0
    except (BudgetError, KeyError, ValueError, TypeError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error) if isinstance(error, BudgetError) else 'Invalid or unavailable CI timing evidence',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
