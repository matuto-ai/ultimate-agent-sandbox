"""Gate CI against the median of five distinct, successful first-attempt main runs."""
import argparse
from datetime import datetime
import json
import os
import re
from statistics import median
import subprocess
import sys


ABSOLUTE_SECONDS = 150
GROWTH_PERCENT = 10
BASELINE_SAMPLES = 5
UNIT_JOBS = frozenset(('validate', 'unit-slow', 'unit-integration', 'unit-additional',
                       'unit-synthesis', 'unit-scheduler', 'unit-operator', 'unit-inspection',
                       'unit-lifecycle', 'unit-disposition', 'unit-maintenance', 'unit-archive'))
SEAM_JOBS = frozenset(('forge-broker-smoke', 'artifact-linux-smoke', 'docker-lifecycle',
                       'git-native-seams', 'gate-linux-smoke', 'gate-command-native',
                       'gate-artifact-native', 'room-control-plane', 'manager-mtls',
                       'manager-field-notes'))
STAGES = {
    'validate.yml': (UNIT_JOBS, SEAM_JOBS),
    'pi-native.yml': (frozenset(('official-pi-native-0', 'official-pi-native-1', 'official-pi-native-2')),),
    'claude-native.yml': (frozenset(('official-claude-fixture',)),),
}


class BudgetError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise BudgetError(message)


def critical_path(workflow, jobs, *, historical=False):
    """Include job setup/cleanup, not queue time or this accounting job."""
    accounting = workflow.removesuffix('.yml') + ' runtime budget'
    measured = [job for job in jobs if job['name'] != accounting]
    require(len(jobs) - len(measured) <= 1, 'Duplicate runtime accounting job')
    names = [job['name'] for job in measured]
    stages = STAGES[workflow]
    if historical and workflow == 'pi-native.yml' and names == ['official-pi-native']:
        stages = (frozenset(names),)
    expected = set().union(*stages)
    # Recognize only complete historical graphs; current runs require all twelve roots.
    if historical and workflow == 'validate.yml':
        for absent in ({'unit-archive'}, {'unit-archive', 'unit-maintenance'},
                       {'unit-archive', 'unit-maintenance', 'unit-lifecycle', 'unit-disposition'},
                       {'unit-archive', 'unit-maintenance', 'unit-lifecycle', 'unit-disposition', 'unit-inspection'}):
            if set(names) == expected - absent:
                expected -= absent
                break
    require(len(names) == len(set(names)) and set(names) == expected,
            'Missing, duplicate or unexpected validation jobs; update the measured graph')
    by_name = {job['name']: job for job in measured}
    # A docs-only run is not a faster full-suite baseline.
    if workflow == 'validate.yml' and all(
            by_name[name]['conclusion'] == 'success' and any(
                step['name'] == 'Report tests not applicable' and step['conclusion'] == 'success'
                for step in by_name[name]['steps']) for name in UNIT_JOBS & expected):
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
    return sum(max(durations[name] for name in stage & expected) for stage in stages)


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
    response = api(repo, f'actions/runs/{run_id}/attempts/1/jobs?per_page=100')
    require(response['total_count'] == len(response['jobs']) <= 100,
            'Incomplete job inventory')
    require(all(job['run_id'] == run_id and job['run_attempt'] == 1 for job in response['jobs']),
            'Job/run/attempt identity mismatch')
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
    response = api(repo, f'actions/workflows/{workflow}/runs?event=push'
                   f'&branch={quote(branch, safe="")}&per_page=100')
    # Re-pushing a commit cannot buy another baseline sample or replace its first run.
    first_runs = {}
    for run in sorted(response['workflow_runs'], key=lambda row: row['id']):
        if run['id'] < current_id:
            first_runs.setdefault(run['head_sha'], run)
    samples = []
    for run in sorted(first_runs.values(), key=lambda row: row['id'], reverse=True):
        if run['run_attempt'] != 1:
            original = api(repo, f'actions/runs/{run["id"]}/attempts/1')
            require(original['id'] == run['id'] and original['head_sha'] == run['head_sha']
                    and original['run_attempt'] == 1, 'Baseline attempt identity mismatch')
            run = original
        require(run['path'] == f'.github/workflows/{workflow}' and run['event'] == 'push'
                and run['head_branch'] == branch, 'Baseline run identity mismatch')
        if run['status'] != 'completed' or run['conclusion'] != 'success':
            continue
        if not ancestor(run['head_sha'], base):
            continue
        seconds = critical_path(workflow, run_jobs(repo, run['id']), historical=True)
        if seconds is not None:
            allowed_seconds(seconds)
            samples.append((run['id'], run['head_sha'], seconds))
            if len(samples) == BASELINE_SAMPLES:
                return median(sample[2] for sample in samples), samples
    raise BudgetError('Need five distinct successful first-attempt full main runs among the last 100 runs')


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
    previous, samples = baseline(repo, workflow, branch, base, run_id)
    limit = allowed_seconds(previous)
    sources = '; '.join(f'run {number}, commit {commit}: {seconds:.1f}s'
                        for number, commit, seconds in samples)
    summary = (f'CI critical path (first attempt): {elapsed:.1f}s; baseline median: {previous:.1f}s; '
               f'limit: {limit:.1f}s (+{GROWTH_PERCENT}%, absolute {ABSOLUTE_SECONDS}s). '
               f'Sources: {sources}.')
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
    except (BudgetError, KeyError, ValueError, TypeError, AttributeError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error) if isinstance(error, BudgetError) else 'Invalid or unavailable CI timing evidence',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
