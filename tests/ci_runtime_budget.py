"""Gate CI against the median of five distinct, successful first-attempt main runs."""
import argparse
import hashlib
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
    'pi-native.yml': (frozenset(('official-pi-native-0', 'official-pi-native-1', 'official-pi-native-2', 'official-pi-native-3')),),
    'claude-native.yml': (frozenset(('official-claude-fixture-0', 'official-claude-fixture-1')),),
}


class BudgetError(Exception):
    pass


class EvidenceUnavailable(BudgetError):
    pass


class CancelledFunctionalJob(BudgetError):
    def __init__(self, message, job_ids):
        super().__init__(message)
        self.job_ids = sorted(job_ids)


def require(condition, message):
    if not condition:
        raise BudgetError(message)


def job_timing(job):
    """Keep every runner step; report pre-step provisioning and post-step finalization."""
    def timestamp(value):
        require(isinstance(value, str), 'Missing job/step timestamp')
        try:
            result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as error:
            raise BudgetError('Invalid job/step timestamp') from error
        require(result.utcoffset() is not None, 'Timezone missing from job/step timestamp')
        return result

    start, end = timestamp(job.get('started_at')), timestamp(job.get('completed_at'))
    require(end > start, 'Invalid job wall duration')
    steps = job.get('steps')
    require(isinstance(steps, list) and len(steps) >= 2, 'Missing complete runner step inventory')
    require(all(isinstance(step, dict) for step in steps), 'Invalid runner step metadata')
    require(steps[0].get('name') == 'Set up job' and steps[-1].get('name') == 'Complete job'
            and steps[0].get('conclusion') == steps[-1].get('conclusion') == 'success',
            'Missing successful runner setup/completion boundary')
    previous, number = start, 0
    for step in steps:
        require(isinstance(step.get('number'), int) and not isinstance(step['number'], bool)
                and step['number'] > number, 'Invalid runner step order')
        require(step.get('status') == 'completed' and step.get('conclusion') in ('success', 'skipped'),
                'Incomplete or failed runner step')
        step_start, step_end = timestamp(step.get('started_at')), timestamp(step.get('completed_at'))
        require(previous <= step_start <= step_end <= end, 'Invalid runner step timing interval')
        previous, number = step_end, step['number']
    first_step = timestamp(steps[0]['started_at'])
    execution = (previous - first_step).total_seconds()
    require(execution > 0, 'Invalid execution duration')
    return dict(provisioning=(first_step - start).total_seconds(), execution=execution, wall=(end - start).total_seconds(),
                finalization=(end - previous).total_seconds())


def critical_path(workflow, jobs, *, historical=False, diagnostics=None):
    """Include setup/tests/cleanup steps; exclude only pre/post-step GitHub intervals."""
    accounting = workflow.removesuffix('.yml') + ' runtime budget'
    measured = [job for job in jobs if job['name'] != accounting]
    require(len(jobs) - len(measured) <= 1, 'Duplicate runtime accounting job')
    names = [job['name'] for job in measured]
    stages = STAGES[workflow]
    if historical and workflow == 'pi-native.yml' and names == ['official-pi-native']:
        stages = (frozenset(names),)
    if historical and workflow == 'pi-native.yml' and set(names) == {
            'official-pi-native-0', 'official-pi-native-1', 'official-pi-native-2'}:
        stages = (frozenset(names),)
    if historical and workflow == 'claude-native.yml' and names == ['official-claude-fixture']:
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
        durations[name] = job_timing(job)
    execution = sum(max(durations[name]['execution'] for name in stage & expected) for stage in stages)
    if diagnostics is not None:
        diagnostics.update(jobs=durations,
            wall_path=sum(max(durations[name]['wall'] for name in stage & expected) for stage in stages),
            span=(max(datetime.fromisoformat(job['completed_at'].replace('Z', '+00:00')) for job in measured)
                  - min(datetime.fromisoformat(job['started_at'].replace('Z', '+00:00')) for job in measured)).total_seconds())
    return execution


def scoped_jobs(workflow, jobs, path):
    """Select a fixed lane inside the unified workflow, never an arbitrary subset."""
    if path != '.github/workflows/verify.yaml':
        require(path == f'.github/workflows/{workflow}', 'Workflow lane identity mismatch')
        return jobs
    prefixes = {'pi-native.yml': 'pi-native / ', 'claude-native.yml': 'claude-native / '}
    if workflow in prefixes:
        prefix = prefixes[workflow]
        return [dict(job, name=job['name'][len(prefix):]) for job in jobs
                if job['name'].startswith(prefix)]
    require(workflow == 'validate.yml', 'Unknown unified workflow lane')
    # Explicitly exclude sibling reusable jobs and the final gate. Unexpected
    # unscoped jobs still fail critical_path's exact inventory check.
    return [job for job in jobs if job['name'] != 'verify'
            # A skipped reusable workflow is exposed as its caller job, without
            # a child prefix. Only this exact skip is exempt; verify checks its
            # path-applicability output before accepting it.
            and not (job['name'] == 'pi-durable-fit' and job.get('conclusion') == 'skipped')
            and not job['name'].startswith(('pi-native / ', 'claude-native / ', 'pi-durable-fit / '))]


def allowed_seconds(baseline):
    require(0 < baseline <= ABSOLUTE_SECONDS, 'Baseline is outside the 150-second ceiling')
    return min(ABSOLUTE_SECONDS, baseline * (100 + GROWTH_PERCENT) / 100)


def api(repo, path):
    # gh owns token handling; never print API bodies or command stderr.
    try:
        result = subprocess.run(['gh', 'api', f'repos/{repo}/{path}'],
                                capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        raise EvidenceUnavailable('GitHub evidence request timed out') from error
    if result.returncode != 0:
        raise EvidenceUnavailable('GitHub evidence unavailable; check actions:read permission and retry')
    return json.loads(result.stdout)


def run_jobs(repo, run_id, attempt=1):
    require(type(attempt) is int and attempt in (1, 2), 'Unsupported run attempt')
    response = api(repo, f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    require(response['total_count'] == len(response['jobs']) <= 100,
            'Incomplete job inventory')
    require(all(type(job['run_id']) is int and job['run_id'] == run_id and type(job['run_attempt']) is int
                and job['run_attempt'] == attempt for job in response['jobs']),
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
    response = api(repo, 'actions/runs?event=push'
                   f'&branch={quote(branch, safe="")}&per_page=100')
    # Re-pushing a commit cannot buy another baseline sample or replace its first run.
    first_runs = {}
    for run in sorted(response['workflow_runs'], key=lambda row: row['id']):
        if (run['id'] < current_id and run['path'] in
                (f'.github/workflows/{workflow}', '.github/workflows/verify.yaml')):
            first_runs.setdefault(run['head_sha'], run)
    samples = []
    for run in sorted(first_runs.values(), key=lambda row: row['id'], reverse=True):
        if run['run_attempt'] != 1:
            original = api(repo, f'actions/runs/{run["id"]}/attempts/1')
            require(original['id'] == run['id'] and original['head_sha'] == run['head_sha']
                    and original['run_attempt'] == 1, 'Baseline attempt identity mismatch')
            run = original
        require(run['path'] in (f'.github/workflows/{workflow}', '.github/workflows/verify.yaml') and run['event'] == 'push'
                and run['head_branch'] == branch, 'Baseline run identity mismatch')
        if run['status'] != 'completed' or run['conclusion'] != 'success':
            continue
        if not ancestor(run['head_sha'], base):
            continue
        seconds = critical_path(workflow, scoped_jobs(workflow, run_jobs(repo, run['id']), run['path']), historical=True)
        if seconds is not None:
            allowed_seconds(seconds)
            samples.append((run['id'], run['head_sha'], seconds))
            if len(samples) == BASELINE_SAMPLES:
                return median(sample[2] for sample in samples), samples
    raise BudgetError('Need five distinct successful first-attempt full main runs among the last 100 runs')


def parse_recovery_approval(raw):
    """Parse operator-supplied evidence; never infer or create authorization."""
    if raw == '':
        return None
    require(type(raw) is str and len(raw.encode('utf-8')) <= 4096,
            'Invalid recovery approval size')
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate recovery approval field')
            result[key] = value
        return result
    try:
        record = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, TypeError, RecursionError) as error:
        raise BudgetError('Invalid recovery approval JSON') from error
    require(type(record) is dict and set(record) == {
        'version', 'repository', 'run_id', 'head_sha', 'attempt',
        'cancelled_job_ids', 'approval_reference', 'original_job_conclusions_sha256'}, 'Invalid recovery approval schema')
    require(type(record['version']) is int and record['version'] == 1
            and type(record['attempt']) is int and record['attempt'] == 2,
            'Recovery permits only explicit attempt two')
    require(type(record['repository']) is str
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', record['repository'])
            and type(record['head_sha']) is str
            and re.fullmatch(r'[0-9a-f]{40}', record['head_sha'])
            and type(record['run_id']) is int and record['run_id'] > 0,
            'Invalid recovery identity')
    ids = record['cancelled_job_ids']
    require(type(ids) is list and 1 <= len(ids) <= len(recovery_functional_names())
            and all(type(value) is int and value > 0 for value in ids)
            and len(set(ids)) == len(ids), 'Invalid cancelled job inventory')
    require(type(record['approval_reference']) is str
            and re.fullmatch(r'[A-Za-z0-9_:-]{1,160}', record['approval_reference']),
            'Missing bounded operator approval reference')
    require(type(record['original_job_conclusions_sha256']) is str
            and re.fullmatch(r'[0-9a-f]{64}', record['original_job_conclusions_sha256']),
            'Missing original conclusion inventory digest')
    return record


RECEIPT_PREFIX = 'CI_RUNTIME_ACCOUNTING_RECEIPT '


def conclusion_digest(jobs):
    rows = [[job.get(key) for key in ('id', 'name', 'status', 'conclusion')] for job in jobs]
    require(rows and all(type(row[0]) is int and row[0] > 0
            and type(row[1]) is str and row[1] and row[2] == 'completed'
            and row[3] in ('success', 'failure', 'cancelled', 'skipped') for row in rows)
            and len({row[0] for row in rows}) == len(rows)
            and len({row[1] for row in rows}) == len(rows), 'Invalid original conclusion inventory')
    return hashlib.sha256(json.dumps(sorted(rows), separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def emit_accounting_receipt(workflow, reason, cancelled_ids=()):
    """Only typed outcomes emit receipts; malformed identity emits no usable proof."""
    try:
        receipt = dict(version=1, repository=os.environ['GITHUB_REPOSITORY'],
                       run_id=int(os.environ['GITHUB_RUN_ID']),
                       head_sha=os.environ['CI_RUNTIME_HEAD_SHA'],
                       attempt=int(os.environ['GITHUB_RUN_ATTEMPT']), workflow=workflow,
                       reason=reason, cancelled_job_ids=sorted(cancelled_ids))
        require(re.fullmatch(r'[0-9a-f]{40}', receipt['head_sha'])
                and receipt['run_id'] > 0 and receipt['attempt'] in (1, 2), 'Invalid receipt identity')
    except (KeyError, ValueError, BudgetError):
        return
    print(RECEIPT_PREFIX + json.dumps(receipt, sort_keys=True, separators=(',', ':')))


def accounting_log(repo, job_id):
    result = subprocess.run(['gh', 'api', f'repos/{repo}/actions/jobs/{job_id}/logs'],
                            capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and len(result.stdout.encode()) <= 1024 * 1024,
            'Original accounting log unavailable or oversized')
    return result.stdout


def verify_original_accounting(repo, jobs, approval):
    lanes = {'validate runtime budget': 'validate.yml',
             'pi-native / pi-native runtime budget': 'pi-native.yml',
             'claude-native / claude-native runtime budget': 'claude-native.yml'}
    approved = set(approval['cancelled_job_ids'])
    for job in jobs:
        if job['name'] not in lanes or job['conclusion'] == 'success':
            continue
        require(job['conclusion'] in ('failure', 'cancelled'), 'Original accounting did not execute')
        lines = accounting_log(repo, job['id']).splitlines()
        records = []
        for line in lines:
            match = re.fullmatch(r'(?:\d{4}-\d\d-\d\dT\S+Z )?' + re.escape(RECEIPT_PREFIX) + r'(.*)', line)
            if match:
                require(0 < len(match[1].encode()) <= 1024, 'Oversized accounting receipt')
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        require(key not in result, 'Duplicate accounting receipt field')
                        result[key] = value
                    return result
                try:
                    records.append(json.loads(match[1], object_pairs_hook=unique))
                except (ValueError, RecursionError) as error:
                    raise BudgetError('Malformed accounting receipt') from error
        require(len(records) == 1, 'Missing or ambiguous original accounting receipt')
        receipt = records[0]
        workflow = lanes[job['name']]
        expected = dict(version=1, repository=repo, run_id=approval['run_id'],
                        head_sha=approval['head_sha'], attempt=1, workflow=workflow)
        require(type(receipt) is dict and set(receipt) == set(expected) | {'reason', 'cancelled_job_ids'}
                and all(type(receipt[key]) is type(value) and receipt[key] == value
                        for key, value in expected.items()), 'Original accounting receipt identity mismatch')
        ids = receipt['cancelled_job_ids']
        require(type(ids) is list and all(type(value) is int and value > 0 for value in ids)
                and len(set(ids)) == len(ids), 'Invalid receipt cancellation identities')
        reason = receipt['reason']
        require(reason in ('passed', 'evidence_unavailable', 'functional_cancellation'),
                'Original accounting failure is not recoverable')
        steps = job.get('steps', [])
        checks = [step for step in steps if step.get('name') == 'Enforce measured runtime growth and absolute ceiling']
        require(len(checks) == 1 and checks[0].get('status') == 'completed', 'Original accounting step missing')
        if reason == 'passed':
            require_successful_recovery_steps(job)
            require(job['conclusion'] == 'cancelled' and not ids
                    and checks[0].get('conclusion') == 'success'
                    and job_timing(job)['finalization'] > 0,
                    'Accounting cancellation was not after successful verification')
        else:
            require(checks[0].get('conclusion') == 'failure', 'Accounting failure receipt contradicts step')
            checked = dict(job, steps=[dict(step, conclusion='success') if step is checks[0]
                                      else dict(step) for step in steps])
            require_successful_recovery_steps(checked)
            timing = job_timing(checked)
            require(job['conclusion'] != 'cancelled' or timing['finalization'] > 0,
                    'Accounting cancellation occurred before complete runner steps')
            if reason == 'evidence_unavailable':
                require(not ids, 'Unexpected infrastructure receipt identities')
            else:
                lane_ids = {row['id'] for row in scoped_jobs(workflow, jobs, '.github/workflows/verify.yaml')
                            if row['id'] in approved}
                require(ids and set(ids) == lane_ids, 'Accounting cancellation receipt differs from approval')


RECOVERY_CACHE_PROOF = 'Confirm exact public npm acquisition cache hit'
RECOVERY_CACHE_SAVE = 'Save verified public acquisition bytes before fixture execution'
RECOVERY_CACHE_PREREQUISITES = frozenset((
    'Restore exact locked public npm acquisition cache',
    'Acquire exact official package without lifecycle scripts or account configuration',
    'Acquire matching official TypeScript SDK without extra native binaries or scripts',
    'Acquire exact existing Library parser without lifecycle scripts',
    'Actual Claude CLI against loopback protocol fixture, never upstream'))


def require_successful_recovery_steps(job):
    """Only named nonfunctional branches may skip after affirmative execution proof."""
    steps = job['steps']
    names = [step.get('name') for step in steps]
    require(all(type(name) is str and name for name in names)
            and len(names) == len(set(names)), 'Ambiguous recovery step inventory')
    require(all(step.get('status') == 'completed' for step in steps),
            'Incomplete recovery step')
    by_name = {step['name']: step['conclusion'] for step in steps}
    skipped = {name for name, result in by_name.items() if result == 'skipped'}
    require(all(result in ('success', 'skipped') for result in by_name.values()),
            'Failed recovery step')
    name = job['name']
    cache_jobs = {'claude-native / official-claude-fixture-0',
                  'claude-native / official-claude-fixture-1'}
    cache_steps = {RECOVERY_CACHE_PROOF, RECOVERY_CACHE_SAVE}
    if name in cache_jobs and cache_steps & set(by_name):
        require(cache_steps <= set(by_name)
                and {by_name[step] for step in cache_steps} == {'success', 'skipped'},
                'Missing or inconsistent cache branch proof')
    if not skipped:
        return
    allowed = set()
    if name in UNIT_JOBS:
        test = ('Validate successor interfaces' if name == 'validate' else
                'Validate measured slow unit partition' if name == 'unit-slow' else
                'Validate measured integration unit partition')
        prerequisites = {'Detect test applicability', 'Install pinned Python dependencies', test}
        if name == 'validate':
            prerequisites.add('Check account-free local CLI process lifecycle')
        if all(by_name.get(step) == 'success' for step in prerequisites):
            allowed.add('Report tests not applicable')
    if name in {'claude-native / official-claude-fixture-0',
                'claude-native / official-claude-fixture-1'}:
        if all(by_name.get(step) == 'success' for step in RECOVERY_CACHE_PREREQUISITES):
            if by_name.get(RECOVERY_CACHE_PROOF) == 'success' and by_name.get(RECOVERY_CACHE_SAVE) == 'skipped':
                allowed.add(RECOVERY_CACHE_SAVE)
            elif by_name.get(RECOVERY_CACHE_SAVE) == 'success' and by_name.get(RECOVERY_CACHE_PROOF) == 'skipped':
                allowed.add(RECOVERY_CACHE_PROOF)
    require(skipped <= allowed, 'Skipped functional or unproved recovery step')


def normalize_original_cancellations(jobs, approval):
    """Copy for accounting only; original GitHub conclusions are immutable."""
    ids = [job.get('id') for job in jobs]
    require(all(type(value) is int and value > 0 for value in ids)
            and len(set(ids)) == len(ids), 'Invalid original job identities')
    expected = set(approval['cancelled_job_ids'])
    cancelled = {job['id'] for job in jobs if job.get('conclusion') == 'cancelled'
                 and job.get('name') in recovery_functional_names()}
    require(cancelled == expected, 'Original cancellation inventory differs from approval')
    result = []
    for job in jobs:
        require(type(job.get('run_id')) is int and job.get('run_id') == approval['run_id']
                and job.get('run_attempt') == 1
                and job.get('head_sha') == approval['head_sha'],
                'Original job/run/attempt/head mismatch')
        if job['id'] in expected:
            require(job.get('status') == 'completed', 'Original cancellation is not terminal')
            timing = job_timing(job)
            require_successful_recovery_steps(job)
            require(timing['finalization'] > 0,
                    'Cancellation was not after successful complete runner steps')
            result.append(dict(job, conclusion='success'))
        else:
            result.append(dict(job))
    return result

def recovery_functional_names():
    names = set().union(*STAGES['validate.yml'])
    for workflow, prefix in (('pi-native.yml', 'pi-native / '),
                             ('claude-native.yml', 'claude-native / ')):
        names.update(prefix + name for stage in STAGES[workflow] for name in stage)
    return names


RECOVERY_ACCOUNTING = frozenset(('validate runtime budget',
    'pi-native / pi-native runtime budget', 'claude-native / claude-native runtime budget'))
RECOVERY_DURABLE = 'pi-durable-fit / model-free-fit'


def recovery_inventory(jobs, approval, attempt, *, original=False):
    """Validate fixed unified functional graph, not a caller-selected subset."""
    names = [job.get('name') for job in jobs]
    ids = [job.get('id') for job in jobs]
    functional = recovery_functional_names()
    require(len(names) == len(set(names)) and len(ids) == len(set(ids))
            and all(type(value) is int and value > 0 for value in ids),
            'Duplicate or invalid recovery jobs')
    require(all(type(job.get('run_id')) is int and job.get('run_id') == approval['run_id']
                and type(job.get('run_attempt')) is int
                and job['run_attempt'] == attempt
                and job.get('head_sha') == approval['head_sha'] for job in jobs),
            'Recovery job/run/attempt/head identity mismatch')
    by_name = {job['name']: job for job in jobs}
    durable = set(names) & {'pi-durable-fit', RECOVERY_DURABLE}
    require(len(durable) == 1 and functional <= set(names)
            and set(names) <= functional | RECOVERY_ACCOUNTING | {'verify'} | durable,
            'Incomplete or unexpected recovery graph')
    for name in functional:
        job = by_name[name]
        require(job.get('status') == 'completed' and job.get('conclusion') == 'success',
                'Recovery functional job did not succeed')
        job_timing(job)
        if any(step.get('conclusion') == 'skipped' for step in job['steps']):
            require_successful_recovery_steps(job)
    durable_name = next(iter(durable))
    job = by_name[durable_name]
    require(job.get('status') == 'completed', 'Durable-fit recovery evidence incomplete')
    if durable_name == 'pi-durable-fit':
        require(job.get('conclusion') == 'skipped' and job.get('steps') == [],
                'Invalid durable-fit exemption shape')
    else:
        require(job.get('conclusion') == 'success', 'Durable-fit recovery failed')
        job_timing(job)
    required_accounting = RECOVERY_ACCOUNTING if original else (
        RECOVERY_ACCOUNTING - {'validate runtime budget'})
    require(required_accounting <= set(names), 'Missing recovery accounting jobs')
    for name in required_accounting:
        require(by_name[name].get('status') == 'completed', 'Recovery accounting incomplete')
        if not original:
            require(by_name[name].get('conclusion') == 'success',
                    'Replacement native accounting failed')
    if original:
        require('verify' in by_name and by_name['verify'].get('status') == 'completed',
                'Original verification is not terminal')
    return durable_name

def recovery_original(repo, current, approval):
    require(repo == approval['repository'] and type(current.get('id')) is int
            and current.get('id') == approval['run_id']
            and type(current.get('head_branch')) is str and bool(current['head_branch'])
            and current.get('head_sha') == approval['head_sha']
            and type(current.get('run_attempt')) is int and current['run_attempt'] == 2
            and current.get('path') == '.github/workflows/verify.yaml',
            'Recovery approval does not match current run')
    original = api(repo, f'actions/runs/{approval["run_id"]}/attempts/1')
    require(original.get('status') == 'completed'
            and original.get('conclusion') in ('failure', 'cancelled')
            and type(original.get('run_attempt')) is int and original['run_attempt'] == 1
            and all(original.get(key) == current.get(key) for key in
                    ('id', 'head_sha', 'path', 'event', 'head_branch')),
            'Original recovery run identity mismatch')
    jobs = run_jobs(repo, approval['run_id'])
    require(conclusion_digest(jobs) == approval['original_job_conclusions_sha256'],
            'Original conclusion inventory differs from approval')
    cancelled = set(approval['cancelled_job_ids'])
    require(all(job.get('name') in recovery_functional_names()
                for job in jobs if job.get('id') in cancelled),
            'Only functional job cancellations may be recovered')
    copied = normalize_original_cancellations(jobs, approval)
    recovery_inventory(copied, approval, 1, original=True)
    verify_original_accounting(repo, jobs, approval)
    for workflow in STAGES:
        require(critical_path(workflow, scoped_jobs(workflow, copied, original['path'])) is not None,
                'Documentation-only recovery is not permitted')
    return copied, original


def validate_replacement_inventory(jobs, original_jobs, approval):
    durable = recovery_inventory(jobs, approval, 2)
    original_durable = ({job['name'] for job in original_jobs}
                        & {'pi-durable-fit', RECOVERY_DURABLE})
    require(original_durable == {durable}, 'Replacement changed durable-fit applicability')

def check(repo, workflow, branch, base, run_id, recovery_approval=None):
    require(re.fullmatch(r'[\w.-]+/[\w.-]+', repo) and re.fullmatch(r'[0-9a-f]{40}', base)
            and run_id > 0, 'Invalid repository, base or run identity')
    current = api(repo, f'actions/runs/{run_id}')
    require(current['path'] in (f'.github/workflows/{workflow}', '.github/workflows/verify.yaml')
            and current['event'] in ('push', 'pull_request'), 'Current workflow identity mismatch')
    original_elapsed = None
    attempt = 1
    if recovery_approval is not None:
        original_jobs, original = recovery_original(repo, current, recovery_approval)
        attempt = 2
        jobs = run_jobs(repo, run_id, attempt)
        require(all(job.get('head_sha') == recovery_approval['head_sha'] for job in jobs),
                'Replacement head mismatch')
        if workflow == 'validate.yml':
            validate_replacement_inventory(jobs, original_jobs, recovery_approval)
        original_elapsed = critical_path(workflow, scoped_jobs(workflow, original_jobs, original['path']))
    else:
        jobs = run_jobs(repo, run_id)
    diagnostics = {}
    selected = scoped_jobs(workflow, jobs, current['path'])
    try:
        elapsed = critical_path(workflow, selected, diagnostics=diagnostics)
    except BudgetError as error:
        cancelled = [job for job in selected if job.get('conclusion') == 'cancelled'
                     and job.get('name') != workflow.removesuffix('.yml') + ' runtime budget']
        if recovery_approval is None and cancelled and any(str(error) ==
                f'{job["name"]} did not complete successfully; no runtime acceptance' for job in cancelled):
            raise CancelledFunctionalJob(str(error), [job['id'] for job in cancelled]) from error
        raise
    if elapsed is None:
        return 'Documentation-only run: runtime unchanged; no new full-suite baseline.'
    details = (f'Full job-wall critical path: {diagnostics["wall_path"]:.1f}s; '
               f'observed lane span (including queue gaps): {diagnostics["span"]:.1f}s. '
               'Per-job pre-step / execution / after-step finalization / full wall (seconds): '
               + '; '.join(f'{name}: {timing["provisioning"]:.1f} / {timing["execution"]:.1f} / {timing["finalization"]:.1f} / {timing["wall"]:.1f}'
                           for name, timing in sorted(diagnostics['jobs'].items())) + '.')
    require(elapsed <= ABSOLUTE_SECONDS,
            f'CI critical path {elapsed:.1f}s exceeds the absolute 150-second ceiling. ' + details)
    previous, samples = baseline(repo, workflow, branch, base, run_id)
    limit = allowed_seconds(previous)
    if original_elapsed is not None:
        require(original_elapsed <= limit,
                f'Original first-attempt critical path {original_elapsed:.1f}s exceeds {limit:.1f}s; recovery refused')
    sources = '; '.join(f'run {number}, commit {commit}: {seconds:.1f}s'
                        for number, commit, seconds in samples)
    attempt_label = 'first attempt' if attempt == 1 else 'explicitly approved attempt 2'
    summary = (f'CI critical path ({attempt_label}): {elapsed:.1f}s; baseline median: {previous:.1f}s; '
               f'limit: {limit:.1f}s (+{GROWTH_PERCENT}%, absolute {ABSOLUTE_SECONDS}s). '
               f'Sources: {sources}. All current and historical samples use first Set up job start through final Complete job step; '
               'all setup, installation, tests, inter-step gaps and cleanup remain included. ' + details)
    require(elapsed <= limit, summary + ' Runtime growth exceeds the allowance.')
    if attempt == 2:
        summary += (f' Original first attempt: {original_elapsed:.1f}s, independently within the same limit. '
                    'Original GitHub conclusions remain unchanged; recovery is not a baseline sample.')
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workflow', choices=STAGES)
    parser.add_argument('--base', required=True)
    args = parser.parse_args(argv)
    try:
        message = check(os.environ['GITHUB_REPOSITORY'], args.workflow,
                        os.environ['DEFAULT_BRANCH'], args.base, int(os.environ['GITHUB_RUN_ID']),
                        recovery_approval=parse_recovery_approval(os.environ.get('CI_RUNTIME_RECOVERY_APPROVAL', '')))
        print(message)
        emit_accounting_receipt(args.workflow, 'passed')
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
                output.write(message + '\n')
        return 0
    except (BudgetError, KeyError, ValueError, TypeError, AttributeError, OSError, subprocess.TimeoutExpired) as error:
        if isinstance(error, EvidenceUnavailable):
            emit_accounting_receipt(args.workflow, 'evidence_unavailable')
        elif isinstance(error, CancelledFunctionalJob):
            emit_accounting_receipt(args.workflow, 'functional_cancellation', error.job_ids)
        print(str(error) if isinstance(error, BudgetError) else 'Invalid or unavailable CI timing evidence',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
