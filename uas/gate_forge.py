"""Bounded Forge observations and pure Gate reduction, not provider authority.

Only the external Broker constructs ``BrokerForgeState`` with its existing
fixed-host transport. The Hub records intent before observe(), authenticates the
Broker channel, and owns immutable Evaluation/Check records. This module grants
no Participant route, credentials, retries, waits, workflow writes or verdicts
from provider prose. A fresh observation is required after every wait.
"""
from copy import deepcopy
import hashlib
import json
import re
from urllib.parse import quote

from .github_pr import _pull, _sha
from .github_read import GitHubProject, ProviderFailure, _positive
from .github_surface import _Read, _check, _status, _run, _job, _number, _text
from .ledger import LedgerError, Origin, _token

MAX_CI = 32
MAX_BYTES = 48_000
MAX_CALLS = 80
KINDS = frozenset({'check-run', 'commit-status', 'actions-workflow', 'actions-job'})
PURPOSES = frozenset({'complete-suite', 'focused', 'specialized'})
COVERAGE = frozenset({'head', 'head-or-test-merge'})
_TARGET_KEYS = {'repository', 'pull_number', 'pull_id', 'head_sha', 'base_sha', 'base_ref'}
_CI_KEYS = {'id', 'kind', 'producer_id', 'context', 'coverage', 'purpose'}
_SAFE_RULES = frozenset({'creation', 'update', 'deletion', 'non_fast_forward',
    'required_linear_history', 'required_signatures', 'pull_request'})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def gate_forge_origin(room_instance):
    return Origin('gate-hub', 'gate-hub', _token(room_instance),
                  'hub-gate-forge-v1', ('forge-gate',))


def unavailable_forge_observation(target, code):
    result = {'source': 'external-forge-broker', 'status': code,
        'completeness': 'unknown', 'target': validate_forge_target(target),
        'pull': None, 'required': None, 'ancestry': None, 'revisions': [],
        'test_merge': None, 'pages': 0}
    result['observation_digest'] = _digest(result)
    return result


def unavailable_target_observation(target, code):
    result = {'source': 'external-forge-broker', 'status': code,
        'completeness': 'unknown', 'target': validate_forge_target(target),
        'pull': None, 'ancestry': None, 'pages': 0}
    result['observation_digest'] = _digest(result)
    return result


class ExternalGateForgeBroker:
    """Audited internal Gate reader, reusing the sole external Broker owner.

    Credential identity is immutable trusted startup configuration. Participant
    capability names, source strings and envelope fields cannot select it.
    Repeating an uncertain operation never performs another provider read.
    """
    def __init__(self, binding, room_instance, audit, actor_id, providers):
        from .forge import ForgeBinding
        from .forge_audit import ForgeAudit
        if type(binding) is not ForgeBinding or type(audit) is not ForgeAudit or not callable(providers):
            raise LedgerError('INVALID_GATE_FORGE_OWNER')
        self.binding, self.room_instance, self.audit = binding, _token(room_instance), audit
        self.actor_id, self.providers = _token(actor_id), providers
        self.project = GitHubProject(binding.repository, binding.host)
        self.failed = False

    def _guard(self, origin, authorize):
        if self.failed: raise LedgerError('AUDIT_UNAVAILABLE')
        if origin != gate_forge_origin(self.room_instance) or authorize() is not True:
            raise LedgerError('FORBIDDEN')
        return True

    def execute(self, envelope, *, origin, authorize):
        from .forge_read_provider import BrokerReadProvider
        from .forge_audit import READ_AUDIT_STATUSES
        guard = lambda: self._guard(origin, authorize)
        guard()
        if (type(envelope) is not dict or envelope.get('kind') not in {'gate-forge', 'gate-target'}
                or set(envelope) != ({'id', 'kind', 'target', 'config'}
                    if envelope['kind'] == 'gate-forge' else {'id', 'kind', 'target'})):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        target = validate_forge_target(envelope['target'])
        config = compile_forge_config(envelope['config']) if envelope['kind'] == 'gate-forge' else None
        unavailable = unavailable_forge_observation if config is not None else unavailable_target_observation
        if target['repository'] != self.binding.repository:
            raise LedgerError('PROJECT_MISMATCH')
        operation = 'gate-forge-' + _digest([self.binding.room_id, self.room_instance, _token(envelope['id'])])
        metadata = {'room_id': self.binding.room_id, 'room_instance': self.room_instance,
            'project_id': self.binding.project_id, 'actor_id': self.actor_id,
            'participant_id': origin.participant_id, 'incarnation_id': origin.incarnation_id,
            'authority_version': origin.authority_version, 'provider_host': 'github.com',
            'requested_repository': self.binding.repository, 'effective_repository': self.binding.repository,
            'route': envelope['kind'], 'request_digest': _digest(envelope), 'origin_digest': _digest(origin.canonical())}
        try:
            begin = self.audit.begin_read(operation, metadata)
            if not begin['started']:
                # Audit is metadata-only. A lost provider response cannot be
                # reconstructed into a pass or trigger hidden recontact.
                guard()
                return {'observation': unavailable(target, 'INTERRUPTED_OBSERVATION'),
                        'audit_reference': operation}
            contacted = False
            try:
                guard()
                provider = self.providers(self.actor_id)
                if type(provider) is not BrokerReadProvider or provider.project != self.project:
                    raise LedgerError('INVALID_GATE_FORGE_OWNER')
                def transport(path):
                    nonlocal contacted
                    guard()
                    contacted = True
                    return provider.transport(path)
                observer = BrokerForgeState(self.project, transport)
                observation = (observer.observe(target, config) if config is not None
                               else observer.observe_target(target))
                (validate_forge_observation if config is not None else validate_target_observation)(observation, target)
            except Exception as error:
                code = getattr(error, 'code', '')
                code = code if type(code) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', code) else 'PROVIDER_ERROR'
                observation = unavailable(target, code)
            raw = _canonical(observation)
            status = observation['status']
            audit_status = status if status in READ_AUDIT_STATUSES else 'INVALID_PROVIDER_OBSERVATION'
            self.audit.finish_read(operation, {'status': audit_status,
                'completeness': observation['completeness'], 'contact': 'read' if contacted else 'none',
                'output_bytes': len(raw), 'dropped_bytes': 0 if status == 'OK' else None,
                'observation_digest': hashlib.sha256(raw).hexdigest()})
            guard()
            return {'observation': observation, 'audit_reference': operation}
        except LedgerError as error:
            if error.code == 'AUDIT_UNAVAILABLE': self.failed = True
            raise


def compile_forge_config(config, field='gate.config'):
    """Exact source/context policy; coverage labels are never inferred from names."""
    from .config import ConfigError, _object, _array, _id, _integer, _text as text
    value = deepcopy(config)
    _object(value, field, ('ci',))
    items = _array(value['ci'], field + '.ci')
    if len(items) > MAX_CI:
        raise ConfigError(field + '.ci', 'CI configuration exceeds 32 items')
    seen, selectors = set(), set()
    for index, item in enumerate(items):
        path = f'{field}.ci[{index}]'
        _object(item, path, tuple(sorted(_CI_KEYS)))
        _id(item['id'], path + '.id')
        _integer(item['producer_id'], path + '.producer_id')
        text(item['context'], path + '.context', 512)
        if len(item['context'].encode('utf-8')) > 512:
            raise ConfigError(path + '.context', 'CI context exceeds 512 UTF-8 bytes')
        for key, choices in (('kind', KINDS), ('purpose', PURPOSES), ('coverage', COVERAGE)):
            if type(item[key]) is not str or item[key] not in choices:
                raise ConfigError(path + '.' + key, 'unsupported CI contract')
        selector = tuple(item[key] for key in ('kind', 'producer_id', 'context'))
        if item['id'] in seen or selector in selectors:
            raise ConfigError(path, 'duplicate CI identity or producer/context selector')
        seen.add(item['id']); selectors.add(selector)
    if not any(item['purpose'] == 'complete-suite' for item in items):
        raise ConfigError(field + '.ci', 'an explicit complete-suite requirement is required')
    value['ci'] = sorted(items, key=lambda item: item['id'])
    return value


def validate_forge_target(value):
    try:
        if type(value) is not dict or set(value) != _TARGET_KEYS:
            raise ValueError()
        GitHubProject(value['repository'])
        if (not _positive(value['pull_number']) or value['pull_number'] > 9_999_999_999
                or not _positive(value['pull_id'])):
            raise ValueError()
        _sha(value['head_sha']); _sha(value['base_sha'])
        ref = _text(value['base_ref'], 255)
        if (not ref or ref.startswith('/') or ref.endswith('/') or '..' in ref
                or any(c in ref for c in '\\*?[~^:')
                or any(ord(c) <= 32 or ord(c) == 127 for c in ref)):
            raise ValueError()
        return deepcopy(value)
    except (ValueError, TypeError, KeyError, LedgerError):
        raise LedgerError('INVALID_FORGE_GATE_TARGET') from None


def _matches_pull(pull, target):
    return (pull['id'] == target['pull_id'] and pull['number'] == target['pull_number']
            and pull['head']['sha'] == target['head_sha']
            and pull['base']['sha'] == target['base_sha']
            and pull['base']['ref'] == target['base_ref']
            and pull['base']['repo']['full_name'] == target['repository'])


def _requirement(context, producer, *, source):
    context = _text(context, 512)
    if not context or (producer is not None and not _positive(producer)):
        raise ValueError()
    return {'context': context, 'producer_id': producer, 'source': source}


def _ordered_requirements(rows):
    return sorted(rows, key=lambda row: (row['source'], row['context'],
                                         row['producer_id'] if row['producer_id'] is not None else -1))


def _classic(value, repository, ref):
    if type(value) is not dict or 'required_status_checks' not in value:
        raise ValueError()
    expected = f'https://api.github.com/repos/{repository}/branches/{quote(ref, safe="")}/protection'
    if value.get('url') != expected:
        raise ValueError()
    checks = value['required_status_checks']
    if checks is None:
        return {'strict': False, 'checks': []}
    if (type(checks) is not dict or type(checks.get('strict')) is not bool
            or type(checks.get('contexts')) is not list or type(checks.get('checks')) is not list
            or len(checks['checks']) > 100 or len(checks['contexts']) > 100):
        raise ValueError()
    rows = []
    for check in checks['checks']:
        if type(check) is not dict:
            raise ValueError()
        producer = check.get('app_id')
        if producer == -1: producer = None
        rows.append(_requirement(check.get('context'), producer, source='branch-protection'))
    # Legacy contexts must be represented even if the provider omits checks.
    for context in checks['contexts']:
        if not any(row['context'] == context for row in rows):
            rows.append(_requirement(context, None, source='branch-protection'))
    if len({_canonical(row) for row in rows}) != len(rows):
        raise ValueError()
    return {'strict': checks['strict'], 'checks': _ordered_requirements(rows)}


def _rule(value):
    if (type(value) is not dict or not _positive(value.get('ruleset_id'))
            or value.get('ruleset_source_type') not in {'Repository', 'Organization', 'Enterprise'}):
        raise ValueError()
    kind, identifier = value.get('type'), value['ruleset_id']
    source = _text(value.get('ruleset_source'), 512)
    if kind == 'required_status_checks':
        parameters = value.get('parameters')
        if (type(parameters) is not dict or type(parameters.get('required_status_checks')) is not list
                or len(parameters['required_status_checks']) > 100
                or type(parameters.get('strict_required_status_checks_policy')) is not bool):
            raise ValueError()
        rows = []
        for row in parameters['required_status_checks']:
            if type(row) is not dict: raise ValueError()
            rows.append(_requirement(row.get('context'), row.get('integration_id'),
                                     source='ruleset-' + str(identifier)))
        if len({_canonical(row) for row in rows}) != len(rows): raise ValueError()
        return {'id': str(identifier) + ':' + kind, 'type': kind, 'source': source,
                'strict': parameters['strict_required_status_checks_policy'], 'checks': _ordered_requirements(rows)}
    if kind not in _SAFE_RULES:
        # E.g. required workflows, deployments and merge queues require their
        # own explicit evidence, not silent conversion to an empty check set.
        raise LedgerError('UNSUPPORTED_FORGE_REQUIRED_RULE')
    return {'id': str(identifier) + ':' + kind, 'type': kind, 'source': source,
            'strict': False, 'checks': [], 'parameters_digest': _digest(value.get('parameters'))}


class _GateRead(_Read):
    def __init__(self, owner):
        super().__init__(owner)
        self.calls = 0

    def get(self, path, **kwargs):
        self.calls += 1
        if self.calls > MAX_CALLS:
            raise ProviderFailure('OUTPUT_LIMIT')
        return super().get(path, **kwargs)


class BrokerForgeState:
    """Internal, read-only Broker seam using its existing pinned transport.

    No cache is consulted. Each call rereads target, branch requirements, ancestry
    and latest CI attempts, with closing reads. Bounded pending is an observation,
    never a retry loop; the Hub's durable operation owner schedules any later call.
    """
    host = 'github.com'

    def __init__(self, project, transport, *, max_pages=10, max_bytes=1_048_576):
        if type(project) is not GitHubProject or not callable(transport):
            raise LedgerError('INVALID_PROJECT')
        if (type(max_pages) is not int or not 1 <= max_pages <= 10
                or type(max_bytes) is not int or not 1 <= max_bytes <= 1_048_576):
            raise LedgerError('INVALID_PROVIDER_LIMIT')
        self.project, self.transport = project, transport
        self.max_pages, self.max_bytes = max_pages, max_bytes

    def observe_target(self, target):
        """Narrow exact-PR bind proof, independent of a configured CI Gate."""
        target = validate_forge_target(target)
        if target['repository'] != self.project.repository: raise LedgerError('PROJECT_MISMATCH')
        read = _GateRead(self)
        result = unavailable_target_observation(target, 'PROVIDER_ERROR')
        result.pop('observation_digest')
        try:
            base = 'repos/' + self.project.repository
            endpoint = base + '/pulls/' + str(target['pull_number'])
            pull = read.one(endpoint, lambda v: _pull(v, self.project, target['pull_number']))
            if not _matches_pull(pull, target): raise LedgerError('GATE_FORGE_TARGET_CHANGED')
            def branch(value):
                if (type(value) is not dict or value.get('name') != target['base_ref']
                        or type(value.get('commit')) is not dict
                        or _sha(value['commit'].get('sha')) != target['base_sha']):
                    raise LedgerError('GATE_FORGE_TARGET_CHANGED')
                return target['base_sha']
            branch_endpoint = base + '/branches/' + quote(target['base_ref'], safe='')
            read.one(branch_endpoint, branch)
            def ancestry(value):
                if (type(value) is not dict or type(value.get('base_commit')) is not dict
                        or _sha(value['base_commit'].get('sha')) != target['base_sha']
                        or type(value.get('merge_base_commit')) is not dict
                        or value.get('status') not in {'ahead', 'behind', 'identical', 'diverged'}):
                    raise ValueError()
                return {'base_sha': target['base_sha'], 'head_sha': target['head_sha'],
                    'merge_base_sha': _sha(value['merge_base_commit'].get('sha')), 'status': value['status']}
            ancestor = read.one(base + '/compare/' + target['base_sha'] + '...' + target['head_sha'], ancestry)
            closing = read.one(endpoint, lambda v: _pull(v, self.project, target['pull_number']))
            if closing != pull: raise LedgerError('GATE_FORGE_TARGET_CHANGED')
            read.one(branch_endpoint, branch)
            result.update(status='OK', completeness='complete', pull=pull, ancestry=ancestor)
        except Exception as error:
            code = getattr(error, 'code', '')
            result['status'] = code if type(code) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', code) else 'INVALID_FORGE_OBSERVATION'
        result['pages'] = read.pages
        if len(_canonical(result)) > MAX_BYTES - 128:
            result = unavailable_target_observation(target, 'OUTPUT_LIMIT'); result.pop('observation_digest')
        result['observation_digest'] = _digest(result)
        return result

    def _requirements(self, read, target):
        base = 'repos/' + self.project.repository
        ref = quote(target['base_ref'], safe='')
        def branch(value):
            if (type(value) is not dict or value.get('name') != target['base_ref']
                    or type(value.get('protected')) is not bool
                    or type(value.get('commit')) is not dict):
                raise ValueError()
            if _sha(value['commit'].get('sha')) != target['base_sha']:
                raise LedgerError('GATE_FORGE_TARGET_CHANGED')
            return {'name': value['name'], 'sha': value['commit']['sha'], 'protected': value['protected']}
        observed = read.one(base + '/branches/' + ref, branch)
        # A 404 when protected is true is unavailable, never unprotected.
        classic = (read.one(base + '/branches/' + ref + '/protection',
            lambda v: _classic(v, self.project.repository, target['base_ref']))
            if observed['protected'] else {'strict': False, 'checks': []})
        rules = read.many(base + '/rules/branches/' + ref, _rule)
        return {'branch': observed, 'classic': classic, 'rules': sorted(rules, key=lambda row: row['id'])}

    def _revision(self, read, sha, config):
        repository = self.project.repository
        base = 'repos/' + repository
        checks = read.many(base + '/commits/' + sha + '/check-runs?filter=latest',
                           lambda v: _check(v, repository, sha), key='check_runs')
        if len({(c['producer']['id'], c['name']) for c in checks}) != len(checks):
            raise LedgerError('AMBIGUOUS_LATEST_CHECK')
        statuses = read.many(base + '/commits/' + sha + '/statuses',
                            lambda v: _status(v, repository, sha))
        # GitHub documents newest-first status enumeration; retain the first
        # per exact creator/context, not a maximum guessed from numeric IDs.
        latest, seen = [], set()
        for status in statuses:
            marker = status['creator']['id'], status['context']
            if marker not in seen: latest.append(status); seen.add(marker)
        def run(value):
            result = _run(value, repository)
            if result['head_sha'] != sha: raise ValueError()
            result['run_number'] = _number(value.get('run_number'))
            result['pull_requests'].sort(key=lambda p: p['id'])
            return result
        runs = read.many(base + '/actions/runs?head_sha=' + sha, run, key='workflow_runs')
        selected = {}
        for observed in runs:
            marker = observed['workflow_id'], observed['event']
            previous = selected.get(marker)
            if previous is None or observed['run_number'] > previous['run_number']:
                selected[marker] = observed
            elif observed['run_number'] == previous['run_number']:
                raise LedgerError('AMBIGUOUS_LATEST_RUN')
        result = []
        for observed in sorted(selected.values(), key=lambda r: (r['workflow_id'], r['event'])):
            relevant = any(i['kind'].startswith('actions-') and i['producer_id'] == observed['workflow_id']
                           for i in config['ci'])
            if not relevant: continue
            endpoint = base + '/actions/runs/' + str(observed['id'])
            current = read.one(endpoint, run)
            if current != observed: raise LedgerError('GATE_FORGE_ATTEMPT_CHANGED')
            jobs = read.many(endpoint + '/attempts/' + str(current['run_attempt']) + '/jobs',
                            lambda v: _job(v, repository, current), key='jobs')
            if len({job['name'] for job in jobs}) != len(jobs):
                raise LedgerError('AMBIGUOUS_LATEST_JOB')
            jobs.sort(key=lambda job: job['id'])
            final = read.one(endpoint, run)
            if final != current: raise LedgerError('GATE_FORGE_ATTEMPT_CHANGED')
            result.append({'run': current, 'jobs': jobs})
        return {'tested_sha': sha, 'checks': checks, 'statuses': latest, 'runs': result}

    def observe(self, target, config):
        target = validate_forge_target(target)
        config = compile_forge_config(config)
        if target['repository'] != self.project.repository:
            raise LedgerError('PROJECT_MISMATCH')
        read = _GateRead(self)
        result = {'source': 'external-forge-broker', 'status': 'PROVIDER_ERROR',
            'completeness': 'unknown', 'target': target, 'pull': None,
            'required': None, 'ancestry': None, 'revisions': [], 'test_merge': None, 'pages': 0}
        try:
            base = 'repos/' + self.project.repository
            endpoint = base + '/pulls/' + str(target['pull_number'])
            pull = read.one(endpoint, lambda v: _pull(v, self.project, target['pull_number']))
            if not _matches_pull(pull, target): raise LedgerError('GATE_FORGE_TARGET_CHANGED')
            required = self._requirements(read, target)
            def ancestry(value):
                if (type(value) is not dict or type(value.get('base_commit')) is not dict
                        or _sha(value['base_commit'].get('sha')) != target['base_sha']
                        or type(value.get('merge_base_commit')) is not dict
                        or value.get('status') not in {'ahead', 'behind', 'identical', 'diverged'}):
                    raise ValueError()
                return {'base_sha': target['base_sha'], 'head_sha': target['head_sha'],
                    'merge_base_sha': _sha(value['merge_base_commit'].get('sha')), 'status': value['status']}
            ancestor = read.one(base + '/compare/' + target['base_sha'] + '...' + target['head_sha'], ancestry)
            revisions = [self._revision(read, target['head_sha'], config)]
            merge = None
            merge_sha = pull['merge_commit_sha']
            if (any(i['coverage'] == 'head-or-test-merge' for i in config['ci'])
                    and pull['state'] == 'open' and not pull['merged']
                    and merge_sha is not None and merge_sha != target['head_sha']):
                def parents(value):
                    if (type(value) is not dict or value.get('sha') != merge_sha
                            or value.get('url') != f'https://api.github.com/{base}/commits/{merge_sha}'
                            or type(value.get('parents')) is not list or len(value['parents']) > 8):
                        raise ValueError()
                    return [_sha(p.get('sha')) for p in value['parents']]
                observed = read.one(base + '/commits/' + merge_sha, parents)
                merge = {'tested_sha': merge_sha, 'parents': observed,
                         'candidate_sha': target['head_sha'], 'base_sha': target['base_sha']}
                # Unknown association is retained as non-qualifying evidence.
                if observed == [target['base_sha'], target['head_sha']]:
                    revisions.append(self._revision(read, merge_sha, config))
            closing = read.one(endpoint, lambda v: _pull(v, self.project, target['pull_number']))
            if closing != pull or self._requirements(read, target) != required:
                raise LedgerError('GATE_FORGE_TARGET_CHANGED')
            result.update(status='OK', completeness='complete', pull=pull,
                required=required, ancestry=ancestor, revisions=revisions, test_merge=merge)
        except Exception as error:
            code = getattr(error, 'code', '')
            result['status'] = code if type(code) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', code) else 'INVALID_FORGE_OBSERVATION'
        result['pages'] = read.pages
        if len(_canonical(result)) > MAX_BYTES - 128:
            result.update(status='OUTPUT_LIMIT', completeness='unknown', pull=None,
                          required=None, ancestry=None, revisions=[], test_merge=None)
        result['observation_digest'] = _digest(result)
        return result


def _check_result(item, ok, note, refs=()):
    return {'item': item, 'ok': ok, 'note': note, 'evidence_refs': list(refs)}


def validate_target_observation(value, target):
    """Strict target-only Broker evidence; the Hub decides whether binding is allowed."""
    target = validate_forge_target(target)
    try:
        if (type(value) is not dict or set(value) != {'source', 'status', 'completeness',
                'target', 'pull', 'ancestry', 'pages', 'observation_digest'}
                or value['source'] != 'external-forge-broker' or value['target'] != target
                or type(value['status']) is not str or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', value['status'])
                or value['completeness'] not in {'complete', 'unknown'}
                or (value['status'] == 'OK') != (value['completeness'] == 'complete')
                or type(value['pages']) is not int or not 0 <= value['pages'] <= MAX_CALLS
                or len(_canonical(value)) > MAX_BYTES
                or value['observation_digest'] != _digest({k:v for k,v in value.items() if k != 'observation_digest'})):
            raise ValueError()
        if value['status'] != 'OK':
            if value['pull'] is not None or value['ancestry'] is not None: raise ValueError()
            return deepcopy(value)
        pull = value['pull']
        if (_pull(pull, GitHubProject(target['repository']), target['pull_number']) != pull
                or not _matches_pull(pull, target)):
            raise ValueError()
        ancestry = value['ancestry']
        if (type(ancestry) is not dict or set(ancestry) != {'base_sha', 'head_sha', 'merge_base_sha', 'status'}
                or ancestry['base_sha'] != target['base_sha'] or ancestry['head_sha'] != target['head_sha']
                or ancestry['status'] not in {'ahead', 'behind', 'identical', 'diverged'}):
            raise ValueError()
        _sha(ancestry['merge_base_sha'])
        return deepcopy(value)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, LedgerError):
        raise LedgerError('INVALID_FORGE_OBSERVATION') from None


def _ci_fact(item, revision):
    kind, producer, context = (item[k] for k in ('kind', 'producer_id', 'context'))
    if kind == 'check-run':
        rows = [r for r in revision['checks'] if r['producer']['id'] == producer and r['name'] == context]
    elif kind == 'commit-status':
        rows = [r for r in revision['statuses'] if r['creator']['id'] == producer and r['context'] == context]
    else:
        rows = []
        for group in revision['runs']:
            run = group['run']
            if run['workflow_id'] != producer: continue
            if kind == 'actions-workflow' and run['event'] == context:
                rows.append({**run, 'jobs': deepcopy(group['jobs'])})
            elif kind == 'actions-job':
                rows.extend({**job, 'workflow_id': run['workflow_id'], 'run_number': run['run_number'],
                    'event': run['event'], 'run_status': run['status'], 'run_conclusion': run['conclusion']}
                    for job in group['jobs'] if job['name'] == context)
    if len(rows) != 1:
        return None, 'missing-ci' if not rows else 'ambiguous-ci'
    fact = rows[0]
    if kind == 'commit-status':
        outcome = 'passed' if fact['state'] == 'success' else 'pending' if fact['state'] == 'pending' else 'failed'
    else:
        outcome = ('pending' if fact['status'] != 'completed' else
                   'passed' if fact['conclusion'] == 'success' else 'failed')
        if kind == 'actions-job' and fact['run_status'] != 'completed': outcome = 'pending'
        elif kind == 'actions-job' and fact['run_conclusion'] != 'success': outcome = 'failed'
        elif kind == 'actions-workflow' and item['purpose'] == 'complete-suite' and outcome == 'passed':
            if not fact['jobs'] or any(job['status'] != 'completed' or job['conclusion'] != 'success'
                                       for job in fact['jobs']):
                outcome = 'incomplete-suite'
    return fact, outcome


def _dependency_fact(item, fact):
    """Keep qualifying identity/state, not mutable display names or API URLs."""
    kind = item['kind']
    if kind == 'check-run':
        return {key: fact[key] for key in ('id', 'status', 'conclusion')}
    if kind == 'commit-status':
        return {key: fact[key] for key in ('id', 'state')}
    if kind == 'actions-job':
        return {key: fact[key] for key in ('id', 'run_id', 'run_attempt', 'workflow_id',
            'run_number', 'event', 'status', 'conclusion', 'run_status', 'run_conclusion')}
    result = {key: fact[key] for key in ('id', 'repository_id', 'run_attempt', 'workflow_id',
        'run_number', 'event', 'status', 'conclusion')}
    result['jobs'] = [{key: job[key] for key in ('id', 'run_id', 'run_attempt',
        'head_sha', 'name', 'status', 'conclusion')} for job in sorted(fact['jobs'], key=lambda job: job['id'])]
    return result


def adjudicate_forge_state(observation, target, config):
    """Hub-owned reduction. A complete fresh authenticated input is mandatory.

    The caller still checks the trusted Broker envelope and current Run/policy.
    This function checks exact scope/schema/digest; a string source assertion or
    JSON document alone is never authenticated evidence.
    """
    target = validate_forge_target(target)
    config = compile_forge_config(config)
    checks, selected = [], []
    try:
        validate_forge_observation(observation, target)
        if observation['status'] != 'OK' or observation['completeness'] != 'complete':
            raise LedgerError('GATE_FORGE_UNAVAILABLE')
        pull, required = observation['pull'], observation['required']
        checks.append(_check_result('pull-open-current', pull['state'] == 'open'
            and not pull['merged'] and not pull['draft'], 'current-open-nondraft-pull',
            [f'forge/pull/{pull["id"]}/{target["head_sha"]}']))
        revisions = observation['revisions']
        for item in config['ci']:
            candidate = revisions[0]
            fact, outcome = _ci_fact(item, candidate)
            # A present pending/failed head result cannot be bypassed through
            # a previous merge pass. Merge coverage is only a missing-head rule.
            if fact is None and outcome == 'missing-ci' and item['coverage'] == 'head-or-test-merge' and len(revisions) == 2:
                candidate = revisions[1]
                fact, outcome = _ci_fact(item, candidate)
            reference = f'forge/{candidate["tested_sha"]}/{item["kind"]}/{fact["id"]}' if fact is not None else None
            checks.append(_check_result({'ci': item['id'], 'purpose': item['purpose'],
                'applicability': 'required', 'producer_id': item['producer_id'], 'context': item['context'],
                'tested_sha': candidate['tested_sha']}, outcome == 'passed', outcome,
                [reference] if reference else []))
            if fact is not None:
                selected.append({'id': item['id'], 'kind': item['kind'], 'producer_id': item['producer_id'],
                    'context': item['context'], 'tested_sha': candidate['tested_sha'], 'fact': _dependency_fact(item, fact)})
        strict = required['classic']['strict'] or any(r['strict'] for r in required['rules'])
        requirements = required['classic']['checks'] + [c for r in required['rules'] for c in r['checks']]
        for requirement in requirements:
            matches = [i for i in config['ci'] if i['context'] == requirement['context'] and
                i['kind'] in {'check-run', 'commit-status'} and (requirement['producer_id'] is None
                    or i['kind'] == 'check-run' and i['producer_id'] == requirement['producer_id'])]
            qualified = []
            observed_selectors = set()
            for item in matches:
                result = next(c for c in checks if type(c['item']) is dict and c['item']['ci'] == item['id'])
                qualified.append(result['ok'])
                revision = next(r for r in revisions if r['tested_sha'] == result['item']['tested_sha'])
                observed_selectors.update(('check-run', row['producer']['id'], row['name'])
                    for row in revision['checks'] if row['name'] == requirement['context'] and
                    (requirement['producer_id'] is None or row['producer']['id'] == requirement['producer_id']))
                if requirement['producer_id'] is None:
                    observed_selectors.update(('commit-status', row['creator']['id'], row['context'])
                        for row in revision['statuses'] if row['context'] == requirement['context'])
            configured = {(i['kind'], i['producer_id'], i['context']) for i in matches}
            # Same-name statuses/checks can both be required by GitHub. An
            # unconfigured additional producer must not be hidden by a pass
            # from the one configured producer whose evidence we can accept.
            ok = bool(qualified) and all(qualified) and observed_selectors <= configured
            checks.append(_check_result({'branch-required': requirement}, ok,
                'required-check-satisfied' if ok else 'required-check-missing-or-not-passed',
                ['forge/requirements/' + _digest(required)]))
        # Strict branch CI requires current base ancestry or an explicitly
        # allowed, independently verified test-merge measurement for each item.
        if strict:
            ancestor = observation['ancestry']['merge_base_sha'] == target['base_sha']
            checks.append(_check_result('current-base-coverage', ancestor or bool(selected) and
                all(row['tested_sha'] != target['head_sha'] for row in selected), 'strict-base-coverage',
                ['forge/compare/' + target['base_sha'] + '...' + target['head_sha']]))
        required_dependencies = {'strict': strict, 'checks': requirements}
        dependencies = {'target': target,
            'pull_state': {k: pull[k] for k in ('state', 'draft', 'merged')},
            'head_repository_id': pull['head']['repo']['id'],
            'requirements_digest': _digest(required_dependencies), 'ci': selected}
        if strict: dependencies['ancestry'] = deepcopy(observation['ancestry'])
        dependencies['dependency_digest'] = _digest(dependencies)
        return {'checks': checks, 'verdict': 'passed' if all(c['ok'] for c in checks) else 'failed',
                'reason': None, 'dependencies': dependencies}
    except Exception as error:
        code = getattr(error, 'code', None) or 'INVALID_FORGE_OBSERVATION'
        return {'checks': [_check_result('forge-observation', False, code)],
                'verdict': 'error', 'reason': code, 'dependencies': {'target': target}}


def validate_forge_observation(value, target):
    """Independent typed envelope validation before pure Hub adjudication."""
    expected = {'source', 'status', 'completeness', 'target', 'pull', 'required',
                'ancestry', 'revisions', 'test_merge', 'pages', 'observation_digest'}
    try:
        if (type(value) is not dict or set(value) != expected
                or value['source'] != 'external-forge-broker' or value['target'] != target
                or type(value['status']) is not str or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', value['status'])
                or value['completeness'] not in {'complete', 'unknown'}
                or (value['status'] == 'OK') != (value['completeness'] == 'complete')
                or type(value['pages']) is not int or not 0 <= value['pages'] <= MAX_CALLS
                or len(_canonical(value)) > MAX_BYTES
                or value['observation_digest'] != _digest({k:v for k,v in value.items() if k != 'observation_digest'})):
            raise ValueError()
        if value['status'] != 'OK':
            if any(value[k] is not None for k in ('pull', 'required', 'ancestry', 'test_merge')) or value['revisions'] != []:
                raise ValueError()
            return deepcopy(value)
        project = GitHubProject(target['repository'])
        pull = value['pull']
        if _pull(pull, project, target['pull_number']) != pull or not _matches_pull(pull, target):
            raise ValueError()
        required = value['required']
        if type(required) is not dict or set(required) != {'branch', 'classic', 'rules'}:
            raise ValueError()
        branch = required['branch']
        if branch != {'name': target['base_ref'], 'sha': target['base_sha'], 'protected': branch.get('protected')} or type(branch['protected']) is not bool:
            raise ValueError()
        classic = required['classic']
        if type(classic) is not dict or set(classic) != {'strict', 'checks'} or type(classic['strict']) is not bool:
            raise ValueError()
        if type(required['rules']) is not list or len(required['rules']) > 100:
            raise ValueError()
        for group in [classic, *required['rules']]:
            if type(group.get('checks')) is not list or len(group['checks']) > 100 or type(group.get('strict')) is not bool:
                raise ValueError()
            for row in group['checks']:
                if type(row) is not dict or set(row) != {'context', 'producer_id', 'source'} or _requirement(row['context'], row['producer_id'], source=row['source']) != row:
                    raise ValueError()
                _text(row['source'], 128)
        if not branch['protected'] and classic != {'strict': False, 'checks': []}:
            raise ValueError()
        if len({r['id'] for r in required['rules']}) != len(required['rules']): raise ValueError()
        for rule in required['rules']:
            keys = {'id', 'type', 'source', 'strict', 'checks'}
            if type(rule) is not dict or rule.get('type') not in _SAFE_RULES | {'required_status_checks'}:
                raise ValueError()
            if rule['type'] != 'required_status_checks': keys.add('parameters_digest')
            if set(rule) != keys or not re.fullmatch(r'[1-9][0-9]*:' + re.escape(rule['type']), rule['id']):
                raise ValueError()
            _text(rule['source'], 512)
            if rule['type'] != 'required_status_checks' and (rule['strict'] or rule['checks']
                    or not re.fullmatch(r'[0-9a-f]{64}', rule['parameters_digest'])):
                raise ValueError()
        ancestry = value['ancestry']
        if (type(ancestry) is not dict or set(ancestry) != {'base_sha', 'head_sha', 'merge_base_sha', 'status'}
                or ancestry['base_sha'] != target['base_sha'] or ancestry['head_sha'] != target['head_sha']
                or ancestry['status'] not in {'ahead', 'behind', 'identical', 'diverged'}):
            raise ValueError()
        _sha(ancestry['merge_base_sha'])
        revisions = value['revisions']
        if type(revisions) is not list or not 1 <= len(revisions) <= 2 or revisions[0]['tested_sha'] != target['head_sha']:
            raise ValueError()
        merge = value['test_merge']
        if merge is not None:
            if (type(merge) is not dict or set(merge) != {'tested_sha', 'parents', 'candidate_sha', 'base_sha'}
                    or merge['tested_sha'] != pull['merge_commit_sha']
                    or merge['candidate_sha'] != target['head_sha'] or merge['base_sha'] != target['base_sha']
                    or type(merge['parents']) is not list or len(merge['parents']) > 8):
                raise ValueError()
            _sha(merge['tested_sha'])
            for parent in merge['parents']: _sha(parent)
        if len(revisions) == 2 and (merge is None or revisions[1]['tested_sha'] != merge['tested_sha']
                or merge['parents'] != [target['base_sha'], target['head_sha']]):
            raise ValueError()
        for revision in revisions:
            if type(revision) is not dict or set(revision) != {'tested_sha', 'checks', 'statuses', 'runs'}:
                raise ValueError()
            sha = _sha(revision['tested_sha'])
            for key in ('checks', 'statuses', 'runs'):
                if type(revision[key]) is not list or len(revision[key]) > 1000: raise ValueError()
            seen = set()
            for check in revision['checks']:
                raw = {**check, 'url': f'https://api.github.com/repos/{target["repository"]}/check-runs/{check["id"]}', 'app': check['producer']}
                if _check(raw, target['repository'], sha) != check: raise ValueError()
                marker = check['producer']['id'], check['name']
                if marker in seen: raise ValueError()
                seen.add(marker)
            seen = set()
            for status in revision['statuses']:
                raw = {**status, 'url': f'https://api.github.com/repos/{target["repository"]}/statuses/{sha}'}
                if _status(raw, target['repository'], sha) != status: raise ValueError()
                marker = status['creator']['id'], status['context']
                if marker in seen: raise ValueError()
                seen.add(marker)
            seen = set()
            for group in revision['runs']:
                if type(group) is not dict or set(group) != {'run', 'jobs'}: raise ValueError()
                run = group['run']
                expected_run = {'id', 'repository_id', 'url', 'head_sha', 'run_attempt', 'workflow_id',
                                'event', 'status', 'conclusion', 'pull_requests', 'coverage', 'run_number'}
                if type(run) is not dict or set(run) != expected_run or run['head_sha'] != sha:
                    raise ValueError()
                _number(run['run_number'])
                if run['repository_id'] != pull['base']['repo']['id']: raise ValueError()
                api = 'https://api.github.com/repos/' + target['repository']
                raw = {**run, 'repository': {'id': run['repository_id'],
                    'full_name': target['repository'], 'url': api}, 'pull_requests': []}
                for association in run['pull_requests']:
                    if type(association) is not dict or set(association) != {'id', 'number', 'head', 'base'}:
                        raise ValueError()
                    branches = {}
                    for name in ('head', 'base'):
                        branch_value = association[name]
                        if type(branch_value) is not dict or set(branch_value) != {'sha', 'repository_id'}:
                            raise ValueError()
                        branches[name] = {'sha': branch_value['sha'],
                            'repo': {'id': branch_value['repository_id'], 'url': api}}
                    raw['pull_requests'].append({'id': association['id'], 'number': association['number'],
                        'url': api + '/pulls/' + str(association['number']), **branches})
                normalized = _run(raw, target['repository'])
                normalized['run_number'] = run['run_number']
                normalized['pull_requests'].sort(key=lambda p: p['id'])
                if normalized != run: raise ValueError()
                if run['event'] in {'pull_request', 'pull_request_target'} and not any(
                        p['id'] == target['pull_id'] and p['number'] == target['pull_number']
                        and p['head'] == {'sha': target['head_sha'], 'repository_id': pull['head']['repo']['id']}
                        and p['base'] == {'sha': target['base_sha'], 'repository_id': pull['base']['repo']['id']}
                        for p in run['pull_requests']):
                    raise ValueError()
                marker = run['workflow_id'], run['event']
                if marker in seen: raise ValueError()
                seen.add(marker)
                if type(group['jobs']) is not list or len(group['jobs']) > 1000: raise ValueError()
                for job in group['jobs']:
                    raw = {**job, 'run_url': f'https://api.github.com/repos/{target["repository"]}/actions/runs/{run["id"]}'}
                    if _job(raw, target['repository'], run) != job: raise ValueError()
                if len({job['name'] for job in group['jobs']}) != len(group['jobs']): raise ValueError()
        return deepcopy(value)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, LedgerError):
        raise LedgerError('INVALID_FORGE_OBSERVATION') from None
