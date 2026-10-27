"""Complete bounded, read-only GitHub surface behind the external Broker.

Only trusted Broker code provides the fixed-host transport. Returned document
content is Participant output, NOT audit: metadata_summary is the audit view.
No route here grants workflow, review, merge, or CI coverage authority.
"""
import base64
import hashlib
import json
import re
import time
from urllib.parse import quote, urlencode
from collections.abc import Mapping

from .github_read import (GitHubProject, ProviderResponse,
                          ProviderFailure, MAX_OUTPUT, _positive,
                          _unique, _LOGIN)
from .github_pr import _pull, _review, _user, _sha
from .ledger import LedgerError

KINDS = frozenset({'repo-view', 'repo-file', 'issue-list', 'issue-status',
    'issue-display', 'issue-comments', 'issue-dependencies', 'issue-blocks',
    'label-list', 'pr-list', 'pr-display', 'pr-comments', 'pr-review-comments',
    'pr-reviews', 'pr-diff', 'pr-checks', 'pr-status', 'workflow-list',
    'workflow-view', 'run-list', 'run-view', 'run-jobs', 'commit-checks',
    'commit-statuses'})
CODES = frozenset({'OK', 'NOT_FOUND', 'PROVIDER_ERROR', 'TIMEOUT', 'OUTPUT_LIMIT',
    'INVALID_RESPONSE', 'CREDENTIAL_UNAVAILABLE', 'PAGINATION_LIMIT',
    'STALE_SOURCE'})
_STATUSES = {'queued', 'in_progress', 'completed', 'waiting', 'pending', 'requested'}
_CONCLUSIONS = {'success', 'failure', 'neutral', 'cancelled', 'skipped',
                'timed_out', 'action_required', 'stale', 'startup_failure'}


def _text(value, maximum=MAX_OUTPUT, *, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not str or len(value.encode('utf-8')) > maximum or '\0' in value:
        raise ValueError('invalid text')
    return value


def _number(value):
    if not _positive(value):
        raise ValueError('invalid identity')
    return value


def _url(value, expected):
    if value != expected:
        raise ValueError('wrong repository/object')
    return value


def _path(value):
    value = _text(value, 4096)
    if (not value or value.startswith('/') or '\\' in value
            or any(p in {'', '.', '..'} for p in value.split('/'))
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('invalid repository path')
    return value


def _repository(value, repository):
    if (type(value) is not dict or value.get('full_name') != repository
            or type(value.get('private')) is not bool):
        raise ValueError('wrong repository')
    return {'id': _number(value.get('id')), 'full_name': repository,
            'private': value['private'],
            'url': _url(value.get('url'), 'https://api.github.com/repos/' + repository),
            'html_url': _url(value.get('html_url'), 'https://github.com/' + repository),
            'default_branch': _text(value.get('default_branch'), 255),
            'description': _text(value.get('description'), 8192, nullable=True)}


def _label(value, repository):
    if type(value) is not dict:
        raise ValueError()
    name = _text(value.get('name'), 256)
    if not name or any(ord(c) < 32 for c in name):
        raise ValueError()
    # GitHub label URLs percent-encode names; identity comes from this endpoint
    # and exact repository URL prefix, not a caller-selected next URL.
    expected = 'https://api.github.com/repos/' + repository + '/labels/' + quote(name, safe='')
    _url(value.get('url'), expected)
    color = value.get('color')
    if type(color) is not str or not re.fullmatch('[0-9a-fA-F]{6}', color):
        raise ValueError()
    return {'id': _number(value.get('id')), 'name': name, 'color': color,
            'description': _text(value.get('description'), 4096, nullable=True)}


def _issue(value, repository, number=None):
    if type(value) is not dict or 'pull_request' in value:
        raise ValueError()
    n = _number(value.get('number'))
    if (number is not None and n != number) or value.get('state') not in {'open', 'closed'}:
        raise ValueError()
    api = 'https://api.github.com/repos/' + repository
    users = value.get('assignees')
    if type(users) is not list or len(users) > 100:
        raise ValueError()
    assignees = [_user(user) for user in users]
    if len({u['id'] for u in assignees}) != len(assignees):
        raise ValueError()
    return {'id': _number(value.get('id')), 'number': n, 'state': value['state'],
            'url': _url(value.get('url'), f'{api}/issues/{n}'),
            'repository_url': _url(value.get('repository_url'), api),
            'html_url': _url(value.get('html_url'), f'https://github.com/{repository}/issues/{n}'),
            'title': _text(value.get('title'), 4096),
            'body': _text(value.get('body'), nullable=True),
            'user': _user(value.get('user')), 'assignees': assignees}



def _skip_pull(value, repository):
    if type(value) is not dict:
        raise ValueError()
    if 'pull_request' not in value:
        return False
    number = _number(value.get('number'))
    _number(value.get('id'))
    base = 'https://api.github.com/repos/' + repository
    _url(value.get('url'), f'{base}/issues/{number}')
    _url(value.get('repository_url'), base)
    _url(value.get('html_url'), f'https://github.com/{repository}/pull/{number}')
    nested = value['pull_request']
    if type(nested) is not dict:
        raise ValueError()
    _url(nested.get('url'), f'{base}/pulls/{number}')
    return True


def _pull_display(value, project, number, *, listing=False):
    raw = dict(value)
    # GitHub pull-list objects omit merged; do not turn that absence into false.
    observed_merged = raw.get('merged')
    if listing and 'merged' not in raw:
        raw['merged'] = False
    result = _pull(raw, project, number)
    if listing:
        result['merged'] = observed_merged
        result['merged_at'] = _text(value.get('merged_at'), 64, nullable=True)
    result.update(title=_text(value.get('title'), 4096),
                  body=_text(value.get('body'), nullable=True))
    for name in ('assignees', 'requested_reviewers'):
        users = value.get(name)
        if users is None:
            result[name] = None  # unknown, never fabricated empty membership
        elif type(users) is list and len(users) <= 100:
            result[name] = [_user(user) for user in users]
            if len({user['id'] for user in result[name]}) != len(result[name]):
                raise ValueError()
        else:
            raise ValueError()
    if not listing:
        merger = value.get('merged_by')
        result['merged_by'] = _user(merger) if merger is not None else None
        if result['merged'] and result['merged_by'] is None:
            raise ValueError('unknown merged identity')
    return result


def _comment(value, repository, number, *, review=False):
    if type(value) is not dict:
        raise ValueError()
    identifier = _number(value.get('id'))
    api = 'https://api.github.com/repos/' + repository
    result = {'id': identifier, 'user': _user(value.get('user')),
              'body': _text(value.get('body'), nullable=True)}
    if review:
        _url(value.get('url'), f'{api}/pulls/comments/{identifier}')
        _url(value.get('pull_request_url'), f'{api}/pulls/{number}')
        result.update(commit_id=_sha(value.get('commit_id')),
            original_commit_id=_sha(value.get('original_commit_id')),
            pull_request_review_id=_number(value.get('pull_request_review_id')),
            path=_path(value.get('path')))
    else:
        _url(value.get('url'), f'{api}/issues/comments/{identifier}')
        _url(value.get('issue_url'), f'{api}/issues/{number}')
    return result


def _check(value, repository, sha):
    identifier = _number(value.get('id'))
    _url(value.get('url'), f'https://api.github.com/repos/{repository}/check-runs/{identifier}')
    if value.get('head_sha') != sha or value.get('status') not in _STATUSES:
        raise ValueError()
    conclusion = value.get('conclusion')
    if (conclusion is not None and conclusion not in _CONCLUSIONS
            or (value['status'] == 'completed') != (conclusion is not None)):
        raise ValueError()
    app = value.get('app')
    if type(app) is not dict:
        raise ValueError()
    return {'id': identifier, 'head_sha': sha, 'name': _text(value.get('name'), 512),
            'status': value['status'], 'conclusion': conclusion,
            'producer': {'id': _number(app.get('id')), 'slug': _text(app.get('slug'), 256)},
            'coverage': 'not-evaluated'}


def _status(value, repository, sha):
    _url(value.get('url'), f'https://api.github.com/repos/{repository}/statuses/{sha}')
    if value.get('state') not in {'error', 'failure', 'pending', 'success'}:
        raise ValueError()
    return {'id': _number(value.get('id')), 'sha': sha,
            'context': _text(value.get('context'), 512), 'state': value['state'],
            'creator': _user(value.get('creator')), 'coverage': 'not-evaluated'}


def _workflow(value, repository, number=None):
    identifier = _number(value.get('id'))
    if number is not None and identifier != number:
        raise ValueError()
    if value.get('state') not in {'active', 'deleted', 'disabled_fork', 'disabled_inactivity', 'disabled_manually'}:
        raise ValueError()
    return {'id': identifier, 'name': _text(value.get('name'), 512),
            'path': _path(value.get('path')), 'state': value['state'],
            'url': _url(value.get('url'), f'https://api.github.com/repos/{repository}/actions/workflows/{identifier}')}


def _run(value, repository, number=None, attempt=None):
    if type(value) is not dict:
        raise ValueError()
    identifier = _number(value.get('id'))
    observed_attempt = _number(value.get('run_attempt'))
    repo = value.get('repository')
    if (number is not None and identifier != number or attempt is not None and observed_attempt != attempt
            or type(repo) is not dict or repo.get('full_name') != repository
            or value.get('status') not in _STATUSES):
        raise ValueError()
    _url(repo.get('url'), 'https://api.github.com/repos/' + repository)
    conclusion = value.get('conclusion')
    if (conclusion is not None and conclusion not in _CONCLUSIONS
            or (value['status'] == 'completed') != (conclusion is not None)):
        raise ValueError()
    associations = value.get('pull_requests')
    if type(associations) is not list or len(associations) > 100:
        raise ValueError()
    pulls = []
    for pull in associations:
        pnumber = _number(pull.get('number'))
        _url(pull.get('url'), f'https://api.github.com/repos/{repository}/pulls/{pnumber}')
        branches = {}
        for name in ('head', 'base'):
            branch = pull.get(name)
            if type(branch) is not dict or type(branch.get('repo')) is not dict:
                raise ValueError()
            refrepo = branch['repo']
            if name == 'base':
                _url(refrepo.get('url'), 'https://api.github.com/repos/' + repository)
            elif (type(refrepo.get('url')) is not str
                    or not re.fullmatch(r'https://api\.github\.com/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', refrepo['url'])):
                raise ValueError()
            branches[name] = {'sha': _sha(branch.get('sha')), 'repository_id': _number(refrepo.get('id'))}
        pulls.append({'id': _number(pull.get('id')), 'number': pnumber, **branches})
    if len({p['id'] for p in pulls}) != len(pulls):
        raise ValueError()
    return {'id': identifier, 'repository_id': _number(repo.get('id')),
            'url': _url(value.get('url'), f'https://api.github.com/repos/{repository}/actions/runs/{identifier}'),
            'head_sha': _sha(value.get('head_sha')), 'run_attempt': observed_attempt,
            'workflow_id': _number(value.get('workflow_id')),
            'event': _text(value.get('event'), 128), 'status': value['status'],
            'conclusion': conclusion, 'pull_requests': pulls, 'coverage': 'not-evaluated'}


def _job(value, repository, run):
    identifier = _number(value.get('id'))
    _url(value.get('run_url'), f'https://api.github.com/repos/{repository}/actions/runs/{run["id"]}')
    if (value.get('run_id') != run['id'] or ('run_attempt' in value and value['run_attempt'] != run['run_attempt'])
            or value.get('head_sha') != run['head_sha'] or value.get('status') not in _STATUSES):
        raise ValueError()
    conclusion = value.get('conclusion')
    if (conclusion is not None and conclusion not in _CONCLUSIONS
            or (value['status'] == 'completed') != (conclusion is not None)):
        raise ValueError()
    return {'id': identifier, 'run_id': run['id'], 'run_attempt': run['run_attempt'],
            'head_sha': run['head_sha'], 'status': value['status'], 'conclusion': conclusion,
            'name': _text(value.get('name'), 512),
            'url': _url(value.get('url'), f'https://api.github.com/repos/{repository}/actions/jobs/{identifier}'),
            'coverage': 'not-evaluated'}


class _Read:
    def __init__(self, owner):
        self.owner, self.used, self.pages = owner, 0, 0
        self.deadline = time.monotonic() + 30
        self.observed = False
        self.limit = 1000

    def get(self, path, *, accept=None, raw=False):
        if time.monotonic() >= self.deadline:
            raise ProviderFailure('TIMEOUT')
        if accept is None:
            response = self.owner.transport(path)
        else:
            getter = getattr(self.owner.transport, 'get', None)
            if not callable(getter):
                raise ProviderFailure('PROVIDER_ERROR')
            response = getter(path, accept=accept)
        if time.monotonic() >= self.deadline:
            raise ProviderFailure('TIMEOUT')
        if (type(response) is not ProviderResponse or type(response.status) is not int
                or type(response.body) is not bytes or type(response.headers) is not dict):
            raise ProviderFailure('INVALID_RESPONSE')
        self.used += len(response.body)
        if self.used > self.owner.max_bytes:
            raise ProviderFailure('OUTPUT_LIMIT')
        if response.status != 200:
            if response.status == 404 and not self.observed:
                raise _NotFound()
            raise ProviderFailure('PROVIDER_ERROR')
        if raw:
            self.observed = True
            return response.body, response.headers
        try:
            value = json.loads(response.body, object_pairs_hook=_unique)
        except (ValueError, UnicodeError, RecursionError):
            raise ProviderFailure('INVALID_RESPONSE') from None
        self.observed = True
        return value, response.headers

    def one(self, path, normalize):
        value, _ = self.get(path)
        return normalize(value)

    def many(self, path, normalize, *, key=None, skip=None, identity='id'):
        result, seen, numbers = [], set(), set()
        for page in range(1, self.owner.max_pages + 1):
            value, headers = self.get(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
            if key is not None:
                if type(value) is not dict or not isinstance(value.get('total_count'), int) or type(value.get('total_count')) is bool or value['total_count'] < 0:
                    raise ValueError()
                values = value.get(key)
            else:
                values = value
            if type(values) is not list or len(values) > 100:
                raise ValueError()
            self.pages += 1
            for raw in values:
                if skip is not None and skip(raw):
                    continue
                item = normalize(raw)
                marker = item[identity]
                if marker in seen:
                    raise ValueError('duplicate record')
                seen.add(marker)
                if 'number' in item:
                    if item['number'] in numbers:
                        raise ValueError('duplicate object number')
                    numbers.add(item['number'])
                if len(result) >= self.limit:
                    raise _Incomplete('PAGINATION_LIMIT', result)
                result.append(item)
                if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_OUTPUT - 4096:
                    raise ProviderFailure('OUTPUT_LIMIT')
            links = [v for k, v in headers.items() if type(k) is str and k.lower() == 'link']
            if any(type(v) is not str for v in links):
                raise ValueError()
            if len(values) < 100 and not any(re.search(r'rel\s*=\s*["\']?next', v, re.I) for v in links):
                # Count is advisory during concurrent changes, but a declared
                # larger set contradicts exhaustion and cannot prove absence.
                if key is not None and value['total_count'] > page * 100 - 100 + len(values):
                    raise ProviderFailure('INVALID_RESPONSE')
                return result
        raise _Incomplete('PAGINATION_LIMIT', result)


class _NotFound(Exception):
    pass


class _Incomplete(Exception):
    def __init__(self, code, data):
        self.code, self.data = code, data


class GitHubSurfaceProvider:
    host = 'github.com'
    def __init__(self, project, transport, *, max_pages=10, max_bytes=MAX_OUTPUT):
        if type(project) is not GitHubProject or not callable(transport):
            raise LedgerError('INVALID_PROJECT')
        if (type(max_pages) is not int or not 1 <= max_pages <= 10
                or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_OUTPUT):
            raise LedgerError('INVALID_PROVIDER_LIMIT')
        self.project, self.transport = project, transport
        self.max_pages, self.max_bytes = max_pages, max_bytes

    def read(self, route):
        repository = GitHubProject(route.repository, self.project.host).repository
        kind, number = route.kind, route.number
        if not isinstance(route.options, Mapping):
            raise LedgerError('UNSUPPORTED_ROUTE')
        options = dict(route.options)
        if kind not in KINDS:
            raise LedgerError('UNSUPPORTED_ROUTE')
        if number is not None and not _positive(number):
            raise LedgerError('INVALID_COMMAND')
        read = _Read(self)
        read.limit = options.get('limit', 1000)
        if type(read.limit) is not int or not 1 <= read.limit <= 1000:
            raise LedgerError('INVALID_PROVIDER_LIMIT')
        result = {'kind': kind, 'repository': repository, 'status': 'PROVIDER_ERROR',
                  'completeness': 'unknown', 'data': None, 'pages': 0}
        try:
            data = self._dispatch(read, repository, kind, number, options)
            result.update(status='OK', completeness='complete', data=data)
        except _NotFound:
            result.update(status='NOT_FOUND', reason='not-found-or-inaccessible')
        except _Incomplete as error:
            result.update(status=error.code, completeness='incomplete', data=error.data)
        except ProviderFailure as error:
            result.update(status=error.code, completeness='incomplete' if read.observed else 'unknown')
        except (ValueError, KeyError, TypeError, AttributeError, LedgerError, RecursionError, UnicodeError):
            result.update(status='INVALID_RESPONSE', completeness='incomplete' if read.observed else 'unknown')
        except Exception:
            result.update(status='PROVIDER_ERROR', completeness='incomplete' if read.observed else 'unknown')
        result['pages'] = read.pages
        if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_OUTPUT:
            result.update(status='OUTPUT_LIMIT', completeness='incomplete', data=None)
        return result

    def _dispatch(self, read, repository, kind, number, options):
        base = 'repos/' + repository
        project = GitHubProject(repository)
        if kind == 'repo-view':
            return read.one(base, lambda v: _repository(v, repository))
        if kind == 'repo-file':
            path = _path(options.get('path'))
            ref = _text(options.get('ref', 'HEAD'), 255)
            if not ref or any(ord(c) < 32 for c in ref):
                raise ValueError()
            def commit(value):
                sha = _sha(value.get('sha'))
                _url(value.get('url'), f'https://api.github.com/{base}/commits/{sha}')
                return sha
            sha = read.one(base + '/commits/' + quote(ref, safe=''), commit)
            def content(value):
                if (type(value) is not dict or value.get('type') != 'file'
                        or value.get('path') != path or value.get('encoding') != 'base64'
                        or type(value.get('size')) is not int or value['size'] < 0):
                    raise ValueError()
                raw = base64.b64decode(''.join(_text(value.get('content')).splitlines()), validate=True)
                if len(raw) != value['size'] or len(raw) > MAX_OUTPUT:
                    raise ValueError()
                blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                if value.get('sha') != blob:
                    raise ValueError()
                text = raw.decode('utf-8')
                _text(text)
                return {'path': path, 'commit_sha': sha, 'blob_sha': blob, 'content': text}
            return read.one(base + '/contents/' + quote(path, safe='/') + '?ref=' + sha, content)
        if kind == 'label-list':
            return read.many(base + '/labels', lambda v: _label(v, repository))
        if kind in {'issue-list', 'pr-list'}:
            state = options.get('state', 'open')
            if state not in {'open', 'closed', 'all', 'merged'} or kind == 'issue-list' and state == 'merged':
                raise ValueError()
            if kind == 'issue-list':
                return read.many(base + '/issues?state=' + state,
                    lambda v: _issue(v, repository), skip=lambda v: _skip_pull(v, repository))
            pulls = read.many(base + '/pulls?state=' + ('closed' if state == 'merged' else state),
                lambda v: _pull_display(v, project, _number(v.get('number')), listing=True))
            if state == 'merged':
                # List lacks merged boolean; immutable merge timestamp is only
                # an observed list filter, never current merger authority.
                return [p for p in pulls if p['merged_at'] is not None]
            return pulls
        if kind in {'issue-status', 'pr-status'}:
            actor = read.one('user', _user)
            if kind == 'issue-status':
                return {name: read.many(base + '/issues?' + urlencode({'state': 'open', selector: actor['login']}),
                    lambda v: _issue(v, repository), skip=lambda v: _skip_pull(v, repository))
                    for name, selector in (('assigned', 'assignee'), ('created', 'creator'), ('mentioned', 'mentioned'))}
            pulls = read.many(base + '/pulls?state=open',
                lambda v: _pull_display(v, project, _number(v.get('number')), listing=True))
            return {'actor': actor, 'created': [p for p in pulls if p['user']['id'] == actor['id']],
                'assigned': [p for p in pulls if p['assignees'] is not None and any(u['id'] == actor['id'] for u in p['assignees'])],
                'review_requested': [p for p in pulls if p['requested_reviewers'] is not None and any(u['id'] == actor['id'] for u in p['requested_reviewers'])],
                'membership': 'unknown' if any(p['assignees'] is None or p['requested_reviewers'] is None for p in pulls) else 'observed',
                'current_branch': 'unknown-no-checkout-context'}
        if kind in {'issue-display', 'issue-comments', 'issue-dependencies', 'issue-blocks', 'pr-comments'}:
            if number is None:
                raise ValueError()
            endpoint = base + f'/issues/{number}'
            if kind == 'pr-comments':
                pull = read.one(base + f'/pulls/{number}', lambda v: _pull(v, project, number))
                comments = read.many(endpoint + '/comments', lambda v: _comment(v, repository, number))
                self._unchanged_pull(read, base, project, number, pull)
                return {'pull': pull, 'comments': comments}
            issue = read.one(endpoint, lambda v: _issue(v, repository, number))
            if kind == 'issue-display':
                comments = read.many(endpoint + '/comments', lambda v: _comment(v, repository, number)) if options.get('comments') else []
                labels = read.many(endpoint + '/labels', lambda v: _label(v, repository))
                return {'issue': issue, 'comments': comments, 'labels': labels}
            if kind == 'issue-comments':
                return {'issue': issue, 'comments': read.many(endpoint + '/comments', lambda v: _comment(v, repository, number))}
            direction = 'blocked_by' if kind == 'issue-dependencies' else 'blocking'
            dependencies = read.many(endpoint + '/dependencies/' + direction, lambda v: _issue(v, repository))
            if any(v['id'] == issue['id'] or v['number'] == number for v in dependencies):
                raise ValueError()
            return {'issue': issue, 'dependencies': dependencies, 'direction': direction}
        if kind in {'pr-display', 'pr-reviews', 'pr-review-comments', 'pr-diff', 'pr-checks'}:
            if number is None:
                raise ValueError()
            endpoint = base + f'/pulls/{number}'
            pull = read.one(endpoint, lambda v: _pull_display(v, project, number))
            if kind == 'pr-display':
                data = {'pull': pull,
                    'labels': read.many(base + f'/issues/{number}/labels', lambda v: _label(v, repository)),
                    'reviews': read.many(endpoint + '/reviews', lambda v: {**_review(v, project, number), 'body': _text(v.get('body'), nullable=True)})}
                if options.get('comments'):
                    data['comments'] = read.many(base + f'/issues/{number}/comments', lambda v: _comment(v, repository, number))
            elif kind == 'pr-reviews':
                data = {'pull': pull, 'reviews': read.many(endpoint + '/reviews',
                    lambda v: {**_review(v, project, number), 'body': _text(v.get('body'), nullable=True)})}
            elif kind == 'pr-review-comments':
                data = {'pull': pull, 'comments': read.many(endpoint + '/comments', lambda v: _comment(v, repository, number, review=True))}
            elif kind == 'pr-diff':
                raw, _ = read.get(endpoint, accept='application/vnd.github.diff', raw=True)
                data = {'pull': pull, 'diff': _text(raw.decode('utf-8'))}
            else:
                sha = pull['head']['sha']
                checks = self._ci(read, base, repository, sha)
                runs = read.many(base + '/actions/runs?head_sha=' + sha,
                    lambda v: _run(v, repository), key='workflow_runs')
                for run in runs:
                    if run['head_sha'] != sha:
                        raise ValueError()
                data = {'candidate_sha': sha, 'base_sha': pull['base']['sha'],
                    'pull': pull, **checks, 'runs': runs, 'coverage': 'not-evaluated',
                    'test_merge': None}
                merge_sha = pull['merge_commit_sha']
                if pull['state'] == 'open' and not pull['merged'] and merge_sha is not None and merge_sha != sha:
                    def merge_commit(value):
                        if value.get('sha') != merge_sha:
                            raise ValueError()
                        _url(value.get('url'), f'https://api.github.com/{base}/commits/{merge_sha}')
                        parents = value.get('parents')
                        if type(parents) is not list or len(parents) > 8:
                            raise ValueError()
                        return [_sha(parent.get('sha')) for parent in parents]
                    parents = read.one(base + '/commits/' + merge_sha, merge_commit)
                    merge_ci = self._ci(read, base, repository, merge_sha)
                    merge_runs = read.many(base + '/actions/runs?head_sha=' + merge_sha,
                        lambda v: _run(v, repository), key='workflow_runs')
                    if any(run['head_sha'] != merge_sha for run in merge_runs):
                        raise ValueError()
                    data['test_merge'] = {'tested_sha': merge_sha, 'parents': parents,
                        'candidate_sha': sha, 'base_sha': pull['base']['sha'],
                        'association': 'verified-parents' if parents == [pull['base']['sha'], sha] else 'unknown',
                        'coverage': 'not-evaluated', **merge_ci, 'runs': merge_runs}
            self._unchanged_pull(read, base, project, number, pull)
            return data
        if kind in {'commit-checks', 'commit-statuses'}:
            sha = _sha(options.get('sha'))
            suffix = 'check-runs' if kind == 'commit-checks' else 'statuses'
            return {'sha': sha, 'coverage': 'not-evaluated', 'items': read.many(
                base + '/commits/' + sha + '/' + suffix + ('?filter=all' if kind == 'commit-checks' else ''),
                (lambda v: _check(v, repository, sha)) if kind == 'commit-checks' else (lambda v: _status(v, repository, sha)),
                key='check_runs' if kind == 'commit-checks' else None)}
        if kind == 'workflow-list':
            return read.many(base + '/actions/workflows', lambda v: _workflow(v, repository), key='workflows')
        if kind == 'workflow-view':
            return read.one(base + f'/actions/workflows/{_number(number)}', lambda v: _workflow(v, repository, number))
        if kind == 'run-list':
            return read.many(base + '/actions/runs', lambda v: _run(v, repository), key='workflow_runs')
        if kind in {'run-view', 'run-jobs'}:
            raw_job = None
            if 'job' in options:
                job_number = _number(options['job'])
                raw_job, _ = read.get(base + f'/actions/jobs/{job_number}')
                if type(raw_job) is not dict or raw_job.get('id') != job_number:
                    raise ValueError()
                derived_run = _number(raw_job.get('run_id'))
                _url(raw_job.get('url'), f'https://api.github.com/{base}/actions/jobs/{job_number}')
                _url(raw_job.get('run_url'), f'https://api.github.com/{base}/actions/runs/{derived_run}')
                if number is not None and number != derived_run:
                    raise ValueError()
                number = derived_run
            number = _number(number)
            attempt = options.get('attempt')
            if attempt is not None:
                _number(attempt)
            endpoint = base + f'/actions/runs/{number}'
            if attempt is not None:
                endpoint += f'/attempts/{attempt}'
            run = read.one(endpoint, lambda v: _run(v, repository, number, attempt))
            if raw_job is None:
                data = {'run': run, 'jobs': read.many(base + f'/actions/runs/{number}/attempts/{run["run_attempt"]}/jobs',
                    lambda v: _job(v, repository, run), key='jobs')}
            else:
                # GitHub job responses need not carry run_attempt. Membership
                # in the exact attempt-qualified jobs listing is the proof;
                # an optional response field is checked, never the only proof.
                latest = run['run_attempt']
                attempts = [attempt] if attempt is not None else range(latest, max(0, latest - 10), -1)
                found = None
                for candidate in attempts:
                    if candidate != run['run_attempt']:
                        endpoint = base + f'/actions/runs/{number}/attempts/{candidate}'
                        run = read.one(endpoint, lambda v: _run(v, repository, number, candidate))
                    jobs = read.many(base + f'/actions/runs/{number}/attempts/{candidate}/jobs',
                        lambda v: _job(v, repository, run), key='jobs')
                    found = next((job for job in jobs if job['id'] == job_number), None)
                    if found is not None:
                        if _job(raw_job, repository, run) != found:
                            raise _Incomplete('STALE_SOURCE', None)
                        break
                if found is None:
                    raise _Incomplete('PAGINATION_LIMIT' if attempt is None and latest > 10 else 'STALE_SOURCE', None)
                current_job = read.one(base + f'/actions/jobs/{job_number}', lambda v: _job(v, repository, run))
                if current_job != found:
                    raise _Incomplete('STALE_SOURCE', None)
                data = {'run': run, 'job': found}
            final = read.one(endpoint, lambda v: _run(v, repository, number))
            if final != run:
                raise _Incomplete('STALE_SOURCE', None)
            return data
        raise ValueError('unsupported surface')

    @staticmethod
    def _unchanged_pull(read, base, project, number, before):
        after = read.one(base + f'/pulls/{number}', lambda v: _pull(v, project, number))
        if any(before[k] != value for k, value in after.items()):
            raise _Incomplete('STALE_SOURCE', None)

    @staticmethod
    def _ci(read, base, repository, sha):
        return {'checks': read.many(base + '/commits/' + sha + '/check-runs?filter=all',
                    lambda v: _check(v, repository, sha), key='check_runs'),
                'statuses': read.many(base + '/commits/' + sha + '/statuses',
                    lambda v: _status(v, repository, sha))}


def metadata_summary(result):
    """Metadata-only audit: never document body, argv, URL, or provider errors."""
    if (type(result) is not dict or set(result) not in (
            {'kind', 'repository', 'status', 'completeness', 'data', 'pages'},
            {'kind', 'repository', 'status', 'completeness', 'data', 'pages', 'reason'})
            or type(result['kind']) is not str or result['kind'] not in KINDS
            or type(result['status']) is not str or result['status'] not in CODES
            or type(result['completeness']) is not str
            or result['completeness'] not in {'complete', 'incomplete', 'unknown'}
            or (result['status'] == 'OK') != (result['completeness'] == 'complete')
            or type(result['pages']) is not int or not 0 <= result['pages'] <= 100
            or ('reason' in result and (result['status'] != 'NOT_FOUND'
                or result['reason'] != 'not-found-or-inaccessible'))):
        raise LedgerError('INVALID_PROVIDER_OBSERVATION')
    GitHubProject(result['repository'])
    try:
        encoded = json.dumps(result, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise LedgerError('INVALID_PROVIDER_OBSERVATION') from None
    if len(encoded) > MAX_OUTPUT:
        raise LedgerError('INVALID_PROVIDER_OBSERVATION')
    return {'kind': result['kind'], 'repository': result['repository'],
            'status': result['status'], 'completeness': result['completeness'],
            'pages': result['pages'], 'output_bytes': len(encoded),
            'output_sha256': hashlib.sha256(encoded).hexdigest()}
