"""Bounded PR/review observations only; no Gate, eligibility or review verdict.

A closing PR read detects changed candidate/base facts, not an atomic snapshot of
GitHub. Transport is trusted, deadline-bounded and supplied outside Participant.
"""
from datetime import datetime
import json
import re
import time

from .github_read import (GitHubProject, ProviderResponse, ProviderFailure, MAX_OUTPUT,
                          MAX_OBSERVATION, _positive, _LOGIN, _unique)
from .ledger import LedgerError

_SHA = re.compile(r'[0-9a-f]{40}\Z')
_STATES = {'PENDING', 'APPROVED', 'CHANGES_REQUESTED', 'COMMENTED', 'DISMISSED'}
_CODES = {'OK', 'NOT_FOUND', 'PROVIDER_ERROR', 'TIMEOUT', 'OUTPUT_LIMIT',
          'INVALID_RESPONSE', 'CREDENTIAL_UNAVAILABLE', 'PAGINATION_LIMIT', 'STALE_PULL'}


def _user(value):
    if (type(value) is not dict or not _positive(value.get('id'))
            or type(value.get('login')) is not str or not _LOGIN.fullmatch(value['login'])):
        raise ValueError()
    return {'id': value['id'], 'login': value['login']}


def _sha(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        raise ValueError()
    return value


def _branch(value):
    if type(value) is not dict:
        raise ValueError()
    name, repo = value.get('ref'), value.get('repo')
    if (type(name) is not str or not 1 <= len(name) <= 255
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or type(repo) is not dict or not _positive(repo.get('id'))):
        raise ValueError()
    project = GitHubProject(repo.get('full_name'))
    return {'sha': _sha(value.get('sha')), 'ref': name,
            'repo': {'id': repo['id'], 'full_name': project.repository}}


def _pull(value, project, number):
    api = f'https://api.github.com/repos/{project.repository}/pulls/{number}'
    web = f'https://github.com/{project.repository}/pull/{number}'
    if (type(value) is not dict or not _positive(value.get('id'))
            or type(value.get('number')) is not int or value['number'] != number
            or value.get('url') != api or value.get('html_url') != web
            or value.get('state') not in {'open', 'closed'}
            or type(value.get('draft')) is not bool or type(value.get('merged')) is not bool
            or 'merge_commit_sha' not in value
            or (value['merged'] and value['state'] != 'closed')):
        raise ValueError()
    base, head = _branch(value.get('base')), _branch(value.get('head'))
    if base['repo']['full_name'] != project.repository:
        raise ValueError()
    # GitHub repository names are case-insensitive; name and immutable ID
    # must agree on whether these two branches belong to one repository.
    same_name = base['repo']['full_name'].lower() == head['repo']['full_name'].lower()
    same_id = base['repo']['id'] == head['repo']['id']
    if same_name != same_id:
        raise ValueError()
    merge = value.get('merge_commit_sha')
    if merge is not None:
        _sha(merge)
    return {'id': value['id'], 'number': number, 'url': api, 'html_url': web,
            'state': value['state'], 'draft': value['draft'], 'merged': value['merged'],
            'user': _user(value.get('user')), 'base': base, 'head': head,
            'merge_commit_sha': merge}


def _review(value, project, number):
    api = f'https://api.github.com/repos/{project.repository}/pulls/{number}'
    web = f'https://github.com/{project.repository}/pull/{number}#pullrequestreview-'
    if (type(value) is not dict or not _positive(value.get('id'))
            or type(value.get('state')) is not str or value['state'] not in _STATES
            or value.get('html_url') != web + str(value['id']) or value.get('pull_request_url') != api):
        raise ValueError()
    submitted, commit = value.get('submitted_at'), value.get('commit_id')
    if submitted is not None:
        if type(submitted) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', submitted):
            raise ValueError()
        datetime.strptime(submitted, '%Y-%m-%dT%H:%M:%SZ')
    if commit is not None:
        _sha(commit)
    if value['state'] == 'PENDING':
        if submitted is not None:
            raise ValueError()
    elif submitted is None or commit is None:
        raise ValueError()
    return {'id': value['id'], 'html_url': value['html_url'], 'pull_request_url': api,
            'user': _user(value.get('user')), 'state': value['state'],
            'submitted_at': submitted, 'commit_id': commit}


def validate_pull_observation(value, project, number):
    """Independent exact-schema Broker boundary; rejects raw extra fields."""
    try:
        if type(project) is not GitHubProject or not _positive(number) or number > 9_999_999_999:
            raise ValueError()
        if (type(value) is not dict or set(value) not in (
                {'status', 'completeness', 'pull', 'reviews', 'pages'},
                {'status', 'completeness', 'pull', 'reviews', 'pages', 'reason'})
                or type(value['status']) is not str or value['status'] not in _CODES
                or value['completeness'] not in {'complete', 'incomplete', 'unknown'}
                or (value['status'] == 'OK') != (value['completeness'] == 'complete')
                or type(value['reviews']) is not list or len(value['reviews']) > 1000
                or type(value['pages']) is not int or not 0 <= value['pages'] <= 10
                or len(json.dumps(value, ensure_ascii=False).encode()) > MAX_OBSERVATION):
            raise ValueError()
        if 'reason' in value and (value['status'] != 'NOT_FOUND' or value['reason'] != 'not-found-or-inaccessible'):
            raise ValueError()
        if value['status'] in {'NOT_FOUND', 'STALE_PULL'} and value['completeness'] != 'unknown':
            raise ValueError()
        if value['pull'] is None:
            if value['completeness'] != 'unknown' or value['reviews'] or value['pages']:
                raise ValueError()
        else:
            if value['completeness'] == 'unknown' or _pull(value['pull'], project, number) != value['pull']:
                raise ValueError()
        if value['status'] == 'OK' and (value['pages'] < 1
                or len(value['reviews']) >= value['pages'] * 100):
            # A complete observation includes a final short page. Counts are
            # not verdicts, but impossible pagination metadata is not evidence.
            raise ValueError()
        if value['completeness'] == 'incomplete' and len(value['reviews']) > (value['pages'] + 1) * 100:
            raise ValueError()
        ids = set()
        for review in value['reviews']:
            if _review(review, project, number) != review or review['id'] in ids:
                raise ValueError()
            ids.add(review['id'])
        # Normalize/detach so transport-owned mutable objects cannot change audit.
        return json.loads(json.dumps(value))
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError, LedgerError):
        raise LedgerError('INVALID_PROVIDER_OBSERVATION') from None


class GitHubPullProvider:
    def __init__(self, project, transport, *, max_pages=10, max_bytes=MAX_OUTPUT):
        if type(project) is not GitHubProject or not callable(transport):
            raise LedgerError('INVALID_PROJECT')
        if (type(max_pages) is not int or not 1 <= max_pages <= 10
                or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_OUTPUT):
            raise LedgerError('INVALID_PROVIDER_LIMIT')
        self.project, self.transport = project, transport
        self.max_pages, self.max_bytes = max_pages, max_bytes

    def read_pull(self, number):
        if not _positive(number) or number > 9_999_999_999:
            raise LedgerError('INVALID_PULL')
        result = {'status': 'PROVIDER_ERROR', 'completeness': 'unknown', 'pull': None, 'reviews': [], 'pages': 0}
        used, deadline = 0, time.monotonic() + 30
        def get(path):
            nonlocal used
            if time.monotonic() >= deadline:
                raise ProviderFailure('TIMEOUT')
            response = self.transport(path)
            if time.monotonic() >= deadline:
                raise ProviderFailure('TIMEOUT')
            if (type(response) is not ProviderResponse or type(response.status) is not int
                    or type(response.body) is not bytes or type(response.headers) is not dict):
                raise ProviderFailure('INVALID_RESPONSE')
            used += len(response.body)
            if used > self.max_bytes:
                raise ProviderFailure('OUTPUT_LIMIT')
            if response.status != 200:
                return response, None
            try:
                return response, json.loads(response.body, object_pairs_hook=_unique)
            except (ValueError, UnicodeError, RecursionError):
                raise ProviderFailure('INVALID_RESPONSE') from None
        try:
            base = f'repos/{self.project.repository}/pulls/{number}'
            response, value = get(base)
            if response.status == 404:
                return {**result, 'status': 'NOT_FOUND', 'reason': 'not-found-or-inaccessible'}
            if response.status != 200:
                return result
            result['pull'] = _pull(value, self.project, number)
            result['completeness'] = 'incomplete'
            seen = set()
            for page in range(1, self.max_pages + 1):
                response, values = get(base + f'/reviews?per_page=100&page={page}')
                if response.status != 200:
                    raise ProviderFailure('PROVIDER_ERROR')
                if type(values) is not list or len(values) > 100:
                    raise ProviderFailure('INVALID_RESPONSE')
                for value in values:
                    review = _review(value, self.project, number)
                    if review['id'] in seen:
                        raise ProviderFailure('INVALID_RESPONSE')
                    seen.add(review['id'])
                    if len(json.dumps({**result, 'reviews': result['reviews'] + [review]}, ensure_ascii=False).encode()) > MAX_OBSERVATION - 512:
                        result['status'] = 'OUTPUT_LIMIT'
                        return result
                    result['reviews'].append(review)
                result['pages'] = page
                links = [v for k, v in response.headers.items() if type(k) is str and k.lower() == 'link']
                if any(type(v) is not str for v in links):
                    raise ProviderFailure('INVALID_RESPONSE')
                has_next = any(re.search(r'rel\s*=\s*["\']?next', v, re.I) for v in links)
                if len(values) < 100 and not has_next:
                    response, final = get(base)
                    if response.status != 200:
                        raise ProviderFailure('PROVIDER_ERROR')
                    if _pull(final, self.project, number) != result['pull']:
                        return {'status': 'STALE_PULL', 'completeness': 'unknown',
                                'pull': None, 'reviews': [], 'pages': 0}
                    result.update(status='OK', completeness='complete')
                    return result
            result['status'] = 'PAGINATION_LIMIT'
            return result
        except ProviderFailure as error:
            result['status'] = error.code
            return result
        except (ValueError, TypeError, KeyError, LedgerError, RecursionError):
            result['status'] = 'INVALID_RESPONSE'
            return result
        except Exception:
            result['status'] = 'PROVIDER_ERROR'
            return result
