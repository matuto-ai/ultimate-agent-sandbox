"""Pure bounded provider tests. No sockets, subprocesses, accounts or native CLI."""
import base64
from copy import deepcopy
import hashlib
import json
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

from uas.github_read import GitHubProject, ProviderResponse, ProviderFailure
from uas.github_routes import parse_read_route
from uas.github_surface import GitHubSurfaceProvider, metadata_summary, KINDS
from uas.ledger import LedgerError

R = 'owner/project'
API = 'https://api.github.com/repos/' + R
SHA = 'a' * 40
HEAD = 'b' * 40
BODY = 'Project text is Participant output, never audit SECRET_BODY'


def response(value, status=200, headers=None):
    return ProviderResponse(status, json.dumps(value).encode(), headers or {})


def user(identifier=7, login='actor'):
    return {'id': identifier, 'login': login, 'email': 'DO_NOT_RETURN_EMAIL'}


def issue(number=42, repository=R):
    api = 'https://api.github.com/repos/' + repository
    return {'id': 1000 + number, 'number': number, 'state': 'open',
        'url': f'{api}/issues/{number}', 'repository_url': api,
        'html_url': f'https://github.com/{repository}/issues/{number}',
        'title': 'Issue title', 'body': BODY, 'user': user(), 'assignees': [user()]}


def pull(number=42, repository=R):
    api = 'https://api.github.com/repos/' + repository
    branch = {'sha': SHA, 'ref': 'main', 'repo': {'id': 900, 'full_name': repository}}
    return {'id': 2000 + number, 'number': number, 'state': 'open',
        'url': f'{api}/pulls/{number}', 'html_url': f'https://github.com/{repository}/pull/{number}',
        'draft': False, 'merged': False, 'merged_by': None, 'merged_at': None,
        'user': user(), 'base': branch, 'head': {**deepcopy(branch), 'sha': HEAD, 'ref': 'feature'},
        'merge_commit_sha': 'c' * 40, 'title': 'Pull title', 'body': BODY,
        'assignees': [user()], 'requested_reviewers': [user(8, 'reviewer')]}


def label(identifier=1):
    return {'id': identifier, 'name': f'label-{identifier}', 'color': 'ff0000',
        'url': f'{API}/labels/label-{identifier}', 'description': 'Label description'}


def comment(identifier=1, number=42, review=False):
    value = {'id': identifier, 'user': user(), 'body': BODY,
             'url': f'{API}/issues/comments/{identifier}', 'issue_url': f'{API}/issues/{number}'}
    if review:
        value.update(url=f'{API}/pulls/comments/{identifier}', pull_request_url=f'{API}/pulls/{number}',
            commit_id=HEAD, original_commit_id=HEAD, pull_request_review_id=99, path='src/main.py')
    return value


def review(identifier=1):
    return {'id': identifier, 'user': user(8, 'reviewer'), 'body': BODY,
        'html_url': f'https://github.com/{R}/pull/42#pullrequestreview-{identifier}',
        'pull_request_url': f'{API}/pulls/42', 'state': 'APPROVED',
        'submitted_at': '2026-10-27T14:00:00Z', 'commit_id': HEAD}


def check(identifier=1, sha=HEAD):
    return {'id': identifier, 'url': f'{API}/check-runs/{identifier}', 'name': 'unit',
        'head_sha': sha, 'status': 'completed', 'conclusion': 'success',
        'app': {'id': 4, 'slug': 'actions'}, 'output': {'text': 'DO_NOT_COPY_CHECK_LOG'}}


def status(identifier=1, sha=HEAD):
    return {'id': identifier, 'url': f'{API}/statuses/{sha}', 'context': 'build',
            'state': 'success', 'creator': user()}


def workflow(identifier=5):
    return {'id': identifier, 'url': f'{API}/actions/workflows/{identifier}',
            'name': 'CI', 'path': '.github/workflows/ci.yml', 'state': 'active'}


def run(identifier=8, attempt=2, sha=HEAD):
    return {'id': identifier, 'url': f'{API}/actions/runs/{identifier}', 'head_sha': sha,
        'run_attempt': attempt, 'workflow_id': 5, 'event': 'pull_request',
        'status': 'completed', 'conclusion': 'success',
        'repository': {'id': 900, 'full_name': R, 'url': API},
        'pull_requests': [{'id': 2042, 'number': 42, 'url': f'{API}/pulls/42',
            'head': {'sha': HEAD, 'repo': {'id': 900, 'url': API}},
            'base': {'sha': SHA, 'repo': {'id': 900, 'url': API}}}]}


def job(identifier=9, attempt=2, sha=HEAD):
    return {'id': identifier, 'url': f'{API}/actions/jobs/{identifier}', 'run_id': 8,
        'run_url': f'{API}/actions/runs/8',
        'run_attempt': attempt, 'head_sha': sha, 'status': 'completed',
        'conclusion': 'success', 'name': 'unit', 'logs': 'DO_NOT_COPY_JOB_LOG'}


class Transport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, path):
        return self.get(path)

    def get(self, path, *, accept=None):
        self.calls.append((path, accept))
        if not self.responses:
            raise AssertionError('unexpected transport call')
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class SurfaceTests(unittest.TestCase):
    def setUp(self):
        self.project = GitHubProject(R)

    def read(self, argv, responses, **limits):
        self.transport = Transport(responses)
        provider = GitHubSurfaceProvider(self.project, self.transport, **limits)
        value = provider.read(parse_read_route(argv, self.project))
        self.assertFalse(self.transport.responses, 'expected all test responses to be consumed')
        metadata_summary(value)
        return value

    def route(self, kind, number=None, options=None):
        return SimpleNamespace(kind=kind, repository=R, number=number,
                               options=MappingProxyType(options or {}))

    def test_repository_metadata_ignores_untrusted_extra_content(self):
        raw = {'id': 900, 'full_name': R, 'private': True, 'url': API,
            'html_url': 'https://github.com/' + R, 'default_branch': 'main',
            'description': 'Repository', 'token': 'SECRET_TOKEN'}
        value = self.read(['repo', 'view'], [response(raw)])
        self.assertEqual('OK', value['status'])
        self.assertNotIn('SECRET_TOKEN', json.dumps(value))

    def test_file_pins_resolved_commit_and_verifies_git_blob(self):
        data = b'print("hello")\n'
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        value = self.read(['repo', 'read-file', 'src/a b.py', '--ref', 'feature'], [
            response({'sha': SHA, 'url': f'{API}/commits/{SHA}'}),
            response({'path': 'src/a b.py', 'type': 'file', 'encoding': 'base64',
                'size': len(data), 'sha': blob, 'content': base64.b64encode(data).decode()})])
        self.assertEqual('complete', value['completeness'])
        self.assertEqual(data.decode(), value['data']['content'])
        self.assertEqual(f'repos/{R}/contents/src/a%20b.py?ref={SHA}', self.transport.calls[1][0])
        self.assertNotIn('print', json.dumps(metadata_summary(value)))

    def test_symlink_binary_mismatched_file_identity_fails_closed(self):
        base = {'path': 'a', 'type': 'file', 'encoding': 'base64', 'size': 1,
            'sha': '1' * 40, 'content': base64.b64encode(b'x').decode()}
        for change in ({'type': 'symlink'}, {'path': '../b'}, {'size': True}, {'encoding': 'none'}, {'content': '@@@'}, {}):
            with self.subTest(change=change):
                value = self.read(['repo', 'read-file', 'a'], [
                    response({'sha': SHA, 'url': f'{API}/commits/{SHA}'}), response({**base, **change})])
                self.assertEqual('INVALID_RESPONSE', value['status'])
                self.assertIsNone(value['data'])

    def test_issue_display_returns_body_labels_and_optional_comments_only_to_output(self):
        value = self.read(['issue', 'view', '42', '--comments'], [
            response(issue()), response([comment()]), response([label()])])
        self.assertEqual(BODY, value['data']['issue']['body'])
        self.assertEqual(BODY, value['data']['comments'][0]['body'])
        self.assertEqual('label-1', value['data']['labels'][0]['name'])
        self.assertNotIn('SECRET_BODY', json.dumps(metadata_summary(value)))
        self.assertNotIn('DO_NOT_RETURN_EMAIL', json.dumps(value))

    def test_issue_list_skips_pull_objects_without_claiming_they_are_issues(self):
        as_issue = issue(43)
        as_issue.update(html_url=f'https://github.com/{R}/pull/43', pull_request={'url': f'{API}/pulls/43'})
        value = self.read(['issue', 'list', '--state', 'all'], [response([issue(), as_issue])])
        self.assertEqual([42], [v['number'] for v in value['data']])
        self.assertIn('state=all', self.transport.calls[0][0])

    def test_same_forge_repository_is_selected_not_project_allowlisted(self):
        value = self.read(['issue', 'list', '--repo', 'other/project'], [response([issue(repository='other/project')])])
        self.assertEqual('OK', value['status'])
        self.assertEqual('other/project', value['repository'])
        self.assertTrue(self.transport.calls[0][0].startswith('repos/other/project/'))
        wrong = self.read(['issue', 'list', '--repo', 'other/project'], [response([issue()])])
        self.assertEqual('INVALID_RESPONSE', wrong['status'])

    def test_malformed_pr_marker_cannot_hide_invalid_issue_list_response(self):
        value = self.read(['issue', 'list'], [response([{'pull_request': {}}])])
        self.assertEqual('INVALID_RESPONSE', value['status'])
        changed = issue(); changed['id'] += 1
        value = self.read(['issue', 'list'], [response([issue(), changed])])
        self.assertEqual('INVALID_RESPONSE', value['status'])

    def test_permission_and_not_found_do_not_become_absence(self):
        for code, expected in ((404, 'NOT_FOUND'), (403, 'PROVIDER_ERROR'), (429, 'PROVIDER_ERROR'), (500, 'PROVIDER_ERROR')):
            value = self.read(['issue', 'list'], [response({'body': 'SECRET_ERROR'}, code)])
            self.assertEqual(expected, value['status'])
            self.assertEqual('unknown', value['completeness'])
            self.assertIsNone(value['data'])
            self.assertNotIn('SECRET_ERROR', json.dumps(value))

    def test_labels_and_both_native_dependency_directions(self):
        value = self.read(['label', 'list'], [response([label()])])
        self.assertEqual('OK', value['status'])
        for noun, path in (('dependencies', 'blocked_by'), ('blocks', 'blocking')):
            value = self.read(['issue', noun, '42'], [response(issue()), response([issue(41)])])
            self.assertEqual('OK', value['status'])
            self.assertEqual(path, value['data']['direction'])
            self.assertIn('/dependencies/' + path, self.transport.calls[1][0])
        value = self.read(['issue', 'dependencies', '42'], [response(issue()), response([issue()])])
        self.assertEqual('INVALID_RESPONSE', value['status'])

    def test_issue_status_uses_current_native_credential_identity(self):
        value = self.read(['issue', 'status'], [response(user()), response([issue()]), response([]), response([])])
        self.assertEqual('OK', value['status'])
        self.assertEqual(('user', None), self.transport.calls[0])
        self.assertIn('assignee=actor', self.transport.calls[1][0])
        self.assertIn('creator=actor', self.transport.calls[2][0])
        self.assertIn('mentioned=actor', self.transport.calls[3][0])

    def test_pull_display_review_and_comments_keep_exact_candidates(self):
        raw = pull()
        value = self.read(['pr', 'view', '42', '--comments'], [response(raw), response([label()]),
            response([review()]), response([comment()]), response(raw)])
        self.assertEqual('complete', value['completeness'])
        self.assertEqual(HEAD, value['data']['reviews'][0]['commit_id'])
        self.assertEqual(BODY, value['data']['pull']['body'])
        self.assertEqual(BODY, value['data']['reviews'][0]['body'])
        self.assertNotIn('SECRET_BODY', json.dumps(metadata_summary(value)))
        self.assertNotIn('verdict', json.dumps(value))

    def test_pull_lists_and_native_status_do_not_invent_merge_or_membership(self):
        raw = pull(); del raw['merged']
        value = self.read(['pr', 'list'], [response([raw])])
        self.assertIsNone(value['data'][0]['merged'])
        value = self.read(['pr', 'status'], [response(user()), response([raw])])
        self.assertEqual(1, len(value['data']['created']))
        self.assertEqual(1, len(value['data']['assigned']))
        self.assertEqual([], value['data']['review_requested'])
        self.assertEqual('observed', value['data']['membership'])
        del raw['assignees']
        value = self.read(['pr', 'status'], [response(user()), response([raw])])
        self.assertEqual('unknown', value['data']['membership'])

    def test_pull_merged_filter_uses_literal_merge_timestamp(self):
        a, b = pull(), pull(43)
        b.update(state='closed', merged_at='2026-10-27T14:00:00Z')
        value = self.read(['pr', 'list', '--state', 'merged'], [response([a, b])])
        self.assertEqual([43], [p['number'] for p in value['data']])
        self.assertIn('state=closed', self.transport.calls[0][0])

    def test_actual_unified_diff_uses_fixed_accept_and_closing_pull_fence(self):
        diff = b'diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n'
        value = self.read(['pr', 'diff', '42'], [response(pull()), ProviderResponse(200, diff, {}), response(pull())])
        self.assertEqual(diff.decode(), value['data']['diff'])
        self.assertEqual((f'repos/{R}/pulls/42', 'application/vnd.github.diff'), self.transport.calls[1])
        self.assertNotIn('diff --git', json.dumps(metadata_summary(value)))

    def test_diff_cannot_fallback_to_fake_complete_patch_fragments(self):
        transport = lambda _: response(pull())
        value = GitHubSurfaceProvider(self.project, transport).read(self.route('pr-diff', 42))
        self.assertEqual('PROVIDER_ERROR', value['status'])
        self.assertNotEqual('complete', value['completeness'])

    def test_pull_reviews_and_review_comments_are_distinct(self):
        for kind, raw, key in (('reviews', review(), 'reviews'), ('review-comments', comment(review=True), 'comments')):
            value = self.read(['pr', kind, '42'], [response(pull()), response([raw]), response(pull())])
            self.assertEqual('OK', value['status'])
            self.assertEqual(BODY, value['data'][key][0]['body'])
        raw = comment(review=True); raw['pull_request_url'] = 'https://api.github.com/repos/other/project/pulls/42'
        value = self.read(['pr', 'review-comments', '42'], [response(pull()), response([raw])])
        self.assertEqual('INVALID_RESPONSE', value['status'])

    def test_changed_pull_head_base_or_identity_invalidates_output(self):
        for field in ('head', 'base', 'id'):
            changed = pull()
            if field == 'id': changed['id'] += 1
            else: changed[field]['sha'] = 'd' * 40
            value = self.read(['pr', 'reviews', '42'], [response(pull()), response([review()]), response(changed)])
            self.assertEqual('STALE_SOURCE', value['status'])
            self.assertIsNone(value['data'])
            self.assertNotEqual('complete', value['completeness'])

    def test_checks_statuses_and_actions_are_distinct_and_not_gate_pass(self):
        value = self.read(['pr', 'checks', '42'], [response(pull()),
            response({'total_count': 1, 'check_runs': [check()]}), response([status()]),
            response({'total_count': 1, 'workflow_runs': [run()]}),
            response({'sha': 'c' * 40, 'url': f'{API}/commits/' + 'c' * 40,
                      'parents': [{'sha': SHA}, {'sha': HEAD}]}),
            response({'total_count': 0, 'check_runs': []}), response([]),
            response({'total_count': 0, 'workflow_runs': []}), response(pull())])
        self.assertEqual('OK', value['status'])
        data = value['data']
        self.assertEqual((HEAD, SHA), (data['candidate_sha'], data['base_sha']))
        self.assertEqual('not-evaluated', data['coverage'])
        self.assertEqual('success', data['checks'][0]['conclusion'])
        self.assertEqual('success', data['statuses'][0]['state'])
        self.assertEqual(2, data['runs'][0]['run_attempt'])
        self.assertEqual('verified-parents', data['test_merge']['association'])
        self.assertEqual('not-evaluated', data['test_merge']['coverage'])
        self.assertNotEqual(data['candidate_sha'], data['test_merge']['tested_sha'])
        self.assertNotIn('DO_NOT_COPY_CHECK_LOG', json.dumps(value))
        self.assertNotIn('passed', json.dumps(value))

    def test_wrong_check_sha_or_test_merge_run_is_not_head_evidence(self):
        for wrong in ('check', 'run'):
            responses = [response(pull()), response({'total_count': 1, 'check_runs': [check(sha=SHA if wrong == 'check' else HEAD)]})]
            if wrong == 'run': responses += [response([]), response({'total_count': 1, 'workflow_runs': [run(sha='c' * 40)]})]
            value = self.read(['pr', 'checks', '42'], responses)
            self.assertEqual('INVALID_RESPONSE', value['status'])
            self.assertNotEqual('complete', value['completeness'])

    def test_unverified_test_merge_parents_never_become_head_coverage(self):
        value = self.read(['pr', 'checks', '42'], [response(pull()),
            response({'total_count': 0, 'check_runs': []}), response([]),
            response({'total_count': 0, 'workflow_runs': []}),
            response({'sha': 'c' * 40, 'url': f'{API}/commits/' + 'c' * 40,
                      'parents': [{'sha': 'd' * 40}, {'sha': HEAD}]}),
            response({'total_count': 1, 'check_runs': [check(sha='c' * 40)]}), response([]),
            response({'total_count': 0, 'workflow_runs': []}), response(pull())])
        self.assertEqual('OK', value['status'])
        self.assertEqual('unknown', value['data']['test_merge']['association'])
        self.assertEqual('success', value['data']['test_merge']['checks'][0]['conclusion'])
        self.assertEqual('not-evaluated', value['data']['test_merge']['coverage'])
        self.assertEqual([], value['data']['checks'])

    def test_workflow_metadata_and_run_list(self):
        value = self.read(['workflow', 'list'], [response({'total_count': 1, 'workflows': [workflow()]})])
        self.assertEqual('OK', value['status'])
        value = self.read(['workflow', 'view', '5'], [response(workflow())])
        self.assertEqual('.github/workflows/ci.yml', value['data']['path'])
        value = self.read(['run', 'list'], [response({'total_count': 1, 'workflow_runs': [run()]})])
        self.assertEqual('not-evaluated', value['data'][0]['coverage'])

    def test_run_view_binds_jobs_to_exact_attempt_and_head(self):
        value = self.read(['run', 'view', '8', '--attempt', '2'], [response(run()),
            response({'total_count': 1, 'jobs': [job()]}), response(run())])
        self.assertEqual('OK', value['status'])
        self.assertEqual(2, value['data']['jobs'][0]['run_attempt'])
        self.assertEqual(f'repos/{R}/actions/runs/8/attempts/2/jobs?per_page=100&page=1', self.transport.calls[1][0])
        self.assertNotIn('DO_NOT_COPY_JOB_LOG', json.dumps(value))

    def test_job_view_derives_run_without_trusting_caller_identity(self):
        value = self.read(['run', 'view', '--job', '9'], [response(job()), response(run()),
            response({'total_count': 1, 'jobs': [job()]}), response(job()), response(run())])
        self.assertEqual('OK', value['status'])
        self.assertEqual(8, value['data']['run']['id'])
        self.assertEqual(9, value['data']['job']['id'])
        self.assertEqual(f'repos/{R}/actions/runs/8', self.transport.calls[1][0])
        self.assertEqual(f'repos/{R}/actions/runs/8/attempts/2/jobs?per_page=100&page=1', self.transport.calls[2][0])
        value = self.read(['run', 'view', '10', '--job', '9'], [response(job())])
        self.assertEqual('INVALID_RESPONSE', value['status'])
        value = self.read(['run', 'view', '--job', '9', '--attempt', '1'], [response(job()), response(run(attempt=1)),
            response({'total_count': 1, 'jobs': [job()]})])
        self.assertEqual('INVALID_RESPONSE', value['status'])

    def test_job_without_attempt_field_is_bound_by_paginated_attempt_membership(self):
        raw = job(); raw.pop('run_attempt')
        value = self.read(['run', 'view', '--job', '9'], [response(raw), response(run()),
            response({'total_count': 0, 'jobs': []}), response(run(attempt=1)),
            response({'total_count': 1, 'jobs': [raw]}), response(raw), response(run(attempt=1))])
        self.assertEqual('OK', value['status'])
        self.assertEqual(1, value['data']['job']['run_attempt'])
        self.assertEqual(f'repos/{R}/actions/runs/8/attempts/1/jobs?per_page=100&page=1', self.transport.calls[4][0])

    def test_run_attempt_job_scope_and_status_races_fail(self):
        for raw in (job(attempt=1), job(sha=SHA), {**job(), 'run_id': 10}):
            value = self.read(['run', 'view', '8'], [response(run()), response({'total_count': 1, 'jobs': [raw]})])
            self.assertEqual('INVALID_RESPONSE', value['status'])
        changed = run(); changed['run_attempt'] = 3
        value = self.read(['run', 'view', '8'], [response(run()), response({'total_count': 0, 'jobs': []}), response(changed)])
        self.assertEqual('STALE_SOURCE', value['status'])
        self.assertIsNone(value['data'])

    def test_every_full_page_needs_terminal_page_and_never_follows_next_url(self):
        first = [label(i) for i in range(1, 101)]
        value = self.read(['label', 'list'], [response(first, headers={'Link': '<https://evil.invalid/secret>; rel="next"'}), response([])])
        self.assertEqual('complete', value['completeness'])
        self.assertEqual(2, value['pages'])
        self.assertEqual(f'repos/{R}/labels?per_page=100&page=2', self.transport.calls[1][0])
        self.assertNotIn('evil', repr(self.transport.calls))

    def test_pagination_count_cap_and_explicit_limit_are_incomplete(self):
        value = self.read(['label', 'list'], [response([label(i) for i in range(1, 101)])], max_pages=1)
        self.assertEqual('PAGINATION_LIMIT', value['status'])
        self.assertEqual('incomplete', value['completeness'])
        value = self.read(['label', 'list', '--limit', '1'], [response([label(), label(2)])])
        self.assertEqual('PAGINATION_LIMIT', value['status'])
        self.assertEqual(1, len(value['data']))
        value = self.read(['workflow', 'list'], [response({'total_count': 2, 'workflows': [workflow()]})])
        self.assertEqual('INVALID_RESPONSE', value['status'])

    def test_duplicate_ids_and_later_page_failure_cannot_report_empty_success(self):
        value = self.read(['label', 'list'], [response([label(), label()])])
        self.assertEqual('INVALID_RESPONSE', value['status'])
        value = self.read(['label', 'list'], [response([label(i) for i in range(1, 101)]), response({}, 404)])
        self.assertEqual('PROVIDER_ERROR', value['status'])
        self.assertEqual('incomplete', value['completeness'])
        self.assertIsNone(value['data'])

    def test_deadline_byte_bounds_malformed_json_and_exception_sanitization(self):
        cases = [(ProviderFailure('TIMEOUT'), 'TIMEOUT'), (RuntimeError('SECRET_EXCEPTION'), 'PROVIDER_ERROR'),
            (ProviderResponse(200, b'{"id":1,"id":2}', {}), 'INVALID_RESPONSE')]
        for raw, expected in cases:
            value = self.read(['repo', 'view'], [raw])
            self.assertEqual(expected, value['status'])
            self.assertNotIn('SECRET_EXCEPTION', json.dumps(value))
        value = self.read(['issue', 'list'], [response([issue()])], max_bytes=10)
        self.assertEqual('OUTPUT_LIMIT', value['status'])
        transport = Transport([])
        provider = GitHubSurfaceProvider(self.project, transport)
        with patch('uas.github_surface.time.monotonic', side_effect=[0, 31]):
            value = provider.read(self.route('repo-view'))
        self.assertEqual('TIMEOUT', value['status'])
        self.assertFalse(transport.calls)

    def test_audit_summary_contains_only_bounded_metadata_and_digest(self):
        value = self.read(['issue', 'list'], [response([issue()])])
        summary = metadata_summary(value)
        self.assertEqual({'kind', 'repository', 'status', 'completeness', 'pages', 'output_bytes', 'output_sha256'}, set(summary))
        self.assertNotIn('SECRET_BODY', json.dumps(summary))
        for change in ({'status': 'SECRET_ERROR'}, {'completeness': 'unknown'}, {'pages': True}, {'repository': 'https://evil.invalid'}):
            with self.assertRaises(LedgerError): metadata_summary({**value, **change})

    def test_internal_commit_read_helpers_validate_exact_sha(self):
        for kind, raw, key in (('commit-checks', {'total_count': 1, 'check_runs': [check()]}, 'checks'),
                               ('commit-statuses', [status()], 'statuses')):
            provider = GitHubSurfaceProvider(self.project, Transport([response(raw)]))
            value = provider.read(self.route(kind, options={'sha': HEAD}))
            self.assertEqual('OK', value['status'])
            self.assertEqual(HEAD, value['data']['sha'])


if __name__ == '__main__':
    unittest.main()
