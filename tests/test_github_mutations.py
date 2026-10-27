"""Account-free provider tests: no commands, listeners, sockets or network."""
from copy import deepcopy
import json
import re
import unittest
from unittest.mock import patch

from uas.github_mutation_routes import parse_mutation_route
from uas.github_mutations import GitHubMutationProvider
from uas.github_read import GitHubProject, MAX_OUTPUT, ProviderResponse
from uas.ledger import LedgerError


class MemoryGitHub:
    """Literal bounded response fixture; it does not emulate GitHub permission."""
    repository = 'owner/repo'
    base = 'repos/owner/repo'
    api = 'https://api.github.com/repos/owner/repo'
    web = 'https://github.com/owner/repo'

    def __init__(self):
        self.user = {'id': 41, 'login': 'alice'}
        self.repo = {'id': 7, 'full_name': self.repository, 'html_url': self.web}
        self.issues = {1: self.issue(1), 2: self.issue(2, user_id=88)}
        self.pulls = {3: self.pull(3)}
        self.parent = {'id': 501, 'pull_request_url': self.api + '/pulls/3'}
        self.calls, self.effects = [], []
        self.before = self.after = None
        self.next_number, self.next_id = 4, 700

    def issue(self, number, *, user_id=41):
        return {'id': 100 + number, 'number': number, 'state': 'open',
                'repository_url': self.api, 'html_url': self.web + '/issues/' + str(number),
                'url': self.api + '/issues/' + str(number), 'user': {'id': user_id},
                'title': 'Before', 'body': 'Before body', 'assignees': [], 'labels': [{'name': 'docs'}]}

    def pull(self, number, *, user_id=41):
        return {'id': 200 + number, 'number': number, 'state': 'open',
                'html_url': self.web + '/pull/' + str(number), 'user': {'id': user_id},
                'title': 'Before', 'body': 'Before body', 'draft': False,
                'base': {'ref': 'main', 'repo': {'full_name': self.repository}},
                'head': {'ref': 'feature', 'sha': 'a' * 40, 'repo': {'full_name': self.repository}},
                'assignees': [], 'labels': [{'name': 'docs'}]}

    @staticmethod
    def response(value, status=200):
        return ProviderResponse(status, json.dumps(value).encode(), {})

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        if self.before:
            override = self.before(method, path, body)
            if override is not None: return override
        response = self._dispatch(method, path, body)
        if method != 'GET': self.effects.append((method, path, deepcopy(body)))
        if self.after:
            override = self.after(method, path, body, response)
            if override is not None: return override
        return response

    def _dispatch(self, method, path, body):
        if method == 'GET' and path == 'user': return self.response(self.user)
        if method == 'GET' and path == self.base: return self.response(self.repo)
        if method == 'GET' and path == self.base + '/pulls/comments/501': return self.response(self.parent)
        if method == 'POST' and path in {self.base + '/issues', self.base + '/pulls'}:
            number = self.next_number; self.next_number += 1
            is_pull = path.endswith('/pulls')
            item = self.pull(number) if is_pull else self.issue(number)
            for key, value in body.items():
                if key in {'base', 'head'}: item[key]['ref'] = value
                else: item[key] = value
            (self.pulls if is_pull else self.issues)[number] = item
            return self.response(item, 201)
        match = re.fullmatch(re.escape(self.base) + r'/(issues|pulls)/(\d+)(.*)', path)
        if not match: raise AssertionError('Unimplemented fixture endpoint: ' + path)
        family, raw_number, suffix = match.groups(); number = int(raw_number)
        item = (self.pulls if family == 'pulls' else {**self.issues, **self.pulls})[number]
        def issue_facade():
            value=deepcopy(item)
            if family=='issues' and number in self.pulls:
                value['id']+=100000
                value['repository_url']=self.api
                value['pull_request']={'url':self.api+'/pulls/'+str(number)}
            return value
        if not suffix:
            if method == 'PATCH':
                for key, value in body.items():
                    if key == 'base': item['base']['ref'] = value
                    else: item[key] = value
            return self.response(issue_facade())
        if suffix == '/assignees':
            if method == 'POST' and not any(a['id'] == self.user['id'] for a in item['assignees']):
                item['assignees'].append(deepcopy(self.user))
            if method == 'DELETE': item['assignees'] = [a for a in item['assignees'] if a['id'] != self.user['id']]
            return self.response(issue_facade(), 201 if method == 'POST' else 200)
        if suffix.startswith('/labels'):
            if method == 'POST':
                item['labels'] += [{'name': label} for label in body['labels'] if label not in [v['name'] for v in item['labels']]]
            if method == 'DELETE':
                from urllib.parse import unquote
                label = unquote(suffix[len('/labels/'):]); item['labels'] = [v for v in item['labels'] if v['name'] != label]
            return self.response(item['labels'])
        if suffix == '/comments' or suffix == '/comments/501/replies':
            self.next_id += 1
            field = 'pull_request_url' if suffix.endswith('/replies') else 'issue_url'
            return self.response({'id': self.next_id, 'user': deepcopy(self.user), 'body': body['body'],
                                  **({'in_reply_to_id':501} if suffix.endswith('/replies') else {}),
                                  field: self.api + ('/pulls/' if field == 'pull_request_url' else '/issues/') + str(number)}, 201)
        if suffix == '/reviews':
            self.next_id += 1
            return self.response({'id': self.next_id, 'user': deepcopy(self.user), 'body': body['body'],
                                  'commit_id': body['commit_id'], 'pull_request_url': self.api + '/pulls/' + str(number),
                                  'state': {'APPROVE': 'APPROVED', 'REQUEST_CHANGES': 'CHANGES_REQUESTED', 'COMMENT': 'COMMENTED'}[body['event']],
                                  'submitted_at': '2026-10-27T15:00:00Z'})
        if suffix.startswith('/dependencies/blocked_by'):
            issue_id = body['issue_id'] if method == 'POST' else int(suffix.rsplit('/', 1)[1])
            other = next(value for value in self.issues.values() if value['id'] == issue_id)
            return self.response(other, 201 if method == 'POST' else 200)
        raise AssertionError('Unimplemented fixture endpoint: ' + path)


class MutationProviderTests(unittest.TestCase):
    def setUp(self):
        self.fixture = MemoryGitHub()
        self.project = GitHubProject('owner/repo')
        self.provider = GitHubMutationProvider(self.project, self.fixture)
        self.events = []

    def execute(self, argv, *, authorize=lambda: True):
        route = parse_mutation_route(argv, self.project, work_labels=('bug', 'docs'))
        return self.provider.execute(route, 41,
            before_write=lambda step, target: self.events.append(('prepared', step, deepcopy(target))),
            confirmed=lambda step, fields, obj: self.events.append(('confirmed', step, fields, deepcopy(obj))),
            rejected=lambda step, code: self.events.append(('rejected', step, code)), authorize=authorize)

    def test_close_reason_must_match_confirmed_state_receipt(self):
        def wrong_reason(method,path,body,response):
            if method=='PATCH':
                value=json.loads(response.body);value['state_reason']='completed'
                return self.fixture.response(value)
        self.fixture.after=wrong_reason
        response=self.execute(['issue','close','1','--reason','not-planned'])
        self.assertEqual('UNKNOWN_OUTCOME',response['status'])
        self.assertEqual([],response['confirmed_fields'])

    def test_pull_assignment_uses_verified_issue_facade_not_pull_id(self):
        pull_id=self.fixture.pulls[3]['id']
        for flag in ('--add-assignee','--remove-assignee'):
            response=self.execute(['pr','edit','3',flag,'@me'])
            self.assertEqual('OK',response['status'])
            self.assertEqual([{'kind':'issue','id':pull_id+100000,'number':3}],response['objects'])
        def wrong_facade(method,path,body,response):
            if method=='GET' and path.endswith('/issues/3'):
                value=json.loads(response.body);value['pull_request']['url']=self.fixture.api+'/pulls/4'
                return self.fixture.response(value)
        self.fixture.after=wrong_facade;before=len(self.fixture.effects)
        response=self.execute(['pr','edit','3','--add-assignee','@me'])
        self.assertEqual('PROVIDER_FAILURE',response['status'])
        self.assertEqual(before,len(self.fixture.effects))

    def test_issue_create_edit_close_reopen_confirm_exact_fields(self):
        created = self.execute(['issue', 'create', '--title', 'Created', '--body', 'Content'])
        self.assertEqual('OK', created['status'])
        self.assertEqual(['create', 'title', 'body'], created['confirmed_fields'])
        self.assertEqual([{'kind': 'issue', 'id': 104, 'number': 4}], created['objects'])
        edited = self.execute(['issue', 'edit', '1', '--title', 'Changed', '--body', 'Changed body'])
        self.assertEqual(['title', 'body'], edited['confirmed_fields'])
        self.assertEqual('Changed body', self.fixture.issues[1]['body'])
        for verb, state in [('close', 'closed'), ('reopen', 'open')]:
            outcome = self.execute(['issue', verb, '1'])
            self.assertEqual(['state'], outcome['confirmed_fields'])
            self.assertEqual(state, self.fixture.issues[1]['state'])
        self.assertEqual('prepared', self.events[0][0])
        self.assertEqual('confirmed', self.events[1][0])

    def test_pull_create_edit_and_review_are_exact_candidate(self):
        created = self.execute(['pr', 'create', '--title', 'Pull', '--body', 'Description',
                                '--head', 'topic', '--base', 'main', '--draft'])
        self.assertEqual('OK', created['status'])
        self.assertEqual(['create', 'title', 'body', 'base', 'head', 'draft'], created['confirmed_fields'])
        changed = self.execute(['pr', 'edit', '3', '--base', 'release'])
        self.assertEqual(['base'], changed['confirmed_fields'])
        self.assertEqual('release', self.fixture.pulls[3]['base']['ref'])
        for flag in ['approve', 'request-changes', 'comment']:
            reviewed = self.execute(['pr', 'review', '3', '--' + flag, '--commit', 'a' * 40, '--body', 'Review'])
            self.assertEqual('OK', reviewed['status'])
            self.assertEqual(['review'], reviewed['confirmed_fields'])
            self.assertEqual('review', reviewed['objects'][0]['kind'])

    def test_issue_and_pull_comments_and_parent_bound_reply(self):
        for argv, field in [(['issue', 'comment', '1', '--body', 'Text'], 'comment'),
                            (['pr', 'comment', '3', '--body', 'Text'], 'comment'),
                            (['pr', 'reply', '3', '--comment-id', '501', '--body', 'Reply'], 'reply')]:
            outcome = self.execute(argv)
            self.assertEqual('OK', outcome['status'])
            self.assertEqual([field], outcome['confirmed_fields'])
            self.assertEqual('comment', outcome['objects'][0]['kind'])
        self.fixture.parent['pull_request_url'] = self.fixture.api + '/pulls/999'
        count = len(self.fixture.effects)
        self.assertEqual('PROVIDER_FAILURE', self.execute(['pr', 'reply', '3', '--comment-id', '501', '--body', 'Bad'])['status'])
        self.assertEqual(count, len(self.fixture.effects))

    def test_additive_assignment_and_owned_label_changes(self):
        self.fixture.issues[1]['assignees'] = [{'id': 88, 'login': 'other'}]
        outcome = self.execute(['issue', 'edit', '1', '--add-assignee', '@me', '--add-label', 'bug', '--remove-label', 'docs'])
        self.assertEqual('OK', outcome['status'])
        self.assertEqual(['add-assignee', 'add-label', 'remove-label'], outcome['confirmed_fields'])
        self.assertEqual([88, 41], [v['id'] for v in self.fixture.issues[1]['assignees']])
        outcome = self.execute(['issue', 'edit', '1', '--remove-assignee', '@me'])
        self.assertEqual(['remove-assignee'], outcome['confirmed_fields'])
        self.assertEqual([88], [v['id'] for v in self.fixture.issues[1]['assignees']])
        self.assertEqual([{'name': 'bug'}], self.fixture.issues[1]['labels'])

    def test_native_dependency_resolves_both_issue_ids_and_pinned_paths(self):
        for verb, field in [('add', 'dependency'), ('remove', 'remove-dependency')]:
            outcome = self.execute(['issue', 'dependency', verb, '1', '--blocked-by', '2'])
            self.assertEqual('OK', outcome['status'])
            self.assertEqual([field], outcome['confirmed_fields'])
            self.assertEqual([{'kind': 'issue', 'id': 101, 'number': 1}], outcome['objects'])
            checkpoint = self.events[-2][2]
            self.assertEqual((102, 2), (checkpoint['related_id'], checkpoint['related_number']))
        self.assertIn(('POST', self.fixture.base + '/issues/1/dependencies/blocked_by', {'issue_id': 102}), self.fixture.effects)
        self.assertIn(('DELETE', self.fixture.base + '/issues/1/dependencies/blocked_by/102', None), self.fixture.effects)
        for corrupt in ['pull', 'repository', 'self-id']:
            fixture = MemoryGitHub()
            if corrupt == 'pull': fixture.issues[2]['pull_request'] = {}
            elif corrupt == 'repository': fixture.issues[2]['repository_url'] = 'https://api.github.com/repos/other/repo'
            else: fixture.issues[2]['id'] = fixture.issues[1]['id']
            self.fixture = fixture; self.provider = GitHubMutationProvider(self.project, fixture)
            with self.subTest(corrupt=corrupt):
                outcome = self.execute(['issue', 'dependency', 'add', '1', '--blocked-by', '2'])
                self.assertEqual('PROVIDER_FAILURE', outcome['status'])
                self.assertEqual([], fixture.effects)

    def test_partial_mutation_reports_confirmed_title_not_failed_body(self):
        self.fixture.before = lambda method, path, body: (MemoryGitHub.response({'message': 'secret'}, 403)
            if method == 'PATCH' and 'body' in body else None)
        outcome = self.execute(['issue', 'edit', '1', '--title', 'Applied', '--body', 'Rejected'])
        self.assertEqual('PARTIAL_MUTATION', outcome['status'])
        self.assertEqual(['title'], outcome['confirmed_fields'])
        self.assertEqual('body', outcome['failed_field'])
        self.assertEqual('Before body', self.fixture.issues[1]['body'])
        self.assertEqual('rejected', self.events[-1][0])
        self.assertNotIn('secret', str(outcome))

    def test_lost_response_after_effect_is_unknown_with_earlier_fields_preserved(self):
        def lost(method, path, body, response):
            if method == 'PATCH' and 'body' in body: raise OSError('raw-secret-provider-detail')
        self.fixture.after = lost
        outcome = self.execute(['issue', 'edit', '1', '--title', 'Applied', '--body', 'Applied but lost'])
        self.assertEqual('UNKNOWN_OUTCOME', outcome['status'])
        self.assertEqual(['title'], outcome['confirmed_fields'])
        self.assertEqual('Applied but lost', self.fixture.issues[1]['body'])
        self.assertEqual('write-possible', outcome['contact'])
        self.assertNotIn('raw-secret', str(outcome))

    def test_actor_and_owner_denial_make_no_write_contact(self):
        self.fixture.user['id'] = 999
        self.assertEqual('ACTOR_MISMATCH', self.execute(['issue', 'close', '1'])['error_code'])
        self.assertEqual([], self.fixture.effects)
        self.fixture.user['id'] = 41
        outcome = self.execute(['issue', 'edit', '2', '--title', 'not-owned'])
        self.assertEqual(('DENIED', 'OWNERSHIP_DENIED'), (outcome['status'], outcome['error_code']))
        self.assertEqual([], self.fixture.effects)
        # Comments and self-assignment own their fact, not the issue's author.
        self.assertEqual('OK', self.execute(['issue', 'comment', '2', '--body', 'Allowed'])['status'])

    def test_bad_response_identity_and_stale_review_never_confirm_fields(self):
        self.fixture.pulls[3]['head']['sha'] = 'b' * 40
        outcome = self.execute(['pr', 'review', '3', '--approve', '--commit', 'a' * 40])
        self.assertEqual(('PROVIDER_FAILURE', 'STALE_PULL'), (outcome['status'], outcome['error_code']))
        self.assertEqual([], self.fixture.effects)
        def changed(method, path, body, response):
            if method == 'PATCH':
                value = json.loads(response.body); value['id'] = 999
                return MemoryGitHub.response(value)
        self.fixture.after = changed
        outcome = self.execute(['issue', 'edit', '1', '--title', 'Applied'])
        self.assertEqual('UNKNOWN_OUTCOME', outcome['status'])
        self.assertEqual([], outcome['confirmed_fields'])

    def test_created_pull_requires_pinned_head_repository_not_only_branch_spelling(self):
        def wrong_head(method, path, body, response):
            if method == 'POST' and path.endswith('/pulls'):
                value = json.loads(response.body); value['head']['repo']['full_name'] = 'other/repo'
                return MemoryGitHub.response(value, 201)
        self.fixture.after = wrong_head
        outcome = self.execute(['pr', 'create', '--title', 'Pull', '--body', '', '--base', 'main', '--head', 'topic'])
        self.assertEqual('UNKNOWN_OUTCOME', outcome['status'])
        self.assertEqual([], outcome['confirmed_fields'])

    def test_output_timeout_and_authority_fail_closed(self):
        self.fixture.before = lambda *_: ProviderResponse(200, b'x' * (MAX_OUTPUT + 1), {})
        self.assertEqual('OUTPUT_LIMIT', self.execute(['issue', 'close', '1'])['error_code'])
        self.assertEqual([], self.fixture.effects)
        self.fixture.before = None
        with patch('uas.github_mutations.time.monotonic', side_effect=[0, 31]):
            self.assertEqual('TIMEOUT', self.execute(['issue', 'close', '1'])['error_code'])
        with self.assertRaises(LedgerError) as error:
            self.execute(['issue', 'close', '1'], authorize=lambda: False)
        self.assertEqual('FORBIDDEN', error.exception.code)


if __name__ == '__main__':
    unittest.main()
