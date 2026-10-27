"""Pure controlled GitHub semantics: no processes, sockets, network or credentials."""
from copy import deepcopy
import json
import unittest
from urllib.parse import parse_qs

from test_github_mutations import MemoryGitHub
from uas.github_executor import GhSurfaceTransport
from uas.github_mutation_routes import MAX_BODY, parse_mutation_route
from uas.github_mutations import GitHubMutationProvider
from uas.github_read import GitHubProject, ProviderResponse
from uas.github_reconciliation import (GitHubReconciliationProvider, MARKER_OVERHEAD,
    marked_body, planned_fields, preimage_digest)
from uas.ledger import LedgerError

MARKER = '<!-- uas:mutation:' + 'a' * 64 + ' -->'


class RecoverableGitHub(MemoryGitHub):
    def __init__(self):
        super().__init__()
        self.comments, self.reviews, self.replies, self.dependencies = {}, {}, {}, {}
        self.custom_pages = {}

    def _dispatch(self, method, path, body):
        bare, _, query = path.partition('?')
        if method == 'GET' and query:
            page = int(parse_qs(query)['page'][0])
            if (bare, page) in self.custom_pages: return self.custom_pages[bare, page]
            if bare == self.base + '/issues': values = list(self.issues.values())
            elif bare == self.base + '/pulls': values = list(self.pulls.values())
            elif bare.endswith('/labels'):
                number = int(bare.split('/')[-2]); item = {**self.issues, **self.pulls}[number]
                values = [{'id': 1000 + index, **value} for index, value in enumerate(item['labels'])]
            elif bare.endswith('/dependencies/blocked_by'):
                number = int(bare.split('/')[-3]); values = [self.issues[n] for n in self.dependencies.get(number, set())]
            elif bare.endswith('/reviews'): values = self.reviews.get(int(bare.split('/')[-2]), [])
            elif bare.endswith('/comments'):
                number = int(bare.split('/')[-2])
                values = (self.replies if '/pulls/' in bare else self.comments).get(number, [])
            else: raise AssertionError(bare)
            return self.response(values[(page - 1) * 100:page * 100])
        response = super()._dispatch(method, path, body)
        if method == 'POST' and '/comments' in path:
            value = json.loads(response.body); number = int(path.split('/')[4])
            (self.replies if path.endswith('/replies') else self.comments).setdefault(number, []).append(value)
        elif method == 'POST' and path.endswith('/reviews'):
            self.reviews.setdefault(int(path.split('/')[-2]), []).append(json.loads(response.body))
        elif method in {'POST', 'DELETE'} and '/dependencies/blocked_by' in path:
            value = json.loads(response.body); number = int(path.split('/')[4])
            relation = self.dependencies.setdefault(number, set())
            if method == 'POST': relation.add(value['number'])
            else: relation.discard(value['number'])
        return response


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RecoverableGitHub()
        self.project = GitHubProject('owner/repo')
        self.provider = GitHubMutationProvider(self.project, self.fixture)
        self.reconciler = GitHubReconciliationProvider(self.project, self.fixture)

    def route(self, argv):
        return parse_mutation_route(argv, self.project, work_labels=('docs', 'bug', 'feature'))

    def execute(self, argv, *, lost=False, marker=MARKER, fail_field=None):
        route, steps, intents = self.route(argv), [], {}
        if lost:
            def lose(method, path, body, response):
                if method != 'GET': raise TimeoutError('lost after actual effect')
            self.fixture.after = lose
        if fail_field:
            def reject(method, path, body):
                if method == 'PATCH' and fail_field in body: return self.fixture.response({}, 422)
            self.fixture.before = reject
        def before(step, target):
            self.assertEqual(step, len(steps))
            steps.append({'step': step, 'target': deepcopy(target), 'intent': intents[step],
                          'fields': None, 'object': None, 'error_code': None})
        def confirmed(step, fields, obj): steps[step].update(fields=list(fields), object=deepcopy(obj))
        def rejected(step, code): steps[step]['error_code'] = code
        result = self.provider.execute(route, 41, before_write=before, confirmed=confirmed,
            rejected=rejected, authorize=lambda: True, marker=marker,
            prepared_intent=lambda step, intent: intents.__setitem__(step, deepcopy(intent)))
        self.fixture.before = self.fixture.after = None
        return route, {'steps': steps, 'result': result}

    def reconcile(self, route, record, *, marker=MARKER, reconciler=None, authorize=lambda: True):
        before = len(self.fixture.effects)
        start = len(self.fixture.calls)
        result = (reconciler or self.reconciler).reconcile(route, 41, record, marker=marker, authorize=authorize)
        self.assertEqual(before, len(self.fixture.effects))
        self.assertTrue(all(call[0] == 'GET' for call in self.fixture.calls[start:]))
        self.assertEqual('observed-only', result['attribution'])
        return result

    def test_lost_issue_and_pull_create_find_marker_without_replay(self):
        for argv in (['issue', 'create', '--title', 'Created', '--body', 'Private body'],
                     ['pr', 'create', '--title', 'Created', '--body', 'Private body', '--head', 'topic', '--base', 'main']):
            with self.subTest(argv=argv):
                self.setUp()
                route, record = self.execute(argv, lost=True)
                self.assertEqual('UNKNOWN_OUTCOME', record['result']['status'])
                self.assertEqual([], record['result']['confirmed_fields'])
                outcome = self.reconcile(route, record)
                self.assertEqual('MATCHED', outcome['status'])
                self.assertTrue(all(row['status'] == 'MATCHED' for row in outcome['fields']))
                self.assertNotIn('Private body', json.dumps(outcome))
                self.assertEqual(1, len(self.fixture.effects))
                self.reconcile(route, record)
                self.assertEqual(1, len(self.fixture.effects))

    def test_lost_comment_reply_and_review_resolve_exact_parent_author_candidate(self):
        cases = [(['issue', 'comment', '1', '--body', 'Secret note'], 'comment'),
                 (['pr', 'comment', '3', '--body', 'Secret note'], 'comment'),
                 (['pr', 'reply', '3', '--comment-id', '501', '--body', 'Secret note'], 'reply'),
                 (['pr', 'review', '3', '--approve', '--commit', 'a' * 40], 'review')]
        for argv, field in cases:
            with self.subTest(field=field, argv=argv):
                self.setUp(); route, record = self.execute(argv, lost=True)
                self.assertEqual('MATCHED', self.reconcile(route, record)['status'])
                source = {'comment': self.fixture.comments, 'reply': self.fixture.replies, 'review': self.fixture.reviews}[field]
                value = next(iter(source.values()))[0]
                value['user']['id'] = 88
                self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])

    def test_review_match_is_historical_write_not_current_review_authority(self):
        route, record = self.execute(['pr', 'review', '3', '--request-changes', '--body', 'Fix it', '--commit', 'a' * 40], lost=True)
        self.fixture.pulls[3]['head']['sha'] = 'b' * 40
        self.assertEqual('MATCHED', self.reconcile(route, record)['status'])
        self.fixture.reviews[3][0]['commit_id'] = 'b' * 40
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])
        self.fixture.reviews[3][0]['commit_id'] = 'a' * 40
        self.fixture.reviews[3][0]['state'] = 'DISMISSED'
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])

    def test_partial_patch_retains_confirmed_fields_and_observes_absent_preimage(self):
        route, record = self.execute(['issue', 'edit', '1', '--title', 'Changed', '--body', 'Changed body'], fail_field='body')
        self.assertEqual('PARTIAL_MUTATION', record['result']['status'])
        self.assertEqual(['title'], record['result']['confirmed_fields'])
        observed = self.reconcile(route, record)
        self.assertEqual('PARTIAL', observed['status'])
        self.assertEqual(['MATCHED', 'ABSENT'], [f['status'] for f in observed['fields']])
        self.fixture.issues[1]['body'] = 'External edit'
        self.assertEqual(['MATCHED', 'CONFLICT'], [f['status'] for f in self.reconcile(route, record)['fields']])
        self.assertNotIn('Changed body', json.dumps(record))

    def test_lost_second_patch_observes_all_fields_without_upgrading_original_receipt(self):
        def lose(method, path, body, response):
            if method == 'PATCH' and 'body' in body: raise TimeoutError()
        self.fixture.after = lose
        route, record = self.execute(['issue', 'edit', '1', '--title', 'Changed', '--body', 'Changed body'])
        self.assertEqual('UNKNOWN_OUTCOME', record['result']['status'])
        self.assertEqual(['title'], record['result']['confirmed_fields'])
        self.assertEqual('MATCHED', self.reconcile(route, record)['status'])
        self.assertEqual(['title'], record['result']['confirmed_fields'])

    def test_scalar_preimage_hashes_make_absence_distinct_from_external_edit(self):
        route, record = self.execute(['issue', 'edit', '1', '--title', 'Changed'], fail_field='title')
        self.assertEqual('ABSENT', self.reconcile(route, record)['status'])
        self.fixture.issues[1]['title'] = 'External title'
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])
        record['steps'][0]['intent'] = None
        self.fixture.issues[1]['title'] = 'Before'
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])

    def test_state_reason_pull_base_assignments_labels_and_dependencies(self):
        cases = [['issue', 'close', '1', '--reason', 'not-planned'], ['issue', 'reopen', '1'],
                 ['pr', 'edit', '3', '--base', 'release'], ['issue', 'edit', '1', '--add-assignee', '@me'],
                 ['issue', 'edit', '1', '--remove-assignee', '@me'],
                 ['pr', 'edit', '3', '--add-label', 'bug,feature', '--remove-label', 'docs'],
                 ['issue', 'dependency', 'add', '1', '--blocked-by', '2'],
                 ['issue', 'dependency', 'remove', '1', '--blocked-by', '2']]
        for argv in cases:
            with self.subTest(argv=argv):
                route, record = self.execute(argv)
                self.assertEqual('MATCHED', self.reconcile(route, record)['status'])
        self.assertEqual([], self.fixture.pulls[3]['assignees'])

    def test_assignment_external_conflict_stays_visible_no_overwrite(self):
        route, record = self.execute(['issue', 'edit', '1', '--add-assignee', '@me'], lost=True)
        self.fixture.issues[1]['assignees'].append({'id': 88, 'login': 'external'})
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])
        self.assertEqual([41, 88], [v['id'] for v in self.fixture.issues[1]['assignees']])
        self.fixture.issues[1]['assignees'] = [{'id': 88, 'login': 'external'}]
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])

    def test_duplicate_markers_conflict_and_never_become_success(self):
        route, record = self.execute(['issue', 'comment', '1', '--body', 'Note'], lost=True)
        duplicate = deepcopy(self.fixture.comments[1][0]); duplicate['id'] += 1
        self.fixture.comments[1].append(duplicate)
        observed = self.reconcile(route, record)
        self.assertEqual('CONFLICT', observed['status'])
        self.assertEqual(3, len(observed['objects']))  # Target plus both candidates.
        route, record = self.execute(['issue', 'create', '--title', 'Created', '--body', 'Body'], lost=True)
        duplicate = deepcopy(self.fixture.issues[4]); duplicate.update(id=105, number=5, html_url=self.fixture.web + '/issues/5')
        self.fixture.issues[5] = duplicate
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])

    def test_marker_removal_does_not_turn_executed_create_or_comment_into_absence(self):
        for argv in (['issue', 'create', '--title', 'Created', '--body', 'Body'],
                     ['issue', 'comment', '1', '--body', 'Body']):
            with self.subTest(argv=argv):
                self.setUp(); route, record = self.execute(argv, lost=True)
                value = self.fixture.issues[4] if route.kind.endswith('-create') else self.fixture.comments[1][0]
                value['body'] = 'External rewritten body with no marker'
                self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])
                self.assertEqual(1, len(self.fixture.effects))

    def test_missing_precontact_identity_set_cannot_prove_marker_absence(self):
        route, record = self.execute(['issue', 'comment', '1', '--body', 'Body'], lost=True)
        record['steps'][0]['intent']['preimage_digest'] = None
        self.fixture.comments[1] = []
        self.assertEqual('UNKNOWN', self.reconcile(route, record)['status'])

    def test_legacy_unknown_create_or_comment_does_not_assert_absence(self):
        for argv in (['issue', 'create', '--title', 'Created', '--body', 'Body'], ['issue', 'comment', '1', '--body', 'Note']):
            with self.subTest(argv=argv):
                self.setUp(); route, record = self.execute(argv, marker=None, lost=True)
                for step in record['steps']: step['intent'] = None
                outcome = self.reconcile(route, record, marker=None)
                self.assertEqual('UNKNOWN', outcome['status'])
                self.assertEqual('LEGACY_MARKER_UNAVAILABLE', outcome['error_code'])

    def test_known_legacy_object_reconciles_by_identity_without_marker(self):
        route, record = self.execute(['issue', 'comment', '1', '--body', 'Note'], marker=None)
        for step in record['steps']: step['intent'] = None
        self.assertEqual('MATCHED', self.reconcile(route, record, marker=None)['status'])

    def test_absence_requires_complete_pagination_and_each_page_success(self):
        route, record = self.execute(['issue', 'comment', '1', '--body', 'Note'], lost=True)
        self.fixture.comments[1] = []
        self.assertEqual('ABSENT', self.reconcile(route, record)['status'])
        path = self.fixture.base + '/issues/1/comments'
        values = [{'id': n, 'body': 'other', 'issue_url': self.fixture.api + '/issues/1', 'user': {'id': 88}} for n in range(1, 101)]
        self.fixture.custom_pages[path, 1] = self.fixture.response(values)
        self.fixture.custom_pages[path, 2] = self.fixture.response({})
        self.assertEqual('UNKNOWN', self.reconcile(route, record)['status'])
        self.fixture.custom_pages[path, 2] = self.fixture.response([])
        # A new immutable child could have had our marker removed; presence
        # without a marker is not proof that the write never happened.
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])
        self.fixture.custom_pages[path, 1] = ProviderResponse(200, b'[]', {'Link': '<https://evil.invalid/>; rel="next"'})
        limited = GitHubReconciliationProvider(self.project, self.fixture, max_pages=1)
        self.assertEqual('PAGINATION_LIMIT', self.reconcile(route, record, reconciler=limited)['error_code'])

    def test_target_hidden_permissions_rate_limits_and_bad_responses_stay_unknown(self):
        route, record = self.execute(['issue', 'edit', '1', '--title', 'Changed'], lost=True)
        for status in (403, 404, 429, 500):
            with self.subTest(status=status):
                self.fixture.before = lambda method, path, body: self.fixture.response({}, status) if path.endswith('/issues/1') else None
                result = self.reconcile(route, record)
                self.assertEqual('UNKNOWN', result['status'])
        self.fixture.before = lambda *_: ProviderResponse(200, b'{"id":41,"id":42}', {})
        self.assertEqual('INVALID_RESPONSE', self.reconcile(route, record)['error_code'])
        self.fixture.before = None
        limited = GitHubReconciliationProvider(self.project, self.fixture, max_bytes=1)
        self.assertEqual('OUTPUT_LIMIT', self.reconcile(route, record, reconciler=limited)['error_code'])

    def test_immutable_identity_mismatch_is_conflict_not_success(self):
        route, record = self.execute(['issue', 'edit', '1', '--title', 'Changed'], lost=True)
        self.fixture.issues[1]['id'] = 999
        self.assertEqual('CONFLICT', self.reconcile(route, record)['status'])
        self.assertEqual('IDENTITY_CONFLICT', self.reconcile(route, record)['error_code'])

    def test_every_read_checks_fresh_authority(self):
        route, record = self.execute(['issue', 'comment', '1', '--body', 'Note'], lost=True)
        calls = []
        def authorize():
            calls.append(1)
            return len(calls) < 3
        count = len(self.fixture.calls)
        with self.assertRaises(LedgerError) as caught: self.reconcile(route, record, authorize=authorize)
        self.assertEqual('FORBIDDEN', caught.exception.code)
        self.assertEqual(2, len(self.fixture.calls) - count)

    def test_marker_spoof_is_rejected_before_any_contact(self):
        for argv in (['issue', 'create', '--title', 'X', '--body', MARKER],
                     ['issue', 'edit', '1', '--body', MARKER]):
            before = len(self.fixture.calls)
            with self.assertRaises(LedgerError): self.execute(argv)
            self.assertEqual(before, len(self.fixture.calls))

    def test_full_caller_body_keeps_quota_and_transport_allows_only_marker_overhead(self):
        body = marked_body('x' * MAX_BODY, MARKER)
        self.assertEqual(MAX_BODY + MARKER_OVERHEAD, len(body.encode()))
        transport = object.__new__(GhSurfaceTransport)
        transport._execute = lambda method, path, payload, accept: len(payload)
        self.assertGreater(transport.mutate('POST', self.fixture.base + '/issues/1/comments', {'body': body}, repository='owner/repo'), MAX_BODY)
        from uas.github_read import ProviderFailure
        for invalid in ('x' * (MAX_BODY + 1), body + 'x', marked_body('x' * (MAX_BODY + 1), MARKER)):
            with self.assertRaises(ProviderFailure):
                transport.mutate('POST', self.fixture.base + '/issues/1/comments', {'body': invalid}, repository='owner/repo')

    def test_intents_are_metadata_only_and_label_item_indices_are_stable(self):
        route, record = self.execute(['issue', 'edit', '1', '--body', 'PRIVATE BODY', '--add-label', 'bug,feature'])
        self.assertEqual([None, 0, 1], [step['intent']['item_index'] for step in record['steps']])
        self.assertEqual(preimage_digest('Before body'), record['steps'][0]['intent']['preimage_digest'])
        self.assertNotIn('PRIVATE BODY', json.dumps(record))
        self.assertEqual(planned_fields(route), [{k: field[k] for k in ('field', 'item_index')} for field in self.reconcile(route, record)['fields']])


if __name__ == '__main__': unittest.main()
