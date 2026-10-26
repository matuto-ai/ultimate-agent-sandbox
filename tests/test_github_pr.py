"""Controlled PR/review REST observations, never live account or Gate proof."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from uas.github_pr import GitHubPullProvider, validate_pull_observation
from uas.github_read import GitHubProject, ProviderResponse, ProviderFailure
from uas.ledger import LedgerError


def pull(number=42, repository='owner/project', **changes):
    api = 'https://api.github.com/repos/' + repository
    branch = {'ref': 'main', 'sha': 'a' * 40, 'repo': {'id': 900, 'full_name': repository}}
    return {'id': 1000 + number, 'number': number, 'url': f'{api}/pulls/{number}',
            'html_url': f'https://github.com/{repository}/pull/{number}',
            'state': 'open', 'draft': False, 'merged': False,
            'user': {'id': 7, 'login': 'builder', 'email': 'SECRET_EMAIL'},
            'base': branch, 'head': {**deepcopy(branch), 'ref': 'feature', 'sha': 'b' * 40},
            'merge_commit_sha': 'c' * 40, 'body': 'SECRET_BODY', 'title': 'SECRET_TITLE', **changes}


def review(identifier=80, number=42, repository='owner/project', **changes):
    return {'id': identifier,
            'html_url': f'https://github.com/{repository}/pull/{number}#pullrequestreview-{identifier}',
            'pull_request_url': f'https://api.github.com/repos/{repository}/pulls/{number}',
            'user': {'id': 8, 'login': 'reviewer', 'email': 'SECRET_EMAIL'},
            'state': 'APPROVED', 'submitted_at': '2026-10-26T12:00:00Z',
            'commit_id': 'b' * 40, 'body': 'SECRET_REVIEW_BODY', **changes}


def response(value, status=200, headers=None):
    return ProviderResponse(status, json.dumps(value).encode(), headers or {})


class PullProviderTests(unittest.TestCase):
    def setUp(self):
        self.project = GitHubProject('owner/project')
        self.calls = []

    def provider(self, responses, **options):
        def transport(path):
            self.calls.append(path)
            result = responses.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        return GitHubPullProvider(self.project, transport, **options)

    def read(self, responses=None, **options):
        value = self.provider(responses or [response(pull()), response([review()]), response(pull())], **options).read_pull(42)
        self.assertEqual(value, validate_pull_observation(value, self.project, 42))
        return value

    def test_exact_pull_and_reviews_are_sanitized_without_verdict(self):
        result = self.read()
        self.assertEqual('OK', result['status'])
        self.assertEqual('complete', result['completeness'])
        self.assertEqual('b' * 40, result['pull']['head']['sha'])
        self.assertEqual('a' * 40, result['pull']['base']['sha'])
        self.assertEqual('c' * 40, result['pull']['merge_commit_sha'])
        self.assertEqual('b' * 40, result['reviews'][0]['commit_id'])
        self.assertEqual(['repos/owner/project/pulls/42',
                          'repos/owner/project/pulls/42/reviews?per_page=100&page=1',
                          'repos/owner/project/pulls/42'], self.calls)
        for forbidden in ('SECRET', 'body', 'title', 'email', 'verdict', 'eligible', 'gate'):
            self.assertNotIn(forbidden, json.dumps(result))

    def test_repository_identity_contradictions_fail_raw_and_boundary(self):
        valid = self.read()
        for repo in ({'id': 901, 'full_name': 'owner/project'},
                     {'id': 901, 'full_name': 'OWNER/Project'},
                     {'id': 900, 'full_name': 'fork/project'}):
            with self.subTest(repo=repo):
                raw = pull()
                raw['head']['repo'] = repo
                result = self.read([response(raw)])
                self.assertEqual('INVALID_RESPONSE', result['status'])
                self.assertEqual('unknown', result['completeness'])
                malformed = deepcopy(valid)
                malformed['pull']['head']['repo'] = repo
                with self.assertRaisesRegex(LedgerError, 'INVALID_PROVIDER_OBSERVATION'):
                    validate_pull_observation(malformed, self.project, 42)

    def test_case_variation_preserves_same_repository_identity(self):
        raw = pull()
        raw['head']['repo']['full_name'] = 'OWNER/Project'
        result = self.read([response(raw), response([]), response(raw)])
        self.assertEqual('complete', result['completeness'])

    def test_empty_reviews_require_complete_page_and_closing_pull(self):
        result = self.read([response(pull()), response([]), response(pull())])
        self.assertEqual('complete', result['completeness'])
        self.assertEqual([], result['reviews'])
        self.assertEqual(1, result['pages'])
        self.assertEqual(3, len(self.calls))

    def test_pending_dismissed_and_old_commit_are_facts_not_success(self):
        values = [review(1, state='PENDING', submitted_at=None, commit_id=None),
                  review(2, state='DISMISSED'), review(3, state='CHANGES_REQUESTED', commit_id='d' * 40),
                  review(4, state='COMMENTED')]
        result = self.read([response(pull()), response(values), response(pull())])
        self.assertEqual([v['state'] for v in values], [r['state'] for r in result['reviews']])
        self.assertEqual('d' * 40, result['reviews'][2]['commit_id'])
        self.assertNotIn('verdict', result)

    def test_full_page_requires_next_bounded_page_not_link_following(self):
        result = self.read([response(pull()), response([review(i) for i in range(1,101)],
            headers={'link': '<https://attacker.invalid/secret>; rel="next"'}), response([]), response(pull())])
        self.assertEqual('complete', result['completeness'])
        self.assertEqual(2, result['pages'])
        self.assertEqual(100, len(result['reviews']))
        self.assertEqual('repos/owner/project/pulls/42/reviews?per_page=100&page=2', self.calls[2])
        self.assertTrue(all('attacker' not in p for p in self.calls))

    def test_pagination_cap_and_contradictory_short_page_are_incomplete(self):
        for values, headers in (([review(i) for i in range(1,101)], {}),
                                ([], {'Link': '<https://api.github.com/untrusted>; rel="next"'})):
            with self.subTest(count=len(values)):
                result = self.read([response(pull()), response(values, headers=headers)], max_pages=1)
                self.assertEqual('PAGINATION_LIMIT', result['status'])
                self.assertEqual('incomplete', result['completeness'])
        self.assertEqual(4, len(self.calls))

    def test_review_page_errors_never_prove_absence(self):
        for failed in (response({},403), response({},404), ProviderFailure('TIMEOUT'), RuntimeError('SECRET')):
            with self.subTest(failed=type(failed).__name__):
                result = self.read([response(pull()), failed])
                self.assertEqual('incomplete', result['completeness'])
                self.assertNotEqual('OK', result['status'])
                self.assertNotIn('SECRET', json.dumps(result))

    def test_first_404_is_unknown_not_absence(self):
        result = self.read([response({},404)])
        self.assertEqual('NOT_FOUND', result['status'])
        self.assertEqual('unknown', result['completeness'])
        self.assertEqual('not-found-or-inaccessible', result['reason'])
        self.assertIsNone(result['pull'])

    def test_closing_head_base_identity_or_state_drift_is_unknown(self):
        for field in ('head', 'base', 'id', 'draft', 'state', 'merge_commit_sha'):
            changed = pull()
            if field in {'head','base'}:
                changed[field]['sha'] = 'd' * 40
            else:
                changed[field] = {'id':9999,'draft':True,'state':'closed','merge_commit_sha':'d'*40}[field]
            with self.subTest(field=field):
                result = self.read([response(pull()), response([review()]), response(changed)])
                self.assertEqual('STALE_PULL', result['status'])
                self.assertEqual('unknown', result['completeness'])
                self.assertIsNone(result['pull'])
                self.assertEqual([],result['reviews'])

    def test_failed_closing_read_remains_incomplete(self):
        result=self.read([response(pull()),response([]),response({},403)])
        self.assertEqual('incomplete',result['completeness'])
        self.assertNotEqual('OK',result['status'])

    def test_cross_project_wrong_number_malformed_sha_and_pr_urls_fail(self):
        invalid = [pull(number=43),pull(url='https://attacker.invalid/42'),
                   pull(html_url='https://github.com/other/project/pull/42'),
                   pull(id=True),pull(draft=1),pull(merged=True)]
        foreign=pull();foreign['base']['repo']['full_name']='other/project';invalid.append(foreign)
        malformed=pull();malformed['head']['sha']='b'*39;invalid.append(malformed)
        for value in invalid:
            with self.subTest(value=value):
                result=self.read([response(value)])
                self.assertEqual('INVALID_RESPONSE',result['status'])
                self.assertIsNone(result['pull'])

    def test_fork_head_identity_is_observed_without_cross_repo_request(self):
        value=pull();value['head']['repo']={'id':901,'full_name':'fork/project'}
        result=self.read([response(value),response([]),response(value)])
        self.assertEqual('fork/project',result['pull']['head']['repo']['full_name'])
        self.assertTrue(all(p.startswith('repos/owner/project/') for p in self.calls))

    def test_malformed_review_id_url_author_date_or_commit_never_complete(self):
        variants=[review(id=True),review(html_url='https://attacker.invalid/review'),
                  review(pull_request_url='https://api.github.com/repos/other/project/pulls/42'),
                  review(user={'id':0,'login':'reviewer'}),review(state='FAKE'),
                  review(submitted_at='2026-02-30T12:00:00Z'),review(commit_id=None),
                  review(state='PENDING'),review(commit_id='c'*39)]
        for value in variants:
            with self.subTest(value=value):
                result=self.read([response(pull()),response([value])])
                self.assertEqual('INVALID_RESPONSE',result['status'])
                self.assertEqual('incomplete',result['completeness'])

    def test_duplicate_review_id_rejected(self):
        result=self.read([response(pull()),response([review(),review()])])
        self.assertEqual('INVALID_RESPONSE',result['status'])
        self.assertEqual('incomplete',result['completeness'])

    def test_total_bytes_and_sanitized_output_are_bounded(self):
        result=self.read([response(pull())],max_bytes=100)
        self.assertEqual('OUTPUT_LIMIT',result['status'])
        values=[review(i) for i in range(1,101)]
        result=self.read([response(pull()),response(values),response([review(i) for i in range(101,201)])])
        self.assertEqual('OUTPUT_LIMIT',result['status'])
        self.assertEqual('incomplete',result['completeness'])
        self.assertLess(len(json.dumps(result).encode()),48000)

    def test_duplicate_json_keys_are_rejected(self):
        result=self.read([ProviderResponse(200,b'{"id":1,"id":2}',{})])
        self.assertEqual('INVALID_RESPONSE',result['status'])

    def test_deadline_checked_after_transport(self):
        with patch('uas.github_pr.time.monotonic',side_effect=[0,0,31]):
            result=self.read([response(pull())])
        self.assertEqual('TIMEOUT',result['status'])
        self.assertIsNone(result['pull'])

    def test_independent_boundary_rejects_extra_raw_fields_and_identity_confusion(self):
        valid=self.read()
        changes=[]
        raw=deepcopy(valid);raw['pull']['body']='SECRET';changes.append(raw)
        raw=deepcopy(valid);raw['reviews'][0]['user']['email']='SECRET';changes.append(raw)
        raw=deepcopy(valid);raw['pull']['base']['repo']['full_name']='other/project';changes.append(raw)
        raw=deepcopy(valid);raw['reviews'].append(deepcopy(raw['reviews'][0]));changes.append(raw)
        raw=deepcopy(valid);raw['status']='STALE_PULL';changes.append(raw)
        raw=deepcopy(valid);raw['pages']=True;changes.append(raw)
        raw=deepcopy(valid);raw['verdict']='pass';changes.append(raw)
        raw=deepcopy(valid);raw['reviews']=[{**deepcopy(raw['reviews'][0]),'id':i,
            'html_url':f'https://github.com/owner/project/pull/42#pullrequestreview-{i}'} for i in range(1,101)];changes.append(raw)
        for value in changes:
            with self.subTest(value=value),self.assertRaisesRegex(LedgerError,'INVALID_PROVIDER_OBSERVATION'):
                validate_pull_observation(value,self.project,42)
        with self.assertRaises(LedgerError):validate_pull_observation(valid,self.project,43)

    def test_limits_and_number_validate_before_contact(self):
        for options in ({'max_pages':0},{'max_pages':True},{'max_bytes':1048577}):
            with self.assertRaises(LedgerError):self.provider([],**options)
        for number in (True,0,-1,10_000_000_000,'42'):
            with self.assertRaises(LedgerError):self.provider([]).read_pull(number)
        self.assertEqual([],self.calls)

    def test_missing_merge_fact_and_deleted_head_do_not_claim_complete(self):
        missing=pull();missing.pop('merge_commit_sha')
        deleted=pull();deleted['head']['repo']=None
        for value in (missing,deleted):
            with self.subTest(value=value):
                result=self.read([response(value)])
                self.assertEqual('INVALID_RESPONSE',result['status'])
                self.assertEqual('unknown',result['completeness'])
