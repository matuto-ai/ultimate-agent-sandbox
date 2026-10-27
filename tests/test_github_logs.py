"""Pure completed-log policy/framing fixtures: no network or native process."""
import base64
from copy import deepcopy
import hashlib
import http.client
import json
import unittest
from unittest.mock import patch

from uas.github_logs import (CompletedJobLogProvider, GitHubJobLogTransport, LogStream,
                             LogFailure, storage_location, CHUNK, MAX_TAIL, validate_log_observation, metadata_summary)
from uas.github_read import GitHubProject, ProviderResponse, ProviderFailure
from uas.ledger import LedgerError

REPO = 'owner/project'
BASE = f'https://api.github.com/repos/{REPO}'
HEAD, TESTED, BASE_SHA = 'a' * 40, 'b' * 40, 'c' * 40
RUN, JOB, ATTEMPT = 42, 73, 2
LOCATION = 'https://productionresultssa30.blob.core.windows.net/logs/73.txt?sig=SECRET_SIGNED_URL'


def run(**changes):
    return {'id': RUN, 'run_attempt': ATTEMPT, 'head_sha': HEAD,
            'url': BASE + f'/actions/runs/{RUN}', 'status': 'completed', 'conclusion': 'success',
            'repository': {'id': 10, 'full_name': REPO, 'url': BASE}, 'pull_requests': [], **changes}


def job(number=JOB, **changes):
    return {'id': number, 'run_id': RUN, 'run_url': BASE + f'/actions/runs/{RUN}',
            'url': BASE + f'/actions/jobs/{number}', 'head_sha': HEAD,
            'status': 'completed', 'conclusion': 'failure', **changes}


def pull(**changes):
    return {'id': 31, 'number': 7, 'url': BASE + '/pulls/7',
            'html_url': 'https://github.com/' + REPO + '/pull/7',
            'state': 'open', 'draft': False, 'merged': False,
            'merge_commit_sha': TESTED, 'user': {'id': 5, 'login': 'human'},
            'head': {'sha': HEAD, 'ref': 'work', 'repo': {'id': 10, 'full_name': REPO}},
            'base': {'sha': BASE_SHA, 'ref': 'main', 'repo': {'id': 10, 'full_name': REPO}}, **changes}


def response(value, status=200, headers=None):
    return ProviderResponse(status, json.dumps(value).encode(), headers or {})


def log_stream(data=b'line one\nline two\n', *, headers=None, status=200, complete=True, error=None):
    result = LogStream(status, headers if headers is not None else {
        'Content-Length': str(len(data)), 'Content-Type': 'text/plain'}, None)
    def chunks():
        for offset in range(0, len(data), CHUNK):
            yield data[offset:offset + CHUNK]
        if error:
            raise error
        result.complete = complete
    result.chunks = chunks()
    return result


class CompletedLogTests(unittest.TestCase):
    def setUp(self):
        self.calls, self.log_calls, self.streams = [], [], []
        self.run, self.job = run(), job()
        self.page = {'total_count': 1, 'jobs': [self.job]}
        self.extra = {}
        self.stream = log_stream()

    def transport(self, path):
        self.calls.append(path)
        if path in self.extra:
            value = self.extra[path]
            if isinstance(value, Exception):
                raise value
            return value
        if path.endswith(f'/actions/runs/{RUN}/attempts/{ATTEMPT}'):
            return response(self.run)
        if path.endswith(f'/actions/jobs/{JOB}'):
            return response(self.job)
        if path.endswith('/jobs?per_page=100&page=1'):
            return response(self.page)
        raise AssertionError('Unexpected metadata path: ' + path)

    def logs(self, path):
        self.log_calls.append(path)
        return self.stream

    def provider(self, **kwargs):
        return CompletedJobLogProvider(GitHubProject(REPO), self.transport, self.logs, **kwargs)

    def read(self, **kwargs):
        return self.provider(**kwargs).read(RUN, JOB, ATTEMPT, HEAD)

    def denied_before_logs(self, code=None):
        result = self.read()
        self.assertNotEqual('OK', result['status'])
        if code:
            self.assertEqual(code, result['status'])
        self.assertEqual('unknown', result['completeness'])
        self.assertEqual([], self.log_calls)
        self.assertNotIn('tail', result)
        self.assertNotIn('dropped_bytes', result)
        return result

    def test_exact_completed_job_returns_tail_and_exact_dropped_bytes(self):
        data = b'prefix\x00\xff' + b'x' * 80 + b'last ten!!'
        self.stream = log_stream(data)
        result = self.read(tail_bytes=10)
        self.assertEqual('OK', result['status'])
        self.assertEqual(b'last ten!!', base64.b64decode(result['tail']))
        self.assertEqual(len(data), result['total_bytes'])
        self.assertEqual(len(data) - 10, result['dropped_bytes'])
        self.assertEqual(hashlib.sha256(data).hexdigest(), result['sha256'])
        self.assertEqual('failure', result['job_conclusion'])
        self.assertEqual(HEAD, result['tested_sha'])
        self.assertEqual([f'repos/{REPO}/actions/jobs/{JOB}/logs'], self.log_calls)
        self.assertEqual(5, len(self.calls))
        self.assertNotIn('SECRET_SIGNED_URL', json.dumps(result))

    def test_independent_result_validator_and_metadata_only_summary(self):
        valid = self.read()
        self.assertEqual(valid, validate_log_observation(valid, GitHubProject(REPO), RUN, JOB, ATTEMPT, HEAD))
        summary = metadata_summary(valid)
        self.assertNotIn('tail', summary)
        self.assertEqual(valid['total_bytes'], summary['returned_bytes'])
        for changes in ({'tail': 'invalid!'}, {'total_bytes': True}, {'total_bytes': 999},
                        {'dropped_bytes': 1}, {'sha256': 'f' * 64}, {'repository': 'other/repo'},
                        {'tested_sha': TESTED}, {'signed_url': LOCATION}, {'job_id': JOB + 1},
                        {'completeness': 'unknown'}, {'base_sha': BASE_SHA}):
            with self.subTest(changes=changes), self.assertRaises(LedgerError):
                validate_log_observation({**valid, **changes}, GitHubProject(REPO), RUN, JOB, ATTEMPT, HEAD)
        failed = {k: v for k, v in valid.items() if k in {
            'status', 'completeness', 'repository', 'run_id', 'job_id', 'attempt', 'head_sha'}}
        failed.update(status='LOG_TRANSFER_INCOMPLETE', completeness='unknown')
        self.assertEqual(failed, validate_log_observation(failed, GitHubProject(REPO), RUN, JOB, ATTEMPT, HEAD))
        self.assertIsNone(metadata_summary(failed)['dropped_bytes'])
        with self.assertRaises(LedgerError):
            validate_log_observation({**failed, 'dropped_bytes': 0}, GitHubProject(REPO), RUN, JOB, ATTEMPT, HEAD)

    def test_timeout_after_stream_creation_still_closes_the_owned_connection(self):
        closed = []
        self.stream.close = lambda: closed.append(True)
        times = [0] * 8 + [31]
        with patch('uas.github_logs.time.monotonic', side_effect=times):
            result = self.read()
        self.assertEqual('TIMEOUT', result['status'])
        self.assertEqual([True], closed)

    def test_default_output_is_bounded_even_for_large_complete_log(self):
        self.stream = log_stream(b'x' * (MAX_TAIL + CHUNK))
        result = self.read()
        self.assertEqual(MAX_TAIL, len(base64.b64decode(result['tail'])))
        self.assertEqual(CHUNK, result['dropped_bytes'])
        self.assertLess(len(json.dumps(result).encode()), 1_048_576)

    def test_empty_complete_log_and_chunked_http_framing(self):
        self.stream = log_stream(b'', headers={'Transfer-Encoding': 'chunked'})
        result = self.read()
        self.assertEqual(('OK', '', 0, 0), (result['status'], result['tail'],
                                             result['total_bytes'], result['dropped_bytes']))

    def test_invalid_request_never_contacts_provider(self):
        for args, kwargs in (((True, JOB, ATTEMPT, HEAD), {}),
                             ((RUN, JOB, 0, HEAD), {}), ((RUN, JOB, ATTEMPT, 'main'), {}),
                             ((RUN, JOB, ATTEMPT, HEAD), {'base_sha': BASE_SHA}),
                             ((RUN, JOB, ATTEMPT, HEAD), {'base_sha': BASE_SHA, 'pull_number': False})):
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(LedgerError):
                self.provider().read(*args, **kwargs)
        self.assertEqual([], self.calls)

    def test_run_identity_repository_attempt_and_head_mismatch_denied(self):
        changes = ({'id': RUN + 1}, {'id': True}, {'run_attempt': ATTEMPT + 1},
                   {'head_sha': TESTED}, {'url': BASE + '/actions/runs/999'},
                   {'repository': {'id': 11, 'full_name': 'other/repo', 'url': BASE}},
                   {'repository': {'id': False, 'full_name': REPO, 'url': BASE}})
        for change in changes:
            with self.subTest(change=change):
                self.run = run(**change)
                self.denied_before_logs()

    def test_run_and_job_must_be_completed_with_literal_conclusions(self):
        for target, change in [('run', {'status': 'in_progress'}), ('run', {'conclusion': None}),
                               ('job', {'status': 'queued'}), ('job', {'conclusion': 'pending'}),
                               ('job', {'conclusion': 'future-new-value'})]:
            self.run, self.job = run(), job()
            getattr(self, target).update(change)
            with self.subTest(target=target, change=change):
                self.denied_before_logs('LOG_NOT_COMPLETED')

    def test_exact_job_identity_and_repository_url_required(self):
        for change in ({'id': JOB + 1}, {'run_id': RUN + 1}, {'head_sha': TESTED},
                       {'run_url': BASE + '/actions/runs/99'},
                       {'url': 'https://api.github.com/repos/other/repo/actions/jobs/73'}):
            self.job = job(**change)
            with self.subTest(change=change):
                self.denied_before_logs('INVALID_LOG_METADATA')

    def test_attempt_membership_not_assumed_from_run_id(self):
        self.page = {'total_count': 1, 'jobs': [job(JOB + 1)]}
        self.denied_before_logs('LOG_ATTEMPT_UNVERIFIED')
        self.page = {'total_count': 2, 'jobs': [job()]}
        self.denied_before_logs('LOG_ATTEMPT_UNVERIFIED')
        self.page = {'total_count': 1, 'jobs': [job(conclusion='success')]}
        self.denied_before_logs('LOG_ATTEMPT_UNVERIFIED')

    def test_full_pages_require_terminal_page_and_unique_job_ids(self):
        self.page = {'total_count': 100, 'jobs': [job(n) for n in range(1, 101)]}
        second = f'repos/{REPO}/actions/runs/{RUN}/attempts/{ATTEMPT}/jobs?per_page=100&page=2'
        self.extra[second] = response({'total_count': 100, 'jobs': []})
        self.assertEqual('OK', self.read()['status'])
        self.assertIn(second, self.calls)
        self.log_calls.clear()
        self.extra[second] = response({'total_count': 100, 'jobs': [job()]})
        self.denied_before_logs('INVALID_LOG_METADATA')

    def test_pagination_caps_failed_pages_and_next_link_are_not_membership(self):
        self.page = {'total_count': 100, 'jobs': [job(n) for n in range(1, 101)]}
        self.assertEqual('LOG_ATTEMPT_UNVERIFIED', self.read(max_pages=1)['status'])
        self.assertEqual([], self.log_calls)
        first = f'repos/{REPO}/actions/runs/{RUN}/attempts/{ATTEMPT}/jobs?per_page=100&page=1'
        self.extra[first] = response({'total_count': 1, 'jobs': [job()]}, headers={
            'Link': '<https://evil.invalid/secret>; rel="next"'})
        self.assertNotEqual('OK', self.read()['status'])
        self.assertTrue(all('evil.invalid' not in p for p in self.calls))
        self.assertEqual([], self.log_calls)

    def test_metadata_failures_do_not_escape_raw_messages_or_claim_absence(self):
        path = f'repos/{REPO}/actions/runs/{RUN}/attempts/{ATTEMPT}'
        for value in (response({'error': 'SECRET_TOKEN'}, 403), response({}, 404),
                      ProviderResponse(200, b'{"id":1,"id":2}', {}),
                      RuntimeError(LOCATION), ProviderFailure('TIMEOUT')):
            self.extra[path] = value
            result = self.denied_before_logs()
            self.assertNotIn('SECRET', json.dumps(result))
            self.assertNotIn('https:', json.dumps(result))

    def test_test_merge_requires_fresh_exact_head_base_and_run_association(self):
        self.run = run(head_sha=TESTED, pull_requests=[{'id': 31, 'number': 7,
            'url': BASE + '/pulls/7', 'head': {'sha': HEAD}, 'base': {'sha': BASE_SHA}}])
        self.job = job(head_sha=TESTED)
        self.page = {'total_count': 1, 'jobs': [self.job]}
        self.extra[f'repos/{REPO}/pulls/7'] = response(pull())
        result = self.provider().read(RUN, JOB, ATTEMPT, HEAD, base_sha=BASE_SHA, pull_number=7)
        self.assertEqual('OK', result['status'])
        self.assertEqual((HEAD, TESTED, BASE_SHA), (result['head_sha'], result['tested_sha'], result['base_sha']))
        for change in ({'merge_commit_sha': 'd' * 40}, {'merged': True, 'state': 'closed'},
                       {'head': {'sha': 'e' * 40, 'ref': 'work', 'repo': {'id': 10, 'full_name': REPO}}}):
            self.log_calls.clear()
            self.extra[f'repos/{REPO}/pulls/7'] = response(pull(**change))
            failed = self.provider().read(RUN, JOB, ATTEMPT, HEAD, base_sha=BASE_SHA, pull_number=7)
            self.assertEqual('LOG_CANDIDATE_MISMATCH', failed['status'])
            self.assertEqual([], self.log_calls)

    def test_missing_duplicate_or_wrong_run_pr_association_is_not_proof(self):
        association = {'id': 31, 'number': 7, 'url': BASE + '/pulls/7',
                       'head': {'sha': HEAD}, 'base': {'sha': BASE_SHA}}
        self.job = job(head_sha=TESTED)
        self.page = {'total_count': 1, 'jobs': [self.job]}
        self.extra[f'repos/{REPO}/pulls/7'] = response(pull())
        for associations in ([], [association, association], [{**association, 'number': 8}]):
            self.run = run(head_sha=TESTED, pull_requests=associations)
            result = self.provider().read(RUN, JOB, ATTEMPT, HEAD, base_sha=BASE_SHA, pull_number=7)
            self.assertEqual('LOG_CANDIDATE_MISMATCH', result['status'])
            self.assertEqual([], self.log_calls)

    def test_drift_during_download_discards_content(self):
        def logs(path):
            self.run['conclusion'] = 'failure'
            return log_stream(b'PRIVATE_LOG')
        provider = CompletedJobLogProvider(GitHubProject(REPO), self.transport, logs)
        result = provider.read(RUN, JOB, ATTEMPT, HEAD)
        self.assertEqual('INVALID_LOG_METADATA', result['status'])
        self.assertNotIn('tail', result)
        self.assertNotIn('dropped_bytes', result)

    def test_short_long_incomplete_and_failed_transfers_never_claim_counts(self):
        streams = [log_stream(b'abc', headers={'content-length': '4'}),
                   log_stream(b'abc', headers={'content-length': '2'}),
                   log_stream(b'abc', complete=False),
                   log_stream(b'abc', error=http.client.IncompleteRead(b'abc', 4)),
                   log_stream(b'abc', error=RuntimeError(LOCATION))]
        for stream in streams:
            self.stream = stream
            with self.subTest(stream=stream):
                result = self.read()
                self.assertNotEqual('OK', result['status'])
                self.assertNotIn('tail', result)
                self.assertNotIn('dropped_bytes', result)
                self.assertNotIn('SECRET', json.dumps(result))

    def test_ambiguous_compressed_partial_archive_and_redirect_responses_rejected(self):
        headers = [{}, {'content-length': '03'}, {'content-length': '-1'},
                   {'content-length': '3', 'Content-Length': '3'},
                   {'content-length': '3', 'transfer-encoding': 'chunked'},
                   {'content-length': '3', 'content-encoding': 'gzip'},
                   {'content-length': '3', 'content-type': 'application/zip'},
                   {'transfer-encoding': 'garbage'}]
        for value in headers:
            self.stream = log_stream(b'abc', headers=value)
            with self.subTest(headers=value):
                self.assertEqual('LOG_TRANSFER_INCOMPLETE', self.read()['status'])
        for code in (206, 302, 404):
            self.stream = log_stream(b'abc', status=code)
            self.assertEqual('LOG_TRANSFER_INCOMPLETE', self.read()['status'])

    def test_transfer_budget_chunk_bounds_and_deadline(self):
        self.stream = log_stream(b'x' * 11)
        self.assertEqual('OUTPUT_LIMIT', self.read(tail_bytes=5, max_transfer=10)['status'])
        self.stream = LogStream(200, {'content-length': '1'}, iter([b'']), complete=True)
        self.assertEqual('LOG_TRANSFER_INCOMPLETE', self.read()['status'])
        self.stream = LogStream(200, {'content-length': str(CHUNK + 1)}, iter([b'x' * (CHUNK + 1)]), complete=True)
        self.assertEqual('LOG_TRANSFER_INCOMPLETE', self.read()['status'])
        with patch('uas.github_logs.time.monotonic', side_effect=[0, 31]):
            self.assertEqual('TIMEOUT', self.read()['status'])


class FakeResponse:
    def __init__(self, status, headers, data=b''):
        self.status, self.headers, self.data = status, headers, data
    def getheaders(self):
        return list(self.headers.items()) if type(self.headers) is dict else self.headers
    def read1(self, maximum):
        data, self.data = self.data[:maximum], self.data[maximum:]
        return data


class FakeConnection:
    def __init__(self, response):
        self.response, self.requests, self.closed = response, [], 0
    def request(self, *args, **kwargs):
        self.requests.append((args, kwargs))
    def getresponse(self):
        return self.response
    def close(self):
        self.closed += 1


class LogTransportTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeConnection(FakeResponse(302, {'Location': LOCATION, 'Set-Cookie': 'SECRET_COOKIE'}))
        self.storage = FakeConnection(FakeResponse(200, {'Content-Length': '3'}, b'abc'))
        self.credentials = []
    def select(self, actor, host):
        self.credentials.append((actor, host))
        return {'GH_TOKEN': 'SECRET_TOKEN'}
    def transport(self):
        return GitHubJobLogTransport('actor-a', self.select)
    def path(self):
        return f'repos/{REPO}/actions/jobs/{JOB}/logs'

    def test_official_redirect_has_new_connection_and_no_inherited_auth_headers(self):
        with patch('uas.github_logs.http.client.HTTPSConnection', side_effect=[self.api, self.storage]) as connect:
            with self.transport()(self.path()) as stream:
                self.assertEqual([b'abc'], list(stream.chunks))
                self.assertTrue(stream.complete)
        self.assertEqual([('actor-a', 'github.com')], self.credentials)
        self.assertEqual('api.github.com', connect.call_args_list[0].args[0])
        self.assertEqual('productionresultssa30.blob.core.windows.net', connect.call_args_list[1].args[0])
        self.assertEqual('Bearer SECRET_TOKEN', self.api.requests[0][1]['headers']['Authorization'])
        headers = self.storage.requests[0][1]['headers']
        self.assertEqual({'Accept', 'Accept-Encoding', 'User-Agent'}, set(headers))
        self.assertNotIn('SECRET', json.dumps(headers))
        self.assertEqual(1, self.api.closed)
        self.assertEqual(1, self.storage.closed)
        self.assertNotIn('location', stream.headers)

    def test_untrusted_hosts_userinfo_ports_fragments_encoding_and_schemes_denied(self):
        urls = ['http://productionresultssa30.blob.core.windows.net/x',
                'https://productionresultssa30.blob.core.windows.net.evil.invalid/x',
                'https://evilproductionresultssa30.blob.core.windows.net/x',
                'https://productionresultssa30.blob.core.windows.net@evil.invalid/x',
                'https://u:p@productionresultssa30.blob.core.windows.net/x',
                'https://productionresultssa30.blob.core.windows.net:444/x',
                'https://productionresultssa30.blob.core.windows.net./x',
                'https://PRODUCTIONRESULTSSA30.blob.core.windows.net/x',
                'https://productionresultssa30.blob.core.windows.net/x#secret',
                'https://productionresultssa30.blob.core.windows.net/x#',
                'https://127.0.0.1/x', 'https://[::1]/x',
                'https://productionresultssa30.blob.core.windows.net/x\r\nX:bad',
                'file:///etc/passwd', 'https://storage.blob.core.windows.net/x']
        for url in urls:
            with self.subTest(url=url), self.assertRaises(LogFailure):
                storage_location(url)
        self.assertEqual(('productionresultssa199.blob.core.windows.net', '/logs/a?sig=x'),
                         storage_location('https://productionresultssa199.blob.core.windows.net:443/logs/a?sig=x'))

    def test_denied_redirect_does_not_connect_to_storage(self):
        self.api.response.headers = {'Location': 'https://127.0.0.1/secret'}
        with patch('uas.github_logs.http.client.HTTPSConnection', return_value=self.api) as connect:
            with self.assertRaises(LogFailure) as raised:
                self.transport()(self.path())
        self.assertEqual('LOG_REDIRECT_DENIED', raised.exception.code)
        self.assertEqual(1, connect.call_count)
        self.assertEqual(1, self.api.closed)

    def test_storage_redirect_is_returned_without_following_and_rejected_by_consumer(self):
        self.storage.response = FakeResponse(302, {'Location': 'https://evil.invalid/x'})
        with patch('uas.github_logs.http.client.HTTPSConnection', side_effect=[self.api, self.storage]) as connect:
            with self.transport()(self.path()) as stream:
                self.assertEqual(302, stream.status)
        self.assertEqual(2, connect.call_count)

    def test_only_exact_job_log_paths_and_exact_actor_credentials_are_accepted(self):
        invalid = ['repos/owner/project/actions/runs/42/logs', 'https://api.github.com/' + self.path(),
                   self.path() + '?host=evil.invalid', 'repos/owner/project/actions/artifacts/1/zip',
                   'repos/owner/project/actions/jobs/73/steps/1/logs']
        with patch('uas.github_logs.http.client.HTTPSConnection') as connect:
            for path in invalid:
                with self.subTest(path=path), self.assertRaises(LogFailure):
                    self.transport()(path)
            for secret in ({}, {'GH_TOKEN': 'x', 'COOKIE': 'x'}, {'GH_TOKEN': 'bad\r\nheader'}):
                with self.assertRaises(LogFailure):
                    GitHubJobLogTransport('actor-a', lambda *_, secret=secret: secret)(self.path())
            connect.assert_not_called()
        self.assertEqual([], self.credentials)

    def test_transport_exceptions_never_disclose_credential_or_signed_url(self):
        def unavailable(*_):
            raise RuntimeError('SECRET_TOKEN')
        with self.assertRaises(LogFailure) as raised:
            GitHubJobLogTransport('actor-a', unavailable)(self.path())
        self.assertEqual('CREDENTIAL_UNAVAILABLE', str(raised.exception))
        for error, expected in ((OSError(LOCATION), 'PROVIDER_FAILURE'),
                                (TimeoutError(LOCATION), 'TIMEOUT')):
            with patch('uas.github_logs.http.client.HTTPSConnection', side_effect=[self.api, error]):
                with self.assertRaises(LogFailure) as raised:
                    self.transport()(self.path())
            self.assertEqual(expected, str(raised.exception))

    def test_api_error_and_duplicate_location_fail_closed_and_close(self):
        for reply in (FakeResponse(200, {'Location': LOCATION}), FakeResponse(403, {}),
                      FakeResponse(302, [('Location', LOCATION), ('location', LOCATION)])):
            self.api = FakeConnection(reply)
            with patch('uas.github_logs.http.client.HTTPSConnection', return_value=self.api) as connect:
                with self.assertRaises(LogFailure):
                    self.transport()(self.path())
            self.assertEqual(1, connect.call_count)
            self.assertEqual(1, self.api.closed)


if __name__ == '__main__':
    unittest.main()
