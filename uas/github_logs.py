"""Completed, exact-attempt GitHub job logs at the external Broker boundary.

Only the authenticated GitHub API supplies a download location. Storage requests
have no Actor credential, cookie, proxy, redirect handler, or caller headers.
Returned content is user output, NEVER an audit event or Room projection.

Provider contracts checked against GitHub REST workflow jobs/runs documentation
and the 2026-10-22 Actions blob-storage announcement. No live-account claim.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import http.client
import json
import re
import ssl
import time
from urllib.parse import urlsplit

from .github_read import GitHubProject, ProviderResponse, ProviderFailure, API_VERSION, _positive, _unique
from .ledger import LedgerError

MAX_TAIL = 750_000  # Base64 + bounded metadata stays below the 1 MiB output cap.
MAX_TRANSFER = 64 * 1024 * 1024
CHUNK = 65536
_SHA = re.compile(r'[0-9a-f]{40}\Z')
_CONCLUSIONS = {'success', 'failure', 'neutral', 'cancelled', 'skipped', 'timed_out',
                'action_required', 'stale', 'startup_failure'}
_CODES = {'INVALID_LOG_METADATA', 'LOG_NOT_COMPLETED', 'LOG_ATTEMPT_UNVERIFIED',
          'LOG_CANDIDATE_MISMATCH', 'LOG_REDIRECT_DENIED', 'LOG_TRANSFER_INCOMPLETE',
          'OUTPUT_LIMIT', 'TIMEOUT', 'PROVIDER_FAILURE', 'NOT_FOUND', 'CREDENTIAL_UNAVAILABLE'}


class LogFailure(Exception):
    def __init__(self, code):
        self.code = code if code in _CODES else 'PROVIDER_FAILURE'
        super().__init__(self.code)


def _headers(values):
    """A duplicate framing/location header is ambiguity, never last-value-wins."""
    pairs = list(values.items()) if type(values) is dict else values
    result = {}
    for key, value in pairs:
        if type(key) is not str or type(value) is not str:
            raise LogFailure('LOG_TRANSFER_INCOMPLETE')
        key = key.lower()
        if key in result or any(c in value for c in '\r\n'):
            raise LogFailure('LOG_TRANSFER_INCOMPLETE')
        result[key] = value.strip()
    return result


def storage_location(url):
    """Accept only GitHub Actions' documented results-storage host family.

    The location itself must originate in the fixed authenticated job-log API.
    This function does not make a user-supplied URL into an authorized request.
    """
    try:
        if type(url) is not str or not 1 <= len(url) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in url):
            raise ValueError()
        parsed = urlsplit(url)
        host = parsed.hostname
        if (parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None
                or '#' in url or parsed.port not in (None, 443) or not parsed.path.startswith('/')
                or not host or parsed.netloc != host + (':443' if parsed.port == 443 else '')
                or not re.fullmatch(r'productionresultssa[0-9]+\.blob\.core\.windows\.net', host)):
            raise ValueError()
        return host, parsed.path + ('?' + parsed.query if parsed.query else '')
    except (ValueError, TypeError):
        raise LogFailure('LOG_REDIRECT_DENIED') from None


@dataclass
class LogStream:
    """Trusted HTTP framing adapter, not an untrusted Participant result.

    chunks must yield at most CHUNK bytes and set complete only after a verified
    terminal HTTP frame/EOF. Content-Length is independently checked by consumer.
    """
    status: int
    headers: dict
    chunks: object
    close: object = field(default=lambda: None, repr=False)
    complete: bool = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class GitHubJobLogTransport:
    """Fixed credentialed API GET followed by a separate credential-free GET.

    Deliberately not urllib/requests: ambient proxy, netrc, cookie jars and
    redirect authentication inheritance cannot alter this narrow transport.
    """
    def __init__(self, actor_id, credential_env, *, timeout=10):
        if (type(actor_id) is not str or not actor_id or not callable(credential_env)
                or type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise LedgerError('INVALID_LOG_TRANSPORT')
        self.actor_id, self.credentials, self.timeout = actor_id, credential_env, timeout

    def __call__(self, path):
        if (type(path) is not str or not re.fullmatch(
                r'repos/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/actions/jobs/[1-9][0-9]*/logs', path)):
            raise LogFailure('LOG_REDIRECT_DENIED')
        try:
            secret = self.credentials(self.actor_id, 'github.com')
        except Exception:
            raise LogFailure('CREDENTIAL_UNAVAILABLE') from None
        if (type(secret) is not dict or set(secret) != {'GH_TOKEN'}
                or type(secret['GH_TOKEN']) is not str or not secret['GH_TOKEN']
                or any(ord(c) < 33 or ord(c) > 126 for c in secret['GH_TOKEN'])):
            raise LogFailure('CREDENTIAL_UNAVAILABLE')
        connection = None
        try:
            connection = http.client.HTTPSConnection('api.github.com', timeout=self.timeout,
                                                     context=ssl.create_default_context())
            connection.request('GET', '/' + path, headers={
                'Authorization': 'Bearer ' + secret['GH_TOKEN'],
                'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': API_VERSION,
                'Accept-Encoding': 'identity', 'User-Agent': 'uas-github-read-broker'})
            response = connection.getresponse()
            headers = _headers(response.getheaders())
            if response.status != 302 or 'location' not in headers:
                raise LogFailure('NOT_FOUND' if response.status == 404 else 'PROVIDER_FAILURE')
            host, target = storage_location(headers['location'])
        except LogFailure:
            raise
        except TimeoutError:
            raise LogFailure('TIMEOUT') from None
        except (OSError, http.client.HTTPException, ValueError):
            raise LogFailure('PROVIDER_FAILURE') from None
        finally:
            if connection is not None:
                connection.close()
        connection = None
        try:
            # New connection and fixed fresh headers. No Authorization, cookies,
            # provider headers or redirect handler crosses this boundary.
            connection = http.client.HTTPSConnection(host, timeout=self.timeout,
                                                     context=ssl.create_default_context())
            connection.request('GET', target, headers={'Accept': 'text/plain',
                'Accept-Encoding': 'identity', 'User-Agent': 'uas-github-read-broker'})
            response = connection.getresponse()
            headers = _headers(response.getheaders())
            stream = LogStream(response.status, headers, None, close=connection.close)
            def chunks():
                try:
                    while True:
                        data = response.read1(CHUNK)
                        if not data:
                            stream.complete = True
                            return
                        yield data
                except TimeoutError:
                    raise LogFailure('TIMEOUT') from None
                except (OSError, http.client.HTTPException):
                    raise LogFailure('LOG_TRANSFER_INCOMPLETE') from None
            stream.chunks = chunks()
            return stream
        except (OSError, http.client.HTTPException, ValueError) as error:
            if connection is not None:
                connection.close()
            raise LogFailure('TIMEOUT' if isinstance(error, TimeoutError) else 'PROVIDER_FAILURE') from None
        except BaseException:
            if connection is not None:
                connection.close()
            raise


class CompletedJobLogProvider:
    """Pin Project/run/attempt/job/candidate before contacting the log route."""
    def __init__(self, project, metadata_transport, log_transport, *, max_pages=10,
                 tail_bytes=MAX_TAIL, max_transfer=MAX_TRANSFER, timeout=30):
        if (type(project) is not GitHubProject or not callable(metadata_transport)
                or not callable(log_transport) or type(max_pages) is not int or not 1 <= max_pages <= 10
                or type(tail_bytes) is not int or not 1 <= tail_bytes <= MAX_TAIL
                or type(max_transfer) is not int or not tail_bytes <= max_transfer <= MAX_TRANSFER
                or type(timeout) not in (int, float) or not 0 < timeout <= 30):
            raise LedgerError('INVALID_LOG_PROVIDER')
        self.project, self.metadata, self.logs = project, metadata_transport, log_transport
        self.max_pages, self.tail_bytes, self.max_transfer, self.timeout = max_pages, tail_bytes, max_transfer, timeout

    def read(self, run_id, job_id, attempt, head_sha, *, base_sha=None, pull_number=None):
        if (not all(_positive(v) for v in (run_id, job_id, attempt))
                or type(head_sha) is not str or not _SHA.fullmatch(head_sha)
                or (base_sha is None) != (pull_number is None)
                or (base_sha is not None and (type(base_sha) is not str or not _SHA.fullmatch(base_sha)
                                              or not _positive(pull_number)))):
            raise LedgerError('INVALID_LOG_REQUEST')
        result = {'status': 'PROVIDER_FAILURE', 'completeness': 'unknown',
                  'repository': self.project.repository, 'run_id': run_id, 'job_id': job_id,
                  'attempt': attempt, 'head_sha': head_sha}
        deadline, used = time.monotonic() + self.timeout, 0
        base = f'repos/{self.project.repository}'
        api = 'https://api.github.com/' + base
        def check_time():
            if time.monotonic() >= deadline:
                raise LogFailure('TIMEOUT')
        def get(path):
            nonlocal used
            check_time()
            response = self.metadata(path)
            check_time()
            if (type(response) is not ProviderResponse or type(response.status) is not int
                    or type(response.body) is not bytes or type(response.headers) is not dict):
                raise LogFailure('INVALID_LOG_METADATA')
            used += len(response.body)
            if used > 1_048_576:
                raise LogFailure('OUTPUT_LIMIT')
            if response.status != 200:
                raise LogFailure('NOT_FOUND' if response.status == 404 else 'PROVIDER_FAILURE')
            try:
                value = json.loads(response.body, object_pairs_hook=_unique)
            except (ValueError, UnicodeError, RecursionError):
                raise LogFailure('INVALID_LOG_METADATA') from None
            return value, _headers(response.headers)
        def run_view(value):
            repo = value.get('repository') if type(value) is dict else None
            if (type(value) is not dict or type(value.get('id')) is not int or value['id'] != run_id
                    or type(value.get('run_attempt')) is not int or value['run_attempt'] != attempt
                    or value.get('url') != api + f'/actions/runs/{run_id}'
                    or type(repo) is not dict or not _positive(repo.get('id'))
                    or repo.get('full_name') != self.project.repository
                    or repo.get('url') != api
                    or type(value.get('head_sha')) is not str or not _SHA.fullmatch(value['head_sha'])):
                raise LogFailure('INVALID_LOG_METADATA')
            if value.get('status') != 'completed' or value.get('conclusion') not in _CONCLUSIONS:
                raise LogFailure('LOG_NOT_COMPLETED')
            return {k: value[k] for k in ('id', 'run_attempt', 'head_sha', 'status', 'conclusion')}, repo['id']
        def job_view(value, tested):
            if (type(value) is not dict or not _positive(value.get('id'))
                    or type(value.get('run_id')) is not int or value['run_id'] != run_id
                    or value.get('run_url') != api + f'/actions/runs/{run_id}'
                    or value.get('url') != api + f'/actions/jobs/{value["id"]}'
                    or value.get('head_sha') != tested):
                raise LogFailure('INVALID_LOG_METADATA')
            if value.get('status') != 'completed' or value.get('conclusion') not in _CONCLUSIONS:
                raise LogFailure('LOG_NOT_COMPLETED')
            return {k: value[k] for k in ('id', 'run_id', 'head_sha', 'status', 'conclusion')}
        def pull_view(value, repo_id, tested):
            from .github_pr import _pull
            try:
                pull = _pull(value, self.project, pull_number)
            except (ValueError, KeyError, TypeError, LedgerError):
                raise LogFailure('LOG_CANDIDATE_MISMATCH') from None
            if (pull['base']['repo']['id'] != repo_id or pull['head']['sha'] != head_sha
                    or pull['base']['sha'] != base_sha or pull['state'] != 'open' or pull['merged']
                    or (tested != head_sha and pull['merge_commit_sha'] != tested)):
                raise LogFailure('LOG_CANDIDATE_MISMATCH')
            return pull
        try:
            run_raw, _ = get(base + f'/actions/runs/{run_id}/attempts/{attempt}')
            run, repo_id = run_view(run_raw)
            tested = run['head_sha']
            if tested != head_sha and pull_number is None:
                raise LogFailure('LOG_CANDIDATE_MISMATCH')
            pull = None
            if pull_number is not None:
                pull_raw, _ = get(base + f'/pulls/{pull_number}')
                pull = pull_view(pull_raw, repo_id, tested)
                associations = run_raw.get('pull_requests')
                if type(associations) is not list or len(associations) > 100:
                    raise LogFailure('LOG_CANDIDATE_MISMATCH')
                matches = [p for p in associations if type(p) is dict and p.get('id') == pull['id']
                           and p.get('number') == pull_number and p.get('url') == api + f'/pulls/{pull_number}'
                           and type(p.get('head')) is dict and p['head'].get('sha') == head_sha
                           and type(p.get('base')) is dict and p['base'].get('sha') == base_sha]
                if len(matches) != 1:
                    raise LogFailure('LOG_CANDIDATE_MISMATCH')
            job_raw, _ = get(base + f'/actions/jobs/{job_id}')
            job = job_view(job_raw, tested)
            if job['id'] != job_id:
                raise LogFailure('INVALID_LOG_METADATA')
            # A job response has no guaranteed run_attempt field. Establish its
            # membership via the explicit attempt's complete paginated job list.
            count, total, seen, member = 0, None, set(), None
            for page in range(1, self.max_pages + 1):
                page_value, headers = get(base + f'/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}')
                if (type(page_value) is not dict or type(page_value.get('total_count')) is not int
                        or not 0 <= page_value['total_count'] <= 1000
                        or type(page_value.get('jobs')) is not list or len(page_value['jobs']) > 100
                        or (total is not None and total != page_value['total_count'])):
                    raise LogFailure('INVALID_LOG_METADATA')
                total = page_value['total_count']
                for entry in page_value['jobs']:
                    observed = job_view(entry, tested)
                    if observed['id'] in seen:
                        raise LogFailure('INVALID_LOG_METADATA')
                    seen.add(observed['id']); count += 1
                    if observed['id'] == job_id:
                        member = observed
                next_page = bool(re.search(r'rel\s*=\s*["\']?next', headers.get('link', ''), re.I))
                if len(page_value['jobs']) < 100 and not next_page:
                    if count != total or member != job:
                        raise LogFailure('LOG_ATTEMPT_UNVERIFIED')
                    break
            else:
                raise LogFailure('LOG_ATTEMPT_UNVERIFIED')
            check_time()
            stream = self.logs(base + f'/actions/jobs/{job_id}/logs')
            if type(stream) is not LogStream:
                raise LogFailure('LOG_TRANSFER_INCOMPLETE')
            tail, count, digest = bytearray(), 0, hashlib.sha256()
            with stream:
                check_time()
                headers = _headers(stream.headers)
                length = headers.get('content-length')
                framing = headers.get('transfer-encoding')
                if (type(stream.status) is not int or stream.status != 200
                        or headers.get('content-encoding', 'identity') != 'identity'
                        or (length is not None and (not re.fullmatch(r'0|[1-9][0-9]*', length) or framing is not None))
                        or (length is None and framing != 'chunked')
                        or headers.get('content-type', 'text/plain').split(';', 1)[0].strip().lower()
                           not in {'text/plain', 'application/octet-stream'}):
                    raise LogFailure('LOG_TRANSFER_INCOMPLETE')
                expected = int(length) if length is not None else None
                if expected is not None and expected > self.max_transfer:
                    raise LogFailure('OUTPUT_LIMIT')
                for chunk in stream.chunks:
                    check_time()
                    if type(chunk) is not bytes or not 1 <= len(chunk) <= CHUNK:
                        raise LogFailure('LOG_TRANSFER_INCOMPLETE')
                    count += len(chunk)
                    if count > self.max_transfer:
                        raise LogFailure('OUTPUT_LIMIT')
                    digest.update(chunk); tail.extend(chunk)
                    if len(tail) > self.tail_bytes:
                        del tail[:-self.tail_bytes]
                check_time()
                if stream.complete is not True or (expected is not None and count != expected):
                    raise LogFailure('LOG_TRANSFER_INCOMPLETE')
            # No data returned if identity/conclusion changes during transfer.
            closing_run, _ = get(base + f'/actions/runs/{run_id}/attempts/{attempt}')
            closing_job, _ = get(base + f'/actions/jobs/{job_id}')
            if run_view(closing_run) != (run, repo_id) or job_view(closing_job, tested) != job:
                raise LogFailure('INVALID_LOG_METADATA')
            if pull is not None:
                closing_pull, _ = get(base + f'/pulls/{pull_number}')
                if pull_view(closing_pull, repo_id, tested) != pull:
                    raise LogFailure('LOG_CANDIDATE_MISMATCH')
            return {**result, 'status': 'OK', 'completeness': 'complete', 'tested_sha': tested,
                    'base_sha': base_sha, 'pull_number': pull_number,
                    'run_conclusion': run['conclusion'], 'job_conclusion': job['conclusion'],
                    'encoding': 'base64', 'tail': base64.b64encode(tail).decode('ascii'),
                    'total_bytes': count, 'dropped_bytes': count - len(tail), 'sha256': digest.hexdigest()}
        except (LogFailure, ProviderFailure) as error:
            return {**result, 'status': error.code if error.code in _CODES else 'PROVIDER_FAILURE'}
        except Exception:
            return result  # Never expose error text, body, credential or URL.


def validate_log_observation(value, project, run_id, job_id, attempt, head_sha, *,
                             base_sha=None, pull_number=None):
    """Independent typed result boundary before content leaves the Broker.

    This checks scope/shape/count consistency, not whether untrusted code
    performed a real HTTP transfer. The provider and transport remain trusted.
    """
    common = {'status', 'completeness', 'repository', 'run_id', 'job_id', 'attempt', 'head_sha'}
    success = {'tested_sha', 'base_sha', 'pull_number', 'run_conclusion', 'job_conclusion',
               'encoding', 'tail', 'total_bytes', 'dropped_bytes', 'sha256'}
    try:
        if (type(project) is not GitHubProject or type(value) is not dict
                or not all(_positive(v) for v in (run_id, job_id, attempt))
                or type(head_sha) is not str or not _SHA.fullmatch(head_sha)
                or (base_sha is None) != (pull_number is None)
                or (base_sha is not None and (type(base_sha) is not str or not _SHA.fullmatch(base_sha)
                                              or not _positive(pull_number)))
                or value.get('repository') != project.repository
                or any(type(value.get(k)) is not type(v) or value.get(k) != v
                       for k, v in {'run_id': run_id, 'job_id': job_id, 'attempt': attempt,
                                    'head_sha': head_sha}.items())):
            raise ValueError()
        if value.get('status') == 'OK':
            if (set(value) != common | success or value['completeness'] != 'complete'
                    or value['encoding'] != 'base64' or type(value['tail']) is not str
                    or len(value['tail']) > (MAX_TAIL + 2) // 3 * 4
                    or type(value['tested_sha']) is not str or not _SHA.fullmatch(value['tested_sha'])
                    or value['base_sha'] != base_sha or type(value['base_sha']) is not type(base_sha)
                    or value['pull_number'] != pull_number or type(value['pull_number']) is not type(pull_number)
                    or (base_sha is None and value['tested_sha'] != head_sha)
                    or value['run_conclusion'] not in _CONCLUSIONS
                    or value['job_conclusion'] not in _CONCLUSIONS
                    or type(value['total_bytes']) is not int or not 0 <= value['total_bytes'] <= MAX_TRANSFER
                    or type(value['dropped_bytes']) is not int or not 0 <= value['dropped_bytes'] <= value['total_bytes']
                    or type(value['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', value['sha256'])):
                raise ValueError()
            tail = base64.b64decode(value['tail'], validate=True)
            if (len(tail) > MAX_TAIL or base64.b64encode(tail).decode('ascii') != value['tail']
                    or value['total_bytes'] - len(tail) != value['dropped_bytes']
                    or (value['dropped_bytes'] == 0 and hashlib.sha256(tail).hexdigest() != value['sha256'])):
                raise ValueError()
        elif (set(value) != common or type(value.get('status')) is not str
              or value['status'] not in _CODES or value['completeness'] != 'unknown'):
            raise ValueError()
        encoded = json.dumps(value, allow_nan=False, separators=(',', ':'))
        if len(encoded.encode()) > 1_048_576:
            raise ValueError()
        return json.loads(encoded)
    except (KeyError, TypeError, ValueError, RecursionError):
        raise LedgerError('INVALID_PROVIDER_OBSERVATION') from None


def metadata_summary(value):
    """Audit-safe summary of an independently validated log observation.

    No log text/base64, URL, raw header, credential or exception is returned.
    Unknown results explicitly cannot supply an exact transfer count.
    """
    complete = value['status'] == 'OK' and value['completeness'] == 'complete'
    return {'status': value['status'], 'completeness': value['completeness'],
            'returned_bytes': value['total_bytes'] - value['dropped_bytes'] if complete else None,
            'total_bytes': value['total_bytes'] if complete else None,
            'dropped_bytes': value['dropped_bytes'] if complete else None,
            'sha256': value['sha256'] if complete else None}
