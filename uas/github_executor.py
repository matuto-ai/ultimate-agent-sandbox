"""Pinned external gh executor. No Workstation token/config inheritance."""
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time

from .github_read import API_VERSION, MAX_OUTPUT, ProviderFailure, ProviderResponse
from .ledger import LedgerError

# Only internally constructed REST paths for the declared read table. Query
# names and values are fixed/reduced by the provider, never raw Participant argv.
_PATH = re.compile(r'repos/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+(?:/(?:issues(?:/[1-9][0-9]*(?:/(?:comments|labels|dependencies/(?:blocked_by|blocking)))?)?|pulls(?:/comments/[1-9][0-9]*|/[1-9][0-9]*(?:/(?:comments|reviews|files|commits))?)?|labels|contents/[^?#]+|commits/[A-Za-z0-9._%/-]+(?:/(?:check-runs|statuses|status))?|actions/(?:workflows(?:/[1-9][0-9]*)?|runs(?:/[1-9][0-9]*(?:/attempts/[1-9][0-9]*)?(?:/jobs)?)?|jobs/[1-9][0-9]*)))?(?:\?[A-Za-z0-9_%.=,&+-]+)?\Z')
_ALLOWED_QUERY = {'per_page', 'page', 'state', 'ref', 'filter', 'status', 'branch', 'head_sha', 'assignee', 'creator', 'mentioned'}
_ACCEPT = {'application/vnd.github+json', 'application/vnd.github.diff', 'application/vnd.github.raw+json'}


class GhSurfaceTransport:
    host = 'github.com'
    def __init__(self, executable, sha256, actor_id, credential_env, *, timeout=10):
        path = Path(executable)
        if (not path.is_absolute() or path.resolve() != path or not re.fullmatch('[0-9a-f]{64}', sha256)
                or type(actor_id) is not str or not actor_id or not callable(credential_env)
                or type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise LedgerError('INVALID_GH_EXECUTOR')
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            node = os.fstat(self.fd)
            if (not stat.S_ISREG(node.st_mode) or node.st_uid not in (0, os.getuid())
                    or node.st_mode & 0o022 or not node.st_mode & 0o111):
                raise LedgerError('INVALID_GH_EXECUTOR')
            self.sha256, self.actor, self.credentials, self.timeout = sha256, actor_id, credential_env, timeout
            self.identity = (node.st_dev, node.st_ino)
            self.failed = False
            self._pin()
        except BaseException:
            os.close(self.fd); self.fd = -1
            raise

    def close(self):
        if self.fd >= 0: os.close(self.fd); self.fd = -1

    def _pin(self):
        if self.fd < 0 or self.failed: raise ProviderFailure('PROVIDER_ERROR')
        node = os.fstat(self.fd)
        if (node.st_dev, node.st_ino) != self.identity or node.st_mode & 0o022:
            raise ProviderFailure('PROVIDER_ERROR')
        digest, offset = hashlib.sha256(), 0
        while True:
            block = os.pread(self.fd, 65536, offset)
            if not block: break
            digest.update(block); offset += len(block)
            if offset > 128 * 1024 * 1024: raise ProviderFailure('PROVIDER_ERROR')
        if digest.hexdigest() != self.sha256: raise ProviderFailure('PROVIDER_ERROR')

    def __call__(self, path):
        return self.get(path)

    def get(self, path, *, accept='application/vnd.github+json'):
        from urllib.parse import parse_qsl
        if (type(path) is not str or len(path) > 4096 or (path != 'user' and not _PATH.fullmatch(path))
                or '..' in path.split('?')[0].split('/') or accept not in _ACCEPT):
            raise ProviderFailure('INVALID_RESPONSE')
        query = parse_qsl(path.partition('?')[2], keep_blank_values=True, strict_parsing=True)
        if len({k for k, _ in query}) != len(query) or any(k not in _ALLOWED_QUERY for k, _ in query):
            raise ProviderFailure('INVALID_RESPONSE')
        return self._execute('GET', path, None, accept)

    def mutate(self, method, path, body, *, repository):
        # Only typed provider calls reach this API. It is not exposed as gh api.
        from .github_read import GitHubProject
        from .github_mutation_routes import MAX_BODY
        from .forge_wire import MAX_REQUEST
        import json
        project = GitHubProject(repository)
        prefix = 'repos/' + project.repository
        suffix = path[len(prefix):] if type(path) is str and path.startswith(prefix + '/') else None
        patterns = {
            'POST': r'/(?:issues|pulls|issues/[1-9][0-9]*/(?:comments|labels|assignees|dependencies/blocked_by)|pulls/[1-9][0-9]*/(?:reviews|comments/[1-9][0-9]*/replies))',
            'PATCH': r'/(?:issues|pulls)/[1-9][0-9]*',
            'DELETE': r'/issues/[1-9][0-9]*/(?:assignees|labels/[A-Za-z0-9._%~-]+|dependencies/blocked_by/[1-9][0-9]*)',
        }
        if (method not in patterns or suffix is None or any(part in {'','.', '..'} for part in path.split('/'))
                or not re.fullmatch(patterns[method], suffix)
                or (body is not None and type(body) is not dict)):
            raise ProviderFailure('INVALID_RESPONSE')
        try: payload = None if body is None else json.dumps(body,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode()
        except (ValueError,TypeError,UnicodeError): raise ProviderFailure('INVALID_RESPONSE') from None
        if body is not None and 'body' in body and (type(body['body']) is not str or len(body['body'].encode('utf-8'))>MAX_BODY):
            raise ProviderFailure('OUTPUT_LIMIT')
        if payload is not None and len(payload) > MAX_REQUEST: raise ProviderFailure('OUTPUT_LIMIT')
        return self._execute(method, path, payload, 'application/vnd.github+json')

    def _execute(self, method, path, payload, accept):
        # This transport belongs to the dedicated single-threaded Broker,
        # the exclusive reaper of its gh children. main resets SIGCHLD to DFL
        # (clearing inherited ignore/no-child-wait semantics) before launch.
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise ProviderFailure('PROVIDER_ERROR')
        self._pin()
        secret = self.credentials(self.actor, 'github.com')
        if type(secret) is not dict or set(secret) != {'GH_TOKEN'} or type(secret['GH_TOKEN']) is not str or not secret['GH_TOKEN']:
            raise ProviderFailure('CREDENTIAL_UNAVAILABLE')
        with tempfile.TemporaryDirectory(prefix='uas-gh-') as home, tempfile.TemporaryFile() as input_file:
            env = {'HOME': home, 'GH_CONFIG_DIR': home, 'GH_HOST': 'github.com', 'GH_PROMPT_DISABLED': '1',
                'GH_NO_UPDATE_NOTIFIER': '1', 'GH_NO_EXTENSION_UPDATE_NOTIFIER': '1', 'GH_PAGER': 'cat',
                'LC_ALL': 'C', **secret}
            command = [f'/proc/self/fd/{self.fd}', 'api', '--hostname', 'github.com', '--method', method, '--include',
                '-H', 'Accept: ' + accept, '-H', 'X-GitHub-Api-Version: ' + API_VERSION, path]
            if payload is not None:
                input_file.write(payload); input_file.seek(0)
                command += ['--input', '-']
            proc = subprocess.Popen(command, cwd=home, env=env, pass_fds=(self.fd,), stdin=input_file if payload is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False, start_new_session=True)
            data = bytearray(); deadline = time.monotonic() + self.timeout
            owned = True
            def observe_owned():
                nonlocal owned
                try:
                    return os.waitid(os.P_PID,proc.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                except ChildProcessError:
                    # ECHILD is lost ownership, not proof of completed cleanup.
                    # Never signal a numeric group after an external/auto reap.
                    owned = False
                    self.failed = True
                    raise ProviderFailure('PROVIDER_ERROR') from None
            try:
                with selectors.DefaultSelector() as poll:
                    poll.register(proc.stdout, selectors.EVENT_READ)
                    while poll.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0: raise ProviderFailure('TIMEOUT')
                        for key, _ in poll.select(remaining):
                            block = os.read(key.fileobj.fileno(), 65536)
                            if not block: poll.unregister(key.fileobj)
                            else:
                                data.extend(block)
                                if len(data) > MAX_OUTPUT + 16384: raise ProviderFailure('OUTPUT_LIMIT')
                    # Observe without reaping. No other code in this dedicated
                    # owner may wait/poll these children or install a reaper.
                    while observe_owned() is None:
                        if time.monotonic() >= deadline: raise ProviderFailure('TIMEOUT')
                        time.sleep(.001)
            finally:
                try:
                    if owned:
                        observe_owned()  # Also prove ownership on setup failure.
                        try: os.killpg(proc.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                        # Exactly one wait boundary. It can reap before raising
                        # (e.g. interruption); never retry numeric group signaling
                        # afterward, even when returncode was not published.
                        owned = False
                        proc.wait(timeout=2)
                except BaseException:
                    self.failed = True
                    raise ProviderFailure('PROVIDER_ERROR') from None
                finally:
                    proc.stdout.close()
        try:
            # Official gh api --include (v2.87.3 api.go:420-424,540-555)
            # prints LF after status, CRLF after each header and the blank line.
            # Parse that envelope, not a guessed raw HTTP-wire status framing.
            status_line, rest = bytes(data).split(b'\n',1)
            if status_line.endswith(b'\r'):status_line=status_line[:-1]
            if rest.startswith(b'\r\n'):header,body=b'',rest[2:]
            else:header,body=rest.split(b'\r\n\r\n',1)
            if len(status_line)+len(header)>16384 or len(body)>MAX_OUTPUT:raise ValueError()
            status_line=status_line.decode('ascii')
            if not re.fullmatch(r'HTTP/\S+ [1-5][0-9]{2}(?: [^\r\n]*)?',status_line):raise ValueError()
            status=int(status_line.split()[1])
            if proc.returncode and 200 <= status < 300:raise ValueError()
            headers={}
            for line in header.decode('ascii').split('\r\n') if header else ():
                if '\n' in line or '\r' in line:raise ValueError()
                key, value = line.split(':', 1)
                if key.lower() == 'link': headers['link'] = headers.get('link', '') + value.strip()
            return ProviderResponse(status, body, headers)
        except (ValueError, UnicodeError):
            raise ProviderFailure('INVALID_RESPONSE') from None
