"""T14: bounded, authorized source excerpts, with no fetch or persistent content.

The service supplies a trusted, read-only bare source clone (not a Participant
checkout) or an already captured content-addressed snapshot. Caller requests
cannot choose a filesystem path, credential, command, or transport. The live
scope and source-authority callbacks are mandatory: possession of a prior
LibraryScope or of cached bytes is never fresh authorization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import posixpath
import re
import selectors
import stat
import subprocess
import time

from . import library as contracts
from . import library_gate as gate

MAX_SOURCE_BYTES = contracts.MAXIMA['document_bytes']
MAX_PATH_BYTES = 1024
READ_SECONDS = 5
ARCHIVES = ('.zip', '.tar', '.tgz', '.gz', '.bz2', '.xz', '.7z', '.rar', '.jar', '.war')
MAGIC = (b'PK\x03\x04', b'PK\x05\x06', b'\x1f\x8b', b'BZh', b'\xfd7zXZ\x00', b'7z\xbc\xaf\x27\x1c', b'Rar!')


def _fail(code):
    raise contracts.LibraryError(code, 'source')


def _require(ok, code):
    if not ok:
        _fail(code)


def _utf8(value, limit, code):
    _require(type(value) is str, code)
    try:
        _require(0 < len(value.encode('utf-8')) <= limit, code)
    except UnicodeError:
        raise contracts.LibraryError(code, 'source') from None
    return value


def _path(value):
    _utf8(value, MAX_PATH_BYTES, 'SOURCE_PATH_INVALID')
    _require(type(value) is str
             and not value.startswith(('/', '-')) and '\\' not in value
             and '%' not in value and '?' not in value and '#' not in value
             and all(ord(c) >= 32 and ord(c) != 127 for c in value)
             and all(part not in ('', '.', '..') for part in value.split('/'))
             and posixpath.normpath(value) == value, 'SOURCE_PATH_INVALID')
    _require(not value.lower().endswith(ARCHIVES), 'SOURCE_KIND_UNSUPPORTED')
    return value


def _snapshot_identity(resource):
    """Explicit snapshot syntax, never a URL containing a coincidental hash."""
    _utf8(resource, 2048, 'SOURCE_DECLARATION_INVALID')
    _require(resource.startswith('https://'), 'SOURCE_IMMUTABLE_REQUIRED')
    authority, slash, path = resource[len('https://'):].partition('/')
    _require(bool(slash) and bool(authority) and authority == authority.lower(),
             'SOURCE_DECLARATION_INVALID')
    parts = path.split('/', 2)
    _require(len(parts) == 3 and parts[0] == 'objects'
             and contracts.DIGEST.fullmatch(parts[1]) is not None,
             'SOURCE_IMMUTABLE_REQUIRED')
    _path(parts[2])
    return parts[1]


def _declaration(value):
    _require(type(value) is dict and set(value) == {'resource', 'range', 'sha256'},
             'SOURCE_DECLARATION_INVALID')
    resource = value['resource']
    _utf8(resource, 2048, 'SOURCE_DECLARATION_INVALID')
    declared = gate.source(resource)
    _require(declared['pinned'] is True, 'SOURCE_IMMUTABLE_REQUIRED')
    match = gate.RANGE.fullmatch(value['range']) if type(value['range']) is str and len(value['range']) <= 24 else None
    _require(match is not None, 'SOURCE_RANGE_INVALID')
    first, last = map(int, match.groups())
    _require(1 <= first <= last <= 2**31 - 1 and last-first+1 <= gate.MAX_EXCERPT_LINES,
             'SOURCE_RANGE_INVALID')
    _require(type(value['sha256']) is str and contracts.DIGEST.fullmatch(value['sha256']),
             'SOURCE_HASH_INVALID')
    return dict(value), first, last


@dataclass(frozen=True)
class Excerpt:
    """Ephemeral result; repr and metadata omit content and private source paths."""
    content: bytes = field(repr=False)
    resource: str = field(repr=False)
    immutable_identity: str
    first_line: int
    last_line: int
    sha256: str
    source_sha256: str
    project_identity: str

    def metadata(self):
        return {'project_identity': self.project_identity,
                'source_ref_sha256': hashlib.sha256(self.resource.encode()).hexdigest(),
                'immutable_identity': self.immutable_identity,
                'range': [self.first_line, self.last_line], 'sha256': self.sha256,
                'source_sha256': self.source_sha256, 'bytes': len(self.content)}


class GitSource:
    """Trusted selected bare clone; local object reads only, no source write.

    The owner must populate/refresh this clone through its existing authenticated
    source-reading boundary. This adapter never authenticates or fetches. A
    missing object fails unavailable, including in a partial clone. The clone
    and its object store must remain service-owned, not Participant-writable.
    """
    def __init__(self, root, *, project_identity, repository):
        _require(type(project_identity) is str and contracts.TOKEN.fullmatch(project_identity), 'SOURCE_BINDING_INVALID')
        _require(type(repository) is str and re.fullmatch(r'github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', repository), 'SOURCE_BINDING_INVALID')
        try:
            self.root = Path(root)
            _require(self.root.is_absolute() and self.root.resolve() == self.root, 'SOURCE_STORE_INVALID')
            node = self.root.lstat()
        except (OSError, ValueError, TypeError, UnicodeError):
            raise contracts.LibraryError('SOURCE_STORE_INVALID', 'source') from None
        _require(stat.S_ISDIR(node.st_mode) and node.st_uid == os.geteuid() and not node.st_mode & 0o022, 'SOURCE_STORE_INVALID')
        self.identity = (node.st_dev, node.st_ino)
        self.project_identity, self.repository = project_identity, repository

    def reference(self, resource):
        prefix = 'https://' + self.repository + '/blob/'
        _require(resource.startswith(prefix), 'SOURCE_SCOPE_REFUSED')
        commit, slash, path = resource[len(prefix):].partition('/')
        _require(slash and contracts.COMMIT.fullmatch(commit), 'SOURCE_IMMUTABLE_REQUIRED')
        return commit, _path(path)

    def _git(self, arguments, limit, current):
        current()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            _require((info.st_dev, info.st_ino) == self.identity and info.st_uid == os.geteuid()
                     and not info.st_mode & 0o022, 'SOURCE_STORE_CHANGED')
            env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                   'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0',
                   'GIT_OPTIONAL_LOCKS': '0', 'GIT_ALLOW_PROTOCOL': '',
                   'GIT_PROTOCOL_FROM_USER': '0'}
            command = ['/usr/bin/git', '--no-replace-objects', '--git-dir=/proc/self/fd/'+str(fd),
                       '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                       '-c', 'protocol.allow=never', *arguments]
            with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=env, pass_fds=(fd,)) as process:
                data = bytearray()
                deadline = time.monotonic() + READ_SECONDS
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        while True:
                            remaining = deadline-time.monotonic()
                            _require(remaining > 0, 'SOURCE_UNAVAILABLE')
                            current()
                            _require(selector.select(remaining), 'SOURCE_UNAVAILABLE')
                            chunk = os.read(process.stdout.fileno(), min(65536, limit+1-len(data)))
                            if not chunk:
                                break
                            data.extend(chunk)
                            _require(len(data) <= limit, 'SOURCE_TOO_LARGE')
                        _require(process.wait(timeout=max(.001, deadline-time.monotonic())) == 0,
                                 'SOURCE_UNAVAILABLE')
                    current()
                    return bytes(data)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
        finally:
            os.close(fd)

    def read(self, resource, limit, current):
        commit, path = self.reference(resource)
        _require(self._git(['rev-parse', '--is-bare-repository'], 8, current) == b'true\n', 'SOURCE_STORE_INVALID')
        # A commit pin must name an actual commit, never an annotated tag or blob.
        _require(self._git(['cat-file', '-t', commit], 32, current) == b'commit\n', 'SOURCE_IMMUTABLE_REQUIRED')
        raw = self._git(['ls-tree', '-z', commit, '--', path], MAX_PATH_BYTES+128, current)
        _require(raw.endswith(b'\0') and raw.count(b'\0') == 1, 'SOURCE_UNAVAILABLE')
        header, tab, named = raw[:-1].partition(b'\t')
        _require(tab and named == path.encode('utf-8'), 'SOURCE_UNAVAILABLE')
        parts = header.split(b' ')
        _require(len(parts) == 3 and parts[0] in (b'100644', b'100755') and parts[1] == b'blob', 'SOURCE_KIND_UNSUPPORTED')
        oid = parts[2].decode('ascii')
        _require(contracts.COMMIT.fullmatch(oid), 'SOURCE_UNAVAILABLE')
        size = self._git(['cat-file', '-s', oid], 32, current)
        _require(re.fullmatch(rb'[0-9]{1,12}\n', size), 'SOURCE_UNAVAILABLE')
        _require(int(size) <= limit, 'SOURCE_TOO_LARGE')
        content = self._git(['cat-file', 'blob', oid], limit, current)
        _require(len(content) == int(size), 'SOURCE_UNAVAILABLE')
        hash_name = 'sha1' if len(oid) == 40 else 'sha256'
        observed = hashlib.new(hash_name, b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        _require(observed == oid, 'SOURCE_OBJECT_MISMATCH')
        return content, commit + ':' + oid


class CapturedSource:
    """Already-authorized immutable snapshot, not an HTTP client or body store.

    The source URL must be HTTPS /objects/<full-lowercase-sha256>/<name>,
    with an exact normalized relative name (nested paths are allowed). A plain mutable URL alone is deliberately unsupported. Selection
    and bytes come from the trusted caller's ephemeral captured source owner.
    """
    def __init__(self, *, project_identity, resource, content):
        _require(type(content) is bytes and len(content) <= MAX_SOURCE_BYTES, 'SOURCE_TOO_LARGE')
        identity = _snapshot_identity(resource)
        declared = gate.source(resource)
        digest = hashlib.sha256(content).hexdigest()
        _require(declared['pinned'] and declared['kind'] == 'snapshot'
                 and identity == digest, 'SOURCE_IMMUTABLE_REQUIRED')
        _require(type(project_identity) is str and contracts.TOKEN.fullmatch(project_identity), 'SOURCE_BINDING_INVALID')
        self.project_identity, self.resource = project_identity, resource
        self._content, self.digest = content, digest

    def read(self, resource, limit, current):
        current()
        _require(resource == self.resource, 'SOURCE_SCOPE_REFUSED')
        _require(len(self._content) <= limit, 'SOURCE_TOO_LARGE')
        _require(hashlib.sha256(self._content).hexdigest() == self.digest, 'SOURCE_OBJECT_MISMATCH')
        current()
        return self._content, 'sha256:' + self.digest

    def __repr__(self):
        return 'CapturedSource(sha256=' + self.digest + ')'


class Resolver:
    """One Project resolver with fresh live scope and per-source permission.

    current_scope returns a freshly authenticated LibraryScope, not a boolean
    based on a stored one. source_allowed(scope, resource) checks the current
    source grant on every call, including just before local Git object I/O.
    Neither callback may be supplied by an untrusted request. Future import and
    synthesis owners consume this seam; it never invokes them itself.
    """
    def __init__(self, *, source, current_scope, source_allowed):
        _require(type(source) in (GitSource, CapturedSource) and callable(current_scope)
                 and callable(source_allowed), 'SOURCE_AUTHORITY_REQUIRED')
        self.source, self.current_scope, self.source_allowed = source, current_scope, source_allowed

    def authorize(self, scope, resource):
        """Recheck a retained excerpt grant without rereading or returning content."""
        _require(type(scope) is contracts.LibraryScope and scope.subject != 'operator'
                 and scope.project_identity == self.source.project_identity, 'SOURCE_SCOPE_REFUSED')
        try:
            fresh = self.current_scope()
            allowed = (type(fresh) is contracts.LibraryScope and fresh.canonical() == scope.canonical()
                       and self.source_allowed(fresh, resource) is True)
        except Exception:
            raise contracts.LibraryError('SOURCE_AUTHORITY_UNAVAILABLE', 'source') from None
        _require(allowed, 'SOURCE_AUTHORITY_REVOKED')

    def resolve(self, scope, settings, declaration):
        # No source bytes or source commands are accessed before both checks.
        settings = contracts.admit_settings_value(settings)
        value, first, last = _declaration(declaration)
        resource = value['resource']
        def current():
            self.authorize(scope, resource)
        try:
            current()
            content, immutable = self.source.read(resource, settings['limits']['document_bytes'], current)
            _require(not content.startswith(MAGIC) and content[257:262] != b'ustar', 'SOURCE_KIND_UNSUPPORTED')
            _require(b'\0' not in content, 'SOURCE_ENCODING_UNSUPPORTED')
            try:
                text = content.decode('utf-8')
            except UnicodeError:
                _fail('SOURCE_ENCODING_UNSUPPORTED')
            _require(not text.startswith('\ufeff') and not any(ord(c) < 32 and c not in '\r\n\t' for c in text), 'SOURCE_ENCODING_UNSUPPORTED')
            # LF is the source line delimiter. Retain CRLF and final newline
            # exactly; Unicode splitlines would silently invent extra lines.
            lines = content.splitlines(keepends=True) if b'\r' not in content.replace(b'\r\n', b'') else None
            _require(lines is not None and last <= len(lines), 'SOURCE_RANGE_UNAVAILABLE')
            excerpt = b''.join(lines[first-1:last])
            _require(len(excerpt) <= settings['limits']['body_bytes'], 'SOURCE_TOO_LARGE')
            _require(hashlib.sha256(excerpt).hexdigest() == value['sha256'], 'SOURCE_HASH_MISMATCH')
            # Reuse the single policy implementation. No second credential
            # taxonomy or model invocation; findings retain only safe hashes.
            observations = []
            gate._credentials('source', excerpt.decode('utf-8'), settings['filters'], observations)
            current()
            return Excerpt(excerpt, resource, immutable, first, last, value['sha256'],
                           hashlib.sha256(content).hexdigest(), scope.project_identity)
        except contracts.LibraryError as error:
            evidence = {'source_ref_sha256': hashlib.sha256(resource.encode()).hexdigest(),
                        'range': [first, last], 'sha256': value['sha256']}
            raise contracts.LibraryError(error.code, 'source', evidence) from None
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise contracts.LibraryError('SOURCE_UNAVAILABLE', 'source') from None
