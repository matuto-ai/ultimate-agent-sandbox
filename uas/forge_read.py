"""External read Broker owner: fixed GitHub provider, canonical metadata audit.

Only a process-authenticated Supervisor may construct Origin/authorize. Response
content is private bounded Broker cache, never a Hub or canonical audit event.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from .forge import ForgeBinding
from .forge_audit import ForgeAudit, READ_AUDIT_STATUSES
from .github_read import GitHubProject, ProviderFailure
from .github_routes import help_text, parse_read_route
from .ledger import LedgerError, Origin, _json, _token

MAX_RESULT = 1_040_000  # Leave bounded protocol-envelope space below 1 MiB.
MAX_CACHED = 64


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


class ExternalReadBroker:
    def __init__(self, binding, room_instance, audit, provider_for_actor, result_root):
        if (type(binding) is not ForgeBinding or type(audit) is not ForgeAudit
                or not callable(provider_for_actor)):
            raise LedgerError('INVALID_READ_BROKER')
        self.project = GitHubProject(binding.repository, binding.host)
        self.binding, self.room_instance, self.audit = binding, _token(room_instance), audit
        self.providers = provider_for_actor
        self.root = Path(result_root)
        if not self.root.is_absolute() or self.root.resolve() != self.root:
            raise LedgerError('INVALID_STORE')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or self.root.stat().st_mode & 0o077:
            raise LedgerError('INVALID_STORE')
        self.failed = False

    def _authorize(self, origin, authorize):
        if self.failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        if (type(origin) is not Origin or 'forge-read' not in origin.capabilities
                or authorize() is not True):
            raise LedgerError('FORBIDDEN')
        origin.canonical()

    def _cache_path(self, operation):
        return self.root / (hashlib.sha256(operation.encode()).hexdigest() + '.json')

    def _cache(self, operation, result):
        content = _json(result).encode()
        if len(content) > MAX_RESULT:
            raise LedgerError('OUTPUT_LIMIT')
        path = self._cache_path(operation)
        if path.exists():
            if path.is_symlink() or path.read_bytes() != content:
                raise LedgerError('RESULT_CONFLICT')
            return
        if len(list(self.root.glob('*.json'))) >= MAX_CACHED:
            raise LedgerError('READ_CAPACITY')
        temporary = self.root / ('.result-' + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            os.link(temporary, path)
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)

    def _cached(self, operation, terminal):
        if terminal['observation_digest'] is None:
            return {'status': terminal['status'], 'completeness': terminal['completeness']}
        path = self._cache_path(operation)
        try:
            if path.is_symlink() or path.stat().st_size > MAX_RESULT:
                raise ValueError()
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != terminal['observation_digest']:
                raise ValueError()
            return json.loads(content)
        except (OSError, ValueError):
            return {'status': 'RESULT_UNAVAILABLE', 'completeness': 'unknown'}

    def execute(self, envelope, *, origin, authorize):
        self._authorize(origin, authorize)
        if (type(envelope) is not dict or set(envelope) != {'id', 'kind', 'argv'}
                or envelope['kind'] != 'forge-read'):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        try:
            _json(envelope)
            operation = 'read-' + _digest([self.binding.room_id, self.room_instance, _token(envelope['id'])])
        except LedgerError:
            raise LedgerError('INVALID_FORGE_ENVELOPE') from None
        # Fixed provider/host exists before request parsing. Selection of Actor
        # credentials remains external and cannot be influenced by argv.
        denied = None
        try:
            route = parse_read_route(envelope['argv'], self.project)
        except LedgerError as error:
            route, denied = None, error.code
        metadata = {'room_id': self.binding.room_id, 'room_instance': self.room_instance,
            'project_id': self.binding.project_id, 'actor_id': origin.actor_id,
            'participant_id': origin.participant_id, 'incarnation_id': origin.incarnation_id,
            'authority_version': origin.authority_version, 'provider_host': 'github.com',
            'requested_repository': route.repository if route else self.project.repository,
            'effective_repository': route.repository if route else self.project.repository,
            'route': route.kind if route else 'denied',
            'request_digest': _digest(envelope), 'origin_digest': _digest(origin.canonical())}
        try:
            begin = self.audit.begin_read(operation, metadata)
            record = begin['record']
            if not begin['started']:
                if record['result'] is None:
                    return {'status': 'INTERRUPTED_OBSERVATION', 'completeness': 'unknown'}
                self._authorize(origin, authorize)
                return self._cached(operation, record['result'])
            # Refuse before provider selection if no bounded response capacity.
            if len(list(self.root.glob('*.json'))) >= MAX_CACHED:
                self.audit.finish_read(operation, {'status':'READ_CAPACITY','completeness':'unknown','contact':'none',
                    'output_bytes':0,'dropped_bytes':None,'observation_digest':None})
                return {'status':'READ_CAPACITY','completeness':'unknown'}
            self._authorize(origin, authorize)
            contact = 'none'
            if denied:
                result = {'status': denied, 'completeness': 'unknown'}
            elif route.kind == 'help':
                result = {'status': 'HELP', 'completeness': 'complete', 'text': help_text()}
            else:
                try:
                    provider = self.providers(origin.actor_id)
                    if getattr(provider, 'host', None) != 'github.com':
                        raise LedgerError('INVALID_RESPONSE')
                except Exception as error:
                    code = error.code if isinstance(error,(LedgerError,ProviderFailure)) else None
                    result = {'status':code if code in READ_AUDIT_STATUSES else 'PROVIDER_FAILURE',
                        'completeness':'unknown'}
                    provider = None
                self._authorize(origin, authorize)
                if provider is not None:
                    contact = 'read'
                    try:
                        result = provider.read(route)
                    except Exception as error:
                        code = error.code if isinstance(error,(LedgerError,ProviderFailure)) else None
                        result = {'status':code if code in READ_AUDIT_STATUSES else 'PROVIDER_FAILURE',
                            'completeness':'unknown'}
                if (type(result) is not dict or result.get('completeness') not in {'complete', 'incomplete', 'unknown'}
                        or result.get('status') not in READ_AUDIT_STATUSES):
                    result = {'status': 'PROVIDER_FAILURE', 'completeness': 'unknown'}
            try:
                content = _json(result).encode()
                if len(content) > MAX_RESULT: raise LedgerError('OUTPUT_LIMIT')
            except LedgerError:
                result = {'status': 'OUTPUT_LIMIT', 'completeness': 'unknown'}
                content = _json(result).encode()
            self._cache(operation, result)
            # Terminal audit carries only bounds/digests, no repository text.
            status = result['status']
            terminal = {'status': status, 'completeness': result['completeness'], 'contact': contact,
                'output_bytes': len(content), 'dropped_bytes': (result.get('dropped_bytes', 0) if result['completeness'] == 'complete' else None),
                'observation_digest': hashlib.sha256(content).hexdigest()}
            self.audit.finish_read(operation, terminal)
            self._authorize(origin, authorize)  # Late revocation blocks disclosure.
            return result
        except LedgerError as error:
            if error.code == 'AUDIT_UNAVAILABLE': self.failed = True
            raise

    def denied(self, code):
        """No attacker identity is attributed to an unauthenticated packet."""
        allowed = {'WRONG_PROCESS', 'AUTHORITY_REVOKED', 'PROCESS_EXITED',
            'MISSING_ACTOR_CREDENTIAL', 'INVALID_PROCESS_RECORD',
            'AUTHORITY_STORE_UNAVAILABLE', 'INVALID_AUTHORITY_STORE',
            'CONTROLLER_REPLACED', 'ROOM_NOT_RUNNING', 'ROOM_REPLACED', 'FORBIDDEN',
            'INVALID_FORGE_ENVELOPE', 'INVALID_NATIVE_FRAME', 'PROJECT_MISMATCH'}
        if type(code) is not str or code not in allowed: return
        operation = 'read-denied-' + uuid.uuid4().hex
        metadata = {'room_id': self.binding.room_id, 'room_instance': self.room_instance,
            'project_id': self.binding.project_id, 'actor_id': 'unauthenticated',
            'participant_id': 'unauthenticated', 'incarnation_id': 'no-authority',
            'authority_version': 'none', 'provider_host': 'github.com',
            'requested_repository': self.project.repository, 'effective_repository': self.project.repository,
            'route': 'denied', 'request_digest': _digest({'code':code}),
            'origin_digest': _digest({'source':'authenticated-supervisor-denial'})}
        self.audit.begin_read(operation, metadata)
        self.audit.finish_read(operation, {'status': code, 'completeness':'unknown','contact':'none',
            'output_bytes':0,'dropped_bytes':None,'observation_digest':None})

    def recover(self, fenced):
        """Trusted replacement owner only: never repeat an interrupted read."""
        for record in self.audit.pending_reads(self.binding.room_id):
            if record['metadata']['room_instance'] != self.room_instance or not fenced(record['metadata']):
                continue
            self.audit.finish_read(record['operation_id'], {
                'status': 'INTERRUPTED_OBSERVATION', 'completeness': 'unknown', 'contact': 'unknown',
                'output_bytes': 0, 'dropped_bytes': None, 'observation_digest': None})
