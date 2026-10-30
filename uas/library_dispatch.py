"""T17 qualified dispatch consumer. Trusted external adapters, no provider client.

The singleton Gateway bounds a single low-priority adapter and reaps it before
releasing capacity. It is process containment, not a sandbox for adapter code.
"""
from dataclasses import dataclass, field
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import selectors
import signal
import threading
import time
from urllib.parse import urlsplit

from . import library, library_gate as gate
from .library_assembly import Request, INSTRUCTIONS
from .library_records import LibraryRecords

MAX_RESPONSE = 1048576


def fail(code):
    raise library.LibraryError(code, 'dispatch')


def _constant(value):
    fail('MODEL_JSON_INVALID')


def digest(value):
    return hashlib.sha256(library._canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class Profile:
    reference: str
    placement: str
    provider: str
    version: str
    endpoint: str = field(repr=False)
    region: str
    retention: str
    terms: str
    training: bool = False
    shared_interactive: bool = False

    def identity(self):
        for value in (self.reference, self.provider, self.version, self.region,
                      self.retention, self.terms):
            library._token(value, 'profile')
        endpoint = urlsplit(self.endpoint)
        if (self.placement not in ('local', 'hosted') or type(self.training) is not bool
                or self.training or type(self.shared_interactive) is not bool
                or endpoint.scheme not in ('http', 'https') or not endpoint.hostname
                or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment
                or (self.placement == 'hosted' and endpoint.scheme != 'https')):
            fail('PROFILE_UNSAFE')
        return digest(vars(self))


@dataclass(frozen=True)
class Evidence:
    """Externally authenticated current proof, not caller/settings assertions."""
    reference: str
    profile_sha256: str
    project_identity: str
    valid_until: str
    qualified: bool = True

    def check(self, reference, profile_sha256, project_identity, now):
        library._timestamp(self.valid_until, 'evidence.valid_until')
        library._token(self.reference, 'evidence.reference')
        if (self.qualified is not True or self.reference != reference
                or self.profile_sha256 != profile_sha256
                or self.project_identity != project_identity
                or datetime.fromisoformat(self.valid_until) <= now):
            fail('MODEL_EVIDENCE_INVALID')


@dataclass(frozen=True)
class Selection:
    profile: Profile
    qualification: Evidence
    authorization: Evidence
    hosted_approval: Evidence | None = None


@dataclass(frozen=True)
class Result:
    proposal: bytes = field(repr=False)
    evidence: dict


class Gateway:
    """Singleton trusted external adapter process, with fixed hash-bound routes.

    routes maps exact qualified profile digests to fixed executable argv tuples.
    A fresh adapter receives one JSON object on stdin: profile + request (the
    exact serialized model request as a string), response_limit, timeout_seconds.
    It returns raw proposal JSON on stdout and must disable fallback/retries and
    model tools. No generic shell or model-selected command is exposed. T42
    qualifies the actual adapter/profile route; fixtures are not that evidence.
    """
    def __init__(self, routes, *, interactive):
        if (type(routes) is not dict or not routes or not callable(interactive)
                or any(type(k) is not str or not library.DIGEST.fullmatch(k)
                       or type(v) is not tuple or not v or not os.path.isabs(v[0])
                       or any(type(arg) is not str or not arg or '\0' in arg for arg in v)
                       for k, v in routes.items())):
            fail('GATEWAY_REQUIRED')
        self.routes, self.interactive = dict(routes), interactive
        self.lock = threading.Lock()

    def call(self, profile, request, *, response_limit, seconds, before_contact):
        if not self.lock.acquire(blocking=False):
            fail('MODEL_CAPACITY_UNAVAILABLE')
        process = None
        try:
            command = self.routes.get(profile.identity())
            if command is None:
                fail('MODEL_ROUTE_UNAVAILABLE')
            if profile.shared_interactive and self.interactive():
                fail('INTERACTIVE_PRIORITY')
            before_contact()
            wire = library._canonical({'profile': vars(profile),
                'request': request.decode('utf-8'), 'response_limit': response_limit,
                'timeout_seconds': seconds}).encode()
            deadline = time.monotonic() + seconds
            process = subprocess.Popen(('/usr/bin/nice', '-n', '10', '--', *command),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True, close_fds=True)
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            data = bytearray()
            position = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin, selectors.EVENT_WRITE, 'input')
                selector.register(process.stdout, selectors.EVENT_READ, 'output')
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        fail('MODEL_TIMEOUT')
                    if profile.shared_interactive and self.interactive():
                        fail('INTERACTIVE_PRIORITY')
                    for key, event in selector.select(min(remaining, .02)):
                        if key.data == 'input':
                            position += os.write(key.fd, wire[position:position + 65536])
                            if position == len(wire):
                                selector.unregister(key.fileobj)
                                process.stdin.close()
                        else:
                            chunk = os.read(key.fd, min(65536, response_limit + 1 - len(data)))
                            if not chunk:
                                selector.unregister(key.fileobj)
                            else:
                                data.extend(chunk)
                                if len(data) > response_limit:
                                    fail('MODEL_RESPONSE_BOUND')
            while process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0: fail('MODEL_TIMEOUT')
                if profile.shared_interactive and self.interactive():
                    fail('INTERACTIVE_PRIORITY')
                time.sleep(min(.02, remaining))
            status = process.returncode
            if status != 0: fail('MODEL_UNAVAILABLE')
            return bytes(data)
        except library.LibraryError:
            raise
        except Exception:
            fail('MODEL_UNAVAILABLE')
        finally:
            if process is not None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait()
                for stream in (process.stdin, process.stdout):
                    if stream is not None: stream.close()
            self.lock.release()


class Dispatcher:
    """Service-only seam; never reads canonical data or edits pending work.

    selection(scope) retrieves externally authenticated live evidence; settings
    alone cannot authorize model use. current(request) must revalidate the pinned
    input/batch/source grants before contact and release. token_count is local,
    profile-bound and qualified externally. audit must persist metadata or fail.
    """
    def __init__(self, gateway, *, current_scope, settings, selection, current,
                 token_count, audit, records_path, deployment_id, now=lambda: datetime.now(timezone.utc)):
        if type(gateway) is not Gateway or not all(callable(f) for f in
                (current_scope, settings, selection, current, token_count, audit, now)):
            fail('DISPATCH_DEPENDENCY_REQUIRED')
        self.gateway, self.current_scope, self.settings = gateway, current_scope, settings
        self.selection, self.current, self.token_count = selection, current, token_count
        self.audit, self.now = audit, now
        self.records_path, self.deployment_id = records_path, deployment_id

    def dispatch(self, request):
        profile_id = None
        metadata = {}
        try:
            settings = deepcopy(library.admit_settings_value(self.settings()))
            scope = self.current_scope()
            library._require_scope(scope, 'participant', library.ENQUEUE_CAPABILITY)
            if (type(request) is not Request or type(request.encoded) is not bytes
                    or request.settings_id != settings['settings_id']
                    or request.project_identity != scope.project_identity
                    or hashlib.sha256(request.encoded).hexdigest() != request.sha256):
                fail('INVALID_MODEL_REQUEST')
            limits = settings['limits']
            if (len(request.encoded) > limits['request_bytes'] or type(request.files) is not int
                    or not 1 <= request.files <= limits['request_files']):
                fail('REQUEST_TOO_LARGE')
            payload = json.loads(request.encoded, object_pairs_hook=library._unique_pairs, parse_constant=_constant)
            if (type(payload) is not dict or set(payload) != {'version','instructions','drain_id','attempt','data','tools','network'}
                    or type(payload['version']) is not int or payload['version'] != 1 or payload['instructions'] != INSTRUCTIONS
                    or payload['tools'] != [] or payload['network'] is not False
                    or type(payload['data']) is not dict
                    or set(payload['data']) != {'drafts','concepts','indexes','excerpts'}):
                fail('INVALID_MODEL_REQUEST')
            data = payload['data']
            if (any(type(items) is not list for items in data.values())
                    or sum(len(items) for items in data.values()) != request.files
                    or type(request.selected) is not tuple
                    or any(type(d) is not dict for d in data['drafts'])
                    or tuple(d.get('queue_id') for d in data['drafts']) != request.selected):
                fail('INVALID_MODEL_REQUEST')
            for queue in request.selected:
                library._digest_value(queue, 'selected')
            if not request.selected or len(set(request.selected)) != len(request.selected):
                fail('INVALID_MODEL_REQUEST')
            library._token(payload['drain_id'], 'drain_id')
            library._integer(payload['attempt'], 'attempt')
            gate._credentials('request', request.encoded.decode(), settings['filters'], [])
            gate._decoded(payload, 'request', settings['filters'], [])
            selected = self.selection(scope)
            if type(selected) is not Selection or type(selected.profile) is not Profile:
                fail('MODEL_EVIDENCE_INVALID')
            profile = selected.profile
            profile_id = profile.identity()
            if (profile.reference != settings['model']['profile_ref']
                    or profile.placement != settings['model']['placement']):
                fail('MODEL_PROFILE_MISMATCH')
            tokens = self.token_count(profile, request.encoded)
            if type(tokens) is not int or tokens != request.tokens or not 1 <= tokens <= limits['request_tokens']:
                fail('REQUEST_TOKEN_BOUND')
            metadata = {**request.metadata(), 'profile_sha256': profile_id,
                'profile_ref': profile.reference, 'model_version': profile.version,
                'placement': profile.placement, 'drain_id': payload['drain_id'],
                'attempt': payload['attempt']}
            metadata['selected_count'] = len(metadata['selected'])
            metadata['selected_sha256'] = digest(metadata.pop('selected'))

            def fresh():
                fresh_scope = self.current_scope()
                if type(fresh_scope) is not library.LibraryScope or fresh_scope.canonical() != scope.canonical():
                    fail('LIBRARY_AUTHENTICATION_REQUIRED')
                active = library.admit_settings_value(self.settings())
                if active['settings_id'] != settings['settings_id']:
                    fail('CONFIGURATION_CHANGED')
                chosen = self.selection(fresh_scope)
                if chosen != selected:
                    fail('MODEL_EVIDENCE_CHANGED')
                now = self.now()
                if type(now) is not datetime or now.tzinfo is None:
                    fail('MODEL_CLOCK_INVALID')
                for proof, reference in ((chosen.qualification, settings['model']['qualification_ref']),
                                         (chosen.authorization, profile.reference)):
                    if type(proof) is not Evidence: fail('MODEL_EVIDENCE_INVALID')
                    proof.check(reference, profile_id, scope.project_identity, now)
                if profile.placement == 'hosted':
                    approval = library.egress_approval(active, scope.project_id)
                    if type(chosen.hosted_approval) is not Evidence: fail('EGRESS_NOT_AUTHORIZED')
                    chosen.hosted_approval.check(approval['approval_ref'], profile_id, scope.project_identity, now)
                if self.current(request) is not True:
                    fail('MODEL_INPUT_STALE')
                operation_id = 'assembly-' + digest([scope.project_identity,
                    payload['drain_id'], payload['attempt']])
                with LibraryRecords(self.records_path, self.deployment_id) as records:
                    prepared = records.record(operation_id, project_identity=scope.project_identity)
                if (prepared is None or prepared['receipt'] is None
                        or prepared['receipt']['outcome'] != 'ACKNOWLEDGED'
                        or prepared['receipt']['acknowledgement'] != request.sha256):
                    fail('MODEL_REQUEST_NOT_PREPARED')

            fresh()
            def contact():
                fresh()
                try:
                    self.audit({**metadata, 'state': 'admitted'})
                except Exception:
                    fail('DISPATCH_AUDIT_UNAVAILABLE')
                fresh()  # audit may block while permission changes
            raw = self.gateway.call(profile, request.encoded,
                response_limit=min(MAX_RESPONSE, limits['document_bytes']),
                seconds=limits['attempt_seconds'], before_contact=contact)
            fresh()
            try:
                proposal = json.loads(raw, object_pairs_hook=library._unique_pairs, parse_constant=_constant)
                if (type(proposal) is not dict or set(proposal) != {'version','drain_id','attempt','operations','outcomes'}
                        or type(proposal['version']) is not int or proposal['version'] != 1 or proposal['drain_id'] != payload['drain_id']
                        or type(proposal['attempt']) is not int or proposal['attempt'] != payload['attempt']
                        or type(proposal['operations']) is not list or type(proposal['outcomes']) is not list):
                    fail('MODEL_OUTPUT_INVALID')
            except (ValueError, UnicodeError, library.LibraryError):
                fail('MODEL_OUTPUT_INVALID')
            evidence = {**metadata, 'state': 'returned', 'response_sha256': hashlib.sha256(raw).hexdigest(),
                        'response_bytes': len(raw)}
            self.audit(evidence)
            return Result(raw, evidence)
        except library.LibraryError:
            raise
        except Exception:
            fail('DISPATCH_UNAVAILABLE')
