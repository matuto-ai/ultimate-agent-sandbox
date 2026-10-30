"""T22 host-local human admission and fenced scheduling acknowledgements.

Only the trusted host composes the principal resolver and service. Wire requests
cannot provide Actor/Participant identities, paths, credentials or human grants.
"""
from copy import deepcopy
import json
import hashlib
import fcntl
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import stat

from . import library, library_bundle, library_gate
from .library_records import LibraryRecords
from .library_service import Service
from .library_registration import project_state
from .local_host import peer_owner

MAX_REQUEST = 8192
MAX_RESPONSE = 16384
INSPECTION_REASONS = frozenset(('MISSING_CONTEXT', 'CONTEXT_LIMIT', 'RESPONSE_LIMIT',
    'RECURSION_NOT_EXPANDED', 'UNAVAILABLE_REFERENCE', 'INERT_RESOURCE'))


def fail(code):
    raise library.LibraryError(code, 'operator')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def content(files):
    """Version of one complete canonical Project tree, by per-file digest."""
    return library._digest({p: hashlib.sha256(data).hexdigest() for p, data in files.items()})


def decode(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST: fail('CONTROL_REQUEST_LIMIT')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: fail('INVALID_CONTROL_REQUEST')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _:fail('INVALID_CONTROL_REQUEST'))
    except (ValueError, UnicodeError, RecursionError): fail('INVALID_CONTROL_REQUEST')
    if type(value) is not dict or type(value.get('version')) is not int or value['version'] != 1:
        fail('INVALID_CONTROL_REQUEST')
    if value.get('action') in ('settings-observe','settings-update'):
        from .library_settings import decode as settings_decode
        return settings_decode(raw)
    library._identifier(value.get('project_id'), 'project_id')
    action = value.get('action')
    if action == 'observe':
        keys = {'version','action','project_id','for_action'}
        if value.get('for_action') == 'inspect': keys.add('queue_id')
        if set(value) != keys or value['for_action'] not in (
                'drain','retry','inspect','repair','archive','restore','requeue'):
            fail('INVALID_CONTROL_REQUEST')
        if 'queue_id' in value: library._digest_value(value['queue_id'], 'queue_id')
    elif action in ('reject', 'adjudicate'):
        content = ('reason',) if action == 'reject' else ('conclusion', 'rationale')
        if set(value) != {'version','action','project_id','queue_id','drain_id','request_id','settings_id','observed_version', *content}:
            fail('INVALID_CONTROL_REQUEST')
        library._digest_value(value['queue_id'], 'queue_id')
        library._token(value['request_id'], 'request_id')
        library._digest_value(value['settings_id'], 'settings_id')
        library._digest_value(value['observed_version'], 'observed_version')
        if value['drain_id'] is not None: library._token(value['drain_id'], 'drain_id')
        for key in content:
            if action == 'adjudicate' and type(value[key]) is str:
                import unicodedata
                value[key] = unicodedata.normalize('NFC', value[key].replace('\r\n', '\n').replace('\r', '\n'))
            library._text(value[key], key, MAX_REQUEST, multiline=True)
            if not value[key].strip(): fail('INVALID_TEXT')
    elif action == 'inspect':
        if set(value) != {'version','action','project_id','queue_id','request_id','settings_id','observed_version'}:
            fail('INVALID_CONTROL_REQUEST')
        library._digest_value(value['queue_id'], 'queue_id')
        library._token(value['request_id'], 'request_id')
        library._digest_value(value['settings_id'], 'settings_id')
        library._digest_value(value['observed_version'], 'observed_version')
    elif action in ('drain','retry','repair','archive','restore','requeue'):
        keys = {'version','action','project_id','request_id','settings_id','observed_version'}
        if action in ('retry','requeue'): keys.add('drain_id')
        if set(value) != keys: fail('INVALID_CONTROL_REQUEST')
        library._token(value['request_id'], 'request_id')
        library._digest_value(value['settings_id'], 'settings_id')
        library._digest_value(value['observed_version'], 'observed_version')
        # Retry may retry a pre-batch selection ticket; requeue always names the
        # drain whose recorded parked outcomes it may release.
        if action == 'retry' and value['drain_id'] is not None: library._token(value['drain_id'], 'drain_id')
        if action == 'requeue': library._token(value['drain_id'], 'drain_id')
    else: fail('UNKNOWN_CONTROL_ACTION')
    return value


class Controls:
    """Compose with an already started, host-owned Service, never a Room session.

    A transport calls handle only with its freshly authenticated LocalHuman. The
    same typed principal and version contract can be used by future trusted UI
    transports. Configuration/Project authority is rechecked under selection lock.
    """
    def __init__(self, service, *, settings_owner=None):
        if type(service) is not Service or service.scheduler is None: fail('SERVICE_NOT_STARTED')
        from .library_settings import SettingsOwner
        if settings_owner is not None and type(settings_owner) is not SettingsOwner:
            fail('LOCAL_SETTINGS_DEPENDENCY')
        self.settings_owner = settings_owner
        self.service = service

    def _entry(self, project_id):
        if self.service._closed or self.service._stop.is_set(): fail('SERVICE_NOT_AVAILABLE')
        matches = [e for e in self.service.scheduler._entries.values() if e['scope'].project_id == project_id]
        if len(matches) != 1: fail('PROJECT_UNAVAILABLE')
        return matches[0]

    def _scope(self, principal, entry, kind):
        scope = entry['scope']
        return library.local_human_scope(principal, binding=scope.canonical(), kind=kind)

    def _settings(self, entry):
        settings = library.admit_settings_value(entry['runner'].assembler._settings())
        publisher = self.service.publisher
        if settings['repository']['target'] != publisher.target or settings['repository']['branch'] != publisher.branch:
            fail('SCHEDULER_TARGET_MISMATCH')
        return settings

    def _version(self, entry, scope, settings, target):
        # Scheduling touches no content. The complete fixed batch/state and
        # current coordinates are the relevant target version, not a Git claim.
        return library._digest({'project_identity':scope.project_identity,
            'project_path':scope.project_path, 'settings_id':settings['settings_id'],
            'state':entry['state'], 'target':target})

    def _target(self, entry, scope, settings, principal, kind):
        def current():
            if (self._scope(principal,entry,kind).canonical() != scope.canonical()
                    or self._settings(entry)['settings_id'] != settings['settings_id']):
                fail('STALE_CONTROL_STATE')
        _, tree = self.service.publisher.project_snapshot(scope, settings, current=current)
        library_gate.validate(scope,settings,proposed=tree,current=tree)
        if project_state(tree,library_bundle._prefix(scope)) != 'active': fail('PROJECT_ARCHIVED')
        return content(tree.files)

    def reconcile(self, raw, principal):
        """Read-only recovery: an absent service reservation can never write.

        The scheduler RLock covers both lookup and the existing disposition
        duplicate path. That path may finish operational receipts, not republish.
        """
        value = decode(raw)
        if value['action'] not in ('reject', 'adjudicate', 'repair', 'archive', 'restore'):
            fail('INVALID_CONTROL_REQUEST')
        if value['action'] in ('archive','restore'):
            from .library_lifecycle import handle
            return handle(self, value, principal, reconcile_only=True)
        with self.service.scheduler._lock:
            entry = self._entry(value['project_id'])
            scope = self._scope(principal, entry, value['action'])
            identity = 'human-control-' + library._digest([scope.project_identity, value['request_id']])
            with self.service.scheduler._records() as records:
                prior = records.record(identity, project_identity=scope.project_identity)
            if prior is None:
                fail('CONTROL_OUTCOME_UNKNOWN')
            return self.handle(raw, principal)

    def handle(self, raw, principal):
        value = decode(raw)
        if value['action'] in ('settings-observe','settings-update'):
            if self.service._closed or self.service._stop.is_set(): fail('SERVICE_NOT_AVAILABLE')
            if self.settings_owner is None: fail('SETTINGS_UNAVAILABLE')
            return self.settings_owner.handle(raw, principal)
        scheduler = self.service.scheduler
        if value.get('for_action', value['action']) in ('archive','restore'):
            from .library_lifecycle import handle
            return handle(self, value, principal)
        with scheduler._lock:
            entry = self._entry(value['project_id'])
            kind = value.get('for_action', value['action'])
            scope = self._scope(principal, entry, kind)
            key = scope.project_identity
            # Fresh configured authority/settings; no authority inferred from UID.
            settings = self._settings(entry)
            if kind == 'repair':
                from .library_repair import handle
                return handle(self, value, principal, entry, scope, settings)
            if kind in ('reject', 'adjudicate'):
                from .library_disposition import apply
                return apply(self, value, principal, entry, scope, settings)
            if kind == 'requeue' and value['action'] == 'requeue':
                from .library_requeue import apply
                return apply(self, value, principal, entry, scope, settings)
            if kind == 'inspect':
                return self._inspect(value, principal, entry, scope, settings)
            if value['action'] == 'observe':
                scheduler._check()
                target = self._target(entry,scope,settings,principal,kind)
                return {'version':1, 'project_id':scope.project_id,
                    'settings_id':settings['settings_id'], 'observed_version':self._version(entry,scope,settings,target),
                    'state':entry['state']['state'], 'drain_id':entry['state']['drain_id']}
            operation_id = 'human-control-' + library._digest([key, value['request_id']])
            payload = {'observed_version':value['observed_version']}
            if kind == 'retry': payload['drain_id'] = value['drain_id']
            with scheduler._records() as records:
                prior = records.record(operation_id, project_identity=key)
            if prior is not None:
                original = prior['scope']
                if (prior['kind'] != kind or prior['request_id'] != value['request_id']
                        or prior['settings_id'] != value['settings_id']
                        or prior['payload_sha256'] != library._digest(payload)
                        or any(original[k] != scope.canonical()[k] for k in ('human_id','actor_id','subject','project_id','project_identity'))):
                    fail('ID_CONFLICT')
                # A current grant can read its exact historical acknowledgement;
                # it never re-applies a write against a newer schedule/config.
                if prior['receipt'] is not None: return deepcopy(prior['receipt'])
                fail('CONTROL_OUTCOME_UNKNOWN')
            scheduler._check()
            target = self._target(entry,scope,settings,principal,kind)
            if (value['settings_id'] != settings['settings_id']
                    or value['observed_version'] != self._version(entry, scope, settings, target)):
                fail('STALE_CONTROL_STATE')
            if kind == 'retry' and value['drain_id'] != entry['state']['drain_id']:
                fail('STALE_CONTROL_STATE')
            operation = library.action(scope, settings, kind=kind,
                operation_id=operation_id, request_id=value['request_id'], payload=payload,
                at=scheduler.now().isoformat())
            # Revalidate immediately before the durable transaction, while holding
            # the scheduler selection lock. The service makes no model call or Git publication.
            fresh = self._scope(principal, entry, kind)
            current = self._settings(entry)
            if fresh.canonical() != scope.canonical() or current['settings_id'] != settings['settings_id']:
                fail('STALE_CONTROL_STATE')
            return scheduler.request(key, retry=kind=='retry', control=operation)


    def _inspect(self, value, principal, entry, scope, settings):
        """One committed pending item; no body receipt, event, cache or fetch.

        Observation returns only opaque version evidence. Every open, even with
        the same request ID, reads and authorizes again. It is not write replay.
        The enclosing scheduler lock fences local lifecycle/coordinate changes.
        """
        def current():
            if (self._scope(principal, entry, 'inspect').canonical() != scope.canonical()
                    or self._settings(entry)['settings_id'] != settings['settings_id']):
                fail('STALE_INSPECTION')
            self._entry(scope.project_id)
        current()
        commit, tree = self.service.publisher.project_snapshot(scope, settings, current=current)
        library_gate.validate(scope, settings, proposed=tree, current=tree)
        prefix = library_bundle._prefix(scope)
        if project_state(tree, prefix) != 'active': fail('PROJECT_ARCHIVED')
        relative = 'pending/' + value['queue_id'] + '.md'
        data = tree.files.get(prefix + '/' + relative)
        if data is None: fail('PENDING_ITEM_UNAVAILABLE')
        text = data.decode('utf-8')
        meta, body = library_bundle.frontmatter(text, relative)
        if meta.get('status') != 'draft': fail('PENDING_ITEM_UNAVAILABLE')
        content_version = content(tree.files)
        target_version = hashlib.sha256(data).hexdigest()
        version = library._digest({'human_scope':scope.canonical(), 'project_identity':scope.project_identity,
            'project_path':scope.project_path, 'queue_id':value['queue_id'],
            'commit':commit, 'content_version':content_version, 'target_version':target_version,
            'settings_id':settings['settings_id']})
        evidence = dict(version=1, project_id=scope.project_id, queue_id=value['queue_id'],
            commit_sha=commit, target_version=target_version, content_version=content_version,
            settings_id=settings['settings_id'], observed_version=version)
        if value['action'] == 'observe':
            current()
            return evidence
        operation_id = 'human-control-' + library._digest([scope.project_identity, value['request_id']])
        payload = {'queue_id':value['queue_id'], 'observed_version':value['observed_version']}
        with self.service.scheduler._records() as records:
            prior = records.record(operation_id, project_identity=scope.project_identity)
        if prior is not None:
            original = prior['scope']
            if (prior['kind'] != 'inspect' or prior['settings_id'] != value['settings_id']
                    or prior['payload_sha256'] != library._digest(payload)
                    or any(original[k] != scope.canonical()[k] for k in ('human_id','actor_id','subject','project_id','project_identity'))):
                fail('ID_CONFLICT')
        if value['settings_id'] != settings['settings_id'] or value['observed_version'] != version:
            fail('STALE_INSPECTION')
        limits = settings['limits']
        if len(data) > limits['inspection_context_bytes']: fail('INSPECTION_CONTEXT_LIMIT')
        result = dict(evidence, request_id=value['request_id'], media_type='text/plain',
            item={'text':text, 'sha256':target_version}, context=[],
            context_bytes=len(data), insufficient_context=False, reasons=[],
            selection='direct-local-concept-references-only', recursive=False,
            remote_resources=False)
        # Bound the *complete encoded transport response*, including escaping
        # and version metadata, not just Python character count or body length.
        ceiling = min(limits['inspection_bytes'], MAX_RESPONSE)
        def fits(): return len(canonical({'outcome':'observed','result':result})) <= ceiling
        if not fits(): fail('INSPECTION_RESPONSE_LIMIT')
        references, incomplete = self._inspection_references(meta, body, relative)
        reasons = set(incomplete)
        total = len(data)
        for reference in sorted(references):
            raw = tree.files.get(prefix + '/' + reference)
            if raw is None:
                reasons.add('MISSING_CONTEXT'); continue
            if total + len(raw) > limits['inspection_context_bytes']:
                reasons.add('CONTEXT_LIMIT'); continue
            context_text = raw.decode('utf-8')
            context_meta, context_body = library_bundle.frontmatter(context_text, reference)
            nested, omitted = self._inspection_references(context_meta, context_body, reference)
            if nested: reasons.add('RECURSION_NOT_EXPANDED')
            reasons.update(omitted)
            item = dict(reference=reference, text=context_text, sha256=hashlib.sha256(raw).hexdigest())
            result['context'].append(item)
            result['context_bytes'] = total + len(raw)
            # Reserve all finite reason labels so adding the final omission
            # explanation cannot turn a valid partial response into overflow.
            result['reasons'] = sorted(INSPECTION_REASONS)
            result['insufficient_context'] = True
            if not fits():
                result['context'].pop(); result['context_bytes'] = total
                reasons.add('RESPONSE_LIMIT'); continue
            total += len(raw)
        result['reasons'] = sorted(reasons)
        result['insufficient_context'] = bool(reasons)
        if not fits(): fail('INSPECTION_RESPONSE_LIMIT')
        current()  # revoke/reconfigure during reads or serialization: disclose nothing
        operation = library.action(scope, settings, kind='inspect', operation_id=operation_id,
            request_id=value['request_id'], payload=payload,
            at=prior['at'] if prior is not None else self.service.scheduler.now().isoformat())
        with self.service.scheduler._records() as records:
            records.inspection_identity(operation)
        current()  # persistence is not authority to disclose a cached body
        return result

    @staticmethod
    def _inspection_references(meta, body, relative):
        """Service-selected direct concept edges. No arbitrary file or traversal.

        Existing canonical reader data may contain unsafe historical references;
        refuse expansion rather than render/fetch them or infer new authority.
        Other pending items, indexes, logs and sibling Projects are not context.
        """
        refs, reasons = set(), set()
        def concept(path):
            if (type(path) is str and len(path.split('/')) == 2
                    and path.split('/')[0] in library.CONCEPT_DIRECTORIES
                    and path.endswith('.md') and path.split('/')[1] != 'index.md'
                    and library.SLUG.fullmatch(path.split('/')[1][:-3])):
                refs.add(path)
            else: reasons.add('UNAVAILABLE_REFERENCE')
        for source in meta.get('sources', ()):
            concept(source.get('resource'))
        for kind, destination in library_gate.scan(body, relative, include_definitions=False):
            if kind != 'link':
                reasons.add('INERT_RESOURCE'); continue
            try: path = library_gate.destination(relative, destination)
            except library.LibraryError:
                reasons.add('UNAVAILABLE_REFERENCE'); continue
            if path is not None: concept(path)
        return refs, reasons


def private_root(root):
    root = Path(root)
    try:
        node = root.lstat()
        if (not root.is_absolute() or root.resolve() != root or not stat.S_ISDIR(node.st_mode)
                or node.st_uid != os.geteuid() or node.st_mode & 0o077): fail('LOCAL_CONTROL_ROOT_UNSAFE')
    except OSError: fail('LOCAL_CONTROL_ROOT_UNSAFE')
    return root


@contextmanager
def endpoint_lock(root):
    fd = os.open(root/'library-operator.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
    try:
        node = os.fstat(fd)
        if (not stat.S_ISREG(node.st_mode) or node.st_nlink != 1
                or node.st_uid != os.geteuid() or node.st_mode & 0o077): fail('LOCAL_CONTROL_LOCK_UNSAFE')
        try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: fail('LOCAL_CONTROL_ALREADY_ACTIVE')
        yield
    finally: os.close(fd)


def _serve(root, controls, *, authenticate, stopped):
    """Existing OS-owner boundary plus explicit current human grant resolver.

    root is trusted host configuration, never a request path; provision it
    privately before service startup. The dedicated lock permits recovery of an
    owned stale socket; live or foreign endpoints are never adopted.
    The owning Supervisor runs this loop alongside Service.run().
    """
    root = private_root(root)
    if type(controls) is not Controls or not callable(authenticate) or not callable(stopped):
        fail('LOCAL_CONTROL_DEPENDENCY')
    endpoint = root/'library-operator.sock'
    if len(os.fsencode(endpoint)) > 107: fail('LOCAL_SOCKET_PATH_TOO_LONG')
    if os.path.lexists(endpoint):
        node = endpoint.lstat()
        if not stat.S_ISSOCK(node.st_mode) or node.st_uid != os.geteuid(): fail('LOCAL_SOCKET_OWNER')
        # Dedicated interface lock excludes another thread/process even when
        # both have the same Service reference. No live endpoint is unlinked.
        endpoint.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owned = None
    try:
        listener.bind(str(endpoint))
        node = endpoint.lstat(); owned = (node.st_dev,node.st_ino)
        listener.listen(8); listener.settimeout(.1)
        while not stopped():
            try: channel,_ = listener.accept()
            except socket.timeout: continue
            with channel:
                channel.settimeout(2)
                try:
                    peer_owner(channel, os.geteuid())
                    # Read only after kernel peer admission; drain the bounded packet
                    # before human refusal so closing does not reset a queued request.
                    raw = channel.recv(MAX_REQUEST+1)
                    principal = authenticate(os.geteuid())
                    if type(principal) is not library.LocalHuman: fail('LIBRARY_AUTHENTICATION_REQUIRED')
                    result = controls.handle(raw, principal)
                    response = {'outcome':'observed','result':result}
                except Exception as error:
                    # A transport error cannot promise no scheduling effect.
                    response = {'outcome':'unknown','error':getattr(error,'code','LOCAL_CONTROL_FAILED')}
                encoded = canonical(response)
                if len(encoded) > MAX_RESPONSE: encoded = canonical({'outcome':'unknown','error':'LOCAL_RESPONSE_LIMIT'})
                try: channel.sendall(encoded)
                except OSError: pass  # retry the same ID to reconcile; no rollback claim
    finally:
        listener.close()
        if owned is not None:
            try:
                node = endpoint.lstat()
                if (node.st_dev,node.st_ino)==owned and stat.S_ISSOCK(node.st_mode): endpoint.unlink()
            except FileNotFoundError: pass


def serve(root, controls, *, authenticate, stopped):
    root = private_root(root)
    with endpoint_lock(root):
        return _serve(root, controls, authenticate=authenticate, stopped=stopped)


def request(root, value):
    """Narrow host client. Lost response raises; it never invents an outcome."""
    root = private_root(root); raw = canonical(value); decode(raw)
    endpoint = root/'library-operator.sock'
    node = endpoint.lstat()
    if not stat.S_ISSOCK(node.st_mode) or node.st_uid != os.geteuid(): fail('LOCAL_SOCKET_OWNER')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(5); channel.connect(str(endpoint)); peer_owner(channel, os.geteuid())
        channel.sendall(raw); result = channel.recv(MAX_RESPONSE+1)
        if not 0 < len(result) <= MAX_RESPONSE: fail('LOCAL_RESPONSE_LIMIT')
        return json.loads(result)
