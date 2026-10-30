"""Explicit human-confirmed pinned-file import. No scan, model, or partial write.

Preview content is ephemeral; records store only identity, digest and receipts.
The service owns the selected GitSource/Resolver and current human authority.
A preview receipt is not confirmation. Confirmation is a distinct authorized
human operation fenced to the exact source identity and complete manifest.
"""
from copy import deepcopy
from dataclasses import dataclass, field, replace
import hashlib
import json

from . import library, library_bundle, library_gate
from .library_enqueue import _label
from .library_records import LibraryRecords
from .library_registration import project_state
from .library_sources import GitSource, Resolver, _path


@dataclass(frozen=True)
class Preview:
    preview_id: str
    source_commit: str
    repository: str = field(repr=False)
    files: tuple = field(repr=False)
    receipt: dict = field(repr=False)

    @property
    def observed_version(self):
        return self.preview_id

    @property
    def request_id(self):
        return 'import:' + self.preview_id


@dataclass(frozen=True)
class ImportResult:
    manifest_id: str
    queue_ids: tuple
    receipt: dict


class Importer:
    def __init__(self, publisher, *, resolver, current_scope):
        if (type(resolver) is not Resolver or type(resolver.source) is not GitSource
                or not callable(current_scope)):
            raise library.LibraryError('IMPORT_AUTHORITY_REQUIRED')
        self.publisher, self.resolver, self.current_scope = publisher, resolver, current_scope

    def _admit(self, operation, settings, kind):
        settings = library.admit_settings_value(settings)
        operation = replace(operation, payload=deepcopy(operation.payload), provenance=deepcopy(operation.provenance)) if type(operation) is library.Operation else operation
        if type(operation) is not library.Operation or operation.kind != kind:
            raise library.LibraryError('INVALID_OPERATION')
        fresh = library.action(operation.scope, settings, kind=kind,
            operation_id=operation.operation_id, request_id=operation.request_id,
            payload=operation.payload, at=operation.at)
        if fresh != operation:
            raise library.LibraryError('INVALID_OPERATION')
        if (self.publisher.target != settings['repository']['target']
                or self.publisher.branch != settings['repository']['branch']):
            raise library.LibraryError('TARGET_MISMATCH')
        def current():
            scope = self.current_scope(kind)
            if type(scope) is not library.LibraryScope or scope.canonical() != operation.scope.canonical():
                raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED')
            library._require_scope(scope, 'human', 'library-' + kind)
        current()
        return operation, settings, current

    def _manifest(self, operation, settings, current):
        payload, scope = operation.payload, operation.scope
        paths = payload['paths']
        if len(set(paths)) != len(paths):
            raise library.LibraryError('DUPLICATE_IMPORT_PATH')
        if len(paths) > settings['limits']['batch_drafts']:
            raise library.LibraryError('IMPORT_TOO_LARGE')
        types = payload.get('types', ['context'] * len(paths))
        files, total = [], 0
        source = self.resolver.source
        for path, intended in sorted(zip(paths, types)):
            _path(path)
            resource = 'https://' + source.repository + '/blob/' + payload['source_commit'] + '/' + path
            def allowed():
                current()
                self.resolver.authorize(scope, resource)
            allowed()
            raw, immutable = source.read(resource, settings['limits']['body_bytes'], allowed)
            if not raw:
                raise library.LibraryError('EMPTY_IMPORT_SOURCE')
            declaration = {'resource': resource, 'range': '1-' + str(len(raw.splitlines())),
                           'sha256': hashlib.sha256(raw).hexdigest()}
            excerpt = self.resolver.resolve(scope, settings, declaration)
            total += len(raw)
            if total > settings['limits']['batch_bytes']:
                raise library.LibraryError('IMPORT_TOO_LARGE')
            text = excerpt.content.decode('utf-8')
            heading = next((line[2:].strip() for line in text.splitlines() if line.startswith('# ')), None)
            title = heading or path.rsplit('/', 1)[-1]
            library._text(title, 'source.title', settings['limits']['title_chars'])
            # Bounded metadata from the same pinned history, never working tree.
            metadata = source._git(['--literal-pathspecs', 'log', '-1', '--format=%an%x00%aI', payload['source_commit'], '--', path], 4096, allowed)
            try:
                author, modified = metadata.decode('utf-8').rstrip('\n').split('\0')
                library._text(author, 'source.author', 512)
                library._timestamp(modified, 'source.modified')
            except (UnicodeError, ValueError):
                raise library.LibraryError('SOURCE_METADATA_INVALID') from None
            observations = []
            library_gate._decoded({'title': title, 'author': author, 'modified': modified},
                'source:' + hashlib.sha256(resource.encode()).hexdigest(), settings['filters'], observations)
            files.append({'observations': observations, 'path': path, 'type': intended, 'title': title, 'author': author,
                          'modified': modified, 'source': declaration, 'bytes': len(raw),
                          'content': text, 'immutable_identity': immutable})
        identity = {'project_identity': scope.project_identity, 'repository': source.repository,
                    'source_commit': payload['source_commit'],
                    'files': [{k:v for k,v in item.items() if k not in ('content', 'observations')} for item in files]}
        digest = library._digest(identity)
        current()
        return digest, files

    def _normalized(self, operation, digest, files, records, settings):
        payload = {'source_commit': operation.payload['source_commit'],
                   'paths': [item['path'] for item in files],
                   'types': [item['type'] for item in files]}
        if operation.kind == 'import-confirm':
            payload.update(preview_id=digest, observed_version=digest)
        request_id = ('preview-manifest:' if operation.kind == 'import-preview' else 'import-manifest:') + digest
        normalized = library.action(operation.scope, settings, kind=operation.kind,
            operation_id=operation.operation_id, request_id=request_id, payload=payload, at=operation.at)
        normalized = replace(normalized, kind=('import-preview-manifest' if operation.kind == 'import-preview' else 'import-publication'),
                             operation_id='manifest:' + library._digest(operation.operation_id))
        prior = records.submission(operation.scope.project_identity, request_id)
        if prior is not None:
            normalized = replace(normalized, provenance=dict(prior['origin']))
        return normalized

    def _execute(self, operation, settings, kind, callback):
        operation, settings, current = self._admit(operation, settings, kind)
        with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
            prior = records.begin(operation)['record']
            if prior['state']=='DETAIL_EXPIRED': raise library.LibraryError('DETAIL_EXPIRED')
            if prior['receipt'] is not None and prior['receipt']['outcome'] in ('REFUSED', 'NOT_DURABLE'):
                raise library.LibraryError(prior['receipt']['reason'])
            try:
                return callback(operation, settings)
            except Exception as caught:
                error = caught if isinstance(caught, library.LibraryError) else library.LibraryError('SERVICE_UNAVAILABLE')
                # An absent terminal is not absence of publication. Unknown
                # transport/storage outcomes remain explicitly retryable.
                outcome = _failure_outcome(error)
                if prior['receipt'] is None:
                    try:
                        records.finish(operation, library.receipt(operation, outcome,
                            at=operation.at, reason=error.code,
                            evidence=_failure_evidence(error)))
                    except library.LibraryError:
                        pass  # Preserve unresolved journal state; never claim absence.
                raise error from None

    def preview(self, operation, settings):
        return self._execute(operation, settings, 'import-preview', self._preview)

    def confirm(self, operation, settings):
        return self._execute(operation, settings, 'import-confirm', self._confirm)

    def _preview(self, operation, settings):
        operation, settings, current = self._admit(operation, settings, 'import-preview')
        digest, files = self._manifest(operation, settings, current)
        # The metadata ACK is the durable evidence that this manifest was prepared.
        with self.publisher.registration_lock:
            with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
                records.begin(operation)  # Preserve exact caller Command/request identity.
                op = self._normalized(operation, digest, files, records, settings)
                prior = records.begin(op)['record']
                try:
                    current()
                    receipt = prior['receipt'] or library.receipt(op, 'ACKNOWLEDGED', at=op.at,
                                                                  acknowledgement=digest)
                    records.finish(op, receipt)
                    receipt = library.receipt(operation, 'ACKNOWLEDGED', at=operation.at, acknowledgement=digest)
                    records.finish(operation, receipt)
                except Exception as caught:
                    error = caught if isinstance(caught, library.LibraryError) else library.LibraryError('SERVICE_UNAVAILABLE')
                    if prior['receipt'] is None:
                        try:
                            records.finish(op, library.receipt(op, _failure_outcome(error), at=op.at,
                                reason=error.code, evidence=_failure_evidence(error)))
                        except library.LibraryError:
                            pass
                    raise error from None
        # Public manifest deliberately includes chosen paths, source metadata and
        # hashes for human inspection, but never full file bodies.
        shown = tuple({k:v for k,v in item.items() if k not in ('content', 'observations')} for item in files)
        return Preview(digest, operation.payload['source_commit'], self.resolver.source.repository,
                       shown, receipt)

    def _confirm(self, operation, settings):
        operation, settings, current = self._admit(operation, settings, 'import-confirm')
        digest, files = self._manifest(operation, settings, current)
        if (operation.payload['preview_id'] != digest
                or operation.payload['observed_version'] != digest):
            raise library.LibraryError('STALE_IMPORT_MANIFEST')
        with self.publisher.registration_lock:
            with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
                shown = records.submission(operation.scope.project_identity, 'preview-manifest:' + digest)
                if shown is None or not any(item['receipt'] is not None
                        and item['receipt']['outcome'] == 'ACKNOWLEDGED'
                        and item['receipt']['acknowledgement'] == digest for item in shown['attempts']):
                    raise library.LibraryError('IMPORT_PREVIEW_REQUIRED')
                records.begin(operation)  # Preserve exact caller Command/request identity.
                op = self._normalized(operation, digest, files, records, settings)
                prior = records.begin(op)['record']
                publication_started = False
                try:
                    queue_ids = tuple(library._digest({'manifest': digest, 'path': item['path']}) for item in files)
                    def authorized():
                        current()
                        for item in files:
                            self.resolver.authorize(op.scope, item['source']['resource'])
                    authorized()
                    evidence = []
                    publication = self.publisher.publication_for(op, current=authorized)
                    if publication is None:
                        head, tree = self.publisher.project_snapshot(op.scope, settings, current=authorized)
                        prefix = library_bundle._prefix(op.scope)
                        library_gate.validate(op.scope, settings, proposed=tree, current=tree)
                        if project_state(tree, prefix) == 'archived':
                            raise library.LibraryError('PROJECT_ARCHIVED')
                        proposed = dict(tree.files)
                        for item, queue_id in zip(files, queue_ids):
                            path = library.queue_path(op.scope.project_path, queue_id)
                            if path in proposed:
                                raise library.LibraryError('QUEUE_PATH_CONFLICT')
                            proposed[path] = _draft(op, item, queue_id)
                            proposed[prefix + '/pending/index.md'] += ('\n* [' + _label(item['title']) + ']('
                                + queue_id + '.md) - DRAFT.\n').encode('utf-8')
                        proposed[prefix + '/log.md'] += ('\n## ' + op.provenance['at'][:10]
                            + '\n* **Import**: Confirmed manifest ' + digest + ' (' + str(len(files))
                            + ' pending drafts).\n').encode('utf-8')
                        checked = library_gate.validate(op.scope, settings,
                            proposed=library_bundle.Tree(proposed), current=tree)
                        evidence = list(checked.observations)
                        for item in files:
                            library_gate._record(evidence, item['observations'])
                        library.receipt(op, 'NOT_DURABLE', at=op.at, reason='VALIDATING', evidence=evidence)
                        authorized()
                        publication_started = True
                        publication = self.publisher.publish(op, checked.bundle, input_sha=head, current=authorized)
                    if not evidence:
                        for item in files:
                            library_gate._record(evidence, item['observations'])
                        for item, queue_id in zip(files, queue_ids):
                            text = _draft(op, item, queue_id).decode('utf-8')
                            meta, _ = library_bundle.frontmatter(text, 'pending')
                            relative = 'pending/' + queue_id + '.md'
                            filters = {'high_confidence': 'observe', 'heuristic': 'observe'}
                            library_gate._credentials(relative, text, filters, evidence)
                            library_gate._decoded(meta, relative + '.metadata', filters, evidence)
                    authorized()
                    receipt = prior['receipt'] or library.receipt(op, 'COMMITTED', at=op.at,
                        publication={'commit_sha': publication.resulting_sha,
                                     'path': library_bundle._prefix(op.scope) + '/pending'}, evidence=evidence)
                    records.finish(op, receipt)
                    receipt = library.receipt(operation, 'COMMITTED', at=operation.at, publication=receipt['publication'], evidence=receipt.get('evidence'))
                    records.finish(operation, receipt)
                    return ImportResult(digest, queue_ids, receipt)
                except Exception as caught:
                    error = caught if isinstance(caught, library.LibraryError) else library.LibraryError('SERVICE_UNAVAILABLE')
                    if publication_started and error.code not in ('PUBLICATION_UNAVAILABLE', 'PUBLICATION_UNCERTAIN', 'INCOMPATIBLE_HEAD', 'PUBLICATION_REJECTED'):
                        error = library.LibraryError('PUBLICATION_UNCERTAIN')
                    if prior['receipt'] is None:
                        try:
                            records.finish(op, library.receipt(op, _failure_outcome(error),
                                at=op.at, reason=error.code, evidence=_failure_evidence(error)))
                        except library.LibraryError:
                            pass
                    raise error from None



def _draft(operation, item, queue_id):
    source = dict(item['source'], title=item['title'])
    lines = ['---', 'type: ' + json.dumps(item['type']), 'title: ' + json.dumps(item['title']),
             'status: draft', 'generated: true', 'sources:', '  - resource: ' + json.dumps(source.pop('resource'))]
    lines += ['    ' + key + ': ' + json.dumps(value) for key,value in source.items()]
    lines += ['---', '', library_gate.NOTICE, '', 'Submission Actor: ' + operation.provenance['actor_id'],
              'Submission time: ' + operation.provenance['at'], 'Queue identity: ' + queue_id,
              'Source author: ' + _label(item['author']), 'Source modification time: ' + item['modified'],
              '', item['content']]
    return ('\n'.join(lines).rstrip('\n') + '\n').encode('utf-8')


def _failure_evidence(error):
    value = error.evidence
    if type(value) is not dict:
        return None
    if set(value) == {'rule', 'path', 'line', 'sha256'}:
        return [value]
    if set(value) == {'source_ref_sha256', 'range', 'sha256'}:
        return [{'rule': error.code, 'path': 'source:' + value['source_ref_sha256'],
                 'line': value['range'][0], 'sha256': value['sha256']}]
    return None


def _failure_outcome(error):
    return 'NOT_DURABLE' if error.code in (
        'PUBLICATION_UNAVAILABLE', 'PUBLICATION_UNCERTAIN', 'PUBLICATION_REJECTED',
        'INCOMPATIBLE_HEAD', 'GIT_UNAVAILABLE', 'GIT_FAILED', 'SOURCE_UNAVAILABLE',
        'SOURCE_AUTHORITY_UNAVAILABLE', 'RECORD_UNCERTAIN', 'SERVICE_UNAVAILABLE') else 'REFUSED'
