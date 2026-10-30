"""Explicit service capture: canonical Git durability, separate projection evidence.

The trusted service supplies current Participant authority and optional originating
Run from its authenticated request context. No caller path, frontmatter, lifecycle
hook, transcript scanner, model invocation or alternate content queue exists here.
"""
from dataclasses import dataclass, replace
import json
import re

from . import library, library_bundle, library_gate
from .library_records import LibraryRecords
from .library_registration import project_state


@dataclass(frozen=True)
class CaptureResult:
    outcome: str
    request_id: str | None
    reason: str | None
    retryable: bool
    queue_id: str | None = None
    path: str | None = None  # bundle-relative; never a caller-selected path
    published_sha: str | None = None
    projection_sha: str | None = None
    visible: bool = False


def _label(value):
    return re.sub(r'([\\`*_{}\[\]()<>!#|])', r'\\\1', value)


def draft(operation):
    """Deterministic OKF writer; JSON quoting is a strict YAML scalar subset."""
    payload, origin = operation.payload, operation.provenance
    lines = ['---', 'type: ' + json.dumps(payload['type']),
             'title: ' + json.dumps(payload['title'], ensure_ascii=False),
             'status: draft', 'generated: true']
    if payload['sources']:
        lines.append('sources:')
        for source in payload['sources']:
            lines.append('  - resource: ' + json.dumps(source['resource'], ensure_ascii=False))
            if 'title' in source:
                lines.append('    title: ' + json.dumps(source['title'], ensure_ascii=False))
    lines.extend(['---', '', library_gate.NOTICE, '',
                  'Submission Actor: ' + origin['actor_id'],
                  'Submission time: ' + origin['at'],
                  'Queue identity: ' + operation.queue_id])
    if 'run_id' in origin:
        lines.append('Originating Run: ' + origin['run_id'])
    lines.extend(['', payload['body']])
    if payload['hints']:
        lines.extend(['', '## Submitted relationship hints', ''])
        lines.extend('* ' + _label(hint) for hint in payload['hints'])
    return ('\n'.join(lines).rstrip('\n') + '\n').encode('utf-8')


class Enqueuer:
    """One explicit service surface, composed with T02/T03/T05/T07.

    current_scope/current_run are trusted authenticated-context readers, not
    payload fields. The caller supplies only the bounded capture and IDs; the
    Hub layer separately owns origin-bound Command replay. projection, if set,
    is the already-bound ProjectProjection, never an arbitrary requested root.
    """
    def __init__(self, publisher, *, current_scope, current_run=lambda: None,
                 projection=None):
        if not callable(current_scope) or not callable(current_run):
            raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED', 'scope')
        self.publisher = publisher
        self.current_scope = current_scope
        self.current_run = current_run
        self.projection = projection

    def enqueue(self, settings, *, operation_id, request_id, value, at):
        # Invalid opaque IDs are not reflected into diagnostics.
        safe_id = request_id if type(request_id) is str and library.TOKEN.fullmatch(request_id) else None
        operation = None
        phase = 'dependency'
        records = None
        begun = False
        evidence = []
        with self.publisher.registration_lock:
            try:
                admitted = library.admit_settings_value(settings)
                scope = self.current_scope()
                library._require_scope(scope, 'participant', library.ENQUEUE_CAPABILITY)
                run_id = self.current_run()
                phase = 'admission'
                operation = library.capture(scope, admitted, operation_id=operation_id,
                                            request_id=request_id, value=value, at=at,
                                            run_id=run_id)
                phase = 'dependency'
                if (self.publisher.target != admitted['repository']['target']
                        or self.publisher.branch != admitted['repository']['branch']):
                    raise library.LibraryError('TARGET_MISMATCH', 'repository')

                def current():
                    fresh = self.current_scope()
                    if (type(fresh) is not library.LibraryScope
                            or fresh.canonical() != scope.canonical()):
                        raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED', 'scope')
                    library._require_scope(fresh, 'participant', library.ENQUEUE_CAPABILITY)

                current()
                phase = 'records'
                records = LibraryRecords(self.publisher.records_path, self.publisher.deployment_id)
                submission = records.submission(scope.project_identity, request_id)
                if submission is not None:
                    if submission['origin']['payload_sha256'] != operation.digest():
                        raise library.LibraryError('ID_CONFLICT', 'request_id')
                    # First provenance is authoritative, never re-derived from a retry.
                    operation = replace(operation, provenance=dict(submission['origin']))
                prior = records.begin(operation)['record']
                begun = True
                if prior['receipt'] is not None:
                    return self._from_receipt(prior['receipt'], operation)
                # A deterministic refusal binds the librarian request, even when
                # retried using a fresh Hub Command ID.
                if submission is not None:
                    refused = next((item['receipt'] for item in submission['attempts']
                                    if item['receipt'] is not None
                                    and item['receipt']['outcome'] == 'REJECTED'
                                    and item['receipt']['reason'] not in ('FORBIDDEN', 'LIBRARY_AUTHENTICATION_REQUIRED')), None)
                    if refused is not None:
                        receipt = library.receipt(operation, 'REJECTED', at=at,
                                                  reason=refused['reason'], evidence=refused.get('evidence'))
                        records.finish(operation, receipt)
                        return self._from_receipt(receipt, operation)
                evidence = []
                phase = 'canonical'
                # Before repeating any write, reconcile T03 even when the prior
                # attempt ended NOT_DURABLE or crashed without a terminal receipt.
                publication = self.publisher.publication_for(operation, current=current)
                if publication is None:
                    head, tree = self.publisher.project_snapshot(scope, admitted, current=current)
                    phase = 'gate'
                    prefix = library_bundle._prefix(scope)
                    if not tree.files:
                        raise library.LibraryError('PROJECT_NOT_REGISTERED', 'project')
                    library_gate.validate(scope, admitted, proposed=tree, current=tree)
                    if project_state(tree, prefix) == 'archived':
                        raise library.LibraryError('PROJECT_ARCHIVED', 'project')
                    if not operation.payload['body'].strip():
                        raise library.LibraryError('EMPTY_BODY', 'capture.body')
                    if re.match(r'\A---\n.*?\n---(?:\n|$)', operation.payload['body'].lstrip(), re.S):
                        raise library.LibraryError('RAW_FRONTMATTER', 'capture.body')
                    path = library.queue_path(scope.project_path, operation.queue_id)
                    if path in tree.files:
                        raise library.LibraryError('QUEUE_PATH_CONFLICT', 'pending')
                    files = dict(tree.files)
                    files[path] = draft(operation)
                    entry = ('\n* [' + _label(operation.payload['title']) + ']('
                             + operation.queue_id + '.md) - DRAFT.\n')
                    files[prefix + '/pending/index.md'] += entry.encode('utf-8')
                    files[prefix + '/log.md'] += ('\n## ' + operation.provenance['at'][:10]
                        + '\n* **Capture**: Queued [' + operation.queue_id + '](pending/'
                        + operation.queue_id + '.md).\n').encode('utf-8')
                    checked = library_gate.validate(scope, admitted,
                               proposed=library_bundle.Tree(files), current=tree)
                    evidence = list(checked.observations)
                    # Check the metadata receipt bound before publishing content.
                    library.receipt(operation, 'NOT_DURABLE', at=at,
                                    reason='VALIDATING', evidence=evidence)
                    phase = 'publication'
                    publication = self.publisher.publish(operation, checked.bundle,
                                                         input_sha=head, current=current)
                if not evidence:
                    # Recover safe findings from the exact original draft even
                    # after a crash before its receipt. This is observation-only;
                    # a changed blocking policy cannot revoke historical durability.
                    text = draft(operation).decode('utf-8')
                    meta, _ = library_bundle.frontmatter(text, 'pending')
                    filters = {'high_confidence': 'observe', 'heuristic': 'observe'}
                    relative = 'pending/' + operation.queue_id + '.md'
                    library_gate._credentials(relative, text, filters, evidence)
                    library_gate._decoded(meta, relative + '.metadata', filters, evidence)
                current()
                phase = 'records'
                projected = self._projection(operation)
                receipt = library.receipt(operation, 'DURABLY_QUEUED', at=at,
                    publication={'commit_sha': publication.resulting_sha,
                                 'path': library.queue_path(scope.project_path, operation.queue_id)},
                    projection=projected, evidence=evidence)
                records.finish(operation, receipt)
                return self._from_receipt(receipt, operation)
            except library.LibraryError as error:
                # A stale basis is a publication retry, not an invalid capture.
                deterministic = (phase in ('admission', 'gate') or error.code in
                                 ('ID_CONFLICT', 'FORBIDDEN', 'LIBRARY_AUTHENTICATION_REQUIRED'))
                outcome = 'REJECTED' if deterministic else 'NOT_DURABLE'
                if begun:
                    try:
                        receipt = library.receipt(operation, outcome, at=at, reason=error.code,
                                                  evidence=[error.evidence] if error.evidence else evidence)
                        records.finish(operation, receipt)
                    except library.LibraryError:
                        outcome = 'NOT_DURABLE'
                        error = library.LibraryError('RECORD_UNCERTAIN')
                return CaptureResult(outcome, safe_id, error.code, outcome == 'NOT_DURABLE',
                                     operation.queue_id if operation else None)
            except Exception:
                if begun:
                    try:
                        records.finish(operation, library.receipt(operation, 'NOT_DURABLE',
                                       at=at, reason='SERVICE_UNAVAILABLE', evidence=evidence))
                    except Exception:
                        pass
                # No exception text, submitted body or credentials in diagnostics.
                return CaptureResult('NOT_DURABLE', safe_id, 'SERVICE_UNAVAILABLE', True,
                                     operation.queue_id if operation else None)
            finally:
                if records is not None:
                    records.close()

    def _projection(self, operation):
        unknown = {'commit_sha': None, 'visible': False}
        if self.projection is None:
            return unknown
        try:
            snapshot = self.projection.read()
            manifest = snapshot.manifest
            if (manifest['project_id'] != operation.scope.project_id
                    or manifest['project_identity'] != operation.scope.project_identity):
                return unknown
            path = 'pending/' + operation.queue_id + '.md'
            return {'commit_sha': manifest['commit_sha'],
                    'visible': snapshot.files.get(path) == draft(operation)}
        except Exception:
            return unknown

    def _from_receipt(self, receipt, operation):
        publication = receipt['publication']
        projection = self._projection(operation) if publication else {'commit_sha': None, 'visible': False}
        return CaptureResult(receipt['outcome'], receipt['request_id'], receipt['reason'],
                             receipt['retryable'], receipt['queue_id'],
                             'pending/' + operation.queue_id + '.md' if publication else None,
                             publication['commit_sha'] if publication else None,
                             projection['commit_sha'], projection['visible'])


class EnqueueEndpoint:
    """External service-side composition for an authenticated Hub client.

    Transport authentication/provisioning must already bind this endpoint to the
    trusted Hub. Participant payloads cannot call it or supply scope/current.
    The service retains clone/settings ownership; the Hub receives only contact.
    """
    def __init__(self, publisher, *, settings, projection=None):
        if not callable(settings):
            raise library.LibraryError('INVALID_SETTINGS', 'settings')
        self.publisher, self.settings, self.projection = publisher, settings, projection

    def contact(self, *, scope, current, operation_id, request_id, value, at, run_id):
        def fresh():
            if current() is not True:
                raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED', 'scope')
            return scope
        return Enqueuer(self.publisher, current_scope=fresh, current_run=lambda: run_id,
                        projection=self.projection).enqueue(self.settings(), operation_id=operation_id,
                        request_id=request_id, value=value, at=at)
