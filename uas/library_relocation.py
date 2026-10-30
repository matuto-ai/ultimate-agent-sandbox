"""Atomic source-coordinate changes from trusted binding updates, never payload paths."""
from dataclasses import dataclass

from . import library, library_bundle as bundle, library_gate as gate
from .library_records import LibraryRecords
from .library_registration import project_state


@dataclass(frozen=True)
class Relocation:
    project_identity: str
    previous_path: str
    path: str
    commit_sha: str
    observed_sha: str
    created: bool
    receipt: dict


class Relocator:
    """Service consumes previous trusted binding and freshly authorized new binding.

    The Manager confirms `library-relocate`; its operation payload is empty.
    The configured source identity owner, not the user/model payload, constructs
    both scopes. Changing coordinates does not change the reference root/Project.
    """
    def __init__(self, publisher, *, previous_scope, current_scope):
        if type(previous_scope) is not library.LibraryScope or not callable(current_scope):
            raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED', 'scope')
        self.publisher, self.previous_scope, self.current_scope = publisher, previous_scope, current_scope

    def move(self, operation, settings):
        with self.publisher.registration_lock:
            return self._move(operation, settings)

    def _move(self, operation, settings):
        if type(operation) is not library.Operation or operation.kind != 'relocate':
            raise library.LibraryError('INVALID_OPERATION', 'relocation')
        settings = library.admit_settings_value(settings)
        rebuilt = library.action(operation.scope, settings, kind='relocate',
            operation_id=operation.operation_id, request_id=operation.request_id,
            payload=operation.payload, at=operation.at)
        if rebuilt != operation: raise library.LibraryError('INVALID_OPERATION', 'relocation')
        old_scope, scope = self.previous_scope, operation.scope
        old, new = bundle._prefix(old_scope), bundle._prefix(scope)
        if (old_scope.project_identity != scope.project_identity or old_scope.project_id != scope.project_id
                or old_scope.reference_root != scope.reference_root or old == new):
            raise library.LibraryError('PROJECT_MISMATCH', 'relocation')
        if (self.publisher.target != settings['repository']['target']
                or self.publisher.branch != settings['repository']['branch']):
            raise library.LibraryError('TARGET_MISMATCH', 'repository')
        def current():
            fresh = self.current_scope()
            if type(fresh) is not library.LibraryScope or fresh.canonical() != scope.canonical():
                raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED', 'scope')
            library._require_scope(fresh, 'human', 'library-relocate')
        current()
        # Coordinates are stable request metadata derived from trusted scopes,
        # not omitted from idempotency as ordinary capture coordinates are.
        op = library._operation('relocate-publication', scope, settings, operation.operation_id,
            operation.request_id, {'previous_path': old_scope.project_path,
                                   'current_path': scope.project_path}, operation.at)
        with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
            prior = records.begin(op)['record']
            if prior['receipt'] is not None and prior['receipt']['outcome'] != 'COMMITTED':
                raise library.LibraryError(prior['receipt']['reason'], 'relocation')
            publishing = [False]
            try:
                publication = self.publisher.publication_for(op, current=current)
                publishing[0] = publication is not None
                if publication is None:
                    head, before = self.publisher.project_snapshot(old_scope, settings, current=current)
                    if not before.files: raise library.LibraryError('PROJECT_NOT_REGISTERED', 'relocation')
                    gate.validate(old_scope, settings, proposed=before, current=before)
                    if project_state(before, old) == 'archived':
                        raise library.LibraryError('PROJECT_ARCHIVED', 'relocation')
                    files = {new + path[len(old):]: data for path,data in before.files.items()}
                    root = new + '/index.md'
                    lines = files[root].decode('utf-8').splitlines(keepends=True)
                    coordinates = [i for i,line in enumerate(lines) if line.strip().startswith('Source coordinates:')]
                    identities = [line for line in lines if line.strip().startswith('Source identity:')]
                    if len(coordinates) != 1 or len(identities) != 1:
                        raise library.LibraryError('INVALID_PROJECT_IDENTITY', 'relocation')
                    i = coordinates[0]
                    lines[i] = 'Source coordinates: ' + scope.project_path + '\n'
                    files[root] = ''.join(lines).encode('utf-8')
                    baseline_files = {new + p[len(old):]:d for p,d in before.files.items()}
                    baseline_files[root] = files[root]
                    baseline = bundle.Tree(baseline_files)
                    # Rewrite only service-owned coordinates; authored relative links,
                    # pending bytes, accepted documents and history remain untouched.
                    files[new + '/log.md'] += ('\n## ' + op.at[:10] + '\n* **Relocation**: '
                        + old_scope.project_path + ' -> ' + scope.project_path + '.\n').encode()
                    checked = gate.validate(scope, settings, proposed=bundle.Tree(files), current=baseline)
                    # Coordinate normalization is structural only; the changed root
                    # must still pass the same writer content policy.
                    gate._policy('index.md', files[root].decode('utf-8'), settings['filters'], [])
                    current()
                    publishing[0] = True
                    publication = self.publisher.move(op, old_scope, checked.bundle, input_sha=head, current=current)
                # A lost acknowledgement is reconciled against history; require the
                # current destination to exist and remain this same immutable Project.
                observed, tree = self.publisher.project_snapshot(scope, settings, current=current, registration=True)
                if not tree.files: raise library.LibraryError('RELOCATION_NOT_CURRENT', 'relocation')
                gate.validate(scope, settings, proposed=tree, current=tree)
                current()
                receipt = library.receipt(op, 'COMMITTED', at=op.at,
                    publication={'commit_sha': publication.resulting_sha, 'path': new})
                prior = records.record(op.operation_id, project_identity=scope.project_identity)
                if prior['receipt'] is None: records.finish(op, receipt)
                else: receipt = prior['receipt']
                return Relocation(scope.project_identity, old, new, publication.resulting_sha,
                                  observed, publication.created, receipt)
            except library.LibraryError as error:
                # Only positively known pre-publication failures become terminal.
                # Any publisher/contact/storage uncertainty remains reconcilable.
                if (not publishing[0] and prior['receipt'] is None and error.code not in
                        ('PUBLICATION_UNAVAILABLE', 'PUBLICATION_UNCERTAIN', 'GIT_UNAVAILABLE',
                         'GIT_FAILED', 'RELOCATION_NOT_CURRENT', 'NOT_READY')):
                    records.finish(op, library.receipt(op, 'REFUSED', at=op.at, reason=error.code))
                raise
