"""T06: deterministic, idempotent registration through the canonical publisher.

Only a freshly authorized human register operation enters this seam. Existing
bundles are read from one fetched canonical commit, never the working tree.
Registration has no source reader, model client, projection or restore action.
"""
from dataclasses import dataclass

from . import library, library_bundle, library_gate
from .library_records import LibraryRecords


@dataclass(frozen=True)
class Registration:
    project_identity: str
    path: str
    commit_sha: str
    observed_sha: str
    state: str
    created: bool
    receipt: dict


def project_state(tree, prefix):
    """Read the optional canonical root-body lifecycle line; absence is active.

    T06 consumes, but does not implement, archival/restoration. Their owner can
    publish this line through the same gate without adding OKF frontmatter.
    Multiple or unsupported state declarations are ambiguous and fail closed.
    """
    _, body = library_bundle.frontmatter(tree.files[prefix + '/index.md'].decode('utf-8'),
                                        'index.md')
    values = [line[len('Library state:'):].strip() for line in body.splitlines()
              if line.startswith('Library state:')]
    if len(values) > 1 or any(value not in ('active', 'archived') for value in values):
        raise library.LibraryError('INVALID_PROJECT_STATE', 'index.md')
    return values[0] if values else 'active'


def skeleton(scope, at):
    """Six deterministic files, derived only from the trusted Project binding."""
    notice = library_gate.NOTICE + '\n'
    root = ('---\nokf_version: "0.2"\n---\n\n# Project Library\n\n'
            + notice + '\nSource coordinates: ' + scope.project_path
            + '\nSource identity: ' + scope.project_identity + '\n\n'
            + ''.join('* [%s](%s/index.md)\n' % (name.title(), name)
                      for name in ('context', 'decisions', 'research', 'pending')))
    files = {'index.md': root,
             'log.md': '# Update log\n\n## ' + at[:10]
                       + '\n* **Initialization**: Created the Project bundle.\n'}
    for name in ('context', 'decisions', 'research', 'pending'):
        files[name + '/index.md'] = '# ' + name.title() + '\n\n' + notice
    prefix = 'projects/' + scope.project_path
    return library_bundle.Tree({prefix + '/' + path: value.encode('utf-8')
                                for path, value in files.items()})


class Registrar:
    """Service composition; current_scope rechecks current human authority.

    The trusted owner supplies the same admitted settings used to construct
    the canonical publisher. No caller supplies a target, path or state flag.
    A receipt says canonical publication only; projection visibility is separate.
    """
    def __init__(self, publisher, *, current_scope):
        if not callable(current_scope):
            raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED', 'scope')
        self.publisher = publisher
        self.current_scope = current_scope

    def register(self, operation, settings):
        if type(operation) is not library.Operation or operation.kind != 'register':
            raise library.LibraryError('INVALID_OPERATION', 'operation')
        admitted = library.admit_settings_value(settings)
        # Re-admit the public contract, including exact empty payload and scope.
        rebuilt = library.action(operation.scope, admitted, kind='register',
                                 operation_id=operation.operation_id,
                                 request_id=operation.request_id, payload=operation.payload,
                                 at=operation.at)
        if rebuilt != operation:
            raise library.LibraryError('INVALID_OPERATION', 'operation')
        if (self.publisher.target != admitted['repository']['target']
                or self.publisher.branch != admitted['repository']['branch']):
            raise library.LibraryError('TARGET_MISMATCH', 'repository')

        def current():
            fresh = self.current_scope()
            if (type(fresh) is not library.LibraryScope
                    or fresh.canonical() != operation.scope.canonical()):
                raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED', 'scope')
            library._require_scope(fresh, 'human', 'library-register')

        current()
        prefix = library_bundle._prefix(operation.scope)
        with LibraryRecords(self.publisher.records_path, self.publisher.deployment_id) as records:
            prior = records.begin(operation)['record']
            if prior['receipt'] is not None and prior['receipt']['outcome'] != 'COMMITTED':
                raise library.LibraryError(prior['receipt']['reason'], 'registration')
            publication_started = [False]

            def execute():
                head, tree = self.publisher.project_snapshot(operation.scope, admitted, current=current, registration=True)
                if tree.files:
                    checked = library_gate.validate(operation.scope, admitted, proposed=tree, current=tree)
                    state = project_state(tree, prefix)
                    created, sha = False, head
                else:
                    if prior['receipt'] is not None:
                        raise library.LibraryError('REGISTRATION_MISSING', 'project')
                    checked = library_gate.validate(operation.scope, admitted,
                                                     proposed=skeleton(operation.scope, operation.at))
                    state = 'active'
                    current()
                    publication_started[0] = True
                    result = self.publisher.publish(operation, checked.bundle, input_sha=None, current=current)
                    created, sha = result.created, result.resulting_sha
                    # A historical recovered operation is not proof that its
                    # bundle still exists in the current canonical tree.
                    head, confirmed = self.publisher.project_snapshot(
                        operation.scope, admitted, current=current, registration=True)
                    if not confirmed.files:
                        raise library.LibraryError('REGISTRATION_MISSING', 'project')
                    library_gate.validate(operation.scope, admitted, proposed=confirmed, current=confirmed)
                    state = project_state(confirmed, prefix)
                current()
                receipt = prior['receipt']
                if receipt is None:
                    receipt = library.receipt(operation, 'COMMITTED', at=operation.at,
                                               publication={'commit_sha': sha, 'path': prefix},
                                               reason='archived' if state == 'archived' else None)
                    records.finish(operation, receipt)
                # Existing receipts remain immutable historical evidence. Current
                # observed state is separately reported, never a silent restoration.
                return Registration(operation.scope.project_identity, prefix,
                                    receipt['publication']['commit_sha'], head,
                                    state, created, receipt)
            try:
                return execute()
            except library.LibraryError as error:
                definitely_refused = (not publication_started[0] or error.code in (
                    'INCOMPATIBLE_HEAD', 'UNSUPPORTED_PROJECT_ENTRY',
                    'PROJECT_COORDINATE_CONFLICT'))
                if definitely_refused and prior['receipt'] is None:
                    refused = library.receipt(operation, 'REFUSED', at=operation.at,
                                              reason=error.code)
                    records.finish(operation, refused)
                raise
