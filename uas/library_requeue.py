"""T27: release parked work whose recorded prerequisite is resolved.

A parked draft stays pending but the pending index marks it ``DRAFT PARKED``, so
selection skips it. Requeue removes that marker only for the parked outcomes the
trusted source-failure handler recorded for that drain, and only where the
trusted source resolver now confirms the recorded prerequisite. A model-chosen
reason token is never such evidence, even when it names a source code. A model- or human-declared contradiction,
a still-unresolved source, an archived Project and a Project block are never
bypassed: scheduling state is untouched, so no drain is invented or resumed.
"""
from copy import deepcopy
import json

from . import library, library_bundle as bundle, library_gate as gate
from .library_assembly import DETERMINISTIC as PREREQUISITES
from .library_compiler import _index
from .library_controls import content
from .library_disposition import finish
from .library_sources import Excerpt, Resolver

SYNTHESIS = '* **Synthesis**: '
SOURCE_RECEIPT = 'Library source receipt '
PARKED = 'DRAFT PARKED: '
MARKER = 'Library requeue receipt '


def fail(code):
    raise library.LibraryError(code, 'requeue')


def token(value):
    """A recorded reason must still be a safe token; authored text is not one."""
    try:
        library._token(value, 'reason')
    except library.LibraryError:
        return False
    return True


def episodes(tree, prefix):
    """The newest recorded parking per queue: (drain, reason, trusted source).

    Each attempt appends one synthesis block, and the source-failure handler also
    appends a ``Library source receipt`` line after its block; the model proposal
    path never does. So that line—not a model-chosen reason token that happens to
    look like a source code—establishes that a source prerequisite parked the
    draft. Reading the log in order keeps the newest episode authoritative, so an
    already released or superseded source park cannot vouch for a later model
    park of the same queue.
    """
    newest, current, trusted = {}, None, set()
    for line in tree.files[prefix + '/log.md'].decode('utf-8').splitlines():
        if line.startswith(SYNTHESIS):
            current = line[len(SYNTHESIS):].split(';', 1)[0].strip()
            trusted = set()
            continue
        if current is None:
            continue
        if line.startswith('* '):
            queue, separator, rest = line[2:].partition(': PARKED; ')
            if separator and rest.endswith('.') and token(rest[:-1]):
                newest[queue] = (current, rest[:-1], queue in trusted)
            continue
        if not line.startswith(SOURCE_RECEIPT):
            continue
        parts = line[len(SOURCE_RECEIPT):].split(': ', 1)
        if len(parts) != 2:
            continue
        try:
            outcomes = json.loads(parts[1], object_pairs_hook=library._unique_pairs)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            continue
        if type(outcomes) is not list:
            continue
        for outcome in outcomes:
            if (type(outcome) is dict and set(outcome) == {'queue_id', 'kind', 'reason'}
                    and outcome['kind'] == 'parked' and type(outcome['queue_id']) is str
                    and library.DIGEST.fullmatch(outcome['queue_id']) is not None
                    and token(outcome['reason'])):
                trusted.add(outcome['queue_id'])
                episode = newest.get(outcome['queue_id'])
                if episode is not None and episode[0] == current and episode[1] == outcome['reason']:
                    newest[outcome['queue_id']] = (current, outcome['reason'], True)
    return newest


def parked(tree, prefix):
    """Currently parked pending queues and the reason the pending index records."""
    index = tree.files[prefix + '/pending/index.md'].decode('utf-8').splitlines()
    found = {}
    for path in tree.files:
        if not path.startswith(prefix + '/pending/') or path.endswith('/index.md'):
            continue
        queue = path[len(prefix + '/pending/'):-3]
        for line in index:
            if queue + '.md)' in line and PARKED in line:
                reason = line.split(PARKED, 1)[1].split(';', 1)[0].strip()
                if token(reason):
                    found[queue] = reason
                break
    return found


def resolves(assembler, scope, settings, tree, prefix, queue):
    """Recheck every recorded source pin through the same trusted resolver.

    Eligibility is evidence, not the recorded label: a draft with no recheckable
    pinned source, a pin that still fails deterministically, or any uncertain
    resolver outcome stays parked. Uncertainty is never permission to release,
    and it never blocks another draft that can be confirmed. The human's
    capability gates this action; a source is read, as in assembly, under the
    service's own current Project composition rather than a stored human scope.
    """
    data = tree.files.get(prefix + '/pending/' + queue + '.md')
    if data is None:
        return False
    meta, _ = bundle.frontmatter(data.decode('utf-8'), 'pending/' + queue + '.md')
    pins = [{key: item.get(key) for key in ('resource', 'range', 'sha256')}
            for item in meta.get('sources', ())
            if type(item) is dict and ('range' in item or 'sha256' in item)]
    if not pins:
        return False
    try:
        subject = assembler._scope()
        if (type(subject) is not library.LibraryScope
                or subject.project_identity != scope.project_identity):
            return False
        for declaration in pins:
            resolver = assembler.resolve_source(subject, declaration)
            if resolver is None:
                return False
            if (type(resolver) is not Resolver
                    or resolver.source.project_identity != subject.project_identity):
                return False
            excerpt = resolver.resolve(subject, settings, declaration)
            if (type(excerpt) is not Excerpt
                    or excerpt.project_identity != subject.project_identity
                    or excerpt.resource != declaration['resource']
                    or excerpt.sha256 != declaration['sha256']):
                return False
    except Exception:
        return False
    return True


def historic_operation(scope, settings, settings_id, identity, request, payload, at):
    """Re-admit the recorded request under its original settings identity.

    Current authority and configuration stay separate fences; they are not new
    identity evidence, so an unchanged historical request must still reconcile
    its pushed commit after a settings change instead of conflicting.
    """
    library._require_scope(scope, 'human', 'library-requeue')
    limits = {**settings['limits'], 'payload_bytes': 8192}
    library._human_payload('requeue', payload, limits)
    return library._operation('requeue', scope, {**settings, 'settings_id': settings_id,
        'limits': limits}, identity, request, payload, at, drain_id=payload['drain_id'])


def apply(controls, value, principal, entry, scope, settings):
    scheduler, publisher = controls.service.scheduler, controls.service.publisher

    def current():
        controls._entry(scope.project_id)
        if (controls._scope(principal, entry, 'requeue').canonical() != scope.canonical()
                or controls._settings(entry)['settings_id'] != settings['settings_id']):
            fail('STALE_CONTROL_STATE')

    current()
    payload = {key: value[key] for key in library.HUMAN_PAYLOADS['requeue'][0]}
    identity = 'human-control-' + library._digest([scope.project_identity, value['request_id']])
    with scheduler._records() as records:
        prior = records.record(identity, project_identity=scope.project_identity)
    if prior is not None:
        if (prior['kind'] != 'requeue' or prior['settings_id'] != value['settings_id']
                or prior['payload_sha256'] != library._digest(payload)
                or any(prior['scope'][key] != scope.canonical()[key] for key in
                       ('human_id', 'actor_id', 'subject', 'project_id', 'project_identity'))):
            fail('ID_CONFLICT')
        if prior['receipt'] is not None:
            return deepcopy(prior['receipt'])
        # Unknown never means permission to reapply a stale release.
        historic = dict(prior['scope'])
        historic['project_path'] = prior['project_path']
        historic['capabilities'] = tuple(historic['capabilities'])
        operation = historic_operation(library.LibraryScope(seal=library._SCOPE_SEAL, **historic),
            settings, prior['settings_id'], identity, value['request_id'], payload, prior['at'])
        publication = publisher.publication_for(operation, current=current)
        if publication is None:
            fail('CONTROL_OUTCOME_UNKNOWN')
        return finish(publisher, operation, publication)
    operation = library.action(scope, settings, kind='requeue', operation_id=identity,
        request_id=value['request_id'], payload=payload, at=scheduler.now().isoformat())
    scheduler._check()
    target = controls._target(entry, scope, settings, principal, 'requeue')
    if (value['settings_id'] != settings['settings_id']
            or value['observed_version'] != controls._version(entry, scope, settings, target)):
        fail('STALE_CONTROL_STATE')
    if not publisher.synthesis_lock.acquire(blocking=False):
        fail('CONTROL_BUSY')
    publishing = False
    try:
        head, tree = publisher.project_snapshot(scope, settings, current=current)
        if content(tree.files) != target:
            fail('STALE_CONTROL_STATE')
        prefix = bundle._prefix(scope)
        newest, currently = episodes(tree, prefix), parked(tree, prefix)
        released, retained = {}, {}
        for queue in sorted(newest):
            drain, recorded, trusted = newest[queue]
            reason = currently.get(queue)
            # Only this drain's current, trusted source park is this action's;
            # already released, superseded or differently parked work is not.
            if drain != value['drain_id'] or not trusted or reason != recorded:
                continue
            if reason not in PREREQUISITES or not resolves(
                    entry['runner'].assembler, scope, settings, tree, prefix, queue):
                retained[queue] = reason
                continue
            released[queue] = reason
        if not released:
            fail('NO_ELIGIBLE_PARKED_WORK')
        # Only an active attempt's own selected inputs are unaffected by a
        # release of work selection already excluded.
        if entry['state']['state'] == 'ACTIVE' and any(
                queue in entry['state']['selected'] for queue in released):
            fail('CONTROL_BUSY')
        files = dict(tree.files)
        files[prefix + '/pending/index.md'] = _index(tree.files[prefix + '/pending/index.md'],
            'pending', {'pending/' + queue + '.md' for queue in released}, files, prefix, {}, tree.files)
        evidence = dict(operation_id=identity, request_id=value['request_id'], at=operation.at,
            scope=scope.canonical(), settings_id=settings['settings_id'], payload=payload,
            released=[dict(queue_id=q, prerequisite=r) for q, r in sorted(released.items())],
            retained=[dict(queue_id=q, reason=r) for q, r in sorted(retained.items())])
        files[prefix + '/log.md'] += ('\n' + MARKER + library._canonical(evidence) + '\n').encode('utf-8')
        checked = gate.validate(scope, settings, proposed=bundle.Tree(files), current=tree)
        current()
        publishing = True
        publication = publisher.publish(operation, checked.bundle, input_sha=head, current=current)
        current()
        return finish(publisher, operation, publication)
    except BaseException:
        if publishing:
            scheduler._failed = True
        raise
    finally:
        publisher.synthesis_lock.release()
