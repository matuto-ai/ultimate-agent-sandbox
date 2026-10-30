"""T19: one durably identified fixed-batch attempt, not a scheduler/model store."""
from copy import copy, deepcopy
from dataclasses import dataclass, replace
import hashlib
import json
import time

from . import library, library_bundle as bundle, library_compiler as compiler, library_gate as gate
from .library_assembly import Assembler
from .library_dispatch import Dispatcher
from .library_records import LibraryRecords
from . import library_deadline


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fail(code):
    raise library.LibraryError(code, 'attempt')


@dataclass(frozen=True)
class AttemptResult:
    state: str
    drain_id: str
    attempt: int
    input_sha: str
    previous_sha: str | None
    resulting_sha: str | None
    outcomes: tuple = ()


class Attempts:
    """Service-owned bounded attempt; trusted authorities are inherited from T16/T17.

    Each instance may handle concurrent callers: the SQLite contact reservation
    is exclusive across instances/processes. The shared T17 gateway still owns
    global inference serialization. No output bytes survive a process restart.
    """
    def __init__(self, assembler, dispatcher, *, clock=time.monotonic):
        if type(assembler) is not Assembler or type(dispatcher) is not Dispatcher or not callable(clock):
            fail('ATTEMPT_DEPENDENCY_REQUIRED')
        if (assembler.publisher.records_path != dispatcher.records_path
                or assembler.publisher.deployment_id != dispatcher.deployment_id):
            fail('ATTEMPT_STORE_MISMATCH')
        self.assembler, self.dispatcher, self.clock = assembler, dispatcher, clock
        self.publisher = assembler.publisher

    def records(self):
        return LibraryRecords(self.publisher.records_path, self.publisher.deployment_id)

    def operation(self, scope, settings, drain_id, attempt, at, manifest):
        identity = 'attempt-' + library._digest([scope.project_identity, drain_id, attempt])
        op = library._operation('synthesis-attempt', scope, settings, identity, identity,
            {'manifest_sha256': library._digest(manifest)}, at, drain_id=drain_id)
        return replace(op, manifest=library.synthesis_manifest(manifest))

    def _recover(self, op, settings, current):
        publication = self.publisher.publication_for(op, current=current)
        if publication is None: return None
        # A committed attempt may predate an atomic coordinate move. Its
        # metadata-only record pins the historical source prefix; current
        # authority still belongs to the same immutable Project identity.
        with self.records() as records:
            recorded = records.record(op.operation_id, project_identity=op.scope.project_identity)
        values = op.scope.canonical()
        values['capabilities'] = tuple(values['capabilities'])
        values['project_path'] = recorded['project_path']
        historical_scope = library.LibraryScope(seal=library._SCOPE_SEAL, **values)
        _, tree = self.publisher.project_snapshot_at(historical_scope, settings,
                                                     publication.resulting_sha, current=current)
        gate.validate(historical_scope, settings, proposed=tree, current=tree)
        prefix = bundle._prefix(historical_scope)
        marker = 'Library attempt receipt ' + op.operation_id + ': '
        lines = tree.files[prefix + '/log.md'].decode('utf-8').splitlines()
        matches = [line[len(marker):] for line in lines if line.startswith(marker)]
        if len(matches) != 1: fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
        try:
            value = json.loads(matches[0], object_pairs_hook=library._unique_pairs)
            if (set(value) != {'attempt', 'input_sha', 'selected', 'proposal_sha256', 'outcomes'}
                    or value['attempt'] != op.manifest['attempt']
                    or value['input_sha'] != op.manifest['input_sha']
                    or value['selected'] != op.manifest['selected']):
                fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
            library._digest_value(value['proposal_sha256'], 'proposal_sha256')
            self._outcomes(value['outcomes'], value['selected'])
        except (ValueError, KeyError, TypeError, UnicodeError):
            fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
        with self.records() as records:
            records.finish(op, library.receipt(op, 'COMMITTED', at=op.at,
                publication={'commit_sha': publication.resulting_sha, 'path': prefix + '/log.md'}))
        return AttemptResult('COMMITTED', op.drain_id, op.manifest['attempt'],
            op.manifest['input_sha'], publication.previous_sha, publication.resulting_sha,
            tuple(value['outcomes']))

    @staticmethod
    def _outcomes(values, selected):
        if type(values) is not list or len(values) != len(selected): fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
        seen = []
        for value in values:
            if type(value) is not dict: fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
            queue, kind = value.get('queue_id'), value.get('kind')
            if queue not in selected or queue in seen: fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
            seen.append(queue)
            if kind == 'parked':
                if set(value) != {'queue_id','kind','reason'}: fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
                library._token(value['reason'], 'reason')
            elif kind in ('integrated', 'merged'):
                if set(value) != {'queue_id','kind','targets'} or type(value['targets']) is not list or not value['targets']:
                    fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
                for path in value['targets']:
                    if (type(path) is not str or len(path) > 1024 or '..' in path.split('/')
                            or not path.startswith(('context/','decisions/','research/'))):
                        fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
            else: fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')
        library._reject_content({'outcomes': values})
        if len(library._canonical(values).encode()) > 262144: fail('ATTEMPT_CANONICAL_EVIDENCE_INVALID')

    def run(self, **arguments):
        if not self.publisher.synthesis_lock.acquire(blocking=False): fail("ATTEMPT_BUSY")
        try:
            seconds = self.assembler._settings()["limits"]["attempt_seconds"]
            with library_deadline.bounded(seconds): return self._run(**arguments)
        finally: self.publisher.synthesis_lock.release()

    def _run(self, *, drain_id, attempt, selected, accepted=(), indexes=(), at):
        start = self.clock()
        settings = self.assembler._settings()
        scope = self.assembler._scope()
        library._require_scope(scope, 'participant', library.ENQUEUE_CAPABILITY)
        library._token(drain_id, 'drain_id'); library._integer(attempt, 'attempt'); library._timestamp(at, 'at')
        selected, accepted, indexes = tuple(selected), tuple(accepted), tuple(indexes)
        bundle._selected(selected, settings['limits'])
        if not selected or len(set(selected)) != len(selected): fail('INVALID_BATCH')
        def authority():
            fresh = self.assembler._scope()
            if type(fresh) is not library.LibraryScope or fresh.canonical() != scope.canonical():
                fail('LIBRARY_AUTHENTICATION_REQUIRED')
            active = self.assembler._settings()
            # Operation ceilings/filter snapshot stays fixed; route/egress revocation does not.
            if any(active[key] != settings[key] for key in ('repository', 'model', 'egress')):
                fail('CONFIGURATION_CHANGED')
        def remaining():
            left = settings['limits']['attempt_seconds'] - (self.clock() - start)
            if not 0 < left <= settings['limits']['attempt_seconds']: fail('ATTEMPT_TIMEOUT')
            return left
        authority()
        # Fix the ordered batch even if source assembly parks before model work.
        batch_id = 'batch-' + library._digest([scope.project_identity, drain_id])
        with self.records() as records:
            batch = records.record(batch_id, project_identity=scope.project_identity)
            batch_settings = {**settings, 'settings_id': batch['settings_id']} if batch else settings
            batch_at = batch['at'] if batch else at
            batch_op = library._operation('synthesis-batch', scope, batch_settings, batch_id, batch_id,
                {'selected': list(selected)}, batch_at, drain_id=drain_id)
            batch_op = replace(batch_op, manifest={'selected': list(selected)})
            records.begin(batch_op)
            records.finish(batch_op, library.receipt(batch_op, 'ACKNOWLEDGED', at=batch_at,
                acknowledgement=library._digest(list(selected)), reason='BATCH_FIXED'))
        identity = 'attempt-' + library._digest([scope.project_identity, drain_id, attempt])
        with self.records() as records:
            prior_attempts = [r for r in records.drain(drain_id, project_identity=scope.project_identity)
                              if r['kind'] == 'synthesis-attempt']
        prior = None
        for record in prior_attempts:
            manifest = record['manifest']
            if tuple(manifest['selected']) != selected: fail('DRAIN_BATCH_CONFLICT')
            if manifest['attempt'] == attempt:
                if (record['at'] != at or record['settings_id'] != settings['settings_id']
                        or tuple(manifest['accepted']) != accepted or tuple(manifest['indexes']) != indexes):
                    fail('ID_CONFLICT')
            original_settings = {**settings, 'settings_id': record['settings_id']}
            op = self.operation(scope, original_settings, drain_id, manifest['attempt'], record['at'], manifest)
            recovered = self._recover(op, settings, authority)
            if recovered is not None: return recovered
            if manifest['attempt'] == attempt: prior = record
            elif manifest['attempt'] > attempt: fail('ATTEMPT_NUMBER_STALE')
        if prior is not None:
            if prior['at'] != at or prior['settings_id'] != settings['settings_id']:
                fail('ID_CONFLICT')
            if tuple(prior['manifest']['accepted']) != accepted or tuple(prior['manifest']['indexes']) != indexes:
                fail('ID_CONFLICT')
            with self.records() as records:
                contact = records.record(identity + '-contact', project_identity=scope.project_identity)
            if contact is not None: fail('NEW_ATTEMPT_REQUIRED')
        head, tree = self.publisher.project_snapshot(scope, settings, current=authority)
        if prior is not None and head != prior['manifest']['input_sha']: fail('NEW_ATTEMPT_REQUIRED')
        remaining()
        assembler = copy(self.assembler)
        assembler.settings = lambda: deepcopy(settings)
        assembler.current_scope = lambda: (authority(), scope)[1]
        assembly = assembler.assemble(input_sha=head, selected=selected, accepted=accepted,
            indexes=indexes, drain_id=drain_id, attempt=attempt, at=at)
        if assembly.request is None:
            return AttemptResult('SOURCE_PARKED', drain_id, attempt, head, None,
                                 assembly.published_sha, tuple(assembly.parked))
        request = assembly.request
        payload = json.loads(request.encoded)
        prefix = bundle._prefix(scope)
        _, _, drafts, concepts = compiler._inputs(scope, settings, tree, selected)
        paths = [prefix + '/pending/' + q + '.md' for q in selected]
        paths += [prefix + '/' + concepts[r][0] for r in accepted]
        paths += [prefix + '/' + name for name in indexes]
        inputs = [{'name_sha256': digest(path.encode()), 'bytes_sha256': digest(tree.files[path])} for path in paths]
        manifest = dict(attempt=attempt, input_sha=head, selected=list(selected), accepted=list(accepted),
            indexes=list(indexes), request_sha256=request.sha256, request_bytes=len(request.encoded),
            request_files=request.files, request_tokens=request.tokens, inputs=inputs,
            **{k: settings['limits'][k] for k in ('batch_drafts','batch_bytes','attempt_seconds')})
        op = self.operation(scope, settings, drain_id, attempt, at, manifest)
        with self.records() as records: records.begin(op)
        def fenced():
            authority(); remaining()
            latest, current_tree = self.publisher.project_snapshot(scope, settings, current=authority)
            compiler._inputs(scope, settings, current_tree, selected)
            if any(path not in current_tree.files or digest(current_tree.files[path]) != fact['bytes_sha256']
                   for path, fact in zip(paths, manifest['inputs'])):
                fail('ATTEMPT_INPUT_CHANGED')
            pending = current_tree.files[prefix + '/pending/index.md'].decode()
            if any(q + '.md)' in line and 'DRAFT PARKED:' in line
                   for q in selected for line in pending.splitlines()): fail('ATTEMPT_INPUT_CHANGED')
            recheck_sources()
            return latest, current_tree
        def recheck_sources():
            authority(); remaining()
            for excerpt in payload['data']['excerpts']:
                declaration = {'resource': excerpt['resource'], 'range': '-'.join(map(str, excerpt['range'])),
                               'sha256': excerpt['sha256']}
                resolver = self.assembler.resolve_source(scope, declaration)
                if resolver is None: fail('SOURCE_AUTHORITY_REVOKED')
                actual = resolver.resolve(scope, settings, declaration)
                if actual.content.decode('utf-8') != excerpt['document']: fail('ATTEMPT_INPUT_CHANGED')
        dispatcher = copy(self.dispatcher)
        dispatcher.settings = lambda: deepcopy(settings)
        original_current = dispatcher.current
        def current_request(value):
            if value != request or original_current(value) is not True: return False
            fenced(); return True
        dispatcher.current = current_request
        original_audit = dispatcher.audit
        def audit(event):
            authority(); remaining()
            if event['state'] == 'admitted':
                contact = library._operation('synthesis-contact', scope, settings,
                    identity + '-contact', identity + '-contact', {'request_sha256': request.sha256}, at,
                    drain_id=drain_id)
                with self.records() as records:
                    records.begin(contact, exclusive=True)
                    records.finish(contact, library.receipt(contact, 'ACKNOWLEDGED', at=at,
                        acknowledgement=request.sha256, reason='CONTACT_RESERVED'))
            original_audit(event)
        dispatcher.audit = audit
        result = dispatcher.dispatch(request, max_seconds=remaining())
        proposal = json.loads(result.proposal, object_pairs_hook=library._unique_pairs)
        if any(item.get('op') in ('update','deprecate') and item.get('target') not in accepted
               for item in proposal['operations']): fail('UNSELECTED_CONCEPT_TARGET')
        # Compatible concurrent publication is reconciliation, not another call.
        while True:
            latest, current_tree = fenced()
            compiled = compiler.compile_proposal(scope, settings, current=current_tree, selected=selected,
                input_sha=head, drain_id=drain_id, attempt=attempt, at=at, proposal=proposal)
            outcomes = [dict(value) for value in compiled.outcomes]
            for value in outcomes:
                if 'targets' in value: value['targets'] = [compiled.paths[ref] for ref in value['targets']]
            self._outcomes(outcomes, list(selected))
            evidence = dict(attempt=attempt, input_sha=head, selected=list(selected),
                            proposal_sha256=compiled.proposal_sha256, outcomes=outcomes)
            files = dict(compiled.tree.files)
            files[prefix + '/log.md'] += ('\nLibrary attempt receipt ' + identity + ': '
                                          + library._canonical(evidence) + '\n').encode()
            validated = gate.validate(scope, settings, proposed=bundle.Tree(files), current=current_tree, selected=selected)
            def publication_current():
                authority(); remaining(); recheck_sources()
            try:
                self.publisher.publish(op, validated.bundle, input_sha=latest, original_input_sha=head,
                                       current=publication_current)
                break
            except library.LibraryError as error:
                if error.code not in ('INCOMPATIBLE_HEAD', 'PUBLICATION_REJECTED'): raise
                recovered = self._recover(op, settings, authority)
                if recovered is not None: return recovered
                remaining()
        return self._recover(op, settings, authority)
