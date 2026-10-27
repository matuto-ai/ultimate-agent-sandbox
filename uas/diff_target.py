"""Supervisor-owned exact base/head target pair, with independent measured leases.

The authenticated Hub supplies its Broker-verified subject. A checkout HEAD is
only an ownership/freshness observation; it can never supply a missing base.
No caller-selected path, Git expression, checkout command or network is used.
"""
from copy import deepcopy
import hashlib
import os
import threading

from .artifact_protocol import ArtifactError, RESERVATION_BYTES, canonical, validate_scope
from .artifact_target import (ArtifactTargets, MAX_RESOURCE_RECORDS, _open_dir, _names,
    _identity, _read_at)
from .diff_protocol import (PROFILE_ID, artifact_source, source_binding,
                           validate_diff_source, validate_diff_target)

DIFF_RESERVATION_BYTES = 2 * RESERVATION_BYTES


class DiffSourceResolver:
    def __init__(self, resolver):
        self.resolver = resolver
        self.repo = resolver.repo

    def resolve(self, run_id, participant_id, room_instance, subject):
        # subject is delivered solely on the authenticated private Hub control
        # channel, never from Participant argv, declaration, prose or checkout.
        from .gate_forge import validate_forge_target
        from .ledger import LedgerError
        try:
            subject = validate_forge_target(subject)
        except LedgerError as error:
            raise ArtifactError('INVALID_DIFF_SUBJECT') from error
        source = self.resolver.resolve(run_id, participant_id, room_instance)
        result = {**source, 'profile': PROFILE_ID, 'subject': deepcopy(subject),
                  'binding_digest': source_binding(source, subject)}
        return validate_diff_source(result, require_head=True)

    def current(self, source):
        validate_diff_source(source)
        current = self.resolver.current(artifact_source(source))
        result = {**current, 'profile': PROFILE_ID, 'subject': deepcopy(source['subject']),
                  'binding_digest': source_binding(current, source['subject'])}
        # The exact requested subject remains historical. The Hub refreshes the
        # Broker subject separately; a new owned HEAD is staleness, not authority
        # to silently replace either requested revision.
        return validate_diff_source(result)

    def recheck(self, source):
        validate_diff_source(source, require_head=True)
        if self.current(source) != source:
            raise ArtifactError('DIFF_SOURCE_CHANGED')
        return deepcopy(source)


def _child_scope(scope, side):
    result = dict(scope)
    result['evaluation_id'] = 'diff-' + side + '-' + hashlib.sha256(
        scope['evaluation_id'].encode()).hexdigest()
    return result


class DiffTargetLease:
    def __init__(self, owner, scope, source):
        self.owner, self.scope, self.source = owner, dict(scope), deepcopy(source)
        self.target = None
        self.launch_possible = False

    def _leases(self):
        return [self.owner._trees.owned.get(_child_scope(self.scope, side)['evaluation_id'])
                for side in ('base', 'head')]

    def document(self):
        if self.target is None:
            raise ArtifactError('DIFF_TARGET_NOT_PREPARED')
        return deepcopy(self.target)

    def recheck(self):
        self.owner.resolver.recheck(self.source)
        self.postverify()
        return True

    def recheck_binding(self):
        self.owner.resolver.current(self.source)
        return True

    def postverify(self):
        document = self.document()
        for side, lease in zip(('base', 'head'), self._leases()):
            if lease is None or lease.postverify() != document[side]:
                raise ArtifactError('DIFF_TARGET_CHANGED')
        return document

    def mark_launch_possible(self):
        if self.launch_possible or self.target is None:
            raise ArtifactError('DIFF_LAUNCH_REPLAY')
        # Fence the pair before either durable child transition. An uncertain
        # second transition never permits cleanup or retry of the first.
        self.launch_possible = True
        for lease in self._leases():
            lease.mark_launch_possible()

    def mark_exit_confirmed(self):
        if not self.launch_possible:
            raise ArtifactError('DIFF_NO_LIVE_LAUNCH')
        for lease in self._leases():
            lease.mark_exit_confirmed()

    def cleanup(self):
        failure = None
        for side, lease in zip(('base', 'head'), self._leases()):
            try:
                if lease is None:
                    # Artifact preparation writes exclusive intent before any
                    # scratch effect. Missing live owner plus existing intent
                    # is never reconstructed as cleanup authority.
                    evaluation = _child_scope(self.scope, side)['evaluation_id']
                    if os.path.lexists(self.owner._trees._journal(evaluation)):
                        raise ArtifactError('DIFF_TARGET_OWNERSHIP_UNKNOWN')
                elif lease.cleanup() is not True:
                    raise ArtifactError('DIFF_CLEANUP_FAILED')
            except BaseException as error:
                failure = failure or error
        if failure is not None:
            raise failure
        return True


class DiffTargets:
    """Two 32-MiB child reservations admitted atomically as one 64-MiB pair.

    Every child keeps its independent durable ownership journal, measurement,
    process-exit fence and identity-checked cleanup. Restart never adopts these
    records. Both lifetime records count, including a failed partial pair.
    """
    def __init__(self, root, journal_root, resolver, *, reserve_capacity):
        if type(resolver) is not DiffSourceResolver or not callable(reserve_capacity):
            raise ArtifactError('TRUSTED_DIFF_TARGETS_REQUIRED')
        self.resolver, self.reserve_capacity = resolver, reserve_capacity
        self._lock, self.owned, self._admission = threading.RLock(), {}, None
        self._trees = ArtifactTargets(root, journal_root, resolver.resolver,
                                      reserve_capacity=self._reserved_child)

    def _reserved_child(self, scope, amount):
        return (self._admission is not None and amount == RESERVATION_BYTES
                and scope in self._admission)

    def prepare(self, scope, source):
        with self._lock:
            validate_scope(scope); validate_diff_source(source, require_head=True)
            if any(scope[key] != source[key] for key in
                    ('room_instance', 'project_id', 'repository', 'run_id', 'participant_id')):
                raise ArtifactError('DIFF_SCOPE_SOURCE_MISMATCH')
            evaluation = scope['evaluation_id']
            children = [_child_scope(scope, side) for side in ('base', 'head')]
            if (evaluation in self.owned or any(os.path.lexists(
                    self._trees._journal(child['evaluation_id'])) for child in children)):
                raise ArtifactError('DIFF_PREPARATION_REPLAY')
            self.resolver.recheck(source)
            journal = _open_dir(self._trees.journal_root)
            try:
                if _identity(os.fstat(journal)) != self._trees.journal_identity:
                    raise ArtifactError('ARTIFACT_JOURNAL_OWNERSHIP')
                names = _names(journal, MAX_RESOURCE_RECORDS)
                if len(names) + 2 > MAX_RESOURCE_RECORDS:
                    raise ArtifactError('DIFF_RESOURCE_RECORD_LIMIT')
                for name in names:
                    _read_at(journal, name, 8192)
            finally:
                os.close(journal)
            root = _open_dir(self._trees.root)
            try:
                fs = os.fstatvfs(root)
                if (_identity(os.fstat(root)) != self._trees.root_identity
                        or fs.f_frsize > 4096 or fs.f_bsize > 4096
                        or fs.f_bavail * fs.f_frsize < DIFF_RESERVATION_BYTES):
                    raise ArtifactError('DIFF_SCRATCH_CAPACITY_UNAVAILABLE')
            finally:
                os.close(root)
            if self.reserve_capacity(scope, DIFF_RESERVATION_BYTES) is not True:
                raise ArtifactError('DIFF_ROOM_CAPACITY_UNAVAILABLE')
            lease = DiffTargetLease(self, scope, source)
            self.owned[evaluation] = lease  # retain partial and failed attempts
            self._admission = children
            try:
                targets = {}
                for side, child in zip(('base', 'head'), children):
                    self.resolver.recheck(source)
                    with self._trees._lock:
                        targets[side] = self._trees._prepare(child, artifact_source(source),
                            revision=source['subject'][side + '_sha'])
                self.resolver.recheck(source)
                lease.target = validate_diff_target({'version': 1, 'profile': PROFILE_ID,
                    'source_digest': source['binding_digest'], 'subject': deepcopy(source['subject']),
                    **targets})
                return lease.document()
            finally:
                self._admission = None

    def lease(self, target):
        validate_diff_target(target)
        matches = [lease for lease in self.owned.values() if lease.target == target]
        if len(matches) != 1:
            raise ArtifactError('DIFF_TARGET_NOT_OWNED')
        return matches[0]

    def verify(self, target):
        return self.lease(target).postverify()

    def cleanup(self, target):
        return self.lease(target).cleanup()

    def reconcile(self, evaluation_id):
        with self._lock:
            reference = 'diff-quarantine:' + hashlib.sha256(evaluation_id.encode()).hexdigest()
            lease = self.owned.get(evaluation_id)
            if lease is None or lease.launch_possible:
                return {'cleanup': False, 'quarantine_ref': reference}
            try:
                removed = lease.cleanup()
            except (ArtifactError, OSError):
                return {'cleanup': False, 'quarantine_ref': reference}
            return {'cleanup': removed is True, 'quarantine_ref': None if removed is True else reference}
