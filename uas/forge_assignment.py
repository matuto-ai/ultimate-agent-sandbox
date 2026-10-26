"""Opt-in single-effect broker extension; durable Forge audit owns mutation truth."""
import hashlib

from .github_assignment import GitHubAssignmentProvider, assignment_result
from .github_read import parse_assignment_route, _positive
from .ledger import LedgerError, Origin, _json, _token


class AssignmentBroker:
    def __init__(self, binding, audit, actor_user_ids, provider_for_actor):
        from .forge_audit import ForgeAudit
        if (type(audit) is not ForgeAudit or type(actor_user_ids) is not dict
                or not actor_user_ids or not callable(provider_for_actor)):
            raise LedgerError('INVALID_ASSIGNMENT_BROKER')
        for actor, user_id in actor_user_ids.items():
            _token(actor)
            if not _positive(user_id):
                raise LedgerError('INVALID_ASSIGNMENT_BROKER')
        self.binding, self.audit = binding, audit
        self.actor_user_ids, self.provider_for_actor = dict(actor_user_ids), provider_for_actor
        self.failed = False

    def _authorize(self, origin, authorize):
        if self.failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        if (authorize() is not True or 'forge-write' not in origin.capabilities
                or origin.actor_id not in self.actor_user_ids):
            raise LedgerError('FORBIDDEN')
        origin.canonical()

    def _audit(self, method, *args):
        try:
            return getattr(self.audit, method)(*args)
        except LedgerError as error:
            if error.code == 'AUDIT_UNAVAILABLE':
                self.failed = True
            raise

    def _key(self, operation):
        return 'assignment-' + hashlib.sha256((self.binding.room_id + '\0' + _token(operation)).encode()).hexdigest()

    def prepare(self, envelope, *, origin, authorize):
        self._authorize(origin, authorize)
        if (type(envelope) is not dict or set(envelope) != {'id', 'kind', 'argv'}
                or envelope['kind'] != 'forge-write'):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        route = parse_assignment_route(envelope['argv'], self._project())
        operation = _token(envelope['id'])
        metadata = {'room_id': self.binding.room_id, 'project_id': self.binding.project_id,
            'repository': self.binding.repository, 'actor_id': origin.actor_id,
            'participant_id': origin.participant_id, 'incarnation_id': origin.incarnation_id,
            'authority_version': origin.authority_version, 'issue_number': route.issue_number,
            'github_user_id': self.actor_user_ids[origin.actor_id],
            'request_digest': hashlib.sha256(_json(envelope).encode()).hexdigest()}
        begun = self._audit('begin', self._key(operation), metadata)
        return {'_assignment_broker': self, 'operation': operation, 'key': self._key(operation),
                'origin': origin, 'authorize': authorize, 'metadata': metadata,
                'started': begun['started'], 'record': begun['record']}

    def _project(self):
        from .github_read import GitHubProject
        return GitHubProject(self.binding.repository, self.binding.host)

    def _provider(self, origin):
        provider = self.provider_for_actor(origin.actor_id)
        if type(provider) is not GitHubAssignmentProvider or provider.project != self._project():
            raise LedgerError('PROVIDER_BINDING_MISMATCH')
        return provider

    def perform(self, intent):
        if intent.get('_assignment_broker') is not self:
            raise LedgerError('INVALID_FORGE_INTENT')
        if not intent['started']:
            return None
        self._authorize(intent['origin'], intent['authorize'])
        def before_write(issue_id):
            self._authorize(intent['origin'], intent['authorize'])
            self._audit('prepared', intent['key'], issue_id)
            self._authorize(intent['origin'], intent['authorize'])
        try:
            return self._provider(intent['origin']).assign_self(intent['metadata']['issue_number'],
                intent['metadata']['github_user_id'], before_write=before_write)
        except LedgerError:
            raise
        except Exception:
            return assignment_result('PROVIDER_FAILURE', contact='none', attribution='unknown')

    def _receipt(self, intent, record):
        result = record.get('result')
        if result is None:
            result = assignment_result('UNKNOWN_OUTCOME', issue_id=record.get('issue_id'),
                                       contact='write-possible', attribution='unknown')
        return {'operation_id': intent['operation'], 'audit_reference': intent['key'],
                'project_id': self.binding.project_id, 'repository': self.binding.repository,
                'admission': 'not-evaluated', 'assignment': result}

    def complete(self, intent, outcome, *, authorize):
        self._authorize(intent['origin'], authorize)
        record = self._audit('get', intent['key'])
        if intent['started'] and record.get('result') is None:
            record = self._audit('finish', intent['key'], outcome)
        return self._receipt(intent, record)

    def abandon(self, intent, reason):
        # Terminal evidence is independent of disclosing a receipt to a revoked
        # Participant. No read, write, or automatic replay occurs here.
        if reason not in {'AUTHORITY_REVOKED', 'PROCESS_EXITED', 'MISSING_ACTOR_CREDENTIAL',
                          'ROOM_NOT_RUNNING', 'ROOM_REPLACED', 'CONTROLLER_REPLACED'}:
            raise LedgerError('INVALID_FORGE_ABANDONMENT')
        record = self._audit('get', intent['key'])
        if record.get('result') is None:
            issue_id = record.get('issue_id')
            self._audit('finish', intent['key'], assignment_result(
                'NOT_EXECUTED' if issue_id is None else 'UNKNOWN_OUTCOME',
                issue_id=issue_id, contact='none' if issue_id is None else 'write-possible', attribution='unknown'))

    def reconcile(self, operation, reconciliation_id, *, origin, authorize):
        self._authorize(origin, authorize)
        record = self._audit('get', self._key(operation))
        if record is None:
            raise LedgerError('UNKNOWN_OPERATION')
        metadata = record['metadata']
        if (metadata['actor_id'] != origin.actor_id or metadata['participant_id'] != origin.participant_id
                or metadata['github_user_id'] != self.actor_user_ids[origin.actor_id]
                or metadata['room_id'] != self.binding.room_id
                or metadata['project_id'] != self.binding.project_id
                or metadata['repository'] != self.binding.repository):
            raise LedgerError('FORBIDDEN')
        begin = self._audit('begin_reconciliation', self._key(operation), _token(reconciliation_id))
        if not begin['started']:
            previous = next(r for r in begin['record']['reconciliations'] if r['id'] == reconciliation_id)
            return {'operation_id': operation, 'audit_reference': self._key(operation),
                    'assignment': previous['observation'] or assignment_result('UNKNOWN', issue_id=record.get('issue_id'))}
        # Original immutable receipt is not rewritten. A fresh read is separate
        # evidence, not proof that this request caused the current assignment.
        self._authorize(origin, authorize)
        observation = self._provider(origin).reconcile(metadata['issue_number'],
            metadata['github_user_id'], record.get('issue_id'))
        self._authorize(origin, authorize)
        self._audit('reconcile', self._key(operation), _token(reconciliation_id), observation)
        return {'operation_id': operation, 'audit_reference': self._key(operation), 'assignment': observation}

    def recover_pending(self, is_fenced):
        """Supervisor-only recovery after proving the original process fenced.

        No provider contact. Missing pre-write checkpoint proves no authorized
        POST; otherwise possible execution remains unknown for explicit reads.
        """
        if not callable(is_fenced):
            raise LedgerError('INVALID_FORGE_INTENT')
        for record in self._audit('pending', self.binding.room_id):
            metadata = record['metadata']
            if metadata['project_id'] != self.binding.project_id or metadata['repository'] != self.binding.repository:
                raise LedgerError('PROJECT_MISMATCH')
            origin = Origin(metadata['actor_id'], metadata['participant_id'], metadata['incarnation_id'],
                            metadata['authority_version'], ('forge-write',))
            if is_fenced(origin) is not True:
                continue
            issue_id = record['issue_id']
            self._audit('finish', record['operation_id'], assignment_result(
                'NOT_EXECUTED' if issue_id is None else 'UNKNOWN_OUTCOME', issue_id=issue_id,
                contact='none' if issue_id is None else 'write-possible', attribution='unknown'))
