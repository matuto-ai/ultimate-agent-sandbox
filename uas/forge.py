"""Connected read-only Forge observation seam; not a production Deployment ledger.

The controller supplies fresh process authority. Provider contact occurs between
committed intent and terminal observation, never inside a RoomLedger decision.
An interrupted observation is unknown and is never automatically re-contacted.
"""
import hashlib
import uuid
from dataclasses import dataclass

from .ledger import Command, Event, LedgerError, Origin, Transition, _json, _token


@dataclass(frozen=True)
class ForgeBinding:
    room_id: str
    project_id: str
    repository: str
    host: str = 'github.com'


class ReadOnlyForgeBroker:
    def __init__(self, ledger, binding, provider_for_actor):
        from .github_read import GitHubProject
        if type(binding) is not ForgeBinding or binding.room_id != ledger.room_id:
            raise LedgerError('ROOM_MISMATCH')
        _token(binding.project_id)
        self.project = GitHubProject(binding.repository, binding.host)
        self.ledger, self.binding, self.provider_for_actor = ledger, binding, provider_for_actor
        self._audit_failed = False

    def denied(self, code):
        """Controller-only audit of an unauthenticated record; no caller attribution."""
        allowed = {'WRONG_PROCESS', 'AUTHORITY_REVOKED', 'PROCESS_EXITED',
                   'MISSING_ACTOR_CREDENTIAL', 'INVALID_PROCESS_RECORD',
                   'AUTHORITY_STORE_UNAVAILABLE', 'INVALID_AUTHORITY_STORE',
                   'CONTROLLER_REPLACED', 'ROOM_NOT_RUNNING', 'ROOM_REPLACED', 'FORBIDDEN',
                   'INVALID_FORGE_ENVELOPE', 'INVALID_NATIVE_FRAME', 'PROJECT_MISMATCH'}
        if code not in allowed:
            return
        origin = Origin('forge-audit', 'forge-audit', 'controller', 'denial-v1', ())
        try:
            self.ledger.apply(Command('forge-denial-' + uuid.uuid4().hex, 'forge-denied',
                self.binding.project_id, None, {'code': code}), origin,
                authorize=lambda *_: True,
                decide=lambda state, command: Transition(state,
                    (Event('forge-record-denied', {'code': code}),), {'denied': True}))
        except LedgerError as error:
            self._audit_failed = True
            raise LedgerError('AUDIT_UNAVAILABLE') from error

    def _capacity(self, state):
        # Shared projection owners preserve already-admitted peer/context work.
        if 'peer_traffic' in state:
            from .peer import FixturePeerHub
            FixturePeerHub._reserve_capacity(state)
        else:
            _json(state)

    def _receipt(self, key, origin, authorize):
        return self.ledger.operation_receipt('forge-terminal-' + key, origin, authorize=authorize)

    def prepare(self, envelope, *, origin, authorize, admission=False, admission_reservation=None):
        """Under lifecycle lock: authenticate, validate, dedupe and reserve intent."""
        from .github_read import parse_route
        if self._audit_failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        if authorize() is not True or 'forge-read' not in origin.capabilities:
            raise LedgerError('FORBIDDEN')
        if (type(envelope) is not dict or set(envelope) != {'id', 'kind', 'argv'}
                or envelope['kind'] != 'forge-read'):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        operation = _token(envelope['id'])
        if type(admission) is not bool:
            raise LedgerError('INVALID_FORGE_INTENT')
        if admission_reservation is not None:
            _token(admission_reservation)
            if not admission:
                raise LedgerError('INVALID_FORGE_INTENT')
        digest = hashlib.sha256(_json({'envelope': envelope, 'admission': True,
                                      'admission_reservation': admission_reservation}
            if admission else envelope).encode()).hexdigest()
        code = None
        try:
            route = parse_route(envelope['argv'], self.project)
        except LedgerError as error:
            route, code = None, error.code
        payload = {'request_digest': digest, 'project_id': self.binding.project_id,
                   'host': self.binding.host, 'repository': self.binding.repository}
        key = hashlib.sha256((self.ledger.room_id + '\0' + operation).encode()).hexdigest()
        started = False
        def begin(state, command):
            nonlocal started
            pending = state.setdefault('forge_pending', {})
            if len(pending) >= 8:
                raise LedgerError('FORGE_CAPACITY')
            # Conservative maximum terminal footprint is reserved before any
            # external contact. Peer/context admissions include this reservation.
            # Terminal receipts live in immutable operations/history, not state.
            pending[key] = {'reserved': 'x' * 65536, 'command': command.canonical(),
                            'origin': origin.canonical()}
            if admission_reservation is not None:
                admission_row = state.get('run_admissions', {}).get(admission_reservation)
                if (not admission_row or admission_row['status'] != 'PREPARING'
                        or admission_row['participant_id'] != origin.participant_id
                        or admission_row['actor_id'] != origin.actor_id
                        or type(admission_row.get('reservation')) is not str):
                    raise LedgerError('INVALID_ADMISSION_RESERVATION')
                # Transfer, do not double-charge, the pending read's complete
                # bounded footprint. A padded count and separator allowance make
                # the charge conservative even when adding to a nonempty map.
                funding = {'run_id': admission_reservation, 'released_bytes': 9999999}
                pending[key]['admission_funding'] = funding
                charge = len(_json({key: pending[key]}).encode()) + 256
                if charge > 131072 or len(admission_row['reservation']) < charge:
                    raise LedgerError('ADMISSION_READ_CAPACITY')
                funding['released_bytes'] = charge
                admission_row['reservation'] = admission_row['reservation'][:-charge]
            self._capacity(state)
            started = True
            return Transition(state, (Event('forge-read-started', payload),), {'status': 'pending'})
        try:
            command = Command(operation, 'forge-read', self.binding.project_id, None, payload)
            self.ledger.apply(command, origin,
                              authorize=lambda *_: authorize(), decide=begin)
            existing = self._receipt(key, origin, authorize)
        except LedgerError as error:
            if error.code in {'STORAGE_ERROR', 'CLOSED'}:
                self._audit_failed = True
                raise LedgerError('AUDIT_UNAVAILABLE') from error
            raise
        return {'key': key, 'operation': operation, 'origin': origin, 'route': route,
                'code': code, 'started': started, 'existing': existing,
                '_broker': self, 'command': command, 'admission': admission}

    @staticmethod
    def _release_pending(state, key):
        row = state['forge_pending'][key]
        funding = row.get('admission_funding')
        if funding is not None:
            if (type(funding) is not dict or set(funding) != {'run_id', 'released_bytes'}
                    or type(funding['released_bytes']) is not int
                    or not 65536 <= funding['released_bytes'] <= 131072):
                raise LedgerError('INVALID_ADMISSION_RESERVATION')
            admission = state.get('run_admissions', {}).get(funding['run_id'])
            if not admission or admission['status'] not in {'PREPARING', 'ACTIVE'}:
                raise LedgerError('INVALID_ADMISSION_RESERVATION')
            if admission['status'] == 'PREPARING':
                if type(admission.get('reservation')) is not str:
                    raise LedgerError('INVALID_ADMISSION_RESERVATION')
                admission['reservation'] += 'x' * funding['released_bytes']
            # An already activated Run no longer has future admission work to
            # fund. Retire the transfer, never resurrect its removed reservation.
        del state['forge_pending'][key]

    def _validate_intent(self, intent):
        if type(intent) is not dict or intent.get('_broker') is not self:
            raise LedgerError('INVALID_FORGE_INTENT')
        command = intent.get('command')
        if (type(command) is not Command or command.kind != 'forge-read'
                or command.target != self.binding.project_id or command.generation is not None
                or intent.get('operation') != command.id
                or intent.get('key') != hashlib.sha256(
                    (self.ledger.room_id + '\0' + command.id).encode()).hexdigest()
                or command.payload.get('project_id') != self.binding.project_id
                or command.payload.get('repository') != self.binding.repository
                or command.payload.get('host') != self.binding.host):
            raise LedgerError('INVALID_FORGE_INTENT')

    def perform(self, intent):
        """Outside lifecycle/ledger locks: a bounded read, never a mutation."""
        from .github_read import validate_observation, generated_help
        self._validate_intent(intent)
        if intent['existing'] is not None:
            return None
        if not intent['started']:
            return {'completeness': 'unknown', 'status': 'INTERRUPTED_OBSERVATION'}
        if intent['code']:
            return {'completeness': 'unknown', 'status': intent['code']}
        if intent['route'].kind == 'help':
            return {'completeness': 'complete', 'status': 'HELP', 'help': generated_help()}
        try:
            provider = self.provider_for_actor(intent['origin'].actor_id)
            if provider.project != self.project:
                raise LedgerError('PROVIDER_BINDING_MISMATCH')
            number = intent['route'].issue_number
            outcome = validate_observation(provider.read_issue(number, admission=True)
                if intent['admission'] else provider.read_issue(number))
            if outcome['issue'] is not None and outcome['issue']['number'] != number:
                raise LedgerError('PROVIDER_BINDING_MISMATCH')
            return outcome
        except Exception:
            return {'completeness': 'unknown', 'status': 'PROVIDER_FAILURE'}

    def complete(self, intent, outcome, *, authorize):
        """Under lifecycle lock: late Stop/revoke/replacement defeats publication."""
        self._validate_intent(intent)
        if authorize() is not True:
            raise LedgerError('FORBIDDEN')
        if self._audit_failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        # Reconcile a competing terminal commit before releasing reservation.
        try:
            existing = self._receipt(intent['key'], intent['origin'], authorize)
            if existing is not None:
                return existing['result']
            terminal = {'project_id': self.binding.project_id, 'repository': self.binding.repository,
                        'admission': 'not-evaluated', 'observation': outcome}
            def finish(state, command):
                receipt = {'operation_id': intent['operation'], **terminal}
                if intent['key'] not in state.get('forge_pending', {}):
                    raise LedgerError('INVALID_FORGE_INTENT')
                self._release_pending(state, intent['key'])
                self._capacity(state)
                return Transition(state, (Event('forge-read-observed', terminal),), receipt)
            receipt = self.ledger.apply(Command('forge-terminal-' + intent['key'], 'forge-read-result',
                self.binding.project_id, None, terminal), intent['origin'],
                authorize=lambda *_: authorize(), decide=finish)
            return receipt['result']
        except LedgerError as error:
            if error.code in {'STORAGE_ERROR', 'CLOSED'}:
                self._audit_failed = True
                raise LedgerError('AUDIT_UNAVAILABLE') from error
            raise

    def abandon(self, intent, reason):
        """Controller-only late-authority-loss cleanup; never a caller receipt.

        The exact server-created intent is required, and immutable terminal
        reconciliation precedes any reservation change. No provider call occurs.
        """
        if (type(intent) is not dict or intent.get('_broker') is not self
                or reason not in {'AUTHORITY_REVOKED', 'PROCESS_EXITED', 'MISSING_ACTOR_CREDENTIAL',
                                  'ROOM_NOT_RUNNING', 'ROOM_REPLACED', 'CONTROLLER_REPLACED'}):
            raise LedgerError('INVALID_FORGE_ABANDONMENT')
        self._validate_intent(intent)
        origin, key = intent['origin'], intent['key']
        try:
            def missing(state, command):
                raise LedgerError('INVALID_FORGE_INTENT')
            # Verify original complete command/origin equality; never create an
            # arbitrary selected old operation under cleanup authority.
            self.ledger.apply(intent['command'], origin, authorize=lambda *_: True, decide=missing)
            existing = self._receipt(key, origin, lambda: True)
            if existing is not None:
                return  # Do not downgrade an earlier committed observation.
            terminal = {'project_id': self.binding.project_id, 'repository': self.binding.repository,
                        'admission': 'not-evaluated', 'observation': {
                            'completeness': 'unknown', 'status': 'AUTHORITY_LOST',
                            'controller_reason': reason}}
            def release(state, command):
                if key not in state.get('forge_pending', {}):
                    raise LedgerError('INVALID_FORGE_INTENT')
                self._release_pending(state, key)
                self._capacity(state)
                return Transition(state, (Event('forge-read-abandoned', terminal),),
                                  {'operation_id': intent['operation'], **terminal})
            self.ledger.apply(Command('forge-terminal-' + key, 'forge-read-result',
                self.binding.project_id, None, terminal), origin,
                authorize=lambda *_: True, decide=release)
        except LedgerError as error:
            if error.code in {'STORAGE_ERROR', 'CLOSED'}:
                self._audit_failed = True
                raise LedgerError('AUDIT_UNAVAILABLE') from error
            raise

    def recover_pending(self, is_fenced):
        """Supervisor-only restart reconciliation of proven-fenced incarnations.

        Pending metadata is sanitized command digest/target and original Origin,
        not raw argv or provider output. Never re-contact or disclose receipts.
        The controller invokes this under its lifecycle lock after reconstruction.
        """
        try:
            pending = self.ledger.snapshot()['state'].get('forge_pending', {})
            if type(pending) is not dict or len(pending) > 8:
                raise LedgerError('INVALID_FORGE_INTENT')
            for key, row in pending.items():
                if type(row) is not dict or set(row) not in (
                        {'reserved', 'command', 'origin'},
                        {'reserved', 'command', 'origin', 'admission_funding'}):
                    raise LedgerError('INVALID_FORGE_INTENT')
                command = Command(**row['command'])
                origin = Origin(**{**row['origin'], 'capabilities': tuple(row['origin']['capabilities'])})
                origin.canonical()
                intent = {'key': key, 'operation': command.id, 'origin': origin,
                          'command': command, '_broker': self}
                self._validate_intent(intent)
                if is_fenced(origin) is True:
                    self.abandon(intent, 'CONTROLLER_REPLACED')
        except (KeyError, TypeError, ValueError) as error:
            raise LedgerError('INVALID_FORGE_INTENT') from error
        except LedgerError as error:
            if error.code in {'STORAGE_ERROR', 'CLOSED'}:
                self._audit_failed = True
                raise LedgerError('AUDIT_UNAVAILABLE') from error
            raise

    def submit(self, envelope, *, origin, authorize):
        """Trusted synchronous unit seam. Controller uses explicit lock phases."""
        intent = self.prepare(envelope, origin=origin, authorize=authorize)
        return self.complete(intent, self.perform(intent), authorize=authorize)
