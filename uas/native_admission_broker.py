"""Canonical admission receipts over the existing external credential Broker.

Only the trusted admission owner constructs this adapter. It does not grant
human/native authority, self-assign, launch a task, or create another ledger.
"""
from copy import deepcopy

from .forge import ReadOnlyForgeBroker
from .forge_read_service import ReadBrokerClient
from .github_read import parse_route, validate_observation
from .ledger import LedgerError
from .lifecycle import Supervisor


class NativeAdmissionBroker(ReadOnlyForgeBroker):
    def __init__(self, ledger, binding, client):
        if (type(client) is not ReadBrokerClient or type(client.supervisor) is not Supervisor
                or client.binding != binding or client.supervisor.room_id != ledger.room_id):
            raise LedgerError('ADMISSION_BINDING_MISMATCH')
        # No provider or credential selection is available in this process.
        super().__init__(ledger, binding, None, assignments=None)
        self.client = client
        self._intents = {}
        self._finished = set()

    def _reservation(self, run, origin):
        state = self.ledger.snapshot()['state']
        row = state.get('run_admissions', {}).get(run)
        context = state.get('fixture_context', {}).get('participants', {}).get(origin.participant_id)
        if (row is None or row.get('status') != 'PREPARING'
                or row.get('participant_id') != origin.participant_id
                or row.get('actor_id') != origin.actor_id or context is None
                or context.get('context_generation') != row.get('context_generation')
                or (context.get('bound_run') or context.get('reserved_run')) != {'run_id': run, 'generation': 1}):
            raise LedgerError('INVALID_ADMISSION_RESERVATION')
        return deepcopy({k: row.get(k) for k in ('issue_number', 'participant_id', 'actor_id',
            'context_generation', 'seat_binding', 'admission_origin', 'admission_operation')})

    @staticmethod
    def _fingerprint(intent):
        return deepcopy({k: v for k, v in intent.items() if k != '_broker'})

    def prepare(self, envelope, *, origin, authorize, admission=False, admission_reservation=None):
        if admission is not True or admission_reservation is None or not callable(authorize):
            raise LedgerError('INVALID_FORGE_INTENT')
        if type(envelope) is not dict or envelope.get('kind') != 'forge-read':
            raise LedgerError('FORGE_WRITE_UNAVAILABLE')
        route = parse_route(envelope.get('argv'), self.project)
        if route.kind != 'issue-view':
            raise LedgerError('UNSUPPORTED_ROUTE')
        if len(self._intents) >= 64 or len(self._intents) - len(self._finished) >= 8:
            raise LedgerError('FORGE_CAPACITY')
        if authorize() is not True:
            raise LedgerError('FORBIDDEN')
        captured = self._reservation(admission_reservation, origin)
        if route.issue_number != captured['issue_number']:
            raise LedgerError('INVALID_ADMISSION_RESERVATION')
        intent = super().prepare(envelope, origin=origin, authorize=authorize,
            admission=True, admission_reservation=admission_reservation)
        def guard():
            if authorize() is not True:
                raise LedgerError('FORBIDDEN')
            if self._reservation(admission_reservation, origin) != captured:
                raise LedgerError('ADMISSION_BINDING_CHANGED')
            return True
        self._intents[id(intent)] = (intent, self._fingerprint(intent), guard)
        return intent

    def _owned(self, intent):
        self._validate_intent(intent)
        entry = self._intents.get(id(intent))
        if entry is None or entry[0] is not intent or self._fingerprint(intent) != entry[1]:
            raise LedgerError('INVALID_FORGE_INTENT')
        return entry[2]

    def perform(self, intent):
        guard = self._owned(intent)
        # Exact committed receipt/recovered pending intent never recontacts.
        if intent['existing'] is not None:
            return None
        if not intent['started']:
            return {'completeness': 'unknown', 'status': 'INTERRUPTED_OBSERVATION'}
        with self.client.supervisor._locked():
            guard()
            packet = self.client.prepare({'id': intent['operation'], 'kind': 'admission-read',
                'issue_number': intent['route'].issue_number}, intent['origin'], authorize=guard)
        result = self.client.perform(packet)  # No lifecycle/Room transaction held.
        if (type(result) is not dict or set(result) != {'admission', 'observation'}
                or result['admission'] != 'not-evaluated'):
            raise LedgerError('INVALID_PROVIDER_OBSERVATION')
        outcome = validate_observation(result['observation'])
        if outcome.get('issue') is not None and outcome['issue']['number'] != intent['route'].issue_number:
            raise LedgerError('PROVIDER_BINDING_MISMATCH')
        if outcome.get('status') == 'OK' and 'delivery_class' not in outcome:
            raise LedgerError('INVALID_PROVIDER_OBSERVATION')
        return outcome

    def complete(self, intent, outcome, *, authorize):
        guard = self._owned(intent)
        result = super().complete(intent, outcome, authorize=lambda: guard() and authorize())
        self._finished.add(id(intent))
        return result

    def abandon(self, intent, reason):
        self._owned(intent)
        result = super().abandon(intent, reason)
        self._finished.add(id(intent))
        return result
