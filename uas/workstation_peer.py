"""Thin admitted peer transport into the existing Hub/ledger, source-only.

No Engine, launch/RPC object, workflow reducer or Broker is owned here. Trusted
orchestration must attach an existing current Hub connection for each admission.
"""
from dataclasses import asdict
import hashlib
import json
import re

from .kernel_origin import OriginDenied, OriginUnavailable, receive
from .ledger import LedgerError, Origin, _json
from .lifecycle import _unique_object
from .peer import FixtureConnection, FixturePeerHub
from .workstation_admission import HubAdmission, _canonical

REQUEST = re.compile(r'[0-9a-f]{32}\Z')


class AdmittedPeerDispatcher:
    def __init__(self, admissions, hub):
        if type(admissions) is not HubAdmission or type(hub) is not FixturePeerHub:
            raise OriginDenied('trusted admission and existing Hub required')
        self.admissions, self.hub = admissions, hub
        self._connections = {}

    def attach_current(self, operation, *, context_generation):
        """Trusted Hub-local ADMIT hook; no native receiver/Engine crosses here.

        Existing Hub connect owns context validation and durable attachment.
        This inbound-only connection cannot deliver to the Runtime until a
        separately authenticated Supervisor delivery bridge is implemented.
        """
        try:
            with self.admissions.authorize(operation, None) as binding:
                peer = self.hub._state()['definition']['participants'].get(binding.seat.participant_id)
                if (peer is None or peer['actor_id'] != binding.seat.actor_id
                        or self.hub.ledger.room_id != binding.seat.room_id):
                    raise OriginDenied('Hub Actor/Room does not match admitted Participant')
                if operation in self._connections:
                    raise OriginDenied('admission connection already attached')
                connection = self.hub.connect('admit-' + operation,
                    binding.seat.participant_id, binding.incarnation,
                    _InboundOnlyReceiver(), context_generation=context_generation)
                self.admissions.recheck(operation, None)
                self.attach(operation, connection)
                return connection
        except BaseException:
            self.admissions.revoke(operation)
            raise

    def attach(self, operation, connection):
        binding = self.admissions.binding(operation)
        if (type(connection) is not FixtureConnection or not self.hub._current(connection)
                or connection.participant_id != binding.seat.participant_id
                or connection.incarnation_id != binding.incarnation
                or self.hub.ledger.room_id != binding.seat.room_id):
            raise OriginDenied('connection does not match admitted Participant')
        peer = self.hub._state()['definition']['participants'][connection.participant_id]
        if peer['actor_id'] != binding.seat.actor_id:
            raise OriginDenied('Hub Actor does not match admitted Participant')
        if operation in self._connections:
            raise OriginDenied('admission connection already attached')
        self._connections[operation] = connection

    @staticmethod
    def _decode(data):
        try:
            value = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_object)
            _json(value)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise LedgerError('INVALID_NATIVE_FRAME') from error
        if (type(value) is not dict or set(value) != {'request_id', 'envelope'}
                or type(value['request_id']) is not str or not REQUEST.fullmatch(value['request_id'])
                or type(value['envelope']) is not dict):
            raise LedgerError('INVALID_NATIVE_FRAME')
        return value

    def _origin(self, binding):
        # Same authoritative context controls idempotency and attribution. The
        # packet can supply neither Actor nor capability/namespace identity.
        context = {'controller': self.admissions.controller, 'binding': asdict(binding)}
        authority = 'seat-' + hashlib.sha256(_canonical(context)).hexdigest()
        return Origin(binding.seat.actor_id, binding.seat.participant_id,
                      binding.incarnation, authority, binding.seat.capabilities)

    def receive(self, operation):
        channel = self.admissions.peer_channel(operation)
        request_id = None
        try:
            # Potentially blocking I/O happens before acquiring authority lock.
            with receive(channel) as record:
                with self.admissions.authorize(operation, record) as binding:
                    frame = self._decode(record.data)
                    request_id = frame['request_id']
                    if frame['envelope'].get('kind') == 'forge-read':
                        raise LedgerError('FORGE_UNAVAILABLE')
                    connection = self._connections.get(operation)
                    if connection is None:
                        raise LedgerError('STALE_CONNECTION')
                    receipt = self.hub.submit(connection, frame['envelope'],
                        origin=self._origin(binding),
                        authorize=lambda: self.admissions.recheck(operation, record))
            result = {'request_id': request_id, 'ok': True, 'receipt': receipt}
        except LedgerError as error:
            result = {'request_id': request_id, 'ok': False, 'error': error.code}
        except (OriginDenied, OriginUnavailable, OSError):
            # Any consuming RoomLedger transaction has already rolled back.
            # Fencing belongs here, never in the transaction's pure recheck.
            self.admissions.revoke(operation)
            result = {'request_id': request_id, 'ok': False, 'error': 'AUTHORITY_REVOKED'}
        # Reply loss never retracts a committed ledger receipt. No provider I/O
        # or socket backpressure may hold the admission/revocation lock.
        try:
            data = _json(result).encode()
            if channel.send(data) != len(data):
                raise OSError('incomplete peer reply')
        except OSError:
            pass  # Existing operation ID provides durable retry reconciliation.
        return result


class _InboundOnlyReceiver:
    def accept(self, envelope):
        raise LedgerError('SUPERVISOR_DELIVERY_UNAVAILABLE')
