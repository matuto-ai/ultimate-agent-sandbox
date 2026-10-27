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
from .peer import FixtureConnection, FixturePeerHub, Readiness
from .workstation_admission import HubAdmission, _canonical

REQUEST = re.compile(r'[0-9a-f]{32}\Z')


class AdmittedPeerDispatcher:
    def __init__(self, admissions, hub, *, contributions=None):
        if type(admissions) is not HubAdmission or type(hub) is not FixturePeerHub:
            raise OriginDenied('trusted admission and existing Hub required')
        if contributions is not None:
            from .gate_identity import ContributionOwner
            if type(contributions) is not ContributionOwner or contributions.ledger is not hub.ledger:
                raise OriginDenied('canonical contribution owner required')
        self.contributions = contributions
        self.admissions, self.hub = admissions, hub
        self._connections = {}
        self._delivery_offers = {}
        self._delivery_confirmed = set()

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

    def delivery(self, operation, kind, receipt=None):
        """Trusted Supervisor safe-point poll/receipt, never participant traffic.

        Only immutable bounded offers cross the private channel. The native
        effect happens in Supervisor between these existing ledger phases.
        One outstanding offer per seat survives lost poll/confirmation replies;
        it is not restart authority or a second durable workflow journal.
        """
        with self.admissions.authorize(operation, None):
            connection = self._connections.get(operation)
            if connection is None:
                raise LedgerError('STALE_CONNECTION')
            authorize = lambda: self.admissions.recheck(operation, None)
            if kind == 'POLL_DELIVERY':
                if operation in self._delivery_confirmed:
                    self._delivery_offers.pop(operation, None)
                    self._delivery_confirmed.discard(operation)
                offer = self._delivery_offers.get(operation)
                if offer is None:
                    # The authenticated Supervisor polls only after its owned
                    # native receiver observed SAFE; acceptance rechecks SAFE.
                    self.hub.observe(connection, Readiness.SAFE)
                    offer = self.hub.prepare_delivery(connection, authorize=authorize)
                    if offer is None:
                        return {'status': 'HELD'}
                    self._delivery_offers[operation] = offer
                else:
                    # Re-evaluate cancellation, Run pause and context scope even
                    # when replaying a lost poll response. No native effect yet.
                    refreshed = self.hub.prepare_delivery(connection,
                        traffic_id=offer.envelope['id'], authorize=authorize)
                    if refreshed is None:
                        return {'status': 'HELD'}
                    if refreshed != offer:
                        raise LedgerError('DELIVERY_FENCED')
                if (not authorize() or not self.hub._current(connection, safe=True,
                        observation_id=offer.observation_id)):
                    raise LedgerError('DELIVERY_FENCED')
                result = {'status': 'OFFER', 'envelope': offer.envelope}
                return result
            if kind == 'CONFIRM_DELIVERY':
                offer = self._delivery_offers.get(operation)
                if offer is None:
                    raise LedgerError('UNCONFIRMED_DELIVERY')
                confirmed = self.hub.confirm_delivery(connection, offer, receipt,
                                                       authorize=authorize)
                self._delivery_confirmed.add(operation)
                return {'status': 'CONFIRMED', 'receipt': confirmed}
            raise LedgerError('INVALID_DELIVERY_COMMAND')

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

    def actor_authority(self, actor_id, authority_version=None):
        """Read current admitted Actor while caller retains admission fence.

        Match the exact authenticated submission epoch rather than borrowing
        a sibling seat's profile. A reset invalidates old authority but never
        rewrites contribution history.
        """
        if not getattr(self.admissions._authorization, 'depth', 0):
            raise OriginDenied('authority fence required before Gate transaction')
        if actor_id not in {seat.actor_id for seat in self.admissions.seats.values()}:
            raise LedgerError('GATE_IDENTITY_UNAVAILABLE')
        origins = []
        for operation, connection in tuple(self._connections.items()):
            active = self.admissions._active.get(operation)
            if active is None or active[1].seat.actor_id != actor_id:
                continue
            _, binding = self.admissions._check_current(operation)
            if not self.hub._current(connection):
                continue
            origins.append(self._origin(binding))
        if authority_version is not None:
            origins = [origin for origin in origins if origin.authority_version == authority_version]
        if len(origins) > 1:
            raise LedgerError('GATE_IDENTITY_AMBIGUOUS')
        if not origins:
            return {'actor_id': actor_id, 'kind': 'participant', 'active': False,
                    'authority_epoch': authority_version or 'inactive', 'capabilities': []}
        origin = origins[0]
        return {'actor_id': actor_id, 'kind': 'participant', 'active': True,
                'authority_epoch': origin.authority_version, 'capabilities': sorted(origin.capabilities)}

    def _submit(self, operation, record, binding, envelope):
        connection = self._connections.get(operation)
        if connection is None or not self.hub._current(connection):
            raise LedgerError('STALE_CONNECTION')
        authorize = lambda: (self.admissions.recheck(operation, record)
                             and self.hub._current(connection))
        origin = self._origin(binding)
        if envelope.get('kind') == 'contribution':
            if self.contributions is None: raise LedgerError('CONTRIBUTION_UNAVAILABLE')
            return self.contributions.submit(envelope, origin=origin, authorize=authorize)
        return self.hub.submit(connection, envelope, origin=origin, authorize=authorize)

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
                    receipt = self._submit(operation, record, binding, frame['envelope'])
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
