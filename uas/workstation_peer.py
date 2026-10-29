"""Thin admitted peer transport into the existing Hub/ledger, source-only.

No Engine, launch/RPC object, workflow reducer or Broker is owned here. Trusted
orchestration must attach an existing current Hub connection for each admission.
"""
from dataclasses import asdict
import hashlib
import json
import re

from .kernel_origin import MAX_PACKET, OriginDenied, OriginUnavailable, receive
from .ledger import LedgerError, Origin, RoomLedger, _json
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
        self.reviews = None
        self.read_service = None
        self.host_forge_binding = None
        self.admissions, self.hub = admissions, hub
        self._connections = {}
        self._pending_connections = {}
        self._delivery_offers = {}
        self._delivery_confirmed = set()
        self._revocation_store = hub.ledger.writer_binding()
        admissions.bind_revocations(self)

    def lost(self, operation):
        """Admission → thread-local connection to the SAME canonical Room DB."""
        connection = self._connections.get(operation) or self._pending_connections.get(operation)
        if connection is None:
            return
        path, identity = self._revocation_store
        with RoomLedger.open_writer(path, self.hub.ledger.room_id, identity=identity) as ledger:
            hub = FixturePeerHub(ledger)
            hub._connections[connection.participant_id] = connection
            def already_absent():
                current = hub._state()['connections'].get(connection.participant_id, {})
                exact = (current.get('attachment_id') == connection.attachment_id
                         and current.get('incarnation_id') == connection.incarnation_id
                         and current.get('context_generation') == connection.context_generation)
                return not exact or current.get('readiness') == Readiness.LOST.value
            if already_absent():
                return
            try:
                # observe rechecks the same attachment under BEGIN IMMEDIATE;
                # a replacement after the preliminary read cannot be marked LOST.
                hub.observe(connection, Readiness.LOST)
            except LedgerError as error:
                if error.code in ('STALE_CONNECTION', 'FORBIDDEN') and already_absent():
                    return
                raise

    def attach_host_forge_binding(self, binding):
        """Immutable trusted startup Project binding, never credentials/authority."""
        from .forge import ForgeBinding
        if (type(binding) is not ForgeBinding or binding.room_id != self.hub.ledger.room_id
                or self.host_forge_binding is not None):
            raise OriginDenied('one canonical Room Forge binding required')
        self.host_forge_binding = binding

    def reserve_host_forge(self, operation, helper, envelope, digest):
        """Private Supervisor control only; namespace reservation is not a grant.

        Caller was authenticated by HubAdmission. Host received original helper
        bytes separately; Hub cannot manufacture that kernel record or its Origin.
        """
        from .forge_read_service import reserve_forge_operation
        if self.host_forge_binding is None:
            raise LedgerError('FORGE_UNAVAILABLE')
        if hashlib.sha256(_canonical(envelope)).hexdigest() != digest:
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        authority = (self.admissions.authorize(operation, None) if helper is None
                     else self.admissions.authorize_descendant(helper, None))
        with authority as binding:
            connection = self._connections.get(operation)
            if (binding.operation_id != operation or connection is None
                    or not self.hub._current(connection)):
                raise LedgerError('STALE_CONNECTION')
            guard = lambda: ((self.admissions.recheck(operation, None) if helper is None
                              else self.admissions.recheck_descendant(helper, None))
                             and self.hub._current(connection))
            reserve_forge_operation(self.hub.ledger, self.host_forge_binding,
                                    envelope, self._origin(binding), guard)
            return {'status':'RESERVED', 'digest':digest}

    def attach_read_service(self, client):
        """Attach the existing trusted Broker client, never a peer-selected URL.

        Lifecycle lock precedes admission lock everywhere this service is used.
        Provider I/O remains outside both locks, with local guards re-entered
        by the existing Broker before dispatch, authorization and disclosure.
        """
        from .forge_read_service import ReadBrokerClient
        from .lifecycle import Supervisor
        if (type(client) is not ReadBrokerClient or type(client.supervisor) is not Supervisor
                or self.read_service is not None or client.closed
                or client.binding.room_id != self.hub.ledger.room_id
                or client.supervisor.room_id != self.hub.ledger.room_id
                or any(seat.room_id != client.binding.room_id or seat.room_instance != client.room_instance
                       for seat in self.admissions.seats.values())):
            raise OriginDenied('canonical same-Room Broker client required')
        with client.supervisor._locked():
            self._forge_room_current(client)
            self.read_service = client

    @staticmethod
    def _forge_room_current(client):
        state = client.supervisor._read()
        if (client.closed or not state or state['phase'] != 'running'
                or state['instance_id'] != client.room_instance
                or state['spec']['project_id'] != client.binding.project_id):
            raise LedgerError('ROOM_NOT_RUNNING')
        return True

    def attach_reviews(self, owner):
        """Trusted host composition after constructing the admitted identity."""
        from .run_review import RunReview
        if (type(owner) is not RunReview or owner.ledger is not self.hub.ledger
                or owner.identity.dispatcher is not self or self.reviews is not None):
            raise OriginDenied('canonical review owner required')
        self.reviews = owner

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
                if context_generation is None:
                    # Trusted service mode derives only canonical READY context,
                    # never a generation claimed by the incoming ADMIT packet.
                    state=self.hub.ledger.snapshot()['state']
                    context=state.get('fixture_context',{}).get('participants',{}).get(binding.seat.participant_id)
                    if (not context or context['status']!='READY'
                            or type(context.get('context_generation')) is not int
                            or not 0<context['context_generation']<2**53):
                        raise OriginDenied('canonical ready context required')
                    context_generation=context['context_generation']
                connection = self.hub.connect('admit-' + operation,
                    binding.seat.participant_id, binding.incarnation,
                    _InboundOnlyReceiver(), context_generation=context_generation)
                self._pending_connections[operation] = connection
                self.admissions.recheck(operation, None)
                self.attach(operation, connection)
                self._pending_connections.pop(operation, None)
                return connection
        except BaseException:
            try:
                self.admissions.revoke(operation)
            finally:
                self._pending_connections.pop(operation, None)
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
        # Native admission accepts one bounded request record only. Fragmented
        # writes are rejected before reservation/effects, not reassembled here.
        if type(data) is not bytes or len(data) > MAX_PACKET:
            raise LedgerError('INVALID_NATIVE_FRAME')
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
        document = asdict(binding)
        if document.get('native_payload_digest') is None:
            document.pop('native_payload_digest', None)  # Preserve legacy authority/idempotency.
        context = {'controller': self.admissions.controller, 'binding': document}
        authority = 'seat-' + hashlib.sha256(_canonical(context)).hexdigest()
        return Origin(binding.seat.actor_id, binding.seat.participant_id,
                      binding.incarnation, authority, binding.seat.capabilities)

    def reviewer_authority(self, participant_id, run_id, generation):
        """Exact active seat authority, never borrow a sibling Actor seat."""
        if not getattr(self.admissions._authorization, 'depth', 0):
            raise OriginDenied('authority fence required before review selection')
        matches = []
        for operation, connection in tuple(self._connections.items()):
            active = self.admissions._active.get(operation)
            if active is None or active[1].seat.participant_id != participant_id:
                continue
            _, binding = self.admissions._check_current(operation)
            if (self.hub._current(connection) and self.hub._scope_permits(
                    participant_id, connection.context_generation, run_id, generation)):
                matches.append(self._origin(binding))
        if len(matches) != 1: raise LedgerError('REVIEW_PARTICIPANT_UNAVAILABLE')
        return matches[0]

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

    def _submit(self, operation, record, binding, envelope, *, helper=None):
        connection = self._connections.get(operation)
        if connection is None or not self.hub._current(connection):
            raise LedgerError('STALE_CONNECTION')
        authorize = lambda: (self._recheck(operation, record, helper=helper)
                             and self.hub._current(connection))
        origin = self._origin(binding)
        if envelope.get('kind') in {'submit-for-review', 'review-result'}:
            if self.reviews is None: raise LedgerError('REVIEW_UNAVAILABLE')
            return self.reviews.submit(envelope, origin=origin, authorize=authorize, admission_operation=operation)
        if envelope.get('kind') == 'contribution':
            if self.contributions is None: raise LedgerError('CONTRIBUTION_UNAVAILABLE')
            return self.contributions.submit(envelope, origin=origin, authorize=authorize)
        return self.hub.submit(connection, envelope, origin=origin, authorize=authorize)

    def _authorize(self, operation, record, *, helper=None):
        if helper is not None:
            return self.admissions.authorize_descendant(helper, record)
        return self.admissions.authorize(operation, record)

    def _recheck(self, operation, record, *, helper=None):
        if helper is not None:
            return self.admissions.recheck_descendant(helper, record)
        return self.admissions.recheck(operation, record)

    def _forge(self, operation, record, envelope, *, helper=None):
        from .forge_read_service import reserve_forge_operation
        client = self.read_service
        if client is None:
            raise LedgerError('FORGE_UNAVAILABLE')
        # A helper's root binding is selected by HubAdmission, not by its packet.
        # Capture that exact Origin once, and re-enter admission for every later
        # Broker callback. A transaction-only recheck alone has no held depth.
        with client.supervisor._locked():
            self._forge_room_current(client)
            with self._authorize(operation, record, helper=helper) as binding:
                root_operation = binding.operation_id
                connection = self._connections.get(root_operation)
                if connection is None or not self.hub._current(connection):
                    raise LedgerError('STALE_CONNECTION')
                if (binding.seat.room_instance != client.room_instance
                        or binding.seat.room_id != client.binding.room_id):
                    raise LedgerError('ROOM_MISMATCH')
                origin = self._origin(binding)
                def guard():
                    self._forge_room_current(client)  # Broker holds lifecycle lock.
                    try:
                        with self._authorize(root_operation, record, helper=helper) as current:
                            return (current == binding and self._origin(current) == origin
                                and self._recheck(root_operation, record, helper=helper)
                                and self.hub._current(connection))
                    except (OriginDenied, OriginUnavailable):
                        return False
                # RoomLedger callbacks remain pure/local under the already-held
                # lifecycle/admission fences; no nested filesystem observation.
                transaction_guard = lambda: (self._recheck(root_operation, record, helper=helper)
                                              and self.hub._current(connection))
                reserve_forge_operation(self.hub.ledger, client.binding, envelope, origin, transaction_guard)
                packet = client.prepare(envelope, origin, authorize=guard)
        receipt = client.perform(packet)  # Never hold admission/ledger lock over provider I/O.
        with client.supervisor._locked():
            if guard() is not True:
                raise LedgerError('FORBIDDEN')
        return receipt

    def receive(self, operation):
        return self._receive(operation, self.admissions.peer_channel(operation))

    def receive_helper(self, helper):
        """Dedicated fixed MCP transport; direct HeldOrigin checks stay intact."""
        return self._receive(None, self.admissions.helper_channel(helper), helper=helper)

    def _receive(self, operation, channel, *, helper=None):
        request_id = None
        envelope = None
        try:
            # Blocking reads and provider calls are outside admission locks.
            # Keep the received kernel pidfd alive through all Broker rechecks.
            with receive(channel) as record:
                with self._authorize(operation, record, helper=helper):
                    frame = self._decode(record.data)
                    request_id = frame['request_id']
                envelope = frame['envelope']
                if envelope.get('kind') in {'forge-read','forge-write','forge-reconcile'}:
                    receipt = self._forge(operation, record, envelope, helper=helper)
                else:
                    with self._authorize(operation, record, helper=helper) as binding:
                        receipt = self._submit(binding.operation_id, record, binding,
                                               envelope, helper=helper)
            result = {'request_id': request_id, 'ok': True, 'receipt': receipt}
        except LedgerError as error:
            result = {'request_id': request_id, 'ok': False, 'error': error.code}
        except (OriginDenied, OriginUnavailable, OSError):
            # Transaction locks have unwound before any authority is fenced.
            if helper is None:
                self.admissions.revoke(operation)
            else:
                self.admissions.revoke_helper(helper)
            result = {'request_id': request_id, 'ok': False, 'error': 'AUTHORITY_REVOKED'}
        return self._reply(channel, result, forge=(envelope is not None
            and envelope.get('kind') in {'forge-read','forge-write','forge-reconcile'}))

    @staticmethod
    def _reply(channel, result, *, forge=False):
        # Reuse the established digest/index/count protocol understood by the
        # fixed Pi/Claude channel. This adds no framing/recovery store. Only
        # Forge replies may be chunked; all requests remain a single record.
        from .forge_read_service import send_result
        try:
            data = _json(result).encode()
        except LedgerError:
            result = {'request_id':result['request_id'],'ok':False,'error':'OUTPUT_LIMIT'}
            data = _json(result).encode()
        if len(data) > 1_048_576 or (len(data) > MAX_PACKET and not forge):
            result = {'request_id':result['request_id'],'ok':False,'error':'OUTPUT_LIMIT'}
            data = _json(result).encode()
        try:
            if len(data) > MAX_PACKET:
                send_result(channel, result['request_id'], result)
            elif channel.send(data) != len(data):
                raise OSError('incomplete peer reply')
        except (OriginDenied, OSError):
            pass  # Reply loss never retracts the canonical committed receipt.
        return result


class _InboundOnlyReceiver:
    def accept(self, envelope):
        raise LedgerError('SUPERVISOR_DELIVERY_UNAVAILABLE')
