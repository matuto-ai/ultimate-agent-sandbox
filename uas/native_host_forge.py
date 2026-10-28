"""Direct fixed-helper Forge ingress; the Hub never supplies request authorship.

The Supervisor retains original kernel records on the helper's private FD4.
Only namespace reservation crosses to Hub; external audit/idempotency remain in
ReadBrokerClient/ExternalReadBroker. No new durable store, bearer or replay loop.
"""
from dataclasses import asdict
import hashlib
import json
import uuid

from .claude_native_admission import NativeClaudeSupervisorAdmission
from .forge_read_service import ReadBrokerClient, send_result
from .kernel_origin import OriginDenied, OriginUnavailable, receive
from .ledger import LedgerError, Origin, _json
from .lifecycle import Supervisor
from .native_helper import NativeDescendantLease
from .workstation_admission import AdmittedBinding, MAX_PACKET, _canonical, _unique
from .workstation_peer import AdmittedPeerDispatcher


class NativeHostForge:
    def __init__(self, helper, client):
        if (type(helper) is not NativeDescendantLease
                or type(helper._admission) is not NativeClaudeSupervisorAdmission
                or type(client) is not ReadBrokerClient
                or type(client.supervisor) is not Supervisor
                or helper.forge_channel is None):
            raise OriginDenied('exact admitted helper and trusted Broker required')
        self.helper, self.admission, self.client = helper, helper._admission, client
        self.closed = False
        self.binding = self._binding()
        seat = self.binding.seat
        if (seat.room_id != client.binding.room_id or seat.room_instance != client.room_instance
                or client.supervisor.room_id != seat.room_id):
            raise OriginDenied('direct Forge Room binding differs')
        self.origin = self._origin(self.binding)
        helper.forge_channel.settimeout(5)
        with client.supervisor._locked():
            self._current()

    def _binding(self):
        helper, admission = self.helper, self.admission
        helper.current()
        if helper.state != 'admitted' or helper._admission is not admission:
            raise OriginDenied('helper ADMIT acknowledgment required')
        root = helper._ready(admission)
        return AdmittedBinding(admission.seat, root['operation_id'],
            helper.root.incarnation, root['epoch'], root['readiness_digest'],
            helper.root.recipe.manifest_digest)

    def _origin(self, binding):
        # Exact same canonical authority version as Hub's admitted dispatcher.
        document = asdict(binding)
        if document.get('native_payload_digest') is None:
            document.pop('native_payload_digest', None)
        context = {'controller':self.admission.controller,'binding':document}
        version = 'seat-' + hashlib.sha256(_canonical(context)).hexdigest()
        return Origin(binding.seat.actor_id, binding.seat.participant_id,
                      binding.incarnation, version, binding.seat.capabilities)

    def _current(self, record=None):
        if self.closed or self._binding() != self.binding:
            raise OriginDenied('direct Forge authority changed')
        self.admission._current()
        if self._origin(self.binding) != self.origin:
            raise OriginDenied('direct Forge controller changed')
        if record is not None:
            self.helper.origin.require(record)
        state = self.client.supervisor._read()  # Caller holds lifecycle lock.
        if (self.client.closed or not state or state['phase'] != 'running'
                or state['instance_id'] != self.client.room_instance
                or state['spec']['project_id'] != self.client.binding.project_id):
            raise LedgerError('ROOM_NOT_RUNNING')
        return True

    def _reservation(self):
        return {'kind':'RESERVE_FORGE','helper_operation':self.helper.operation_id}

    def _reserve(self, envelope):
        try:
            return self._reserve_exchange(envelope)
        except LedgerError:
            raise  # An authenticated explicit rejection is known-no-contact.
        except BaseException:
            # An uncertain private reply must not remain queued for a different
            # command on the shared controller channel. Fence; never resend.
            self.admission.control_lost()
            raise

    def _reserve_exchange(self, envelope):
        """Authenticated private control; ACK grants namespace, NOT authority."""
        admission = self.admission
        digest = hashlib.sha256(_canonical(envelope)).hexdigest()
        exchange = uuid.uuid4().hex
        packet = _canonical({'version':1,**self._reservation(),
            'operation_id':self.binding.operation_id,'controller':admission.controller,
            'exchange_id':exchange,
            'envelope':envelope,'digest':digest})
        if len(packet) > MAX_PACKET:
            raise LedgerError('INVALID_NATIVE_FRAME')
        # No lifecycle/admission/ledger lock across Hub RPC. The shared channel
        # I/O lock orders this exchange with ADMIT/revoke/delivery only.
        with admission._io:
            admission._current()
            if admission.control.send(packet) != len(packet):
                raise OriginDenied('partial Forge reservation; outcome unknown')
            with receive(admission.control) as record:
                admission.hub_origin.require(record)
                reply = json.loads(record.data, object_pairs_hook=_unique)
            expected = {'version':1,'kind':'REPLY','operation_id':self.binding.operation_id,
                        'controller':admission.controller,'exchange_id':exchange}
            if (type(reply) is not dict or set(reply) != set(expected) | {'result'}
                    or any(type(reply[k]) is not type(v) or reply[k] != v for k,v in expected.items())):
                raise OriginDenied('uncorrelated Forge reservation')
            result = reply['result']
            if type(result) is dict and set(result) == {'error'}:
                raise LedgerError('FORGE_RESERVATION_DENIED')
            if result != {'status':'RESERVED','digest':digest}:
                raise OriginDenied('Forge reservation digest differs')
        return digest

    def receive_once(self):
        """No retries. Lost response fences this transport, not a new operation.

        Caller selects readability; timeout never replays a write. Reconciliation
        uses the original canonical operation/body through forge-reconcile after
        explicit recovery, subject to the same process authority and Broker audit.
        """
        if self.closed:
            raise OriginDenied('direct Forge transport closed')
        channel = self.helper.forge_channel
        request_id = None
        try:
            with receive(channel) as record:
                with self.client.supervisor._locked():
                    self._current(record)
                frame = AdmittedPeerDispatcher._decode(record.data)
                request_id, envelope = frame['request_id'], frame['envelope']
                if envelope.get('kind') not in {'forge-read','forge-write','forge-reconcile'}:
                    raise LedgerError('INVALID_FORGE_ENVELOPE')
                digest = self._reserve(envelope)
                with self.client.supervisor._locked():
                    self._current(record)
                    # Only our decoded original packet reaches prepare. Hub's
                    # response cannot replace bytes, Actor, endpoint or capability.
                    if hashlib.sha256(_canonical(envelope)).hexdigest() != digest:
                        raise OriginDenied('original Forge bytes changed')
                    def guard():
                        try:
                            return self._current(record)
                        except (OriginDenied, OriginUnavailable, LedgerError):
                            return False
                    packet = self.client.prepare(envelope, self.origin, authorize=guard)
                receipt = self.client.perform(packet)
                with self.client.supervisor._locked():
                    self._current(record)
                result = {'request_id':request_id,'ok':True,'receipt':receipt}
        except LedgerError as error:
            result = {'request_id':request_id,'ok':False,'error':error.code}
        except BaseException:
            self.close()
            raise
        try:
            wire = _json(result).encode()
            if len(wire) > 1_048_576:
                result = {'request_id':request_id,'ok':False,'error':'OUTPUT_LIMIT'}
                wire = _json(result).encode()
            if len(wire) > MAX_PACKET:
                send_result(channel, request_id, result)
            elif channel.send(wire) != len(wire):
                raise OriginDenied('Forge response lost; outcome unknown')
            return result
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closed = True
        channel, self.helper.forge_channel = self.helper.forge_channel, None
        if channel is not None:
            channel.close()


class NativePiHostForge(NativeHostForge):
    """Same packet/Broker mechanics; authority is the exact native Pi root itself."""
    def __init__(self, admission, client):
        from .workstation_control import SupervisorAdmission
        from .workstation_exec import ExecLaunch
        from .native_pi_recipe import NativePiRecipe
        if (type(admission) is not SupervisorAdmission or type(admission.launch) is not ExecLaunch
                or type(admission.launch.native_recipe) is not NativePiRecipe
                or type(client) is not ReadBrokerClient or type(client.supervisor) is not Supervisor
                or admission.launch.forge_channel is None):
            raise OriginDenied('exact native Pi admission and trusted Broker required')
        self.helper, self.admission, self.client = admission.launch, admission, client
        self.closed = False
        self.binding = self._binding()
        seat = self.binding.seat
        if (seat.room_id != client.binding.room_id or seat.room_instance != client.room_instance
                or client.supervisor.room_id != seat.room_id):
            raise OriginDenied('direct Pi Forge Room binding differs')
        self.origin = self._origin(self.binding)
        self.helper.forge_channel.settimeout(5)
        with client.supervisor._locked():
            self._current()

    def _binding(self):
        admission = self.admission
        admission._current()
        current = admission.launch.admission
        if (current is None or current['state'] != 'admitted'
                or current['controller'] != admission.controller):
            raise OriginDenied('Pi ADMIT acknowledgment required')
        return AdmittedBinding(admission.seat, current['operation_id'],
            admission.launch.incarnation, current['epoch'], current['readiness_digest'])

    def _reservation(self):
        return {'kind':'RESERVE_PI_FORGE'}
