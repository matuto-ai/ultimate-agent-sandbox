"""Supervisor-only single ADMIT journal/reconciliation, not a workflow engine.

The existing ExecLaunch journal is the durable owner. Hub receives only the
bounded messages/FDs in workstation_admission, never this object or its launch.
A restarted owner cannot reconstruct live task authority from these records.
"""
import hashlib
from _thread import LockType
import json
import select
import threading
import uuid

from .kernel_origin import HeldOrigin, OriginDenied, alive, enable, receive
from .workstation_admission import (AdmissionSeat, OPERATION, _admission_document,
                                    _canonical, _unique, send_admit)
from .workstation_exec import ExecLaunch
from .ledger import LedgerError, MAX_SEQUENCE
from .peer import Readiness


class SupervisorAdmission:
    def __init__(self, launch, seat, control, *, hub_origin, controller, control_lock, timeout=2):
        if (type(launch) is not ExecLaunch or type(seat) is not AdmissionSeat
                or type(hub_origin) is not HeldOrigin or hub_origin.revoked
                or not alive(hub_origin.pidfd) or type(controller) is not str
                or not OPERATION.fullmatch(controller) or type(control_lock) is not LockType
                or not 0 < timeout <= 5):
            raise OriginDenied('trusted live launch and Hub controller required')
        self.launch, self.seat, self.control = launch, seat, control
        self.hub_origin, self.controller = hub_origin, controller
        self._authority = threading.RLock()
        self._io = control_lock  # One shared Room channel lock across every seat.
        self._fenced = False
        self._delivery_lock = threading.Lock()
        self._delivery_pending = None
        self.forge_service = None
        enable(control)
        control.settimeout(timeout)

    def attach_forge_service(self, client):
        from .native_host_forge import NativePiHostForge
        if type(self) is not SupervisorAdmission or self.forge_service is not None:
            raise OriginDenied('one direct native Pi Forge service required')
        self.forge_service = NativePiHostForge(self, client)
        return self.forge_service

    def receive_forge_once(self):
        if self.forge_service is None:
            raise OriginDenied('trusted native Pi Forge service unavailable')
        return self.forge_service.receive_once()

    def _current(self):
        # poll reports HUP even with unread replies queued; PEEK alone cannot.
        # Observation only: no control bytes consumed, no authority lock taken.
        try:
            poll = select.poll()
            flags = select.POLLHUP | select.POLLERR | select.POLLNVAL | getattr(select, 'POLLRDHUP', 0)
            poll.register(self.control, flags)
            lost = any(events & flags for _, events in poll.poll(0))
        except (OSError, ValueError):
            lost = True
        if lost:
            self._fenced = True
            raise OriginDenied('Supervisor control channel unavailable')
        if (self._fenced or self.hub_origin.revoked or not alive(self.hub_origin.pidfd)
                or self.launch.origin is None or self.launch.origin.revoked
                or not alive(self.launch.origin.pidfd) or self.launch.state != 'active'):
            raise OriginDenied('Supervisor admission authority fenced')
        self.launch.endpoint.require()

    def _save(self, state, **fields):
        self.launch.admission = {**self.launch.admission, **fields, 'state': state}
        try:
            self.launch._save()
        except BaseException:
            self._fenced = True
            self.launch.origin.revoke()
            self.control.close()  # Hub EOF monitor must fence transferred authority.
            raise

    def _empty_native_forge(self):
        import socket
        channel = self.launch.forge_channel
        if channel is None:
            raise OriginDenied('native Pi Forge channel missing')
        try:
            channel.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        except BlockingIOError:
            return
        raise OriginDenied('premature Pi Forge traffic or closed channel')

    def admit(self, operation_id, epoch):
        """Exactly one send attempt; any uncertain result requires status only."""
        with self._io:
            with self._authority:
                self._current()
                proof = self.launch.native_readiness
                if proof is None or self.launch.admission is not None:
                    raise OriginDenied('durable native readiness and unused admission required')
                if type(self.launch) is ExecLaunch and getattr(self.launch, 'native_recipe', None) is not None:
                    self._empty_native_forge()
                exchange_id = uuid.uuid4().hex  # Correlation only, never bearer authority.
                document = _admission_document(self.launch, self.seat, operation_id, epoch, proof['digest'], exchange_id)
                self.launch.admission = {'version': 1, 'operation_id': operation_id,
                    'epoch': epoch, 'controller': self.controller, 'admit_exchange_id': exchange_id,
                    'readiness_digest': proof['digest'],
                    'admission_digest': hashlib.sha256(_canonical(document)).hexdigest()}
                self._save('intent')  # Must precede the first possible FD transfer.
                try:
                    send_admit(self.control, launch=self.launch, seat=self.seat,
                               operation_id=operation_id, epoch=epoch,
                               readiness_digest=proof['digest'], exchange_id=exchange_id)
                except BaseException:
                    self._save('unknown')
                    raise
            return self._receive('ADMIT', exchange_id)

    def status(self):
        with self._io:
            with self._authority:
                self._current()
                if self.launch.admission is None:
                    raise OriginDenied('no admission operation to reconcile')
                exchange_id = self._send_command('STATUS')
            return self._receive('STATUS', exchange_id)

    def _send_command(self, kind):
        exchange_id = uuid.uuid4().hex
        packet = _canonical({'version': 1, 'kind': kind,
            'operation_id': self.launch.admission['operation_id'], 'controller': self.controller,
            'exchange_id': exchange_id})
        if self.control.send(packet) != len(packet):
            raise OriginDenied('partial private control command')
        return exchange_id

    def _receive(self, kind, exchange_id):
        # Blocking receive never holds lifecycle authorization. Revocation can
        # fence the task while this control call waits for its bounded response.
        try:
            with receive(self.control) as record:
                self.hub_origin.require(record)
                reply = json.loads(record.data.decode('utf-8'), object_pairs_hook=_unique)
            with self._authority:
                expected = self.launch.admission
                if (type(reply) is not dict or set(reply) != {'version','kind','operation_id','controller','exchange_id','result'}
                        or type(reply['version']) is not int or reply['version'] != 1
                        or reply['kind'] != 'REPLY' or reply['operation_id'] != expected['operation_id']
                        or reply['controller'] != self.controller or reply['exchange_id'] != exchange_id):
                    raise OriginDenied('unmatched private Hub reply')
                result = reply['result']
                if kind == 'ADMIT':
                    if type(result) is not dict or result.get('status') != 'ADMITTED':
                        raise OriginDenied('missing admission acknowledgment')
                    receipt, installed = {k:v for k,v in result.items() if k != 'status'}, True
                else:
                    if (type(result) is not dict or set(result) != {'receipt','installed','state'}
                            or type(result['installed']) is not bool
                            or result['state'] not in ('absent','active','revoked')):
                        raise OriginDenied('invalid admission status')
                    receipt, installed = result['receipt'], result['installed']
                if receipt is not None and _canonical(receipt) != _canonical({
                        'version': 1, 'operation_id': expected['operation_id'],
                        'epoch': expected['epoch'], 'controller': self.controller,
                        'admission_digest': expected['admission_digest']}):
                    raise OriginDenied('receipt does not match durable intent')
                if kind == 'REVOKE':
                    if installed:
                        raise OriginDenied('revoked task remains installed')
                    self._save('revoked', receipt=receipt)
                else:
                    self._current()  # Late revoke wins over an earlier ACK.
                    if installed and receipt is None:
                        raise OriginDenied('installed admission without receipt')
                    self._save('admitted' if installed else 'unavailable', receipt=receipt)
                    if installed and self.launch.channel is not None:
                        channel, self.launch.channel = self.launch.channel, None
                        channel.close()  # Only Hub consumes queued participant records.
                return result
        except BaseException as error:
            with self._authority:
                try:
                    if self.launch.admission['state'] not in ('revoking','revoked'):
                        self._save('unknown')
                finally:
                    if not isinstance(error, TimeoutError):
                        self._fenced = True
                        self.launch.origin.revoke()
                        self.control.close()
            raise

    def _delivery_exchange(self, kind, receipt=None):
        with self._io:
            try:
                with self._authority:
                    self._current()
                    expected = self.launch.admission
                    if expected is None or expected['state'] != 'admitted':
                        raise OriginDenied('current acknowledged admission required')
                    exchange_id = uuid.uuid4().hex
                    packet = {'version': 1, 'kind': kind,
                        'operation_id': expected['operation_id'], 'controller': self.controller,
                        'exchange_id': exchange_id}
                    if kind == 'CONFIRM_DELIVERY':
                        packet['receipt'] = receipt
                    data = _canonical(packet)
                if len(data) > 8192 or self.control.send(data) != len(data):
                    raise OriginDenied('invalid or partial delivery control command')
                with receive(self.control) as record:
                    self.hub_origin.require(record)
                    reply = json.loads(record.data.decode('utf-8'), object_pairs_hook=_unique)
                with self._authority:
                    self._current()
                    if (type(reply) is not dict
                            or set(reply) != {'version','kind','operation_id','controller','exchange_id','result'}
                            or type(reply['version']) is not int or reply['version'] != 1
                            or reply['kind'] != 'REPLY' or reply['controller'] != self.controller
                            or reply['operation_id'] != expected['operation_id']
                            or reply['exchange_id'] != exchange_id or type(reply['result']) is not dict):
                        raise OriginDenied('unmatched private delivery reply')
                    return reply['result']
            except TimeoutError:
                # Keep the pending offer/native receipt. Next call reconciles
                # through the existing native journal or exact confirmation.
                raise
            except BaseException:
                self.control_lost()
                raise

    def deliver_one(self):
        """One Supervisor-owned safe-point delivery, no native object in Hub.

        Lost confirmation retries only the receipt; lost native response uses
        the existing receiver journal's read-only reconciliation, not reinject.
        Hub restart/control loss fences this live owner rather than restoring
        authority from the local offer or durable native acceptance record.
        """
        with self._delivery_lock:
            with self._authority:
                self._current()
                receiver = self.launch.native_receiver
                if receiver is None:
                    raise OriginDenied('owned native receiver required')
            if self._delivery_pending is None:
                if receiver.observe() is not Readiness.SAFE:
                    return {'status': 'HELD'}
                result = self._delivery_exchange('POLL_DELIVERY')
                if set(result) == {'error'} and type(result['error']) is str:
                    raise LedgerError(result['error'])
                if result == {'status': 'HELD'}:
                    return result
                if set(result) != {'status', 'envelope'} or result['status'] != 'OFFER':
                    self.control_lost()
                    raise OriginDenied('invalid native delivery offer')
                envelope = result['envelope']
                scope = receiver.scope
                if (type(envelope) is not dict
                        or any(type(envelope.get(k)) is not type(v) or envelope.get(k) != v
                               for k,v in scope.items())
                        or envelope.get('participant_id') != self.seat.participant_id
                        or envelope.get('incarnation_id') != self.launch.incarnation):
                    self.control_lost()
                    raise OriginDenied('delivery offer scope mismatch')
                self._delivery_pending = {'envelope': envelope, 'receipt': None}
            pending = self._delivery_pending
            if pending['receipt'] is None:
                with self._authority:
                    self._current()
                # No authority or Room control I/O lock spans native/provider I/O.
                pending['receipt'] = receiver.accept(pending['envelope'])
            result = self._delivery_exchange('CONFIRM_DELIVERY', pending['receipt'])
            if set(result) == {'error'} and type(result['error']) is str:
                raise LedgerError(result['error'])
            confirmed = result.get('receipt')
            if (set(result) != {'status','receipt'} or result['status'] != 'CONFIRMED'
                    or type(confirmed) is not dict
                    or set(confirmed) != {'room_id','operation_id','first_seq','last_seq','result'}
                    or confirmed['room_id'] != self.seat.room_id
                    or confirmed['operation_id'] != pending['envelope']['delivery_id'] + ':confirm'
                    or type(confirmed['first_seq']) is not int or type(confirmed['last_seq']) is not int
                    or not 0 < confirmed['first_seq'] <= confirmed['last_seq'] <= MAX_SEQUENCE
                    or _canonical(confirmed['result']) != _canonical(pending['receipt'])):
                self.control_lost()
                raise OriginDenied('native confirmation receipt mismatch')
            self._delivery_pending = None
            return result

    def revoke(self):
        # Fence before waiting for another control exchange, then durably record.
        with self._authority:
            self._fenced = True
            try:
                self.launch.revoke()
                if self.launch.admission is None:
                    return
                self._save('revoking')
            except BaseException:
                self.control.close()
                raise
        with self._io:
            try:
                exchange_id = self._send_command('REVOKE')
                return self._receive('REVOKE', exchange_id)
            except BaseException:
                self.control.close()
                raise

    def control_lost(self):
        with self._authority:
            self._fenced = True
            try:
                self.launch.revoke()
            finally:
                self.control.close()
