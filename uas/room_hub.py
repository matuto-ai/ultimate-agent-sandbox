"""Persistent fixture Hub control channel, separate from Workstation lifetime.

Owns a real RoomLedger/FixturePeerHub. Only the authenticated trusted Supervisor
may read its status. Participant admission/traffic keeps its existing adapters;
this narrow lifecycle channel cannot fabricate a Participant or run a command.
"""
from dataclasses import asdict
import json
import hashlib
import socket
import uuid

from .kernel_origin import HeldOrigin, OriginDenied, alive, enable, receive
from .ledger import RoomLedger, _token
from .peer import FixturePeerHub
from .lifecycle import _canonical, _unique_object


def _receive(channel):
    record = receive(channel)
    try:
        document = json.loads(record.data, object_pairs_hook=_unique_object)
        if type(document) is not dict:
            raise ValueError()
        return record, document
    except (ValueError, UnicodeError):
        record.close()
        raise OriginDenied('invalid Hub control document') from None


def _send(channel, document):
    content = _canonical(document).encode()
    if len(content) > 65536 or channel.send(content) != len(content):
        raise OriginDenied('bounded Hub control response unavailable')


def status_summary(snapshot):
    """Bounded real-state summary; retained ledger history never kills status."""
    content = _canonical(snapshot['state']).encode()
    return {'room_seq':snapshot['room_seq'], 'state_digest':hashlib.sha256(content).hexdigest(),
            'state_bytes':len(content), 'configured':'peer_traffic' in snapshot['state']}


def serve(channel, hub, instance, *, supervisor_uid, supervisor_gid):
    if type(hub) is not FixturePeerHub or type(hub.ledger) is not RoomLedger:
        raise OriginDenied('actual persistent Hub owner required')
    _token(instance)
    scope = {'room_id': hub.ledger.room_id, 'instance_id': instance}
    enable(channel)
    record, hello = _receive(channel)
    with record:
        if (record.credentials[1:] != (supervisor_uid, supervisor_gid)
                or set(hello) != {'kind','nonce','scope'} or hello['kind'] != 'ROOM_HUB_HELLO'
                or hello['scope'] != scope or type(hello['nonce']) is not str
                or len(hello['nonce']) != 32 or any(c not in '0123456789abcdef' for c in hello['nonce'])):
            raise OriginDenied('Hub Supervisor startup binding differs')
        supervisor = HeldOrigin(record)
    try:
        _send(channel, {'kind':'ROOM_HUB_READY','nonce':hello['nonce'],'scope':scope})
        # No Workstation-dependent timeout or test-only lifetime. The host owns
        # this process; verified channel loss/Destroy terminates its authority.
        while alive(supervisor.pidfd):
            record, request = _receive(channel)
            with record:
                supervisor.require(record)
                if set(request) != {'kind','nonce'} or request['kind'] != 'status':
                    raise OriginDenied('Hub control vocabulary refused')
                nonce = request['nonce']
                if type(nonce) is not str or len(nonce) != 32:
                    raise OriginDenied('Hub status correlation refused')
            snapshot = hub.ledger.snapshot()
            _send(channel, {'kind':'status','nonce':nonce,'scope':scope,
                            **status_summary(snapshot)})
    finally:
        supervisor.close()


class RoomHubClient:
    def __init__(self, channel, room_id, instance_id, *, hub_uid, hub_gid):
        _token(room_id); _token(instance_id)
        self.channel = channel
        self.scope = {'room_id':room_id,'instance_id':instance_id}
        self.closed = False
        enable(channel); channel.settimeout(5)
        nonce = uuid.uuid4().hex
        _send(channel, {'kind':'ROOM_HUB_HELLO','nonce':nonce,'scope':self.scope})
        record, response = _receive(channel)
        with record:
            if (record.credentials[1:] != (hub_uid,hub_gid)
                    or response != {'kind':'ROOM_HUB_READY','nonce':nonce,'scope':self.scope}):
                raise OriginDenied('Hub startup identity/scope differs')
            self.worker = HeldOrigin(record)

    def status(self):
        if self.closed or self.worker.revoked or not alive(self.worker.pidfd):
            raise OriginDenied('Hub authority unavailable')
        nonce = uuid.uuid4().hex
        _send(self.channel, {'kind':'status','nonce':nonce})
        record, response = _receive(self.channel)
        with record:
            self.worker.require(record)
            if (set(response) != {'kind','nonce','scope','room_seq','state_digest','state_bytes','configured'}
                    or response['kind'] != 'status' or response['nonce'] != nonce or response['scope'] != self.scope
                    or type(response['room_seq']) is not int or response['room_seq'] < 0
                    or type(response['state_digest']) is not str or len(response['state_digest']) != 64
                    or type(response['state_bytes']) is not int or response['state_bytes'] < 0
                    or type(response['configured']) is not bool):
                raise OriginDenied('Hub status correlation differs')
        return response

    def close(self):
        if not self.closed:
            self.closed = True
            self.channel.close()
            self.worker.close()
