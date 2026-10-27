"""Supervisor admission of the fixed Claude MCP immediate child.

Lineage is checked at binding and transfer, NOT by remote RPC in Hub ledger
transactions. After transfer Hub retains exact helper/root identities and the
root epoch locally. This is a stable auxiliary admission, not fresh Git child
attribution. A manifest digest binds the entire approved helper installation.
No receipt restores authority after a Supervisor restart.
"""
import array
import hashlib
import json
import socket
import uuid

from .claude_native_admission import NativeClaudeRoot, NativeClaudeSupervisorAdmission
from .git_process import GitChildAuthority, GitSeat
from .kernel_origin import HeldOrigin, OriginDenied, Record, alive, receive
from .ledger import Origin
from .workstation_admission import _canonical, _unique

HELLO = b'UAS-CLAUDE-MCP-1\n'
RELEASE = b'UAS-RELEASE-1\n'


class NativeDescendantLease:
    """One-shot helper lease; private metadata derives from the typed root.

    Caller owns the accepted connected seqpacket and its already received hello
    Record. On successful construction this object owns the channel and consumes
    the Record's pidfd. release() permits only MCP initialize/list. Application
    traffic must remain gated until Hub acknowledges installation separately.
    """
    def __init__(self, root, channel, record):
        if (type(root) is not NativeClaudeRoot or type(record) is not Record
                or record.data != HELLO or type(channel) is not socket.socket
                or channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
            raise OriginDenied('typed native root and fixed kernel helper hello required')
        channel.getpeername()  # Reject an unconnected/listening socket.
        root.current()
        self.root, self.channel = root, channel
        self.origin = self._lineage = self._authority = None
        self.operation_id = uuid.uuid4().hex
        self.state = 'new'
        self._document = self._digest = self._admission = None
        self._root_identity = root.origin.identity
        self._root_incarnation = root.incarnation
        self._manifest_digest = root.recipe.manifest_digest
        try:
            # Root's retained task was obtained from actual SCM_PIDFD ancestry,
            # not a numeric PID supplied by SDK diagnostics or a packet.
            seat = GitSeat(Origin(root.seat.actor_id, root.seat.participant_id,
                           root.incarnation, 'native-helper-bootstrap', ()),
                           root.origin, root.current, root.native_namespace, root.native_pid_depth)
            self._authority = GitChildAuthority((seat,))
            self._lineage = self._authority.bind(record)
            if (len(self._lineage.tasks) != 2
                    or self._lineage.tasks[-1].identity != self._root_identity
                    or self._lineage.tasks[0].identity == self._root_identity):
                raise OriginDenied('fixed helper must be immediate native Claude child')
            self._lineage.require(record)
            self.origin = HeldOrigin(record)
            self.state = 'bound'
        except BaseException:
            self.close()
            raise

    def current(self):
        if (self.state not in ('bound','released','intent','unknown','admitted','revoking')
                or self.origin is None or self.origin.revoked or not alive(self.origin.pidfd)
                or self.root.origin is None or self.root.origin.identity != self._root_identity
                or self.root.incarnation != self._root_incarnation
                or self.root.recipe.manifest_digest != self._manifest_digest):
            raise OriginDenied('native helper lease unavailable')
        self.root.current()
        return True

    def release(self):
        if self.state != 'bound':
            raise OriginDenied('helper release is one-shot')
        self.current()
        self._lineage.current()
        self.state = 'releasing'  # Even a partial/uncertain release is not retried.
        try:
            if self.channel.send(RELEASE) != len(RELEASE):
                raise OriginDenied('partial helper release')
            self.state = 'released'
        except BaseException:
            self.close()
            raise

    def _ready(self, admission):
        self.current()
        if (type(admission) is not NativeClaudeSupervisorAdmission or admission.launch is not self.root
                or self.root.state != 'active' or self.root.native_readiness is None
                or type(self.root.admission) is not dict or self.root.admission.get('state') != 'admitted'
                or admission.controller != self.root.admission.get('controller')):
            raise OriginDenied('acknowledged active native root required')
        admission._current()
        if self._document is not None and any(self._document[key] != value for key,value in (
                ('controller',admission.controller),
                ('root_operation',self.root.admission['operation_id']),
                ('root_epoch',self.root.admission['epoch']))):
            raise OriginDenied('helper root admission epoch changed')
        return self.root.admission

    def _empty_channel(self):
        # EOF is not an empty queue. No pre-admission application record may be
        # transferred for later replay. Fixed helper additionally gates calls.
        try:
            self.channel.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        except BlockingIOError:
            return
        raise OriginDenied('premature helper traffic or closed helper channel')

    def admit(self, admission):
        """One FD-transfer attempt; timeout/partial send permits status only."""
        if self.state != 'released':
            raise OriginDenied('helper transfer cannot be replayed')
        if type(admission) is not NativeClaudeSupervisorAdmission:
            raise OriginDenied('typed native root admission required')
        with admission._io:
            with admission._authority:
                root = self._ready(admission)
                self._lineage.current()
                self._empty_channel()
                exchange = uuid.uuid4().hex
                document = {'version':1,'kind':'ADMIT_NATIVE_HELPER',
                    'operation_id':self.operation_id,'exchange_id':exchange,
                    'controller':admission.controller,'root_operation':root['operation_id'],
                    'root_incarnation':self.root.incarnation,'root_epoch':root['epoch'],
                    'root_identity':list(self.root.origin.identity),
                    'helper_identity':list(self.origin.identity),
                    'helper_payload_digest':self._manifest_digest}
                self._document, self._admission = document, admission
                self._digest = hashlib.sha256(_canonical({k:v for k,v in document.items()
                                                       if k != 'exchange_id'})).hexdigest()
                self.state = 'intent'  # Set before any possible send, never restore released.
                try:
                    packet = _canonical(document)
                    sent = admission.control.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                          array.array('i', [self.channel.fileno(), self.origin.pidfd]))])
                    if sent != len(packet):
                        raise OriginDenied('partial helper transfer; reconcile status')
                except BaseException:
                    self.state = 'unknown'
                    raise
            return self._receive(exchange)

    def _receive(self, exchange, *, revoking=False):
        admission = self._admission
        try:
            with receive(admission.control) as record:
                admission.hub_origin.require(record)
                reply = json.loads(record.data.decode('utf-8'), object_pairs_hook=_unique)
            with admission._authority:
                self._ready(admission)
                expected = {'version':1,'kind':'REPLY','operation_id':self.operation_id,
                            'controller':admission.controller,'exchange_id':exchange}
                if (type(reply) is not dict or set(reply) != set(expected) | {'result'}
                        or any(type(reply[k]) is not type(v) or reply[k] != v for k,v in expected.items())):
                    raise OriginDenied('unmatched helper reply')
                result = reply['result']
                if (type(result) is not dict or set(result) != {'state','helper_digest'}
                        or result['state'] not in ('active','absent','revoked')
                        or result['helper_digest'] not in (None,self._digest)
                        or (result['state']=='active' and result['helper_digest'] != self._digest)):
                    raise OriginDenied('unmatched helper receipt')
                if revoking and result['state'] == 'active':
                    raise OriginDenied('helper revocation not confirmed')
                self.state = 'admitted' if result['state']=='active' else 'unavailable'
                if self.channel is not None:
                    self.channel.close(); self.channel = None
                return result
        except TimeoutError:
            self.state = 'unknown'
            raise
        except BaseException:
            self.close()
            raise

    def status(self):
        if self.state not in ('intent','unknown','admitted') or self._admission is None:
            raise OriginDenied('no helper transfer to reconcile')
        admission = self._admission
        with admission._io:
            with admission._authority:
                self._ready(admission)
                exchange = uuid.uuid4().hex
                packet = _canonical({'version':1,'kind':'STATUS_NATIVE_HELPER',
                    'operation_id':self.operation_id,'controller':admission.controller,'exchange_id':exchange})
                if admission.control.send(packet) != len(packet):
                    raise OriginDenied('partial helper status command')
            return self._receive(exchange)

    def close(self):
        """Local fence; transferred authority requires controller/root revocation.

        Closing the private controller deliberately fences all its leases rather
        than leaving uncertain transferred authority live after cleanup.
        """
        self.state = 'revoked'
        error = None
        if self._admission is not None:
            try:
                self._admission.control_lost()
            except BaseException as failure:
                error = failure
        for name in ('origin','channel','_lineage','_authority'):
            resource = getattr(self,name,None)
            setattr(self,name,None)
            if resource is not None:
                try:
                    resource.close()
                except BaseException as failure:
                    error = error or failure
        if error is not None:
            raise error

    def revoke(self):
        """Explicit helper revocation, or controller fence if outcome is unknown."""
        if self._admission is None or self.state == 'unavailable':
            self.close()
            return None
        admission = self._admission
        try:
            with admission._io:
                with admission._authority:
                    self._ready(admission)
                    self.state = 'revoking'
                    exchange = uuid.uuid4().hex
                    packet = _canonical({'version':1,'kind':'REVOKE_NATIVE_HELPER',
                        'operation_id':self.operation_id,'controller':admission.controller,'exchange_id':exchange})
                    if admission.control.send(packet) != len(packet):
                        raise OriginDenied('partial helper revocation')
                result = self._receive(exchange, revoking=True)
            # Confirmed helper removal needs no Room-wide controller fence.
            self._admission = None
            self.close()
            return result
        except BaseException:
            self.close()
            raise
