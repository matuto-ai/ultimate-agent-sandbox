"""Bounded, non-listening installed Library transport.

Anonymous descriptors are handed over only on the authenticated bootstrap. Each
hop pins a live kernel process object; no pathname, token or claimed PID grants
access. The Hub is the authority for its already admitted Participant; the host
reconstructs scope from the fixed Room binding and challenges that live authority
at every capture fence. Neither relay persists capture bytes.
"""
import array
import base64
from dataclasses import asdict
import json
import hashlib
import secrets
import os
import select
import socket
import struct
import threading
import time

from . import library
from .kernel_origin import (HeldOrigin, Record, OriginDenied, SCM_PIDFD, MAX_PACKET,
                            _identity, alive, enable, receive)
from .ledger import Origin
from .library_hub import safe_result
from .workstation_admission import _canonical, _unique


def require(ok):
    if not ok:
        raise OriginDenied('installed Library channel refused')


MAX_MESSAGE = 1114112
CHUNK = 32768


def send(channel, value):
    raw = _canonical(value)
    require(0 < len(raw) <= MAX_MESSAGE)
    digest = hashlib.sha256(raw).hexdigest()
    count = (len(raw) + CHUNK - 1) // CHUNK
    deadline = time.monotonic() + 5
    previous = channel.gettimeout()
    try:
        for index in range(count):
            left = deadline-time.monotonic(); require(left > 0)
            channel.settimeout(left)
            packet = _canonical({'frame':1,'digest':digest,'index':index,
                'count':count,'size':len(raw),
                'data':base64.b64encode(raw[index*CHUNK:(index+1)*CHUNK]).decode()})
            require(len(packet) <= MAX_PACKET and channel.send(packet) == len(packet))
    finally: channel.settimeout(previous)


def read(channel, origin, *, seconds=5):
    deadline = time.monotonic()+seconds
    body = bytearray(); first = None
    while first is None or len(body) < first['size']:
        require(alive(origin.pidfd) and not origin.revoked)
        left = deadline-time.monotonic(); require(left > 0)
        require(bool(select.select([channel], [], [], left)[0]))
        with receive(channel) as record:
            origin.require(record)
            frame = json.loads(record.data, object_pairs_hook=_unique)
        require(type(frame) is dict and set(frame) == {'frame','digest','index','count','size','data'}
                and type(frame['frame']) is int and frame['frame'] == 1
                and type(frame['index']) is int and frame['index'] == len(body)//CHUNK
                and type(frame['size']) is int and 0 < frame['size'] <= MAX_MESSAGE
                and type(frame['count']) is int and frame['count'] == (frame['size']+CHUNK-1)//CHUNK
                and type(frame['digest']) is str and len(frame['digest']) == 64
                and type(frame['data']) is str)
        if first is None: first=frame
        require(all(frame[k] == first[k] for k in ('size','count','digest')))
        chunk=base64.b64decode(frame['data'],validate=True)
        require(len(chunk) == min(CHUNK,frame['size']-len(body)))
        body.extend(chunk)
    require(hashlib.sha256(body).hexdigest() == first['digest'])
    value=json.loads(body,object_pairs_hook=_unique)
    require(type(value) is dict)
    return value


def handoff(control, channel):
    """Only the fixed startup phase accepts one connected endpoint."""
    raw = b'LIBRARY-CHANNEL-1'
    require(control.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array('i', [channel.fileno()]))]) == len(raw))


def accept_handoff(control, supervisor):
    installed = []; rights = []; pids = []; creds = []
    channel = None
    try:
        data, ancillary, flags, _ = control.recvmsg(64, socket.CMSG_SPACE(12) +
            socket.CMSG_SPACE(4) + socket.CMSG_SPACE(253*4), socket.MSG_CMSG_CLOEXEC)
        require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        for level, kind, raw in ancillary:
            require(level == socket.SOL_SOCKET)
            if kind in (socket.SCM_RIGHTS, SCM_PIDFD):
                require(len(raw) % 4 == 0)
                fds = array.array('i'); fds.frombytes(raw); installed.extend(fds)
                (rights if kind == socket.SCM_RIGHTS else pids).extend(fds)
            elif kind == socket.SCM_CREDENTIALS:
                require(len(raw) == 12); creds.append(struct.unpack('3i', raw))
            else: require(False)
        require(data == b'LIBRARY-CHANNEL-1' and len(rights) == len(pids) == len(creds) == 1
                and all(fd >= 0 and not os.get_inheritable(fd) for fd in installed))
        supervisor.require(Record(data, creds[0], pids[0]))
        channel = socket.socket(fileno=rights[0]); installed.remove(rights[0])
        require(channel.family == socket.AF_UNIX and channel.type == socket.SOCK_SEQPACKET
                and not channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
        channel.getpeername(); enable(channel); channel.settimeout(5)
        result, channel = channel, None
        return result
    finally:
        if channel is not None: channel.close()
        for fd in installed: os.close(fd)


class Client:
    """Hub-only callable, invoked after LibraryHub's canonical reservation."""
    def __init__(self, channel, supervisor, binding, *, control_current=lambda: True, reports=None):
        self.channel, self.supervisor, self.binding = channel, supervisor, binding
        self.control_current = control_current
        self.reports = reports
        self.lock = threading.Lock()
        self.sequence = 0

    def _report(self, message):
        require(set(message) == {"kind", "report"} and message["kind"] == "report"
                and self.reports is not None)
        accepted = self.reports.receive(message["report"]) is True
        send(self.channel, {"kind":"report-result", "accepted":accepted})

    def poll(self):
        send(self.channel, {'kind':'poll'})
        response = read(self.channel, self.supervisor)
        if response.get('kind') == 'report':
            self._report(response)
            response = read(self.channel, self.supervisor)
        require(response == {'kind':'polled'})

    def __call__(self, *, scope, current, operation_id, request_id, value, at, run_id):
        require(type(scope) is library.LibraryScope and scope.subject == 'participant')
        expected = self.binding
        require(all(getattr(scope, key) == expected[key] for key in
                    ('project_id', 'project_identity', 'project_path', 'reference_root')))
        with self.lock:
            self.poll()
            self.sequence += 1; seq = self.sequence
            require(current() is True and self.control_current() is True)
            send(self.channel, {'kind':'capture', 'sequence':seq,
                'authority':{'participant_id':scope.participant_id,'actor_id':scope.actor_id,
                             'authority_version':scope.authority_version,
                             'capabilities':list(scope.capabilities)},
                'operation_id':operation_id,'request_id':request_id,'value':value,
                'at':at,'run_id':run_id})
            deadline = time.monotonic() + 60
            while True:
                require(time.monotonic() < deadline)
                response = read(self.channel, self.supervisor,
                                seconds=min(5, deadline-time.monotonic()))
                require(response.get('sequence') == seq)
                if response.get('kind') == 'current' and set(response) == {'kind','sequence'}:
                    active = current() is True and self.control_current() is True
                    send(self.channel, {'kind':'current','sequence':seq,'active':active})
                    continue
                require(set(response) == {'kind','sequence','result'} and response['kind']=='result')
                result = library.CaptureResult(**response['result'])
                safe_result(result, request_id)
                require(current() is True and self.control_current() is True)
                return result


class RootServer:
    """One host-owned endpoint per exact child lifetime, no retry after failure."""
    def __init__(self, channel, peer, endpoint_for, binding, seats, *, current):
        self.channel, self.peer, self.endpoint_for = channel, peer, endpoint_for
        self.binding, self.seats, self.current = binding, seats, current
        self.closed = threading.Event(); self.failure = None
        self.reports, self.report_worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.reports.setblocking(False); self.report_worker.setblocking(False)
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self): self.thread.start()

    def report(self, value):
        # Forked bounded_report children can be killed at any instruction. No
        # shared mutex, buffered pipe framing or child-owned durable state.
        nonce = secrets.token_hex(16)
        try:
            raw = _canonical({'nonce':nonce, 'report':value})
            if len(raw) > 16384: return False
            if self.report_worker.send(raw) != len(raw): return False
            deadline = time.monotonic() + .15
            while time.monotonic() < deadline:
                if not select.select([self.report_worker], [], [], max(0,deadline-time.monotonic()))[0]: return False
                response = self.report_worker.recv(128)
                if response == ('recorded:' + nonce).encode(): return True
                # A killed prior sender's receipt is not this request's ACK.
            return False
        except OSError: return False

    def close(self):
        if getattr(self, "released", False): return not self.thread.is_alive()
        self.closed.set()
        try: self.channel.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        if self.thread.ident is not None: self.thread.join(timeout=6)
        if self.thread.is_alive(): return False
        self.channel.close(); self.peer.close()
        self.reports.close(); self.report_worker.close()
        self.released = True
        return True

    def _scope(self, authority):
        require(type(authority) is dict and set(authority) ==
                {'participant_id','actor_id','authority_version','capabilities'})
        seat = self.seats.get(authority['participant_id'])
        require(seat is not None and authority['actor_id'] == seat['actor_id']
                and type(authority['capabilities']) is list
                and set(authority['capabilities']) <= set(seat['capabilities'])
                and library.ENQUEUE_CAPABILITY in authority['capabilities'])
        library._token(authority['authority_version'], 'authority_version')
        origin = Origin(seat['actor_id'], authority['participant_id'], authority['authority_version'],
                        authority['authority_version'], tuple(authority['capabilities']))
        return library.participant_scope(origin, binding=self.binding)

    def once(self):
        request = read(self.channel, self.peer)
        if request == {'kind':'poll'}:
            if select.select([self.reports], [], [], 0)[0]:
                raw, _, flags, _ = self.reports.recvmsg(16384)
                require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                message = json.loads(raw, object_pairs_hook=_unique)
                require(set(message) == {'nonce','report'} and type(message['nonce']) is str
                        and len(message['nonce']) == 32)
                report = message['report']
                send(self.channel, {'kind':'report', 'report':report})
                response = read(self.channel,self.peer,seconds=2)
                accepted = response == {'kind':'report-result', 'accepted':True}
                try: self.reports.send(('recorded:' + message['nonce']).encode() if accepted else b'unconfirmed')
                except BlockingIOError: pass  # Missing ACK is replayed, never guessed.
            send(self.channel, {'kind':'polled'})
            return
        require(set(request) == {'kind','sequence','authority','operation_id','request_id','value','at','run_id'}
                and request['kind']=='capture' and type(request['sequence']) is int
                and request['sequence'] > 0)
        scope = self._scope(request['authority']); seq=request['sequence']
        def current():
            if self.closed.is_set() or self.current() is not True: return False
            send(self.channel, {'kind':'current','sequence':seq})
            response=read(self.channel,self.peer)
            return (response == {'kind':'current','sequence':seq,'active':True}
                    and self.current() is True)
        require(current())
        result = self.endpoint_for().contact(scope=scope,current=current,
            **{k:request[k] for k in ('operation_id','request_id','value','at','run_id')})
        send(self.channel, {'kind':'result','sequence':seq,
                           'result':safe_result(result,request['request_id'])})

    def run(self):
        try:
            while not self.closed.is_set():
                require(self.current() is True and alive(self.peer.pidfd))
                if select.select([self.channel],[],[],.1)[0]: self.once()
        except Exception as error:
            self.failure = type(error).__name__
            self.closed.set()
            try:self.channel.shutdown(socket.SHUT_RDWR)
            except OSError:pass


class Relay:
    """Authenticated Supervisor hop; dedicated channels avoid control races."""
    def __init__(self, hub_channel, hub_origin, root_channel, root_origin):
        self.hub_channel,self.hub_origin=hub_channel,hub_origin
        self.root_channel,self.root_origin=root_channel,root_origin
        self.closed=threading.Event();self.failure=None
        self.thread=threading.Thread(target=self.run,daemon=True)

    def start(self): self.thread.start()

    def run(self):
        try:
            while not self.closed.is_set():
                require(alive(self.hub_origin.pidfd) and alive(self.root_origin.pidfd))
                if not select.select([self.hub_channel],[],[],.1)[0]:continue
                request=read(self.hub_channel,self.hub_origin);send(self.root_channel,request)
                deadline=time.monotonic()+60
                while True:
                    require(time.monotonic()<deadline)
                    response=read(self.root_channel,self.root_origin)
                    send(self.hub_channel,response)
                    if response.get('kind') in ('result','polled'):break
                    require(response.get('kind') in ('current','report'))
                    send(self.root_channel,read(self.hub_channel,self.hub_origin))
        except Exception as error:
            self.failure=type(error).__name__;self.closed.set()
        finally:
            for channel in (self.hub_channel,self.root_channel):
                try:channel.shutdown(socket.SHUT_RDWR)
                except OSError:pass

    def close(self):
        self.closed.set()
        for channel in (self.hub_channel,self.root_channel):
            try:channel.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        self.thread.join(timeout=6)
        if self.thread.is_alive(): return False
        for channel in (self.hub_channel,self.root_channel):channel.close()
        self.root_origin.close()
        return True
