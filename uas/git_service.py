"""External Git byte Broker, reached only by its bound trusted Supervisor.

The Supervisor authenticates native children through git_process and rechecks
their current Room/epoch before every forwarded record.  No credential, Actor
selection, arbitrary SSH option or reusable SSH-agent socket is disclosed.
"""
from dataclasses import asdict
import hashlib
import json
import os
import selectors
import socket
import time
import threading
import uuid

from .forge import ForgeBinding
from .git_audit import GitAudit
from .git_policy import GitPolicyError, parse_ssh
from .git_sources import AdvertisedRefs
from .git_transport import GitTransportError, SshTransport
from .kernel_origin import HeldOrigin, OriginDenied, alive, enable, receive
from .ledger import LedgerError, Origin, _json, _token
from .lifecycle import _unique_object


def decode(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise OriginDenied('invalid Git control record')
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if type(value) is not dict: raise ValueError()
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise OriginDenied('invalid Git control JSON') from None


def send(channel, value):
    raw = _json(value).encode()
    if len(raw) > 65536 or channel.send(raw) != len(raw):
        raise OriginDenied('incomplete Git control record')


def origin_from_document(value):
    if type(value) is not dict or set(value) != {'actor_id', 'participant_id', 'incarnation_id',
                                                'authority_version', 'capabilities'}:
        raise LedgerError('FORBIDDEN')
    if (type(value['capabilities']) is not list or len(value['capabilities']) > 32
            or any(type(item) is not str for item in value['capabilities'])
            or value['capabilities'] != sorted(set(value['capabilities']))):
        raise LedgerError('FORBIDDEN')
    origin = Origin(value['actor_id'], value['participant_id'], value['incarnation_id'],
                    value['authority_version'], tuple(value['capabilities']))
    if origin.canonical() != value: raise LedgerError('FORBIDDEN')
    return origin


class ExternalGitBroker:
    def __init__(self, binding, room_instance, audit, transport):
        if (type(binding) is not ForgeBinding or type(audit) is not GitAudit
                or type(transport) is not SshTransport or transport.binding != binding):
            raise LedgerError('INVALID_GIT_BROKER')
        self.binding, self.room_instance = binding, _token(room_instance)
        self.audit, self.transport = audit, transport
        self.failed = False

    def scope(self):
        return {**asdict(self.binding), 'room_instance': self.room_instance}

    def run(self, channel, supervisor, request):
        from .git_stream import GitStreamError, proxy_ssh
        if self.failed or self.audit.failed or self.transport.failed:
            raise LedgerError('AUDIT_UNAVAILABLE')
        if (type(request) is not dict or set(request) != {'kind', 'id', 'binding', 'origin', 'argv'}
                or request['kind'] != 'GIT_OPEN' or request['binding'] != self.scope()):
            raise LedgerError('INVALID_GIT_REQUEST')
        operation_id = _token(request['id'])
        origin = origin_from_document(request['origin'])
        target = parse_ssh(request['argv'], self.binding)
        capability = 'git-read' if target.service == 'git-upload-pack' else 'git-push'
        if capability not in origin.capabilities: raise LedgerError('FORBIDDEN')
        meta = {'room_id': self.binding.room_id, 'room_instance': self.room_instance,
            'project_id': self.binding.project_id, 'actor_id': origin.actor_id,
            'participant_id': origin.participant_id, 'incarnation_id': origin.incarnation_id,
            'authority_version': origin.authority_version,
            'origin_digest': hashlib.sha256(_json(origin.canonical()).encode()).hexdigest(),
            'host': target.host, 'repository': target.repository, 'service': target.service,
            'request_digest': hashlib.sha256(_json(request).encode()).hexdigest()}
        begun = self.audit.begin(operation_id, meta)
        if not begun['execute']:
            # Git byte streams cannot be replayed from counts/digests; even a
            # completed native push must not be performed again automatically.
            send(channel, {'kind': 'refused', 'error': 'GIT_STREAM_ALREADY_CONSUMED',
                           'record': begun['record']['result']})
            return
        key = begun['record']['id']
        contact = 'read' if target.service == 'git-upload-pack' else 'write-possible'
        source = AdvertisedRefs()
        receipt = None
        try:
            session = self.transport.open(origin.actor_id, target)
        except GitTransportError as error:
            before_contact = error.code in {'SSH_CREDENTIAL_UNAVAILABLE', 'SSH_EXECUTABLE_UNAVAILABLE',
                'INVALID_GIT_TARGET', 'INVALID_SSH_CONFIGURATION', 'SSH_TRANSPORT_UNAVAILABLE',
                'SSH_OWNERSHIP_UNKNOWN', 'SSH_SESSION_CAPACITY'}
            result = {'status': 'DENIED' if before_contact else ('UNKNOWN_OUTCOME' if contact == 'write-possible' else 'FAILED'),
                'contact': 'none' if before_contact else contact, 'input_bytes': 0,
                'output_bytes': 0, 'output_sha256': None}
            self.audit.finish(key, result)
            send(channel, {'kind': 'refused', 'error': 'GIT_TRANSPORT_UNAVAILABLE', 'record': result})
            return
        try:
            send(channel, {'kind': 'ready'})
            previous_timeout = channel.gettimeout()
            try:
                receipt = proxy_ssh(channel, session, supervisor.require,
                    lambda: not supervisor.revoked and alive(supervisor.pidfd),
                    observe_output=source.feed if target.service == 'git-upload-pack' else None)
            finally:
                channel.settimeout(previous_timeout)
            status = 'OK' if receipt.exit_code == 0 else ('UNKNOWN_OUTCOME' if contact == 'write-possible' else 'FAILED')
        except GitStreamError as error:
            receipt = error.receipt
            status = ('UNKNOWN_OUTCOME' if contact == 'write-possible' else
                      'TIMEOUT' if error.code == 'GIT_STREAM_TIMEOUT' else
                      'REVOKED' if error.code == 'GIT_STREAM_REVOKED' else 'FAILED')
        except BaseException:
            try: session.abort()
            finally:
                self.failed = True
            # Interrupted start remains pending until a positively fenced
            # replacement recovers it; do not claim a terminal from uncertainty.
            raise
        result = {'status': status, 'contact': contact,
            'input_bytes': 0 if receipt is None else receipt.input_bytes,
            'output_bytes': 0 if receipt is None else receipt.output_bytes,
            'output_sha256': None if receipt is None else receipt.output_sha256}
        try:
            self.audit.finish(key, result)
        except BaseException:
            self.failed = True
            self.transport.close()
            raise  # Never send success before the durable terminal.
        send(channel, {'kind': 'exit', 'code': 0 if status == 'OK' else 128,
            'status': status, 'repository': target.repository,
            'advertised': list(source.result(transport_succeeded=status == 'OK')[:1024])})
        # An upload-pack may exit before the client closes its input. The
        # trusted pump records whether it actually consumed that EOF. On the
        # serialized Supervisor socket, one already-sent EOF may still follow
        # this terminal; it is not a new request or a reusable authority grant.
        return status == 'OK' and receipt is not None and receipt.input_eof is False


def serve(channel, broker, *, supervisor_uid, supervisor_gid):
    """Inherited private endpoint. The launcher never connects here directly."""
    if type(broker) is not ExternalGitBroker: raise LedgerError('INVALID_GIT_BROKER')
    enable(channel); channel.settimeout(35)
    with receive(channel) as record:
        if record.credentials[1:] != (supervisor_uid, supervisor_gid):
            raise OriginDenied('unexpected Git Supervisor identity')
        hello = decode(record.data)
        if (set(hello) != {'kind', 'nonce', 'binding'} or hello['kind'] != 'GIT_HELLO'
                or type(hello['nonce']) is not str or len(hello['nonce']) != 32
                or any(c not in '0123456789abcdef' for c in hello['nonce'])
                or hello['binding'] != broker.scope()):
            raise OriginDenied('invalid Git Broker bootstrap')
        supervisor = HeldOrigin(record)
    try:
        send(channel, {'kind': 'GIT_READY', 'nonce': hello['nonce'], 'binding': broker.scope()})
        late_eof = False
        while not broker.failed and alive(supervisor.pidfd):
            # Idle is not a transaction deadline. Keep the persistent Broker
            # available after Workstation Stop while observing owner death.
            channel.settimeout(1)
            try:
                record = receive(channel)
            except socket.timeout:
                continue
            channel.settimeout(35)
            with record:
                supervisor.require(record)
                request = decode(record.data)
            if late_eof and request == {'kind': 'eof'}:
                late_eof = False
                continue
            # The sole Supervisor serializes streams on this FIFO channel.
            # Any next request ends the preceding stream's one-EOF allowance;
            # data, cancel, duplicate EOF and arbitrary frames are never drained
            # or answered with an uncorrelated refusal for the next operation.
            late_eof = False
            if request.get('kind') != 'GIT_OPEN':
                raise OriginDenied('unexpected Git Broker request boundary')
            try:
                late_eof = broker.run(channel, supervisor, request) is True
            except (LedgerError, GitPolicyError) as error:
                if broker.audit.failed or broker.transport.failed:
                    broker.failed = True
                    raise
                send(channel, {'kind': 'refused', 'error': error.code, 'record': None})
    finally:
        supervisor.close()
        broker.transport.close()


def validate_reply(value, target, *, streaming=False):
    """No unvalidated advertisement becomes trusted source evidence."""
    from .git_stream import parse_frame
    import re
    if type(value) is not dict: raise OriginDenied('invalid Git Broker reply')
    kind = value.get('kind')
    if kind == 'data' and streaming:
        parse_frame(_json(value).encode())
    elif kind == 'refused' and not streaming:
        if (set(value) != {'kind', 'error', 'record'} or type(value['error']) is not str
                or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', value['error'])
                or value['record'] is not None and type(value['record']) is not dict):
            raise OriginDenied('invalid Git Broker refusal')
    elif kind == 'exit' and streaming:
        if (set(value) != {'kind', 'code', 'status', 'repository', 'advertised'}
                or type(value['code']) is not int or value['code'] not in {0, 128}
                or value['status'] not in {'OK', 'FAILED', 'UNKNOWN_OUTCOME', 'TIMEOUT', 'REVOKED'}
                or (value['code'] == 0) != (value['status'] == 'OK')
                or value['repository'] != target.repository or type(value['advertised']) is not list
                or len(value['advertised']) > 1024
                or any(type(oid) is not str or not re.fullmatch('[0-9a-f]{40}', oid) for oid in value['advertised'])
                or value['advertised'] != sorted(set(value['advertised']))
                or value['advertised'] and (value['status'] != 'OK' or target.service != 'git-upload-pack')):
            raise OriginDenied('invalid Git Broker terminal')
    else:
        raise OriginDenied('invalid Git Broker stream frame')
    return value


class GitBrokerClient:
    """Supervisor-only; all caller forwarding rechecks the bound native task."""
    def __init__(self, channel, binding, room_instance, *, broker_uid, broker_gid):
        self.channel, self.binding = channel, binding
        self.scope = {**asdict(binding), 'room_instance': _token(room_instance)}
        self.closed = False
        self._stream_lock = threading.Lock()
        enable(channel); channel.settimeout(35)
        nonce = uuid.uuid4().hex
        send(channel, {'kind': 'GIT_HELLO', 'nonce': nonce, 'binding': self.scope})
        with receive(channel) as record:
            if (record.credentials[1:] != (broker_uid, broker_gid)
                    or decode(record.data) != {'kind': 'GIT_READY', 'nonce': nonce, 'binding': self.scope}):
                raise OriginDenied('Git Broker identity/binding differs')
            self.worker = HeldOrigin(record)

    def relay(self, caller, authority, *, operation_id, argv, lock):
        """One byte stream at a time; no interleaved endpoint ownership."""
        if not self._stream_lock.acquire(blocking=False):
            raise LedgerError('GIT_BROKER_BUSY')
        try:
            return self._relay(caller, authority, operation_id=operation_id, argv=argv, lock=lock)
        except BaseException:
            self.close()
            raise
        finally:
            self._stream_lock.release()

    def _relay(self, caller, authority, *, operation_id, argv, lock):
        """Bounded bidirectional seqpacket pump; no blocking I/O under lock."""
        import select
        from .git_stream import MAX_BYTES, parse_frame
        if self.closed: raise LedgerError('GIT_BROKER_UNAVAILABLE')
        target = parse_ssh(argv, self.binding)
        request = {'kind': 'GIT_OPEN', 'id': _token(operation_id), 'binding': self.scope,
                   'origin': authority.origin.canonical(), 'argv': argv}
        deadline = time.monotonic() + 32
        modes = (caller.gettimeout(), self.channel.gettimeout())
        def current():
            with lock(): authority.current()
            if time.monotonic() >= deadline: raise OriginDenied('Git stream relay deadline exceeded')
        def transmit(channel, value):
            packet = _json(value).encode()
            if len(packet) > 65536: raise OriginDenied('Git relay frame exceeds bound')
            while True:
                current()
                try:
                    with lock():
                        authority.current()
                        if channel.send(packet) != len(packet): raise OriginDenied('incomplete Git relay frame')
                    return
                except BlockingIOError:
                    select.select([], [channel], [], .1)
        input_bytes = 0
        input_eof = False
        def accept_input(raw):
            nonlocal input_bytes, input_eof
            kind, payload = parse_frame(raw)
            if kind == 'eof':
                if input_eof: raise OriginDenied('duplicate Git input EOF')
                input_eof = True
            elif kind == 'data':
                if input_eof: raise OriginDenied('Git input data after EOF')
                input_bytes += len(payload)
                if input_bytes > MAX_BYTES: raise OriginDenied('Git relay input limit')
            else:
                raise OriginDenied('unexpected Git input frame')
        def finish_terminal():
            # The Worker acknowledges consuming our terminal on the same FIFO
            # channel as earlier input. Drain only that authenticated stream;
            # never let crossed data/EOF become the next command's input.
            while True:
                current()
                try:
                    with receive(caller) as record:
                        with lock(): authority.require(record)
                        value = decode(record.data)
                        if value == {'kind': 'stream-finished'}:
                            current()
                            return
                        accept_input(record.data)
                except BlockingIOError:
                    select.select([caller], [], [], .1)
        try:
            caller.setblocking(False); self.channel.setblocking(False)
            transmit(self.channel, request)
            while True:
                current()
                try:
                    with receive(self.channel) as record:
                        self.worker.require(record); reply = decode(record.data)
                    break
                except BlockingIOError:
                    select.select([self.channel], [], [], .1)
            if reply.get('kind') == 'refused':
                validate_reply(reply, target); transmit(caller, reply)
                finish_terminal()
                return reply
            if reply != {'kind': 'ready'}: raise OriginDenied('invalid Git stream readiness')
            transmit(caller, reply)
            queued = {'caller': [], 'broker': []}
            sizes = {'caller': 0, 'broker': 0}
            channels = {'caller': caller, 'broker': self.channel}
            terminal = None
            limit = 131072
            with selectors.DefaultSelector() as poll:
                watched = {}
                def watch(name, events):
                    channel = channels[name]
                    if events and name not in watched:
                        poll.register(channel, events, name); watched[name] = events
                    elif events and watched[name] != events:
                        poll.modify(channel, events, name); watched[name] = events
                    elif not events and name in watched:
                        poll.unregister(channel); del watched[name]
                while True:
                    current()
                    if terminal is not None and not queued['caller']:
                        finish_terminal()
                        return terminal
                    for name, other in (('caller', 'broker'), ('broker', 'caller')):
                        events = selectors.EVENT_WRITE if queued[name] else 0
                        if terminal is None and sizes[other] <= limit - 65536:
                            events |= selectors.EVENT_READ
                        watch(name, events)
                    for event, mask in poll.select(.1):
                        name = event.data
                        channel = channels[name]
                        if mask & selectors.EVENT_READ:
                            try:
                                with receive(channel) as record:
                                    if name == 'caller':
                                        with lock(): authority.require(record)
                                        accept_input(record.data)
                                        frame = decode(record.data)
                                    else:
                                        self.worker.require(record)
                                        frame = validate_reply(decode(record.data), target, streaming=True)
                            except BlockingIOError:
                                continue
                            current()
                            destination = 'broker' if name == 'caller' else 'caller'
                            packet = _json(frame).encode()
                            if len(packet) > 65536 or sizes[destination] + len(packet) > limit:
                                raise OriginDenied('Git relay queue exceeds bound')
                            queued[destination].append(packet); sizes[destination] += len(packet)
                            if name == 'broker' and frame.get('kind') == 'exit':
                                terminal = frame
                                queued['broker'].clear(); sizes['broker'] = 0
                        if mask & selectors.EVENT_WRITE and queued[name]:
                            packet = queued[name][0]
                            try:
                                with lock():
                                    authority.current()
                                    sent = channel.send(packet)
                            except BlockingIOError:
                                continue
                            if sent != len(packet): raise OriginDenied('incomplete Git relay frame')
                            queued[name].pop(0); sizes[name] -= sent
        except BaseException:
            # Cancellation is not proof that an already-contacted push had no
            # effect. Never wait under the lifecycle lock, never replay.
            try: self.channel.send(b'{"kind":"cancel"}')
            except (OSError, OriginDenied): pass
            self.close()
            raise
        finally:
            try: caller.settimeout(modes[0])
            finally:
                if not self.closed: self.channel.settimeout(modes[1])

    def close(self):
        if not self.closed:
            self.closed = True
            try: self.worker.close()
            finally: self.channel.close()


def main():
    """Fixed external host entrypoint; trusted stdin config, never client input.

    This does not provision credentials or alter permissions. Existing private
    credential paths and the pinned SSH executable belong to the external owner.
    A pending prior start blocks restart: a lock alone is not proof that an old
    SSH child exited. Supervisor recovery must positively fence that owner first
    and record GitAudit.recover; no automatic recontact/replay is performed here.
    """
    from contextlib import ExitStack
    from pathlib import Path
    import signal
    import sys
    from .forge_audit import ForgeAudit
    from .forge_read_service import ReadOwner
    from .git_transport import GitTransportConfig, SshActorCredential
    if (len(sys.argv) != 2 or not sys.argv[1].isdigit() or not 3 <= int(sys.argv[1]) <= 2**20
            or os.getuid() in {0, 65530, 65532} or signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL):
        raise LedgerError('INVALID_GIT_BROKER')
    config = decode(sys.stdin.buffer.readline(65537))
    if (set(config) != {'binding', 'room_instance', 'deployment_id', 'audit_path', 'ssh_executable',
            'ssh_sha256', 'credentials', 'supervisor_uid', 'supervisor_gid'}
            or type(config['binding']) is not dict or set(config['binding']) != {'room_id', 'project_id', 'repository', 'host'}
            or any(type(config[key]) is not int or config[key] <= 0 for key in ('supervisor_uid', 'supervisor_gid'))
            or config['supervisor_uid'] == os.getuid() or type(config['credentials']) is not list
            or not 1 <= len(config['credentials']) <= 32
            or any(type(row) is not dict or set(row) != {'actor_id', 'key_path', 'known_hosts_path'} for row in config['credentials'])):
        raise LedgerError('INVALID_GIT_BROKER')
    binding = ForgeBinding(**config['binding'])
    _token(binding.room_id); _token(binding.project_id)
    instance = _token(config['room_instance'])
    credential_config = GitTransportConfig(config['ssh_executable'], config['ssh_sha256'],
        tuple(SshActorCredential(**row) for row in config['credentials']))
    # Reuse the existing bounded private-file owner mechanism, disjoint family.
    owner = ReadOwner(config['audit_path'], binding.room_id, instance)
    key = hashlib.sha256(_json([binding.room_id, instance]).encode()).hexdigest()
    owner.path = Path(config['audit_path']).with_name(Path(config['audit_path']).name + '.git-' + key + '.lock')
    with ExitStack() as stack:
        stack.enter_context(owner)
        audit_owner = stack.enter_context(ForgeAudit(config['audit_path'], config['deployment_id']))
        audit = GitAudit(audit_owner)
        for row in audit_owner._db.execute('SELECT s.id FROM git_starts s LEFT JOIN git_terminals t ON s.id=t.id '
                'WHERE s.room_id=? AND t.id IS NULL LIMIT 257', (binding.room_id,)):
            if audit.get(row['id'])['metadata']['room_instance'] == instance:
                raise LedgerError('GIT_RECOVERY_REQUIRES_FENCED_OWNER')
        transport = SshTransport(credential_config, binding); stack.callback(transport.close)
        channel = stack.enter_context(socket.socket(fileno=int(sys.argv[1])))
        serve(channel, ExternalGitBroker(binding, instance, audit, transport),
              supervisor_uid=config['supervisor_uid'], supervisor_gid=config['supervisor_gid'])


if __name__ == '__main__': main()
