"""One private Supervisor↔external Broker channel, using existing kernel origin.

No Participant-selected process, endpoint, credential, filesystem or RPC command.
The trusted Supervisor alone vouches for an already checked immutable seat.
"""
from dataclasses import asdict
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import uuid

from .forge_wire import request_json, MAX_REQUEST
from .forge import ForgeBinding
from .forge_read import ExternalReadBroker, MAX_RESULT
from .kernel_origin import HeldOrigin, OriginDenied, alive, enable, receive
from .ledger import Command, Event, LedgerError, Origin, Transition, _json
from .lifecycle import _unique_object

_FRAME = 40000


def reserve_forge_operation(ledger, binding, envelope, origin, authorize):
    """Keep the existing Room-wide ID namespace without copying read content."""
    if (type(binding) is not ForgeBinding or binding.room_id != ledger.room_id
            or type(origin) is not Origin
            or authorize() is not True):
        raise LedgerError('FORBIDDEN')
    if type(envelope) is not dict: raise LedgerError('INVALID_FORGE_ENVELOPE')
    kind=envelope.get('kind')
    if kind=='forge-reconcile':
        if (set(envelope)!={'id','kind','audit_reference','mutation'}
                or type(envelope['mutation']) is not dict
                or set(envelope['mutation']) not in ({'id','kind','argv'},{'id','kind','argv','body'})
                or envelope['mutation']['kind']!='forge-write'):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        if not {'forge-read','forge-write'} <= set(origin.capabilities): raise LedgerError('FORBIDDEN')
    else:
        if (set(envelope) not in ({'id','kind','argv'},{'id','kind','argv','body'})
                or kind not in {'forge-read','forge-write'}
                or (kind=='forge-read' and 'body' in envelope)):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        if kind not in origin.capabilities: raise LedgerError('FORBIDDEN')
    metadata = {'request_digest':hashlib.sha256((request_json(envelope) if kind!='forge-read' else _json(envelope)).encode()).hexdigest(),
        'host':binding.host,'repository':binding.repository}
    command = Command(envelope['id'],envelope['kind']+'-external',binding.project_id,None,metadata)
    try:
        return ledger.apply(command, origin, authorize=lambda *_:authorize(),
            decide=lambda state,_:Transition(state,(Event(envelope['kind']+'-reserved',metadata),),{'status':'RESERVED'}))
    except LedgerError as error:
        if error.code in {'STORAGE_ERROR','CLOSED'}:
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        raise


def reserve_read_operation(ledger,binding,envelope,origin,authorize):
    if type(envelope) is dict and envelope.get('kind') in {'forge-write','forge-reconcile'}:
        raise LedgerError('INVALID_FORGE_ENVELOPE')
    return reserve_forge_operation(ledger,binding,envelope,origin,authorize)


class ReadOwner:
    """One live read owner per audit/Room/instance; lock never enters gh."""
    def __init__(self, audit_path, room_id, room_instance):
        audit_path = Path(audit_path)
        if not audit_path.is_absolute() or audit_path.resolve() != audit_path:
            raise LedgerError('INVALID_STORE')
        key = hashlib.sha256(_json([room_id,room_instance]).encode()).hexdigest()
        self.path = audit_path.with_name(audit_path.name + '.read-' + key + '.lock')
        self.fd = -1

    def __enter__(self):
        import fcntl
        import stat
        self.fd = os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            node = os.fstat(self.fd)
            if not stat.S_ISREG(node.st_mode) or node.st_uid != os.getuid() or node.st_mode & 0o077:
                raise LedgerError('INVALID_STORE')
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return self
        except BaseException:
            os.close(self.fd);self.fd=-1
            raise LedgerError('BROKER_OWNER_UNAVAILABLE') from None

    def __exit__(self,*_):
        if self.fd >= 0:os.close(self.fd);self.fd=-1


def send_result(channel, request_id, result, *, request=False):
    raw = (request_json(result) if request else _json(result)).encode()
    if len(raw) > (MAX_REQUEST if request else 1_048_576): raise LedgerError('OUTPUT_LIMIT')
    digest = hashlib.sha256(raw).hexdigest()
    count = max(1, (len(raw) + _FRAME - 1) // _FRAME)
    for index in range(count):
        frame = {'request_id': request_id, 'index': index, 'count': count, 'sha256': digest,
                 'data': base64.b64encode(raw[index * _FRAME:(index + 1) * _FRAME]).decode('ascii')}
        packet = _json(frame).encode()
        if channel.send(packet) != len(packet): raise OriginDenied('partial Broker frame')


def receive_result(channel, worker, request_id, *, first=None, request=False):
    raw = bytearray(); expected = None
    for index in range(28 if request else 27):
        if index == 0 and first is not None:
            frame = first
        else:
            with receive(channel) as record:
                worker.require(record)
                frame = json.loads(record.data, object_pairs_hook=_unique_object)
        if (type(frame) is not dict or set(frame) != {'request_id','index','count','sha256','data'}
                or frame['request_id'] != request_id or type(frame['index']) is not int or frame['index'] != index
                or type(frame['count']) is not int or not 1 <= frame['count'] <= (28 if request else 27)
                or type(frame['sha256']) is not str or len(frame['sha256']) != 64
                or type(frame['data']) is not str):
            raise OriginDenied('invalid Broker frame')
        scope = (frame['count'], frame['sha256'])
        if expected is not None and expected != scope: raise OriginDenied('changed Broker response')
        expected = scope
        chunk = base64.b64decode(frame['data'], validate=True)
        if len(chunk) > _FRAME or (index + 1 < frame['count'] and len(chunk) != _FRAME):
            raise OriginDenied('invalid Broker chunk size')
        raw.extend(chunk)
        if len(raw) > (MAX_REQUEST if request else 1_048_576): raise OriginDenied('oversized Broker response')
        if index + 1 == frame['count']:
            if hashlib.sha256(raw).hexdigest() != frame['sha256']: raise OriginDenied('Broker digest mismatch')
            return json.loads(raw, object_pairs_hook=_unique_object)
    raise OriginDenied('incomplete Broker response')


class ReadBrokerClient:
    """Supervisor-owned object, never supplied by a Participant request."""
    def __init__(self, channel, supervisor, binding, room_instance, *, worker_uid, worker_gid):
        if type(binding) is not ForgeBinding or binding.room_id != supervisor.room_id:
            raise LedgerError('ROOM_MISMATCH')
        self.channel, self.supervisor, self.binding, self.room_instance = channel, supervisor, binding, room_instance
        self.lock = threading.Lock(); self.closed = False; self.worker = None; self._guards = {}
        enable(channel); channel.settimeout(40)
        nonce = uuid.uuid4().hex
        scope = {**asdict(binding), 'room_instance':room_instance}
        hello = _json({'kind': 'READ_BROKER_HELLO', 'nonce': nonce, 'binding':scope}).encode()
        if channel.send(hello) != len(hello): raise OriginDenied('partial Broker bootstrap')
        with receive(channel) as record:
            if record.credentials[1:] != (worker_uid, worker_gid):
                raise OriginDenied('unexpected Broker identity')
            ready = json.loads(record.data)
            expected = {'kind': 'READ_BROKER_READY', 'nonce': nonce, 'binding':scope}
            if type(ready) is not dict: raise OriginDenied('invalid Broker bootstrap')
            self.write_enabled = ready.get('mutation_enabled') is True
            self.projection_enabled = ready.get('projection_enabled') is True
            extensions={**({'mutation_enabled':True} if self.write_enabled else {}),
                **({'projection_enabled':True} if self.projection_enabled else {})}
            if ready != {**expected,**extensions}:
                raise OriginDenied('uncorrelated Broker bootstrap')
            self.worker = HeldOrigin(record)

    def prepare(self, envelope, origin, *, authorize=None):
        if self.closed or type(origin) is not Origin: raise LedgerError('FORBIDDEN')
        if type(envelope) is dict and envelope.get('kind') in {'forge-write','forge-reconcile'} and not self.write_enabled:
            raise LedgerError('FORGE_WRITE_UNAVAILABLE')
        if type(envelope) is dict and envelope.get('kind')=='forge-projection' and not self.projection_enabled:
            raise LedgerError('FORGE_PROJECTION_UNAVAILABLE')
        state = self.supervisor._read()  # Caller holds existing lifecycle lock.
        if (not state or state['phase'] != 'running' or state['instance_id'] != self.room_instance
                or state['spec']['project_id'] != self.binding.project_id):
            raise LedgerError('ROOM_NOT_RUNNING')
        request_id = uuid.uuid4().hex
        if len(self._guards) >= 8: raise LedgerError('READ_CAPACITY')
        packet = {'request_id': request_id, 'room_id': self.binding.room_id,
                'room_instance': self.room_instance, 'origin': origin.canonical(), 'envelope': envelope}
        encoded = request_json(packet).encode()
        if len(encoded) > MAX_REQUEST: raise LedgerError('INVALID_FORGE_ENVELOPE')
        self._guards[request_id] = (hashlib.sha256(encoded).hexdigest(), authorize)
        return packet

    def perform(self, packet):
        with self.lock:
            if self.closed or not alive(self.worker.pidfd): raise LedgerError('BROKER_UNAVAILABLE')
            if packet.get('request_id') not in self._guards: raise LedgerError('FORBIDDEN')
            digest, guard = self._guards.pop(packet['request_id'])
            raw = request_json(packet).encode()
            if len(raw) > MAX_REQUEST or hashlib.sha256(raw).hexdigest() != digest:
                raise LedgerError('INVALID_FORGE_ENVELOPE')
            try:
                # Guard rechecks current process/epoch under the existing Room
                # lock immediately before dispatch. No new request is issued
                # after Stop; already accepted I/O may finish but not disclose.
                if guard is not None:
                    with self.supervisor._locked():
                        if guard() is not True: raise LedgerError('FORBIDDEN')
                        send_result(self.channel,packet['request_id'],packet,request=True)
                else:
                    send_result(self.channel,packet['request_id'],packet,request=True)
                while True:
                    result = receive_result(self.channel, self.worker, packet['request_id'])
                    if type(result) is not dict or set(result) != {'authorize'}: break
                    nonce = result['authorize']
                    if type(nonce) is not str or len(nonce)!=32: raise OriginDenied('invalid authority challenge')
                    allowed = False
                    if guard is not None:
                        try:
                            with self.supervisor._locked(): allowed = guard() is True
                        except LedgerError: pass
                    response = _json({'request_id':packet['request_id'],'authorization':nonce,'allowed':allowed}).encode()
                    if self.channel.send(response)!=len(response): raise OriginDenied('partial authority response')
                if type(result) is not dict or set(result) not in ({'ok','observation'},{'ok','error'}):
                    raise OriginDenied('invalid Broker result')
                if result['ok'] is not True: raise LedgerError(result['error'])
                if guard is not None:
                    with self.supervisor._locked():
                        if guard() is not True: raise LedgerError('FORBIDDEN')
                return ({'admission':'not-evaluated', **result['observation']} if packet['envelope']['kind'] in {'forge-write','forge-reconcile','forge-projection'}
                        else {'admission': 'not-evaluated', 'observation': result['observation']})
            except (OSError, OriginDenied, ValueError):
                self.close()
                raise LedgerError('BROKER_UNAVAILABLE') from None
            finally:
                self._guards.pop(packet['request_id'], None)

    def denied(self, code):
        # The code is chosen by the trusted controller, never raw client prose.
        with self.lock:
            if self.closed: raise LedgerError('AUDIT_UNAVAILABLE')
            request_id = uuid.uuid4().hex
            packet = {'request_id':request_id,'room_id':self.binding.room_id,
                'room_instance':self.room_instance,'denial':code}
            raw = request_json(packet).encode()
            if self.channel.send(raw) != len(raw): raise LedgerError('AUDIT_UNAVAILABLE')
            reply = receive_result(self.channel, self.worker, request_id)
            if reply != {'ok':True}: raise LedgerError('AUDIT_UNAVAILABLE')

    def close(self):
        self.closed = True
        if self.worker is not None: self.worker.close()
        self.channel.close()


class ProjectionBrokerClient:
    """Trusted Hub adapter over the existing Supervisor-owned private channel.

    No Participant dispatch accepts forge-projection. Every authority challenge
    rechecks both the Room incarnation and current outbox version before contact.
    """
    def __init__(self, client):
        if type(client) is not ReadBrokerClient or not client.projection_enabled:
            raise LedgerError('FORGE_PROJECTION_UNAVAILABLE')
        self.client=client

    def _call(self,action,intent,operation,authorize,observed=None):
        from .forge_projection_broker import hub_origin
        envelope={'id':operation,'kind':'forge-projection','action':action,'intent':intent}
        if observed is not None:envelope['observed']=observed
        def guard():
            state=self.client.supervisor._read()
            return (state is not None and state['phase']=='running'
                and state['instance_id']==self.client.room_instance and authorize() is True)
        with self.client.supervisor._locked():
            if not guard():raise LedgerError('FORBIDDEN')
            packet=self.client.prepare(envelope,hub_origin(self.client.room_instance),authorize=guard)
        reply=self.client.perform(packet)
        reply.pop('admission',None)
        return reply

    def observe(self,intent,operation_id,*,authorize):
        return self._call('observe',intent,operation_id,authorize)

    def repair(self,intent,operation_id,observed,*,authorize):
        return self._call('repair',intent,operation_id,authorize,observed)


def serve(channel, broker, *, supervisor_uid, supervisor_gid):
    """Fixed external process entrypoint over an inherited private endpoint."""
    if type(broker) is not ExternalReadBroker: raise LedgerError('INVALID_READ_BROKER')
    enable(channel); channel.settimeout(45)
    with receive(channel) as record:
        if record.credentials[1:] != (supervisor_uid, supervisor_gid):
            raise OriginDenied('unexpected Supervisor identity')
        hello = json.loads(record.data, object_pairs_hook=_unique_object)
        if (type(hello) is not dict or set(hello) != {'kind','nonce','binding'}
                or hello['kind'] != 'READ_BROKER_HELLO' or type(hello['nonce']) is not str
                or len(hello['nonce']) != 32
                or hello['binding'] != {**asdict(broker.binding),'room_instance':broker.room_instance}):
            broker.denied('PROJECT_MISMATCH')
            raise OriginDenied('invalid Broker bootstrap')
        supervisor = HeldOrigin(record)
    try:
        ready = _json({'kind':'READ_BROKER_READY','nonce':hello['nonce'],'binding':hello['binding'],
            **({'mutation_enabled':True} if broker.mutations is not None else {}),
            **({'projection_enabled':True} if broker.projections is not None else {})}).encode()
        if channel.send(ready) != len(ready): raise OriginDenied('partial Broker bootstrap')
        while alive(supervisor.pidfd):
            try:
                with receive(channel) as record:
                    supervisor.require(record)
                    packet = json.loads(record.data, object_pairs_hook=_unique_object)
                if type(packet) is dict and set(packet)=={'request_id','index','count','sha256','data'}:
                    packet = receive_result(channel,supervisor,packet['request_id'],first=packet,request=True)
            except (OriginDenied, ValueError):
                broker.denied('WRONG_PROCESS')
                raise
            if (type(packet) is not dict or set(packet) not in ({'request_id','room_id','room_instance','origin','envelope'},
                        {'request_id','room_id','room_instance','denial'})
                    or packet['room_id'] != broker.binding.room_id or packet['room_instance'] != broker.room_instance
                    or type(packet['request_id']) is not str or len(packet['request_id']) != 32):
                broker.denied('PROJECT_MISMATCH')
                raise OriginDenied('invalid Supervisor read scope')
            try:
                if 'denial' in packet:
                    broker.denied(packet['denial'])
                    send_result(channel, packet['request_id'], {'ok':True})
                    continue
                origin_doc = packet['origin']
                if type(origin_doc) is not dict or set(origin_doc) != {'actor_id','participant_id','incarnation_id','authority_version','capabilities'}:
                    raise LedgerError('FORBIDDEN')
                if type(origin_doc['capabilities']) is not list: raise LedgerError('FORBIDDEN')
                origin = Origin(**{**origin_doc, 'capabilities': tuple(origin_doc['capabilities'])})
                def current_authority():
                    if not alive(supervisor.pidfd): return False
                    if packet['envelope'].get('kind') not in {'forge-write','forge-reconcile','forge-projection'}: return True
                    nonce = uuid.uuid4().hex
                    send_result(channel,packet['request_id'],{'authorize':nonce})
                    with receive(channel) as record:
                        supervisor.require(record)
                        answer = json.loads(record.data,object_pairs_hook=_unique_object)
                    if answer not in ({'request_id':packet['request_id'],'authorization':nonce,'allowed':True},
                                      {'request_id':packet['request_id'],'authorization':nonce,'allowed':False}):
                        raise OriginDenied('invalid current authority')
                    return answer['allowed'] is True
                result = broker.execute(packet['envelope'], origin=origin,authorize=current_authority)
                reply = {'ok': True, 'observation': result}
            except LedgerError as error:
                broker.denied(error.code)
                reply = {'ok': False, 'error': error.code}
            send_result(channel, packet['request_id'], reply)
            if broker.failed: break
    finally:
        supervisor.close(); channel.close()


class ActorCredentialFile:
    """Trusted Broker-only exact Actor/host lookup, no ambient token fallback."""
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_absolute() or self.path.resolve() != self.path:
            raise LedgerError('CREDENTIAL_UNAVAILABLE')

    def __call__(self, actor, host):
        from .github_read import ProviderFailure
        import stat
        try:
            if host != 'github.com': raise ValueError()
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                node = os.fstat(fd)
                if (not stat.S_ISREG(node.st_mode) or node.st_uid != os.getuid()
                        or node.st_mode & 0o077 or node.st_size > 65536): raise ValueError()
                raw = os.read(fd, 65537)
            finally: os.close(fd)
            values = json.loads(raw, object_pairs_hook=_unique_object)
            if type(values) is not dict or set(values) != {'github.com'} or type(values['github.com']) is not dict:
                raise ValueError()
            secret = values['github.com'].get(actor)
            if (type(secret) is not str or not 1 <= len(secret) <= 8192
                    or any(ord(c) < 33 or ord(c) > 126 for c in secret)): raise ValueError()
            return {'GH_TOKEN':secret}
        except (OSError, ValueError, TypeError):
            raise ProviderFailure('CREDENTIAL_UNAVAILABLE') from None


def main():
    """Fixed host entrypoint; stdin is trusted startup config, not client traffic."""
    import sys
    from contextlib import ExitStack
    from .forge_audit import ForgeAudit
    from .github_executor import GhSurfaceTransport
    from .github_logs import GitHubJobLogTransport
    from .github_read import GitHubProject
    from .forge_read_provider import BrokerReadProvider
    if len(sys.argv) != 2 or not sys.argv[1].isdigit() or int(sys.argv[1]) < 3 or os.getuid() == 0:
        raise LedgerError('INVALID_READ_BROKER')
    config = json.loads(sys.stdin.buffer.readline(16385), object_pairs_hook=_unique_object)
    expected = {'room_id','room_instance','project_id','repository','deployment_id','audit_path',
        'result_root','credential_path','gh_executable','gh_sha256','supervisor_uid','supervisor_gid'}
    if (type(config) is not dict or set(config) not in (expected,expected|{'mutation_actors','work_labels'},expected|{'mutation_actors','work_labels','projection_actor'})
            or any(type(config[k]) is not int or config[k] <= 0 for k in ('supervisor_uid','supervisor_gid'))
            or config['supervisor_uid'] == os.getuid()):
        raise LedgerError('INVALID_READ_BROKER')
    binding = ForgeBinding(config['room_id'],config['project_id'],config['repository'])
    # This dedicated single-threaded owner is the sole gh-child reaper.
    # Reset inherited SIGCHLD ignore/SA_NOCLDWAIT before any child can exist.
    import signal
    signal.signal(signal.SIGCHLD,signal.SIG_DFL)
    credentials = ActorCredentialFile(config['credential_path'])
    with ExitStack() as stack:
        stack.enter_context(ReadOwner(config['audit_path'],binding.room_id,config['room_instance']))
        audit = stack.enter_context(ForgeAudit(config['audit_path'],config['deployment_id']))
        transports = {}
        def select(actor):
            if actor not in transports:
                transport = GhSurfaceTransport(config['gh_executable'],config['gh_sha256'],actor,credentials)
                stack.callback(transport.close)
                transports[actor] = BrokerReadProvider(GitHubProject(binding.repository),transport,
                    GitHubJobLogTransport(actor,credentials))
            return transports[actor]
        mutations = None
        if 'mutation_actors' in config:
            from .forge_mutations import ExternalMutationBroker
            from .github_mutations import GitHubMutationProvider
            def mutation_provider(actor):
                transport = select(actor).transport
                return GitHubMutationProvider(GitHubProject(binding.repository),
                    lambda method,path,body: transport.get(path) if method=='GET' else
                    transport.mutate(method,path,body,repository=binding.repository))
            mutations = ExternalMutationBroker(binding,config['room_instance'],audit,config['mutation_actors'],
                mutation_provider,work_labels=config['work_labels'])
            mutations.recover(lambda _:True)
        projections=None
        if 'projection_actor' in config:
            from .forge_projection_broker import ExternalProjectionBroker
            actor=config['projection_actor']
            if type(actor) is not str or actor not in config['mutation_actors']:
                raise LedgerError('INVALID_PROJECTION_OWNER')
            projections=ExternalProjectionBroker(binding,config['room_instance'],audit,actor,
                config['mutation_actors'][actor],mutation_provider)
        broker = ExternalReadBroker(binding,config['room_instance'],audit,select,config['result_root'],
            mutations=mutations,projections=projections)
        # The exclusive owner lock proves no old process can still complete a
        # pending read. Recovery records unknown, never repeats provider I/O.
        broker.recover(lambda _:True)
        channel = socket.socket(fileno=int(sys.argv[1]))
        serve(channel,broker,supervisor_uid=config['supervisor_uid'],supervisor_gid=config['supervisor_gid'])


if __name__ == '__main__':
    main()
