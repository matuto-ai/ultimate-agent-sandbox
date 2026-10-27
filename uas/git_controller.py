"""Trusted Git command composition; public callers send arguments, not evidence.

The existing Supervisor supplies the admitted checkout, fixed worker factory,
Room lifecycle lock and current kernel ancestry. Neither a launcher response nor
mutable HEAD/object files can stand in for a controlled worker receipt.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import base64
import select
import socket
import time
from pathlib import PurePosixPath
import re
import threading
import uuid

from .forge import ForgeBinding
from .git_policy import GitIdentity, GitPolicyError, generated_help, parse_git, parse_ssh
from .git_provenance import GitProvenance, _run_scope, parse_commit
from .git_service import decode, send
from .git_worker import TrustedGitWorker
from .git_worker_native import receive_blob, send_blob
from .kernel_origin import OriginDenied, alive, enable, receive
from .ledger import LedgerError, _json, _token

_OID = re.compile(r'[0-9a-f]{40}\Z')


def _oid(value, *, nullable=True):
    if value is None and nullable: return None
    if type(value) is not str or not _OID.fullmatch(value):
        raise LedgerError('INVALID_GIT_NATIVE_RESULT')
    return value


@dataclass(frozen=True)
class GitCheckout:
    id: str
    worktree: str
    gitdir: str
    common: str
    config: str
    helpers: str
    checkout_owner: int

    def __post_init__(self):
        _token(self.id)
        if type(self.checkout_owner) is not int or self.checkout_owner <= 0:
            raise LedgerError('INVALID_GIT_CHECKOUT')
        for name in ('worktree', 'gitdir', 'common', 'config', 'helpers'):
            path = getattr(self, name)
            if (type(path) is not str or not path.startswith('/') or path.startswith('//')
                    or str(PurePosixPath(path)) != path or '..' in PurePosixPath(path).parts
                    or '\x00' in path):
                raise LedgerError('INVALID_GIT_CHECKOUT')

    def view(self):
        return {key: value for key, value in asdict(self).items() if key != 'id'}


class _RunAuthority:
    def __init__(self, caller, resolver, checkout_id, scope):
        self.caller, self.resolver, self.checkout_id, self.scope = caller, resolver, checkout_id, scope
        self.origin = caller.origin

    def current(self):
        self.caller.current()
        if _run_scope(self.resolver(self.origin, self.checkout_id)) != self.scope:
            raise OriginDenied('Git Run scope changed')
        return True

    def require(self, record):
        self.caller.require(record)
        return self.current()


class _WorkerAuthority:
    def __init__(self, worker, caller):
        self.worker, self.caller = worker, caller
        self.origin = caller.origin

    def current(self):
        self.caller.current()
        launch = self.worker.launch
        launch.endpoint.require()
        if launch.state != 'active' or launch.origin.revoked or not alive(launch.origin.pidfd):
            raise OriginDenied('Git worker revoked')
        return True

    def require(self, record):
        self.worker.require(record)
        return self.current()


class GitCoordinator:
    """One Room/Project owner; dependencies are trusted Supervisor objects.

    worker_factory(origin) must create/release exactly one GitExecLaunch, never
    a caller-selected executable. Checkout locks are in addition to the durable
    provenance slot: an uncertain command cannot be retried after a restart.
    """
    def __init__(self, binding, room_instance, identities, checkouts, provenance,
                 broker, worker_factory, *, backend_fd, backend_sha256, lifecycle_lock, run_scope):
        if (type(binding) is not ForgeBinding or type(provenance) is not GitProvenance
                or provenance.room_id != binding.room_id or provenance.project_id != binding.project_id
                or type(identities) is not dict or not identities
                or any(type(value) is not GitIdentity or key != value.actor_id for key, value in identities.items())
                or type(checkouts) is not tuple or not 1 <= len(checkouts) <= 32
                or any(type(value) is not GitCheckout for value in checkouts)
                or len({value.worktree for value in checkouts}) != len(checkouts)
                or len({value.id for value in checkouts}) != len(checkouts)
                or type(backend_fd) is not int or backend_fd < 3
                or type(backend_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', backend_sha256)
                or not callable(worker_factory) or not callable(lifecycle_lock) or not callable(run_scope)):
            raise LedgerError('INVALID_GIT_CONTROLLER')
        self.binding, self.room_instance = binding, _token(room_instance)
        self.identities, self.checkouts = dict(identities), {value.worktree: value for value in checkouts}
        self.provenance, self.broker, self.worker_factory = provenance, broker, worker_factory
        self.backend_fd, self.backend_sha256 = backend_fd, backend_sha256
        self.lifecycle_lock, self.run_scope = lifecycle_lock, run_scope
        self._locks = {value.id: threading.Lock() for value in checkouts}
        self.failed = False

    def request(self, request, authority):
        if self.failed: raise LedgerError('GIT_CONTROLLER_FENCED')
        if (type(request) is not dict or set(request) != {'kind', 'id', 'invoked_as', 'argv', 'cwd'}
                or request['kind'] != 'git' or type(request['cwd']) is not str):
            raise LedgerError('INVALID_GIT_REQUEST')
        operation = _token(request['id'])
        command = parse_git(request['invoked_as'], request['argv'])
        with self.lifecycle_lock(): authority.current()
        capability = 'git-read' if command.kind in {'help', 'local-read', 'remote-read'} else 'git-push'
        if capability not in authority.origin.capabilities: raise LedgerError('FORBIDDEN')
        if command.kind == 'help':
            return {'code': 0, 'status': 'OK', 'stdout': generated_help().encode(), 'stderr': b'', 'receipt': None}
        checkout = self.checkouts.get(command.cwd or request['cwd'])
        if checkout is None:
            raise LedgerError('GIT_CHECKOUT_ROOT_REQUIRED')
        if command.kind not in {'local-read', 'remote-read'}:
            with self.lifecycle_lock():
                scope = _run_scope(self.run_scope(authority.origin, checkout.id))
                authority = _RunAuthority(authority, self.run_scope, checkout.id, scope)
                authority.current()
        identity = self.identities.get(authority.origin.actor_id)
        if identity is None: raise LedgerError('GIT_IDENTITY_UNAVAILABLE')
        lock = self._locks[checkout.id]
        if not lock.acquire(blocking=False): raise LedgerError('GIT_CHECKOUT_BUSY')
        try:
            result = self._execute(request, command, checkout, identity, authority, operation)
            # Internal held scope guard; never serialized onto the launcher wire.
            result['_disclosure_authority'] = authority
            return result
        finally:
            lock.release()

    def _prepare(self, command, checkout, preflight, source, authority, identity, operation, digest, source_repository=None):
        provenance = self.provenance
        pending = provenance.pending_checkout(checkout.id)
        if pending is not None and pending['status'] != 'CONFLICT':
            if command.kind not in {'local-read', 'remote-read'}:
                raise LedgerError('GIT_CHECKOUT_FENCED')
        if command.kind == 'cherry-pick':
            oid = _oid(preflight['source_oid'], nullable=False)
            if parse_commit(source).oid != oid: raise LedgerError('GIT_SOURCE_MISMATCH')
            if command.args in (('--continue',), ('--abort',)):
                if (pending is None or pending['status'] != 'CONFLICT'
                        or pending['source_oid'] != oid or pending['parent_oid'] != preflight['head']
                        or pending['run_scope'] != authority.scope):
                    raise LedgerError('GIT_CONFLICT_STATE_MISMATCH')
                anchor = provenance.source_anchor(pending['source_repository'], oid)
                if anchor['raw_digest'] != hashlib.sha256(source).hexdigest():
                    raise LedgerError('GIT_SOURCE_MISMATCH')
                receipt = provenance.continue_conflict(pending['operation_id'], authority.origin,
                    identity, authorize=authority.current)
                return receipt, command.args == ('--abort',)
            if pending is not None: raise LedgerError('GIT_CHECKOUT_BUSY')
            if command.args != (oid,): raise LedgerError('GIT_SOURCE_MISMATCH')
            repositories = [source_repository] if source_repository is not None else provenance.advertised_repositories(oid)
            if not repositories: raise LedgerError('GIT_SOURCE_UNANCHORED')
            # Every member is authenticated same-Forge advertisement evidence.
            # No author email is ever mapped to an Actor.
            repository = repositories[0]
            if source_repository is None:
                provenance.anchor_source(repository, oid, source, contributors=provenance.contributors(oid),
                    advertised_tip=oid, proof_digest=hashlib.sha256(source).hexdigest())
            receipt = provenance.prepare(operation, authority.origin, identity, kind='cherry-pick',
                source_repository=repository, source_oid=oid, parent_oid=preflight['head'],
                checkout_id=checkout.id, request_digest=digest, authorize=authority.current, run_scope=authority.scope)
            return receipt, False
        if preflight['source_oid'] is not None or source:
            raise LedgerError('UNEXPECTED_GIT_SOURCE')
        if command.kind == 'commit':
            if pending is not None: raise LedgerError('GIT_CHECKOUT_BUSY')
            return provenance.prepare(operation, authority.origin, identity,
                parent_oid=preflight['parent'], checkout_id=checkout.id,
                request_digest=digest, authorize=authority.current, run_scope=authority.scope,
                replaced_oid=preflight['head'] if '--amend' in command.args else None), False
        if pending is not None and command.kind not in {'local-read', 'remote-read'}:
            if pending['status'] != 'CONFLICT' or command.command not in {'add', 'rm', 'mv', 'restore'}:
                raise LedgerError('GIT_CHECKOUT_BUSY')
            provenance.record_resolution(pending['operation_id'], authority.origin, authorize=authority.current)
        return None, False

    def _execute(self, request, command, checkout, identity, authority, operation):
        worker, receipt, dispatched = None, None, False
        push_possible, push_unknown = False, False
        worker_failed, cleanup_attempted = False, False
        digest = hashlib.sha256(_json(request).encode()).hexdigest()
        try:
            with self.lifecycle_lock():
                authority.current()
                self.provenance.reserve_worker(operation, checkout.id, authority.origin, digest, authorize=authority.current)
                worker = self.worker_factory(authority.origin)
                if type(worker) is not TrustedGitWorker:
                    raise OriginDenied('exact trusted Git worker required')
                seat = worker.launch.seat
                if (seat.room_id != self.binding.room_id or seat.room_instance != self.room_instance
                        or seat.actor_id != authority.origin.actor_id
                        or seat.participant_id != authority.origin.participant_id):
                    raise OriginDenied('Git worker seat mismatch')
                guarded = _WorkerAuthority(worker, authority)
                guarded.current()
                worker.channel.settimeout(.1)
                worker.configure({'kind': 'execute', 'version': 1, 'operation_id': operation,
                    'invoked_as': request['invoked_as'], 'argv': request['argv'],
                    'binding': asdict(self.binding), 'identity': asdict(identity), 'view': checkout.view(),
                    'backend_sha256': self.backend_sha256}, self.backend_fd)
            deadline = time.monotonic() + 40
            def receive_current():
                nonlocal worker_failed
                while time.monotonic() < deadline:
                    with self.lifecycle_lock(): guarded.current()
                    try:
                        value = worker.receive()
                        if value == {'kind': 'worker-failed', 'code': 'GIT_WORKER_COMMAND_FAILED'}:
                            worker_failed = True
                            raise LedgerError('GIT_WORKER_COMMAND_FAILED')
                        return value
                    except socket.timeout: continue
                raise OriginDenied('Git command deadline exceeded')
            preflight = receive_current()
            if type(preflight) is not dict or set(preflight) != {'kind', 'head', 'parent', 'source_oid', 'head_ref'} or preflight['kind'] != 'preflight':
                raise LedgerError('INVALID_GIT_PREFLIGHT')
            for key in ('head', 'parent', 'source_oid'): _oid(preflight[key])
            if (type(preflight['head_ref']) is not str or preflight['head_ref'] != 'HEAD'
                    and not re.fullmatch(r'refs/heads/[A-Za-z0-9][A-Za-z0-9_./-]{0,255}', preflight['head_ref'])):
                raise LedgerError('INVALID_GIT_PREFLIGHT')
            source = receive_blob('source', receive_current) if preflight['source_oid'] is not None else b''
            if (command.kind == 'cherry-pick' and command.args not in (('--continue',), ('--abort',))
                    and preflight['source_oid'] is not None
                    and not self.provenance.advertised_repositories(preflight['source_oid'])):
                from .git_source_proof import verify
                from .lifecycle import _unique_object
                tips = self.provenance.source_tips()
                if not tips: raise LedgerError('GIT_SOURCE_UNANCHORED')
                tip_oids = sorted({row['oid'] for row in tips})
                with self.lifecycle_lock():
                    guarded.current()
                    worker.reply({'kind': 'source-proof', 'source_oid': preflight['source_oid'], 'tips': tip_oids})
                raw_proof = receive_blob('source-proof', receive_current)
                try: proof = json.loads(raw_proof, object_pairs_hook=_unique_object)
                except (ValueError, UnicodeError, RecursionError): raise LedgerError('INVALID_GIT_SOURCE_PROOF') from None
                proved = verify(proof, source_oid=preflight['source_oid'], tips=tip_oids)
                if proved != source: raise LedgerError('GIT_SOURCE_PROOF_MISMATCH')
                repository = next(row['repository'] for row in tips if row['oid'] == proof['tip_oid'])
                # Persist the verified parent chain's source anchor, not a fake
                # advertisement. A separate event retains its exact tip binding.
                self.provenance.anchor_source(repository, preflight['source_oid'], source,
                    contributors=self.provenance.contributors(preflight['source_oid']),
                    advertised_tip=proof['tip_oid'], proof_digest=hashlib.sha256(raw_proof).hexdigest())
                source_repository = repository
            else:
                source_repository = None
            with self.lifecycle_lock():
                guarded.current()
                receipt, aborting = self._prepare(command, checkout, preflight, source, authority, identity, operation, digest, source_repository=source_repository)
                if receipt is not None and not receipt['execute']:
                    raise LedgerError('GIT_COMMAND_ALREADY_CONSUMED')
                if command.kind not in {'local-read', 'remote-read'}:
                    if not self.provenance.record_mutation(operation, authority.scope, authority.origin,
                            command.command, digest, authorize=authority.current):
                        raise LedgerError('GIT_COMMAND_ALREADY_CONSUMED')
                dispatched = True  # A failed send may nevertheless have reached Git.
                worker.reply({'kind': 'go', 'operation_id': operation})
            streams = 0
            while True:
                value = receive_current()
                with self.lifecycle_lock(): guarded.current()
                if value.get('kind') != 'ssh-open': break
                if set(value) != {'kind', 'argv'} or command.kind not in {'remote-read', 'remote-write'} or streams >= 4:
                    raise LedgerError('UNEXPECTED_GIT_TRANSPORT')
                target = parse_ssh(value['argv'], self.binding)
                if command.kind == 'remote-read' and target.service != 'git-upload-pack':
                    raise LedgerError('FORBIDDEN')
                streams += 1
                if target.service == 'git-receive-pack': push_possible = True
                terminal = self.broker.relay(worker.channel, guarded,
                    operation_id=hashlib.sha256((operation + ':' + str(streams)).encode()).hexdigest(),
                    argv=value['argv'], lock=self.lifecycle_lock)
                if target.service == 'git-receive-pack' and (terminal.get('status') == 'UNKNOWN_OUTCOME'
                        or terminal.get('error') == 'GIT_STREAM_ALREADY_CONSUMED'
                        or (terminal.get('record') or {}).get('status') == 'UNKNOWN_OUTCOME'):
                    push_unknown = True
                if terminal.get('status') == 'OK' and target.service == 'git-upload-pack':
                    self.provenance.record_advertisements(target.repository, terminal['advertised'])
            if (set(value) != {'kind', 'returncode', 'conflict', 'commit_oid'} or value['kind'] != 'result'
                    or type(value['returncode']) is not int or not -255 <= value['returncode'] <= 255
                    or type(value['conflict']) is not bool):
                raise LedgerError('INVALID_GIT_NATIVE_RESULT')
            oid = _oid(value['commit_oid'])
            stdout, stderr, raw = (receive_blob(name, receive_current) for name in ('stdout', 'stderr', 'commit'))
            if len(stdout) + len(stderr) > 1048576: raise LedgerError('GIT_OUTPUT_BOUND')
            with self.lifecycle_lock():
                guarded.current()
                status = 'UNKNOWN_OUTCOME' if push_unknown else 'OK' if value['returncode'] == 0 else 'FAILED'
                if receipt is None:
                    if oid is not None or raw: raise LedgerError('UNEXPECTED_GIT_COMMIT')
                elif aborting and value['returncode'] == 0 and not value['conflict'] and oid is None and not raw:
                    receipt = self.provenance.abort(receipt['operation_id'], authority.origin, authorize=authority.current)
                    status = 'ABORTED'
                elif oid is not None and parse_commit(raw).oid == oid and value['returncode'] == 0 and not value['conflict']:
                    receipt = self.provenance.finish(receipt['operation_id'], authority.origin, raw, authorize=authority.current)
                    status = 'COMMITTED'
                elif command.kind == 'cherry-pick' and not aborting and value['conflict'] and value['returncode'] != 0 and oid is None and not raw:
                    receipt = self.provenance.mark_conflict(receipt['operation_id'], authority.origin, authorize=authority.current)
                    status = 'CONFLICT'
                else:
                    receipt = self.provenance.mark_unknown(receipt['operation_id'], authority.origin, authorize=authority.current)
                    status = 'UNKNOWN'
                worker.reply({'kind': 'receipt', 'status': status})
            cleanup_attempted = True
            evidence = worker.finish(operation)
            self.provenance.finish_worker(operation, evidence)
            with self.lifecycle_lock(): authority.current()
            return {'code': value['returncode'] if status not in {'UNKNOWN', 'UNKNOWN_OUTCOME'} and value['returncode'] >= 0 else 128,
                        'status': status, 'stdout': stdout, 'stderr': stderr, 'receipt': receipt}
        except BaseException:
            if receipt is not None and receipt['execute']:
                try:
                    # Revocation cannot prohibit recording a conservative fence.
                    # This grants no execution/retry authority and releases no slot.
                    self.provenance.mark_unknown(receipt['operation_id'], authority.origin, authorize=lambda: True)
                except BaseException:
                    self.failed = True
            if worker is not None and not cleanup_attempted:
                try:
                    if not worker_failed:
                        worker.reply({'kind': 'cancel'} if dispatched else {'kind': 'deny', 'code': 'GIT_COMMAND_DENIED'})
                        # No Actor authority is granted here: only the exact
                        # already-owned worker may prove conservative cleanup.
                        worker.channel.settimeout(2)
                        failed = worker.receive()
                        if failed != {'kind': 'worker-failed', 'code': 'GIT_WORKER_COMMAND_FAILED'}:
                            raise OriginDenied('Git worker cleanup response differs')
                    cleanup_attempted = True
                    evidence = worker.finish(operation)
                    self.provenance.finish_worker(operation, evidence)
                except BaseException:
                    pass  # Durable active_workers slot survives restart.
            if push_possible:
                raise LedgerError('GIT_PUSH_OUTCOME_UNKNOWN') from None
            raise
        finally:
            if worker is not None:
                worker.launch.close()


def _output_frames(name, raw):
    count = max(1, (len(raw) + 32767) // 32768)
    yield {'kind': 'blob', 'name': name, 'bytes': len(raw), 'count': count,
           'sha256': hashlib.sha256(raw).hexdigest()}
    for index in range(count):
        yield {'kind': 'blob-part', 'name': name, 'index': index,
               'data': base64.b64encode(raw[index * 32768:(index + 1) * 32768]).decode('ascii')}


def disclose(channel, result, authority, lifecycle_lock):
    """Nonblocking per-frame disclosure; backpressure cannot hold revocation."""
    def frames():
        yield from _output_frames('stdout', result['stdout'])
        yield from _output_frames('stderr', result['stderr'])
        yield {'kind': 'exit', 'code': result['code'], 'status': result['status'], 'receipt': result['receipt']}
    previous = channel.gettimeout()
    channel.setblocking(False)
    deadline = time.monotonic() + 5
    try:
        for value in frames():
            while True:
                if time.monotonic() >= deadline: raise OriginDenied('Git output disclosure deadline')
                try:
                    with lifecycle_lock():
                        authority.current()
                        send(channel, value)  # Nonblocking atomic seqpacket send.
                    break
                except BlockingIOError:
                    select.select([], [channel], [], .1)  # No Room lock held.
    finally:
        channel.settimeout(previous)


def serve_one(channel, coordinator, child_authority, *, lifecycle_lock):
    """Called on the existing Supervisor-owned protected request endpoint."""
    enable(channel); channel.settimeout(40)
    authority = None
    try:
        with receive(channel) as record:
            with lifecycle_lock():
                authority = child_authority.bind(record)
                request = decode(record.data)
        result = coordinator.request(request, authority)
        disclosure_authority = result.pop('_disclosure_authority', authority)
        disclose(channel, result, disclosure_authority, lifecycle_lock)
        return result
    except (LedgerError, GitPolicyError, OriginDenied) as error:
        send(channel, {'kind': 'refused', 'error': getattr(error, 'code', 'GIT_AUTHORITY_DENIED'), 'record': None})
    finally:
        if authority is not None: authority.close()
