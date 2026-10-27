"""Composition inside the fixed, Supervisor-launched credential-free Git worker.

Nothing here admits a Participant or selects an Actor from shim input. The
Supervisor has already authenticated this distinct-UID worker and supplies one
operation, identity, immutable view and sealed backend. Native subprocesses are
owned exclusively by GitRuntime. Only the authenticated reference-transaction
receipt selects a created commit; native output is never commit authority.
"""
import base64
from contextlib import ExitStack, nullcontext
import errno
import hashlib
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import tempfile
import threading
import time

from .forge import ForgeBinding
from .git_policy import GitIdentity, GitTarget, parse_git
from .git_provenance import parse_commit
from .git_runtime import BACKEND_FD, GitRuntime, RuntimeView, SealedGit
from .git_service import decode, send
from .git_stream import MAX_BYTES, MAX_DATA, MAX_QUEUE, data_frame, parse_frame
from .kernel_origin import HeldOrigin, OriginDenied, alive, enable, receive
from .ledger import _token

MAX_BLOB = 1_048_576
_NAMES = {'source', 'source-proof', 'stdout', 'stderr', 'commit'}
_OID = re.compile(r'[0-9a-f]{40}\Z')
_CODE = re.compile(r'[A-Z][A-Z0-9_]{0,63}\Z')


class GitWorkerError(OriginDenied):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code='INVALID_GIT_WORKER_PROTOCOL'):
    raise GitWorkerError(code)


def send_blob(channel, name, data):
    if type(name) is not str or name not in _NAMES or type(data) is not bytes or len(data) > MAX_BLOB:
        _fail('INVALID_GIT_WORKER_BLOB')
    count = max(1, (len(data) + MAX_DATA - 1) // MAX_DATA)
    send(channel, {'kind': 'blob', 'name': name, 'bytes': len(data), 'count': count,
                   'sha256': hashlib.sha256(data).hexdigest()})
    for index in range(count):
        send(channel, {'kind': 'blob-part', 'name': name, 'index': index,
            'data': base64.b64encode(data[index * MAX_DATA:(index + 1) * MAX_DATA]).decode('ascii')})


def receive_blob(name, recv_callback):
    """Shared with Supervisor controller; callback authenticates every record."""
    if type(name) is not str or name not in _NAMES or not callable(recv_callback):
        _fail('INVALID_GIT_WORKER_BLOB')
    header = recv_callback()
    if (type(header) is not dict or set(header) != {'kind', 'name', 'bytes', 'count', 'sha256'}
            or header['kind'] != 'blob' or header['name'] != name
            or type(header['bytes']) is not int or not 0 <= header['bytes'] <= MAX_BLOB
            or type(header['count']) is not int
            or header['count'] != max(1, (header['bytes'] + MAX_DATA - 1) // MAX_DATA)
            or type(header['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', header['sha256'])):
        _fail('INVALID_GIT_WORKER_BLOB')
    raw = bytearray()
    for index in range(header['count']):
        part = recv_callback()
        if (type(part) is not dict or set(part) != {'kind', 'name', 'index', 'data'}
                or part['kind'] != 'blob-part' or part['name'] != name
                or type(part['index']) is not int or part['index'] != index
                or type(part['data']) is not str or len(part['data']) > 43692):
            _fail('INVALID_GIT_WORKER_BLOB')
        try:
            block = base64.b64decode(part['data'], validate=True)
        except (ValueError, UnicodeError):
            _fail('INVALID_GIT_WORKER_BLOB')
        expected = min(MAX_DATA, header['bytes'] - index * MAX_DATA)
        if len(block) != expected or base64.b64encode(block).decode('ascii') != part['data']:
            _fail('INVALID_GIT_WORKER_BLOB')
        raw.extend(block)
    if len(raw) != header['bytes'] or hashlib.sha256(raw).hexdigest() != header['sha256']:
        _fail('INVALID_GIT_WORKER_BLOB')
    return bytes(raw)


def _supervisor_value(channel, supervisor):
    with receive(channel) as record:
        supervisor.require(record)
        return decode(record.data)


def validate_configuration(value):
    if (type(value) is not dict or set(value) != {'kind', 'version', 'operation_id', 'invoked_as',
            'argv', 'binding', 'identity', 'view', 'backend_sha256'}
            or value['kind'] != 'execute' or type(value['version']) is not int or value['version'] != 1
            or type(value['binding']) is not dict
            or set(value['binding']) != {'room_id', 'project_id', 'repository', 'host'}
            or type(value['identity']) is not dict or set(value['identity']) != {'actor_id', 'name', 'email'}
            or type(value['view']) is not dict
            or set(value['view']) != {'worktree', 'gitdir', 'common', 'config', 'helpers', 'checkout_owner'}
            or type(value['view']['checkout_owner']) is not int or value['view']['checkout_owner'] <= 0
            or type(value['backend_sha256']) is not str
            or not re.fullmatch(r'[0-9a-f]{64}', value['backend_sha256'])):
        _fail('INVALID_GIT_WORKER_CONFIGURATION')
    try:
        _token(value['operation_id'])
        binding = ForgeBinding(**value['binding'])
        _token(binding.room_id)
        _token(binding.project_id)
        GitTarget(binding.host, binding.repository, 'git-upload-pack')
        identity = GitIdentity(**value['identity'])
        command = parse_git(value['invoked_as'], value['argv'])
    except Exception:
        _fail('INVALID_GIT_WORKER_CONFIGURATION')
    return binding, identity, command


def _server_frame(value):
    if type(value) is not dict:
        _fail()
    kind = value.get('kind')
    if kind == 'data':
        # Use the same exact data shape/canonical base64 as the external pump.
        from .ledger import _json
        parse_frame(_json(value).encode())
    elif kind == 'ready':
        if value != {'kind': 'ready'}:
            _fail()
    elif kind == 'exit':
        if (set(value) not in ({'kind', 'code', 'status'}, {'kind', 'code', 'status', 'repository', 'advertised'})
                or type(value['code']) is not int or not 0 <= value['code'] <= 255
                or type(value['status']) is not str or not _CODE.fullmatch(value['status'])):
            _fail()
    elif kind == 'refused':
        if (set(value) != {'kind', 'error', 'record'} or type(value['error']) is not str
                or not _CODE.fullmatch(value['error'])):
            _fail()
    else:
        _fail()
    return kind


class WorkerBridge:
    """One trusted worker thread mediates untrusted shim requests to Supervisor.

    Main thread does not touch the Supervisor channel during run(). No Actor or
    Room field is accepted from the shim, and all Supervisor records match its
    held process object. Native SSH-shim tasks are bound per local stream too.
    """
    def __init__(self, channel, supervisor, shim_channel):
        self.channel, self.supervisor, self.shim_channel = channel, supervisor, shim_channel
        self.stopping = threading.Event()
        self.cancelled = threading.Event()
        self.failure = None
        self.thread = None
        self._active = False

    def current(self):
        return (not self.cancelled.is_set() and self.failure is None
                and not self.supervisor.revoked and alive(self.supervisor.pidfd))

    def start(self):
        if self.thread is not None:
            _fail()
        self.thread = threading.Thread(target=self._loop, name='uas-git-shim-bridge', daemon=True)
        self.thread.start()

    def _loop(self):
        shim = None
        terminal = False
        shim_eof = False
        shim_bytes = 0
        try:
            with selectors.DefaultSelector() as poll:
                poll.register(self.shim_channel, selectors.EVENT_READ, 'shim')
                poll.register(self.channel, selectors.EVENT_READ, 'supervisor')
                deadline = time.monotonic() + 35
                while not self.stopping.is_set():
                    if not self.current() or time.monotonic() >= deadline:
                        _fail('GIT_WORKER_CANCELLED')
                    for key, _ in poll.select(.1):
                        if key.data == 'shim':
                            with receive(self.shim_channel) as record:
                                value = decode(record.data)
                                if not self._active:
                                    if (record.credentials[1:] != (os.getuid(), os.getgid())
                                            or set(value) != {'kind', 'argv'} or value['kind'] != 'ssh-open'
                                            or type(value['argv']) is not list or not 1 <= len(value['argv']) <= 16
                                            or any(type(word) is not str or not word or len(word) > 4096
                                                   or '\x00' in word for word in value['argv'])):
                                        _fail()
                                    shim = HeldOrigin(record)
                                    self._active = True
                                    terminal = shim_eof = False
                                    shim_bytes = 0
                                else:
                                    shim.require(record)
                                    if terminal and value == {'kind': 'shim-finished'}:
                                        if not self.current():
                                            _fail('GIT_WORKER_CANCELLED')
                                        send(self.shim_channel, {'kind': 'shim-finish-ack'})
                                        shim.close()
                                        shim = None
                                        self._active = False
                                        terminal = False
                                        continue
                                    frame_kind, payload = parse_frame(record.data)
                                    if frame_kind == 'eof':
                                        if shim_eof:
                                            _fail()
                                        shim_eof = True
                                    elif frame_kind == 'data':
                                        if shim_eof:
                                            _fail()
                                        shim_bytes += len(payload)
                                        if shim_bytes > MAX_BYTES:
                                            _fail('GIT_SHIM_INPUT_LIMIT')
                                    elif terminal:
                                        _fail()
                                    # Terminal response and shim input may cross.
                                    # Drain only this live bound sender until its
                                    # explicit FIFO finish barrier; never relay
                                    # post-terminal input to another operation.
                                    if terminal:
                                        continue
                                if not self.current():
                                    _fail('GIT_WORKER_CANCELLED')
                                send(self.channel, value)
                        else:
                            value = _supervisor_value(self.channel, self.supervisor)
                            if value == {'kind': 'cancel'}:
                                _fail('GIT_WORKER_CANCELLED')
                            if not self._active or terminal:
                                _fail()
                            kind = _server_frame(value)
                            send(self.shim_channel, value)
                            if kind in {'exit', 'refused'}:
                                terminal = True
        except BaseException:
            self.failure = 'GIT_WORKER_BRIDGE_FAILED'
            self.cancelled.set()
            if self._active:
                try:
                    send(self.channel, {'kind': 'cancel'})
                except BaseException:
                    pass
        finally:
            if shim is not None:
                shim.close()
            if self._active and self.stopping.is_set():
                self.failure = 'GIT_WORKER_BRIDGE_INCOMPLETE'
                try:
                    send(self.channel, {'kind': 'cancel'})
                except BaseException:
                    pass

    def stop(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
            if self.thread.is_alive():
                self.failure = 'GIT_WORKER_BRIDGE_INCOMPLETE'
                self.cancelled.set()
                try:
                    self.channel.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.thread.join(timeout=1)
        if self.failure is not None:
            _fail(self.failure)


def _native(runtime, argv, current):
    result = runtime.run(parse_git('git', argv), current=current, timeout=10)
    if type(result.returncode) is not int or type(result.stdout) is not bytes or type(result.stderr) is not bytes:
        _fail('INVALID_GIT_NATIVE_RESULT')
    return result


def _resolve(runtime, ref, current):
    result = _native(runtime, ['rev-parse', '--verify', ref], current)
    if result.returncode != 0:
        if result.returncode == 128 and not result.stdout:
            return None
        _fail('GIT_NATIVE_PREFLIGHT_FAILED')
    try:
        oid = result.stdout.decode('ascii')
    except UnicodeError:
        _fail('GIT_NATIVE_PREFLIGHT_FAILED')
    if not oid.endswith('\n') or not _OID.fullmatch(oid[:-1]):
        _fail('GIT_NATIVE_PREFLIGHT_FAILED')
    return oid[:-1]


def _commit(runtime, oid, current):
    if type(oid) is not str or not _OID.fullmatch(oid):
        _fail('INVALID_GIT_NATIVE_COMMIT')
    result = _native(runtime, ['cat-file', '-p', oid], current)
    if result.returncode != 0:
        _fail('GIT_NATIVE_OBJECT_UNAVAILABLE')
    try:
        commit = parse_commit(result.stdout)
    except Exception:
        _fail('INVALID_GIT_NATIVE_COMMIT')
    if commit.oid != oid:
        _fail('GIT_NATIVE_OBJECT_CHANGED')
    return commit, result.stdout


def _valid_head_ref(value):
    return (type(value) is str and re.fullmatch(r'refs/heads/[A-Za-z0-9][A-Za-z0-9_./-]{0,240}', value)
            and '..' not in value and all(part and not part.startswith('.')
                and not part.endswith(('.', '.lock')) for part in value.split('/')))


def _head_ref(runtime, head, current):
    if head is not None:
        result = _native(runtime, ['rev-parse', '--symbolic-full-name', 'HEAD'], current)
        try:
            value = result.stdout.decode('ascii')
        except UnicodeError:
            _fail('GIT_HEAD_REF_UNKNOWN')
        if result.returncode != 0 or not value.endswith('\n'):
            _fail('GIT_HEAD_REF_UNKNOWN')
        value = value[:-1]
        if value != 'HEAD' and not _valid_head_ref(value):
            _fail('GIT_HEAD_REF_UNKNOWN')
        return value
    # rev-parse cannot resolve an unborn symbolic HEAD. Read only this exact
    # file in the already admitted gitdir, never a caller-supplied filesystem
    # path, and retain its full branch as the expected native transaction ref.
    descriptor = os.open('HEAD', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=runtime.view.gitdir_fd)
    try:
        node = os.fstat(descriptor)
        if not stat.S_ISREG(node.st_mode) or not 0 < node.st_size <= 1024:
            _fail('GIT_HEAD_REF_UNKNOWN')
        raw = os.read(descriptor, 1025)
        if len(raw) != node.st_size or not raw.startswith(b'ref: ') or not raw.endswith(b'\n'):
            _fail('GIT_HEAD_REF_UNKNOWN')
        try:
            value = raw[5:-1].decode('ascii')
        except UnicodeError:
            _fail('GIT_HEAD_REF_UNKNOWN')
        if not _valid_head_ref(value):
            _fail('GIT_HEAD_REF_UNKNOWN')
        return value
    finally:
        os.close(descriptor)


def _transaction(document, command, head, head_ref):
    from .git_transaction import ReferenceTransaction
    kind = 'abort' if command.kind == 'cherry-pick' and command.args == ('--abort',) else command.kind
    return ReferenceTransaction(document['operation_id'], expected_old=head,
                                expected_ref=head_ref, kind=kind)


def execute_native(channel, supervisor, document, runtime, bridge):
    """Testable operation composition; all native execution remains in runtime."""
    _, _, command = validate_configuration(document)
    current = lambda: (not supervisor.revoked and alive(supervisor.pidfd) and bridge.failure is None)
    head = _resolve(runtime, 'HEAD', current)
    head_ref = _head_ref(runtime, head, current)
    parent = head
    if command.kind == 'commit' and '--amend' in command.args:
        if head is None:
            _fail('GIT_AMEND_HEAD_UNAVAILABLE')
        previous, _ = _commit(runtime, head, current)
        parent = previous.parents[0] if previous.parents else None
    conflict_oid = _resolve(runtime, 'CHERRY_PICK_HEAD', current)
    source_oid = None
    source = None
    if command.kind == 'cherry-pick':
        source_oid = (conflict_oid if command.args in (('--continue',), ('--abort',)) else command.args[0])
        if source_oid is not None:
            _, source = _commit(runtime, source_oid, current)
    send(channel, {'kind': 'preflight', 'head': head, 'head_ref': head_ref,
                   'parent': parent, 'source_oid': source_oid})
    if source is not None:
        send_blob(channel, 'source', source)
    reply = _supervisor_value(channel, supervisor)
    if reply.get('kind') == 'source-proof':
        from .git_source_proof import build
        from .ledger import _json
        if (set(reply) != {'kind', 'source_oid', 'tips'} or reply['source_oid'] != source_oid
                or command.kind != 'cherry-pick' or command.args in (('--continue',), ('--abort',))):
            _fail('INVALID_GIT_SOURCE_PROOF')
        def source_object(oid):
            try: return _commit(runtime, oid, current)[1]
            except GitWorkerError as error:
                if error.code == 'GIT_NATIVE_OBJECT_UNAVAILABLE': return None
                raise
        proof = build(source_oid, reply['tips'], source_object, current=current)
        send_blob(channel, 'source-proof', _json(proof).encode())
        reply = _supervisor_value(channel, supervisor)
    if reply != {'kind': 'go', 'operation_id': document['operation_id']}:
        if (set(reply) == {'kind', 'code'} and reply['kind'] == 'deny'
                and type(reply['code']) is str and _CODE.fullmatch(reply['code'])):
            _fail(reply['code'])
        _fail()
    if not current():
        _fail('GIT_WORKER_CANCELLED')
    transaction = _transaction(document, command, head, head_ref) if command.kind in {'commit', 'cherry-pick'} else nullcontext(None)
    produced_oid = None
    with transaction as receipt:
        bridge.start()
        try:
            result = runtime.run(command, current=bridge.current, timeout=30, transaction=receipt)
            if receipt is not None:
                needs_commit = (command.kind == 'commit' or command.args != ('--abort',))
                produced_oid = receipt.committed_oid(required=result.returncode == 0 and needs_commit)
                if produced_oid is not None and result.returncode != 0:
                    _fail('GIT_COMMIT_OUTCOME_UNKNOWN')
        finally:
            bridge.stop()
    if (type(result.returncode) is not int or not -255 <= result.returncode <= 255
            or type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or len(result.stdout) + len(result.stderr) > MAX_BLOB):
        _fail('INVALID_GIT_NATIVE_RESULT')
    conflict = _resolve(runtime, 'CHERRY_PICK_HEAD', current) is not None
    commit_oid, raw_commit = None, b''
    if result.returncode == 0 and (command.kind == 'commit' or
            (command.kind == 'cherry-pick' and command.args != ('--abort',))):
        commit_oid = produced_oid
        _, raw_commit = _commit(runtime, commit_oid, current)
    send(channel, {'kind': 'result', 'returncode': result.returncode,
                   'conflict': conflict, 'commit_oid': commit_oid})
    send_blob(channel, 'stdout', result.stdout)
    send_blob(channel, 'stderr', result.stderr)
    send_blob(channel, 'commit', raw_commit)
    receipt = _supervisor_value(channel, supervisor)
    if (set(receipt) != {'kind', 'status'} or receipt['kind'] != 'receipt'
            or type(receipt['status']) is not str or not _CODE.fullmatch(receipt['status'])):
        _fail('GIT_RECEIPT_UNKNOWN')
    return receipt


def _remap_backend(owned):
    descriptor = owned[0]
    if type(descriptor) is not int or descriptor < 3:
        _fail('INVALID_GIT_BACKEND')
    if descriptor == BACKEND_FD:
        os.set_inheritable(descriptor, False)
        return descriptor
    try:
        os.fstat(BACKEND_FD)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
    else:
        _fail('GIT_BACKEND_DESCRIPTOR_COLLISION')
    os.dup2(descriptor, BACKEND_FD, inheritable=False)
    owned[0] = BACKEND_FD  # Ownership moves before a possibly ambiguous close.
    os.close(descriptor)
    return BACKEND_FD


def worker_main(channel, document, backend_fd, supervisor):
    """Own received backend and paths opened inside the admitted Workstation."""
    from .git_worker import open_inside
    # Register backend ownership before config validation, including refusal.
    backend_owned = [backend_fd]
    try:
        binding, identity, _ = validate_configuration(document)
        _remap_backend(backend_owned)
        with ExitStack() as stack:
            descriptors = {}
            for name in ('worktree', 'gitdir', 'common', 'config', 'helpers'):
                descriptor = open_inside(document['view'][name], directory=name != 'config')
                stack.callback(os.close, descriptor)
                descriptors[name] = descriptor
            view = RuntimeView(descriptors['worktree'], descriptors['gitdir'], descriptors['config'],
                descriptors['helpers'], binding=binding, common_fd=descriptors['common'],
                checkout_owner=document['view']['checkout_owner'])
            backend = SealedGit(backend_owned[0], document['backend_sha256'])
            worker_socket, shim_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            stack.callback(worker_socket.close)
            stack.callback(shim_socket.close)
            enable(worker_socket)
            enable(shim_socket)
            worker_socket.settimeout(35)
            home = stack.enter_context(tempfile.TemporaryDirectory(prefix='uas-native-git-'))
            runtime = GitRuntime(view, backend, identity, transport_fd=shim_socket.fileno(), home=home)
            bridge = WorkerBridge(channel, supervisor, worker_socket)
            try:
                return execute_native(channel, supervisor, document, runtime, bridge)
            except BaseException:
                # Only verified native group cleanup permits the worker's outer
                # quiescent/exit handshake. Closing a stream is not enough.
                if not runtime.quiescent or (bridge.thread is not None and bridge.thread.is_alive()):
                    raise
                send(channel, {'kind': 'worker-failed', 'code': 'GIT_WORKER_COMMAND_FAILED'})
                return {'kind': 'receipt', 'status': 'FAILED'}
    finally:
        descriptor, backend_owned[0] = backend_owned[0], -1
        os.close(descriptor)


def _shim_reply(channel, worker):
    with receive(channel) as record:
        worker.require(record)
        value = decode(record.data)
    if value == {'kind': 'shim-finish-ack'}:
        return 'shim-finish-ack', value
    return _server_frame(value), value


def shim_stream(channel, worker, *, stdin=0, stdout=1, timeout=30, initial_refused=False):
    """Fixed native-SSH stdio adapter. No credential, actor selector or shell."""
    pending_in, pending_out = [], bytearray()
    input_bytes = output_bytes = queued_input = 0
    eof = False
    exit_code = 128 if initial_refused else None
    finish_sent = finish_ack = False
    deadline = time.monotonic() + timeout
    channel.setblocking(False)
    os.set_blocking(stdin, False)
    os.set_blocking(stdout, False)
    with selectors.DefaultSelector() as poll:
        watched = {}
        def watch(fd, events, label):
            if not events:
                if fd in watched:
                    poll.unregister(fd)
                    del watched[fd]
            elif fd not in watched:
                poll.register(fd, events, label)
                watched[fd] = events
            elif watched[fd] != events:
                poll.modify(fd, events, label)
                watched[fd] = events
        while True:
            if worker.revoked or not alive(worker.pidfd) or time.monotonic() >= deadline:
                _fail('GIT_SHIM_INTERRUPTED')
            if finish_ack and not pending_out:
                return exit_code
            channel_events = selectors.EVENT_READ if (exit_code is None and len(pending_out) <= MAX_QUEUE - MAX_DATA) or finish_sent else 0
            if exit_code is not None and not pending_out and not finish_sent:
                channel_events |= selectors.EVENT_WRITE
            if pending_in and exit_code is None:
                channel_events |= selectors.EVENT_WRITE
            watch(channel.fileno(), channel_events, 'channel')
            watch(stdin, selectors.EVENT_READ if not eof and exit_code is None and queued_input <= MAX_QUEUE - MAX_DATA else 0, 'stdin')
            watch(stdout, selectors.EVENT_WRITE if pending_out else 0, 'stdout')
            for key, mask in poll.select(.1):
                if key.data == 'stdin':
                    try:
                        data = os.read(stdin, min(MAX_DATA, MAX_BYTES - input_bytes + 1))
                    except BlockingIOError:
                        continue
                    if not data:
                        eof = True
                        pending_in.append((b'{"kind":"eof"}', 0))
                    else:
                        input_bytes += len(data)
                        if input_bytes > MAX_BYTES:
                            _fail('GIT_SHIM_INPUT_LIMIT')
                        pending_in.append((data_frame(data), len(data)))
                        queued_input += len(data)
                elif key.data == 'stdout':
                    try:
                        count = os.write(stdout, pending_out)
                    except BlockingIOError:
                        continue
                    if not 0 < count <= len(pending_out):
                        _fail('GIT_SHIM_OUTPUT_FAILED')
                    del pending_out[:count]
                else:
                    if mask & selectors.EVENT_READ:
                        try:
                            kind, value = _shim_reply(channel, worker)
                        except BlockingIOError:
                            continue
                        if exit_code is not None:
                            if not finish_sent or kind != 'shim-finish-ack':
                                _fail()
                            finish_ack = True
                        elif kind == 'data':
                            from .ledger import _json
                            _, data = parse_frame(_json(value).encode())
                            output_bytes += len(data)
                            if output_bytes > MAX_BYTES:
                                _fail('GIT_SHIM_OUTPUT_LIMIT')
                            pending_out.extend(data)
                        elif kind == 'exit':
                            exit_code = value['code']
                        elif kind == 'refused':
                            exit_code = 128
                        else:
                            _fail()
                    if mask & selectors.EVENT_WRITE and exit_code is not None and not pending_out and not finish_sent:
                        packet = b'{"kind":"shim-finished"}'
                        try:
                            sent = channel.send(packet)
                        except BlockingIOError:
                            continue
                        if sent != len(packet):
                            _fail('GIT_SHIM_INPUT_FAILED')
                        finish_sent = True
                    if mask & selectors.EVENT_WRITE and pending_in and exit_code is None:
                        packet, count = pending_in[0]
                        try:
                            sent = channel.send(packet)
                        except BlockingIOError:
                            continue
                        if sent != len(packet):
                            _fail('GIT_SHIM_DISCONNECTED')
                        pending_in.pop(0)
                        queued_input -= count


def ssh_shim_main(argv):
    if (type(argv) is not list or not 3 <= len(argv) <= 18
            or any(type(word) is not str or not word or len(word) > 4096 or '\x00' in word for word in argv)
            or argv[0] != '--fd'
            or not re.fullmatch(r'[1-9][0-9]{0,6}', argv[1]) or not 3 <= int(argv[1]) <= 2**20
            ):
        _fail('INVALID_GIT_SHIM_ARGUMENTS')
    worker = None
    with socket.socket(fileno=int(argv[1])) as channel:
        enable(channel)
        channel.settimeout(35)
        send(channel, {'kind': 'ssh-open', 'argv': argv[2:]})
        try:
            with receive(channel) as record:
                if record.credentials[1:] != (os.getuid(), os.getgid()):
                    _fail('INVALID_GIT_SHIM_WORKER')
                worker = HeldOrigin(record)
                response = decode(record.data)
            kind = _server_frame(response)
            if kind not in ('ready', 'refused'):
                _fail()
            try:
                # Even admission refusal owns an active bridge binding. Finish
                # it while this shim is alive, without reading or sending stdin.
                return shim_stream(channel, worker, initial_refused=kind == 'refused')
            except BaseException:
                try:
                    send(channel, {'kind': 'cancel'})
                except BaseException:
                    pass
                raise
        finally:
            if worker is not None:
                worker.close()
