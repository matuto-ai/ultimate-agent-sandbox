"""Private, kernel-bound native reference-transaction receipts.

Only the fixed Git worker constructs a collector. The immutable hook reports
Git's transaction input, not stdout, HEAD after execution, or a participant's
claims. Each hook waits for an authenticated acknowledgement while its pidfd is
live. The native child remains exclusively owned/unreaped until collection stops.
"""
import hashlib
import json
import os
import re
import secrets
import socket
import threading

from .kernel_origin import alive, enable, receive
from .ledger import _token

WORKER_UID = 65530
PROJECT_GID = 65532
HOOK_DIRECTORY = '/opt/uas/git-hooks'
HOOK_SCRIPT = b'''#!/usr/bin/python3 -I
"""Immutable native reference-transaction reporter; never import Project code."""
import sys

sys.path.insert(0, '/opt/uas')
from uas.git_transaction import hook_main

if __name__ == '__main__':
    try:
        raise SystemExit(hook_main(sys.argv[1:]))
    except Exception:
        raise SystemExit(128)
'''
MAX_INPUT = 16384
MAX_PHASES = 64
ZERO = '0' * 40
_OID = re.compile(r'[0-9a-f]{40}\Z')
_NONCE = re.compile(r'[0-9a-f]{64}\Z')
_BRANCH = re.compile(r'refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,240}\Z')
_PHASES = {'preparing', 'prepared', 'committed', 'aborted'}
_ENV = ('UAS_GIT_TX_FD', 'UAS_GIT_TX_NONCE', 'UAS_GIT_TX_OPERATION', 'UAS_GIT_TX_WORKER_PID')


class GitTransactionError(ValueError):
    def __init__(self, code='GIT_TRANSACTION_UNVERIFIED'):
        self.code = code
        super().__init__(code)


def _ref(value):
    if value in ('HEAD', 'AUTO_MERGE', 'CHERRY_PICK_HEAD', 'ORIG_HEAD'):
        return value
    if (type(value) is not str or not _BRANCH.fullmatch(value) or '..' in value
            or any(part.startswith('.') or part.endswith(('.', '.lock')) or not part
                   for part in value.split('/'))):
        raise GitTransactionError('INVALID_GIT_TRANSACTION_REF')
    return value


def parse_updates(raw):
    """Bounded Git hook stdin; no symbolic values, duplicate refs or text tail."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT or not raw.endswith(b'\n'):
        raise GitTransactionError('INVALID_GIT_TRANSACTION_UPDATES')
    try:
        lines = raw.decode('ascii').splitlines(keepends=True)
    except UnicodeError:
        raise GitTransactionError('INVALID_GIT_TRANSACTION_UPDATES') from None
    result = []
    for line in lines:
        fields = line[:-1].split(' ')
        if (not line.endswith('\n') or len(fields) != 3 or not _OID.fullmatch(fields[0])
                or not _OID.fullmatch(fields[1])):
            raise GitTransactionError('INVALID_GIT_TRANSACTION_UPDATES')
        result.append((fields[0], fields[1], _ref(fields[2])))
    if not 1 <= len(result) <= 32 or len({row[2] for row in result}) != len(result):
        raise GitTransactionError('INVALID_GIT_TRANSACTION_UPDATES')
    return tuple(sorted(result, key=lambda row: row[2]))


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise GitTransactionError()
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        if type(value) is not dict or _wire(value) != raw:
            raise GitTransactionError()
        return value
    except (ValueError, TypeError, UnicodeError):
        raise GitTransactionError() from None


class TransactionSequence:
    """Pure state machine; one exact HEAD target, complete auxiliary updates."""
    def __init__(self, *, expected_old, expected_ref, kind):
        if expected_old is not None and (type(expected_old) is not str or not _OID.fullmatch(expected_old) or expected_old == ZERO):
            raise GitTransactionError('INVALID_GIT_TRANSACTION_EXPECTATION')
        if _ref(expected_ref) not in ('HEAD',) and not expected_ref.startswith('refs/heads/'):
            raise GitTransactionError('INVALID_GIT_TRANSACTION_EXPECTATION')
        if kind not in ('commit', 'cherry-pick', 'abort'):
            raise GitTransactionError('INVALID_GIT_TRANSACTION_EXPECTATION')
        self.expected_old, self.expected_ref, self.kind = expected_old or ZERO, expected_ref, kind
        self.pending = None
        self.preparing = None
        self.created = None
        self.target_count = 0
        self.count = 0
        self.failed = False

    def _classify(self, updates, *, preparing=False):
        refs = {row[2] for row in updates}
        target_refs = {self.expected_ref, 'HEAD'}
        if refs <= target_refs:
            if self.expected_ref not in refs and not (preparing and refs == {'HEAD'}):
                raise GitTransactionError()
            values = {(row[0], row[1]) for row in updates}
            if len(values) != 1:
                raise GitTransactionError()
            old, new = next(iter(values))
            if new == ZERO or (self.kind != 'abort' and old != self.expected_old):
                raise GitTransactionError()
            return ('target', old, new)
        # Native commit's sequencer cleanup requests AUTO_MERGE deletion with
        # an unspecified old OID (zero), even when the ref does not exist. This
        # is not created-object evidence: accept only the exact fixed cleanup
        # after the one fully committed target, with normal phase pairing.
        if (self.kind == 'commit' and self.target_count == 1
                and updates == ((ZERO, ZERO, 'AUTO_MERGE'),)):
            return ('auxiliary',)
        auxiliary = {'AUTO_MERGE', 'CHERRY_PICK_HEAD'} if self.kind != 'commit' else set()
        if self.kind == 'abort':
            auxiliary.add('ORIG_HEAD')
        if refs <= auxiliary:
            return ('auxiliary',)
        raise GitTransactionError()

    def accept(self, phase, raw):
        try:
            if self.failed or phase not in _PHASES or self.count >= MAX_PHASES:
                raise GitTransactionError()
            self.count += 1
            updates = parse_updates(raw)
            if phase == 'aborted':
                raise GitTransactionError()
            classification = self._classify(updates, preparing=phase == 'preparing')
            if phase == 'preparing':
                if (self.pending is not None or self.preparing is not None
                        or classification[0] == 'target' and self.target_count):
                    raise GitTransactionError()
                self.preparing = (updates, classification)
            elif phase == 'prepared':
                if self.pending is not None or (classification[0] == 'target' and self.target_count):
                    raise GitTransactionError()
                if self.preparing is not None:
                    previous, previous_class = self.preparing
                    if previous_class != classification or (classification[0] == 'auxiliary' and previous != updates):
                        raise GitTransactionError()
                self.preparing = None
                self.pending = (updates, classification)
            else:
                if self.preparing is not None or self.pending != (updates, classification):
                    raise GitTransactionError()
                if classification[0] == 'target':
                    self.target_count += 1
                    self.created = classification[2]
                self.pending = None
        except (ValueError, TypeError):
            self.failed = True
            raise GitTransactionError() from None

    def committed_oid(self, *, required):
        if (type(required) is not bool or self.failed or self.pending is not None or self.preparing is not None
                or self.target_count > 1):
            raise GitTransactionError()
        if self.kind == 'abort':
            if required:
                raise GitTransactionError()
            return None
        if required != (self.created is not None):
            raise GitTransactionError()
        return self.created


class ReferenceTransaction:
    """One invocation's owned socketpair, bounded collector, and private nonce."""
    def __init__(self, operation_id, *, expected_old, expected_ref, kind):
        _token(operation_id)
        if (os.getuid() != WORKER_UID or os.geteuid() != WORKER_UID
                or os.getgid() != PROJECT_GID or os.getegid() != PROJECT_GID):
            raise GitTransactionError('GIT_TRANSACTION_WORKER_REQUIRED')
        self.sequence = TransactionSequence(expected_old=expected_old, expected_ref=expected_ref, kind=kind)
        self.kind = kind
        self.operation_id, self.nonce = operation_id, secrets.token_hex(32)
        self.worker_pid = os.getpid()
        self.left = self.right = None
        self.thread = None
        self.native_pid = None
        self.failure = None
        self.stopping = threading.Event()
        self.stopped = False
        self.closed = False
        try:
            self.left, self.right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            enable(self.left)
            enable(self.right)
            self.left.settimeout(.1)
            self.right.settimeout(5)
        except Exception:
            self.close()
            raise GitTransactionError() from None

    @property
    def child_fd(self):
        if self.closed:
            raise GitTransactionError()
        return self.right.fileno()

    @property
    def environment(self):
        return dict(zip(_ENV, (str(self.child_fd), self.nonce, self.operation_id, str(self.worker_pid))))

    def start(self, native_pid):
        self.require_fresh()
        if (type(native_pid) is not int or native_pid <= 0
                or os.getsid(native_pid) != native_pid or os.getpgid(native_pid) != native_pid):
            raise GitTransactionError()
        self.native_pid = native_pid
        self.thread = threading.Thread(target=self._collect, name='uas-git-reference-receipt', daemon=True)
        self.thread.start()

    def _authenticate(self, record):
        pid, uid, gid = record.credentials
        # The record's still-live pidfd prevents PID reuse during these group
        # observations. The owned native leader is not reaped until stop().
        if (self.stopping.is_set() or pid <= 0 or (uid, gid) != (WORKER_UID, PROJECT_GID) or not alive(record.pidfd)
                or os.getsid(pid) != self.native_pid or os.getpgid(pid) != self.native_pid
                or not alive(record.pidfd)):
            raise GitTransactionError()

    def _record(self, record):
        self._authenticate(record)
        value = _decode(record.data)
        if (set(value) != {'kind', 'operation', 'nonce', 'phase', 'updates'}
                or value['kind'] != 'reference-transaction' or value['operation'] != self.operation_id
                or value['nonce'] != self.nonce or type(value['updates']) is not str):
            raise GitTransactionError()
        try:
            raw = value['updates'].encode('ascii')
        except UnicodeError:
            raise GitTransactionError() from None
        self.sequence.accept(value['phase'], raw)
        self._authenticate(record)
        ack = _wire({'kind': 'ack', 'operation': self.operation_id, 'nonce': self.nonce,
            'phase': value['phase'], 'digest': hashlib.sha256(raw).hexdigest()})
        if self.left.send(ack) != len(ack):
            raise GitTransactionError()

    def _collect(self):
        try:
            while not self.stopping.is_set():
                try:
                    with receive(self.left) as record:
                        self._record(record)
                except socket.timeout:
                    continue
        except Exception:
            self.failure = GitTransactionError()

    def require(self):
        if self.failure is not None or self.closed or self.sequence.failed:
            raise GitTransactionError()

    def require_fresh(self):
        self.require()
        if self.thread is not None or self.stopped or self.native_pid is not None or self.sequence.count:
            raise GitTransactionError()

    def stop(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
            if self.thread.is_alive():
                self.failure = GitTransactionError()
        self.stopped = True

    def committed_oid(self, *, required):
        self.require()
        if self.thread is None or not self.stopped or self.thread.is_alive():
            raise GitTransactionError()
        return self.sequence.committed_oid(required=required)

    def close(self):
        if self.closed:
            return
        self.stop()
        self.closed = True
        for channel in (self.left, self.right):
            if channel is not None:
                channel.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def hook_main(argv, *, environ=None, stdin=None):
    """Fixed image hook. Missing receipt context is a no-op, never evidence."""
    import sys
    env = os.environ if environ is None else environ
    if type(argv) is not list or len(argv) != 1 or argv[0] not in _PHASES:
        raise GitTransactionError()
    present = [name in env for name in _ENV]
    if not any(present):
        return 0  # Non-attributed fetch/branch/abort operations do not mint proof.
    if not all(present):
        raise GitTransactionError()
    fd_text, nonce, operation, pid_text = (env[name] for name in _ENV)
    if (any(type(value) is not str for value in (fd_text, nonce, operation, pid_text))
            or not re.fullmatch(r'[1-9][0-9]{0,9}', fd_text)
            or not 3 <= int(fd_text) <= 2**20 or not _NONCE.fullmatch(nonce)
            or not re.fullmatch(r'[1-9][0-9]{0,9}', pid_text) or int(pid_text) >= 2**31
            or os.getuid() != WORKER_UID or os.geteuid() != WORKER_UID
            or os.getgid() != PROJECT_GID or os.getegid() != PROJECT_GID):
        raise GitTransactionError()
    _token(operation)
    source = sys.stdin.buffer if stdin is None else stdin
    raw = source.read(MAX_INPUT + 1)
    parse_updates(raw)
    with socket.socket(fileno=int(fd_text)) as channel:
        enable(channel)
        channel.settimeout(5)
        packet = _wire({'kind': 'reference-transaction', 'operation': operation, 'nonce': nonce,
            'phase': argv[0], 'updates': raw.decode('ascii')})
        if channel.send(packet) != len(packet):
            raise GitTransactionError()
        with receive(channel) as record:
            if (record.credentials != (int(pid_text), WORKER_UID, PROJECT_GID) or not alive(record.pidfd)
                    or _decode(record.data) != {'kind': 'ack', 'operation': operation, 'nonce': nonce,
                        'phase': argv[0], 'digest': hashlib.sha256(raw).hexdigest()}):
                raise GitTransactionError()
    return 0
