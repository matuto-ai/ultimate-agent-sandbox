"""Source-only artifacts helper ownership and private Gate control transport.

Nothing here enables production launch. The trusted Room launcher must freshly
admit the immutable static payload, dedicated UID mapping, read-only target
mount and mandatory outer confinement. Mocked admission is test evidence only.
There is no Participant seat, Actor badge, ADMIT, process adoption or retry.
"""
import array
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import select
import secrets
import socket
import stat
import struct
import threading
import time
import uuid

from .artifact_paths import open_directory
from .artifact_protocol import (ArtifactError, PROFILE_ID, HELPER_UID, HELPER_GID, MAX_OUTPUT_BYTES,
    canonical, validate_scope, validate_target, validate_paths, scope_digest, profile_scope_digest,
    encode_request, decode_observation, encode_final_ack)
from .kernel_origin import (HeldOrigin, Record, ReceiverIdentity, OriginDenied,
    OriginUnavailable, SCM_PIDFD, _identity, alive, enable, receive)

BOOTSTRAP = '/opt/uas/bin/artifact-bootstrap'
COMMAND_PROFILE = 'command-v1-source'
DIFF_PROFILE = 'diff-claims-v1-source'
BOOTSTRAPS = {PROFILE_ID: BOOTSTRAP, COMMAND_PROFILE: '/opt/uas/bin/command-bootstrap', DIFF_PROFILE: '/opt/uas/bin/diff-bootstrap'}
HELPER_HOST_UID = HELPER_HOST_GID = 165530
WALL_SECONDS = 15
CONTROL_LIMIT = 16384
MAX_EVALUATIONS = 16  # lifetime source-profile records; no pruning or automatic reset
_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


def _profile_target(profile, value):
    if profile == COMMAND_PROFILE:
        from .gate_repository import validate_command_target
        return validate_command_target(value)
    if profile == DIFF_PROFILE:
        from .diff_protocol import validate_diff_target
        return validate_diff_target(value)
    return validate_target(value)


def _profile_request(profile, value):
    if profile in (COMMAND_PROFILE, DIFF_PROFILE):
        from .gate_repository import compile_repository_config
        return compile_repository_config('command' if profile == COMMAND_PROFILE else 'diff-claims', value, 'gate')
    if profile != PROFILE_ID:
        raise ArtifactError('UNSUPPORTED_GATE_PROFILE')
    return validate_paths(value)


def _copy(value):
    return json.loads(canonical(value))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError('DUPLICATE_GATE_CONTROL_FIELD')
        result[key] = value
    return result


def _document(data):
    if type(data) is not bytes or not 0 < len(data) <= CONTROL_LIMIT:
        raise ArtifactError('INVALID_GATE_CONTROL')
    try:
        result = json.loads(data.decode('utf-8'), object_pairs_hook=_unique)
        if type(result) is not dict or canonical(result) != data:
            raise ValueError()
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError) as error:
        raise ArtifactError('INVALID_GATE_CONTROL') from error


def _send(channel, value):
    data = canonical(value)
    if len(data) > CONTROL_LIMIT or channel.send(data) != len(data):
        raise ArtifactError('GATE_CONTROL_SEND_UNKNOWN')


def _directory(path):
    """Shared search-only ancestors and readable leaf; no path resolution."""
    return open_directory(path, invalid_code='INVALID_GATE_RESOURCE_PATH',
                          unsupported_code='GATE_PATH_TRAVERSAL_UNAVAILABLE')


@dataclass(frozen=True)
class GateWorkstation:
    """Trusted immutable image/profile binding, not evidence of admission."""
    room_id: str
    room_instance: str
    container_id: str
    image_digest: str
    profile_digest: str
    bootstrap_digest: str
    evaluator_digest: str
    mapping_digest: str
    receiver_context: str
    profile: str = PROFILE_ID

    def __post_init__(self):
        if self.profile not in BOOTSTRAPS:
            raise ArtifactError('UNSUPPORTED_GATE_PROFILE')
        if (any(type(v) is not str or not _TOKEN.fullmatch(v)
                for v in (self.room_id, self.room_instance, self.receiver_context))
                or any(type(v) is not str or not _HEX64.fullmatch(v) for v in
                       (self.container_id, self.image_digest, self.profile_digest,
                        self.bootstrap_digest, self.evaluator_digest, self.mapping_digest))):
            raise ArtifactError('INVALID_GATE_WORKSTATION')


class GateEndpointLease:
    """Supervisor-owned endpoint identity; does not create or repair anything."""
    def __init__(self, path, *, owner, group):
        self.path = Path(path)
        if any(type(v) is not int or v <= 0 for v in (owner, group)):
            raise ArtifactError('INVALID_GATE_ENDPOINT')
        self.owner, self.group = owner, group
        self.expected = self._observe()

    def _observe(self):
        fd = _directory(self.path.parent)
        try:
            parent = os.fstat(fd)
            node = os.stat(self.path.name, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISSOCK(node.st_mode) or parent.st_uid != self.owner
                    or node.st_uid != self.owner or parent.st_gid != self.group
                    or node.st_gid != self.group or stat.S_IMODE(parent.st_mode) != 0o710
                    or stat.S_IMODE(node.st_mode) != 0o620):
                raise ArtifactError('INVALID_GATE_ENDPOINT')
            return (parent.st_dev, parent.st_ino, node.st_dev, node.st_ino)
        finally:
            os.close(fd)

    def require(self):
        if self._observe() != self.expected:
            raise ArtifactError('GATE_ENDPOINT_REPLACED')
        return True


class _LaunchJournal:
    """Exclusive operational intent. Existing/torn files always prohibit reuse."""
    def __init__(self, path):
        self.path = Path(path)
        self.parent = _directory(self.path.parent)
        self.fd = -1
        try:
            info = os.fstat(self.parent)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ArtifactError('PRIVATE_GATE_JOURNAL_REQUIRED')
            # Private dedicated launch-journal directory. Retained replay
            # markers count against a lifetime bound, including prior owners.
            with os.scandir(self.parent) as entries:
                for count, entry in enumerate(entries, 1):
                    if count >= MAX_EVALUATIONS or not entry.is_file(follow_symlinks=False):
                        raise ArtifactError('GATE_LAUNCH_JOURNAL_CAPACITY')
                    item = entry.stat(follow_symlinks=False)
                    if item.st_nlink != 1 or item.st_size > 131072:
                        raise ArtifactError('INVALID_GATE_LAUNCH_JOURNAL')
            self.fd = os.open(self.path.name, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.parent)
            self.identity = _identity_of_stat(os.fstat(self.fd))
            self.bytes = 0
            os.fsync(self.parent)
        except BaseException:
            self.close()
            raise

    def append(self, value):
        data = canonical(value) + b'\n'
        current = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        if (_identity_of_stat(current) != self.identity or not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1 or len(data) > CONTROL_LIMIT
                or self.bytes + len(data) > 131072):
            raise ArtifactError('GATE_JOURNAL_REPLACED_OR_FULL')
        count = os.write(self.fd, data)
        if count != len(data):
            raise ArtifactError('GATE_JOURNAL_WRITE_UNKNOWN')
        os.fsync(self.fd); self.bytes += count

    def close(self):
        # Retire each number before one close attempt, including interruption.
        # A failed file close must not skip the independently owned parent.
        try:
            fd, self.fd = getattr(self, 'fd', -1), -1
            if fd >= 0:
                os.close(fd)
        finally:
            parent, self.parent = getattr(self, 'parent', -1), -1
            if parent >= 0:
                os.close(parent)


def _identity_of_stat(info):
    return info.st_dev, info.st_ino


def _exited_events(events, fd):
    return (len(events) == 1 and events[0][0] == fd
            and bool(events[0][1] & select.POLLIN)
            and not events[0][1] & (select.POLLERR | select.POLLNVAL))


class GateHelperLaunch:
    """One Supervisor-owned attempt, never transferable Engine authority.

    admission.require(workstation) must perform fresh, trusted outer-boundary
    inspection; it is not selected by the Hub or Participant. target_lease is
    created by the Supervisor target service, not reconstructed from JSON.
    """
    def __init__(self, engine, workstation, endpoint, journal, *, admission,
                 target_lease, scope):
        if type(workstation) is not GateWorkstation or type(endpoint) is not GateEndpointLease:
            raise ArtifactError('TRUSTED_GATE_LAUNCH_REQUIRED')
        self.scope = validate_scope(scope)
        self.target = _profile_target(workstation.profile, target_lease.document())
        if (self.scope['room_id'] != workstation.room_id
                or self.scope['room_instance'] != workstation.room_instance):
            raise ArtifactError('GATE_ROOM_BINDING_MISMATCH')
        self.engine, self.workstation, self.endpoint = engine, workstation, endpoint
        self.admission, self.target_lease = admission, target_lease
        self.journal_path, self.journal = Path(journal), None
        self.origin = self.channel = self.transport = None
        self.exec_id = self.deadline = None
        self.state = 'new'
        self.tree_exit_confirmed = False
        self.incarnation = uuid.uuid4().hex
        self.binding = None

    def _save(self, state, error_code=None):
        self.state = state
        self.journal.append({'version': 1, 'state': state, 'incarnation': self.incarnation,
            'scope_digest': profile_scope_digest(self.workstation.profile, self.scope, self.target),
            'evaluation_id': self.scope['evaluation_id'], 'target_id': (self.target['head']['target_id']
                if self.workstation.profile == DIFF_PROFILE else self.target['target_id']),
            'container_id': self.workstation.container_id, 'exec_id': self.exec_id,
            'profile_digest': self.workstation.profile_digest, 'error_code': error_code})

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ArtifactError('ARTIFACT_HELPER_TIMEOUT')
        return remaining

    def _inspect(self):
        self._remaining()
        value = self.engine.inspect(self.exec_id)
        if (type(value) is not dict or value.get('ID') != self.exec_id
                or value.get('ContainerID') != self.workstation.container_id
                or value.get('Running') is not True or type(value.get('Pid')) is not int
                or self.origin is None or self.origin.revoked or not alive(self.origin.pidfd)
                or value['Pid'] != self.origin.credentials[0]):
            raise ArtifactError('GATE_EXEC_IDENTITY_UNVERIFIED')
        self._remaining()

    def start(self, listener):
        if self.state != 'new':
            raise ArtifactError('GATE_LAUNCH_ALREADY_ATTEMPTED')
        # These checks cannot turn a source-profile constant into qualification.
        if self.admission.require(self.workstation) is not True:
            raise ArtifactError('GATE_BOUNDARY_NOT_ADMITTED')
        self.endpoint.require()
        if self.target_lease.recheck() is not True:
            raise ArtifactError('ARTIFACT_SOURCE_CHANGED')
        enable(listener)
        self.journal = _LaunchJournal(self.journal_path)
        self.deadline = time.monotonic() + WALL_SECONDS
        try:
            self._save('creating')  # precedes every possible Engine mutation
            self.target_lease.mark_launch_possible()
            self.exec_id = self.engine.create(self.workstation.container_id, {
                'AttachStdin': True, 'AttachStdout': False, 'AttachStderr': False,
                'Tty': False, 'Privileged': False, 'User': '65530:65530',
                'WorkingDir': '/', 'Cmd': [BOOTSTRAPS[self.workstation.profile]], 'Env': []})
            # Env [] does NOT scrub inherited environment; static bootstrap does.
            if type(self.exec_id) is not str or not _HEX64.fullmatch(self.exec_id):
                raise ArtifactError('INVALID_GATE_EXEC_ID')
            self._save('starting')
            self.transport = self.engine.start(self.exec_id)
            challenge = secrets.token_bytes(32)
            self.transport.write(challenge, timeout=self._remaining())
            listener.settimeout(self._remaining())
            self.channel, _ = listener.accept()
            enable(self.channel); self.channel.settimeout(self._remaining())
            with receive(self.channel) as record:
                if (len(record.data) != 36 or record.data[:4] != b'AGH1'
                        or not hmac.compare_digest(record.data[4:], challenge)
                        or record.credentials[1:] != (HELPER_HOST_UID, HELPER_HOST_GID)):
                    raise ArtifactError('GATE_BOOTSTRAP_ORIGIN_MISMATCH')
                self.origin = HeldOrigin(record)
            challenge = None
            self._inspect(); self.endpoint.require()
            if (self.admission.require(self.workstation) is not True
                    or self.target_lease.recheck() is not True):
                raise ArtifactError('GATE_RELEASE_DEPENDENCY_CHANGED')
            release = (b'DGR1' + self.target['base']['target_id'].encode('ascii') + self.target['head']['target_id'].encode('ascii')
                       if self.workstation.profile == DIFF_PROFILE else b'AGR1' + self.target['target_id'].encode('ascii'))
            if self.channel.send(release) != len(release):
                raise ArtifactError('GATE_RELEASE_UNKNOWN')
            self._save('bound')
            return self
        except BaseException:
            self._quarantine('launch-uncertain')
            raise

    def _quarantine(self, reason):
        if self.origin is not None:
            self.origin.revoke()
        self.state = 'quarantined'
        if self.journal is not None:
            try:
                code = reason.upper().replace('-', '_')
                if not re.fullmatch(r'[A-Z_]{1,96}', code):
                    code = 'GATE_FAILURE'
                self._save('quarantined', code)
            except BaseException:
                pass  # prior durable intent still blocks replay
        return {'exit_confirmed': False, 'post_target': None, 'cleanup': False,
                'quarantine_ref': 'gate-launch-' + self.incarnation, 'launch_state': 'unknown'}

    def transfer(self, control, *, exchange_id, controller):
        if self.state != 'bound' or self.origin is None or self.origin.revoked:
            raise ArtifactError('GATE_NOT_BOUND')
        self._inspect(); self.endpoint.require()
        document = _binding_document(self, exchange_id, controller)
        self._save('binding')  # no replay after possible descriptor transfer
        data = canonical(document)
        try:
            count = control.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                array.array('i', [self.channel.fileno(), self.origin.pidfd]))])
            if count != len(data):
                raise ArtifactError('GATE_BIND_UNKNOWN')
            self.binding = document
            self._save('running')
            self.channel.close(); self.channel = None  # only Hub reads facts
            return document
        except BaseException:
            self._quarantine('binding-unknown')
            raise

    def _exit(self):
        if self.origin is None or self.origin.pidfd < 0:
            return False
        try:
            if _identity(self.origin.pidfd) != self.origin.identity:
                return False
        except (OSError, OriginUnavailable):
            return False
        poller = select.poll(); poller.register(self.origin.pidfd, select.POLLIN)
        # The helper's immutable alarm bounds its lifetime. A pidfd is not a
        # signal permission; no kill, container stop or guessed PID cleanup.
        remaining = max(0, self.deadline - time.monotonic())
        events = poller.poll(int(remaining * 1000) + 1)
        return (_exited_events(events, self.origin.pidfd)
                and _identity(self.origin.pidfd) == self.origin.identity
                and not alive(self.origin.pidfd))

    def finish(self, *, final_digest):
        """Called only by authenticated GATE_FINISH dispatch, never public JSON."""
        if (self.state != 'running' or self.binding is None
                or final_digest != profile_scope_digest(self.workstation.profile, self.scope, self.target)):
            raise ArtifactError('GATE_COMPLETION_NOT_CORRELATED')
        if not self._exit():
            return self._quarantine('helper-exit-unconfirmed')
        self._save('exited')
        try:
            # Command helper exit alone proves no descendant state. Its trusted
            # success path exits zero only after independently guarded whole-tree
            # exhaustion; a failed/lost helper keeps both resources quarantined.
            if self.workstation.profile != COMMAND_PROFILE:
                self.target_lease.mark_exit_confirmed()
            terminal = self.engine.inspect(self.exec_id)
            if (type(terminal) is not dict or terminal.get('ID') != self.exec_id
                    or terminal.get('ContainerID') != self.workstation.container_id
                    or terminal.get('Running') is not False
                    or type(terminal.get('ExitCode')) is not int or terminal['ExitCode'] != 0):
                raise ArtifactError('ARTIFACT_HELPER_EXIT_ERROR')
            if self.workstation.profile == COMMAND_PROFILE:
                self.tree_exit_confirmed = True
                self.target_lease.mark_exit_confirmed()
            if canonical(self.target_lease.postverify()) != canonical(self.target):
                raise ArtifactError('ARTIFACT_POST_TARGET_MISMATCH')
            if self.target_lease.recheck_binding() is not True:
                raise ArtifactError('ARTIFACT_SOURCE_BINDING_CHANGED')
            if self.target_lease.cleanup() is not True:
                raise ArtifactError('ARTIFACT_CLEANUP_FAILED')
            self._save('cleaned')
            return {'exit_confirmed': True, 'post_target': _copy(self.target), 'cleanup': True,
                    'quarantine_ref': None, 'launch_state': 'exited'}
        except BaseException as error:
            result = self._quarantine(getattr(error, 'code', 'postproof-or-cleanup-failed'))
            result['exit_confirmed'] = True
            result['launch_state'] = 'exited'
            return result

    def abort(self):
        if (self.workstation.profile == COMMAND_PROFILE and self.state not in ('cleaned', 'cleaned-error')
                and not getattr(self, 'tree_exit_confirmed', False)):
            return self._quarantine('command-tree-proof-unavailable')
        if self.state in ('cleaned', 'cleaned-error'):
            return {'exit_confirmed': True, 'post_target': _copy(self.target) if self.state == 'cleaned' else None, 'cleanup': True,
                    'quarantine_ref': None, 'launch_state': 'exited'}
        if self.origin is None or not self._exit():
            return self._quarantine('abort-exit-unconfirmed')
        # Error cleanup need not make target observations credible. Only the
        # target owner's identity-checked removal is allowed after actual exit.
        try:
            self.target_lease.mark_exit_confirmed()
            if self.target_lease.cleanup() is not True:
                raise ArtifactError('ARTIFACT_CLEANUP_FAILED')
            self._save('cleaned-error')
            return {'exit_confirmed': True, 'post_target': None, 'cleanup': True,
                    'quarantine_ref': None, 'launch_state': 'exited'}
        except BaseException as error:
            result = self._quarantine(getattr(error, 'code', 'abort-cleanup-failed'))
            result['exit_confirmed'] = True
            result['launch_state'] = 'exited'
            return result

    def close(self):
        # Closing handles fences but never demonstrates exit or removes targets.
        error = None
        for resource in (self.channel, self.transport, self.origin, self.journal):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as failure:
                    error = error or failure
        self.channel = self.transport = self.origin = self.journal = None
        if error is not None:
            raise error


def _binding_document(launch, exchange_id, controller):
    if not _HEX32.fullmatch(exchange_id) or not _HEX32.fullmatch(controller):
        raise ArtifactError('INVALID_GATE_CONTROL_CORRELATION')
    document = {'version': 1, 'kind': 'GATE_BIND', 'exchange_id': exchange_id,
        'controller': controller, 'scope': launch.scope, 'target': launch.target,
        'profile': launch.workstation.profile, 'profile_digest': launch.workstation.profile_digest,
        'mapping_digest': launch.workstation.mapping_digest,
        'receiver_context': launch.workstation.receiver_context,
        'origin_identity': list(launch.origin.identity)}
    if len(canonical(document)) > CONTROL_LIMIT:
        raise ArtifactError('GATE_BIND_TOO_LARGE')
    return document


class GateOffer:
    """Hub-owned exact helper channel/pidfd. Never contains Engine authority."""
    def __init__(self, document, channel, origin, paths):
        self._document = _copy(document)
        self.scope, self.target = self._document['scope'], self._document['target']
        self.channel, self.origin = channel, origin
        self.profile = self._document['profile']
        if self.profile in (COMMAND_PROFILE, DIFF_PROFILE):
            self.config = _profile_request(self.profile, paths)
            self.paths = ()
            if self.profile == COMMAND_PROFILE:
                from .gate_repository import command_correlation
                self.correlation = command_correlation(self.scope, self.target, self.config)
            else:
                from .diff_protocol import diff_correlation
                self.correlation = diff_correlation(self.scope, self.target, self.config)
        else:
            self.paths = tuple(paths); validate_paths(self.paths)
        self.state = 'bound'
        self.deadline = time.monotonic() + WALL_SECONDS
        self.final = None
        self._bytes = 0

    def document(self):
        return {'source': 'supervisor-one-shot-helper',
            'provenance': 'workstation-local / tamper-evident',
            'profile': self.profile, 'profile_digest': self._document['profile_digest'],
            'binding_digest': hashlib.sha256(canonical(self._document)).hexdigest(),
            'scope_digest': profile_scope_digest(self.profile, self.scope, self.target)}

    def _current(self):
        if self.origin.revoked or not alive(self.origin.pidfd):
            raise ArtifactError('ARTIFACT_HELPER_LOST')
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ArtifactError('ARTIFACT_HELPER_TIMEOUT')
        self.channel.settimeout(remaining)

    def records(self):
        if self.profile == DIFF_PROFILE:
            yield from self._diff_records()
            return
        if self.profile == COMMAND_PROFILE:
            yield from self._command_records()
            return
        if self.state != 'bound':
            raise ArtifactError('ARTIFACT_REQUEST_ALREADY_SENT')
        self.state = 'reading'  # uncertainty after any send cannot be replayed
        try:
            for packet in encode_request(self.scope, self.target, self.paths):
                self._current()
                if self.channel.send(packet) != len(packet):
                    raise ArtifactError('ARTIFACT_REQUEST_UNKNOWN')
            for index in range(len(self.paths) + 2):
                self._current()
                with receive(self.channel) as record:
                    self.origin.require(record)
                    self._bytes += len(record.data)
                    if self._bytes > MAX_OUTPUT_BYTES:
                        raise ArtifactError('ARTIFACT_OUTPUT_LIMIT')
                    value = decode_observation(record.data, self.scope, self.target, self.paths)
                expected = 'header' if index == 0 else 'final' if index == len(self.paths) + 1 else 'item'
                if value['kind'] != expected or (expected == 'item' and value['index'] != index - 1):
                    raise ArtifactError('ARTIFACT_RECORD_ORDER')
                if expected == 'final':
                    self.final = value; self.state = 'final'
                yield value
        except BaseException:
            self.state = 'error'; self.origin.revoke()
            raise

    def _command_records(self):
        from .gate_repository import command_request, command_observation
        if self.state != 'bound':
            raise ArtifactError('ARTIFACT_REQUEST_ALREADY_SENT')
        self.state = 'reading'
        try:
            self._current()
            packet = command_request(self.scope, self.target, self.config)
            if self.channel.send(packet) != len(packet):
                raise ArtifactError('COMMAND_REQUEST_UNKNOWN')
            for index in range(10):
                self._current()
                with receive(self.channel) as record:
                    self.origin.require(record)
                    self._bytes += len(record.data)
                    if self._bytes > MAX_OUTPUT_BYTES:
                        raise ArtifactError('COMMAND_OUTPUT_LIMIT')
                    value = command_observation(record.data, self.correlation)
                if index == 0 and value['kind'] != 'header':
                    raise ArtifactError('COMMAND_RECORD_ORDER')
                if value['kind'] == 'final':
                    self.final = value; self.state = 'final'
                    yield value
                    return
                yield value
            raise ArtifactError('COMMAND_RECORD_LIMIT')
        except BaseException:
            self.state = 'error'; self.origin.revoke()
            raise

    def _diff_records(self):
        from .diff_protocol import diff_request, diff_observation
        if self.state != 'bound':
            raise ArtifactError('ARTIFACT_REQUEST_ALREADY_SENT')
        self.state = 'reading'
        try:
            self._current()
            packet = diff_request(self.scope, self.target, self.config)
            if self.channel.send(packet) != len(packet):
                raise ArtifactError('DIFF_REQUEST_UNKNOWN')
            for index in range(130):
                self._current()
                with receive(self.channel) as record:
                    self.origin.require(record)
                    self._bytes += len(record.data)
                    if self._bytes > MAX_OUTPUT_BYTES:
                        raise ArtifactError('DIFF_OUTPUT_LIMIT')
                    value = diff_observation(record.data, self.correlation)
                if index == 0 and value['kind'] != 'header':
                    raise ArtifactError('DIFF_RECORD_ORDER')
                if value['kind'] == 'final':
                    self.final = value; self.state = 'final'
                    yield value
                    return
                yield value
            raise ArtifactError('DIFF_RECORD_LIMIT')
        except BaseException:
            self.state = 'error'; self.origin.revoke()
            raise

    def acknowledge_final(self, validated_final):
        if self.state != 'final' or canonical(validated_final) != canonical(self.final):
            raise ArtifactError('ARTIFACT_FINAL_NOT_VALIDATED')
        self._current()
        pending = select.poll(); pending.register(self.channel.fileno(), select.POLLIN)
        if pending.poll(0):
            # Any extra record/EOF before ACK is an error. receive() owns and
            # closes ancillary FDs even when the record is malicious.
            with receive(self.channel):
                raise ArtifactError('ARTIFACT_EXTRA_OUTPUT')
        packet = (b'CGA1' + bytes.fromhex(self.correlation) if self.profile == COMMAND_PROFILE
                  else b'DGA1' + bytes.fromhex(self.correlation) if self.profile == DIFF_PROFILE
                  else encode_final_ack(self.scope, self.target))
        self.state = 'ack-unknown'
        if self.channel.send(packet) != len(packet):
            self.origin.revoke()
            raise ArtifactError('ARTIFACT_FINAL_ACK_UNKNOWN')
        self.state = 'acked'

    def confirm_exit(self):
        if self.state != 'acked' or self.origin.pidfd < 0:
            raise ArtifactError('ARTIFACT_FINAL_ACK_REQUIRED')
        if _identity(self.origin.pidfd) != self.origin.identity:
            raise ArtifactError('ARTIFACT_HELPER_IDENTITY_LOST')
        poller = select.poll(); poller.register(self.origin.pidfd, select.POLLIN)
        events = poller.poll(int(max(0, self.deadline - time.monotonic()) * 1000) + 1)
        if (not _exited_events(events, self.origin.pidfd)
                or _identity(self.origin.pidfd) != self.origin.identity
                or alive(self.origin.pidfd)):
            self.origin.revoke()
            raise ArtifactError('ARTIFACT_HELPER_EXIT_UNCONFIRMED')
        # Complete packet stream must end after final. EOF is checked only now;
        # it never substitutes for held-kernel-task exit evidence.
        if self.channel.recv(1, socket.MSG_DONTWAIT):
            raise ArtifactError('ARTIFACT_EXTRA_OUTPUT')
        self.state = 'exited'
        return True

    def close(self):
        try:
            self.origin.close()
        finally:
            self.channel.close()


def receive_gate_bind(control, supervisor, *, scope, target, paths, receiver,
                      profile_digest, exchange_id, controller, profile=PROFILE_ID):
    """Only on the already-authenticated private Supervisor–Hub connection."""
    validate_scope(scope); _profile_target(profile, target); _profile_request(profile, paths)
    if (type(supervisor) is not HeldOrigin or type(receiver) is not ReceiverIdentity
            or receiver.uid != HELPER_UID or receiver.gid != HELPER_GID
            or supervisor.revoked or not alive(supervisor.pidfd)):
        raise ArtifactError('TRUSTED_GATE_RECEIVER_REQUIRED')
    data, ancillary, flags, _ = control.recvmsg(CONTROL_LIMIT,
        socket.CMSG_SPACE(12) + socket.CMSG_SPACE(4) + socket.CMSG_SPACE(253 * 4),
        socket.MSG_CMSG_CLOEXEC)
    installed, credentials, pidfds, rights = [], [], [], []
    channel = origin = result = None
    invalid = not data or bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
    try:
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind in (SCM_PIDFD, socket.SCM_RIGHTS):
                fds = array.array('i'); fds.frombytes(raw[:len(raw) - len(raw) % 4])
                installed.extend(fd for fd in fds if fd >= 0)
                invalid |= bool(len(raw) % 4 or any(fd < 0 for fd in fds))
                (pidfds if kind == SCM_PIDFD else rights).extend(fds)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(raw) == 12:
                credentials.append(struct.unpack('3i', raw))
            else:
                invalid = True
        if invalid or len(credentials) != 1 or len(pidfds) != 1:
            raise ArtifactError('INVALID_GATE_BIND_ANCILLARY')
        if any(os.get_inheritable(fd) for fd in installed):
            raise ArtifactError('INHERITABLE_GATE_DESCRIPTOR')
        supervisor.require(Record(data, credentials[0], pidfds[0]))
        document = _document(data)
        error_reply = {'version': 1, 'kind': 'GATE_REPLY', 'exchange_id': exchange_id,
                       'controller': controller}
        if (not rights and set(document) == set(error_reply) | {'error'}
                and all(type(document[k]) is type(v) and document[k] == v for k, v in error_reply.items())
                and type(document['error']) is str and re.fullmatch(r'[A-Z_]{1,96}', document['error'])):
            raise ArtifactError(document['error'])
        if len(rights) != 2:
            raise ArtifactError('INVALID_GATE_BIND_DESCRIPTOR_COUNT')
        expected = {'version': 1, 'kind': 'GATE_BIND', 'exchange_id': exchange_id,
            'controller': controller, 'scope': scope, 'target': target, 'profile': profile,
            'profile_digest': profile_digest, 'mapping_digest': receiver.mapping_digest,
            'receiver_context': receiver.context,
            'origin_identity': list(_identity(rights[1]))}
        if canonical(document) != canonical(expected):
            raise ArtifactError('GATE_BIND_SCOPE_MISMATCH')
        channel = socket.socket(fileno=rights[0]); installed.remove(rights[0])
        if (channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise ArtifactError('GATE_CONNECTED_CHANNEL_REQUIRED')
        channel.getpeername(); enable(channel)
        record = Record(b'', (0, receiver.uid, receiver.gid), rights[1])
        origin = HeldOrigin(record, receiver=receiver); installed.remove(rights[1])
        result = GateOffer(document, channel, origin, paths)
        channel = origin = None
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError, OSError, OriginUnavailable) as error:
        raise ArtifactError('INVALID_GATE_BIND') from error
    finally:
        failure = None
        while installed:
            fd = installed.pop()
            try:
                os.close(fd)
            except BaseException as error:
                failure = failure or error
        for resource in (origin, channel):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    failure = failure or error
        if failure is not None:
            try:
                if result is not None:
                    result.close()
            finally:
                raise failure


class GateControlClient:
    """Hub's narrow facade over its existing authenticated private connection.

    The Room's existing lock serializes this with non-Gate control exchanges.
    No timeout, lost reply or restart resends a mutation automatically.
    """
    def __init__(self, control, *, supervisor, receiver, profile_digest,
                 controller, control_lock, profile=PROFILE_ID):
        if profile not in BOOTSTRAPS:
            raise ArtifactError('UNSUPPORTED_GATE_PROFILE')
        self.profile = profile
        if (type(supervisor) is not HeldOrigin or type(receiver) is not ReceiverIdentity
                or receiver.uid != HELPER_UID or receiver.gid != HELPER_GID
                or type(profile_digest) is not str or not _HEX64.fullmatch(profile_digest)
                or type(controller) is not str or not _HEX32.fullmatch(controller)
                or not hasattr(control_lock, '__enter__')):
            raise ArtifactError('TRUSTED_GATE_CONTROL_REQUIRED')
        self.control, self.supervisor, self.receiver = control, supervisor, receiver
        self.profile_digest, self.controller = profile_digest, controller
        self._io = control_lock
        self._offers = {}

    def _send(self, command, payload):
        if self.supervisor.revoked or not alive(self.supervisor.pidfd):
            raise ArtifactError('GATE_SUPERVISOR_LOST')
        exchange = uuid.uuid4().hex
        self.control.settimeout(45)  # materialization source profile wall bound
        _send(self.control, {'version': 1, 'kind': 'GATE_CONTROL', 'command': command,
            'controller': self.controller, 'exchange_id': exchange, 'payload': payload})
        return exchange

    def _reply(self, exchange):
        with receive(self.control) as record:
            self.supervisor.require(record)
            reply = _document(record.data)
        base = {'version': 1, 'kind': 'GATE_REPLY', 'controller': self.controller,
                'exchange_id': exchange}
        if (set(reply) not in (set(base) | {'result'}, set(base) | {'error'})
                or any(type(reply[k]) is not type(v) or reply[k] != v for k, v in base.items())):
            raise ArtifactError('UNMATCHED_GATE_REPLY')
        if 'error' in reply:
            if type(reply['error']) is not str or not re.fullmatch(r'[A-Z_]{1,96}', reply['error']):
                raise ArtifactError('INVALID_GATE_ERROR')
            raise ArtifactError(reply['error'])
        return reply['result']

    def _call(self, command, payload):
        with self._io:
            return self._reply(self._send(command, payload))

    def resolve(self, run_id, participant_id, room_instance, subject=None):
        payload = {'run_id': run_id, 'participant_id': participant_id, 'room_instance': room_instance}
        if self.profile == DIFF_PROFILE:
            payload['subject'] = subject
        elif subject is not None:
            raise ArtifactError('UNSUPPORTED_GATE_SUBJECT')
        return self._call('resolve', payload)

    def current(self, source):
        return self._call('current', {'source': source})

    def prepare(self, scope, source):
        validate_scope(scope)
        return _profile_target(self.profile, self._call('prepare', {'scope': scope, 'source': source}))

    def start(self, scope, target, paths):
        validate_scope(scope); _profile_target(self.profile, target); _profile_request(self.profile, paths)
        evaluation = scope['evaluation_id']
        if evaluation in self._offers or len(self._offers) >= MAX_EVALUATIONS:
            raise ArtifactError('GATE_START_ALREADY_ATTEMPTED')
        self._offers[evaluation] = None  # fences even a lost request/reply
        with self._io:
            # Paths travel only over the direct helper channel, not copied into
            # the 16 KiB control envelope. Supervisor never evaluates them.
            exchange = self._send('start', {'scope': scope, 'target': target})
            offer = receive_gate_bind(self.control, self.supervisor, scope=scope,
                target=target, paths=paths, receiver=self.receiver,
                profile_digest=self.profile_digest, exchange_id=exchange,
                controller=self.controller, profile=self.profile)
        self._offers[evaluation] = offer
        return offer

    def finish(self, target, offer):
        if (type(offer) is not GateOffer or offer.state != 'exited'
                or canonical(target) != canonical(offer.target)
                or self._offers.get(offer.scope['evaluation_id']) is not offer):
            raise ArtifactError('GATE_EXITED_OFFER_REQUIRED')
        return self._call('finish', {'evaluation_id': offer.scope['evaluation_id'],
            'target': target, 'final_digest': profile_scope_digest(self.profile, offer.scope, target)})

    def abort(self, evaluation_id, target=None, offer=None):
        if offer is not None and (type(offer) is not GateOffer
                or self._offers.get(evaluation_id) is not offer):
            raise ArtifactError('GATE_OFFER_BINDING_MISMATCH')
        return self._call('abort', {'evaluation_id': evaluation_id, 'target': target})

    def reconcile(self, evaluation_id):
        return self._call('reconcile', {'evaluation_id': evaluation_id})


class GateSupervisorService:
    """Operational ownership, not another Gate/Run ledger.

    resolver/targets are trusted Supervisor services. launch_factory is fixed
    at Room construction and must return GateHelperLaunch, never a caller argv.
    An in-memory owner cannot be reconstructed from a PID or journal after loss.
    """
    def __init__(self, resolver, targets, *, launch_factory, listener, profile=PROFILE_ID):
        if profile not in BOOTSTRAPS:
            raise ArtifactError('UNSUPPORTED_GATE_PROFILE')
        self.profile = profile
        self.resolver, self.targets = resolver, targets
        self.launch_factory, self.listener = launch_factory, listener
        self._prepared, self._launches, self._attempted = {}, {}, set()
        self._lock = threading.RLock()

    def handle(self, command, payload):
        with self._lock:
            if type(payload) is not dict:
                raise ArtifactError('INVALID_GATE_CONTROL_PAYLOAD')
            if command == 'resolve' and set(payload) == ({'run_id', 'participant_id', 'room_instance', 'subject'}
                    if self.profile == DIFF_PROFILE else {'run_id', 'participant_id', 'room_instance'}):
                return self.resolver.resolve(**payload)
            if command == 'current' and set(payload) == {'source'}:
                return self.resolver.current(payload['source'])
            if command == 'prepare' and set(payload) == {'scope', 'source'}:
                scope = validate_scope(payload['scope'])
                evaluation = scope['evaluation_id']
                if (evaluation in self._prepared or evaluation in self._attempted
                        or len(self._prepared) >= MAX_EVALUATIONS):
                    raise ArtifactError('ARTIFACT_PREPARATION_ALREADY_ATTEMPTED')
                self._prepared[evaluation] = None  # intent also covers partial preparation
                target = _profile_target(self.profile, self.targets.prepare(scope, payload['source']))
                self._prepared[evaluation] = (scope, target)
                return target
            if command == 'start' and set(payload) == {'scope', 'target'}:
                scope, target = validate_scope(payload['scope']), _profile_target(self.profile, payload['target'])
                evaluation = scope['evaluation_id']
                if (evaluation in self._attempted or self._prepared.get(evaluation) is None
                        or canonical(self._prepared[evaluation]) != canonical((scope, target))):
                    raise ArtifactError('GATE_START_BINDING_OR_REPLAY')
                self._attempted.add(evaluation)  # before constructing or starting launch
                launch = self.launch_factory(scope, target, self.targets.lease(target))
                if type(launch) is not GateHelperLaunch or launch.workstation.profile != self.profile:
                    raise ArtifactError('TRUSTED_GATE_LAUNCH_REQUIRED')
                self._launches[evaluation] = launch
                return launch.start(self.listener)
            if command == 'finish' and set(payload) == {'evaluation_id', 'target', 'final_digest'}:
                launch = self._launches.get(payload['evaluation_id'])
                if launch is None or canonical(payload['target']) != canonical(launch.target):
                    raise ArtifactError('GATE_LIVE_OWNER_REQUIRED')
                result = launch.finish(final_digest=payload['final_digest'])
                if result['cleanup']:
                    launch.close()
                return result
            if command in ('abort', 'reconcile') and set(payload) == (
                    {'evaluation_id', 'target'} if command == 'abort' else {'evaluation_id'}):
                evaluation = payload['evaluation_id']
                if type(evaluation) is not str or not _TOKEN.fullmatch(evaluation):
                    raise ArtifactError('INVALID_EVALUATION_ID')
                launch = self._launches.get(evaluation)
                if launch is not None:
                    if command == 'abort' and payload['target'] is not None and canonical(payload['target']) != canonical(launch.target):
                        raise ArtifactError('GATE_TARGET_BINDING_MISMATCH')
                    result = launch.abort()
                    if result['cleanup']:
                        launch.close()
                    return result
                if evaluation in self._attempted or evaluation not in self._prepared:
                    # Restart/unknown launch has no held process authority. Keep
                    # scratch reservation until explicit external reconciliation.
                    return {'launch_state': 'unknown', 'exit_confirmed': False,
                        'cleanup': False, 'post_target': None,
                        'quarantine_ref': 'gate-recovery-' + hashlib.sha256(evaluation.encode()).hexdigest()[:32]}
                result = self.targets.reconcile(evaluation)
                cleanup = result is True or (type(result) is dict and result.get('cleanup') is True)
                return {'launch_state': 'never-launched', 'exit_confirmed': False,
                    'cleanup': cleanup, 'post_target': None,
                    'quarantine_ref': None if cleanup else 'gate-target-' + hashlib.sha256(evaluation.encode()).hexdigest()[:32]}
            raise ArtifactError('UNSUPPORTED_GATE_CONTROL')


def dispatch_gate_control(control, hub, service, *, controller):
    """One request on an existing authenticated Room connection; no listener.

    Its caller uses the Room's existing I/O lock/dispatch ownership. Service
    replies are operational data only. Hub remains the sole verdict authority.
    """
    if (type(hub) is not HeldOrigin or hub.revoked or not alive(hub.pidfd)
            or type(service) is not GateSupervisorService
            or type(controller) is not str or not _HEX32.fullmatch(controller)):
        raise ArtifactError('TRUSTED_GATE_DISPATCH_REQUIRED')
    with receive(control) as record:
        hub.require(record)
        request = _document(record.data)
    expected = {'version', 'kind', 'command', 'controller', 'exchange_id', 'payload'}
    if (set(request) != expected or type(request['version']) is not int or request['version'] != 1
            or request['kind'] != 'GATE_CONTROL' or request['controller'] != controller
            or type(request['exchange_id']) is not str or not _HEX32.fullmatch(request['exchange_id'])
            or type(request['command']) is not str):
        raise ArtifactError('INVALID_GATE_CONTROL_REQUEST')
    reply = {'version': 1, 'kind': 'GATE_REPLY', 'controller': controller,
             'exchange_id': request['exchange_id']}
    try:
        result = service.handle(request['command'], request['payload'])
        if type(result) is GateHelperLaunch:
            result.transfer(control, exchange_id=request['exchange_id'], controller=controller)
            return
        _send(control, {**reply, 'result': result})
    except (ArtifactError, OriginDenied, OriginUnavailable, OSError) as error:
        code = error.code if isinstance(error, ArtifactError) else 'GATE_OPERATION_UNAVAILABLE'
        _send(control, {**reply, 'error': code})
