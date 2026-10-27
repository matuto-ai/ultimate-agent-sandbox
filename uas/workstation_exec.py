"""Trusted Supervisor-side exact Docker exec launch seam (not yet qualified).

Engine access stays outside Hub/Workstation. This module never launches a docker
CLI and never treats its own transport as the Runtime task. Failed/uncertain
operations remain fenced and cannot be automatically retried. A qualified Room
launcher must supply an admitted immutable container and private endpoint; no
production launch command is exposed by this source slice.
"""
from dataclasses import dataclass
import hmac
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import time
import uuid

from .kernel_origin import HeldOrigin, OriginDenied, alive, enable, probe, receive

ID = re.compile(r'[0-9a-f]{64}\Z')
RELEASE = b'UAS-RELEASE-1\n'
CONNECTOR = '/opt/uas/bin/pi-connector'


class ExecUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecSeat:
    room_id: str
    room_instance: str
    participant_id: str
    actor_id: str
    slot: str
    container_id: str
    host_uid: int
    host_gid: int

    def __post_init__(self):
        if (self.slot not in ('seat-a', 'seat-b') or not ID.fullmatch(self.container_id)
                or any(type(x) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', x)
                       for x in (self.room_id, self.room_instance, self.participant_id, self.actor_id))
                or any(type(x) is not int or x <= 0 for x in (self.host_uid, self.host_gid))):
            raise ExecUnavailable('invalid trusted seat definition')


class EndpointLease:
    """Hold trusted host path identities; never recreate/repair an endpoint.

    Paths are supplied by the Supervisor, not the runtime. Mount/SELinux
    admission remains a separate required production gate.
    """
    def __init__(self, path, *, owner, group):
        self.path = Path(path)
        self.owner, self.group = owner, group
        self.expected = self._observe()

    def _observe(self):
        parent, endpoint = self.path.parent, self.path
        if not endpoint.is_absolute() or parent.resolve() != parent:
            raise ExecUnavailable('noncanonical endpoint')
        directory, node = parent.lstat(), endpoint.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or not stat.S_ISSOCK(node.st_mode)
                or directory.st_uid != self.owner or node.st_uid != self.owner
                or directory.st_gid != self.group or node.st_gid != self.group
                or stat.S_IMODE(directory.st_mode) != 0o710
                or stat.S_IMODE(node.st_mode) != 0o620):
            raise ExecUnavailable('endpoint ownership/mode rejected')
        return (directory.st_dev, directory.st_ino, node.st_dev, node.st_ino)

    def require(self):
        if self._observe() != self.expected:
            raise ExecUnavailable('endpoint replaced')


class ExecLaunch:
    """One launch attempt; never reconstruct authority from persisted PID/exec ID.

    journal is an exclusive Supervisor-owned file: creation precedes Engine
    contact. Any previous file (including torn/uncertain/revoked state) blocks
    reuse. Recovery must reconcile its exact owned exec/container separately.
    The one-use challenge correlates the trusted fixed bootstrap's exec stdin
    to a kernel record; it is not a badge or post-launch bearer credential.
    """
    def __init__(self, engine, seat, endpoint, journal, *, timeout=10):
        if type(seat) is not ExecSeat or not 0 < timeout <= 10:
            raise ExecUnavailable('invalid launch')
        self.engine, self.seat, self.endpoint = engine, seat, endpoint
        self.journal = Path(journal)
        self.timeout = timeout
        self.exec_id = None
        self.origin = self.channel = self.transport = None
        self.state = 'new'
        self._owns_journal = False
        self.incarnation = uuid.uuid4().hex
        self.challenge = None
        self.deadline = None
        self._native_readiness = None
        self.native_receiver = None
        self.admission = None

    def _save(self, *, first=False):
        document = {'version': 1, 'room_id': self.seat.room_id,
                    'room_instance': self.seat.room_instance,
                    'participant_id': self.seat.participant_id, 'actor_id': self.seat.actor_id,
                    'container_id': self.seat.container_id, 'exec_id': self.exec_id,
                    'incarnation': self.incarnation, 'state': self.state,
                    'native_readiness': self._native_readiness, 'admission': self.admission}
        # No challenge, credential or replayable process authority is persisted.
        data = json.dumps(document, sort_keys=True, allow_nan=False).encode()
        if len(data) > 16384 or (self.admission is not None and type(self.admission) is not dict):
            raise ExecUnavailable('bounded launch journal required')
        parent = self.journal.parent.lstat()
        if (self.journal.parent.resolve() != self.journal.parent
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ExecUnavailable('private Supervisor journal directory required')
        if first:
            fd = os.open(self.journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self._owns_journal = True
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
            finally:
                self._sync_parent()
        else:
            if not self._owns_journal:
                raise ExecUnavailable('launch journal not owned')
            fd = os.open(self.journal, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                prior = json.loads(stream.read(16385))
            if prior.get('incarnation') != self.incarnation:
                raise ExecUnavailable('launch journal replaced')
            temporary = self.journal.with_name(self.journal.name + '.' + self.incarnation + '.tmp')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.journal)
            self._sync_parent()

    def _sync_parent(self):
        fd = os.open(self.journal.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ExecUnavailable('launch rendezvous expired')
        return remaining

    def _inspect(self, pid):
        self._remaining()
        info = self.engine.inspect(self.exec_id)
        # Engine PID is a cross-check against a held sender object, not a lookup
        # used to acquire authority. Stale inspect cannot resurrect an origin.
        if (type(info) is not dict or info.get('ID') != self.exec_id
                or info.get('ContainerID') != self.seat.container_id
                or info.get('Running') is not True or type(info.get('Pid')) is not int
                or info['Pid'] != pid or not alive(self.origin.pidfd)):
            raise ExecUnavailable('exact exec identity not verified')
        self._remaining()

    def launch(self, listener):
        if self.state != 'new':
            raise ExecUnavailable('launch is one-shot; reconcile before replacement')
        # No engine mutation before actual platform and endpoint checks.
        probe(); self.endpoint.require(); enable(listener)
        self.state = 'creating'
        self._save(first=True)
        self.deadline = time.monotonic() + self.timeout
        try:
            self.exec_id = self.engine.create(self.seat.container_id, {
                'AttachStdin': True, 'AttachStdout': True, 'AttachStderr': True,
                'Tty': False, 'Privileged': False, 'User': '65532:65532',
                'WorkingDir': '/uas/workspace', 'Cmd': [CONNECTOR, self.seat.slot],
                'Env': []})
            if type(self.exec_id) is not str or not ID.fullmatch(self.exec_id):
                raise ExecUnavailable('invalid exec-create result')
            self.state = 'starting'; self._save()
            self.transport = self.engine.start(self.exec_id)
            self.challenge = secrets.token_bytes(32)
            self.transport.write(self.challenge, timeout=self._remaining())
            listener.settimeout(self._remaining())
            self.channel, _ = listener.accept()
            enable(self.channel)
            self.channel.settimeout(self._remaining())
            with receive(self.channel) as record:
                if (len(record.data) != 36 or record.data[:4] != b'UAS1'
                        or not hmac.compare_digest(record.data[4:], self.challenge)
                        or record.credentials[1:] != (self.seat.host_uid, self.seat.host_gid)):
                    raise OriginDenied('unmatched launch record')
                self.origin = HeldOrigin(record)
            self.challenge = None  # consumed before inspecting or releasing
            self._inspect(self.origin.credentials[0])
            self.endpoint.require()
            self.state = 'bound'; self._save()
            self._inspect(self.origin.credentials[0])
            if self.channel.send(RELEASE) != len(RELEASE):
                raise ExecUnavailable('incomplete release')
            self.state = 'released'; self._save()
            return self
        except BaseException:
            self.challenge = None
            self.state = 'uncertain'
            if self.origin is not None:
                self.origin.revoke()
            try:
                self._save()
            except (OSError, ExecUnavailable, ValueError):
                pass  # Existing creating/starting marker still blocks retry.
            self.close_transport()
            raise

    def require_record(self, record, *, room_id, participant_id):
        if (self.state != 'active' or room_id != self.seat.room_id
                or participant_id != self.seat.participant_id):
            raise OriginDenied('inactive or wrong Room/Participant')
        try:
            self.endpoint.require()
        except (OSError, ExecUnavailable):
            self.origin.revoke()
            self.state = 'revoked'
            raise
        self.origin.require(record)

    def activate(self, native_ready):
        # Adapter must freshly prove native version/context/readiness. A string,
        # payload claim or a surviving Docker I/O stream cannot activate a seat.
        if self.state != 'released' or not callable(native_ready):
            raise ExecUnavailable('not released for native attachment')
        self.endpoint.require()
        if self.origin.revoked or not alive(self.origin.pidfd) or native_ready(self) is not True:
            raise ExecUnavailable('native readiness not established')
        self.endpoint.require()
        if self.origin.revoked or not alive(self.origin.pidfd):
            raise ExecUnavailable('task exited or revoked during native attachment')
        self.state = 'active'
        try:
            self._save()
        except BaseException:
            self.origin.revoke()
            self.state = 'uncertain'
            raise

    @property
    def native_readiness(self):
        """Defensive immutable-by-ownership metadata; never a live authority."""
        return None if self._native_readiness is None else json.loads(json.dumps(self._native_readiness))

    def attach_native(self, *, journal, scope, profile_digest, timeout=8, startup_observer=None):
        """Supervisor-only concrete fresh-native proof over exact Engine RPC.

        profile_digest identifies trusted immutable payload admission; this
        method does not itself verify that image/profile or infer binary version
        from the extension's API-baseline field. No peer-channel read occurs.
        """
        from .pi_runtime import FixturePiRpcReceiver
        if self.state != 'released' or self.native_receiver is not None:
            raise ExecUnavailable('native attachment is one-shot after release')
        try:
            if (type(profile_digest) is not str or not ID.fullmatch(profile_digest)
                    or type(scope) is not dict
                    or set(scope) != {'room_id', 'participant_id', 'run_id', 'generation', 'context_generation'}
                    or any(type(scope[k]) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', scope[k])
                           for k in ('room_id', 'participant_id', 'run_id'))
                    or any(type(scope[k]) is not int or not 1 <= scope[k] < 2**53
                           for k in ('generation', 'context_generation'))
                    or type(self.exec_id) is not str or not ID.fullmatch(self.exec_id)
                    or scope.get('room_id') != self.seat.room_id
                    or scope.get('participant_id') != self.seat.participant_id):
                raise ExecUnavailable('trusted native scope/profile required')
            scope = dict(scope)
            receiver = FixturePiRpcReceiver.attach_workstation(self, journal=journal,
                scope=scope, timeout=timeout, startup_observer=startup_observer)
            self.native_receiver = receiver
            if (receiver.incarnation_id != self.incarnation or receiver.scope != scope
                    or receiver.runtime_version != '1.4.0'):
                raise ExecUnavailable('native attachment binding mismatch')
            proof = receiver.prove_fresh_context()
            prefix = '/uas/runtime/' + self.seat.slot + '/sessions/'
            if (type(proof) is not dict
                    or set(proof) != {'runtime_id', 'session_id', 'session_file', 'source'}
                    or any(type(proof[k]) is not str or not 0 < len(proof[k]) <= 1024
                           for k in proof)
                    or proof['source'] != 'native-empty-session-and-no-pending-messages'
                    or any(ord(c) < 32 or ord(c) == 127 for c in proof['session_file'])
                    or not proof['session_file'].startswith(prefix)
                    or str(Path(proof['session_file'])) != proof['session_file']
                    or '..' in Path(proof['session_file']).parts
                    or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', proof[k])
                           for k in ('runtime_id', 'session_id'))):
                raise ExecUnavailable('bounded fresh native proof required')
            metadata = {'version': 1, 'runtime': 'Pi', 'runtime_version': '1.4.0',
                'profile_digest': profile_digest, 'scope': dict(scope),
                'incarnation': self.incarnation, 'exec_id': self.exec_id,
                'container_id': self.seat.container_id,
                'origin_identity': list(self.origin.identity), 'native': dict(proof)}
            canonical = json.dumps(metadata, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            if len(canonical) > 8192:
                raise ExecUnavailable('oversized native readiness')
            metadata['digest'] = hashlib.sha256(canonical).hexdigest()
            self._native_readiness = metadata
            # activate rechecks endpoint/liveness before and after the callback,
            # then fsyncs active state AND this proof in the existing journal.
            self.activate(lambda launch: launch.native_receiver is receiver)
            return receiver
        except BaseException:
            self._native_readiness = None
            self.state = 'uncertain'
            if self.origin is not None:
                self.origin.revoke()
            try:
                self._save()
            except BaseException:
                pass  # Cleanup must still run; prior marker blocks blind relaunch.
            try:
                self.close_transport()
            finally:
                receiver, self.native_receiver = self.native_receiver, None
                if receiver is not None:
                    receiver.close()
            raise

    def revoke(self):
        if self.origin is not None:
            self.origin.revoke()
        self.state = 'revoked'
        self._save()

    def close_transport(self):
        # No numeric-PID kill, whole-container kill, broad cleanup or respawn.
        # Transport closure does not assert actual task exit.
        resources = (self.channel, self.transport)
        self.channel = self.transport = None
        error = None
        for resource in resources:
            if resource is not None:
                try:
                    resource.close()
                except BaseException as failure:
                    error = failure
        if error is not None:
            raise error

    def close(self):
        try:
            if self._owns_journal:
                self.revoke()
        finally:
            try:
                self.close_transport()
            finally:
                try:
                    receiver, self.native_receiver = self.native_receiver, None
                    if receiver is not None:
                        receiver.close()
                finally:
                    if self.origin is not None:
                        self.origin.close()
