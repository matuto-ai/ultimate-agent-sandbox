"""Supervisor-owned read-only revision plus separately bounded writable work.

The launcher must independently admit a hard 8 MiB, nosuid/nodev/noexec tmpfs
mounted at the fixed Workstation /uas/gate-work path. This owner never mounts,
changes accounts, repairs permissions or cleans an uncertain command tree.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import threading

from .artifact_protocol import ArtifactError, TARGET_KEYS, RESERVATION_BYTES, canonical, validate_scope, validate_source
from .artifact_target import ArtifactTargets, _open_dir, _identity, _read_at
from .artifact_helper import HELPER_HOST_GID
from .gate_repository import WORK_BYTES, validate_command_target


class CommandTargetLease:
    def __init__(self, owner, evaluation, source):
        self.owner, self.evaluation_id, self.source = owner, evaluation, deepcopy(source)
        self.target = self.base = None
        self.work_identity = None
        self.work_create_possible = False
        self.launch_possible = self.exit_confirmed = False
        self.phase = 'intent'

    def document(self):
        if self.target is None:
            raise ArtifactError('COMMAND_TARGET_NOT_PREPARED')
        return deepcopy(self.target)

    def _work(self):
        parent = self.owner._root()
        try:
            fd = os.open(self.base.target_id, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)
        node = os.fstat(fd)
        if (_identity(node) != self.work_identity or node.st_uid != os.getuid()
                or node.st_gid != HELPER_HOST_GID or stat.S_IMODE(node.st_mode) != 0o770):
            os.close(fd)
            raise ArtifactError('COMMAND_WORK_IDENTITY_CHANGED')
        return fd

    def recheck(self):
        self.base.recheck()
        fd = self._work(); os.close(fd)
        return True

    def recheck_binding(self):
        return self.base.recheck_binding()

    def postverify(self):
        if self.base.postverify() != {key: self.target[key] for key in TARGET_KEYS}:
            raise ArtifactError('COMMAND_TARGET_CHANGED')
        fd = self._work(); os.close(fd)
        return self.document()

    def mark_launch_possible(self):
        if self.phase != 'prepared' or self.launch_possible:
            raise ArtifactError('COMMAND_LAUNCH_REPLAY')
        self.launch_possible = True
        self.phase = 'launch-possible'
        self.owner._save(self)
        self.base.mark_launch_possible()

    def mark_exit_confirmed(self):
        # Only successful fixed command-helper completion proves whole-tree
        # exhaustion. A helper pidfd alone must never call this method.
        if not self.launch_possible:
            raise ArtifactError('COMMAND_TREE_EXIT_UNVERIFIED')
        self.exit_confirmed = True
        self.base.mark_exit_confirmed()

    def cleanup(self):
        if self.launch_possible and not self.exit_confirmed:
            raise ArtifactError('COMMAND_TREE_EXIT_UNVERIFIED')
        if self.phase == 'removed':
            return True
        try:
            if self.work_identity is None and self.work_create_possible:
                parent = self.owner._root()
                try:
                    try:
                        os.stat(self.base.target_id, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise ArtifactError('COMMAND_WORK_CREATION_UNCERTAIN')
                finally:
                    os.close(parent)
            if self.work_identity is not None:
                fd = self._work()
                try:
                    # Native trusted cleanup happens after all descendants exit.
                    # Supervisor independently establishes empty exact identity.
                    if os.listdir(fd):
                        raise ArtifactError('COMMAND_WORK_CLEANUP_INCOMPLETE')
                finally:
                    os.close(fd)
                parent = self.owner._root()
                try:
                    node = os.stat(self.base.target_id, dir_fd=parent, follow_symlinks=False)
                    if _identity(node) != self.work_identity:
                        raise ArtifactError('COMMAND_WORK_IDENTITY_CHANGED')
                    os.rmdir(self.base.target_id, dir_fd=parent)
                    os.fsync(parent)
                    self.work_identity = None
                    self.owner._save(self)
                finally:
                    os.close(parent)
            if self.base is not None and self.base.cleanup() is not True:
                raise ArtifactError('COMMAND_TARGET_CLEANUP_FAILED')
            self.phase = 'removed'; self.owner._save(self)
            return True
        except BaseException:
            self.phase = 'quarantined'; self.owner._save(self)
            raise


class CommandTargets:
    """One fixed source/work owner, no generic scratch or process service."""
    def __init__(self, root, journal_root, resolver, *, work_root, reserve_capacity, admit_work):
        if not callable(admit_work) or not callable(reserve_capacity):
            raise ArtifactError('COMMAND_WORK_ADMISSION_REQUIRED')
        self.work_root, self.journal_root = Path(work_root), Path(journal_root)
        self.admit_work = admit_work
        self.resolver = resolver
        self.owned = {}
        self._lock = threading.RLock()
        # The shared hard tmpfs bound is conservative per Evaluation. Concurrent
        # work may exhaust it and fail; it never permits unbounded output/work.
        self.targets = ArtifactTargets(root, self.journal_root, resolver,
            reserve_capacity=lambda scope, amount: reserve_capacity(scope, amount + WORK_BYTES))
        self.root_identity = None
        self.journal_identity = None
        fd = self._root(first=True)
        try:
            self.root_identity = _identity(os.fstat(fd))
        finally:
            os.close(fd)

    def _root(self, *, first=False):
        if self.admit_work(self.work_root, WORK_BYTES) is not True:
            raise ArtifactError('COMMAND_WORK_NOT_ADMITTED')
        fd = _open_dir(self.work_root)
        node, fs = os.fstat(fd), os.fstatvfs(fd)
        if (node.st_uid != os.getuid() or stat.S_IMODE(node.st_mode) != 0o711
                or not 0 < fs.f_frsize <= 4096 or fs.f_blocks * fs.f_frsize > WORK_BYTES
                or fs.f_flag & os.ST_RDONLY or not first and _identity(node) != self.root_identity):
            os.close(fd)
            raise ArtifactError('COMMAND_WORK_ROOT_MISMATCH')
        return fd

    def _save(self, lease, *, first=False):
        # Separate fixed-prefix records are outside ArtifactTargets' bounded
        # resource journal; the launcher supplies an existing private directory.
        directory = self.journal_root.parent / 'command-work'
        parent = _open_dir(directory)
        try:
            node = os.fstat(parent)
            if node.st_uid != os.getuid() or stat.S_IMODE(node.st_mode) != 0o700:
                raise ArtifactError('COMMAND_WORK_JOURNAL_UNTRUSTED')
            if self.journal_identity is None:
                self.journal_identity = _identity(node)
            elif _identity(node) != self.journal_identity:
                raise ArtifactError('COMMAND_WORK_JOURNAL_CHANGED')
            name = hashlib.sha256(lease.evaluation_id.encode()).hexdigest() + '.json'
            document = {'version': 1, 'evaluation_id': lease.evaluation_id, 'phase': lease.phase,
                'target_id': None if lease.base is None else lease.base.target_id,
                'work_identity': lease.work_identity, 'work_create_possible': lease.work_create_possible, 'launch_possible': lease.launch_possible,
                'reservation_bytes': RESERVATION_BYTES + WORK_BYTES}
            data = canonical(document)
            if first:
                if len(os.listdir(parent)) >= 16:
                    raise ArtifactError('COMMAND_WORK_HISTORY_CAPACITY')
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            else:
                prior, prior_node = _read_at(parent, name, 4096)
                try:
                    previous = json.loads(prior)
                    matches = type(previous) is dict and previous.get('evaluation_id') == lease.evaluation_id
                except (ValueError, TypeError):
                    matches = False
                if (not matches or prior_node.st_uid != os.getuid()
                        or stat.S_IMODE(prior_node.st_mode) != 0o600):
                    raise ArtifactError('COMMAND_WORK_JOURNAL_CHANGED')
                # Exclusive staging preserves the last durable intent on a
                # partial write. An uncertain staging file blocks, never retries
                # or reconstructs execution/cleanup authority after restart.
                fd = os.open(name + '.next', os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                if os.write(fd, data) != len(data):
                    raise ArtifactError('COMMAND_WORK_JOURNAL_UNKNOWN')
                os.fsync(fd)
            finally:
                os.close(fd)
            if not first:
                if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(prior_node):
                    raise ArtifactError('COMMAND_WORK_JOURNAL_CHANGED')
                os.replace(name + '.next', name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)

    def prepare(self, scope, source):
        with self._lock:
            validate_scope(scope); validate_source(source)
            evaluation = scope['evaluation_id']
            if evaluation in self.owned:
                raise ArtifactError('COMMAND_PREPARATION_REPLAY')
            lease = CommandTargetLease(self, evaluation, source)
            self._save(lease, first=True); self.owned[evaluation] = lease
            try:
                base = self.targets.prepare(scope, source)
                lease.base = self.targets.lease(base); self._save(lease)
                parent = self._root()
                try:
                    lease.work_create_possible = True; self._save(lease)
                    os.mkdir(base['target_id'], 0o770, dir_fd=parent)
                    fd = os.open(base['target_id'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    try:
                        lease.work_identity = _identity(os.fstat(fd)); self._save(lease)
                        os.fchown(fd, -1, HELPER_HOST_GID); os.fchmod(fd, 0o770)
                    finally:
                        os.close(fd)
                    os.fsync(parent)
                finally:
                    os.close(parent)
                lease.target = validate_command_target({**base, 'work': {'device': lease.work_identity[0],
                    'inode': lease.work_identity[1], 'limit_bytes': WORK_BYTES}})
                lease.phase = 'prepared'; self._save(lease)
                return lease.document()
            except BaseException:
                # A materializer can fail after its own durable resource intent.
                # Retain that exact existing lease rather than declaring an
                # absent wrapper target clean while its base remains live.
                if lease.base is None:
                    lease.base = self.targets.owned.get(evaluation)
                lease.phase = 'quarantined'; self._save(lease)
                raise

    def lease(self, target):
        validate_command_target(target)
        matches = [lease for lease in self.owned.values() if lease.target == target]
        if len(matches) != 1:
            raise ArtifactError('COMMAND_TARGET_NOT_OWNED')
        return matches[0]

    def reconcile(self, evaluation_id):
        lease = self.owned.get(evaluation_id)
        reference = 'command-work-' + hashlib.sha256(evaluation_id.encode()).hexdigest()[:32]
        if lease is None or lease.launch_possible and not lease.exit_confirmed:
            return {'cleanup': False, 'quarantine_ref': reference}
        try:
            cleaned = lease.cleanup() is True
        except (ArtifactError, OSError):
            cleaned = False
        return {'cleanup': cleaned, 'quarantine_ref': None if cleaned else reference}
