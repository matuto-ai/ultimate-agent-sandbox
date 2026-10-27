"""Explicit, quiescent Project setup for a neutral primary commondir marker.

Not a launcher repair path. The Supervisor supplies an already ownership-bound
primary Git directory and its lifecycle/writer guards. Only an absent marker is
created. Existing human metadata, interrupted creations, and changed identities
raise attention; nothing is adopted, overwritten, chmodded or removed in repair.
The new marker is the sole Project metadata change: b'.\\n', preserving the same
common directory. Native host-Git compatibility remains a required qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from .ledger import LedgerError, _json, _token
from .lifecycle import _unique_object

MARKER = b'.\n'


def _node(info): return [info.st_dev, info.st_ino]


class GitPrimarySetup:
    def __init__(self, journal, *, room_id, project_id):
        self.room_id, self.project_id = _token(room_id), _token(project_id)
        self.journal = Path(journal)
        if (not self.journal.is_absolute() or self.journal.parent.resolve() != self.journal.parent
                or self.journal.name in {'.', '..'}):
            raise LedgerError('INVALID_GIT_SETUP_STORE')
        parent = self.journal.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise LedgerError('INVALID_GIT_SETUP_STORE')
        self.directory = os.open(self.journal.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.parent = _node(os.fstat(self.directory))
        self.failed = False

    def close(self):
        if self.directory >= 0:
            fd, self.directory = self.directory, -1
            os.close(fd)

    def _require(self):
        if self.failed or self.directory < 0 or _node(self.journal.parent.stat()) != self.parent:
            raise LedgerError('GIT_SETUP_UNAVAILABLE')

    def _read(self):
        self._require()
        try: fd = os.open(self.journal.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.directory)
        except FileNotFoundError: return None
        try:
            node = os.fstat(fd)
            if (not stat.S_ISREG(node.st_mode) or node.st_uid != os.getuid() or node.st_mode & 0o077
                    or node.st_nlink != 1 or not 0 < node.st_size <= 8192):
                raise LedgerError('INVALID_GIT_SETUP_STORE')
            raw = os.read(fd, 8193)
            value = json.loads(raw, object_pairs_hook=_unique_object)
            if (type(value) is not dict or _json(value).encode() != raw or set(value) != {'version', 'room_id',
                    'project_id', 'parent', 'project_owner', 'phase', 'marker'}
                    or type(value['version']) is not int or value['version'] != 1
                    or value['room_id'] != self.room_id or value['project_id'] != self.project_id
                    or value['phase'] not in {'intent', 'owned'}):
                raise LedgerError('INVALID_GIT_SETUP_STORE')
            return value
        except (ValueError, UnicodeError, RecursionError):
            raise LedgerError('INVALID_GIT_SETUP_STORE') from None
        finally:
            os.close(fd)

    def _save(self, value, *, first=False):
        self._require()
        raw = _json(value).encode()
        if len(raw) > 8192: raise LedgerError('INVALID_GIT_SETUP_STORE')
        name = self.journal.name if first else '.git-setup-' + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.directory)
        try:
            position = 0
            while position < len(raw):
                count = os.write(fd, raw[position:])
                if count <= 0: raise OSError('incomplete Git setup journal')
                position += count
            os.fsync(fd)
        finally:
            os.close(fd)
        if not first:
            # The held private Supervisor directory excludes untrusted writers.
            os.replace(name, self.journal.name, src_dir_fd=self.directory, dst_dir_fd=self.directory)
        os.fsync(self.directory)

    @staticmethod
    def _parent(gitdir_fd, expected_identity, project_owner):
        node = os.fstat(gitdir_fd)
        if (type(expected_identity) is not tuple or len(expected_identity) != 2
                or any(type(value) is not int or value < 0 for value in expected_identity)
                or type(project_owner) is not int or project_owner < 0
                or not stat.S_ISDIR(node.st_mode) or node.st_uid != project_owner
                or tuple(_node(node)) != expected_identity):
            raise LedgerError('GIT_SETUP_PROJECT_MISMATCH')
        return node

    @staticmethod
    def _observe(gitdir_fd):
        fd = os.open('commondir', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gitdir_fd)
        try:
            node = os.fstat(fd)
            if (not stat.S_ISREG(node.st_mode) or node.st_uid != os.getuid()
                    or stat.S_IMODE(node.st_mode) != 0o444 or node.st_nlink != 1
                    or node.st_size != len(MARKER) or os.read(fd, 3) != MARKER):
                raise LedgerError('GIT_SETUP_MARKER_CHANGED')
            return {'identity': _node(node), 'owner': node.st_uid, 'sha256': hashlib.sha256(MARKER).hexdigest()}
        finally:
            os.close(fd)

    def prepare(self, gitdir_fd, *, expected_identity, project_owner, authorize, quiescent):
        """Caller holds the existing Supervisor lifecycle + checkout writer lock."""
        if not callable(authorize) or not callable(quiescent) or authorize() is not True or quiescent() is not True:
            raise LedgerError('GIT_SETUP_REQUIRES_QUIESCENCE')
        parent = self._parent(gitdir_fd, expected_identity, project_owner)
        old = self._read()
        if old is not None:
            if old['parent'] != _node(parent) or old['project_owner'] != project_owner:
                raise LedgerError('GIT_SETUP_PROJECT_MISMATCH')
            if old['phase'] != 'owned': raise LedgerError('GIT_SETUP_INTERRUPTED')
            if self._observe(gitdir_fd) != old['marker']: raise LedgerError('GIT_SETUP_MARKER_CHANGED')
            return old
        value = {'version': 1, 'room_id': self.room_id, 'project_id': self.project_id,
            'parent': _node(parent), 'project_owner': project_owner, 'phase': 'intent', 'marker': None}
        try:
            self._save(value, first=True)  # Durable intent precedes any Project effect.
            if authorize() is not True or quiescent() is not True:
                raise LedgerError('GIT_SETUP_REQUIRES_QUIESCENCE')
            self._parent(gitdir_fd, expected_identity, project_owner)
            try:
                fd = os.open('commondir', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o444, dir_fd=gitdir_fd)
            except FileExistsError:
                raise LedgerError('GIT_SETUP_COLLISION') from None
            try:
                if os.write(fd, MARKER) != len(MARKER): raise OSError('incomplete neutral Git marker')
                os.fchmod(fd, 0o444)  # Only the newly O_EXCL-created owned inode.
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(gitdir_fd)
            value.update(phase='owned', marker=self._observe(gitdir_fd))
            self._save(value)
            return value
        except BaseException:
            self.failed = True
            # No unlink/overwrite rollback: partial state is explicit attention.
            raise
