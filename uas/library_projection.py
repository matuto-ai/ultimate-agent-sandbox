"""Supervisor-owned, Project-bound atomic read projections (T07).

One immutable generation holds both the bundle and its manifest. The two fixed
public links traverse one atomic current pointer, never two independently
updated files. A multi-file consumer pins that generation with ``read``; native
file readers may bracket a group of reads with the manifest and retry if it
changes. Independent opens across any publication boundary are not a transaction.
The existing supervisor-owned, read-only reference mount remains the Participant
write boundary; this module neither provisions a mount nor changes host policy.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import threading
from types import MappingProxyType
import uuid

from . import library, library_bundle

STATE = '.library-snapshots'
CURRENT = '.library-current'
MANIFEST = 'library.snapshot.json'
GENERATION = re.compile(r'[0-9a-f]{32}\Z')
LINKS = {'library': CURRENT + '/library', MANIFEST: CURRENT + '/' + MANIFEST}


def _fail(code='UNSAFE_PROJECTION', field='projection'):
    raise library.LibraryError(code, field)


def _root(scope):
    library_bundle._prefix(scope)
    path = Path(scope.reference_root)
    if path.name != 'library' or not library._absolute(str(path)):
        _fail('INVALID_BINDING')
    root = path.parent
    if root.resolve() != root:
        _fail()
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        _fail()
    return root


def _directory(path, *, create=False):
    if create:
        try:
            path.mkdir(mode=0o755)
        except FileExistsError:
            pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        _fail()


def _bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            _fail()
        data = b''
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > limit:
            _fail('BUNDLE_TOO_LARGE')
        return data
    finally:
        os.close(fd)


def _write(path, data, mode=0o444):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(data)
            out.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _guard(root, exclusive=False):
    fd = os.open(root / STATE / 'read.lock', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            _fail()
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        os.close(fd)


def _selected(root):
    target = os.readlink(root / CURRENT)
    if not target.startswith(STATE + '/') or not GENERATION.fullmatch(target[len(STATE)+1:]):
        _fail()
    path = root / target
    _directory(path)
    return path


def _links(root):
    for name, target in LINKS.items():
        if os.readlink(root / name) != target:
            _fail()


@dataclass(frozen=True)
class PublishedSnapshot:
    manifest: dict
    files: dict

    def __post_init__(self):
        object.__setattr__(self, 'manifest', MappingProxyType(dict(self.manifest)))
        object.__setattr__(self, 'files', MappingProxyType(dict(self.files)))


def _read(root, scope, limits):
    _links(root)
    generation = _selected(root)
    manifest = library.snapshot(json.loads(_bytes(generation / MANIFEST, 4096)))
    if (manifest['project_id'] != scope.project_id
            or manifest['project_identity'] != scope.project_identity):
        _fail('PROJECT_MISMATCH')
    bundle = generation / 'library'
    files, total = {}, 0
    if manifest['commit_sha'] is None:
        if os.path.lexists(bundle):
            _fail('INCOHERENT_PROJECTION')
    else:
        _directory(bundle)
        def walk_error(error):
            raise error
        for directory, dirs, names in os.walk(bundle, followlinks=False, onerror=walk_error):
            for name in dirs:
                _directory(Path(directory) / name)
            for name in names:
                path = Path(directory) / name
                relative = path.relative_to(bundle).as_posix()
                library_bundle._path(relative, 'projection')
                data = _bytes(path, limits['document_bytes'])
                files[relative] = data
                total += len(data)
                if total > limits['projection_bytes'] or len(files) > limits['scan_documents']:
                    _fail('BUNDLE_TOO_LARGE')
        if not files:
            _fail('INCOHERENT_PROJECTION')
    return PublishedSnapshot(manifest, files)


def read_projection(scope, settings):
    """Read one complete, pinned generation. No caller-selected path or write API.

    Trusted routing supplies scope; native Runtime reads use the fixed mounted
    paths. The shared short read lock prevents reclamation during this copy.
    """
    root = _root(scope)
    limits = library.admit_settings_value(settings)['limits']
    _directory(root / STATE)
    with _guard(root):
        return _read(root, scope, limits)


class ProjectProjection:
    """One supervisor projection worker, separate from the canonical write path.

    ``scope`` and ``current_scope`` derive from the same trusted Room binding.
    The approved reference parent must already exist and be supervisor-owned;
    callers cannot pass a destination or a canonical source prefix.
    """
    def __init__(self, publisher, scope, settings, *, current_scope, clock=None):
        self.publisher, self.scope = publisher, scope
        self.settings = library.admit_settings_value(settings)
        if not callable(current_scope):
            _fail('LIBRARY_AUTHENTICATION_REQUIRED')
        self.current_scope = current_scope
        self.clock = clock or (lambda: datetime.now(timezone.utc).isoformat())
        self.root = _root(scope)
        canonical = publisher.root.resolve()
        if (self.root == canonical or canonical in self.root.parents or self.root in canonical.parents):
            _fail('INVALID_BINDING')
        if (publisher.target != self.settings['repository']['target']
                or publisher.branch != self.settings['repository']['branch']):
            _fail('TARGET_MISMATCH')
        self._mutex = threading.RLock()
        self._condition = threading.Condition()
        self._processed = 0
        self._thread = None
        self._subscription = None
        self._lease = None
        self.last_error = None
        self._current()
        try:
            self._initialize()
        except BaseException:
            self.close()
            raise

    def _current(self):
        fresh = self.current_scope()
        if (type(fresh) is not library.LibraryScope or fresh.canonical() != self.scope.canonical()):
            _fail('LIBRARY_AUTHENTICATION_REQUIRED')

    def _initialize(self):
        state = self.root / STATE
        _directory(state, create=True)
        staging = state / 'staging'
        try:
            staging.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _directory(staging)
        if stat.S_IMODE(staging.stat().st_mode) != 0o700:
            _fail()
        fd = os.open(state / 'lease', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                _fail()
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(fd)
            raise
        self._lease = fd
        pin = {'project_id': self.scope.project_id, 'project_identity': self.scope.project_identity,
               'project_path': self.scope.project_path}
        pin_path = state / 'project.json'
        if not os.path.lexists(pin_path):
            _write(pin_path, json.dumps(pin, sort_keys=True).encode())
        elif json.loads(_bytes(pin_path, 4096)) != pin:
            _fail('PROJECT_MISMATCH')
        if not os.path.lexists(state / 'read.lock'):
            _write(state / 'read.lock', b'')
        with _guard(self.root, True):
            for name, target in LINKS.items():
                path = self.root / name
                if os.path.lexists(path):
                    if not path.is_symlink() or os.readlink(path) != target:
                        _fail()
                else:
                    os.symlink(target, path)
            if not os.path.lexists(self.root / CURRENT):
                manifest = self._manifest(None, None)
                generation = self._stage(manifest, {})
                self._switch(generation)
            _read(self.root, self.scope, self.settings['limits'])
            self._reclaim(_selected(self.root))

    def _reclaim(self, keep):
        # Only UUID generation directories in our pinned owned namespace.
        # Unknown human files are never cleanup candidates.
        for parent in (self.root / STATE, self.root / STATE / 'staging'):
            for path in parent.iterdir():
                if path != keep and GENERATION.fullmatch(path.name):
                    info = path.lstat()
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                        _fail()
                    self._discard(path)

    def _manifest(self, sha, at):
        return library.snapshot({'version': 1, 'project_id': self.scope.project_id,
                                 'project_identity': self.scope.project_identity,
                                 'commit_sha': sha, 'published_at': at})

    def _stage(self, manifest, files):
        staging = self.root / STATE / 'staging'
        generation = staging / uuid.uuid4().hex
        generation.mkdir(mode=0o700)
        try:
            if files:
                (generation / 'library').mkdir(mode=0o755)
                for name, data in files.items():
                    path = generation / 'library' / name
                    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    _write(path, data)
            _write(generation / MANIFEST, json.dumps(manifest, sort_keys=True).encode())
            for directory, _, _ in os.walk(generation, topdown=False):
                _sync(Path(directory))
                os.chmod(directory, 0o700 if Path(directory) == generation else 0o555)
            _sync(staging)
            return generation
        except BaseException:
            self._discard(generation)
            raise

    def _switch(self, generation):
        temporary = self.root / (CURRENT + '-' + uuid.uuid4().hex)
        # Only complete immutable generations leave the supervisor-only staging
        # directory; partial construction is never reachable by Participants.
        public = self.root / STATE / generation.name
        os.rename(generation, public)
        os.chmod(public, 0o555)
        _sync(public)
        _sync(self.root / STATE)
        try:
            os.symlink(STATE + '/' + generation.name, temporary)
            os.replace(temporary, self.root / CURRENT)  # publication linearization point
        finally:
            if os.path.lexists(temporary):
                temporary.unlink()
        # Once visible, never call this a failed refresh or roll it back. A
        # directory-sync error is a crash-durability diagnostic, not invisibility.
        try:
            _sync(self.root)
        except OSError:
            self.last_error = 'PROJECTION_SYNC_UNCERTAIN'

    @staticmethod
    def _discard(generation):
        if generation.exists() and not generation.is_symlink():
            for directory, _, _ in os.walk(generation):
                os.chmod(directory, 0o755)
            shutil.rmtree(generation)

    def refresh(self):
        """Supervisor reconciliation; failures retain the previous publication."""
        with self._mutex:
            generation = None
            try:
                if self._lease is None:
                    _fail('NOT_READY')
                self._current()
                sha, tree = self.publisher.projection_snapshot(self.scope, self.settings, current=self._current)
                prefix = library_bundle._prefix(self.scope)
                if not tree.files:
                    _fail('PROJECT_NOT_REGISTERED')
                library_bundle._tree(tree, 'projection')
                parsed = library_bundle._canonical_files(tree, prefix, self.settings['limits'], 'projection')
                # Reader safety and exact immutable identity, not the write gate:
                # a new write-policy refusal must not hide existing reference data.
                for name in library_bundle.REQUIRED:
                    if name not in parsed:
                        _fail('MALFORMED_EXISTING_BUNDLE')
                library_bundle._root_index(parsed['index.md'][1], self.scope)
                files = {name: tree.files[path] for name, (path, _) in parsed.items()}
                prior = self.read()
                if prior.manifest['commit_sha'] == sha:
                    self.last_error = None
                    return True
                manifest = self._manifest(sha, self.clock())
                generation = self._stage(manifest, files)
                self._current()
                with _guard(self.root, True):
                    self._current()
                    _links(self.root)
                    previous = _selected(self.root)
                    self.last_error = None
                    self._switch(generation)
                    generation = None
                    # All pinned readers have released the shared lock. Retain
                    # just the new generation; no historical content accumulates.
                    try:
                        self._discard(previous)
                    except OSError:
                        self.last_error = 'PROJECTION_CLEANUP_PENDING'
                return True
            except (library.LibraryError, OSError, ValueError, UnicodeError) as error:
                self.last_error = error.code if isinstance(error, library.LibraryError) else 'PROJECTION_UNAVAILABLE'
                if generation is not None:
                    try:
                        self._discard(generation)
                    except OSError:
                        pass
                    public = self.root / STATE / generation.name
                    try:
                        if public != _selected(self.root):
                            self._discard(public)
                    except OSError:
                        pass
                return False

    def read(self):
        return read_projection(self.scope, self.settings)

    def visibility(self, commit_sha=None):
        """Conservative exact-commit observation, never a durability decision.

        Later capture composition can inspect a newer pinned tree for its exact
        draft; this seam does not infer that an older draft survived later writes.
        """
        if commit_sha is not None:
            library._commit(commit_sha, 'commit_sha')
        view = self.read()
        sha = view.manifest['commit_sha']
        return {'commit_sha': sha, 'visible': sha is not None and (commit_sha is None or sha == commit_sha)}

    def start(self):
        with self._mutex:
            if self._thread is not None or self._lease is None:
                _fail('ALREADY_STARTED')
            self._subscription = self.publisher.subscribe(self.scope)
            self._thread = threading.Thread(target=self._run, name='library-projection', daemon=True)
            self._thread.start()
        return self

    def _run(self):
        after = 0
        while True:
            version, _, closed = self._subscription.wait(after)
            if closed:
                return
            self.refresh()
            after = version
            with self._condition:
                self._processed = version
                self._condition.notify_all()

    def reconcile(self):
        """Schedule reconnect reconciliation without blocking interactive work."""
        if self._subscription is None:
            _fail('NOT_READY')
        self._subscription.signal()

    def wait_idle(self, timeout=5):
        """Bounded supervisor diagnostic/test wait, never on a capture path."""
        if self._subscription is None:
            _fail('NOT_READY')
        version, _, _ = self._subscription.wait(-1, 0)
        with self._condition:
            return self._condition.wait_for(lambda: self._processed >= version, timeout)

    def close(self):
        if self._subscription is not None:
            self.publisher.unsubscribe(self._subscription)
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        with self._mutex:
            if self._lease is not None:
                os.close(self._lease)
                self._lease = None
