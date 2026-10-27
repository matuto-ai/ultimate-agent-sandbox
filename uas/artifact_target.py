"""Supervisor-only inert Git ownership resolver and bounded disposable target.

Never invokes Git in the Project or copies configuration. A fresh generated bare
store contains only contained ordinary object data. This source profile is not
production-qualified; trusted runtime admission and Hub reservation are separate.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import threading
import time
import uuid

from .artifact_paths import READABLE_DIRECTORY_FLAGS, open_directory
from .checkout_scope import valid_writer_scope
from .manager_owner import REVISION_FIELDS, validate_revision
from .artifact_protocol import (ArtifactError, MAX_BLOB_BYTES, MAX_DEPTH, MAX_ENTRIES,
    MAX_METADATA_BYTES, MAX_OBJECT_BYTES, MAX_TARGET_BYTES, RESERVATION_BYTES,
    canonical, validate_path, validate_scope, validate_source, validate_target)

_DIR = READABLE_DIRECTORY_FLAGS
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_OID = re.compile(r'[0-9a-f]{40}\Z')
_BRANCH = re.compile(r'refs/heads/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\Z')
MAX_TEXT = 1 << 20
MAX_OBJECT_FILES = 512
MAX_RESOURCE_RECORDS = 16
GIT_BINARY = '/usr/bin/git'
LIMIT_BINARY = '/usr/bin/prlimit'
GIT_LIMITS = ('--as=268435456:268435456', '--cpu=10:10', '--fsize=0:0',
              '--core=0:0', '--nofile=64:64')
GIT_ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
    'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
    'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
    'GIT_NO_LAZY_FETCH': '1', 'GIT_ATTR_NOSYSTEM': '1', 'GIT_CONFIG_COUNT': '0'}


def _fail(code):
    raise ArtifactError(code)


def _identity(info):
    return [info.st_dev, info.st_ino]


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _parts(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or str(path) == '/':
        _fail('UNSAFE_ARTIFACT_PATH')
    return path.parts[1:]


def _open_dir(path):
    """Shared Gate traversal; every returned leaf remains readable."""
    return open_directory(path, invalid_code='UNSAFE_ARTIFACT_PATH',
                          unsupported_code='ARTIFACT_PATH_TRAVERSAL_UNAVAILABLE')


def _names(directory, limit):
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > limit:
                _fail('ARTIFACT_DIRECTORY_LIMIT')
    return names


def _read_at(directory, name, limit=MAX_TEXT):
    if '/' in name or name in ('', '.', '..'):
        _fail('UNSAFE_ARTIFACT_METADATA')
    fd = os.open(name, _FILE, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            _fail('UNSAFE_ARTIFACT_METADATA')
        data = bytearray()
        while True:
            part = os.read(fd, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
            if len(data) > limit:
                _fail('ARTIFACT_METADATA_LIMIT')
        if _stamp(before) != _stamp(os.fstat(fd)) or len(data) != before.st_size:
            _fail('ARTIFACT_SOURCE_CHANGED')
        if _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != _identity(before):
            _fail('ARTIFACT_SOURCE_CHANGED')
        return bytes(data), before
    finally:
        os.close(fd)


def _read_path(directory, relative, limit=MAX_TEXT):
    parts = relative.split('/')
    fd = os.dup(directory)
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIR, dir_fd=fd)
            previous, fd = fd, child
            os.close(previous)
        return _read_at(fd, parts[-1], limit)
    finally:
        os.close(fd)


def _unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            _fail('INVALID_ARTIFACT_OWNERSHIP')
        result[k] = v
    return result


class ArtifactSourceResolver:
    """Consumes trusted allocator fields, never its Git/observation methods."""
    def __init__(self, supervisor, allocator):
        if allocator.supervisor.directory != supervisor.directory:
            _fail('ARTIFACT_SUPERVISOR_MISMATCH')
        self.supervisor = supervisor
        self.room = deepcopy(allocator.room)
        self.repo, self.root = Path(allocator.repo), Path(allocator.root)
        self.manifest = Path(allocator.manifest)

    def resolve(self, run_id, participant_id, room_instance):
        try:
            # Existing trusted control-store lock only; no allocator _locked().
            with self.supervisor._locked():
                lifecycle = self.supervisor._read()
                if (lifecycle is None or lifecycle['phase'] != 'running'
                        or lifecycle['instance_id'] != room_instance
                        or lifecycle['spec']['project_id'] != self.room['project']['id']
                        or not {str(self.repo), str(self.root)} <= set(lifecycle['spec']['project_paths'])):
                    _fail('ARTIFACT_ROOM_UNAVAILABLE')
                with ExitStack() as stack:
                    def hold(path):
                        fd = _open_dir(path); stack.callback(os.close, fd); return fd
                    repo, root = hold(self.repo), hold(self.root)
                    common = os.open('.git', _DIR, dir_fd=repo); stack.callback(os.close, common)
                    control = hold(self.manifest.parent)
                    encoded, _ = _read_at(control, self.manifest.name)
                    state = json.loads(encoded, object_pairs_hook=_unique)
                    binding = {'version': 1, 'room_id': self.room['id'],
                        'instance_id': room_instance, 'project_id': self.room['project']['id'],
                        'repo': str(self.repo), 'root': str(self.root), 'common': str(self.repo / '.git'),
                        'filesystem': {'repo': _identity(os.fstat(repo)), 'root': _identity(os.fstat(root)),
                                       'common': _identity(os.fstat(common))}}
                    required = set(binding) | {'slots'}
                    if (type(state) is not dict or not required <= state.keys()
                            or set(state) - required - REVISION_FIELDS
                            or any(state[k] != v for k, v in binding.items())
                            or type(state['slots']) is not dict or len(state['slots']) > 1000):
                        _fail('INVALID_ARTIFACT_OWNERSHIP')
                    try:
                        validate_revision(state)
                    except ValueError:
                        _fail('INVALID_ARTIFACT_OWNERSHIP')
                    matches = [(key, slot) for key, slot in state['slots'].items()
                               if type(slot) is dict and slot.get('active') is True
                               and slot.get('run') == run_id]
                    if len(matches) != 1:
                        _fail('ARTIFACT_SLOT_NOT_OWNED')
                    key, slot = matches[0]
                    fields = {'path', 'branch', 'base', 'run', 'participant', 'active', 'phase', 'identity'}
                    if (set(slot) not in (fields, fields | {'writer_scope'})
                            or ('writer_scope' in slot and not valid_writer_scope(slot['writer_scope'], room_instance))
                            or slot['participant'] != participant_id or slot['phase'] != 'ready'
                            or (key != 'primary' and not re.fullmatch(r'[0-9a-f]{32}', key))
                            or not isinstance(slot['branch'], str) or not _BRANCH.fullmatch(slot['branch'])
                            or len(slot['branch']) > 512
                            or (key != 'primary' and slot['branch'] != 'refs/heads/uas-slot/' + key)):
                        _fail('ARTIFACT_SLOT_NOT_OWNED')
                    path = self.repo if key == 'primary' else self.root / key
                    if slot['path'] != str(path):
                        _fail('ARTIFACT_SLOT_NOT_OWNED')
                    slotfd = hold(path)
                    metadata = os.stat('.git', dir_fd=slotfd, follow_symlinks=False)
                    expected = {'directory': _identity(os.fstat(slotfd)), 'git_metadata': _identity(metadata)}
                    if slot['identity'] != expected:
                        _fail('ARTIFACT_SLOT_IDENTITY_CHANGED')
                    extra = {}
                    admin = common
                    if key != 'primary':
                        raw, _ = _read_at(slotfd, '.git', 4096)
                        try:
                            text = raw.decode('utf-8')
                        except UnicodeError:
                            _fail('INVALID_ARTIFACT_ADMIN')
                        prefix = 'gitdir: ' + str(self.repo / '.git' / 'worktrees') + '/'
                        if not text.startswith(prefix) or not text.endswith('\n'):
                            _fail('INVALID_ARTIFACT_ADMIN')
                        admin_name = text[len(prefix):-1]
                        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', admin_name):
                            _fail('INVALID_ARTIFACT_ADMIN')
                        wt = os.open('worktrees', _DIR, dir_fd=common); stack.callback(os.close, wt)
                        admin = os.open(admin_name, _DIR, dir_fd=wt); stack.callback(os.close, admin)
                        commontext, _ = _read_at(admin, 'commondir', 4096)
                        reciprocal, _ = _read_at(admin, 'gitdir', 4096)
                        if commontext != b'../..\n' or reciprocal != (str(path / '.git') + '\n').encode():
                            _fail('INVALID_ARTIFACT_ADMIN')
                        extra = {'admin': _identity(os.fstat(admin)), 'gitdir': text,
                                 'reciprocal': reciprocal.decode(), 'commondir': '../..'}
                    elif not stat.S_ISDIR(metadata.st_mode) or _identity(metadata) != _identity(os.fstat(common)):
                        _fail('INVALID_ARTIFACT_ADMIN')
                    head, _ = _read_at(admin, 'HEAD', 1024)
                    if head != ('ref: ' + slot['branch'] + '\n').encode('ascii'):
                        _fail('ARTIFACT_HEAD_BINDING_CHANGED')
                    oid = self._ref(common, slot['branch'])
                    result = {'room_instance': room_instance, 'project_id': self.room['project']['id'],
                        'repository': self.room['project']['repository'], 'run_id': run_id,
                        'participant_id': participant_id, 'slot_id': key, 'branch': slot['branch'], 'head_sha': oid}
                    result['source_digest'] = hashlib.sha256(canonical({'binding': binding,
                        'slot': slot, 'admin': extra})).hexdigest()
                    validate_source(result)
                    for current_path, held in ((self.repo, repo), (self.root, root),
                            (self.repo / '.git', common), (path, slotfd)):
                        fresh = _open_dir(current_path)
                        try:
                            if _identity(os.fstat(fresh)) != _identity(os.fstat(held)):
                                _fail('ARTIFACT_SOURCE_CHANGED')
                        finally:
                            os.close(fresh)
                    if (_read_at(admin, 'HEAD', 1024)[0] != head
                            or self._ref(common, slot['branch']) != oid):
                        _fail('ARTIFACT_SOURCE_CHANGED')
                    return result
        except ArtifactError:
            raise
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
            raise ArtifactError('ARTIFACT_SOURCE_UNVERIFIABLE') from error

    @staticmethod
    def _ref(common, branch):
        try:
            raw, _ = _read_path(common, branch, 128)
        except FileNotFoundError:
            raw = None
        if raw is not None:
            if not re.fullmatch(b'[0-9a-f]{40}\n', raw):
                _fail('INVALID_ARTIFACT_REF')
            return raw[:-1].decode('ascii')
        packed, _ = _read_at(common, 'packed-refs', MAX_TEXT)
        found, names = None, set()
        for line in packed.splitlines():
            if line.startswith(b'#') or re.fullmatch(rb'\^[0-9a-f]{40}', line):
                continue
            if not re.fullmatch(b'[0-9a-f]{40} refs/[!-~]+', line):
                _fail('INVALID_ARTIFACT_REF')
            oid, name = line.split(b' ', 1)
            if name in names:
                _fail('INVALID_ARTIFACT_REF')
            names.add(name)
            if name == branch.encode('ascii'):
                found = oid.decode()
        if found is None:
            _fail('ARTIFACT_REF_MISSING')
        return found

    def current(self, source):
        validate_source(source)
        result = self.resolve(source['run_id'], source['participant_id'], source['room_instance'])
        if any(result[k] != source[k] for k in source.keys() - {'head_sha'}):
            _fail('ARTIFACT_SOURCE_BINDING_CHANGED')
        return result

    def recheck(self, source):
        if self.current(source) != source:
            _fail('ARTIFACT_SOURCE_CHANGED')
        return dict(source)


def copy_objects(common_path, destination, deadline):
    """Copy ordinary contained compressed objects, never any source Git config."""
    total = files = 0
    common = _open_dir(common_path)
    objects = None
    try:
        objects = os.open('objects', _DIR, dir_fd=common)
        destination.mkdir(mode=0o700)
        (destination / 'pack').mkdir(mode=0o700)
        # Git dependency metadata is never read as instructions, nor copied.
        try:
            info = os.open('info', _DIR, dir_fd=objects)
        except FileNotFoundError:
            info = None
        if info is not None:
            try:
                for name in ('alternates', 'http-alternates'):
                    try:
                        os.stat(name, dir_fd=info, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    _fail('ARTIFACT_ALTERNATE_UNSUPPORTED')
            finally:
                os.close(info)
        names = _names(objects, 258)
        if len(names) > 258:
            _fail('ARTIFACT_OBJECT_LIMIT')
        for prefix in sorted(names):
            if time.monotonic() >= deadline:
                _fail('ARTIFACT_MATERIALIZATION_TIMEOUT')
            if prefix == 'info':
                continue
            if prefix != 'pack' and not re.fullmatch(r'[0-9a-f]{2}', prefix):
                _fail('UNSUPPORTED_ARTIFACT_OBJECT_LAYOUT')
            directory = os.open(prefix, _DIR, dir_fd=objects)
            try:
                entries = _names(directory, MAX_OBJECT_FILES)
                if len(entries) + files > MAX_OBJECT_FILES:
                    _fail('ARTIFACT_OBJECT_LIMIT')
                if prefix == 'pack':
                    if any(n.endswith('.promisor') for n in entries):
                        _fail('ARTIFACT_PROMISOR_UNSUPPORTED')
                    # Auxiliary accelerators are intentionally unsupported rather
                    # than importing additional parser/config surfaces.
                    if any(not re.fullmatch(r'pack-[0-9a-f]{40}\.(pack|idx)', n) for n in entries):
                        _fail('UNSUPPORTED_ARTIFACT_PACK_LAYOUT')
                    packs = {n[:-5] for n in entries if n.endswith('.pack')}
                    indexes = {n[:-4] for n in entries if n.endswith('.idx')}
                    if packs != indexes:
                        _fail('INCOMPLETE_ARTIFACT_PACK')
                elif any(not re.fullmatch(r'[0-9a-f]{38}', n) for n in entries):
                    _fail('UNSUPPORTED_ARTIFACT_OBJECT_LAYOUT')
                output = destination / prefix
                if prefix != 'pack':
                    output.mkdir(mode=0o700)
                for name in sorted(entries):
                    if time.monotonic() >= deadline:
                        _fail('ARTIFACT_MATERIALIZATION_TIMEOUT')
                    source = os.open(name, _FILE, dir_fd=directory)
                    try:
                        before = os.fstat(source)
                        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                                or before.st_size < 1 or total + before.st_size > MAX_OBJECT_BYTES):
                            _fail('ARTIFACT_OBJECT_LIMIT_OR_TYPE')
                        target = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        copied = 0
                        try:
                            while True:
                                if time.monotonic() >= deadline:
                                    _fail('ARTIFACT_MATERIALIZATION_TIMEOUT')
                                part = os.read(source, min(65536, before.st_size + 1 - copied))
                                if not part:
                                    break
                                copied += len(part)
                                if copied > before.st_size:
                                    _fail('ARTIFACT_SOURCE_CHANGED')
                                view = memoryview(part)
                                while view:
                                    amount = os.write(target, view)
                                    if amount <= 0:
                                        _fail('ARTIFACT_COPY_FAILED')
                                    view = view[amount:]
                            os.fsync(target)
                        finally:
                            os.close(target)
                        if (copied != before.st_size or _stamp(before) != _stamp(os.fstat(source))
                                or _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != _identity(before)):
                            _fail('ARTIFACT_SOURCE_CHANGED')
                        total += copied; files += 1
                    finally:
                        os.close(source)
                if sorted(_names(directory, MAX_OBJECT_FILES)) != sorted(entries):
                    _fail('ARTIFACT_SOURCE_CHANGED')
            finally:
                os.close(directory)
        if sorted(_names(objects, 258)) != sorted(names):
            _fail('ARTIFACT_SOURCE_CHANGED')
        return {'bytes': total, 'files': files}
    finally:
        try:
            if objects is not None:
                os.close(objects)
        finally:
            os.close(common)


def _trusted_executable(path):
    # Fixed binaries and all ancestors must be ordinary immutable-by-ownership
    # installation nodes. The admitted image additionally pins their digests.
    descriptor = os.open('/', _DIR)
    try:
        for component in _parts(path)[:-1]:
            parent = os.fstat(descriptor)
            if parent.st_uid != 0 or parent.st_mode & 0o022:
                _fail('ARTIFACT_GIT_UNTRUSTED')
            child = os.open(component, _DIR, dir_fd=descriptor)
            previous, descriptor = descriptor, child
            os.close(previous)
        parent = os.fstat(descriptor)
        if parent.st_uid != 0 or parent.st_mode & 0o022:
            _fail('ARTIFACT_GIT_UNTRUSTED')
        fd = os.open(Path(path).name, _FILE, dir_fd=descriptor)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022 or not info.st_mode & 0o111):
                _fail('ARTIFACT_GIT_UNTRUSTED')
        finally:
            os.close(fd)
    finally:
        os.close(descriptor)


class CopiedObjectReader:
    """One bounded trusted Git process reads only a fresh generated bare store.

    Git parses pack compression/deltas; we verify every consumed raw object hash
    and type. No revision expressions, archive, checkout, pretty output or fetch.
    """
    def __init__(self, store, deadline):
        self.store, self.deadline = Path(store), deadline
        self.process = None
        self.buffer = bytearray()
        self.total = 0
        # Never use Python preexec_fn: it can deadlock before exec in a threaded
        # Supervisor and evade the parent deadline. The fixed trusted prlimit
        # binary lowers only its own limits then execs this fixed Git command.
        _trusted_executable(LIMIT_BINARY); _trusted_executable(GIT_BINARY)
        self.process = subprocess.Popen([LIMIT_BINARY, *GIT_LIMITS, '--', GIT_BINARY, '--no-replace-objects',
            '--git-dir=' + str(self.store), '-c', 'core.hooksPath=/dev/null',
            '-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never',
            '-c', 'submodule.recurse=false', '-c', 'core.attributesFile=/dev/null',
            'cat-file', '--batch'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=self.store, env=dict(GIT_ENV),
            close_fds=True)
        self.selector = None
        try:
            os.set_blocking(self.process.stdout.fileno(), False)
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
        except BaseException:
            # The caller cannot close an object whose constructor never returned.
            # Reap only this directly spawned child, including partial setup.
            self.close(force=True)
            raise

    def _more(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or not self.selector.select(remaining):
            _fail('ARTIFACT_MATERIALIZATION_TIMEOUT')
        part = os.read(self.process.stdout.fileno(), 65536)
        if not part:
            _fail('ARTIFACT_OBJECT_UNAVAILABLE')
        self.total += len(part)
        # Raw used tree/commit/blob data stays bounded even when the source pack
        # is a small compression bomb; unused objects are never expanded.
        if self.total > MAX_TARGET_BYTES + MAX_METADATA_BYTES:
            _fail('ARTIFACT_OBJECT_OUTPUT_LIMIT')
        self.buffer.extend(part)
        if len(self.buffer) > MAX_BLOB_BYTES + 1024:
            _fail('ARTIFACT_OBJECT_OUTPUT_LIMIT')

    def read(self, oid, expected):
        if not isinstance(oid, str) or not _OID.fullmatch(oid) or expected not in ('commit', 'tree', 'blob'):
            _fail('INVALID_ARTIFACT_OBJECT_REQUEST')
        if time.monotonic() >= self.deadline:
            _fail('ARTIFACT_MATERIALIZATION_TIMEOUT')
        self.process.stdin.write(oid.encode() + b'\n'); self.process.stdin.flush()
        while b'\n' not in self.buffer:
            if len(self.buffer) > 128:
                _fail('INVALID_ARTIFACT_OBJECT_HEADER')
            self._more()
        line, _, rest = self.buffer.partition(b'\n'); self.buffer = bytearray(rest)
        fields = line.split(b' ')
        if (len(fields) != 3 or fields[0] != oid.encode() or fields[1] != expected.encode()
                or not re.fullmatch(b'0|[1-9][0-9]{0,9}', fields[2])):
            _fail('INVALID_ARTIFACT_OBJECT_HEADER')
        length = int(fields[2])
        limit = MAX_BLOB_BYTES if expected == 'blob' else MAX_TEXT
        if length > limit:
            _fail('ARTIFACT_OBJECT_SIZE_LIMIT')
        while len(self.buffer) < length + 1:
            self._more()
        raw = bytes(self.buffer[:length])
        if self.buffer[length:] != b'\n':
            _fail('INVALID_ARTIFACT_OBJECT_FRAMING')
        self.buffer.clear()
        if hashlib.sha1(expected.encode() + b' ' + str(length).encode() + b'\0' + raw).hexdigest() != oid:
            _fail('ARTIFACT_OBJECT_HASH_MISMATCH')
        return raw

    def close(self, *, force=False):
        if self.process is None:
            return
        process, self.process = self.process, None
        failures = []
        if self.selector is not None:
            try:
                self.selector.close()
            except BaseException as error:
                failures.append(error)
        try:
            process.stdin.close()
        except BaseException as error:
            failures.append(error)
        # This is our direct child, not a helper/PID adoption or container kill.
        try:
            if force:
                process.kill()
            process.wait(timeout=max(0.001, min(1, self.deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            try:
                process.kill(); process.wait(timeout=1)
            except BaseException as error:
                failures.append(error)
        except BaseException as error:
            failures.append(error)
            try:
                process.kill(); process.wait(timeout=1)
            except BaseException as cleanup_error:
                failures.append(cleanup_error)
        finally:
            try:
                process.stdout.close()
            except BaseException as error:
                failures.append(error)
        if failures:
            raise ArtifactError('ARTIFACT_GIT_CLEANUP_UNCONFIRMED') from failures[0]
        if not force and process.returncode != 0:
            _fail('ARTIFACT_GIT_EXIT_ERROR')


def _tree_entries(raw):
    entries, seen, previous = [], set(), None
    while raw:
        try:
            mode, _, tail = raw.partition(b' ')
            name, separator, tail = tail.partition(b'\0')
            if not separator or len(tail) < 20 or mode not in (b'40000', b'100644', b'100755'):
                _fail('UNSUPPORTED_ARTIFACT_TREE_ENTRY')
            text = name.decode('utf-8', errors='strict')
            validate_path(text)
            if '/' in text or name in seen:
                _fail('UNSAFE_ARTIFACT_TREE_ENTRY')
            sortkey = name + (b'/' if mode == b'40000' else b'\0')
            if previous is not None and sortkey <= previous:
                _fail('NONCANONICAL_ARTIFACT_TREE')
            seen.add(name); previous = sortkey
            entries.append((mode, text, tail[:20].hex()))
            raw = tail[20:]
            if len(entries) > MAX_ENTRIES:
                _fail('ARTIFACT_TREE_LIMIT')
        except UnicodeError as error:
            raise ArtifactError('UNSAFE_ARTIFACT_TREE_ENTRY') from error
    return entries


def materialize(reader, head, root, deadline):
    commit = reader.read(head, 'commit')
    first, _, _ = commit.partition(b'\n')
    if not re.fullmatch(b'tree [0-9a-f]{40}', first):
        _fail('INVALID_ARTIFACT_COMMIT')
    tree = first[5:].decode()
    root.mkdir(mode=0o700)
    count = expanded = 0
    def walk(oid, path, depth):
        nonlocal count, expanded
        if depth > MAX_DEPTH or time.monotonic() >= deadline:
            _fail('ARTIFACT_TREE_LIMIT')
        for mode, name, child in _tree_entries(reader.read(oid, 'tree')):
            relative = (path / name).relative_to(root).as_posix()
            validate_path(relative)
            count += 1
            if count > MAX_ENTRIES:
                _fail('ARTIFACT_TREE_LIMIT')
            destination = path / name
            if mode == b'40000':
                destination.mkdir(mode=0o700)
                walk(child, destination, depth + 1)
                destination.chmod(0o555)
            else:
                data = reader.read(child, 'blob')
                expanded += len(data)
                if len(data) > MAX_BLOB_BYTES or expanded > MAX_TARGET_BYTES:
                    _fail('ARTIFACT_EXPANSION_LIMIT')
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
                destination.chmod(0o555 if mode == b'100755' else 0o444)
    walk(tree, root, 0)
    root.chmod(0o555)
    observed = observe_target(root, deadline)
    if observed['tree_sha'] != tree or observed['entries'] != count or observed['expanded_bytes'] != expanded:
        _fail('ARTIFACT_MATERIALIZATION_MISMATCH')
    return observed


def observe_target(path, deadline):
    """Independent descriptor-relative complete tree and manifest reconstruction."""
    count = expanded = 0
    manifest = hashlib.sha256()
    root = _open_dir(path)
    def walk(directory, relative, depth):
        nonlocal count, expanded
        before = os.fstat(directory)
        if (depth > MAX_DEPTH or time.monotonic() >= deadline or
                stat.S_IMODE(before.st_mode) != 0o555 or before.st_dev != root_info.st_dev):
            _fail('ARTIFACT_TARGET_CHANGED')
        names = _names(directory, MAX_OBJECT_FILES + MAX_ENTRIES + 10)
        if len(names) > MAX_ENTRIES:
            _fail('ARTIFACT_TREE_LIMIT')
        entries = []
        for name in sorted(names, key=lambda value: value.encode('utf-8')):
            part = relative + '/' + name if relative else name
            validate_path(part)
            node = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if node.st_dev != root_info.st_dev:
                _fail('ARTIFACT_TARGET_CHANGED')
            count += 1
            if count > MAX_ENTRIES:
                _fail('ARTIFACT_TREE_LIMIT')
            if stat.S_ISDIR(node.st_mode):
                fd = os.open(name, _DIR, dir_fd=directory)
                try:
                    if _identity(node) != _identity(os.fstat(fd)):
                        _fail('ARTIFACT_TARGET_CHANGED')
                    oid = walk(fd, part, depth + 1)
                finally:
                    os.close(fd)
                mode, size, digest = b'40000', 0, None
            elif stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) in (0o444, 0o555):
                data, opened = _read_at(directory, name, MAX_BLOB_BYTES)
                if _stamp(node) != _stamp(opened):
                    _fail('ARTIFACT_TARGET_CHANGED')
                expanded += len(data)
                if expanded > MAX_TARGET_BYTES:
                    _fail('ARTIFACT_EXPANSION_LIMIT')
                mode = b'100755' if node.st_mode & 0o111 else b'100644'
                oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                size, digest = len(data), hashlib.sha256(data).hexdigest()
            else:
                _fail('ARTIFACT_TARGET_CHANGED')
            entries.append((name.encode(), mode, oid, part, size, digest))
        entries.sort(key=lambda entry: entry[0] + (b'/' if entry[1] == b'40000' else b'\0'))
        raw = b''
        for name, mode, oid, part, size, digest in entries:
            raw += mode + b' ' + name + b'\0' + bytes.fromhex(oid)
            manifest.update(canonical([part, mode.decode(), size, digest]) + b'\n')
        if _stamp(before) != _stamp(os.fstat(directory)) or set(_names(directory, MAX_ENTRIES)) != set(names):
            _fail('ARTIFACT_TARGET_CHANGED')
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    try:
        root_info = os.fstat(root)
        tree = walk(root, '', 0)
        again = _open_dir(path)
        try:
            if _identity(os.fstat(again)) != _identity(root_info):
                _fail('ARTIFACT_TARGET_CHANGED')
        finally:
            os.close(again)
        return {'tree_sha': tree, 'manifest_sha256': manifest.hexdigest(),
                'device': root_info.st_dev, 'inode': root_info.st_ino,
                'entries': count, 'expanded_bytes': expanded}
    finally:
        os.close(root)

HELPER_HOST_GID = 165530


class ArtifactTargetLease:
    """Operational owned resource, never Hub workflow truth or restored authority."""
    def __init__(self, owner, evaluation_id, source, target_id, parent_identity):
        self.owner, self.evaluation_id = owner, evaluation_id
        self.source, self.target_id = dict(source), target_id
        self.parent_identity = parent_identity
        self.path = owner.root / target_id
        self.target = None
        self.phase = 'preparing'
        self.launch_possible = False
        self.exit_confirmed = False
        self.materializer_exit_unconfirmed = False

    def document(self):
        if self.target is None:
            _fail('ARTIFACT_TARGET_NOT_PREPARED')
        return dict(self.target)

    def _parent(self):
        root = _open_dir(self.owner.root)
        fd = None
        try:
            try:
                if _identity(os.fstat(root)) != self.owner.root_identity:
                    _fail('ARTIFACT_SCRATCH_REPLACED')
                fd = os.open(self.target_id, _DIR, dir_fd=root)
            finally:
                os.close(root)
            info = os.fstat(fd)
            if (_identity(info) != self.parent_identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) not in (0o700, 0o710)):
                _fail('ARTIFACT_TARGET_OWNERSHIP_LOST')
            result, fd = fd, None
            return result
        finally:
            if fd is not None:
                os.close(fd)

    def recheck(self):
        self.owner.resolver.recheck(self.source)
        self.postverify()
        return True

    def recheck_binding(self):
        # A later committed head leaves credible historical evidence stale, not
        # corrupted. current() still compares every owned binding/token field.
        self.owner.resolver.current(self.source)
        return True

    def postverify(self):
        if self.target is None:
            _fail('ARTIFACT_TARGET_NOT_PREPARED')
        fd = self._parent()
        try:
            actual = observe_target(self.path / 'tree', time.monotonic() + 15)
            expected = {k: v for k, v in self.target.items() if k in actual}
            if actual != expected:
                _fail('ARTIFACT_TARGET_CHANGED')
            return self.document()
        finally:
            os.close(fd)

    def mark_launch_possible(self):
        if self.phase != 'prepared' or self.launch_possible:
            _fail('ARTIFACT_LAUNCH_REPLAY')
        self.launch_possible = True
        self.phase = 'launch-possible'
        self.owner._save(self)

    def mark_exit_confirmed(self):
        # Called only by trusted Supervisor after the held process exits; a
        # persisted flag is never enough to reconstruct this live authority.
        if not self.launch_possible:
            _fail('ARTIFACT_NO_LIVE_LAUNCH')
        self.exit_confirmed = True

    def cleanup(self):
        try:
            return self._cleanup()
        except BaseException:
            # Include final rmdir/fsync/journal failure, not only recursion.
            # No failed stage may leave a prepared-looking ownership record.
            self.phase = 'quarantined'
            self.owner._save(self)
            raise

    def _cleanup(self):
        if self.materializer_exit_unconfirmed:
            _fail('ARTIFACT_GIT_CLEANUP_UNCONFIRMED')
        if self.launch_possible and not self.exit_confirmed:
            _fail('ARTIFACT_EXIT_UNCONFIRMED')
        if self.phase == 'removed':
            return True
        if self.parent_identity is None:
            # Durable intent may precede mkdir failure. Prove absence only;
            # never adopt a similarly named inode after an uncertain creation.
            root = _open_dir(self.owner.root)
            try:
                if _identity(os.fstat(root)) != self.owner.root_identity:
                    _fail('ARTIFACT_SCRATCH_REPLACED')
                try:
                    os.stat(self.target_id, dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    self.phase = 'removed'; self.owner._save(self)
                    return True
                _fail('ARTIFACT_TARGET_OWNERSHIP_LOST')
            finally:
                os.close(root)
        fd = self._parent()
        try:
            # This private resource was generated here. Neither Project roots nor
            # source slot paths are traversed or deleted. No symlink following.
            self._remove_contents(fd)
        except BaseException:
            self.phase = 'quarantined'; self.owner._save(self); raise
        finally:
            os.close(fd)
        root = _open_dir(self.owner.root)
        try:
            if _identity(os.stat(self.target_id, dir_fd=root, follow_symlinks=False)) != self.parent_identity:
                _fail('ARTIFACT_TARGET_OWNERSHIP_LOST')
            os.rmdir(self.target_id, dir_fd=root)
            os.fsync(root)
        finally:
            os.close(root)
        self.phase = 'removed'; self.owner._save(self)
        return True

    @classmethod
    def _remove_contents(cls, directory, depth=0):
        if depth > MAX_DEPTH + 4:
            _fail('ARTIFACT_CLEANUP_LIMIT')
        os.fchmod(directory, 0o700)
        names = _names(directory, MAX_OBJECT_FILES + MAX_ENTRIES + 10)
        if len(names) > MAX_OBJECT_FILES + MAX_ENTRIES + 10:
            _fail('ARTIFACT_CLEANUP_LIMIT')
        for name in names:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, _DIR, dir_fd=directory)
                try:
                    if (_identity(os.fstat(child)) != _identity(info)
                            or info.st_dev != os.fstat(directory).st_dev):
                        _fail('ARTIFACT_TARGET_OWNERSHIP_LOST')
                    cls._remove_contents(child, depth + 1)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                os.unlink(name, dir_fd=directory)
            else:
                _fail('ARTIFACT_CLEANUP_UNSAFE_NODE')


class ArtifactTargets:
    """One Supervisor resource owner; restart never adopts an old helper task.

    reserve_capacity is a trusted Room resource admission callback. It must prove
    currently free quota capacity, including existing usage and all reservations,
    not merely compare this profile to the configured disk limit. Absent proof is
    refusal. The ledger independently reserves evaluations before calling here.
    """
    def __init__(self, root, journal_root, resolver, *, reserve_capacity):
        if not callable(reserve_capacity):
            _fail('ARTIFACT_CAPACITY_ADMISSION_REQUIRED')
        self.root, self.journal_root = Path(root), Path(journal_root)
        self.resolver, self.reserve_capacity = resolver, reserve_capacity
        self.owned = {}
        self._lock = threading.RLock()
        fd = _open_dir(self.root)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o711:
                _fail('ARTIFACT_SCRATCH_OWNERSHIP')
            self.root_identity = _identity(info)
        finally:
            os.close(fd)
        fd = _open_dir(self.journal_root)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                _fail('ARTIFACT_JOURNAL_OWNERSHIP')
            self.journal_identity = _identity(info)
        finally:
            os.close(fd)

    def _journal(self, evaluation_id):
        return self.journal_root / (hashlib.sha256(evaluation_id.encode()).hexdigest() + '.json')

    def _save(self, lease, *, first=False):
        data = canonical({'version': 1, 'evaluation_id': lease.evaluation_id,
            'target_id': lease.target_id, 'parent_identity': lease.parent_identity,
            'source': lease.source, 'target': lease.target, 'phase': lease.phase,
            'launch_possible': lease.launch_possible,
            'materializer_exit_unconfirmed': lease.materializer_exit_unconfirmed,
            'reservation_bytes': RESERVATION_BYTES})
        if len(data) > 8192:
            _fail('ARTIFACT_RESOURCE_JOURNAL_LIMIT')
        parent = _open_dir(self.journal_root)
        try:
            if _identity(os.fstat(parent)) != self.journal_identity:
                _fail('ARTIFACT_JOURNAL_OWNERSHIP')
            name = self._journal(lease.evaluation_id).name
            if first:
                temporary = name
            else:
                previous, _ = _read_at(parent, name, 8192)
                if json.loads(previous)['target_id'] != lease.target_id:
                    _fail('ARTIFACT_JOURNAL_OWNERSHIP')
                temporary = name + '.' + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            if not first:
                os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)

    def prepare(self, scope, source):
        with self._lock:
            return self._prepare(scope, source)

    def _prepare(self, scope, source):
        validate_scope(scope); validate_source(source)
        if any(scope[k] != source[k] for k in ('room_instance', 'project_id', 'repository', 'run_id', 'participant_id')):
            _fail('ARTIFACT_SCOPE_SOURCE_MISMATCH')
        evaluation = scope['evaluation_id']
        if evaluation in self.owned or os.path.lexists(self._journal(evaluation)):
            _fail('ARTIFACT_PREPARATION_REPLAY')
        journal = _open_dir(self.journal_root)
        try:
            if _identity(os.fstat(journal)) != self.journal_identity:
                _fail('ARTIFACT_JOURNAL_OWNERSHIP')
            names = _names(journal, MAX_RESOURCE_RECORDS)
            for name in names:
                if not re.fullmatch(r'[0-9a-f]{64}\.json', name):
                    _fail('ARTIFACT_JOURNAL_RECONCILIATION_REQUIRED')
                _read_at(journal, name, 8192)
            if len(names) >= MAX_RESOURCE_RECORDS:
                _fail('ARTIFACT_RESOURCE_RECORD_LIMIT')
        finally:
            os.close(journal)
        self.resolver.recheck(source)
        if self.reserve_capacity(scope, RESERVATION_BYTES) is not True:
            _fail('ARTIFACT_ROOM_CAPACITY_UNAVAILABLE')
        root = _open_dir(self.root)
        lease = None
        try:
            fs = os.fstatvfs(root)
            if (fs.f_frsize > 4096 or fs.f_bsize > 4096
                    or fs.f_bavail * fs.f_frsize < RESERVATION_BYTES
                    or _identity(os.fstat(root)) != self.root_identity):
                _fail('ARTIFACT_SCRATCH_CAPACITY_UNAVAILABLE')
            target_id = uuid.uuid4().hex
            # Intent is exclusive and precedes any target/cache effects. A lost
            # process can leave this intent, but cannot resume or relaunch it.
            lease = ArtifactTargetLease(self, evaluation, source, target_id, None)
            self._save(lease, first=True)
            self.owned[evaluation] = lease
            os.mkdir(target_id, 0o700, dir_fd=root)
            parent = os.open(target_id, _DIR, dir_fd=root)
            try:
                lease.parent_identity = _identity(os.fstat(parent))
                self._save(lease)
                # No account/group setup or privilege escalation. The admitted
                # Supervisor must already have this fixed mapped group grant.
                os.fchown(parent, -1, HELPER_HOST_GID)
                info = os.fstat(parent)
                if info.st_uid != os.getuid() or info.st_gid != HELPER_HOST_GID:
                    _fail('ARTIFACT_HELPER_GROUP_UNAVAILABLE')
                os.fchmod(parent, 0o710)
            finally:
                os.close(parent)
            deadline = time.monotonic() + 30
            store = lease.path / 'store'; store.mkdir(mode=0o700)
            copy_objects(self.resolver.repo / '.git', store / 'objects', deadline)
            (store / 'refs').mkdir(mode=0o700)
            (store / 'HEAD').write_bytes(b'ref: refs/heads/unused\n')
            (store / 'config').write_bytes(b'[core]\n\trepositoryformatversion = 0\n\tbare = true\n')
            try:
                reader = CopiedObjectReader(store, deadline)
                try:
                    observed = materialize(reader, source['head_sha'], lease.path / 'tree', deadline)
                finally:
                    reader.close()
            except ArtifactError as error:
                if error.code == 'ARTIFACT_GIT_CLEANUP_UNCONFIRMED':
                    lease.materializer_exit_unconfirmed = True
                raise
            self.resolver.recheck(source)
            # Include actual allocated blocks, directory and copied metadata
            # blocks, not only logical object/blob bytes. Fixed entry/file bounds
            # reserve the remaining inode/rounding metadata margin as well.
            allocated = 0
            for directory, dirs, files in os.walk(lease.path, followlinks=False,
                    onerror=lambda error: (_ for _ in ()).throw(error)):
                allocated += os.lstat(directory).st_blocks * 512
                for name in files:
                    allocated += os.lstat(Path(directory) / name).st_blocks * 512
            if allocated > RESERVATION_BYTES - (1 << 20):
                _fail('ARTIFACT_ALLOCATION_LIMIT')
            lease.target = {'target_id': target_id, 'head_sha': source['head_sha'],
                'source_digest': source['source_digest'], **observed}
            validate_target(lease.target)
            lease.phase = 'prepared'; self._save(lease)
            return lease.document()
        except BaseException:
            if lease is not None:
                lease.phase = 'quarantined'
                self._save(lease)
            raise
        finally:
            os.close(root)

    def lease(self, target):
        validate_target(target)
        matches = [lease for lease in self.owned.values() if lease.target == target]
        if len(matches) != 1:
            _fail('ARTIFACT_TARGET_NOT_OWNED')
        return matches[0]

    def verify(self, target):
        return self.lease(target).postverify()

    def cleanup(self, target):
        return self.lease(target).cleanup()

    def reconcile(self, evaluation_id):
        with self._lock:
            return self._reconcile(evaluation_id)

    def _reconcile(self, evaluation_id):
        lease = self.owned.get(evaluation_id)
        reference = 'artifact-quarantine:' + hashlib.sha256(evaluation_id.encode()).hexdigest()
        if lease is None or lease.launch_possible:
            return {'cleanup': False, 'quarantine_ref': reference}
        try:
            removed = lease.cleanup()
        except (ArtifactError, OSError):
            return {'cleanup': False, 'quarantine_ref': reference}
        return {'cleanup': removed is True, 'quarantine_ref': None if removed is True else reference}
