"""Persistent local installation references, not a credential/configuration store.

Setup is explicit and non-destructive. All selected bytes are digest-pinned;
opening an existing installation never silently adopts changed input files.
"""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import stat
import sys
import uuid

from .config import load

MAX_BYTES = 1024 * 1024


class LocalInstallationError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise LocalInstallationError(code)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_FIELD')
        result[key] = value
    return result


def document(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'DOCUMENT_SIZE')
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError) as error:
        raise LocalInstallationError('INVALID_DOCUMENT') from error
    require(type(value) is dict, 'INVALID_DOCUMENT')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def path(value):
    require(type(value) is str, 'ABSOLUTE_PATH_REQUIRED')
    p = Path(value)
    require(p.is_absolute() and p != Path('/') and '..' not in p.parts
            and p.resolve() == p, 'CANONICAL_PATH_REQUIRED')
    return p


def reference(value):
    require(type(value) is dict and set(value) == {'path', 'sha256'}, 'INVALID_REFERENCE')
    path(value['path'])
    digest = value['sha256']
    require(type(digest) is str and len(digest) == 64
            and all(c in '0123456789abcdef' for c in digest), 'INVALID_DIGEST')
    return dict(value)


def read_reference(value):
    ref = reference(value)
    fd = os.open(ref['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022
                and 0 < info.st_size <= MAX_BYTES, 'UNSAFE_REFERENCE')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            raw = source.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'REFERENCE_CHANGED')
        require(hashlib.sha256(raw).hexdigest() == ref['sha256'], 'REFERENCE_DIGEST_MISMATCH')
        return raw
    finally:
        os.close(fd)


def selection(raw):
    value = document(raw)
    require(set(value) in ({'version', 'project', 'native', 'manager'}, {'version', 'project', 'native', 'manager','runtime'})
            and type(value['version']) is int and value['version'] == 1, 'INSTALLATION_SCHEMA')
    result = {'version': 1, 'project': reference(value['project'])}
    for name in ('native', 'manager'):
        result[name] = None if value[name] is None else reference(value[name])
    if 'runtime' in value:
        require(type(value['runtime']) is dict and len(value['runtime'])<=64,'LOCAL_RUNTIME_SELECTION')
        result['runtime']={room:reference(ref) for room,ref in value['runtime'].items()}
    return result


class Installation:
    def __init__(self, root):
        self.root = path(str(root))

    def _safe_root(self):
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and not info.st_mode & 0o077 and self.root.resolve() == self.root,
                'PRIVATE_INSTALLATION_REQUIRED')

    @contextmanager
    def _locked(self):
        self._safe_root()
        fd = os.open(self.root / 'installation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and not info.st_mode & 0o077, 'UNSAFE_LOCK')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _read(self):
        target = self.root / 'installation.json'
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and not info.st_mode & 0o077, 'UNSAFE_INSTALLATION')
            with os.fdopen(fd, 'rb', closefd=False) as source:
                return selection(source.read(MAX_BYTES + 1))
        finally:
            os.close(fd)

    @staticmethod
    def inspect(value):
        config_text=read_reference(value['project']).decode('utf-8')
        config = load(StringIO(config_text))
        selected = {}
        for name in ('native', 'manager'):
            selected[name] = None if value[name] is None else document(read_reference(value[name]))
        if selected['native'] is not None:
            from .local_native import validate_document, LocalNativeProfile
            from .lifecycle import LifecycleError
            try:
                native = validate_document(selected['native'])
                require(set(native['rooms']) == {room['id'] for room in config['rooms']},
                        'LOCAL_NATIVE_ROOM_SELECTION_MISMATCH')
                for room in config['rooms']:
                    # Constructor is pure: bind exact selected Project roots,
                    # limits and control paths, without observing/mutating host.
                    LocalNativeProfile(config, native, room['id'], config['deployment']['state_root'])
            except LifecycleError as error:
                raise LocalInstallationError(error.code) from error
        if selected['manager'] is not None:
            from .local_manager import ManagerSelection
            manager = selected['manager']
            require(manager.get('room_id') in {room['id'] for room in config['rooms']},
                    'LOCAL_MANAGER_ROOM_SELECTION_MISMATCH')
            # Validate schema/scope against selected config. Instance is a claim
            # until runtime compares it to canonical persisted owner identity.
            from .ledger import LedgerError
            from .native_pi_recipe import NativeRecipeError
            try:
                ManagerSelection.read(value['manager'], deployment_id=config['deployment']['id'],
                    room_id=manager['room_id'], instance_id=manager.get('instance_id'),
                    configuration_sha256=hashlib.sha256(canonical(config)).hexdigest())
            except (LedgerError, NativeRecipeError) as error:
                raise LocalInstallationError('LOCAL_MANAGER_SELECTION_INVALID') from error
        runtime=value.get('runtime',{})
        require(not runtime or selected['native'] is not None,'LOCAL_RUNTIME_NATIVE_REQUIRED')
        require(set(runtime)<={room['id'] for room in config['rooms']},'LOCAL_RUNTIME_ROOM_SELECTION')
        for room_id,ref in runtime.items():
            from .local_runtime_plan import LocalRuntimePlan
            profile=LocalNativeProfile(config,selected['native'],room_id,config['deployment']['state_root'])
            plan=LocalRuntimePlan.read(config_text,ref['path'],ref['sha256'],native_profile=profile)
            require(plan.room['id']==room_id,'LOCAL_RUNTIME_ROOM_SELECTION')
            profile.bind_runtime(plan)
        if 'runtime' in value:selected['runtime']=deepcopy(runtime)
        return config, selected

    def setup(self, raw):
        value = selection(raw)
        self.inspect(value)  # No directories or state written for invalid inputs.
        try:
            self.root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        with self._locked():
            target = self.root / 'installation.json'
            if target.exists() or target.is_symlink():
                require(self._read() == value, 'EXISTING_INSTALLATION_DIFFERS')
                return {'status': 'already-installed', 'installation': str(self.root)}
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            # A write failure leaves explicit incomplete state; no automatic overwrite.
            with os.fdopen(fd, 'wb') as out:
                out.write(canonical(value)); out.flush(); os.fsync(out.fileno())
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return {'status': 'installed', 'installation': str(self.root)}

    def runtime_plan_for(self,profile):
        from .local_native import LocalNativeProfile
        from .local_runtime_plan import LocalRuntimePlan
        require(type(profile) is LocalNativeProfile,'LOCAL_NATIVE_PROFILE_REQUIRED')
        value,config,selected=self.open()
        ref=value.get('runtime',{}).get(profile.room['id'])
        if ref is None:return None
        require(selected['native']==profile.native_document,'LOCAL_RUNTIME_PROFILE_BINDING')
        if profile.runtime_plan is not None:
            plan=profile.runtime_plan;plan.require_unchanged()
            require(plan.installation_digest==ref['sha256'],'LOCAL_RUNTIME_SELECTION_CHANGED')
            return plan
        return LocalRuntimePlan.read(read_reference(value['project']).decode('utf-8'),ref['path'],ref['sha256'],native_profile=profile)

    def select_manager(self, reference_or_none):
        selected=None if reference_or_none is None else reference(reference_or_none)
        return self._select_optional('manager',selected)

    def select_runtime(self,room_id,reference_or_none):
        require(type(room_id) is str,'LOCAL_RUNTIME_ROOM_SELECTION')
        selected=None if reference_or_none is None else reference(reference_or_none)
        return self._select_optional('runtime',selected,room_id=room_id)

    def _select_optional(self,kind,selected,*,room_id=None):
        from .local_host import host_lock
        with host_lock(self), self._locked():
            before = self._read()
            after = {**before, 'manager': selected}
            if kind=='runtime':
                refs=dict(before.get('runtime',{}))
                if selected is None:refs.pop(room_id,None)
                else:refs[room_id]=selected
                after={**before,'runtime':refs}
            if kind=='runtime':
                config,unused=self.inspect(before)
                rooms={room['id']:room for room in config['rooms']}
                require(room_id in rooms,'LOCAL_RUNTIME_ROOM_SELECTION')
                if before.get('runtime',{}).get(room_id)!=selected:
                    require(not os.path.lexists(Path(rooms[room_id]['state_root'])/'lifecycle.json'),
                            'LOCAL_RUNTIME_RECONFIGURATION_REQUIRES_UNCREATED_ROOM')
            self.inspect(after)
            receipt = {'installation': str(self.root), kind: selected,
                       'previous_sha256': hashlib.sha256(canonical(before)).hexdigest(),
                       'selected_sha256': hashlib.sha256(canonical(after)).hexdigest()}
            if before == after:
                return {**receipt, 'status': 'already-selected'}
            pending = self.root / (('.'+kind+'-selection-') + uuid.uuid4().hex + '.json')
            fd = os.open(pending, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            identity = os.fstat(fd)
            try:
                with os.fdopen(fd, 'wb') as out:
                    out.write(canonical(after)); out.flush(); os.fsync(out.fileno())
                # Read under held installation lock immediately before replacing.
                require(self._read() == before, 'INSTALLATION_CHANGED')
                try:
                    os.replace(pending, self.root/'installation.json')
                    directory = os.open(self.root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                    try: os.fsync(directory)
                    finally: os.close(directory)
                except OSError as error:
                    try: observed = self._read()
                    except (OSError, ValueError):
                        raise LocalInstallationError(kind.upper()+'_SELECTION_RESULT_UNKNOWN') from error
                    code = (kind.upper()+'_SELECTION_DURABILITY_UNCONFIRMED' if observed == after else
                            kind.upper()+'_SELECTION_NOT_REPLACED' if observed == before else
                            kind.upper()+'_SELECTION_RESULT_UNKNOWN')
                    raise LocalInstallationError(code) from error
                require(self._read() == after, kind.upper()+'_SELECTION_READBACK_MISMATCH')
                return {**receipt, 'status': 'selected'}
            finally:
                # Only the temporary inode created by this invocation is ours.
                primary = sys.exc_info()[1]
                try:
                    try: current = pending.lstat()
                    except FileNotFoundError: pass
                    else:
                        if (current.st_dev,current.st_ino)==(identity.st_dev,identity.st_ino):
                            pending.unlink()
                except OSError:
                    if primary is None:
                        raise LocalInstallationError(kind.upper()+'_SELECTION_TEMP_CLEANUP_UNCONFIRMED') from None
                    primary.add_note(kind.upper()+'_SELECTION_TEMP_CLEANUP_UNCONFIRMED')

    def open(self):
        with self._locked():
            value = self._read()
            config, selected = self.inspect(value)
            return value, config, selected

    def status(self):
        value, config, selected = self.open()
        return {'installation': str(self.root), 'deployment_id': config['deployment']['id'],
                'rooms': [room['id'] for room in config['rooms']],
                'native': 'not-configured' if selected['native'] is None else 'selected-not-observed',
                'manager': 'not-configured' if selected['manager'] is None else 'selected-not-authenticated',
                'runtime': 'not-observed', 'isolation': 'not-verified'}
