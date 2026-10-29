"""Explicit root-owned preparation of new trees on a compatible existing host.

No daemon, network, account, mount, quota or credential changes are performed by
this increment. Unsupported operations are refused before creating receipts.
The entrypoint is deliberately not called by import or by normal local startup.
"""
import fcntl
import json
import os
from pathlib import Path
import stat

from .local_host_profile import LocalHostProfile, canonical, digest, require
from .local_host_plan import verify_plan
from .local_host_observe import canonical_node, inspect
from .local_host_receipt import PreparationReceipt


MARKER = '.uas-preparation.json'
SUPPORTED = {'prepare-owned-xfs-tree': 0o711, 'prepare-owned-endpoints': 0o711}


def owned_directory(path, *, plan_id, operation, owner_uid, mode, create, repair_partial=False,
                    expected_parent_identity=None):
    """Create exclusively or reconcile an exact marker; never adopt a tree."""
    path = Path(path)
    parent = canonical_node(path.parent)
    require(parent.st_uid == owner_uid and not parent.st_mode & 0o022, 'HOST_APPLY_PARENT')
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(parent_fd)
        require((opened.st_dev, opened.st_ino) == (parent.st_dev, parent.st_ino), 'HOST_APPLY_PARENT_CHANGED')
        if expected_parent_identity is not None:
            require([opened.st_dev, opened.st_ino] == expected_parent_identity,
                    'HOST_APPLY_STORAGE_PARENT_CHANGED')
        if create:
            # No exist_ok: a preexisting unmarked/foreign tree is never ours.
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if expected_parent_identity is not None:
                require(info.st_dev == expected_parent_identity[0], 'HOST_APPLY_STORAGE_DEVICE_CHANGED')
            require(info.st_uid == owner_uid and not info.st_mode & 0o077 if create
                    else info.st_uid == owner_uid and (stat.S_IMODE(info.st_mode) == mode or
                         (repair_partial and stat.S_IMODE(info.st_mode) == 0o700)),
                    'HOST_APPLY_DIRECTORY_OWNER')
            marker = {'version': 1, 'plan_id': plan_id, 'operation': operation,
                      'identity': [info.st_dev, info.st_ino], 'owner_uid': owner_uid, 'mode': mode}
            raw = canonical(marker)
            if create:
                marker_fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    0o600, dir_fd=fd)
                with os.fdopen(marker_fd, 'wb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                os.fchmod(fd, mode)
                os.fsync(fd)
            marker_fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            try:
                metadata = os.fstat(marker_fd)
                require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == owner_uid
                        and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o600
                        and metadata.st_size == len(raw), 'HOST_APPLY_MARKER')
                require(os.read(marker_fd, len(raw)+1) == raw, 'HOST_APPLY_MARKER_CHANGED')
                if repair_partial:
                    os.fsync(marker_fd)
            finally:
                os.close(marker_fd)
            if not create and stat.S_IMODE(info.st_mode) != mode:
                # Only a matching durable marker authorizes completion of the
                # interrupted mode change; confirmed resources never get repaired.
                require(repair_partial, 'HOST_APPLY_DIRECTORY_MODE')
                os.fchmod(fd, mode)
            if repair_partial:
                os.fsync(fd)
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            require(stat.S_ISDIR(current.st_mode) and current.st_uid == owner_uid
                    and stat.S_IMODE(current.st_mode) == mode and (current.st_dev, current.st_ino) ==
                    (info.st_dev, info.st_ino), 'HOST_APPLY_DIRECTORY_CHANGED')
            selected_parent = canonical_node(path.parent)
            require((selected_parent.st_dev, selected_parent.st_ino) == (opened.st_dev, opened.st_ino),
                    'HOST_APPLY_PARENT_CHANGED')
            return {'identity': marker['identity'], 'observed_sha256': digest(marker)}
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _stable_observation(value):
    value = json.loads(canonical(value))
    # Owned directories and receipt writes change allocation/free space; these
    # are reobserved by ownership below, never accepted as arbitrary foreign data.
    value['storage'].pop('free_bytes')
    value.pop('occupied_paths')
    return value


def apply(plan):
    """Apply supported operations only after an explicit privileged invocation.

    No privilege escalation is attempted. Source tests must mock this complete
    boundary; running it on a real host requires separate user authorization.
    """
    require(os.geteuid() == 0, 'HOST_APPLY_ROOT_REQUIRED')
    profile = LocalHostProfile.parse(plan['profile'])
    require(profile.mode == 'reuse',
            'HOST_APPLY_PROFILE_INTEGRATION_REQUIRED')
    require(type(plan.get('operations')) is list and len(plan['operations']) == 2
            and [op.get('kind') for op in plan['operations']] ==
            ['prepare-owned-xfs-tree', 'prepare-owned-endpoints'], 'HOST_APPLY_UNSUPPORTED_OPERATION')
    receipt_root = Path(plan['receipt_root'])
    paths = [plan['storage_root'], plan['endpoints_root'], str(receipt_root)]
    # For a new application the source observation is captured before any write.
    # For resume it is read from the exact existing receipt after ownership proof.
    resume = os.path.lexists(receipt_root)
    original = None
    if resume:
        owned_directory(receipt_root, plan_id=plan['plan_id'], operation='receipt-root',
                        owner_uid=0, mode=0o700, create=False)
        with PreparationReceipt(receipt_root, plan, owner_uid=0) as receipt:
            original = receipt._read('observations.json')
        require(original is not None, 'HOST_APPLY_ORIGINAL_OBSERVATION_REQUIRED')
        # A modified/rehashed operation plan cannot enter the apply owner.
        verify_plan(plan, original)
    else:
        # The selected storage parent is the existing root named by the plan's
        # immutable initial observation, supplied through the approved envelope.
        require(type(plan.get('storage_parent')) is str, 'HOST_APPLY_STORAGE_PARENT_REQUIRED')
    parent = plan.get('storage_parent') if original is None else original['storage']['path']
    current = inspect(profile.document(), storage_parent=parent, proposed_paths=paths)
    if original is None:
        verify_plan(plan, current)
        original = current
        owned_directory(receipt_root, plan_id=plan['plan_id'], operation='receipt-root',
                        owner_uid=0, mode=0o700, create=True)
    else:
        require(_stable_observation(original) == _stable_observation(current), 'HOST_APPLY_HOST_DRIFT')
    with PreparationReceipt(receipt_root, plan, owner_uid=0) as receipt:
        # Serialize all applies of this exact installation. Locking the held
        # directory descriptor does not create an extra untracked lock path.
        fcntl.flock(receipt.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt._append('observations.json', original)
        for index, operation in enumerate(plan['operations']):
            mode = SUPPORTED[operation['kind']]
            state = receipt.state(index)
            create = receipt.intent(index) if state['state'] == 'not-started' else False
            observed = owned_directory(operation['path'], plan_id=plan['plan_id'],
                                       operation=operation['kind'], owner_uid=0, mode=mode, create=create,
                                       repair_partial=state['state'] == 'unknown',
                                       expected_parent_identity=plan['storage_identity']
                                       if operation['kind'] == 'prepare-owned-xfs-tree' else None)
            if state['state'] == 'confirmed':
                require(observed == state['evidence'], 'HOST_APPLY_CONFIRMED_DRIFT')
            else:
                receipt.confirm(index, observed)
        return {'version': 1, 'plan_id': plan['plan_id'], 'status': 'owned-directories-prepared',
                'native_ready': False, 'remaining': ['room-quota-label-preparation', 'native-handoff']}
