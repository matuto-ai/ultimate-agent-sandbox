"""Explicit root-owned preparation of new trees on a compatible existing host.

Only selected owned directory or bounded XFS-image preparation is supported.
No daemon, account, credential, foreign mount or global configuration changes.
The entrypoint is deliberately not called by import or by normal local startup.
"""
import fcntl
import json
import os
from pathlib import Path
import stat
import uuid

from .local_host_profile import LocalHostProfile, canonical, digest, require
from .local_host_plan import verify_plan
from .local_host_observe import canonical_node, inspect
from .local_host_receipt import PreparationReceipt


MARKER = '.uas-preparation.json'
SUPPORTED = {'prepare-owned-xfs-tree': 0o711, 'prepare-owned-endpoints': 0o711}


def owned_directory(path, *, plan_id, operation, owner_uid, mode, create, repair_partial=False,
                    expected_parent_identity=None, owned_xfs=None, storage_root=None):
    """Create exclusively or reconcile an exact marker; never adopt a tree."""
    path = Path(path)
    selected_mount=None
    if owned_xfs is not None:
        from .local_xfs_storage import verify_owned_mount
        require(Path(storage_root) in path.parents,'XFS_PATH_SCOPE')
        selected_mount=verify_owned_mount(owned_xfs,storage_root)
    parent = canonical_node(path.parent)
    if selected_mount is not None:
        require(parent.st_dev==selected_mount['identity'][0],'XFS_PATH_DEVICE')
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
            if selected_mount is not None:
                require(info.st_dev==selected_mount['identity'][0],'XFS_PATH_DEVICE')
            if expected_parent_identity is not None:
                require(info.st_dev == expected_parent_identity[0], 'HOST_APPLY_STORAGE_DEVICE_CHANGED')
            require(info.st_uid == owner_uid and not info.st_mode & 0o077 if create
                    else info.st_uid == owner_uid and (stat.S_IMODE(info.st_mode) == mode or
                         (repair_partial and stat.S_IMODE(info.st_mode) == 0o700)),
                    'HOST_APPLY_DIRECTORY_OWNER')
            marker = {'version': 1, 'plan_id': plan_id, 'operation': operation,
                      'identity': [0 if selected_mount is not None else info.st_dev, info.st_ino], 'owner_uid': owner_uid, 'mode': mode}
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
            if selected_mount is not None:
                require(verify_owned_mount(owned_xfs,storage_root)==selected_mount,'XFS_MOUNT_CHANGED')
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


def apply(plan, *, readmission=False):
    """Apply supported operations only after an explicit privileged invocation.

    No privilege escalation is attempted. Source tests must mock this complete
    boundary; running it on a real host requires separate user authorization.
    """
    require(os.geteuid() == 0, 'HOST_APPLY_ROOT_REQUIRED')
    profile = LocalHostProfile.parse(plan['profile'])
    require(profile.mode == 'reuse',
            'HOST_APPLY_PROFILE_INTEGRATION_REQUIRED')
    require(type(plan.get('operations')) is list and len(plan['operations']) == 2
            and plan['operations'][0].get('kind') in {'prepare-owned-xfs-tree','prepare-owned-xfs-file'}
            and plan['operations'][1].get('kind')=='prepare-owned-endpoints', 'HOST_APPLY_UNSUPPORTED_OPERATION')
    receipt_root = Path(plan['receipt_root'])
    if plan['operations'][0]['kind']=='prepare-owned-xfs-file':
        require(canonical_node(receipt_root.parent).st_dev==plan['storage_identity'][0],
                'XFS_BACKING_FILESYSTEM')
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
        if readmission:
            with PreparationReceipt(receipt_root,plan,owner_uid=0) as receipt:
                require(receipt._read('xfs-identity-policy.json')=={'version':3,'plan_id':plan['plan_id'],
                    'uuid':str(uuid.UUID(hex=plan['plan_id'][:32]))}
                    and all(receipt.state(i)['state']=='confirmed' for i in range(len(plan['operations']))),
                    'HOST_READMISSION_PREPARED_REQUIRED')
                request=receipt._read('room-request.json')
                require(type(request) is dict and request.get('host_plan')==plan
                        and request.get('request_id')==digest({k:v for k,v in request.items() if k!='request_id'}),
                        'HOST_READMISSION_REQUEST_REQUIRED')
                owned_networks={row['subnet'] for row in request['settings']['rooms'].values()}
        # A modified/rehashed operation plan cannot enter the apply owner.
        verify_plan(plan, original)
    else:
        require(not readmission,'HOST_READMISSION_PREPARED_REQUIRED')
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
        old,new=_stable_observation(original),_stable_observation(current)
        if readmission:
            # Selected root-owned endpoint, Engine version/data-root/confinement
            # and subordinate mappings were freshly verified by inspect. Only
            # the ephemeral socket inode is refreshed, not another endpoint.
            require(old['engine'] is not None and new['engine'] is not None,'HOST_ENGINE_UNAVAILABLE')
            old['engine'].pop('socket_identity');new['engine'].pop('socket_identity')
            # Starting these exact configured Rooms creates their own routes.
            # No other route drift is excused by readmission.
            old['networks']=[n for n in old['networks'] if n not in owned_networks]
            new['networks']=[n for n in new['networks'] if n not in owned_networks]
        require(old == new, 'HOST_APPLY_HOST_DRIFT')
    with PreparationReceipt(receipt_root, plan, owner_uid=0) as receipt:
        # Serialize all applies of this exact installation. Locking the held
        # directory descriptor does not create an extra untracked lock path.
        fcntl.flock(receipt.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt._append('observations.json', original)
        for index, operation in enumerate(plan['operations']):
            if operation['kind']=='prepare-owned-xfs-file':
                from .local_xfs_storage import prepare
                prepare(receipt,index,make_directory=owned_directory,stable=True)
                continue
            if operation['kind']=='prepare-owned-endpoints' and receipt._read('xfs-identity-policy.json') is not None:
                from .local_boot_endpoints import prepare_endpoints
                prepare_endpoints(receipt,index,make_directory=owned_directory)
                continue
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
