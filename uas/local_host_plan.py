"""Bounded, side-effect-free host preparation decision and recovery contract.

These decisions are not native admission evidence. Only a privileged owner may
apply a confirmed plan; unknown effects must be observed, not assumed absent.
"""
from copy import deepcopy
from pathlib import PurePosixPath

from .local_host_profile import LocalHostProfile, absolute_path, canonical, digest, require


OBSERVATION_FIELDS = {'version', 'selinux', 'engine', 'subuid', 'subgid',
                      'allocated_ids', 'storage', 'occupied_paths', 'networks'}
STORAGE_FIELDS = {'path', 'identity', 'filesystem', 'project_accounting',
                  'project_enforcement', 'free_bytes', 'owner_uid', 'mode'}


def interval(row):
    require(type(row) is dict and set(row) == {'user', 'offset', 'size'}
            and type(row['user']) is str and len(row['user']) <= 128
            and type(row['offset']) is int and type(row['size']) is int
            and 0 <= row['offset'] < 2**32 and 0 < row['size']
            and row['offset'] + row['size'] <= 2**32, 'HOST_SUBORDINATE_OBSERVATION')
    return row['offset'], row['offset'] + row['size']


def observe_value(value):
    require(type(value) is dict and set(value) == OBSERVATION_FIELDS
            and type(value['version']) is int and value['version'] == 1, 'HOST_OBSERVATION')
    require(value['selinux'] in ('Enforcing', 'Permissive', 'Disabled', 'unknown'), 'HOST_SELINUX_OBSERVATION')
    for key in ('subuid', 'subgid'):
        require(type(value[key]) is list and len(value[key]) <= 65536, 'HOST_SUBORDINATE_OBSERVATION')
        for row in value[key]:
            interval(row)
    require(type(value['allocated_ids']) is list and len(value['allocated_ids']) <= 65536
            and all(type(x) is int and 0 <= x < 2**32 for x in value['allocated_ids']), 'HOST_ID_OBSERVATION')
    storage = value['storage']
    require(type(storage) is dict and set(storage) == STORAGE_FIELDS, 'HOST_STORAGE_OBSERVATION')
    absolute_path(storage['path'])
    require(type(storage['identity']) is list and len(storage['identity']) == 2
            and all(type(x) is int and x >= 0 for x in storage['identity']), 'HOST_STORAGE_IDENTITY')
    require(type(storage['filesystem']) is str and len(storage['filesystem']) <= 32
            and type(storage['project_accounting']) is bool
            and type(storage['project_enforcement']) is bool
            and type(storage['free_bytes']) is int and storage['free_bytes'] >= 0
            and type(storage['owner_uid']) is int and storage['owner_uid'] >= 0
            and type(storage['mode']) is int and 0 <= storage['mode'] <= 0o7777, 'HOST_STORAGE_OBSERVATION')
    require(type(value['occupied_paths']) is list and len(value['occupied_paths']) <= 1024, 'HOST_PATH_OBSERVATION')
    for item in value['occupied_paths']:
        absolute_path(item)
    import ipaddress
    require(type(value['networks']) is list and len(value['networks']) <= 65536, 'HOST_NETWORK_OBSERVATION')
    for item in value['networks']:
        try:
            network = ipaddress.ip_network(item, strict=True)
            require(type(item) is str and str(network) == item, 'HOST_NETWORK_OBSERVATION')
        except (ValueError, TypeError):
            require(False, 'HOST_NETWORK_OBSERVATION')
    require(len(canonical(value)) <= 4*1024*1024, 'HOST_OBSERVATION_BOUND')
    return deepcopy(value)


def plan(profile_document, observed, *, storage_root, endpoints_root, allocation_bytes=None):
    """Return proposals and blockers, never silently substitute host choices.

    A non-XFS host produces a bounded file-allocation proposal only when the
    operator supplied a size. It never selects or formats a block device.
    """
    profile = LocalHostProfile.parse(profile_document)
    observed = observe_value(observed)
    storage_root, endpoints_root = absolute_path(storage_root), absolute_path(endpoints_root)
    roots = [PurePosixPath(x) for x in (storage_root, endpoints_root)]
    require(roots[0] != roots[1] and roots[0] not in roots[1].parents
            and roots[1] not in roots[0].parents, 'HOST_ROOT_OVERLAP')
    engine_paths = [PurePosixPath(value) for value in
                    (profile.socket, profile.data_root, profile.exec_root)]
    require(all(root != engine and root not in engine.parents and engine not in root.parents
                for root in roots for engine in engine_paths), 'HOST_ENGINE_ROOT_OVERLAP')
    require(len(endpoints_root.encode()) + len('/'+'0'*32+'/control/hub.sock') < 108, 'HOST_SOCKET_PATH')
    parent = PurePosixPath(observed['storage']['path'])
    require(parent in roots[0].parents, 'HOST_STORAGE_PARENT')
    if allocation_bytes is not None:
        require(type(allocation_bytes) is int and 512*1024**2 <= allocation_bytes <= 1024**4
                and allocation_bytes % (1024**2) == 0, 'HOST_ALLOCATION_BOUND')
    blockers, operations = [], []
    if observed['selinux'] != 'Enforcing':
        blockers.append('SELINUX_ENFORCING_REQUIRED')
    if any(root == occupied or PurePosixPath(occupied) in PurePosixPath(root).parents
           for root in (storage_root, endpoints_root) for occupied in observed['occupied_paths']):
        blockers.append('OWNERSHIP_RECONCILIATION_REQUIRED')
    for key in ('subuid', 'subgid'):
        rows = observed[key]
        selected = [r for r in rows if r['user'] == profile.remap_user]
        desired = {'user': profile.remap_user, 'offset': profile.offset, 'size': profile.size}
        collision = any(max(interval(r)[0], profile.offset) < min(interval(r)[1], profile.offset+profile.size)
                        and r != desired for r in rows)
        if collision or (selected and selected != [desired]):
            blockers.append(key.upper() + '_COLLISION')
        elif not selected:
            operations.append({'kind': 'reserve-' + key, 'selection': desired})
    if any(profile.offset <= uid < profile.offset+profile.size for uid in observed['allocated_ids']):
        blockers.append('HOST_ID_COLLISION')
    if profile.mode == 'reuse':
        if observed['engine'] is None:
            blockers.append('SELECTED_ENGINE_UNAVAILABLE')
        else:
            profile.verify_engine(observed['engine'])
        if operations:
            blockers.append('REUSE_REQUIRES_EXISTING_MAPPING')
    else:
        # Exact containerd/bridge/firewall coexistence proof is a source gate,
        # not a human permission that can waive an incomplete implementation.
        blockers.append('OWNED_ENGINE_COEXISTENCE_IMPLEMENTATION_REQUIRED')
        operations.append({'kind': 'prepare-owned-engine', 'profile_digest': digest(profile.document())})
    storage = observed['storage']
    if storage['owner_uid'] != 0 or storage['mode'] & 0o022:
        blockers.append('STORAGE_PARENT_NOT_ROOT_MANAGED')
    if storage['filesystem'] == 'xfs' and storage['project_accounting'] and storage['project_enforcement']:
        require(allocation_bytes is None, 'HOST_ALLOCATION_NOT_NEEDED')
        operations.append({'kind': 'prepare-owned-xfs-tree', 'path': storage_root})
    elif allocation_bytes is None:
        blockers.append('OWNED_XFS_ALLOCATION_SELECTION_REQUIRED')
    elif allocation_bytes > storage['free_bytes']:
        blockers.append('OWNED_XFS_ALLOCATION_SPACE')
    else:
        operations.append({'kind': 'prepare-owned-xfs-file', 'path': storage_root,
                           'bytes': allocation_bytes, 'format_existing_device': False})
    operations.append({'kind': 'prepare-owned-endpoints', 'path': endpoints_root})
    body = {'version': 1, 'profile': profile.document(), 'observations': digest(observed),
            'storage_identity': storage['identity'], 'storage_root': storage_root,
            'endpoints_root': endpoints_root, 'operations': operations,
            'blockers': sorted(set(blockers)), 'status': 'blocked' if blockers else 'planned'}
    return dict(body, plan_id=digest(body))


def verify_plan(value, observed):
    """Require fresh observation and unchanged plan before privileged effects."""
    require(type(value) is dict and set(value) == {'version', 'profile', 'observations',
            'storage_identity', 'storage_root', 'endpoints_root', 'operations', 'blockers',
            'status', 'plan_id'}, 'HOST_PLAN')
    profile = LocalHostProfile.parse(value['profile'])
    body = {k: v for k, v in value.items() if k != 'plan_id'}
    require(digest(body) == value['plan_id'], 'HOST_PLAN_CHANGED')
    require(digest(observe_value(observed)) == value['observations'], 'HOST_PLAN_STALE')
    require(value['status'] == 'planned' and value['blockers'] == [], 'HOST_PLAN_BLOCKED')
    # Recompute semantics; a caller cannot hash arbitrary operations into a plan.
    sizes = [op['bytes'] for op in value['operations'] if op.get('kind') == 'prepare-owned-xfs-file']
    require(len(sizes) <= 1, 'HOST_PLAN')
    expected = plan(profile.document(), observed, storage_root=value['storage_root'],
                    endpoints_root=value['endpoints_root'], allocation_bytes=sizes[0] if sizes else None)
    require(expected == value, 'HOST_PLAN_SEMANTICS')
    return deepcopy(value)
