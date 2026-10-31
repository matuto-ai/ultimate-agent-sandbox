"""Explicit preparation of one reserved Room quota and fresh empty owned leaves.

Called only by a privileged preparation owner while its declared lock is held.
That lock coordinates this installer, not unrelated root administrators. No
effect is performed on import, and no operation traverses populated data.
"""
import json
import os
from pathlib import Path
import re
import stat

from .local_host_profile import LocalHostProfile, absolute_path, canonical, digest, require
from .local_host_observe import canonical_node
from .local_host_process import run_fixed
from .guest_fixture import project_attributes


def quota_rows(raw, *, anchored=True):
    """Numeric xfs_quota report -p -{b,i} -n -N, with an accounting anchor."""
    require(type(raw) is str and len(raw) <= 1024*1024, 'ROOM_QUOTA_REPORT')
    if not raw.strip():
        require(not anchored, 'ROOM_QUOTA_REPORT')
        return {}
    rows = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'#([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+[0-9]+\s+\[[^\]\r\n]{1,32}\]\s*', line.strip())
        require(match is not None, 'ROOM_QUOTA_REPORT')
        project, used, soft, hard = map(int, match.groups())
        require(project not in rows and 0 <= project < 2**31
                and all(0 <= value < 2**63 for value in (used, soft, hard)), 'ROOM_QUOTA_REPORT')
        rows[project] = {'used': used, 'soft': soft, 'hard': hard}
    # Empty output is not proof that an ID is free. Require the numeric default
    # project's accounting row and independent block/inode inventories.
    require(not anchored or 0 in rows, 'ROOM_QUOTA_ACCOUNTING_ANCHOR')
    return rows


def observe_quotas(storage, project):
    storage = absolute_path(storage)
    require(type(project) is int and 0 < project < 2**31, 'ROOM_QUOTA_SELECTION')
    result = {}
    for unit, flag in (('blocks', 'b'), ('inodes', 'i')):
        prefix = ['/usr/sbin/xfs_quota', '-x', '-D', '/dev/null', '-P', '/dev/null', '-c']
        command = 'report -p -'+flag+' -n -N'
        quota_rows(run_fixed(prefix+[command, storage]))
        # Upstream quota/report.c report_project_mount: without a range,
        # GETNEXTQUOTA can fall back to the project-name database. Never infer
        # candidate absence from that enumeration. An explicit one-ID range
        # forces GETQUOTA for that ID, with stderr/errors rejected by run_fixed.
        selected = quota_rows(run_fixed(prefix+[command+' -L '+str(project)+
                              ' -U '+str(project), storage]), anchored=False)
        require(set(selected) <= {project}, 'ROOM_QUOTA_RANGE')
        result[unit] = selected
    return result


def _operation(receipt, index, kind, fields):
    require(os.geteuid() == 0, 'ROOM_PREPARE_ROOT_REQUIRED')
    require(type(index) is int and 0 <= index < len(receipt.plan['operations']), 'ROOM_PREPARE_INDEX')
    operation = receipt.plan['operations'][index]
    require(type(operation) is dict and set(operation) == {'kind', *fields}
            and operation['kind'] == kind, 'ROOM_PREPARE_OPERATION')
    return operation


def _storage(operation, receipt=None):
    path = Path(absolute_path(operation['storage_root']))
    info = canonical_node(path)
    expected=[info.st_dev,info.st_ino]
    if receipt is not None and 'owned_xfs' in receipt.plan:
        from .local_xfs_storage import verify_owned_mount
        mount=verify_owned_mount(receipt.plan['owned_xfs'],str(path))
        require(mount['identity']==expected,'ROOM_STORAGE_CHANGED')
        expected=[0,info.st_ino]
    require(info.st_uid == 0 and not info.st_mode & 0o022
            and expected == operation['storage_identity'], 'ROOM_STORAGE_CHANGED')
    return path, info


def reserve_quota(receipt, index):
    operation = _operation(receipt, index, 'reserve-room-quota',
                           {'storage_root', 'storage_identity', 'project_id', 'disk_bytes'})
    storage, identity = _storage(operation,receipt)
    project, size = operation['project_id'], operation['disk_bytes']
    require(type(project) is int and 0 < project < 2**31 and type(size) is int
            and 0 < size < 2**63 and size % 1024 == 0, 'ROOM_QUOTA_SELECTION')
    state = receipt.state(index)
    before = observe_quotas(str(storage), project)
    absent = all(project not in rows for rows in before.values())
    if state['state'] == 'not-started':
        require(absent, 'ROOM_QUOTA_ALREADY_ALLOCATED')
        require(receipt.intent(index), 'ROOM_QUOTA_INTENT_UNCERTAIN')
    if state['state'] == 'not-started' or (state['state'] == 'unknown' and absent):
        # A root-controlled canonical path is held unchanged before and after
        # this fixed tool call; no caller command, shell or /etc/projects edit.
        _storage(operation,receipt)
        run_fixed(['/usr/sbin/xfs_quota', '-x', '-D', '/dev/null', '-P', '/dev/null', '-c',
                   'limit -p bhard='+str(size//1024)+'k '+str(project), str(storage)])
    # Unknown outcomes are observed first. Only verified absence in both quota
    # inventories permits the same reserved intent to make an effect again.
    after = observe_quotas(str(storage), project)
    _storage(operation,receipt)
    require(project in after['blocks'] and after['blocks'][project]['hard'] == size//1024
            and after['blocks'][project]['soft'] == 0
            and (project not in after['inodes'] or
                 after['inodes'][project]['hard'] == after['inodes'][project]['soft'] == 0),
            'ROOM_QUOTA_UNCONFIRMED')
    evidence = {'identity': [0 if 'owned_xfs' in receipt.plan else identity.st_dev, project],
                'observed_sha256': digest({'project': project, 'hard_bytes': size, 'storage': operation['storage_identity']})}
    if state['state'] == 'confirmed':
        require(evidence == state['evidence'], 'ROOM_QUOTA_CONFIRMED_DRIFT')
    else:
        receipt.confirm(index, evidence)
    return evidence


def _marker(parent_fd, name, value=None):
    if value is not None:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent_fd)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096, 'ROOM_OWNER_RECORD')
        raw = os.read(fd, 4097)
        result = json.loads(raw)
        require(canonical(result) == raw, 'ROOM_OWNER_RECORD')
        os.fsync(fd)
        return result
    finally:
        os.close(fd)


def prepare_leaf(receipt, index):
    # Legacy explicit operations retain runtime ownership. New generated plans
    # carry one closed boolean selected by the trusted reference-root role.
    require(type(index) is int and 0 <= index < len(receipt.plan['operations']), 'ROOM_PREPARE_INDEX')
    selected=receipt.plan['operations'][index]
    fields={'storage_root', 'storage_identity', 'path', 'project_id', 'mcs_level'}
    if type(selected) is dict and 'readonly' in selected: fields.add('readonly')
    operation = _operation(receipt, index, 'prepare-room-leaf', fields)
    readonly=operation.get('readonly',False)
    require(type(readonly) is bool,'ROOM_LEAF_ROLE')
    storage, storage_info = _storage(operation,receipt)
    path = Path(absolute_path(operation['path']))
    require(storage in path.parents and len(path.name.encode()) < 220, 'ROOM_LEAF_PATH')
    project, level = operation['project_id'], operation['mcs_level']
    require(type(project) is int and 0 < project < 2**31, 'ROOM_QUOTA_SELECTION')
    reservations = [i for i, prior in enumerate(receipt.plan['operations'][:index])
                    if prior.get('kind') == 'reserve-room-quota'
                    and prior.get('project_id') == project
                    and prior.get('storage_root') == str(storage)
                    and prior.get('storage_identity') == operation['storage_identity']]
    require(len(reservations) == 1 and receipt.state(reservations[0])['state'] == 'confirmed',
            'ROOM_QUOTA_RESERVATION_REQUIRED')
    match = re.fullmatch(r's0:c([0-9]{1,4}),c([0-9]{1,4})', level) if type(level) is str else None
    require(match is not None and 0 <= int(match[1]) < int(match[2]) <= 1023, 'ROOM_MCS_SELECTION')
    parent_info = canonical_node(path.parent)
    require(parent_info.st_uid == 0 and not parent_info.st_mode & 0o022
            and parent_info.st_dev == storage_info.st_dev, 'ROOM_LEAF_PARENT')
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    leaf_fd = None
    marker_name = '.'+path.name+'.uas-owner.json'
    try:
        opened = os.fstat(parent_fd)
        require((opened.st_dev, opened.st_ino) == (parent_info.st_dev, parent_info.st_ino), 'ROOM_LEAF_PARENT_CHANGED')
        state = receipt.state(index)
        first = receipt.intent(index) if state['state'] == 'not-started' else False
        if first:
            # Check the sibling record before creating anything; neither path is
            # adopted. The owner record stays OUTSIDE Git/runtime leaf contents.
            try: os.stat(marker_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError: pass
            else: require(False, 'ROOM_OWNER_RECORD_EXISTS')
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        leaf_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        info = os.fstat(leaf_fd)
        require(info.st_dev == storage_info.st_dev, 'ROOM_LEAF_DEVICE')
        binding = {'version': 1, 'plan_id': receipt.plan['plan_id'], 'operation': digest(operation),
                   'identity': [0 if 'owned_xfs' in receipt.plan else info.st_dev, info.st_ino],
                   'parent': [0 if 'owned_xfs' in receipt.plan else opened.st_dev, opened.st_ino]}
        marker = _marker(parent_fd, marker_name, binding if first else None)
        require(marker == binding, 'ROOM_OWNER_RECORD_CHANGED')
        expected_label = 'system_u:object_r:container_file_t:'+level

        def current():
            _storage(operation,receipt)
            fresh = os.fstat(leaf_fd)
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            require(stat.S_ISDIR(named.st_mode) and (named.st_dev, named.st_ino) ==
                    (fresh.st_dev, fresh.st_ino) == (info.st_dev, info.st_ino), 'ROOM_LEAF_CHANGED')
            parent = canonical_node(path.parent)
            require((parent.st_dev, parent.st_ino) == (opened.st_dev, opened.st_ino), 'ROOM_LEAF_PARENT_CHANGED')
            attributes = project_attributes(path)
            label = run_fixed(['/usr/bin/stat', '-c', '%C', str(path)])
            return fresh, attributes, label

        fresh, attributes, label = current()
        profile=LocalHostProfile.parse(receipt.plan['host_profile'])
        final_owner = (0,0) if readonly else (profile.owners['runtime'], profile.owners['runtime'])
        if ((fresh.st_uid, fresh.st_gid) == final_owner
                and (not readonly or stat.S_IMODE(fresh.st_mode) == 0o755)):
            # Ownership was already handed off. Runtime may have populated data;
            # only observation is permitted, not a recursive repair/relabel.
            require(attributes == (project, True) and label == expected_label,
                    'ROOM_HANDED_OFF_DRIFT')
        else:
            require(state['state'] != 'confirmed' and (fresh.st_uid, fresh.st_gid) == (0, 0)
                    and stat.S_IMODE(fresh.st_mode) == 0o700 and os.listdir(leaf_fd) == [],
                    'ROOM_LEAF_NOT_FRESH_EMPTY')
            require(attributes in ((0, False), (project, True)), 'ROOM_LEAF_FOREIGN_PROJECT')
            if attributes != (project, True):
                current(); require(os.listdir(leaf_fd) == [], 'ROOM_LEAF_POPULATED')
                run_fixed(['/usr/sbin/xfs_quota', '-x', '-D', '/dev/null', '-P', '/dev/null', '-c',
                           'project -s -p '+str(path)+' '+str(project), str(storage)])
            fresh, attributes, label = current()
            require(attributes == (project, True), 'ROOM_LEAF_QUOTA_UNCONFIRMED')
            if label != expected_label:
                require(os.listdir(leaf_fd) == [], 'ROOM_LEAF_POPULATED')
                run_fixed(['/usr/bin/chcon', '-u', 'system_u', '-r', 'object_r', '-t', 'container_file_t',
                           '-l', level, str(path)])
            fresh, attributes, label = current()
            require(attributes == (project, True) and label == expected_label
                    and (fresh.st_uid, fresh.st_gid) == (0, 0) and os.listdir(leaf_fd) == [],
                    'ROOM_LEAF_HANDOFF_UNCONFIRMED')
            if readonly:
                # Final mode is the handoff marker for root-owned read-only
                # projections. Never chmod a populated or already handed leaf.
                os.fchmod(leaf_fd,0o755)
            else:
                os.fchown(leaf_fd, *final_owner)
            os.fsync(leaf_fd)
        fresh, attributes, label = current()
        require((fresh.st_uid, fresh.st_gid) == final_owner and attributes == (project, True)
                and label == expected_label and (not readonly or stat.S_IMODE(fresh.st_mode) == 0o755),
                'ROOM_LEAF_HANDOFF_UNCONFIRMED')
        evidence = {'identity': binding['identity'], 'observed_sha256': digest({
            'binding': binding, 'project': project, 'mcs': level, 'owner': list(final_owner)})}
        if state['state'] == 'confirmed':
            require(evidence == state['evidence'], 'ROOM_LEAF_CONFIRMED_DRIFT')
        else:
            receipt.confirm(index, evidence)
        return evidence
    finally:
        if leaf_fd is not None: os.close(leaf_fd)
        os.close(parent_fd)
