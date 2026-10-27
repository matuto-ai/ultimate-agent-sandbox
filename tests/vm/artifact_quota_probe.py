#!/usr/bin/env python3
"""Fixed nonroot disposable-VM project quota proof; never helper authority.

Trusted root fixture supplies *observed* XFS quota facts on bounded stdin. The
probe independently checks opened-FD project membership/inheritance, same-FS
identity, global free space and real positive allocation before over-limit denial.
ENOSPC is not evidence without every prerequisite. Exact guest errno remains a
native observation, not inferred from a kernel version or upstream source.

UAPI: linux/fs.h FS_IOC_FSGETXATTR and struct fsxattr (query only, no SET ioctl).
https://man7.org/linux/man-pages/man2/ioctl_xfs_fsgetxattr.2.html
XFS project quota may return ENOSPC (not proof of this guest's observed errno):
https://github.com/torvalds/linux/blob/v6.18/fs/xfs/xfs_trans_dquot.c
"""
import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import struct
import sys

UID = 165533
PROJECTS = {'alpha': 301, 'beta': 303}
HARD_LIMIT_BYTES = 256 << 20
POSITIVE_BYTES = 1 << 20
REQUEST_BYTES = HARD_LIMIT_BYTES + 4096
GLOBAL_MARGIN_BYTES = 64 << 20
MAX_FACT_BYTES = 4096
MAX_REPORT_BYTES = 8192
NAME = '.quota-exhaustion-probe'
# Fixed admitted Linux x86-64 UAPI: _IOR('X', 31, struct fsxattr), 28 bytes.
FS_IOC_FSGETXATTR = 0x801c581f
FS_XFLAG_PROJINHERIT = 0x200
FSXATTR = struct.Struct('=5I8s')
FACT_KEYS = {'version', 'room', 'project_id', 'device', 'hard_limit_bytes',
             'accounting', 'enforcement', 'user_enforcement', 'group_enforcement', 'filesystem'}


class ProbeError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def expect(condition, code):
    if not condition:
        raise ProbeError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        expect(key not in result, 'DUPLICATE_PARENT_FACT')
        result[key] = value
    return result


def parent_facts(raw, room):
    """Fixed values/identity only; no command, path, quota change or fallback."""
    expect(type(raw) is bytes and 0 < len(raw) <= MAX_FACT_BYTES, 'PARENT_FACT_BOUND')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ProbeError('INVALID_PARENT_FACT_JSON') from error
    expect(type(value) is dict and set(value) == FACT_KEYS, 'PARENT_FACT_FIELDS')
    expect(type(value['version']) is int and value['version'] == 1
           and value['room'] == room and type(value['room']) is str
           and type(value['project_id']) is int and value['project_id'] == PROJECTS[room]
           and type(value['device']) is int and 0 <= value['device'] < 2**64
           and type(value['hard_limit_bytes']) is int and value['hard_limit_bytes'] == HARD_LIMIT_BYTES
           and value['accounting'] is True and value['enforcement'] is True
           and value['user_enforcement'] is False and value['group_enforcement'] is False
           and value['filesystem'] == 'xfs', 'PARENT_QUOTA_FACT_MISMATCH')
    return value


def attributes(descriptor):
    value = bytearray(FSXATTR.size)
    fcntl.ioctl(descriptor, FS_IOC_FSGETXATTR, value, True)
    flags, _, _, project_id, _, _ = FSXATTR.unpack(value)
    return {'project_id': project_id, 'flags': flags}


def identity(node):
    return node.st_dev, node.st_ino


def open_mount():
    """Only the fixed mount, all ancestors no-follow; no caller path."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open('/', flags)
    try:
        for component in ('mnt', 'uas-artifacts'):
            following = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def global_space(descriptor):
    """Observe mount root, not quota-clamped PROJINHERIT Room statvfs."""
    value = os.fstatvfs(descriptor)
    unit = value.f_frsize
    expect(type(unit) is int and 512 <= unit <= 65536 and unit & (unit - 1) == 0,
           'UNSUPPORTED_ALLOCATION_UNIT')
    available = min(value.f_bavail, value.f_bfree) * unit
    expect(available >= REQUEST_BYTES + GLOBAL_MARGIN_BYTES, 'INSUFFICIENT_GLOBAL_SPACE')
    return {'available_bytes': available, 'allocation_unit': unit}


def require_membership(mount, directory, descriptor, facts):
    root, parent = os.fstat(mount), os.fstat(directory)
    expect(stat.S_ISDIR(root.st_mode) and root.st_uid == 0 and root.st_mode & 0o022 == 0,
           'UNTRUSTED_GLOBAL_ROOT')
    expect(stat.S_ISDIR(parent.st_mode) and parent.st_uid == UID
           and parent.st_gid == UID and parent.st_mode & 0o022 == 0, 'UNOWNED_ROOM_ROOT')
    expect(root.st_dev == parent.st_dev == facts['device'], 'QUOTA_DEVICE_MISMATCH')
    linked_parent = os.stat(facts['room'], dir_fd=mount, follow_symlinks=False)
    expect(stat.S_ISDIR(linked_parent.st_mode) and identity(linked_parent) == identity(parent),
           'ROOM_NAME_IDENTITY_CHANGED')
    global_attributes, parent_attributes = attributes(mount), attributes(directory)
    expect(global_attributes['project_id'] == 0
           and not global_attributes['flags'] & FS_XFLAG_PROJINHERIT, 'GLOBAL_ROOT_QUOTA_CLAMPED')
    expect(parent_attributes['project_id'] == facts['project_id']
           and parent_attributes['flags'] & FS_XFLAG_PROJINHERIT, 'ROOM_PROJECT_ASSIGNMENT_MISMATCH')
    result = {'mount_identity': list(identity(root)), 'room_identity': list(identity(parent)),
              'mount': global_attributes, 'room': parent_attributes}
    if descriptor is not None:
        node = os.fstat(descriptor)
        expect(stat.S_ISREG(node.st_mode) and node.st_nlink == 1
               and node.st_uid == UID and node.st_gid == UID
               and stat.S_IMODE(node.st_mode) == 0o600 and node.st_dev == root.st_dev,
               'UNOWNED_PROBE_FILE')
        file_attributes = attributes(descriptor)
        expect(file_attributes['project_id'] == facts['project_id'], 'FILE_PROJECT_ASSIGNMENT_MISMATCH')
        result.update(file_identity=list(identity(node)), file=file_attributes)
    return result


def cleanup_file(directory, descriptor, initial, room_identity):
    """Held ordinary file, held parent and exact name; no guessed replacement."""
    expect(identity(os.fstat(directory)) == room_identity, 'CLEANUP_ROOM_IDENTITY_CHANGED')
    held = os.fstat(descriptor)
    current = os.stat(NAME, dir_fd=directory, follow_symlinks=False)
    expect(identity(held) == initial == identity(current) and stat.S_ISREG(current.st_mode)
           and current.st_uid == UID and current.st_nlink == 1, 'CLEANUP_FILE_IDENTITY_CHANGED')
    os.unlink(NAME, dir_fd=directory)
    os.fsync(directory)
    expect(os.fstat(descriptor).st_nlink == 0, 'CLEANUP_UNLINK_UNCONFIRMED')
    try:
        os.stat(NAME, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ProbeError('CLEANUP_NAME_RECREATED')


def exercise(room, facts, evidence):
    mount = directory = descriptor = -1
    initial = room_identity = None
    try:
        evidence['phase'] = 'open-mount'
        mount = open_mount()
        evidence['phase'] = 'open-room'
        directory = os.open(room, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=mount)
        room_identity = identity(os.fstat(directory))
        evidence['phase'] = 'project-prerequisites'
        require_membership(mount, directory, None, facts)
        evidence['global_before'] = global_space(mount)
        evidence['phase'] = 'exclusive-create'
        descriptor = os.open(NAME, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
        initial = identity(os.fstat(descriptor))
        evidence['phase'] = 'file-project-membership'
        before = require_membership(mount, directory, descriptor, facts)
        evidence['membership'] = before
        evidence['phase'] = 'positive-allocation'
        os.posix_fallocate(descriptor, 0, POSITIVE_BYTES)
        os.fsync(descriptor)
        node = os.fstat(descriptor)
        expect(identity(node) == initial and node.st_size == POSITIVE_BYTES
               and node.st_blocks * 512 >= POSITIVE_BYTES, 'POSITIVE_ALLOCATION_UNPROVEN')
        evidence['positive_bytes'] = POSITIVE_BYTES
        evidence['positive_allocated_bytes'] = node.st_blocks * 512
        evidence['global_pre_excess'] = global_space(mount)
        evidence['phase'] = 'over-limit-allocation'
        denied = None
        try:
            os.posix_fallocate(descriptor, 0, REQUEST_BYTES)
        except OSError as error:
            denied = error.errno
        evidence['observed_errno'] = denied
        expect(denied in (errno.EDQUOT, errno.ENOSPC), 'PROJECT_OVERLIMIT_NOT_DENIED')
        evidence['phase'] = 'post-denial-proof'
        after = require_membership(mount, directory, descriptor, facts)
        # File PREALLOC extent flags may change after actual allocation. Bind
        # project ID and exact held object, not unrelated mutable extent hints.
        for key in ('mount_identity', 'room_identity', 'file_identity'):
            expect(after[key] == before[key], 'QUOTA_IDENTITY_CHANGED')
        evidence['membership_after'] = after
        evidence['global_after'] = global_space(mount)
        evidence['requested_bytes'] = REQUEST_BYTES
        evidence['phase'] = 'owned-cleanup'
    finally:
        try:
            if descriptor >= 0:
                failure_phase = evidence['phase']
                evidence['owned_cleanup'] = False
                try:
                    cleanup_file(directory, descriptor, initial, room_identity)
                    evidence['owned_cleanup'] = True
                except BaseException:
                    evidence['phase'] = 'owned-cleanup'
                    evidence['failed_before_cleanup'] = failure_phase
                    raise
        finally:
            for descriptor_ in (descriptor, directory, mount):
                if descriptor_ >= 0:
                    os.close(descriptor_)
    evidence['phase'] = 'complete'
    evidence['project_hard_quota_enforced'] = True


def main():
    evidence = {'version': 1, 'status': 'failed', 'phase': 'fixed-identity',
                'uid': os.getuid(), 'owned_cleanup': False}
    try:
        expect(len(sys.argv) == 2 and sys.argv[1] in PROJECTS
               and (os.getuid(), os.getgid()) == (165533,165533), 'FIXED_DISPOSABLE_IDENTITY_REQUIRED')
        expect(sys.byteorder == 'little' and struct.calcsize('P') == 8
               and os.uname().machine == 'x86_64', 'UNSUPPORTED_IOCTL_ABI')
        room = sys.argv[1]
        evidence['room'] = room
        # Fatal self deadline also covers bounded stdin and all allocation calls.
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(15)
        evidence['phase'] = 'boot-marker'
        marker = Path('/run/uas-vm-fixture').lstat()
        expect(stat.S_ISREG(marker.st_mode) and marker.st_uid == 0 and marker.st_nlink == 1,
               'DISPOSABLE_BOOT_MARKER_REQUIRED')
        evidence['phase'] = 'parent-quota-facts'
        facts = parent_facts(sys.stdin.buffer.read(MAX_FACT_BYTES + 1), room)
        evidence['quota_facts'] = facts
        exercise(room, facts, evidence)
        evidence['status'] = 'passed'
    except Exception as error:
        evidence['error_type'] = type(error).__name__
        evidence['error_code'] = getattr(error, 'code', None)
        evidence['errno'] = getattr(error, 'errno', None)
    data = json.dumps(evidence, sort_keys=True, separators=(',', ':'))
    expect(len(data.encode()) <= MAX_REPORT_BYTES, 'REPORT_BOUND')
    print(data, flush=True)
    return 0 if evidence['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
