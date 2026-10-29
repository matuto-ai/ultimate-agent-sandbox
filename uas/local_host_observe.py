"""Bounded Linux capability observations. No installation or host mutation.

Only fixed read commands are admitted. Returned records contain no credential,
environment or daemon-configuration contents. A failed read is not absence.
"""
import json
import os
from pathlib import Path
import stat

from .local_host_profile import LocalHostProfile, absolute_path, require
from .local_host_plan import observe_value


LIMIT = 1024*1024


def read_text(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= LIMIT, 'HOST_READ_FILE')
        data = os.read(fd, LIMIT+1)
        require(len(data) <= LIMIT, 'HOST_READ_BOUND')
        return data.decode('utf-8', errors='strict')
    finally:
        os.close(fd)


def command(arguments):
    from .local_host_process import run_fixed
    return run_fixed(arguments, limit=LIMIT)


def canonical_node(path, *, directory=True):
    absolute_path(str(path))
    path = Path(path)
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'HOST_PATH_SUBSTITUTION')
        if part != path:
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                    and not info.st_mode & 0o022, 'HOST_PATH_ANCESTOR')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISSOCK(info.st_mode), 'HOST_NODE_TYPE')
    return info


def subordinate(text):
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split(':')
        require(len(fields) == 3 and fields[1].isascii() and fields[1].isdecimal()
                and fields[2].isascii() and fields[2].isdecimal(), 'HOST_SUBORDINATE_FORMAT')
        rows.append({'user': fields[0], 'offset': int(fields[1]), 'size': int(fields[2])})
    return rows


def allocated_ids(passwd, group):
    result = set()
    for text, count in ((passwd, 7), (group, 4)):
        for line in text.splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            fields = line.split(':')
            require(len(fields) == count and fields[2].isascii() and fields[2].isdecimal(), 'HOST_ACCOUNT_FORMAT')
            result.add(int(fields[2]))
    return sorted(result)


def inspect(profile_document, *, storage_parent, proposed_paths):
    profile = LocalHostProfile.parse(profile_document)
    parent = Path(absolute_path(storage_parent))
    info = canonical_node(parent)
    require(type(proposed_paths) is list and 1 <= len(proposed_paths) <= 1024, 'HOST_INSPECTION_PATHS')
    occupied = []
    for value in proposed_paths:
        path = Path(absolute_path(value))
        # lexists detects dangling symlinks rather than treating them as free.
        if os.path.lexists(path):
            occupied.append(value)
        existing_parent = path.parent
        while not os.path.lexists(existing_parent):
            existing_parent = existing_parent.parent
        canonical_node(existing_parent)
    filesystem = command(['/usr/bin/stat', '-f', '-c', '%T', str(parent)])
    accounting = enforcement = False
    if filesystem == 'xfs':
        report = command(['/usr/sbin/xfs_quota', '-x', '-c', 'state -p', str(parent)])
        # Exactly one selected project-quota report; no generic grep for another
        # filesystem or user/group-quota section is accepted as evidence.
        require(report.count('Project quota state on ') == 1, 'HOST_QUOTA_OBSERVATION')
        accounting = report.count('Accounting: ON') == 1
        enforcement = report.count('Enforcement: ON') == 1
    engine = None
    if os.path.lexists(profile.socket):
        socket = canonical_node(profile.socket, directory=False)
        require(socket.st_uid == 0 and not socket.st_mode & 0o002, 'HOST_ENGINE_SOCKET_OWNER')
        before = [socket.st_dev, socket.st_ino]
        engine = {'version': command(profile.docker_argv(['version', '--format', '{{.Server.Version}}'])),
                  'docker_root': command(profile.docker_argv(['info', '--format', '{{.DockerRootDir}}'])),
                  'security_options': json.loads(command(profile.docker_argv(['info', '--format', '{{json .SecurityOptions}}']))),
                  'socket_identity': before}
        after = canonical_node(profile.socket, directory=False)
        require(before == [after.st_dev, after.st_ino], 'HOST_ENGINE_SOCKET_CHANGED')
    import ipaddress
    networks = set()
    for family in ('-4', '-6'):
        routes = json.loads(command(['/usr/sbin/ip', '-j', family, 'route', 'show', 'table', 'all']))
        require(type(routes) is list and len(routes) <= 65536, 'HOST_ROUTES')
        for row in routes:
            require(type(row) is dict, 'HOST_ROUTES')
            destination = row.get('dst')
            # A default route is not an occupied subnet. Specific LAN/bridge
            # routes are retained for explicit nonoverlapping Room selection.
            if destination and destination != 'default':
                networks.add(str(ipaddress.ip_network(destination, strict=False)))
    space = os.statvfs(parent)
    result = {'version': 1, 'selinux': command(['/usr/sbin/getenforce']),
              'engine': engine, 'subuid': subordinate(read_text('/etc/subuid')),
              'subgid': subordinate(read_text('/etc/subgid')),
              'allocated_ids': allocated_ids(read_text('/etc/passwd'), read_text('/etc/group')),
              'storage': {'path': str(parent), 'identity': [info.st_dev, info.st_ino],
                          'filesystem': filesystem, 'project_accounting': accounting,
                          'project_enforcement': enforcement,
                          'free_bytes': space.f_bavail*space.f_frsize,
                          'owner_uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)},
              'occupied_paths': sorted(occupied), 'networks': sorted(networks)}
    after = canonical_node(parent)
    require([after.st_dev, after.st_ino] == [info.st_dev, info.st_ino], 'HOST_STORAGE_CHANGED')
    return observe_value(result)
