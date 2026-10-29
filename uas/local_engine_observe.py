"""Conservative, bounded first-root-Engine inventory (no installation effects).

An observation is not a lock or ownership authority. Any incomplete observation
blocks provisioning. Owned exceptions require existing root-private receipts,
exact artifact and process identity; passing a plan cannot authorize adoption.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from .local_host_profile import LocalHostProfile, require
from .local_host_observe import read_text, subordinate
from .local_host_process import run_fixed

LIMIT = 1024 * 1024
TOOLS = ('/usr/bin/dockerd', '/usr/bin/containerd', '/usr/bin/runc',
         '/usr/bin/systemctl', '/usr/sbin/iptables-save',
         '/usr/sbin/ip6tables-save', '/usr/sbin/nft',
         '/usr/sbin/useradd', '/usr/sbin/groupadd', '/usr/sbin/usermod', '/usr/sbin/nologin', '/usr/bin/docker')
UNITS = ('docker.service', 'docker.socket', 'containerd.service')


def _tool(path):
    # Distribution alternatives may be symlinks; pin canonical target and all
    # ancestor ownership rather than trusting a writable PATH or link target.
    resolved = Path(path).resolve(strict=True)
    for node in (Path(path), *Path(path).parents, resolved, *resolved.parents):
        s = node.lstat()
        require(s.st_uid == 0 and (stat.S_ISLNK(s.st_mode) or not s.st_mode & 0o022), 'ENGINE_TOOL_OWNER')
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_mode & 0o111
                and s.st_size <= 256 * 1024 * 1024, 'ENGINE_TOOL_TYPE')
        h = hashlib.sha256()
        deadline = time.monotonic() + 10
        remaining = 256 * 1024 * 1024 + 1
        while remaining:
            require(time.monotonic() < deadline, 'ENGINE_TOOL_TIMEOUT')
            data = os.read(fd, min(1024 * 1024, remaining))
            if not data: break
            h.update(data); remaining -= len(data)
        require(remaining > 0, 'ENGINE_TOOL_BOUND')
        end = os.fstat(fd)
        require((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) ==
                (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns), 'ENGINE_TOOL_CHANGED')
        return {'path': str(resolved), 'identity': [s.st_dev, s.st_ino], 'sha256': h.hexdigest()}
    finally: os.close(fd)


def _entries(path, bound=8192):
    result = []
    with os.scandir(path) as entries:
        for entry in entries:
            require(len(result) < bound, 'ENGINE_INVENTORY_BOUND')
            result.append(entry.name)
    return sorted(result)


def _processes():
    rows = []
    deadline = time.monotonic() + 10
    for name in _entries('/proc'):
        require(time.monotonic() < deadline, 'ENGINE_PROCESS_SCAN_TIMEOUT')
        if not name.isascii() or not name.isdecimal(): continue
        root = Path('/proc') / name
        try:
            status = read_text(root / 'status')
            uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$', status, re.M)
            require(uid is not None, 'ENGINE_PROCESS_UID')
            if 0 not in [int(x) for x in uid.groups()]: continue
            comm = read_text(root / 'comm').strip()
            # Inspect executable too: a changed process title does not hide dockerd.
            try: exe = os.readlink(root / 'exe')
            except FileNotFoundError:
                fields = read_text(root / 'stat').rsplit(')', 1)[1].split()
                require(int(fields[6]) & 0x200000, 'ENGINE_PROCESS_EXECUTABLE')
                continue
            selected = comm.startswith(('dockerd', 'containerd')) or Path(exe.removesuffix(' (deleted)')).name.startswith(('dockerd', 'containerd'))
            if not selected: continue
            before = read_text(root / 'stat')
            args = read_text(root / 'cmdline').split('\0')
            args = [x for x in args if x]
            require(len(args) <= 256 and sum(map(len, args)) <= 16384, 'ENGINE_PROCESS_ARGS')
            # These are local root daemon flags, not the process environment.
            # Do not persist arbitrary argument values: only identity-relevant paths.
            safe = {}
            for i, arg in enumerate(args):
                for flag in ('--config-file', '--config', '--data-root', '--exec-root', '--pidfile', '--address', '--root', '--state'):
                    if arg.startswith(flag + '='): safe[flag] = arg[len(flag)+1:]
                    elif arg == flag and i + 1 < len(args): safe[flag] = args[i+1]
            cgroup = read_text(root / 'cgroup').strip()
            after = read_text(root / 'stat')
            require(before.rsplit(')', 1)[1].split()[19] == after.rsplit(')', 1)[1].split()[19]
                    and exe == os.readlink(root / 'exe'), 'ENGINE_PROCESS_CHANGED')
            # stat fields before ')' can contain spaces; starttime is field22.
            fields = before.rsplit(')', 1)[1].split()
            require(len(fields) >= 20 and fields[19].isdecimal(), 'ENGINE_PROCESS_STAT')
            rows.append({'pid': int(name), 'uid': [int(x) for x in uid.groups()],
                         'comm': comm, 'exe': exe, 'starttime': int(fields[19]),
                         'arguments': safe, 'arguments_sha256': hashlib.sha256('\0'.join(args).encode()).hexdigest(),
                         'cgroup': cgroup, 'netns': os.readlink(root / 'ns/net')})
        except FileNotFoundError:
            # Process churn is not proof of daemon absence; request a fresh scan.
            require(False, 'ENGINE_PROCESS_CHANGED')
    return rows


def _accounts():
    result = {'passwd': [], 'group': []}
    for kind, count in (('passwd', 7), ('group', 4)):
        for line in read_text('/etc/' + kind).splitlines():
            if not line or line.startswith('#'): continue
            fields = line.split(':')
            require(len(fields) == count and fields[2].isascii() and fields[2].isdecimal(), 'ENGINE_ACCOUNT_FORMAT')
            if kind == 'passwd':
                require(fields[3].isascii() and fields[3].isdecimal(), 'ENGINE_ACCOUNT_FORMAT')
                row = {'name': fields[0], 'uid': int(fields[2]), 'gid': int(fields[3]), 'home': fields[5], 'shell': fields[6]}
            else: row = {'name': fields[0], 'gid': int(fields[2]), 'members': fields[3]}
            result[kind].append(row)
    return result


def _empty_config_directory(path):
    """Package scaffolding is observed, never changed or adopted."""
    from .local_host_observe import canonical_node
    node=canonical_node(path)
    require(node.st_uid==0 and not node.st_mode&0o022,'ENGINE_CONFIG_DIRECTORY_OWNER')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        held=os.fstat(fd)
        require((held.st_dev,held.st_ino)==(node.st_dev,node.st_ino),'ENGINE_CONFIG_DIRECTORY_CHANGED')
        with os.scandir(fd) as entries:empty=next(entries,None) is None
        named=os.lstat(path)
        require((held.st_dev,held.st_ino)==(named.st_dev,named.st_ino),'ENGINE_CONFIG_DIRECTORY_CHANGED')
        return empty
    finally:os.close(fd)


def socket_parent(profile):
    from .local_host_observe import canonical_node
    path=Path(profile.socket).parent
    node=canonical_node(path)
    require(node.st_uid==0 and not node.st_mode&0o022,'ENGINE_SOCKET_PARENT_OWNER')
    return {'path':str(path),'identity':[node.st_dev,node.st_ino]}


def _footprints(profile):
    paths = {'/var/lib/docker', '/var/lib/containerd', '/etc/docker', '/etc/containerd',
             '/run/containerd', '/run/docker', '/run/docker.sock', '/run/docker.pid',
             profile.socket, profile.data_root, profile.exec_root}
    paths.update('/run/' + n for n in _entries('/run') if n.startswith(('docker', 'containerd')))
    rows = []
    for path in sorted(paths):
        try: s = os.lstat(path)
        except FileNotFoundError: continue
        if path in ('/etc/docker','/etc/containerd') and _empty_config_directory(path):continue
        rows.append({'path': path, 'identity': [s.st_dev, s.st_ino], 'uid': s.st_uid, 'gid': s.st_gid, 'mode': s.st_mode})
    return rows


def _networks(command):
    rows = []
    for family, tool in (('ipv4', '/usr/sbin/iptables-save'), ('ipv6', '/usr/sbin/ip6tables-save')):
        value = command([tool])
        require(not value or '*filter' in value or '*' in value, 'ENGINE_FIREWALL_FORMAT')
        for line in value.splitlines():
            if 'docker' in line.lower(): rows.append({'kind': family, 'evidence_sha256': hashlib.sha256(line.encode()).hexdigest(), 'exclusive_candidate': _docker_rule(line)})
    nft = json.loads(command(['/usr/sbin/nft', '-j', 'list', 'ruleset']))
    require(type(nft) is dict and type(nft.get('nftables')) is list, 'ENGINE_NFT_FORMAT')
    for item in nft['nftables']:
        if 'docker' in json.dumps(item).lower():
            rows.append({'kind': 'nft', 'evidence_sha256': hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest(), 'exclusive_candidate': _docker_nft(item)})
    for name in _entries('/sys/class/net', 4096):
        if name == 'docker0' or re.fullmatch(r'br-[0-9a-f]{12}', name):
            rows.append({'kind': 'netdev', 'name': name})
    return rows


def inspect_exclusive(profile_document, *, owned=None):
    profile = LocalHostProfile.parse(profile_document)
    require(profile.mode == 'owned', 'ENGINE_OWNED_SELECTION')
    out = {'version': 1, 'complete': True, 'blockers': [], 'tools': {}, 'units': {},
           'root_processes': [], 'docker_footprints': [], 'docker_networks': [],
           'accounts': {'passwd': [], 'group': []}, 'subuid': [], 'subgid': [], 'engine_version': None,'ipv4_forwarding':None,'socket_parent':None}
    deadline = time.monotonic() + 30
    def block(code):
        if code not in out['blockers']: out['blockers'].append(code)
    def probe(key, action):
        try: out[key] = action()
        except (OSError, ValueError, KeyError, IndexError) as exc:
            out['complete'] = False
            block(getattr(exc, 'code', 'ENGINE_OBSERVATION_' + key.upper()))
    def command(args):
        require(args[0] in out['tools'], 'ENGINE_TOOL_UNVERIFIED')
        require(_tool(args[0]) == out['tools'][args[0]], 'ENGINE_TOOL_CHANGED')
        return run_fixed(args, limit=LIMIT, deadline=deadline)
    for path in TOOLS:
        try: out['tools'][path] = _tool(path)
        except (OSError, ValueError): out['complete'] = False; block('ENGINE_TOOL_UNAVAILABLE')
    def version():
        text = command(['/usr/bin/dockerd', '--version'])
        require(re.fullmatch(r'Docker version ' + re.escape(profile.engine_version) + r', build [0-9a-f]+', text) is not None, 'ENGINE_VERSION')
        return profile.engine_version
    probe('socket_parent',lambda:socket_parent(profile))
    probe('engine_version', version)
    probe('ipv4_forwarding',lambda:read_text('/proc/sys/net/ipv4/ip_forward').strip())
    if out['ipv4_forwarding']!='1':block('ENGINE_IPV4_FORWARDING_PREREQUISITE')
    for unit in UNITS:
        def observe_unit(unit=unit):
            raw = command(['/usr/bin/systemctl', 'show', unit, '--no-pager', '--property=LoadState,ActiveState,UnitFileState,FragmentPath'])
            pairs = [line.split('=', 1) for line in raw.splitlines()]
            require(all(len(x) == 2 for x in pairs) and len(pairs) == 4, 'ENGINE_UNIT_FORMAT')
            data = dict(pairs)
            require(set(data) == {'LoadState', 'ActiveState', 'UnitFileState', 'FragmentPath'}, 'ENGINE_UNIT_FORMAT')
            require(data['ActiveState'] in ('inactive', 'active', 'failed', 'activating', 'deactivating', 'reloading'), 'ENGINE_UNIT_STATE')
            return data
        key = 'unit_temp'; probe(key, observe_unit)
        if key in out: out['units'][unit] = out.pop(key)
    probe('root_processes', _processes)
    probe('accounts', _accounts)
    for key in ('subuid', 'subgid'): probe(key, lambda key=key: subordinate(read_text('/etc/' + key)))
    probe('docker_footprints', lambda: _footprints(profile))
    probe('docker_networks', lambda: _networks(command))
    for unit, value in out['units'].items():
        if value['ActiveState'] != 'inactive' or value['UnitFileState'] not in ('disabled', 'masked', ''):
            block('ENGINE_FOREIGN_UNIT')
        if value['LoadState'] not in ('loaded', 'not-found', 'masked'): block('ENGINE_UNIT_AMBIGUOUS')
    if out['root_processes']: block('ENGINE_FOREIGN_PROCESS')
    if out['docker_footprints']: block('ENGINE_FOREIGN_FOOTPRINT')
    if out['docker_networks']: block('ENGINE_FOREIGN_NETWORK')
    if owned is not None:
        try: _reconcile_owned(profile, owned, out, command)
        except (OSError, ValueError, KeyError, IndexError) as exc:
            out['complete'] = False
            block(getattr(exc, 'code', 'ENGINE_OWNED_OBSERVATION'))
    return out


def _receipt_states(value):
    """Read an already-created receipt without constructor _append effects."""
    from .local_host_receipt import PreparationReceipt
    from .local_host_apply import owned_directory
    from .local_engine_prepare import _verify_plan
    _verify_plan(value)
    owned_directory(value['receipt_root'], plan_id=value['plan_id'],
                    operation='engine-receipt-root', owner_uid=0, mode=0o700, create=False)
    r = PreparationReceipt.__new__(PreparationReceipt)
    r.root = Path(value['receipt_root']); r.plan = value; r.owner_uid = 0; r.poisoned = False
    r.fd = os.open(r.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        node = os.fstat(r.fd); r.identity = (node.st_dev, node.st_ino)
        require(node.st_uid == 0 and stat.S_IMODE(node.st_mode) == 0o700, 'ENGINE_RECEIPT_OWNER')
        require(r._read('plan.json') == value, 'ENGINE_RECEIPT_PLAN')
        states = {op['kind']: r.state(i) for i, op in enumerate(value['operations'])}
        # The owner writes in order; later intents without predecessors cannot
        # be used to turn arbitrary resources into an owned installation.
        pending = False
        for op in value['operations']:
            state = states[op['kind']]['state']
            require(not pending or state == 'not-started', 'ENGINE_RECEIPT_ORDER')
            if state != 'confirmed': pending = True
        return states
    finally: r.close()


def _reconcile_owned(profile, value, out, command):
    from .local_engine_prepare import _file
    from .local_host_apply import owned_directory
    from .local_host_profile import canonical
    require(type(value) is dict and value.get('profile') == profile.document(), 'ENGINE_OWNED_PROFILE')
    states = _receipt_states(value)
    def started(kind): return states[kind]['state'] != 'not-started'
    a = value['artifacts']
    # No filtering is committed until *every* ownership check has passed.
    allowed = set()
    if started('directories'):
        for path in (profile.data_root, profile.exec_root):
            if os.path.lexists(path):
                owned_directory(path, plan_id=value['plan_id'], operation={'kind': 'engine-directory', 'path': path},
                                owner_uid=0, mode=0o711, create=False)
                allowed.add(path)
    for kind, path, raw in (('config', a['config_path'], canonical(a['config'])), ('unit', a['unit_path'], a['service'].encode())):
        if os.path.lexists(path):
            require(started(kind), 'ENGINE_UNOWNED_ARTIFACT')
            identity = _file(path, raw)
            if states[kind]['state'] == 'confirmed':
                require(identity == states[kind]['evidence']['identity'], 'ENGINE_ARTIFACT_CHANGED')
    # Accounts/ranges are permitted only with scoped intent and exact values.
    account = value['account']
    for kind, operation in (('passwd', 'account'), ('group', 'group')):
        rows = out['accounts'][kind]
        selected = [r for r in rows if r['name'] == profile.remap_user]
        expected = account if kind == 'passwd' else {'name': profile.remap_user, 'gid': account['gid'], 'members': ''}
        require(not selected or started(operation) and selected == [expected], 'ENGINE_UNOWNED_ACCOUNT')
        require([r for r in rows if r['name'] != profile.remap_user] == value['observed']['accounts'][kind], 'ENGINE_ACCOUNTS_CHANGED')
    for kind in ('subuid', 'subgid'):
        selected = [r for r in out[kind] if r['user'] == profile.remap_user]
        require(not selected or started(kind) and selected == [{'user': profile.remap_user, 'offset': profile.offset, 'size': profile.size}], 'ENGINE_UNOWNED_RANGE')
        require([r for r in out[kind] if r['user'] != profile.remap_user] == value['observed'][kind], 'ENGINE_RANGES_CHANGED')
    verified_daemon = False
    if out['root_processes'] or os.path.lexists(profile.socket):
        require(started('start'), 'ENGINE_UNOWNED_PROCESS')
        _file(a['unit_path'], a['service'].encode()); _file(a['config_path'], canonical(a['config']))
        raw = command(['/usr/bin/systemctl', 'show', a['unit'], '--property=FragmentPath,ActiveState,UnitFileState,MainPID,ControlGroup,DropInPaths', '--no-pager'])
        pairs = [x.split('=', 1) for x in raw.splitlines()]
        require(len(pairs) == 6 and all(len(x) == 2 for x in pairs), 'ENGINE_OWNED_UNIT')
        unit = dict(pairs)
        require(set(unit) == {'FragmentPath', 'ActiveState', 'UnitFileState', 'MainPID', 'ControlGroup', 'DropInPaths'}
                and unit['DropInPaths']=='' and unit['FragmentPath'] == a['unit_path'] and unit['ActiveState'] == 'active'
                and unit['UnitFileState'] == 'enabled' and unit['MainPID'].isascii() and unit['MainPID'].isdecimal()
                and unit['ControlGroup'] == '/system.slice/' + a['unit'], 'ENGINE_OWNED_UNIT')
        daemon = [r for r in out['root_processes'] if r['pid'] == int(unit['MainPID'])]
        require(len(daemon) == 1, 'ENGINE_OWNED_PID')
        d = daemon[0]
        expected_args = ['/usr/bin/dockerd', '--config-file=' + a['config_path']]
        require(d['exe'] == out['tools']['/usr/bin/dockerd']['path']
                and d['arguments_sha256'] == hashlib.sha256('\0'.join(expected_args).encode()).hexdigest()
                and d['arguments'] == {'--config-file': a['config_path']}, 'ENGINE_OWNED_DAEMON')
        require(len(out['root_processes']) == 2, 'ENGINE_OWNED_PROCESS_SET')
        for row in out['root_processes']:
            require(row['uid'] == [0, 0, 0, 0] and row['cgroup'] == '0::' + unit['ControlGroup']
                    and row['netns'] == d['netns'] == os.readlink('/proc/self/ns/net'), 'ENGINE_OWNED_CGROUP')
            if row is not d:
                require(row['exe'] == out['tools']['/usr/bin/containerd']['path']
                        and row['arguments'] == {'--config': profile.exec_root + '/containerd/containerd.toml'}
                        and row['arguments_sha256'] in {hashlib.sha256('\0'.join([binary, '--config', profile.exec_root + '/containerd/containerd.toml']).encode()).hexdigest() for binary in ('containerd', '/usr/bin/containerd')}, 'ENGINE_OWNED_CONTAINERD')
        node = os.lstat(profile.socket)
        require(stat.S_ISSOCK(node.st_mode) and node.st_uid == 0 and node.st_gid == 0
                and not node.st_mode & 0o007, 'ENGINE_OWNED_SOCKET')
        allowed.add(profile.socket); verified_daemon = True
    remaining = [r for r in out['docker_footprints'] if r['path'] not in allowed]
    # Do not erase evidence. Exceptions are separate and available to caller.
    out['owned_evidence'] = {'allowed_paths': sorted(allowed), 'daemon_verified': verified_daemon}
    if not remaining and 'ENGINE_FOREIGN_FOOTPRINT' in out['blockers']: out['blockers'].remove('ENGINE_FOREIGN_FOOTPRINT')
    if verified_daemon:
        if 'ENGINE_FOREIGN_PROCESS' in out['blockers']: out['blockers'].remove('ENGINE_FOREIGN_PROCESS')
        # Explicit FIRST/exclusive-root policy: authenticated pristine baseline
        # plus sole exact owned daemon permits only known Docker firewall chains.
        # An independent concurrent root administrator remains outside this lock.
        if out['docker_networks'] and all(r.get('exclusive_candidate') is True for r in out['docker_networks']):
            if 'ENGINE_FOREIGN_NETWORK' in out['blockers']: out['blockers'].remove('ENGINE_FOREIGN_NETWORK')


DOCKER_CHAINS = {'DOCKER', 'DOCKER-USER', 'DOCKER-FORWARD', 'DOCKER-BRIDGE',
                 'DOCKER-CT', 'DOCKER-INTERNAL', 'DOCKER-ISOLATION-STAGE-1',
                 'DOCKER-ISOLATION-STAGE-2', 'DOCKER-INGRESS'}

def _docker_rule(line):
    if line.startswith(':'):
        return line.split()[0][1:] in DOCKER_CHAINS
    parts = line.split()
    if len(parts) < 3 or parts[0] != '-A': return False
    if parts[1] in DOCKER_CHAINS: return True
    # Only Docker's standard hooks into builtin chains; arbitrary custom-chain
    # references are not owned simply because they mention Docker.
    return parts[1] in {'FORWARD', 'PREROUTING', 'OUTPUT', 'POSTROUTING'} and any(
        parts[i] in ('-j', '-g') and parts[i+1] in DOCKER_CHAINS for i in range(len(parts)-1))


def _docker_nft(item):
    if type(item) is not dict or len(item) != 1: return False
    kind, value = next(iter(item.items()))
    if type(value) is not dict or value.get('family') not in ('ip', 'ip6'): return False
    if value.get('table') not in ('filter', 'nat') and not (kind=='table' and value.get('name') in ('filter','nat')): return False
    if kind == 'chain': return value.get('name') in DOCKER_CHAINS
    if kind != 'rule': return False
    if value.get('chain') in DOCKER_CHAINS: return True
    if value.get('chain') not in {'FORWARD','PREROUTING','OUTPUT','POSTROUTING'}: return False
    return any(type(e) is dict and any(type(e.get(k)) is dict and e[k].get('target') in DOCKER_CHAINS
                                      for k in ('jump','goto')) for e in value.get('expr', []))
