"""Disposable native backend; root provisioning, trusted Supervisor observation.

Existing prepared storage is a prerequisite, not a declaration of qualification.
This module never formats a disk, rewrites provider state, or repairs permissions
on Project roots. No production launcher or #62 fixture profile is changed.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from contextlib import contextmanager
import socket
import ctypes
import subprocess
import secrets
import shutil
import time
from decimal import Decimal

from .docker_fixture import DockerFixtureBackend
from .guest_fixture import guard, project_attributes, canonical_firewall, firewall_document
from .lifecycle import BackendUnknown, LifecycleError, OwnershipConflict, FixtureSpec, Supervisor
from .native_image_package import REFERENCE, canonical
from .native_pi_recipe import read_manifest

STORAGE = Path('/mnt/uas-native')
ENDPOINTS = Path('/run/uas-native')
PROJECT_ID = 301
LEVEL = 's0:c301,c302'
HOST_UID = 165533
RUNTIME_UID = 165532
HUB_UID = 165531
BROKER_UID = 165534
HUB_COMMAND = ['/opt/uas/bin/tini', '--', '/usr/bin/python3', '-m', 'uas.workstation_service']
ID = re.compile(r'[0-9a-f]{64}\Z')


def require(value, code):
    if not value:
        raise LifecycleError('NATIVE_' + code)


def exact(value, fields, code):
    require(type(value) is dict and set(value) == set(fields), code)
    return value


def fixed_docker(arguments, *, timeout, missing_ok=False):
    """Fixed trusted Engine endpoint; no ambient Docker context/config override."""
    try:
        result = subprocess.run(['/usr/bin/docker','--host','unix:///run/docker.sock',*arguments],
            capture_output=True,text=True,timeout=timeout,check=False,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/nonexistent',
                 'DOCKER_CONFIG':'/nonexistent'})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BackendUnknown() from error
    if len(result.stdout)>262144 or len(result.stderr)>65536: raise BackendUnknown()
    if result.returncode:
        if missing_ok and result.returncode == 1 and len(arguments)==4 and arguments[:2]==['inspect','--type']:
            kind,name=arguments[2:]
            allowed={f'Error: No such {kind}: {name}',f'Error response from daemon: No such {kind}: {name}',
                     f'Error: No such object: {name}'}
            if kind=='volume': allowed.add(f'Error response from daemon: get {name}: no such volume')
            if kind in ('container','volume') and result.stderr.strip().casefold() in {s.casefold() for s in allowed}:
                return None
        raise BackendUnknown()
    return result.stdout


def command(*arguments, input=None, deadline=None):
    # Unlike the historical fixture helper, diagnostics on stderr also deny an
    # observation: e.g. xfs_quota skipping an inode cannot count as a clean tree.
    try:
        timeout=30 if deadline is None else min(30,deadline-time.monotonic())
        require(timeout>0,'DEADLINE')
        result=subprocess.run(arguments,input=input,capture_output=True,text=True,timeout=timeout,check=False,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
    except (OSError,subprocess.TimeoutExpired) as error: raise BackendUnknown() from error
    if result.returncode or result.stderr or len(result.stdout)>262144: raise BackendUnknown()
    return result.stdout


def directory_identity(path):
    """Trusted control namespace observation, not an adversarial rename lease."""
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'PATH_BINDING')
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode), 'PATH_BINDING')
    return [info.st_dev, info.st_ino]


def bind_options(host, expected):
    values=host.get('Mounts')
    require(type(values) is list and len(values)==len(expected),'BIND_OPTIONS')
    actual=[]
    for mount in values:
        require(type(mount) is dict and mount.get('Type')=='bind'
                and type(mount.get('ReadOnly',False)) is bool
                and mount.get('BindOptions',{}).get('NonRecursive') is True
                and mount['BindOptions'].get('Propagation')=='rprivate','BIND_OPTIONS')
        actual.append((mount.get('Source'),mount.get('Target'),not mount.get('ReadOnly',False)))
    require(len(set(actual))==len(expected) and set(actual)==set(expected),'BIND_OPTIONS')


def parse_gate_quota(report, hard_bytes):
    require(type(report) is str and len(report)<=262144 and type(hard_bytes) is int
        and hard_bytes>0 and hard_bytes%1024==0,'GATE_QUOTA_REPORT')
    rows=[line.split() for line in report.splitlines() if line.split() and line.split()[0]=='#'+str(PROJECT_ID)]
    require(len(rows)==1 and len(rows[0])==6,'GATE_QUOTA_REPORT')
    row=rows[0]
    require(all(re.fullmatch(r'[0-9]+',v) for v in row[1:4]),'GATE_QUOTA_REPORT')
    used,soft,hard=(int(v) for v in row[1:4])
    require(hard*1024==hard_bytes and used<=hard and soft<=hard,'GATE_QUOTA_REPORT')
    return {'used_bytes':used*1024,'hard_bytes':hard_bytes}


def validate_native_container(state,value,*,image_id,image_reference,limits,nano_cpus,mounts,level=None):
    """Pure exact provider-connected declaration predicate; no admission authority."""
    level = LEVEL if level is None else level
    try:
        config, host = value['Config'], value['HostConfig']
        require(value['Image'] == image_id and config['Image'] == image_reference
                and config['User'] == '65532:65532' and config['Entrypoint'] == ['/bin/sleep']
                and config['Cmd'] == ['infinity'] and config['Tty'] is False, 'IMAGE_COMMAND')
        require(host['ReadonlyRootfs'] is True and host['Privileged'] is False
                and host['CapDrop'] == ['ALL'] and host['CapAdd'] in (None, [])
                and host.get('GroupAdd') in (None,[]), 'CONFINEMENT')
        require([s.replace('no-new-privileges=true','no-new-privileges') for s in host['SecurityOpt']]
                == ['no-new-privileges', 'label=level:' + level], 'SECURITY_OPTIONS')
        require(host['NetworkMode'] == names(state)[0]
                and set(value['NetworkSettings']['Networks']) == {names(state)[0]}, 'NETWORK_POLICY')
        require(all(host[k] == v for k, v in {'PidMode':'', 'IpcMode':'private', 'UTSMode':'',
                'UsernsMode':'', 'CgroupnsMode':'private'}.items()), 'NAMESPACES')
        require(all(host[k] in (None, []) for k in ('Devices','DeviceRequests','DeviceCgroupRules'))
                and host['PublishAllPorts'] is False and host['PortBindings'] in (None, {}), 'DEVICES_PORTS')
        require(host['RestartPolicy'] == {'Name':'no','MaximumRetryCount':0}, 'RESTART_POLICY')
        expected = {'Memory':limits['memory_bytes'], 'MemorySwap':limits['memory_bytes'],
                    'NanoCpus':nano_cpus, 'PidsLimit':limits['pids']}
        require(all(type(host[k]) is int and host[k] == v for k, v in expected.items()), 'LIMITS')
        require(host['LogConfig'] == {'Type':'local','Config':{'max-size':str(limits['log_bytes']),
                'max-file':'1','compress':'false'}}, 'LOG_LIMIT')
        require({'/proc/kcore','/proc/keys','/proc/timer_list','/sys/firmware'} <= set(host['MaskedPaths'])
                and {'/proc/bus','/proc/fs','/proc/irq','/proc/sys','/proc/sysrq-trigger'} <=
                set(host['ReadonlyPaths']), 'KERNEL_MASKS')
        require(value['ProcessLabel'] == 'system_u:system_r:container_t:' + level
                and value['MountLabel'] == 'system_u:object_r:container_file_t:' + level, 'MCS_LABELS')
        actual = value['Mounts']
        require(type(actual) is list and len(actual) == len(mounts)
                and all(m['Type'] == 'bind' and type(m['RW']) is bool and m['Propagation'] == 'rprivate'
                        for m in actual)
                and {(m['Source'],m['Destination'],m['RW']) for m in actual} == set(mounts), 'MOUNTS')
        require(type(value['State']['Running']) is bool, 'RUNNING_STATE')
        bind_options(host,mounts)
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise BackendUnknown('native container observation incomplete') from error
    return True

class NativeBoundaryProfile:
    """Exact finite installation declarations, independent of effect adapters."""

    def __init__(self, plan, boundary, hub):
        self.room = deepcopy(plan.room)
        self.nonce = plan.installation['nonce']
        self.config_digest = plan.config_digest
        self.root = STORAGE / self.nonce
        self.state_root = Path(self.room['state_root'])
        require(self.state_root == self.root / 'state' / self.room['id'], 'STATE_ROOT')
        roots = self.room['project']['roots']
        self.paths = {k: roots[k] for k in ('repo', 'workspace', 'reference', 'checkouts')}
        self.paths['runtime'] = str(self.state_root / 'runtime')
        require(all(Path(p).is_relative_to(self.root) and Path(p) != self.root
                    and re.fullmatch(r'/[A-Za-z0-9_./-]+',p)
                    for p in self.paths.values()), 'PROJECT_ROOT')
        require(len(set(self.paths.values())) == 5, 'PROJECT_ROOT')
        exact(boundary, ('version', 'nonce', 'room_id', 'project_id', 'level', 'root_identity', 'paths'),
              'BOUNDARY_MANIFEST')
        require(type(boundary['version']) is int and boundary['version'] == 1
                and boundary['nonce'] == self.nonce and boundary['room_id'] == self.room['id']
                and type(boundary['project_id']) is int and boundary['project_id'] == PROJECT_ID
                and boundary['level'] == LEVEL, 'BOUNDARY_MANIFEST')
        require(type(boundary['paths']) is dict and set(boundary['paths']) == set(self.paths),
                'BOUNDARY_MANIFEST')
        for key, path in self.paths.items():
            record = exact(boundary['paths'][key], ('path', 'identity'), 'BOUNDARY_PATH')
            require(record['path'] == path, 'BOUNDARY_PATH')
        for identity in [boundary['root_identity'], *(r['identity'] for r in boundary['paths'].values())]:
            require(type(identity) is list and len(identity) == 2
                    and all(type(v) is int and v >= 0 for v in identity), 'BOUNDARY_IDENTITY')
        self.boundary = deepcopy(boundary)
        exact(hub, ('version', 'image_reference', 'image_id', 'entrypoint'), 'HUB_MANIFEST')
        require(type(hub['version']) is int and hub['version'] == 1
                and type(hub['image_reference']) is str and REFERENCE.fullmatch(hub['image_reference'])
                and type(hub['image_id']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', hub['image_id'])
                and hub['entrypoint'] == HUB_COMMAND, 'HUB_MANIFEST')
        self.hub = deepcopy(hub)
        self.limits = deepcopy(self.room['resources'])
        require(type(self.limits['disk_bytes']) is int and self.limits['disk_bytes'] > 0
                and self.limits['disk_bytes'] % 1024 == 0, 'EXACT_DISK_QUOTA_REQUIRED')
        nano = Decimal(str(self.limits['cpu'])) * 1000000000
        require(nano == nano.to_integral_value(), 'EXACT_CPU_LIMIT_REQUIRED')
        self.nano_cpus = int(nano)
        checked = plan.check()
        require(not checked['missing_prerequisites'], 'IMAGE_MANIFESTS_REQUIRED')
        self.image_id = checked['images']['pi']['image_id']
        self.image_reference = checked['images']['pi']['image_reference']
        self.git_manifest = None
        self.git_plan = None
        if 'git_manifest' in plan.installation:
            from .native_git_resources import selection
            from .kernel_origin import OriginDenied
            try:self.git_manifest = selection(plan)
            except (OSError,ValueError,OriginDenied) as error:
                raise LifecycleError('NATIVE_GIT_PREPARED_IMAGE_UNAVAILABLE') from error
            require(self.git_manifest['image_id']==self.image_id, 'GIT_IMAGE_PAIRING')
            self.git_plan = plan
        self.gate_manifest = None
        self.gate_plan = None
        if 'gate_manifest' in plan.installation:
            from .native_gate_resources import selection
            self.gate_manifest = selection(plan)
            require(self.git_manifest is not None, 'GATE_GIT_PROFILE_REQUIRED')
            self.gate_plan = plan
        self.digest = hashlib.sha256(canonical({'boundary': boundary, 'hub': hub,
            'config': self.config_digest, 'images': checked['images'],
            **({'git':self.git_manifest} if self.git_manifest is not None else {}),
            **({'gate':self.gate_manifest} if self.gate_manifest is not None else {})})).hexdigest()

    @classmethod
    def read(cls, plan):
        refs = [plan.installation[name] for name in ('boundary_manifest', 'hub_manifest')]
        return cls(plan, *(read_manifest(ref['path'], ref['sha256']) for ref in refs))

    def spec(self):
        return FixtureSpec(self.room['id'], self.room['project']['id'],
            tuple(self.paths[k] for k in ('repo', 'workspace', 'reference', 'checkouts')),
            self.image_id, 'sha256:' + self.config_digest, 'sha256:' + self.digest)

    @property
    def storage(self): return STORAGE

    @property
    def level(self): return LEVEL

    @property
    def project_id(self): return PROJECT_ID

    def guard(self, *, require_selinux=True):
        guard(self.nonce, require_selinux=require_selinux)

    def storage_ancestors(self): return (self.storage, self.root, self.root/'state')

    def observe_storage(self):
        self.guard()
        require(directory_identity(self.root) == self.boundary['root_identity'], 'ROOT_IDENTITY')
        require(self.root.stat().st_uid == 0 and not self.root.stat().st_mode & 0o022, 'ROOT_OWNER')
        for ancestor in self.storage_ancestors():
            info=ancestor.stat()
            require(info.st_uid==0 and not info.st_mode & 0o022 and info.st_mode & 0o001,
                    'PREPARED_CONTROL_TRAVERSAL')
        require(command('stat', '-f', '-c', '%T', str(self.storage)).strip() == 'xfs', 'XFS_REQUIRED')
        quota = command('xfs_quota', '-x', '-c', 'state -p', str(self.storage))
        require('Accounting: ON' in quota and 'Enforcement: ON' in quota, 'QUOTA_REQUIRED')
        report = command('xfs_quota', '-x', '-c', 'report -p -b -n -N', str(self.storage))
        rows = [line.split() for line in report.splitlines()
                if line.split() and line.split()[0] == '#' + str(self.project_id)]
        require(len(rows) == 1 and len(rows[0]) >= 4
                and rows[0][3] == str(self.limits['disk_bytes'] // 1024), 'QUOTA_DRIFT')
        for key, path in self.paths.items():
            require(directory_identity(path) == self.boundary['paths'][key]['identity'], 'PATH_IDENTITY')
            info = Path(path).stat()
            require(info.st_dev == self.storage.stat().st_dev, 'QUOTA_FILESYSTEM')
            require(info.st_uid == RUNTIME_UID and info.st_gid == RUNTIME_UID, 'PATH_OWNER')
            require(project_attributes(path) == (self.project_id, True), 'PROJECT_QUOTA')
            label = command('stat', '-c', '%C', path).strip()
            require(label == 'system_u:object_r:container_file_t:' + self.level, 'PATH_LABEL')
            output=command('xfs_quota','-x','-D','/dev/null','-P','/dev/null','-c',
                f'project -c -p {path} {self.project_id}',str(self.storage))
            require(output.splitlines()==[f'Checking project {self.project_id} (path {path})...',
                f'Processed 1 (/dev/null and cmdline) paths for project {self.project_id} with recursion depth infinite (-1).'],
                'EXISTING_TREE_QUOTA_DRIFT')
        # The underlying namespace is root-managed; initial stat comparisons do
        # not attest SQLite/file descriptors against hostile path replacement.
        return True


def names(state):
    instance = state['instance_id']
    require(type(instance) is str and re.fullmatch(r'[0-9a-f]{32}', instance), 'INSTANCE')
    return 'uas-native-' + instance, 'uan' + instance[:12], 'uan_' + instance


def firewall(state, nonce):
    # Reuse the existing fixed deny-set/packet expressions, with an independent
    # table/bridge namespace. No caller-supplied nft expression is accepted.
    instance = state['instance_id']; _, bridge, table = names(state)
    substitutions = {'uas' + instance[:12]: bridge, 'uas_' + instance: table}
    def rewrite(value):
        if type(value) is dict: return {k: rewrite(v) for k, v in value.items()}
        if type(value) is list: return [rewrite(v) for v in value]
        return substitutions.get(value, value) if type(value) is str else value
    return rewrite(firewall_document(state, nonce))


class NativeQualificationBackend(DockerFixtureBackend):
    """Distinct opt-in profile; inherited methods supply exact ownership only."""
    LABEL = 'im.puglab.uas.native-qualification'

    def __init__(self, profile):
        require(type(profile) is NativeBoundaryProfile, 'PROFILE_REQUIRED')
        super().__init__(executable='/usr/bin/docker', timeout=20)
        self.profile = profile
        self.listeners = []
        self.instance = None

    @property
    def storage(self): return getattr(self.profile, 'storage', STORAGE)

    @property
    def endpoints(self): return getattr(self.profile, 'endpoints', ENDPOINTS)

    @property
    def level(self): return getattr(self.profile, 'level', LEVEL)

    @property
    def project_id(self): return getattr(self.profile, 'project_id', PROJECT_ID)

    @property
    def hub_command(self): return getattr(self.profile, 'hub_command', HUB_COMMAND)

    def _guard(self, *, require_selinux=True):
        guard(self.profile.nonce, require_selinux=require_selinux)

    def _subnet(self): return getattr(self.profile, 'subnet', '10.90.78.0/24')
    def _gateway(self): return getattr(self.profile, 'gateway', '10.90.78.1')

    def name(self, state, kind):
        require(kind in ('volume', 'container'), 'RESOURCE_KIND')
        return names(state)[0] + ('-anchor' if kind == 'volume' else '')

    def _run(self, arguments, *, missing_ok=False):
        return fixed_docker(arguments, timeout=self.timeout, missing_ok=missing_ok)

    def inspect(self, state, kind):
        self._binding(state)
        value = super().inspect(state, kind)
        if kind == 'volume' and value is None:
            require(self._network(state) is None and self._firewall(state) is None
                    and self._hub(state) is None and not os.path.lexists(self.endpoints/state['instance_id']),
                    'MISSING_ANCHOR_WITH_LEFTOVERS')
        return value

    def _inspect_object(self,state,kind):
        value=super()._inspect_object(state,kind)
        if value is not None and kind=='container':
            require(type(value.get('Id')) is str and ID.fullmatch(value['Id']),'CONTAINER_IDENTITY')
        return value

    def layout(self, state):
        names(state)
        root = self.profile.state_root / 'instances' / state['instance_id'] / 'native'
        result={name: root / name for name in ('supervisor', 'hub', 'broker')}
        result.update({name:self.endpoints/state['instance_id']/name for name in ('peer','control')})
        if self.profile.git_manifest is not None:
            result['git']=self.endpoints/state['instance_id']/'git'
            result['git-broker']=root/'git-broker'
        if getattr(self.profile,'gate_manifest',None) is not None:
            from .native_gate_resources import paths
            selected=paths(self.profile.gate_plan,state)
            result['gate']=selected['endpoint_root']
            result['gate-targets']=selected['scratch_root']
        return result

    def _endpoint_record(self,state):
        return {'version':1,'nonce':self.profile.nonce,'instance':state['instance_id'],
                'profile_digest':self.profile.digest,'path':str(self.endpoints/state['instance_id'])}

    def _remove_endpoints(self,state):
        root=self.endpoints/state['instance_id']
        if not os.path.lexists(root):return
        info=root.stat()
        require(root.resolve()==root and info.st_uid==0 and not info.st_mode & 0o022,'ENDPOINT_OWNERSHIP')
        descriptor=os.open(root/'owner.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            info=os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_mode & 0o077==0
                    and info.st_nlink==1 and 0<info.st_size<=4096,'ENDPOINT_OWNERSHIP')
            value=json.loads(os.read(descriptor,4097))
        finally:os.close(descriptor)
        require(value=={**self._endpoint_record(state),'identity':directory_identity(root)},'ENDPOINT_OWNERSHIP')
        shutil.rmtree(root)  # Exact marked instance only; never follow symlinks.

    def _binding(self, state):
        require(state['room_id'] == self.profile.room['id']
                and state['spec'] == self.profile.spec().document(), 'LIFECYCLE_BINDING')
        names(state)
        require(self.instance is None or self.instance == state['instance_id'], 'INSTANCE_REPLACED')
        self.instance = state['instance_id']

    def _network(self, state):
        name, bridge, _ = names(state)
        found = self._run(['network', 'ls', '--filter', 'name=^' + name + '$', '--format', '{{.Name}}'])
        if not found.strip(): return None
        require(found.splitlines() == [name], 'NETWORK_IDENTITY')
        values = json.loads(self._run(['network', 'inspect', name]))
        require(type(values) is list and len(values) == 1, 'NETWORK_IDENTITY')
        value = values[0]
        require(value.get('Name') == name and value.get('Labels') == self._labels(state, 'network'),
                'NETWORK_OWNERSHIP')
        require(type(value.get('Id')) is str and ID.fullmatch(value['Id']),'NETWORK_IDENTITY')
        return value

    def _firewall(self, state):
        table = names(state)[2]
        found = [x['table'] for x in json.loads(command('nft', '-j', 'list', 'tables'))['nftables']
                 if 'table' in x and x['table']['family'] == 'inet' and x['table']['name'] == table]
        if not found: return None
        require(len(found) == 1, 'FIREWALL_IDENTITY')
        value = json.loads(command('nft', '-j', 'list', 'table', 'inet', table))
        owners = [x['table'].get('comment') for x in value['nftables'] if 'table' in x]
        require(owners == ['uas:' + self.profile.nonce + ':' + state['instance_id']], 'FIREWALL_OWNERSHIP')
        return value

    def _network_policy(self, state):
        value = self._network(state); name, bridge, _ = names(state)
        require(value is not None and value.get('Driver') == 'bridge'
                and value.get('Internal') is False and value.get('EnableIPv6') is False
                and value.get('IPAM', {}).get('Config') == [{'Subnet': self._subnet(), 'Gateway': self._gateway()}]
                and value.get('Options') == {'com.docker.network.bridge.name': bridge,
                    'com.docker.network.bridge.enable_ip_masquerade': 'true',
                    'com.docker.network.bridge.gateway_mode_ipv4': 'nat'}, 'NETWORK_POLICY')
        observed = self._firewall(state)
        require(observed is not None and canonical_firewall(observed) ==
                canonical_firewall(firewall(state, self.profile.nonce)), 'FIREWALL_POLICY')

    def _ensure_network(self, state):
        require(self._inspect_object(state, 'volume') is not None, 'OWNERSHIP_ANCHOR_REQUIRED')
        name, bridge, _ = names(state)
        if self._network(state) is None:
            self._run(['network', 'create', '--driver', 'bridge', '--subnet', self._subnet(),
                '--gateway', self._gateway(), '--opt', 'com.docker.network.bridge.name=' + bridge,
                '--opt', 'com.docker.network.bridge.enable_ip_masquerade=true',
                '--opt', 'com.docker.network.bridge.gateway_mode_ipv4=nat',
                *self._label_args(state, 'network'), name])
        if self._firewall(state) is None:
            command('nft', '-j', '-f', '-', input=json.dumps(firewall(state, self.profile.nonce)))
        self._network_policy(state)

    def _label_args(self, state, kind):
        return [x for k, v in self._labels(state, kind).items() for x in ('--label', k + '=' + v)]

    def mounts(self, state):
        values = [(p, p, key != 'reference') for key, p in self.profile.paths.items()] + [
            (str(self.layout(state)['peer']), str(self.layout(state)['peer']), False)]
        if self.profile.git_manifest is not None:
            from .native_git_resources import git_mounts
            values += [(m.source,m.destination,not m.read_only) for m in git_mounts(self.profile.git_plan,state)]
        if getattr(self.profile,'gate_manifest',None) is not None:
            from .native_gate_resources import gate_mounts
            values += [(m.source,m.destination,False) for m in gate_mounts(self.profile.gate_plan,state)]
        return values

    def container_arguments(self, state):
        self._binding(state)
        limits = self.profile.limits
        mounts = [x for source, destination, writable in self.mounts(state) for x in ('--mount',
            'type=bind,source=' + source + ',target=' + destination + ',bind-recursive=disabled,bind-propagation=rprivate'
            + ('' if writable else ',readonly'))]
        return ['create', '--name', self.name(state, 'container'), *self._label_args(state, 'container'),
            '--user', '65532:65532', '--read-only', '--network', names(state)[0],
            '--ipc', 'private', '--cgroupns', 'private', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--security-opt', 'label=level:' + self.level,
            '--memory', str(limits['memory_bytes']), '--memory-swap', str(limits['memory_bytes']),
            '--cpus', str(limits['cpu']), '--pids-limit', str(limits['pids']),
            '--log-driver', 'local', '--log-opt', 'max-size=' + str(limits['log_bytes']),
            '--log-opt', 'max-file=1', '--log-opt', 'compress=false',
            *mounts, '--entrypoint', '/bin/sleep', self.profile.image_reference, 'infinity']

    def create(self, state, kind):
        self._guard(); self._binding(state); self.profile.observe_storage()
        if self.inspect(state, kind) is not None: return
        if kind == 'volume':
            self._run(['volume', 'create', *self._label_args(state, kind), self.name(state, kind)])
            self._prepare_layout(state)
        elif kind == 'container':
            self._ensure_network(state)
            require(all(path.is_dir() for path in self.layout(state).values()), 'CONTROL_LAYOUT_REQUIRED')
            self._run(self.container_arguments(state))
        else:
            raise LifecycleError('NATIVE_RESOURCE_KIND')

    def admit(self, state):
        self._guard(); self._binding(state); self.profile.observe_storage()
        self._network_policy(state)
        value = self._inspect_object(state, 'container')
        require(value is not None, 'CONTAINER_REQUIRED')
        security = json.loads(self._run(['info', '--format', '{{json .SecurityOptions}}']))
        require(self._run(['version','--format','{{.Server.Version}}']).strip()=='29.8.2','ENGINE_PROFILE')
        require(type(security) is list and {'name=seccomp,profile=builtin', 'name=selinux', 'name=userns'}
                <= set(security), 'DAEMON_CONFINEMENT')
        require(self._run(['info', '--format', '{{.DockerRootDir}}']).strip() ==
                '/var/lib/docker/100000.100000', 'USERNS_MAPPING')
        for name in ('subuid', 'subgid'):
            rows = [line for line in Path('/etc/' + name).read_text().splitlines() if line.startswith('uas-remap:')]
            require(rows == ['uas-remap:100000:65536'], 'USERNS_MAPPING')
        self.validate_container(state, value)
        if value['State']['Running']:
            pid = value['State'].get('Pid')
            require(type(pid) is int and pid > 0, 'KERNEL_MAPPING')
            for name in ('uid_map', 'gid_map'):
                require(Path('/proc/' + str(pid) + '/' + name).read_text().split() ==
                        ['0', '100000', '65536'], 'KERNEL_MAPPING')
        return value

    def validate_container(self, state, value):
        return validate_native_container(state,value,image_id=self.profile.image_id,
            image_reference=self.profile.image_reference,limits=self.profile.limits,
            nano_cpus=self.profile.nano_cpus,mounts=self.mounts(state),level=self.level)

    def stop(self, state):
        self._guard(require_selinux=False)
        return super().stop(state)

    def stop_hub(self,state):
        self._guard(require_selinux=False);self._binding(state)
        hub=self._hub(state)
        if hub is None:return
        if hub['State']['Running']:self._run(['stop','--time','3',hub['Id']])
        current=self._hub(state)
        require(current is not None and current['Id']==hub['Id'] and current['State']['Running'] is False,
                'HUB_STOP_UNCERTAIN')

    def remove(self, state, kind):
        self._guard(require_selinux=False)
        if kind == 'volume':
            require(self.inspect(state, 'container') is None, 'WORKSTATION_REMAINS')
            hub = self._hub(state)
            if hub is not None:
                if hub['State']['Running']: self._run(['stop', '--time', '3', hub['Id']])
                current = self._hub(state)
                require(current is not None and current['Id'] == hub['Id'] and
                        current['State']['Running'] is False, 'HUB_CLEANUP_UNCERTAIN')
                self._run(['rm', current['Id']])
            network = self._network(state)
            if network is not None: self._run(['network', 'rm', network['Id']])
            if self._firewall(state) is not None: command('nft', 'delete', 'table', 'inet', names(state)[2])
            self._remove_endpoints(state)
        return super().remove(state, kind)

    def _prepare_layout(self, state):
        layout = self.layout(state); parent = layout['supervisor'].parent
        # Canonical Supervisor persisted ownership before this create. A stale
        # partial attempt must be destroyed/reconciled, never silently adopted.
        parent.mkdir(mode=0o711)
        os.chown(parent, 0, 0);os.chmod(parent,0o711)
        # Unix socket addresses cannot use the long canonical state path.
        # This separate short namespace is owned by the same cleanup anchor.
        self.endpoints.mkdir(mode=0o755,exist_ok=True)
        info=self.endpoints.stat()
        require(self.endpoints.resolve()==self.endpoints and info.st_uid==0 and not info.st_mode & 0o022,'ENDPOINT_ROOT')
        endpoint_root=self.endpoints/state['instance_id']
        endpoint_root.mkdir(mode=0o711);os.chmod(endpoint_root,0o711)
        record={**self._endpoint_record(state),'identity':directory_identity(endpoint_root)}
        descriptor=os.open(endpoint_root/'owner.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            raw=canonical(record);require(os.write(descriptor,raw)==len(raw),'ENDPOINT_RECORD_INCOMPLETE')
            os.fsync(descriptor)
        finally:os.close(descriptor)
        for key, path in layout.items():
            mode, uid, gid = ((0o700, HOST_UID, HOST_UID) if key == 'supervisor' else
                (0o700, BROKER_UID, BROKER_UID) if key in ('broker','git-broker') else
                (0o711, HOST_UID, HOST_UID) if key == 'gate-targets' else
                (0o710, HOST_UID, 165530) if key == 'gate' else
                (0o2770, HOST_UID, HUB_UID) if key == 'hub' else
                (0o710, HOST_UID, RUNTIME_UID if key in ('peer','git') else HUB_UID))
            path.mkdir(mode=mode); os.chown(path, uid, gid); os.chmod(path, mode)
            if key not in ('supervisor','broker','git-broker'): command('chcon', '-t', 'container_file_t', '-l', self.level, str(path))
        if getattr(self.profile,'gate_manifest',None) is not None:
            from .native_gate_resources import paths
            selected=paths(self.profile.gate_plan,state)
            for key in ('journal_root','launch_journal_root'):
                selected[key].mkdir(mode=0o700)
                os.chown(selected[key],HOST_UID,HOST_UID);os.chmod(selected[key],0o700)
            # Assign only these freshly created owned trees, never Project data.
            for key in ('scratch_root','journal_root','launch_journal_root'):
                path=selected[key]
                require(path.stat().st_dev==self.storage.stat().st_dev,'GATE_QUOTA_FILESYSTEM')
                command('xfs_quota','-x','-D','/dev/null','-P','/dev/null','-c',
                    f'project -s -p {path} {self.project_id}',str(self.storage))
                require(project_attributes(path)==(self.project_id,True),'GATE_QUOTA_PROVISION')
            record={'version':1,'instance':state['instance_id'],'profile_digest':self.profile.digest,
                'paths':{key:{'path':str(selected[key]),'identity':directory_identity(selected[key])}
                    for key in ('scratch_root','journal_root','launch_journal_root')}}
            fd=os.open(endpoint_root/'gate-scratch.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                raw=canonical(record);require(os.write(fd,raw)==len(raw),'GATE_OWNERSHIP_WRITE');os.fsync(fd)
            finally:os.close(fd)
        # Gate socket is deliberately NOT created here: its actual creator must
        # be Supervisor UID/GID165533 so bootstrap SO_PEERCRED is truthful.
        for path,group in ((layout['peer'] / 'pi.sock',RUNTIME_UID),(layout['control'] / 'hub.sock',HUB_UID)):
            self.listeners.append(labeled_listener(path,group,level=self.level))
        if self.profile.git_manifest is not None:
            from .native_git_resources import prepare_views
            journal=layout['supervisor']/'git-launches'
            journal.mkdir(mode=0o700);os.chown(journal,HOST_UID,HOST_UID);os.chmod(journal,0o700)
            prepare_views(self.profile.git_plan,state)
            for name in ('git-views','git-fixed','git-workspace'):
                command('chcon','-R','-t','container_file_t','-l',self.level,str(endpoint_root/name))
            for name in ('request.sock','worker.sock'):
                self.listeners.append(labeled_listener(layout['git']/name,RUNTIME_UID,listen=name!='request.sock',level=self.level))

    def observe_gate_quota(self,state,*,deadline):
        """Fixed read-only current usage, outside lifecycle/Room locks."""
        require(type(deadline) in (int,float) and time.monotonic()<deadline,'DEADLINE')
        self._guard(require_selinux=False);self._binding(state)
        require(command('getenforce',deadline=deadline).strip()=='Enforcing'
            and Path('/sys/fs/selinux/enforce').read_text().strip()=='1','SELINUX_REQUIRED')
        require(self.profile.gate_manifest is not None,'GATE_PROFILE_REQUIRED')
        from .native_gate_resources import paths
        selected=paths(self.profile.gate_plan,state)
        fd=os.open(self.endpoints/state['instance_id']/'gate-scratch.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            node=os.fstat(fd)
            require(stat.S_ISREG(node.st_mode) and node.st_uid==0 and stat.S_IMODE(node.st_mode)==0o600
                and node.st_nlink==1 and 0<node.st_size<=4096,'GATE_OWNERSHIP')
            raw=os.read(fd,4097);record=json.loads(raw)
            require(canonical(record)==raw,'GATE_OWNERSHIP')
        finally:os.close(fd)
        def observe():
            identities={}
            for key in ('scratch_root','journal_root','launch_journal_root'):
                path=selected[key];node=path.stat(follow_symlinks=False)
                require(path.resolve()==path and stat.S_ISDIR(node.st_mode) and node.st_uid==HOST_UID
                    and node.st_gid==HOST_UID and stat.S_IMODE(node.st_mode)==(0o711 if key=='scratch_root' else 0o700)
                    and node.st_dev==self.storage.stat().st_dev and project_attributes(path)==(self.project_id,True), 'GATE_QUOTA_RESOURCE')
                identities[key]={'path':str(path),'identity':[node.st_dev,node.st_ino]}
            require(record=={'version':1,'instance':state['instance_id'],'profile_digest':self.profile.digest,
                'paths':identities},'GATE_OWNERSHIP')
            return identities
        before=observe()
        require(command('stat','-f','-c','%T',str(self.storage),deadline=deadline).strip()=='xfs','XFS_REQUIRED')
        status=command('xfs_quota','-x','-c','state -p',str(self.storage),deadline=deadline)
        require('Accounting: ON' in status and 'Enforcement: ON' in status,'QUOTA_REQUIRED')
        result=parse_gate_quota(command('xfs_quota','-x','-c','report -p -b -n -N',str(self.storage),deadline=deadline),
            self.profile.limits['disk_bytes'])
        require(observe()==before,'GATE_QUOTA_RESOURCE_CHANGED')
        require(time.monotonic()<deadline,'DEADLINE')
        return {**result,'scratch_identity':before['scratch_root']['identity']}

    def _hub(self, state):
        name = names(state)[0] + '-hub'
        raw = self._run(['inspect','--type','container',name], missing_ok=True)
        if raw is None: return None
        values = json.loads(raw)
        require(type(values) is list and len(values) == 1, 'HUB_OBSERVATION')
        value = values[0]
        require(value.get('Name', '').lstrip('/') == name
                and value.get('Config', {}).get('Labels') == self._labels(state, 'hub'), 'HUB_OWNERSHIP')
        require(type(value.get('Id')) is str and ID.fullmatch(value['Id'])
                and type(value.get('State', {}).get('Running')) is bool, 'HUB_OBSERVATION')
        return value

    def create_hub(self, state):
        self._guard(); self._binding(state)
        require(self._inspect_object(state, 'volume') is not None, 'OWNERSHIP_ANCHOR_REQUIRED')
        require(self._hub(state) is None, 'HUB_ALREADY_EXISTS')
        layout = self.layout(state)
        mounts = [(layout['peer'],'/uas/peer',False),(layout['control'],'/uas/control',False),
                  (layout['hub'],'/uas/hub',True)]
        args = [x for source,destination,writable in mounts for x in ('--mount',
            'type=bind,source=' + str(source) + ',target=' + destination + ',bind-recursive=disabled,bind-propagation=rprivate'
            + ('' if writable else ',readonly'))]
        self._run(['create','--name',names(state)[0] + '-hub',*self._label_args(state,'hub'),
            '--interactive','--user','65531:65531','--group-add','65532',
            '--read-only','--network','none','--ipc','private','--cgroupns','private',
            '--cap-drop','ALL','--security-opt','no-new-privileges=true','--security-opt','label=level:' + self.level,
            '--memory','268435456','--memory-swap','268435456','--cpus','0.25','--pids-limit','32',
            '--log-driver','local','--log-opt','max-size=1048576','--log-opt','max-file=1','--log-opt','compress=false',
            '--env','PYTHONPATH=/opt/uas','--env','PYTHONDONTWRITEBYTECODE=1',*args,
            '--entrypoint',self.hub_command[0],self.profile.hub['image_reference'],*self.hub_command[1:]])
        value = self._hub(state)
        self.validate_hub(state,value)
        return value['Id']

    def validate_hub(self,state,value):
        require(value is not None and value['Image'] == self.profile.hub['image_id'], 'HUB_IMAGE')
        layout=self.layout(state)
        mounts=[(layout['peer'],'/uas/peer',False),(layout['control'],'/uas/control',False),
                (layout['hub'],'/uas/hub',True)]
        config,host = value['Config'],value['HostConfig']
        require(config['Image'] == self.profile.hub['image_reference'] and config['Entrypoint'] == self.hub_command[:1]
                and config['Cmd'] == self.hub_command[1:] and config['User'] == '65531:65531'
                and config['Tty'] is False and config['OpenStdin'] is True, 'HUB_COMMAND')
        require(host['Privileged'] is False and host['ReadonlyRootfs'] is True and host['NetworkMode'] == 'none'
                and host['CapDrop'] == ['ALL'] and host['CapAdd'] in (None,[]) and host['GroupAdd'] == ['65532'], 'HUB_BOUNDARY')
        require(all(host[k]==v for k,v in {'PidMode':'','IpcMode':'private','UTSMode':'',
                'UsernsMode':'','CgroupnsMode':'private'}.items()),'HUB_NAMESPACES')
        require([s.replace('no-new-privileges=true','no-new-privileges') for s in host['SecurityOpt']]
                == ['no-new-privileges','label=level:'+self.level],'HUB_SECURITY_OPTIONS')
        require(all(type(host[k]) is int and host[k]==v for k,v in {'Memory':268435456,'MemorySwap':268435456,
                'NanoCpus':250000000,'PidsLimit':32}.items()),'HUB_LIMITS')
        require(host['LogConfig']=={'Type':'local','Config':{'max-size':'1048576','max-file':'1','compress':'false'}},
                'HUB_LOG_LIMIT')
        require(all(host[k] in (None,[]) for k in ('Devices','DeviceRequests','DeviceCgroupRules'))
                and host['PortBindings'] in (None,{}) and host['PublishAllPorts'] is False,'HUB_DEVICES_PORTS')
        require(host['RestartPolicy']=={'Name':'no','MaximumRetryCount':0},'HUB_RESTART')
        require({'/proc/kcore','/proc/keys','/proc/timer_list','/sys/firmware'} <= set(host['MaskedPaths'])
                and {'/proc/bus','/proc/fs','/proc/irq','/proc/sys','/proc/sysrq-trigger'} <= set(host['ReadonlyPaths']),
                'HUB_KERNEL_MASKS')
        require(value['ProcessLabel']=='system_u:system_r:container_t:'+self.level
                and value['MountLabel']=='system_u:object_r:container_file_t:'+self.level,'HUB_MCS_LABELS')
        require(len(value['Mounts']) == 3 and {(m['Source'],m['Destination'],m['RW']) for m in value['Mounts']} ==
                {(str(s),d,w) for s,d,w in mounts} and all(m['Type']=='bind' and type(m['RW']) is bool
                    and m['Propagation']=='rprivate' for m in value['Mounts']), 'HUB_MOUNTS')
        bind_options(host,[(str(s),d,w) for s,d,w in mounts])
        return True


def labeled_listener(path, group, *, listen=True, level=None):
    """Existing disposable fixed socket-context seam, not a domain transition."""
    level = LEVEL if level is None else level
    original = Path('/proc/self/attr/current').read_text()
    require('container_t' not in original, 'ROOT_SETUP_DOMAIN')
    library = ctypes.CDLL('libselinux.so.1', use_errno=True)
    library.setsockcreatecon.argtypes = [ctypes.c_char_p]
    library.setsockcreatecon.restype = ctypes.c_int
    require(library.setsockcreatecon(('system_u:system_r:container_t:' + level).encode()) == 0,
            'SOCKET_LABEL_DENIED')
    listener = None
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.bind(str(path))
        if listen: listener.listen(4)
        listener.settimeout(3)
        os.chown(path, HOST_UID, group); os.chmod(path, 0o620)
    except BaseException:
        if listener is not None: listener.close()
        raise
    finally:
        if library.setsockcreatecon(None) != 0:
            if listener is not None: listener.close()
            raise LifecycleError('NATIVE_SOCKET_LABEL_RESET_FAILED')
    require(Path('/proc/self/attr/current').read_text() == original, 'ROOT_SETUP_DOMAIN')
    try:
        command('chcon','-t','container_file_t','-l',level,str(path))
        return listener
    except BaseException:
        listener.close()
        raise


@dataclass
class LaunchResources:
    data: dict
    pass_fds: tuple
    _child: object = None
    _broker: object = None
    _git_broker: object = None
    _child_expected: bool = False
    _broker_expected: bool = False
    _git_broker_expected: bool = False
    _preserve: bool = False
    retained_evidence: object = None
    _supervisor: object = None  # Root-only owner reference; never serialized.

    def preserve_evidence(self):
        self._preserve=True

    def expect_child(self):
        require(not self._child_expected,'CHILD_CUSTODY')
        self._child_expected=True
        self._preserve=True

    def expect_broker(self):
        require(not self._broker_expected,'BROKER_CUSTODY')
        self._broker_expected=True
        self._preserve=True

    def expect_git_broker(self):
        require(not self._git_broker_expected,'GIT_BROKER_CUSTODY')
        self._git_broker_expected=True
        self._preserve=True

    def hold_git_broker(self,process):
        require(type(process) is subprocess.Popen and self._git_broker is None,'GIT_BROKER_CUSTODY')
        self._git_broker_expected=True
        self._preserve=True
        self._git_broker=process

    def hold_child(self, process):
        require(type(process) is subprocess.Popen and self._child is None, 'CHILD_CUSTODY')
        self._child_expected=True
        self._preserve=True
        self._child = process

    def hold_broker(self, process):
        require(type(process) is subprocess.Popen and self._broker is None, 'BROKER_CUSTODY')
        self._broker_expected=True
        self._preserve=True
        self._broker = process

    def issuer_exited(self, *_):
        # No PID lookup, serialized receipt, generic truthy callback, or claim
        # that channel closure undoes already accepted Broker/provider work.
        return all(not expected or process is not None and process.poll() is not None
                   for expected,process in ((self._child_expected,self._child),(self._broker_expected,self._broker),(self._git_broker_expected,self._git_broker)))


class NativeQualificationObserver(DockerFixtureBackend):
    """The trusted child may read ownership, never drive lifecycle transitions."""
    LABEL = NativeQualificationBackend.LABEL
    name = NativeQualificationBackend.name
    _run = NativeQualificationBackend._run

    def __init__(self, room_id, instance, config_digest):
        super().__init__(executable='/usr/bin/docker', timeout=10)
        self.binding = (room_id,instance,'sha256:' + config_digest)

    def inspect(self, state, kind):
        require((state['room_id'],state['instance_id'],state['spec']['config_digest']) == self.binding,
                'OBSERVER_BINDING')
        return super().inspect(state,kind)

    def _deny(self,*args,**kwargs):
        raise LifecycleError('NATIVE_ROOT_LIFECYCLE_OWNER_REQUIRED')
    create = start = stop = remove = admit = _deny


def readonly_supervisor(plan, resources):
    data = resources.data if type(resources) is LaunchResources else resources
    require(data['room_id'] == plan.room['id'], 'OBSERVER_BINDING')
    backend = NativeQualificationObserver(plan.room['id'],data['instance'],plan.config_digest)
    def deny(*args,**kwargs): return False
    owner = Supervisor(Path(plan.room['state_root']).parent,plan.room['id'],backend,authorize=deny,revoke=deny)
    with owner._locked():
        state = owner._read()
        require(state is not None and state['instance_id'] == data['instance'] and state['phase'] == 'running'
                and state['spec']['config_digest'] == 'sha256:' + plan.config_digest, 'OBSERVER_BINDING')
    return owner


def copy_public_manifest(ref, target):
    value = read_manifest(ref['path'],ref['sha256'])
    # Preserve exact bytes, not a reserialization with a different digest. Open
    # again only for public metadata; digest comparison protects this copy race.
    fd = os.open(ref['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=16384,'PUBLIC_MANIFEST_CHANGED')
        raw = os.read(fd,16385)
    finally: os.close(fd)
    require(len(raw)<=1048576 and hashlib.sha256(raw).hexdigest()==ref['sha256'], 'PUBLIC_MANIFEST_CHANGED')
    fd = os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno());os.fchown(stream.fileno(),HOST_UID,HOST_UID)
    except BaseException:
        raise
    return value


@contextmanager
def provision(plan):
    """Root-owned bounded startup/cleanup; no actual provider authentication."""
    profile = NativeBoundaryProfile.read(plan)
    profile.observe_storage()  # Fail before any lifecycle or runtime creation.
    # Distinct per-attempt provenance means an interrupted/concurrent earlier
    # Room state can never be mistaken for this invocation's cleanup custody.
    profile.digest = hashlib.sha256(canonical({'profile':profile.digest,
        'attempt':secrets.token_hex(32)})).hexdigest()
    backend = NativeQualificationBackend(profile)
    resources = LaunchResources({},())
    selected_spec = profile.spec().document()
    def authorize(action, room_id, instance):
        if os.geteuid()!=0 or room_id!=profile.room['id']: return False
        # Supervisor invokes this while holding its canonical lifecycle lock.
        current=owner._read()
        return ((action=='start' and current is None) or
                current is not None and current['spec']==selected_spec and current['instance_id']==instance
                and backend.instance==instance)
    owner = Supervisor(profile.state_root.parent,profile.room['id'],backend,
                       authorize=authorize,revoke=resources.issuer_exited)
    state = None
    handed_off = False
    git_backend_fd = None
    # Existing canonical state, including a failed or destroyed prior attempt,
    # requires its own explicit reconciliation path; never adopt it here.
    with owner._locked():
        require(owner._read() is None, 'EXISTING_LIFECYCLE_REQUIRES_RECONCILIATION')
    # The finite profile has one quota/MCS/subnet assignment. Serialize the
    # entire qualification across Rooms in this disposable guest, not merely
    # within one Room's lifecycle lock. Unknown teardown retains this lease.
    lease_path=STORAGE/'.native-qualification-owner'
    lease=os.open(lease_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    lease_identity=os.fstat(lease)
    record=canonical({'room_id':profile.room['id'],'profile_digest':profile.digest})
    try:
        require(os.write(lease,record)==len(record),'LEASE_WRITE_INCOMPLETE')
        os.fsync(lease)
        directory=os.open(STORAGE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    except BaseException:
        os.close(lease)
        raise  # Incomplete ownership record remains an explicit blocker.
    try:
        result = owner.start(profile.spec())
        with owner._locked(): state = owner._read()
        require(state is not None and state['phase']=='running', 'START_INCOMPLETE')
        hub_id = backend.create_hub(state)
        workstation = backend.admit(state)
        layout = backend.layout(state)
        # Existing-only prepared state parents remain root-owned; grant the
        # fixed trusted Supervisor lock/read, not directory mutation authority.
        for path in (profile.state_root,profile.state_root/'instances',profile.state_root/'instances'/state['instance_id']):
            require(path.stat().st_uid==0,'CONTROL_OWNER')
            os.chown(path,0,0);os.chmod(path,0o711)
        for filename,mode in (('lifecycle.lock',0o660),('lifecycle.json',0o640)):
            path=profile.state_root/filename
            require(path.stat().st_uid==0 and not path.is_symlink(),'CONTROL_OWNER')
            os.chown(path,0,HOST_UID);os.chmod(path,mode)
        manifests={}
        for runtime in ('pi','claude'):
            target=layout['supervisor']/(runtime+'-manifest.json')
            copy_public_manifest(plan.installation[runtime+'_manifest'],target)
            manifests[runtime+'_manifest_path']=str(target)
        pid=workstation['State']['Pid']
        mapping={name:Path('/proc/'+str(pid)+'/'+name).read_text() for name in ('uid_map','gid_map')}
        for name in ('overflowuid','overflowgid'):
            mapping['overflow_'+('uid' if name=='overflowuid' else 'gid')]=int(Path('/proc/sys/kernel/'+name).read_text())
        require(mapping['overflow_uid']==65534 and mapping['overflow_gid']==65534,'OVERFLOW_MAPPING')
        mapping_digest=hashlib.sha256(json.dumps(mapping,sort_keys=True).encode()).hexdigest()
        data={'version':1,'room_id':profile.room['id'],'instance':state['instance_id'],
              'workstation_id':workstation['Id'],'hub_id':hub_id,
              'supervisor_directory':str(layout['supervisor']),
              'hub_ledger_path':str(layout['hub']/'room.db'),
              'peer_path':str(layout['peer']/'pi.sock'),'control_path':str(layout['control']/'hub.sock'),
              'peer_fd':backend.listeners[0].fileno(),'control_fd':backend.listeners[1].fileno(),
              'mapping_digest':mapping_digest,**manifests}
        if profile.git_manifest is not None:
            from .native_git_resources import seal_backend
            git_backend_fd=seal_backend(profile.git_manifest)
            target=layout['supervisor']/'git-manifest.json'
            copy_public_manifest(plan.installation['git_manifest'],target)
            data.update(git_manifest_path=str(target),git_backend_fd=git_backend_fd,
                git_request_path=str(layout['git']/'request.sock'),git_worker_path=str(layout['git']/'worker.sock'),
                git_request_fd=backend.listeners[2].fileno(),git_worker_fd=backend.listeners[3].fileno(),
                git_broker_directory=str(layout['git-broker']))
        if profile.gate_manifest is not None:
            from .native_gate_resources import paths
            selected=paths(plan,state)
            target=layout['supervisor']/'gate-manifest.json'
            copy_public_manifest(plan.installation['gate_manifest'],target)
            data.update(gate_manifest_path=str(target),gate_endpoint_path=str(selected['endpoint_root']/'gate.sock'),
                **{'gate_'+key:str(selected[key]) for key in ('scratch_root','journal_root','launch_journal_root')})
        resources._supervisor = owner
        resources.data = data
        resources.pass_fds = tuple(s.fileno() for s in backend.listeners) + (() if git_backend_fd is None else (git_backend_fd,))
        handed_off=True
        yield resources
    except BaseException:
        if handed_off:resources.preserve_evidence()
        raise
    finally:
        errors=[]
        if git_backend_fd is not None:
            try:os.close(git_backend_fd)
            except BaseException as error:errors.append(error)
        for listener in backend.listeners:
            try: listener.close()
            except BaseException as error: errors.append(error)
        # Child has exited before this context exits. Closing channels is NOT
        # claimed to kill native tasks; exact owned lifecycle teardown does so.
        try:
            with owner._locked(): state=owner._read()
        except BaseException as error:
            errors.append(error);state=None
        if state is not None and state['spec'] == selected_spec and state['instance_id'] == backend.instance:
            try:
                if resources._preserve:
                    owner.stop()
                    with owner._locked():current=owner._read()
                    require(current is not None and current['phase']=='stopped','STOP_INCOMPLETE')
                    require(resources.issuer_exited(),'ISSUER_EXIT_UNCONFIRMED')
                    backend.stop_hub(state)
                    resources.retained_evidence={'status':'stopped-evidence-retained','instance':state['instance_id'],
                        'path':str(backend.layout(state)['supervisor'].parent),'reason':'NATIVE_EVIDENCE_RETAINED'}
                else:
                    owner.destroy()
                    with owner._locked(): current=owner._read()
                    require(current is not None and current['phase']=='destroyed','CLEANUP_INCOMPLETE')
            except BaseException as error: errors.append(error)
        elif state is not None and state['spec']==selected_spec:
            errors.append(LifecycleError('NATIVE_OWNERSHIP_UNCONFIRMED'))
        elif state is not None:
            # Do not destroy the foreign Room, but also do not reopen this
            # fixed quota/MCS/subnet profile while its ownership is unresolved.
            errors.append(LifecycleError('NATIVE_FOREIGN_LIFECYCLE'))
        elif backend.instance is not None:
            errors.append(LifecycleError('NATIVE_OWNED_LIFECYCLE_MISSING'))
        if not errors and not resources._preserve:
            try:
                current=os.stat(lease_path,follow_symlinks=False)
                require((current.st_dev,current.st_ino)==(lease_identity.st_dev,lease_identity.st_ino),'LEASE_REPLACED')
                lease_path.unlink()
            except BaseException as error: errors.append(error)
        os.close(lease)
        if errors: raise LifecycleError('NATIVE_CLEANUP_INCOMPLETE') from errors[0]
