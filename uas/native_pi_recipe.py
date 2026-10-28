from .runtime_provider import ProviderAuthReference, select_reference, require_reference
"""Opt-in trusted installation recipe consumed by the canonical exact exec owner.

No configuration is loaded from a Participant. The selected manifest binds an
image artifact, not observed binary execution or a qualified Room boundary.
Only an already admitted Workstation/container and provisioned mounts are used.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat


class NativeRecipeError(ValueError):
    pass


CONNECTOR = '/opt/uas/bin/pi-native-connector'
ARTIFACTS = frozenset(('/opt/uas/runtime/pi/provider-store.mjs',
    '/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/dist/core/auth-storage.js', CONNECTOR, '/opt/uas/node/bin/node',
    '/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/package.json',
    '/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js',
    '/opt/uas/runtime/pi/extension.mjs', '/opt/uas/runtime/pi/channel.mjs',
    '/opt/uas/runtime/pi/native-entry.mjs', '/opt/uas/runtime/provider-auth.mjs',
    '/opt/uas/pi/node_modules/@earendil-works/pi-coding-agent/dist/index.js'))
SHA = re.compile(r'[0-9a-f]{64}\Z')
CHOICE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z')


def path(value):
    if (type(value) is not str or not value.startswith('/') or value == '/'
            or len(value.encode()) > 512 or any(ord(c) < 33 or ord(c) == 127 for c in value)
            or any(part in ('', '.', '..') for part in value[1:].split('/'))):
        raise NativeRecipeError('canonical bounded path required')
    return value


def below(value, root):
    return value == root or value.startswith(root + '/')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise NativeRecipeError('duplicate manifest field')
        result[key] = value
    return result


@dataclass(frozen=True)
class NativeMount:
    source: str
    destination: str
    read_only: bool

    def __post_init__(self):
        path(self.source); path(self.destination)
        if type(self.read_only) is not bool:
            raise NativeRecipeError('typed mount mode required')
        # No bind can replace a selected immutable executable/library subtree.
        for fixed in ('/opt/uas', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc'):
            if below(fixed, self.destination) or below(self.destination, fixed):
                raise NativeRecipeError('native payload overlay denied')


def read_manifest(filename, expected_digest):
    """Hold one nofollow regular FD; reject mutable/shared ownership and races.

    Installation chooses the digest independently. A runtime-selected filename
    or label is not authority. Read no credentials, tokens, settings or sessions.
    """
    if type(expected_digest) is not str or not SHA.fullmatch(expected_digest):
        raise NativeRecipeError('selected manifest digest required')
    selected = Path(path(str(filename)))
    # Open each directory without following links; inspect trusted ownership.
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in selected.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory); directory = child
            info = os.fstat(directory)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise NativeRecipeError('untrusted manifest directory')
        fd = os.open(selected.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.getuid())
                    or before.st_mode & 0o077 or before.st_nlink != 1 or not 0 < before.st_size <= 16384):
                raise NativeRecipeError('private regular manifest required')
            data = b''
            while len(data) <= 16384:
                chunk = os.read(fd, min(4096, 16385-len(data)))
                if not chunk: break
                data += chunk
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise NativeRecipeError('manifest changed during read')
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    if len(data) > 16384 or hashlib.sha256(data).hexdigest() != expected_digest:
        raise NativeRecipeError('manifest digest mismatch')
    return json.loads(data, object_pairs_hook=unique)


def verify_payload_manifest(manifest):
    """External image envelope commits to one non-circular baked payload."""
    keys = ('version', 'runtime', 'runtime_version', 'artifacts')
    baked = {key: manifest[key] for key in keys}
    if manifest['runtime'] == 'claude': baked['sdk_version'] = manifest['sdk_version']
    digest = hashlib.sha256(json.dumps(baked, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
    if manifest.get('payload_manifest_digest') != digest:
        raise NativeRecipeError('image envelope and baked payload digest differ')
    return digest


class NativePiRecipe:
    """Installation-only opt-in; no generic executable or credential fields.

    This API consumes the trusted launcher's exact admitted mount contract.
    It does not create mounts, qualify confinement, pull images or grant access.
    User provider/model choices are explicit native values, not logical config IDs.
    Existing native auth/settings remain in the selected provisioned HOME.
    """
    def __setattr__(self, key, value):
        if getattr(self, '_frozen', False):
            raise NativeRecipeError('native recipe is immutable')
        object.__setattr__(self, key, value)

    @property
    def scope(self):
        return json.loads(self._scope_json)

    @property
    def identity(self):
        return json.loads(self._identity_json)

    def __init__(self, manifest_path, manifest_digest, *, seat, scope, checkout,
                 runtime_root, endpoint, mounts, provider, model, provider_auth=None):
        from .workstation_exec import ExecSeat
        if type(seat) is not ExecSeat:
            raise NativeRecipeError('canonical selected seat required')
        manifest = read_manifest(manifest_path, manifest_digest)
        if (type(manifest) is not dict or set(manifest) != {'version','runtime','runtime_version',
                'image_reference','image_id','artifacts','payload_manifest_digest'} or type(manifest['version']) is not int
                or manifest['version'] != 1 or manifest['runtime'] != 'pi'
                or manifest['runtime_version'] != '1.4.0'
                or type(manifest['image_reference']) is not str
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}@sha256:[0-9a-f]{64}', manifest['image_reference'])
                or type(manifest['image_id']) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',manifest['image_id'])
                or type(manifest['artifacts']) is not dict or set(manifest['artifacts']) != ARTIFACTS
                or any(type(v) is not str or not SHA.fullmatch(v) for v in manifest['artifacts'].values())):
            raise NativeRecipeError('invalid selected native image manifest')
        self.payload_manifest_digest = verify_payload_manifest(manifest)
        if (type(scope) is not dict or set(scope) != {'room_id','participant_id','run_id','generation','context_generation'}
                or scope['room_id'] != seat.room_id or scope['participant_id'] != seat.participant_id
                or type(scope['run_id']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',scope['run_id'])
                or any(type(scope[k]) is not int or not 1 <= scope[k] < 2**53 for k in ('generation','context_generation'))):
            raise NativeRecipeError('exact native scope required')
        if any(type(v) is not str or not CHOICE.fullmatch(v) for v in (provider,model)):
            raise NativeRecipeError('explicit native provider and model required')
        self.seat = seat
        self._scope_json = json.dumps(scope,sort_keys=True)
        self.checkout, self.endpoint = path(checkout), path(endpoint)
        if len(endpoint.encode()) >= 108:
            raise NativeRecipeError('Unix endpoint path too long')
        self.home = path(runtime_root) + '/' + seat.slot
        self.sessions = path(self.home + '/contexts/' + str(scope['context_generation']) + '/sessions')
        if (type(mounts) is not tuple or not 1 <= len(mounts) <= 16
                or any(type(m) is not NativeMount for m in mounts)
                or len({m.destination for m in mounts}) != len(mounts)):
            raise NativeRecipeError('exact admitted mounts required')
        for index, first in enumerate(mounts):
            if any(below(first.destination, second.destination) or below(second.destination, first.destination)
                   for second in mounts[index+1:]):
                raise NativeRecipeError('overlapping mounts denied')
        # Project paths are identical on host/Workstation; runtime state must not
        # alias Project data or the endpoint mount. No implicit directory setup.
        project = [m for m in mounts if below(self.checkout,m.destination)]
        homes = [m for m in mounts if below(self.home,m.destination)]
        peers = [m for m in mounts if below(self.endpoint,m.destination)]
        if (len(project)!=1 or project[0].read_only or project[0].source!=project[0].destination
                or len(homes)!=1 or homes[0].read_only or homes[0].source != runtime_root
                or homes[0].destination != runtime_root or len(peers)!=1
                or project[0] in homes or peers[0] in homes or project[0] in peers):
            raise NativeRecipeError('separate admitted Project/runtime/endpoint mounts required')
        if provider_auth is not None: require_reference(provider_auth, 'pi')
        self.provider_auth = provider_auth
        self.auth_path = None if provider_auth is None else provider_auth.path(runtime_root)
        self.mounts, self.provider, self.model = mounts, provider, model
        self.manifest_digest = manifest_digest
        self.image_id, self.image_reference = manifest['image_id'], manifest['image_reference']
        identity = {'runtime':'pi','runtime_version':'1.4.0','manifest_digest':manifest_digest,
            'image_id':self.image_id,'image_reference':self.image_reference,
            'payload_manifest_digest':self.payload_manifest_digest,
            'scope':dict(scope), 'recipe_sha256':hashlib.sha256(json.dumps({
                'checkout':self.checkout,'home':self.home,'sessions':self.sessions,'endpoint':self.endpoint,
                'provider':provider,'model':model,'provider_auth':None if provider_auth is None else provider_auth.document(),'mounts':[m.__dict__ for m in mounts]},sort_keys=True).encode()).hexdigest()}
        self._identity_json = json.dumps(identity,sort_keys=True)
        self._frozen = True

    @classmethod
    def from_configuration(cls, source, room_id, participant_id, manifest_path, manifest_digest,
                           *, seat, scope, checkout, runtime_root, endpoint, mounts):
        """Resolve existing configuration without changing native saved settings.

        Only explicit Pi provider/model arguments are qualified initially. A
        logical provider ID is never silently treated as a Pi provider name.
        Custom endpoint mapping remains blocked, not written into auth/settings.
        """
        from .config import load
        config = load(source)
        room = next((r for r in config['rooms'] if r['id'] == room_id), None)
        configured = next((s for s in room['seats'] if s['participant'] == participant_id), None) if room else None
        if (configured is None or configured['runtime'] != 'pi' or seat.room_id != room_id
                or seat.participant_id != participant_id or configured['actor'] != seat.actor_id):
            raise NativeRecipeError('configured native Pi seat mismatch')
        if runtime_root != room['state_root'] + '/runtime':
            raise NativeRecipeError('Room-owned runtime subtree required')
        runtime_mounts = [m for m in mounts if m.source == runtime_root and m.destination == runtime_root and not m.read_only]
        if (len(runtime_mounts) != 1 or len(mounts) != 6
                or any(below(room['state_root'], m.source) for m in mounts)):
            raise NativeRecipeError('dedicated runtime subtree and no control-store exposure required')
        provider = next(p for p in config['deployment']['providers'] if p['id'] == configured['provider'])
        if 'endpoint' in provider:
            raise NativeRecipeError('custom provider endpoint requires native configuration qualification')
        arguments = configured['arguments']
        if len(arguments) % 2 or len(arguments) > 4:
            raise NativeRecipeError('only explicit provider/model native arguments qualified')
        choices = {}
        for key, value in zip(arguments[::2], arguments[1::2]):
            if key not in ('--provider','--model') or key in choices:
                raise NativeRecipeError('native argument not qualified')
            choices[key] = value
        selected_model = choices.get('--model', provider.get('model'))
        if '--provider' not in choices or selected_model is None:
            raise NativeRecipeError('explicit native provider/model selection required')
        if 'model' in provider and selected_model != provider['model']:
            raise NativeRecipeError('conflicting configured model choices')
        project = room['project']['roots']
        if checkout != project['repo'] and str(Path(checkout).parent) != project['checkouts']:
            raise NativeRecipeError('owned configured checkout required')
        for key in ('repo','workspace','reference','checkouts'):
            selected = [m for m in mounts if m.source == project[key] and m.destination == project[key]]
            if len(selected) != 1 or selected[0].read_only != (key == 'reference'):
                raise NativeRecipeError('configured Project mount contract differs')
        recipe = cls(manifest_path, manifest_digest, seat=seat, scope=scope, checkout=checkout,
            runtime_root=runtime_root, endpoint=endpoint, mounts=mounts,
            provider=choices['--provider'], model=selected_model,
            provider_auth=select_reference(provider,'pi',native_provider=choices['--provider']))
        image = next(i for i in config['deployment']['images'] if i['id'] == room['image'])
        if image['reference'] != recipe.image_reference:
            raise NativeRecipeError('configured image differs from selected manifest')
        return recipe

    def validate_container(self, engine):
        value = engine.inspect_container(self.seat.container_id)
        if type(value) is not dict:
            raise NativeRecipeError('container observation unavailable')
        host, config = value.get('HostConfig'), value.get('Config')
        if (value.get('Id') != self.seat.container_id or value.get('Image') != self.image_id
                or type(config) is not dict or config.get('Image') != self.image_reference
                or type(host) is not dict or host.get('Privileged') is not False
                or host.get('ReadonlyRootfs') is not True or host.get('PidMode') == 'host'
                or host.get('IpcMode') == 'host' or host.get('NetworkMode') in ('host','none')
                or host.get('CapAdd') not in (None,[]) or host.get('Devices') not in (None,[])
                or host.get('DeviceRequests') not in (None,[])
                or type(host.get('SecurityOpt')) is not list or 'label=disable' in host['SecurityOpt']
                or not value.get('ProcessLabel') or value.get('State',{}).get('Running') is not True):
            raise NativeRecipeError('selected admitted container differs')
        actual = value.get('Mounts')
        if type(actual) is not list or len(actual) != len(self.mounts):
            raise NativeRecipeError('admitted mount inventory differs')
        expected = {(m.source,m.destination,not m.read_only) for m in self.mounts}
        observed=[]
        for m in actual:
            if type(m) is not dict or m.get('Type')!='bind' or type(m.get('RW')) is not bool:
                raise NativeRecipeError('admitted mount kind differs')
            observed.append((m.get('Source'),m.get('Destination'),m['RW']))
        if len(set(observed))!=len(observed) or set(observed)!=expected:
            raise NativeRecipeError('admitted mount identity differs')

    def exec_spec(self):
        return {'AttachStdin':True,'AttachStdout':True,'AttachStderr':True,'Tty':False,
            'Privileged':False,'User':'65532:65532','WorkingDir':self.checkout,
            'Cmd':[CONNECTOR,self.endpoint,self.checkout,self.home,self.sessions,self.provider,self.model] + ([] if self.provider_auth is None else [self.auth_path]), 'Env':[]}

    def require_provider_auth(self):
        return require_reference(self.provider_auth, 'pi')
