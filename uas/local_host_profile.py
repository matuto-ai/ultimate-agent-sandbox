"""Explicit local Engine identity; no discovery, process or filesystem effects.

Qualification keeps its fixed profile. A local host profile is an operator
selection, not evidence that the selected daemon enforces that selection.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re


class HostProfileError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise HostProfileError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def absolute_path(value):
    require(type(value) is str and len(value) <= 1024
            and re.fullmatch(r'/[A-Za-z0-9_./-]+', value) is not None,
            'HOST_PATH')
    path = PurePosixPath(value)
    require(value != '/' and str(path) == value and '..' not in path.parts,
            'HOST_PATH')
    return value


@dataclass(frozen=True)
class LocalHostProfile:
    """All host UID translations derive from one explicit subordinate range."""
    installation_id: str
    mode: str
    socket: str
    data_root: str
    exec_root: str
    remap_user: str
    offset: int
    size: int
    engine_version: str = '29.8.2'

    @classmethod
    def parse(cls, document):
        fields = {'version', 'profile', 'installation_id', 'mode', 'engine', 'mapping'}
        require(type(document) is dict and set(document) == fields, 'HOST_PROFILE')
        require(type(document['version']) is int and document['version'] == 1
                and document['profile'] == 'local-host-v1', 'HOST_PROFILE')
        require(type(document['installation_id']) is str and
                re.fullmatch(r'[0-9a-f]{32}', document['installation_id']), 'HOST_INSTALLATION')
        require(document['mode'] in ('reuse', 'owned'), 'HOST_MODE')
        engine, mapping = document['engine'], document['mapping']
        require(type(engine) is dict and set(engine) == {'version', 'socket', 'data_root', 'exec_root'}, 'HOST_ENGINE')
        require(engine['version'] == '29.8.2', 'HOST_ENGINE_VERSION')
        for key in ('socket', 'data_root', 'exec_root'):
            absolute_path(engine[key])
        require(len(engine['socket'].encode()) < 108, 'HOST_SOCKET')
        paths = [PurePosixPath(engine[k]) for k in ('socket', 'data_root', 'exec_root')]
        require(all(a != b and a not in b.parents and b not in a.parents
                    for i, a in enumerate(paths) for b in paths[i+1:]), 'HOST_ENGINE_OVERLAP')
        require(type(mapping) is dict and set(mapping) == {'user', 'offset', 'size'}, 'HOST_MAPPING')
        require(type(mapping['user']) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,30}', mapping['user']), 'HOST_MAPPING')
        require(type(mapping['offset']) is int and type(mapping['size']) is int
                and mapping['size'] == 65536 and mapping['offset'] >= 65536
                and mapping['offset'] + mapping['size'] <= 2**31, 'HOST_MAPPING')
        return cls(document['installation_id'], document['mode'], engine['socket'],
                   engine['data_root'], engine['exec_root'], mapping['user'],
                   mapping['offset'], mapping['size'])

    def document(self):
        return {'version': 1, 'profile': 'local-host-v1',
                'installation_id': self.installation_id, 'mode': self.mode,
                'engine': {'version': self.engine_version, 'socket': self.socket,
                           'data_root': self.data_root, 'exec_root': self.exec_root},
                'mapping': {'user': self.remap_user, 'offset': self.offset, 'size': self.size}}

    def host_id(self, container_id):
        require(type(container_id) is int and 0 <= container_id < self.size, 'HOST_CONTAINER_ID')
        return self.offset + container_id

    @property
    def owners(self):
        return {name: self.host_id(uid) for name, uid in
                {'gate': 65530, 'hub': 65531, 'runtime': 65532,
                 'supervisor': 65533, 'broker': 65534}.items()}

    @property
    def docker_root(self):
        return self.data_root + '/' + str(self.offset) + '.' + str(self.offset)

    def docker_argv(self, arguments):
        require(type(arguments) is list and all(type(arg) is str and '\0' not in arg
                                              for arg in arguments), 'HOST_ENGINE_ARGUMENTS')
        return ['/usr/bin/docker', '--host', 'unix://' + self.socket, *arguments]

    @staticmethod
    def environment():
        return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                'HOME': '/nonexistent', 'DOCKER_CONFIG': '/nonexistent'}

    def verify_engine(self, observation):
        require(type(observation) is dict and set(observation) ==
                {'version', 'docker_root', 'security_options', 'socket_identity'}, 'HOST_ENGINE_OBSERVATION')
        require(observation['version'] == self.engine_version
                and observation['docker_root'] == self.docker_root, 'HOST_ENGINE_DRIFT')
        security = observation['security_options']
        require(type(security) is list and all(type(x) is str for x in security)
                and {'name=seccomp,profile=builtin', 'name=selinux', 'name=userns'} <= set(security),
                'HOST_ENGINE_CONFINEMENT')
        identity = observation['socket_identity']
        require(type(identity) is list and len(identity) == 2
                and all(type(x) is int and x >= 0 for x in identity), 'HOST_ENGINE_SOCKET_IDENTITY')
        return tuple(identity)


def plan_owners(plan):
    """Identity policy from a concrete validated local plan, or fixed qualifier.

    A mapping-shaped object is not sufficient to select privileged identities.
    """
    from .native_qualification import is_local_runtime_plan
    if is_local_runtime_plan(plan):
        plan.require_unchanged()
        return plan.native_profile.host_profile.owners
    require(not hasattr(plan, 'native_profile'), 'HOST_LOCAL_PLAN_REQUIRED')
    return {'gate':165530, 'hub':165531, 'runtime':165532,
            'supervisor':165533, 'broker':165534}
