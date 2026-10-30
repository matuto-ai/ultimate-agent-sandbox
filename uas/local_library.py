"""Installed Deployment wiring for the external Library service (#252).

One digest-pinned Library deployment document selects the already composed T40
``DeploymentLibrary`` for this installation: the canonical target/branch,
credential references, approved per-Room Project source identities, target
qualification evidence, the fixed model route and an optional host-local
operator principal. This module admits that document against the closed
installation configuration and builds the composition. It provisions no target,
credential, mount, model or network route, and it stores no secret value: the
document names host environment variables and a missing one fails closed.

The installed supervisor owns admission of its approved Project bindings, so
``scope_for`` mints the Project scope from an installation-authority origin over
that exact binding. It invents no Participant identity: Participant captures
still require the Room Hub's authenticated origin, and this origin never leaves
the host process.
"""
from datetime import datetime, timezone
from io import StringIO
import json
import os

from . import library
from .ledger import Origin
from .library_assembly import Assembler
from .library_attempts import Attempts
from .library_deployment import DeploymentLibrary
from .library_dispatch import Dispatcher, Gateway, Profile
from .library_git import _ENVIRONMENT, LibraryGit
from .local_installation import LocalInstallationError, require

FIELDS = ('version', 'settings', 'credentials', 'rooms', 'qualification', 'model', 'operator')
REQUIRED = ('version', 'settings', 'credentials', 'rooms', 'qualification', 'model')
PROFILE = ('reference', 'placement', 'provider', 'version', 'endpoint', 'region',
           'retention', 'terms')
OPERATOR = ('human_id', 'actor_id')
# The installation owner is the authenticated host-local principal; a document
# may rename it or disable the path explicitly with null.
INSTALLATION_OWNER = {'human_id': 'installation-owner', 'actor_id': 'installation-owner'}


def fail(code):
    raise LocalInstallationError(code)


def _names(value):
    """Only the admitted Git transport variables; admission is the closed check."""
    require(type(value) is list and 0 < len(value) <= 16, 'LIBRARY_DOCUMENT_CREDENTIALS')
    for name in value:
        require(type(name) is str and name in _ENVIRONMENT,
                'LIBRARY_DOCUMENT_CREDENTIALS')
    require(len(set(value)) == len(value), 'LIBRARY_DOCUMENT_CREDENTIALS')
    return tuple(value)


def _settings(value):
    require(type(value) is dict, 'LIBRARY_DOCUMENT_SETTINGS')
    try:
        # Hosted egress needs an explicit approval this document cannot grant.
        return library.admit_settings(StringIO(json.dumps(value)))
    except library.LibraryError as error:
        raise LocalInstallationError('LIBRARY_DOCUMENT_SETTINGS') from error


def _credentials(value, settings, config):
    """Credential identities stay configured; the document names their environment."""
    require(type(value) is dict and 0 < len(value) <= 16, 'LIBRARY_DOCUMENT_CREDENTIALS')
    configured = {entry['id']: entry for entry in config['deployment']['credentials']}
    result = {}
    for reference, entry in value.items():
        library._token(reference, 'credential_ref')
        require(reference in configured and configured[reference]['kind'] == 'git',
                'LIBRARY_DOCUMENT_CREDENTIALS')
        require(type(entry) is dict and set(entry) == {'environment'},
                'LIBRARY_DOCUMENT_CREDENTIALS')
        result[reference] = _names(entry['environment'])
    require(settings['repository']['credential_ref'] in result, 'LIBRARY_DOCUMENT_CREDENTIALS')
    return result


def _rooms(value, config):
    """Approved Rooms plus their immutable source identity; Project stays configured."""
    require(type(value) is dict and 0 < len(value) <= 64, 'LIBRARY_DOCUMENT_ROOMS')
    configured = {room['id']: room for room in config['rooms']}
    # Partial adoption would leave a configured Room without a Library and only
    # fail on its first Start, so the document must bind every Room.
    require(set(value) == set(configured), 'LIBRARY_DOCUMENT_ROOMS')
    result = {}
    for room, entry in value.items():
        require(room in configured, 'LIBRARY_DOCUMENT_ROOMS')
        require(type(entry) is dict and set(entry) == {'source_identity'},
                'LIBRARY_DOCUMENT_ROOMS')
        library._token(entry['source_identity'], 'source_identity')
        try:
            binding = library.project_binding(configured[room]['project'],
                                             source_identity=entry['source_identity'])
        except library.LibraryError as error:
            raise LocalInstallationError('LIBRARY_DOCUMENT_ROOMS') from error
        result[room] = {'project': configured[room]['project'],
                        'source_identity': entry['source_identity'], 'binding': binding}
    identities = {entry['binding']['project_identity'] for entry in result.values()}
    projects = {entry['binding']['project_id'] for entry in result.values()}
    require(len(identities) == len(result) and len(projects) == len(result),
            'LIBRARY_DOCUMENT_ROOMS')
    return result


def _qualification(value):
    """Externally established evidence; absent, false or mismatched blocks writes."""
    require(type(value) is dict and set(value) == {'evidence'}, 'LIBRARY_DOCUMENT_QUALIFICATION')
    evidence = value['evidence']
    require(type(evidence) is dict
            and set(evidence) == {'version', 'target', 'branch', 'qualified'}
            and type(evidence['version']) is int and evidence['version'] == 1
            and type(evidence['target']) is str and 0 < len(evidence['target']) <= 2048
            and type(evidence['branch']) is str and 0 < len(evidence['branch']) <= 128
            and type(evidence['qualified']) is bool, 'LIBRARY_DOCUMENT_QUALIFICATION')
    return dict(evidence)


def _model(value, settings):
    require(type(value) is dict and set(value) == {'profile', 'command'},
            'LIBRARY_DOCUMENT_MODEL')
    profile = _profile(value['profile'])
    command = value['command']
    require(type(command) is list and 0 < len(command) <= 64
            and type(command[0]) is str and os.path.isabs(command[0])
            and all(type(arg) is str and 0 < len(arg) <= 4096 and '\0' not in arg
                    for arg in command), 'LIBRARY_DOCUMENT_MODEL')
    require(profile.reference == settings['model']['profile_ref'], 'LIBRARY_DOCUMENT_MODEL')
    return {'profile': profile, 'command': tuple(command)}


def _profile(value):
    require(type(value) is dict and set(value) <= set(PROFILE) | {'training', 'shared_interactive'}
            and set(PROFILE) <= set(value), 'LIBRARY_DOCUMENT_MODEL')
    try:
        profile = Profile(*[value[name] for name in PROFILE],
                          training=value.get('training', False),
                          shared_interactive=value.get('shared_interactive', False))
        profile.identity()
    except library.LibraryError as error:
        raise LocalInstallationError('LIBRARY_DOCUMENT_MODEL') from error
    return profile


def _operator(value):
    if value is None:
        return None
    require(type(value) is dict and set(value) == set(OPERATOR), 'LIBRARY_DOCUMENT_OPERATOR')
    for name in OPERATOR:
        library._token(value[name], name)
    return dict(value)


def admit(raw, config):
    """Validate one complete Library deployment document; no effect or secret read."""
    require(type(raw) is dict and set(raw) <= set(FIELDS) and set(REQUIRED) <= set(raw),
            'LIBRARY_DOCUMENT_SCHEMA')
    require(type(raw['version']) is int and raw['version'] == 1, 'LIBRARY_DOCUMENT_SCHEMA')
    settings = _settings(raw['settings'])
    return {'settings': settings,
            'credentials': _credentials(raw['credentials'], settings, config),
            'rooms': _rooms(raw['rooms'], config),
            'qualification': _qualification(raw['qualification']),
            'model': _model(raw['model'], settings),
            'operator': _operator(raw['operator'] if 'operator' in raw else INSTALLATION_OWNER)}


def _in_process_ingress():
    """Supervisor ingress seam: only this host's own Service queue reports."""
    return True


def _environment(names):
    """Referred host variables only; a missing one refuses the whole startup."""
    if any(name not in os.environ for name in names):
        fail('LIBRARY_CREDENTIAL_UNAVAILABLE')
    return {name: os.environ[name] for name in names}


def composition(admitted, *, deployment_id, state_root, ledger_for,
                publisher_factory=LibraryGit, now=lambda: datetime.now(timezone.utc),
                interactive=lambda: False):
    """Build the one Deployment Library for this installation lifetime."""
    bindings = {room: entry['binding'] for room, entry in admitted['rooms'].items()}
    authority = Origin('installation-owner', 'installation-owner', 'installation-owner',
                       'installation-v1', (library.ENQUEUE_CAPABILITY,))

    def scope_for(binding):
        if binding not in bindings.values():
            fail('LIBRARY_DOCUMENT_ROOMS')
        return library.participant_scope(authority, binding=binding)

    operator = admitted['operator']
    principal = None if operator is None else library.LocalHuman(
        operator['human_id'], operator['actor_id'], 'installation-v1',
        lambda _principal, identity, action: (
            identity in {binding['project_identity'] for binding in bindings.values()}
            and action in ('library-' + kind for kind in library.HUMAN_KINDS)),
        lambda: True)

    holder = {}

    def runner_for(scope):
        deployment = holder['deployment']
        settings = admitted['settings']
        model = admitted['model']
        gateway = Gateway({model['profile'].identity(): model['command']},
                          interactive=interactive)
        dispatcher = Dispatcher(
            gateway, current_scope=lambda: scope, settings=lambda: settings,
            selection=lambda _scope: None, current=lambda _request: True,
            token_count=lambda _profile, body: len(body), audit=lambda _event: None,
            records_path=deployment.publisher.records_path,
            deployment_id=deployment.publisher.deployment_id, now=now)
        assembler = Assembler(
            deployment.publisher, current_scope=lambda: scope, settings=lambda: settings,
            resolve_source=lambda _scope, _declaration: None,
            token_count=lambda body: len(body))
        return Attempts(assembler, dispatcher), lambda _selected: ((), ())

    deployment = DeploymentLibrary(
        state_root, deployment_id=deployment_id, settings=admitted['settings'],
        credentials={reference: _environment(names)
                     for reference, names in admitted['credentials'].items()},
        rooms={room: {'project': entry['project'], 'source_identity': entry['source_identity']}
               for room, entry in admitted['rooms'].items()},
        scope_for=scope_for, runner_for=runner_for, ledger_for=ledger_for,
        authenticate=_in_process_ingress,
        qualification=lambda settings: (
            admitted['qualification']['qualified'] is True
            and admitted['qualification']['target'] == settings['repository']['target']
            and admitted['qualification']['branch'] == settings['repository']['branch']),
        operator=None if principal is None else (lambda _uid: principal),
        publisher_factory=publisher_factory, now=now)
    holder['deployment'] = deployment
    return deployment


def open_library(installation, *, ledger_for, **options):
    """The selected Library deployment, or None when the installation selects none.

    ``state_root`` is the private installation root; the T40 owner keeps its
    service state, clone and operator endpoint in its own ``library`` child.
    """
    _value, config, selected = installation.open()
    admitted = selected['library']
    if admitted is None:
        return None
    return composition(admitted, deployment_id=config['deployment']['id'],
                       state_root=installation.root, ledger_for=ledger_for, **options)
