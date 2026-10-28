"""Explicit disposable native qualification, never production activation.

Checking a selection reads configuration and installation references only. It
does not read credential material or turn a declaration into launch authority.
The executable path is deliberately separate from production check-launch.
"""
from copy import deepcopy
from io import StringIO
import hashlib
import json

from .config import load
from .native_pi_recipe import read_manifest, path, SHA
from .native_image_package import payload, envelope, canonical
from .runtime_provider import select_reference, require_reference
from .lifecycle import LifecycleError, BackendUnknown, OwnershipConflict


class QualificationError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _exact(value, fields, code):
    if type(value) is not dict or set(value) != set(fields):
        raise QualificationError(code)
    return value


class QualificationPlan:
    """Validated declarations; not an admission receipt or serializable grant."""

    def __init__(self, config_text, installation, *, installation_digest):
        if type(config_text) is not str or len(config_text.encode()) > 1048576:
            raise QualificationError('CONFIGURATION_REQUIRED')
        self.config_text = config_text
        self.config = load(StringIO(config_text))
        required = {'version', 'profile', 'room_id', 'nonce', 'timeout_seconds',
                    'pi_manifest', 'claude_manifest', 'boundary_manifest', 'hub_manifest',
                    'broker_manifest', 'human_mergers'}
        git_refs = {'git_manifest', 'git_broker_manifest'}
        if type(installation) is not dict or set(installation) not in (required, required | git_refs, required | git_refs | {'gate_manifest'}):
            raise QualificationError('INVALID_NATIVE_SELECTION')
        selection = installation
        if (type(selection['version']) is not int or selection['version'] != 1
                or selection['profile'] != 'disposable-native-v1'
                or type(selection['nonce']) is not str or len(selection['nonce']) != 32
                or any(c not in '0123456789abcdef' for c in selection['nonce'])
                or type(selection['timeout_seconds']) is not int
                or not 1 <= selection['timeout_seconds'] <= 180
                or type(installation_digest) is not str or not SHA.fullmatch(installation_digest)):
            raise QualificationError('INVALID_NATIVE_SELECTION')
        if (type(selection['human_mergers']) is not list or not 1 <= len(selection['human_mergers']) <= 32
                or any(type(n) is not int or not 0 < n < 2**53 for n in selection['human_mergers'])
                or len(set(selection['human_mergers'])) != len(selection['human_mergers'])):
            raise QualificationError('EXPLICIT_HUMAN_MERGER_POLICY_REQUIRED')
        rooms = [r for r in self.config['rooms'] if r['id'] == selection['room_id']]
        if len(rooms) != 1:
            raise QualificationError('QUALIFICATION_ROOM_UNAVAILABLE')
        self.room = rooms[0]
        seats = self.room['seats']
        if len(seats) != 2 or sorted(s['runtime'] for s in seats) != ['claude', 'pi']:
            raise QualificationError('EXACT_NATIVE_PAIR_REQUIRED')
        self.seats = {s['runtime']: s for s in seats}
        providers = {p['id']: p for p in self.config['deployment']['providers']}
        for runtime, seat in self.seats.items():
            provider = providers[seat['provider']]
            if 'endpoint' in provider:
                raise QualificationError('CUSTOM_PROVIDER_NOT_QUALIFIED')
            try:
                require_reference(select_reference(provider, runtime), runtime)
            except ValueError:
                raise QualificationError('RUNTIME_AUTH_REFERENCE_REQUIRED') from None
        references=('pi', 'claude', 'boundary', 'hub', 'broker')
        if 'git_manifest' in selection:references+=('git','git_broker')
        if 'gate_manifest' in selection:references+=('gate',)
        for name in references:
            ref = _exact(selection[name + '_manifest'], ('path', 'sha256'), 'INVALID_INSTALLATION_REFERENCE')
            try:
                path(ref['path'])
            except (ValueError, TypeError):
                raise QualificationError('INVALID_INSTALLATION_REFERENCE') from None
            if type(ref['sha256']) is not str or not SHA.fullmatch(ref['sha256']):
                raise QualificationError('INVALID_INSTALLATION_REFERENCE')
        # No per-seat secret isolation is claimed: the accepted boundary shares
        # Runtime/provider state inside this Room, never across Rooms or host.
        self.installation = deepcopy(selection)
        self.installation_digest = installation_digest
        self.config_digest = hashlib.sha256(config_text.encode()).hexdigest()
        self._declarations = canonical({'configuration': self.config, 'installation': self.installation})

    def require_unchanged(self):
        if (hashlib.sha256(self.config_text.encode()).hexdigest() != self.config_digest
                or canonical({'configuration': self.config, 'installation': self.installation}) != self._declarations):
            raise QualificationError('QUALIFICATION_SELECTION_CHANGED')

    def review_configuration(self):
        selected = self.seats['claude']
        actor = next(a for a in self.config['deployment']['actors'] if a['id'] == selected['actor'])
        identifier = actor.get('github_user_id')
        if type(identifier) is not int or identifier <= 0:
            raise QualificationError('REVIEWER_GITHUB_ID_REQUIRED')
        return {'reviewers': [{'actor_id': actor['id'], 'participant_id': selected['participant'],
                             'github_user_id': identifier}],
                'human_mergers': list(self.installation['human_mergers'])}

    @classmethod
    def read(cls, config_text, installation_path, installation_digest):
        try:
            selection = read_manifest(installation_path, installation_digest)
        except (OSError, ValueError, TypeError):
            raise QualificationError('INSTALLATION_REFERENCE_UNVERIFIABLE') from None
        return cls(config_text, selection, installation_digest=installation_digest)

    def check(self):
        """Read selected public metadata, not providers/Engine or credentials."""
        self.require_unchanged()
        manifests = {}
        problems = []
        try: self.review_configuration()
        except QualificationError as error: problems.append(error.code)
        image = next(i['reference'] for i in self.config['deployment']['images']
                     if i['id'] == self.room['image'])
        for runtime in ('pi', 'claude'):
            ref = self.installation[runtime + '_manifest']
            try:
                manifest = read_manifest(ref['path'], ref['sha256'])
                expected = envelope(payload(runtime, manifest.get('artifacts')),
                    image_reference=image, image_id=manifest.get('image_id'))
                if canonical(manifest) != canonical(expected):
                    raise ValueError()
                manifests[runtime] = {'sha256': ref['sha256'], 'image_reference': image,
                                      'image_id': manifest.get('image_id')}
            except (OSError, ValueError, TypeError, AttributeError):
                problems.append(runtime.upper() + '_IMAGE_MANIFEST_UNAVAILABLE')
        if len(manifests) == 2 and manifests['pi']['image_id'] != manifests['claude']['image_id']:
            problems.append('PAIRED_IMAGE_ID_MISMATCH')
        return {'version': 1, 'profile': 'disposable-native-v1',
            'room_id': self.room['id'], 'production_launcher': 'disabled',
            'configuration_sha256': self.config_digest,
            'installation_sha256': self.installation_digest,
            'mode': 'check-only', 'effects': False, 'images': manifests,
            'missing_prerequisites': problems,
            'unobserved': ['disposable-guest-boundary', 'owned-runtime-resources',
                           'provider-authentication', 'native-process-admission'],
            'lifecycle_blockers': ['AUTHENTICATED_NATIVE_RUN_HOST_UNAVAILABLE']}

    def preflight(self):
        result = self.check()
        # Profile construction parses selected public metadata only. The
        # privileged observe_storage/provision paths are never called here.
        try:
            from .native_qualification_backend import NativeBoundaryProfile
            NativeBoundaryProfile.read(self)
        except (OSError, ValueError, LifecycleError, BackendUnknown, OwnershipConflict) as error:
            code = getattr(error, 'code', 'BOUNDARY_INSTALLATION_UNAVAILABLE')
            result['missing_prerequisites'].append(code)
        try:
            broker_selection(self)
        except (OSError, ValueError, TypeError):
            result['missing_prerequisites'].append('BROKER_INSTALLATION_UNAVAILABLE')
        if 'git_manifest' in self.installation:
            try:git_broker_selection(self)
            except (OSError,ValueError,TypeError):
                result['missing_prerequisites'].append('GIT_BROKER_INSTALLATION_UNAVAILABLE')
        result['missing_prerequisites'] = sorted(set(result['missing_prerequisites']))
        return result


def broker_selection(plan):
    """Public Broker setup reference; never open its referenced credential file."""
    plan.require_unchanged()
    ref = plan.installation['broker_manifest']
    value = read_manifest(ref['path'], ref['sha256'])
    required = {'version', 'credential_path', 'gh_executable', 'gh_sha256', 'gate_actor', 'review_actor'}
    if (type(value) is not dict or set(value) not in (required, required | {'mutation_actors', 'work_labels'})
            or type(value['version']) is not int or value['version'] != 1):
        raise QualificationError('INVALID_BROKER_INSTALLATION')
    actors = {a['id']: a for a in plan.config['deployment']['actors']}
    if value['gate_actor'] not in actors or value['review_actor'] not in actors:
        raise QualificationError('INVALID_BROKER_ACTOR')
    for name in ('credential_path', 'gh_executable'):
        path(value[name])
    if type(value['gh_sha256']) is not str or not SHA.fullmatch(value['gh_sha256']):
        raise QualificationError('INVALID_BROKER_INSTALLATION')
    mounted = list(plan.room['project']['roots'].values()) + [plan.room['state_root'] + '/runtime']
    if any(value['credential_path'] == root or value['credential_path'].startswith(root + '/') for root in mounted):
        raise QualificationError('BROKER_CREDENTIAL_INSIDE_WORKSTATION')
    if 'mutation_actors' in value:
        selected = value['mutation_actors']
        if (type(selected) is not dict or not selected or set(selected) - set(actors)
                or any(type(identifier) is not int or identifier <= 0
                       or actors[actor].get('github_user_id') != identifier for actor, identifier in selected.items())
                or type(value['work_labels']) is not list or not 1 <= len(value['work_labels']) <= 32
                or any(type(label) is not str or not 1 <= len(label) <= 64 for label in value['work_labels'])):
            raise QualificationError('INVALID_BROKER_MUTATION_POLICY')
    return value


def git_broker_selection(plan):
    """Digest-bound public existing SSH references; never read credential bytes."""
    from .git_transport import GitTransportConfig, SshActorCredential, GitTransportError
    plan.require_unchanged()
    ref=plan.installation.get('git_broker_manifest')
    if ref is None:raise QualificationError('GIT_BROKER_INSTALLATION_UNAVAILABLE')
    value=read_manifest(ref['path'],ref['sha256'])
    _exact(value,('version','ssh_executable','ssh_sha256','credentials'),'INVALID_GIT_BROKER_INSTALLATION')
    expected={seat['actor'] for seat in plan.seats.values()}
    if (type(value['version']) is not int or value['version']!=1
            or type(value['credentials']) is not list or len(value['credentials'])!=len(expected)):
        raise QualificationError('INVALID_GIT_BROKER_INSTALLATION')
    rows=[_exact(row,('actor_id','key_path','known_hosts_path'),'INVALID_GIT_BROKER_INSTALLATION')
          for row in value['credentials']]
    if {row['actor_id'] for row in rows}!=expected:
        raise QualificationError('INVALID_GIT_BROKER_ACTORS')
    path(value['ssh_executable'])
    try:
        GitTransportConfig(value['ssh_executable'],value['ssh_sha256'],
                           tuple(SshActorCredential(**row) for row in rows))
    except GitTransportError:
        raise QualificationError('INVALID_GIT_BROKER_INSTALLATION') from None
    mounted=list(plan.room['project']['roots'].values())+[plan.room['state_root']+'/runtime']
    for row in rows:
        for name in ('key_path','known_hosts_path'):
            path(row[name])
            if any(row[name]==root or row[name].startswith(root+'/') for root in mounted):
                raise QualificationError('GIT_CREDENTIAL_INSIDE_WORKSTATION')
    return value


def check_git_credentials(plan,selection):
    """Root metadata check only; canonical Broker reopens/rechecks before each use."""
    import stat
    from pathlib import Path
    mounted=[Path(value).resolve(strict=True) for value in plan.room['project']['roots'].values()]
    mounted.append(Path(plan.room['state_root']+'/runtime').resolve(strict=True))
    # Every additional fixed Git/peer projection is below this root; none may
    # become a credential source even if its public-file mode were changed.
    mounted.append(Path('/run/uas-native'))
    for row in selection['credentials']:
        for name in ('key_path','known_hosts_path'):
            candidate=Path(row[name]);resolved=candidate.resolve(strict=True);info=candidate.lstat()
            if (candidate!=resolved or any(candidate==root or root in candidate.parents for root in mounted)
                    or not stat.S_ISREG(info.st_mode) or info.st_uid!=165534 or info.st_nlink!=1
                    or info.st_mode & 0o177 or not info.st_mode & 0o400
                    or not 0<info.st_size<=1048576):
                raise QualificationError('GIT_CREDENTIAL_UNAVAILABLE')


def write_startup(stream, raw, deadline):
    """One bounded write of public fixed-service startup; never resend."""
    import os
    import select
    import time
    offset = 0
    try:
        descriptor = stream.fileno()
        os.set_blocking(descriptor, False)
        while offset < len(raw):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QualificationError('BROKER_STARTUP_TIMEOUT')
            _, writable, exceptional = select.select([], [descriptor], [descriptor], remaining)
            if exceptional or not writable:
                raise QualificationError('BROKER_STARTUP_TIMEOUT')
            try:
                count = os.write(descriptor, raw[offset:])
            except BlockingIOError:
                continue
            if count <= 0:
                raise QualificationError('BROKER_STARTUP_UNKNOWN')
            offset += count
    finally:
        stream.close()


def execute(plan):
    """Root owns the fixed child processes and exact disposable cleanup.

    No automatic retry: failure preserves unknown native journals for the owner.
    This function is reachable only via explicit --execute-qualification.
    """
    import os
    import socket
    import stat
    import subprocess
    import sys
    import time
    from pathlib import Path
    from .native_qualification_backend import provision
    from .native_checkout_handoff import RootCheckoutHandoff, collect_child
    from .kernel_origin import enable
    plan.require_unchanged()
    if os.getuid() != 0:
        raise QualificationError('DISPOSABLE_ROOT_SETUP_REQUIRED')
    checked = plan.preflight()
    if checked['missing_prerequisites']:
        raise QualificationError('NATIVE_INSTALLATION_INPUTS_UNAVAILABLE')
    selected = broker_selection(plan)
    git_selected = git_broker_selection(plan) if 'git_manifest' in plan.installation else None
    if git_selected is not None:check_git_credentials(plan,git_selected)
    credential = Path(selected['credential_path'])
    try:
        info = credential.lstat()
        valid = (credential.resolve() == credential and stat.S_ISREG(info.st_mode)
                 and info.st_uid == 165534 and not info.st_mode & 0o077 and info.st_nlink == 1)
    except OSError:
        valid = False
    if not valid:
        raise QualificationError('PROTECTED_BROKER_CREDENTIAL_UNAVAILABLE')
    with provision(plan) as resources:
        private = Path(resources.data['supervisor_directory']).parent / 'broker'
        node = private.lstat()
        if (private.resolve() != private or not stat.S_ISDIR(node.st_mode)
                or node.st_uid != 165534 or stat.S_IMODE(node.st_mode) != 0o700):
            raise QualificationError('BROKER_PRIVATE_DIRECTORY_UNAVAILABLE')
        result_root = private / 'results'; result_root.mkdir(mode=0o700); os.chown(result_root, 165534, 165534)
        host_channel, broker_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        allocation_root, allocation_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        broker = child = handoff = git_broker = None
        git_host_channel = git_broker_channel = None
        deadline = time.monotonic() + plan.installation['timeout_seconds']
        def left():
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise QualificationError('NATIVE_SESSION_DEADLINE')
            return remaining
        try:
            enable(allocation_root)
            configuration = {'room_id': plan.room['id'], 'room_instance': resources.data['instance'],
                'project_id': plan.room['project']['id'], 'repository': plan.room['project']['repository'],
                'deployment_id': plan.config['deployment']['id'], 'audit_path': str(private / 'audit.db'),
                'result_root': str(result_root), 'supervisor_uid': 165533, 'supervisor_gid': 165533,
                **{k: v for k, v in selected.items() if k != 'version'}}
            environment = {'PATH': '/usr/bin:/bin', 'PYTHONPATH': str(Path(__file__).resolve().parent.parent),
                           'PYTHONDONTWRITEBYTECODE': '1', 'HOME': '/nonexistent'}
            resources.expect_broker()
            broker = subprocess.Popen([sys.executable, '-m', 'uas.forge_read_service', str(broker_channel.fileno())],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                user=165534, group=165534, extra_groups=[], pass_fds=(broker_channel.fileno(),), env=environment, cwd='/')
            resources.hold_broker(broker)
            # Only bounded public startup metadata, never credential contents.
            raw = canonical(configuration) + b'\n'
            if len(raw) > 16384: raise QualificationError('BROKER_STARTUP_TOO_LARGE')
            write_startup(broker.stdin, raw, deadline)
            broker_channel.close()
            if git_selected is not None:
                git_private=private.parent/'git-broker'
                node=git_private.lstat()
                if (git_private.resolve()!=git_private or not stat.S_ISDIR(node.st_mode)
                        or node.st_uid!=165534 or stat.S_IMODE(node.st_mode)!=0o700):
                    raise QualificationError('GIT_BROKER_PRIVATE_DIRECTORY_UNAVAILABLE')
                git_host_channel,git_broker_channel=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
                git_configuration={'binding':{'room_id':plan.room['id'],'project_id':plan.room['project']['id'],
                    'repository':plan.room['project']['repository'],'host':'github.com'},
                    'room_instance':resources.data['instance'],'deployment_id':plan.config['deployment']['id'],
                    'audit_path':str(git_private/'audit.db'),'supervisor_uid':165533,'supervisor_gid':165533,
                    **{k:v for k,v in git_selected.items() if k!='version'}}
                raw=canonical(git_configuration)+b'\n'
                if len(raw)>16384:raise QualificationError('GIT_BROKER_STARTUP_TOO_LARGE')
                resources.expect_git_broker()
                git_broker=subprocess.Popen([sys.executable,'-m','uas.git_service',str(git_broker_channel.fileno())],
                    stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    user=165534,group=165534,extra_groups=[],pass_fds=(git_broker_channel.fileno(),),env=environment,cwd='/')
                resources.hold_git_broker(git_broker)
                write_startup(git_broker.stdin,raw,deadline)
                git_broker_channel.close()
            resources.expect_child()
            host_argv=[sys.executable,'-m','uas.native_session',str(host_channel.fileno()),str(allocation_child.fileno())]
            git_fds=() if git_host_channel is None else (git_host_channel.fileno(),)
            if git_fds:host_argv.append(str(git_fds[0]))
            child = subprocess.Popen(host_argv,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                user=165533, group=165533, extra_groups=[165531, os.stat('/run/docker.sock').st_gid] + ([165530] if 'gate_manifest' in plan.installation else []),
                pass_fds=resources.pass_fds + (host_channel.fileno(), allocation_child.fileno()) + git_fds, env=environment, cwd='/')
            resources.hold_child(child)
            allocation_child.close()
            handoff = RootCheckoutHandoff(plan, resources, child, allocation_root, deadline=deadline)
            host_channel.close()
            if git_host_channel is not None:git_host_channel.close()
            startup = canonical({'configuration': plan.config_text, 'installation': plan.installation,
                'installation_digest': plan.installation_digest, 'resources': resources.data})
            if len(startup) > 2 * 1048576: raise QualificationError('HOST_STARTUP_TOO_LARGE')
            write_startup(child.stdin, startup, deadline)
            output = collect_child(child, handoff, deadline=deadline)
            if len(output) > 16384:
                raise QualificationError('NATIVE_PAIR_STARTUP_FAILED')
            result = json.loads(output)
            if child.returncode != 0:
                code = result.get('error') if type(result) is dict else None
                if type(code) is not str or len(code) > 96 or not code.replace('_', '').isalnum():
                    code = 'UNKNOWN'
                raise QualificationError('NATIVE_PAIR_STARTUP_FAILED_' + code)
            if (type(result) is not dict or result.get('status') != 'NATIVE_PAIR_ATTACHED'
                    or result.get('instance') != resources.data['instance']
                    or result.get('configuration_sha256') != plan.config_digest
                    or result.get('installation_sha256') != plan.installation_digest):
                raise QualificationError('NATIVE_EVIDENCE_INVALID')
            broker.wait(timeout=min(5, left()))
            if broker.returncode != 0: raise QualificationError('BROKER_EXIT_UNCERTAIN')
            if git_broker is not None:
                git_broker.wait(timeout=min(5,left()))
                if git_broker.returncode!=0:raise QualificationError('GIT_BROKER_EXIT_UNCERTAIN')
        finally:
            host_channel.close(); broker_channel.close()
            allocation_root.close(); allocation_child.close()
            for channel in (git_host_channel,git_broker_channel):
                if channel is not None:channel.close()
            if child is not None and child.poll() is None:
                # Exact owned trusted child only, not a PID supplied in data.
                child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=5)
            if handoff is not None:
                handoff.close()
            if broker is not None and broker.poll() is None:
                # Channel EOF is the canonical stop request. A stuck Broker may
                # own an uncertain provider effect: never call it successful or
                # resend a mutation merely to force a result.
                try: broker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise QualificationError('BROKER_CLEANUP_PENDING') from None
            if git_broker is not None and git_broker.poll() is None:
                try:git_broker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise QualificationError('GIT_BROKER_CLEANUP_PENDING') from None
    retained = resources.retained_evidence
    if (type(retained) is not dict or retained.get('status') != 'stopped-evidence-retained'
            or retained.get('instance') != result['instance']):
        raise QualificationError('QUALIFICATION_EVIDENCE_RETENTION_UNVERIFIED')
    result['resources'] = retained
    return result
