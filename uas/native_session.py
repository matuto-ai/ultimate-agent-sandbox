"""Fixed trusted non-root qualification Supervisor, invoked only by its owner.

This composes actual owners. Serialized input selects public installation refs,
never human authority. CLI startup attaches the pair only; an existing trusted
HumanSession may select the retained finite-Run hosting API. Neither mode
claims complete native implementation/review/completion qualification.
"""
from contextlib import ExitStack, closing, contextmanager
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import socket
import sys
import threading
import time
import uuid

from .native_qualification import QualificationPlan, QualificationError
from .kernel_origin import HeldOrigin, ReceiverIdentity, _identity, enable, probe, receive
from .workstation_admission import AdmissionSeat, _canonical, _unique
from .workstation_exec import EndpointLease, ExecLaunch, ExecSeat
from .workstation_control import SupervisorAdmission
from .workstation_service import RELEASE
from .docker_exec_api import DockerExecAPI
from .native_pi_recipe import NativePiRecipe, NativeMount
from .native_claude_recipe import NativeClaudeRecipe
from .claude_native_admission import NativeClaudeHostLaunch, NativeClaudeRoot
from .forge import ForgeBinding
from .forge_read_service import ReadBrokerClient
from .ledger import RoomLedger
from .git_provenance import GitProvenance
from .checkouts import CheckoutAllocator
from .artifact_target import ArtifactSourceResolver
from .gate_evaluation import GateRoomBinding
from .native_review_host import NativeReviewStartup
from .native_host_forge import NativeHostForge, NativePiHostForge

HOST_UID = 165533
HUB_UID = 165531
RUNTIME_UID = 165532
BROKER_UID = 165534


def require(value, code):
    if not value:
        raise QualificationError(code)


class SessionBudget:
    """One monotonic whole-session budget; never reset for a retry."""
    def __init__(self, seconds, *, current=None):
        require(type(seconds) is int and 1 <= seconds <= 180, 'INVALID_SESSION_BUDGET')
        self.deadline = time.monotonic() + seconds
        self.current = current

    def remaining(self, ceiling=10):
        if self.current is not None: self.current()
        left = self.deadline - time.monotonic()
        require(left > 0, 'NATIVE_SESSION_DEADLINE')
        return min(left, ceiling)


@contextmanager
def admission_cleanup(admissions):
    try:
        yield
    finally:
        failures = []
        for current in reversed(admissions):
            try: current.revoke()
            except Exception: failures.append('ADMISSION_REVOCATION_UNKNOWN')
        require(not failures, 'ADMISSION_REVOCATION_UNKNOWN')


def admit_once(admission, operation_id, *, epoch=1):
    """Only STATUS may follow an uncertain transfer; never a second ADMIT."""
    require(type(admission) is SupervisorAdmission, 'EXACT_PI_ADMISSION_REQUIRED')
    try:
        return admission.admit(operation_id, epoch)
    except Exception:
        try:
            reconciled = admission.status()
        except Exception:
            raise QualificationError('PI_ADMISSION_UNKNOWN') from None
        if (type(reconciled) is dict and reconciled.get('installed') is True
                and reconciled.get('state') == 'active'):
            return reconciled
        raise QualificationError('PI_ADMISSION_NOT_INSTALLED') from None


def _hub(engine, resources, plan, peer, control_listener, stack, budget):
    control_lease = EndpointLease(resources['control_path'], owner=HOST_UID, group=HUB_UID)
    self_pidfd = os.pidfd_open(os.getpid(), 0)
    stack.callback(os.close, self_pidfd)
    challenge = secrets.token_hex(32)
    room, instance = plan.room, resources['instance']
    profiles = {p['id']: p for p in room['profiles']}
    metadata = {'version': 1, 'challenge': challenge, 'supervisor_identity': list(_identity(self_pidfd)),
        'mapping_digest': resources['mapping_digest'], 'room_id': room['id'], 'room_instance': instance,
        'run_id': 'qualification-scope',
        'forge': {'project_id': room['project']['id'], 'repository': room['project']['repository'], 'host': 'github.com'},
        'seats': [{'participant_id': s['participant'], 'actor_id': s['actor'], 'profile_id': s['profile'],
                   'capabilities': sorted(set(profiles[s['profile']]['capabilities']) | {'peer-traffic'})}
                  for s in room['seats']]}
    return start_hub_channel(engine, resources, metadata, control_listener, stack, budget)


def start_hub_channel(engine, resources, metadata, control_listener, stack, budget):
    """One authenticated startup; callers retain stack for the owner lifetime."""
    control_lease = EndpointLease(resources['control_path'], owner=HOST_UID, group=HUB_UID)
    challenge = metadata['challenge']
    room_id, instance = metadata['room_id'], metadata['room_instance']
    stream = engine.attach_hub(resources['hub_id']); stack.callback(stream.close)
    # Existing exact-owned stopped Hub only. An uncertain start is never repeated.
    engine.start_hub(resources['hub_id'])
    stream.write(_canonical(metadata) + b'\n', timeout=budget.remaining(8))
    control_listener.settimeout(budget.remaining(10))
    control, _ = control_listener.accept(); stack.callback(control.close)
    enable(control); control.settimeout(budget.remaining(8))
    with receive(control) as record:
        require(record.data == b'HUB1' + bytes.fromhex(challenge)
                and record.credentials[1:] == (HUB_UID, HUB_UID), 'HUB_STARTUP_IDENTITY_MISMATCH')
        origin = HeldOrigin(record)
    stack.callback(origin.close)
    control_lease.require()
    require(control.send(RELEASE) == len(RELEASE), 'HUB_RELEASE_UNKNOWN')
    with receive(control) as record:
        origin.require(record); ready = json.loads(record.data, object_pairs_hook=_unique)
    require(type(ready) is dict and set(ready) == {'version', 'kind', 'controller', 'room_id', 'room_instance', 'observation'}
            and ready['version'] == 1 and ready['kind'] == 'HUB_READY'
            and ready['room_id'] == room_id and ready['room_instance'] == instance,
            'HUB_STARTUP_SCOPE_MISMATCH')
    return control, origin, ready, metadata


def dispatch(services, budget, *, max_packets=16):
    """Finite direct ingress; no request retransmission or generated prompt.

    The outer root-owned deadline also bounds a provider call. We do not start
    one unless its existing maximum operation budget fits in this session.
    """
    require(type(max_packets) is int and 0 <= max_packets <= 16, 'INVALID_DISPATCH_BOUND')
    require(type(services) is tuple and len(services) == 2
            and type(services[0]) is NativePiHostForge and type(services[1]) is NativeHostForge
            and type(budget) is SessionBudget, 'EXACT_NATIVE_SERVICES_REQUIRED')
    processed = 0
    while processed < max_packets:
        left = budget.remaining(180)
        if left < 45:
            return {'packets': processed, 'stop': 'operation-budget-exhausted'}
        channels = [service.helper.forge_channel for service in services]
        for service in services: service._current()
        ready, _, exceptional = select.select(channels, [], channels, min(.1, left))
        require(not exceptional, 'NATIVE_CHANNEL_UNAVAILABLE')
        if not ready:
            # This milestone proves startup/attachment, not model work. Do not
            # spend a full qualification budget polling idle native sessions.
            return {'packets': processed, 'stop': 'idle'}
        for service, channel in zip(services, channels):
            if channel in ready:
                if budget.remaining(180) < 45:
                    return {'packets': processed, 'stop': 'operation-budget-exhausted'}
                service.receive_once()  # Original record; owner handles uncertainty.
                processed += 1
                if processed == max_packets: break
    return {'packets': processed, 'stop': 'packet-budget-exhausted'}


def _gate_listener(resources, *, local_plan=None):
    """Actual Supervisor-created fixed listener; root only provisions its parent."""
    import stat
    from .artifact_helper import GateEndpointLease
    instance=resources.get('instance')
    require(type(instance) is str and len(instance)==32 and all(c in '0123456789abcdef' for c in instance),
            'GATE_ENDPOINT_UNAVAILABLE')
    filename=Path(resources['gate_endpoint_path'])
    root=Path('/run/uas-native')
    level='s0:c301,c302'
    if local_plan is not None:
        from .local_runtime_plan import LocalRuntimePlan
        require(type(local_plan) is LocalRuntimePlan,'LOCAL_RUNTIME_PLAN_REQUIRED')
        local_plan.require_unchanged();root=local_plan.native_profile.endpoints;level=local_plan.native_profile._level
    expected=root/instance/'gate'/'gate.sock'
    require(filename==expected and not os.path.lexists(filename),'GATE_ENDPOINT_UNAVAILABLE')
    parent=filename.parent;info=parent.lstat()
    require(parent.resolve()==parent and stat.S_ISDIR(info.st_mode)
        and info.st_uid==HOST_UID and info.st_gid==165530 and stat.S_IMODE(info.st_mode)==0o710
        and os.getuid()==HOST_UID and 165530 in os.getgroups(),'GATE_ENDPOINT_OWNER_REQUIRED')
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        enable(channel);channel.bind(str(filename))
        os.chown(filename,HOST_UID,165530);os.chmod(filename,0o620)
        channel.listen(8)
        # Observe stock policy outcome, never install a type/domain transition.
        require(os.getxattr(filename,'security.selinux',follow_symlinks=False).rstrip(b'\0')
            == ('system_u:object_r:container_file_t:'+level).encode(),'GATE_ENDPOINT_MAC_UNAVAILABLE')
        GateEndpointLease(filename,owner=HOST_UID,group=165530).require()
        return channel
    except BaseException:
        channel.close();raise


def run(plan, resources, broker_fd, checkout_fd=None, git_fd=None, *, human_request=None, next_request=None, human_actions=None, human_control=None, local_host=None):
    from .native_qualification_backend import readonly_supervisor
    require((os.getuid(), os.getgid()) == (HOST_UID, HOST_UID), 'TRUSTED_NATIVE_SUPERVISOR_REQUIRED')
    require(type(resources) is dict and resources.get('room_id') == plan.room['id'], 'INVALID_LAUNCH_RESOURCES')
    require(('git_manifest' in plan.installation)==(git_fd is not None),'GIT_BROKER_CHANNEL_REQUIRED')
    if human_control is not None:
        from .native_human_control import NativeHumanControl
        from .native_run_admission import NativeHumanRunRequest
        require(type(human_control) is NativeHumanControl and type(human_request) is NativeHumanRunRequest
                and human_actions is None and next_request is None
                and human_control.session is human_request.session and human_control._first_taken
                and human_control._first is not None
                and (human_request.operation_id, human_request.issue_number) ==
                    (human_control._first.operation_id, human_control._first.issue_number),
                'EXACT_NATIVE_HUMAN_CONTROL_REQUIRED')
    if human_actions is not None:
        from .native_session_driver import NativeHumanReviewInbox
        from .native_run_admission import NativeHumanRunRequest
        require(type(human_actions) is NativeHumanReviewInbox and type(human_request) is NativeHumanRunRequest
                and human_actions.session is human_request.session and next_request is None,
                'EXACT_NATIVE_HUMAN_ACTION_OWNER_REQUIRED')
    if next_request is not None and human_request is None:
        raise QualificationError('AUTHENTICATED_NATIVE_RUN_REQUEST_REQUIRED')
    if human_request is not None:
        from .native_run_admission import NativeHumanRunRequest
        require(type(human_request) is NativeHumanRunRequest and checkout_fd is not None,
                'AUTHENTICATED_NATIVE_RUN_REQUEST_REQUIRED')
        if next_request is not None:
            require(type(next_request) is NativeHumanRunRequest
                    and next_request.session is human_request.session
                    and next_request.participant_id == human_request.participant_id
                    and next_request.operation_id != human_request.operation_id
                    and next_request.issue_number != human_request.issue_number,
                    'EXPLICIT_NATIVE_SUCCESSOR_REQUIRED')
        session = human_request.session
        require(session.deployment_id == plan.config['deployment']['id']
                and session.room_id == plan.room['id'] and session.instance_id == resources['instance']
                and 'human-open-run' in session.human.capabilities and session.allowed('open-run'),
                'AUTHENTICATED_NATIVE_RUN_REQUEST_REQUIRED')
    os.umask(0o007)  # Shared Room SQLite files only; private owners use explicit0600.
    probe()
    if local_host is not None:
        from .local_native_run_session import LocalNativeRunSession
        require(type(local_host) is LocalNativeRunSession and local_host.plan is plan,
                'EXACT_LOCAL_RUN_HOST_REQUIRED')
        local_host._require_owner()
    budget = (SessionBudget(plan.operation_timeout_seconds, current=local_host.operation_current)
              if local_host is not None else SessionBudget(plan.installation['timeout_seconds']))
    if human_control is not None:
        budget.deadline = min(budget.deadline, human_control._deadline)
        budget.remaining()
    if local_host is not None:
        from .local_native import readonly_local_supervisor
        supervisor = local_host.supervisor
        local_host.current()
    else: supervisor = readonly_supervisor(plan, resources)
    room, instance = plan.room, resources['instance']
    journal = Path(resources['supervisor_directory'])
    engine = DockerExecAPI(plan.native_profile.host_profile.socket
                           if local_host is not None else '/run/docker.sock')
    peer_lease = EndpointLease(resources['peer_path'], owner=HOST_UID, group=RUNTIME_UID)
    admissions = []
    with ExitStack() as stack, admission_cleanup(admissions):
        def socket_fd(fd):
            return os.dup(fd) if local_host is not None else fd
        peer = stack.enter_context(closing(socket.socket(fileno=socket_fd(resources['peer_fd']))))
        enable(peer)
        if local_host is None:
            control_listener = stack.enter_context(closing(socket.socket(fileno=resources['control_fd'])))
            enable(control_listener)
            control, hub_origin, ready, metadata = _hub(engine, resources, plan, peer, control_listener, stack, budget)
        else:
            control, hub_origin, ready, metadata = local_host.hub_channel()
            require(human_request is not None,'LOCAL_HUMAN_RUN_REQUIRED')
        binding = ForgeBinding(room['id'], room['project']['id'], room['project']['repository'])
        if local_host is not None:
            broker,git_broker=local_host.clients()
        else:
            broker_channel = socket.socket(fileno=broker_fd); stack.callback(broker_channel.close)
            broker = ReadBrokerClient(broker_channel, supervisor, binding, instance,
                                      worker_uid=BROKER_UID, worker_gid=BROKER_UID)
            stack.callback(broker.close)
        if human_control is not None:
            from .native_broker_audit import NativeBrokerAudit
            from .native_session_driver import NativeHumanReviewInbox
            # The original private Broker client is created here, not supplied
            # by a transport thread or replaced with a host-local audit DB.
            human_actions = NativeHumanReviewInbox(human_request.session,
                                                   NativeBrokerAudit(broker, human_request.session))
        if local_host is None: git_broker=None
        if git_fd is not None and local_host is None:
            from .git_service import GitBrokerClient
            git_channel=socket.socket(fileno=socket_fd(git_fd));stack.callback(git_channel.close)
            git_broker=GitBrokerClient(git_channel,binding,instance,broker_uid=BROKER_UID,broker_gid=BROKER_UID)
            stack.callback(git_broker.close)
        # Same database mounted into Hub. No snapshot copy and no private state.
        require(Path(resources['hub_ledger_path']).is_file(), 'CANONICAL_ROOM_LEDGER_UNAVAILABLE')
        ledger = RoomLedger(resources['hub_ledger_path'], room['id']); stack.callback(ledger.close)
        provenance = GitProvenance(journal / 'git-history.db', room['id'], room['project']['id'])
        stack.callback(provenance.close)
        git_resources=None
        if git_broker is not None:
            from .native_git_resources import NativeGitResources
            if local_host is None: stack.callback(os.close,resources['git_backend_fd'])
            git_resources=NativeGitResources.from_session(plan,resources,engine,supervisor=supervisor,deadline=budget.deadline)
            stack.callback(git_resources.close)
        allocator = CheckoutAllocator(supervisor, StringIO(plan.config_text))
        source = ArtifactSourceResolver(supervisor, allocator)
        mounts = tuple(NativeMount(room['project']['roots'][key], room['project']['roots'][key], key == 'reference')
                       for key in ('repo', 'workspace', 'reference', 'checkouts')) + (
            NativeMount(room['state_root'] + '/runtime', room['state_root'] + '/runtime', False),
            NativeMount(str(Path(resources['peer_path']).parent), str(Path(resources['peer_path']).parent), True))
        if git_resources is not None:mounts+=git_resources.profile.mounts
        gate_profile=None if git_resources is None else getattr(git_resources,'gate_profile',None)
        gate_listener=None
        if gate_profile is not None:
            mounts+=gate_profile.mounts
            gate_listener=_gate_listener(resources,local_plan=plan if local_host is not None else None)
            if local_host is not None:
                filename=Path(resources['gate_endpoint_path']);info=filename.lstat()
                def remove_owned_gate(filename=filename, identity=(info.st_dev,info.st_ino)):
                    try:current=filename.lstat()
                    except FileNotFoundError:return
                    if (current.st_dev,current.st_ino)==identity:filename.unlink()
                stack.callback(remove_owned_gate)
            stack.callback(gate_listener.close)
        git_options={} if git_resources is None else {'git_profile':git_resources.profile}
        if gate_profile is not None:git_options['gate_profile']=gate_profile
        receiver = ReceiverIdentity(65532, 65532, 'hub-' + instance, resources['mapping_digest'])
        control_lock = threading.Lock()
        def seats(runtime, slot):
            selected = plan.seats[runtime]
            declared = next(s for s in metadata['seats'] if s['participant_id'] == selected['participant'])
            exec_seat = ExecSeat(room['id'], instance, selected['participant'], selected['actor'], slot,
                resources['workstation_id'], RUNTIME_UID, RUNTIME_UID)
            admission_seat = AdmissionSeat(room['id'], instance, selected['participant'], selected['actor'],
                selected['profile'], tuple(declared['capabilities']), receiver)
            scope = {'room_id': room['id'], 'participant_id': selected['participant'],
                'run_id': 'qualification-scope', 'generation': 1, 'context_generation': 1}
            return exec_seat, admission_seat, scope
        pi_seat, pi_admit, pi_scope = seats('pi', 'seat-a')
        if human_request is not None:
            from .native_run_admission import NativeHumanRunRequest, NativeRunLauncher, NativeRunAdmission
            from .native_admission_broker import NativeAdmissionBroker
            from .native_checkout_handoff import NativeCheckoutClient
            require(type(human_request) is NativeHumanRunRequest and checkout_fd is not None,
                    'AUTHENTICATED_NATIVE_RUN_REQUEST_REQUIRED')
            checkout_channel = socket.socket(fileno=socket_fd(checkout_fd))
            checkout_client = NativeCheckoutClient(checkout_channel, deadline=budget.deadline)
            stack.callback(checkout_client.close)
            admission_broker = NativeAdmissionBroker(ledger,binding,broker)
            launcher = NativeRunLauncher(plan,resources,supervisor,ledger,admission_broker,
                engine=engine,endpoint=peer_lease,listener=peer,control=control,
                hub_origin=hub_origin,controller=ready['controller'],control_lock=control_lock,
                exec_seat=pi_seat,admission_seat=pi_admit,mounts=mounts,stack=stack,
                admissions=admissions,budget=budget,git_resources=git_resources,gate_profile=gate_profile)
            owner = NativeRunAdmission(launcher,allocator,checkout_client)
            activated = owner.open_human(human_request.operation_id,human_request.issue_number,
                human_request.participant_id,session=human_request.session,attempt_id=human_request.attempt_id)
            held = launcher.started.get(human_request.participant_id)
            require(type(held) is SupervisorAdmission,'NATIVE_RUN_OWNER_UNAVAILABLE')
            from .native_reviewer_recruitment import NativeReviewerRecruitment
            recruitment=NativeReviewerRecruitment(owner,held,provenance,source,
                GateRoomBinding(room['id'],instance,room['project']['id'],room['project']['repository'],room['resources']['disk_bytes']))
            claude=recruitment.recruit('reviewer-'+hashlib.sha256(human_request.operation_id.encode()).hexdigest(),
                activated['run_id'],activated['generation'],session=human_request.session)
            from .native_session_driver import NativeSessionDriver
            git_operations=None
            if git_resources is not None:
                from .native_git_operations import NativeGitOperations
                git_operations=NativeGitOperations(owner,recruitment,git_resources,git_broker)
                stack.callback(git_operations.close)
            gate_operations=None
            if gate_profile is not None:
                from .native_gate_resources import NativeGateResources
                from .native_gate_operations import NativeGateOperations
                from .native_gate_workflow import NativeGateWorkflow
                gate_resources=NativeGateResources.from_session(plan,resources,engine,supervisor=supervisor,
                    listener=gate_listener,git_resources=git_resources,gate_profile=gate_profile,
                    review_host=recruitment.root.review_host,quota_client=checkout_client,deadline=budget.deadline)
                stack.callback(gate_resources.close)
                gate_operations=NativeGateOperations(recruitment.root.review_host,gate_resources)
                stack.callback(gate_operations.close)
                NativeGateWorkflow(recruitment.root.review_host,gate_operations.control)
            # One-Run crash recovery retains these exact live host/Hub/Claude
            # owners. The optional second-Run flow remains a separate contract.
            from .native_pi_restore import NativePiSameRunRestore
            pi_restoration=(None if next_request is not None else
                NativePiSameRunRestore(owner,recruitment,human_request,budget,git_operations=git_operations))
            driver=NativeSessionDriver(owner,recruitment,human_request,budget,next_request=next_request,
                                       git_operations=git_operations,human_actions=human_actions,
                                       pi_restoration=pi_restoration,human_control=human_control)
            result=driver.run()
            return {'version':1,'status':'NATIVE_RUN_SESSION_FINISHED','room_id':room['id'],'instance':instance,
                'run_id':result['current_run'],'product_run_created':True,'reviewer_attached':True,
                'session':result,'human_review_actions_attached':human_actions is not None,
                'human_host_attached':human_control is not None,
                'configuration_sha256':plan.config_digest,
                'installation_sha256':plan.installation_digest,
                'lifecycle_blockers':((['NATIVE_COMMAND_DIFF_GATE_PROFILES_UNAVAILABLE',
                                        'NATIVE_GATE_IDENTITY_TRANSPORT_UNAVAILABLE'] if gate_operations is not None else
                                       ['NATIVE_GATE_WORKER_COMPOSITION_UNAVAILABLE'])+
                                      ['NATIVE_SUCCESSOR_GIT_VIEW_UNAVAILABLE'] if git_operations is not None else
                                      ['NATIVE_GIT_GATE_WORKER_COMPOSITION_UNAVAILABLE'])+
                                     ([] if human_control is not None else ['AUTHENTICATED_MANAGER_DISPATCH_UNAVAILABLE'])+
                                     ['FULL_NATIVE_RUN_COMPLETION_UNQUALIFIED'],
                'production_launcher':'disabled'}
        pi_recipe = NativePiRecipe.from_configuration(StringIO(plan.config_text), room['id'], pi_seat.participant_id,
            resources['pi_manifest_path'], plan.installation['pi_manifest']['sha256'], seat=pi_seat, scope=pi_scope,
            checkout=room['project']['roots']['repo'], runtime_root=room['state_root'] + '/runtime',
            endpoint=resources['peer_path'], mounts=mounts, **git_options)
        pi = ExecLaunch(engine, pi_seat, peer_lease, journal / 'pi-launch.json', native_recipe=pi_recipe,
                        timeout=budget.remaining(10))
        stack.callback(pi.close); pi.launch(peer)
        pi.attach_native(journal=journal / 'pi-native.db', scope=pi_scope, profile_digest=pi_recipe.manifest_digest,
                         timeout=budget.remaining(8), initial_state_timeout=budget.remaining(30))
        admission = SupervisorAdmission(pi, pi_admit, control, hub_origin=hub_origin, controller=ready['controller'],
                                        control_lock=control_lock)
        admissions.append(admission)
        admit_once(admission, hashlib.sha256(('qualification-pi-' + instance).encode()).hexdigest()[:32])
        pi_forge = admission.attach_forge_service(broker)
        claude_seat, claude_admit, claude_scope = seats('claude', 'seat-b')
        claude_recipe = NativeClaudeRecipe.from_configuration(StringIO(plan.config_text), room['id'], claude_seat.participant_id,
            resources['claude_manifest_path'], plan.installation['claude_manifest']['sha256'], seat=claude_seat,
            scope=claude_scope, checkout=room['project']['roots']['repo'], home=room['state_root'] + '/runtime/seat-b/contexts/1/home',
            runtime_root=room['state_root'] + '/runtime', endpoint=resources['peer_path'],
            session_id=str(uuid.uuid4()), mounts=mounts, **git_options)
        host = NativeClaudeHostLaunch(engine, claude_recipe, peer_lease, journal / 'claude-launch.json', timeout=budget.remaining(10))
        stack.callback(host.close); host.launch(peer)
        claude = NativeClaudeRoot(host, claude_admit); stack.callback(claude.close)
        review = plan.review_configuration()
        startup = NativeReviewStartup(pi_forge, ledger, provenance, source,
            GateRoomBinding(room['id'], instance, room['project']['id'], room['project']['repository'], room['resources']['disk_bytes']),
            reviewers=review['reviewers'], human_mergers=review['human_mergers'])
        try:
            claude.initialize_helper(peer, journal=journal / 'claude-native.db', control=control, hub_origin=hub_origin,
                controller=ready['controller'], control_lock=control_lock,
                operation_id=hashlib.sha256(('qualification-claude-' + instance).encode()).hexdigest()[:32],
                epoch=1, timeout=budget.remaining(10), forge_client=broker, review_startup=startup)
        except Exception:
            # Reconcile only existing intent owners, never repeat initialization.
            if claude.native_admission is not None:
                try: claude.native_admission.status()
                except Exception: pass
            if claude.helper_lease is not None and claude.helper_lease._admission is not None:
                try: claude.helper_lease.status()
                except Exception: pass
            raise QualificationError('CLAUDE_INITIALIZATION_INCOMPLETE') from None
        finally:
            if claude.native_admission is not None:
                admissions.append(claude.native_admission)
        evidence = {'version': 1, 'status': 'NATIVE_PAIR_ATTACHED', 'production_launcher': 'disabled',
            'room_id': room['id'], 'instance': instance, 'hub_identity': list(hub_origin.identity),
            'pi_identity': list(pi.origin.identity), 'claude_identity': list(claude.origin.identity),
            'controller': ready['controller'], 'same_room_ledger': True,
            'scope_kind': 'synthetic-transport-qualification-only',
            'product_run_created': False, 'git_history': 'new-empty-owner-not-independence-evidence',
            'configuration_sha256': plan.config_digest,
            'installation_sha256': plan.installation_digest,
            'lifecycle_blockers': ['AUTHENTICATED_NATIVE_RUN_HOST_UNAVAILABLE']}
        evidence['dispatch'] = dispatch((pi_forge, claude.forge_service), budget)
        return evidence


def main():
    require(len(sys.argv) in (3,4) and all(x.isdigit() and int(x) >= 3 for x in sys.argv[1:]),
            'INHERITED_BROKER_CHANNEL_REQUIRED')
    raw = sys.stdin.buffer.read(2 * 1048576 + 1)
    require(len(raw) <= 2 * 1048576, 'BOUNDED_TRUSTED_STARTUP_REQUIRED')
    value = json.loads(raw, object_pairs_hook=_unique)
    require(type(value) is dict and set(value) == {'configuration', 'installation', 'installation_digest', 'resources'},
            'INVALID_TRUSTED_STARTUP')
    plan = QualificationPlan(value['configuration'], value['installation'], installation_digest=value['installation_digest'])
    # No serialized human grant. Authenticated hosting may call run(..., human_request=...)
    # after constructing the existing exact HumanSession; CLI remains pair-only.
    arguments=(plan,value['resources'],int(sys.argv[1]),int(sys.argv[2]))
    result = run(*arguments) if len(sys.argv)==3 else run(*arguments,int(sys.argv[3]))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = getattr(error, 'code', type(error).__name__)
        if type(code) is not str or not code.replace('_', '').isalnum() or len(code) > 96:
            code = 'NATIVE_SESSION_FAILED'
        print(json.dumps({'version': 1, 'status': 'FAILED', 'error': code}))
        raise SystemExit(3) from None
