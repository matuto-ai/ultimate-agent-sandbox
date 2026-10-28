"""Initial native Pi Run admission using canonical Run transitions and owners.

No serialized human identity grants authority. The authenticated host supplies an
existing HumanSession; root owns checkout allocation, this host owns native tasks.
Reset, replacement, migration and stop remain unavailable here, never fixture APIs.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from io import StringIO
import hashlib
from pathlib import Path
import threading

from .config import load
from .context import FixtureContextHub
from .ledger import LedgerError
from .manager_actions import HumanSession
from .native_admission_broker import NativeAdmissionBroker
from .native_checkout_handoff import NativeCheckoutClient
from .native_host_forge import NativePiHostForge
from .native_pi_recipe import NativePiRecipe
from .native_qualification import QualificationPlan
from .peer import FixturePeerHub, Readiness
from .run_admission import RunAdmission
from .workstation_control import SupervisorAdmission
from .workstation_exec import ExecLaunch, ExecSeat, EndpointLease
from .workstation_admission import AdmissionSeat


@dataclass(frozen=True)
class NativeHumanRunRequest:
    """Trusted hosting API only: HumanSession is never parsed from JSON."""
    operation_id: str
    issue_number: int
    participant_id: str
    session: HumanSession
    attempt_id: str | None = None

    def __post_init__(self):
        if type(self.session) is not HumanSession:
            raise LedgerError('MANAGER_AUTHENTICATION_REQUIRED')


@dataclass(frozen=True)
class NativeRunSeat:
    participant_id: str
    actor_id: str
    profile_id: str
    capabilities: tuple
    selection: str
    runtime: str = 'pi-native'

    def document(self):
        import json
        return {'participant_id': self.participant_id, 'actor_id': self.actor_id,
                'profile_id': self.profile_id, 'capabilities': list(self.capabilities),
                'runtime': self.runtime, 'configured_selection': json.loads(self.selection)}


class NativeRunLauncher:
    """Exact held host resources; no caller-selected recipe, process or authority."""
    def __init__(self, plan, resources, supervisor, ledger, broker, *, engine,
                 endpoint, listener, control, hub_origin, controller, control_lock,
                 exec_seat, admission_seat, mounts, stack, admissions, budget):
        from .native_session import SessionBudget
        from .docker_exec_api import DockerExecAPI
        if (type(plan) is not QualificationPlan or type(broker) is not NativeAdmissionBroker
                or broker.ledger is not ledger or broker.client.supervisor is not supervisor
                or type(engine) is not DockerExecAPI or type(endpoint) is not EndpointLease
                or type(exec_seat) is not ExecSeat or type(admission_seat) is not AdmissionSeat
                or type(budget) is not SessionBudget
                or exec_seat.participant_id != plan.seats['pi']['participant']
                or exec_seat.actor_id != plan.seats['pi']['actor']
                or exec_seat.room_id != ledger.room_id
                or exec_seat.room_instance != resources['instance']
                or admission_seat.participant_id != exec_seat.participant_id
                or admission_seat.actor_id != exec_seat.actor_id):
            raise LedgerError('ADMISSION_BINDING_MISMATCH')
        selected = plan.seats['pi']
        profile = next(p for p in plan.room['profiles'] if p['id'] == selected['profile'])
        if (admission_seat.room_id != exec_seat.room_id
                or admission_seat.room_instance != exec_seat.room_instance
                or admission_seat.profile_id != selected['profile']
                or set(admission_seat.capabilities) != set(profile['capabilities']) | {'peer-traffic'}
                or str(endpoint.path) != resources['peer_path']):
            raise LedgerError('ADMISSION_BINDING_MISMATCH')
        self.plan, self.resources, self.supervisor = plan, deepcopy(resources), supervisor
        self.hub, self.forge_broker = FixturePeerHub(ledger), broker
        self.engine, self.endpoint, self.listener = engine, endpoint, listener
        self.control, self.hub_origin, self.controller = control, hub_origin, controller
        self.control_lock, self.exec_seat, self.admission_seat = control_lock, exec_seat, admission_seat
        self.mounts, self.stack, self.admissions, self.budget = tuple(mounts), stack, admissions, budget
        self.started = {}  # Held objects only; journal text never restores task authority.

    def launch(self, run, pending, slot, *, authorize):
        from .native_session import admit_once
        if not callable(authorize):
            raise LedgerError('ADMISSION_REVOKED')
        def allowed():
            with self.supervisor._locked():
                state = self.supervisor._read()
                if (not state or state['phase'] != 'running' or state['desired'] != 'running'
                        or state['instance_id'] != self.resources['instance'] or authorize() is not True):
                    raise LedgerError('ADMISSION_REVOKED')
            return True
        allowed()
        self.plan.require_unchanged()
        participant = self.exec_seat.participant_id
        if pending.get('preceding_run') is not None or pending['context_generation'] != 1:
            raise LedgerError('NATIVE_CONTEXT_RESET_UNAVAILABLE')
        if participant in self.started:
            held = self.started[participant]
            if (type(held) is not SupervisorAdmission or held.launch.native_recipe.scope['run_id'] != run):
                raise LedgerError('NATIVE_ADMISSION_RECONCILIATION_REQUIRED')
            held._current()
            allowed()
            return held
        scope = {'room_id': self.hub.ledger.room_id, 'participant_id': participant,
                 'run_id': run, 'generation': 1, 'context_generation': 1}
        journal = Path(self.resources['supervisor_directory'])
        # Mark before the first native effect. Unknown launch cannot become a
        # second process on a later explicit attempt, even if no handle returned.
        self.started[participant] = None
        recipe = NativePiRecipe.from_configuration(StringIO(self.plan.config_text),
            self.plan.room['id'], participant, self.resources['pi_manifest_path'],
            self.plan.installation['pi_manifest']['sha256'], seat=self.exec_seat,
            scope=scope, checkout=slot['path'], runtime_root=self.plan.room['state_root']+'/runtime',
            endpoint=self.resources['peer_path'], mounts=self.mounts)
        if recipe.checkout != slot['path']:
            raise LedgerError('NATIVE_CHECKOUT_MISMATCH')
        launch = ExecLaunch(self.engine, self.exec_seat, self.endpoint,
            journal/('run-'+run+'-pi.json'), native_recipe=recipe, timeout=self.budget.remaining(10))
        self.stack.callback(launch.close)
        admission = None
        try:
            allowed()
            launch.launch(self.listener, authorize=allowed)
            allowed()
            launch.attach_native(journal=journal/('run-'+run+'-pi.db'), scope=scope,
                profile_digest=recipe.manifest_digest, timeout=self.budget.remaining(8),
                initial_state_timeout=self.budget.remaining(30))
            allowed()
            admission = SupervisorAdmission(launch, self.admission_seat, self.control,
                hub_origin=self.hub_origin, controller=self.controller, control_lock=self.control_lock)
            self.admissions.append(admission)
            allowed()
            admit_once(admission, hashlib.sha256(('native-run-'+self.resources['instance']+run).encode()).hexdigest()[:32])
            allowed()
            admission.attach_forge_service(self.forge_broker.client)
            allowed()
            self.started[participant] = admission
            return admission
        except BaseException:
            # Revoke only exact retained owners. Keep the one-shot started marker
            # and journals; transport closure is not a claim that the task exited.
            try:
                if admission is not None: admission.revoke()
            finally:
                launch.close()
            raise



class NativeRunAdmission(RunAdmission):
    """Canonical initial admission; unsupported inherited fixture effects denied."""
    def __init__(self, launcher, allocator, checkout_client):
        import json
        if (type(launcher) is not NativeRunLauncher or type(checkout_client) is not NativeCheckoutClient
                or allocator.supervisor is not launcher.supervisor):
            raise LedgerError('ADMISSION_BINDING_MISMATCH')
        self.launcher, self.checkout_client = launcher, checkout_client
        self._session = None
        self._owner_thread = threading.get_ident()
        config = load(StringIO(launcher.plan.config_text))
        selected = launcher.plan.seats['pi']
        profile = next(p for p in launcher.plan.room['profiles'] if p['id'] == selected['profile'])
        seat = NativeRunSeat(selected['participant'], selected['actor'], selected['profile'],
            tuple(sorted(set(profile['capabilities']) | {'peer-traffic'})), json.dumps(selected,sort_keys=True))
        super().__init__(launcher, launcher.forge_broker, allocator, StringIO(launcher.plan.config_text),
            seats={seat.participant_id: seat}, install=None,
            runtime_root=launcher.plan.room['state_root']+'/runtime', authorize_human=self._session_authorized)
        self.deployment = config['deployment']['id']

    @staticmethod
    def _runtime_binding(configured, seat):
        return type(seat) is NativeRunSeat and configured['runtime'] == 'pi' and seat.runtime == 'pi-native'

    def _require_owner(self):
        if threading.get_ident() != self._owner_thread:
            raise LedgerError('NATIVE_ADMISSION_OWNER_THREAD')

    @contextmanager
    def human_scope(self, session):
        self._require_owner()
        if (self._session is not None or type(session) is not HumanSession
                or session.deployment_id != self.deployment or session.room_id != self.ledger.room_id
                or session.instance_id != self.launcher.resources['instance']):
            raise LedgerError('MANAGER_AUTHENTICATION_REQUIRED')
        self._session = session
        try: yield
        finally: self._session = None

    def _session_authorized(self, origin, command):
        self._require_owner()
        session = self._session
        action = ('open-run' if command.kind in {'run.human-open','run.admission-attempt','run.admission-attempt-result'}
                  else 'authorize-run-request')
        return session is not None and origin == session.human and session.allowed(action)

    def open_human(self, operation_id, issue_number, participant_id, *, session, attempt_id=None):
        with self.human_scope(session):
            return self._open(operation_id, issue_number, participant_id, session.human, attempt_id=attempt_id)

    def _room(self):
        state = self.supervisor._read()
        if (not state or state['phase'] != 'running' or state['desired'] != 'running'
                or state['instance_id'] != self.launcher.resources['instance']):
            raise LedgerError('ROOM_NOT_RUNNING')

    def _participant_started(self, participant):
        return participant in self.launcher.started

    def _slot(self, run, participant, *, authorize=None):
        if authorize is not None and authorize() is not True:
            raise LedgerError('ADMISSION_REVOKED')
        pending = self._pending(run)
        if pending is None or pending['participant_id'] != participant:
            raise LedgerError('ADMISSION_BINDING_MISMATCH')
        method = (self.checkout_client.observe if participant in self.launcher.started
                  else self.checkout_client.allocate)
        slot = method(run, pending['admission_operation'])
        if (slot['run'] != run or slot['participant'] != participant or slot['phase'] != 'ready'
                or slot['reason'] != 'ACTIVE' or slot['observed_dirty'] is not False
                or slot['observed_head'] != slot['base']):
            raise LedgerError('CHECKOUT_NOT_READY')
        if authorize is not None and authorize() is not True:
            raise LedgerError('ADMISSION_REVOKED')
        return slot

    def _authority(self, handle):
        if (type(handle) is not SupervisorAdmission or type(handle.forge_service) is not NativePiHostForge
                or handle.forge_service.client is not self.broker.client
                or self.launcher.started.get(handle.seat.participant_id) is not handle):
            raise LedgerError('NATIVE_ADMISSION_BINDING')
        self._room()
        handle.forge_service._current()
        self._current_attachment(self.ledger.snapshot()['state'], handle)
        return True

    def _current_attachment(self, state, handle):
        ingress = handle.forge_service
        row = state.get('peer_traffic',{}).get('connections',{}).get(handle.seat.participant_id)
        definition = state.get('peer_traffic',{}).get('definition',{}).get('participants',{}).get(handle.seat.participant_id)
        if (not row or not definition or definition['actor_id'] != handle.seat.actor_id
                or row['attachment_id'] != 'admit-'+ingress.binding.operation_id
                or row['incarnation_id'] != handle.launch.incarnation or row['readiness'] == 'lost'):
            raise LedgerError('STALE_CONNECTION')
        scope = handle.launch.native_recipe.scope
        contexts = self.hub.contexts
        if (row.get('context_generation') != scope['context_generation']
                or not contexts.permits(handle.seat.participant_id, scope['context_generation'],
                                        scope['run_id'], scope['generation'], state)):
            raise LedgerError('STALE_CONNECTION')
        return row

    def _observe_handle(self, handle):
        with self.supervisor._locked():
            self._authority(handle)
            if handle.launch.native_receiver.observe() is not Readiness.SAFE:
                raise LedgerError('NATIVE_NOT_SAFE')
        # Existing authenticated delivery poll marks SAFE in the canonical Hub;
        # no synthetic FixtureConnection or Hub-supplied Actor is constructed.
        if handle._delivery_exchange('POLL_DELIVERY') != {'status':'HELD'}:
            raise LedgerError('UNUSED_NATIVE_CONTEXT_REQUIRED')

    def _safe_handle(self, handle):
        return handle.launch.native_receiver.observe() is Readiness.SAFE

    def _current_context(self, state, handle, run, pending):
        handle.forge_service._current()
        row = self._current_attachment(state,handle)
        context = state['fixture_context']['participants'][pending['participant_id']]
        scope = handle.launch.native_recipe.scope
        expected = {'room_id': self.ledger.room_id, 'participant_id': pending['participant_id'],
                    'run_id': run, 'generation':1, 'context_generation':pending['context_generation']}
        if (row['readiness'] != 'safe' or context['status'] != 'READY'
                or context['context_generation'] != expected['context_generation']
                or (context['bound_run'] or context['reserved_run']) != {'run_id':run,'generation':1}
                or scope != expected or handle.launch.native_receiver.scope != expected):
            raise LedgerError('CONTEXT_MISMATCH')

    def _handle_origin(self, handle):
        return handle.forge_service.origin

    def _advance(self, run, command, pending, attempt_id, terminal,
                 issue_number, participant_id, human, authorize):
        if (self._seat_binding(participant_id) != pending['seat_binding']
                or self.seats[participant_id].actor_id != pending['actor_id']
                or self.actors[pending['actor_id']].get('github_user_id') != pending['github_user_id']):
            raise LedgerError('ACTOR_BINDING_CHANGED')
        if pending.get('preceding_run') is not None:
            raise LedgerError('NATIVE_CONTEXT_RESET_UNAVAILABLE')
        def allowed():
            return authorize(human,command) and self._pending(run)['status']=='PREPARING'
        with self.supervisor._locked():
            self._room()
            if not allowed(): raise LedgerError('ADMISSION_REVOKED')
        slot = self._slot(run,participant_id,authorize=allowed)
        handle = self.launcher.launch(run,pending,slot,authorize=allowed)
        return self._observe_and_activate(run,command,pending,attempt_id,terminal,
            issue_number,participant_id,human,authorize,handle,slot)

    def _unsupported(self,*args,**kwargs):
        raise LedgerError('NATIVE_RUN_CONTROL_UNAVAILABLE')

    open = pause = resume = manager_action = manager_eligibility = _unsupported
    migrate_policy = force_stop = terminal_stop = withdraw = _unsupported
    appoint_coordinator = reconcile_coordinator = nominate_coordinator = _unsupported

    issue_request = propose = approve_proposal = revoke_request = open_requested = submit = _unsupported
