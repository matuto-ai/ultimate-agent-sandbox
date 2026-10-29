"""One retained-host Pi crash restore in the SAME Run, never restart recovery.

The host, Hub, Claude, canonical ledgers and checkout remain held. A journal
supplies session continuity, never task authority. Only an exact held dead task
and authenticated revoke permit one new launch; any uncertain effect holds.
"""
from copy import deepcopy
import hashlib
from io import StringIO
import json
from pathlib import Path
import select
import time

from .kernel_origin import HeldOrigin, OriginDenied, _identity, alive
from .ledger import LedgerError
from .native_pi_recipe import NativePiRecipe, NativePiResume
from .native_pi_rebind import NativePiRebind
from .native_run_admission import NativeRunAdmission, NativeHumanRunRequest
from .native_reviewer_recruitment import NativeReviewerRecruitment
from .pi_runtime import FixturePiRpcReceiver
from .workstation_control import SupervisorAdmission
from .workstation_exec import ExecLaunch


def held_exit(origin):
    """Nonblocking exact retained-pidfd observation; invalid is not dead."""
    if type(origin) is not HeldOrigin or _identity(origin.pidfd) != origin.identity:
        raise OriginDenied('exact retained Pi process identity required')
    poll = select.poll()
    poll.register(origin.pidfd, select.POLLIN)
    events = poll.poll(0)
    if not events:
        return False
    # A reaped task remains the same held pidfd: Linux pidfd_poll adds HUP to
    # IN after reaping. This is not socket EOF or an invalid/reused descriptor.
    exited = (select.POLLIN, select.POLLIN | select.POLLHUP)
    if (len(events) != 1 or events[0][0] != origin.pidfd
            or events[0][1] not in exited or _identity(origin.pidfd) != origin.identity):
        raise OriginDenied('held Pi exit observation unknown')
    return True


class NativePiSameRunRestore:
    def __init__(self, owner, recruitment, request, budget, *, git_operations=None):
        from .native_session import SessionBudget
        if (type(owner) is not NativeRunAdmission or type(recruitment) is not NativeReviewerRecruitment
                or recruitment.owner is not owner or type(request) is not NativeHumanRunRequest
                or type(budget) is not SessionBudget or budget is not owner.launcher.budget):
            raise LedgerError('NATIVE_RESTORE_OWNERS_REQUIRED')
        owner._require_owner()
        old = recruitment.pi
        if (type(old) is not SupervisorAdmission or type(old.launch) is not ExecLaunch
                or type(old.launch.native_recipe) is not NativePiRecipe
                or type(old.launch.origin) is not HeldOrigin
                or type(old.launch.native_receiver) is not FixturePiRpcReceiver
                or old.seat.participant_id != request.participant_id
                or old.launch.native_recipe.scope['run_id'] != owner.run_id(request.operation_id)
                or old.launch.native_recipe.resume is not None):
            raise LedgerError('NATIVE_RESTORE_RETAINED_PI_REQUIRED')
        self.owner, self.recruitment, self.request, self.budget = owner, recruitment, request, budget
        self.old, self.root, self.origin = old, old.launch, old.launch.origin
        self.receiver = self.root.native_receiver
        self.scope = self.root.native_recipe.scope
        self.graph = NativePiRebind(owner, recruitment, old, git_operations)
        self.phase = 'ready'
        self.pin = self.context = self.proof = None
        self.new = None
        self.revoked = False
        self.next_epoch = None
        self.operation = None

    def _unchanged_owners(self):
        if (self.recruitment.pi is not self.old or self.old.launch is not self.root
                or self.root.origin is not self.origin or self.root.native_receiver is not self.receiver
                or self.root.native_recipe.scope != self.scope):
            raise LedgerError('NATIVE_RESTORE_RETAINED_OWNER_CHANGED')
        self.graph.require()

    def _allowed_locked(self):
        owner = self.owner
        owner._require_owner(); owner._room()
        session = self.request.session
        if (session.deployment_id != owner.deployment or session.room_id != owner.ledger.room_id
                or session.instance_id != owner.launcher.resources['instance']
                or not session.allowed('open-run')):
            raise LedgerError('NATIVE_RESTORE_AUTHORIZATION_REVOKED')
        self._unchanged_owners()
        if (self.old.hub_origin is not owner.launcher.hub_origin or self.old.hub_origin.revoked
                or not alive(self.old.hub_origin.pidfd) or self.old.control is not owner.launcher.control
                or self.old.controller != owner.launcher.controller):
            raise OriginDenied('retained Hub authority required for Pi restore')
        self.recruitment.root.forge_service._current()
        owner.launcher.plan.require_unchanged()
        state = owner.ledger.snapshot()['state']
        run = state.get('runs', {}).get(self.scope['run_id'])
        pending = state.get('run_admissions', {}).get(self.scope['run_id'])
        context = state.get('fixture_context', {}).get('participants', {}).get(self.request.participant_id)
        if (not run or run['status'] != 'ACTIVE' or run['generation'] != self.scope['generation']
                or run['participant_id'] != self.old.seat.participant_id or run['actor_id'] != self.old.seat.actor_id
                or run.get('control_pending') or run['checkout']['path'] != self.root.native_recipe.checkout
                or run.get('admission_origin') != session.human.canonical()
                or not pending or pending['status'] != 'ACTIVE'
                or pending['participant_id'] != self.old.seat.participant_id
                or not context or context['status'] != 'READY'
                or context['context_generation'] != self.scope['context_generation']
                or (context.get('bound_run') or context.get('reserved_run')) != {
                    'run_id': self.scope['run_id'], 'generation': self.scope['generation']}
                or context.get('reset') and context['reset']['status'] != 'SUCCEEDED'):
            raise LedgerError('NATIVE_RESTORE_SAME_RUN_REQUIRED')
        if self.pin is not None and (run != self.pin or context != self.context):
            raise LedgerError('NATIVE_RESTORE_CANONICAL_SCOPE_CHANGED')
        return run, context

    def _allowed(self):
        with self.owner.supervisor._locked():
            self._allowed_locked()
            if not held_exit(self.origin):
                raise OriginDenied('original Pi exit required')
        return True

    def _capture_locked(self):
        run, context = self._allowed_locked()
        proof = self.root.native_readiness
        epoch = self.old.forge_service.binding.epoch
        if (type(epoch) is not int or not 0 < epoch < 2**53 - 1
                or type(proof) is not dict or proof.get('scope') != self.scope
                or proof.get('incarnation') != self.root.incarnation
                or proof.get('profile_digest') != self.root.native_recipe.manifest_digest
                or type(proof.get('native')) is not dict
                or proof['native'].get('source') != 'native-empty-session-and-no-pending-messages'
                or self.receiver.scope != self.scope or self.receiver._owns_process
                or self.receiver._binding != {k: proof['native'].get(k) for k in ('runtime_id', 'session_id')}):
            raise LedgerError('NATIVE_RESTORE_NATIVE_BINDING_REQUIRED')
        resume = NativePiResume(proof['native'].get('session_file'), proof['native'].get('session_id'))
        if str(Path(resume.session_file).parent) != self.root.native_recipe.sessions:
            raise LedgerError('NATIVE_RESTORE_SESSION_PATH_CHANGED')
        journal = Path(self.owner.launcher.resources['supervisor_directory']) / ('run-' + self.scope['run_id'] + '-pi.db')
        databases = self.receiver.db.execute('PRAGMA database_list').fetchall()
        binding = self.receiver.db.execute('SELECT scope FROM binding WHERE singleton=1').fetchone()
        if ([row[2] for row in databases if row[1] == 'main'] != [str(journal)]
                or not binding or json.loads(binding[0]) != self.scope
                or self.receiver.db.execute('SELECT count(*) FROM handoffs WHERE session_id != ?',
                                            (resume.session_id,)).fetchone()[0]):
            raise LedgerError('NATIVE_RESTORE_EXISTING_JOURNAL_REQUIRED')
        self.pin, self.context, self.proof = deepcopy(run), deepcopy(context), deepcopy(proof)
        self.resume, self.journal = resume, journal
        self.next_epoch = epoch + 1
        self.operation = hashlib.sha256(('native-pi-restore:' + self.old.controller + ':' +
            self.old.forge_service.binding.operation_id + ':' + str(self.next_epoch)).encode()).hexdigest()[:32]

    def preflight(self):
        """Only the driver's idle/pre-effect cut calls this, never an effect catch."""
        if self.phase == 'restored':
            return False  # The single accepted crash budget is not reset.
        if self.phase != 'ready':
            raise LedgerError('NATIVE_RESTORE_ORIGINAL_OWNER_RECONCILIATION_REQUIRED')
        self.owner._require_owner()
        self._unchanged_owners()
        if not held_exit(self.origin):
            return False
        with self.owner.supervisor._locked():
            self._capture_locked()
        # Set before first effect; no uncertain revoke, launch, or ADMIT is repeated.
        self.phase = 'revoking'
        try:
            self._allowed()
            result = self.old.revoke(deadline=time.monotonic() + self.budget.remaining(5))
            if (type(result) is not dict or result.get('installed') is not False
                    or result.get('state') not in ('revoked', 'absent')):
                raise OriginDenied('authenticated Pi revocation unconfirmed')
            self.revoked = True
            self._allowed()
            # Exact native task exited. Close only its retained RPC receiver and
            # transport, not checkout, descendants, Hub or shared control channel.
            self.receiver.close()
            self.root.close_transport()
            self.phase = 'launching'
            self._launch()
            self.phase = 'restored'
            return True
        except BaseException:
            self.phase = 'unknown'
            if self.new is not None:
                # One deny-only cleanup attempt; no claim that a new task exited.
                try: self.new.revoke(deadline=time.monotonic() + self.budget.remaining(2))
                except BaseException: pass
            raise

    def _launch(self):
        from .native_session import admit_once
        launcher = self.owner.launcher
        self._allowed()
        recipe = NativePiRecipe.from_configuration(StringIO(launcher.plan.config_text),
            launcher.plan.room['id'], self.request.participant_id,
            launcher.resources['pi_manifest_path'], launcher.plan.installation['pi_manifest']['sha256'],
            seat=launcher.exec_seat, scope=self.scope, checkout=self.pin['checkout']['path'],
            runtime_root=launcher.plan.room['state_root'] + '/runtime', endpoint=launcher.resources['peer_path'],
            mounts=launcher.mounts, resume=self.resume,
            git_profile=self.root.native_recipe.git_profile, gate_profile=self.root.native_recipe.gate_profile)
        if (recipe.scope != self.scope or recipe.checkout != self.root.native_recipe.checkout
                or recipe.manifest_digest != self.root.native_recipe.manifest_digest
                or recipe.sessions != self.root.native_recipe.sessions):
            raise LedgerError('NATIVE_RESTORE_RECIPE_CHANGED')
        journal = self.journal.with_name('run-' + self.scope['run_id'] + '-pi-restore-e' + str(self.next_epoch) + '.json')
        launch = ExecLaunch(launcher.engine, launcher.exec_seat, launcher.endpoint, journal,
                            native_recipe=recipe, timeout=self.budget.remaining(10))
        launcher.stack.callback(launch.close)
        launch.launch(launcher.listener, authorize=self._allowed)
        self._allowed()
        launch.attach_native(journal=self.journal, scope=self.scope, profile_digest=recipe.manifest_digest,
            timeout=self.budget.remaining(8), initial_state_timeout=self.budget.remaining(30),
            preceding_runtime_id=self.proof['native']['runtime_id'])
        self._allowed()
        new = SupervisorAdmission(launch, launcher.admission_seat, launcher.control,
            hub_origin=launcher.hub_origin, controller=launcher.controller, control_lock=launcher.control_lock)
        self.new = new
        launcher.admissions.append(new)
        if launch.incarnation == self.root.incarnation or launch.origin.identity == self.origin.identity:
            raise OriginDenied('fresh held Pi incarnation required')
        admit_once(new, self.operation, epoch=self.next_epoch)
        self._allowed()
        new.attach_forge_service(launcher.forge_broker.client)
        sample = launch.native_receiver.prepare_admission_observation()  # No held lifecycle/ledger lock.
        try:
            with self.owner.supervisor._locked() as capability:
                self._allowed_locked()
                if not self.revoked or not self.origin.revoked or not held_exit(self.origin):
                    raise OriginDenied('old Pi revocation/exit changed')
                self.graph.apply(new, capability, sample)
        finally:
            launch.native_receiver.discard_admission_observation(sample)

    def result(self):
        return {'phase': self.phase, 'canonical_revoked': self.revoked,
                'old_incarnation': self.root.incarnation,
                'new_incarnation': None if self.new is None else self.new.launch.incarnation,
                'epoch': self.next_epoch, 'same_run': dict(self.scope),
                'authority_restored_from_journal': False, 'checkout_released': False,
                'descendant_quiescence_claimed': False}
