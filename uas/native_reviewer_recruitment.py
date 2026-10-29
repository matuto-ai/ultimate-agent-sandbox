"""Initial unopened Claude reviewer recruitment on the canonical Room ledger.

No relabeling of a running conversation and no reset/termination claim. Existing
native host/child/helper admission supplies process authority; context reservation
only selects the unopened configured seat for this already-authorized active Run.
"""
from contextlib import contextmanager
from copy import deepcopy
from io import StringIO
from pathlib import Path
import hashlib
import os
import uuid

from .artifact_target import ArtifactSourceResolver
from .git_provenance import GitProvenance
from .gate_evaluation import GateRoomBinding
from .claude_native_admission import NativeClaudeHostLaunch, NativeClaudeRoot
from .context import FixtureRun, FixtureContextHub
from .ledger import Command, Event, Transition, LedgerError, _token
from .manager_actions import HumanSession
from .native_claude_recipe import NativeClaudeRecipe
from .native_host_forge import NativePiHostForge
from .native_review_host import NativeReviewStartup
from .native_run_admission import NativeRunAdmission
from .peer import FixturePeerHub
from .workstation_admission import AdmissionSeat
from .workstation_control import SupervisorAdmission
from .workstation_exec import ExecSeat


class NativeReviewerRecruitment:
    def __init__(self, owner, pi, provenance, resolver, binding):
        if (type(owner) is not NativeRunAdmission or type(pi) is not SupervisorAdmission
                or type(pi.forge_service) is not NativePiHostForge
                or owner.launcher.started.get(pi.seat.participant_id) is not pi
                or pi.forge_service.client is not owner.broker.client
                or type(resolver) is not ArtifactSourceResolver or type(provenance) is not GitProvenance
                or type(binding) is not GateRoomBinding or resolver.supervisor is not owner.supervisor
                or provenance.room_id != owner.ledger.room_id or binding.room_id != owner.ledger.room_id
                or provenance.project_id != binding.project_id or binding.room_instance != owner.launcher.resources['instance']):
            raise LedgerError('NATIVE_REVIEWER_BINDING')
        self.owner,self.pi=owner,pi
        self.launcher=owner.launcher
        self.ledger,self.supervisor=owner.ledger,owner.supervisor
        self.provenance,self.resolver,self.binding=provenance,resolver,binding
        self.selected=deepcopy(self.launcher.plan.seats['claude'])
        self.profile=next(p for p in self.owner.room['profiles'] if p['id']==self.selected['profile'])
        if ('review' not in self.profile['capabilities'] or self.selected['actor']==pi.seat.actor_id
                or self.selected['participant']==pi.seat.participant_id):
            raise LedgerError('NATIVE_REVIEWER_BINDING')
        review=self.launcher.plan.review_configuration()
        if not any(r['participant_id']==self.selected['participant'] and r['actor_id']==self.selected['actor']
                   for r in review['reviewers']):
            raise LedgerError('NATIVE_REVIEWER_BINDING')
        self.review=review
        self._operation=None;self._pin=None;self._session=None;self._busy=False
        self._reserved=False;self._started=False;self.root=None;self.host=None
        self._capability=None;self._source=None;self._reset=None;self._context_generation=1
        self.journal=Path(self.launcher.resources['supervisor_directory'])/'claude-launch.json'

    @staticmethod
    def _scope(run):
        return deepcopy({k:run.get(k) for k in ('run_id','generation','status','participant_id','actor_id',
            'github_user_id','checkout','policy','control_revision','admission_operation','admission_origin')})

    @contextmanager
    def _fence(self):
        if self._capability is not None:raise LedgerError('NATIVE_REVIEWER_NESTED_FENCE')
        with self.supervisor._locked() as capability:
            self._capability=capability
            try:yield
            finally:self._capability=None

    def _allowed_locked(self,state=None):
        self.owner._require_owner();self.owner._room()
        session=self._session
        if (type(session) is not HumanSession or session.deployment_id!=self.owner.deployment
                or session.room_id!=self.ledger.room_id
                or session.instance_id!=self.launcher.resources['instance']
                or 'human-open-run' not in session.human.capabilities or not session.allowed('open-run')):
            raise LedgerError('NATIVE_REVIEWER_AUTHORIZATION_REVOKED')
        self.owner._authority(self.pi)
        state=self.ledger.snapshot()['state'] if state is None else state
        run=state.get('runs',{}).get(self._pin['run_id'])
        if (run is None or run['status']!='ACTIVE' or self._scope(run)!=self._pin
                or run.get('admission_origin')!=session.human.canonical()
                or self.pi.launch.native_recipe.scope['run_id']!=run['run_id']
                or self.pi.launch.native_recipe.scope['generation']!=run['generation']):
            raise LedgerError('NATIVE_REVIEWER_RUN_CHANGED')
        self.launcher.plan.require_unchanged()
        if self._capability is None:raise LedgerError('NATIVE_REVIEWER_FENCE_REQUIRED')
        source=self.resolver.resolve_locked(self._capability,run['run_id'],run['participant_id'],
                                            self.launcher.resources['instance'])
        if self._source is None:self._source=deepcopy(source)
        elif source!=self._source:raise LedgerError('NATIVE_REVIEWER_SOURCE_CHANGED')
        definition=state['peer_traffic']['definition']['participants'].get(self.selected['participant'])
        if not definition or definition['actor_id']!=self.selected['actor']:
            raise LedgerError('NATIVE_REVIEWER_BINDING')
        if self._reserved and self._reset is not None:
            self._reset.allowed(state)
        elif self._reserved:
            row=state['fixture_context']['participants'][self.selected['participant']]
            if (row['status']!='READY' or row['context_generation']!=1 or row['reset'] is not None
                    or (row['bound_run'] or row['reserved_run'])!={'run_id':run['run_id'],'generation':run['generation']}):
                raise LedgerError('NATIVE_REVIEWER_CONTEXT_CHANGED')
        if self.root is not None and getattr(self.root, 'review_host', None) is not None:
            self.root.review_host.identity.seat_current(
                self.root.forge_service, state, run['run_id'], run['generation'])
        return True

    def _allowed(self):
        with self._fence():return self._allowed_locked()

    def recruit(self,operation_id,run_id,generation,*,session,reset_from=None):
        self.owner._require_owner();_token(operation_id);_token(run_id)
        if self._busy:raise LedgerError('NATIVE_REVIEWER_BUSY')
        if type(generation) is not int or not 1<=generation<2**53:
            raise LedgerError('INVALID_SCOPE')
        if self._operation is not None and self._operation!=(operation_id,run_id,generation):
            raise LedgerError('NATIVE_REVIEWER_OPERATION_CONFLICT')
        self._busy=True;self._session=session
        try:
            with self._fence():
                run=self.ledger.snapshot()['state'].get('runs',{}).get(run_id)
                if run is None or run['generation']!=generation:raise LedgerError('UNKNOWN_RUN')
                if self._pin is None:self._pin=self._scope(run)
                self._allowed_locked()
                if reset_from is not None:
                    from .native_reviewer_reset import NativeReviewerReset
                    if self._reset is None:
                        self._reset=NativeReviewerReset(self,reset_from,operation_id)
                        self._context_generation=self._reset.next_generation
                        self.journal=Path(self.launcher.resources['supervisor_directory'])/('claude-launch-g'+str(self._context_generation)+'.json')
                    elif self._reset.previous is not reset_from:
                        raise LedgerError('NATIVE_RESET_OWNERS_REQUIRED')
                    self._reset.request_locked()
                elif self._reset is not None:
                    raise LedgerError('NATIVE_RESET_OWNERS_REQUIRED')
                command=Command(operation_id,'context.native-reviewer-reserve',run_id,generation,
                    {'participant_id':self.selected['participant'],'configured_seat':self.selected,
                     'run_scope':self._pin})
                def decide(state,_):
                    self._allowed_locked(state)
                    if self._started or os.path.lexists(self.journal):
                        raise LedgerError('NATIVE_REVIEWER_RESET_REQUIRED')
                    if not FixtureContextHub.unused_initial(state,self.selected['participant']):
                        raise LedgerError('NATIVE_REVIEWER_RESET_REQUIRED')
                    FixtureContextHub.reserve_unused_initial(state,self.selected['participant'],FixtureRun(run_id,generation))
                    FixturePeerHub._reserve_capacity(state)
                    result={'run_id':run_id,'generation':generation,'participant_id':self.selected['participant'],
                            'context_generation':1,'status':'RESERVED'}
                    return Transition(state,(Event('context.native-reviewer-reserved',result),),result)
                if self._reset is None:
                    self.ledger.apply(command,session.human,authorize=lambda *_:self._allowed_locked(),decide=decide)
                self._operation=(operation_id,run_id,generation);self._reserved=True
            if self.root is not None:
                self._allowed()
                if self.root.forge_service is None or getattr(self.root,'review_host',None) is None:
                    raise LedgerError('NATIVE_REVIEWER_RECONCILIATION_REQUIRED')
                with self.supervisor._locked():self.root.forge_service._current()
                return self.root
            if self._started:raise LedgerError('NATIVE_REVIEWER_RECONCILIATION_REQUIRED')
            if self._reset is not None:self._reset.retire()
            self._started=True
            return self._launch(operation_id,run_id,generation)
        finally:
            self._session=None;self._busy=False

    def _launch(self,operation_id,run_id,generation):
        launch=self.launcher;plan=launch.plan;room=self.owner.room;selected=self.selected
        resources=launch.resources;instance=resources['instance'];journal=Path(resources['supervisor_directory'])
        seat=ExecSeat(room['id'],instance,selected['participant'],selected['actor'],'seat-b',
            resources['workstation_id'],165532,165532)
        admitted=AdmissionSeat(room['id'],instance,selected['participant'],selected['actor'],selected['profile'],
            tuple(sorted(set(self.profile['capabilities'])|{'peer-traffic'})),launch.admission_seat.receiver)
        scope={'room_id':room['id'],'participant_id':selected['participant'],'run_id':run_id,
               'generation':generation,'context_generation':self._context_generation}
        self._allowed()
        recipe=NativeClaudeRecipe.from_configuration(StringIO(plan.config_text),room['id'],selected['participant'],
            resources['claude_manifest_path'],plan.installation['claude_manifest']['sha256'],seat=seat,scope=scope,
            checkout=self._pin['checkout']['path'],home=room['state_root']+'/runtime/seat-b/contexts/'+str(self._context_generation)+'/home',
            runtime_root=room['state_root']+'/runtime',endpoint=resources['peer_path'],session_id=str(uuid.uuid4()),
            mounts=launch.mounts,
            **({} if getattr(launch,'git_resources',None) is None else {'git_profile':launch.git_resources.profile}),
            **({} if getattr(launch,'gate_profile',None) is None else {'gate_profile':launch.gate_profile}))
        if recipe.scope!=scope or recipe.checkout!=self._pin['checkout']['path']:
            raise LedgerError('NATIVE_REVIEWER_BINDING')
        host=NativeClaudeHostLaunch(launch.engine,recipe,launch.endpoint,self.journal,timeout=launch.budget.remaining(10))
        self.host=host;launch.stack.callback(host.close)
        try:
            host.launch(launch.listener,authorize=self._allowed)
            self._allowed()
            root=NativeClaudeRoot(host,admitted);self.root=root;launch.stack.callback(root.close)
            startup=NativeReviewStartup(self.pi.forge_service,self.ledger,self.provenance,self.resolver,self.binding,
                reviewers=self.review['reviewers'],human_mergers=self.review['human_mergers'])
            initialize=root.initialize_helper if self._reset is None else root.prepare_helper
            native_journal=journal/('claude-native.db' if self._reset is None else 'claude-native-g'+str(self._context_generation)+'.db')
            initialize(launch.listener,journal=native_journal,control=launch.control,
                hub_origin=launch.hub_origin,controller=launch.controller,control_lock=launch.control_lock,
                operation_id=hashlib.sha256(('native-reviewer-'+instance+operation_id).encode()).hexdigest()[:32],
                epoch=1 if self._reset is None else self._reset.next_epoch,
                timeout=launch.budget.remaining(10),forge_client=self.owner.broker.client,
                review_startup=startup,authorize=self._allowed)
            if self._reset is not None:
                self._reset.complete(root)
                root.admit_prepared_helper()
            self._allowed()
            with self.supervisor._locked():root.forge_service._current()
            return root
        except BaseException:
            root=self.root
            try:
                if root is not None and root.native_admission is not None:root.native_admission.revoke()
            finally:
                if root is not None:root.close()
                host.close()
            raise
        finally:
            if self.root is not None and self.root.native_admission is not None:
                launch.admissions.append(self.root.native_admission)
