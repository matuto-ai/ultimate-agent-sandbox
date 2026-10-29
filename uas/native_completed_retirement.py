"""Exact all-target retirement annotation for an already completed native Run."""
from copy import deepcopy

from .claude_native_admission import NativeClaudeRoot
from .ledger import LedgerError
from .native_claude_retirement import NativeClaudeRetirement
from .native_pi_retirement import NativePiRetirement
from .native_reviewer_recruitment import NativeReviewerRecruitment
from .workstation_control import SupervisorAdmission


class NativeCompletedRetirement:
    def __init__(self, owner, reviewer, operation_id, run_id):
        from .native_run_admission import NativeRunAdmission
        if (type(owner) is not NativeRunAdmission or type(reviewer) is not NativeReviewerRecruitment
                or reviewer.owner is not owner or reviewer.ledger is not owner.ledger
                or reviewer.supervisor is not owner.supervisor):
            raise LedgerError('NATIVE_RETIREMENT_OWNER_REQUIRED')
        self.owner,self.reviewer=owner,reviewer
        self.operation_id,self.run_id=operation_id,run_id
        self.owners={owner.launcher.exec_seat.participant_id:owner.launcher.started.get(owner.launcher.exec_seat.participant_id),
                     reviewer.selected['participant']:reviewer.root}
        self.targets=None;self.retirements={}

    @classmethod
    def from_local_stop(cls, observations, owner, reviewer, operation_id, run_id):
        from .local_native_stop import LocalNativeStopObservations
        from .local_runtime_plan import LocalRuntimePlan
        if (cls is not NativeCompletedRetirement or type(observations) is not LocalNativeStopObservations
                or observations.owner is not owner or observations.reviewer is not reviewer
                or observations.run_id!=run_id or type(owner.launcher.plan) is not LocalRuntimePlan):
            raise LedgerError('LOCAL_STOP_OWNER_REQUIRED')
        observations.require_exited()
        if observations.adopted is not None:
            held=observations.adopted
            if held.operation_id!=operation_id:raise LedgerError('LOCAL_STOP_ALREADY_ADOPTED')
            return held
        row=observations._unchanged()
        if row.get('control_pending') is not None or row.get('control_revision',0)!=observations.revision:
            raise LedgerError('LOCAL_STOP_SCOPE_CHANGED')
        held=cls(owner,reviewer,operation_id,run_id)
        if any(held.owners.get(key) is not value for key,value in observations.held.owners.items()):
            raise LedgerError('LOCAL_STOP_OWNER_CHANGED')
        held.targets=deepcopy(observations.targets)
        held.retirements=dict(observations.held.retirements)
        held._local_stop_observations=observations
        observations.adopted=held
        return held

    def _targets(self,state):
        targets=self.owner._control_contexts(state,self.run_id)
        for target in targets:
            participant=target['participant_id']
            definition=state['peer_traffic']['definition']['participants'].get(participant)
            row=state['peer_traffic']['connections'].get(participant)
            target.update(actor_id=None if definition is None else definition['actor_id'],
                incarnation_id=None if row is None else row['incarnation_id'],
                attachment_id=None if row is None else row['attachment_id'])
        return targets

    def capture(self,state,run_id):
        if run_id!=self.run_id:raise LedgerError('NATIVE_RETIREMENT_OWNER_REQUIRED')
        targets=self._targets(state)
        if self.targets is not None and self.targets!=targets:
            raise LedgerError('NATIVE_OWNERSHIP_CHANGED')
        self.targets=deepcopy(targets)
        self.completion_digest=self.owner._completion_digest(state['runs'][run_id])
        self.completed_revision=state['runs'][run_id].get('control_revision',0)+1
        return targets

    def validate(self,state,pending):
        self.owner._room()
        row=state.get('runs',{}).get(self.run_id)
        if (row is None or row.get('control_pending')!=pending
                or row['control_revision']!=pending['control_revision']
                or self.owner._completion_digest(row)!=pending['completion_digest']
                or pending['operation_id']!=self.operation_id or pending['targets']!=self.targets
                or self._targets(state)!=self.targets):
            raise LedgerError('NATIVE_OWNERSHIP_CHANGED')
        self._validate_owners()
        return True

    def _validate_owners(self):
        for target in self.targets:
            participant=target['participant_id'];held=self.owners.get(participant)
            if type(held) is SupervisorAdmission:
                if self.owner.launcher.started.get(participant) is not held:
                    raise LedgerError('NATIVE_OWNERSHIP_CHANGED')
                scope=held.launch.native_recipe.scope;ingress=held.forge_service
            elif type(held) is NativeClaudeRoot:
                if self.reviewer.root is not held:raise LedgerError('NATIVE_OWNERSHIP_CHANGED')
                scope=held.scope;ingress=held.forge_service
            else:raise LedgerError('NATIVE_RETIREMENT_CUSTODY_UNKNOWN')
            if (ingress is None or scope!=target['scope']
                    or ingress.origin.actor_id!=target['actor_id']
                    or ingress.origin.incarnation_id!=target['incarnation_id']
                    or 'admit-'+ingress.binding.operation_id!=target['attachment_id']):
                raise LedgerError('NATIVE_OWNERSHIP_CHANGED')
        return True

    def stop(self,pending,human,command):
        owner=self.owner
        observations=getattr(self,'_local_stop_observations',None)
        if observations is not None:
            with owner.supervisor._locked():
                if not owner._control_authorized(pending,human,command):raise LedgerError('FORBIDDEN')
                self.validate(owner.ledger.snapshot()['state'],pending)
                observations.require_exited()
                self.verify(pending)
            return
        with owner.supervisor._locked() as capability:
            if not owner._control_authorized(pending,human,command):raise LedgerError('FORBIDDEN')
            self.validate(owner.ledger.snapshot()['state'],pending)
            # Capture ALL exact owners before the first irreversible revocation.
            for target in self.targets:
                participant=target['participant_id'];held=self.owners[participant]
                if participant not in self.retirements:
                    cls=NativePiRetirement if type(held) is SupervisorAdmission else NativeClaudeRetirement
                    retirement=cls(held,lifecycle=capability)
                    self.retirements[participant]=retirement
                    owner.launcher.stack.callback(retirement.close)
        for target in self.targets:
            with owner.supervisor._locked():
                if not owner._control_authorized(pending,human,command):raise LedgerError('FORBIDDEN')
                self.validate(owner.ledger.snapshot()['state'],pending)
            self.retirements[target['participant_id']].retire(timeout=owner.launcher.budget.remaining(10))
        with owner.supervisor._locked():self.verify(pending)

    def verify(self,pending):
        self.validate(self.owner.ledger.snapshot()['state'],pending)
        for target in self.targets:
            participant=target['participant_id'];retirement=self.retirements.get(participant)
            if retirement is None:raise LedgerError('NATIVE_RETIREMENT_CUSTODY_UNKNOWN')
            retirement.require_exited(self.owners[participant])

    def checkout(self,run,pending,human,command):
        with self.owner.supervisor._locked():
            if run!=self.run_id or not self.owner._control_authorized(pending,human,command):
                raise LedgerError('FORBIDDEN')
            self.verify(pending)
        # This concrete host has no allocator mutation/writer-quiescence grant.
        # Preserve the old owned slot; never claim release from task exits.
        return {'status':'RETAINED','reason':'NATIVE_CHECKOUT_WRITER_QUIESCENCE_UNAVAILABLE'}


    def require_completed(self):
        """Retained exact exit facts survive replacement; no new stop authority."""
        self.owner._room()
        row=self.owner.ledger.snapshot()['state'].get('runs',{}).get(self.run_id)
        stopped={} if row is None else row.get('native_stop') or {}
        if (not isinstance(stopped,dict) or stopped.get('operation_id')!=self.operation_id
                or stopped.get('status')!='VERIFIED' or row.get('control_pending') is not None
                or row.get('control_revision')!=getattr(self,'completed_revision',None)
                or stopped.get('generation')!=row.get('generation')
                or self.owner._completion_digest(row)!=getattr(self,'completion_digest',None)):
            raise LedgerError('NATIVE_RETIREMENT_UNVERIFIED')
        if not self.targets or len(self.retirements)!=len(self.targets):
            raise LedgerError('NATIVE_RETIREMENT_UNVERIFIED')
        for target in self.targets:
            participant=target['participant_id']
            self.retirements[participant].require_exited(self.owners[participant])
        return True
