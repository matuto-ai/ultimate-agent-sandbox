"""Explicit fresh-human terminal stop over retained local native exit facts.

This reuses RunControl's generation-fence and CLOSED/stopped reducer. It never
restores a Run, adopts a PID, releases a dirty checkout, or grants open-run the
power to cancel active work.
"""
from copy import deepcopy

from .ledger import LedgerError
from .run_control import RunControl
from .manager_actions import HumanSession
from .local_native_stop import LocalNativeStopObservations


from .native_completed_retirement import retirement_for, require_retired, preceding_scope


class LocalNativeTerminalProof:
    def __init__(self, observations, operation, reason):
        if type(observations) is not LocalNativeStopObservations:
            raise LedgerError('LOCAL_STOP_OWNER_REQUIRED')
        row=observations._unchanged();observations.require_exited()
        if row.get('status') not in {'ACTIVE','PAUSED'} or row.get('control_pending') is not None:
            raise LedgerError('LOCAL_TERMINAL_ACTIVE_RUN_REQUIRED')
        self.observations=observations;self.owner=observations.owner;self.reviewer=observations.reviewer
        self.run_id=observations.run_id;self.operation_id=operation;self.reason=reason
        self.generation=observations.generation;self.revision=observations.revision
        self.targets=deepcopy(observations.targets);self.owners=dict(observations.held.owners)
        self.retirements=dict(observations.held.retirements);self.result=None
        # Pin the ONLY allowed terminal projection before any canonical write.
        # A lost return after commit must never rebaseline policy/worktree or
        # completion evidence from the state seen by a later retry.
        expected=deepcopy(row)
        expected.update(generation=self.generation+1,status='CLOSED',outcome='stopped')
        self.digest=self.owner._completion_digest(expected)
        self.expected_stop={'operation_id':operation,'status':'VERIFIED',
                            'generation':self.generation+1,'restored':False,'restore_attention':None}
        self.expected_result={'run_id':self.run_id,'generation':self.generation+1,
            'status':'CLOSED','control_revision':self.revision+1,'reason':reason,
            'outcome':'stopped','native_stop':deepcopy(self.expected_stop)}

    def _native(self):
        observations=self.observations
        if observations.closed or observations.unknown or not observations.complete or observations.graph.closed:
            raise LedgerError('LOCAL_STOP_CLEANUP_UNKNOWN')
        observations.graph.host.plan.require_unchanged()
        for target in self.targets:
            participant=target['participant_id']
            held=self.owners[participant]
            from .workstation_control import SupervisorAdmission
            native_scope=(held.launch.native_recipe.scope if type(held) is SupervisorAdmission else held.scope)
            ingress=held.forge_service
            if (native_scope!=target['scope'] or ingress is None
                    or ingress.origin.actor_id!=target['actor_id']
                    or ingress.origin.incarnation_id!=target['incarnation_id']
                    or 'admit-'+ingress.binding.operation_id!=target['attachment_id']):
                raise LedgerError('LOCAL_TERMINAL_OWNER_CHANGED')
            self.retirements[participant].require_exited(held)
        if any(self.observations.held.owners.get(key) is not value for key,value in self.owners.items()):
            raise LedgerError('LOCAL_STOP_OWNER_CHANGED')
        return True

    def validate_pending(self,pending):
        self._native()
        state=self.owner.ledger.snapshot()['state']
        row=state['runs'][self.run_id]
        expected_targets=[{**target,'scope':{**target['scope'],'generation':self.generation+1}}
                          for target in self.targets]
        current_targets=self.observations.held._targets(state)
        original={**row,'generation':self.generation,'status':self.observations.status}
        if (current_targets!=expected_targets
                or self.owner._completion_digest(original)!=self.observations.digest
                or row.get('control_pending')!=pending or pending.get('kind')!='terminal-stop'
                or pending.get('operation_id')!=self.operation_id
                or pending.get('targets')!=self.targets or pending.get('reason')!=self.reason
                or pending.get('source_generation')!=self.generation
                or pending.get('target_generation')!=self.generation+1
                or row.get('control_revision')!=self.revision+1
                or row.get('generation')!=self.generation+1):
            raise LedgerError('LOCAL_TERMINAL_SCOPE_CHANGED')
        return True

    def require_terminal(self):
        if self.result!=self.expected_result:raise LedgerError('LOCAL_TERMINAL_UNVERIFIED')
        return self._validate_terminal_state()

    def _validate_terminal_state(self):
        self._native();self.owner._room()
        row=self.owner.ledger.snapshot()['state'].get('runs',{}).get(self.run_id)
        if (not row or row.get('status')!='CLOSED'
                or row.get('outcome')!='stopped' or row.get('generation')!=self.generation+1
                or row.get('control_revision')!=self.revision+1 or row.get('control_pending') is not None
                or row.get('native_stop')!=self.expected_stop
                or row.get('successor_run') is not None
                or row.get('checkout_release')!={'status':'RETAINED','reason':'NATIVE_CHECKOUT_WRITER_QUIESCENCE_UNAVAILABLE'}
                or row.get('stop_reason')!=self.reason
                or self.owner._completion_digest(row)!=self.digest):
            raise LedgerError('LOCAL_TERMINAL_UNVERIFIED')
        return True


class LocalNativeTerminalControl(RunControl):
    def __init__(self,owner,proof):
        from .native_run_admission import NativeRunAdmission
        if type(owner) is not NativeRunAdmission or type(proof) is not LocalNativeTerminalProof or proof.owner is not owner:
            raise LedgerError('LOCAL_STOP_OWNER_REQUIRED')
        self.owner=owner;self.proof=proof;self.session=None

    def __getattr__(self,name):return getattr(self.owner,name)

    def _human(self,origin,command):
        session=self.session;proof=self.proof
        if session is None:return False
        self.owner._require_owner();self.owner._room()
        prepare=command.kind=='run.human-terminal-stop'
        expected=(proof.operation_id if prepare else self._finish_id(proof.operation_id))
        payload=({'expected_revision':proof.revision,'reason':proof.reason,'successor_run':None}
                 if prepare else {'operation_id':proof.operation_id})
        return (command.kind in {'run.human-terminal-stop','run.human-terminal-stop-result'}
            and command.id==expected and command.target==proof.run_id
            and command.generation==proof.generation and command.payload==payload
            and origin==session.human and 'human-control-run' in origin.capabilities
            and session.allowed('terminal-stop'))

    def _apply(self,command,origin,decide,*,authorize=None):
        return self.ledger.apply(command,origin,authorize=lambda o,c:self._human(o,c),decide=decide)

    def _control_document(self):return None

    def _control_targets(self,state,run_id,document,*,admission=None):
        self.proof.observations.require_exited()
        if run_id!=self.proof.run_id:raise LedgerError('LOCAL_TERMINAL_SCOPE_CHANGED')
        return deepcopy(self.proof.targets)

    def _stop_owned(self,pending,human,command):
        if not self._control_authorized(pending,human,command):raise LedgerError('FORBIDDEN')
        self.proof.validate_pending(pending)  # Root Stop already revoked exact owners.

    def _verify_control_effect(self,pending,kind):
        if kind not in {'terminal-stop','stop'}:raise LedgerError('NATIVE_RUN_CONTROL_UNAVAILABLE')
        return self.proof.validate_pending(pending)

    def _release_checkout(self,*args,**kwargs):
        return {'status':'RETAINED','reason':'NATIVE_CHECKOUT_WRITER_QUIESCENCE_UNAVAILABLE'}

    def execute(self,session):
        if type(session) is not HumanSession:raise LedgerError('MANAGER_AUTHENTICATION_REQUIRED')
        if self.session is not None:raise LedgerError('LOCAL_TERMINAL_BUSY')
        self.session=session
        try:
            with self.owner.human_scope(session):
                proof=self.proof
                if proof.result is not None:proof.require_terminal()
                result=RunControl.terminal_stop(self,proof.operation_id,proof.run_id,
                    proof.generation,proof.revision,proof.reason,human=session.human)
                with self.owner.supervisor._locked():
                    if result!=proof.expected_result:raise LedgerError('LOCAL_TERMINAL_SCOPE_CHANGED')
                    proof._validate_terminal_state()
                    if proof.result is None:
                        expected_targets=[{**target,'scope':{**target['scope'],'generation':proof.generation+1}}
                                          for target in proof.targets]
                        state=self.ledger.snapshot()['state']
                        if proof.observations.held._targets(state)!=expected_targets:
                            raise LedgerError('LOCAL_TERMINAL_SCOPE_CHANGED')
                        proof.result=deepcopy(result)
                    elif result!=proof.result:raise LedgerError('LOCAL_TERMINAL_SCOPE_CHANGED')
                    proof.require_terminal()
                return result
        finally:self.session=None


def terminal_stopped_run(owner,observations,operation_id,run_id,generation,revision,reason,*,session):
    from .ledger import _token
    from .native_run_admission import NativeRunAdmission
    if type(owner) is not NativeRunAdmission:raise LedgerError('LOCAL_STOP_OWNER_REQUIRED')
    _token(operation_id);_token(run_id);_token(reason)
    if (type(generation) is not int or type(revision) is not int
            or type(observations) is not LocalNativeStopObservations or observations.owner is not owner
            or observations.run_id!=run_id or observations.generation!=generation
            or observations.revision!=revision):raise LedgerError('LOCAL_TERMINAL_SCOPE_CHANGED')
    with owner.human_scope(session):
        owner._room()
        if not session.allowed('terminal-stop') or 'human-control-run' not in session.human.capabilities:
            raise LedgerError('FORBIDDEN')
    proofs=getattr(owner,'_local_terminal_proofs',None)
    if proofs is None:proofs={};owner._local_terminal_proofs=proofs
    proof=proofs.get(operation_id)
    if proof is None:
        if len(proofs)>=8:raise LedgerError('NATIVE_RETIREMENT_CAPACITY')
        proof=LocalNativeTerminalProof(observations,operation_id,reason);proofs[operation_id]=proof
    elif (proof.observations is not observations or proof.reason!=reason):
        raise LedgerError('ID_CONFLICT')
    return LocalNativeTerminalControl(owner,proof).execute(session)
