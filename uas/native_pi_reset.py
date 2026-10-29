"""Repeated retained Pi context reset using canonical context reducers and owners."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import re

from .context import FixtureContextHub, FixtureRun, MAX_CONTEXT_GENERATION
from .ledger import Command, LedgerError
from .native_completed_retirement import NativeCompletedRetirement
from .workstation_control import SupervisorAdmission


class _NativePiResetContexts(FixtureContextHub):
    def __init__(self,reset):
        super().__init__(reset.owner.hub);self.reset_owner=reset

    def _control(self,operation_id,kind,payload,decide,authorize=None):
        reset=self.reset_owner;owner=reset.owner
        reset.capability.require(owner.supervisor)
        def allowed(*_):
            reset.allowed_locked()
            return authorize is None or authorize() is True
        def checked(state,command):
            reset.allowed_locked(state)
            return decide(state,command)
        return self.ledger.apply(Command(operation_id,'context.native-pi-reset.'+kind,reset.run,1,payload),
            owner._session.human,authorize=allowed,decide=checked)


class NativePiReset:
    def __init__(self,owner,run,pending,retirement):
        from .native_run_admission import NativeRunAdmission
        if (type(owner) is not NativeRunAdmission or type(retirement) is not NativeCompletedRetirement
                or retirement.owner is not owner
                or type(pending.get('context_generation')) is not int
                or not 2 <= pending['context_generation'] <= MAX_CONTEXT_GENERATION
                or type(pending.get('preceding_run')) is not dict
                or pending['preceding_run'].get('run_id')!=retirement.run_id):
            raise LedgerError('NATIVE_PI_RESET_OWNER_REQUIRED')
        self.owner,self.run,self.retirement=owner,run,retirement
        self.preceding=deepcopy(pending['preceding_run'])
        self.participant=pending['participant_id'];self.operation=pending['admission_operation']
        self.old=retirement.owners.get(self.participant)
        if type(self.old) is not SupervisorAdmission:
            raise LedgerError('NATIVE_PI_RESET_OWNER_REQUIRED')
        old_scope=self.old.launch.native_recipe.scope
        self.expected_generation=old_scope.get('context_generation')
        if (type(self.expected_generation) is not int
                or not 1 <= self.expected_generation < MAX_CONTEXT_GENERATION
                or pending['context_generation'] != self.expected_generation + 1
                or old_scope != {'room_id': owner.ledger.room_id, 'participant_id': self.participant,
                                 **self.preceding, 'context_generation': self.expected_generation}):
            raise LedgerError('NATIVE_PI_RESET_OWNER_REQUIRED')
        self.next_generation=self.expected_generation+1
        epoch=self.old.forge_service.binding.epoch
        if type(epoch) is not int or not 1<=epoch<2**53-1:raise LedgerError('NATIVE_RESET_EPOCH_EXHAUSTED')
        self.next_epoch=epoch+1
        self.old_proof=deepcopy(self.old.launch.native_readiness)
        if type(self.old_proof) is not dict:raise LedgerError('NATIVE_PI_RESET_OWNER_REQUIRED')
        self.reset_id='native-pi-reset-'+hashlib.sha256(self.operation.encode()).hexdigest()
        self.contexts=_NativePiResetContexts(self);self.capability=None
        self.authorize=None;self.new=None;self.requested=False

    @contextmanager
    def fence(self):
        if self.capability is not None:raise LedgerError('NATIVE_PI_RESET_NESTED_FENCE')
        with self.owner.supervisor._locked() as capability:
            self.capability=capability
            try:yield
            finally:self.capability=None

    def allowed_locked(self,state=None):
        self.owner._require_owner();self.owner._room()
        self.retirement.require_completed()
        if self.authorize is None or self.authorize() is not True:raise LedgerError('ADMISSION_REVOKED')
        state=self.owner.ledger.snapshot()['state'] if state is None else state
        pending=state.get('run_admissions',{}).get(self.run)
        if (not pending or pending['status']!='PREPARING' or pending['admission_operation']!=self.operation
                or pending['participant_id']!=self.participant or pending.get('context_generation')!=self.next_generation
                or pending.get('preceding_run')!=self.preceding):
            raise LedgerError('NATIVE_PI_RESET_SCOPE_CHANGED')
        row=state['fixture_context']['participants'][self.participant]
        target={'run_id':self.run,'generation':1}
        reset=row.get('reset')
        if not self.requested and row['status']=='READY' and row['context_generation']==self.expected_generation:
            if (row['bound_run'] or row['reserved_run'])!=self.preceding:
                raise LedgerError('NATIVE_PI_RESET_SCOPE_CHANGED')
        else:
            if (not reset or reset['id']!=self.reset_id or reset['preceding_run']!=self.preceding
                    or reset['target_run']!=target or reset['expected_context_generation']!=self.expected_generation
                    or reset['next_context_generation']!=self.next_generation):raise LedgerError('NATIVE_PI_RESET_SCOPE_CHANGED')
            if reset['status']=='REQUESTED':
                if row['status']!='RESETTING' or row['context_generation']!=self.expected_generation:raise LedgerError('NATIVE_PI_RESET_SCOPE_CHANGED')
            elif reset['status']=='SUCCEEDED':
                if (row['status']!='READY' or row['context_generation']!=self.next_generation
                        or (row['bound_run'] or row['reserved_run'])!=target):raise LedgerError('NATIVE_PI_RESET_SCOPE_CHANGED')
            else:raise LedgerError('NATIVE_PI_RESET_RECONCILIATION_REQUIRED')
        return True

    def request(self,authorize):
        self.authorize=authorize
        with self.fence():
            self.allowed_locked()
            self.contexts.request_reset(self.reset_id,self.participant,self.expected_generation,FixtureRun(self.run))
            self.requested=True

    def complete(self,admission):
        if type(admission) is not SupervisorAdmission or admission.seat.participant_id!=self.participant:
            raise LedgerError('NATIVE_PI_RESET_FRESH_PROOF_REQUIRED')
        if self.new is not None and self.new is not admission:raise LedgerError('NATIVE_PI_RESET_RECONCILIATION_REQUIRED')
        self.new=admission
        with self.fence():
            self.allowed_locked()
            scope=self.contexts.pending_scope(self.reset_id)
            def fresh():
                self.allowed_locked();admission._current()
                launch=admission.launch;proof=launch.native_readiness
                if (launch.native_recipe.scope!=scope or type(proof) is not dict or proof.get('scope')!=scope
                        or proof.get('profile_digest')!=launch.native_recipe.manifest_digest
                        or type(proof.get('native')) is not dict
                        or proof['native'].get('source')!='native-empty-session-and-no-pending-messages'
                        or any(type(proof['native'].get(key)) is not str
                            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',proof['native'][key])
                            for key in ('session_id','runtime_id'))
                        or proof['native'].get('session_id')==self.old_proof['native']['session_id']
                        or proof['native'].get('runtime_id')==self.old_proof['native']['runtime_id']):
                    raise LedgerError('NATIVE_PI_RESET_FRESH_PROOF_REQUIRED')
                return True
            fresh()
            self.contexts.succeed_reset(self.reset_id,self.expected_generation,authorize=fresh)
