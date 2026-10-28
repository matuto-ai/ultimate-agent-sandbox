"""Native reviewer reset: canonical context reducers, exact retained task custody.

Only a trusted live owner can reset; metadata/receipts never reconstruct native
custody. This proves three owned tasks exited, not arbitrary writer quiescence.
"""
from copy import deepcopy
import hashlib
import time

from .context import FixtureContextHub, FixtureRun
from .ledger import Command, LedgerError
from .claude_native_admission import NativeClaudeRoot
from .native_claude_retirement import NativeClaudeRetirement
from .native_helper import NativeDescendantLease


class _NativeResetContexts(FixtureContextHub):
    def __init__(self, reset):
        super().__init__(reset.owner.owner.hub)
        self.reset_owner=reset

    def _control(self, operation_id, kind, payload, decide, authorize=None):
        reset=self.reset_owner;owner=reset.owner
        if owner._capability is None:raise LedgerError('NATIVE_REVIEWER_FENCE_REQUIRED')
        owner._capability.require(owner.supervisor)
        def allowed(*_):
            owner._allowed_locked()
            return authorize is None or authorize() is True
        command=Command(operation_id,'context.native-reset.'+kind,
                        owner._pin['run_id'],owner._pin['generation'],payload)
        def checked_decide(state, operation):
            owner._allowed_locked(state)
            if kind=='reset.request':
                old=reset.previous.root
                old.review_host.identity.seat_current(old.forge_service,state)
            return decide(state,operation)
        return self.ledger.apply(command,owner._session.human,authorize=allowed,decide=checked_decide)


class NativeReviewerReset:
    def __init__(self, owner, previous, operation_id):
        from .native_reviewer_recruitment import NativeReviewerRecruitment
        if (type(owner) is not NativeReviewerRecruitment or type(previous) is not NativeReviewerRecruitment
                or owner is previous or owner.ledger is not previous.ledger
                or owner.supervisor is not previous.supervisor or owner.selected!=previous.selected
                or owner.launcher.control is not previous.launcher.control
                or owner.pi is previous.pi or type(previous.root) is not NativeClaudeRoot
                or previous.root.review_host is None or previous.root.forge_service is None):
            raise LedgerError('NATIVE_RESET_OWNERS_REQUIRED')
        owner._capability.require(owner.supervisor)
        state=owner.ledger.snapshot()['state'];root=previous.root
        participant=owner.selected['participant']
        row=state['fixture_context']['participants'][participant]
        preceding=row['bound_run'] or row['reserved_run']
        if (row['status']!='READY' or not preceding or preceding['run_id']==owner._pin['run_id']
                or root.scope['run_id']!=preceding['run_id']
                or root.scope['generation']!=preceding['generation']
                or root.scope['context_generation']!=row['context_generation']
                or state['fixture_context']['runs'].get(preceding['run_id'],{}).get('status')!='CLOSED'
                or state.get('runs',{}).get(preceding['run_id'],{}).get('status')!='CLOSED'):
            raise LedgerError('PRECEDING_RUN_OPEN')
        # Context is still READY here; check attachment without requiring old Run OPEN.
        root.review_host.identity.seat_current(root.forge_service,state)
        self.owner,self.previous=owner,previous
        self.preceding=deepcopy(preceding)
        self.preceding_session=root.recipe.session_id
        epoch=root.forge_service.binding.epoch
        if type(epoch) is not int or not 1<=epoch<2**53-1:
            raise LedgerError('NATIVE_RESET_EPOCH_EXHAUSTED')
        self.next_epoch=epoch+1
        self.expected_generation=row['context_generation']
        self.next_generation=self.expected_generation+1
        self.operation_id=operation_id
        self.reset_id='native-reviewer-reset-'+hashlib.sha256(operation_id.encode()).hexdigest()
        self.contexts=_NativeResetContexts(self)
        self.retirement=NativeClaudeRetirement(root,lifecycle=owner._capability)
        owner.launcher.stack.callback(self.retirement.close)
        self.requested=False

    def request_locked(self):
        owner=self.owner
        self.contexts.request_reset(self.reset_id,owner.selected['participant'],self.expected_generation,
                                   FixtureRun(owner._pin['run_id'],owner._pin['generation']))
        self.requested=True

    def allowed(self,state):
        owner=self.owner;row=state['fixture_context']['participants'][owner.selected['participant']]
        old=state['fixture_context']['runs'].get(self.preceding['run_id'])
        run=state.get('runs',{}).get(self.preceding['run_id'])
        reset=row['reset'];target={'run_id':owner._pin['run_id'],'generation':owner._pin['generation']}
        if (not old or old['status']!='CLOSED' or not run or run['status']!='CLOSED'
                or not reset or reset['id']!=self.reset_id or reset['preceding_run']!=self.preceding
                or reset['target_run']!=target or reset['expected_context_generation']!=self.expected_generation
                or reset['next_context_generation']!=self.next_generation):
            raise LedgerError('NATIVE_RESET_SCOPE_CHANGED')
        if reset['status']=='REQUESTED':
            if row['status']!='RESETTING' or row['context_generation']!=self.expected_generation:
                raise LedgerError('NATIVE_RESET_SCOPE_CHANGED')
        elif reset['status']=='SUCCEEDED':
            if (row['status']!='READY' or row['context_generation']!=self.next_generation
                    or (row['bound_run'] or row['reserved_run'])!=target):
                raise LedgerError('NATIVE_RESET_SCOPE_CHANGED')
            self.retirement.require_exited(self.previous.root)
        else:raise LedgerError('NATIVE_RESET_RECONCILIATION_REQUIRED')
        return True

    def retire(self):
        if not self.requested:raise LedgerError('NATIVE_RESET_REQUEST_REQUIRED')
        self.owner._allowed()
        self.retirement.retire(timeout=self.owner.launcher.budget.remaining(10))
        self.retirement.require_exited(self.previous.root)
        self.owner._allowed()

    def complete(self,root):
        owner=self.owner
        with owner._fence():
            owner._allowed_locked()
            self.retirement.require_exited(self.previous.root)
            if type(root) is not NativeClaudeRoot or root is not owner.root:
                raise LedgerError('NATIVE_RESET_FRESH_PROOF_REQUIRED')
            pending=getattr(root,'_prepared_initialization',None)
            if (not pending or pending['deadline']<=time.monotonic()
                    or pending.get('epoch')!=self.next_epoch or getattr(root,'_prepared_admit_started',True)):
                raise LedgerError('NATIVE_RESET_FRESH_PROOF_REQUIRED')
            scope=self.contexts.pending_scope(self.reset_id)
            def fresh():
                self.retirement.require_exited(self.previous.root)
                owner._allowed_locked()
                root.current()
                if (type(root.helper_lease) is not NativeDescendantLease
                        or root.helper_lease.root is not root or root.helper_lease.state!='released'):
                    raise LedgerError('NATIVE_RESET_FRESH_PROOF_REQUIRED')
                root.helper_lease.current()
                root.helper_lease._lineage.current()
                proof=root.native_readiness
                if (type(proof) is not dict or type(proof.get('native')) is not dict
                        or root.scope!=scope or root.recipe.scope!=scope
                        or root.recipe.session_id==self.preceding_session
                        or proof['scope']!=scope or proof['native']['session_id']!=root.recipe.session_id
                        or proof['native']['source']!='fresh-home-explicit-session-native-idle-no-input'):
                    raise LedgerError('NATIVE_RESET_FRESH_PROOF_REQUIRED')
                return True
            fresh()
            self.contexts.succeed_reset(self.reset_id,self.expected_generation,authorize=fresh)
