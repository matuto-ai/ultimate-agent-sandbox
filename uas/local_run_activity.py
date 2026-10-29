"""Service one explicitly admitted local Run without retaining HTTP authority.

The admission grant is a revocation fence, not a HumanSession or authority for
new commands. Existing native owners enforce every Participant operation.
"""
from dataclasses import dataclass
from copy import deepcopy
import select
import time

from .ledger import LedgerError
from .native_run_admission import NativeHumanRunRequest
from .native_session_driver import NativeSessionDriver


@dataclass(frozen=True)
class LocalRunIdentity:
    operation_id: str
    issue_number: int
    participant_id: str


class LocalRunActivity(NativeSessionDriver):
    def __init__(self, owner, recruitment, request, budget, *, grant, host,
                 git_operations=None, gate_resources=None):
        from .human_mtls import AdmittedRunGrant
        from .local_native_run_session import LocalNativeRunSession
        if (type(grant) is not AdmittedRunGrant or type(host) is not LocalNativeRunSession
                or type(request) is not NativeHumanRunRequest
                or host.supervisor is not owner.supervisor
                or grant.operation_id != request.operation_id
                or grant.issue_number != request.issue_number
                or grant.human != request.session.human
                or grant.room_id != owner.ledger.room_id
                or grant.instance_id != owner.launcher.resources['instance']
                or not request.session.allowed('open-run')):
            raise LedgerError('LOCAL_ADMITTED_RUN_BINDING')
        grant.require_current()
        super().__init__(owner, recruitment, request, budget, git_operations=git_operations)
        # No request, session, connection or authenticated callback is retained.
        self.request=LocalRunIdentity(request.operation_id,request.issue_number,request.participant_id)
        self.grant,self.host,self.gate_resources=grant,host,gate_resources
        self.pin=self._pin(self._row())
        if self.pin['admission_origin'] != grant.human.canonical():
            raise LedgerError('LOCAL_ADMITTED_RUN_ORIGIN')
        self.blocked=None;self._stepping=False

    @staticmethod
    def _pin(row):
        return deepcopy({key:row.get(key) for key in
            ('run_id','generation','participant_id','issue_number','admission_origin','policy')})

    def _session(self):
        self.owner._require_owner()
        self.host.operation_current()
        self.grant.require_current()
        if self._pin(self._row()) != self.pin:
            raise LedgerError('LOCAL_ADMITTED_RUN_CHANGED')

    def _current(self):
        self._session()
        if self._row()['status']!='ACTIVE':raise LedgerError('LOCAL_RUN_NOT_ACTIVE')
        with self.owner.supervisor._locked():
            self.owner._room();self.owner._authority(self.recruitment.pi)
            for service in self._services():service._current()
        return True

    def _completion(self,row):
        # Local Run lifetime has no qualification-session observation cap. Each
        # read is a new bounded observation, never a replay of a mutation.
        from .native_session_driver import _operation
        state=self.owner.ledger.snapshot()['state']
        review=(state.get('run_reviews',{}).get(row['run_id']) or {}).get('current')
        if (not review or review['generation']!=row['generation']
                or review['stage'] not in ('READY_FOR_HUMAN','ATTENTION')
                or not (review.get('result')=='pass' or review.get('override_id'))):return
        key=(row['run_id'],review['submission_id'])
        attempt=self.completion_attempts.get(key,0)
        self._current();self._headroom(45)
        self.completion_attempts[key]=attempt+1
        operation=_operation(self.request,'completion:'+review['submission_id']+':'+str(attempt))
        self.recruitment.root.review_host.observe_completion(operation,row['run_id'],row['generation'],
                                                            review['submission_id'])
        self.counts['completion_reads']+=1

    def run(self):
        raise LedgerError('LOCAL_RUN_STEP_REQUIRED')

    def status(self):
        self.owner._require_owner()
        row=self._row()
        result={key:row[key] for key in ('run_id','generation','status')}
        if row['status']=='CLOSED':result['outcome']=row['outcome']
        if self.blocked is not None:result.update(status='attention',reason=self.blocked)
        return result

    def step(self):
        """At most one bounded native/provider effect per owner-loop turn.

        A fresh deadline bounds a new operation, never repeats an uncertain one.
        Errors fence this owner until explicit reconciliation. The qualification
        SessionBudget and finite driver path are unchanged.
        """
        self.owner._require_owner()
        if self._stepping:raise LedgerError('LOCAL_RUN_STEP_REENTRANT')
        if self.blocked is not None:return self.status()
        self._stepping=True
        try:
            self._session();row=self._row()
            if row['status']!='ACTIVE':return self.status()
            self.budget.deadline=time.monotonic()+min(60,self.host.plan.operation_timeout_seconds)
            self.owner.checkout_client.deadline=self.budget.deadline
            if self.gate_resources is not None:self.gate_resources.deadline=self.budget.deadline
            self._current()
            if self._pending_comments():return self.status()
            now=time.monotonic()
            # Bounded round-robin delivery, not a blocking lifetime driver.
            if now>=self.next_delivery:
                self._headroom(45)
                index=self.counts.get('delivery_turn',0)%2
                admission=(self.recruitment.pi,self.recruitment.root.native_admission)[index]
                value=admission.deliver_one()
                self.counts['delivery_turn']=index+1
                if value.get('status')=='CONFIRMED':self.counts['deliveries']+=1
                self.next_delivery=now+0.5
                return self.status()
            if now>=self.next_completion:
                self._completion(row)
                # Also back off when no eligible review exists.
                self.next_completion=now+15
                return self.status()
            channels=[service.helper.forge_channel for service in self._services()]
            git=None if self.git_operations is None else self.git_operations.request_listener
            ready,_,failed=select.select(channels+([] if git is None else [git]),[],channels,0)
            if failed:raise LedgerError('LOCAL_NATIVE_CHANNEL_LOST')
            for service,channel in zip(self._services(),channels):
                if channel in ready:
                    self._current();self._headroom(45);service.receive_once()
                    self.counts['packets']+=1
                    return self.status()
            if git is not None and git in ready:
                self._current();self._headroom(45)
                self.git_operations.serve_next(timeout=self.budget.remaining(1))
                self.counts['git_requests']+=1
            return self.status()
        except Exception as error:
            self.blocked=(error.code if isinstance(error,LedgerError) else 'LOCAL_RUN_EFFECT_UNKNOWN')
            return self.status()
        finally:self._stepping=False
