"""Finite retained-owner native session; no login, PID adoption or write retries."""
import hashlib
import select
import time

from .claude_native_admission import NativeClaudeRoot, NativeClaudeSupervisorAdmission
from .kernel_origin import OriginDenied, OriginUnavailable
from .ledger import LedgerError
from .native_host_forge import NativeHostForge, NativePiHostForge
from .native_review_host import NativeReviewHost
from .native_reviewer_recruitment import NativeReviewerRecruitment
from .native_run_admission import NativeHumanRunRequest, NativeRunAdmission
from .workstation_control import SupervisorAdmission


def _operation(request, milestone):
    return 'native-session-'+hashlib.sha256((request.operation_id+':'+milestone).encode()).hexdigest()


class NativeSessionDriver:
    """One initial Run and optional explicitly requested successor, same live host.

    The outer qualification process deadline remains authoritative. The driver
    checks scheduling headroom before beginning provider/native I/O; that is not
    an aggregate bound for nested Gates/Broker observations or lifecycle locks.
    Unknown effects stop this invocation with their original owners/journals intact.
    """
    def __init__(self, owner, recruitment, request, budget, *, next_request=None):
        from .native_session import SessionBudget
        if (type(owner) is not NativeRunAdmission or type(recruitment) is not NativeReviewerRecruitment
                or recruitment.owner is not owner or type(request) is not NativeHumanRunRequest
                or type(budget) is not SessionBudget or budget is not owner.launcher.budget
                or type(recruitment.root) is not NativeClaudeRoot
                or type(recruitment.root.native_admission) is not NativeClaudeSupervisorAdmission
                or type(recruitment.root.review_host) is not NativeReviewHost
                or type(recruitment.pi) is not SupervisorAdmission
                or type(recruitment.pi.forge_service) is not NativePiHostForge
                or type(recruitment.root.forge_service) is not NativeHostForge):
            raise LedgerError('EXACT_NATIVE_SESSION_OWNERS_REQUIRED')
        if next_request is not None and (type(next_request) is not NativeHumanRunRequest
                or next_request.session is not request.session
                or next_request.participant_id!=request.participant_id
                or next_request.operation_id==request.operation_id
                or next_request.issue_number==request.issue_number):
            raise LedgerError('EXPLICIT_NATIVE_SUCCESSOR_REQUIRED')
        self.owner,self.recruitment,self.request,self.budget=owner,recruitment,request,budget
        self.next_request=next_request
        self.runs=[];self.counts={'packets':0,'deliveries':0,'completion_reads':0}
        self.started=False;self.completion_attempts={}
        self.next_delivery=0.;self.next_completion=0.
        self.phase='active';self.pending_successor=None;self.last_observed=None

    def _headroom(self,seconds):
        if self.budget.deadline-time.monotonic()<seconds:raise TimeoutError('session operation budget')

    def _session(self):
        self.owner._require_owner()
        if not self.request.session.allowed('open-run'):
            raise LedgerError('NATIVE_SESSION_AUTHORIZATION_REVOKED')

    def _current(self):
        self._session()
        with self.owner.supervisor._locked():
            self.owner._room()
            self.owner._authority(self.recruitment.pi)
            for service in self._services():service._current()
        return True

    def _services(self):
        return (self.recruitment.pi.forge_service,self.recruitment.root.forge_service)

    def _row(self):
        run=self.owner.run_id(self.request.operation_id)
        row=self.owner.ledger.snapshot()['state'].get('runs',{}).get(run)
        if not row or row['participant_id']!=self.request.participant_id:
            raise LedgerError('NATIVE_SESSION_RUN_CHANGED')
        return row

    def _result(self, outcome, reason):
        return {'outcome':outcome,'reason':reason,'runs':list(self.runs),
                'current_run':self.owner.run_id(self.request.operation_id),
                'counts':dict(self.counts),'successor_started':len(self.runs)>0,
                'phase':self.phase,'pending_successor':self.pending_successor,'last_observed_run':self.last_observed,
                'crash_recovery':'explicit-native-restoration-unavailable',
                'authority_restored_from_journal':False}

    def _deliver(self):
        for admission in (self.recruitment.pi,self.recruitment.root.native_admission):
            self._current()
            self._headroom(45)
            result=admission.deliver_one()  # Existing offer/receipt reconciliation; never reprompt here.
            if result.get('status')=='CONFIRMED':self.counts['deliveries']+=1
        self.next_delivery=time.monotonic()+1.

    def _completion(self,row):
        state=self.owner.ledger.snapshot()['state']
        review=(state.get('run_reviews',{}).get(row['run_id']) or {}).get('current')
        if (not review or review['generation']!=row['generation']
                or review['stage'] not in ('READY_FOR_HUMAN','ATTENTION')
                or not (review.get('result')=='pass' or review.get('override_id'))):return
        key=(row['run_id'],review['submission_id'])
        attempt=self.completion_attempts.get(key,0)
        if attempt>=8:return  # Finite observation budget; no effect resend.
        self._current();self._headroom(45)
        self.completion_attempts[key]=attempt+1
        operation=_operation(self.request,'completion:'+review['submission_id']+':'+str(attempt))
        self.recruitment.root.review_host.observe_completion(operation,row['run_id'],row['generation'],
                                                            review['submission_id'])
        self.counts['completion_reads']+=1
        self.next_completion=time.monotonic()+15.

    def _successor(self,row):
        previous=self.recruitment;request=self.next_request
        self._headroom(90)
        self.pending_successor={'run_id':self.owner.run_id(request.operation_id),
                                'operation_id':request.operation_id}
        self.phase='predecessor-retirement'
        self.owner.retire_completed(_operation(self.request,'retire-completed'),row['run_id'],
            row['generation'],row['control_revision'],session=self.request.session,reviewer=previous)
        # No mutable loop pointer changes until the original retirement is confirmed.
        self.phase='successor-admission'
        activated=self.owner.open_human(request.operation_id,request.issue_number,request.participant_id,
                                        session=request.session,attempt_id=request.attempt_id)
        pi=self.owner.launcher.started.get(request.participant_id)
        self.phase='successor-reviewer'
        successor=NativeReviewerRecruitment(self.owner,pi,previous.provenance,previous.resolver,previous.binding)
        successor.recruit(_operation(request,'reviewer'),activated['run_id'],activated['generation'],
                          session=request.session,reset_from=previous)
        self.runs.append({'run_id':row['run_id'],'generation':row['generation'],'outcome':row['outcome']})
        self.request,self.recruitment,self.next_request=request,successor,None
        self.next_delivery=self.next_completion=0.
        self.phase='active';self.pending_successor=None

    def run(self):
        if self.started:raise LedgerError('NATIVE_SESSION_DRIVER_ONE_SHOT')
        self.started=True
        try:
            while True:
                # Scheduling margin only: the outer root deadline bounds aggregate work.
                # Expiry during an effect retains its canonical unknown intent/audit.
                self._session();row=self._row()
                self.last_observed={key:row.get(key) for key in ('run_id','generation','status','outcome')}
                if row['status']=='CLOSED':
                    if row.get('outcome')!='completed':return self._result('attention','canonical-run-closed')
                    if self.next_request is not None:
                        if self.budget.deadline-time.monotonic()<90:
                            return self._result('inconclusive','successor-not-started-budget')
                        self._successor(row);continue
                    return self._result('completed','canonical-human-merge-observed')
                if row['status']!='ACTIVE':return self._result('attention','canonical-run-not-active')
                if self.budget.deadline-time.monotonic()<45:
                    return self._result('inconclusive','operation-deadline')
                self._current()
                now=time.monotonic()
                if now>=self.next_delivery:self._deliver()
                if now>=self.next_completion:self._completion(row)
                if self._row()['status']=='CLOSED':continue
                channels=[service.helper.forge_channel for service in self._services()]
                ready,_,exceptional=select.select(channels,[],channels,min(.1,self.budget.remaining(.1)))
                if exceptional:raise OriginDenied('native ingress failed')
                for service,channel in zip(self._services(),channels):
                    if channel in ready:
                        self._current();self._headroom(45)
                        service.receive_once()  # Original packet; canonical owner returns its exact response.
                        self.counts['packets']+=1
                # Idle is only idle. It neither closes the Run nor ends the session.
        except TimeoutError:
            return self._result('unknown','operation-timeout-reconcile-original-owner')
        except (OriginDenied,OriginUnavailable):
            return self._result('attention','native-authority-lost-restoration-required')
        except LedgerError as error:
            return self._result('attention',error.code)
