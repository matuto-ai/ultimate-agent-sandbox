"""Finite retained-owner native session; no login, PID adoption or write retries."""
from copy import deepcopy
import threading
import hashlib
import select
import sqlite3
import time

from .claude_native_admission import NativeClaudeRoot, NativeClaudeSupervisorAdmission
from .kernel_origin import OriginDenied, OriginUnavailable
from .pi_runtime import NativeUnavailable
from .workstation_exec import ExecUnavailable
from .native_pi_recipe import NativeRecipeError
from .ledger import LedgerError
from .native_host_forge import NativeHostForge, NativePiHostForge
from .native_review_host import NativeReviewHost
from .native_reviewer_recruitment import NativeReviewerRecruitment
from .native_run_admission import NativeHumanRunRequest, NativeRunAdmission
from .workstation_control import SupervisorAdmission


def _operation(request, milestone):
    return 'native-session-'+hashlib.sha256((request.operation_id+':'+milestone).encode()).hexdigest()


class NativeHumanReviewInbox:
    """Bounded host scheduling only; canonical Manager/Room owners grant effects.

    The authenticated hosting application supplies this object and exact observed
    requests. It is neither a login/transport nor durable recovery authority.
    """
    def __init__(self,session,audit):
        from .manager_actions import HumanSession
        from .forge_audit import ForgeAudit
        from .native_broker_audit import NativeBrokerAudit
        if (type(session) is not HumanSession or type(audit) not in (ForgeAudit, NativeBrokerAudit)
                or audit.deployment_id!=session.deployment_id
                or type(audit) is NativeBrokerAudit and audit.session is not session):
            raise LedgerError('MANAGER_AUTHENTICATION_REQUIRED')
        self.session,self.audit=session,audit
        self._lock=threading.Lock();self._items={};self._queue=[];self._consumer=None

    def enqueue(self,value):
        from .manager_actions import request
        from .ledger import _json
        from .manager_action_protocol import MAX_ACTION_BYTES
        parsed=request(value,self.session)
        if len(_json(parsed).encode('utf-8'))>MAX_ACTION_BYTES:
            raise LedgerError('INVALID_MANAGER_ACTION')
        if parsed['action'] not in {'request-changes','reconcile-changes'}:
            raise LedgerError('NATIVE_HUMAN_ACTION_UNSUPPORTED')
        payload=parsed['payload']
        if (parsed['action']=='request-changes' and (set(payload)!={'body'}
                or type(payload['body']) is not str or not 1<=len(payload['body'])<=8192)
                or parsed['action']=='reconcile-changes' and payload):
            raise LedgerError('INVALID_MANAGER_ACTION')
        if not self.session.allowed(parsed['action']):raise LedgerError('FORBIDDEN')
        with self._lock:
            prior=self._items.get(parsed['operation_id'])
            if prior is not None:
                if prior['request']!=parsed:raise LedgerError('ID_CONFLICT')
                return prior['status']
            if len(self._items)>=8:raise LedgerError('NATIVE_HUMAN_ACTION_CAPACITY')
            self._items[parsed['operation_id']]={'request':parsed,'status':'queued','reason':None}
            self._queue.append(parsed['operation_id'])
        return 'queued'

    def _bind(self,consumer):
        with self._lock:
            if self._consumer is not None:raise LedgerError('NATIVE_HUMAN_INBOX_ALREADY_BOUND')
            self._consumer=consumer

    def _take(self,consumer):
        with self._lock:
            if self._consumer is not consumer:raise LedgerError('NATIVE_HUMAN_INBOX_OWNER_REQUIRED')
            if not self._queue:return None
            item=self._items[self._queue.pop(0)];item['status']='attempted'
            return deepcopy(item['request'])

    def _record(self,consumer,operation,status,reason=None):
        with self._lock:
            if self._consumer is not consumer:raise LedgerError('NATIVE_HUMAN_INBOX_OWNER_REQUIRED')
            self._items[operation].update(status=status,reason=reason)

    def snapshot(self):
        with self._lock:
            return [{'operation_id':key,'action':item['request']['action'],
                     'status':item['status'],'reason':item['reason']} for key,item in self._items.items()]


class NativeSessionDriver:
    """One initial Run and optional explicitly requested successor, same live host.

    The outer qualification process deadline remains authoritative. The driver
    checks scheduling headroom before beginning provider/native I/O; that is not
    an aggregate bound for nested Gates/Broker observations or lifecycle locks.
    Unknown effects stop this invocation with their original owners/journals intact.
    """
    def __init__(self, owner, recruitment, request, budget, *, next_request=None, git_operations=None, human_actions=None,
                 pi_restoration=None, human_control=None):
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
        if git_operations is not None:
            from .native_git_operations import NativeGitOperations
            if (type(git_operations) is not NativeGitOperations or git_operations.owner is not owner
                    or git_operations.reviewer is not recruitment):
                raise LedgerError('NATIVE_GIT_OWNER_REQUIRED')
        if human_actions is not None and (type(human_actions) is not NativeHumanReviewInbox
                or human_actions.session is not request.session
                or human_actions.audit.deployment_id!=request.session.deployment_id
                or request.session.room_id!=owner.ledger.room_id
                or request.session.instance_id!=recruitment.binding.room_instance
                or next_request is not None):
            raise LedgerError('EXACT_NATIVE_HUMAN_ACTION_OWNER_REQUIRED')
        if human_control is not None:
            from .native_human_control import NativeHumanControl
            from .native_broker_audit import NativeBrokerAudit
            if (type(human_control) is not NativeHumanControl or human_actions is None
                    or human_control.session is not request.session
                    or type(human_actions.audit) is not NativeBrokerAudit
                    or human_actions.audit.client is not owner.broker.client
                    or budget.deadline > human_control._deadline):
                raise LedgerError('EXACT_NATIVE_HUMAN_CONTROL_REQUIRED')
        self.human_control, self._human_view = human_control, None
        self.human_actions=human_actions
        if pi_restoration is not None:
            from .native_pi_restore import NativePiSameRunRestore
            if (type(pi_restoration) is not NativePiSameRunRestore or pi_restoration.owner is not owner
                    or pi_restoration.recruitment is not recruitment or pi_restoration.request is not request
                    or pi_restoration.budget is not budget or pi_restoration.graph.git is not git_operations
                    or next_request is not None):
                raise LedgerError('EXACT_SAME_RUN_RESTORATION_OWNER_REQUIRED')
        self.pi_restoration=pi_restoration
        if human_actions is not None:human_actions._bind(self)
        self.git_operations=git_operations
        self.owner,self.recruitment,self.request,self.budget=owner,recruitment,request,budget
        self.next_request=next_request
        self.runs=[];self.counts={'packets':0,'deliveries':0,'completion_reads':0}
        if git_operations is not None:self.counts['git_requests']=0
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
                'crash_recovery':('explicit-native-restoration-unavailable' if self.pi_restoration is None
                                  else self.pi_restoration.result()),
                'authority_restored_from_journal':False,
                'human_actions':[] if self.human_actions is None else self.human_actions.snapshot(),
                'pending_human_comments':self._pending_comments()}

    def _pending_comments(self):
        run=self.owner.run_id(self.request.operation_id)
        return sorted(key for key,row in self.owner.ledger.snapshot()['state'].get('review_comments',{}).items()
                      if row['run_id']==run and row['status'] in {'pending','unknown','confirmed-awaiting-target'})

    def _restore_unknown(self):
        return self.pi_restoration is not None and self.pi_restoration.phase == 'unknown'

    def _human_transport(self, *, observe=True):
        """Drain authenticated data and publish bounded views outside owner locks."""
        control = self.human_control
        if control is None: return
        self._session()
        for value in control.drain_commands():
            self.human_actions.enqueue(value)
        if observe and control.take_observation_request():
            from .manager_actions import current_run
            operation = self.human_actions.audit.observation()
            with operation.prepare_manager_guard():
                with self.owner.supervisor._locked():
                    self.owner._room()
                    with operation.manager_action_guard(self.owner.ledger.room_id,
                            self.human_actions.audit.binding.repository) as forge:
                        self._session()
                        state = self.owner.ledger.snapshot()['state']
                        operation.require_current()
                        view = current_run(state, self.owner.run_id(self.request.operation_id), forge)
                        self._human_view = None if view is None else {key:view[key] for key in (
                            'run_id','generation','status','observed_version','review_stage','submission_id','forge_uncertain')}
        statuses = tuple({'operation_id':item['operation_id'], 'status':item['status']}
                         for item in self.human_actions.snapshot())
        control.publish(self._human_view, statuses)

    def _human_action(self,row):
        inbox=self.human_actions
        if inbox is None:return
        value=inbox._take(self)
        if value is None:return
        operation=value['operation_id']
        try:
            if (inbox.session is not self.request.session
                    or inbox.audit.deployment_id!=inbox.session.deployment_id
                    or value['run_id']!=row['run_id'] or value['generation']!=row['generation']):
                raise LedgerError('MANAGER_SCOPE_MISMATCH')
            pending=self._pending_comments()
            if pending and (value['action']!='reconcile-changes' or value['object_id'] not in pending):
                raise LedgerError('NATIVE_HUMAN_RECONCILIATION_REQUIRED')
            self._current();self._headroom(45)
            self.recruitment.root.review_host.human_action(value,session=inbox.session,audit=inbox.audit)
            original=operation if value['action']=='request-changes' else value['object_id']
            comment=self.owner.ledger.snapshot()['state'].get('review_comments',{}).get(original)
            if not comment or comment['run_id']!=row['run_id'] or comment['generation']!=row['generation']:
                raise LedgerError('NATIVE_HUMAN_RESULT_UNVERIFIED')
            inbox._record(self,operation,comment['status'])
        except LedgerError as error:
            inbox._record(self,operation,'unknown' if self._pending_comments() else 'rejected',error.code)
        except BaseException:
            inbox._record(self,operation,'unknown','original-owner-reconciliation-required')
            raise

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
        if self.git_operations is not None:self.git_operations.require_successor()
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
                self._session();self._human_transport();row=self._row()
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
                    return self._result('unknown','human-action-reconciliation-pending') if self._pending_comments() else self._result('inconclusive','operation-deadline')
                # Only this loop preflight may restore an observed dead Pi.
                # Never recover from an exception raised by delivery, Forge,
                # Git, Gates or human mutation: their original unknowns hold.
                if self.pi_restoration is not None and not self._pending_comments():
                    if self.pi_restoration.preflight():
                        self.next_delivery=self.next_completion=0.
                self._current()
                self._human_action(row)
                self._human_transport(observe=False)
                if self._pending_comments():
                    # No native/Git/provider work while a human comment is
                    # unresolved. Only a supplied explicit reconciliation may run.
                    select.select([],[],[],min(.1,self.budget.remaining(.1)))
                    continue
                now=time.monotonic()
                if now>=self.next_delivery:self._deliver()
                if now>=self.next_completion:self._completion(row)
                if self._row()['status']=='CLOSED':continue
                channels=[service.helper.forge_channel for service in self._services()]
                git_listener=None if self.git_operations is None else self.git_operations.request_listener
                watched=channels+([] if git_listener is None else [git_listener])
                ready,_,exceptional=select.select(watched,[],watched,min(.1,self.budget.remaining(.1)))
                if exceptional:raise OriginDenied('native ingress failed')
                for service,channel in zip(self._services(),channels):
                    if channel in ready:
                        self._current();self._headroom(45)
                        service.receive_once()  # Original packet; canonical owner returns its exact response.
                        self.counts['packets']+=1
                if git_listener is not None and git_listener in ready:
                    self._current();self._headroom(45)
                    self.git_operations.serve_next(timeout=self.budget.remaining(1))
                    self.counts['git_requests']+=1
                # Idle is only idle. It neither closes the Run nor ends the session.
        except TimeoutError:
            return self._result('unknown','operation-timeout-reconcile-original-owner')
        except (OriginDenied,OriginUnavailable):
            if self._restore_unknown():
                return self._result('unknown','native-restoration-unknown-reconcile-original-owner')
            return self._result('attention','native-authority-lost-restoration-required')
        except LedgerError as error:
            return self._result('unknown' if self._restore_unknown() else 'attention',error.code)
        except (NativeUnavailable,ExecUnavailable,NativeRecipeError,OSError,sqlite3.Error):
            # Neither runtime I/O failure nor a lost file/SQLite observation is
            # permission to restart. Preserve the exact restoration marker.
            return self._result('unknown','native-runtime-unverified-reconcile-original-owner')
