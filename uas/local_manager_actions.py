"""Bounded native admission under the current authenticated HTTP request.

No task queue, serialized authority or fixture fallback. Construct and invoke on
NativeRunAdmission's owner thread. HTTP scope expires when the request returns;
this object does not retain HumanSession or authorize later background work.
"""
import threading
from .ledger import LedgerError, _token
from .manager_actions import HumanSession
from .native_run_admission import NativeRunAdmission, NativeHumanRunRequest


class LocalNativeRunActions:
    def __init__(self, owner):
        if type(owner) is not NativeRunAdmission:
            from .local_native_run_session import LocalNativeRunSession
            if type(owner) is not LocalNativeRunSession:
                raise LedgerError('EXACT_NATIVE_RUN_ADMISSION_REQUIRED')
        owner._require_owner()
        self.owner = owner
        self._thread = threading.get_ident()
        self.participant = (owner.launcher.plan.seats['pi']['participant']
            if type(owner) is NativeRunAdmission else owner.participant_id)
        _token(self.participant)

    def status(self, session):
        from .local_native_run_session import LocalNativeRunSession
        if type(self.owner) is not LocalNativeRunSession:return {'service':'unavailable'}
        self.owner.current()
        if (type(session) is not HumanSession or not session.allowed('observe')
                or session.deployment_id!=self.owner.plan.config['deployment']['id']
                or session.room_id!=self.owner.plan.room['id']
                or session.instance_id!=self.owner.resources['instance']):
            raise LedgerError('LOCAL_NATIVE_STATUS_SCOPE')
        graph=getattr(self.owner,'_graph',None)
        if graph is None:return {'service':'idle'}
        result={'service':'stopped' if graph.closed else 'running'}
        if getattr(graph,'_cleanup_unknown',False):result['service']='cleanup-unknown'
        if graph.activity is not None:
            status=graph.activity.status()
            result.update({key:status[key] for key in ('run_id','generation','status')})
            if status['status']=='attention' and result['service']!='cleanup-unknown':
                result['service']='attention'
            if 'outcome' in status:result['outcome']=status['outcome']
            if 'reason' in status:result['reason']=status['reason']
        return result

    def control(self, frame, payload, session, *, available_actions=()):
        from .local_native_run_session import LocalNativeRunSession
        if type(self.owner) is not LocalNativeRunSession:
            raise LedgerError('LOCAL_NATIVE_CONTROLS_UNAVAILABLE')
        self.owner.operation_current()
        graph=self.owner._graph
        if graph is None or graph.closed:raise LedgerError('LOCAL_NATIVE_CONTROLS_UNAVAILABLE')
        graph._new_budget()
        from .local_native_human_controls import handle_native_human
        return handle_native_human(graph,frame,payload,session,available_actions=available_actions)

    def open(self, payload, session, *, grant=None):
        if threading.get_ident() != self._thread:
            raise LedgerError('LOCAL_NATIVE_ACTION_OWNER_THREAD')
        self.owner._require_owner()
        if (type(payload) is not dict or set(payload) not in (
                {'operation_id','issue_number'}, {'operation_id','issue_number','attempt_id'},
                {'operation_id','issue_number','next_operation_id','next_issue_number'})):
            raise LedgerError('INVALID_NATIVE_HUMAN_OPEN')
        if (type(session) is not HumanSession or not session.allowed('open-run')
                or not session.allowed('authorize-run-request')):
            raise LedgerError('HUMAN_ACTION_DENIED')
        request = NativeHumanRunRequest(payload['operation_id'],payload['issue_number'],
            self.participant,session,attempt_id=payload.get('attempt_id'))
        # This is the real owner, not a browser-selected callback. Its durable
        # command receipts reconcile explicit repeats; this transport never retries.
        if type(self.owner) is NativeRunAdmission:
            if 'next_operation_id' in payload:raise LedgerError('NATIVE_SUCCESSOR_HOST_REQUIRED')
            result = self.owner.open_human(request.operation_id,request.issue_number,
                request.participant_id,session=request.session,attempt_id=request.attempt_id)
        else:
            result = self.owner.open_human(request.operation_id,request.issue_number,
                session=request.session,grant=grant,attempt_id=request.attempt_id,
                **({} if 'next_operation_id' not in payload else {key:payload[key] for key in ('next_operation_id','next_issue_number')}))
        if (type(result) is not dict or type(result.get('run_id')) is not str
                or type(result.get('generation')) is not int or result['generation']<1
                or result.get('status') not in {'ACTIVE','finished'}):
            raise LedgerError('NATIVE_ADMISSION_RESULT_UNCONFIRMED')
        _token(result['run_id'])
        # Deliberately omit native paths, tokens, owners and internal observations.
        receipt = {key:result[key] for key in ('status','run_id','generation')}
        if result['status']!='ACTIVE':
            raise LedgerError('NATIVE_ADMISSION_RESULT_UNCONFIRMED')
        return receipt
