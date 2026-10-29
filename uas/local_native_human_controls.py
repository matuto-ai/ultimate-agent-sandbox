"""Fresh request-only controls; advisory UI hints never lend human authority."""
import hashlib
from .ledger import LedgerError, _json
from .manager_actions import HumanSession, current_run, request
from .native_broker_audit import NativeBrokerAudit
from .native_review_host import NativeReviewHost

ACTIONS = frozenset({'request-changes', 'reconcile-changes'})


def _current(graph, session, action):
    from .local_native_graph import LocalNativeGraph
    if type(graph) is not LocalNativeGraph or graph.closed or graph.activity is None:
        raise LedgerError('LOCAL_NATIVE_CONTROLS_UNAVAILABLE')
    graph.host.operation_current()
    activity = graph.activity
    activity._session()
    if (type(session) is not HumanSession or not session.allowed(action)
            or not session.allowed('observe')
            or any(getattr(session, name) != getattr(activity.grant, name)
                   for name in ('deployment_id', 'room_id', 'instance_id', 'manager_id'))):
        raise LedgerError('LOCAL_NATIVE_CONTROL_AUTHENTICATION_REQUIRED')
    return activity


def _observe(graph, session, audit, action, *, value=None):
    """One actual Broker/Hub read cut, optionally match an exact prior command."""
    operation = audit.observation()
    receipt = None
    with operation.prepare_manager_guard():
        with graph.owner.supervisor._locked():
            graph.owner._room()
            with operation.manager_action_guard(graph.ledger.room_id, audit.binding.repository) as forge:
                activity = _current(graph, session, action)
                if value is not None:
                    digest = hashlib.sha256(_json(value).encode()).hexdigest()
                    def authorize(origin, command):
                        _current(graph, session, action)
                        return origin == session.human and 'human-control-run' in origin.capabilities
                    def matches(command):
                        metadata = command.payload.get('_manager')
                        return (command.kind == 'review.human-changes'
                            and command.run_id == value['run_id'] and command.generation == value['generation']
                            and type(metadata) is dict and metadata.get('request_digest') == digest
                            and metadata.get('human_origin') == session.human.canonical())
                    receipt = graph.ledger.matched_receipt(value['operation_id'], session.human,
                                                          authorize=authorize, matches=matches)
                state = graph.ledger.snapshot()['state']
                view = current_run(state, activity._row()['run_id'], forge)
                operation.require_current()
    _current(graph, session, action)
    return view, state, receipt


def _hints(view, state, available, session):
    """Advisory state only: each click requires a new independently checked frame."""
    if view is None: return []
    run_id = view['run_id']; run = state['runs'][run_id]
    review = state.get('run_reviews', {}).get(run_id, {}).get('current')
    result = []
    for action in sorted(ACTIONS):
        target = review['submission_id'] if review else run_id
        reason = None
        pending = [key for key, item in state.get('review_comments', {}).items()
            if item['run_id'] == run_id and item['generation'] == view['generation']
            and item['status'] in {'pending', 'unknown', 'confirmed-awaiting-target'}]
        if action not in available or 'human-control-run' not in session.human.capabilities:
            reason = 'HUMAN_AUTHORITY_UNAVAILABLE'
        elif run.get('control_pending'): reason = 'RUN_CONTROL_PENDING'
        elif run['status'] == 'CLOSED': reason = 'RUN_CLOSED'
        elif action == 'request-changes':
            if view['forge_uncertain']: reason = 'MANAGER_FORGE_RECONCILIATION_REQUIRED'
            elif run['status'] != 'ACTIVE' or not review or review['stage'] != 'READY_FOR_HUMAN':
                reason = 'INELIGIBLE_STATE'
        elif len(pending) != 1: reason = 'RECONCILIATION_TARGET_REQUIRED'
        else: target = pending[0]
        result.append({'action':action,'object_id':target,'eligible':reason is None,'reason':reason,
                       'requires_fresh_authentication':True})
    return result


def handle_native_human(graph, frame, payload, session, *, available_actions=()):
    """Use existing FieldNotes envelopes without storing request authority.

    available_actions is advisory metadata supplied by the trusted Manager from
    its current certificate binding, NEVER JSON. It cannot authorize execution.
    Execute exceptions may follow a committed effect: report unknown, no retry.
    """
    if (type(frame) is not dict or set(frame) != {'version', 'action', 'payload'}
            or type(frame['version']) is not int or frame['version'] != 1
            or type(payload) is not dict or payload != frame['payload']
            or type(frame['action']) is not str):
        raise LedgerError('LOCAL_NATIVE_CONTROL_FRAME_REQUIRED')
    if type(available_actions) is not tuple or any(type(item) is not str for item in available_actions):
        raise LedgerError('LOCAL_NATIVE_CONTROL_HINTS_REQUIRED')
    action = frame['action']
    if action not in ACTIONS | {'observe'}:
        raise LedgerError('LOCAL_NATIVE_CONTROL_UNSUPPORTED')
    activity = _current(graph, session, action)
    if action == 'observe':
        if set(payload) != {'kind','run_id'} or payload['kind'] != 'run':
            raise LedgerError('LOCAL_NATIVE_CONTROL_UNSUPPORTED')
        if payload['run_id'] != activity._row()['run_id']:
            raise LedgerError('LOCAL_NATIVE_CONTROL_RUN_MISMATCH')
        audit = NativeBrokerAudit(graph.broker, session)
        view, state, _ = _observe(graph, session, audit, action)
        return {'status':'available','scope':{key:getattr(session,key)
                for key in ('deployment_id','room_id','instance_id')},
                'current':view,'actions':_hints(view,state,available_actions,session)}
    if (set(payload) != {'kind', 'request'} or payload['kind'] not in ('execute', 'inspect')
            or type(payload['request']) is not dict or payload['request'].get('action') != action):
        raise LedgerError('LOCAL_NATIVE_CONTROL_ACTION_MISMATCH')
    value = request(payload['request'], session)
    row = activity._row()
    if value['run_id'] != row['run_id'] or value['generation'] != row['generation']:
        raise LedgerError('LOCAL_NATIVE_CONTROL_RUN_MISMATCH')
    audit = NativeBrokerAudit(graph.broker, session)
    if payload['kind'] == 'inspect':
        if action != 'request-changes': raise LedgerError('INVALID_MANAGER_ACTION')
        view, state, receipt = _observe(graph, session, audit, action, value=value)
        item = state.get('review_comments', {}).get(value['operation_id'])
        outcome = 'unknown'
        if (receipt is not None and item is not None and item.get('run_id') == value['run_id']
                and item.get('generation') == value['generation']):
            if item.get('status') == 'confirmed': outcome = 'confirmed'
            elif item.get('status') == 'stale': outcome = 'partial'
        return {'operation_id':value['operation_id'],'outcome':outcome,
            'reason':None if outcome == 'confirmed' else 'OWNER_OUTCOME_UNCONFIRMED','current':view,
            'receipt':{'operation_id':value['operation_id'],'status':outcome,
                       'source':'exact-owner-receipt','read_only':True}}
    root = None if graph.recruitment is None else graph.recruitment.root
    review = None if root is None else root.review_host
    if type(review) is not NativeReviewHost:
        raise LedgerError('LOCAL_NATIVE_REVIEW_UNAVAILABLE')
    pending = activity._pending_comments()
    if pending and (action != 'reconcile-changes' or value['object_id'] not in pending):
        raise LedgerError('NATIVE_HUMAN_RECONCILIATION_REQUIRED')
    _current(graph, session, action)
    result = review.human_action(value, session=session, audit=audit)
    _current(graph, session, action)
    view, _, _ = _observe(graph, session, audit, action)
    status = result.get('status')
    outcome = ('confirmed' if status == 'confirmed' else 'partial' if status == 'stale'
               else 'denied' if status == 'error' else 'unknown')
    return {'operation_id':value['operation_id'],'outcome':outcome,
        'reason':None if outcome == 'confirmed' else 'OWNER_OUTCOME_UNCONFIRMED','current':view}
