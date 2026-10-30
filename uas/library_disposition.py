"""Human dispositions: one canonical Git transition, metadata-only recovery/reporting.

Historical human scopes below are evidence, never authority. Every read and
publication uses a freshly trusted caller-supplied current-authority fence.
"""
from copy import deepcopy
import json

from . import library, library_bundle as bundle, library_gate as gate
from .library_compiler import _index
from .library_records import LibraryRecords

MARKER = 'Library disposition receipt '


def fail(code):
    raise library.LibraryError(code, 'disposition')


def evidence(operation, state):
    selected = list(state['selected']) if operation.drain_id else []
    return dict(operation_id=operation.operation_id, request_id=operation.request_id,
        at=operation.at, scope=operation.scope.canonical(), settings_id=operation.settings_id,
        payload=operation.payload, selected=selected, attempt=state['attempt'] if selected else 0,
        sequence=state['sequence'] + 1 if selected else 0)


def historic_operation(scope, settings, settings_id, identity, request, payload, at):
    # Re-admit bounded historical evidence, not today's write settings. Its
    # original digest is verified against the durable record and Git trailer.
    kind = 'adjudicate' if 'conclusion' in payload else 'reject'
    library._require_scope(scope, 'human', 'library-'+kind)
    limits={**settings['limits'],'body_bytes':8192,'payload_bytes':8192}
    library._human_payload(kind,payload,limits)
    return library._operation(kind,scope,{**settings,'settings_id':settings_id,'limits':limits},
        identity,request,payload,at,drain_id=payload['drain_id'])


def admitted(value, scope, settings):
    library._object(value, 'disposition', ('operation_id','request_id','at','scope',
        'settings_id','payload','selected','attempt','sequence'))
    original = dict(value['scope']); original['capabilities'] = tuple(original['capabilities'])
    historic = library.LibraryScope(seal=library._SCOPE_SEAL, **original)
    if historic.project_identity != scope.project_identity or historic.project_id != scope.project_id:
        fail('DISPOSITION_EVIDENCE_INVALID')
    op = historic_operation(historic, settings, value['settings_id'],
        value['operation_id'], value['request_id'], value['payload'], value['at'])
    selected = library.batch_manifest({'selected':value['selected']})['selected'] if value['selected'] else []
    if bool(selected) != bool(op.drain_id) or (selected and op.payload['queue_id'] not in selected):
        fail('DISPOSITION_EVIDENCE_INVALID')
    for key in ('attempt','sequence'):
        if type(value[key]) is not int or not 0 <= value[key] <= 2**53-1: fail('DISPOSITION_EVIDENCE_INVALID')
    if bool(value['sequence']) != bool(selected): fail('DISPOSITION_EVIDENCE_INVALID')
    return op


def markers(tree, scope, settings):
    prefix = bundle._prefix(scope)
    for line in tree.files.get(prefix+'/log.md', b'').decode('utf-8').splitlines():
        if not line.startswith(MARKER): continue
        try:
            value = json.loads(line[len(MARKER):], object_pairs_hook=library._unique_pairs)
            operation = admitted(value, scope, settings)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError): fail('DISPOSITION_EVIDENCE_INVALID')
        yield value, operation


def finish(publisher, operation, publication):
    receipt = library.receipt(operation, 'COMMITTED', at=operation.at,
        publication={'commit_sha':publication.resulting_sha,
                     'path':bundle._prefix(operation.scope)+'/log.md'})
    with LibraryRecords(publisher.records_path, publisher.deployment_id) as records:
        prior=records.record(operation.operation_id, project_identity=operation.scope.project_identity)
        if prior['receipt'] is None: records.finish(operation, receipt)
        else: receipt=prior['receipt']
    return receipt


def find(publisher, scope, settings, current, drain_id, *, tree=None):
    """Canonical tombstone wins over old attempt output, even after record loss."""
    if tree is None: _, tree = publisher.project_snapshot(scope, settings, current=current)
    current()
    gate.validate(scope, settings, proposed=tree, current=tree)
    matches = [(v,o) for v,o in markers(tree,scope,settings) if o.drain_id and (drain_id is None or o.drain_id == drain_id)]
    if not matches: return None
    if drain_id is None: matches=matches[-1:]
    if len(matches) != 1: fail('DISPOSITION_EVIDENCE_INVALID')
    value, operation = matches[0]
    publication = publisher.publication_evidence(operation, current=current)
    if publication is None: fail('DISPOSITION_EVIDENCE_INVALID')
    _, original = publisher.project_snapshot_at(operation.scope, settings, publication.resulting_sha, current=current)
    if not any(v==value for v,o in markers(original, operation.scope, settings)):
        fail('DISPOSITION_EVIDENCE_INVALID')
    current()
    with LibraryRecords(publisher.records_path,publisher.deployment_id) as records: records.begin(operation)
    finish(publisher,operation,publication)
    current()
    return value, publication.resulting_sha


def apply_schedule(scheduler, entry, value, commit):
    if not value['selected']: return
    old=entry['state']
    if old['state']=='DISPOSED' and old['drain_id']==value['payload']['drain_id']: return
    # Canonical sequence is a lower bound, not a claim on an occupied outbox
    # slot: an intervening revoked-authority restart can report BLOCKED first.
    # _save atomically persists the chosen schedule/report identity before send.
    adjudicated = 'conclusion' in value['payload']
    outcomes=[dict(queue_id=q,kind=('adjudicated' if adjudicated else 'rejected') if q==value['payload']['queue_id'] else 'retained',
        reason=('OPERATOR_ADJUDICATED' if adjudicated else 'OPERATOR_REJECTED') if q==value['payload']['queue_id'] else 'OPERATOR_RETAINED') for q in value['selected']]
    scheduler._save(entry,{**old,'state':'DISPOSED','due':None,'wake':False,
        'drain_id':value['payload']['drain_id'],'selected':value['selected'],
        'attempt':value['attempt'],'reason':'OPERATOR_DISPOSED'}, scheduler.now(),
        sequence=max(value['sequence'],old['sequence']+1), transition=dict(phase='OPERATOR_DISPOSED',
            resulting_sha=commit,outcomes=outcomes,attempt=value['attempt']))


def apply(controls, value, principal, entry, scope, settings):
    kind = value['action']
    scheduler=controls.service.scheduler; publisher=controls.service.publisher
    def current():
        controls._entry(scope.project_id)
        if (controls._scope(principal,entry,kind).canonical()!=scope.canonical()
                or controls._settings(entry)['settings_id']!=settings['settings_id']): fail('STALE_CONTROL_STATE')
    current()
    payload={k:value[k] for k in library.HUMAN_PAYLOADS[kind][0]}
    identity='human-control-'+library._digest([scope.project_identity,value['request_id']])
    with scheduler._records() as records: prior=records.record(identity,project_identity=scope.project_identity)
    if prior:
        if (prior['kind']!=kind or prior['settings_id']!=value['settings_id']
                or prior['payload_sha256']!=library._digest(payload)
                or any(prior['scope'][k]!=scope.canonical()[k] for k in ('human_id','actor_id','subject','project_id','project_identity'))): fail('ID_CONFLICT')
        if prior['receipt'] is not None:
            # Reconcile only while the live schedule still shows that batch. A
            # later resume already released the remainder; an old disposition
            # must not re-dispose it from this replay.
            if payload['drain_id'] and entry['state']['drain_id']==payload['drain_id']:
                recovered=find(publisher,scope,settings,current,payload['drain_id'])
                if recovered is None: fail('DISPOSITION_EVIDENCE_INVALID')
                apply_schedule(scheduler,entry,*recovered)
            return deepcopy(prior['receipt'])
        # Unknown never means permission to reapply a stale payload.
        historic=dict(prior['scope']); historic['project_path']=prior['project_path']
        historic['capabilities']=tuple(historic['capabilities'])
        operation=historic_operation(library.LibraryScope(seal=library._SCOPE_SEAL,**historic),
            settings,prior['settings_id'],identity,value['request_id'],payload,prior['at'])
        publication=publisher.publication_for(operation,current=current)
        if publication is None: fail('CONTROL_OUTCOME_UNKNOWN')
        if operation.drain_id and entry['state']['drain_id']==operation.drain_id:
            recovered=find(publisher,scope,settings,current,operation.drain_id)
            if recovered is None: fail('DISPOSITION_EVIDENCE_INVALID')
            apply_schedule(scheduler,entry,*recovered)
        return finish(publisher,operation,publication)
    operation=library.action(scope,settings,kind=kind,operation_id=identity,
        request_id=value['request_id'],payload=payload,at=scheduler.now().isoformat())
    scheduler._check()
    old=entry['state']; queue=value['queue_id']
    if old['state']=='ACTIVE' and queue in old['selected']: fail('CONTROL_BUSY')
    affected=queue in old['selected'] and old['state']!='DISPOSED'
    if affected and old['state']!='BLOCKED': fail('CONTROL_BUSY')
    if value['drain_id']!=(old['drain_id'] if affected else None): fail('STALE_CONTROL_STATE')
    # Same exact trusted human inspection evidence as T23; caller cannot supply paths.
    inspected=controls._scope(principal,entry,'inspect')
    observed=controls._inspect(dict(action='observe',queue_id=queue),principal,entry,inspected,settings)
    if value['settings_id']!=settings['settings_id'] or value['observed_version']!=observed['observed_version']:
        fail('STALE_INSPECTION')
    if not publisher.synthesis_lock.acquire(blocking=False): fail('CONTROL_BUSY')
    publishing=False
    try:
        head,tree=publisher.project_snapshot(scope,settings,current=current)
        if head!=observed['commit_sha']: fail('STALE_INSPECTION')
        prefix=bundle._prefix(scope); path='pending/'+queue+'.md'
        files=dict(tree.files); del files[prefix+'/'+path]
        files[prefix+'/pending/index.md']=_index(tree.files[prefix+'/pending/index.md'],
            'pending',{path},files,prefix,{},tree.files)
        canonical=evidence(operation,old)
        if kind == 'adjudicate':
            from .library_adjudication import render
            render(files, tree, operation, settings, head)
        else:
            # Check unescaped reason as authored Markdown, not audit metadata.
            gate._policy('log.md',value['reason'],settings['filters'],[])
        files[prefix+'/log.md'] += ('\n'+MARKER+library._canonical(canonical)+'\n').encode('utf-8')
        checked=gate.validate(scope,settings,proposed=bundle.Tree(files),current=tree,selected=(queue,))
        current()
        publishing=True
        publication=publisher.publish(operation,checked.bundle,input_sha=head,current=current)
        apply_schedule(scheduler,entry,canonical,publication.resulting_sha)
        current()
        return finish(publisher,operation,publication)
    except BaseException:
        # Once publication may have happened, no new scheduler/control turn may
        # use the old in-memory batch. Restart reconstructs canonical evidence;
        # exact request reconciliation above remains available without a write.
        if publishing: scheduler._failed=True
        raise
    finally: publisher.synthesis_lock.release()


# Compatibility for existing trusted service callers.
def reject(controls, value, principal, entry, scope, settings):
    if value.get("action") != "reject": fail("INVALID_CONTROL_REQUEST")
    return apply(controls, value, principal, entry, scope, settings)
