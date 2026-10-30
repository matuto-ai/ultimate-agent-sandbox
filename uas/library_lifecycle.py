"""Explicit T35 archive/restore: durable admission, one final attempt, Git-only retry.

No human content leaves this module except through the normal complete-result
and fast-forward publication owners. A pending operation is not success.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
from . import library, library_bundle as bundle, library_gate as gate
from .library_records import LibraryRecords
from .library_registration import project_state


def fail(code):
    raise library.LibraryError(code, 'lifecycle')


def frozen(publisher, key):
    with LibraryRecords(publisher.records_path, publisher.deployment_id) as records:
        latest = records.latest_lifecycle(key)
    return latest is not None and (latest['kind'] == 'archive' or latest['receipt'] is None)


def proposed_state(operation, tree):
    """Exactly the root lifecycle marker plus append-only lifecycle history."""
    prefix = bundle._prefix(operation.scope)
    before = project_state(tree, prefix)
    expected, after = ('active','archived') if operation.kind == 'archive' else ('archived','active')
    if before != expected: fail('PROJECT_ARCHIVED' if before == 'archived' else 'PROJECT_NOT_ARCHIVED')
    files = dict(tree.files)
    root = files[prefix+'/index.md'].decode('utf-8')
    lines = root.splitlines(keepends=True)
    marker = 'Library state: '+after+'\n'
    if any(line.startswith('Library state:') for line in lines):
        root = ''.join(marker if line.startswith('Library state:') else line for line in lines)
    else:
        root = root+('\n' if root.endswith('\n') else '\n\n')+marker
    files[prefix+'/index.md'] = root.encode()
    files[prefix+'/log.md'] += ('\n## '+operation.at[:10]+'\n* **'+operation.kind.title()
        +'**: Project '+after+'. Lifecycle receipt '+operation.operation_id+'.\n').encode()
    return bundle.Tree(files)


def finish(scheduler, operation, publication):
    result = library.receipt(operation, 'COMMITTED', at=operation.at,
        publication={'commit_sha':publication.resulting_sha,
            'path':bundle._prefix(operation.scope)+'/index.md'})
    with scheduler._records() as records:
        prior = records.record(operation.operation_id, project_identity=operation.scope.project_identity)
        if prior['receipt'] is not None: return deepcopy(prior['receipt'])
        records.finish(operation, result)
    return result


def handle(controls, value, principal, *, reconcile_only=False):
    scheduler, publisher = controls.service.scheduler, controls.service.publisher
    kind = value.get('for_action', value['action'])
    with scheduler._lock:
        entry = controls._entry(value['project_id'])
        scope = controls._scope(principal, entry, kind)
        settings = controls._settings(entry)
        def current():
            controls._entry(scope.project_id)
            if (controls._scope(principal, entry, kind).canonical() != scope.canonical()
                    or controls._settings(entry)['settings_id'] != settings['settings_id']):
                fail('STALE_CONTROL_STATE')
        def snapshot():
            current()
            head, tree = publisher.project_snapshot(scope, settings, current=current)
            if not tree.files: fail('PROJECT_UNAVAILABLE')
            gate.validate(scope, settings, proposed=tree, current=tree)
            target = library._digest({p:hashlib.sha256(b).hexdigest() for p,b in tree.files.items()})
            return head, tree, controls._version(entry, scope, settings, target)
        if value['action'] == 'observe':
            _, tree, version = snapshot()
            return dict(version=1,project_id=scope.project_id,settings_id=settings['settings_id'],
                observed_version=version,state=project_state(tree,bundle._prefix(scope)))
        identity = 'human-control-'+library._digest([scope.project_identity,value['request_id']])
        payload = {'observed_version':value['observed_version']}
        with scheduler._records() as records:
            prior = records.record(identity, project_identity=scope.project_identity)
        if prior:
            if (prior['kind'] != kind or prior['settings_id'] != value['settings_id']
                    or prior['payload_sha256'] != library._digest(payload)
                    or any(prior['scope'][k] != scope.canonical()[k]
                           for k in ('human_id','actor_id','subject','project_id','project_identity'))): fail('ID_CONFLICT')
            if prior['receipt'] is not None: return deepcopy(prior['receipt'])
            if prior['project_path'] != scope.project_path:
                fail('STALE_CONTROL_STATE')
        elif reconcile_only:
            fail('CONTROL_OUTCOME_UNKNOWN')
        if prior:
            historical = dict(prior['scope']); historical['project_path'] = prior['project_path']
            historical['capabilities'] = tuple(historical['capabilities'])
            operation = library._operation(kind,library.LibraryScope(seal=library._SCOPE_SEAL,**historical),
                {**settings,'settings_id':prior['settings_id']},identity,value['request_id'],payload,prior['at'])
        else:
            operation = library.action(scope, settings, kind=kind, operation_id=identity,
                request_id=value['request_id'], payload=payload,at=scheduler.now().isoformat())
        if not prior:
            scheduler._check()
            # Same boundary as enqueue: no accepted capture can cross this intent.
            with publisher.registration_lock:
                _, tree, version = snapshot()
                if value['settings_id'] != settings['settings_id'] or value['observed_version'] != version:
                    fail('STALE_CONTROL_STATE')
                with scheduler._records() as records:
                    latest = records.latest_lifecycle(scope.project_identity)
                    if latest and latest['receipt'] is None: fail('LIFECYCLE_PENDING')
                    # Validate the complete proposed lifecycle delta before reserving.
                    gate.validate(scope,settings,proposed=proposed_state(operation,tree),current=tree,lifecycle=operation)
                    current(); records.begin(operation)
        publication = publisher.publication_for(operation, current=current)
        if publication is not None:
            _settle_final_schedule(scheduler,entry,operation)
            return finish(scheduler,operation,publication)
        if reconcile_only: fail('CONTROL_OUTCOME_UNKNOWN')
        if prior and prior['settings_id'] != settings['settings_id']: fail('STALE_CONTROL_STATE')
        # A continuing attempt retains current egress admission as well as its identity.
        library.action(scope,settings,kind=kind,operation_id=identity,request_id=value['request_id'],
            payload=payload,at=operation.at)
    # Never wait under scheduler._lock: the active global turn needs it to finish.
    # A timeout leaves the durable fence pending; exact request retry continues it.
    if not scheduler._turn.acquire(timeout=min(30, settings['limits']['attempt_seconds'])):
        fail('CONTROL_BUSY')
    try:
        current()
        publication = publisher.publication_for(operation,current=current)
        if publication is not None:
            _settle_final_schedule(scheduler,entry,operation)
            return finish(scheduler,operation,publication)
        if kind == 'archive':
            _final_attempt(controls,entry,operation,settings,current)
        with scheduler._lock, publisher.registration_lock:
            current()
            head, tree, _ = snapshot()
            proposed = proposed_state(operation,tree)
            checked = gate.validate(operation.scope,settings,proposed=proposed,current=tree,lifecycle=operation)
            # A rejected/uncertain push retries only this deterministic publication.
            publication = publisher.publish(operation,checked.bundle,input_sha=head,current=current)
            current()
            return finish(scheduler,operation,publication)
    finally:
        scheduler._turn.release()


def _final_attempt(controls,entry,operation,settings,current):
    scheduler = controls.service.scheduler
    identity = 'archive-final-'+library._digest(operation.operation_id)
    with scheduler._records() as records:
        reserved = records.record(identity,project_identity=operation.scope.project_identity)
    if reserved:
        # Recovery may reconcile the exact final drain but never call its model again.
        with scheduler._records() as records:
            attempted = any(r['kind'] in ('synthesis-attempt','source-park')
                for r in records.iter_drain(identity,project_identity=operation.scope.project_identity))
        recovered = entry['runner'].recover(identity) if attempted else None
        _settle_final_schedule(scheduler,entry,operation,result=recovered)
        return
    with scheduler._lock:
        current()
        old = deepcopy(entry['state'])
        if old['state']=='ACTIVE':
            old.update(state='BLOCKED',due=None,reason='ARCHIVE_INTERRUPTED_ATTEMPT')
        reserve = library._operation('archive-final',operation.scope,settings,identity,identity,
            {'manifest_sha256':library._digest(old)},operation.at,drain_id=identity)
        reserve = replace(reserve,manifest=old)
        with scheduler._records() as records:
            records.begin(reserve,exclusive=True)
            records.finish(reserve,library.receipt(reserve,'ACKNOWLEDGED',at=operation.at,
                acknowledgement=library._digest(reserve.payload),reason='FINAL_ATTEMPT_RESERVED'))
        # Archive is not an implicit retry of a failed/blocked/disposed batch.
        if old['failures'] or old['state'] in ('BACKOFF','BLOCKED','DISPOSED') or old['selected']:
            _settle_final_schedule(scheduler,entry,operation)
            return
        try:
            selected = scheduler._batch(entry)
        except library.LibraryError as error:
            # No model call. Storage/transport uncertainty still requires recovery.
            if uncertain(error): raise
            return
        if not selected: return
        state = {**old,'state':'ACTIVE','due':None,'selected':selected,'drain_id':identity,
            'attempt':1,'wake':False,'reason':None}
        scheduler._save(entry,state,scheduler.now())
    result = None
    settled = False
    reason = 'ARCHIVE_FINAL_ATTEMPT_INTERRUPTED'
    try:
        current()
        accepted,indexes = entry['context'](tuple(selected))
        result = entry['runner'].run(drain_id=identity,attempt=1,selected=selected,
            accepted=accepted,indexes=indexes,at=operation.at)
        settled = True
    except library.LibraryError as error:
        reason = error.code
        # The final attempt owner reconciles any canonical publication on retry.
        # Ordinary final model/source failure never schedules a second attempt.
        if uncertain(error): raise
        settled = True
    finally:
        if settled: _settle_final_schedule(scheduler,entry,operation,result=result,reason=reason)


def _settle_final_schedule(scheduler, entry, operation, *, result=None, reason='ARCHIVE_FINAL_ATTEMPT_INTERRUPTED'):
    """A crashed final turn cannot leak its batch into the restored scheduler."""
    if operation.kind != 'archive': return
    identity = 'archive-final-'+library._digest(operation.operation_id)
    with scheduler._records() as records:
        reserved = records.record(identity,project_identity=operation.scope.project_identity)
    if reserved is None: return
    target = deepcopy(reserved['manifest'])
    def state(value): return {k:v for k,v in value.items() if k not in ('sequence','transition')}
    with scheduler._lock:
        if state(entry['state']) != state(target):
            transition = None
            if entry['state']['drain_id'] == identity and entry['state']['attempt'] == 1:
                outcomes = []
                if result is not None:
                    outcomes = ([dict(queue_id=q,kind='parked',reason=r) for q,r in result.outcomes]
                        if result.state=='SOURCE_PARKED' else list(result.outcomes))
                transition = dict(phase='COMMITTED' if result is not None else 'BLOCKED',
                    drain_id=identity,attempt=1,resulting_sha=result.resulting_sha if result else None,
                    outcomes=outcomes,reason=None if result else reason)
            scheduler._save(entry,target,scheduler.now(),transition=transition)


def uncertain(error):
    return (error.code.startswith(('RECORD_','STORE_','GIT_','REMOTE_','LEASE_','CLONE_','PIN_'))
        or error.code in ('PUBLICATION_UNAVAILABLE','PUBLICATION_REJECTED','ATTEMPT_TIMEOUT','INVALID_STORE','INVALID_RECORD'))
