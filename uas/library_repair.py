"""Explicit human, fair bounded deterministic index repair; no model or retry loop."""
from copy import deepcopy
from datetime import datetime
import hashlib
from . import library, library_bundle as bundle, library_gate as gate, library_deadline
from .library_indexes import reconstruct
from .library_registration import project_state


def fail(code):
    raise library.LibraryError(code, 'repair')


def finish(scheduler, operation, publication=None):
    receipt = library.receipt(operation, 'COMMITTED' if publication else 'ACKNOWLEDGED',
        at=operation.at, **({'publication':{'commit_sha':publication.resulting_sha,
            'path':bundle._prefix(operation.scope)+'/index.md'}} if publication else
            {'acknowledgement':library._digest(operation.canonical()), 'reason':'REPAIR_NO_CHANGE'}))
    with scheduler._records() as records:
        prior = records.record(operation.operation_id, project_identity=operation.scope.project_identity)
        if prior is None: records.begin(operation)
        if prior is None or prior['receipt'] is None: records.finish(operation, receipt)
        else: receipt = prior['receipt']
    return receipt


def handle(controls, value, principal, entry, scope, settings):
    with library_deadline.bounded(min(30, settings['limits']['attempt_seconds'])):
        return _handle(controls, value, principal, entry, scope, settings)


def _handle(controls, value, principal, entry, scope, settings):
    scheduler = controls.service.scheduler
    publisher = controls.service.publisher
    def current():
        library_deadline.remaining(30)
        controls._entry(scope.project_id)
        if (controls._scope(principal, entry, 'repair').canonical() != scope.canonical()
                or controls._settings(entry)['settings_id'] != settings['settings_id']):
            fail('STALE_CONTROL_STATE')
    def snapshot():
        head, tree = publisher.project_snapshot(scope, settings, current=current)
        prefix = bundle._prefix(scope)
        if prefix+'/index.md' not in tree.files: fail('PROJECT_UNAVAILABLE')
        if project_state(tree, prefix) != 'active': fail('PROJECT_ARCHIVED')
        target = library._digest({p:hashlib.sha256(data).hexdigest() for p,data in tree.files.items()})
        return head, tree, controls._version(entry, scope, settings, target)
    current()
    if value['action'] == 'observe':
        scheduler._check()
        head, tree, version = snapshot()
        _, reports = reconstruct(scope, tree)
        return {'version':1,'project_id':scope.project_id,'settings_id':settings['settings_id'],
                'observed_version':version,'commit_sha':head,'reports':list(reports)}
    identity = 'human-control-'+library._digest([scope.project_identity,value['request_id']])
    payload = {'observed_version':value['observed_version']}
    with scheduler._records() as records:
        prior = records.record(identity, project_identity=scope.project_identity)
    if prior:
        if (prior['kind'] != 'repair' or prior['settings_id'] != value['settings_id']
                or prior['payload_sha256'] != library._digest(payload)
                or any(prior['scope'][k] != scope.canonical()[k]
                       for k in ('human_id','actor_id','subject','project_id','project_identity'))): fail('ID_CONFLICT')
        if prior['receipt'] is not None: return deepcopy(prior['receipt'])
        historic = dict(prior['scope']); historic['project_path'] = prior['project_path']
        historic['capabilities'] = tuple(historic['capabilities'])
        old_scope = library.LibraryScope(seal=library._SCOPE_SEAL, **historic)
        operation = library._operation('repair', old_scope, {**settings,'settings_id':prior['settings_id']},
            identity, value['request_id'], payload, prior['at'])
        publication = publisher.publication_for(operation, current=current)
        if publication is None: fail('CONTROL_OUTCOME_UNKNOWN')
        current()
        return finish(scheduler, operation, publication)
    scheduler._check()
    if not scheduler._turn.acquire(blocking=False): fail('CONTROL_BUSY')
    locked = False
    try:
        # Share the scheduler's durable least-recently-served priority. Explicit
        # repair does not jump ahead of another ready Project or preempt work.
        now = scheduler.now()
        priority = (entry['state']['served'], scope.project_identity)
        for key, other in scheduler._entries.items():
            state = other['state']
            if (key != scope.project_identity and state['state'] in ('READY','BACKOFF')
                    and state['due'] is not None and datetime.fromisoformat(state['due']) <= now
                    and (state['served'], key) <= priority): fail('REPAIR_YIELD_REQUIRED')
        if entry['state']['state'] == 'ACTIVE': fail('CONTROL_BUSY')
        locked = publisher.synthesis_lock.acquire(blocking=False)
        if not locked: fail('CONTROL_BUSY')
        head, tree, version = snapshot()
        if value['settings_id'] != settings['settings_id'] or value['observed_version'] != version:
            fail('STALE_CONTROL_STATE')
        proposed, reports = reconstruct(scope, tree)
        # Complete normal Project policy/structure, with only independently
        # reconstructed index bytes admitted as predecessor normalization.
        checked = gate.validate(scope, settings, proposed=proposed, current=tree, repair=True)
        operation = library.action(scope, settings, kind='repair', operation_id=identity,
            request_id=value['request_id'],payload=payload,at=now.isoformat())
        current()
        state = deepcopy(entry['state'])
        state['served'] = max(int(now.timestamp()*1000000), max(e['state']['served'] for e in scheduler._entries.values())+1)
        scheduler._save(entry, state, now)
        with scheduler._records() as records: records.begin(operation)
        if dict(proposed.files) == dict(tree.files): return finish(scheduler, operation)
        publication = publisher.publish(operation, checked.bundle, input_sha=head, current=current)
        current()
        return finish(scheduler, operation, publication)
    finally:
        if locked: publisher.synthesis_lock.release()
        scheduler._turn.release()
