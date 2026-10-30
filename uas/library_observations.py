"""T29 passive, strict metadata export; no content API, model calls or polling.

The Library owner explicitly samples, journals and sends observations. The Hub
retains them under authenticated immutable Project binding. Manager reads that
cache without opening the canonical clone or pretending its own cut refreshed it.
"""
from copy import deepcopy
from dataclasses import replace, dataclass
from datetime import datetime, timezone
import threading
from . import library
from .library_records import LibraryRecords

from .manager_projection import (library_COUNTS as COUNTS, library_TIMES as TIMES, library_HASHES as HASHES, library_ENUMS as ENUMS, library_FIELDS as FIELDS, library_validate_row as validate_row, library_observation as observation, library_moment as moment, library_fail as fail)

def failure_class(code):
    if not code: return None
    for prefix,category in (('SOURCE','source'),('MODEL','model'),('PROVIDER','model'),
                           ('RECORD','audit'),('AUDIT','audit'),('RECOVER','recovery'),
                           ('GIT','transport'),('PUSH','transport'),('REMOTE','transport'),
                           ('TRANSPORT','transport'),('CAPTURE','capture')):
        if code.startswith(prefix): return category
    return 'validation'


@dataclass(frozen=True)
class ProviderObservation:
    """Trusted provider adapter observation, never derived from queue/drain success."""
    project_identity: str
    observed_at: str
    profile_sha256: str
    mode: str
    state: str
    version: int


class Owner:
    """Trusted service composition; current authority is rechecked around sampling.

    projection is a fixed ProjectProjection (or absent), never caller-supplied paths.
    Provider facts are explicitly unknown until a future provider-owned evidence
    adapter exists; dispatch success/readiness is not a quota/availability probe.
    """
    def __init__(self, publisher, *, current_scope, settings, projection=None):
        self.publisher,self.current_scope,self.settings,self.projection=publisher,current_scope,settings,projection
        self.scope=current_scope(); self._lock=threading.Lock()
        if type(self.scope) is not library.LibraryScope: fail()
        if projection is not None:
            from .library_projection import ProjectProjection
            if type(projection) is not ProjectProjection or projection.scope.project_identity!=self.scope.project_identity: fail()
    def _current(self):
        scope=self.current_scope()
        if type(scope) is not library.LibraryScope or scope.canonical()!=self.scope.canonical():
            raise library.LibraryError('LIBRARY_AUTHENTICATION_REQUIRED')
        library._require_scope(scope,'participant',library.ENQUEUE_CAPABILITY)
        return scope
    def latest(self):
        self._current()
        with LibraryRecords(self.publisher.records_path,self.publisher.deployment_id) as records:
            saved=records.latest_observation(self.scope.project_identity)
        self._current()
        return None if saved is None else observation(saved['manifest'])
    def capture(self, *, observed_at, window_start, max_records=1024, provider=None):
        now,start=moment(observed_at),moment(window_start)
        if start>now or type(max_records) is not int or not 1<=max_records<=10000: fail()
        with self._lock:
            scope=self._current(); settings=self.settings()
            # Git reads are bounded by admitted Project limits, not Manager requests.
            head,tree=self.publisher.project_snapshot(scope,settings,current=self._current)
            from .library_bundle import _prefix
            from . import library_gate
            library_gate.validate(scope,settings,proposed=tree,current=tree)
            prefix=_prefix(scope)
            queues={p[len(prefix+'/pending/'):-3] for p in tree.files
                    if p.startswith(prefix+'/pending/') and p.endswith('.md') and not p.endswith('/index.md')}
            pending=tree.files.get(prefix+'/pending/index.md',b'').decode('utf-8')
            parked={q for q in queues if any(q+'.md)' in l and 'DRAFT PARKED:' in l for l in pending.splitlines())}
            with LibraryRecords(self.publisher.records_path,self.publisher.deployment_id) as records:
                previous=records.latest_observation(scope.project_identity)
                history,complete=records.project_history(scope.project_identity,limit=max_records)
                schedule=records.latest_schedule(scope.project_identity)
            row={key:None for key in FIELDS}
            row.update(project_identity=scope.project_identity,window_start=window_start,window_end=observed_at,
                active_depth=len(queues-parked),parked_depth=len(parked),queue_status='known',canonical_sha=head,
                coverage='complete' if complete else 'partial',drain_state='unknown',projection_state='unknown',
                provider_state='unknown',provider_mode='unknown',effectiveness='unmeasured',feedback='unmeasured')
            captures={}; parking={}; published=set(); outcomes=merged=humans=corrections=0; lag=0
            acknowledgements={r['operation_id'] for r in history if r['kind']=='drain-report-ack' and r['receipt'] is not None}
            for record in history:
                if record["state"]=="DETAIL_EXPIRED": continue
                transition=record.get('manifest',{}).get('transition')
                if record['kind']=='scheduler-state' and transition:
                    ident='report-'+library._digest([scope.project_identity,transition['drain_id'],transition['sequence']])
                    lag+=ident not in acknowledgements
            for category in ('capture','source','model','validation','transport','audit','recovery'):row[category+'_failures']=0
            for record in history:
                if record["state"]=="DETAIL_EXPIRED": continue
                if record['kind']=='enqueue' and record['receipt'] and record['receipt']['outcome']=='DURABLY_QUEUED':
                    when=moment(record['provenance']['at'])
                    captures[record['queue_id']]=min(when,captures.get(record['queue_id'],when))
                transition=record.get('manifest',{}).get('transition')
                if record['kind']=='scheduler-state' and transition and transition['phase']=='COMMITTED':
                    for outcome in transition['outcomes']:
                        if outcome['kind']=='parked':
                            when=moment(record['at']); q=outcome['queue_id']
                            parking[q]=max(when,parking.get(q,when))
                at=moment(record['at'])
                if not start<=at<=now: continue
                receipt=record['receipt']
                if record['kind']=='enqueue' and receipt and receipt['outcome']=='DURABLY_QUEUED':published.add(record['queue_id'])
                if record['kind']=='scheduler-state':
                    transition=record['manifest'].get('transition')
                    if transition:
                        if transition['phase']=='COMMITTED':
                            outcomes+=len(transition['outcomes']);merged+=sum(x['kind']=='merged' for x in transition['outcomes'])
                        category=failure_class(transition['reason'])
                        if category:row[category+'_failures']+=1
                elif receipt and receipt['outcome'] in ('REJECTED','NOT_DURABLE'):
                    category=failure_class(receipt.get('reason'))
                    row[(category or 'validation')+'_failures']+=1
            row['published_drafts']=len(published) if complete else None
            row['replay_lag']=lag if complete else None
            if complete and outcomes:row.update(effectiveness='observed',completed_outcomes=outcomes,duplicate_merges=merged)
            for key,selection,origins in (('oldest_age_seconds',queues-parked,captures),('adjudication_wait_seconds',parked,parking)):
                if selection and complete and selection<=origins.keys():row[key]=max(0,int((now-min(origins[q] for q in selection)).total_seconds()))
            if not complete:
                for key in row:
                    if key.endswith('_failures'):row[key]=None
            if schedule:
                state=schedule['manifest'];row.update(drain_state=state['state'],drain_id=state['drain_id'],
                    attempt=state['attempt'],retry_count=state['failures'],next_retry_at=state['due'] if state['state']=='BACKOFF' else None)
            if self.projection is not None:
                try:
                    view=self.projection.read(); manifest=view.manifest
                    row.update(projected_sha=manifest['commit_sha'],projected_at=manifest['published_at'],
                        projection_state='unknown' if manifest['commit_sha'] is None else 'current' if manifest['commit_sha']==head else 'stale')
                except library.LibraryError:row['projection_state']='unavailable'
            if provider is not None:
                if type(provider) is not ProviderObservation or provider.project_identity!=scope.project_identity: fail()
                if moment(provider.observed_at)>now: fail()
                row.update(provider_state=provider.state,provider_mode=provider.mode,provider_profile_sha256=provider.profile_sha256,provider_observed_at=provider.observed_at,provider_version=provider.version)
            self._current()
            value=observation({'sequence':1 if previous is None else previous['manifest']['sequence']+1,
                               'observed_at':observed_at,'row':row})
            from uuid import uuid4
            ident='observation-'+uuid4().hex
            op=library._operation('library-observation',scope,settings,ident,ident,{'manifest_sha256':library._digest(value)},observed_at)
            op=replace(op,manifest=value)
            with LibraryRecords(self.publisher.records_path,self.publisher.deployment_id) as records:
                records.begin(op);records.finish(op,library.receipt(op,'ACKNOWLEDGED',at=observed_at,
                    acknowledgement=library._digest(value),reason='OBSERVATION_RECORDED'))
            return value


class HubObservations:
    """Authenticated service ingress and passive fixed-Project RoomStream owner."""
    def __init__(self, ledger, *, project_identity, authenticate):
        from .ledger import RoomLedger
        if type(ledger) is not RoomLedger or not callable(authenticate):fail()
        library._token(project_identity,'project_identity')
        self.ledger,self.project_identity,self.authenticate=ledger,project_identity,authenticate
    def receive(self, value):
        from .ledger import Command,Event,Transition,LedgerError
        from .library_hub import _RESULT_ORIGIN
        if self.authenticate() is not True:raise LedgerError('FORBIDDEN')
        data=observation(value)
        if data['row']['project_identity']!=self.project_identity:raise LedgerError('INVALID_LIBRARY_BINDING')
        ident='library-observation-'+library._digest([self.project_identity,data['sequence']])
        def decide(state,_):
            old=state.get('library_observation')
            if old is not None and (old['row']['project_identity']!=self.project_identity or old['sequence']>=data['sequence']):
                raise LedgerError('STALE_LIBRARY_OBSERVATION')
            state=deepcopy(state);state['library_observation']=data
            return Transition(state,(Event('library.observation.recorded',data),),{'recorded':True})
        self.ledger.apply(Command(ident,'library.observation',self.project_identity,None,data),_RESULT_ORIGIN,
            authorize=lambda *_:self.authenticate() is True,decide=decide)
        return True
    def manager_observations(self):
        from .manager_projection import SourceObservation
        data=self.ledger.snapshot()['state'].get('library_observation')
        if data is None:return (SourceObservation('library','library-service',None,None,None,status='unknown',reason='SOURCE_NOT_OBSERVED'),)
        data=observation(data)
        if data['row']['project_identity']!=self.project_identity:fail()
        return (SourceObservation('library','library-service',data['sequence'],data['observed_at'],
             {self.project_identity:data['row']},freshness='unknown',source_committed_at=None),)
