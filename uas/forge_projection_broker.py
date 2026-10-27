"""Trusted Hub label effects in the existing external Deployment Broker.

This is not a Participant route and owns no workflow truth. The Hub's committed
outbox supplies immutable issue identity and desired reserved labels. Private
startup selects the credential Actor; caller content cannot select credentials.
"""
from copy import deepcopy
import hashlib
import json
import re
import sqlite3
import time

from .forge import ForgeBinding
from .forge_audit import ForgeAudit
from .forge_mutations import digest
from .forge_projections import OWNED_LABELS, validate_intent, validate_observation
from .github_mutation_routes import MutationRoute
from .github_mutations import GitHubMutationProvider, MutationFailure, result
from .github_read import GitHubProject, ProviderResponse, MAX_OUTPUT, _positive, _unique
from .github_reconciliation import GitHubReconciliationProvider
from .ledger import LedgerError, Origin, _json, _token


def hub_origin(room_instance):
    return Origin('projection-hub','projection-hub',_token(room_instance),'hub-projection-v1',('forge-project',))


class ExternalProjectionBroker:
    def __init__(self,binding,room_instance,audit,actor_id,user_id,providers):
        if (type(binding) is not ForgeBinding or type(audit) is not ForgeAudit
                or not _positive(user_id) or not callable(providers)):
            raise LedgerError('INVALID_PROJECTION_OWNER')
        self.binding,self.room_instance,self.audit=binding,_token(room_instance),audit
        self.actor_id,self.user_id,self.providers=_token(actor_id),user_id,providers
        self.project=GitHubProject(binding.repository,binding.host)
        self.failed=False

    def _guard(self,origin,authorize):
        if self.failed: raise LedgerError('AUDIT_UNAVAILABLE')
        if origin!=hub_origin(self.room_instance) or authorize() is not True: raise LedgerError('FORBIDDEN')
        return True

    def _key(self,operation):
        # Hub operation IDs already include a Room/run/attempt digest. Do not
        # bind to ephemeral Broker process/incarnation: restart must find them.
        return 'projection-mutation-'+digest([self.binding.room_id,_token(operation)])

    def _provider(self):
        try: provider=self.providers(self.actor_id)
        except Exception: raise LedgerError('CREDENTIAL_UNAVAILABLE') from None
        if type(provider) is not GitHubMutationProvider or provider.project!=self.project:
            raise LedgerError('INVALID_PROJECTION_OWNER')
        return provider

    def _metadata(self,kind,envelope,origin):
        shared={'room_id':self.binding.room_id,'room_instance':self.room_instance,
            'project_id':self.binding.project_id,'actor_id':self.actor_id,
            'participant_id':origin.participant_id,'incarnation_id':origin.incarnation_id,
            'authority_version':origin.authority_version,'provider_host':'github.com',
            'request_digest':digest(envelope),'origin_digest':digest(origin.canonical())}
        if kind=='write':return {**shared,'repository':self.binding.repository,
            'github_user_id':self.user_id,'route':'hub-projection'}
        return {**shared,'requested_repository':self.binding.repository,
            'effective_repository':self.binding.repository,'route':'hub-projection-labels'}

    def _observation(self,intent,key,code=None,*,labels=(),assignees=()):
        return {'status':'UNKNOWN' if code else ('OK' if list(assignees)==[intent['github_user_id']] else 'CONFLICT'),
            'completeness':'unknown' if code else 'complete',
            'repository':intent['repository'],'issue_id':intent['issue_id'],'issue_number':intent['issue_number'],
            'labels':list(labels),'assignee_ids':list(assignees),'audit_reference':key,
            'error_code':code or (None if list(assignees)==[intent['github_user_id']] else 'ASSIGNMENT_CONFLICT')}

    def _observe_provider(self,intent,key,provider,guard):
        used=0;deadline=time.monotonic()+30
        base='repos/'+self.binding.repository
        def get(path):
            nonlocal used
            guard()
            if time.monotonic()>=deadline: raise LedgerError('TIMEOUT')
            response=provider.transport('GET',path,None)
            if (type(response) is not ProviderResponse or response.status!=200
                    or type(response.body) is not bytes or type(response.headers) is not dict):
                raise LedgerError('PROVIDER_ERROR')
            used+=len(response.body)
            if used>MAX_OUTPUT: raise LedgerError('OUTPUT_LIMIT')
            if time.monotonic()>=deadline: raise LedgerError('TIMEOUT')
            try:value=json.loads(response.body,object_pairs_hook=_unique)
            except (ValueError,UnicodeError,RecursionError):raise LedgerError('INVALID_RESPONSE') from None
            return response,value
        _,user=get('user')
        if type(user) is not dict or user.get('id')!=self.user_id: raise LedgerError('ACTOR_MISMATCH')
        number=intent['issue_number'];path=base+'/issues/'+str(number)
        _,issue=get(path)
        if (type(issue) is not dict or issue.get('id')!=intent['issue_id'] or issue.get('number')!=number
                or 'pull_request' in issue or issue.get('repository_url')!='https://api.github.com/'+base
                or issue.get('html_url')!='https://github.com/'+self.binding.repository+'/issues/'+str(number)):
            raise LedgerError('INVALID_TARGET')
        assignees=issue.get('assignees')
        if (type(assignees) is not list or len(assignees)>100
                or any(type(v) is not dict or not _positive(v.get('id')) for v in assignees)):
            raise LedgerError('INVALID_RESPONSE')
        ids=sorted(v['id'] for v in assignees)
        if len(ids)!=len(set(ids)):raise LedgerError('INVALID_RESPONSE')
        labels={};complete=False
        for page in range(1,11):
            response,values=get(path+f'/labels?per_page=100&page={page}')
            if type(values) is not list or len(values)>100:raise LedgerError('INVALID_RESPONSE')
            for value in values:
                if (type(value) is not dict or not _positive(value.get('id')) or type(value.get('name')) is not str
                        or value['id'] in labels or value['name'] in labels.values()):raise LedgerError('INVALID_RESPONSE')
                labels[value['id']]=value['name']
            links=[v for k,v in response.headers.items() if type(k) is str and k.lower()=='link']
            if any(type(v) is not str for v in links):raise LedgerError('INVALID_RESPONSE')
            if len(values)<100 and not any(re.search(r'rel\s*=\s*["\']?next',v,re.I) for v in links):
                complete=True;break
        if not complete:raise LedgerError('PAGINATION_LIMIT')
        return self._observation(intent,key,labels=sorted(set(labels.values())&OWNED_LABELS),assignees=ids)

    def _store_plan(self,key,intent,observed):
        plan={'intent':deepcopy(intent),'observed':deepcopy(observed)}
        db=self.audit._mutation_write_connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT INTO projection_plans VALUES(?,?)',(key,_json(plan)))
            self.audit._commit()
        except sqlite3.Error as error:
            self.audit._mutation_failed=True;self.failed=True;db.rollback()
            raise LedgerError('AUDIT_UNAVAILABLE') from error
        except BaseException:db.rollback();raise

    def _plan(self,key,operation):
        try:row=self.audit._connection().execute('SELECT plan FROM projection_plans WHERE id=?',(key,)).fetchone()
        except sqlite3.Error:raise LedgerError('AUDIT_UNAVAILABLE') from None
        if row is None:return None
        try:
            plan=json.loads(row['plan'])
            if type(plan) is not dict or set(plan)!={'intent','observed'}:raise ValueError()
            validate_intent(plan['intent']);validate_observation(plan['observed'],plan['intent'])
            if row['plan']!=_json(plan):raise ValueError()
            record=self.audit.get_mutation(key)
            envelope={'id':operation,'kind':'forge-projection','action':'repair',**plan}
            if record['metadata']['request_digest']!=digest(envelope):raise ValueError()
            return plan
        except (ValueError,TypeError,LedgerError):raise LedgerError('AUDIT_UNAVAILABLE') from None

    def _route(self,plan):
        desired=set(plan['intent']['labels']);observed=set(plan['observed']['labels'])
        return MutationRoute('hub-projection',self.binding.repository,plan['intent']['issue_number'],
            {'add-label':tuple(sorted(desired-observed)),'remove-label':tuple(sorted(observed-desired))})

    def _reconcile_prior(self,intent,operation,origin,provider,guard):
        key=self._key(intent['reconcile_operation']);record=self.audit.get_mutation(key)
        # Outbox committed send before the Broker received it: no contact.
        if record is None:return
        meta=record['metadata']
        if (meta['route']!='hub-projection' or meta['room_id']!=self.binding.room_id
                or meta['project_id']!=self.binding.project_id or meta['repository']!=self.binding.repository):
            raise LedgerError('PROJECT_MISMATCH')
        if record['result'] is None:raise LedgerError('FORGE_OPERATION_PENDING')
        if record['result']['status'] not in {'UNKNOWN_OUTCOME','PARTIAL_MUTATION'}:return
        plan=self._plan(key,intent['reconcile_operation'])
        if plan is None:raise LedgerError('AUDIT_UNAVAILABLE')
        if any(plan['intent'][k]!=intent[k] for k in ('run_id','issue_id','issue_number','github_user_id')):
            raise LedgerError('PROJECT_MISMATCH')
        reconciliation='projection-reconcile-'+digest([self.binding.room_id,operation,key])
        begun=self.audit.begin_mutation_reconciliation(key,reconciliation,{
            'room_instance':self.room_instance,'origin_digest':digest(origin.canonical()),'request_digest':digest(intent)})
        if begun['started']:
            observed=GitHubReconciliationProvider(self.project,provider.transport).reconcile(
                self._route(plan),self.user_id,record,authorize=guard)
            record=self.audit.observe_mutation(key,reconciliation,observed)
        else:record=begun['record']
        observation=next(v['observation'] for v in record['reconciliations'] if v['id']==reconciliation)
        if observation is None or observation['status']=='UNKNOWN':raise LedgerError('FORGE_RECONCILIATION_REQUIRED')

    def execute(self,envelope,*,origin,authorize):
        guard=lambda:self._guard(origin,authorize)
        guard()
        if (type(envelope) is not dict or envelope.get('kind')!='forge-projection'
                or envelope.get('action') not in {'observe','repair'}
                or set(envelope)!=({'id','kind','action','intent'} if envelope['action']=='observe'
                    else {'id','kind','action','intent','observed'})):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        operation=_token(envelope['id']);intent=validate_intent(envelope['intent'])
        if any(intent[k]!=getattr(self.binding,k) for k in ('room_id','project_id','repository')):
            raise LedgerError('PROJECT_MISMATCH')
        try:
            if envelope['action']=='observe':return self._observe(envelope,intent,origin,guard)
            return self._repair(envelope,intent,origin,guard)
        except LedgerError as error:
            if error.code=='AUDIT_UNAVAILABLE':self.failed=True
            raise

    def _observe(self,envelope,intent,origin,guard):
        key='projection-observation-'+digest([self.binding.room_id,envelope['id']])
        begun=self.audit.begin_read(key,self._metadata('read',envelope,origin))
        if not begun['started']:
            # Metadata-only audit never fabricates a lost observation payload.
            return self._observation(intent,key,'INTERRUPTED_OBSERVATION')
        contacted=False;used=0;deadline=time.monotonic()+30
        try:
            selected=self._provider()
            def transport(method,path,body):
                nonlocal contacted,used
                guard()
                if time.monotonic()>=deadline:raise LedgerError('TIMEOUT')
                contacted=True
                response=selected.transport(method,path,body)
                if type(response) is not ProviderResponse or type(response.body) is not bytes:
                    raise LedgerError('INVALID_RESPONSE')
                used+=len(response.body)
                if used>MAX_OUTPUT:raise LedgerError('OUTPUT_LIMIT')
                if time.monotonic()>=deadline:raise LedgerError('TIMEOUT')
                return response
            provider=GitHubMutationProvider(self.project,transport)
            if intent['reconcile_operation'] is not None:
                self._reconcile_prior(intent,envelope['id'],origin,provider,guard)
            observed=self._observe_provider(intent,key,provider,guard)
        except LedgerError as error:
            if error.code=='AUDIT_UNAVAILABLE':raise
            observed=self._observation(intent,key,error.code if re.fullmatch('[A-Z][A-Z0-9_]{0,63}',error.code) else 'PROVIDER_ERROR')
        except Exception:observed=self._observation(intent,key,'PROVIDER_ERROR')
        complete=observed['completeness']=='complete'
        self.audit.finish_read(key,{'status':'OK' if complete else 'UNKNOWN','completeness':'complete' if complete else 'unknown',
            'contact':'read' if contacted else 'none','output_bytes':len(_json(observed).encode()) if complete else 0,
            'dropped_bytes':0 if complete else None,'observation_digest':digest(observed) if complete else None})
        guard();return observed

    def _repair(self,envelope,intent,origin,guard):
        observed=validate_observation(envelope['observed'],intent)
        if observed['status']!='OK' or observed['assignee_ids']!=[intent['github_user_id']]:
            raise LedgerError('ASSIGNMENT_CONFLICT')
        key=self._key(envelope['id'])
        # Stable operation across restart; fresh authority before exact disclosure.
        metadata=self._metadata('write',envelope,origin)
        prior=self.audit.get_mutation(key)
        if prior is not None:
            if (prior['metadata']['request_digest']!=metadata['request_digest']
                    or prior['metadata']['actor_id']!=self.actor_id):raise LedgerError('OPERATION_CONFLICT')
            return {'audit_reference':key,'mutation':prior['result'] or
                result('UNKNOWN_OUTCOME',contact='write-possible',error_code='INTERRUPTED_MUTATION')}
        self.audit.begin_mutation(key,metadata)
        self._store_plan(key,intent,observed)
        try:provider=self._provider()
        except LedgerError:
            record=self.audit.finish_mutation(key,result('PROVIDER_FAILURE',error_code='CREDENTIAL_UNAVAILABLE'))
            guard();return {'audit_reference':key,'mutation':record['result']}
        route=self._route({'intent':intent,'observed':observed})
        expected={'kind':'issue','id':intent['issue_id'],'number':intent['issue_number']}
        intents={}
        def transport(method,path,body):
            value=provider.transport(method,path,body)
            if method=='GET' and path=='repos/'+self.binding.repository+'/issues/'+str(intent['issue_number']):
                try:issue=json.loads(value.body)
                except (ValueError,AttributeError):raise MutationFailure('INVALID_RESPONSE') from None
                if issue.get('id')!=intent['issue_id']:raise MutationFailure('INVALID_TARGET')
                if (type(issue.get('assignees')) is not list
                        or sorted(a.get('id',0) for a in issue['assignees'])!=[intent['github_user_id']]):
                    raise MutationFailure('INVALID_TARGET')
            return value
        def before(step,target):
            guard()
            if target!=expected:raise LedgerError('PROJECT_MISMATCH')
            self.audit.mutation_prepared(key,step,target,intent=intents.pop(step))
        try:
            outcome=GitHubMutationProvider(self.project,transport).execute(route,self.user_id,
                before_write=before,confirmed=lambda step,fields,obj:self.audit.mutation_confirmed(key,step,fields,obj),
                rejected=lambda step,code:self.audit.mutation_rejected(key,step,code),authorize=guard,
                prepared_intent=lambda step,value:intents.__setitem__(step,value))
            if outcome['status']=='OK' and not outcome['confirmed_fields']:outcome=result('NOT_EXECUTED',contact='read')
            record=self.audit.finish_mutation(key,outcome)
        except LedgerError as error:
            if error.code!='AUDIT_UNAVAILABLE':
                record=self.audit.get_mutation(key)
                fields,objects=[],[]
                for row in record['steps']:
                    if row['fields'] is not None:
                        fields.extend(f for f in row['fields'] if f not in fields)
                        if row['object'] not in objects:objects.append(row['object'])
                outcome=result('UNKNOWN_OUTCOME',fields,objects,contact='write-possible',error_code='FORBIDDEN') if record['steps'] else result('NOT_EXECUTED',error_code='FORBIDDEN')
                if record['steps'] and all(row['fields'] is not None for row in record['steps']):
                    # The next guard failed before preparing/contacting another
                    # step. Earlier confirmed effects are known partial, not an
                    # invented uncertainty about a step that never started.
                    outcome['status']='PARTIAL_MUTATION'
                if record['steps'] and record['steps'][-1]['error_code'] is not None:
                    outcome['status']='PARTIAL_MUTATION' if fields else 'PROVIDER_FAILURE'
                    outcome['error_code']=record['steps'][-1]['error_code']
                    if all(r['error_code'] in {'AUTHORITY_REVOKED_BEFORE_CONTACT','TIMEOUT_BEFORE_CONTACT'} for r in record['steps']):outcome['contact']='read'
                self.audit.finish_mutation(key,outcome)
            # No stale success disclosure or rollback of remote effects.
            raise
        guard();return {'audit_reference':key,'mutation':record['result']}
