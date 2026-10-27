"""Authenticated mutation owner using the same Deployment ForgeAudit as reads."""
import hashlib

from .forge_wire import request_json
from .forge import ForgeBinding
from .forge_audit import ForgeAudit
from .github_read import GitHubProject, _positive
from .github_mutations import GitHubMutationProvider, result
from .github_mutation_routes import parse_mutation_route, MutationRouteError, _work_labels
from .ledger import LedgerError, Origin, _json, _token


def digest(value):
    return hashlib.sha256(request_json(value).encode()).hexdigest()


class ExternalMutationBroker:
    def __init__(self, binding, room_instance, audit, actor_user_ids, providers, *, work_labels=()):
        if (type(binding) is not ForgeBinding or type(audit) is not ForgeAudit
                or type(actor_user_ids) is not dict or not callable(providers)
                or any(type(k) is not str or not _positive(v) for k,v in actor_user_ids.items())):
            raise LedgerError('INVALID_MUTATION_BROKER')
        self.binding, self.room_instance, self.audit = binding, _token(room_instance), audit
        self.project = GitHubProject(binding.repository,binding.host)
        if type(work_labels) not in (tuple,list,frozenset): raise LedgerError('INVALID_WORK_LABEL_POLICY')
        self.actors, self.providers, self.work_labels = dict(actor_user_ids), providers, tuple(work_labels)
        _work_labels(self.work_labels)
        self.failed = False

    def _authorize(self, origin, authorize):
        if self.failed: raise LedgerError('AUDIT_UNAVAILABLE')
        if (type(origin) is not Origin or 'forge-write' not in origin.capabilities
                or origin.actor_id not in self.actors or authorize() is not True):
            raise LedgerError('FORBIDDEN')
        origin.canonical()

    @staticmethod
    def _executed_steps(steps):
        counts, result = {}, []
        for row in steps:
            if row['fields'] is None: continue
            field = row['fields'][0] if len(row['fields'])==1 else None
            index = counts.get(field,0) if field in {'add-label','remove-label'} else None
            if index is not None: counts[field]=index+1
            result.append({'step':row['step'],'fields':row['fields'],'object':row['object'],'item_index':index})
        return result

    def _receipt(self, envelope, key, record, route=None, diagnostic=None):
        outcome = record['result']
        if outcome is None:
            confirmed = [step for step in record['steps'] if step['fields'] is not None]
            fields, objects = [], []
            for step in confirmed:
                fields.extend(f for f in step['fields'] if f not in fields)
                if step['object'] not in objects: objects.append(step['object'])
            outcome = result('UNKNOWN_OUTCOME',fields,objects,contact='write-possible')
        reply = {'operation_id':envelope['id'],'audit_reference':key,'repository':self.binding.repository,
                 'project_id':self.binding.project_id,'mutation':outcome,'exit_code':0 if outcome['status']=='OK' else 1,
                 'warnings':list(route.warnings) if route else [],
                 'executed_steps':self._executed_steps(record['steps'])}
        if diagnostic: reply['diagnostic'] = diagnostic
        elif outcome['status']=='DENIED':
            reply['diagnostic']={'code':outcome['error_code'],'token_index':None,'token':'<target>',
                'correction':'Use an allowed target owned by the authenticated Actor.'}
        return reply

    def execute(self, envelope, *, origin, authorize):
        self._authorize(origin,authorize)
        if (type(envelope) is not dict or set(envelope) not in ({'id','kind','argv'},{'id','kind','argv','body'})
                or envelope['kind']!='forge-write'):
            raise LedgerError('INVALID_FORGE_ENVELOPE')
        key = 'mutation-' + digest([self.binding.room_id,self.room_instance,_token(envelope['id'])])
        denied, route = None, None
        try:
            route = parse_mutation_route(envelope['argv'],self.project,body=envelope.get('body'),work_labels=self.work_labels)
        except MutationRouteError as error:
            denied = error.diagnostic()
        metadata = {'room_id':self.binding.room_id,'room_instance':self.room_instance,'project_id':self.binding.project_id,
            'repository':self.binding.repository,'provider_host':'github.com','actor_id':origin.actor_id,
            'participant_id':origin.participant_id,'incarnation_id':origin.incarnation_id,'authority_version':origin.authority_version,
            'github_user_id':self.actors[origin.actor_id],'route':route.kind if route else 'denied',
            'request_digest':digest(envelope),'origin_digest':digest(origin.canonical())}
        possible_contact = False
        durable_fields, durable_objects, durable_steps = [], [], []
        try:
            begun = self.audit.begin_mutation(key,metadata)
            if not begun['started']:
                return self._receipt(envelope,key,begun['record'],route,denied)
            if denied:
                outcome = result('DENIED',error_code='UNSUPPORTED_ROUTE')
            else:
                def guard():
                    self._authorize(origin,authorize)
                    return True
                def before(step,target):
                    nonlocal possible_contact
                    guard();self.audit.mutation_prepared(key,step,target)
                    possible_contact = True
                def confirmed(step,fields,obj):
                    self.audit.mutation_confirmed(key,step,fields,obj)
                    durable_fields.extend(f for f in fields if f not in durable_fields)
                    if obj not in durable_objects: durable_objects.append(obj)
                    durable_steps.append({'step':step,'fields':fields,'object':obj})
                def rejected(step,code):
                    nonlocal possible_contact
                    if code in {'AUTHORITY_REVOKED_BEFORE_CONTACT','TIMEOUT_BEFORE_CONTACT'}: possible_contact=bool(durable_fields)
                    self.audit.mutation_rejected(key,step,code)
                guard()
                try: provider = self.providers(origin.actor_id)
                except Exception: provider = None
                if type(provider) is not GitHubMutationProvider or provider.project != self.project:
                    outcome = result('PROVIDER_FAILURE',error_code='INVALID_RESPONSE')
                else:
                    try:
                        outcome = provider.execute(route,self.actors[origin.actor_id],before_write=before,
                            confirmed=confirmed,rejected=rejected,authorize=guard)
                    except LedgerError as error:
                        if error.code=='AUDIT_UNAVAILABLE': raise
                        record = self.audit.get_mutation(key)
                        if record['steps']:
                            outcome = self._receipt(envelope,key,record)['mutation']
                            if record['steps'][-1]['error_code'] is not None:
                                outcome['status']='PARTIAL_MUTATION' if outcome['confirmed_fields'] else 'PROVIDER_FAILURE'
                                outcome['error_code']=record['steps'][-1]['error_code']
                                if not any(step['error_code'] not in {'AUTHORITY_REVOKED_BEFORE_CONTACT','TIMEOUT_BEFORE_CONTACT'} for step in record['steps']):
                                    outcome['contact']='read'
                            else:
                                if all(step['fields'] is not None for step in record['steps']):
                                    outcome['status']='PARTIAL_MUTATION'
                                outcome['error_code']='FORBIDDEN'
                        else: outcome = result('NOT_EXECUTED',error_code='FORBIDDEN')
            record = self.audit.finish_mutation(key,outcome)
            self._authorize(origin,authorize)
            return self._receipt(envelope,key,record,route,denied)
        except LedgerError as error:
            if error.code=='AUDIT_UNAVAILABLE':
                self.failed=True
                if possible_contact:
                    return {'operation_id':envelope['id'],'audit_reference':key,
                        'repository':self.binding.repository,'project_id':self.binding.project_id,
                        'mutation':result('UNKNOWN_OUTCOME',durable_fields,durable_objects,
                            contact='write-possible',error_code='AUDIT_UNAVAILABLE'),
                        'exit_code':1,'warnings':[],'executed_steps':self._executed_steps(durable_steps)}
            raise

    def recover(self, fenced):
        for record in self.audit.pending_mutations(self.binding.room_id):
            # The external owner lock covers one Room incarnation only. A new
            # incarnation cannot claim it fenced a still-live prior owner.
            if record['metadata']['room_instance'] != self.room_instance or not fenced(record['metadata']): continue
            outcome = self._receipt({'id':record['operation_id']},record['operation_id'],record)['mutation']
            if not record['steps']: outcome=result('NOT_EXECUTED')
            elif record['steps'][-1]['error_code'] is not None:
                outcome['status']='PARTIAL_MUTATION' if outcome['confirmed_fields'] else 'PROVIDER_FAILURE'
                outcome['error_code']=record['steps'][-1]['error_code']
                if not any(step['error_code'] not in {'AUTHORITY_REVOKED_BEFORE_CONTACT','TIMEOUT_BEFORE_CONTACT'} for step in record['steps']):
                    outcome['contact']='read'
            self.audit.finish_mutation(record['operation_id'],outcome)
