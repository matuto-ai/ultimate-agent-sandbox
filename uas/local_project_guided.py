"""Pure new-user Project intent; no image guess, credential or authority grant.

The currently supported native profile is an explicitly selected Pi implementer
and Claude independent reviewer pair. Ref names identify slots, not secrets.
"""
from copy import deepcopy
from io import StringIO
import json
from urllib.parse import urlsplit

from .config import (load, _id, _integer, _text, REPOSITORY, ConfigError,
                     CONTROLS, NETWORK_CONTROLS, _url)
from .git_policy import GitIdentity
from .runtime_provider import ProviderAuthReference


def project_intent(project_id, repository, *, pi_actor, claude_actor,
                   pi_github_id, reviewer_github_id, pi_auth_ref, claude_auth_ref,
                   pi_git_name, pi_git_email, claude_git_name, claude_git_email,
                   pi_model=None, claude_model=None, disk_bytes=10737418240,
                   manager_url=None, manager_client_ref=None, manager_trust_ref=None):
    _id(project_id, 'project_id')
    if isinstance(repository, str) and repository.startswith('https://'):
        url = urlsplit(repository)
        if url.netloc != 'github.com' or url.query or url.fragment:
            raise ConfigError('repository', 'expected GitHub repository URL')
        repository = url.path.strip('/')
        if repository.endswith('.git'): repository = repository[:-4]
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository) or any(p in ('.','..') for p in repository.split('/')):
        raise ConfigError('repository', 'expected GitHub owner/repository')
    _integer(pi_github_id, 'pi_github_id', maximum=2**53-1)
    if pi_github_id == reviewer_github_id:
        raise ConfigError('actors', 'independent review requires distinct GitHub identities')
    _integer(reviewer_github_id, 'reviewer_github_id', maximum=2**53-1)
    _integer(disk_bytes, 'disk_bytes', minimum=64*1024*1024)
    actors=[];providers=[];credentials=[]
    for runtime, actor, auth, name, email, model in (
            ('pi',pi_actor,pi_auth_ref,pi_git_name,pi_git_email,pi_model),
            ('claude',claude_actor,claude_auth_ref,claude_git_name,claude_git_email,claude_model)):
        _id(actor, runtime+'_actor')
        for suffix in ('git','forge'):_id(actor+'-'+suffix,runtime+'_actor')
        identity=GitIdentity(actor,name,email)
        row={'id':actor,'git_identity':{'name':identity.name,'email':identity.email},
             'git_credential_ref':actor+'-git','forge_credential_ref':actor+'-forge'}
        row['github_user_id']=pi_github_id if runtime=='pi' else reviewer_github_id
        actors.append(row)
        method='pi-oauth-json' if runtime=='pi' else 'claude-oauth-token'
        ProviderAuthReference(runtime,runtime+'-provider',auth,method)
        provider={'id':runtime+'-provider','runtime':runtime,'auth':{'credential_ref':auth,'method':method}}
        if model is not None:provider['model']=_text(model,runtime+'_model',256)
        providers.append(provider)
        credentials.extend([{'id':actor+'-git','kind':'git'},{'id':actor+'-forge','kind':'forge'},
                            {'id':auth,'kind':'runtime-provider'}])
    manager=None
    if any(v is not None for v in (manager_url,manager_client_ref,manager_trust_ref)):
        _url(manager_url,'manager_url')
        _id(manager_client_ref,'manager_client_ref');_id(manager_trust_ref,'manager_trust_ref')
        manager={'url':manager_url,'client_credential_ref':manager_client_ref,'server_trust_ref':manager_trust_ref}
        credentials.extend([{'id':manager_client_ref,'kind':'manager-client'}, {'id':manager_trust_ref,'kind':'manager-trust'}])
    if pi_actor==claude_actor or len({c['id'] for c in credentials})!=len(credentials):
        raise ConfigError('actors','expected distinct actors and credential references')
    return {'version':1,'profile':'native-review-pair','project_id':project_id,
            'repository':repository,'actors':actors,'providers':providers,
            'credentials':credentials,'disk_bytes':disk_bytes,'manager':manager}


def _validate_intent(value):
    if type(value) is not dict or set(value)!={'version','profile','project_id','repository','actors','providers','credentials','disk_bytes','manager'} or type(value['version']) is not int or value['version']!=1 or value['profile']!='native-review-pair':
        raise ConfigError('intent','unsupported Project intent')
    try:
        a,b=value['actors'];p,q=value['providers']
        expected=project_intent(value['project_id'],value['repository'],pi_actor=a['id'],claude_actor=b['id'],
            pi_github_id=a['github_user_id'],reviewer_github_id=b['github_user_id'],pi_auth_ref=p['auth']['credential_ref'],claude_auth_ref=q['auth']['credential_ref'],
            pi_git_name=a['git_identity']['name'],pi_git_email=a['git_identity']['email'],
            claude_git_name=b['git_identity']['name'],claude_git_email=b['git_identity']['email'],
            pi_model=p.get('model'),claude_model=q.get('model'),disk_bytes=value['disk_bytes'],
            manager_url=value['manager']['url'] if value['manager'] else None,
            manager_client_ref=value['manager']['client_credential_ref'] if value['manager'] else None,
            manager_trust_ref=value['manager']['server_trust_ref'] if value['manager'] else None)
    except (KeyError,TypeError,ValueError) as error:
        raise ConfigError('intent','invalid explicit Project selections') from error
    if expected!=value:raise ConfigError('intent','Project selections changed')


def materialize(intent, image_reference, storage_root):
    _validate_intent(intent)
    value=deepcopy(intent);name=value['project_id'];root=storage_root.rstrip('/')
    policy={'id':'review','version':1,'gates':[{'id':'independent-review','kind':'attestation',
        'config':{'statement_id':'review-approved','scope':'head','eligible_actors':[value['actors'][1]['id']],
            'relationship':'independent-reviewer','required_capability':'review','allow_self':False,'continuing_authority':True}}],
        'protected_operations':{'submit-for-review':['implementation-ready'],'complete':['independent-review']},
        'review_return_cap':5,'queue_timeout_seconds':300,'response_timeout_seconds':1800}
    policy['gates'].append({'id':'implementation-ready','kind':'attestation','config':{
        'statement_id':'implementation-ready','scope':'head','eligible_actors':[value['actors'][0]['id']],
        'relationship':'implementer','required_capability':'implement','allow_self':True,'continuing_authority':True}})
    profiles=[{'id':'implementer','instructions':'Implement only the authenticated assigned Run; declarations do not grant authority.',
               'tools':['read','edit'],'capabilities':['implement','forge-read','forge-write','git-read','git-push']},
              {'id':'reviewer','instructions':'Review the exact candidate independently; do not approve your own changes.',
               'tools':['read'],'capabilities':['review','forge-read','forge-write','git-read']}]
    room={'version':1,'id':name,'project':{'id':name,'repository':value['repository'],
          'roots':{key:root+'/'+name+'/'+key for key in ('repo','workspace','reference','checkouts')}},
          'state_root':root+'/state/'+name,'image':'workstation','network':{'id':name,**dict.fromkeys(NETWORK_CONTROLS,True)},
          'boundary':dict.fromkeys(CONTROLS,True),'resources':{'cpu':2,'memory_bytes':2147483648,'disk_bytes':value['disk_bytes'],'pids':256,'log_bytes':10485760},
          'profiles':profiles,'policies':[policy],'default_policy':'review','seats':[
              {'id':runtime,'participant':runtime,'runtime':runtime,'arguments':[],'actor':actor['id'],
               'profile':role,'provider':runtime+'-provider'}
              for runtime,actor,role in zip(('pi','claude'),value['actors'],('implementer','reviewer'))]}
    result={'version':1,'deployment':{'id':name,'state_root':root+'/state','mode':'local' if value['manager'] is None else 'remote','manager':value['manager'],
            'credentials':value['credentials'],'actors':value['actors'],'providers':value['providers'],
            'images':[{'id':'workstation','reference':image_reference}],
            'audit':{'retention_days':30,'max_bytes':10485760}},'rooms':[room]}
    load(StringIO(json.dumps(result))) # canonical validation without serializing normalized-only fields
    return result
