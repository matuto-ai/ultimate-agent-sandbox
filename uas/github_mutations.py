"""Project-pinned REST mutations behind the validated native gh vocabulary.

The provider returns only confirmed field names and immutable object identities.
No response body or provider error prose crosses into canonical mutation audit.
"""
import json
import re
import time
from urllib.parse import quote

from .github_read import GitHubProject, ProviderFailure, ProviderResponse, MAX_OUTPUT, _LOGIN, _positive, _unique
from .ledger import LedgerError


class MutationFailure(Exception):
    def __init__(self, code):
        self.code=code
        super().__init__(code)


class Rejected(MutationFailure):
    """A literal provider 4xx response, not a guessed absent mutation."""


def result(status, fields=(), objects=(), *, contact='none', failed_field=None, error_code=None):
    return {'status': status, 'confirmed_fields': list(fields), 'objects': list(objects),
            'contact': contact, 'failed_field': failed_field, 'error_code': error_code}


class GitHubMutationProvider:
    host = 'github.com'
    def __init__(self, project, transport):
        if type(project) is not GitHubProject or not callable(transport):
            raise LedgerError('INVALID_PROJECT')
        self.project, self.transport = project, transport

    def execute(self, route, user_id, *, before_write, confirmed, rejected, authorize,
                marker=None, prepared_intent=None):
        if route.repository != self.project.repository or not _positive(user_id):
            raise LedgerError('PROJECT_MISMATCH')
        used, deadline, fields, objects = 0, time.monotonic() + 30, [], []
        contact, step, failed_field, possible = 'none', 0, None, False
        transport_entered = False
        last_headers = {}
        base = 'repos/' + self.project.repository
        api = 'https://api.github.com/' + base
        web = 'https://github.com/' + self.project.repository
        options = dict(route.options)
        from .github_reconciliation import MARKER_PREFIX, marked_body, preimage_digest
        if marker is not None:
            marked_body('', marker)  # Validate even routes without a body.
            if MARKER_PREFIX in options.get('body', ''): raise LedgerError('INVALID_MUTATION_MARKER')
            # The marker is Broker-supplied, never selected by Participant argv.
            if route.kind.endswith(('-create', '-comment')) or route.kind in {'pr-reply', 'pr-review'}:
                options['body'] = marked_body(options.get('body', ''), marker)
        intent_counts = {}
        planned = 1 + sum(len(options.get(k,())) for k in ('add-label','remove-label')) + sum(k in options for k in ('title','body','base','add-assignee','remove-assignee'))
        if planned > 32: return result('DENIED',error_code='INVALID_ARGUMENT')

        def request(method, path, body=None, statuses=(200,)):
            nonlocal used, contact, transport_entered, last_headers
            if authorize() is not True: raise LedgerError('FORBIDDEN')
            if time.monotonic() >= deadline: raise MutationFailure('TIMEOUT')
            if method == 'GET' and contact == 'none': contact = 'read'
            if method != 'GET': transport_entered = True
            response = self.transport(method, path, body)
            if (time.monotonic() >= deadline or type(response) is not ProviderResponse
                    or type(response.status) is not int or type(response.body) is not bytes
                    or type(response.headers) is not dict): raise MutationFailure('INVALID_RESPONSE')
            last_headers = response.headers
            used += len(response.body)
            if used > MAX_OUTPUT: raise MutationFailure('OUTPUT_LIMIT')
            if response.status not in statuses:
                if 400 <= response.status < 500 and response.status != 408:
                    raise Rejected('NOT_FOUND' if response.status == 404 else 'PROVIDER_ERROR')
                raise MutationFailure('PROVIDER_ERROR')
            if response.status == 204:
                if response.body: raise MutationFailure('INVALID_RESPONSE')
                return None
            try: return json.loads(response.body, object_pairs_hook=_unique)
            except (ValueError, UnicodeError, RecursionError): raise MutationFailure('INVALID_RESPONSE') from None

        def collection_preimage(path, query=''):
            # Markers are editable Markdown. Record only the pre-contact set
            # of immutable collection IDs so a removed marker cannot establish
            # false absence. Missing/capped read evidence is not a write retry;
            # the first authorized write may proceed, but later absence stays
            # unknown. Authority/time/output failures still stop this attempt.
            if marker is None or prepared_intent is None: return None
            ids = set()
            try:
                for page in range(1, 11):
                    values = request('GET', path + '?' + (query + '&' if query else '') + f'per_page=100&page={page}')
                    if type(values) is not list or len(values) > 100: raise MutationFailure('INVALID_RESPONSE')
                    for value in values:
                        if type(value) is not dict or not _positive(value.get('id')) or value['id'] in ids:
                            raise MutationFailure('INVALID_RESPONSE')
                        ids.add(value['id'])
                    links = [v for k, v in last_headers.items() if type(k) is str and k.lower() == 'link']
                    if any(type(v) is not str for v in links): raise MutationFailure('INVALID_RESPONSE')
                    if len(values) < 100 and not any(re.search(r'rel\s*=\s*[\"\']?next', v, re.I) for v in links):
                        return sorted(ids)
                return None
            except LedgerError:
                raise
            except Exception as error:
                if getattr(error, 'code', '') in {'TIMEOUT', 'OUTPUT_LIMIT'}: raise
                return None

        def identity(value, kind, number=None):
            if type(value) is not dict or not _positive(value.get('id')):
                raise MutationFailure('INVALID_RESPONSE')
            obj = {'kind': kind, 'id': value['id']}
            if number is not None:
                if value.get('number') != number: raise MutationFailure('INVALID_RESPONSE')
                obj['number'] = number
            return obj

        def target(value, kind, number=None):
            n = value.get('number') if number is None and type(value) is dict else number
            if not _positive(n): raise MutationFailure('INVALID_RESPONSE')
            obj = identity(value, kind, n)
            if (value.get('html_url') != f'{web}/{"pull" if kind == "pull" else "issues"}/{n}'
                    or type(value.get('user')) is not dict or not _positive(value['user'].get('id'))
                    or value.get('state') not in {'open', 'closed'}):
                raise MutationFailure('INVALID_RESPONSE')
            if kind == 'issue':
                if 'pull_request' in value or value.get('repository_url') != api:
                    raise MutationFailure('INVALID_TARGET')
            else:
                if (type(value.get('base')) is not dict or type(value['base'].get('repo')) is not dict
                        or value['base']['repo'].get('full_name') != self.project.repository
                        or type(value.get('head')) is not dict
                        or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value['head'].get('sha', ''))):
                    raise MutationFailure('INVALID_TARGET')
            return obj

        def do(field_names, method, path, body, expected, validate, bound, *, preimage=None):
            nonlocal step, contact, failed_field, possible, transport_entered
            failed_field = field_names[0]
            field = field_names[0] if len(field_names) == 1 else None
            index = intent_counts.get(field, 0) if field in {'add-label', 'remove-label'} else None
            if index is not None: intent_counts[field] = index + 1
            if prepared_intent is not None:
                prepared_intent(step, {'fields': list(field_names), 'item_index': index,
                    'preimage_digest': None if preimage is None else preimage_digest(preimage)})
            before_write(step, bound)
            transport_entered = False
            try:
                if authorize() is not True: raise LedgerError('FORBIDDEN')
                possible, contact = True, 'write-possible'
                value = request(method, path, body, expected)
            except LedgerError:
                if not transport_entered:
                    possible = False
                    rejected(step,'AUTHORITY_REVOKED_BEFORE_CONTACT')
                raise
            except Rejected as error:
                rejected(step, error.code)
                possible = False
                raise
            except MutationFailure as error:
                if not transport_entered and error.code=='TIMEOUT':
                    rejected(step,'TIMEOUT_BEFORE_CONTACT')
                    possible=False
                    contact='write-possible' if fields else 'read'
                    raise Rejected('TIMEOUT_BEFORE_CONTACT') from None
                raise
            obj = validate(value)
            confirmed(step, list(field_names), obj)
            fields.extend(f for f in field_names if f not in fields)
            if obj not in objects: objects.append(obj)
            step += 1; possible = False; failed_field = None
            return value, obj

        try:
            user = request('GET', 'user')
            if (type(user) is not dict or user.get('id') != user_id
                    or type(user.get('login')) is not str or not _LOGIN.fullmatch(user['login'])):
                return result('DENIED', contact=contact, error_code='ACTOR_MISMATCH')
            kind = 'pull' if route.kind.startswith('pr-') else 'issue'
            endpoint = 'pulls' if kind == 'pull' else 'issues'
            if route.kind.endswith('-create'):
                repo = request('GET', base)
                bound = identity(repo, 'repository')
                if repo.get('full_name') != self.project.repository or repo.get('html_url') != web:
                    raise MutationFailure('INVALID_TARGET')
                body = {key: options[key] for key in ('title','body','base','head','draft') if key in options}
                def created(value):
                    obj = target(value, kind)
                    if value['user']['id'] != user_id or any(value.get(k) != body[k] for k in ('title','body') if k in body):
                        raise MutationFailure('INVALID_RESPONSE')
                    if kind == 'pull' and (value['base'].get('ref') != body['base']
                            or value['head'].get('ref') != body['head']
                            or value['head'].get('repo',{}).get('full_name') != self.project.repository
                            or value.get('draft') is not body.get('draft',False)):
                        raise MutationFailure('INVALID_RESPONSE')
                    return obj
                prior_ids = collection_preimage(base + '/' + endpoint, 'state=all')
                current, bound = do(['create', *body], 'POST', base+'/'+endpoint, body, (201,), created, bound,
                                    preimage=prior_ids)
                number = bound['number']
            else:
                number = route.number
                current = request('GET', f'{base}/{endpoint}/{number}')
                bound = target(current, kind, number)
            path = f'{base}/{endpoint}/{number}'
            issue_path = f'{base}/issues/{number}'
            # Participant-owned text/state only. Self-assignment, comments and
            # submitted independent review need not own the target's author.
            owned_fields = {'title','body','base','add-label','remove-label'} & options.keys()
            content_edit = route.kind.endswith('-edit') and owned_fields
            if ((content_edit or route.kind.endswith(('-close','-reopen')) or route.kind.startswith('dependency-'))
                    and current['user']['id'] != user_id):
                return result('DENIED', fields, objects, contact=contact, error_code='OWNERSHIP_DENIED')
            if route.kind.endswith('-edit') or route.kind.endswith(('-close','-reopen')):
                edits = {k: options[k] for k in ('title','body','base') if k in options}
                if route.kind.endswith('-close'): edits['state'] = 'closed'
                if route.kind.endswith('-reopen'): edits['state'] = 'open'
                for field, value in edits.items():
                    payload = {field:value}
                    if kind == 'issue' and field == 'state':
                        payload['state_reason'] = options.get('reason','completed') if value == 'closed' else 'reopened'
                    def edited(response, field=field, value=value):
                        obj = target(response,kind,number)
                        actual = response.get('base',{}).get('ref') if field == 'base' else response.get(field)
                        if obj != bound or actual != value: raise MutationFailure('INVALID_RESPONSE')
                        if kind=='issue' and field=='state' and response.get('state_reason')!=payload['state_reason']:
                            raise MutationFailure('INVALID_RESPONSE')
                        return obj
                    previous = (current.get('base', {}).get('ref') if field == 'base' else
                                [current.get('state'), current.get('state_reason')] if kind == 'issue' and field == 'state'
                                else current.get(field))
                    current,_ = do([field],'PATCH',path,payload,(200,),edited,bound,preimage=previous)
            # GitHub's issue facade and pull object have DIFFERENT immutable
            # IDs. Issue-backed PR operations must bind the facade, not compare
            # its response ID to /pulls/{number}. Same number is not enough.
            issue_bound = bound
            if kind=='pull' and (route.kind=='pr-comment' or any(k in options for k in
                    ('add-assignee','remove-assignee','add-label','remove-label'))):
                facade=request('GET',issue_path)
                issue_bound=identity(facade,'issue',number)
                if (facade.get('repository_url')!=api or facade.get('html_url')!=f'{web}/pull/{number}'
                        or type(facade.get('pull_request')) is not dict
                        or facade['pull_request'].get('url')!=api+'/pulls/'+str(number)):
                    raise MutationFailure('INVALID_TARGET')
            for field in ('add-assignee','remove-assignee'):
                if field not in options: continue
                method = 'POST' if field == 'add-assignee' else 'DELETE'
                def assignment(value, field=field):
                    obj = identity(value,'issue',number)
                    assignees = value.get('assignees')
                    if value.get('repository_url') != api or value.get('html_url') != f'{web}/{"pull" if kind=="pull" else "issues"}/{number}':
                        raise MutationFailure('INVALID_RESPONSE')
                    if (obj != issue_bound or type(assignees) is not list or len(assignees)>100
                            or any(type(v) is not dict or not _positive(v.get('id')) for v in assignees)
                            or (user_id in [v['id'] for v in assignees]) != (field == 'add-assignee')):
                        raise MutationFailure('INVALID_RESPONSE')
                    return obj
                do([field],method,issue_path+'/assignees',{'assignees':[user['login']]},
                   (201,) if method=='POST' else (200,),assignment,issue_bound,
                   preimage=sorted(v['id'] for v in (facade if kind == 'pull' else current).get('assignees', [])))
            label_names = set()
            if any(options.get(field) for field in ('add-label', 'remove-label')):
                for page in range(1, 11):
                    values = request('GET', issue_path + f'/labels?per_page=100&page={page}')
                    if (type(values) is not list or len(values) > 100
                            or any(type(v) is not dict or type(v.get('name')) is not str for v in values)):
                        raise MutationFailure('INVALID_RESPONSE')
                    names = [v['name'] for v in values]
                    if len(names) != len(set(names)) or label_names.intersection(names):
                        raise MutationFailure('INVALID_RESPONSE')
                    label_names.update(names)
                    # request retains the response headers; provider-selected
                    # URLs are never followed, only fixed next page numbers.
                    links = [v for k, v in last_headers.items() if type(k) is str and k.lower() == 'link']
                    if any(type(v) is not str for v in links): raise MutationFailure('INVALID_RESPONSE')
                    if len(values) < 100 and not any(re.search(r'rel\s*=\s*[\"\']?next', v, re.I) for v in links): break
                else: raise MutationFailure('PAGINATION_LIMIT')
            for field in ('add-label','remove-label'):
                for label in options.get(field,()):
                    def labels(value, label=label, field=field):
                        if (type(value) is not list or len(value)>100
                                or any(type(v) is not dict or type(v.get('name')) is not str for v in value)
                                or (label in [v['name'] for v in value]) != (field=='add-label')):
                            raise MutationFailure('INVALID_RESPONSE')
                        return issue_bound
                    do([field], 'POST' if field=='add-label' else 'DELETE',
                       issue_path+'/labels'+('' if field=='add-label' else '/'+quote(label,safe='')),
                       {'labels':[label]} if field=='add-label' else None,(200,),labels,issue_bound,
                       preimage=label in label_names)
                    if field == 'add-label': label_names.add(label)
                    else: label_names.discard(label)
            if route.kind.endswith('-comment') or route.kind == 'pr-reply':
                comment_path = issue_path+'/comments'
                comment_target = issue_bound
                if route.kind == 'pr-reply':
                    parent = request('GET',base+'/pulls/comments/'+str(options['comment-id']))
                    comment_target = identity(parent,'comment')
                    if parent['id'] != options['comment-id'] or parent.get('pull_request_url') != api+'/pulls/'+str(number):
                        raise MutationFailure('INVALID_TARGET')
                    comment_path = path+'/comments/'+str(options['comment-id'])+'/replies'
                def comment(value):
                    obj = identity(value,'comment')
                    link = 'pull_request_url' if route.kind == 'pr-reply' else 'issue_url'
                    expected = api+('/pulls/' if route.kind == 'pr-reply' else '/issues/')+str(number)
                    if (value.get(link)!=expected or value.get('body')!=options['body']
                            or value.get('user',{}).get('id')!=user_id): raise MutationFailure('INVALID_RESPONSE')
                    if route.kind=='pr-reply' and value.get('in_reply_to_id')!=options['comment-id']:
                        raise MutationFailure('INVALID_RESPONSE')
                    return obj
                prior_ids = collection_preimage(path + '/comments' if route.kind == 'pr-reply' else comment_path)
                do(['reply' if route.kind=='pr-reply' else 'comment'],'POST',comment_path,
                   {'body':options['body']},(201,),comment,comment_target,preimage=prior_ids)
            if route.kind.startswith('dependency-'):
                other_number = options['blocked-by']
                if number == other_number: raise MutationFailure('INVALID_TARGET')
                other = request('GET',base+'/issues/'+str(other_number))
                dependency = target(other,'issue',other_number)
                if dependency['id']==bound['id']: raise MutationFailure('INVALID_TARGET')
                dep_path = issue_path+'/dependencies/blocked_by'
                if route.kind=='dependency-add':
                    def added(value):
                        if target(value,'issue',other_number)!=dependency: raise MutationFailure('INVALID_RESPONSE')
                        return bound
                    dependency_target = {**bound,'related_id':dependency['id'],'related_number':other_number}
                    do(['dependency'],'POST',dep_path,{'issue_id':dependency['id']},(201,),added,dependency_target)
                else:
                    do(['remove-dependency'],'DELETE',dep_path+'/'+str(dependency['id']),None,(200,),
                       lambda value: bound if target(value,'issue',other_number)==dependency else (_ for _ in ()).throw(MutationFailure('INVALID_RESPONSE')),{**bound,'related_id':dependency['id'],'related_number':other_number})
            if route.kind=='pr-review':
                if current['head']['sha'] != options['commit']: raise MutationFailure('STALE_PULL')
                def review(value):
                    obj = identity(value,'review')
                    states = {'APPROVE':'APPROVED','REQUEST_CHANGES':'CHANGES_REQUESTED','COMMENT':'COMMENTED'}
                    if (value.get('user',{}).get('id') != user_id or value.get('commit_id')!=options['commit']
                            or value.get('state')!=states[options['event']]
                            or value.get('pull_request_url')!=api+'/pulls/'+str(number)
                            or type(value.get('submitted_at')) is not str or not value['submitted_at']
                            or value.get('body') != options.get('body','')): raise MutationFailure('INVALID_RESPONSE')
                    return obj
                do(['review'],'POST',path+'/reviews',{'event':options['event'],
                    'commit_id':options['commit'],'body':options.get('body','')},(200,),review,bound,
                    preimage=collection_preimage(path + '/reviews'))
            return result('OK',fields,objects,contact=contact)
        except LedgerError:
            raise  # Authority or durable audit failure is never provider prose.
        except Exception as error:
            code = getattr(error,'code','PROVIDER_ERROR')
            if code not in {'PROVIDER_ERROR','INVALID_RESPONSE','INVALID_TARGET','OUTPUT_LIMIT','TIMEOUT','TIMEOUT_BEFORE_CONTACT','NOT_FOUND','STALE_PULL'}:
                code = 'PROVIDER_ERROR'
            return result('UNKNOWN_OUTCOME' if possible else 'PARTIAL_MUTATION' if fields else 'PROVIDER_FAILURE',
                fields, objects, contact=contact, failed_field=failed_field, error_code=code)
