"""Bounded, read-only reconciliation of recorded GitHub mutation intent.

An observed value is not proof that our request caused it. The authenticated
Broker supplies the original digest-checked route, audit checkpoints and marker;
this adapter never executes or retries a mutation. Provider bodies stay here.
"""
import hashlib
import json
import re
import time

from .github_read import GitHubProject, ProviderResponse, MAX_OUTPUT, _positive, _unique
from .ledger import LedgerError

MARKER_PREFIX = '<!-- uas:mutation:'
_MARKER = re.compile(r'<!-- uas:mutation:[0-9a-f]{64} -->\Z')
MARKER_OVERHEAD = len('\n\n<!-- uas:mutation:' + '0' * 64 + ' -->')
_ERRORS = frozenset({'PROVIDER_ERROR', 'INVALID_RESPONSE', 'INVALID_TARGET', 'OUTPUT_LIMIT',
    'TIMEOUT', 'PAGINATION_LIMIT', 'ACTOR_MISMATCH', 'IDENTITY_CONFLICT',
    'LEGACY_MARKER_UNAVAILABLE', 'FORBIDDEN', 'NOT_FOUND', 'CREDENTIAL_UNAVAILABLE'})


def marked_body(body, marker):
    """Append exactly one server marker without consuming the caller body quota."""
    if (type(body) is not str or type(marker) is not str or not _MARKER.fullmatch(marker)
            or MARKER_PREFIX in body):
        raise LedgerError('INVALID_MUTATION_MARKER')
    return body + '\n\n' + marker


def preimage_digest(value):
    # Intentionally metadata-only: body/title values never enter the audit.
    canonical = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def planned_fields(route):
    """Normalized field order is identical to the mutation provider's steps."""
    options = route.options
    fields = []
    if route.kind.endswith('-create'):
        fields = [{'field': 'create', 'item_index': None}]
        fields.extend({'field': f, 'item_index': None} for f in ('title', 'body', 'base', 'head', 'draft') if f in options)
    elif route.kind.endswith('-edit'):
        fields.extend({'field': f, 'item_index': None} for f in ('title', 'body', 'base') if f in options)
    elif route.kind.endswith(('-close', '-reopen')):
        fields.append({'field': 'state', 'item_index': None})
    for field in ('add-assignee', 'remove-assignee'):
        if field in options: fields.append({'field': field, 'item_index': None})
    for field in ('add-label', 'remove-label'):
        fields.extend({'field': field, 'item_index': index} for index, _ in enumerate(options.get(field, ())))
    if route.kind.endswith('-comment'): fields.append({'field': 'comment', 'item_index': None})
    elif route.kind == 'pr-reply': fields.append({'field': 'reply', 'item_index': None})
    elif route.kind == 'pr-review': fields.append({'field': 'review', 'item_index': None})
    elif route.kind.startswith('dependency-'):
        fields.append({'field': 'dependency' if route.kind == 'dependency-add' else 'remove-dependency', 'item_index': None})
    return fields


def observation(fields, objects=(), *, error_code=None):
    statuses = {field['status'] for field in fields}
    status = ('UNKNOWN' if 'UNKNOWN' in statuses or not statuses else
              next(iter(statuses)) if len(statuses) == 1 else 'PARTIAL')
    return {'status': status, 'fields': fields, 'objects': list(objects),
            'contact': 'read', 'attribution': 'observed-only', 'error_code': error_code}


class ReconciliationFailure(Exception):
    def __init__(self, code):
        self.code = code if code in _ERRORS else 'PROVIDER_ERROR'
        super().__init__(self.code)


class GitHubReconciliationProvider:
    host = 'github.com'

    def __init__(self, project, transport, *, max_pages=10, max_bytes=MAX_OUTPUT):
        if type(project) is not GitHubProject or not callable(transport):
            raise LedgerError('INVALID_PROJECT')
        if (type(max_pages) is not int or not 1 <= max_pages <= 10
                or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_OUTPUT):
            raise LedgerError('INVALID_PROVIDER_LIMIT')
        self.project, self.transport = project, transport
        self.max_pages, self.max_bytes = max_pages, max_bytes

    def reconcile(self, route, user_id, record, *, marker=None, authorize):
        if route.repository != self.project.repository or not _positive(user_id):
            raise LedgerError('PROJECT_MISMATCH')
        if marker is not None and (type(marker) is not str or not _MARKER.fullmatch(marker)):
            raise LedgerError('INVALID_MUTATION_MARKER')
        fields = [{**field, 'status': 'UNKNOWN'} for field in planned_fields(route)]
        objects, steps = [], record['steps']
        used, deadline = 0, time.monotonic() + 30
        base = 'repos/' + self.project.repository
        api, web = 'https://api.github.com/' + base, 'https://github.com/' + self.project.repository
        options = dict(route.options)
        body = options.get('body', '')
        expected_body = marked_body(body, marker) if marker is not None else body
        kind = 'pull' if route.kind.startswith('pr-') else 'issue'
        endpoint = 'pulls' if kind == 'pull' else 'issues'

        def get(path):
            nonlocal used
            if authorize() is not True: raise LedgerError('FORBIDDEN')
            if time.monotonic() >= deadline: raise ReconciliationFailure('TIMEOUT')
            response = self.transport('GET', path, None)
            if time.monotonic() >= deadline: raise ReconciliationFailure('TIMEOUT')
            if (type(response) is not ProviderResponse or type(response.status) is not int
                    or type(response.body) is not bytes or type(response.headers) is not dict):
                raise ReconciliationFailure('INVALID_RESPONSE')
            used += len(response.body)
            if used > self.max_bytes: raise ReconciliationFailure('OUTPUT_LIMIT')
            if response.status != 200:
                # A hidden/inaccessible object, 403, 404 or rate-limit is never
                # absence evidence. Even a collection 404 stays unknown.
                raise ReconciliationFailure('NOT_FOUND' if response.status == 404 else 'PROVIDER_ERROR')
            try: value = json.loads(response.body, object_pairs_hook=_unique)
            except (ValueError, UnicodeError, RecursionError): raise ReconciliationFailure('INVALID_RESPONSE') from None
            return response, value

        def pages(path, *, query=''):
            items, ids = [], set()
            for page in range(1, self.max_pages + 1):
                response, values = get(path + '?' + (query + '&' if query else '') + f'per_page=100&page={page}')
                if type(values) is not list or len(values) > 100: raise ReconciliationFailure('INVALID_RESPONSE')
                for value in values:
                    if type(value) is not dict or not _positive(value.get('id')) or value['id'] in ids:
                        raise ReconciliationFailure('INVALID_RESPONSE')
                    ids.add(value['id']); items.append(value)
                links = [v for k, v in response.headers.items() if type(k) is str and k.lower() == 'link']
                if any(type(v) is not str for v in links): raise ReconciliationFailure('INVALID_RESPONSE')
                if len(values) < 100 and not any(re.search(r'rel\s*=\s*["\']?next', value, re.I) for value in links):
                    return items
            raise ReconciliationFailure('PAGINATION_LIMIT')

        def identity(value, item_kind, number=None):
            if type(value) is not dict or not _positive(value.get('id')):
                raise ReconciliationFailure('INVALID_RESPONSE')
            obj = {'kind': item_kind, 'id': value['id']}
            if number is not None:
                if value.get('number') != number: raise ReconciliationFailure('INVALID_RESPONSE')
                obj['number'] = number
            return obj

        def target(value, item_kind, number=None, *, facade=False):
            number = value.get('number') if number is None and type(value) is dict else number
            if not _positive(number): raise ReconciliationFailure('INVALID_RESPONSE')
            obj = identity(value, item_kind, number)
            if (value.get('html_url') != f'{web}/{"pull" if item_kind == "pull" or facade else "issues"}/{number}'
                    or type(value.get('user')) is not dict or not _positive(value['user'].get('id'))
                    or value.get('state') not in {'open', 'closed'}):
                raise ReconciliationFailure('INVALID_RESPONSE')
            if item_kind == 'issue':
                if value.get('repository_url') != api: raise ReconciliationFailure('INVALID_TARGET')
                if facade:
                    if value.get('pull_request', {}).get('url') != api + '/pulls/' + str(number):
                        raise ReconciliationFailure('INVALID_TARGET')
                elif 'pull_request' in value: raise ReconciliationFailure('INVALID_TARGET')
            elif (type(value.get('base')) is not dict or value['base'].get('repo', {}).get('full_name') != self.project.repository
                    or type(value.get('head')) is not dict
                    or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value['head'].get('sha', ''))):
                raise ReconciliationFailure('INVALID_TARGET')
            return obj

        def add(obj):
            if obj not in objects:
                if len(objects) >= 32: raise ReconciliationFailure('OUTPUT_LIMIT')
                objects.append(obj)

        def checkpoint_for(field, index=None):
            for step in steps:
                intent = step.get('intent')
                if intent is not None and field in intent['fields'] and intent['item_index'] == index:
                    return step
            return None

        def before(field, index=None):
            step = checkpoint_for(field, index)
            return None if step is None else step['intent']['preimage_digest']

        def set_field(field, state, index=None):
            for row in fields:
                if row['field'] == field and row['item_index'] == index: row['status'] = state

        def value_state(field, value, expected, index=None):
            if value == expected: return 'MATCHED'
            digest = before(field, index)
            return 'ABSENT' if digest is not None and preimage_digest(value) == digest else 'CONFLICT'

        def anchored(obj):
            # Every prepared/confirmed identity for this object family must
            # agree. PR facade IDs are deliberately different from pull IDs.
            anchors = [step['target'] for step in steps] + [step['object'] for step in steps if step.get('object')]
            for anchor in anchors:
                if (anchor['kind'] == obj['kind'] and anchor.get('number') == obj.get('number')
                        and obj['kind'] in {'issue', 'pull'} and anchor['id'] != obj['id']):
                    raise ReconciliationFailure('IDENTITY_CONFLICT')

        def children(path, field, child_kind, matches, *, parent_key):
            known = {step['object']['id'] for step in steps if step.get('fields') and field in step['fields']}
            if marker is None and not known: raise ReconciliationFailure('LEGACY_MARKER_UNAVAILABLE')
            values = pages(path)
            candidates = []
            for value in values:
                obj = identity(value, child_kind)
                if value.get(parent_key) != api + ('/pulls/' if parent_key == 'pull_request_url' else '/issues/') + str(number):
                    raise ReconciliationFailure('INVALID_TARGET')
                text = value.get('body')
                if type(text) not in (str, type(None)): raise ReconciliationFailure('INVALID_RESPONSE')
                if value['id'] in known or (marker is not None and marker in (text or '')):
                    candidates.append((value, obj))
            if not candidates:
                baseline = before(field)
                state = ('CONFLICT' if marker is None and known else
                         'UNKNOWN' if baseline is None else
                         'ABSENT' if preimage_digest(sorted(value['id'] for value in values)) == baseline else 'CONFLICT')
                set_field(field, state)
                return
            for _, obj in candidates: add(obj)
            if len(candidates) != 1:
                set_field(field, 'CONFLICT'); return
            value, obj = candidates[0]
            exact = (value.get('user', {}).get('id') == user_id and value.get('body') == expected_body
                     and (not known or obj['id'] in known) and matches(value))
            set_field(field, 'MATCHED' if exact else 'CONFLICT')

        try:
            _, user = get('user')
            if type(user) is not dict or user.get('id') != user_id:
                raise ReconciliationFailure('ACTOR_MISMATCH')
            # Repository identity is an immutable anchor for create requests.
            _, repository = get(base)
            repo_obj = identity(repository, 'repository')
            if repository.get('full_name') != self.project.repository or repository.get('html_url') != web:
                raise ReconciliationFailure('INVALID_TARGET')
            if any(step['target']['kind'] == 'repository' and step['target']['id'] != repo_obj['id'] for step in steps):
                raise ReconciliationFailure('IDENTITY_CONFLICT')
            number = route.number
            current = None
            if route.kind.endswith('-create'):
                known = [step['object'] for step in steps if step.get('fields') and 'create' in step['fields']]
                if marker is None and not known: raise ReconciliationFailure('LEGACY_MARKER_UNAVAILABLE')
                matches = []
                collection = pages(base + '/' + endpoint, query='state=all')
                for value in collection:
                    # Issue collection includes PR facades; they cannot satisfy
                    # an issue create even if someone copies the marker there.
                    if kind == 'issue' and 'pull_request' in value: continue
                    text = value.get('body')
                    if type(text) not in (str, type(None)): raise ReconciliationFailure('INVALID_RESPONSE')
                    if ((marker is not None and marker in (text or ''))
                            or any(item['id'] == value['id'] for item in known)):
                        obj = target(value, kind)
                        matches.append((value, obj))
                if not matches:
                    baseline = before('create')
                    state = ('CONFLICT' if marker is None and known else
                             'UNKNOWN' if baseline is None else
                             'ABSENT' if preimage_digest(sorted(value['id'] for value in collection)) == baseline else 'CONFLICT')
                    for field in fields: field['status'] = state
                    return observation(fields)

                if len(matches) != 1:
                    for _, obj in matches: add(obj)
                    for field in fields: field['status'] = 'CONFLICT'
                    return observation(fields, objects)
                listing, listed_obj = matches[0]; number = listed_obj['number']
                _, current = get(base + '/' + endpoint + '/' + str(number))
                obj = target(current, kind, number)
                if obj != listed_obj or (known and obj not in known):
                    raise ReconciliationFailure('IDENTITY_CONFLICT')
                add(obj); anchored(obj)
                create_match = (current['user']['id'] == user_id
                    and (marker is None or marker in (current.get('body') or ''))
                    and (kind != 'pull' or current.get('draft') is options.get('draft', False)))
                set_field('create', 'MATCHED' if create_match else 'CONFLICT')
                for field in ('title', 'body', 'base', 'head', 'draft'):
                    if field not in options: continue
                    value = current.get(field, {}).get('ref') if field in {'base', 'head'} else current.get(field)
                    desired = expected_body if field == 'body' else options[field]
                    state = 'MATCHED' if create_match and value == desired else 'CONFLICT'
                    if field == 'head' and current.get('head', {}).get('repo', {}).get('full_name') != self.project.repository:
                        state = 'CONFLICT'
                    set_field(field, state)
            else:
                _, current = get(base + '/' + endpoint + '/' + str(number))
                obj = target(current, kind, number); anchored(obj); add(obj)
            issue_path = base + '/issues/' + str(number)
            path = base + '/' + endpoint + '/' + str(number)
            for field in ('title', 'body', 'base'):
                if not route.kind.endswith('-edit') or field not in options: continue
                value = current.get('base', {}).get('ref') if field == 'base' else current.get(field)
                if type(value) is not str: raise ReconciliationFailure('INVALID_RESPONSE')
                set_field(field, value_state(field, value, options[field]))
            if route.kind.endswith(('-close', '-reopen')):
                desired = 'closed' if route.kind.endswith('-close') else 'open'
                value = current['state']
                if kind == 'issue':
                    value = [value, current.get('state_reason')]
                    desired = [desired, options.get('reason', 'completed') if desired == 'closed' else 'reopened']
                set_field('state', value_state('state', value, desired))
            facade = current
            if kind == 'pull' and (route.kind == 'pr-comment' or any(field in options for field in
                    ('add-assignee', 'remove-assignee', 'add-label', 'remove-label'))):
                _, facade = get(issue_path)
                facade_obj = target(facade, 'issue', number, facade=True); anchored(facade_obj); add(facade_obj)
            for field in ('add-assignee', 'remove-assignee'):
                if field not in options: continue
                assignees = facade.get('assignees')
                if (type(assignees) is not list or len(assignees) > 100
                        or any(type(v) is not dict or not _positive(v.get('id')) for v in assignees)):
                    raise ReconciliationFailure('INVALID_RESPONSE')
                ids = sorted(v['id'] for v in assignees)
                if len(ids) != len(set(ids)): raise ReconciliationFailure('INVALID_RESPONSE')
                desired = (user_id in ids) == (field == 'add-assignee')
                digest = before(field)
                if field == 'add-assignee' and any(item != user_id for item in ids):
                    state = 'CONFLICT'  # Never overwrite somebody else's assignment.
                elif desired:
                    alternative = sorted(set(ids) - {user_id}) if field == 'add-assignee' else sorted({*ids, user_id})
                    state = ('MATCHED' if digest is None or digest in {preimage_digest(ids), preimage_digest(alternative)}
                             else 'CONFLICT')
                else:
                    state = 'ABSENT' if digest is not None and digest == preimage_digest(ids) else 'CONFLICT'
                set_field(field, state)
            if any(options.get(field) for field in ('add-label', 'remove-label')):
                values = pages(issue_path + '/labels')
                if any(type(v.get('name')) is not str for v in values): raise ReconciliationFailure('INVALID_RESPONSE')
                names = {v['name'] for v in values}
                if len(names) != len(values): raise ReconciliationFailure('INVALID_RESPONSE')
                for field in ('add-label', 'remove-label'):
                    for index, label in enumerate(options.get(field, ())):
                        set_field(field, value_state(field, label in names, field == 'add-label', index), index)
            if route.kind.endswith('-comment'):
                children(issue_path + '/comments', 'comment', 'comment', lambda _: True, parent_key='issue_url')
            elif route.kind == 'pr-reply':
                _, parent = get(base + '/pulls/comments/' + str(options['comment-id']))
                parent_obj = identity(parent, 'comment')
                if parent_obj['id'] != options['comment-id'] or parent.get('pull_request_url') != api + '/pulls/' + str(number):
                    raise ReconciliationFailure('INVALID_TARGET')
                if any(step['target']['kind'] == 'comment' and step['target'] != parent_obj for step in steps):
                    raise ReconciliationFailure('IDENTITY_CONFLICT')
                children(path + '/comments', 'reply', 'comment',
                         lambda value: value.get('in_reply_to_id') == options['comment-id'], parent_key='pull_request_url')
            elif route.kind == 'pr-review':
                states = {'APPROVE': 'APPROVED', 'REQUEST_CHANGES': 'CHANGES_REQUESTED', 'COMMENT': 'COMMENTED'}
                children(path + '/reviews', 'review', 'review',
                    lambda value: (value.get('commit_id') == options['commit'] and value.get('state') == states[options['event']]
                        and type(value.get('submitted_at')) is str and bool(value['submitted_at'])), parent_key='pull_request_url')
            elif route.kind.startswith('dependency-'):
                other_number = options['blocked-by']
                _, other = get(base + '/issues/' + str(other_number))
                other_obj = target(other, 'issue', other_number)
                if other_obj['id'] == obj['id']: raise ReconciliationFailure('INVALID_TARGET')
                for step in steps:
                    bound = step['target']
                    if 'related_id' in bound and (bound['related_id'] != other_obj['id'] or bound['related_number'] != other_number):
                        raise ReconciliationFailure('IDENTITY_CONFLICT')
                values = pages(issue_path + '/dependencies/blocked_by')
                dependencies = [target(value, 'issue') for value in values]
                if any(v['number'] == other_number and v['id'] != other_obj['id'] for v in dependencies):
                    raise ReconciliationFailure('IDENTITY_CONFLICT')
                present = other_obj in dependencies
                field = 'dependency' if route.kind == 'dependency-add' else 'remove-dependency'
                # Membership is the complete native dependency relation, not
                # body text or a guessed provider 404. No write is inferred.
                set_field(field, 'MATCHED' if present == (field == 'dependency') else 'ABSENT')
                add(other_obj)
            return observation(fields, objects)
        except LedgerError:
            raise
        except Exception as error:
            code = getattr(error, 'code', 'PROVIDER_ERROR')
            if code == 'IDENTITY_CONFLICT':
                fields = [{**field, 'status': 'CONFLICT'} for field in fields]
            return observation(fields, objects, error_code=code if code in _ERRORS else 'PROVIDER_ERROR')
