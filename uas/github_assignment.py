"""One additive self-assignment route; controlled provider seam, no live qualification.

The trusted transport takes (method, path, body), with no caller-selected endpoint.
It must enforce its own I/O deadline. Reads never imply causal proof of a write.
"""
import json
import time

from .github_read import GitHubProject, GitHubReadProvider, ProviderResponse, ProviderFailure, MAX_OUTPUT, _positive, _LOGIN, _unique
from .ledger import LedgerError


def assignment_result(status, *, issue_id=None, assignees=(), fields=(), contact='read', attribution='observed-only'):
    return {'status': status, 'issue_id': issue_id, 'observed_assignee_ids': sorted(assignees),
            'confirmed_fields': list(fields), 'contact': contact, 'attribution': attribution}


class GitHubAssignmentProvider:
    def __init__(self, project, transport):
        if type(project) is not GitHubProject or not callable(transport):
            raise LedgerError('INVALID_PROJECT')
        self.project, self.transport = project, transport
        self.reader = GitHubReadProvider(project, lambda _: None)

    def _session(self):
        used, deadline = 0, time.monotonic() + 30
        def request(method, path, body=None):
            nonlocal used
            if time.monotonic() >= deadline:
                raise ProviderFailure('TIMEOUT')
            response = self.transport(method, path, body)
            if (time.monotonic() >= deadline or type(response) is not ProviderResponse
                    or type(response.body) is not bytes or type(response.status) is not int
                    or type(response.headers) is not dict):
                raise ProviderFailure('INVALID_RESPONSE')
            used += len(response.body)
            if used > MAX_OUTPUT:
                raise ProviderFailure('OUTPUT_LIMIT')
            if response.status != (201 if method == 'POST' else 200):
                raise ProviderFailure('PROVIDER_ERROR')
            try:
                return json.loads(response.body, object_pairs_hook=_unique)
            except (ValueError, UnicodeError, RecursionError):
                raise ProviderFailure('INVALID_RESPONSE') from None
        return request

    def assign_self(self, number, user_id, *, before_write):
        request = self._session()
        issue_id, possible = None, False
        try:
            # Verify the provider credential's account rather than trusting login
            # text or silently substituting another configured Actor.
            user = request('GET', 'user')
            if (type(user) is not dict or not _positive(user.get('id'))
                    or type(user.get('login')) is not str or not _LOGIN.fullmatch(user['login'])):
                raise ProviderFailure('INVALID_RESPONSE')
            if user['id'] != user_id:
                return assignment_result('ACTOR_MISMATCH')
            base = f'repos/{self.project.repository}/issues/{number}'
            issue = self.reader._issue(request('GET', base), number, assignments=True)
            issue_id = issue['id']
            ids = [u['id'] for u in issue['assignees']]
            if issue['state'] != 'open':
                return assignment_result('ISSUE_NOT_ELIGIBLE', issue_id=issue_id, assignees=ids)
            if ids:
                return assignment_result('ALREADY_ASSIGNED' if ids == [user_id] else 'ASSIGNMENT_CONFLICT',
                                         issue_id=issue_id, assignees=ids)
            # Must durably bind exact object identity before potential mutation.
            before_write(issue_id)
            possible = True
            result = self.reader._issue(request('POST', base + '/assignees',
                                               {'assignees': [user['login']]}), number, assignments=True)
            if result['id'] != issue_id:
                raise ProviderFailure('INVALID_RESPONSE')
            ids = [u['id'] for u in result['assignees']]
            if result['state'] != 'open' or ids != [user_id]:
                # A successful HTTP code can silently ignore an assignee. Never
                # turn it into proof, and never remove a concurrent assignee.
                return assignment_result('UNKNOWN_OUTCOME', issue_id=issue_id, assignees=ids,
                                         contact='write-possible', attribution='unknown')
            return assignment_result('ASSIGNED', issue_id=issue_id, assignees=ids,
                fields=('add-assignee',), contact='write-possible', attribution='confirmed-response')
        except LedgerError:
            raise  # Authority/audit failure must stop before POST.
        except Exception:
            return assignment_result('UNKNOWN_OUTCOME' if possible else 'PROVIDER_FAILURE',
                issue_id=issue_id, contact='write-possible' if possible else 'read', attribution='unknown')

    def reconcile(self, number, user_id, issue_id):
        try:
            request = self._session()
            issue = self.reader._issue(request('GET', f'repos/{self.project.repository}/issues/{number}'),
                                       number, assignments=True)
            if issue_id is None or issue['id'] != issue_id or issue['state'] != 'open':
                return assignment_result('UNKNOWN', issue_id=issue_id)
            ids = [u['id'] for u in issue['assignees']]
            return assignment_result('MATCHED' if ids == [user_id] else 'CONFLICT' if ids else 'ABSENT',
                                     issue_id=issue_id, assignees=ids)
        except Exception:
            return assignment_result('UNKNOWN', issue_id=issue_id)
