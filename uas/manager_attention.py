"""Bounded Gotify attention: finite metadata, canonical links, no Project text.

No notification is sent at import/construction. The trusted host selects one
existing application endpoint and secret reference, then explicitly delivers a
notice. No application/account/token creation, redirect, shell or arbitrary URL.
"""
from dataclasses import dataclass
import hashlib
import http.client
import json
import re
import ssl
import time
from urllib.parse import urlsplit

from .gate_forge import validate_forge_target
from .github_read import GitHubProject
from .ledger import LedgerError, _json
from .manager_actions import run_version, uncertain_forge
from .manager_stream import StreamError
from .manager_transport import _read_exact


MAX_NOTICE_BYTES = 2048
MAX_RESPONSE_BYTES = 4096
REASONS = {
    'HUMAN_REVIEW': 'Human review is ready.',
    'REVIEW_ATTENTION': 'Review needs human attention.',
    'RUN_PAUSED': 'Run is paused.',
    'FORGE_RECONCILIATION': 'Forge outcome is uncertain; reconciliation is required.',
    'PARTICIPANT_RESTORATION': 'Participant restoration failed; human selection is required.',
}
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


def _id(value):
    if type(value) is not str or not _ID.fullmatch(value):
        raise LedgerError('INVALID_ATTENTION_METADATA')
    return value


@dataclass(frozen=True)
class AttentionNotice:
    deployment_id: str
    room_id: str
    run_id: str
    generation: int
    observed_version: str
    reason: str
    source_url: str

    def payload(self):
        for value in (self.deployment_id, self.room_id, self.run_id): _id(value)
        if (type(self.generation) is not int or not 1 <= self.generation < 2**63
                or type(self.observed_version) is not str or not re.fullmatch('[0-9a-f]{64}', self.observed_version)
                or self.reason not in REASONS or type(self.source_url) is not str
                or not re.fullmatch(r'https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}/(?:pull|issues)/[1-9][0-9]{0,9}', self.source_url)):
            raise LedgerError('INVALID_ATTENTION_METADATA')
        value = {'title': 'Ultimate Agent Sandbox attention', 'priority': 5,
            'message': (REASONS[self.reason] + '\nDeployment: ' + self.deployment_id
                + '\nRoom: ' + self.room_id + '\nRun: ' + self.run_id
                + '\nGeneration: ' + str(self.generation)
                + '\nVersion: ' + self.observed_version + '\n' + self.source_url),
            'extras': {'client::display': {'contentType': 'text/plain'}}}
        if len(_json(value).encode()) > MAX_NOTICE_BYTES: raise LedgerError('ATTENTION_LIMIT')
        return value

    def identity(self):
        return hashlib.sha256(_json(self.payload()).encode()).hexdigest()


def from_run(snapshot, *, deployment_id, room_id, repository, run_id, audit):
    """Only canonical owner state and host Project binding supply the notice.

    Arbitrary reason/body/title/log/Participant values are never interpolated.
    A source link must agree with the fixed Project and verified owner target.
    """
    GitHubProject(repository)
    from .forge_audit import ForgeAudit
    if type(audit) is not ForgeAudit or audit.deployment_id != deployment_id:
        raise LedgerError('ATTENTION_AUDIT_REQUIRED')
    forge = audit.manager_action_state(room_id, repository)
    if snapshot.get('room_id') != room_id: raise LedgerError('ATTENTION_ROOM_MISMATCH')
    state = snapshot['state']; run = state.get('runs', {}).get(run_id)
    if not run or run.get('repository') != repository: raise LedgerError('ATTENTION_TARGET_MISMATCH')
    current = state.get('run_reviews', {}).get(run_id, {}).get('current')
    if uncertain_forge(state, run_id, forge=forge): reason = 'FORGE_RECONCILIATION'
    elif any(row.get('run_id') == run_id and row.get('generation') == run['generation']
             and row.get('reason') == 'NATIVE_RESTORE_FAILED' and row.get('selection') is None
             for row in state.get('participant_recoveries', {}).values()): reason = 'PARTICIPANT_RESTORATION'
    elif current and current['stage'] == 'ATTENTION': reason = 'REVIEW_ATTENTION'
    elif current and current['stage'] == 'READY_FOR_HUMAN': reason = 'HUMAN_REVIEW'
    elif run['status'] == 'PAUSED': reason = 'RUN_PAUSED'
    else: return None
    target = run.get('gate_target')
    if target is not None:
        target = validate_forge_target(target)
        if target['repository'] != repository: raise LedgerError('ATTENTION_TARGET_MISMATCH')
        path = '/pull/' + str(target['pull_number'])
    else:
        number, immutable_id = run.get('issue_number'), run.get('issue_id')
        if (type(number) is not int or not 1 <= number <= 9_999_999_999
                or type(immutable_id) is not int or immutable_id <= 0):
            raise LedgerError('ATTENTION_SOURCE_UNVERIFIED')
        path = '/issues/' + str(number)
    notice = AttentionNotice(deployment_id, room_id, run_id, run['generation'],
        run_version(state, run_id, forge), reason, 'https://github.com/' + repository + path)
    notice.payload()
    return notice


class GotifyDelivery:
    """One bounded HTTPS POST; uncertain delivery is never automatically retried.

    Credentials remain host-owned. The resolver receives the fixed reference,
    never a message-selected reference. It must return an existing application
    token; this adapter creates no credentials or account permissions.
    """
    def __init__(self, endpoint, token_reference, resolve_token, *, context=None):
        try:
            url = urlsplit(endpoint)
            if (url.scheme != 'https' or not url.hostname or url.username or url.password
                    or url.query or url.fragment or url.path != '/message'
                    or not re.fullmatch(r'[A-Za-z0-9.-]+', url.hostname)
                    or url.port is not None and not 1 <= url.port <= 65535): raise ValueError()
        except (TypeError, ValueError):
            raise LedgerError('INVALID_GOTIFY_ENDPOINT') from None
        if not callable(resolve_token): raise LedgerError('GOTIFY_CREDENTIAL_RESOLVER_REQUIRED')
        self.host, self.port = url.hostname, url.port or 443
        self.reference, self.resolve = _id(token_reference), resolve_token
        self.context = context
        if context is not None and (type(context) is not ssl.SSLContext
                or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname):
            raise LedgerError('GOTIFY_TLS_REQUIRED')

    def deliver(self, notice):
        if type(notice) is not AttentionNotice: raise LedgerError('INVALID_ATTENTION_METADATA')
        body = _json(notice.payload()).encode()
        try: secret = self.resolve(self.reference)
        except Exception: return {'outcome': 'not-sent', 'reason': 'GOTIFY_CREDENTIAL_UNAVAILABLE'}
        if type(secret) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', secret):
            return {'outcome': 'not-sent', 'reason': 'GOTIFY_CREDENTIAL_UNAVAILABLE'}
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=5, context=self.context)
        try:
            deadline = time.monotonic() + 5
            connection.request('POST', '/message', body=body,
                headers={'Content-Type': 'application/json', 'X-Gotify-Key': secret})
            # Do not let HTTPResponse's per-recv timeout turn a slow trickle
            # into an unbounded notification operation. One absolute deadline
            # covers response headers/body; redirects/chunking are unsupported.
            head = bytearray()
            while not head.endswith(b'\r\n\r\n'):
                if len(head) >= 4096: raise ValueError()
                head.extend(_read_exact(connection.sock, 1, deadline))
            lines = head[:-4].decode('ascii').split('\r\n')
            if lines[0] != 'HTTP/1.1 200 OK': raise ValueError()
            headers = {}
            for line in lines[1:]:
                key, separator, value = line.partition(':'); key = key.lower()
                if (not separator or not re.fullmatch('[a-z0-9-]+', key) or key in headers
                        or any(ord(c) < 32 or ord(c) == 127 for c in value)): raise ValueError()
                headers[key] = value.strip()
            if ('transfer-encoding' in headers or 'content-encoding' in headers
                    or not re.fullmatch('[0-9]{1,4}', headers.get('content-length', ''))
                    or headers.get('content-type', '').split(';')[0] != 'application/json'):
                raise ValueError()
            length = int(headers['content-length'])
            if not 0 < length <= MAX_RESPONSE_BYTES: raise ValueError()
            raw = _read_exact(connection.sock, length, deadline)
            value = json.loads(raw)
            if type(value) is not dict or type(value.get('id')) is not int or value['id'] <= 0:
                return {'outcome': 'unknown', 'reason': 'GOTIFY_UNCONFIRMED'}
            return {'outcome': 'confirmed', 'message_id': value['id']}
        except (OSError, ValueError, http.client.HTTPException, StreamError):
            return {'outcome': 'unknown', 'reason': 'GOTIFY_UNCONFIRMED'}
        finally:
            connection.close()
