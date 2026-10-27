"""Pure serialization and inert HTTP channels; never sends a notification."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest

import test_run_review as harness
from uas import manager_attention as attention
from uas.ledger import LedgerError
from uas.forge_audit import ForgeAudit
import test_forge_mutation_audit as mutation


class Channel:
    def __init__(self, data): self.data = bytearray(data); self.timeouts = []
    def settimeout(self, value): self.timeouts.append(value)
    def recv(self, count):
        value = bytes(self.data[:count]); del self.data[:count]; return value


def response(body=b'{"id":42}', *, status='200 OK', headers=None):
    fields = headers or {'Content-Type': 'application/json; charset=UTF-8', 'Content-Length': str(len(body))}
    return ('HTTP/1.1 ' + status + '\r\n' + '\r\n'.join(k + ': ' + v for k, v in fields.items()) + '\r\n\r\n').encode() + body


class ManagerAttentionTests(unittest.TestCase):
    construct = harness.RunReviewTests.construct
    seed = harness.RunReviewTests.seed
    submit = harness.RunReviewTests.submit
    result = harness.RunReviewTests.result
    state = harness.RunReviewTests.state
    fence = harness.RunReviewTests.fence
    call = harness.RunReviewTests.call
    deliver_accept = harness.RunReviewTests.deliver_accept
    def setUp(self):
        harness.RunReviewTests.setUp(self); self.submit(); self.result()
        self.audit = ForgeAudit(self.path.parent / 'forge.db', 'deployment'); self.addCleanup(self.audit.close)
        self.sent = []; self.wire = response(); self.transport_error = False; self.closed = 0
        case = self
        class InertConnection:
            def __init__(self, host, port, timeout, context):
                case.sent.append({'host': host, 'port': port, 'timeout': timeout}); self.sock = Channel(case.wire)
            def request(self, method, path, body, headers):
                case.sent[-1].update(method=method, path=path, body=body, headers=headers)
                if case.transport_error: raise OSError('sensitive upstream error')
            def close(self): case.closed += 1
        original = attention.http.client.HTTPSConnection
        attention.http.client.HTTPSConnection = InertConnection
        self.addCleanup(setattr, attention.http.client, 'HTTPSConnection', original)

    def notice(self):
        return attention.from_run(self.ledger.snapshot(), deployment_id='deployment', room_id='room',
                                  repository='owner/repo', run_id='run', audit=self.audit)

    def deliver(self):
        sender = attention.GotifyDelivery('https://gotify.fixture.invalid/message', 'gotify-ref', lambda ref: 'fixed_token')
        return sender.deliver(self.notice())

    def test_attention_ignores_body_logs_arbitrary_participant_text(self):
        secret = 'SECRET credentials raw logs arbitrary participant markdown ![](https://evil.invalid)'
        self.seed(lambda state: state['run_reviews']['run']['current'].update(reason=secret, body=secret, logs=secret))
        self.seed(lambda state: state['runs']['run'].update(title=secret, instructions=secret))
        encoded = json.dumps(self.notice().payload())
        self.assertNotIn('SECRET', encoded); self.assertNotIn('evil.invalid', encoded)
        self.assertIn('https://github.com/owner/repo/pull/3', encoded)
        self.assertLessEqual(len(encoded.encode()), attention.MAX_NOTICE_BYTES)
        self.assertEqual('text/plain', self.notice().payload()['extras']['client::display']['contentType'])

    def test_attention_known_target_and_finite_metadata_required(self):
        for changed in ({'reason': 'body content'}, {'source_url': 'https://evil.invalid'},
                        {'run_id': 'line\nbreak'}, {'source_url': 'https://github.com/owner/repo/pull/3?token=secret'}):
            with self.assertRaises(LedgerError): replace(self.notice(), **changed).payload()
        with self.assertRaises(LedgerError):
            attention.from_run(self.ledger.snapshot(), deployment_id='deployment', room_id='other', repository='owner/repo', run_id='run', audit=self.audit)
        self.seed(lambda state: state['runs']['run']['gate_target'].update(repository='other/repository'))
        with self.assertRaises(LedgerError): self.notice()
        self.assertEqual([], self.sent)

    def test_attention_unknown_projection_is_visible_not_ready(self):
        self.seed(lambda state: state.update(forge_projections={'run': {'state': 'partial', 'unresolved': {'id': 'unknown'}}}))
        notice = self.notice(); self.assertEqual('FORGE_RECONCILIATION', notice.reason)
        self.assertIn('uncertain', notice.payload()['message'])

    def test_attention_real_ordinary_audit_and_failed_restoration_have_finite_reasons(self):
        self.seed(lambda state: state.update(participant_recoveries={'builder': {'run_id': 'run',
            'generation': 1, 'reason': 'NATIVE_RESTORE_FAILED', 'selection': None, 'body': 'private'}}))
        self.assertEqual('PARTICIPANT_RESTORATION', self.notice().reason)
        self.audit.begin_mutation('ordinary', mutation.metadata(room_id='room'))
        notice = self.notice()
        self.assertEqual('FORGE_RECONCILIATION', notice.reason)
        self.assertNotIn('private', json.dumps(notice.payload()))

    def test_gotify_fixed_endpoint_header_plain_payload_and_confirmed_id(self):
        result = self.deliver(); self.assertEqual({'outcome': 'confirmed', 'message_id': 42}, result)
        sent = self.sent[0]
        self.assertEqual('POST', sent['method']); self.assertEqual('/message', sent['path'])
        self.assertEqual('fixed_token', sent['headers']['X-Gotify-Key'])
        self.assertNotIn(b'fixed_token', sent['body']); self.assertEqual(1, self.closed)

    def test_gotify_timeout_redirect_malformed_and_oversize_are_unknown_no_retry(self):
        for wire in (response(status='302 Found'), response(b'{"id":true}'),
                     response(headers={'Content-Length': '5000', 'Content-Type': 'application/json'}),
                     response(headers={'Transfer-Encoding': 'chunked'}), b'HTTP/1.1 200 OK\r\nX: ' + b'x' * 4096,
                     response()[:-1]):
            self.wire = wire; self.sent.clear()
            self.assertEqual({'outcome': 'unknown', 'reason': 'GOTIFY_UNCONFIRMED'}, self.deliver())
            self.assertEqual(1, len(self.sent))
        self.transport_error = True
        result = self.deliver(); self.assertEqual('unknown', result['outcome'])
        self.assertNotIn('sensitive', json.dumps(result))

    def test_gotify_invalid_endpoint_and_credential_never_contacts(self):
        for endpoint in ('http://gotify.invalid/message', 'https://user:secret@gotify.invalid/message',
                         'https://gotify.invalid/message?token=secret', 'https://gotify.invalid/other'):
            with self.assertRaises(LedgerError): attention.GotifyDelivery(endpoint, 'ref', lambda ref: 'secret')
        sender = attention.GotifyDelivery('https://gotify.invalid/message', 'ref', lambda ref: 'secret\nheader')
        self.assertEqual('not-sent', sender.deliver(self.notice())['outcome']); self.assertEqual([], self.sent)


if __name__ == '__main__': unittest.main()
