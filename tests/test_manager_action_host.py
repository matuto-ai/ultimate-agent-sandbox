"""Actual host attachment -> typed protocol -> Hub owner, no web server."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest

import test_manager_actions as actions_fixture
from uas.manager_action_host import FieldNotesActionHost


class ManagerActionHostTests(actions_fixture.ManagerActionsTests):
    # Inherited tests are intentionally not rediscovered by the local focused
    # runner. CI's ordinary unittest discovery may safely run them again.
    def setUp(self):
        super().setUp()
        self.context = object()
        self.auth_calls = []
        def authenticate(context):
            self.auth_calls.append(context)
            if context is not self.context: raise ValueError('untrusted context')
            return self.session
        self.host = FieldNotesActionHost(self.actions, authenticate)

    def invoke(self, value, **kwargs):
        return self.host.handle(json.dumps(value).encode(), context=kwargs.get('context', self.context))

    def test_host_actual_owner_view_and_pause_resume(self):
        before = self.invoke({'kind':'run', 'run_id':'run'})
        self.assertEqual('available', before['status'])
        self.assertEqual('room', before['scope']['room_id'])
        packet = self.packet('pause', {'reason':'human-pause'})
        result = self.invoke({'kind':'execute', 'request':packet})
        self.assertEqual('confirmed', result['outcome'])
        self.assertEqual('PAUSED', self.state()['runs']['run']['status'])
        result = self.invoke({'kind':'execute', 'request':self.packet('resume', {'reason':'continue'})})
        self.assertEqual('confirmed', result['outcome'])
        self.assertEqual(3, len(self.auth_calls))

    def test_host_principal_and_room_are_not_browser_selected(self):
        before = self.ledger.snapshot()
        for envelope in ({'kind':'run','run_id':'run','human':self.session.human.canonical()},
                         {'kind':'run','run_id':'run','room_id':'other'},
                         {'kind':'shell','command':'anything'}):
            self.assertEqual('unavailable', self.invoke(envelope)['status'])
        self.assertEqual('unavailable', self.invoke({'kind':'run','run_id':'run'},context=object())['status'])
        self.session = replace(self.session, room_id='other')
        self.assertEqual('unavailable', self.invoke({'kind':'run','run_id':'run'})['status'])
        self.assertEqual(before, self.ledger.snapshot())

    def test_host_disconnect_revocation_and_unknown_are_literal(self):
        self.submit(); self.result(); self.broker.comment_status = 'unknown'
        packet = self.packet('request-changes', {'body':'Human-requested changes'})
        result = self.invoke({'kind':'execute','request':packet})
        self.assertEqual('unknown', result['outcome'])
        count = len(self.broker.calls)
        self.connected = False
        self.assertEqual('unavailable', self.invoke({'kind':'execute','request':packet})['status'])
        self.assertEqual(count, len(self.broker.calls))
        self.connected = True; self.allowed = False
        self.assertEqual('unavailable', self.invoke({'kind':'run','run_id':'run'})['status'])

    def test_host_strict_wire_and_unavailable_owner_do_not_leak_errors(self):
        for raw in (b'{"kind":"run","kind":"execute"}', b'[]', b'NaN', b'x'*16385):
            result = self.host.handle(raw, context=self.context)
            self.assertEqual('unavailable', result['status'])
        self.actions.view = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('secret path'))
        result = self.invoke({'kind':'run','run_id':'run'})
        self.assertEqual('OWNER_STATE_UNAVAILABLE', result['reason'])
        self.assertNotIn('secret', json.dumps(result))

    def test_host_revocation_before_dispatch_hides_current_denied_state(self):
        packet = self.packet('pause', {'reason':'human-pause'})
        checks = []
        def allowed(session, action):
            checks.append(action)
            return len(checks) == 1
        self.session = replace(self.session, authorized=allowed)
        before = self.ledger.snapshot()
        result = self.invoke({'kind':'execute','request':packet})
        self.assertEqual('denied', result['outcome'])
        self.assertIsNone(result['current'])
        self.assertNotIn('receipt', result)
        self.assertEqual(before, self.ledger.snapshot())

    def test_host_revocation_after_write_hides_receipt_without_claiming_rollback(self):
        self.submit(); self.result()
        packet = self.packet('request-changes', {'body':'Human changes'})
        original = self.host.protocol.handle
        def revoke_after(body, *, session):
            result = original(body, session=session)
            self.assertEqual('confirmed', result['outcome'])
            self.allowed = False
            return result
        self.host.protocol.handle = revoke_after
        result = self.invoke({'kind':'execute','request':packet})
        self.assertEqual('unknown', result['outcome'])
        self.assertIsNone(result['current'])
        self.assertNotIn('receipt', result)
        self.assertIsNotNone(self.state()['review_comments']['manager-request-changes']['receipt'])

    def test_host_inspect_original_packet_recovers_lost_local_reply_without_retry(self):
        packet = self.packet('pause', {'reason':'human-pause'})
        self.assertEqual('confirmed', self.invoke({'kind':'execute','request':packet})['outcome'])
        before = self.ledger.snapshot()
        result = self.invoke({'kind':'inspect','request':packet})
        self.assertEqual('confirmed', result['outcome'])
        self.assertEqual(packet['operation_id'], result['receipt']['operation_id'])
        self.assertTrue(result['receipt']['read_only'])
        self.assertEqual(before, self.ledger.snapshot())
        changed = deepcopy(packet); changed['payload']['reason'] = 'different'
        self.assertEqual('ID_CONFLICT', self.invoke({'kind':'inspect','request':changed})['reason'])
        self.assertEqual(before, self.ledger.snapshot())

    def test_host_inspection_missing_unknown_and_revoked_never_retry(self):
        packet = self.packet('pause', {'reason':'human-pause'})
        before = self.ledger.snapshot()
        self.assertEqual('unknown', self.invoke({'kind':'inspect','request':packet})['outcome'])
        self.assertEqual(before, self.ledger.snapshot())
        self.submit(); self.result(); self.broker.comment_status = 'unknown'
        packet = self.packet('request-changes', {'body':'Human changes'})
        self.invoke({'kind':'execute','request':packet}); calls = len(self.broker.calls)
        result = self.invoke({'kind':'inspect','request':packet})
        self.assertEqual('unknown', result['outcome'])
        self.assertEqual(calls, len(self.broker.calls))
        self.allowed = False
        self.assertEqual('unavailable', self.invoke({'kind':'inspect','request':packet})['status'])
        self.assertEqual(calls, len(self.broker.calls))

    def test_host_inspection_matches_confirmed_review_control_and_comment(self):
        self.submit(); self.result('human-needed')
        packet = self.packet('override-review', {'reason':'Human scoped decision','rounds':None})
        self.assertEqual('confirmed', self.invoke({'kind':'execute','request':packet})['outcome'])
        before = self.ledger.snapshot()
        self.assertEqual('confirmed', self.invoke({'kind':'inspect','request':packet})['outcome'])
        self.assertEqual(before, self.ledger.snapshot())
        packet = self.packet('request-changes', {'body':'Human requested changes'})
        self.assertEqual('confirmed', self.invoke({'kind':'execute','request':packet})['outcome'])
        calls = len(self.broker.calls)
        self.assertEqual('confirmed', self.invoke({'kind':'inspect','request':packet})['outcome'])
        self.assertEqual(calls, len(self.broker.calls))
