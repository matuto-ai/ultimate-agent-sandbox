"""Pure diagnostic reducer/receiver tests: no SDK, process, listener or model."""
import copy
import hashlib
import json
import sqlite3
import threading
import unittest
from unittest.mock import Mock

from uas.claude_runtime import ClaudeSignals, FixtureClaudeReceiver, ClaudeUnavailable, FIXTURE_DENIAL_MESSAGE
from uas.peer import Readiness
from uas.ledger import LedgerError


class PermissionReceiverSourceTests(unittest.TestCase):
    def setUp(self):
        self.s = ClaudeSignals('session', safe_for=0, diagnostic_nonce_file='/fixture/nonce.txt')
        self.s.permission_incarnation = 'fixture-incarnation'
        self.s.begin('11111111-1111-4111-8111-111111111111', 'peer-content')
        self.s.event({'type':'system', 'subtype':'init', 'session_id':'session',
                      'claude_code_version':'2.1.310', 'tools':['Read'], 'mcp_servers':[]})
        self.ack = {'type':'user', 'session_id':'session', 'uuid':'11111111-1111-4111-8111-111111111111', 'isReplay':True,
                    'parent_tool_use_id':None, 'message':{'role':'user', 'content':'peer-content'}}
        self.s.event(self.ack)
        self.identity = {'sessionId':'session', 'incarnation':'fixture-incarnation',
                         'invocationId':'11111111-1111-4111-8111-111111111111', 'requestId':'request', 'toolUseID':'tool',
                         'inputDigest':hashlib.sha256(b'{"file_path":"/fixture/nonce.txt"}').hexdigest()}
        self.attention = {'identity':self.identity, 'toolName':'Read',
                          'input':{'file_path':'/fixture/nonce.txt'}}
        self.result = {'type':'user', 'session_id':'session', 'parent_tool_use_id':None,
                       'message':{'role':'user', 'content':[{'type':'tool_result', 'tool_use_id':'tool', 'content':'nonce'}]},
                       'tool_use_result':{'type':'text', 'file':{'filePath':'/fixture/nonce.txt'}},
                       'tool_result_meta':[{'id':'tool', 'permission_decision':{'decision':'accept', 'source':'user_temporary'}}]}
        self.terminal = {'type':'result', 'session_id':'session', 'user_message_uuid':'11111111-1111-4111-8111-111111111111',
                         'subtype':'success', 'is_error':False, 'permission_denials':[],
                         'queued_turn_count':0, 'terminal_reason':'completed', 'stop_reason':'end_turn'}

    def allow(self):
        self.s.attention(self.attention)
        self.s.decision({'identity':self.identity, 'behavior':'allow'})

    def test_allow_and_tool_result_are_not_readiness_or_replay(self):
        self.allow()
        self.assertIs(self.s.readiness(), Readiness.BUSY)
        self.s.event(self.result)
        self.assertIs(self.s.ack, self.ack)
        self.assertIs(self.s.readiness(), Readiness.BUSY)
        self.s.event(self.terminal)
        self.assertFalse(self.s.fenced)
        self.assertIsNone(self.s.pending)
        self.assertIs(self.s.readiness(), Readiness.AMBIGUOUS)

    def test_terminal_missing_decision_or_tool_result_permanently_fences(self):
        for decide in (False, True):
            with self.subTest(decide=decide):
                self.setUp()
                self.s.attention(self.attention)
                if decide:
                    self.s.decision({'identity':self.identity, 'behavior':'allow'})
                self.s.event(self.terminal)
                self.assertTrue(self.s.fenced)

    def test_malformed_tool_result_cannot_be_receipt(self):
        for field in ('isReplay', 'tool_use_id', 'filePath', 'metadata'):
            with self.subTest(field=field):
                self.setUp(); self.allow()
                event = copy.deepcopy(self.result)
                if field == 'isReplay': event[field] = True
                if field == 'tool_use_id': event['message']['content'][0][field] = 'other'
                if field == 'filePath': event['tool_use_result']['file'][field] = '/other'
                if field == 'metadata': event['tool_result_meta'] = []
                self.s.event(event)
                self.assertTrue(self.s.fenced)
                self.assertIs(self.s.ack, self.ack)

    def test_stale_attention_and_decisions_fail_closed(self):
        for field in self.identity:
            with self.subTest(field=field):
                self.setUp()
                bad = copy.deepcopy(self.attention); bad['identity'][field] = 'stale'
                if field in ('requestId', 'toolUseID'):
                    # IDs are assigned natively; a different decision must still fail.
                    self.s.attention(self.attention)
                    self.s.decision({'identity':bad['identity'], 'behavior':'allow'})
                else:
                    self.s.attention(bad)
                self.assertTrue(self.s.fenced)

    def test_unmatched_deny_and_irreversible_fences_cannot_recover(self):
        self.s.attention(self.attention)
        self.s.decision({'identity':self.identity, 'behavior':'deny'})
        self.assertIs(self.s.readiness(), Readiness.BUSY)
        self.s.event(self.terminal)
        self.assertTrue(self.s.fenced)
        self.setUp(); self.s.hold('transport-loss'); self.allow()
        self.s.event(self.result); self.s.event(self.terminal)
        self.assertTrue(self.s.fenced)

    def test_default_remains_tool_less_and_rejects_attention(self):
        plain = ClaudeSignals('session')
        plain.begin('11111111-1111-4111-8111-111111111111', 'peer-content')
        plain.attention(self.attention)
        self.assertTrue(plain.fenced)

    def test_native_idle_does_not_clear_unknown_intent_or_authorize_delivery(self):
        self.allow(); self.s.event(self.result); self.s.event(self.terminal)
        receiver = FixtureClaudeReceiver.__new__(FixtureClaudeReceiver)
        receiver.signals = self.s
        receiver.ended = False
        receiver._host_alive = lambda: True
        receiver._probe = Mock(return_value=Readiness.SAFE)
        receiver.db = sqlite3.connect(':memory:')
        self.addCleanup(receiver.db.close)
        receiver.db.execute('CREATE TABLE handoffs (receipt TEXT, retryable INTEGER)')
        receiver.db.execute('INSERT INTO handoffs VALUES(NULL,0)')
        self.assertIs(receiver.observe(), Readiness.AMBIGUOUS)
        receiver.timeout = 1
        receiver._probe.assert_not_called()
        receiver.wait_safe()  # Native-only liveness/idle, not journal/delivery authority.
        receiver._probe.assert_called_once()
        self.assertIs(receiver.observe(), Readiness.AMBIGUOUS)
        receiver.scope = {'room_id': 'alpha', 'participant_id': 'claude', 'run_id': 'run-1',
                          'generation': 1, 'context_generation': 1}
        receiver.incarnation_id = 'fixture-incarnation'
        receiver._write = Mock()
        with self.assertRaisesRegex(LedgerError, 'NATIVE_NOT_SAFE'):
            receiver.accept({**receiver.scope, 'incarnation_id': receiver.incarnation_id})
        receiver._write.assert_not_called()
        receiver._probe.assert_called_once()
        self.assertEqual(receiver.db.execute('SELECT * FROM handoffs').fetchall(), [(None, 0)])

    def test_probe_requires_new_exact_idle_observation_after_terminal(self):
        self.allow(); self.s.event(self.result); self.s.event(self.terminal)
        receiver = FixtureClaudeReceiver.__new__(FixtureClaudeReceiver)
        receiver.signals = self.s; receiver.ended = False
        receiver.native_pid = 99; receiver.session_id = 'session'; receiver.event_revision = 10
        receiver.condition = threading.Condition(); receiver._kernel = lambda: 'S'
        reply = {'state':'safe', 'pid':99, 'session_id':'session',
                 'liveness':'fresh-public-mcpServerStatus', 'reason':'native-listing-idle',
                 'native_state':'idle', 'revision':10, '_seen_revision':10}
        receiver._command = Mock(return_value=reply)
        self.assertIs(receiver._probe(), Readiness.SAFE)
        for key, value in (('native_state','running'), ('_seen_revision',9), ('liveness','old'), ('pid',100)):
            receiver._command = Mock(return_value={**reply,key:value})
            self.assertIs(receiver._probe(), Readiness.AMBIGUOUS)

    def test_confirmed_controller_reply_survives_denial_fence_without_clearing_it(self):
        receiver = FixtureClaudeReceiver.__new__(FixtureClaudeReceiver)
        receiver.signals = self.s
        receiver.signals.hold('denied-terminal')
        receiver.timeout = 1
        receiver.condition = threading.Condition()
        receiver.reply = {'id':'correlated-command', 'accepted':True}
        receiver.ended = False
        receiver._host_alive = lambda: True
        self.assertIs(receiver._wait(lambda: receiver.reply, decision_reply=True), receiver.reply)
        self.assertTrue(receiver.signals.fenced)
        with self.assertRaises(ClaudeUnavailable):
            receiver._wait(lambda: receiver.reply)

    def test_attention_identity_copy_cannot_change_pending_permission(self):
        self.s.attention(self.attention)
        exposed = self.s.permission
        exposed['requestId'] = 'changed'
        self.assertEqual(self.s.permission['requestId'], 'request')
        self.s.decision({'identity':exposed, 'behavior':'allow'})
        self.assertTrue(self.s.fenced)

    def test_native_attention_ordering_and_second_turn_hold(self):
        event = {'session_id':'session', 'state':'requires_action'}
        self.s.session_state(event)
        self.assertFalse(self.s.fenced)
        self.allow(); self.s.event(self.result); self.s.event(self.terminal)
        self.s.begin('22222222-2222-4222-8222-222222222222', 'next-peer')
        self.s.session_state(event)
        self.assertTrue(self.s.fenced)

    def continuation(self):
        return {'type':'assistant', 'session_id':'session', 'parent_tool_use_id':None,
                'message':{'role':'assistant', 'content':[{'type':'text', 'text':'Text is not identity or authority.'}]}}

    def test_optional_uuid_continuation_never_changes_ack_pending_or_readiness(self):
        self.allow(); self.s.event(self.result)
        pending = self.s.pending
        self.s.event(self.continuation())
        self.assertFalse(self.s.fenced)
        self.assertIs(self.s.pending, pending)
        self.assertIs(self.s.ack, self.ack)
        self.assertIs(self.s.readiness(), Readiness.BUSY)
        self.s.event(self.terminal)
        self.assertFalse(self.s.fenced)
        self.assertIsNone(self.s.pending)
        self.assertIs(self.s.readiness(), Readiness.AMBIGUOUS)

    def test_continuation_wrong_identity_tools_duplicates_and_pretool_frames_fence(self):
        changes = [lambda e: e.update(user_message_uuid='wrong'), lambda e: e.update(user_message_uuid=None),
                   lambda e: e.update(user_message_uuids=['other']), lambda e: e.update(session_id='other'),
                   lambda e: e.pop('parent_tool_use_id'), lambda e: e.update(parent_tool_use_id='subagent'),
                   lambda e: e['message'].update(content=[{'type':'tool_use', 'id':'new-tool'}]),
                   lambda e: e['message']['content'].append({'type':'text', 'text':'extra'})]
        for change in changes:
            self.setUp(); self.allow(); self.s.event(self.result)
            frame = self.continuation(); change(frame); self.s.event(frame)
            self.assertTrue(self.s.fenced)
            self.assertIs(self.s.ack, self.ack)
        self.setUp(); self.allow(); self.s.event(self.continuation())
        self.assertTrue(self.s.fenced)
        self.setUp(); self.allow(); self.s.event(self.result)
        self.s.event(self.continuation()); self.s.event(self.continuation())
        self.assertTrue(self.s.fenced)


class DenialReceiverSourceTests(PermissionReceiverSourceTests):
    """Reuse allow safety/probe/journal assertions with the exact denied shape."""
    def setUp(self):
        super().setUp()
        self.result['message']['content'][0].update(is_error=True, content=FIXTURE_DENIAL_MESSAGE)
        self.result['tool_use_result'] = 'Error: ' + FIXTURE_DENIAL_MESSAGE
        self.result['tool_result_meta'] = [{'id':'tool', 'non_execution_kind':'permission-rule',
                                           'permission_decision':{'decision':'reject','source':'user_reject'}}]
        self.terminal['permission_denials'] = [{'tool_name':'Read','tool_use_id':'tool',
                                               'tool_input':{'file_path':'/fixture/nonce.txt'}}]

    def allow(self):
        self.s.attention(self.attention)
        self.s.decision({'identity':self.identity, 'behavior':'deny'})

    def test_malformed_tool_result_cannot_be_receipt(self):
        changes = [lambda e: e.update(isReplay=True), lambda e: e.update(tool_use_result='Error: cancelled'),
                   lambda e: e['message']['content'][0].update(is_error=False),
                   lambda e: e['message']['content'][0].update(content='cancelled'),
                   lambda e: e['tool_result_meta'][0].update(non_execution_kind='other'),
                   lambda e: e['tool_result_meta'][0]['permission_decision'].update(source='config'),
                   lambda e: e['message']['content'][0].update(tool_use_id='other')]
        for change in changes:
            self.setUp(); self.allow(); event=copy.deepcopy(self.result); change(event)
            self.s.event(event); self.assertTrue(self.s.fenced); self.assertIs(self.s.ack,self.ack)

    def test_denied_terminal_exact_record_and_unmodified_evidence(self):
        mutations = [lambda e: e.pop('permission_denials'), lambda e: e.update(permission_denials=[]),
                     lambda e: e['permission_denials'].append(e['permission_denials'][0]),
                     lambda e: e['permission_denials'][0].update(tool_name='Write'),
                     lambda e: e['permission_denials'][0].update(tool_use_id='other'),
                     lambda e: e['permission_denials'][0]['tool_input'].update(file_path='/other'),
                     lambda e: e['permission_denials'][0]['tool_input'].update(limit=1),
                     lambda e: e['permission_denials'][0].update(extra=True),
                     lambda e: e.update(queued_turn_count=1), lambda e: e.update(is_error=True)]
        for mutate in mutations:
            self.setUp(); self.allow(); self.s.event(self.result)
            event=copy.deepcopy(self.terminal); mutate(event); self.s.event(event); self.assertTrue(self.s.fenced)
        self.setUp(); self.allow(); self.s.event(self.result)
        before=copy.deepcopy(self.terminal); self.s.event(self.terminal)
        self.assertFalse(self.s.fenced); self.assertEqual(before,self.terminal); self.assertIs(self.s.ack,self.ack)

    def test_advisory_permission_signal_stays_irreversible(self):
        self.allow(); self.s.event({'type':'system','subtype':'permission_denied','session_id':'session'})
        self.s.event(self.result); self.s.event(self.terminal); self.assertTrue(self.s.fenced)


    def test_denial_requires_ack_and_cannot_recover_other_fences_or_later_denials(self):
        self.allow(); self.s.event(self.result); self.s.ack=None; self.s.event(self.terminal)
        self.assertTrue(self.s.fenced)
        for reason in ('transport-loss','native-identity','unknown-signal','journal'):
            self.setUp(); self.allow(); self.s.hold(reason); self.s.event(self.result); self.s.event(self.terminal)
            self.assertTrue(self.s.fenced); self.assertEqual(self.s.state,reason)
        self.setUp(); self.allow(); self.s.event(self.result); self.s.event(self.result)
        self.assertTrue(self.s.fenced)
        self.setUp(); self.s.attention(self.attention)
        self.s.decision({'identity':self.identity,'behavior':'allow'}); self.s.event(self.result)
        self.assertTrue(self.s.fenced)
        self.setUp(); self.allow(); self.s.event(self.result); self.s.event(self.terminal)
        next_id='22222222-2222-4222-8222-222222222222'; self.s.begin(next_id,'next')
        self.s.event({**self.ack,'uuid':next_id,'message':{'role':'user','content':'next'}})
        self.s.event({**self.terminal,'user_message_uuid':next_id})
        self.assertTrue(self.s.fenced)  # Old denial is never valid for a new turn.
