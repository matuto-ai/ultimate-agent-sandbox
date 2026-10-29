"""Controlled dispatch/auth tests only: no native, TLS or Broker I/O."""
from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace
import hashlib
import unittest
from unittest.mock import Mock, patch
from uas import human_mtls
from uas import local_native_human_controls as subject
from uas.local_native_graph import LocalNativeGraph
from uas.native_review_host import NativeReviewHost
from uas.ledger import LedgerError, Origin
import test_human_mtls_source as support


class ControlsTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(human_mtls.ssl, 'SSLSocket', support.TLS).start()
        self.channel = support.TLS()
        human = Origin('operator','human','human-session','authority',('human-open-run','human-control-run'))
        grant = human_mtls.HumanActionGrant('deployment','room','instance','manager',human,
                                           tuple(sorted(human_mtls.ACTIONS)))
        self.fingerprint = hashlib.sha256(self.channel.certificate).hexdigest()
        self.bindings = human_mtls.HumanActionBindings({self.fingerprint: grant})
        self.connection = self.bindings.accept(self.channel)
        self.graph = object.__new__(LocalNativeGraph)
        self.graph.closed = False
        self.graph.host = SimpleNamespace(operation_current=Mock())
        self.row = {'run_id':'run','generation':1,'status':'ACTIVE'}
        self.graph.activity = SimpleNamespace(grant=grant,_session=Mock(),_row=lambda: self.row,
                                              _pending_comments=Mock(return_value=()))
        self.review = object.__new__(NativeReviewHost)
        self.review.human_action = Mock(return_value={'status':'confirmed'})
        self.review.human_eligibility = Mock(return_value={'eligible':True})
        self.graph.recruitment = SimpleNamespace(root=SimpleNamespace(review_host=self.review))
        self.graph.broker = object()
        self.audit = SimpleNamespace(binding=SimpleNamespace(repository='owner/repo'))
        self.audit_factory = patch.object(subject, 'NativeBrokerAudit', return_value=self.audit).start()
        self.value = {'version':1,'operation_id':'change-one','action':'request-changes',
            'deployment_id':'deployment','room_id':'room','instance_id':'instance','run_id':'run',
            'generation':1,'object_id':'submission','observed_version':'a'*64,'payload':{}}
        self.view = {**self.row,'forge_uncertain':False}
        self.state = {'runs':{'run':self.row},'run_reviews':{'run':{'current':{'submission_id':'submission','stage':'READY_FOR_HUMAN'}}}}
        self.observation_patch = patch.object(subject,'_observe',return_value=(self.view,self.state,None))
        self.observation = self.observation_patch.start()
        self.frame = {'version':1,'action':'request-changes',
                      'payload':{'kind':'execute','request':self.value}}

    def handle(self, frame=None):
        frame = self.frame if frame is None else frame
        self.connection = self.bindings.accept(self.channel)
        with self.connection.request(frame) as (received, session):
            return subject.handle_native_human(self.graph, received, received['payload'], session, available_actions=tuple(subject.ACTIONS))

    def test_each_invocation_uses_fresh_session_and_no_retained_audit(self):
        self.assertEqual(self.handle()['outcome'], 'confirmed')
        first = self.review.human_action.call_args.kwargs['session']
        self.assertFalse(first.allowed('request-changes'))
        self.handle()
        second = self.review.human_action.call_args.kwargs['session']
        self.assertIsNot(first, second)
        self.audit_factory.assert_called_with(self.graph.broker, second)
        self.assertFalse(any(value is first or value is second or value is self.audit
                             for value in vars(self.graph).values()))

    def test_expired_session_denied_before_audit_or_command(self):
        with self.connection.request(self.frame) as (frame, session): pass
        with self.assertRaisesRegex(LedgerError,'AUTHENTICATION_REQUIRED'):
            subject.handle_native_human(self.graph, frame, frame['payload'], session)
        self.audit_factory.assert_not_called(); self.review.human_action.assert_not_called()

    def test_wrong_scope_and_run_or_generation_denied(self):
        for field, value in [('manager_id','elsewhere'),('deployment_id','elsewhere')]:
            original = self.graph.activity.grant
            self.graph.activity.grant = SimpleNamespace(**{**vars(original), field:value})
            with self.assertRaisesRegex(LedgerError,'AUTHENTICATION_REQUIRED'): self.handle()
            self.graph.activity.grant = original
        for field, value in [('run_id','other-run'),('generation',2)]:
            frame = deepcopy(self.frame); frame['payload']['request'][field] = value
            with self.assertRaisesRegex(LedgerError,'RUN_MISMATCH'): self.handle(frame)
        self.review.human_action.assert_not_called()

    def test_frame_cannot_dispatch_another_action(self):
        frame = deepcopy(self.frame); frame['payload']['request']['action'] = 'reconcile-changes'
        with self.assertRaisesRegex(LedgerError,'ACTION_MISMATCH'): self.handle(frame)
        self.review.human_action.assert_not_called()

    def test_pending_comment_requires_explicit_reconciliation(self):
        self.graph.activity._pending_comments.return_value = ('pending-comment',)
        with self.assertRaisesRegex(LedgerError,'RECONCILIATION_REQUIRED'): self.handle()
        frame = deepcopy(self.frame); frame['action'] = 'reconcile-changes'
        frame['payload']['request'].update(action='reconcile-changes',object_id='pending-comment')
        self.assertEqual(self.handle(frame)['outcome'], 'confirmed')
        self.review.human_action.assert_called_once()

    def test_inspection_does_not_execute(self):
        frame = deepcopy(self.frame); frame['payload']['kind'] = 'inspect'
        self.assertEqual(self.handle(frame)['outcome'], 'unknown')
        self.review.human_eligibility.assert_not_called()
        self.review.human_action.assert_not_called()

    def test_post_effect_revocation_is_not_success_or_retry(self):
        self.review.human_action.side_effect = lambda *a, **kw: self.bindings.revoke(self.fingerprint)
        with self.assertRaisesRegex(LedgerError,'AUTHENTICATION_REQUIRED'): self.handle()
        self.review.human_action.assert_called_once()

    def test_closed_graph_missing_review_and_failed_owner_are_not_fallbacks(self):
        self.graph.closed = True
        with self.assertRaisesRegex(LedgerError,'CONTROLS_UNAVAILABLE'): self.handle()
        self.graph.closed = False; self.graph.recruitment = None
        with self.assertRaisesRegex(LedgerError,'REVIEW_UNAVAILABLE'): self.handle()
        self.graph.host.operation_current.side_effect = LedgerError('OWNER_LOST')
        with self.assertRaisesRegex(LedgerError,'OWNER_LOST'): self.handle()
        self.review.human_action.assert_not_called()

    def test_observe_uses_original_broker_fence_and_actual_view(self):
        self.observation_patch.stop()
        operation = SimpleNamespace(prepare_manager_guard=lambda:nullcontext(),
            manager_action_guard=lambda *args:nullcontext({'blocked':False}),require_current=Mock())
        self.audit.observation = lambda:operation
        self.graph.owner = SimpleNamespace(supervisor=SimpleNamespace(_locked=lambda:nullcontext()),_room=Mock())
        state = {'runs':{'run':self.row}}
        self.graph.ledger = SimpleNamespace(room_id='room',snapshot=lambda:{'state':state})
        with patch.object(subject,'current_run',return_value=self.view) as project:
            result = self.handle({'version':1,'action':'observe','payload':{'kind':'run','run_id':'run'}})
        self.assertEqual(result['current'], self.view)
        self.assertEqual(result['scope'], {'deployment_id':'deployment','room_id':'room','instance_id':'instance'})
        project.assert_called_once_with(state,'run',{'blocked':False})
        operation.require_current.assert_called_once()
        self.review.human_action.assert_not_called()

    def test_ui_hints_are_advisory_and_no_action_scope_is_borrowed(self):
        frame = {'version':1,'action':'observe','payload':{'kind':'run','run_id':'run'}}
        with self.connection.request(frame) as (received, session):
            self.assertFalse(session.allowed('request-changes'))
            result = subject.handle_native_human(self.graph, received, received['payload'], session,
                                                available_actions=('request-changes',))
            hints = {item['action']:item for item in result['actions']}
            self.assertTrue(hints['request-changes']['eligible'])
            self.assertTrue(hints['request-changes']['requires_fresh_authentication'])
            self.assertFalse(hints['reconcile-changes']['eligible'])
            denied = subject.handle_native_human(self.graph, received, received['payload'], session)
            self.assertFalse(any(hint['eligible'] for hint in denied['actions']))
            self.assertFalse(session.allowed('request-changes'))
        self.review.human_action.assert_not_called()
        self.review.human_eligibility.assert_not_called()

    def test_ui_lifecycle_replacement_and_other_run_denied(self):
        for payload in ({'kind':'lifecycle'}, {'kind':'replacement','participant_id':'pi'},
                        {'kind':'run','run_id':'other-run'}):
            with self.assertRaises(LedgerError):
                self.handle({'version':1,'action':'observe','payload':payload})
        self.observation.assert_not_called()

    def test_inspection_matches_original_request_without_execution(self):
        self.observation_patch.stop()
        operation = SimpleNamespace(prepare_manager_guard=lambda:nullcontext(),
            manager_action_guard=lambda *args:nullcontext({'blocked':False}),require_current=Mock())
        self.audit.observation = lambda:operation
        self.graph.owner = SimpleNamespace(supervisor=SimpleNamespace(_locked=lambda:nullcontext()),_room=Mock())
        import hashlib
        from uas.ledger import _json
        digest = hashlib.sha256(_json(self.value).encode()).hexdigest()
        def matched(operation_id, origin, *, authorize, matches):
            self.assertEqual(operation_id, self.value['operation_id'])
            self.assertTrue(authorize(origin,None))
            command = SimpleNamespace(kind='review.human-changes',run_id='run',generation=1,
                payload={'_manager':{'request_digest':digest,'human_origin':origin.canonical()}})
            self.assertTrue(matches(command))
            command.payload['_manager']['request_digest'] = 'b'*64
            self.assertFalse(matches(command))
            return {'confirmed':True}
        state = {**self.state,'review_comments':{'change-one':{'status':'confirmed','run_id':'run','generation':1}}}
        self.graph.ledger = SimpleNamespace(room_id='room',snapshot=lambda:{'state':state},matched_receipt=matched)
        frame = deepcopy(self.frame);frame['payload']['kind'] = 'inspect'
        with patch.object(subject,'current_run',return_value=self.view):
            result = self.handle(frame)
        self.assertEqual(result['outcome'],'confirmed')
        self.assertTrue(result['receipt']['read_only'])
        self.review.human_action.assert_not_called()
        self.review.human_eligibility.assert_not_called()

    def test_no_lifecycle_or_injected_payload_route(self):
        with self.connection.request(self.frame) as (frame, session):
            for modified, payload in [({**frame,'action':'stop'},frame['payload']),
                                      (frame,{'kind':'other'})]:
                with self.assertRaises(LedgerError):
                    subject.handle_native_human(self.graph,modified,payload,session)
        self.review.human_action.assert_not_called()

if __name__ == '__main__': unittest.main()
