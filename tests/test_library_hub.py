"""Actual kernel-authenticated Hub route + real Git service; no live deployment."""
from dataclasses import replace
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import library_support as support
import test_library_enqueue as enqueue_tests
import test_workstation_peer as peer_tests
from uas import library
from uas.context import FixtureRunTerminal
from uas.ledger import LedgerError, RoomLedger, Origin, Command, Event, Transition
from uas.library_enqueue import CaptureResult, EnqueueEndpoint
from uas.library_hub import LibraryHub
from uas.library_records import LibraryRecords
from uas.workstation_admission import AdmissionSeat


class ServiceFixture:
    make_scope = enqueue_tests.EnqueueTests.make_scope
    make_publisher = enqueue_tests.EnqueueTests.make_publisher
    head = enqueue_tests.EnqueueTests.head
    count = enqueue_tests.EnqueueTests.count
    mutate = enqueue_tests.EnqueueTests.mutate
    root = enqueue_tests.EnqueueTests.root
    root_bytes = enqueue_tests.EnqueueTests.root_bytes
    contents = enqueue_tests.EnqueueTests.contents

    def setup_service(self):
        enqueue_tests.EnqueueTests.setUp(self)
        self.endpoint = EnqueueEndpoint(self.publisher, settings=lambda: self.settings)
        self.calls = 0
        def contact(**kwargs):
            self.calls += 1
            self.assertFalse(self.ledger._connection().in_transaction)
            if hasattr(self, 'admissions'):
                self.assertFalse(getattr(self.admissions._authorization, 'depth', 0))
            return self.endpoint.contact(**kwargs)
        self.contact = contact
        self.owner = LibraryHub(self.ledger, room_id='alpha', project={
            'id': 'alpha', 'repository': 'acme/alpha', 'roots': {'reference': '/srv/alpha/reference'}},
            source_identity='1001', contact=contact, clock=lambda: support.AT)

    def envelope(self, command='capture-1', request='request-1', **changes):
        return {'id': command, 'kind': 'library.enqueue', 'request_id': request,
                'capture': support.value(body='PRIVATE_BODY_MARKER', title='Private title marker'), **changes}

    def privacy(self):
        maintained = json.dumps(self.ledger.snapshot()) + json.dumps(self.ledger.replay(0, limit=1000))
        for table in ('operations', 'events', 'room'):
            maintained += str([tuple(r) for r in self.ledger._connection().execute('SELECT * FROM '+table)])
        for marker in ('PRIVATE_BODY_MARKER', 'Private title marker'):
            self.assertNotIn(marker, maintained)
        for path in self.base.glob('hub.db*'):
            self.assertNotIn(b'PRIVATE_BODY_MARKER', path.read_bytes())


class HubOwnerTests(ServiceFixture, unittest.TestCase):
    def setUp(self):
        # The service setup needs the ledger only when contact actually occurs.
        self.setup_service()

    def setup_service(self):
        enqueue_tests.EnqueueTests.setUp(self)
        self.ledger = RoomLedger(self.base/'hub.db', 'alpha')
        self.addCleanup(self.ledger.close)
        self.endpoint = EnqueueEndpoint(self.publisher, settings=lambda: self.settings)
        self.calls = 0
        def contact(**kwargs):
            self.calls += 1
            self.assertFalse(self.ledger._connection().in_transaction)
            return self.endpoint.contact(**kwargs)
        self.owner = LibraryHub(self.ledger, room_id='alpha', project={
            'id': 'alpha', 'repository': 'acme/alpha', 'roots': {'reference': '/srv/alpha/reference'}},
            source_identity='1001', contact=contact, clock=lambda: support.AT)
        self.allowed = True
        self.origin = support.ORIGIN

    def submit(self, envelope=None, run='closed-run-1'):
        prepared = self.owner.prepare(envelope or self.envelope(), self.origin,
                                      authorize=lambda: self.allowed, run_id=run)
        result = self.owner.perform(prepared, current=lambda: self.allowed)
        return self.owner.finish(prepared, result, authorize=lambda: self.allowed)

    def test_real_service_exact_retry_and_new_actor_request_retry(self):
        first = self.submit()
        self.assertEqual(first['outcome'], 'DURABLY_QUEUED')
        self.assertEqual(self.submit(run='different-run'), first)
        self.assertEqual(self.calls, 1)
        self.origin = support.OTHER
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
            self.submit()
        again = self.submit(self.envelope('capture-2'))
        self.assertEqual(again, first)
        self.assertEqual(self.count(), 2)
        with LibraryRecords(self.records, 'deployment-1') as records:
            submission = records.submission(self.scope.project_identity, 'request-1')
        self.assertEqual(submission['origin']['actor_id'], 'actor-alpha')
        self.assertEqual(submission['origin']['run_id'], 'closed-run-1')
        self.assertEqual(submission['attempts'][1]['scope']['actor_id'], 'actor-beta')
        self.privacy()

    def test_distinct_rooms_shared_service_same_command_ids_do_not_collide(self):
        from uas.library_registration import Registrar
        from test_library_git import git
        beta = self.make_scope('beta','acme/beta','2002')
        Registrar(self.publisher,current_scope=lambda:beta).register(
            library.action(beta,self.settings,kind='register',operation_id='register-beta',
                           request_id='register-beta',payload={},at=support.AT),self.settings)
        beta_ledger = RoomLedger(self.base/'beta-hub.db','beta-room')
        self.addCleanup(beta_ledger.close)
        beta_owner = LibraryHub(beta_ledger,room_id='beta-room',project={
            'id':'beta','repository':'acme/beta','roots':{'reference':'/srv/beta/reference'}},
            source_identity='2002',contact=self.endpoint.contact,clock=lambda:support.AT)
        first = self.submit()
        prepared = beta_owner.prepare(self.envelope(),self.origin,authorize=lambda:True)
        result = beta_owner.perform(prepared,current=lambda:True)
        second = beta_owner.finish(prepared,result,authorize=lambda:True)
        self.assertEqual(first['outcome'],'DURABLY_QUEUED')
        self.assertEqual(second['outcome'],'DURABLY_QUEUED')
        self.assertNotEqual(first['queue_id'],second['queue_id'])
        self.assertEqual(self.count(),4)
        text = git(self.target,'show',self.head()+':projects/github.com/acme/beta/'+second['path'])
        self.assertIn('PRIVATE_BODY_MARKER',text)
        self.assertEqual(beta_owner.perform(beta_owner.prepare(self.envelope(),self.origin,
            authorize=lambda:True),current=lambda:True),second)
        self.assertEqual(self.count(),4)

    def test_changed_body_or_request_exact_command_conflicts(self):
        self.submit()
        changed = self.envelope(); changed['capture']['body'] = 'new'
        for envelope in (changed, self.envelope(request='new-request')):
            with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
                self.submit(envelope)
        self.assertEqual(self.calls, 1)

    def test_current_revocation_prevents_historical_disclosure(self):
        self.submit(); self.allowed = False
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.submit()
        self.assertEqual(self.calls, 1)

    def test_no_capability_rejected_before_reservation(self):
        self.origin = replace(support.ORIGIN, capabilities=('read',))
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            self.submit()
        self.assertEqual(self.calls, 0)
        self.assertEqual(self.ledger.snapshot()['room_seq'], 0)

    def test_claimed_authority_or_paths_refused(self):
        for field in ('project_id','actor_id','path','queue_id','frontmatter','status','generated'):
            packet = self.envelope(); packet['capture'][field] = 'other'
            with self.assertRaises(LedgerError): self.submit(packet)
        for field in ('project_id','run_id','actor_id','target','generation'):
            with self.assertRaisesRegex(LedgerError, 'INVALID_LIBRARY_ENVELOPE'):
                self.submit(self.envelope(**{field:'other'}))
        self.assertEqual(self.calls, 0)
        self.privacy()

    def test_service_loss_after_publish_is_uncertain_and_new_command_recovers(self):
        contact = self.owner.contact
        def lost(**kwargs):
            contact(**kwargs)
            raise OSError('PRIVATE_BODY_MARKER')
        self.owner.contact = lost
        first = self.submit()
        self.assertEqual(first['outcome'], 'NOT_DURABLE')
        self.assertTrue(first['retryable'])
        self.assertEqual(self.count(), 2)
        self.owner.contact = contact
        self.assertEqual(self.submit(), first)  # Immutable exact outcome.
        self.assertEqual(self.submit(self.envelope('recover'))['outcome'], 'DURABLY_QUEUED')
        self.assertEqual(self.count(), 2)
        self.privacy()

    def test_crash_after_reservation_and_after_contact_reuses_original_time_run(self):
        prepared = self.owner.prepare(self.envelope(), self.origin, authorize=lambda: True, run_id='original-run')
        result = self.owner.perform(prepared, current=lambda: True)
        self.assertEqual(result['outcome'], 'DURABLY_QUEUED')
        self.owner.clock = lambda: '2026-11-01T00:00:00+00:00'
        again = self.submit(run='new-run')
        self.assertEqual(again, result)
        self.assertIn('Originating Run: original-run', self.contents(result['path']))
        self.assertEqual(self.count(), 2)

    def test_storage_failure_after_service_never_claims_durable(self):
        prepared = self.owner.prepare(self.envelope(), self.origin, authorize=lambda: True)
        result = self.owner.perform(prepared, current=lambda: True)
        with patch.object(self.ledger, 'apply', side_effect=LedgerError('STORAGE_ERROR')):
            response = self.owner.finish(prepared, result, authorize=lambda: True)
        self.assertEqual(response['reason'], 'HUB_RECEIPT_UNAVAILABLE')
        self.assertEqual(self.submit()['outcome'], 'DURABLY_QUEUED')
        self.assertEqual(self.count(), 2)

    def test_invalid_service_result_is_not_retained_or_disclosed(self):
        bad = [None, {'outcome':'DURABLY_QUEUED'},
               CaptureResult('REJECTED','request-1','PRIVATE_BODY_MARKER content',False),
               CaptureResult('DURABLY_QUEUED','request-1',None,False,'a'*64,'../../secret','b'*40),
               CaptureResult('REJECTED','wrong-request','NO',False)]
        for i, result in enumerate(bad):
            self.owner.contact = lambda **_: result
            self.assertEqual(self.submit(self.envelope('bad-'+str(i)))['outcome'], 'NOT_DURABLE')
        self.privacy()

    def test_room_namespace_collision_never_contacts_service(self):
        self.ledger.apply(Command('capture-1','other','alpha',None,{}), self.origin,
            authorize=lambda *_:True, decide=lambda state,_:Transition(state,(Event('other',{}),),{}))
        with self.assertRaisesRegex(LedgerError,'ID_CONFLICT'): self.submit()
        self.assertEqual(self.calls,0)

    def test_deterministic_typed_service_refusal_is_recorded_without_body(self):
        packet = self.envelope(); packet['capture']['type'] = 'invalid'
        result = self.submit(packet)
        self.assertEqual(result['outcome'],'REJECTED')
        self.assertEqual(result['reason'],'UNSAFE_CAPTURE_TYPE')
        self.assertEqual(self.submit(packet),result)
        self.privacy()


class AuthenticatedHubTests(ServiceFixture, unittest.TestCase):
    setUpClass = peer_tests.AdmittedPeerTests.setUpClass
    exchange = peer_tests.AdmittedPeerTests.exchange

    def setUp(self):
        with patch('test_workstation_peer.AdmissionSeat', side_effect=lambda *args:
                   replace(AdmissionSeat(*args), capabilities=(('peer-traffic',) if
                       self._testMethodName == 'test_actual_route_without_enqueue_capability' else
                       ('peer-traffic','library:enqueue')))):
            peer_tests.AdmittedPeerTests.setUp(self)
        ServiceFixture.setup_service(self)
        self.dispatcher.attach_library(self.owner)

    def packet(self, command='capture-1', **changes):
        return {'request_id':'a'*32,'envelope':self.envelope(command, **changes)}

    def test_actual_route_without_enqueue_capability(self):
        result = self.exchange(0,self.packet())
        self.assertEqual(result['error'],'FORBIDDEN')
        self.assertEqual(self.calls,0)
        self.privacy()

    def test_actual_kernel_route_identity_and_privacy(self):
        result = self.exchange(0,self.packet())
        self.assertTrue(result['ok'],result)
        receipt = result['receipt']
        self.assertEqual(receipt['outcome'],'DURABLY_QUEUED')
        self.assertIn('Submission Actor: actor-a',self.contents(receipt['path']))
        self.assertNotIn('actor-b',self.contents(receipt['path']))
        self.assertEqual(self.exchange(0,self.packet()),result)
        conflict = self.exchange(1,self.packet())
        self.assertEqual(conflict['error'],'ID_CONFLICT')
        retry = self.exchange(1,self.packet('other-command'))
        self.assertEqual(retry['receipt'],receipt)
        self.assertEqual(self.count(),2)
        self.privacy()

    def test_closed_run_remains_valid_and_failure_does_not_gate_close(self):
        self.owner.contact = lambda **_: (_ for _ in ()).throw(OSError('unavailable'))
        self.assertEqual(self.exchange(0,self.packet())['receipt']['outcome'],'NOT_DURABLE')
        self.hub.contexts.close_run('close-run','run-1',FixtureRunTerminal.COMPLETED)
        self.owner.contact = self.contact
        receipt = self.exchange(0,self.packet('after-close'))['receipt']
        self.assertEqual(receipt['outcome'],'DURABLY_QUEUED')
        self.assertIn('Originating Run: run-1',self.contents(receipt['path']))

    def test_service_call_does_not_hold_admission_or_ledger_transaction(self):
        self.assertTrue(self.exchange(0,self.packet())['ok'])
        self.assertEqual(self.calls,1)  # contact asserts both boundaries.

    def test_revocation_during_service_blocks_disclosure_and_repeat(self):
        contact = self.owner.contact
        def revoke(**kwargs):
            result = contact(**kwargs)
            self.admissions.revoke(self.operations[0])
            return result
        self.owner.contact = revoke
        self.children[0].send(self.packet())
        response = self.dispatcher.receive(self.operations[0])
        # Revocation closes the channel; a refused result is not delivery proof.
        self.assertFalse(response['ok'])
        self.assertEqual(response['error'],'AUTHORITY_REVOKED')
        self.assertEqual(self.count(),2)
        self.privacy()

    def test_payload_cannot_select_other_project_or_actor(self):
        for key in ('project_id','actor_id','path'):
            packet=self.packet('bad-'+key); packet['envelope']['capture'][key]='elsewhere'
            self.assertFalse(self.exchange(0,packet)['ok'])
        self.assertEqual(self.calls,0)

    def test_distinct_bound_project_writes_only_its_registered_bundle(self):
        from uas.library_registration import Registrar
        from test_library_git import git
        beta = self.make_scope('beta','acme/beta','2002')
        Registrar(self.publisher,current_scope=lambda:beta).register(
            library.action(beta,self.settings,kind='register',operation_id='register-beta',
                           request_id='register-beta',payload={},at=support.AT),self.settings)
        # Separate actual admitted Room fixture with its trusted binding changed
        # at construction, never from a Participant packet.
        beta_owner = LibraryHub(self.ledger,room_id='alpha',project={
            'id':'beta','repository':'acme/beta','roots':{'reference':'/srv/beta/reference'}},
            source_identity='2002',contact=self.contact,clock=lambda:support.AT)
        self.dispatcher.library = beta_owner
        result = self.exchange(0,self.packet())['receipt']
        self.assertEqual(result['outcome'],'DURABLY_QUEUED')
        text = git(self.target,'show',self.head()+':projects/github.com/acme/beta/'+result['path'])
        self.assertIn('PRIVATE_BODY_MARKER',text)
        alpha = git(self.target,'ls-tree','-r','--name-only',self.head(),'projects/github.com/acme/alpha/pending')
        self.assertNotIn(result['queue_id'],alpha)
        event = [e for e in self.ledger.replay(0,limit=1000) if e['kind']=='library.enqueue.reserved'][0]
        self.assertEqual(event['target'],'beta')
        self.privacy()

    def test_missing_route_does_not_fall_through_generic_body_persistence(self):
        self.dispatcher.library = None
        response=self.exchange(0,self.packet())
        self.assertEqual(response['error'],'LIBRARY_UNAVAILABLE')
        self.privacy()
