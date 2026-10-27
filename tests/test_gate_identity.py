"""Pure canonical contribution and actual adapter methods; no native execution."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from uas.gate_identity import ContributionOwner, AdmittedGateIdentity
from uas.gate_evaluation import GateRoomBinding
from uas.gate_hub import identity_fact
from uas.git_provenance import GitProvenance, parse_commit
from uas.ledger import RoomLedger, Command, Origin, Event, Transition, LedgerError
from uas.workstation_peer import AdmittedPeerDispatcher
from uas.kernel_origin import OriginDenied
from test_git_provenance import raw_commit


def origin(actor='alice', incarnation='first'):
    return Origin(actor, 'seat-' + actor, incarnation, 'epoch-' + incarnation, ('peer-traffic', 'review'))


class ContributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = RoomLedger(self.root / 'room.db', 'room')
        self.addCleanup(self.ledger.close)
        self.binding = GateRoomBinding('room', 'instance', 'project', 'owner/repo', 128 << 20)
        self.run = {'run_id': 'run', 'generation': 1, 'status': 'ACTIVE',
                    'project_id': 'project', 'repository': 'owner/repo'}
        self.seed('seed', self.run)
        self.owner = ContributionOwner(self.ledger, self.binding)
        self.git = GitProvenance(self.root / 'git.db', 'room', 'project')
        self.addCleanup(self.git.close)
        raw = raw_commit(); self.oid = parse_commit(raw).oid
        self.git.anchor_source('owner/repo', self.oid, raw, contributors=['builder'])

    def seed(self, op, run):
        def decide(state, _):
            state['runs'] = {'run': deepcopy(run)}
            return Transition(state, (Event('seed', {}),), {})
        self.ledger.apply(Command(op, 'seed', 'run', None, {}), origin(), authorize=lambda *_: True, decide=decide)

    def envelope(self, op='edit', kind='direct-edit', source=None, generation=1):
        return {'id': op, 'kind': 'contribution', 'run_id': 'run', 'generation': generation,
                'payload': {'kind': kind, 'digest': 'a' * 64, 'source_report': source}}

    def submit(self, envelope=None, actor='alice', incarnation='first', allowed=True):
        return self.owner.submit(envelope or self.envelope(), origin=origin(actor, incarnation), authorize=lambda: allowed)

    def test_positive_report_is_durable_and_exact_retry_deduplicates(self):
        first = self.submit(); self.assertEqual(first, self.submit())
        self.assertEqual(['alice'], self.owner.known(self.run)['contributors'])
        self.ledger.close(); self.ledger = RoomLedger(self.root / 'room.db', 'room')
        self.addCleanup(self.ledger.close); self.owner = ContributionOwner(self.ledger, self.binding)
        self.assertEqual(['alice'], self.owner.known(self.run)['contributors'])

    def test_no_claimed_actor_or_clean_or_withdraw(self):
        for extra in ({'actor_id': 'reviewer'}, {'clean': True}):
            row = self.envelope(); row['payload'].update(extra)
            with self.assertRaises(LedgerError): self.submit(row)
        row = self.envelope(); row['payload']['kind'] = 'withdraw'
        with self.assertRaises(LedgerError): self.submit(row)
        self.assertEqual([], self.owner.known(self.run)['contributors'])

    def test_epoch_reset_and_generation_do_not_clear_history(self):
        self.submit(); self.submit(self.envelope('second'), incarnation='replacement')
        self.run['generation'] = 2; self.seed('new-generation', self.run)
        self.assertEqual(['alice'], self.owner.known(self.run)['contributors'])

    def test_adopted_exact_patch_records_source_and_adopter(self):
        self.submit(self.envelope('patch', 'patch'))
        self.assertEqual([], self.owner.known(self.run)['contributors'])
        self.submit(self.envelope('adopt', 'adopted-patch', 'patch'), actor='bob')
        self.assertEqual(['alice', 'bob'], self.owner.known(self.run)['contributors'])

    def test_unknown_or_mismatched_patch_refused(self):
        with self.assertRaises(LedgerError): self.submit(self.envelope('adopt', 'adopted-patch', 'missing'))
        self.submit(self.envelope('patch', 'patch'))
        row = self.envelope('adopt', 'adopted-patch', 'patch'); row['payload']['digest'] = 'b' * 64
        with self.assertRaises(LedgerError): self.submit(row)

    def test_scope_and_current_authority_required_even_retry(self):
        self.submit()
        with self.assertRaises(LedgerError): self.submit(allowed=False)
        with self.assertRaises(LedgerError): self.submit(self.envelope('stale', generation=2))
        self.assertEqual(['alice'], self.owner.known(self.run)['contributors'])

    def test_git_unknown_head_is_not_clean(self):
        with self.assertRaises(LedgerError): self.git.known_contribution_snapshot({'run_id':'run','generation':1}, 'owner/repo', 'f'*40)
        fact = self.git.known_contribution_snapshot({'run_id':'run','generation':1}, 'owner/repo', self.oid)
        self.assertEqual(['builder'], fact['contributors']); self.assertEqual('read', fact['history_status'])

    def test_actual_adapter_unions_controlled_and_positive_records(self):
        dispatcher = object.__new__(AdmittedPeerDispatcher)
        dispatcher.hub = SimpleNamespace(ledger=self.ledger)
        fact = {'actor_id':'reviewer','kind':'participant','active':True,'authority_epoch':'epoch','capabilities':['review']}
        adapter = AdmittedGateIdentity(dispatcher, self.owner, self.git)
        with patch.object(dispatcher, 'actor_authority', return_value=fact):
            before = adapter(self.run, 'reviewer', self.oid)
            self.submit(actor='reviewer')
            after = adapter(self.run, 'reviewer', self.oid)
        self.assertEqual(['builder'], before['contributors'])
        self.assertEqual(['builder','reviewer'], after['contributors'])
        self.assertNotEqual(before['contribution_version'], after['contribution_version'])
        self.assertEqual(after, identity_fact(after, 'reviewer'))

    def test_read_failure_and_legacy_complete_flag_never_qualify(self):
        dispatcher = object.__new__(AdmittedPeerDispatcher); dispatcher.hub = SimpleNamespace(ledger=self.ledger)
        adapter = AdmittedGateIdentity(dispatcher, self.owner, self.git)
        with patch.object(dispatcher, 'actor_authority', side_effect=OriginDenied('fenced')):
            with self.assertRaises(OriginDenied): adapter(self.run, 'reviewer', self.oid)
        with self.assertRaises(LedgerError): identity_fact({'complete':True}, 'reviewer')

    def test_dispatcher_routes_positive_report_using_derived_origin(self):
        dispatcher = object.__new__(AdmittedPeerDispatcher)
        dispatcher.contributions = self.owner; dispatcher._connections = {'operation': object()}
        dispatcher.hub = SimpleNamespace(_current=lambda _: True)
        dispatcher.admissions = SimpleNamespace(recheck=lambda *_: True)
        with patch.object(dispatcher, '_origin', return_value=origin('bob')):
            dispatcher._submit('operation', object(), object(), self.envelope())
        self.assertEqual(['bob'], self.owner.known(self.run)['contributors'])

    def test_admission_identity_requires_existing_fence(self):
        dispatcher = object.__new__(AdmittedPeerDispatcher)
        dispatcher.admissions = SimpleNamespace(_authorization=SimpleNamespace(depth=0))
        with self.assertRaises(OriginDenied): dispatcher.actor_authority('reviewer')

    def test_controlled_mutation_and_unknown_abort_taint_survive_generation(self):
        self.git.record_mutation('mutate', {'run_id':'run','generation':1}, origin('bob'),
                                 'commit', 'b'*64, authorize=lambda *_: True)
        fact = self.git.known_contribution_snapshot({'run_id':'run','generation':2}, 'owner/repo', self.oid)
        self.assertEqual(['bob','builder'], fact['contributors'])

    def test_unrelated_run_does_not_taint_subject(self):
        self.git.record_mutation('mutate', {'run_id':'other','generation':1}, origin('bob'),
                                 'commit', 'b'*64, authorize=lambda *_: True)
        self.assertEqual(['builder'], self.git.known_contribution_snapshot(
            {'run_id':'run','generation':1}, 'owner/repo', self.oid)['contributors'])

    def test_closed_git_history_is_unavailable_not_empty(self):
        self.git.close()
        with self.assertRaises(LedgerError): self.git.known_contribution_snapshot(
            {'run_id':'run','generation':1}, 'owner/repo', self.oid)

    def test_changed_retry_payload_conflicts_without_new_taint(self):
        self.submit(); row = self.envelope(); row['payload']['digest'] = 'c'*64
        with self.assertRaises(LedgerError) as raised: self.submit(row)
        self.assertEqual('ID_CONFLICT', raised.exception.code)
        self.assertEqual(['alice'], self.owner.known(self.run)['contributors'])

    def test_current_authority_reads_exact_binding_without_sibling_profile(self):
        dispatcher = object.__new__(AdmittedPeerDispatcher)
        first, second = object(), object()
        dispatcher._connections = {'one': first, 'two': second}
        seat = SimpleNamespace(actor_id='reviewer')
        a, b = SimpleNamespace(seat=seat), SimpleNamespace(seat=seat)
        dispatcher.admissions = SimpleNamespace(_authorization=SimpleNamespace(depth=1),
            seats={'one':seat, 'two':seat}, _active={'one':(None,a),'two':(None,b)},
            _check_current=lambda operation: (None, a if operation == 'one' else b), controller='controller')
        dispatcher.hub = SimpleNamespace(_current=lambda _: True)
        def derived(binding):
            return Origin('reviewer', 'one' if binding is a else 'two', 'instance', 'epoch-a' if binding is a else 'epoch-b',
                          ('review','peer-traffic') if binding is a else ('peer-traffic',))
        with patch.object(dispatcher, '_origin', side_effect=derived):
            with self.assertRaises(LedgerError): dispatcher.actor_authority('reviewer')
            fact = dispatcher.actor_authority('reviewer', 'epoch-a')
            self.assertEqual(['peer-traffic', 'review'], fact['capabilities'])
            self.assertEqual('epoch-a', fact['authority_epoch'])
            dispatcher.admissions._active.clear()
            after = dispatcher.actor_authority('reviewer')
        self.assertFalse(after['active']); self.assertNotEqual(fact['authority_epoch'], after['authority_epoch'])

    def test_actual_gate_adapter_allows_eligible_then_stales_on_known_edit(self):
        from test_gate_decisions import GateDecisionTests, ORIGIN
        harness = GateDecisionTests('test_pass_is_decided_not_mechanically_verified')
        harness.setUp(); self.addCleanup(harness.doCleanups)
        provenance = GitProvenance(self.root / 'gate-git.db', 'alpha', 'project-alpha')
        self.addCleanup(provenance.close)
        raw = raw_commit(); oid = parse_commit(raw).oid
        provenance.anchor_source('example/project-alpha', oid, raw, contributors=['implementer'])
        harness.control.source['head_sha'] = oid
        owner = ContributionOwner(harness.ledger, harness.hub.binding)
        dispatcher = object.__new__(AdmittedPeerDispatcher); dispatcher.hub = SimpleNamespace(ledger=harness.ledger)
        adapter = AdmittedGateIdentity(dispatcher, owner, provenance)
        harness.hub.identity = adapter
        def authority(actor, version):
            self.assertEqual(ORIGIN.authority_version, version)
            return {'actor_id':actor, 'kind':'participant','active':True,
                    'authority_epoch':version, 'capabilities':['review']}
        with patch.object(dispatcher, 'actor_authority', side_effect=authority):
            self.assertEqual('passed', harness.submit()['result']['verdict'])
            self.assertEqual('passed', harness.projection()['state'])
            row = self.envelope(); row['run_id'] = 'run-one'
            owner.submit(row, origin=Origin('reviewer', 'review-seat', 'review-session',
                         'epoch-1', ('peer-traffic','review')), authorize=lambda: True)
            self.assertEqual('stale', harness.projection()['state'])

    def test_git_fence_prevents_same_owner_and_other_connection_mutations(self):
        import sqlite3
        other = sqlite3.connect(self.root / 'git.db', timeout=0, isolation_level=None)
        self.addCleanup(other.close)
        with self.git.history_fence():
            first = self.git.known_contribution_snapshot({'run_id':'run','generation':1}, 'owner/repo', self.oid)
            with self.assertRaises(LedgerError) as caught:
                self.git.record_mutation('mutate', {'run_id':'run','generation':1}, origin('bob'),
                                         'commit', 'b'*64, authorize=lambda: True)
            self.assertEqual('GIT_HISTORY_FENCED', caught.exception.code)
            with self.assertRaises(sqlite3.OperationalError): other.execute('BEGIN IMMEDIATE')
            second = self.git.known_contribution_snapshot({'run_id':'run','generation':1}, 'owner/repo', self.oid)
            self.assertEqual(first, second); self.assertTrue(self.git._connection().in_transaction)
        self.git.record_mutation('mutate', {'run_id':'run','generation':1}, origin('bob'),
                                 'commit', 'b'*64, authorize=lambda: True)
        self.assertNotEqual(first, self.git.known_contribution_snapshot(
            {'run_id':'run','generation':1}, 'owner/repo', self.oid))

    def test_known_positive_report_between_view_and_consume_is_stale(self):
        from test_gate_decisions import GateDecisionTests, ORIGIN
        from uas.gate_hub import require_operation_gates
        harness = GateDecisionTests('test_pass_is_decided_not_mechanically_verified')
        harness.setUp(); self.addCleanup(harness.doCleanups)
        harness.submit()
        view = harness.hub.operation_gates('run-one', 1, 'complete', origin=ORIGIN)
        owner = ContributionOwner(harness.ledger, harness.hub.binding)
        row = self.envelope(); row['run_id'] = 'run-one'
        owner.submit(row, origin=Origin('reviewer','review-seat','review-session','epoch-1',('peer-traffic',)), authorize=lambda:True)
        def consume(state, _):
            require_operation_gates(state, view)
            state['consumed'] = True
            return Transition(state, (Event('consumed', {}),), {})
        with self.assertRaises(LedgerError) as caught:
            harness.ledger.apply(Command('consume','consume','run-one',1,{}), ORIGIN,
                                 authorize=lambda *_:True, decide=consume)
        self.assertEqual('GATE_OPERATION_STALE', caught.exception.code)
        self.assertNotIn('consumed', harness.ledger.snapshot()['state'])

    def test_actual_adapter_requires_git_and_admission_fences(self):
        from contextlib import contextmanager
        dispatcher = object.__new__(AdmittedPeerDispatcher); dispatcher.hub = SimpleNamespace(ledger=self.ledger)
        authorization = SimpleNamespace(depth=0)
        @contextmanager
        def authorize(operation, record):
            self.assertEqual('operation', operation)
            authorization.depth += 1
            try: yield
            finally: authorization.depth -= 1
        dispatcher.admissions = SimpleNamespace(_authorization=authorization, authorize=authorize)
        adapter = AdmittedGateIdentity(dispatcher, self.owner, self.git)
        with self.assertRaises(LedgerError): adapter.require_operation_fence()
        with adapter.operation_fence('operation'):
            adapter.require_operation_fence()
            self.assertTrue(self.git._connection().in_transaction)
        with self.assertRaises(LedgerError): adapter.require_operation_fence()
