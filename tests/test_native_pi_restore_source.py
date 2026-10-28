"""Finite source-only restore cuts. Run with run_native_pi_restore_source.py guards.

Typed retained-owner doubles control every native boundary. No native execution,
process death, socket, thread, permission, provider or deployment evidence.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import select
import sqlite3
import tempfile
import threading
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas.kernel_origin import HeldOrigin, OriginDenied
from uas.ledger import LedgerError, Origin, RoomLedger
from uas.manager_actions import HumanSession
from uas.native_pi_recipe import NativePiRecipe, NativePiResume
from uas.native_pi_restore import NativePiSameRunRestore, held_exit
from uas.native_pi_rebind import NativePiRebind
from uas.native_run_admission import NativeRunAdmission, NativeHumanRunRequest
from uas.native_reviewer_recruitment import NativeReviewerRecruitment
from uas.native_review_host import NativeReviewHost
from uas.native_host_forge import NativePiHostForge, NativeHostForge
from uas.native_session import SessionBudget
from uas.native_session_driver import NativeSessionDriver
from uas.pi_runtime import FixturePiRpcReceiver, NativeUnavailable
from uas.peer import Readiness, FixturePeerHub, FixtureParticipant, WorkRequest, RequestCommand, digest
from uas.workstation_control import SupervisorAdmission
from uas.workstation_exec import ExecLaunch


def origin(number):
    value = object.__new__(HeldOrigin)
    value.pidfd = number; value.identity = (9, number)
    value.credentials = (number, 165532, 165532); value.revoked = False
    return value


def recipe(scope, resume=None):
    value = object.__new__(NativePiRecipe)
    value._scope_json = json.dumps(scope); value.resume = resume
    value.checkout = '/owned/checkout'; value.sessions = '/runtime/seat-a/contexts/1/sessions'
    value.manifest_digest = 'a' * 64; value.git_profile = value.gate_profile = None
    value.validate_container = Mock(); return value


class NativePiRestoreSourceTests(unittest.TestCase):
    def fixture(self, *, git=False):
        events = []; owner = object.__new__(NativeRunAdmission)
        owner._owner_thread = threading.get_ident(); owner._room = Mock(); owner.deployment = 'deployment'
        human = Origin('human', 'human', 'human-session', 'auth', ('human-open-run',))
        session = HumanSession('deployment', 'room', 'instance', 'manager', human,
                               lambda *_: True, lambda: True)
        request = NativeHumanRunRequest('open', 1, 'pi', session)
        run = owner.run_id('open')
        scope = {'room_id': 'room', 'participant_id': 'pi', 'run_id': run, 'generation': 1, 'context_generation': 1}
        state = {'runs': {run: {'run_id': run, 'generation': 1, 'status': 'ACTIVE', 'participant_id': 'pi',
            'actor_id': 'actor', 'checkout': {'path': '/owned/checkout'}, 'admission_origin': human.canonical(),
            'implementation_request': 'same-work-request'}},
            'run_admissions': {run: {'status': 'ACTIVE', 'participant_id': 'pi'}},
            'fixture_context': {'participants': {'pi': {'status': 'READY', 'context_generation': 1,
                'bound_run': {'run_id': run, 'generation': 1}, 'reserved_run': None, 'reset': None}}}}
        owner.ledger = N(room_id='room', snapshot=lambda: {'state': deepcopy(state)})
        cap = N(require=Mock()); locked = [False]
        @contextmanager
        def fence():
            self.assertFalse(locked[0]); locked[0] = True
            try: yield cap
            finally: locked[0] = False
        owner.supervisor = N(_locked=fence)
        budget = SessionBudget(180)
        launcher = N(budget=budget, started={}, resources={'instance': 'instance',
            'supervisor_directory': '/private', 'pi_manifest_path': '/private/pi.json', 'peer_path': '/private/peer'},
            plan=N(require_unchanged=Mock(), config_text='{}', room={'id': 'room', 'state_root': '/runtime'},
                   installation={'pi_manifest': {'sha256': 'a' * 64}}),
            hub_origin=origin(90), control=object(), controller='controller', stack=ExitStack(), admissions=[],
            control_lock=object(), engine=object(), endpoint=object(), listener=object(), mounts=())
        self.addCleanup(launcher.stack.close); owner.launcher = launcher
        old = object.__new__(SupervisorAdmission); root = object.__new__(ExecLaunch)
        old.launch = root; old.seat = N(participant_id='pi', actor_id='actor')
        old.hub_origin = launcher.hub_origin; old.control = launcher.control; old.controller = launcher.controller
        root.origin = origin(100); root.native_recipe = recipe(scope); root.incarnation = 'old-incarnation'
        root._native_readiness = {'scope': scope, 'profile_digest': 'a' * 64, 'incarnation': root.incarnation,
            'native': {'session_id': 'same-session', 'session_file': root.native_recipe.sessions + '/prior.jsonl',
                       'runtime_id': 'old-runtime', 'source': 'native-empty-session-and-no-pending-messages'}}
        receiver = object.__new__(FixturePiRpcReceiver); root.native_receiver = receiver
        receiver.scope = scope; receiver._owns_process = False
        receiver._binding = {'runtime_id': 'old-runtime', 'session_id': 'same-session'}
        def query(sql, params=()):
            if sql == 'PRAGMA database_list': return N(fetchall=lambda: [(0, 'main', '/private/run-' + run + '-pi.db')])
            if sql.startswith('SELECT scope'): return N(fetchone=lambda: (json.dumps(scope),))
            return N(fetchone=lambda: (0,))
        receiver.db = N(execute=query); receiver.close = lambda: events.append('receiver-close')
        root.close_transport = lambda: events.append('old-transport-close')
        client = object(); ingress = object.__new__(NativePiHostForge)
        ingress.client = client; ingress.origin = Origin('actor', 'pi', root.incarnation, 'old-authority', ('implement',))
        ingress.binding = N(epoch=4, operation_id='old-operation'); ingress._current = Mock()
        old.forge_service = ingress; launcher.forge_broker = N(client=client)
        def revoke(**_):
            self.assertFalse(locked[0]); events.append('revoke'); root.origin.revoked = True
            return {'installed': False, 'state': 'revoked'}
        old.revoke = revoke; launcher.started['pi'] = old
        launcher.exec_seat = launcher.admission_seat = old.seat
        recruitment = object.__new__(NativeReviewerRecruitment)
        recruitment.owner = owner; recruitment.pi = old
        claude = object.__new__(NativeHostForge); claude._current = Mock(return_value=True)
        claude.origin = Origin('reviewer', 'claude', 'claude-incarnation', 'claude-authority', ('review',))
        recruitment.root = N(forge_service=claude, origin=origin(200))
        host = object.__new__(NativeReviewHost); recruitment.root.review_host = host
        identity = N(ingresses=(ingress, claude), active=None, seat_current=Mock())
        host.identity = identity; host.gate_workflow = None
        host.sources = N(identity=identity); host.gates = N(identity=identity, unknown={'held-gate': object()})
        host.reviews = N(identity=identity, unknown={'held-review': object()})
        ingress.review_host = host
        operations = None
        if git:
            from uas.native_git_operations import NativeGitOperations
            from uas.git_supervisor import GitSupervisor
            from uas.git_process import GitChildAuthority, GitSeat
            operations = object.__new__(NativeGitOperations)
            operations.owner = owner; operations.reviewer = recruitment; operations.closed = False
            operations._capability = None; operations.pi = old; operations.claude = recruitment.root
            operations.identity = identity; operations.ingresses = identity.ingresses
            operations.processes = (root.origin, recruitment.root.origin); operations.scope = scope
            operations.resources = N(profile=object()); root.native_recipe.git_profile = operations.resources.profile
            service = object.__new__(GitSupervisor); operations.service = service
            service.closed = False; service.native_resources = operations.resources
            children = object.__new__(GitChildAuthority); service.children = children; children.view = object()
            seat = GitSeat(ingress.origin, root.origin, lambda: False, ((1, 2), (3, 4)), 2)
            service.seats = {'pi': (seat, object())}; children.seats = {root.origin.identity: seat}
            service.coordinator = N(unknown={'original-operation': object()}); service.request_listener = object()
        value = NativePiSameRunRestore(owner, recruitment, request, budget, git_operations=operations)
        return N(value=value, owner=owner, old=old, root=root, receiver=receiver, state=state, scope=scope,
                 launcher=launcher, request=request, budget=budget, recruitment=recruitment, host=host,
                 events=events, locked=locked, git=operations, cap=cap)

    def effects(self, c, *, fail=None, proof_change=None):
        stack = ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch('uas.native_pi_restore.held_exit', return_value=True))
        stack.enter_context(patch('uas.native_pi_restore.alive', return_value=True))
        def make_recipe(*args, **kw):
            self.assertEqual(kw['scope'], c.scope); self.assertEqual(kw['checkout'], '/owned/checkout')
            self.assertEqual(kw['resume'].session_id, 'same-session')
            result = recipe(kw['scope'], kw['resume']); result.git_profile = c.root.native_recipe.git_profile
            return result
        stack.enter_context(patch.object(NativePiRecipe, 'from_configuration', side_effect=make_recipe))
        def init(launch, engine, seat, endpoint, journal, **kw):
            self.assertIn('-restore-e5.json', str(journal)); c.events.append('new-intent')
            launch.native_recipe = kw['native_recipe']; launch.origin = origin(101); launch.incarnation = 'new-incarnation'
            launch.seat = seat; launch._native_readiness = None
        def launch(held, listener, *, authorize):
            self.assertFalse(c.locked[0]); authorize(); c.events.append('launch')
            if fail == 'launch': raise TimeoutError('unknown launch')
        def attach(held, **kw):
            self.assertFalse(c.locked[0]); c.events.append('resume-proof')
            self.assertEqual(str(kw['journal']), '/private/run-' + c.scope['run_id'] + '-pi.db')
            self.assertEqual(kw['preceding_runtime_id'], 'old-runtime')
            native = object.__new__(FixturePiRpcReceiver)
            native.prepare_admission_observation = lambda: c.events.append('safe-observe') or object()
            native.discard_admission_observation = Mock()
            def validate(sample, *, consume):
                self.assertTrue(c.locked[0]); self.assertTrue(consume); c.events.append('safe-consume')
                if fail == 'safe': raise NativeUnavailable('changed sample')
                return Readiness.SAFE
            native.validate_admission_observation = validate; held.native_receiver = native
        def admission(new, launch, seat, control, **kw):
            new.launch = launch; new.seat = seat; new._current = Mock()
            new.revoke = lambda **_: c.events.append('new-revoke')
        def admit(new, operation, *, epoch):
            self.assertFalse(c.locked[0]); c.events.append('admit'); self.assertEqual(epoch, 5)
            if fail == 'admit': raise TimeoutError('unknown ADMIT')
        def ingress(new, client):
            value = object.__new__(NativePiHostForge); value.client = client; value._current = Mock(return_value=True)
            value.origin = Origin('actor', 'pi', new.launch.incarnation, 'fresh-authority', ('implement',))
            new.forge_service = value
        for target, name, fn in ((ExecLaunch, '__init__', init), (ExecLaunch, 'launch', launch),
            (ExecLaunch, 'attach_native', attach), (ExecLaunch, 'close', lambda _: None),
            (SupervisorAdmission, '__init__', admission), (SupervisorAdmission, 'attach_forge_service', ingress)):
            stack.enter_context(patch.object(target, name, fn))
        stack.enter_context(patch('uas.native_session.admit_once', admit))
        if c.git is not None:
            stack.enter_context(patch('uas.native_git_operations._Task', return_value=N(
                namespace=((1, 2), (3, 4)), status={'NSpid': (101, 1)}, close=Mock())))
        return stack

    def test_exact_retained_poll_distinguishes_live_dead_and_unknown(self):
        held = origin(100)
        poll = N(register=Mock(), poll=Mock(return_value=[]))
        with patch('uas.native_pi_restore._identity', return_value=held.identity), patch('uas.native_pi_restore.select.poll', return_value=poll):
            self.assertFalse(held_exit(held))
            for flags in (select.POLLIN, select.POLLIN | select.POLLHUP):
                poll.poll.return_value = [(100, flags)]; self.assertTrue(held_exit(held))
            for flags in (select.POLLERR, select.POLLNVAL, select.POLLHUP,
                          select.POLLIN | select.POLLERR,
                          select.POLLIN | select.POLLHUP | select.POLLNVAL):
                poll.poll.return_value = [(100, flags)]
                with self.assertRaises(OriginDenied): held_exit(held)
            for events in ([(101, select.POLLIN)], [(100, select.POLLIN), (101, select.POLLIN)]):
                poll.poll.return_value = events
                with self.assertRaises(OriginDenied): held_exit(held)
        with patch('uas.native_pi_restore._identity', return_value=(99, 100)):
            with self.assertRaises(OriginDenied): held_exit(held)
        poll.poll.return_value = [(100, select.POLLIN | select.POLLHUP)]
        with patch('uas.native_pi_restore._identity', side_effect=[held.identity, (99, 100)]), patch('uas.native_pi_restore.select.poll', return_value=poll):
            with self.assertRaises(OriginDenied): held_exit(held)

    def test_live_preflight_has_no_revoke_launch_or_context_effect(self):
        c = self.fixture(); before = deepcopy(c.state)
        with patch('uas.native_pi_restore.held_exit', return_value=False): self.assertFalse(c.value.preflight())
        self.assertFalse(c.events); self.assertEqual(c.state, before); self.assertIs(c.launcher.started['pi'], c.old)

    def test_consumed_restore_preserves_same_run_context_request_and_checkout(self):
        c = self.fixture(); before = deepcopy(c.state); self.effects(c)
        self.assertTrue(c.value.preflight()); new = c.value.new
        self.assertEqual(c.events, ['revoke', 'receiver-close', 'old-transport-close', 'new-intent', 'launch',
                                    'resume-proof', 'admit', 'safe-observe', 'safe-consume'])
        self.assertEqual(c.state, before); self.assertIs(c.recruitment.pi, new); self.assertIs(c.launcher.started['pi'], new)
        self.assertIs(new.forge_service.review_host, c.host); self.assertIs(c.host.identity.ingresses[0], new.forge_service)
        self.assertEqual(c.value.result()['phase'], 'restored'); self.assertFalse(c.value.result()['checkout_released'])
        self.assertFalse(c.value.result()['descendant_quiescence_claimed'])
        self.assertFalse(c.value.preflight()); self.assertEqual(c.events.count('launch'), 1)

    def test_git_and_gate_unknown_registries_and_listeners_survive_rebind(self):
        c = self.fixture(git=True); self.effects(c)
        service = c.git.service; coordinator = service.coordinator; children = service.children
        unknown = coordinator.unknown; listener = service.request_listener
        gates, reviews = c.host.gates, c.host.reviews; gate_unknown, review_unknown = gates.unknown, reviews.unknown
        old_seat = service.seats['pi'][0]; worker = service.seats['pi'][1]
        self.assertTrue(c.value.preflight())
        self.assertIs(c.git.service, service); self.assertIs(service.coordinator, coordinator)
        self.assertIs(service.children, children); self.assertIs(service.request_listener, listener)
        self.assertIs(coordinator.unknown, unknown); self.assertIs(gates.unknown, gate_unknown); self.assertIs(reviews.unknown, review_unknown)
        self.assertIs(service.seats['pi'][1], worker); self.assertIs(old_seat.process, c.root.origin)
        self.assertTrue(old_seat.process.revoked); self.assertNotIn(c.root.origin.identity, children.seats)
        self.assertIs(children.seats[c.value.new.launch.origin.identity], service.seats['pi'][0])

    def test_unknown_revoke_never_launches_or_repeats(self):
        c = self.fixture(); self.effects(c)
        c.old.revoke = Mock(side_effect=TimeoutError('unknown revoke'))
        with self.assertRaises(TimeoutError): c.value.preflight()
        with self.assertRaisesRegex(LedgerError, 'RECONCILIATION_REQUIRED'): c.value.preflight()
        c.old.revoke.assert_called_once(); self.assertFalse(c.events); self.assertFalse(c.value.revoked)

    def test_nonconfirmed_revoke_is_not_retirement(self):
        for reply in (None, {'installed': True, 'state': 'active'}, {'installed': False, 'state': 'unknown'}):
            c = self.fixture(); stack = self.effects(c); c.old.revoke = Mock(return_value=reply)
            with self.assertRaises(OriginDenied): c.value.preflight()
            self.assertNotIn('launch', c.events); stack.close()

    def test_unknown_launch_and_admit_do_not_publish_or_retry(self):
        for failure in ('launch', 'admit', 'safe'):
            c = self.fixture(); stack = self.effects(c, fail=failure)
            with self.assertRaises((TimeoutError, NativeUnavailable)): c.value.preflight()
            self.assertIs(c.recruitment.pi, c.old); self.assertIs(c.launcher.started['pi'], c.old)
            with self.assertRaises(LedgerError): c.value.preflight()
            self.assertEqual(c.events.count('launch'), 1); self.assertEqual(c.value.phase, 'unknown'); stack.close()

    def test_changed_run_actor_context_checkout_or_authorization_refuses_before_revoke(self):
        for mutation in ('run', 'actor', 'context', 'checkout', 'authorization'):
            c = self.fixture(); stack = self.effects(c)
            row = c.state['runs'][c.scope['run_id']]
            if mutation == 'run': row['status'] = 'PAUSED'
            elif mutation == 'actor': row['actor_id'] = 'other'
            elif mutation == 'context': c.state['fixture_context']['participants']['pi']['context_generation'] = 2
            elif mutation == 'checkout': row['checkout']['path'] = '/other'
            else: object.__setattr__(c.request.session, 'connected', lambda: False)
            with self.assertRaises(LedgerError): c.value.preflight()
            self.assertFalse(c.events); stack.close()

    def test_epoch_exhaustion_and_journal_scope_mismatch_refuse_before_effect(self):
        for problem in ('epoch', 'journal'):
            c = self.fixture(); stack = self.effects(c)
            if problem == 'epoch': c.old.forge_service.binding.epoch = 2**53 - 1
            else: c.receiver.db = N(execute=lambda *_: N(fetchall=lambda: [(0, 'main', '/wrong')], fetchone=lambda: (json.dumps(c.scope),)))
            with self.assertRaises(LedgerError): c.value.preflight()
            self.assertFalse(c.events); stack.close()

    def test_claude_or_hub_loss_refuses_pi_recovery(self):
        for problem in ('claude', 'hub'):
            c = self.fixture(); stack = self.effects(c)
            if problem == 'claude': c.recruitment.root.forge_service._current.side_effect = OriginDenied('Claude lost')
            else: c.launcher.hub_origin.revoked = True
            with self.assertRaises(OriginDenied): c.value.preflight()
            self.assertFalse(c.events); stack.close()

    def test_graph_or_gate_effect_in_flight_refuses_replacement(self):
        c = self.fixture(); self.effects(c); c.host.identity.active = object()
        with self.assertRaisesRegex(LedgerError, 'GRAPH_CHANGED'): c.value.preflight()
        self.assertFalse(c.events)

    def test_late_canonical_change_after_revoke_holds_without_launch(self):
        c = self.fixture(); self.effects(c); revoke = c.old.revoke
        def changed(**kw):
            result = revoke(**kw); c.state['runs'][c.scope['run_id']]['implementation_request'] = 'changed'; return result
        c.old.revoke = changed
        with self.assertRaisesRegex(LedgerError, 'CANONICAL_SCOPE_CHANGED'): c.value.preflight()
        self.assertEqual(c.events, ['revoke']); self.assertIs(c.launcher.started['pi'], c.old)

    def test_resumed_proof_accepts_history_but_not_wrong_identity_pending_or_old_runtime(self):
        receiver = object.__new__(FixturePiRpcReceiver)
        receiver._binding = {'runtime_id': 'new-runtime', 'session_id': 'same-session'}
        good = {**receiver._binding, 'session_file': '/sessions/prior.jsonl', 'readiness': 'safe'}
        actual = {'sessionId': 'same-session', 'messageCount': 12, 'pendingMessageCount': 0,
                  'isStreaming': False, 'isCompacting': False}
        receiver._native = lambda *_: {'state': good}; receiver.rpc = lambda *_: {'data': actual}
        proof = receiver.prove_resumed_context(session_id='same-session', session_file='/sessions/prior.jsonl', preceding_runtime_id='old-runtime')
        self.assertEqual(proof['source'], 'native-existing-session-and-no-pending-messages')
        for changes in ({'session_id': 'other'}, {'session_file': '/other'}, {'preceding_runtime_id': 'new-runtime'}):
            args = dict(session_id='same-session', session_file='/sessions/prior.jsonl', preceding_runtime_id='old-runtime'); args.update(changes)
            with self.assertRaises(NativeUnavailable): receiver.prove_resumed_context(**args)
        actual['pendingMessageCount'] = 1
        with self.assertRaises(NativeUnavailable): receiver.prove_resumed_context(session_id='same-session', session_file='/sessions/prior.jsonl', preceding_runtime_id='old-runtime')

    def test_missing_existing_journal_never_creates_database(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'missing.db'
            receiver = object.__new__(FixturePiRpcReceiver)
            with self.assertRaises(sqlite3.OperationalError):
                receiver._initialize(journal=missing, runtime_version='1.4.0',
                    scope={'room_id': 'room', 'participant_id': 'pi', 'run_id': 'run', 'generation': 1, 'context_generation': 1},
                    timeout=1, require_existing_journal=True)
            self.assertFalse(missing.exists())

    def test_canonical_exec_attachment_consumes_exact_resume_not_fresh_proof(self):
        c = self.fixture(); launch = object.__new__(ExecLaunch)
        native = object.__new__(FixturePiRpcReceiver)
        native.incarnation_id = 'new-incarnation'; native.scope = c.scope; native.runtime_version = '1.4.0'
        resume = NativePiResume(c.root.native_recipe.sessions + '/prior.jsonl', 'same-session')
        native.prove_resumed_context = Mock(return_value={'runtime_id': 'new-runtime', 'session_id': resume.session_id,
            'session_file': resume.session_file, 'source': 'native-existing-session-and-no-pending-messages'})
        native.prove_fresh_context = Mock(side_effect=AssertionError('fresh fallback forbidden'))
        launch.state = 'released'; launch.native_receiver = None; launch.native_recipe = recipe(c.scope, resume)
        launch.origin = origin(101); launch.incarnation = native.incarnation_id
        launch.seat = N(room_id='room', participant_id='pi', container_id='c' * 64)
        launch.exec_id = 'e' * 64; launch.engine = object(); launch._inspect = Mock()
        launch.activate = Mock(side_effect=lambda checked: self.assertTrue(checked(launch)))
        with patch.object(FixturePiRpcReceiver, 'attach_workstation', return_value=native) as attached:
            self.assertIs(launch.attach_native(journal=Path('/existing/db'), scope=c.scope,
                profile_digest='a' * 64, preceding_runtime_id='old-runtime'), native)
        self.assertTrue(attached.call_args.kwargs['require_existing_journal'])
        native.prove_resumed_context.assert_called_once_with(session_id=resume.session_id,
            session_file=resume.session_file, preceding_runtime_id='old-runtime')
        native.prove_fresh_context.assert_not_called(); launch.activate.assert_called_once()
        self.assertEqual(launch.native_readiness['scope'], c.scope)
        self.assertEqual(launch.native_readiness['native']['session_id'], 'same-session')

    def test_new_git_namespace_mismatch_preserves_old_graph_and_unknowns(self):
        c = self.fixture(git=True); self.effects(c)
        with patch('uas.native_git_operations._Task', return_value=N(
                namespace=((99, 99), (3, 4)), status={'NSpid': (101, 1)}, close=Mock())):
            with self.assertRaises(OriginDenied): c.value.preflight()
        self.assertIs(c.git.pi, c.old); self.assertIs(c.recruitment.pi, c.old)
        self.assertIn(c.root.origin.identity, c.git.service.children.seats)
        self.assertNotIn('safe-consume', c.events); self.assertIn('original-operation', c.git.service.coordinator.unknown)

    def redelivery(self, *, unknown=False):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name); ledger = RoomLedger(root / 'room.db', 'room'); self.addCleanup(ledger.close)
        hub = FixturePeerHub(ledger)
        hub.configure('configure', (FixtureParticipant('sender', 'actor-s'), FixtureParticipant('pi', 'actor-p')), 'run')
        sender = hub.connect('sender', 'sender', 'sender-incarnation', object())
        journal = root / 'handoffs.db'; db = sqlite3.connect(journal); self.addCleanup(db.close)
        db.execute('CREATE TABLE handoffs (logical_digest TEXT PRIMARY KEY, logical TEXT NOT NULL, session_id TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT)')
        db.execute('CREATE TABLE binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), scope TEXT NOT NULL)')
        scope = {'room_id': 'room', 'participant_id': 'pi', 'run_id': 'run', 'generation': 1, 'context_generation': 1}
        db.execute('INSERT INTO binding VALUES (1,?)', (json.dumps(scope),)); db.commit()
        actions = []; native_receipts = {}; available = [not unknown]
        def receiver(incarnation, database):
            value = object.__new__(FixturePiRpcReceiver)
            value.db = database; value.scope = scope; value.incarnation_id = incarnation; value.timeout = 1
            value._binding = {'runtime_id': 'runtime-' + incarnation, 'session_id': 'same-session'}
            value._scope_lock = threading.RLock(); value.observe = lambda: Readiness.SAFE
            def native(command, payload):
                self.assertEqual(command, 'delivery'); actions.append(payload['action'])
                key = digest(payload['logical'])
                if payload['action'] == 'inject':
                    self.assertNotIn(key, native_receipts)
                    native_receipts[key] = {'logical_digest': key, 'session_id': 'same-session',
                        'source': 'native-active-branch-and-session-file', 'entry_id': 'one-native-entry'}
                return {'receipt': native_receipts.get(key)} if available[0] else {}
            value._native = native; return value
        old_native = receiver('old-incarnation', db)
        old = hub.connect('old-attach', 'pi', old_native.incarnation_id, old_native)
        hub.submit(sender, WorkRequest('original-work', 'run', 1, 'pi', 'Same unchanged logical request'))
        hub.observe(old, Readiness.SAFE); old_offer = hub.prepare_delivery(old, traffic_id='original-work')
        if unknown:
            with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'): old_native.accept(old_offer.envelope)
        else:
            receipt = old_native.accept(old_offer.envelope); hub.confirm_delivery(old, old_offer, receipt)
            hub.submit(old, RequestCommand('accept-original', 'run', 1, 'original-work', 'accept'))
        before = ledger.snapshot()['state']['peer_traffic']['traffic']['original-work']
        old_context = deepcopy(ledger.snapshot()['state']['fixture_context']['participants']['pi'])
        hub.observe(old, Readiness.LOST); db.close()
        reopened = sqlite3.connect(journal.as_uri() + '?mode=rw', uri=True); self.addCleanup(reopened.close)
        self.assertEqual(json.loads(reopened.execute('SELECT scope FROM binding').fetchone()[0]), scope)
        resumed = receiver('new-incarnation', reopened)
        new = hub.connect('new-attach', 'pi', resumed.incarnation_id, resumed)
        self.assertEqual(hub.deliver(old)['outcome'], 'HELD')
        # New attachment is ambiguous until a fresh native SAFE observation.
        self.assertEqual(hub.deliver(new)['outcome'], 'HELD')
        hub.observe(new, resumed.observe()); offered = hub.prepare_delivery(new, traffic_id='original-work')
        self.assertNotEqual(offered.envelope['delivery_id'], old_offer.envelope['delivery_id'])
        self.assertEqual(resumed._logical(offered.envelope), old_native._logical(old_offer.envelope))
        if unknown:
            with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'): resumed.accept(offered.envelope)
            self.assertEqual(actions, ['inject', 'reconcile'])
            self.assertEqual(reopened.execute('SELECT state FROM handoffs').fetchone()[0], 'INTENT')
            available[0] = True  # Controlled original native receipt becomes observable, not reinjection.
        receipt = resumed.accept(offered.envelope); hub.confirm_delivery(new, offered, receipt)
        after = ledger.snapshot()['state']['peer_traffic']['traffic']['original-work']
        self.assertEqual(after['id'], before['id']); self.assertEqual(after['text'], before['text'])
        if not unknown: self.assertEqual(after['status'], 'ACCEPTED')
        context_after = ledger.snapshot()['state']['fixture_context']['participants']['pi']
        self.assertEqual(context_after['context_generation'], old_context['context_generation'])
        self.assertEqual(context_after['bound_run'] or context_after['reserved_run'],
                         old_context['bound_run'] or old_context['reserved_run'])
        if not unknown: self.assertEqual(context_after, old_context)
        self.assertEqual(actions.count('inject'), 1); self.assertTrue(all(x == 'reconcile' for x in actions[1:]))
        self.assertEqual(len(native_receipts), 1); self.assertEqual(reopened.execute('SELECT count(*) FROM handoffs').fetchone()[0], 1)
        self.assertEqual(reopened.execute('SELECT state FROM handoffs').fetchone()[0], 'CONFIRMED')

    def test_actual_hub_sqlite_accepted_work_redelivery_reconciles_without_reinjection(self):
        self.redelivery()

    def test_actual_hub_sqlite_unknown_handoff_stays_unknown_until_original_receipt(self):
        self.redelivery(unknown=True)

    def test_driver_effect_failure_cannot_enter_restore_catch(self):
        c = self.fixture(); driver = object.__new__(NativeSessionDriver)
        driver.human_control = None  # Explicitly absent optional authenticated transport.
        driver.started = False; driver.owner = c.owner; driver.request = c.request; driver.budget = c.budget
        driver.next_request = None; driver.next_delivery = 0; driver.next_completion = 10**30
        driver.pi_restoration = N(preflight=Mock(return_value=False), phase='ready')
        driver._session = Mock(); driver._row = lambda: c.state['runs'][c.scope['run_id']]
        driver._pending_comments = lambda: []; driver._current = Mock(); driver._human_action = Mock()
        driver._deliver = Mock(side_effect=OriginDenied('effect uncertainty'))
        driver._result = lambda outcome, reason: (outcome, reason)
        self.assertEqual(driver.run(), ('attention', 'native-authority-lost-restoration-required'))
        driver.pi_restoration.preflight.assert_called_once(); driver._deliver.assert_called_once()

    def test_driver_unknown_human_comment_suppresses_restoration(self):
        c = self.fixture(); driver = object.__new__(NativeSessionDriver)
        driver.human_control = None  # Explicitly absent optional authenticated transport.
        driver.started = False; driver.owner = c.owner; driver.request = c.request; driver.budget = c.budget
        driver.next_request = None; driver.pi_restoration = N(preflight=Mock(), phase='ready')
        driver._session = Mock(); driver._row = lambda: c.state['runs'][c.scope['run_id']]
        driver._pending_comments = lambda: ['original-comment']; driver._current = Mock(side_effect=OriginDenied('lost'))
        driver._result = lambda outcome, reason: (outcome, reason)
        self.assertEqual(driver.run()[0], 'attention'); driver.pi_restoration.preflight.assert_not_called()
