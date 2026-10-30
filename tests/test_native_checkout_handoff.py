"""Pure protocol/owner-budget tests; no subprocess, socket, thread or VM."""
import ast
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.checkouts import CheckoutAllocator
from uas.lifecycle import Supervisor, LifecycleError
from uas.native_checkout_handoff import (request_value, reservation, ready_slot,
    RootCheckoutHandoff, NativeCheckoutClient, collect_child)


def fixture():
    operation = 'open-a'; run = 'run-' + hashlib.sha256(operation.encode()).hexdigest()
    request = {'version': 1, 'kind': 'ALLOCATE', 'run_id': run, 'operation_id': operation}
    seat = dict(id='seat-a', participant='pi', actor='developer', profile='implementer', runtime='pi', arguments=[], provider='provider')
    capabilities = ['implement', 'forge-read']
    room = {'seats': [seat], 'profiles': [{'id': 'implementer', 'capabilities': capabilities}]}
    actors = {'developer': {'github_user_id': 123}}
    native = {'participant_id': 'pi', 'actor_id': 'developer', 'profile_id': 'implementer',
        'capabilities': sorted(capabilities + ['peer-traffic']), 'runtime': 'pi-native', 'configured_selection': seat}
    pending = {'status': 'PREPARING', 'admission_operation': operation, 'participant_id': 'pi',
        'actor_id': 'developer', 'github_user_id': 123, 'context_generation': 1, 'preceding_run': None,
        'authorization_consumed': False, 'admission_origin': {'actor_id': 'human'},
        'human_origin': {'actor_id': 'human'}, 'human_operation': 'human-a',
        'seat_binding': {'seat': native, 'configured_seat': seat, 'configured_capabilities': capabilities}}
    state = {'run_admissions': {run: pending}, 'fixture_context': {
        'participants': {'pi': {'context_generation': 1, 'status': 'READY', 'reset': None,
            'bound_run': None, 'reserved_run': {'run_id': run, 'generation': 1}}},
        'runs': {run: {'generation': 1, 'status': 'OPEN', 'terminal_fact': None}}},
        'peer_traffic': {'definition': {'participants': {'pi': {'actor_id': 'developer'}}}}}
    slot = {'run': run, 'participant': 'pi', 'active': True, 'phase': 'ready', 'reason': 'ACTIVE',
        'observed_dirty': False, 'observed_head': 'a'*40, 'base': 'a'*40}
    return request, room, actors, state, slot


class ProtocolTests(unittest.TestCase):
    def test_exact_request_and_no_claimed_paths_or_authority(self):
        request, *_ = fixture()
        self.assertEqual(request_value(request), request)
        for key in ('path', 'actor_id', 'participant_id', 'command', 'capabilities'):
            with self.assertRaises(LifecycleError): request_value({**request, key: 'anything'})
        for changed in ({'kind': 'RELEASE'}, {'run_id': 'run-other'}, {'version': True}):
            with self.assertRaises(LifecycleError): request_value({**request, **changed})

    def test_exact_reservation_and_bound_observe_only(self):
        request, room, actors, state, _ = fixture()
        self.assertEqual(reservation(state, request, room, actors, initial=True)[0], 'pi')
        context = state['fixture_context']['participants']['pi']
        context['bound_run'], context['reserved_run'] = context['reserved_run'], None
        with self.assertRaises(LifecycleError): reservation(state, request, room, actors, initial=True)
        self.assertEqual(reservation(state, request, room, actors, initial=False)[0], 'pi')

    def test_changed_reservation_configuration_or_context_denied(self):
        request, room, actors, state, _ = fixture()
        for key, value in (('status', 'ACTIVE'), ('participant_id', 'other'), ('actor_id', 'other'),
                           ('admission_operation', 'other'), ('context_generation', 2),
                           ('preceding_run', {'run_id': 'old'}), ('authorization_consumed', True)):
            changed = deepcopy(state); changed['run_admissions'][request['run_id']][key] = value
            with self.assertRaises(LifecycleError): reservation(changed, request, room, actors, initial=False)
        for key, value in (('status', 'LOST'), ('reset', {}), ('context_generation', 2), ('reserved_run', None)):
            changed = deepcopy(state); changed['fixture_context']['participants']['pi'][key] = value
            with self.assertRaises(LifecycleError): reservation(changed, request, room, actors, initial=False)
        changed = deepcopy(room); changed['seats'][0]['arguments'] = ['changed']
        with self.assertRaises(LifecycleError): reservation(state, request, changed, actors, initial=False)

    def test_canonical_broker_funding_return_restores_full_pin(self):
        from uas.forge import ReadOnlyForgeBroker
        request, room, actors, state, _ = fixture()
        row = state['run_admissions'][request['run_id']]
        row['reservation'] = 'x' * 131072
        before = reservation(state, request, room, actors, initial=True)[1]
        row['reservation'] = row['reservation'][:-70000]
        state['forge_pending'] = {'read-a': {'admission_funding':
            {'run_id': request['run_id'], 'released_bytes': 70000}}}
        self.assertNotEqual(reservation(state, request, room, actors, initial=False)[1], before)
        ReadOnlyForgeBroker._release_pending(state, 'read-a')
        self.assertEqual(reservation(state, request, room, actors, initial=False)[1], before)

    def test_slot_clean_base_and_exact_binding_required(self):
        request, _, _, _, slot = fixture()
        self.assertEqual(ready_slot(slot, request['run_id'], 'pi'), slot)
        for key, value in (('run', 'other'), ('participant', 'other'), ('phase', 'creating'),
                           ('observed_head', 'b'*40), ('observed_dirty', True), ('active', False)):
            with self.assertRaises(LifecycleError): ready_slot({**slot, key: value}, request['run_id'], 'pi')

    def test_allocate_failure_never_replayed_observe_is_read_only(self):
        request, _, _, _, slot = fixture()
        owner = RootCheckoutHandoff.__new__(RootCheckoutHandoff)
        owner.deadline = 100; owner.pin = (request['run_id'], 'pi', {})
        owner.owner = SimpleNamespace(_locked=lambda **k: nullcontext())
        owner._authorized = Mock(return_value=True); owner.attempted = set()
        owner.allocator = SimpleNamespace(allocate=Mock(side_effect=LifecycleError('UNKNOWN')),
            _locked=lambda action: nullcontext({'slots': {'primary': slot}}), _observe=Mock(return_value=slot))
        with patch('uas.native_checkout_handoff.time.monotonic', return_value=1):
            with self.assertRaises(LifecycleError): owner.operation(request)
            with self.assertRaises(LifecycleError) as error: owner.operation(request)
            self.assertEqual(error.exception.code, 'CHECKOUT_ALLOCATION_RECONCILE_ONLY')
            self.assertEqual(owner.operation({**request, 'kind': 'OBSERVE'}), slot)
        self.assertEqual(owner.allocator.allocate.call_count, 1)

    def test_origin_change_breaks_pinned_reservation(self):
        request, room, actors, state, _ = fixture()
        owner = RootCheckoutHandoff.__new__(RootCheckoutHandoff)
        owner._held = lambda: None; owner.pin = None; owner.actors = actors
        owner.plan = SimpleNamespace(room=room, config_digest='digest')
        owner.resources = SimpleNamespace(data={'instance': 'instance'})
        owner.owner = SimpleNamespace(_read=lambda: {'phase': 'running', 'instance_id': 'instance',
            'spec': {'config_digest': 'sha256:digest'}})
        owner._snapshot = lambda: state
        self.assertTrue(owner._authorized(request, initial=True))
        state['run_admissions'][request['run_id']]['admission_origin']['actor_id'] = 'replacement'
        with self.assertRaises(LifecycleError): owner._authorized(request, initial=True)


class DeadlineTests(unittest.TestCase):
    def allocator(self, deadline):
        owner = CheckoutAllocator.__new__(CheckoutAllocator); owner.deadline = deadline
        owner.git_identity = owner.manifest_reader_gid = None
        return owner

    def test_each_git_command_uses_remaining_budget_legacy_stays_twenty(self):
        owner = self.allocator(10)
        result = SimpleNamespace(returncode=0, stdout=b'ok\n')
        with patch('uas.checkouts.subprocess.run', return_value=result) as run:
            with patch('uas.checkouts.time.monotonic', side_effect=[2, 7, 11]):
                self.assertEqual(owner._git('/unused', 'status'), 'ok')
                owner._git('/unused', 'status')
                with self.assertRaises(LifecycleError): owner._git('/unused', 'status')
            self.assertEqual([c.kwargs['timeout'] for c in run.call_args_list], [8, 3])
            self.allocator(None)._git('/unused', 'status')
            self.assertEqual(run.call_args.kwargs['timeout'], 20)

    def test_expiry_before_manifest_save_does_not_mutate_state(self):
        owner = self.allocator(1); state = {'working_tree_observations': {'kept': True}}
        with patch('uas.checkouts.time.monotonic', return_value=2):
            with self.assertRaises(LifecycleError): owner._save(state)
        self.assertEqual(state, {'working_tree_observations': {'kept': True}})

    def test_lifecycle_contention_expires_without_scope_or_reentrant_shortcut(self):
        with tempfile.TemporaryDirectory() as root:
            owner = Supervisor(root, 'room', object(), authorize=lambda *a: True, revoke=lambda *a: True)
            with patch('uas.lifecycle.time.monotonic', side_effect=[0, 2]), \
                 patch('uas.lifecycle.time.sleep') as sleep, \
                 patch('uas.lifecycle.fcntl.flock', side_effect=BlockingIOError) as flock:
                with self.assertRaises(LifecycleError):
                    with owner._locked(deadline=1): self.fail('lock unavailable')
                self.assertEqual(flock.call_count, 1); sleep.assert_called_once()
            self.assertFalse(owner._lifecycle_scopes)
            for deadline in (True, float('nan'), float('inf')):
                with self.assertRaises(LifecycleError):
                    with owner._locked(deadline=deadline): self.fail('invalid deadline')

    def test_git_drop_is_exact_scrubbed_and_never_root_safe_directory(self):
        owner = self.allocator(10); owner.git_identity = (165532, 165532)
        owner.repo = Path('/repo'); owner.root = Path('/slots')
        rooted = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=165532, st_gid=165532))
        with patch('uas.checkouts._path', return_value=rooted), \
             patch('uas.checkouts.time.monotonic', return_value=1), \
             patch('uas.checkouts.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'')) as run:
            owner._git('/repo', 'status')
        args, kw = run.call_args
        self.assertEqual((kw['user'], kw['group'], kw['extra_groups']), (165532, 165532, []))
        self.assertTrue(kw['close_fds']); self.assertEqual(kw['stdin'], -3)
        self.assertEqual(kw['env']['HOME'], '/nonexistent')
        self.assertEqual(kw['env']['GIT_CONFIG_NOSYSTEM'], '1')
        self.assertNotIn('safe.directory', str(args))
        rooted.stat = lambda: SimpleNamespace(st_uid=0, st_gid=0)
        with patch('uas.checkouts._path', return_value=rooted), \
             patch('uas.checkouts.subprocess.run', side_effect=AssertionError('must not spawn')):
            with self.assertRaises(LifecycleError): owner._git('/repo', 'status')

    def test_invalid_or_nonroot_native_options_refused(self):
        supervisor = SimpleNamespace(backend=object())
        for value in (True, (0, 0), (165532, True), [165532, 165532]):
            with self.assertRaises(LifecycleError): CheckoutAllocator(supervisor, None, git_identity=value)
        with patch('uas.checkouts.os.geteuid', return_value=123):
            with self.assertRaises(LifecycleError): CheckoutAllocator(supervisor, None, git_identity=(165532, 165532))
            with self.assertRaises(LifecycleError): CheckoutAllocator(supervisor, None, manifest_reader_gid=165533)

    def test_expired_after_manifest_intent_retains_same_owned_slot(self):
        import test_artifact_target as fixtures
        f = fixtures.TargetTests(); f.setUp(); self.addCleanup(f.doCleanups)
        owner = self.allocator(10); owner.repo, owner.root, owner.manifest = f.repo, f.slots, f.allocator.manifest
        owner.supervisor = SimpleNamespace(_sync_directory=lambda path: None)
        owner.writer_guard = None
        state = deepcopy(f.state); state['slots'] = {}
        owner._locked = lambda action: nullcontext(state)
        owner._git = lambda path, *args, **kw: ('refs/heads/main' if args[0] == 'symbolic-ref'
            else f.head if args[0] == 'rev-parse' else '')
        now = [1]
        def observed(state, key):
            now[0] = 11
            return state['slots'][key]
        owner._observe = observed
        with patch('uas.checkouts.time.monotonic', side_effect=lambda: now[0]):
            with self.assertRaises(LifecycleError) as error: owner.allocate('run-new', 'pi')
        self.assertEqual(error.exception.code, 'CHECKOUT_DEADLINE_RECONCILE')
        stored = json.loads(owner.manifest.read_text())
        self.assertEqual(stored['slots']['primary']['run'], 'run-new')
        self.assertTrue(stored['slots']['primary']['active'])

    def test_reader_group_is_readonly_atomic_and_default_stays_private(self):
        import test_artifact_target as fixtures
        f = fixtures.TargetTests(); f.setUp(); self.addCleanup(f.doCleanups)
        owner = self.allocator(None); owner.manifest = f.allocator.manifest
        owner.supervisor = SimpleNamespace(_sync_directory=lambda path: None)
        owner.manifest_reader_gid = 165533
        with patch('uas.checkouts.os.fchown') as chown, patch('uas.checkouts.os.fchmod') as chmod:
            owner._save(deepcopy(f.state))
            self.assertEqual(chown.call_args.args[1:], (0, 165533))
            self.assertEqual(chmod.call_args.args[1:], (0o640,))
            owner.manifest_reader_gid = None; chown.reset_mock(); chmod.reset_mock()
            owner._save(deepcopy(f.state))
            chown.assert_not_called(); chmod.assert_not_called()
        self.assertEqual(owner.manifest.stat().st_mode & 0o777, 0o600)

    def test_existing_held_scope_still_valid_and_expires(self):
        with tempfile.TemporaryDirectory() as root:
            owner = Supervisor(root, 'room', object(), authorize=lambda *a: True, revoke=lambda *a: True)
            with patch('uas.lifecycle.time.monotonic', return_value=0):
                with owner._locked(deadline=1) as scope: scope.require(owner)
            with self.assertRaises(LifecycleError): scope.require(owner)


class SourceTests(unittest.TestCase):
    def test_root_wrapper_and_readonly_host_contract(self):
        import uas.native_qualification as wrapper
        import uas.native_qualification_backend as backend
        source = Path(wrapper.__file__).read_text()
        self.assertIn('RootCheckoutHandoff(plan, resources, child, allocation_root, deadline=deadline)', source)
        self.assertIn('collect_child(child, handoff, deadline=deadline)', source)
        self.assertNotIn('child.communicate(startup', source)
        self.assertIn('str(allocation_child.fileno())', source)
        tree = ast.parse(Path(backend.__file__).read_text())
        observer = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeQualificationObserver')
        self.assertIn('create = start = stop = remove = admit = _deny', ast.get_source_segment(Path(backend.__file__).read_text(), observer))
