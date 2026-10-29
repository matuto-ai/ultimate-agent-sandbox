"""Pure resource/lineage envelope contracts; no native or VM evidence.

Finite fake time distinguishes resource observations outside the lineage clock
from fresh seat and proc observations inside its unchanged absolute deadline.
"""
import ast
from contextlib import ExitStack, contextmanager
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.git_process import GitChildAuthority, GitSeat, MAX_DEPTH, MAX_SECONDS
from uas.kernel_origin import HeldOrigin, OriginDenied, Record
from uas.ledger import Origin
from test_git_process import FakeTask, FakeView, NS

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
try:
    from room_service import ObservedAuthority, observe_authority_phase
finally:
    sys.path.pop(0)


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.locked = False
        self.events = []
        self.clock = [0.0]
        clock = patch('room_service.time.monotonic', side_effect=lambda: self.clock[0])
        clock.start(); self.addCleanup(clock.stop)

    @contextmanager
    def lifecycle_lock(self):
        self.assertFalse(self.locked)
        self.locked = True
        try: yield
        finally: self.locked = False

    def observed(self, method, *, fail=None, cleanup_error=None):
        self.events = []
        checks = {}
        first = OriginDenied('first-' + str(fail))
        resources = [0]
        def resource():
            self.assertTrue(self.locked)
            resources[0] += 1
            phase = 'pre_resource' if resources[0] % 2 else 'post_resource'
            self.events.append(phase)
            self.clock[0] += .010
            if fail == phase: raise first
        def close():
            self.assertTrue(self.locked)
            self.events.append('close')
            if cleanup_error is not None: raise cleanup_error
        binding = SimpleNamespace(origin=object(), close=Mock(side_effect=close))
        output = binding if method == 'bind' else object()
        def lineage(*args):
            self.assertTrue(self.locked)
            self.events.append('lineage')
            self.clock[0] += .002
            if fail == 'lineage': raise first
            return output
        delegate = SimpleNamespace(close=Mock())
        setattr(delegate, method, Mock(side_effect=lineage))
        return ObservedAuthority(delegate, checks, resource), checks, first, binding, output

    def call(self, authority, method):
        return getattr(authority, method)(*(() if method == 'current' else ('record',)))

    def test_each_operation_observes_resources_before_and_after_lineage_under_lock(self):
        for method in ('bind', 'current', 'require'):
            with self.subTest(method=method):
                observed, checks, _, binding, output = self.observed(method)
                with self.lifecycle_lock():
                    result = self.call(observed, method)
                    self.assertEqual(['pre_resource', 'lineage', 'post_resource'], self.events)
                    if method == 'bind':
                        self.assertIs(binding.origin, result.origin)
                        result.close()
                    else: self.assertIs(output, result)
                self.assertNotIn('authority_failure', checks)
                phases = checks['authority_phases']
                self.assertEqual({method + '.' + part for part in
                    ('pre_resource', 'lineage', 'post_resource')}, set(phases))
                self.assertAlmostEqual(.010, phases[method + '.pre_resource']['last_seconds'])
                self.assertAlmostEqual(.002, phases[method + '.lineage']['last_seconds'])
                self.assertAlmostEqual(.010, phases[method + '.post_resource']['last_seconds'])

    def test_all_pre_lineage_and_post_failures_propagate_without_success(self):
        for method in ('bind', 'current', 'require'):
            for phase in ('pre_resource', 'lineage', 'post_resource'):
                with self.subTest(method=method, phase=phase):
                    observed, checks, first, binding, _ = self.observed(method, fail=phase)
                    with self.lifecycle_lock(), self.assertRaises(OriginDenied) as caught:
                        self.call(observed, method)
                    self.assertIs(first, caught.exception)
                    expected = ['pre_resource']
                    if phase != 'pre_resource': expected.append('lineage')
                    if phase == 'post_resource': expected.append('post_resource')
                    if method == 'bind' and phase == 'post_resource': expected.append('close')
                    self.assertEqual(expected, self.events)
                    self.assertEqual(method, checks['authority_failure']['operation'])
                    self.assertEqual(phase, checks['authority_failure']['phase'])
                    self.assertEqual(1, checks['authority_phases'][method + '.' + phase]['failures'])
                    self.assertEqual(int(method == 'bind' and phase == 'post_resource'), binding.close.call_count)
                    observed.delegate.close.assert_not_called()

    def test_post_bind_cleanup_failure_preserves_first_error_and_bounded_cleanup_evidence(self):
        cleanup_error = ValueError('c' * 1000)
        observed, checks, first, binding, _ = self.observed('bind', fail='post_resource', cleanup_error=cleanup_error)
        with self.lifecycle_lock(), self.assertRaises(OriginDenied) as caught: observed.bind('record')
        self.assertIs(first, caught.exception)
        self.assertEqual('post_resource', checks['authority_failure']['phase'])
        binding.close.assert_called_once_with()
        cleanup = checks['bind_cleanup']
        self.assertFalse(cleanup['closed'])
        self.assertLessEqual(len(str(cleanup)), 512)
        self.assertEqual(1, checks['authority_phases']['bind.cleanup']['failures'])

    def test_successful_post_bind_cleanup_is_recorded_without_returning_new_binding(self):
        observed, checks, first, binding, _ = self.observed('bind', fail='post_resource')
        with self.lifecycle_lock(), self.assertRaises(OriginDenied) as caught: observed.bind('record')
        self.assertIs(first, caught.exception)
        self.assertTrue(checks['bind_cleanup']['closed'])
        binding.close.assert_called_once_with()
        self.assertEqual(0, checks['authority_phases']['bind.cleanup']['failures'])

    def test_bound_authority_carries_fresh_resource_callback_for_current_and_require(self):
        calls = []
        def resource():
            self.assertTrue(self.locked)
            calls.append('resource')
        binding = SimpleNamespace(origin=object(), close=Mock(),
            current=Mock(side_effect=lambda: calls.append('current') or True),
            require=Mock(side_effect=lambda record: calls.append(('require', record)) or True))
        delegate = SimpleNamespace(bind=Mock(return_value=binding), close=Mock())
        checks = {}
        with self.lifecycle_lock():
            bound = ObservedAuthority(delegate, checks, resource).bind('first')
            self.assertTrue(bound.current())
            self.assertTrue(bound.require('next'))
            bound.close()
        self.assertEqual(['resource', 'resource', 'resource', 'current', 'resource',
                          'resource', ('require', 'next'), 'resource'], calls)
        binding.close.assert_called_once_with()
        delegate.close.assert_not_called()

    def test_first_failure_is_retained_after_later_failure(self):
        checks = {}
        first, later = OriginDenied('a' * 1000), ValueError('later')
        resources = Mock()
        delegate = SimpleNamespace(current=Mock(side_effect=[first, later]), close=Mock())
        authority = ObservedAuthority(delegate, checks, resources)
        for expected in (first, later):
            with self.assertRaises(type(expected)) as caught: authority.current()
            self.assertIs(expected, caught.exception)
        self.assertEqual('OriginDenied', checks['authority_failure']['error_type'])
        self.assertEqual('a' * 256, checks['authority_failure']['message'])
        self.assertEqual(2, checks['authority_phases']['current.lineage']['failures'])

    def test_unknown_diagnostic_phase_cannot_expand_evidence_keys(self):
        checks, work = {}, Mock()
        with self.assertRaisesRegex(ValueError, 'unknown authority phase'):
            observe_authority_phase(checks, 'untrusted-' * 100, work)
        work.assert_not_called(); self.assertEqual({}, checks)

    def test_phase_timings_aggregate_finitely_without_unbounded_per_call_records(self):
        checks = {}
        for index in range(100):
            def work():
                self.clock[0] += .001
                return index
            self.assertEqual(index, observe_authority_phase(checks, 'seat.current', work))
        self.assertEqual({'seat.current'}, set(checks['authority_phases']))
        phase = checks['authority_phases']['seat.current']
        self.assertEqual(100, phase['calls'])
        self.assertEqual(0, phase['failures'])
        self.assertAlmostEqual(.100, phase['total_seconds'])
        self.assertAlmostEqual(.001, phase['max_seconds'])
        self.assertLessEqual(len(str(checks)), 512)


class CoreEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.clock = [0.0]
        self.checks, self.events = {}, []
        self.state = {'current': True}
        self.root = object.__new__(HeldOrigin)
        self.root.identity, self.root.pidfd = (7, 10), 10
        self.root.credentials, self.root.revoked = (10, 1000, 1000), False
        self.origin = Origin('alice', 'seat-a', 'incarnation', 'epoch-1', ('git-read',))
        FakeTask.graph = {20: {'parent': 10}, 10: {'parent': 1}}
        FakeTask.constructed = []
        for item in (patch('uas.git_process.ProcView', FakeView),
                     patch('uas.git_process._Task', FakeTask),
                     patch('uas.git_process._identity', lambda fd: (7, fd)),
                     patch('uas.git_process.alive', lambda fd: fd >= 0),
                     patch('uas.git_process.time.monotonic', side_effect=lambda: self.clock[0])):
            item.start(); self.addCleanup(item.stop)

    def record(self): return Record(b'{}', (20, 1000, 1000), 20)

    def authority(self, *, seat_work=None, resource_work=None):
        def fresh():
            self.events.append('fresh_seat')
            if seat_work: seat_work()
            return self.state['current']
        def current(): return observe_authority_phase(self.checks, 'seat.current', fresh)
        def resources():
            self.events.append('resources')
            if resource_work: resource_work()
        core = GitChildAuthority((GitSeat(self.origin, self.root, current, NS, 1),))
        self.addCleanup(core.close)
        return ObservedAuthority(core, self.checks, resources)

    def test_slow_resources_are_outside_unchanged_core_clock_and_seat_is_fresh_twice(self):
        authority = self.authority(resource_work=lambda: self.clock.__setitem__(0, self.clock[0] + .075))
        bound = authority.bind(self.record())
        self.addCleanup(bound.close)
        self.assertEqual(32, MAX_DEPTH); self.assertEqual(.050, MAX_SECONDS)
        self.assertEqual(['resources', 'fresh_seat', 'fresh_seat', 'resources'], self.events)
        self.assertEqual(2, self.checks['authority_phases']['seat.current']['calls'])
        self.assertAlmostEqual(.150, self.clock[0])
        self.assertAlmostEqual(0, self.checks['authority_phases']['bind.lineage']['last_seconds'])
        self.assertTrue(bound.current())
        self.assertEqual(4, self.checks['authority_phases']['seat.current']['calls'])
        self.state['current'] = False
        with self.assertRaises(OriginDenied): bound.current()
        self.assertEqual('lineage', self.checks['authority_failure']['phase'])

    def test_admission_and_final_proc_recheck_keep_one_absolute_deadline(self):
        authority = self.authority(resource_work=lambda: self.clock.__setitem__(0, self.clock[0] + .075))
        original = FakeTask.__init__
        def delayed(task, *args, **kwargs):
            original(task, *args, **kwargs)
            self.clock[0] += .020
        def slow_check(): self.clock[0] += .020
        with patch.object(FakeTask, '__init__', delayed), patch.object(FakeTask, 'check', side_effect=slow_check):
            with self.assertRaisesRegex(OriginDenied, 'lineage observation deadline exceeded'):
                authority.bind(self.record())
        self.assertTrue(all(task.closed for task in FakeTask.constructed))
        self.assertEqual(['resources', 'fresh_seat'], self.events)
        self.assertNotIn('bind.post_resource', self.checks['authority_phases'])
        self.assertAlmostEqual(.060, self.checks['authority_phases']['bind.lineage']['last_seconds'])

    def test_slow_second_seat_callback_remains_inside_final_deadline(self):
        calls = [0]
        def seat_work():
            calls[0] += 1
            if calls[0] == 2: self.clock[0] += .060
        authority = self.authority(seat_work=seat_work)
        with self.assertRaisesRegex(OriginDenied, 'lineage observation deadline exceeded'):
            authority.bind(self.record())
        self.assertEqual(2, calls[0])
        self.assertTrue(all(task.closed for task in FakeTask.constructed))
        self.assertEqual(2, self.checks['authority_phases']['seat.current']['calls'])
        self.assertNotIn('bind.post_resource', self.checks['authority_phases'])

    def test_revocation_between_core_callbacks_is_not_cached(self):
        authority = self.authority()
        with patch.object(FakeTask, 'check', side_effect=lambda: self.state.__setitem__('current', False)):
            with self.assertRaisesRegex(OriginDenied, 'native Git authority revoked'):
                authority.bind(self.record())
        self.assertEqual(['resources', 'fresh_seat', 'fresh_seat'], self.events)
        self.assertTrue(all(task.closed for task in FakeTask.constructed))


class FixtureWiringTests(unittest.TestCase):
    def setUp(self):
        self.source = (VM/'room_service.py').read_text()
        tree = ast.parse(self.source)
        self.prove = next(node for node in tree.body
                          if isinstance(node, ast.FunctionDef) and node.name == 'prove_service')
        self.functions = {node.name: node for node in self.prove.body
                          if isinstance(node, ast.FunctionDef)}

    def test_real_fresh_current_reloads_manifest_and_retains_every_held_origin_gate(self):
        node = self.functions['fresh_current']
        for mutation in ('active', 'missing', 'phase', 'instance', 'revoked', 'dead'):
            with self.subTest(mutation=mutation):
                state = {'phase': 'running', 'instance_id': 'instance'}
                origin = SimpleNamespace(revoked=False, pidfd=10)
                supervisor = SimpleNamespace(_read=Mock(return_value=state))
                alive = Mock(return_value=True)
                namespace = dict(supervisor=supervisor, active=True, instance='instance',
                    launch=SimpleNamespace(origin=origin), alive=alive, OriginDenied=OriginDenied)
                # Compile only this audited inert nested predicate, not the VM entrypoint.
                exec(compile(ast.Module(body=[node], type_ignores=[]), '<fresh-current>', 'exec'), namespace)
                current = namespace['fresh_current']
                self.assertTrue(current()); self.assertTrue(current())
                self.assertEqual(2, supervisor._read.call_count)
                self.assertEqual(2, alive.call_count)
                if mutation == 'active': namespace['active'] = False
                elif mutation == 'missing': supervisor._read.return_value = None
                elif mutation == 'phase': state['phase'] = 'stopped'
                elif mutation == 'instance': state['instance_id'] = 'replacement'
                elif mutation == 'revoked': origin.revoked = True
                else: alive.return_value = False
                with self.assertRaisesRegex(OriginDenied, 'Room preflight seat no longer current'):
                    current()
                self.assertEqual(3, supervisor._read.call_count)
        fresh = ast.unparse(node)
        self.assertNotIn('endpoint_', fresh); self.assertNotIn('broker', fresh)
        current = ast.unparse(self.functions['current'])
        self.assertIn("observe_authority_phase(checks, 'seat.current', fresh_current)", current)
        self.assertIn('GitSeat(origin, launch.origin, current, namespace, depth)', self.source)

    def test_prelaunch_to_G_rechecks_actual_current_endpoint_and_broker(self):
        prelaunch = next(n for n in ast.walk(self.prove)
                         if isinstance(n, ast.FunctionDef) and n.name == 'prelaunch_unrelated')
        predicates = [self.functions[name] for name in ('fresh_current', 'current', 'resources')]
        for mutation in ('active', 'missing', 'phase', 'instance', 'revoked', 'dead', 'endpoint', 'broker'):
            with self.subTest(mutation=mutation):
                state = {'phase': 'running', 'instance_id': 'instance'}
                origin = SimpleNamespace(revoked=False, pidfd=10)
                locked = [False]
                @contextmanager
                def lock():
                    self.assertFalse(locked[0], 'nested lifecycle acquisition')
                    locked[0] = True
                    try: yield
                    finally: locked[0] = False
                supervisor = SimpleNamespace(_read=Mock(return_value=state), _locked=lock)
                endpoint, broker, backend = Mock(), Mock(), Mock()
                alive = Mock(return_value=True)
                namespace = dict(supervisor=supervisor, active=True, instance='instance',
                    launch=SimpleNamespace(origin=origin), alive=alive, OriginDenied=OriginDenied,
                    endpoint_=endpoint, broker=broker, backend=backend, state=state, checks={},
                    ExitStack=ExitStack, contextmanager=contextmanager,
                    observe_authority_phase=observe_authority_phase)
                exec(compile(ast.Module(body=predicates+[prelaunch], type_ignores=[]),
                             '<actual prelaunch and fresh predicates>', 'exec'), namespace)
                write = Mock()
                with self.assertRaises((OriginDenied, RuntimeError)):
                    with namespace['prelaunch_unrelated']() as release:
                        self.assertTrue(locked[0]); backend.admit.assert_called_once_with(state)
                        if mutation == 'active': namespace['active'] = False
                        elif mutation == 'missing': supervisor._read.return_value = None
                        elif mutation == 'phase': state['phase'] = 'stopped'
                        elif mutation == 'instance': state['instance_id'] = 'replacement'
                        elif mutation == 'revoked': origin.revoked = True
                        elif mutation == 'dead': alive.return_value = False
                        elif mutation == 'endpoint': endpoint.require.side_effect = RuntimeError('endpoint drift')
                        else: broker.require.side_effect = RuntimeError('broker dead')
                        release(write)
                self.assertFalse(locked[0]); write.assert_not_called()
                backend.admit.assert_called_once_with(state)
                self.assertEqual(2, supervisor._read.call_count)

    def test_resource_checks_remain_at_direct_bootstrap_and_release_locked_gates(self):
        resources = ast.unparse(self.functions['resources'])
        self.assertIn('endpoint_.require()', resources)
        self.assertIn('broker.require()', resources)
        self.assertIn('ObservedAuthority(authority, checks, resources)', self.source)
        gates = []
        for node in ast.walk(self.prove):
            if not isinstance(node, ast.With): continue
            if 'supervisor._locked()' not in ast.unparse(node.items[0].context_expr): continue
            text = ast.unparse(node)
            if "'PROVE_HELP_ONLY'" not in text and "'RELEASE_WORKLOAD'" not in text: continue
            gates.append(text)
            self.assertLess(text.index('current()'), text.index('resources()'))
            self.assertLess(text.index('resources()'), text.index('backend.admit(state)'))
            self.assertLess(text.index('backend.admit(state)'), text.index('send(launch.channel'))
        self.assertEqual(1, len(gates))
        final = ast.unparse(next(n for n in ast.walk(self.prove)
                                if isinstance(n, ast.FunctionDef) and n.name == 'release_workload'))
        expected = ['supervisor._locked()', "'final.current'", "'final.resources'",
                    "'final.admission'", "'final.post_current'", "'final.post_resources'",
                    "'final.broker'", 'bootstrap_control_remaining(control_deadline)',
                    "send(launch.channel, {'kind': 'RELEASE_WORKLOAD'})"]
        # The first deadline check precedes the gates; the last guards the write.
        positions = [final.index(token) if token != 'bootstrap_control_remaining(control_deadline)'
                     else final.rindex(token) for token in expected]
        self.assertEqual(sorted(positions), positions)


if __name__ == '__main__': unittest.main()
