"""Inert CLI/pipe/clock diagnostics tests; no real process, socket or SELinux."""
import ast
import json
from pathlib import Path
import subprocess
import sys
from uas.room_probe import (DENIED_HELP_READY, DENIED_HELP_RELEASE,
                            DENIED_HELP_STARTUP, DENIED_HELP_STARTUP_STEPS)
from unittest import TestCase
from unittest.mock import Mock, patch
from types import SimpleNamespace

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
try:
    import room_service
    import guest_room
finally:
    sys.path.pop(0)


class CLIDiagnosticsTests(TestCase):
    def exercise(self, fault=None, *, noisy=False, startup=.1, lock_cost=0, check_cost=0,
                 gate_fault=None, delivery_lag=0, child_schedule=0, compose=False,
                 startup_chunks=None, after_startup=b'inert stderr\n', bookkeeping_cost=0, release_bookkeeping_cost=0):
        checks = {}
        clock = [0.0]
        calls = {'select': [], 'read': 0, 'wait': 0, 'killed': False, 'order': [], 'launcher': 0}
        error = OSError('inert original ' + str(fault))
        stdin = Mock(); stdin.fileno.return_value = 23
        stdout = Mock(); stdout.fileno.return_value = 21
        stderr = Mock(); stderr.fileno.return_value = 22
        process = Mock(pid=73, stdin=stdin, stdout=stdout, stderr=stderr, returncode=None)
        listener = Mock()
        channel = Mock(); channel.__enter__ = Mock(return_value=channel)
        channel.__exit__ = Mock(return_value=False)
        listener.accept.return_value = (channel, None)
        if fault == 'accept-call': listener.accept.side_effect = error
        payload = b'x' * 65536 if noisy else b'{"code":128}\n'
        chunks = {21: [payload, b''], 22: [DENIED_HELP_STARTUP, after_startup, b'']}
        if fault=='startup-fragmented':chunks[22]=[DENIED_HELP_STARTUP[:8],DENIED_HELP_STARTUP[8:],after_startup,b'']
        if fault=='startup-malformed':chunks[22]=[b'not-the-marker\n',b'']
        if fault=='startup-duplicate':chunks[22]=[DENIED_HELP_READY*2,b'']
        if fault=='startup-eof':chunks[22]=[b'']
        if fault=='startup-oversized':chunks[22]=[b'x'*65536,b'']
        if fault=='startup-flood':chunks[22]=[b'U']*10
        if startup_chunks is not None: chunks[22] = list(startup_chunks)
        if fault in ('flood', 'collect-flood'): chunks[21] = [b'x'] * 20 + [b'']
        def select(readers, _write, _error, timeout):
            calls['select'].append((listener in readers, timeout))
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(timeout, 5)
            if timeout == 0:
                return ([listener] if fault=='early-at-release' else []), [], []
            if checks.get('stage') == 'startup' and not calls['killed']:
                if fault=='startup-timeout':clock[0]+=timeout;return [],[],[]
                clock[0] += min(1,timeout) if fault=='startup-flood' else startup
                if fault=='startup-listener':return [listener],[],[]
                if fault=='startup-stdout':return [stdout],[],[]
                return [stderr],[],[]
            if listener in readers:
                if calls.get('child_expired'):
                    clock[0] += timeout
                    return [], [], []
                if fault in ('accept-timeout', 'early-exit', 'kill', 'cleanup-wait'):
                    clock[0] += timeout
                    return [], [], []
                if fault == 'flood':
                    clock[0] += min(1, timeout)
                    return [stream for stream in readers if stream != listener], [], []
                clock[0] += .1
                return [listener], [], []
            if fault == 'collect-timeout' and not calls['killed']:
                clock[0] += timeout
                return [], [], []
            clock[0] += min(1, timeout) if fault == 'collect-flood' else .1
            return list(readers), [], []
        def read(fd, amount):
            self.assertEqual(65536, amount)
            calls['read'] += 1
            if (fault == 'read' and checks['stage']=='collect' and not calls.get('read_failed')) or fault=='startup-read':
                calls['read_failed']=True
                raise error
            return chunks[fd].pop(0) if chunks[fd] else b''
        def wait(*, timeout):
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(timeout, 5)
            calls['wait'] += 1
            if fault == 'wait' and calls['wait'] == 1:
                raise subprocess.TimeoutExpired('inert', timeout)
            if fault == 'cleanup-wait': raise error
            process.returncode = 7 if fault == 'early-exit' else (-9 if calls['killed'] else 0)
            return process.returncode
        def poll():
            if fault == 'poll' and checks.get('stage') != 'startup': raise error
            if fault == 'startup-exit' or (fault == 'early-exit' and checks.get('stage') != 'startup'): process.returncode = 7
            return process.returncode
        def kill():
            self.assertIsNone(process.returncode, 'never signal a known reaped child')
            calls['killed'] = True
            if fault == 'kill': raise error
        process.wait.side_effect = wait
        process.poll.side_effect = poll
        process.kill.side_effect = kill
        if fault == 'close': stdout.close.side_effect = error
        if fault=='stdin-close':stdin.close.side_effect=error
        serve = Mock(return_value=None)
        if fault == 'serve': serve.side_effect = error
        def setup(fd, blocking):
            self.assertFalse(blocking)
            if fault == 'pipe_setup' and fd == 22: raise error
        def launch(*args, **kwargs):
            self.assertEqual('launch', checks['stage'])
            self.assertEqual('in_progress', checks['status'])
            self.assertEqual(['docker', 'exec', '-i', 'a' * 64, '/usr/bin/python3', '-I',
                              '/opt/uas/uas/room_probe.py', 'denied-help-ready'], args[0])
            self.assertEqual({'stdin':subprocess.PIPE,'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}, kwargs)
            if fault == 'launch': raise error
            return process
        def write(fd, data):
            self.assertEqual(23,fd);self.assertEqual(DENIED_HELP_RELEASE,data)
            calls['write_stage']=checks['stage']
            if compose:
                self.assertTrue(calls['locked'])
                calls['order'].append('G')
                # Run the actual child barrier with the same logical timeline,
                # without a real process/thread. Its first clock is emission;
                # its select resumes only when the parent's G is scheduled.
                from uas import room_probe
                import uas.git_launcher as launcher
                emission = checks['release']['started_elapsed_seconds'] - delivery_lag
                child_now = [emission]
                def child_select(*args):
                    child_now[0] = clock[0] + child_schedule
                    return [0], [], []
                def git(*args, **kwargs):
                    calls['launcher'] += 1
                    return 128
                with patch.object(room_probe.time, 'monotonic', side_effect=lambda: child_now[0]), \
                     patch.object(room_probe.os, 'write', side_effect=lambda fd, data: len(data)), \
                     patch.object(room_probe.os, 'read', return_value=b'G'), \
                     patch.object(room_probe.select, 'select', side_effect=child_select), \
                     patch.object(launcher, 'main', side_effect=git):
                    try: room_probe.denied_help_ready()
                    except RuntimeError: calls['child_expired'] = True
            if fault=='release-write':raise error
            return 0 if fault=='short-release' else 1
        def release(write_fixed):
            if compose:
                tree = ast.parse((VM/'room_service.py').read_text())
                callback = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'release_unrelated')
                class Lock:
                    def __enter__(inner):
                        calls['order'].append('lock'); clock[0] += lock_cost
                        if gate_fault == 'lock': raise error
                        calls['locked'] = True
                    def __exit__(inner, *args):
                        calls['order'].append('unlock'); calls['locked'] = False
                def gate(name):
                    self.assertTrue(calls['locked'])
                    calls['order'].append(name); clock[0] += check_cost
                    if gate_fault == name: raise error
                env = dict(ExitStack=room_service.ExitStack, checks=checks,
                           observe_authority_phase=room_service.observe_authority_phase,
                           supervisor=SimpleNamespace(_locked=Lock), current=lambda: gate('current'),
                           resources=lambda: gate('resources'), backend=SimpleNamespace(admit=lambda state: gate('admit')),
                           state=object(), broker=SimpleNamespace(require=lambda: gate('broker')))
                exec(compile(ast.Module(body=[callback], type_ignores=[]), '<actual release callback>', 'exec'), env)
                return env['release_unrelated'](write_fixed)
            if fault=='release-gate':raise error
            if fault=='release-timeout':clock[0]+=5
            if fault!='no-release':write_fixed()
        def observed_clock():
            if (bookkeeping_cost and checks.get('stage') == 'startup'
                    and len(checks['startup']['milestones_observed_elapsed_seconds']) == 4
                    and not calls.get('bookkeeping_spent')):
                calls['bookkeeping_spent'] = True
                clock[0] += bookkeeping_cost
            if (release_bookkeeping_cost and 'release.broker' in checks.get('authority_phases', {})
                    and not calls.get('release_bookkeeping_spent')):
                calls['release_bookkeeping_spent'] = True
                clock[0] += release_bookkeeping_cost
            return clock[0]
        result = caught = None
        with patch.object(room_service.time, 'monotonic', side_effect=observed_clock), \
             patch.object(room_service.subprocess, 'Popen', side_effect=launch), \
             patch.object(room_service.select, 'select', side_effect=select), \
             patch.object(room_service.os, 'set_blocking', side_effect=setup), \
             patch.object(room_service.os, 'read', side_effect=read), \
             patch.object(room_service.os, 'write', side_effect=write):
            try:
                result = room_service.observe_unrelated_cli(listener, 'a' * 64, serve, checks=checks, release=release)
            except BaseException as failure:
                caught = failure
        return checks, result, caught, error, process, serve, calls

    def test_complete_capture_is_not_itself_an_authority_refusal(self):
        checks, result, error, _, process, serve, _ = self.exercise()
        self.assertIsNone(error)
        self.assertEqual((None, b'{"code":128}\n', DENIED_HELP_STARTUP+b'inert stderr\n'), result)
        self.assertEqual('collected', checks['status'])
        self.assertTrue(checks['connected'])
        self.assertNotIn('authority_refusal_proved', checks)
        self.assertEqual({'status': 'observed', 'returncode': 0}, checks['pre_cleanup_poll'])
        self.assertEqual(0, checks['returncode'])
        self.assertTrue(checks['cleanup']['reaped'])
        self.assertEqual([], checks['cleanup']['errors'])
        self.assertTrue(all(checks[name]['eof_observed'] for name in ('stdout', 'stderr')))
        process.kill.assert_not_called(); serve.assert_called_once()
        process.stdout.close.assert_called_once(); process.stderr.close.assert_called_once()

    def test_every_operation_failure_retains_first_error_and_owned_cleanup(self):
        for fault, stage in (('launch','launch'), ('pipe_setup','pipe_setup'),
                             ('accept-call','accept'), ('serve','serve'), ('read','collect')):
            with self.subTest(fault=fault):
                checks, result, caught, original, process, _, _ = self.exercise(fault)
                self.assertIs(original, caught)
                self.assertIsNone(result)
                self.assertEqual(('failed', stage), (checks['status'], checks['stage']))
                self.assertIn(stage, checks['stage_elapsed_seconds'])
                self.assertNotIn('authority_refusal_proved', checks)
                if fault != 'launch':
                    self.assertTrue(checks['cleanup']['kill_attempted'])
                    process.stdout.close.assert_called_once(); process.stderr.close.assert_called_once()
                if fault == 'pipe_setup': self.assertFalse(checks['stderr']['eof_observed'])
                if fault in ('accept-call', 'serve', 'read'):
                    self.assertEqual('{"code":128}\n', checks['stdout']['output'])
                    self.assertEqual(None, checks['pre_cleanup_poll']['returncode'])
                    self.assertEqual(-9, checks['returncode'])

    def test_no_connection_and_early_exit_never_count_as_refusal(self):
        for fault in ('accept-timeout', 'early-exit'):
            with self.subTest(fault=fault):
                checks, _, caught, _, process, serve, _ = self.exercise(fault)
                self.assertIsInstance(caught, TimeoutError)
                self.assertEqual('accept', checks['stage'])
                self.assertFalse(checks['connected'])
                serve.assert_not_called()
                self.assertEqual('{"code":128}\n', checks['stdout']['output'])
                self.assertNotIn('authority_refusal_proved', checks)
                if fault == 'early-exit':
                    self.assertEqual(7, checks['pre_cleanup_poll']['returncode'])
                    self.assertEqual(7, checks['returncode'])
                    process.kill.assert_not_called()

    def test_absolute_accept_deadline_is_not_reset_by_pipe_activity(self):
        checks, _, caught, _, _, serve, calls = self.exercise('flood')
        self.assertIsInstance(caught, TimeoutError)
        self.assertEqual('accept', checks['stage'])
        waits = [round(timeout,6) for accepting, timeout in calls['select'] if accepting and timeout>0][1:]
        self.assertEqual([5, 4, 3, 2, 1], waits)
        self.assertEqual(5.1, checks['cleanup']['started_elapsed_seconds'])
        serve.assert_not_called()

    def test_collection_timeout_or_wait_error_keeps_partial_output(self):
        for fault in ('collect-timeout', 'wait'):
            with self.subTest(fault=fault):
                checks, _, caught, _, _, _, _ = self.exercise(fault)
                self.assertIsInstance(caught, (TimeoutError, subprocess.TimeoutExpired))
                self.assertEqual('collect', checks['stage'])
                self.assertTrue(checks['connected'])
                self.assertEqual('{"code":128}\n', checks['stdout']['output'])
                self.assertTrue(checks['cleanup']['kill_attempted'])
                self.assertEqual(-9, checks['returncode'])

    def test_collection_and_cleanup_deadlines_are_not_reset_by_output(self):
        checks, _, caught, _, _, _, calls = self.exercise('collect-flood')
        self.assertIsInstance(caught, TimeoutError)
        self.assertEqual('collect', checks['stage'])
        waits = [round(timeout, 6) for accepting, timeout in calls['select'] if not accepting]
        self.assertEqual([5, 4, 3, 2, 1] * 2, waits)
        self.assertEqual(5.2, checks['cleanup']['started_elapsed_seconds'])
        self.assertEqual(10.2, checks['elapsed_seconds'])
        self.assertFalse(checks['stdout']['eof_observed'])
        self.assertIn('drain', [entry['operation'] for entry in checks['cleanup']['errors']])

    def test_cleanup_failure_never_masks_first_failure_or_becomes_pass(self):
        for fault, operation in (('kill', 'kill'), ('cleanup-wait', 'wait'),
                                 ('close', 'stdout_close'), ('poll', 'poll')):
            with self.subTest(fault=fault):
                checks, _, caught, _, process, _, _ = self.exercise(fault)
                if fault in ('kill', 'cleanup-wait'):
                    self.assertIsInstance(caught, TimeoutError)
                    self.assertEqual('accept', checks['stage'])
                else:
                    self.assertRegex(str(caught), 'cleanup incomplete')
                    self.assertEqual('cleanup', checks['stage'])
                    process.kill.assert_not_called()
                self.assertEqual('failed', checks['status'])
                self.assertIn(operation, [entry['operation'] for entry in checks['cleanup']['errors']])
                process.stderr.close.assert_called_once()

    def test_output_retention_is_bounded_while_all_bytes_are_counted(self):
        checks, result, caught, _, _, _, _ = self.exercise(noisy=True)
        self.assertIsNone(caught)
        self.assertEqual(4096, len(result[1]))
        self.assertEqual(65536, checks['stdout']['bytes'])
        self.assertTrue(checks['stdout']['truncated'])
        self.assertTrue(checks['stdout']['eof_observed'])
        self.assertLessEqual(len(checks['stdout']['output']), 4096)

    def test_caller_still_requires_actual_authority_refusal_and_no_worker(self):
        text = (VM/'room_service.py').read_text()
        source = ast.parse(text)
        prove = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                     and node.name == 'prove_service')
        code = ast.unparse(prove)
        self.assertLess(code.index("checks['unrelated_task'] = {}"), code.index('observe_unrelated_cli('))
        self.assertIn('lambda channel: serve_one(channel, service, authority, lifecycle_lock=supervisor._locked)', code)
        self.assertIn("observed['returncode'] == 0", code)
        self.assertIn("denied is None", code)
        self.assertIn("json.loads(stdout) == {'code': 128}", code)
        self.assertIn("effects['worker'] == 0", code)
        self.assertIn("not observed['stdout']['truncated']", code)
        self.assertIn("not observed['stderr']['truncated']", code)
        self.assertLess(code.index('same-UID unrelated task admitted'), code.index("observed['authority_refusal_proved'] = True"))


    def test_startup_readiness_fragmentation_does_not_change_final_stdout_contract(self):
        checks,result,caught,_,process,serve,calls=self.exercise('startup-fragmented')
        self.assertIsNone(caught);self.assertEqual(b'{"code":128}\n',result[1])
        self.assertTrue(checks['startup']['marker_observed'] and checks['startup']['release_sent'])
        self.assertEqual(len(DENIED_HELP_READY),checks['startup']['marker_bytes'])
        self.assertEqual('release',calls['write_stage']);serve.assert_called_once()
        self.assertTrue(checks['cleanup']['reaped'])

    def test_malformed_duplicate_oversize_early_output_exit_and_eof_never_release(self):
        for fault in ('startup-malformed','startup-duplicate','startup-oversized','startup-stdout',
                      'startup-listener','startup-exit','startup-eof','startup-timeout','startup-read','startup-flood'):
            with self.subTest(fault=fault):
                checks,result,caught,_,process,serve,calls=self.exercise(fault)
                self.assertIsNotNone(caught);self.assertIsNone(result)
                self.assertFalse(checks['startup']['release_sent']);self.assertNotIn('write_stage',calls)
                self.assertFalse(checks['connected']);serve.assert_not_called()
                self.assertEqual('failed',checks['status'])
                process.stdin.close.assert_called_once()

    def test_fresh_release_gate_write_and_late_ready_fail_closed(self):
        for fault in ('release-gate','release-write','release-timeout','short-release','no-release','early-at-release','stdin-close'):
            with self.subTest(fault=fault):
                checks,result,caught,original,process,serve,calls=self.exercise(fault)
                self.assertIsNotNone(caught);self.assertIsNone(result);serve.assert_not_called()
                self.assertFalse(checks['connected']);self.assertEqual('failed',checks['status'])
                if fault in ('release-gate','release-write','stdin-close'):self.assertIs(original,caught)
                if fault in ('release-gate','release-timeout','no-release','early-at-release'):
                    self.assertNotIn('write_stage',calls)
                self.assertTrue(process.stdin.close.called)

    def test_release_write_is_inside_same_fresh_lifecycle_lock(self):
        tree=ast.parse((VM/'room_service.py').read_text())
        callback=next(node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name=='release_unrelated')
        self.assertEqual(1,len(callback.body));self.assertIsInstance(callback.body[0],ast.With)
        text=ast.unparse(callback.body[0])
        self.assertIn('with ExitStack() as stack:',text)
        self.assertIn('stack.enter_context(supervisor._locked())',text)
        phases = ['release.' + name for name in ('lock','current','resources','admission','broker','write')]
        self.assertEqual(phases, [node.value for node in ast.walk(callback)
                         if isinstance(node, ast.Constant) and node.value in phases])



    def test_parent_and_child_release_phases_compose_without_spending_startup_twice(self):
        checks, result, caught, _, _, _, calls = self.exercise(
            startup=2.732526, check_cost=3.6527/4, compose=True)
        self.assertIsNone(caught)
        self.assertIsNotNone(result)
        self.assertEqual(['lock','current','resources','admit','broker','G','unlock'], calls['order'])
        self.assertEqual(1, calls['launcher'])
        self.assertEqual(5, checks['timeout_seconds']['release'])
        self.assertEqual(2.732526, checks['release']['started_elapsed_seconds'])
        self.assertEqual(7.732526, checks['release']['deadline_elapsed_seconds'])
        self.assertEqual(6.385226, checks['release']['sent_elapsed_seconds'])
        self.assertEqual('collected', checks['status'])
        self.assertNotIn('authority_refusal_proved', checks)

    def test_startup_lock_and_fresh_check_costs_fail_at_exact_phase_bounds(self):
        for kwargs in (dict(startup=5), dict(startup=5.1), dict(lock_cost=5),
                       dict(check_cost=1.25), dict(lock_cost=2, check_cost=.75),
                       dict(check_cost=2)):
            with self.subTest(kwargs=kwargs):
                checks, result, caught, _, _, serve, calls = self.exercise(compose=True, **kwargs)
                self.assertIsNotNone(caught); self.assertIsNone(result)
                self.assertNotIn('write_stage', calls); self.assertEqual(0, calls['launcher'])
                serve.assert_not_called(); self.assertFalse(checks['startup']['release_sent'])
                self.assertEqual('failed', checks['status'])
                self.assertTrue(checks['cleanup']['reaped'])

    def test_each_fresh_gate_failure_preserves_locked_order_and_never_writes(self):
        gates = ['current','resources','admit','broker']
        for index, gate in enumerate(gates):
            with self.subTest(gate=gate):
                checks, result, caught, original, _, serve, calls = self.exercise(compose=True, gate_fault=gate)
                self.assertIs(original, caught); self.assertIsNone(result)
                self.assertEqual(['lock', *gates[:index+1], 'unlock'], calls['order'])
                self.assertNotIn('write_stage', calls); self.assertEqual(0, calls['launcher'])
                serve.assert_not_called(); self.assertEqual('release', checks['stage'])
                self.assertTrue(checks['cleanup']['reaped'])

    def test_delayed_delivery_and_G_scheduling_cannot_extend_child_deadline(self):
        for lag, schedule in ((2,0), (0,2), (1,1)):
            with self.subTest(lag=lag, schedule=schedule):
                checks, result, caught, _, _, serve, calls = self.exercise(
                    compose=True, startup=2.73, check_cost=.8, delivery_lag=lag, child_schedule=schedule)
                self.assertTrue(checks['startup']['release_sent'])
                self.assertEqual(0, calls['launcher']); self.assertTrue(calls['child_expired'])
                self.assertIsInstance(caught, TimeoutError); self.assertIsNone(result)
                serve.assert_not_called(); self.assertFalse(checks['connected'])
                self.assertNotIn('authority_refusal_proved', checks)
                self.assertEqual('failed', checks['status']); self.assertTrue(checks['cleanup']['reaped'])

    def test_marker_fragments_never_restart_startup_or_release_phase(self):
        checks, _, caught, _, _, _, calls = self.exercise('startup-fragmented', startup=2, compose=True)
        self.assertIsNone(caught)
        self.assertEqual(4, checks['release']['started_elapsed_seconds'])
        self.assertEqual(9, checks['release']['deadline_elapsed_seconds'])
        waits = [t for has_listener,t in calls['select'] if has_listener and t > 0]
        self.assertEqual([5,3], waits[:2])
        checks, result, caught, _, _, serve, calls = self.exercise('startup-fragmented', startup=2.5, compose=True)
        self.assertIsNotNone(caught); self.assertIsNone(result)
        self.assertNotIn('release', checks); self.assertNotIn('write_stage', calls)
        serve.assert_not_called()

    def test_each_fixed_milestone_is_observed_without_granting_readiness(self):
        through = b''
        for index, (name, marker) in enumerate(DENIED_HELP_STARTUP_STEPS[:-1]):
            through += marker
            with self.subTest(name=name):
                checks, result, caught, _, _, serve, calls = self.exercise(startup_chunks=[through, b''])
                self.assertIsNotNone(caught); self.assertIsNone(result)
                observed = checks['startup']['milestones_observed_elapsed_seconds']
                self.assertEqual([step for step, _ in DENIED_HELP_STARTUP_STEPS[:index+1]], list(observed))
                self.assertTrue(all(value == .1 for value in observed.values()))
                self.assertFalse(checks['startup']['marker_observed'])
                self.assertFalse(checks['startup']['release_sent'])
                self.assertNotIn('write_stage', calls); serve.assert_not_called()
                self.assertNotIn('authority_refusal_proved', checks)
                self.assertTrue(checks['stderr']['output'].startswith(through.decode()))
                self.assertTrue(checks['cleanup']['reaped'])

    def test_every_fragment_boundary_and_coalesced_sequence_keep_same_protocol(self):
        for split in range(1, len(DENIED_HELP_STARTUP)):
            with self.subTest(split=split):
                checks, result, caught, _, _, serve, _ = self.exercise(startup_chunks=[
                    DENIED_HELP_STARTUP[:split], DENIED_HELP_STARTUP[split:], b'inert stderr\n', b''])
                self.assertIsNone(caught); self.assertEqual(b'{"code":128}\n', result[1])
                self.assertEqual([name for name, _ in DENIED_HELP_STARTUP_STEPS],
                    list(checks['startup']['milestones_observed_elapsed_seconds']))
                serve.assert_called_once()

    def test_missing_reordered_corrupt_and_duplicate_milestones_never_release(self):
        markers = [marker for _, marker in DENIED_HELP_STARTUP_STEPS]
        invalid = [DENIED_HELP_READY, b''.join(reversed(markers))]
        for index, marker in enumerate(markers):
            invalid.extend((b''.join(markers[:index] + markers[index+1:]),
                            b''.join(markers[:index] + [marker, marker] + markers[index+1:]),
                            b''.join(markers[:index]) + b'BAD\n'))
        for raw in invalid:
            with self.subTest(raw=raw):
                checks, result, caught, _, _, serve, calls = self.exercise(startup_chunks=[raw, b''])
                self.assertIsNotNone(caught); self.assertIsNone(result)
                self.assertFalse(checks['startup']['release_sent'])
                self.assertNotIn('write_stage', calls); serve.assert_not_called()
                self.assertTrue(checks['cleanup']['reaped'])

    def test_milestone_fragments_and_stalls_never_restart_startup_deadline(self):
        markers = [marker for _, marker in DENIED_HELP_STARTUP_STEPS]
        checks, result, caught, _, _, serve, calls = self.exercise(startup_chunks=markers, startup=1.25)
        self.assertIsNotNone(caught); self.assertIsNone(result)
        self.assertEqual([5, 3.75, 2.5, 1.25],
                         [t for listener, t in calls['select'] if listener and t > 0])
        self.assertFalse(checks['startup']['release_sent']); serve.assert_not_called()
        self.assertEqual(['python_entry', 'probe_imported', 'launcher_imported'],
                         list(checks['startup']['milestones_observed_elapsed_seconds']))
        self.assertEqual(5, checks['cleanup']['started_elapsed_seconds'])

    def test_all_late_duplicate_diagnostics_fail_without_becoming_refusal(self):
        for name, marker in DENIED_HELP_STARTUP_STEPS:
            with self.subTest(name=name):
                checks, result, caught, _, _, _, _ = self.exercise(after_startup=marker)
                self.assertIsNotNone(caught); self.assertIsNone(result)
                self.assertEqual('failed', checks['status'])
                self.assertNotIn('authority_refusal_proved', checks)
                self.assertEqual([step for step, _ in DENIED_HELP_STARTUP_STEPS],
                                 list(checks['startup']['milestones_observed_elapsed_seconds']))
                self.assertLessEqual(len(checks['stderr']['output']), 4096)


    def test_startup_bookkeeping_cannot_make_late_ready_eligible_for_release(self):
        for cost in (4.9, 5):
            with self.subTest(cost=cost):
                checks, result, caught, _, _, serve, calls = self.exercise(bookkeeping_cost=cost)
                self.assertIsNotNone(caught); self.assertIsNone(result)
                self.assertTrue(calls['bookkeeping_spent'])
                self.assertEqual(4, len(checks['startup']['milestones_observed_elapsed_seconds']))
                self.assertFalse(checks['startup']['marker_observed'])
                self.assertFalse(checks['startup']['release_sent'])
                self.assertNotIn('release', checks); self.assertNotIn('write_stage', calls)
                serve.assert_not_called(); self.assertTrue(checks['cleanup']['reaped'])


    def test_release_gate_timings_are_fixed_success_aggregates_under_same_lock(self):
        checks, result, caught, _, _, _, calls = self.exercise(
            compose=True, lock_cost=.25, check_cost=.5)
        self.assertIsNone(caught); self.assertIsNotNone(result)
        self.assertEqual(['lock','current','resources','admit','broker','G','unlock'], calls['order'])
        phases = checks['authority_phases']
        expected = {'lock':.25, 'current':.5, 'resources':.5, 'admission':.5, 'broker':.5, 'write':0}
        self.assertEqual({'release.' + name for name in expected}, set(phases))
        for name, elapsed in expected.items():
            self.assertEqual(dict(calls=1, failures=0, last_seconds=elapsed,
                                  max_seconds=elapsed, total_seconds=elapsed), phases['release.' + name])

    def test_release_timings_retain_completed_and_failing_gate_without_G(self):
        gates = ['lock','current','resources','admit','broker']
        for index, gate in enumerate(gates):
            with self.subTest(gate=gate):
                checks, result, caught, original, _, serve, calls = self.exercise(
                    compose=True, gate_fault=gate, lock_cost=.25, check_cost=.5)
                self.assertIs(original, caught); self.assertIsNone(result)
                names = ['release.' + ('admission' if name == 'admit' else name) for name in gates[:index+1]]
                self.assertEqual(names, list(checks['authority_phases']))
                for name in names:
                    self.assertEqual(int(name == names[-1]), checks['authority_phases'][name]['failures'])
                self.assertEqual(.25 if gate == 'lock' else .5,
                                 checks['authority_phases'][names[-1]]['last_seconds'])
                self.assertNotIn('write_stage', calls); self.assertEqual(0, calls['launcher'])
                self.assertEqual(['lock'] if gate == 'lock' else ['lock',*gates[1:index+1],'unlock'], calls['order'])
                serve.assert_not_called(); self.assertTrue(checks['cleanup']['reaped'])

    def test_release_write_failure_retains_all_timings_and_unlocks(self):
        checks, result, caught, original, _, serve, calls = self.exercise('release-write', compose=True)
        self.assertIs(original, caught); self.assertIsNone(result)
        self.assertEqual(1, checks['authority_phases']['release.write']['failures'])
        self.assertFalse(calls['locked']); self.assertEqual('unlock', calls['order'][-1])
        self.assertFalse(checks['startup']['release_sent']); serve.assert_not_called()
        self.assertTrue(checks['cleanup']['reaped'])

    def test_release_timing_bookkeeping_cannot_make_late_G_eligible(self):
        checks, result, caught, _, _, serve, calls = self.exercise(
            compose=True, check_cost=1, release_bookkeeping_cost=1)
        self.assertIsNotNone(caught); self.assertIsNone(result)
        self.assertTrue(calls['release_bookkeeping_spent'])
        self.assertNotIn('write_stage', calls); self.assertEqual(0, calls['launcher'])
        self.assertEqual(1, checks['authority_phases']['release.write']['failures'])
        self.assertFalse(checks['startup']['release_sent']); self.assertFalse(calls['locked'])
        serve.assert_not_called(); self.assertTrue(checks['cleanup']['reaped'])


    def test_release_timings_survive_normal_and_overflow_report_with_primary_cleanup(self):
        phases = {'release.' + name: dict(calls=1, failures=int(name == 'broker'),
                  last_seconds=.5, max_seconds=.5, total_seconds=.5)
                  for name in ('lock','current','resources','admission','broker')}
        endpoint = dict(status='failed', authority_phases=phases,
                        cleanup=dict(status='failed', errors=[dict(owner='broker', error_type='OSError')]))
        report = dict(version=1, nonce='inert', profile=guest_room.PROFILE,
                      production_enabled=False, failure=dict(error_type='PrimaryFailure'),
                      checks=dict(endpoint_service=endpoint))
        self.assertEqual(report, json.loads(guest_room.encode_report(report)))
        report['padding'] = 'x' * 65536
        encoded = guest_room.encode_report(report)
        self.assertLessEqual(len(encoded), 65536)
        compact = json.loads(encoded)
        self.assertEqual(phases, compact['checks']['endpoint_service']['authority_phases'])
        self.assertEqual('PrimaryFailure', compact['primary_failure']['error_type'])
        self.assertEqual('ReportBudgetExceeded', compact['failure']['error_type'])
        self.assertEqual(endpoint['cleanup'], compact['checks']['endpoint_service']['cleanup'])
        self.assertTrue(compact['report_overflow']); self.assertTrue(compact['evidence_omitted'])

    def test_release_overflow_projection_drops_unknown_malformed_and_unbounded_fields(self):
        phases = {'payload': 'secret' * 20000, 'release.lock': 'not a timing',
                  'release.current': dict(calls=2**100, failures=True, last_seconds=float('nan'),
                                          max_seconds=float('inf'), total_seconds=-1),
                  'release.resources': dict(calls=1, failures=0, last_seconds=.25,
                                            max_seconds=.25, total_seconds=.25, payload='secret')}
        report = dict(version=1, nonce='inert', profile=guest_room.PROFILE,
                      production_enabled=False, checks=dict(endpoint_service=dict(
                          status='failed', authority_phases=phases)))
        encoded = guest_room.encode_report(report)
        self.assertLessEqual(len(encoded), 65536)
        compact = json.loads(encoded)
        self.assertEqual({'release.resources':dict(calls=1, failures=0, last_seconds=.25,
                          max_seconds=.25, total_seconds=.25)},
                         compact['checks']['endpoint_service']['authority_phases'])
        self.assertTrue(compact['report_overflow'])
        self.assertNotIn('secret', encoded); self.assertNotIn('NaN', encoded); self.assertNotIn('Infinity', encoded)
