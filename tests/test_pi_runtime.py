"""Actual official Pi CLI, account-free official faux provider; no mock Pi.

Native suite is opt-in locally and mandatory in the dedicated CI job. The
aggregate always checks adapter source compilation, never calls a skip a pass.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import threading
import unittest

from uas.ledger import LedgerError, RoomLedger
from uas.peer import FixtureParticipant, FixturePeerHub, Readiness, RequestCommand, WorkRequest
from uas.pi_runtime import FixturePiRpcReceiver, NativeUnavailable

ROOT = Path(__file__).resolve().parents[1]
INSTALL = os.environ.get('UAS_PI_INSTALL')


@unittest.skipUnless(INSTALL, 'Set UAS_PI_INSTALL for the mandatory official Pi native CI suite')
class PiNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A locked installation is shared, never a session or process. Probe the
        # actual executable once per class run, not before every RPC restart.
        # Clear first so a later failed class setup cannot reuse earlier proof.
        cls.runtime_version = None
        install = Path(INSTALL).resolve()
        package = install / 'node_modules/@earendil-works/pi-coding-agent'
        if json.loads((package / 'package.json').read_text())['version'] != '1.4.0':
            raise AssertionError('Official Pi 1.4.0 required')
        with tempfile.TemporaryDirectory(prefix='uas-pi-version-') as directory:
            home = Path(directory)
            (home / 'agent').mkdir()
            env = {'PATH': os.environ['PATH'], 'HOME': str(home),
                   'PI_CODING_AGENT_DIR': str(home / 'agent'), 'PI_OFFLINE': '1',
                   'NODE_OPTIONS': '--import=' + str(ROOT / 'tests/pi/network-guard.mjs'),
                   'UAS_PI_FAUX_MODULE': str(install / 'node_modules/@earendil-works/pi-ai/dist/providers/faux.js')}
            version = subprocess.run([shutil.which('node'), str(package / 'dist/cli.js'), '--version'],
                                     env=env, cwd=home, capture_output=True, text=True,
                                     check=True, timeout=10).stdout.strip()
            if version != '1.4.0':
                raise AssertionError('Official Pi CLI 1.4.0 required')
        cls.runtime_version = version

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='uas-pi-')
        self.root = Path(self.temp.name)
        self.native = None
        self.install = Path(INSTALL).resolve()
        self.pkg = self.install / 'node_modules/@earendil-works/pi-coding-agent'
        self.assertEqual(json.loads((self.pkg / 'package.json').read_text())['version'], '1.4.0')
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('sender', 'actor-a'),
                                        FixtureParticipant('pi', 'actor-p')), 'run-1')
        self.sender = self.hub.connect('sender-attach', 'sender', 'sender-inc', object())
        self.start()

    def start(self, session=None):
        home = self.root / 'home'
        home.mkdir(exist_ok=True)
        (home / 'agent').mkdir(exist_ok=True)
        (home / 'agent/settings.json').write_text(json.dumps({'compaction': {
            'enabled': False, 'keepRecentTokens': 128, 'reserveTokens': 1024}, 'retry': {'enabled': False}}))
        env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'PI_CODING_AGENT_DIR': str(home / 'agent'),
               'PI_OFFLINE': '1', 'NODE_OPTIONS': '--import=' + str(ROOT / 'tests/pi/network-guard.mjs'), 'UAS_PI_FAUX_MODULE': str(self.install / 'node_modules/@earendil-works/pi-ai/dist/providers/faux.js')}
        argv = [shutil.which('node'), str(self.pkg / 'dist/cli.js'), '--mode', 'rpc', '--no-tools',
                '--no-extensions', '--no-skills', '--no-prompt-templates', '--no-themes',
                '-e', str(ROOT / 'runtime/pi/extension.mjs'), '-e', str(ROOT / 'tests/pi/provider.mjs'),
                '--provider', 'faux', '--model', 'faux-1', '--session-dir', str(self.root / 'sessions')]
        if session:
            argv += ['--session', session]
        self.assertEqual(self.runtime_version, '1.4.0')
        self.native = FixturePiRpcReceiver(argv, cwd=self.root, env=env, journal=self.root / 'intent.db',
                                          runtime_version=self.runtime_version, scope={'room_id': 'alpha', 'participant_id': 'pi',
                                          'run_id': 'run-1', 'generation': 1, 'context_generation': 1})
        self.connection = self.hub.connect('pi-' + self.native.initial_state['runtime_id'], 'pi',
                                          self.native.initial_state['runtime_id'], self.native)

    def tearDown(self):
        if self.native:
            if os.environ.get('UAS_PI_EVIDENCE'):
                events = self.native.event_snapshot()
                evidence = {'case': self.id(), **self.native.evidence(),
                            'rpc_event_types': sorted({event.get('type', 'unknown') for event in events}),
                            'queue_dispositions': sorted({event.get('data', {}).get('disposition') for event in events
                                if event.get('type') == 'response' and type(event.get('data')) is dict
                                and event['data'].get('disposition') in ('started', 'queued', 'handled')})}
                with open(os.environ['UAS_PI_EVIDENCE'], 'a', encoding='utf8') as output:
                    output.write(json.dumps(evidence, sort_keys=True) + '\n')
            self.native.close()
        self.ledger.close()
        self.temp.cleanup()

    def state(self):
        return self.hub.snapshot()['state']['peer_traffic']

    def submit(self, id='work-1'):
        return self.hub.submit(self.sender, WorkRequest(id, 'run-1', 1, 'pi', 'Inspect → fixture safely.'))

    def deliver(self):
        self.hub.observe(self.connection, self.native.observe())
        return self.hub.deliver(self.connection)

    def idle(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.native.observe() is Readiness.SAFE:
                return
            time.sleep(.02)
        self.fail('Pi did not become idle: ' + repr(list(self.native.errors)))

    def entries(self):
        return self.native.rpc('get_entries')['data']['entries']

    def custom(self):
        return [e for e in self.entries() if e.get('type') == 'custom_message' and e.get('customType') == 'uas-peer-v1']

    def test_first_ever_delivery_has_native_persisted_receipt_without_priming(self):
        self.assertFalse(Path(self.native.initial_state['session_file']).exists())
        # Reuse this already-running account-free pinned Pi: prove its actual
        # state notification/prompt ACK pair supports the activation sample.
        sample = self.native.prepare_admission_observation()
        self.assertIs(self.native.validate_admission_observation(sample), Readiness.SAFE)
        self.assertIs(self.native.validate_admission_observation(sample, consume=True), Readiness.SAFE)
        with self.assertRaises(NativeUnavailable):
            self.native.validate_admission_observation(sample, consume=True)
        self.assertFalse(Path(self.native.initial_state['session_file']).exists())
        self.submit()
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(self.state()['traffic']['work-1']['status'], 'DELIVERED')
        self.assertEqual(len(self.custom()), 1)
        self.assertEqual(self.native.evidence()['native_receipts'], 1)
        self.assertIn('custom_message', Path(self.native.initial_state['session_file']).read_text())
        self.assertEqual(self.state()['traffic']['work-1']['status'], 'DELIVERED', 'delivery is not Participant acceptance')

    def test_long_turn_held_abort_settled_then_delivery(self):
        self.native.rpc('prompt', message='/fixture-delay 2000')
        self.native.rpc('prompt', message='Begin a long native fixture turn')
        self.submit()
        self.assertIs(self.native.observe(), Readiness.BUSY)
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertEqual(self.custom(), [])
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.native.rpc('abort')
        self.native.rpc('prompt', message='/fixture-delay 0')
        self.idle()
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertTrue(any(e.get('type') == 'agent_settled' for e in self.native.event_snapshot()))

    def test_lost_hub_confirmation_reconciles_without_second_native_injection(self):
        self.submit()
        original = self.native.accept
        def lose_receipt(envelope):
            original(envelope)
            raise LedgerError('SIMULATED_LOST_RETURN')
        self.native.accept = lose_receipt
        with self.assertRaisesRegex(LedgerError, 'SIMULATED_LOST_RETURN'):
            self.deliver()
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.assertEqual(len(self.custom()), 1)
        self.native.accept = original
        self.idle()
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(len(self.custom()), 1)

    def test_same_session_process_restore_preserves_accepted_work_and_deduplicates(self):
        self.submit()
        self.deliver()
        self.hub.submit(self.connection, RequestCommand('accept', 'run-1', 1, 'work-1', 'accept'))
        file = self.native.initial_state['session_file']
        old = self.connection
        self.native.close()
        self.native = None
        self.start(file)
        self.assertNotEqual(old.incarnation_id, self.connection.incarnation_id)
        self.assertEqual(self.hub.deliver(old)['outcome'], 'HELD')
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(self.state()['traffic']['work-1']['status'], 'ACCEPTED')
        self.assertEqual(len(self.custom()), 1)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Actual stopped-process bounded pipe test requires Linux')
    def test_sigstop_large_handoff_has_bounded_write_and_fenced_restart_recovery(self):
        # Real native session exists before the uncertain frame, so restoration
        # can inspect it and prove no receipt without resending the lost frame.
        self.native.rpc('prompt', message='Create a persisted native fixture session')
        self.idle()
        file = self.native.initial_state['session_file']
        self.hub.submit(self.sender, WorkRequest('work-1', 'run-1', 1, 'pi', 'x' * 16000))
        original = self.native._native
        def stop_before_write(command, payload):
            if command == 'delivery' and payload.get('action') == 'inject':
                os.kill(self.native.process.pid, signal.SIGSTOP)
            return original(command, payload)
        self.native._native = stop_before_write
        # Make pipe capacity deterministic without enlarging it or changing the
        # host: this descriptor belongs solely to this disposable child.
        import fcntl
        fcntl.fcntl(self.native.process.stdin.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        self.native.timeout = .25
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
                self.deliver()
            self.assertLess(time.monotonic() - started, 2)
            self.assertTrue(self.native.evidence()['transport_fenced'])
            self.assertEqual(self.native.evidence()['unknown_intents'], 1)
            self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
            # Resume does not authorize appending a command to the partial JSON.
            os.kill(self.native.process.pid, signal.SIGCONT)
            with self.assertRaisesRegex(NativeUnavailable, 'fenced'):
                self.native.rpc('get_state')
        finally:
            self.native.process.kill()
            self.native.process.wait(timeout=3)
        self.native.close()
        self.native = None
        self.start(file)
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertEqual(self.custom(), [])
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])

    def race_native_busy_before_inject(self):
        self.native.rpc('prompt', message='/fixture-delay 700')
        original = self.native._native
        raced = False
        def race(command, payload):
            nonlocal raced
            if command == 'delivery' and payload.get('action') == 'inject' and not raced:
                raced = True
                self.native.rpc('prompt', message='Independent native turn wins the safe-point race')
            return original(command, payload)
        self.native._native = race

    def test_safe_to_busy_race_proven_not_applied_can_retry_once_after_settled(self):
        self.race_native_busy_before_inject()
        self.submit()
        with self.assertRaisesRegex(LedgerError, 'NATIVE_NOT_SAFE'):
            self.deliver()
        self.assertEqual(self.native.evidence()['retryable_pre_effect_refusals'], 1)
        self.assertEqual(self.native.evidence()['unknown_intents'], 0)
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.assertEqual(self.custom(), [])
        self.native.rpc('prompt', message='/fixture-delay 0')
        self.idle()
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(self.native.evidence()['retryable_pre_effect_refusals'], 0)
        self.assertEqual(len(self.custom()), 1)

    def test_failure_persisting_not_applied_stays_unknown_and_never_reinjects(self):
        self.race_native_busy_before_inject()
        self.native.db.execute("CREATE TRIGGER fail_refusal BEFORE UPDATE ON handoffs "
                               "WHEN NEW.state='NOT_APPLIED' BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END")
        self.native.db.commit()
        self.submit()
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        self.assertEqual(self.native.evidence()['retryable_pre_effect_refusals'], 0)
        self.native.db.execute('DROP TRIGGER fail_refusal')
        self.native.db.commit()
        self.idle()
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertEqual(self.custom(), [])
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])

    def test_slow_first_flush_stays_unconfirmed_then_read_only_retry_recovers(self):
        self.native.rpc('prompt', message='/fixture-delay 1000')
        self.native.timeout = .15
        self.submit()
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        self.native.timeout = 8
        self.idle()
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(len(self.custom()), 1)

    def test_wrong_native_scope_is_rejected_before_intent_or_injection(self):
        self.submit()
        original = self.native.accept
        def wrong_scope(envelope):
            for key, value in [('room_id', 'other'), ('participant_id', 'other'),
                               ('run_id', 'other'), ('generation', 2), ('context_generation', 2),
                               ('incarnation_id', 'stale')]:
                with self.assertRaisesRegex(LedgerError, 'NATIVE_SCOPE_MISMATCH'):
                    original({**envelope, key: value})
            raise LedgerError('TEST_SCOPE_REJECTED')
        self.native.accept = wrong_scope
        with self.assertRaisesRegex(LedgerError, 'TEST_SCOPE_REJECTED'):
            self.deliver()
        self.assertEqual(self.native.evidence()['unknown_intents'], 0)
        self.assertEqual(self.custom(), [])
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.native.accept = original
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')

    def test_mismatched_native_receipt_never_confirms_and_retry_does_not_reinject(self):
        self.submit()
        original = self.native._native
        def corrupt(command, payload):
            result = original(command, payload)
            if command == 'delivery' and result.get('receipt'):
                result['receipt']['logical_digest'] = 'wrong'
            return result
        self.native._native = corrupt
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.native._native = original
        self.idle()
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(len(self.custom()), 1)

    def test_hub_restart_and_lost_receipt_recover_without_duplicate_native_input(self):
        self.submit()
        original = self.native.accept
        def lose_receipt(envelope):
            original(envelope)
            raise LedgerError('SIMULATED_LOST_RETURN')
        self.native.accept = lose_receipt
        with self.assertRaisesRegex(LedgerError, 'SIMULATED_LOST_RETURN'):
            self.deliver()
        self.assertEqual(len(self.custom()), 1)
        file = self.native.initial_state['session_file']
        self.native.close()
        self.native = None
        self.ledger.close()
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.hub = FixturePeerHub(self.ledger)
        self.start(file)
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertEqual(len(self.custom()), 1)
        self.assertEqual(self.state()['traffic']['work-1']['status'], 'DELIVERED')

    def test_native_new_session_fences_old_handle_without_claiming_cross_run_reset(self):
        old = self.native.initial_state['session_id']
        self.assertFalse(self.native.rpc('new_session')['data']['cancelled'])
        self.assertIs(self.native.observe(), Readiness.LOST)
        self.assertEqual(self.native.evidence()['adapter_readiness'], 'lost')
        self.assertNotEqual(self.native.rpc('get_state')['data']['sessionId'], old)
        self.submit()
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])

    def test_native_steer_and_follow_up_are_queued_not_completed(self):
        self.native.rpc('prompt', message='/fixture-delay 500')
        self.native.rpc('prompt', message='Long fixture input')
        for command in ('steer', 'follow_up'):
            result = self.native.rpc(command, message=f'Native {command} input')
            self.assertEqual(result['data']['disposition'], 'queued')
        self.assertGreaterEqual(self.native.rpc('get_state')['data']['pendingMessageCount'], 1)
        self.submit()
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.native.rpc('prompt', message='/fixture-delay 0')
        self.idle()
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        users = [e['message'] for e in self.entries() if e.get('type') == 'message' and e.get('message', {}).get('role') == 'user']
        self.assertEqual(len(users), 3)

    def test_actual_compaction_holds_then_fresh_observation_releases(self):
        self.native.rpc('prompt', message='Create a native conversation for compaction ' * 300)
        self.idle()
        self.native.rpc('prompt', message='Add native conversation for compaction ' * 300)
        self.idle()
        self.native.rpc('prompt', message='/fixture-delay 1000')
        result, errors = [], []
        def compact():
            try:
                result.append(self.native.rpc('compact'))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=compact)
        worker.start()
        try:
            deadline = time.monotonic() + 5
            while self.native.observe() is not Readiness.COMPACTING:
                if time.monotonic() > deadline:
                    self.fail('No actual compaction observation: ' + repr(result) + repr(errors))
                time.sleep(.01)
            self.submit()
            self.assertEqual(self.deliver()['outcome'], 'HELD')
            self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        finally:
            worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(result), 1)
        self.native.rpc('prompt', message='/fixture-delay 0')
        self.idle()
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')
        self.assertTrue(any(e.get('type') == 'compaction_start' for e in self.native.event_snapshot()))
        self.assertTrue(any(e.get('type') == 'compaction_end' for e in self.native.event_snapshot()))

    def test_crash_before_first_native_flush_keeps_unknown_intent_without_reinjection(self):
        self.native.rpc('prompt', message='/fixture-delay 60000')
        self.submit()
        original = self.native._native
        def crash(command, payload):
            result = original(command, payload)
            if command == 'delivery' and payload.get('action') == 'inject':
                self.assertFalse(Path(self.native.initial_state['session_file']).exists())
                self.native.process.kill()
                self.native.process.wait(timeout=3)
            return result
        self.native._native = crash
        with self.assertRaisesRegex(LedgerError, 'UNCONFIRMED_NATIVE_DELIVERY'):
            self.deliver()
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.assertEqual(self.native.evidence()['unknown_intents'], 1)
        self.native.close()
        self.native = None
        self.start()
        with self.assertRaisesRegex(LedgerError, 'NATIVE_SESSION_MISMATCH'):
            self.deliver()
        self.assertEqual(self.custom(), [])
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])

    def test_missing_extension_signal_holds_even_when_process_alive(self):
        self.submit()
        original = self.native._native
        self.native._native = lambda *_: (_ for _ in ()).throw(NativeUnavailable('missing signal'))
        self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
        self.native._native = original
        self.assertEqual(self.deliver()['outcome'], 'CONFIRMED')

    def test_process_exit_holds(self):
        self.submit()
        self.native.process.kill()
        self.native.process.wait(timeout=3)
        self.assertIs(self.native.observe(), Readiness.LOST)
        self.assertEqual(self.deliver()['outcome'], 'HELD')
        self.assertIsNone(self.state()['traffic']['work-1']['response_started_at'])
