"""Non-model state-query applicability probe, NOT a new adapter readiness rule."""
import json
import os
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from claude.readiness_probe import MAX_OUTPUT, query, summarize
from uas.claude_runtime import DirectClaudeDiagnosticReceiver, require_loopback_namespace
from uas.peer import Readiness


class ClaudeListingSourceTests(unittest.TestCase):
    def test_absence_and_identity_mismatch_never_authorize_delivery(self):
        for rows, expected in (([], 'not-listed'),
                               ([{'pid': 10, 'sessionId': 'other', 'status': 'idle'}], 'identity-mismatch'),
                               ([{'pid': 11, 'sessionId': 'ours', 'status': 'idle'}], 'identity-mismatch')):
            result = summarize(json.dumps(rows), pid=10, session_id='ours')
            self.assertEqual(result['applicability'], expected)
            self.assertEqual(result['exact_identity_count'], 0)
            self.assertFalse(result['authorizes_delivery'])

    def test_exact_identity_is_diagnostic_even_for_idle_or_waiting(self):
        for status in ('idle', 'busy', 'waiting', 'new-unknown-status'):
            result = summarize(json.dumps([{'pid': 10, 'sessionId': 'ours', 'status': status}]),
                               pid=10, session_id='ours')
            self.assertEqual(result['applicability'], 'exact-identity-reported')
            self.assertEqual(result['exact_identity_count'], 1)
            self.assertFalse(result['authorizes_delivery'])

    def test_bounded_structured_listing_required(self):
        for output in ('{}', '[1]', 'null', 'not json', json.dumps([{}] * 65), ' ' * (MAX_OUTPUT + 1)):
            with self.subTest(output=output[:30]), self.assertRaises(ValueError):
                summarize(output, pid=10, session_id='ours')

    def test_query_caps_both_output_pipes(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream), tempfile.TemporaryDirectory() as root:
                producer = Path(root) / 'synthetic-output'
                producer.write_text('#!/usr/bin/python3\nimport sys\nsys.' + stream + '.write("x" * 300000)\n')
                producer.chmod(0o700)
                with self.assertRaisesRegex(ValueError, 'oversized session query output'):
                    query(producer, cwd=root, env={'PATH': '/usr/bin:/bin'}, pid=10, session_id='ours')


INSTALL = os.environ.get('UAS_CLAUDE_INSTALL')


@unittest.skipUnless(INSTALL, 'Official Claude applicability probe requires mandatory loopback-only CI')
class ClaudeListingNativeTests(unittest.TestCase):
    def setUp(self):
        from claude.probe import Gateway, Handler
        require_loopback_namespace()
        self.temp = tempfile.TemporaryDirectory(prefix='uas-claude-listing-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.gateway = Gateway(('127.0.0.1', 0), Handler)
        self.gateway.key = 'fixture-only-' + uuid.uuid4().hex
        self.gateway.requests = []
        self.gateway.release = threading.Event()
        self.gateway.entered = threading.Event()
        self.thread = threading.Thread(target=self.gateway.serve_forever,
                                       kwargs={'poll_interval': .05}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_gateway)
        self.binary = Path(INSTALL) / 'node_modules/@anthropic-ai/claude-code-linux-x64/claude'
        self.scope = {'room_id': 'listing', 'participant_id': 'claude', 'run_id': 'run-1',
                      'generation': 1, 'context_generation': 1}
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.home),
                    'CLAUDE_CONFIG_DIR': str(self.home / 'config'),
                    'ANTHROPIC_BASE_URL': f'http://127.0.0.1:{self.gateway.server_port}',
                    'ANTHROPIC_API_KEY': self.gateway.key,
                    'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1'}
        self.native = None
        self.addCleanup(self.close_native)
        self.observations = []

    def close_gateway(self):
        self.gateway.release.set()
        self.gateway.shutdown()
        self.gateway.server_close()
        self.thread.join(timeout=3)

    def close_native(self):
        if self.native is not None:
            self.native.close()
            self.native = None

    def start_unprimed(self, *, resume=False):
        # Only skip the fixture's synthetic bootstrap; do not replace native
        # stdout, events, state-query output, arguments, or signal processing.
        # This diagnostic deliberately cannot hand traffic through the Hub.
        with patch.object(DirectClaudeDiagnosticReceiver, 'refresh', lambda _self: None):
            self.native = DirectClaudeDiagnosticReceiver(self.binary, cwd=self.root, home=self.home,
                gateway_url=self.env['ANTHROPIC_BASE_URL'], fixture_key=self.gateway.key,
                journal=self.root / 'intent.db', scope=self.scope, resume=resume)

    def sample(self, phase):
        before = len(self.gateway.requests)
        result = query(self.binary, cwd=self.root, env=self.env,
                       pid=self.native.process.pid, session_id=self.native.session_id)
        self.assertEqual(len(self.gateway.requests), before, 'state query must not request the model')
        result.update(phase=phase, expected_pid=self.native.process.pid,
                      expected_session_id=self.native.session_id,
                      process_alive=self.native.process.poll() is None,
                      receiver_observation=self.native.observe().value,
                      fixture_request_count=before)
        self.observations.append(result)
        return result

    def test_fresh_listing_while_exact_owned_process_is_stopped(self):
        """A new query process is not necessarily a new target observation.

        SIGSTOP and /proc are only failure injection/evidence for our owned
        child, never a simulated native signal or a private Claude state read.
        The result is diagnostic even if the public listing retains idle.
        """
        stopped = False

        def kernel_state():
            self.assertIsNone(self.native.process.poll())
            status = Path(f'/proc/{self.native.process.pid}/status').read_text()
            return next(line.split()[1] for line in status.splitlines() if line.startswith('State:'))

        try:
            self.start_unprimed()
            time.sleep(.5)
            baseline = self.sample('alive-before-first-input')
            self.assertEqual(baseline['exact_identity_count'], 1)
            self.assertEqual(len(baseline['related_rows']), 1)
            self.assertEqual(baseline['related_rows'][0]['status'], 'idle')
            self.native.process.send_signal(signal.SIGSTOP)
            stopped = True
            deadline = time.monotonic() + 2
            while kernel_state() != 'T':
                self.assertLess(time.monotonic(), deadline, 'owned child did not stop')
                time.sleep(.01)
            stopped_at = time.monotonic()
            # Exceed the existing adapter freshness window without any input.
            time.sleep(2.2)
            for phase in ('stopped-query-one', 'stopped-query-two'):
                self.assertEqual(kernel_state(), 'T')
                sample = self.sample(phase)
                self.assertEqual(kernel_state(), 'T', 'target must remain stopped throughout query')
                sample.update(kernel_state='T', stopped_seconds=time.monotonic() - stopped_at)
                # Pinned native negative evidence: this fresh query can retain
                # idle even though the exact target cannot execute any code.
                self.assertEqual(sample['exact_identity_count'], 1)
                self.assertEqual(len(sample['related_rows']), 1)
                self.assertEqual(sample['related_rows'][0]['status'], 'idle')
                self.assertFalse(sample['authorizes_delivery'])
                self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
            self.native.process.send_signal(signal.SIGCONT)
            stopped = False
            deadline = time.monotonic() + 2
            while kernel_state() == 'T':
                self.assertLess(time.monotonic(), deadline, 'owned child did not continue')
                time.sleep(.01)
            self.sample('continued-without-input')
            self.assertEqual(self.gateway.requests, [], 'diagnostic must make no model requests')
            self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
        finally:
            if stopped and self.native is not None and self.native.process.poll() is None:
                self.native.process.send_signal(signal.SIGCONT)
            print(json.dumps({'probe': 'official-agents-json-stopped-target',
                              'runtime_version': '2.1.310', 'provider': 'loopback-protocol-fixture-only',
                              'product_readiness_changed': False,
                              'observations': self.observations}, sort_keys=True))

    def turn(self, prefix, content):
        self.gateway.release.clear()
        self.gateway.entered.clear()
        message_id = str(uuid.uuid4())
        self.native._write(message_id, content)  # Explicit actual fixture input, not peer admission.
        try:
            self.assertTrue(self.gateway.entered.wait(timeout=5), 'actual fixture request must be in flight')
            self.assertIs(self.native.observe(), Readiness.BUSY)
            self.sample(prefix + '-held-request')
        finally:
            self.gateway.release.set()
        self.native.wait_safe()
        self.assertEqual(self.native.signals.ack['uuid'], message_id)
        self.sample(prefix + '-completed')
        with self.native.condition:
            safe_at = self.native.signals.safe_at
        time.sleep(max(0, safe_at + 2.2 - time.monotonic()))
        self.assertIs(self.native.observe(), Readiness.AMBIGUOUS, 'native listing must not renew the adapter safe point')
        self.sample(prefix + '-completion-older-than-2s')

    def test_exact_native_listing_before_work_during_work_after_expiry_and_resume(self):
        try:
            self.start_unprimed()
            time.sleep(.5)  # Sample startup; silence is explicitly NOT readiness.
            self.assertIsNone(self.native.process.poll())
            self.assertEqual(self.gateway.requests, [])
            self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
            self.sample('initial-before-first-input')
            self.turn('initial', 'LISTING-RESTORED-HISTORY-NONCE')
            session_id = self.native.session_id
            incarnation_id = self.native.incarnation_id
            self.native.process.terminate()
            self.native.process.wait(timeout=3)
            self.assertIs(self.native.observe(), Readiness.LOST)
            self.sample('initial-process-exited')
            self.close_native()
            self.start_unprimed(resume=True)
            self.assertEqual(self.native.session_id, session_id)
            self.assertNotEqual(self.native.incarnation_id, incarnation_id)
            time.sleep(.5)
            self.assertIs(self.native.observe(), Readiness.AMBIGUOUS)
            self.sample('resumed-before-first-input')
            self.turn('resumed', 'Check the restored fixture history.')
            self.assertEqual(json.dumps(self.gateway.requests[-1]['request']['messages']).count('LISTING-RESTORED-HISTORY-NONCE'), 1)
            self.assertEqual(len(self.observations), 9)
        finally:
            print(json.dumps({'probe': 'official-agents-json-print-applicability',
                              'runtime_version': '2.1.310', 'provider': 'loopback-protocol-fixture-only',
                              'product_readiness_changed': False, 'observations': self.observations}, sort_keys=True))
