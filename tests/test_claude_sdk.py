"""Actual public TypeScript SDK qualification; no adapter promotion yet."""
from collections import deque
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from uas.claude_runtime import require_loopback_namespace


ROOT = Path(__file__).resolve().parents[1]
NODE = os.environ.get('UAS_CLAUDE_NODE') or shutil.which('node')
INSTALL = os.environ.get('UAS_CLAUDE_INSTALL')
SDK_INSTALL = os.environ.get('UAS_CLAUDE_SDK_INSTALL')


class ClaudeSDKPolicyTests(unittest.TestCase):
    @unittest.skipUnless(NODE, 'Node required for pure SDK-policy source tests')
    def test_bounded_source_policy(self):
        result = subprocess.run([NODE, '--test', str(ROOT / 'tests/claude/sdk-policy.test.mjs'),
                                 str(ROOT / 'tests/claude/sdk-resources.test.mjs')],
                                cwd=ROOT, env={'PATH': '/usr/bin:/bin'}, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(INSTALL and SDK_INSTALL and NODE, 'Actual SDK requires mandatory loopback-only Claude CI')
class ClaudeSDKNativeTests(unittest.TestCase):
    def setUp(self):
        from claude.probe import Gateway, Handler
        class ObservedHandler(Handler):
            def parse_request(self):
                parsed = super().parse_request()
                if parsed:
                    self.server.all_requests.append({'method': self.command, 'path': self.path})
                return parsed
        require_loopback_namespace()
        self.temp = tempfile.TemporaryDirectory(prefix='uas-claude-sdk-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.gateway = Gateway(('127.0.0.1', 0), ObservedHandler)
        self.gateway.key = 'fixture-only-' + uuid.uuid4().hex
        self.gateway.requests = []
        self.gateway.all_requests = []
        self.gateway.release = threading.Event()
        self.gateway.release.set()
        self.gateway.entered = threading.Event()
        self.server_thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.server_thread.start()
        self.addCleanup(self.close_gateway)
        self.binary = Path(INSTALL) / 'node_modules/@anthropic-ai/claude-code-linux-x64/claude'
        self.session_id = str(uuid.uuid4())
        self.process = None
        self.addCleanup(self.close_host)
        self.samples = []

    def close_gateway(self):
        self.gateway.release.set()
        self.gateway.shutdown()
        self.gateway.server_close()
        self.server_thread.join(timeout=3)

    def close_host(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=3)
        # The test-created process group is the cleanup boundary, including a
        # child stopped during failure injection. No unrelated process lookup.
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for thread in self.readers:
            thread.join(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
        self.process = None

    def start(self, *, resume=False):
        self.events = deque(maxlen=128)
        self.errors = deque(maxlen=8)
        self.condition = threading.Condition()
        self.process = subprocess.Popen([NODE, str(ROOT / 'runtime/claude/sdk-host.mjs'),
            SDK_INSTALL, str(self.binary), str(self.root), str(self.home),
            f'http://127.0.0.1:{self.gateway.server_port}', self.gateway.key,
            self.session_id, '1' if resume else '0'], cwd=ROOT,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home)}, start_new_session=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def read():
            try:
                for line in iter(lambda: self.process.stdout.readline(256 * 1024 + 1), b''):
                    if len(line) > 256 * 1024 or not line.endswith(b'\n'):
                        raise ValueError('oversized/incomplete host frame')
                    event = json.loads(line)
                    with self.condition:
                        self.events.append(event)
                        self.condition.notify_all()
            except Exception as error:
                self.errors.append(str(error))
            finally:
                with self.condition:
                    self.condition.notify_all()

        def errors():
            for line in iter(lambda: self.process.stderr.readline(4096), b''):
                self.errors.append(line.decode(errors='replace'))

        self.readers = [threading.Thread(target=read, daemon=True), threading.Thread(target=errors, daemon=True)]
        for thread in self.readers:
            thread.start()
        ready = self.wait(lambda e: e.get('type') == 'host-ready')
        self.native_pid = ready['native_pid']
        self.assertNotEqual(self.native_pid, self.process.pid, 'SDK host is not native process authority')
        self.assertEqual(ready['session_id'], self.session_id)
        self.assertEqual((ready['sdk_version'], ready['cli_version']), ('0.3.310', '2.1.310'))
        self.samples.append(ready)

    def wait(self, predicate, timeout=6):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                match = next((e for e in self.events if predicate(e)), None)
                if match is not None:
                    return match
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    self.fail(f'missing SDK evidence; exit={self.process.poll()} errors={list(self.errors)} events={list(self.events)}')
                self.condition.wait(min(.1, deadline - time.monotonic()))

    def command(self, op, **data):
        request_id = str(uuid.uuid4())
        wire = (json.dumps({'id': request_id, 'op': op, **data}) + '\n').encode()
        self.assertLessEqual(len(wire), 256 * 1024)
        self.process.stdin.write(wire)
        self.process.stdin.flush()
        reply = self.wait(lambda e: e.get('type') == 'reply' and e.get('id') == request_id)
        self.samples.append(reply)
        return reply

    def probe(self, expected):
        before = len(self.gateway.all_requests)
        reply = self.command('probe')
        self.assertEqual(len(self.gateway.all_requests), before, 'native control/listing must not contact gateway')
        self.assertEqual(reply['state'], expected, reply)
        if expected == 'safe':
            self.assertEqual(reply['liveness'], 'fresh-public-mcpServerStatus')
            self.assertEqual((reply['pid'], reply['session_id']), (self.native_pid, self.session_id))
        return reply

    def finish_turn(self, message_id, content):
        ack = self.wait(lambda e: e.get('type') == 'native' and e['event'].get('type') == 'user'
                        and e['event'].get('uuid') == message_id)['event']
        self.assertTrue(ack['isReplay'])
        self.assertEqual(ack['session_id'], self.session_id)
        self.assertIsNone(ack['parent_tool_use_id'])
        self.assertEqual(ack['message'], {'role': 'user', 'content': content})
        result = self.wait(lambda e: e.get('type') == 'native' and e['event'].get('type') == 'result'
                           and e['event'].get('user_message_uuid') == message_id)['event']
        self.assertFalse(result['is_error'])
        self.assertEqual(result['queued_turn_count'], 0)
        self.assertEqual(result['terminal_reason'], 'completed')
        self.samples.append({'type': 'observed-native-receipt', 'uuid': ack['uuid'],
            'session_id': ack['session_id'], 'isReplay': ack['isReplay'], 'exact_content_verified': True,
            'result_user_message_uuid': result['user_message_uuid'],
            'queued_turn_count': result['queued_turn_count'], 'terminal_reason': result['terminal_reason']})
        self.wait(lambda e: e.get('type') == 'native' and e['event'].get('subtype') == 'session_state_changed'
                  and e['event'].get('state') == 'idle')
        self.probe('safe')

    def report(self):
        print(json.dumps({'probe': self.id(), 'sdk_version': '0.3.310', 'cli_version': '2.1.310',
            'provider': 'loopback-protocol-fixture-only', 'adapter_promoted': False,
            'gateway_requests': len(self.gateway.requests), 'observations': self.samples,
            'all_gateway_requests': self.gateway.all_requests,
            'native_event_types': sorted({(e['event']['type'] + ':' + str(e['event'].get('subtype', '')))
                for e in self.events if e.get('type') == 'native'})}, sort_keys=True))

    def test_no_input_readiness_busy_hold_exact_ack_and_native_resume(self):
        try:
            self.start()
            self.probe('safe')
            self.assertEqual(self.gateway.requests, [])
            self.assertEqual(self.gateway.all_requests, [])
            time.sleep(2.2)
            self.probe('safe')
            self.assertEqual(self.gateway.requests, [])
            self.assertEqual(self.gateway.all_requests, [])
            content = 'SDK-RESTORED-HISTORY-NONCE'
            message_id = str(uuid.uuid4())
            self.gateway.release.clear()
            self.gateway.entered.clear()
            self.assertTrue(self.command('send', uuid=message_id, content=content,
                                         session_id=self.session_id)['released'])
            self.assertTrue(self.gateway.entered.wait(timeout=5))
            self.probe('busy')
            rejected = self.command('send', uuid=str(uuid.uuid4()), content='MUST-NOT-INJECT',
                                    session_id=self.session_id)
            self.assertTrue(rejected['not_applied'])
            self.assertEqual(len(self.gateway.requests), 1)
            self.gateway.release.set()
            self.finish_turn(message_id, content)
            first_pid = self.native_pid
            self.close_host()
            self.start(resume=True)
            self.assertNotEqual(self.native_pid, first_pid)
            self.probe('safe')
            self.assertEqual(len(self.gateway.requests), 1)
            message_id = str(uuid.uuid4())
            content = 'Check actual restored history.'
            self.assertTrue(self.command('send', uuid=message_id, content=content,
                                         session_id=self.session_id)['released'])
            self.finish_turn(message_id, content)
            history = json.dumps(self.gateway.requests[-1]['request']['messages'])
            self.assertEqual(history.count('SDK-RESTORED-HISTORY-NONCE'), 1)
            self.assertNotIn('MUST-NOT-INJECT', history)
            self.assertEqual(len(self.gateway.requests), 2)
        finally:
            self.report()

    def test_stopped_idle_native_times_out_and_fences_without_model_request(self):
        try:
            self.start()
            self.probe('safe')
            os.kill(self.native_pid, signal.SIGSTOP)
            deadline = time.monotonic() + 2
            while '\nState:\tT' not in Path(f'/proc/{self.native_pid}/status').read_text():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            started = time.monotonic()
            reply = self.command('probe')
            self.assertEqual(reply['state'], 'ambiguous')
            self.assertEqual(reply['error'], 'native-control-timeout')
            self.assertLess(time.monotonic() - started, 3)
            self.process.wait(timeout=4)
            self.assertEqual(self.gateway.requests, [])
            self.assertEqual(self.gateway.all_requests, [])
        finally:
            self.report()
