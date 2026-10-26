"""Manual-only native permission qualification, NOT Hub delivery integration.

No provider, account or model: exact CLI/SDK against a loopback protocol fixture.
Run only via the deliberate isolated CI tier. No approval represents a human.
"""
from collections import deque
import http.server
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from uas.claude_runtime import (require_loopback_namespace, _dispose_sdk_process,
                                _pidfd_alive, _sdk_native_pidfd)


def tool_results(request, tool_id):
    return [block for message in request.get('messages', [])
            if isinstance(message.get('content'), list)
            for block in message['content']
            if block.get('type') == 'tool_result' and block.get('tool_use_id') == tool_id]


class Gateway(http.server.ThreadingHTTPServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.connection.settimeout(5)
        if self.headers.get('x-api-key') != self.server.key:
            self.send_error(401)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length < 1024 * 1024:
                raise ValueError('request bound')
            request = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        route = self.path.split('?')[0]
        if route == '/v1/messages/count_tokens':
            body = b'{"input_tokens":10}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if route != '/v1/messages':
            self.send_error(404)
            return
        with self.server.lock:
            self.server.requests.append(request)
            count = len(self.server.requests)
        if count > 2:
            self.send_error(409, 'only one controlled tool request is permitted')
            return
        results = tool_results(request, self.server.tool_id)
        if count == 2 and len(results) != 1:
            self.send_error(409, 'missing correlated native tool result')
            return
        message = {'id': 'msg_' + uuid.uuid4().hex, 'type': 'message',
                   'role': 'assistant', 'model': request['model'], 'content': [],
                   'stop_reason': None, 'stop_sequence': None,
                   'usage': {'input_tokens': 10, 'output_tokens': 0}}
        if count == 1:
            block = {'type': 'tool_use', 'id': self.server.tool_id, 'name': 'Read', 'input': {}}
            delta = {'type': 'input_json_delta', 'partial_json': json.dumps({'file_path': str(self.server.nonce_file)})}
            stop_reason = 'tool_use'
        else:
            block = {'type': 'text', 'text': ''}
            delta = {'type': 'text_delta', 'text': 'fixture-only-permission-complete'}
            stop_reason = 'end_turn'
        events = [('message_start', {'type': 'message_start', 'message': message}),
                  ('content_block_start', {'type': 'content_block_start', 'index': 0, 'content_block': block}),
                  ('content_block_delta', {'type': 'content_block_delta', 'index': 0, 'delta': delta}),
                  ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
                  ('message_delta', {'type': 'message_delta', 'delta': {'stop_reason': stop_reason,
                                     'stop_sequence': None}, 'usage': {'output_tokens': 1}}),
                  ('message_stop', {'type': 'message_stop'})]
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.end_headers()
        try:
            for event, data in events:
                self.wfile.write(('event: ' + event + '\ndata: ' + json.dumps(data) + '\n\n').encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # Exit-during-attention is an explicit qualification case.


class NativePermissionTests(unittest.TestCase):
    def setUp(self):
        # No skip/fallback: selecting this deliberate tier requires its boundary.
        self.assertEqual(os.environ.get('UAS_CLAUDE_PERMISSION_NATIVE'), '1')
        for name in ('UAS_CLAUDE_NODE', 'UAS_CLAUDE_INSTALL', 'UAS_CLAUDE_SDK_INSTALL'):
            self.assertTrue(os.environ.get(name), name + ' required')
        require_loopback_namespace()
        self.temp = tempfile.TemporaryDirectory(prefix='uas-native-permission-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.nonce = 'FIXTURE-READ-NONCE-' + uuid.uuid4().hex
        self.nonce_file = self.root / 'nonce.txt'
        self.nonce_file.write_text(self.nonce + '\n')
        self.gateway = Gateway(('127.0.0.1', 0), Handler)
        self.gateway.key = 'fixture-only-' + uuid.uuid4().hex
        self.gateway.tool_id = 'toolu_fixture_' + uuid.uuid4().hex
        self.gateway.nonce_file = self.nonce_file
        self.gateway.requests = []
        self.gateway.lock = threading.Lock()
        self.thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_gateway)
        self.process = None
        self.host_pidfd = self.native_pidfd = None
        self.readers = []
        self.samples = []
        self.addCleanup(self.report)
        self.addCleanup(self.close_host)

    def close_gateway(self):
        self.gateway.shutdown()
        self.gateway.server_close()
        self.thread.join(timeout=2)

    def close_host(self):
        if self.process is None:
            return
        _dispose_sdk_process(self.process, self.host_pidfd, self.native_pidfd)
        # Observe held identities before releasing descriptors. Report only after
        # disposal; successful setup or a generic runner cleanup line is no proof.
        host_exited = self.host_pidfd is not None and not _pidfd_alive(self.host_pidfd)
        native_exited = self.native_pidfd is not None and not _pidfd_alive(self.native_pidfd)
        host_reaped = self.process.returncode is not None
        self.samples.append({'type': 'cleanup', 'host_exited': host_exited,
                             'native_exited': native_exited,
                             'host_reaped': host_reaped})
        for reader in self.readers:
            reader.join(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
        self.process = None
        for name in ('host_pidfd', 'native_pidfd'):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
        self.assertTrue(host_exited, 'owned host identity must exit during cleanup')
        self.assertTrue(native_exited, 'owned native identity must exit during cleanup')
        self.assertTrue(host_reaped, 'owned host must be reaped during cleanup')

    def start(self):
        self.events = deque(maxlen=256)
        self.errors = deque(maxlen=8)
        self.condition = threading.Condition()
        self.session_id = str(uuid.uuid4())
        self.invocation_id = str(uuid.uuid4())
        self.process = subprocess.Popen([
            os.environ['UAS_CLAUDE_NODE'], str(ROOT / 'tests/claude/permission/runner.mjs'),
            os.environ['UAS_CLAUDE_SDK_INSTALL'],
            str(Path(os.environ['UAS_CLAUDE_INSTALL']) / 'node_modules/@anthropic-ai/claude-code-linux-x64/claude'),
            str(self.root), str(self.home), f'http://127.0.0.1:{self.gateway.server_port}',
            self.gateway.key, self.session_id, str(self.nonce_file)], cwd=ROOT,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home)}, start_new_session=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.host_pidfd = os.pidfd_open(self.process.pid, 0)
        process = self.process

        def read():
            try:
                for line in iter(lambda: process.stdout.readline(256 * 1024 + 1), b''):
                    if len(line) > 256 * 1024 or not line.endswith(b'\n'):
                        raise ValueError('oversized/incomplete runner frame')
                    event = json.loads(line)
                    with self.condition:
                        self.events.append(event)
                        self.condition.notify_all()
            except Exception as error:
                self.errors.append(str(error))

        def errors():
            for line in iter(lambda: process.stderr.readline(4096), b''):
                self.errors.append(line.decode(errors='replace'))
        self.readers = [threading.Thread(target=f, daemon=True) for f in (read, errors)]
        for thread in self.readers:
            thread.start()
        ready = self.wait(lambda e: e.get('type') == 'ready')
        self.assertEqual(ready['session_id'], self.session_id)
        self.assertNotEqual(ready['native_pid'], self.process.pid)
        self.native_pidfd = _sdk_native_pidfd(ready['native_pid'], self.process.pid, ready['native_start'])
        self.samples.append(ready)
        self.assertTrue(self.command('start', uuid=self.invocation_id,
                                    content='Perform the one controlled fixture Read.')['accepted'])
        attention = self.wait(lambda e: e.get('type') == 'attention')
        self.assertEqual(attention['toolName'], 'Read')
        self.assertEqual(attention['input'], {'file_path': str(self.nonce_file)})
        identity = attention['identity']
        self.assertEqual(identity['sessionId'], self.session_id)
        self.assertEqual(identity['incarnation'], ready['incarnation'])
        self.assertEqual(identity['invocationId'], self.invocation_id)
        self.assertEqual(identity['toolUseID'], self.gateway.tool_id)
        self.assertTrue(identity['requestId'])
        self.wait(lambda e: e.get('type') == 'native' and e['event'].get('session_id') == self.session_id
                  and e['event'].get('subtype') == 'session_state_changed'
                  and e['event'].get('state') == 'requires_action')
        self.samples.append(attention)
        self.assert_pending()
        return identity

    def wait(self, predicate, timeout=8):
        end = time.monotonic() + timeout
        with self.condition:
            while True:
                found = next((e for e in self.events if predicate(e)), None)
                if found is not None:
                    return found
                remaining = end - time.monotonic()
                if remaining <= 0 or not _pidfd_alive(self.host_pidfd):
                    self.fail(f'missing native permission evidence: {list(self.errors)} events={list(self.events)}')
                self.condition.wait(min(.1, remaining))

    def command(self, op, **data):
        command_id = str(uuid.uuid4())
        wire = (json.dumps({'id': command_id, 'op': op, **data}) + '\n').encode()
        self.assertLess(len(wire), 256 * 1024)
        self.process.stdin.write(wire)
        self.process.stdin.flush()
        reply = self.wait(lambda e: e.get('type') == 'reply' and e.get('id') == command_id)
        self.samples.append(reply)
        return reply

    def assert_pending(self):
        # A bounded observation window, not a claim of durable delivery readiness.
        time.sleep(.15)
        with self.gateway.lock:
            requests = list(self.gateway.requests)
        self.assertEqual(len(requests), 1)
        self.assertNotIn(self.nonce, json.dumps(requests))
        with self.condition:
            events = list(self.events)
        self.assertFalse(any(e.get('type') == 'native' and e['event'].get('type') == 'result'
                             for e in events))

    def finish(self):
        event = self.wait(lambda e: e.get('type') == 'native' and e['event'].get('type') == 'result'
                          and e['event'].get('user_message_uuid') == self.invocation_id)['event']
        self.assertEqual(event['session_id'], self.session_id)
        self.samples.append({'type': 'terminal', 'event': event})
        with self.gateway.lock:
            requests = list(self.gateway.requests)
        self.assertEqual(len(requests), 2)
        results = tool_results(requests[-1], self.gateway.tool_id)
        self.assertEqual(len(results), 1)
        return event, results[0]

    def test_allow_after_stale_rejection_and_no_second_invocation(self):
        identity = self.start()
        stale = {**identity, 'incarnation': uuid.uuid4().hex}
        self.assertFalse(self.command('decision', identity=stale, behavior='allow')['accepted'])
        self.assertFalse(self.command('start', uuid=str(uuid.uuid4()), content='MUST-NOT-INJECT')['accepted'])
        self.assert_pending()
        self.assertTrue(self.command('decision', identity=identity, behavior='allow')['accepted'])
        self.assertFalse(self.command('decision', identity=identity, behavior='allow')['accepted'])
        result, tool_result = self.finish()
        self.assertFalse(result['is_error'])
        self.assertFalse(tool_result.get('is_error', False))
        self.assertIn(self.nonce, json.dumps(tool_result))
        self.assertNotIn('MUST-NOT-INJECT', json.dumps(self.gateway.requests))

    def test_deny_never_reads_nonce(self):
        identity = self.start()
        self.assertTrue(self.command('decision', identity=identity, behavior='deny')['accepted'])
        _, tool_result = self.finish()
        self.assertTrue(tool_result.get('is_error'))
        self.assertNotIn(self.nonce, json.dumps(self.gateway.requests))
        self.assertFalse(self.command('decision', identity=identity, behavior='allow')['accepted'])

    def test_exit_while_waiting_has_no_tool_result(self):
        self.start()
        self.assertTrue(self.command('close')['accepted'])
        self.assertTrue(select.select([self.host_pidfd], [], [], 4)[0], 'owned host must exit')
        self.assertTrue(select.select([self.native_pidfd], [], [], 1)[0], 'owned native must exit')
        with self.gateway.lock:
            self.assertEqual(len(self.gateway.requests), 1)
            self.assertNotIn(self.nonce, json.dumps(self.gateway.requests))

    def report(self):
        print(json.dumps({'qualification': self.id(), 'sdk_version': '0.3.310',
                          'cli_version': '2.1.310', 'provider': 'loopback-fixture-only',
                          'human_authority': False, 'hub_delivery_integration': False,
                          'observations': self.samples,
                          'gateway_request_count': len(self.gateway.requests)}, sort_keys=True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
