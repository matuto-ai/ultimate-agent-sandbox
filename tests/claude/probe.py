"""Bounded official CLI probe, no upstream, no real credentials or model.

Run only inside a child network namespace with loopback up and no routes.
The protocol reply is a fixture, not Claude inference or provider auth proof.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import uuid


class Gateway(http.server.ThreadingHTTPServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        if self.headers.get('x-api-key') != self.server.key:
            self.send_error(401)
            return
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length < 1024 * 1024:
            self.send_error(413)
            return
        request = json.loads(self.rfile.read(length))
        self.server.requests.append({'path': self.path, 'request': request})
        if self.path.split('?')[0] == '/v1/messages/count_tokens':
            body = b'{"input_tokens":10}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.split('?')[0] != '/v1/messages':
            self.send_error(404)
            return
        time.sleep(getattr(self.server, 'delay', 0))
        text = 'fixture-only-response'
        model = request['model']
        message = {'id': 'msg_' + uuid.uuid4().hex, 'type': 'message',
                   'role': 'assistant', 'model': model, 'content': [],
                   'stop_reason': None, 'stop_sequence': None,
                   'usage': {'input_tokens': 10, 'output_tokens': 0}}
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.end_headers()
        events = [
            ('message_start', {'type': 'message_start', 'message': message}),
            ('content_block_start', {'type': 'content_block_start', 'index': 0,
                                     'content_block': {'type': 'text', 'text': ''}}),
            ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                     'delta': {'type': 'text_delta', 'text': text}}),
            ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
            ('message_delta', {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn',
                                'stop_sequence': None}, 'usage': {'output_tokens': 1}}),
            ('message_stop', {'type': 'message_stop'}),
        ]
        for event, data in events:
            self.wfile.write(('event: ' + event + '\ndata: ' + json.dumps(data) + '\n\n').encode())
        self.wfile.flush()


def main():
    install = Path(os.environ['UAS_CLAUDE_INSTALL']).resolve()
    package = install / 'node_modules/@anthropic-ai/claude-code-linux-x64'
    assert json.loads((package / 'package.json').read_text())['version'] == '2.1.310'
    binary = package / 'claude'
    # Native test refuses a routable namespace, even if the caller forgot it.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from uas.claude_runtime import require_loopback_namespace
    require_loopback_namespace()
    with tempfile.TemporaryDirectory(prefix='uas-claude-probe-') as root:
        gateway = Gateway(('127.0.0.1', 0), Handler)
        gateway.key = 'fixture-only-' + uuid.uuid4().hex
        gateway.requests = []
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        try:
            env = {'PATH': '/usr/bin:/bin', 'HOME': root, 'CLAUDE_CONFIG_DIR': root + '/config',
                   'ANTHROPIC_BASE_URL': f'http://127.0.0.1:{gateway.server_port}',
                   'ANTHROPIC_API_KEY': gateway.key, 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1'}
            version = subprocess.run([binary, '--version'], cwd=root, env=env,
                                     capture_output=True, text=True, timeout=10, check=True).stdout.strip()
            assert version == '2.1.310 (Claude Code)', version
            session_id, message_id = str(uuid.uuid4()), str(uuid.uuid4())
            prompt = {'type': 'user', 'uuid': message_id, 'session_id': session_id,
                      'message': {'role': 'user', 'content': 'Account-free fixture probe'}}
            argv = [binary, '--bare', '--restricted', '-p', '--input-format', 'stream-json',
                    '--output-format', 'stream-json', '--verbose', '--replay-user-messages',
                    '--tools', '', '--disallowedTools', 'mcp__*', '--strict-mcp-config',
                    '--mcp-config', '{"mcpServers":{}}', '--setting-sources', '',
                    '--model', 'claude-sonnet-4-6', '--session-id', session_id]
            result = subprocess.run(argv, input=json.dumps(prompt) + '\n', cwd=root, env=env,
                                    capture_output=True, text=True, timeout=30)
            events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            # Print only fixture native events; no inherited environment/credential.
            print(json.dumps({'version': version, 'exit': result.returncode,
                              'binary_sha256': hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest(),
                              'events': events, 'stderr': result.stderr[-2000:],
                              'gateway_paths': [r['path'] for r in gateway.requests]}, sort_keys=True))
            assert result.returncode == 0
            assert any(e.get('type') == 'user' and e.get('uuid') == message_id for e in events)
            assert any(e.get('type') == 'result' and e.get('is_error') is False and
                       e.get('session_id') == session_id for e in events)
            assert any(r['path'].split('?')[0] == '/v1/messages' for r in gateway.requests)
        finally:
            gateway.shutdown()
            gateway.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    main()
