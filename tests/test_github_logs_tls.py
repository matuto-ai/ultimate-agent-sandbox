"""Opt-in hosted real TLS log transport; never run in restricted local checks."""
import base64
import http.client
import os
import unittest
from unittest.mock import patch

from uas.github_logs import CompletedJobLogProvider, GitHubJobLogTransport, LogFailure
from uas.github_read import GitHubProject
from test_github_logs import REPO, HEAD, RUN, JOB, ATTEMPT, LOCATION, response, run, job


@unittest.skipUnless(os.environ.get('UAS_FORGE_HTTP_TEST') == '1',
                     'actual TLS framing runs only in the hosted opt-in gate')
class HostedLogHTTPTests(unittest.TestCase):
    """Actual loopback TLS; production host policy and HTTP header code unchanged.

    The fixture changes only connection routing and a temporary test trust root.
    No real account, system trust-store modification, Internet or host settings.
    Never enabled in the restricted local development environment.
    """
    def setUp(self):
        import http.server
        from pathlib import Path
        import socket
        import ssl
        import subprocess
        import tempfile
        import threading
        self.directory = tempfile.TemporaryDirectory(prefix='uas-forge-http-')
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        cert, key = root / 'fixture.crt', root / 'fixture.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=api.github.com',
            '-addext', 'subjectAltName=DNS:api.github.com,DNS:productionresultssa30.blob.core.windows.net'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        self.requests, self.truncated = [], False
        outer = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def do_GET(self):
                outer.requests.append((self.headers.get('Host'), self.path, dict(self.headers)))
                if self.headers.get('Host') == 'api.github.com':
                    self.send_response(302)
                    self.send_header('Location', LOCATION)
                    self.send_header('Set-Cookie', 'SECRET_COOKIE')
                    self.send_header('Content-Length', '0')
                else:
                    self.send_response(200)
                    self.send_header('Content-Length', '9' if outer.truncated else '3')
                    self.send_header('Content-Type', 'text/plain')
                self.send_header('Connection', 'close')
                self.end_headers()
                if self.headers.get('Host') != 'api.github.com':
                    self.wfile.write(b'abc'); self.wfile.flush()
                self.close_connection = True
            def log_message(self, *_):
                pass  # Do not log signed fixture paths or synthetic credentials.
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.addCleanup(self.server.server_close)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 2)
        self.addCleanup(self.server.shutdown)
        self.trust = ssl.create_default_context(cafile=str(cert))
        self.port = self.server.server_port
        class RoutedHTTPS(http.client.HTTPSConnection):
            def connect(inner):
                raw = socket.create_connection(('127.0.0.1', outer.port), timeout=inner.timeout)
                inner.sock = inner._context.wrap_socket(raw, server_hostname=inner.host)
        self.connection = RoutedHTTPS
        self.transport = GitHubJobLogTransport('actor-a', lambda *_: {'GH_TOKEN': 'SECRET_TOKEN'})

    def metadata(self, path):
        if '/jobs?' in path:
            return response({'total_count': 1, 'jobs': [job()]})
        if '/actions/jobs/' in path:
            return response(job())
        return response(run())

    def test_actual_tls_redirect_strips_credentials_and_truncated_body_is_unknown(self):
        with patch('uas.github_logs.http.client.HTTPSConnection', self.connection), \
             patch('uas.github_logs.ssl.create_default_context', return_value=self.trust):
            provider = CompletedJobLogProvider(GitHubProject(REPO), self.metadata, self.transport)
            result = provider.read(RUN, JOB, ATTEMPT, HEAD)
            self.assertEqual('OK', result['status'])
            self.assertEqual(b'abc', base64.b64decode(result['tail']))
            self.assertEqual('Bearer SECRET_TOKEN', self.requests[0][2]['Authorization'])
            self.assertEqual('productionresultssa30.blob.core.windows.net', self.requests[1][0])
            self.assertNotIn('Authorization', self.requests[1][2])
            self.assertNotIn('Cookie', self.requests[1][2])
            self.truncated = True
            failed = provider.read(RUN, JOB, ATTEMPT, HEAD)
            self.assertEqual('LOG_TRANSFER_INCOMPLETE', failed['status'])
            self.assertNotIn('tail', failed)
            self.assertNotIn('dropped_bytes', failed)
        self.assertEqual(4, len(self.requests))

    def test_actual_untrusted_server_certificate_never_receives_credentials(self):
        with patch('uas.github_logs.http.client.HTTPSConnection', self.connection):
            with self.assertRaises(LogFailure):
                self.transport(f'repos/{REPO}/actions/jobs/{JOB}/logs')
        self.assertEqual([], self.requests)


if __name__ == '__main__':
    unittest.main()
