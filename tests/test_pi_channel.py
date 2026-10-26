"""Actual pinned Node/Linux raw-FD packet edge probes; not native acceptance."""
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = os.environ.get('UAS_PI_INSTALL')


@unittest.skipUnless(INSTALL, 'Set UAS_PI_INSTALL for required real Node channel tests')
class PiChannelTests(unittest.TestCase):
    def start(self, mode='reply', arg=''):
        self.host, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        child.setblocking(False)
        self.addCleanup(self.host.close)
        self.addCleanup(child.close)
        self.process = subprocess.Popen([shutil.which('node'), str(ROOT / 'tests/pi/channel-client.mjs'),
            str(child.fileno()), mode, arg], pass_fds=(child.fileno(),),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup)
        child.close()
        return self.host

    def cleanup(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.communicate(timeout=3)

    def packet(self):
        self.assertTrue(select.select([self.host], [], [], 3)[0])
        return json.loads(self.host.recv(131072))

    def result(self):
        out, err = self.process.communicate(timeout=3)
        self.assertEqual(0, self.process.returncode, err.decode())
        return json.loads(out)

    def reply(self, request, length=None, **changes):
        reply = {'request_id': request['request_id'], 'ok': True, 'receipt': {'accepted': True}, **changes}
        data = json.dumps(reply).encode()
        if length is not None:
            data += b' ' * (length - len(data))
        self.host.send(data)

    def test_max_reply_and_max_plus_one_truncation_are_distinct(self):
        for size in (65536, 65537, 131072):
            with self.subTest(size=size):
                self.start()
                self.reply(self.packet(), size)
                result = self.result()
                self.assertEqual(size != 65536, result['fenced'])
                if size == 65536:
                    self.assertTrue(result['result']['ok'])
                else:
                    self.assertIn('oversized', result['error'])
                self.host.close()

    def test_exact_max_request_one_packet_and_max_plus_one_no_write(self):
        overhead = len(json.dumps({'request_id': 'a' * 32, 'envelope': {'data': ''}}, separators=(',', ':')).encode())
        for size in (65536, 65537):
            with self.subTest(size=size):
                self.start('size', str(size - overhead))
                if size == 65536:
                    self.assertTrue(select.select([self.host], [], [], 3)[0])
                    data = self.host.recv(131072)
                    self.assertEqual(size, len(data))
                    self.reply(json.loads(data))
                    self.assertTrue(self.result()['result']['ok'])
                else:
                    result = self.result()
                    self.assertIn('too large', result['error'])
                    self.assertFalse(result['fenced'])
                    self.assertEqual(b'', self.host.recv(1))
                self.host.close()

    def test_eof_and_wrong_correlation_fence_without_second_packet(self):
        for mode in ('eof', 'mismatch'):
            with self.subTest(mode=mode):
                self.start('twice')
                request = self.packet()
                if mode == 'eof':
                    self.host.close()
                else:
                    self.reply(request, request_id='b' * 32)
                result = self.result()
                self.assertTrue(result['fenced'])
                self.assertIn('fenced', result['second'])
                self.host.close()

    def test_bounded_queue_serializes_and_rejects_excess(self):
        self.start('queue')
        for _ in range(4):
            self.reply(self.packet())
        result = self.result()
        self.assertEqual(['fulfilled'] * 4 + ['rejected'], [r['status'] for r in result['results']])
        self.assertFalse(result['fenced'])

    def test_eagain_write_deadline_is_bounded_and_does_not_block_node_event_loop(self):
        host, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(host.close)
        self.addCleanup(child.close)
        child.setblocking(False)
        child.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        while True:
            try:
                child.send(b'backpressure' * 100)
            except BlockingIOError:
                break
        self.process = subprocess.Popen([shutil.which('node'), str(ROOT / 'tests/pi/channel-client.mjs'),
            str(child.fileno()), 'twice', ''], pass_fds=(child.fileno(),),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup)
        started = time.monotonic()
        child.close()
        result = self.result()
        self.assertLess(time.monotonic() - started, 2)
        self.assertGreater(result['ticks'], 10)
        self.assertTrue(result['fenced'])
        self.assertIn('deadline', result['error'])
        self.assertIn('fenced', result['second'])
