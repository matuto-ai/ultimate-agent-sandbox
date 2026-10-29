"""Hosted real Unix socketpair contract; never included in local guarded suites."""
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uas.workstation_control import SupervisorAdmission
from uas.kernel_origin import OriginDenied


class NativeControlHupTests(unittest.TestCase):
    def test_unread_reply_does_not_mask_closed_peer_or_get_consumed(self):
        host, hub = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            host.setblocking(False)
            hub.settimeout(1)
            # Valid or stale payload content is deliberately immaterial: the
            # held descriptor's HUP, not parsing/consuming a reply, fences it.
            payload = b'{"kind":"STATUS","exchange_id":"stale-reply"}'
            self.assertEqual(hub.send(payload), len(payload))
            hub.close()
            admission = object.__new__(SupervisorAdmission)
            admission.control = host
            admission._fenced = False
            admission.hub_origin = SimpleNamespace(revoked=False, pidfd=10)
            admission.launch = SimpleNamespace(origin=SimpleNamespace(revoked=False, pidfd=11),
                state='active', endpoint=SimpleNamespace(require=Mock()))
            with patch('uas.workstation_control.alive', return_value=True):
                with self.assertRaisesRegex(OriginDenied, 'control channel unavailable'):
                    admission._current()
            self.assertTrue(admission._fenced)
            admission.launch.endpoint.require.assert_not_called()
            self.assertEqual(host.recv(4096), payload, 'currentness must not consume queued reply')
            self.assertEqual(host.recv(4096), b'')
        finally:
            host.close()
            hub.close()
