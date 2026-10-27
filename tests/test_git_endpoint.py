"""Mocked fixed endpoint peer observations; no kernel or socket execution."""
from contextlib import ExitStack
import socket
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.git_endpoint import EndpointPeer, SO_PEERPIDFD
from uas.kernel_origin import OriginDenied


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.credentials = (123, 0, 0)
        self.channel = Mock()
        self.channel.getsockopt.side_effect = lambda level, option, *args: struct.pack('3i', *self.credentials) if option == socket.SO_PEERCRED else 41
        self.cloexec = self.stack.enter_context(patch('uas.git_endpoint.os.set_inheritable'))
        self.close = self.stack.enter_context(patch('uas.git_endpoint.os.close'))
        self.identity = self.stack.enter_context(patch('uas.git_endpoint._identity', side_effect=lambda fd: (1, 42 if fd in (41, 42) else 99)))
        self.alive = self.stack.enter_context(patch('uas.git_endpoint.alive', return_value=True))
        self.held = self.stack.enter_context(patch('uas.git_endpoint.HeldOrigin'))
        self.stack.enter_context(patch('os.pidfd_open', side_effect=AssertionError('numeric PID fallback forbidden')))

    def record(self, **changes):
        return SimpleNamespace(**({'credentials': self.credentials, 'pidfd': 42} | changes))

    def test_connection_pidfd_and_every_record_object_must_match(self):
        peer = EndpointPeer(self.channel)
        peer.require(self.record())
        self.assertIs(peer.hold(self.record()), self.held.return_value)
        self.cloexec.assert_called_once_with(41, False)
        self.channel.getsockopt.assert_any_call(socket.SOL_SOCKET, SO_PEERPIDFD)
        self.assertEqual((1, 42), peer.identity)
        peer.close()
        peer.close()
        self.close.assert_called_once_with(41)

    def test_same_pid_credentials_cannot_substitute_different_kernel_process(self):
        peer = EndpointPeer(self.channel)
        for record in (self.record(pidfd=43), self.record(credentials=(123, 65532, 65532)),
                       self.record(credentials=(124, 0, 0))):
            with self.assertRaises(OriginDenied):
                peer.hold(record)
        self.held.assert_not_called()

    def test_exited_connection_or_sender_and_closed_peer_fail_closed(self):
        peer = EndpointPeer(self.channel)
        for dead in (41, 42):
            self.alive.side_effect = lambda fd: fd != dead
            with self.assertRaises(OriginDenied):
                peer.require(self.record())
        peer.close()
        self.alive.side_effect = None
        with self.assertRaises(OriginDenied):
            peer.require(self.record())

    def test_cross_namespace_zero_numeric_pid_still_requires_exact_kernel_object(self):
        self.credentials = (0, 100000, 100000)
        peer = EndpointPeer(self.channel)
        peer.require(self.record())
        with self.assertRaises(OriginDenied):
            peer.require(self.record(pidfd=43))

    def test_unsupported_peer_pidfd_or_bad_credentials_has_no_fallback(self):
        for raw in (b'', b'x' * 11, struct.pack('3i', -1, 0, 0)):
            self.channel.getsockopt.return_value = raw
            self.channel.getsockopt.side_effect = None
            with self.assertRaises(OriginDenied):
                EndpointPeer(self.channel)
        self.close.assert_not_called()
        self.channel.getsockopt.side_effect = [struct.pack('3i', 123, 0, 0), OSError('unsupported')]
        with self.assertRaises(OSError):
            EndpointPeer(self.channel)
        self.close.assert_not_called()

    def test_failed_kernel_identity_or_dead_peer_disposes_installed_descriptor(self):
        self.identity.side_effect = OriginDenied('not pidfs')
        with self.assertRaises(OriginDenied):
            EndpointPeer(self.channel)
        self.close.assert_called_once_with(41)
        self.close.reset_mock()
        self.identity.side_effect = None
        self.alive.return_value = False
        with self.assertRaises(OriginDenied):
            EndpointPeer(self.channel)
        self.close.assert_called_once_with(41)

    def test_uncertain_close_never_retries_released_numeric_descriptor(self):
        peer = EndpointPeer(self.channel)
        self.close.side_effect = OSError('uncertain close')
        with self.assertRaises(OSError):
            peer.close()
        self.assertEqual(-1, peer.fd)
        peer.close()
        self.close.assert_called_once_with(41)


if __name__ == '__main__':
    unittest.main()
