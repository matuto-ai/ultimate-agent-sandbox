"""Real kernel records; not Docker/SELinux qualification."""
import array
import os
import socket
import struct
import unittest
from unittest.mock import patch

from uas.kernel_origin import (HeldOrigin, OriginDenied, OriginUnavailable, Record,
                               MAX_PACKET, SCM_PIDFD, alive, enable, probe, receive)


class KernelOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing support is an explicit local test skip, never launch success.
        try:
            cls.observation = probe()
        except OriginUnavailable as error:
            raise unittest.SkipTest(str(error))

    def setUp(self):
        self.left, self.right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        enable(self.left)
        self.left.settimeout(2)
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)

    def bind_self(self):
        self.right.send(b'first')
        with receive(self.left) as record:
            held = HeldOrigin(record)
        self.addCleanup(held.close)
        return held

    def test_real_record_matches_held_kernel_object(self):
        held = self.bind_self()
        self.right.send(b'second')
        with receive(self.left) as record:
            held.require(record)
            self.assertFalse(os.get_inheritable(record.pidfd))
            self.assertEqual(record.credentials, (os.getpid(), os.getuid(), os.getgid()))
        self.assertEqual(record.pidfd, -1)

    def test_fork_inherited_endpoint_not_parent_authority(self):
        held = self.bind_self()
        child = os.fork()
        if child == 0:
            self.right.send(b'fork')
            os._exit(0)
        try:
            with receive(self.left) as record:
                self.assertEqual(record.credentials[0], child)
                with self.assertRaises(OriginDenied):
                    held.require(record)
        finally:
            os.waitpid(child, 0)

    def test_endpoint_passed_to_child_does_not_pass_authority(self):
        held = self.bind_self()
        transfer, receiver = socket.socketpair()
        child = os.fork()
        if child == 0:
            transfer.close(); self.right.close(); self.left.close()
            _, ancillary, _, _ = receiver.recvmsg(1, socket.CMSG_SPACE(4))
            fd = struct.unpack('i', ancillary[0][2])[0]
            peer = socket.socket(fileno=fd)
            peer.send(b'passed-fd')
            peer.close(); receiver.close()
            os._exit(0)
        receiver.close()
        try:
            transfer.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                     array.array('i', [self.right.fileno()]))])
            with receive(self.left) as record:
                with self.assertRaises(OriginDenied):
                    held.require(record)
        finally:
            transfer.close(); os.waitpid(child, 0)

    def test_received_rights_are_closed_even_when_record_denied(self):
        fd = os.open('/dev/null', os.O_RDONLY)
        try:
            before = len(os.listdir('/proc/self/fd'))
            for _ in range(10):
                self.right.sendmsg([b'bad'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                            array.array('i', [fd] * 16))])
                with self.assertRaises(OriginDenied):
                    receive(self.left)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        finally:
            os.close(fd)

    def test_oversized_and_empty_records_close_pidfd(self):
        before = len(os.listdir('/proc/self/fd'))
        for data in (b'x' * (MAX_PACKET + 1), b''):
            self.right.send(data)
            with self.assertRaises(OriginDenied):
                receive(self.left)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_exit_queued_record_and_replacement_are_denied(self):
        ready, release = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(release)
            self.right.send(b'bind')
            os.read(ready, 1)
            self.right.send(b'queued-before-exit')
            os._exit(0)
        os.close(ready)
        try:
            with receive(self.left) as record:
                held = HeldOrigin(record)
            self.addCleanup(held.close)
            os.write(release, b'x')
            os.waitpid(child, 0)
            self.assertFalse(alive(held.pidfd))
            with receive(self.left) as record:
                with self.assertRaises(OriginDenied):
                    held.require(record)
            self.right.send(b'replacement-same-uid')
            with receive(self.left) as record:
                with self.assertRaises(OriginDenied):
                    held.require(record)
        finally:
            os.close(release)

    def test_revocation_fences_still_live_task(self):
        held = self.bind_self()
        held.revoke()
        self.right.send(b'old')
        with receive(self.left) as record:
            with self.assertRaises(OriginDenied):
                held.require(record)

    def test_no_pidfd_option_is_fail_closed(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            right.send(b'old-kernel')
            with self.assertRaises(OriginDenied):
                receive(left)
        finally:
            left.close(); right.close()

    def test_unknown_architecture_and_non_pidfd_fail_closed(self):
        self.right.send(b'first')
        with receive(self.left) as record:
            with patch('uas.kernel_origin.platform.machine', return_value='i686'):
                with self.assertRaises(OriginUnavailable):
                    HeldOrigin(record)
        fd = os.open('/dev/null', os.O_RDONLY)
        with Record(b'', (1, 2, 3), fd) as record:
            with self.assertRaises(OriginUnavailable):
                HeldOrigin(record)

    def test_malformed_duplicate_and_control_truncation_close_all_fds(self):
        # Kernel does not emit malformed ancillary. Inject decoder inputs only;
        # this does not substitute for the real kernel tests above.
        for flag, kinds in ((socket.MSG_CTRUNC, [SCM_PIDFD]), (0, [SCM_PIDFD, SCM_PIDFD]),
                            (0, [socket.SCM_RIGHTS])):
            fds = [os.pidfd_open(os.getpid()) for _ in kinds]
            class Input:
                def recvmsg(self, *_):
                    return b'x', [(socket.SOL_SOCKET, kind, struct.pack('i', fd))
                                  for kind, fd in zip(kinds, fds)], flag, None
            with self.assertRaises(OriginDenied):
                receive(Input())
            for fd in fds:
                with self.assertRaises(OSError):
                    os.fstat(fd)


class KernelCapabilityFailureTests(unittest.TestCase):
    """Fault injection remains runnable even on an unsupported kernel."""
    def test_socketpair_failure_is_reported_as_unavailable(self):
        with patch('uas.kernel_origin.socket.socketpair', side_effect=PermissionError('denied')):
            with self.assertRaises(OriginUnavailable):
                probe()

    def test_both_mandatory_options_are_read_back(self):
        class Channel:
            family = socket.AF_UNIX
            def setsockopt(self, *_):
                pass
            def getsockopt(self, level, option):
                return socket.SOCK_SEQPACKET if option == socket.SO_TYPE else 0
        with self.assertRaises(OriginUnavailable):
            enable(Channel())

    def test_probe_option_and_pidfd_failure_leave_no_descriptors(self):
        before = len(os.listdir('/proc/self/fd'))
        with patch('uas.kernel_origin.enable', side_effect=OriginUnavailable('no option')):
            with self.assertRaises(OriginUnavailable):
                probe()
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        # First acquired pidfd must close if the second acquisition fails.
        real_open = os.pidfd_open
        calls = 0
        def fail_second(pid):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PermissionError('parent pidfd unavailable')
            return real_open(pid)
        with patch('uas.kernel_origin.enable'), patch('uas.kernel_origin.os.pidfd_open', side_effect=fail_second):
            with self.assertRaises(OriginUnavailable):
                probe()
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)


class ReceiverNamespaceTests(unittest.TestCase):
    setUpClass = KernelOriginTests.__dict__['setUpClass']
    setUp = KernelOriginTests.setUp

    def test_pid_zero_uses_held_object_and_pinned_receiver_uid_gid(self):
        from uas.kernel_origin import ReceiverIdentity
        from dataclasses import FrozenInstanceError
        self.right.send(b'bootstrap')
        receiver = ReceiverIdentity(os.getuid(), os.getgid(), 'hub-alpha', 'a'*64)
        with receive(self.left) as record:
            held = HeldOrigin(record, receiver=receiver)
        self.addCleanup(held.close)
        self.right.send(b'peer')
        with receive(self.left) as record:
            # Inject receiver-namespace credentials only. The real pidfd still
            # comes from the kernel; this is NOT a real namespace integration.
            record.credentials = (0, os.getuid(), os.getgid())
            with patch('uas.kernel_origin.os.pidfd_open', side_effect=AssertionError('no PID lookup')):
                held.require(record)
                for wrong in ((0, os.getuid()+1, os.getgid()), (0, os.getuid(), os.getgid()+1)):
                    record.credentials = wrong
                    with self.assertRaises(OriginDenied):
                        held.require(record)
        with self.assertRaises(FrozenInstanceError):
            receiver.uid = 123

    def test_pid_zero_different_task_is_denied(self):
        from uas.kernel_origin import ReceiverIdentity
        self.right.send(b'bootstrap')
        with receive(self.left) as record:
            held = HeldOrigin(record, receiver=ReceiverIdentity(os.getuid(), os.getgid(), 'hub', 'a'*64))
        self.addCleanup(held.close)
        ready, release = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(release)
            self.right.send(b'wrong-task')
            os.read(ready, 1)
            os._exit(0)
        os.close(ready)
        try:
            with receive(self.left) as record:
                record.credentials = (0, os.getuid(), os.getgid())
                with self.assertRaises(OriginDenied):
                    held.require(record)
        finally:
            os.close(release); os.waitpid(child, 0)

    def test_pid_one_profile_without_known_init_fails_closed(self):
        original = os.pidfd_open
        with patch('uas.kernel_origin.os.getppid', return_value=0), patch('uas.kernel_origin.os.pidfd_open', wraps=original) as opened:
            with self.assertRaisesRegex(OriginUnavailable, 'qualified Hub init required'):
                probe()
        self.assertEqual(opened.call_args_list, [unittest.mock.call(os.getpid())])

    def test_unmapped_overflow_identity_is_not_an_admitted_receiver(self):
        from uas.kernel_origin import ReceiverIdentity
        for uid, gid, overflow_uid, overflow_gid in ((65534, 1000, 65534, 65534),
                (1000, 65534, 65534, 65534), (1234, 1000, 1234, 5678)):
            with self.assertRaises(OriginDenied):
                ReceiverIdentity(uid, gid, 'hub', 'a'*64, overflow_uid, overflow_gid)
