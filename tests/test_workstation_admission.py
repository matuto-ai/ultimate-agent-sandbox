"""Real socketpair SCM_PIDFD/SCM_RIGHTS; simulated launch/native readiness.

No filesystem listener, Docker, real PID/user namespaces or SELinux evidence.
"""
import array
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from uas.kernel_origin import HeldOrigin, OriginDenied, OriginUnavailable, ReceiverIdentity, enable, probe, receive
from uas.workstation_admission import AdmissionSeat, HubAdmission, send_admit, _canonical, LIMIT
from uas.workstation_exec import ExecLaunch, ExecSeat


class Endpoint:
    def require(self):
        pass


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe()
        except OriginUnavailable as error:
            raise unittest.SkipTest(str(error))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.control, self.sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.peer, self.runtime = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        for channel in (self.control, self.sender, self.peer, self.runtime):
            channel.settimeout(2)
            self.addCleanup(channel.close)
        enable(self.control); enable(self.peer)
        self.sender.send(b'fixed-supervisor-startup')
        with receive(self.control) as record:
            self.supervisor = HeldOrigin(record)
        self.addCleanup(self.supervisor.close)
        self.runtime.send(b'fixed-runtime-bootstrap')
        with receive(self.peer) as record:
            self.origin = HeldOrigin(record)
        self.addCleanup(self.origin.close)
        self.receiver = ReceiverIdentity(os.getuid(), os.getgid(), 'hub-alpha', 'a'*64)
        self.seat = AdmissionSeat('alpha', 'room-instance', 'alice', 'actor-a', 'builder', ('implement',), self.receiver)
        self.journal = Path(self.temp.name)/'hub.db'
        self.hub = HubAdmission(self.journal, seats=(self.seat,), supervisor=self.supervisor, endpoint=Endpoint())
        self.addCleanup(lambda: self.hub.close())
        self.launch = ExecLaunch(None, ExecSeat('alpha', 'room-instance', 'alice', 'actor-a', 'seat-a', 'b'*64, os.getuid(), os.getgid()),
                                 Endpoint(), Path(self.temp.name)/'not-written')
        self.launch.state = 'active'  # Explicit synthetic native-readiness gate.
        self.launch.origin, self.launch.channel = self.origin, self.peer
        self.operation = '1'*32

    def renew_empty_hub(self):
        self.assertFalse(self.hub._active)
        self.hub.close()
        self.hub = HubAdmission(self.journal, seats=(self.seat,), supervisor=self.supervisor, endpoint=Endpoint())

    def offer(self, *, operation=None, epoch=1):
        send_admit(self.sender, launch=self.launch, seat=self.seat,
                   operation_id=operation or self.operation, epoch=epoch, readiness_digest='c'*64)

    def raw(self, *, change=None, fds=None, data=None):
        document = {'version': 1, 'kind': 'ADMIT', 'operation_id': self.operation, 'exchange_id': self.operation,
            'seat': self.seat.document(), 'incarnation': self.launch.incarnation,
            'epoch': 1, 'readiness_digest': 'c'*64, 'origin_identity': list(self.origin.identity)}
        if change:
            change(document)
        if fds is None:
            fds = [self.peer.fileno(), self.origin.pidfd]
        self.sender.sendmsg([data if data is not None else _canonical(document)],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])

    def active_record(self, data=b'queued'):
        self.runtime.send(data)
        return receive(self.hub._active[self.operation][0].channel)

    def test_single_admit_installs_queued_record_only_after_atomic_binding(self):
        self.runtime.send(b'queued-before-admission')
        self.assertFalse(self.hub.status(self.operation)['installed'])
        self.offer()
        ack = self.hub.admit(self.control)
        self.assertEqual(ack['status'], 'ADMITTED')
        with receive(self.hub._active[self.operation][0].channel) as record:
            with self.hub.authorize(self.operation, record) as binding:
                self.assertEqual(binding.seat.actor_id, 'actor-a')
                self.assertEqual(record.data, b'queued-before-admission')
                self.assertEqual(binding.seat.receiver, self.receiver)
        self.assertNotIn('Engine', self.journal.read_bytes().decode(errors='ignore'))

    def test_lost_ack_reconciles_read_only_without_relaunch_or_second_install(self):
        self.offer(); self.hub.admit(self.control)  # Deliberately discard ACK.
        first = self.hub.status(self.operation)
        second = self.hub.status(self.operation)
        self.assertEqual(first, second)
        self.assertTrue(first['installed'])
        self.assertEqual(len(self.hub._active), 1)
        before = len(os.listdir('/proc/self/fd'))
        self.offer()
        with self.assertRaisesRegex(OriginDenied, 'read-only status'):
            self.hub.admit(self.control)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_receiver_mapping_is_local_immutable_config_not_admit_selected(self):
        for field, value in (('uid', os.getuid()+1), ('gid', os.getgid()+1),
                             ('context', 'other-hub'), ('mapping_digest', 'f'*64),
                             ('overflow_uid', os.getuid())):
            with self.subTest(field=field):
                self.renew_empty_hub()
                before = len(os.listdir('/proc/self/fd'))
                self.raw(change=lambda d: d['seat']['receiver'].__setitem__(field, value))
                with self.assertRaises(OriginDenied):
                    self.hub.admit(self.control)
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.assertFalse(self.hub.status(self.operation)['installed'])

    def test_wrong_room_actor_capabilities_and_extra_fields_rejected(self):
        changes = [lambda d: d['seat'].__setitem__('room_id', 'beta'),
                   lambda d: d['seat'].__setitem__('actor_id', 'actor-b'),
                   lambda d: d['seat'].__setitem__('capabilities', ['admin']),
                   lambda d: d.__setitem__('engine', 'forbidden'),
                   lambda d: d.__setitem__('epoch', True)]
        for change in changes:
            self.renew_empty_hub()
            before = len(os.listdir('/proc/self/fd'))
            self.raw(change=change)
            with self.assertRaises(OriginDenied):
                self.hub.admit(self.control)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_wrong_same_uid_control_sender_is_denied_and_all_rights_closed(self):
        ready, release = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(release)
            self.raw()
            os.read(ready, 1)
            os._exit(0)
        os.close(ready)
        before = len(os.listdir('/proc/self/fd'))
        try:
            with self.assertRaises(OriginDenied):
                self.hub.admit(self.control)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        finally:
            os.close(release); os.waitpid(child, 0)

    def test_missing_third_swapped_or_file_rights_are_closed(self):
        fd = os.open('/dev/null', os.O_RDONLY)
        try:
            for fds in ([self.peer.fileno()], [self.peer.fileno(), self.origin.pidfd, fd],
                        [self.origin.pidfd, self.peer.fileno()], [fd, self.origin.pidfd],
                        [self.peer.fileno(), fd]):
                self.renew_empty_hub()
                before = len(os.listdir('/proc/self/fd'))
                self.raw(fds=fds)
                with self.assertRaises(OriginDenied):
                    self.hub.admit(self.control)
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        finally:
            os.close(fd)

    def test_oversized_malformed_duplicate_json_closes_rights(self):
        for data in (b'x'*(LIMIT+1), b'{', b'{"version":1,"version":1}', b'\xff', b'[]'):
            self.renew_empty_hub()
            before = len(os.listdir('/proc/self/fd'))
            self.raw(data=data)
            with self.assertRaises(OriginDenied):
                self.hub.admit(self.control)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_unready_or_revoked_launch_cannot_send_admit(self):
        for state in ('released', 'uncertain', 'revoked'):
            self.launch.state = state
            with self.assertRaises(OriginDenied):
                self.offer()
        self.launch.state = 'active'; self.origin.revoke()
        with self.assertRaises(OriginDenied):
            self.offer()

    def test_revocation_fences_before_disposal_and_epoch_cannot_repeat(self):
        self.offer(); self.hub.admit(self.control)
        with self.active_record() as record:
            self.hub.revoke(self.operation)
            with self.assertRaises(OriginDenied):
                with self.hub.authorize(self.operation, record):
                    pass
        self.assertEqual(self.hub.status(self.operation)['state'], 'revoked')
        self.offer(operation='2'*32)
        with self.assertRaisesRegex(OriginDenied, 'stale admission epoch'):
            self.hub.admit(self.control)
        self.offer(operation='3'*32, epoch=2)
        self.assertEqual(self.hub.admit(self.control)['status'], 'ADMITTED')

    def test_control_eof_fences_installed_seats(self):
        self.offer(); self.hub.admit(self.control)
        self.sender.close()
        with self.assertRaises(OriginDenied):
            self.hub.admit(self.control)
        self.assertFalse(self.hub.status(self.operation)['installed'])
        self.assertEqual(self.hub._active, {})

    def test_store_failure_installs_nothing_and_closes_transferred_descriptors(self):
        original = self.hub.db
        class FailingDB:
            def execute(self, sql, *args):
                if sql.startswith('INSERT INTO admissions'):
                    raise OSError('store failure')
                return original.execute(sql, *args)
            def __getattr__(self, name):
                return getattr(original, name)
        self.hub.db = FailingDB()
        before = len(os.listdir('/proc/self/fd'))
        self.offer()
        with self.assertRaises(OSError):
            self.hub.admit(self.control)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.assertEqual(self.hub.status(self.operation)['state'], 'absent')

    def test_postcommit_install_failure_receipt_never_becomes_authority(self):
        before = len(os.listdir('/proc/self/fd'))
        self.offer()
        with patch.object(self.hub, '_install', side_effect=OSError('install failure')):
            with self.assertRaises(OSError):
                self.hub.admit(self.control)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        result = self.hub.status(self.operation)
        self.assertIsNotNone(result['receipt'])
        self.assertFalse(result['installed'])
        self.assertTrue(self.hub._fenced)

    def test_restart_never_restores_authority_from_receipt(self):
        self.offer(); self.hub.admit(self.control)
        old_controller = self.hub.controller
        self.hub.close()
        self.hub = HubAdmission(self.journal, seats=(self.seat,), supervisor=self.supervisor, endpoint=Endpoint())
        result = self.hub.status(self.operation)
        self.assertEqual(result['receipt']['controller'], old_controller)
        self.assertNotEqual(self.hub.controller, old_controller)
        self.assertFalse(result['installed'])
        self.assertEqual(self.hub._active, {})

    def test_second_controller_and_different_room_cannot_adopt_journal(self):
        before = len(os.listdir('/proc/self/fd'))
        with self.assertRaises(BlockingIOError):
            HubAdmission(self.journal, seats=(self.seat,), supervisor=self.supervisor, endpoint=Endpoint())
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.hub.close()
        with self.assertRaises(OriginDenied):
            HubAdmission(self.journal, seats=(replace(self.seat, room_id='beta'),), supervisor=self.supervisor, endpoint=Endpoint())

    def test_endpoint_lease_loss_fences_before_authorization(self):
        self.offer(); self.hub.admit(self.control)
        with self.active_record() as record:
            with patch.object(self.hub.endpoint, 'require', side_effect=OSError('endpoint changed')):
                with self.assertRaises(OSError):
                    with self.hub.authorize(self.operation, record):
                        self.fail('must not reach ledger mutation')
        self.assertFalse(self.hub.status(self.operation)['installed'])

    def test_supervisor_revocation_fences_dispatch(self):
        self.offer(); self.hub.admit(self.control)
        with self.active_record() as record:
            self.supervisor.revoke()
            with self.assertRaises(OriginDenied):
                with self.hub.authorize(self.operation, record):
                    pass
        self.assertFalse(self.hub.status(self.operation)['installed'])

    def test_foreign_pidfd_and_exited_task_cannot_install(self):
        ready, release = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(release)
            self.runtime.send(b'child-object')
            os.read(ready, 1)
            os._exit(0)
        os.close(ready)
        with receive(self.peer) as record:
            child_origin = HeldOrigin(record)
        try:
            before = len(os.listdir('/proc/self/fd'))
            self.raw(fds=[self.peer.fileno(), child_origin.pidfd])
            with self.assertRaisesRegex(OriginDenied, 'substituted runtime'):
                self.hub.admit(self.control)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            os.close(release); release = -1
            os.waitpid(child, 0)
            self.renew_empty_hub()
            self.raw(fds=[self.peer.fileno(), child_origin.pidfd],
                     change=lambda d: d.__setitem__('origin_identity', list(child_origin.identity)))
            with self.assertRaisesRegex(OriginDenied, 'origin exited'):
                self.hub.admit(self.control)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before - 1)
        finally:
            child_origin.close()
            if release >= 0:
                os.close(release); os.waitpid(child, 0)

    def test_revocation_store_failure_still_fences_and_disposes(self):
        self.offer(); self.hub.admit(self.control)
        original = self.hub.db
        class FailingDB:
            def execute(self, sql, *args):
                if sql.startswith('UPDATE admissions'):
                    raise OSError('revocation store failure')
                return original.execute(sql, *args)
            def __getattr__(self, name):
                return getattr(original, name)
        self.hub.db = FailingDB()
        with self.assertRaises(OSError):
            self.hub.revoke(self.operation)
        self.assertTrue(self.hub._fenced)
        self.assertEqual(self.hub._active, {})
        self.assertFalse(self.hub.status(self.operation)['installed'])

    def test_revocation_serializes_with_authorized_ledger_transaction(self):
        import threading
        self.offer(); self.hub.admit(self.control)
        requested, finished = threading.Event(), threading.Event()
        failures = []
        def revoke():
            requested.set()
            try:
                self.hub.revoke(self.operation)
            except BaseException as error:
                failures.append(error)
            finally:
                finished.set()
        with self.active_record() as record:
            with self.hub.authorize(self.operation, record):
                thread = threading.Thread(target=revoke)
                thread.start()
                self.assertTrue(requested.wait(1))
                self.assertFalse(finished.wait(0.02))
            self.assertTrue(finished.wait(1))
            thread.join(timeout=1)
            self.assertFalse(failures)
            with self.assertRaises(OriginDenied):
                with self.hub.authorize(self.operation, record):
                    pass

    def test_stalled_control_receive_does_not_block_revocation_or_control_loss(self):
        import threading
        self.offer(); self.hub.admit(self.control)
        entered, unblock, fenced = threading.Event(), threading.Event(), threading.Event()
        failures = []
        control = self.control
        class StalledRead:
            def recvmsg(self, *args):
                entered.set()
                if not unblock.wait(2):
                    raise TimeoutError('test read not released')
                return control.recvmsg(*args)
        def admit():
            try:
                self.hub.admit(StalledRead())
                failures.append('unexpected admission')
            except OriginDenied:
                pass  # Required late packet rejection after fence.
            except BaseException as error:
                failures.append(error)
        def fence():
            try:
                self.hub.revoke(self.operation)
                self.hub.control_lost()
            except BaseException as error:
                failures.append(error)
            finally:
                fenced.set()
        receiver = threading.Thread(target=admit)
        revoker = threading.Thread(target=fence)
        receiver.start()
        try:
            self.assertTrue(entered.wait(1))
            revoker.start()
            self.assertTrue(fenced.wait(1), 'stalled transport held the authority lock')
            self.assertFalse(self.hub.status(self.operation)['installed'])
        finally:
            self.offer(operation='2'*32, epoch=2)
            unblock.set()
            receiver.join(timeout=2)
            if revoker.ident is not None:
                revoker.join(timeout=2)
        self.assertFalse(receiver.is_alive())
        self.assertFalse(failures)
        self.assertEqual(self.hub._active, {})

    def test_offer_close_failure_still_closes_channel_without_fd_retry(self):
        self.offer(); self.hub.admit(self.control)
        offer = self.hub._active[self.operation][0]
        original_close = os.close
        fd = offer.origin.pidfd
        calls = []
        def uncertain_close(value):
            calls.append(value)
            original_close(value)
            if value == fd:
                raise OSError('close reported failure after release')
        with patch('uas.kernel_origin.os.close', side_effect=uncertain_close):
            with self.assertRaises(OSError):
                self.hub.revoke(self.operation)
            offer.close()  # Both wrappers surrendered ownership, no retry.
        self.assertEqual(calls.count(fd), 1)
        self.assertEqual(offer.channel.fileno(), -1)
        self.assertEqual(offer.origin.pidfd, -1)

    def test_hub_close_db_failure_still_releases_exclusive_lease(self):
        original = self.hub.db
        class FailingClose:
            def close(self):
                original.close()
                raise OSError('database close failure')
            def __getattr__(self, name):
                return getattr(original, name)
        self.hub.db = FailingClose()
        with self.assertRaises(OSError):
            self.hub.close()
        self.assertEqual(self.hub._lease, -1)
        replacement = HubAdmission(self.journal, seats=(self.seat,), supervisor=self.supervisor, endpoint=Endpoint())
        replacement.close()

    def test_constructor_failure_and_db_close_failure_still_release_lease(self):
        self.hub.close()
        import sqlite3
        original_connect = sqlite3.connect
        class FailingSetup:
            def __init__(self, connection):
                self.connection = connection
            def execute(self, *args):
                raise OSError('database setup failure')
            def close(self):
                self.connection.close()
                raise OSError('database close failure')
        def connect(*args, **kwargs):
            return FailingSetup(original_connect(*args, **kwargs))
        before = len(os.listdir('/proc/self/fd'))
        with patch('uas.workstation_admission.sqlite3.connect', side_effect=connect):
            with self.assertRaises(OSError):
                HubAdmission(self.journal, seats=(self.seat,), supervisor=self.supervisor, endpoint=Endpoint())
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.hub = HubAdmission(self.journal, seats=(self.seat,), supervisor=self.supervisor, endpoint=Endpoint())

    def test_rejected_ancillary_close_failure_does_not_skip_remaining_fds(self):
        extra = os.open('/dev/null', os.O_RDONLY)
        original_close = os.close
        calls = []
        def fail_first_after_close(fd):
            original_close(fd)
            calls.append(fd)
            if len(calls) == 1:
                raise OSError('uncertain first descriptor close')
        try:
            before = len(os.listdir('/proc/self/fd'))
            self.raw(fds=[self.peer.fileno(), self.origin.pidfd, extra])
            with patch('uas.workstation_admission.os.close', side_effect=fail_first_after_close):
                with self.assertRaises(OSError):
                    self.hub.admit(self.control)
            self.assertEqual(len(calls), 4)  # Three rights plus kernel sender pidfd.
            self.assertEqual(len(set(calls)), 4)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        finally:
            os.close(extra)

    def test_sender_cleanup_failure_cancels_offer_without_stranding_peer_fds(self):
        original_close = os.close
        calls = []
        def fail_first_after_close(fd):
            original_close(fd)
            calls.append(fd)
            if len(calls) == 1:
                raise OSError('sender pidfd close failure')
        before = len(os.listdir('/proc/self/fd'))
        self.offer()
        with patch('uas.workstation_admission.os.close', side_effect=fail_first_after_close):
            with self.assertRaises(OSError):
                self.hub.admit(self.control)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.assertEqual(self.hub._active, {})
        self.assertEqual(len(calls), 2)  # Sender pidfd and assembled runtime pidfd.
        self.assertEqual(len(set(calls)), 2)

    def test_same_held_kernel_task_cannot_bind_a_second_actor_seat(self):
        other = replace(self.seat, participant_id='bob', actor_id='actor-b')
        self.hub.close()
        self.hub = HubAdmission(Path(self.temp.name)/'two-seats.db', seats=(self.seat, other),
                                supervisor=self.supervisor, endpoint=Endpoint())
        self.offer(); self.hub.admit(self.control)
        # Real received kernel task object reused with a second trusted seat;
        # even an authenticated Supervisor packet cannot duplicate active origin.
        self.launch.seat = ExecSeat('alpha', 'room-instance', 'bob', 'actor-b', 'seat-b',
                                   'b'*64, os.getuid(), os.getgid())
        before = len(os.listdir('/proc/self/fd'))
        send_admit(self.sender, launch=self.launch, seat=other, operation_id='2'*32,
                   epoch=1, readiness_digest='c'*64)
        with self.assertRaisesRegex(OriginDenied, 'kernel task already bound'):
            self.hub.admit(self.control)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        self.assertTrue(self.hub.status(self.operation)['installed'])
        self.assertEqual(self.hub.status('2'*32)['state'], 'absent')
