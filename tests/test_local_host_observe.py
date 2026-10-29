import unittest
from types import SimpleNamespace
from unittest.mock import patch

from uas.local_host_profile import HostProfileError
from uas.local_host_observe import subordinate, allocated_ids, command


class FakeStream:
    def __init__(self, number): self.number, self.closed = number, False
    def fileno(self): return self.number
    def close(self): self.closed = True


class FakeProcess:
    pid = 999999
    returncode = None
    def __init__(self, result=0):
        self.stdout, self.stderr = FakeStream(31), FakeStream(32)
        self.result, self.waits = result, []
    def wait(self, timeout):
        self.waits.append(timeout)
        self.returncode = self.result
        return self.result


class FakeSelector:
    def __init__(self): self.entries = {}
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def register(self, stream, events, data):
        self.entries[stream.number] = SimpleNamespace(fileobj=stream, data=data)
    def unregister(self, stream): del self.entries[stream.number]
    def get_map(self): return self.entries
    def select(self, timeout): return [(key, 1) for key in list(self.entries.values())]


class HostObservationParsingTests(unittest.TestCase):
    def test_subordinate_preserves_other_users_and_conflicts(self):
        self.assertEqual(subordinate('# comment\nhuman:100000:65536\nuas:120000:65536\n'), [
            {'user':'human','offset':100000,'size':65536},
            {'user':'uas','offset':120000,'size':65536}])

    def test_subordinate_does_not_guess_malformed_rows(self):
        for value in ('user:abc:65536', 'user:100000', 'user:١٠٠٠٠٠:65536'):
            with self.assertRaises(HostProfileError): subordinate(value)

    def test_ids_only_no_account_password_content(self):
        self.assertEqual(allocated_ids('human:x:1000:1000::/home/human:/bin/bash\n',
                                       'other:x:1500:\n'), [1000, 1500])

    def run_fake(self, stdout, stderr=b'', *, result=0, clock=None):
        process = FakeProcess(result)
        buffers = {31:bytearray(stdout), 32:bytearray(stderr)}
        reads = []
        def read(fd, count):
            reads.append(count)
            answer=bytes(buffers[fd][:count]); del buffers[fd][:count]
            return answer
        patches = [patch('uas.local_host_process.subprocess.Popen', return_value=process),
                   patch('uas.local_host_process.selectors.DefaultSelector', FakeSelector),
                   patch('uas.local_host_process.os.read', side_effect=read),
                   patch('uas.local_host_process.os.killpg'),
                   patch('uas.local_host_observe.LIMIT', 8),
                   patch('uas.local_host_process.os.waitid', return_value=SimpleNamespace(
                       si_pid=process.pid, si_code=__import__('os').CLD_EXITED, si_status=result))]
        if clock is not None:
            patches.append(patch('uas.local_host_process.time.monotonic', side_effect=clock))
        from contextlib import ExitStack
        with ExitStack() as stack:
            mocks=[stack.enter_context(p) for p in patches]
            try:
                answer = command(['/usr/sbin/getenforce'])
                return answer, process, reads, mocks[3].call_count
            finally:
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)
                self.assertTrue(all(n <= 9 for n in reads))
                # No unbounded communicate or ambient environment exists in this
                # fake. Popen itself is mocked; no host command is launched.
                self.assertTrue(mocks[0].call_args.kwargs['start_new_session'])

    def test_fixed_command_incremental_capture(self):
        answer, process, reads, kills = self.run_fake(b'OK\n')
        self.assertEqual(answer, 'OK')
        self.assertEqual(kills, 1)
        self.assertGreater(len(reads), 1)

    def test_stdout_and_stderr_are_capped_before_buffering(self):
        for out, err in ((b'x'*10000,b''), (b'',b'x'*10000)):
            with self.assertRaisesRegex(HostProfileError, 'HOST_READ_BOUND'):
                self.run_fake(out, err)

    def test_fixed_command_deadline(self):
        with self.assertRaisesRegex(HostProfileError, 'HOST_READ_TIMEOUT'):
            self.run_fake(b'', clock=[0,0,11])

    def test_nonzero_exit_is_not_absence(self):
        with self.assertRaisesRegex(HostProfileError, 'HOST_READ_COMMAND'):
            self.run_fake(b'', result=1)


if __name__ == '__main__': unittest.main()
