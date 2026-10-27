"""Pure construction/ownership tests: Popen, signals and waits are mocked."""
import hashlib
import io
import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.forge import ForgeBinding
from uas.git_policy import GitTarget
from uas.git_transport import (GitTransportConfig, GitTransportError,
                               SshActorCredential, SshTransport, _open_without_links)


class DescriptorTraversalTests(unittest.TestCase):
    """Every descriptor observation here is fabricated; no real opens/closes."""
    def test_leaf_transfers_only_after_parent_closed(self):
        with patch('uas.git_transport.os.open', side_effect=[11, 12, 13]) as opened, \
                patch('uas.git_transport.os.close') as closed:
            self.assertEqual(13, _open_without_links(Path('/one/key')))
        self.assertEqual([11, 12], [call.args[0] for call in closed.call_args_list])
        self.assertEqual(12, opened.call_args.kwargs['dir_fd'])

    def test_failed_final_parent_close_disposes_leaf_once(self):
        def close(fd):
            if fd == 12:
                raise OSError('parent may already be closed')
        with patch('uas.git_transport.os.open', side_effect=[11, 12, 13]), \
                patch('uas.git_transport.os.close', side_effect=close) as closed:
            with self.assertRaises(OSError):
                _open_without_links(Path('/one/key'))
        self.assertEqual([11, 12, 13], [call.args[0] for call in closed.call_args_list])

    def test_failed_intermediate_close_disposes_new_parent_without_retry(self):
        def close(fd):
            if fd == 11:
                raise OSError('old parent may already be closed')
        with patch('uas.git_transport.os.open', side_effect=[11, 12]) as opened, \
                patch('uas.git_transport.os.close', side_effect=close) as closed:
            with self.assertRaises(OSError):
                _open_without_links(Path('/one/key'))
        self.assertEqual(2, opened.call_count)
        self.assertEqual([11, 12], [call.args[0] for call in closed.call_args_list])

    def test_failed_parent_and_leaf_closes_are_each_attempted_only_once(self):
        def close(fd):
            if fd in (12, 13):
                raise OSError('disposal uncertain')
        with patch('uas.git_transport.os.open', side_effect=[11, 12, 13]), \
                patch('uas.git_transport.os.close', side_effect=close) as closed:
            with self.assertRaises(OSError):
                _open_without_links(Path('/one/key'))
        self.assertEqual([11, 12, 13], [call.args[0] for call in closed.call_args_list])


class Pipe(io.BytesIO):
    def fileno(self):
        return 99999


class Process:
    def __init__(self):
        self.pid = 999999
        self.stdin, self.stdout, self.stderr = Pipe(), Pipe(), Pipe()
        self.returncode = None
        self.wait = Mock(side_effect=self._wait)

    def _wait(self, timeout=None):
        self.returncode = 0
        return 0


class SshTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = self.root / 'ssh'
        self.executable.write_bytes(b'pinned fixture executable; never executed')
        self.executable.chmod(0o555)
        self.sha = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.key = self.root / 'key'
        self.key.write_bytes(b'NOT_A_REAL_KEY_fixture_secret')
        self.key.chmod(0o600)
        self.hosts = self.root / 'known-hosts'
        self.hosts.write_bytes(b'github.com fixture-host-key-not-a-real-key')
        self.hosts.chmod(0o600)
        self.binding = ForgeBinding('room-a', 'project-a', 'Owner/Project')
        self.credential = SshActorCredential('actor-a', str(self.key), str(self.hosts))
        self.process = Process()
        self.launch = self.enterContext(patch('uas.git_transport.subprocess.Popen', return_value=self.process))
        self.blocking = self.enterContext(patch('uas.git_transport.os.set_blocking'))
        self.disposition = self.enterContext(patch('uas.git_transport.signal.getsignal', return_value=signal.SIG_DFL))
        self.observe = self.enterContext(patch('uas.git_transport.os.waitid', return_value=SimpleNamespace(si_pid=999999)))
        self.kill = self.enterContext(patch('uas.git_transport.os.killpg'))

    def transport(self, *, config=None):
        transport = SshTransport(config or GitTransportConfig(str(self.executable), self.sha, (self.credential,)), self.binding)
        self.addCleanup(transport.close)
        return transport

    def open(self, transport=None, *, actor='actor-a', repository='other/readable', service='git-upload-pack'):
        return (transport or self.transport()).open(actor, GitTarget('github.com', repository, service))

    def test_exact_actor_held_private_descriptors_clean_environment_and_fixed_ssh(self):
        transport = self.transport()
        with patch.dict(os.environ, {'SSH_AUTH_SOCK': '/ambient/socket', 'HOME': '/ambient/home',
                                     'GIT_SSH_COMMAND': 'evil', 'SSH_ASKPASS': 'evil', 'LD_PRELOAD': 'evil'}):
            session = self.open(transport)
        argv = self.launch.call_args.args[0]
        options = self.launch.call_args.kwargs
        self.assertEqual(f'/proc/self/fd/{transport.fd}', argv[0])
        self.assertEqual(['-F', '/dev/null'], argv[1:3])
        self.assertEqual(['-p', '22', '-T', 'git@github.com', "git-upload-pack 'other/readable.git'"], argv[-5:])
        self.assertEqual({'HOME': options['cwd'], 'LC_ALL': 'C'}, options['env'])
        self.assertEqual([], list(Path(options['cwd']).iterdir()))
        for value in ('BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'StrictHostKeyChecking=yes',
                      'GlobalKnownHostsFile=/dev/null', 'ProxyCommand=none', 'ProxyJump=none',
                      'ClearAllForwardings=yes', 'ForwardAgent=no', 'ForwardX11=no', 'PermitLocalCommand=no',
                      'ControlMaster=no', 'ControlPath=none', 'ControlPersist=no', 'UpdateHostKeys=no',
                      'VerifyHostKeyDNS=no', 'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no'):
            self.assertIn(value, argv)
        self.assertEqual((transport.fd,), options['pass_fds'])
        key_path = argv[argv.index('-i') + 1]
        hosts_path = next(word.split('=', 1)[1] for word in argv if word.startswith('UserKnownHostsFile='))
        self.assertTrue(key_path.startswith(f'/proc/{os.getpid()}/fd/'))
        self.assertTrue(hosts_path.startswith(f'/proc/{os.getpid()}/fd/'))
        self.assertEqual(self.key.stat().st_ino, os.fstat(int(key_path.rsplit('/', 1)[1])).st_ino)
        self.assertEqual(self.hosts.stat().st_ino, os.fstat(int(hosts_path.rsplit('/', 1)[1])).st_ino)
        held = tuple(session._descriptors)
        self.assertTrue(options['close_fds'])
        self.assertTrue(options['start_new_session'])
        self.assertFalse(options['shell'])
        self.assertEqual(3, self.blocking.call_count)
        self.assertNotIn('fixture_secret', repr(self.launch.call_args))
        self.assertNotIn(str(self.key), argv)
        session.finish()
        self.assertFalse(Path(options['cwd']).exists())
        for descriptor in held:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_project_push_uses_configured_spelling_and_cross_project_never_launches(self):
        transport = self.transport()
        session = self.open(transport, repository='owner/project', service='git-receive-pack')
        self.assertEqual("git-receive-pack 'Owner/Project.git'", self.launch.call_args.args[0][-1])
        session.finish()
        self.launch.reset_mock()
        with self.assertRaises(GitTransportError):
            self.open(transport, repository='other/project', service='git-receive-pack')
        self.launch.assert_not_called()

    def test_exact_actor_lookup_never_falls_back_to_ambient_or_sibling(self):
        transport = self.transport()
        for actor in ('actor-b', 'default', 'github.com', None, ['actor-a']):
            with self.subTest(actor=actor), self.assertRaises(GitTransportError):
                self.open(transport, actor=actor)
        self.launch.assert_not_called()
        self.assertFalse(transport.failed)

    def test_mutated_or_untyped_target_denied_again_before_contact(self):
        transport = self.transport()
        targets = [None, {}, SimpleNamespace(host='github.com', repository='Owner/Project', service='git-upload-pack')]
        for field, value in (('host', 'evil.invalid'), ('repository', 'Owner/Project;evil'), ('service', 'sh')):
            target = GitTarget('github.com', 'Owner/Project', 'git-upload-pack')
            object.__setattr__(target, field, value)
            targets.append(target)
        for target in targets:
            with self.assertRaises(GitTransportError):
                transport.open('actor-a', target)
        self.launch.assert_not_called()

    def test_missing_nonprivate_symlink_and_empty_files_refuse_precontact(self):
        transport = self.transport()
        original = self.key.read_bytes()
        for mode in (0o644, 0o640, 0o700, 0o200):
            self.key.chmod(mode)
            with self.assertRaises(GitTransportError):
                self.open(transport)
        self.key.chmod(0o600)
        self.key.write_bytes(b'')
        with self.assertRaises(GitTransportError):
            self.open(transport)
        self.key.write_bytes(original)
        self.key.rename(self.root / 'actual-key')
        self.key.symlink_to(self.root / 'actual-key')
        with self.assertRaises(GitTransportError):
            self.open(transport)
        self.key.unlink()
        with self.assertRaises(GitTransportError):
            self.open(transport)
        self.launch.assert_not_called()
        self.assertFalse(transport.failed)  # Other Actors need not be disabled.

    def test_private_files_checked_on_each_session_and_held_after_open(self):
        transport = self.transport()
        first = self.open(transport)
        key_fd = first._descriptors[0]
        prior_inode = os.fstat(key_fd).st_ino
        self.key.rename(self.root / 'old-key')
        self.key.write_bytes(b'new-fixture-key')
        self.key.chmod(0o600)
        self.assertEqual(prior_inode, os.fstat(key_fd).st_ino)
        first.finish()
        self.process = Process()
        self.launch.return_value = self.process
        second = self.open(transport)
        self.assertNotEqual(prior_inode, os.fstat(second._descriptors[0]).st_ino)
        second.abort()
        self.hosts.chmod(0o644)
        self.launch.reset_mock()
        with self.assertRaises(GitTransportError):
            self.open(transport)
        self.launch.assert_not_called()

    def test_symlinked_ancestor_is_refused_even_after_a_stale_resolve_check(self):
        # Simulate replacement between canonical resolution and open. Directory
        # traversal must independently refuse links, not trust the earlier check.
        link = self.root / 'key-directory'
        link.symlink_to(self.root, target_is_directory=True)
        credential = SshActorCredential('actor-a', str(link / 'key'), str(self.hosts))
        transport = self.transport(config=GitTransportConfig(str(self.executable), self.sha, (credential,)))
        with patch('uas.git_transport._canonical_path', side_effect=lambda value: Path(value)):
            with self.assertRaises(GitTransportError):
                self.open(transport)
        self.launch.assert_not_called()

    def test_wrong_credential_owner_and_hardlink_refuse_without_contact(self):
        transport = self.transport()
        actual = os.fstat
        def changed_owner(descriptor):
            observed = actual(descriptor)
            if observed.st_ino == self.key.stat().st_ino:
                return SimpleNamespace(st_mode=observed.st_mode, st_uid=os.getuid() + 1,
                                       st_nlink=observed.st_nlink, st_size=observed.st_size)
            return observed
        with patch('uas.git_transport.os.fstat', side_effect=changed_owner):
            with self.assertRaises(GitTransportError):
                self.open(transport)
        os.link(self.key, self.root / 'other-key-link')
        with self.assertRaises(GitTransportError):
            self.open(transport)
        self.launch.assert_not_called()

    def test_executable_path_replacement_cannot_replace_held_inode(self):
        transport = self.transport()
        identity = transport.identity
        self.executable.rename(self.root / 'original-ssh')
        self.executable.write_bytes(b'not the held executable')
        self.executable.chmod(0o555)
        self.open(transport).finish()
        self.assertEqual(identity, transport.identity)
        (self.root / 'original-ssh').chmod(0o755)
        (self.root / 'original-ssh').write_bytes(b'changed-held-executable')
        self.launch.reset_mock()
        with self.assertRaises(GitTransportError):
            self.open(transport)
        self.assertTrue(transport.failed)
        self.launch.assert_not_called()

    def test_unqualified_executable_modes_pin_symlink_fail_before_launch(self):
        for mode in (0o644, 0o777):
            self.executable.chmod(mode)
            with self.assertRaises(GitTransportError):
                self.transport()
        self.executable.chmod(0o555)
        with self.assertRaises(GitTransportError):
            self.transport(config=GitTransportConfig(str(self.executable), 'f' * 64, (self.credential,)))
        link = self.root / 'ssh-link'
        link.symlink_to(self.executable)
        with self.assertRaises(GitTransportError):
            self.transport(config=GitTransportConfig(str(link), self.sha, (self.credential,)))
        self.launch.assert_not_called()

    def test_finish_signals_owned_group_before_one_reap_and_is_idempotent(self):
        events = []
        self.observe.side_effect = lambda *_: events.append('observe') or SimpleNamespace(si_pid=999999)
        self.kill.side_effect = lambda *_: events.append('signal')
        self.process.wait.side_effect = lambda **_: events.append('reap') or 0
        session = self.open()
        self.assertEqual(0, session.finish())
        self.assertEqual(['observe', 'observe', 'signal', 'reap'], events)
        self.assertEqual(0, session.finish())
        self.assertEqual(0, session.abort())
        self.kill.assert_called_once()
        self.process.wait.assert_called_once()
        self.assertTrue(all(stream.closed for stream in (session.stdin, session.stdout, session.stderr)))

    def test_abort_of_running_leader_still_proves_ownership_before_signal(self):
        self.observe.return_value = None
        session = self.open()
        self.assertEqual(0, session.abort())
        self.observe.assert_called_once()
        self.kill.assert_called_once_with(self.process.pid, signal.SIGKILL)
        self.process.wait.assert_called_once_with(timeout=2)

    def test_echild_never_signals_or_reaps_released_numeric_identity(self):
        transport = self.transport()
        session = self.open(transport)
        self.observe.side_effect = ChildProcessError()
        with self.assertRaises(GitTransportError):
            session.finish()
        self.assertTrue(transport.failed)
        self.kill.assert_not_called()
        self.process.wait.assert_not_called()
        with self.assertRaises(GitTransportError):
            session.abort()
        self.kill.assert_not_called()
        self.launch.reset_mock()
        with self.assertRaises(GitTransportError):
            self.open(transport)
        self.launch.assert_not_called()

    def test_second_ownership_check_failure_refuses_signal_after_prior_exit(self):
        session = self.open()
        self.observe.side_effect = [SimpleNamespace(si_pid=999999), ChildProcessError()]
        with self.assertRaises(GitTransportError):
            session.finish()
        self.kill.assert_not_called()
        self.process.wait.assert_not_called()

    def test_interrupted_reap_is_not_retried_or_signaled_again(self):
        transport = self.transport()
        session = self.open(transport)
        def reaped_then_interrupted(**_):
            self.process.returncode = 0
            raise KeyboardInterrupt()
        self.process.wait.side_effect = reaped_then_interrupted
        with self.assertRaises(GitTransportError):
            session.abort()
        self.assertTrue(transport.failed)
        with self.assertRaises(GitTransportError):
            session.abort()
        self.kill.assert_called_once()
        self.process.wait.assert_called_once()

    def test_nondefault_reaper_refuses_contact_and_changed_disposition_fences(self):
        transport = self.transport()
        self.disposition.return_value = signal.SIG_IGN
        with self.assertRaises(GitTransportError):
            self.open(transport)
        self.launch.assert_not_called()
        self.assertTrue(transport.failed)
        self.disposition.return_value = signal.SIG_DFL
        transport = self.transport()
        session = self.open(transport)
        self.disposition.return_value = signal.SIG_IGN
        with self.assertRaises(GitTransportError):
            session.abort()
        self.kill.assert_not_called()

    def test_pipe_setup_failure_cleans_owned_child_and_files(self):
        transport = self.transport()
        self.blocking.side_effect = OSError('fixture setup failure')
        with self.assertRaises(GitTransportError) as caught:
            self.open(transport)
        self.assertEqual('SSH_PIPE_SETUP_FAILED', caught.exception.code)
        self.kill.assert_called_once()
        self.process.wait.assert_called_once()
        self.assertFalse(transport._sessions)
        self.assertTrue(all(stream.closed for stream in (self.process.stdin, self.process.stdout, self.process.stderr)))
        self.assertFalse(Path(self.launch.call_args.kwargs['cwd']).exists())

    def test_timeout_aborts_once_but_successful_cleanup_does_not_fence_owner(self):
        transport = self.transport()
        session = self.open(transport)
        self.observe.return_value = None
        with self.assertRaises(GitTransportError) as caught:
            session.finish(timeout=0)
        self.assertEqual('SSH_TIMEOUT', caught.exception.code)
        self.kill.assert_called_once()
        self.process.wait.assert_called_once()
        self.assertFalse(transport.failed)

    def test_launch_failure_is_sanitized_fenced_and_releases_private_descriptors(self):
        transport = self.transport()
        self.launch.side_effect = OSError('DO_NOT_EXPOSE_CREDENTIAL_PATH')
        with self.assertRaises(GitTransportError) as caught:
            self.open(transport)
        self.assertEqual('SSH_LAUNCH_UNKNOWN', caught.exception.code)
        self.assertNotIn('DO_NOT_EXPOSE', str(caught.exception))
        self.assertTrue(transport.failed)
        self.assertFalse(Path(self.launch.call_args.kwargs['cwd']).exists())
        self.kill.assert_not_called()
        self.observe.assert_not_called()

    def test_acquisition_cleanup_attempts_all_descriptors_and_home_despite_failures(self):
        transport = self.transport()
        home = Mock(name='/private/mock-home')
        home.name = '/private/mock-home'
        home.cleanup.side_effect = OSError('private home detail')
        self.launch.side_effect = OSError('private launch detail')
        with patch('uas.git_transport._private_file', side_effect=[51, 52]), \
                patch('uas.git_transport.tempfile.TemporaryDirectory', return_value=home), \
                patch('uas.git_transport.os.close', side_effect=OSError('private descriptor detail')) as closed:
            with self.assertRaises(GitTransportError) as caught:
                self.open(transport)
        self.assertEqual('SSH_CLEANUP_UNKNOWN', caught.exception.code)
        self.assertEqual([52, 51], [call.args[0] for call in closed.call_args_list])
        home.cleanup.assert_called_once_with()
        self.assertTrue(transport.failed)
        self.kill.assert_not_called()
        self.observe.assert_not_called()

    def test_prelaunch_home_acquisition_failure_still_disposes_each_descriptor_once(self):
        transport = self.transport()
        def close(fd):
            if fd == 52:
                raise OSError('possibly closed')
        with patch('uas.git_transport._private_file', side_effect=[51, 52]), \
                patch('uas.git_transport.tempfile.TemporaryDirectory', side_effect=OSError('home unavailable')), \
                patch('uas.git_transport.os.close', side_effect=close) as closed:
            with self.assertRaises(GitTransportError) as caught:
                self.open(transport)
        self.assertEqual('SSH_CLEANUP_UNKNOWN', caught.exception.code)
        self.assertEqual([52, 51], [call.args[0] for call in closed.call_args_list])
        self.assertTrue(transport.failed)
        self.launch.assert_not_called()

    def test_missing_process_group_is_safe_but_signal_failure_is_uncertain(self):
        self.kill.side_effect = ProcessLookupError()
        session = self.open()
        self.assertEqual(0, session.abort())
        self.process = Process()
        self.launch.return_value = self.process
        self.kill.reset_mock()
        self.kill.side_effect = PermissionError()
        transport = self.transport()
        session = self.open(transport)
        with self.assertRaises(GitTransportError):
            session.abort()
        self.assertTrue(transport.failed)
        self.process.wait.assert_not_called()
        with self.assertRaises(GitTransportError):
            session.abort()
        self.kill.assert_called_once()

    def test_config_is_exact_immutable_no_duplicates_or_relative_refs(self):
        for args in (('actor-a', 'relative', str(self.hosts)), ('actor-a', '/x/../key', str(self.hosts)),
                     ('actor-a', str(self.key), str(self.key)), ('', str(self.key), str(self.hosts))):
            with self.assertRaises(GitTransportError):
                SshActorCredential(*args)
        for args in ((str(self.executable), self.sha, [self.credential]),
                     (str(self.executable), self.sha, (self.credential, self.credential)),
                     (str(self.executable), 'bad', (self.credential,))):
            with self.assertRaises(GitTransportError):
                GitTransportConfig(*args)
        self.launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
