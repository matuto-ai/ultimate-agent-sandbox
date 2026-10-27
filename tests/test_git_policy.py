from dataclasses import FrozenInstanceError
import unittest

from uas.forge import ForgeBinding
from uas.git_policy import (GitCommand, GitIdentity, GitPolicyError, GitTarget,
                            ROUTES, generated_help, parse_git, parse_ssh)


class GitIdentityTests(unittest.TestCase):
    def test_identity_is_exact_immutable_not_a_runtime_or_model_selector(self):
        identity = GitIdentity('actor-a', 'Canonical Actor', 'actor@example.invalid')
        self.assertEqual('actor-a', identity.actor_id)
        with self.assertRaises(FrozenInstanceError):
            identity.name = 'Other'

    def test_identity_refuses_injection_empty_noncanonical_and_unbounded_values(self):
        for name in ('', ' Actor', 'Actor ', '<Actor>', 'Actor\nOther', 'Actor\tOther',
                     'Actor\x00', 'Actor\u0085', 'Actor\u2028Other', 'Actor\ud800', 'x' * 257):
            with self.subTest(name=repr(name)), self.assertRaises(GitPolicyError):
                GitIdentity('actor', name, 'actor@example.invalid')
        for email in ('', 'a', 'a@@b', 'a@', '@b', 'a b@c', 'a\nb@c', '<a>@b', 'a@bé', 'a' * 255 + '@b'):
            with self.subTest(email=repr(email)), self.assertRaises(GitPolicyError):
                GitIdentity('actor', 'Actor', email)
        for actor in ('', '../other', 'a:b', 'a b', 'a' * 129, None):
            with self.assertRaises(GitPolicyError):
                GitIdentity(actor, 'Actor', 'a@b')


class GitTransportPolicyTests(unittest.TestCase):
    def setUp(self):
        self.binding = ForgeBinding('room-a', 'project-a', 'Owner/Project')

    def test_read_has_no_invented_repository_allowlist(self):
        for repository in ('Owner/Project', 'another/private-repo', 'x/a.b-c_d'):
            result = parse_ssh(['git@github.com', f"git-upload-pack '{repository}.git'"], self.binding)
            self.assertEqual(GitTarget('github.com', repository, 'git-upload-pack'), result)
        self.assertEqual('another/repo', parse_ssh(['-o', 'SendEnv=GIT_PROTOCOL', 'git@github.com',
            "git-upload-pack 'another/repo.git'"], self.binding).repository)

    def test_push_is_project_pinned_and_canonicalized(self):
        result = parse_ssh(['git@github.com', "git-receive-pack 'owner/project.git'"], self.binding)
        self.assertEqual(GitTarget('github.com', 'Owner/Project', 'git-receive-pack'), result)
        with self.assertRaises(GitPolicyError) as caught:
            parse_ssh(['git@github.com', "git-receive-pack 'Owner/Other.git'"], self.binding)
        self.assertEqual('GIT_PROJECT_MISMATCH', caught.exception.code)

    def test_no_arbitrary_ssh_configuration_service_or_shell_syntax(self):
        ordinary = ['git@github.com', "git-upload-pack 'Owner/Project.git'"]
        cases = [[], ordinary + ['extra'], ['-G', *ordinary], ['-T', *ordinary], ['-p', '22', *ordinary],
                 ['-F', '/tmp/config', *ordinary], ['-i', '/tmp/key', *ordinary],
                 ['-o', 'ProxyCommand=evil', *ordinary], ['-oSendEnv=GIT_PROTOCOL', *ordinary],
                 ['-o', 'SendEnv=GIT_PROTOCOL', '-o', 'SendEnv=GIT_PROTOCOL', *ordinary],
                 ['git@evil.invalid', ordinary[1]], ['github.com', ordinary[1]],
                 ['git@github.com', 'sh'], ['git@github.com', 'scp -t x'],
                 ['git@github.com', 'rsync --server x'], ['git@github.com', "git-upload-archive 'Owner/Project.git'"],
                 ['git@github.com', "git-upload-pack 'Owner/Project.git'; evil"],
                 ['git@github.com', 'git-upload-pack "Owner/Project.git"'],
                 ['git@github.com', "git-upload-pack Owner/Project.git"],
                 ['git@github.com', "git-upload-pack '/Owner/Project.git'"],
                 ['git@github.com', "git-upload-pack 'Owner/../Project.git'"],
                 ['git@github.com', "git-upload-pack 'Owner/Project'"],
                 ['git@github.com', "git-upload-pack 'Owner/Project.git'\n"],
                 ['git@github.com', "git-upload-pack 'Owner/Project.git'\x00"]]
        for argv in cases:
            with self.subTest(argv=argv), self.assertRaises(GitPolicyError):
                parse_ssh(argv, self.binding)

    def test_binding_target_and_argument_types_fail_closed(self):
        good = ['git@github.com', "git-upload-pack 'Owner/Project.git'"]
        for binding in (None, {}, ForgeBinding('r', 'p', 'owner/repo', 'evil.invalid'),
                        ForgeBinding('r', 'p', '../repo'), ForgeBinding('r', 'p', 'x/..')):
            with self.assertRaises(GitPolicyError):
                parse_ssh(good, binding)
        for argv in (None, 'git', [1], [None], ['x' * 4097], ['\ud800']):
            with self.assertRaises(GitPolicyError):
                parse_ssh(argv, self.binding)
        for args in (('other', 'x/y', 'git-upload-pack'), ('github.com', 'x/..', 'git-upload-pack'),
                     ('github.com', 'x/y', 'sh')):
            with self.assertRaises(GitPolicyError):
                GitTarget(*args)


class GitCommandPolicyTests(unittest.TestCase):
    EXAMPLES = {
        'status': ['--short', '--branch'], 'log': ['-n', '20', '--oneline', 'HEAD'],
        'show': ['HEAD'], 'diff': ['--cached', '--', 'src/a.py'],
        'rev-parse': ['--verify', 'HEAD'], 'ls-files': ['--stage'],
        'ls-tree': ['-r', 'HEAD'], 'cat-file': ['-p', 'a' * 40],
        'show-ref': ['--heads'], 'merge-base': ['--is-ancestor', 'main', 'HEAD'],
        'add': ['--', 'src/a.py'], 'rm': ['--', 'old.py'], 'mv': ['--', 'old.py', 'new.py'],
        'branch': ['feature', 'main'], 'switch': ['-c', 'feature', 'main'],
        'restore': ['--staged', '--', 'src/a.py'], 'commit': ['-m', 'Exact message'],
        'cherry-pick': ['a' * 40], 'fetch': ['--prune', 'origin'],
        'ls-remote': ['--heads', 'origin'], 'push': ['origin', 'HEAD:refs/heads/feature'],
    }

    def test_table_drives_every_declared_command_and_helper(self):
        self.assertEqual(set(self.EXAMPLES), {row.command for row in ROUTES})
        for row in ROUTES:
            argv = self.EXAMPLES[row.command]
            with self.subTest(command=row.command):
                command = parse_git('/usr/bin/git', [row.command, *argv])
                self.assertEqual(GitCommand(row.command, tuple(argv), row.kind), command)
                self.assertEqual(command, parse_git('/usr/lib/git-core/git-' + row.command, argv))
                self.assertIn('git ' + row.command + ' ', generated_help())
                for flag in (*row.flags, *row.values):
                    self.assertIn(flag, generated_help())
                with self.assertRaises(FrozenInstanceError):
                    command.args = ('evil',)

    def test_cwd_is_one_absolute_lexically_canonical_selector_not_authority(self):
        command = parse_git('git', ['-C', '/checkout/slot', 'status'])
        self.assertEqual('/checkout/slot', command.cwd)
        self.assertIsNone(parse_git('git', ['status']).cwd)
        for argv in (['-C', '.', 'status'], ['-C', '/x/../y', 'status'],
                     ['-C', '//x', 'status'], ['-C', '/x/', 'status'], ['-C', '/x//y', 'status'],
                     ['-C', '/x/./y', 'status'], ['-C', '/x', '-C', '/y', 'status'],
                     ['-C/x', 'status'], ['-C', '/x'], ['-C', '/x\\y', 'status']):
            with self.subTest(argv=argv), self.assertRaises(GitPolicyError):
                parse_git('git', argv)

    def test_no_global_configuration_or_public_transport_helpers(self):
        for leading in (['-c', 'core.sshCommand=evil'], ['-ccore.hooksPath=/tmp'],
                        ['--config-env=x=y'], ['--exec-path=/tmp'], ['--git-dir=/tmp'],
                        ['--work-tree=/tmp'], ['--namespace=x'], ['--bare'], ['--paginate']):
            with self.assertRaises(GitPolicyError):
                parse_git('git', [*leading, 'status'])
        for command in ('am', 'config', 'credential', 'remote', 'clone', 'daemon', 'shell',
                        'upload-pack', 'receive-pack', 'upload-archive', 'remote-ext', 'remote-http',
                        'fast-import', 'commit-tree', 'hash-object', 'filter-branch', 'alias-name'):
            with self.subTest(command=command), self.assertRaises(GitPolicyError):
                parse_git('git', [command])
            with self.subTest(helper=command), self.assertRaises(GitPolicyError):
                parse_git('git-' + command, [])
        for invoked in ('scalar', 'ssh', 'git-backend-exec', '', None):
            with self.assertRaises(GitPolicyError):
                parse_git(invoked, ['status'])

    def test_no_identity_hook_or_program_overrides_on_supported_commands(self):
        cases = [['commit', '--author=Other <other@invalid>', '-m', 'x'],
                 ['commit', '--date=now', '-m', 'x'], ['commit', '--reset-author', '-m', 'x'],
                 ['commit', '--no-verify', '-m', 'x'], ['commit', '-n', '-m', 'x'],
                 ['commit', '-C', 'HEAD'], ['commit', '-c', 'HEAD'], ['commit', '-F', '/tmp/message'],
                 ['commit', '-S', '-m', 'x'], ['commit', '--gpg-sign=key', '-m', 'x'],
                 ['fetch', '--upload-pack=evil', 'origin'], ['ls-remote', '--upload-pack', 'evil', 'origin'],
                 ['push', '--receive-pack=evil', 'origin'], ['push', '--exec=evil', 'origin'],
                 ['fetch', '--recurse-submodules', 'origin'], ['diff', '--ext-diff'],
                 ['diff', '--textconv'], ['log', '--show-signature'], ['log', '--format=evil'],
                 ['status', '-c', 'core.fsmonitor=evil']]
        for argv in cases:
            with self.subTest(argv=argv), self.assertRaises(GitPolicyError):
                parse_git('git', argv)

    def test_commit_and_cherry_pick_are_explicit_bounded_routes(self):
        for argv in (['commit', '--amend', '--no-edit'],
                     ['commit', '--amend', '-m', 'Replacement'],
                     ['commit', '-m', 'Subject', '-m', 'Body'],
                     ['cherry-pick', 'f' * 64], ['cherry-pick', '--continue'], ['cherry-pick', '--abort']):
            self.assertEqual(argv[0], parse_git('git', argv).command)
        for argv in (['commit'], ['commit', '--no-edit'], ['commit', '-m'],
                     ['commit', '-m', 'x', '--no-edit'], ['commit', '-m', 'x', '--', 'path'],
                     ['cherry-pick', 'HEAD'], ['cherry-pick', 'A' * 40],
                     ['cherry-pick', 'a' * 40, 'b' * 40], ['cherry-pick', '-n', 'a' * 40],
                     ['cherry-pick', '--continue', 'a' * 40], ['cherry-pick', '--abort', '--continue'],
                     ['cherry-pick', '--skip'], ['cherry-pick', '-m', '1', 'a' * 40]):
            with self.subTest(argv=argv), self.assertRaises(GitPolicyError):
                parse_git('git', argv)

    def test_remote_urls_refspecs_and_program_arguments_are_not_general_execution(self):
        for remote in ('origin', 'other-remote', 'git@github.com:other/repo.git',
                       'ssh://git@github.com/other/repo.git'):
            for command in ('fetch', 'ls-remote', 'push'):
                self.assertEqual(remote, parse_git('git', [command, remote]).args[0])
        for remote in ('https://github.com/x/y', 'file:///tmp/x', '/tmp/x', '../x', '.', '..',
                       'ext::evil', 'git://github.com/x/y', 'ssh://root@github.com/x/y.git',
                       'ssh://git@evil.invalid/x/y.git', 'git@github.com:x/y.git;evil'):
            with self.subTest(remote=remote), self.assertRaises(GitPolicyError):
                parse_git('git', ['fetch', remote])
        for argv in (['push', '--force', 'origin'], ['push', '--mirror', 'origin'],
                     ['push', '-u', 'origin', 'main'], ['push', '--set-upstream', 'origin', 'main'],
                     ['push', '--delete', 'origin', 'main'], ['push', 'origin', ':main'],
                     ['push', 'origin', '+HEAD:main'], ['fetch', 'origin', '^main'],
                     ['fetch', '--depth=0', 'origin'], ['fetch', '--depth=100001', 'origin'],
                     ['fetch', '--tags', '--no-tags', 'origin'], ['fetch', '--', 'origin']):
            with self.subTest(argv=argv), self.assertRaises(GitPolicyError):
                parse_git('git', argv)
        self.assertEqual('remote-read', parse_git('git', ['fetch', '--depth=2', 'origin',
            'refs/heads/*:refs/remotes/origin/*']).kind)

    def test_operand_relationships_and_path_boundaries(self):
        for argv in (['add'], ['rm'], ['restore'], ['mv', 'one'], ['mv', 'one', 'two', 'three'],
                     ['cat-file', 'HEAD'], ['cat-file', '-p', '-t', 'HEAD'],
                     ['merge-base', 'HEAD'], ['ls-tree'], ['branch', '--show-current', 'other'],
                     ['branch', '-d'], ['switch'], ['rev-parse'], ['rev-parse', '--git-dir', 'HEAD'],
                     ['add', '--', '../escape'], ['rm', '--', '/absolute'], ['add', '--', 'a//b'],
                     ['add', '--', 'a\\b'], ['status', '--'], ['log', '-n', '01'],
                     ['status', '--short', '--short'], ['switch', '-c', '--evil']):
            with self.subTest(argv=argv), self.assertRaises(GitPolicyError):
                parse_git('git', argv)
        self.assertEqual(('--', '-literal'), parse_git('git', ['add', '--', '-literal']).args)
        self.assertEqual(('.',), parse_git('git', ['add', '.']).args)
        self.assertEqual('help', parse_git('git', ['--help']).kind)
        self.assertEqual('help', parse_git('git', ['--version']).kind)

    def test_bad_argument_types_bounds_and_diagnostics_never_echo_secrets(self):
        for argv in (None, 'status', [1], ['status', ''], ['status', '\x00'], ['status', '\ud800'],
                     ['status', 'a' * 4097], ['status'] * 129, ['status', *(['a' * 4096] * 9)]):
            with self.subTest(argv=repr(argv)[:80]), self.assertRaises(GitPolicyError):
                parse_git('git', argv)
        secret = 'secret-should-not-appear'
        with self.assertRaises(GitPolicyError) as caught:
            parse_git('git', ['-c', 'credential.helper=' + secret, 'status'])
        self.assertNotIn(secret, str(caught.exception))


if __name__ == '__main__':
    unittest.main()
