import unittest

from uas.github_mutation_routes import (
    MAX_ARGUMENTS, MAX_BODY, MutationRouteError, _ROUTES, help_text,
    is_mutation_command, parse_mutation_route,
)
from uas.github_read import GitHubProject
from uas.ledger import LedgerError


class MutationRouteTests(unittest.TestCase):
    def setUp(self):
        self.project = GitHubProject('owner/repo')

    def parse(self, argv, **kwargs):
        return parse_mutation_route(argv, self.project, **kwargs)

    def denied(self, argv, code=None, **kwargs):
        with self.assertRaises(MutationRouteError) as caught:
            self.parse(argv, **kwargs)
        if code:
            self.assertEqual(code, caught.exception.code)
        diagnostic = caught.exception.diagnostic()
        self.assertEqual({'code', 'token_index', 'token', 'correction'}, set(diagnostic))
        self.assertIs(type(diagnostic['token_index']), int)
        self.assertTrue(diagnostic['correction'])
        return diagnostic

    def test_each_table_row_is_admitted_and_discovered(self):
        samples = {
            'issue-create': ['--title', 'A title', '--body', ''],
            'issue-edit': ['--title', 'A title'],
            'issue-close': [], 'issue-reopen': [],
            'issue-comment': ['--body', 'A comment'],
            'pr-create': ['--title', 'A title', '--body', '', '--head', 'feature/x', '--base', 'main'],
            'pr-edit': ['--base', 'main'], 'pr-close': [], 'pr-reopen': [],
            'pr-comment': ['--body', 'A comment'],
            'pr-reply': ['--comment-id', '11', '--body', 'A reply'],
            'pr-review': ['--approve', '--commit', 'a' * 40],
            'dependency-add': ['--blocked-by', '2'],
            'dependency-remove': ['--blocked-by', '2'],
        }
        self.assertEqual(set(samples), {row.kind for row in _ROUTES})
        for row in _ROUTES:
            argv = [*row.words, *(['1'] if row.numbered else []), *samples[row.kind]]
            with self.subTest(kind=row.kind):
                route = self.parse(argv)
                self.assertEqual(row.kind, route.kind)
                self.assertEqual('owner/repo', route.repository)
                self.assertIn('gh ' + ' '.join(row.words), help_text())
                self.assertTrue(is_mutation_command(argv))
                self.assertTrue(is_mutation_command(['gh', *argv]))
                self.assertEqual(route.document(), self.parse(['gh', *argv]).document())
        self.assertFalse(is_mutation_command(['api', 'repos/owner/repo/issues']))
        self.assertIn('gh issue comment NUMBER (--body TEXT | --body-file -)', help_text())

    def test_body_stdin_and_utf8_byte_bound(self):
        body = 'é' * (MAX_BODY // 2)
        self.assertEqual(body, self.parse(['issue', 'comment', '1', '--body', body]).options['body'])
        self.assertEqual(body, self.parse(['issue', 'comment', '1', '--body-file', '-'], body=body).options['body'])
        self.denied(['issue', 'comment', '1', '--body', body + 'a'], 'BODY_LIMIT')
        self.denied(['issue', 'comment', '1', '--body-file', '-'], body=body + 'a', code='BODY_LIMIT')
        for path in ['/tmp/secret', '../secret', 'body.md', '/dev/stdin']:
            self.denied(['issue', 'comment', '1', '--body-file', path], 'BODY_FILE_DENIED')
        self.denied(['issue', 'comment', '1', '--body-file', '-'], 'BODY_FILE_DENIED')
        self.denied(['issue', 'comment', '1', '--body', 'body'], 'UNUSED_STDIN', body='unused')
        for flags in [['--body', 'a', '--body-file', '-'], ['--body-file', '-', '--body', 'a']]:
            self.denied(['issue', 'comment', '1', *flags], 'CONFLICTING_OPTIONS', body='b')
        self.assertEqual('a\nb\t\r', self.parse(['issue', 'comment', '1', '--body', 'a\nb\t\r']).options['body'])

    def test_pinned_repository_correction_never_cross_target_rewrite(self):
        route = self.parse(['issue', 'close', '1', '-R', 'OWNER/REPO'])
        self.assertEqual('owner/repo', route.repository)
        self.assertEqual(('Repository spelling normalized to the Room Project.',), route.warnings)
        for repo in ['other/repo', 'github.com/owner/repo', 'https://github.com/owner/repo', 'owner/repo.git']:
            self.denied(['issue', 'close', '1', '--repo', repo], 'PROJECT_MISMATCH')
        self.denied(['issue', 'close', '1', '-R', 'owner/repo', '--repo', 'owner/repo'], 'DUPLICATE_OPTION')

    def test_self_assignment_only_and_harmless_duplicate_warning(self):
        route = self.parse(['issue', 'edit', '1', '--add-assignee', '@me,@me'])
        self.assertEqual(('@me',), route.options['add-assignee'])
        self.assertEqual(1, len(route.warnings))
        self.assertEqual(('@me',), self.parse(['issue', 'create', '--title', 't', '--body', '',
                                              '--assignee', '@me']).options['add-assignee'])
        for selector in ['someone', '@copilot', '@me,someone', '', '@me,']:
            self.denied(['issue', 'edit', '1', '--add-assignee', selector])
        self.denied(['issue', 'edit', '1', '--add-assignee', '@me', '--remove-assignee', '@me'], 'CONFLICTING_OPTIONS')

    def test_trusted_work_label_allowlist_and_hub_owned_namespace(self):
        self.denied(['issue', 'edit', '1', '--add-label', 'bug'], 'LABEL_AUTHORITY_DENIED')
        route = self.parse(['issue', 'edit', '1', '--add-label', 'bug,docs', '--add-label', 'bug'],
                           work_labels=('bug', 'docs'))
        self.assertEqual(('bug', 'docs'), route.options['add-label'])
        self.assertEqual(1, len(route.warnings))
        self.assertEqual(('bug',), self.parse(['issue', 'create', '--title', 't', '--body', '', '--label', 'bug'],
                                            work_labels=('bug',)).options['add-label'])
        for label in ['agent:claimed', 'AGENT:ready', 'run:completed', 'status:open', 'lifecycle:ready']:
            self.denied(['issue', 'edit', '1', '--add-label', label], 'LABEL_AUTHORITY_DENIED', work_labels=(label,))
        self.denied(['pr', 'edit', '1', '--add-label', 'bug', '--remove-label', 'bug'],
                    'CONFLICTING_OPTIONS', work_labels=('bug',))
        with self.assertRaises(LedgerError):
            self.parse(['issue', 'close', '1'], work_labels=['bug'])
        labels = tuple('label' + str(i) for i in range(21))
        self.denied(['issue', 'edit', '1', '--add-label', ','.join(labels[:11]),
                     '--remove-label', ','.join(labels[11:])], 'INPUT_LIMIT', work_labels=labels)

    def test_submitted_review_requires_exact_candidate_and_one_event(self):
        for flag, event in [('approve', 'APPROVE'), ('request-changes', 'REQUEST_CHANGES'), ('comment', 'COMMENT')]:
            for sha in ['a' * 40, 'b' * 64]:
                route = self.parse(['pr', 'review', '1', '--' + flag, '--commit', sha, '--body', 'review'])
                self.assertEqual(event, route.options['event'])
                self.assertEqual(sha, route.options['commit'])
                self.assertNotIn(flag, route.options)
        for flags in [[], ['--approve', '--comment'], ['--request-changes', '--comment']]:
            self.denied(['pr', 'review', '1', '--commit', 'a' * 40, *flags], 'REVIEW_EVENT_REQUIRED')
        for sha in ['A' * 40, 'a' * 7, 'main', 'a' * 41]:
            self.denied(['pr', 'review', '1', '--approve', '--commit', sha], 'INVALID_SELECTOR')
        self.denied(['pr', 'review', '1', '--approve'], 'MISSING_FIELD')
        self.denied(['pr', 'review', '1', '--comment', '--commit', 'a' * 40], 'MISSING_FIELD')

    def test_dependency_number_validation_and_no_self_or_parent(self):
        route = self.parse(['issue', 'dependency', 'add', '12', '--blocked-by', '34'])
        self.assertEqual((12, 34), (route.number, route.options['blocked-by']))
        self.denied(['issue', 'dependency', 'add', '12', '--blocked-by', '12'], 'SELF_DEPENDENCY')
        for number in ['0', '-1', '01', str(2**63), 'https://github.com/owner/repo/issues/1']:
            self.denied(['issue', 'dependency', 'remove', '1', '--blocked-by', number], 'INVALID_SELECTOR')
        self.denied(['issue', 'dependency', 'add', '1', '--parent', '2'], 'UNSUPPORTED_ROUTE')

    def test_admin_attachments_native_escape_and_unsafe_branch_denied(self):
        for argv in [['pr', 'merge', '1'], ['label', 'create', 'bug'], ['repo', 'edit'],
                     ['api', 'repos/owner/repo/issues'], ['workflow', 'run', 'ci'],
                     ['issue', 'comment', '1', '--attach', '/tmp/file'],
                     ['issue', 'edit', '1', '--web'], ['pr', 'close', '1', '--delete-branch'],
                     ['pr', 'review', '1', '--dismiss'], ['issue', 'close', '1', '--hostname', 'elsewhere']]:
            self.denied(argv, 'UNSUPPORTED_ROUTE')
        for branch in ['other:branch', '-exec', '../main', 'a//b', 'a.lock', 'a/.b', 'a b', 'a@{1}', 'a\\b']:
            self.denied(['pr', 'edit', '1', '--base', branch], 'INVALID_SELECTOR')
        self.denied(['pr', 'create', '--title', 't', '--body', '', '--base', 'main', '--head', 'main'], 'INVALID_SELECTOR')

    def test_errors_do_not_echo_secret_body_argv_or_paths(self):
        secret = 'SUPER-SECRET-TOKEN'
        for argv in [['issue', 'comment', '1', '--body-file', '/tmp/' + secret],
                     ['issue', 'edit', '1', '--' + secret],
                     ['issue', 'edit', '1', '--add-assignee', secret],
                     ['issue', 'comment', '1', '--body', secret + '\x00']]:
            diagnostic = self.denied(argv)
            self.assertNotIn(secret, str(diagnostic))
        diagnostic = self.denied(['gh', 'issue', 'edit', '1', '--add-assignee', secret])
        self.assertEqual((5, '--add-assignee'), (diagnostic['token_index'], diagnostic['token']))

    def test_limits_empty_values_duplicates_and_immutable_route(self):
        self.denied(['issue', 'close', '1', *['x'] * MAX_ARGUMENTS], 'INPUT_LIMIT')
        self.denied(['issue', 'edit', '1'], 'MISSING_FIELD')
        self.denied(['issue', 'edit', '1', '--title', 'x' * 257], 'INPUT_LIMIT')
        self.denied(['issue', 'edit', '1', '--title', 'x', '--title', 'y'], 'DUPLICATE_OPTION')
        self.denied(['issue', 'edit', '1', '--title'], 'MISSING_VALUE')
        self.denied(['issue', 'edit', '1', '--title', '\ud800'], 'INVALID_MUTATION_INPUT')
        self.denied(['issue', 'edit', '1', '--title', 'a\nb'], 'INVALID_MUTATION_INPUT')
        self.denied(['issue', 'comment', '1', '--body', ' \n'], 'MISSING_FIELD')
        route = self.parse(['issue', 'close', '1'])
        with self.assertRaises(TypeError): route.options['reason'] = 'other'
        self.assertEqual('completed', route.options['reason'])


if __name__ == '__main__':
    unittest.main()
