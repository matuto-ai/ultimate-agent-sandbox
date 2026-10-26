import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from uas.github_read import (GitHubProject, GitHubReadProvider, GhTransport, ProviderFailure,
                             ProviderResponse, generated_help, parse_route, validate_observation, validate_route_table)
from uas.ledger import LedgerError


def issue(number=42, **changes):
    return {"id": number + 1000, "number": number, "state": "open",
            "repository_url": "https://api.github.com/repos/owner/project",
            "url": f"https://api.github.com/repos/owner/project/issues/{number}",
            "assignees": [{"id": 7, "login": "worker"}], **changes}


def response(value, status=200, headers=None):
    return ProviderResponse(status, json.dumps(value).encode(), headers or {})


class ReadProviderTests(unittest.TestCase):
    def setUp(self):
        self.project = GitHubProject("owner/project")
        self.calls = []

    def provider(self, responses, **kwargs):
        def transport(path):
            self.calls.append(path)
            result = responses.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        return GitHubReadProvider(self.project, transport, **kwargs)

    def test_generated_routes_and_rejected_surface(self):
        self.assertIn("gh issue view NUMBER", generated_help())
        self.assertEqual(parse_route(["gh", "issue", "view", "42", "--repo", "owner/project"], self.project).issue_number, 42)
        self.assertEqual(parse_route(["issue", "view", "42", "-R", "owner/project"], self.project).kind, "issue-view")
        self.assertEqual(parse_route(["gh", "--help"], self.project).kind, "help")
        for args in (["api", "user"], ["issue", "edit", "42"], ["pr", "merge", "42"],
                     ["issue", "view", "../42"], ["issue", "view", "https://github.com/owner/project/issues/42"],
                     ["issue", "view", "42", "--repo", "other/project"],
                     ["issue", "view", "42", "--hostname", "evil.example"],
                     ["issue", "view", "42", "--json", "body"], ["auth", "token"]):
            with self.subTest(args=args), self.assertRaises(LedgerError):
                parse_route(args, self.project)
        self.assertEqual(self.calls, [])

    def test_route_table_startup_rejects_ambiguous_or_missing_signatures(self):
        valid = (("help", ("--help",), "gh --help"),
                 ("issue-view", ("issue", "view"), "gh issue view NUMBER [--repo OWNER/REPO]"))
        self.assertEqual(validate_route_table(valid), valid)
        for rows in ((), valid + (valid[0],), (valid[0],),
                     (valid[0], ("issue-view", ("--help",), "gh --help")),
                     (valid[0], ("issue-view", ("issue", "view"), "wrong help")),
                     (valid[0], ("api", ("api",), "gh api"))):
            with self.assertRaises(LedgerError):
                validate_route_table(rows)

    def test_complete_sanitized_issue_and_dependencies(self):
        result = self.provider([response(issue(body="secret", title="secret")), response([issue(3, body="secret")])]).read_issue(42)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["completeness"], "complete")
        self.assertEqual(result["dependencies"], [{"id": 1003, "number": 3, "state": "open"}])
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(validate_observation(result), result)
        self.assertEqual(self.calls, ["repos/owner/project/issues/42", "repos/owner/project/issues/42/dependencies/blocked_by?per_page=100&page=1"])

    def test_full_page_needs_terminal_page(self):
        rows = [issue(n) for n in range(100, 200)]
        result = self.provider([response(issue()), response(rows), response([])]).read_issue(42)
        self.assertEqual((result["completeness"], result["pages"]), ("complete", 2))
        self.assertTrue(self.calls[-1].endswith("page=2"))

    def test_pagination_limit_cannot_establish_absence(self):
        result = self.provider([response(issue()), response([issue(n) for n in range(100, 200)])], max_pages=1).read_issue(42)
        self.assertEqual((result["status"], result["completeness"]), ("PAGINATION_LIMIT", "incomplete"))

    def test_next_link_is_not_followed_or_ignored_as_complete(self):
        result = self.provider([response(issue()), response([], headers={"Link": '<https://evil.example/private>; rel="next"'})], max_pages=1).read_issue(42)
        self.assertEqual(result["completeness"], "incomplete")
        self.assertTrue(all("evil" not in path for path in self.calls))

    def test_failure_after_first_page_stays_incomplete(self):
        result = self.provider([response(issue()), response([issue(n) for n in range(100, 200)]), ProviderFailure("TIMEOUT")]).read_issue(42)
        self.assertEqual((result["status"], result["completeness"]), ("TIMEOUT", "incomplete"))
        self.assertEqual(len(result["dependencies"]), 100)
        validate_observation(result)

    def test_not_found_is_not_proof_of_absence(self):
        result = self.provider([response({"message": "secret"}, 404)]).read_issue(42)
        self.assertEqual((result["status"], result["completeness"]), ("NOT_FOUND", "unknown"))
        validate_observation(result)
        self.assertEqual(len(self.calls), 1)

    def test_permission_rate_limit_and_dependency_404_are_not_not_found(self):
        for status in (401, 403, 429, 500, 302):
            result = self.provider([response({}, status)]).read_issue(42)
            self.assertEqual((result["status"], result["completeness"]), ("PROVIDER_ERROR", "unknown"))
        result = self.provider([response(issue()), response({}, 404)]).read_issue(42)
        self.assertEqual((result["status"], result["completeness"]), ("PROVIDER_ERROR", "incomplete"))

    def test_exception_text_never_returned(self):
        result = self.provider([RuntimeError("token=SECRET")]).read_issue(42)
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(result["completeness"], "unknown")

    def test_invalid_issue_identity_and_assignments(self):
        changes = [{"repository_url": "https://api.github.com/repos/other/project"}, {"number": 43},
                   {"url": "https://evil.example/issues/42"}, {"pull_request": {}}, {"id": True},
                   {"assignees": None}, {"assignees": [{"id": 7, "login": "bad/token"}]},
                   {"assignees": [{"id": 7, "login": "worker"}] * 2}]
        for change in changes:
            result = self.provider([response(issue(**change))]).read_issue(42)
            self.assertEqual((result["status"], result["completeness"]), ("INVALID_RESPONSE", "unknown"))

    def test_self_duplicate_cross_project_and_pr_dependencies(self):
        for deps in ([issue()], [issue(2), issue(2)], [issue(2, repository_url="https://api.github.com/repos/other/project")], [issue(2, pull_request={})]):
            result = self.provider([response(issue()), response(deps)]).read_issue(42)
            self.assertEqual((result["status"], result["completeness"]), ("INVALID_RESPONSE", "incomplete"))

    def test_output_limit_and_duplicate_json(self):
        result = self.provider([response(issue())], max_bytes=10).read_issue(42)
        self.assertEqual((result["status"], result["completeness"]), ("OUTPUT_LIMIT", "unknown"))
        result = self.provider([ProviderResponse(200, b'{"id":1,"id":2}', {})]).read_issue(42)
        self.assertEqual(result["status"], "INVALID_RESPONSE")

    def test_independent_observation_boundary_rejects_extra_or_false_success(self):
        result = self.provider([response(issue()), response([])]).read_issue(42)
        for changed in ({**result, "raw": "secret"}, {**result, "status": "TIMEOUT"},
                        {**result, "issue": None}, {**result, "pages": True},
                        {**result, "dependencies": [{"id": 7, "number": 3, "state": "open", "body": "secret"}]}):
            with self.assertRaises(LedgerError):
                validate_observation(changed)

    def test_project_and_issue_inputs_are_strict(self):
        for name in ("owner/../project", "../project", "owner/%2f", "owner/project?x", "https://github.com/owner/project"):
            with self.assertRaises(LedgerError):
                GitHubProject(name)
        provider = self.provider([])
        for number in (True, 0, -1, "42", 10000000000):
            with self.assertRaises(LedgerError):
                provider.read_issue(number)
        self.assertEqual(self.calls, [])


class GhExecutorTests(unittest.TestCase):
    def executable(self, root, content):
        path = Path(root) / "gh"
        path.write_text("#!/usr/bin/python3\n" + content)
        path.chmod(0o700)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_fixed_argv_clean_env_and_external_actor_selection(self):
        with tempfile.TemporaryDirectory() as root:
            executable, digest = self.executable(root, '''import os,sys
assert os.environ['GH_TOKEN'] == 'fixture-secret'
assert 'PATH' not in os.environ and 'GITHUB_TOKEN' not in os.environ
assert sys.argv[1:7] == ['api','--hostname','github.com','--method','GET','--include']
assert os.getcwd() == os.environ['HOME']
print('HTTP/2.0 200 OK\\nContent-Type: application/json\\n\\n[]')
''')
            selected = []
            def credentials(actor, host):
                selected.append((actor, host))
                return {"GH_TOKEN": "fixture-secret"}
            result = GhTransport(executable, digest, "actor-one", credentials)("repos/owner/project/issues/42")
            self.assertEqual(selected, [("actor-one", "github.com")])
            self.assertEqual((result.status, json.loads(result.body)), (200, []))

    def test_timeout_output_and_invalid_route_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            executable, digest = self.executable(root, "import time\ntime.sleep(1)\n")
            transport = GhTransport(executable, digest, "actor", lambda *_: {"GH_TOKEN": "fixture"}, timeout=0.05)
            with self.assertRaises(ProviderFailure) as error:
                transport("repos/owner/project/issues/42")
            self.assertEqual(error.exception.code, "TIMEOUT")
            with self.assertRaises(ProviderFailure):
                transport("https://evil.example")
            executable, digest = self.executable(root, "print('X' * 1100000)\n")
            transport = GhTransport(executable, digest, "actor", lambda *_: {"GH_TOKEN": "fixture"})
            with self.assertRaises(ProviderFailure) as error:
                transport("repos/owner/project/issues/42")
            self.assertEqual(error.exception.code, "OUTPUT_LIMIT")

    def test_changed_pin_and_missing_credentials_fail_before_process(self):
        with tempfile.TemporaryDirectory() as root:
            executable, digest = self.executable(root, "raise RuntimeError('must not run')\n")
            transport = GhTransport(executable, digest, "actor", lambda *_: {})
            with self.assertRaises(ProviderFailure) as error:
                transport("repos/owner/project/issues/42")
            self.assertEqual(error.exception.code, "CREDENTIAL_UNAVAILABLE")
            executable.write_text("changed")
            with self.assertRaises(ProviderFailure) as error:
                transport("repos/owner/project/issues/42")
            self.assertEqual(error.exception.code, "PROVIDER_ERROR")
