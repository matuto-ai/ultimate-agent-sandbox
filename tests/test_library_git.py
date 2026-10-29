"""Library canonical Git publication: lease, fast-forward, reconciliation, recovery.

These checks exercise the real seam against a disposable bare Git target: one
host-local writer, fast-forward-only publication, metadata-only commit identity,
refusal of a stale complete result, exactly-once replay, reconciliation of a
lost or uncertain push before retry, clone reconstruction from canonical Git
plus operational records, selected-draft removal, and refusal to switch
target/branch or to lose canonical work.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

import library_support as support
from uas import library, library_bundle
from uas.library import LibraryError
from uas.library_git import CLONE_DIR, LibraryGit
from uas.library_records import LibraryRecords

ROOT = Path(__file__).resolve().parents[1]
WORKER = Path(__file__).parent / "fixtures" / "library_git_worker.py"
BRANCH = "main"
INITIAL_LOG = ("# Update log\n\n## 2026-10-01\n"
               "* **Initialization**: Created the Project bundle.\n")
NEW_LOG = ("# Update log\n\n## 2026-10-20\n"
           "* **Creation**: Added [Pick SQLite](context/pick-sqlite.md).\n\n"
           "## 2026-10-01\n* **Initialization**: Created the Project bundle.\n")
CONTEXT_INDEX = "# Context\n\n* [Pick SQLite](/context/pick-sqlite.md) - short.\n"
_GIT_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@invalid",
            "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@invalid"}


def git(directory, *args, data=None):
    result = subprocess.run(["git", "-C", str(directory), *args], env=dict(_GIT_ENV),
                            input=data, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise AssertionError((args, result.returncode, result.stderr))
    return result.stdout.decode("utf-8")


def root_index(path, identity):
    return ("---\nokf_version: \"0.2\"\n---\n\n# Project Library\n\n"
            "Source coordinates: %s\nSource identity: %s\n\n"
            "* [Context](context/index.md)\n* [Decisions](decisions/index.md)\n"
            "* [Research](research/index.md)\n* [Pending](pending/index.md)\n"
            % (path, identity))


def concept(type_, title, status=None):
    lines = ["---", "type: " + type_, 'title: "%s"' % title]
    if status is not None:
        lines.append("status: " + status)
    return "\n".join(lines + ["---", "", "# Body", "", "Text.", ""])


class Interrupted(LibraryGit):
    """Fault injection at the Git boundary: a push lands but its outcome is lost."""

    def __init__(self, *args, lose_push=False, remote_limit=None, **options):
        super().__init__(*args, **options)
        self.lose_push = lose_push
        self.remote_limit = remote_limit
        self.remotes = 0

    def _git(self, *args, **options):
        if args and args[0] == "ls-remote":
            self.remotes += 1
            if self.remote_limit is not None and self.remotes > self.remote_limit:
                return 1, b"", b"lost"
        code, out, error = super()._git(*args, **options)
        if args and args[0] == "push" and self.lose_push:
            self.lose_push = False
            return 1, b"", b"lost"
        return code, out, error


class LibraryGitTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.root = self.base / "service"
        self.target = self.base / "canonical.git"
        git(self.base, "init", "--bare", "--quiet", str(self.target))
        git(self.target, "config", "receive.denyNonFastForwards", "true")
        git(self.target, "config", "receive.denyDeletes", "true")
        self.records_path = self.base / "records.sqlite3"
        LibraryRecords(self.records_path, "deployment-1").close()
        self.settings = support.settings()

    # --- fixtures ---------------------------------------------------------

    def scope(self, project_id="alpha", repository="acme/alpha", source="1001"):
        return library.participant_scope(
            support.ORIGIN, binding=support.binding(project_id, repository, source))

    def operation(self, project_id="alpha", repository="acme/alpha", source="1001",
                  operation_id="op-1", request_id="request-1"):
        return support.capture(target=support.binding(project_id, repository, source),
                               operation_id=operation_id, request_id=request_id)

    def skeleton(self, scope):
        prefix = "projects/" + scope.project_path
        files = {
            "index.md": root_index(scope.project_path, scope.project_identity),
            "log.md": INITIAL_LOG,
            "context/index.md": "# Context\n",
            "decisions/index.md": "# Decisions\n",
            "research/index.md": "# Research\n",
            "pending/index.md": "# Pending\n",
        }
        return prefix, {prefix + "/" + name: text.encode("utf-8")
                        for name, text in files.items()}

    def initial(self, scope=None):
        scope = scope or self.scope()
        _, files = self.skeleton(scope)
        return library_bundle.validate(scope, self.settings,
                                       proposed=library_bundle.Tree(files=files))

    def update(self, scope=None, current=None):
        scope = scope or self.scope()
        current = current or self.initial(scope)
        prefix = current.prefix
        files = dict(current.files)
        files[prefix + "/context/pick-sqlite.md"] = concept("context", "Pick SQLite").encode()
        files[prefix + "/context/index.md"] = CONTEXT_INDEX.encode()
        files[prefix + "/log.md"] = NEW_LOG.encode()
        return library_bundle.validate(scope, self.settings,
                                       current=library_bundle.Tree(files=dict(current.files)),
                                       proposed=library_bundle.Tree(files=files))

    def drafted(self, scope=None):
        """An update carrying one pending draft, and the bundle that removes it."""
        scope = scope or self.scope()
        operation = self.operation(operation_id="op-draft", request_id="request-draft")
        prefix, current = self.skeleton(scope)
        relative = "pending/" + operation.queue_id + ".md"
        files = dict(current)
        files[prefix + "/" + relative] = concept("decision", "Pick SQLite", "draft").encode()
        files[prefix + "/pending/index.md"] = (
            "# Pending\n\n* [Pick SQLite](/%s) - DRAFT.\n" % relative).encode()
        published = library_bundle.validate(
            scope, self.settings, current=library_bundle.Tree(files=current),
            proposed=library_bundle.Tree(files=files))
        removed = dict(current)
        return operation, published, removed, relative

    def publisher(self, root=None, records_path=None, deployment_id="deployment-1",
                  target=None, branch=BRANCH, **options):
        return LibraryGit(root or self.root, records_path=records_path or self.records_path,
                          deployment_id=deployment_id, target=target or str(self.target),
                          branch=branch, **options)

    def started(self, **options):
        publisher = self.publisher(**options)
        recovery = publisher.startup()
        self.addCleanup(publisher.close)
        return publisher, recovery

    def service(self, name):
        root = self.base / name
        root.mkdir()
        path = root / "records.sqlite3"
        LibraryRecords(path, "deployment-" + name).close()
        return {"root": root, "records_path": path, "deployment_id": "deployment-" + name}

    def refusing_target(self):
        """A readable target that refuses an update to its checked-out branch."""
        shutil.rmtree(self.target)
        git(self.base, "init", "--quiet", "--initial-branch=" + BRANCH, str(self.target))
        (self.target / "seed.md").write_text("seed\n")
        git(self.target, "add", "seed.md")
        git(self.target, "commit", "--quiet", "-m", "seed")
        return git(self.target, "rev-parse", "HEAD").strip()

    def canonical_head(self):
        return git(self.target, "rev-parse", "refs/heads/" + BRANCH).strip()

    def commits(self):
        return len(git(self.target, "rev-list", "refs/heads/" + BRANCH).split())

    def names(self, commit=None):
        return git(self.target, "ls-tree", "-r", "--name-only",
                   commit or "refs/heads/" + BRANCH).splitlines()

    def project_prefix(self):
        return "projects/" + self.scope().project_path

    # --- one writer -------------------------------------------------------

    def test_one_writer_holds_the_host_lease_before_any_clone_work(self):
        publisher, recovery = self.started()
        self.assertIsNone(recovery.head_sha)
        clone = self.root / CLONE_DIR
        self.assertTrue(clone.is_dir())
        shutil.rmtree(clone)
        second = self.publisher()
        with self.assertRaises(LibraryError) as raised:
            second.startup()
        self.assertEqual("LEASE_BUSY", raised.exception.code)
        self.assertFalse(clone.exists(), "a refused instance did no clone work")
        second.close()
        worker = subprocess.run([sys.executable, str(WORKER), str(self.root),
                                 str(self.records_path), str(self.target), BRANCH],
                                capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        self.assertEqual({"error": "LEASE_BUSY"}, json.loads(worker.stdout))
        self.assertFalse(clone.exists())

    # --- fast-forward publication ----------------------------------------

    def test_publishes_one_fast_forward_commit_with_distinct_identities(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        self.assertTrue(first.created)
        self.assertIsNone(first.input_sha)
        self.assertIsNone(first.previous_sha)
        self.assertEqual(first.resulting_sha, self.canonical_head())
        operation = self.operation(operation_id="op-2", request_id="request-2")
        second = publisher.publish(operation, self.update(), input_sha=first.resulting_sha)
        self.assertTrue(second.created)
        self.assertEqual(first.resulting_sha, second.input_sha)
        self.assertEqual(first.resulting_sha, second.previous_sha)
        self.assertEqual(second.resulting_sha, self.canonical_head())
        history = git(self.target, "log", "--format=%H %P", "refs/heads/" + BRANCH).splitlines()
        self.assertEqual(2, len(history))
        self.assertEqual(second.resulting_sha + " " + first.resulting_sha, history[0])
        prefix = self.project_prefix()
        names = self.names(second.resulting_sha)
        self.assertIn(prefix + "/index.md", names)
        self.assertIn(prefix + "/context/pick-sqlite.md", names)
        message = git(self.target, "show", "-s", "--format=%B", second.resulting_sha)
        self.assertIn("Library-Operation: op-2", message)
        self.assertIn("Library-Queue: " + operation.queue_id, message)
        self.assertNotIn("Pick SQLite", message, "commit metadata carries no content")

    def test_serializes_concurrent_publications_without_lost_updates(self):
        publisher, _ = self.started()
        work = []
        for index in range(5):
            name = "p%d" % index
            scope = self.scope(name, "acme/" + name, str(4000 + index))
            work.append((self.operation(name, "acme/" + name, str(4000 + index),
                                        operation_id="op-" + name,
                                        request_id="request-" + name),
                         self.initial(scope)))
        results, errors = [], []

        def publish(operation, bundle):
            try:
                results.append(publisher.publish(operation, bundle, input_sha=None))
            except BaseException as error:  # surfaced by the assertion below
                errors.append(error)

        threads = [threading.Thread(target=publish, args=item) for item in work]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual([], errors)
        self.assertEqual(5, len(results))
        self.assertEqual(5, self.commits())
        self.assertTrue(all(result.created for result in results))
        history = [line.split() for line in
                   git(self.target, "log", "--format=%H %P", "refs/heads/" + BRANCH).splitlines()]
        self.assertEqual(5, len(history))
        self.assertEqual(1, len(history[-1]), "the first publication is the root commit")
        self.assertEqual([item[0] for item in history[1:]],
                         [item[1] for item in history[:-1]])
        self.assertEqual({item[0] for item in history},
                         {result.resulting_sha for result in results})

    # --- stale complete results ------------------------------------------

    def test_refuses_a_stale_complete_result_instead_of_reverting_newer_content(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        second = publisher.publish(self.operation(operation_id="op-2",
                                                  request_id="request-2"),
                                   self.update(), input_sha=first.resulting_sha)
        with self.assertRaises(LibraryError) as raised:
            publisher.publish(self.operation(operation_id="op-3", request_id="request-3"),
                              self.initial(), input_sha=first.resulting_sha)
        self.assertEqual("INCOMPATIBLE_HEAD", raised.exception.code)
        self.assertEqual(second.resulting_sha, self.canonical_head())
        self.assertEqual(2, self.commits())
        self.assertIn(self.project_prefix() + "/context/pick-sqlite.md",
                      self.names(second.resulting_sha))

    def test_refuses_a_stale_replay_of_a_no_op_instead_of_reverting(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        no_op = self.operation(operation_id="op-noop", request_id="request-noop")
        unchanged = publisher.publish(no_op, self.initial(), input_sha=first.resulting_sha)
        self.assertFalse(unchanged.created)
        self.assertEqual(first.resulting_sha, unchanged.resulting_sha)
        replayed = publisher.publish(no_op, self.initial(), input_sha=first.resulting_sha)
        self.assertFalse(replayed.created, "a truthful no-op replays without a commit")
        self.assertEqual(first.resulting_sha, replayed.resulting_sha)
        self.assertEqual(1, self.commits())
        second = publisher.publish(self.operation(operation_id="op-2",
                                                  request_id="request-2"),
                                   self.update(), input_sha=first.resulting_sha)
        with self.assertRaises(LibraryError) as raised:
            publisher.publish(no_op, self.initial(), input_sha=first.resulting_sha)
        self.assertEqual("INCOMPATIBLE_HEAD", raised.exception.code)
        self.assertEqual(second.resulting_sha, self.canonical_head())
        self.assertEqual(2, self.commits())
        self.assertIn(self.project_prefix() + "/context/pick-sqlite.md",
                      self.names(second.resulting_sha))

    # --- exactly once -----------------------------------------------------

    def test_lost_acknowledgement_is_recovered_without_a_second_commit(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        publisher.close()
        restarted, recovery = self.started()
        self.assertEqual(("op-1",), tuple(item.operation_id for item in recovery.settled))
        self.assertEqual(first.resulting_sha, recovery.settled[0].resulting_sha)
        self.assertEqual((), recovery.absent)
        self.assertEqual(first.resulting_sha, recovery.head_sha)
        again = restarted.publish(self.operation(), self.initial(), input_sha=None)
        self.assertFalse(again.created)
        self.assertEqual(first.resulting_sha, again.resulting_sha)
        self.assertEqual(1, self.commits())

    def test_retry_of_the_same_draft_publishes_it_once(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        retried = library.retry(self.scope(), self.settings, self.operation(),
                                operation_id="op-1-retry",
                                at="2026-10-29T09:00:00+00:00")
        self.assertNotEqual(self.operation().operation_id, retried.operation_id)
        again = publisher.publish(retried, self.initial(), input_sha=None)
        self.assertFalse(again.created)
        self.assertEqual(first.resulting_sha, again.resulting_sha)
        self.assertEqual(1, self.commits())

    # --- reconciliation and failure ---------------------------------------

    def test_rejected_push_is_reconciled_before_retry(self):
        seed = self.refusing_target()
        publisher, recovery = self.started()
        self.assertEqual(seed, recovery.head_sha)
        with self.assertRaises(LibraryError) as raised:
            publisher.publish(self.operation(), self.initial(), input_sha=None)
        self.assertEqual("PUBLICATION_REJECTED", raised.exception.code)
        self.assertEqual(seed, self.canonical_head())
        self.assertEqual(1, self.commits())
        with LibraryRecords(self.records_path, "deployment-1") as records:
            record = records.record("op-1",
                                    project_identity=self.scope().project_identity)
        self.assertEqual("PENDING", record["state"], "identity precedes publication")
        git(self.target, "checkout", "--quiet", "-b", "published")
        published = publisher.publish(self.operation(), self.initial(), input_sha=None)
        self.assertTrue(published.created)
        self.assertEqual(seed, published.previous_sha)
        self.assertEqual(published.resulting_sha, self.canonical_head())
        self.assertEqual(2, self.commits())

    def test_a_push_that_lands_but_reports_failure_returns_its_committed_result(self):
        publisher = Interrupted(self.root, records_path=self.records_path,
                                deployment_id="deployment-1", target=str(self.target),
                                branch=BRANCH, lose_push=True)
        publisher.startup()
        self.addCleanup(publisher.close)
        published = publisher.publish(self.operation(), self.initial(), input_sha=None)
        self.assertFalse(published.created, "the committed result was recovered")
        self.assertEqual(published.resulting_sha, self.canonical_head())
        self.assertEqual(1, self.commits())
        self.assertIn(self.project_prefix() + "/index.md",
                      self.names(published.resulting_sha))

    def test_an_unreported_push_with_unavailable_reconciliation_recovers(self):
        publisher = Interrupted(self.root, records_path=self.records_path,
                                deployment_id="deployment-1", target=str(self.target),
                                branch=BRANCH, lose_push=True)
        publisher.startup()
        self.addCleanup(publisher.close)
        publisher.remote_limit = 2  # the pre-push read succeeds, reconciliation cannot
        with self.assertRaises(LibraryError) as raised:
            publisher.publish(self.operation(), self.initial(), input_sha=None)
        self.assertEqual("PUBLICATION_UNCERTAIN", raised.exception.code)
        self.assertEqual(1, self.commits(), "the push did land; nothing claimed success")
        with LibraryRecords(self.records_path, "deployment-1") as records:
            record = records.record("op-1",
                                    project_identity=self.scope().project_identity)
        self.assertEqual("PENDING", record["state"])
        publisher.close()
        restarted, recovery = self.started()
        self.assertEqual(("op-1",), tuple(item.operation_id for item in recovery.settled))
        self.assertEqual(1, self.commits())
        again = restarted.publish(self.operation(), self.initial(), input_sha=None)
        self.assertFalse(again.created)
        self.assertEqual(1, self.commits())

    def test_unreachable_target_blocks_publication_instead_of_duplicating(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        bundle = self.update()
        operation = self.operation(operation_id="op-2", request_id="request-2")
        moved = self.base / "moved.git"
        self.target.rename(moved)
        try:
            with self.assertRaises(LibraryError) as raised:
                publisher.publish(operation, bundle, input_sha=first.resulting_sha)
            self.assertEqual("PUBLICATION_UNAVAILABLE", raised.exception.code)
        finally:
            moved.rename(self.target)
        self.assertEqual(first.resulting_sha, self.canonical_head())
        self.assertEqual(1, self.commits())
        second = publisher.publish(operation, bundle, input_sha=first.resulting_sha)
        self.assertTrue(second.created)
        self.assertEqual(first.resulting_sha, second.previous_sha)
        self.assertEqual(2, self.commits())

    def test_rejects_incompatible_head_without_losing_canonical_work(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        clone = self.root / CLONE_DIR
        tree = git(clone, "rev-parse", first.resulting_sha + "^{tree}").strip()
        foreign = git(clone, "commit-tree", tree, data=b"foreign\n").strip()
        with self.assertRaises(LibraryError) as raised:
            publisher.publish(self.operation(operation_id="op-2", request_id="request-2"),
                              self.update(), input_sha=foreign)
        self.assertEqual("INCOMPATIBLE_HEAD", raised.exception.code)
        self.assertEqual(first.resulting_sha, self.canonical_head())
        self.assertEqual(1, self.commits())
        self.assertNotIn(self.project_prefix() + "/context/pick-sqlite.md",
                         self.names(first.resulting_sha))

    def test_second_writer_builds_on_the_latest_canonical_head(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        other, recovery = self.started(**self.service("other"))
        self.assertEqual(first.resulting_sha, recovery.head_sha)
        second = publisher.publish(self.operation(operation_id="op-2",
                                                  request_id="request-2"),
                                   self.update(), input_sha=first.resulting_sha)
        bundle = self.initial(self.scope("beta", "acme/beta", "2002"))
        operation = self.operation("beta", "acme/beta", "2002",
                                   operation_id="op-beta", request_id="request-beta")
        published = other.publish(operation, bundle, input_sha=None)
        self.assertTrue(published.created)
        self.assertEqual(second.resulting_sha, published.previous_sha)
        self.assertEqual(3, self.commits())
        names = self.names(published.resulting_sha)
        self.assertIn("projects/github.com/acme/beta/index.md", names)
        self.assertIn("projects/github.com/acme/alpha/context/pick-sqlite.md", names)

    # --- selected draft removal -------------------------------------------

    def test_removes_a_selected_pending_draft_from_a_bare_clone(self):
        publisher, _ = self.started()
        base = publisher.publish(self.operation(), self.initial(), input_sha=None)
        operation, published_bundle, removed_bundle, relative = self.drafted()
        first = publisher.publish(operation, published_bundle, input_sha=base.resulting_sha)
        self.assertTrue(first.created)
        self.assertIn(self.project_prefix() + "/" + relative, self.names())
        removal = library_bundle.validate(
            self.scope(), self.settings,
            current=library_bundle.Tree(files=dict(published_bundle.files)),
            proposed=library_bundle.Tree(files=removed_bundle),
            selected=(operation.queue_id,))
        self.assertEqual((relative,), removal.removed)
        second = publisher.publish(self.operation(operation_id="op-remove",
                                                  request_id="request-remove"),
                                   removal, input_sha=first.resulting_sha)
        self.assertTrue(second.created)
        self.assertEqual(first.resulting_sha, second.previous_sha)
        names = self.names()
        self.assertNotIn(self.project_prefix() + "/" + relative, names)
        self.assertIn(self.project_prefix() + "/pending/index.md", names)
        self.assertEqual(3, self.commits())

    # --- recovery ---------------------------------------------------------

    def test_clone_loss_reconstructs_from_canonical_git_and_records(self):
        publisher, _ = self.started()
        first = publisher.publish(self.operation(), self.initial(), input_sha=None)
        publisher.close()
        shutil.rmtree(self.root / CLONE_DIR)
        restarted, recovery = self.started()
        self.assertEqual(first.resulting_sha, recovery.head_sha)
        self.assertIn("op-1", [item.operation_id for item in recovery.settled])
        self.assertIn(self.project_prefix() + "/index.md",
                      self.names(first.resulting_sha))
        again = restarted.publish(self.operation(), self.initial(), input_sha=None)
        self.assertFalse(again.created)
        self.assertEqual(first.resulting_sha, again.resulting_sha)
        second = restarted.publish(self.operation(operation_id="op-2",
                                                  request_id="request-2"),
                                   self.update(), input_sha=first.resulting_sha)
        self.assertEqual(first.resulting_sha, second.previous_sha)
        self.assertEqual(2, self.commits())

    def test_local_only_state_is_never_reported_as_published(self):
        publisher, _ = self.started()
        pending = self.operation(operation_id="op-pending", request_id="request-pending")
        with LibraryRecords(self.records_path, "deployment-1") as records:
            records.begin(pending)
        publisher.close()
        clone = self.root / CLONE_DIR
        empty = git(clone, "mktree", data=b"").strip()
        git(clone, "commit-tree", empty, data=b"local only\n")
        restarted, recovery = self.started()
        self.assertEqual((), recovery.settled)
        self.assertEqual(("op-pending",), recovery.absent)
        self.assertIsNone(recovery.head_sha)
        self.assertEqual("", git(clone, "for-each-ref", "refs/heads").strip())
        self.assertEqual("", git(self.target, "for-each-ref", "refs/heads").strip())
        published = restarted.publish(pending, self.initial(), input_sha=None)
        self.assertTrue(published.created)
        self.assertEqual(published.resulting_sha, self.canonical_head())
        self.assertEqual(1, self.commits())

    # --- refusals ---------------------------------------------------------

    def test_refuses_to_switch_the_pinned_target_or_branch(self):
        publisher, _ = self.started()
        publisher.publish(self.operation(), self.initial(), input_sha=None)
        publisher.close()
        other = self.base / "other.git"
        git(self.base, "init", "--bare", "--quiet", str(other))
        for options in ({"target": str(other)}, {"branch": "elsewhere"}):
            shutil.rmtree(self.root / CLONE_DIR, ignore_errors=True)
            switched = self.publisher(**options)
            with self.assertRaises(LibraryError) as raised:
                switched.startup()
            self.assertEqual("TARGET_MISMATCH", raised.exception.code)
            switched.close()
        _, recovery = self.started()
        self.assertEqual(1, self.commits())
        self.assertEqual(self.canonical_head(), recovery.head_sha)

    def test_transport_environment_is_explicit_and_cannot_weaken_hardening(self):
        for environment in ({"PATH": "/bin"}, {"GIT_CONFIG_GLOBAL": "/tmp/x"},
                            {"GIT_TERMINAL_PROMPT": "1"}, {"GIT_SSH_COMMAND": 1},
                            "GIT_SSH_COMMAND=ssh"):
            with self.assertRaises(LibraryError) as raised:
                self.publisher(environment=environment)
            self.assertEqual("INVALID_ENVIRONMENT", raised.exception.code)
        publisher = self.publisher(environment={"GIT_SSH_COMMAND": "ssh -F /dev/null"})
        publisher.startup()
        self.addCleanup(publisher.close)
        published = publisher.publish(self.operation(), self.initial(), input_sha=None)
        self.assertEqual(published.resulting_sha, self.canonical_head())

    def test_refuses_a_bundle_outside_the_operation_project(self):
        publisher, _ = self.started()
        foreign = self.initial(self.scope("beta", "acme/beta", "2002"))
        with self.assertRaises(LibraryError) as raised:
            publisher.publish(self.operation(), foreign, input_sha=None)
        self.assertEqual("INVALID_PUBLICATION", raised.exception.code)
        self.assertEqual("", git(self.target, "for-each-ref", "refs/heads").strip())


if __name__ == "__main__":
    unittest.main()
