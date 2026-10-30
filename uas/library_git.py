"""Library canonical Git publication under one host-local singleton lease.

The Service owns one private mirror of one configured canonical target and
branch. This seam performs the Git half of a Library operation: it takes the
host-local exclusive lease before any clone work, serializes
reconciliation/commit/push, publishes only fast-forward updates, records the
stable operation identity before publication, and reconciles an uncertain push
against canonical history before repeating it. Target qualification, receiving
policy, credentials, backup durability and the read projection belong to their
own owners: a successful push here is neither qualification nor backup evidence.

Where publication identity lives: the T02 operational record commits the
operation identity before publication, the canonical commit carries the input
and actual-parent identities as metadata-only trailers, and the resulting
commit is that commit. ``publish`` returns all three so the caller can write its
receipt and audit. No local-only ref, commit or file is ever read as publication
success: every publication decision comes from the fetched canonical branch, and
startup settles in-flight records against canonical Git before it discards
local-only state.

The in-process write lock covers reconciliation, commit and push only. No model
work happens under it, so the Git write lock is never held across model latency.

Credentials are not read or stored here: a deployment supplies transport and
credential variables through ``environment``. The canonical target and branch
are pinned in the service root, not in the disposable clone, and a change is
refused rather than followed, so an operator provisions a fresh service root
instead of silently repointing a clone.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import json
import os
import selectors
import time
from pathlib import Path
import shutil
import stat
import subprocess
import threading
import uuid

from . import library
from .library import LibraryError, Operation
from .library_bundle import Bundle, Tree, frontmatter, _prefix as project_prefix
from .library_records import LibraryRecords


LEASE_FILE = "lease"
CLONE_DIR = "clone.git"
PIN_FILE = "canonical.json"
MAX_PIN_BYTES = 4096
TRAILER_KEYS = ("Library-Publication", "Library-Operation", "Library-Request",
                "Library-Queue", "Library-Input", "Library-Parent")
# Transport/credential variables a deployment may supply explicitly. Everything
# this seam relies on for hardening stays out of reach.
_ENVIRONMENT = frozenset({"GIT_SSH_COMMAND", "GIT_SSH", "GIT_ASKPASS",
                          "SSH_AUTH_SOCK", "HOME"})
# No ambient credentials, config, hooks, helper transport, pager or fsmonitor.
_BASE_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
    "GIT_PROTOCOL_FROM_USER": "0",
}
# Clone-local hardening. These live in the clone's own config rather than in
# `-c` arguments: `-c` values propagate through GIT_CONFIG_PARAMETERS to a
# same-host receiving process, which must keep its own hooks and policy.
_CLONE_CONFIG = (("core.hooksPath", "/dev/null"), ("core.fsmonitor", "false"),
                 ("submodule.recurse", "false"), ("user.name", "Library Service"),
                 ("user.email", "library@invalid"))


@dataclass(frozen=True)
class Publication:
    """One operation's canonical publication, including recovered results.

    ``input_sha`` is the head the content was prepared against, ``previous_sha``
    the commit's actual parent and ``resulting_sha`` the published commit.
    ``created`` is false when the canonical result already existed: an
    operation or draft found in canonical history, or a proposal that changes
    nothing.
    """
    operation_id: str
    input_sha: str | None
    previous_sha: str | None
    resulting_sha: str
    created: bool


class PublicationSubscription:
    """Bounded latest-value mailbox, never a callback on a publication path.

    Only metadata crosses this seam. Slow or failed consumers coalesce events;
    they reconcile current canonical state rather than replaying stale trees.
    """
    def __init__(self, project_identity, project_path):
        self.project_identity, self.project_path = project_identity, project_path
        self._condition = threading.Condition()
        self._version, self._publication = 1, None  # initial reconciliation
        self._closed = False

    def signal(self, publication=None):
        with self._condition:
            if not self._closed:
                self._version += 1
                self._publication = publication
                self._condition.notify_all()

    def wait(self, after=0, timeout=None):
        with self._condition:
            self._condition.wait_for(lambda: self._closed or self._version > after,
                                     timeout=timeout)
            return self._version, self._publication, self._closed

    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()


@dataclass(frozen=True)
class Recovery:
    """Startup reconstruction: canonical head, settled publications, absent identities.

    ``settled`` holds the committed result of each in-flight identity found in
    canonical history; ``absent`` names the identities that are not in canonical
    history, so their callers may retry rather than claim success.
    """
    target: str
    branch: str
    head_sha: str | None
    settled: tuple
    absent: tuple


def _unsafe_argv(value, field):
    """Refuse an unsafe Git argument; qualification and admission are upstream."""
    if (type(value) is not str or not value or len(value) > 512
            or value.startswith("-")
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)):
        raise LibraryError("UNSAFE_TARGET", field)
    return value


def _prefix(value):
    if (type(value) is not str or not value.startswith("projects/")
            or any(part in ("", ".", "..") for part in value.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise LibraryError("INVALID_PUBLICATION", "bundle.prefix")
    return value


def _environment(value):
    """Explicit transport/credential variables; the deployment owns their values."""
    if value is None:
        return {}
    if type(value) is not dict:
        raise LibraryError("INVALID_ENVIRONMENT", "environment")
    for key, item in value.items():
        if (key not in _ENVIRONMENT or type(item) is not str or len(item) > 4096
                or any(ord(c) < 32 or ord(c) == 127 for c in item)):
            raise LibraryError("INVALID_ENVIRONMENT", "environment")
    return dict(value)


def _pin_value(value, expected):
    """One bounded canonical target/branch pin; nothing else is tolerated."""
    try:
        stored = json.loads(value.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise LibraryError("PIN_UNAVAILABLE", "canonical") from None
    if (type(stored) is not dict or set(stored) != set(expected)
            or stored["version"] != expected["version"]
            or type(stored["target"]) is not str
            or type(stored["branch"]) is not str):
        raise LibraryError("PIN_UNAVAILABLE", "canonical")
    if stored != expected:
        raise LibraryError("TARGET_MISMATCH", "canonical")


def _trailers(message):
    """The exact metadata-only trailer block this seam writes, or nothing."""
    lines = [line for line in message.splitlines() if line.strip()]
    if len(lines) < len(TRAILER_KEYS):
        return None
    values = {}
    for line, key in zip(lines[-len(TRAILER_KEYS):], TRAILER_KEYS):
        prefix = key + ": "
        if not line.startswith(prefix):
            return None
        values[key] = line[len(prefix):]
    return values


class LibraryGit:
    """One Deployment's canonical Git publisher; one instance per lease holder.

    ``target`` and ``branch`` come from the admitted settings document. This
    seam refuses an unsafe argument or a clone pinned to another target/branch,
    but it does not decide target qualification, and it loads no credential.
    """

    def __init__(self, root, *, records_path, deployment_id, target, branch,
                 environment=None, timeout=120):
        self.root = Path(root)
        self.records_path = Path(records_path)
        self.deployment_id = deployment_id
        self.target = _unsafe_argv(target, "target")
        # One branch contract with the settings owner; no second copy.
        self.branch = library._branch(branch)
        self.environment = _environment(environment)
        self.timeout = timeout
        self._clone = self.root / CLONE_DIR
        self._lease = None
        self._lock = threading.Lock()
        # Registration admission/receipt must not race another same-ID call.
        self.registration_lock = threading.Lock()
        self._head = None
        self._started = False
        self._subscriptions = set()
        self._subscriptions_lock = threading.Lock()

    def _records(self):
        """One store per call: the T02 owner binds its connection to one thread."""
        return LibraryRecords(self.records_path, self.deployment_id)

    # --- lease and startup ------------------------------------------------

    def _acquire(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.root / LEASE_FILE,
                                 os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                                 0o600)
        except OSError as error:
            raise LibraryError("LEASE_UNSAFE", "lease") from error
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1):
                raise LibraryError("LEASE_UNSAFE", "lease")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise LibraryError("LEASE_BUSY", "lease") from error
        except BaseException:
            os.close(descriptor)
            raise
        self._lease = descriptor

    def startup(self):
        """Take the lease, reconstruct the clone and settle in-flight records.

        A second instance fails readiness here, before it reads or writes the
        clone. Local-only state is discarded only after in-flight identities are
        settled against canonical Git.
        """
        if self._started:
            raise LibraryError("ALREADY_STARTED", "lease")
        self._acquire()
        try:
            self._pin()
            state = self._clone_state()
            if state == "mismatch":
                raise LibraryError("TARGET_MISMATCH", "target")
            if state != "ok":
                # A missing or unusable clone holds no trustworthy local state.
                self._rebuild()
            self._fetch()
            settled, absent = self._settle()
            self._reset_local()
        except BaseException:
            self.close()
            raise
        self._started = True
        self._notify()
        return Recovery(self.target, self.branch, self._head,
                        tuple(settled), tuple(absent))

    def close(self):
        """Release the lease; the canonical clone stays as an untrusted cache."""
        descriptor, self._lease = self._lease, None
        self._started = False
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def __enter__(self):
        self.startup()
        return self

    def __exit__(self, *_):
        self.close()

    @property
    def clone_path(self):
        return self._clone

    def head(self):
        """The canonical head observed by the last reconciliation, or None."""
        if not self._started:
            raise LibraryError("NOT_READY", "lease")
        return self._head

    def subscribe(self, scope):
        """Trusted supervisor subscribes one already-bound Project, no paths in payloads."""
        project_prefix(scope)
        subscription = PublicationSubscription(scope.project_identity, scope.project_path)
        with self._subscriptions_lock:
            if len(self._subscriptions) >= 1024:
                raise LibraryError('TOO_MANY_SUBSCRIBERS', 'projection')
            self._subscriptions.add(subscription)
        return subscription

    def unsubscribe(self, subscription):
        with self._subscriptions_lock:
            self._subscriptions.discard(subscription)
        subscription.close()

    def _notify(self, scope=None, publication=None):
        # Fixed in-memory mailboxes only: no consumer code, file IO or network.
        with self._subscriptions_lock:
            for subscription in self._subscriptions:
                if scope is None or (subscription.project_identity == scope.project_identity
                                     and subscription.project_path == scope.project_path):
                    subscription.signal(publication)

    def reconnect(self):
        """Reconcile after transport restoration; projection work stays asynchronous."""
        if not self._started:
            raise LibraryError('NOT_READY', 'lease')
        with self._lock:
            self._fetch()
            settled, absent = self._settle()
            self._reset_local()
            result = Recovery(self.target, self.branch, self._head,
                              tuple(settled), tuple(absent))
        self._notify()
        return result

    def project_snapshot(self, scope, settings, *, current, registration=False):
        """Fetch one bounded, regular-file Project tree at one canonical SHA.

        This is the canonical reader for content operations, not a source or
        Participant read route. Authority is rechecked around every local read.
        The publisher's compatibility check fences later writes against races.
        """
        if not self._started:
            raise LibraryError("NOT_READY", "lease")
        prefix = project_prefix(scope)
        limits = library.admit_settings_value(settings)["limits"]
        with self._lock:
            current()
            self._fetch()
            current()
            head = self._head
            if head is None:
                return None, Tree({})
            if registration:
                self._registration_identity(scope, current)
            return self._project_tree(scope, limits, current, head)

    def projection_snapshot(self, scope, settings, *, current):
        """Read canonical immutable objects without taking the publisher lock.

        A source-only exact-SHA fetch has no ref destination and never changes
        the publisher's head or FETCH_HEAD. Git object installation is atomic;
        the clone is not pruned while the singleton is running. A moving or
        unavailable remote fails this refresh, not the canonical write path.
        """
        if not self._started:
            raise LibraryError('NOT_READY', 'lease')
        project_prefix(scope)
        limits = library.admit_settings_value(settings)['limits']
        current()
        head = self._remote_head()
        if head is None:
            return None, Tree({})
        library._commit(head, 'canonical')
        code, _, _ = self._git('-c', 'gc.auto=0', 'fetch', '--no-write-fetch-head',
                                '--no-tags', '--quiet', 'origin', head)
        if code != 0:
            raise LibraryError('PUBLICATION_UNAVAILABLE', 'project')
        current()
        return self._project_tree(scope, limits, current, head)

    def _project_tree(self, scope, limits, current, head):
        prefix = project_prefix(scope)
        # A file/gitlink at a parent coordinate must not be silently
        # displaced by update-index while creating the Project directory.
        for index in range(1, len(prefix.split('/')) + 1):
            ancestor = '/'.join(prefix.split('/')[:index])
            node = self._bounded_read(['ls-tree', '-z', head, '--', ancestor], 1400, current)
            if node and not node.startswith(b'040000 tree '):
                raise LibraryError('UNSUPPORTED_PROJECT_ENTRY', 'project')
        listing = self._bounded_read(
            ["ls-tree", "-r", "-l", "-z", head, "--", prefix],
            (limits["scan_documents"] + 1) * 1200, current)
        rows = listing.split(b"\0")[:-1]
        if len(rows) > limits["scan_documents"]:
            raise LibraryError("TOO_MANY_DOCUMENTS", "project")
        files, total = {}, 0
        for row in rows:
            header, tab, path = row.partition(b"\t")
            parts = header.split()
            if (not tab or len(parts) != 4 or parts[0] not in (b"100644", b"100755")
                    or parts[1] != b"blob"):
                raise LibraryError("UNSUPPORTED_PROJECT_ENTRY", "project")
            try:
                name, oid, size = path.decode("utf-8"), parts[2].decode("ascii"), int(parts[3])
            except (ValueError, UnicodeError):
                raise LibraryError("INVALID_PROJECT_TREE", "project") from None
            if not name.startswith(prefix + "/") or not library.COMMIT.fullmatch(oid):
                raise LibraryError("INVALID_PROJECT_TREE", "project")
            total += size
            if size > limits["document_bytes"] or total > limits["projection_bytes"]:
                raise LibraryError("BUNDLE_TOO_LARGE", "project")
            files[name] = self._bounded_read(["cat-file", "blob", oid], size, current)
            if len(files[name]) != size:
                raise LibraryError("INVALID_PROJECT_TREE", "project")
        return head, Tree(files)

    def _registration_identity(self, scope, current):
        """Bounded service-only root identity catalog; no source/concept scan.

        Coordinates are not identity. Registration cannot duplicate an existing
        immutable source identity at a new path; the atomic move owner does that.
        Fixed catalog bounds fail closed rather than silently checking a prefix.
        """
        if self._head is None:
            return
        raw = self._bounded_read(['ls-tree', '-r', '-z', '--name-only', self._head,
                                  '--', 'projects'], 4 * 1024 * 1024, current)
        paths = raw.split(b'\0')[:-1]
        if len(paths) > 16384:
            raise LibraryError('REGISTRATION_CATALOG_TOO_LARGE', 'project')
        roots = [path for path in paths if len(path.split(b'/')) == 5
                 and path.endswith(b'/index.md')]
        if len(roots) > 1024:
            raise LibraryError('REGISTRATION_CATALOG_TOO_LARGE', 'project')
        deadline = time.monotonic() + min(self.timeout, 5)
        expected = ('projects/' + scope.project_path + '/index.md').encode()
        for path in roots:
            if time.monotonic() >= deadline:
                raise LibraryError('PUBLICATION_UNAVAILABLE', 'project')
            if path == expected:
                continue  # The complete Project gate checks the selected root.
            try:
                name = path.decode('utf-8')
                raw = self._bounded_read(['show', self._head + ':' + name],
                                         library.MAXIMA['document_bytes'], current)
                _, body = frontmatter(raw.decode('utf-8'), 'project.identity')
            except UnicodeError:
                raise LibraryError('INVALID_PROJECT_IDENTITY', 'project') from None
            identities = [line.strip()[len('Source identity:'):].strip()
                          for line in body.splitlines()
                          if line.strip().startswith('Source identity:')]
            if scope.project_identity in identities:
                raise LibraryError('PROJECT_COORDINATE_CONFLICT', 'project')

    def _bounded_read(self, arguments, limit, current):
        """No lazy network read, hooks, content stderr, or unbounded blob buffer."""
        current()
        environment = self._environment()
        environment.update({"GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""})
        command = ["git", "--no-replace-objects", "--git-dir", str(self._clone), *arguments]
        try:
            with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=environment) as process:
                data = bytearray()
                deadline = time.monotonic() + min(self.timeout, 5)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        while True:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0 or not selector.select(remaining):
                                raise LibraryError("PUBLICATION_UNAVAILABLE", "project")
                            current()
                            chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(data)))
                            if not chunk:
                                break
                            data.extend(chunk)
                            if len(data) > limit:
                                raise LibraryError("BUNDLE_TOO_LARGE", "project")
                        if process.wait(timeout=max(.001, deadline-time.monotonic())) != 0:
                            raise LibraryError("PUBLICATION_UNAVAILABLE", "project")
                    current()
                    return bytes(data)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
        except (OSError, subprocess.TimeoutExpired):
            raise LibraryError("PUBLICATION_UNAVAILABLE", "project") from None

    # --- publication ------------------------------------------------------

    def publish(self, operation, bundle, *, input_sha, current=None):
        """Publish one validated complete Project bundle as one fast-forward commit.

        ``bundle`` is the T04/T05 complete result; this seam replaces exactly
        that Project prefix and preserves every other path. ``input_sha`` is the
        canonical head the complete result was prepared against, or ``None``
        when the caller is creating a Project that has no bundle yet: a complete
        result may never silently revert Project content it did not prepare
        against. An operation already present in canonical history returns its
        committed result without a new commit, which is what makes a lost
        acknowledgement safe to retry.
        """
        if not self._started:
            raise LibraryError("NOT_READY", "lease")
        if type(operation) is not Operation:
            raise LibraryError("INVALID_OPERATION", "operation")
        if operation.scope.project_path is None:
            raise LibraryError("FORBIDDEN", "scope.project_path")
        if type(bundle) is not Bundle:
            raise LibraryError("INVALID_PUBLICATION", "bundle")
        prefix = _prefix(bundle.prefix)
        if prefix != "projects/" + operation.scope.project_path:
            raise LibraryError("INVALID_PUBLICATION", "bundle.prefix")
        files = dict(bundle.files)
        for path in files:
            if type(path) is not str or not path.startswith(prefix + "/"):
                raise LibraryError("INVALID_PUBLICATION", "bundle.files")
            if type(files[path]) is not bytes:
                raise LibraryError("INVALID_PUBLICATION", "bundle.files")
        if input_sha is not None and (type(input_sha) is not str
                                      or not library.COMMIT.fullmatch(input_sha)):
            raise LibraryError("INVALID_COMMIT", "input_sha")

        with self._lock:
            if current is not None:
                current()
            self._fetch()
            if current is not None:
                current()
            if operation.kind == 'register':
                self._registration_identity(operation.scope, current or (lambda: None))
            located = self._locate(operation.operation_id, operation.request_id,
                                   operation.kind, operation.queue_id)
            # The stable operation identity is durable before any publication.
            with self._records() as records:
                records.begin(operation)
            if located is not None:
                self._reset_local()
                result = located
            else:
                result = self._publish(operation, prefix, files, input_sha, current=current)
        self._notify(operation.scope, result)
        return result

    def _publish(self, operation, prefix, files, input_sha, current=None):
        previous = self._head
        self._compatible(input_sha, previous, prefix)
        input_identity = input_sha or previous
        current_paths = self._tree_paths(previous, prefix)
        tree = self._tree(previous, files, current_paths - set(files))
        if tree == self._tree_of(previous):
            # Nothing to publish: the proposal is already the canonical content.
            return Publication(operation.operation_id, input_identity, previous,
                               previous, False)
        if current is not None:
            current()
        commit = self._commit(tree, previous, operation, input_identity)
        if current is not None:
            current()
        rejected = self._push(commit, operation)
        if rejected is not None:
            return rejected
        return Publication(operation.operation_id, input_identity, previous, commit, True)

    def _compatible(self, input_sha, previous, prefix):
        """The caller's basis must still describe this Project's canonical input.

        Ancestry alone is not compatibility: a complete result prepared before
        another publication would otherwise overwrite that newer content. A
        missing basis is only acceptable while the Project has no bundle.
        """
        if input_sha is None:
            if previous is not None:
                for index in range(1, len(prefix.split('/')) + 1):
                    ancestor = '/'.join(prefix.split('/')[:index])
                    oid = self._rev(previous + ':' + ancestor)
                    if oid is not None and self._run('cat-file', '-t', oid) != 'tree':
                        raise LibraryError('UNSUPPORTED_PROJECT_ENTRY', 'project')
            if previous is not None and self._subtree(previous, prefix) is not None:
                raise LibraryError("INCOMPATIBLE_HEAD", "input_sha")
            return
        if previous is None or not self._ancestor(input_sha, previous):
            raise LibraryError("INCOMPATIBLE_HEAD", "input_sha")
        if self._subtree(input_sha, prefix) != self._subtree(previous, prefix):
            raise LibraryError("INCOMPATIBLE_HEAD", "input_sha")

    def _subtree(self, commit, prefix):
        return self._rev("%s:%s" % (commit, prefix))

    def _tree(self, previous, files, removals):
        index = self.root / ("index-" + uuid.uuid4().hex)
        env = {"GIT_INDEX_FILE": str(index)}
        try:
            self._run(*(["read-tree", previous] if previous
                        else ["read-tree", "--empty"]), env=env)
            entries = []
            for path in sorted(files):
                blob = self._run("hash-object", "-w", "--stdin", data=files[path], env=env)
                entries.append(b"100644 %s\t%s\x00" % (blob.encode(), path.encode("utf-8")))
            # Mode 0 removes an index entry without needing a work tree.
            for path in sorted(removals):
                entries.append(b"0 %s\t%s\x00" % (b"0" * 40, path.encode("utf-8")))
            if entries:
                self._run("update-index", "-z", "--index-info",
                          data=b"".join(entries), env=env)
            return self._run("write-tree", env=env)
        finally:
            try:
                os.unlink(index)
            except OSError:
                pass

    def _commit(self, tree, previous, operation, input_identity):
        message = "".join("%s: %s\n" % (key, value) for key, value in (
            ("Library-Publication", operation.kind),
            ("Library-Operation", operation.operation_id),
            ("Library-Request", operation.request_id),
            ("Library-Queue", operation.queue_id or "none"),
            ("Library-Input", input_identity or "none"),
            ("Library-Parent", previous or "none")))
        command = ["commit-tree", tree] + (["-p", previous] if previous else [])
        return self._run(*command, data=("Library publication\n\n" + message).encode())

    def _push(self, commit, operation):
        """Push the commit; a rejection is reconciled, never blindly repeated.

        A push that cannot report its own outcome (transport error or timeout)
        is as uncertain as a rejection: both reconcile canonical history before
        the caller may repeat the operation.
        """
        try:
            code, _, _ = self._git("push", "--porcelain", "origin",
                                   commit + ":refs/heads/" + self.branch)
        except LibraryError:
            code = None
        if code == 0:
            self._head = commit
            self._reset_local()
            return None
        try:
            self._fetch()
        except LibraryError as error:
            raise LibraryError("PUBLICATION_UNCERTAIN", "push") from error
        found = self._locate(operation.operation_id, operation.request_id,
                             operation.kind, operation.queue_id)
        if found is not None:
            self._reset_local()
            return found
        raise LibraryError("PUBLICATION_REJECTED", "push")

    # --- reconciliation and recovery -------------------------------------

    def _settle(self):
        """Resolve every in-flight identity against the fetched canonical branch."""
        settled, absent = [], []
        with self._records() as records:
            pending = records.pending()
        for record in pending:
            found = self._locate(record["operation_id"], record["request_id"],
                                 record["kind"], record["queue_id"])
            if found is None:
                absent.append(record["operation_id"])
            else:
                settled.append(found)
        return settled, absent

    def _locate(self, operation_id, request_id, kind, queue_id):
        """The committed result of one operation or draft in canonical history.

        An operation identity is unique per attempt. A retry of the same
        librarian request carries a new attempt identity but the same draft, so
        an ``enqueue`` also reconciles on its queue identity and never publishes
        the same draft twice.
        """
        if self._head is None:
            return None
        candidates = self._search("Library-Operation: " + operation_id)
        if kind == "enqueue" and queue_id is not None:
            candidates += [sha for sha in self._search("Library-Queue: " + queue_id)
                           if sha not in candidates]
        for sha in candidates:
            code, shown, _ = self._git("show", "-s", "--format=%P%n%B", sha)
            if code != 0:
                raise LibraryError("GIT_FAILED", "show")
            parent, _, message = shown.decode("utf-8", "strict").partition("\n")
            values = _trailers(message)
            if values is None:
                continue
            if (values["Library-Request"] != request_id
                    or values["Library-Publication"] != kind):
                continue
            if (values["Library-Operation"] != operation_id
                    and not (kind == "enqueue" and queue_id is not None
                             and values["Library-Queue"] == queue_id)):
                continue
            previous = parent.split()[0] if parent.split() else None
            input_sha = values["Library-Input"]
            return Publication(operation_id, None if input_sha == "none" else input_sha,
                               previous, sha, False)
        return None

    def _search(self, needle):
        code, out, _ = self._git("log", "--format=%H", "--fixed-strings",
                                 "--grep=" + needle, self._head)
        if code != 0:
            raise LibraryError("GIT_FAILED", "log")
        return out.decode("utf-8", "strict").split()

    def _fetch(self):
        """Read the canonical head from the target and mirror it locally."""
        remote = self._remote_head()
        reference = "refs/remotes/origin/" + self.branch
        if remote is None:
            self._git("update-ref", "-d", reference)
            self._head = None
            return None
        try:
            code, _, _ = self._git("fetch", "--prune", "--no-tags", "--quiet", "origin",
                                   "+refs/heads/%s:%s" % (self.branch, reference))
        except LibraryError as error:
            raise LibraryError("PUBLICATION_UNAVAILABLE", "target") from error
        if code != 0:
            raise LibraryError("PUBLICATION_UNAVAILABLE", "target")
        self._head = self._rev(reference)
        if self._head is None:
            raise LibraryError("PUBLICATION_UNAVAILABLE", "target")
        return self._head

    def _remote_head(self):
        try:
            code, out, _ = self._git("ls-remote", "--heads", "origin",
                                     "refs/heads/" + self.branch)
        except LibraryError as error:
            raise LibraryError("PUBLICATION_UNAVAILABLE", "target") from error
        if code != 0:
            raise LibraryError("PUBLICATION_UNAVAILABLE", "target")
        for line in out.decode("utf-8", "strict").splitlines():
            sha, _, reference = line.partition("\t")
            if reference.strip() == "refs/heads/" + self.branch:
                return sha.strip()
        return None

    def _reset_local(self):
        """Make the local mirror match canonical; local-only commits are dropped."""
        local = "refs/heads/" + self.branch
        if self._head is None:
            self._git("update-ref", "-d", local)
            return
        code, _, _ = self._git("update-ref", local, self._head)
        if code != 0:
            raise LibraryError("GIT_FAILED", "update-ref")

    def _tree_of(self, commit):
        return None if commit is None else self._rev(commit + "^{tree}")

    def _tree_paths(self, commit, prefix):
        if commit is None:
            return set()
        code, out, _ = self._git("ls-tree", "-r", "--name-only", commit, "--", prefix)
        if code != 0:
            raise LibraryError("GIT_FAILED", "ls-tree")
        return set(out.decode("utf-8", "strict").splitlines())

    def _ancestor(self, commit, head):
        code, _, _ = self._git("merge-base", "--is-ancestor", commit, head)
        if code == 0:
            return True
        if code == 1:
            return False
        raise LibraryError("GIT_FAILED", "merge-base")

    def _rev(self, reference):
        code, out, _ = self._git("rev-parse", "--verify", "--quiet", reference)
        if code != 0:
            return None
        return out.decode("utf-8", "strict").strip()

    # --- canonical pin ----------------------------------------------------

    def _pin(self):
        """Canonical target/branch identity, durable outside the clone cache.

        The clone is disposable, so the pin lives in the service root: losing
        the clone must not let a different target or branch take its place.
        """
        expected = {"version": 1, "target": self.target, "branch": self.branch}
        path = self.root / PIN_FILE
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            self._write_pin(path, expected)
            return
        except OSError as error:
            raise LibraryError("PIN_UNAVAILABLE", "canonical") from error
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise LibraryError("PIN_UNAVAILABLE", "canonical")
            raw = os.read(descriptor, MAX_PIN_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_PIN_BYTES:
            raise LibraryError("PIN_UNAVAILABLE", "canonical")
        _pin_value(raw, expected)

    def _write_pin(self, path, expected):
        temporary = self.root / (PIN_FILE + "." + uuid.uuid4().hex)
        data = json.dumps(expected, sort_keys=True).encode("utf-8")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            try:
                os.write(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as error:
            raise LibraryError("PIN_UNAVAILABLE", "canonical") from error

    # --- clone state ------------------------------------------------------

    def _clone_state(self):
        if not self._clone.exists():
            return "missing"
        if not self._clone.is_dir():
            return "invalid"
        if self._rev("HEAD") is None and not (self._clone / "HEAD").is_file():
            return "invalid"
        code, out, _ = self._git("config", "--get", "remote.origin.url")
        if code != 0 or out.decode("utf-8", "strict").strip() != self.target:
            return "mismatch" if code == 0 else "invalid"
        code, out, _ = self._git("config", "--get", "library.branch")
        if code != 0:
            return "invalid"
        return "ok" if out.decode("utf-8", "strict").strip() == self.branch else "mismatch"

    def _rebuild(self):
        if self._clone.is_dir():
            shutil.rmtree(self._clone)
        elif self._clone.exists():
            self._clone.unlink()
        code, _, _ = self._git("init", "--bare", "--quiet", str(self._clone), git_dir=False)
        if code != 0:
            raise LibraryError("CLONE_UNAVAILABLE", "clone")
        for key, value in (("remote.origin.url", self.target),
                           ("library.branch", self.branch), *_CLONE_CONFIG):
            code, _, _ = self._git("config", key, value)
            if code != 0:
                raise LibraryError("CLONE_UNAVAILABLE", "clone")

    # --- Git invocation ---------------------------------------------------

    def _environment(self):
        env = dict(_BASE_ENV)
        env.update(self.environment)
        env["GIT_ALLOW_PROTOCOL"] = self._protocol()
        return env

    def _protocol(self):
        scheme = self.target.partition("://")[0].lower()
        return scheme if scheme in ("https", "ssh") else "file"

    def _git(self, *args, data=None, env=None, git_dir=True):
        command = ["git"]
        if git_dir:
            command += ["--git-dir", str(self._clone)]
        command += list(args)
        environment = self._environment()
        if env:
            environment.update(env)
        try:
            result = subprocess.run(command, env=environment, input=data,
                                    stdin=None if data is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LibraryError("GIT_UNAVAILABLE", "git") from error
        return result.returncode, result.stdout, result.stderr

    def _run(self, *args, **options):
        code, out, _ = self._git(*args, **options)
        if code != 0:
            raise LibraryError("GIT_FAILED", "git")
        return out.decode("utf-8", "strict").strip()
