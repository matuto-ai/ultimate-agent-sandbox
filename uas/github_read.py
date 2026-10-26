"""Bounded GitHub observation seam, not Run admission or live-provider qualification.

Only supervisor-owned code supplies Project, transport and external credentials.
Participant argv is reduced to one typed read route before any provider call.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time

from .ledger import LedgerError

MAX_OUTPUT = 1_048_576
MAX_OBSERVATION = 48_000
API_VERSION = "2026-03-10"
DELIVERY_CLASSES = frozenset({"mechanical", "bounded", "cross-cutting", "critical", "unclassified"})
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?\Z")
def validate_route_table(rows):
    """Reject ambiguous discovery/enforcement vocabulary at module startup."""
    if type(rows) is not tuple or not rows:
        raise LedgerError("INVALID_ROUTE_TABLE")
    kinds, prefixes, signatures = set(), [], set()
    for row in rows:
        if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not str
                or row[0] not in {"help", "issue-view"} or row[0] in kinds
                or type(row[1]) is not tuple or not 1 <= len(row[1]) <= 2
                or any(type(word) is not str or not re.fullmatch(r"(?:[a-z]+|--help)", word) for word in row[1])
                or type(row[2]) is not str or row[2] in signatures
                or not row[2].startswith("gh " + " ".join(row[1]))
                or any(prefix[:len(row[1])] == row[1] or row[1][:len(prefix)] == prefix for prefix in prefixes)):
            raise LedgerError("INVALID_ROUTE_TABLE")
        kinds.add(row[0])
        prefixes.append(row[1])
        signatures.add(row[2])
    if kinds != {"help", "issue-view"}:
        raise LedgerError("INVALID_ROUTE_TABLE")
    return rows


_ROUTES = validate_route_table((("help", ("--help",), "gh --help"),
                               ("issue-view", ("issue", "view"), "gh issue view NUMBER [--repo OWNER/REPO]")))
_BY_KIND = {row[0]: row for row in _ROUTES}


@dataclass(frozen=True)
class GitHubProject:
    repository: str
    host: str = "github.com"

    def __post_init__(self):
        if (self.host != "github.com" or type(self.repository) is not str
                or not _REPOSITORY.fullmatch(self.repository)
                or self.repository.split("/")[1] in {".", ".."}):
            raise LedgerError("INVALID_PROJECT")


@dataclass(frozen=True)
class ReadRoute:
    kind: str
    issue_number: int | None = None


def generated_help():
    return "Read-only GitHub routes (pinned Room Project):\n" + "\n".join(row[2] for row in _ROUTES)


def parse_route(argv, project):
    if type(project) is not GitHubProject:
        raise LedgerError("INVALID_PROJECT")
    if (type(argv) not in {list, tuple} or not 1 <= len(argv) <= 6
            or any(type(arg) is not str or len(arg) > 256 for arg in argv)):
        raise LedgerError("UNSUPPORTED_ROUTE")
    args = list(argv)
    if args and args[0] == "gh":
        args.pop(0)
    if args == list(_BY_KIND["help"][1]):
        return ReadRoute("help")
    if len(args) not in {3, 5} or args[:2] != list(_BY_KIND["issue-view"][1]):
        raise LedgerError("UNSUPPORTED_ROUTE")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", args[2]):
        raise LedgerError("INVALID_ISSUE")
    if len(args) == 5:
        if args[3] not in {"--repo", "-R"}:
            raise LedgerError("UNSUPPORTED_ROUTE")
        if args[4] != project.repository:
            raise LedgerError("CROSS_PROJECT_READ_UNSUPPORTED")
    return ReadRoute("issue-view", int(args[2]))


@dataclass(frozen=True)
class ProviderResponse:
    status: int
    body: bytes
    headers: dict


class ProviderFailure(Exception):
    def __init__(self, code):
        # Never propagate command output, provider messages, or credentials.
        self.code = code if code in {"TIMEOUT", "OUTPUT_LIMIT", "PROVIDER_ERROR", "INVALID_RESPONSE", "CREDENTIAL_UNAVAILABLE"} else "PROVIDER_ERROR"
        super().__init__(self.code)


def _positive(value):
    return type(value) is int and 1 <= value <= 2**63 - 1


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


class GitHubReadProvider:
    """Sequential, bounded REST observations; completeness is not an admission.

    transport is a trusted one-argument callable, not supplied by Participant.
    It returns raw response bytes only to this adapter, never to audit or Pi.
    """
    def __init__(self, project, transport, *, max_pages=10, max_bytes=MAX_OUTPUT):
        if type(project) is not GitHubProject or not callable(transport):
            raise LedgerError("INVALID_PROJECT")
        if type(max_pages) is not int or not 1 <= max_pages <= 10 or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_OUTPUT:
            raise LedgerError("INVALID_PROVIDER_LIMIT")
        self.project, self.transport = project, transport
        self.max_pages, self.max_bytes = max_pages, max_bytes

    def _issue(self, value, number=None, *, assignments=False):
        base = "https://api.github.com/repos/" + self.project.repository
        if (type(value) is not dict or not _positive(value.get("id")) or not _positive(value.get("number"))
                or (number is not None and value["number"] != number)
                or value.get("repository_url") != base
                or value.get("url") != base + "/issues/" + str(value["number"])
                or value.get("state") not in {"open", "closed"} or "pull_request" in value):
            raise ProviderFailure("INVALID_RESPONSE")
        result = {key: value[key] for key in ("id", "number", "state")}
        if assignments:
            users = value.get("assignees")
            if type(users) is not list or len(users) > 100:
                raise ProviderFailure("INVALID_RESPONSE")
            result["assignees"] = []
            ids = set()
            for user in users:
                if (type(user) is not dict or not _positive(user.get("id")) or type(user.get("login")) is not str
                        or not _LOGIN.fullmatch(user["login"]) or user["id"] in ids):
                    raise ProviderFailure("INVALID_RESPONSE")
                ids.add(user["id"])
                result["assignees"].append({"id": user["id"], "login": user["login"]})
            result["assignees"].sort(key=lambda user: user["id"])
        return result

    def read_issue(self, number, *, admission=False):
        if type(admission) is not bool:
            raise LedgerError("INVALID_ADMISSION_READ")
        if not _positive(number) or number > 9_999_999_999:
            raise LedgerError("INVALID_ISSUE")
        result = {"status": "PROVIDER_ERROR", "completeness": "unknown", "issue": None,
                  "dependencies": [], "pages": 0}
        if admission:
            result["delivery_class"] = {"status": "unknown", "value": None, "pages": 0}
        used = 0
        deadline = time.monotonic() + 30
        def get(path):
            nonlocal used
            if time.monotonic() >= deadline:
                raise ProviderFailure("TIMEOUT")
            response = self.transport(path)
            if time.monotonic() >= deadline:
                raise ProviderFailure("TIMEOUT")
            if (type(response) is not ProviderResponse or type(response.status) is not int
                    or type(response.body) is not bytes or type(response.headers) is not dict):
                raise ProviderFailure("INVALID_RESPONSE")
            used += len(response.body)
            if used > self.max_bytes:
                raise ProviderFailure("OUTPUT_LIMIT")
            if response.status != 200:
                return response, None
            try:
                value = json.loads(response.body, object_pairs_hook=_unique)
            except (ValueError, UnicodeError, RecursionError):
                raise ProviderFailure("INVALID_RESPONSE") from None
            return response, value
        try:
            base = f"repos/{self.project.repository}/issues/{number}"
            response, value = get(base)
            if response.status == 404:
                # GitHub can hide inaccessible objects with 404: never proof of absence.
                return {**result, "status": "NOT_FOUND", "reason": "not-found-or-inaccessible"}
            if response.status != 200:
                return result
            result["issue"] = self._issue(value, number, assignments=True)
            seen_ids, seen_numbers = {result["issue"]["id"]}, {number}
            for page in range(1, self.max_pages + 1):
                path = base + f"/dependencies/blocked_by?per_page=100&page={page}"
                response, values = get(path)
                if response.status != 200:
                    result.update(status="PROVIDER_ERROR", completeness="incomplete")
                    return result
                if type(values) is not list or len(values) > 100:
                    raise ProviderFailure("INVALID_RESPONSE")
                for value in values:
                    item = self._issue(value)
                    if item["id"] in seen_ids or item["number"] in seen_numbers:
                        raise ProviderFailure("INVALID_RESPONSE")
                    seen_ids.add(item["id"])
                    seen_numbers.add(item["number"])
                    if len(json.dumps({**result, "dependencies": result["dependencies"] + [item]}).encode()) > MAX_OBSERVATION - 512:
                        result.update(status="OUTPUT_LIMIT", completeness="incomplete")
                        return result
                    result["dependencies"].append(item)
                result["pages"] = page
                # Only a terminal short page proves exhaustion. An explicit next
                # Link contradicts it; never follow provider-selected URLs.
                links = [v for k, v in response.headers.items() if type(k) is str and k.lower() == "link"]
                if any(type(v) is not str for v in links):
                    raise ProviderFailure("INVALID_RESPONSE")
                if len(values) < 100 and not any(re.search(r'rel\s*=\s*["\']?next', v, re.I) for v in links):
                    if admission:
                        self._delivery_class(base, get, result)
                    else:
                        result.update(status="OK", completeness="complete")
                    return result
            result.update(status="PAGINATION_LIMIT", completeness="incomplete")
            return result
        except ProviderFailure as error:
            result.update(status=error.code, completeness="incomplete" if result["issue"] else "unknown")
            return result
        except Exception:
            # A trusted transport can fail unexpectedly. No exception text escapes.
            result.update(status="PROVIDER_ERROR", completeness="incomplete" if result["issue"] else "unknown")
            return result

    def _delivery_class(self, base, get, result):
        """Enumerate labels under the enclosing read's byte/time budget.

        Embedded issue labels are not a completeness proof. Only the bounded
        recognized classification is retained, never arbitrary label text.
        """
        ids, names, classifications = set(), set(), []
        for page in range(1, self.max_pages + 1):
            response, values = get(base + f"/labels?per_page=100&page={page}")
            if response.status != 200:
                raise ProviderFailure("PROVIDER_ERROR")
            if type(values) is not list or len(values) > 100:
                raise ProviderFailure("INVALID_RESPONSE")
            for label in values:
                if (type(label) is not dict or not _positive(label.get("id"))
                        or type(label.get("name")) is not str
                        or not 1 <= len(label["name"]) <= 256
                        or any(ord(c) < 32 for c in label["name"])
                        or label["id"] in ids or label["name"].casefold() in names):
                    raise ProviderFailure("INVALID_RESPONSE")
                ids.add(label["id"])
                names.add(label["name"].casefold())
                if label["name"].casefold().startswith("delivery:"):
                    # Non-canonical spellings and unsupported classes remain
                    # unknown rather than being corrected into permission.
                    classifications.append(label["name"][len("delivery:"):]
                                           if label["name"].startswith("delivery:") else None)
            result["delivery_class"]["pages"] = page
            links = [v for k, v in response.headers.items() if type(k) is str and k.lower() == "link"]
            if any(type(v) is not str for v in links):
                raise ProviderFailure("INVALID_RESPONSE")
            if len(values) < 100 and not any(re.search(r'rel\s*=\s*["\']?next', v, re.I) for v in links):
                if len(classifications) == 1 and classifications[0] in DELIVERY_CLASSES:
                    result["delivery_class"].update(status="known", value=classifications[0])
                result.update(status="OK", completeness="complete")
                return
        result.update(status="PAGINATION_LIMIT", completeness="incomplete")


class GhTransport:
    """Optional external Broker-side official gh executor, not enabled by default.

    The supervisor pins the executable SHA-256 and Actor. credential_env(actor,
    'github.com') supplies ONLY GH_TOKEN externally; no secret is stored here or
    copied into the Workstation. Live redirect/account behavior remains unqualified.
    """
    def __init__(self, executable, sha256, actor_id, credential_env, *, timeout=10):
        self.executable = Path(executable)
        if (not self.executable.is_absolute() or self.executable.is_symlink()
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)
                or hashlib.sha256(self.executable.read_bytes()).hexdigest() != sha256
                or type(actor_id) is not str or not actor_id or not callable(credential_env)
                or type(timeout) not in {float, int} or not 0 < timeout <= 10):
            raise LedgerError("INVALID_GH_EXECUTOR")
        self.sha256, self.actor_id, self.credentials, self.timeout = sha256, actor_id, credential_env, timeout

    def __call__(self, path):
        # Internal route defense in depth: caller cannot turn this into raw API.
        if not re.fullmatch(r"repos/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*(?:/(?:dependencies/blocked_by|labels)\?per_page=100&page=[1-9][0-9]*)?", path):
            raise ProviderFailure("INVALID_RESPONSE")
        if hashlib.sha256(self.executable.read_bytes()).hexdigest() != self.sha256:
            raise ProviderFailure("PROVIDER_ERROR")
        secrets = self.credentials(self.actor_id, "github.com")
        if type(secrets) is not dict or set(secrets) != {"GH_TOKEN"} or type(secrets["GH_TOKEN"]) is not str or not secrets["GH_TOKEN"]:
            raise ProviderFailure("CREDENTIAL_UNAVAILABLE")
        with tempfile.TemporaryDirectory(prefix="uas-gh-") as home:
            env = {"HOME": home, "GH_CONFIG_DIR": home, "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1",
                   "GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1", "GH_PAGER": "cat",
                   "LC_ALL": "C", **secrets}
            argv = [str(self.executable), "api", "--hostname", "github.com", "--method", "GET", "--include",
                    "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: " + API_VERSION, path]
            proc = subprocess.Popen(argv, cwd=home, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)
            data = bytearray()
            try:
                with selectors.DefaultSelector() as poll:
                    poll.register(proc.stdout, selectors.EVENT_READ)
                    deadline = time.monotonic() + self.timeout
                    while poll.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ProviderFailure("TIMEOUT")
                        for key, _ in poll.select(remaining):
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                poll.unregister(key.fileobj)
                            else:
                                data.extend(chunk)
                                if len(data) > MAX_OUTPUT:
                                    raise ProviderFailure("OUTPUT_LIMIT")
                    proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise ProviderFailure("TIMEOUT") from None
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                proc.stdout.close()
        try:
            header, body = bytes(data).replace(b"\r\n", b"\n", 100).split(b"\n\n", 1)
            lines = header.decode("ascii").split("\n")
            match = re.fullmatch(r"HTTP/\S+ ([0-9]{3})(?: .*)?", lines[0])
            if match is None:
                raise ValueError()
            status = int(match[1])
            if proc.returncode and status == 200:
                raise ValueError()
            headers = {}
            for line in lines[1:]:
                key, value = line.split(":", 1)
                key = key.lower()
                if key == "link":
                    headers[key] = headers.get(key, "") + value.strip()
            return ProviderResponse(status, body, headers)
        except (ValueError, UnicodeError):
            raise ProviderFailure("INVALID_RESPONSE") from None


def validate_observation(value):
    """Independent Broker result boundary; reject, do not coerce untrusted fields."""
    codes = {"OK", "NOT_FOUND", "PROVIDER_ERROR", "TIMEOUT", "OUTPUT_LIMIT", "INVALID_RESPONSE",
             "CREDENTIAL_UNAVAILABLE", "PAGINATION_LIMIT"}
    try:
        if (type(value) is not dict or set(value) not in (
                {"status", "completeness", "issue", "dependencies", "pages"},
                {"status", "completeness", "issue", "dependencies", "pages", "reason"},
                {"status", "completeness", "issue", "dependencies", "pages", "delivery_class"},
                {"status", "completeness", "issue", "dependencies", "pages", "delivery_class", "reason"})
                or value["status"] not in codes or value["completeness"] not in {"complete", "incomplete", "unknown"}
                or (value["status"] == "OK") != (value["completeness"] == "complete")
                or type(value["pages"]) is not int or not 0 <= value["pages"] <= 10
                or type(value["dependencies"]) is not list
                or len(json.dumps(value).encode()) > MAX_OBSERVATION):
            raise ValueError()
        if value["status"] == "OK" and value["pages"] < 1:
            raise ValueError()
        if value["status"] == "NOT_FOUND" and (value["completeness"] != "unknown" or value["issue"] is not None):
            raise ValueError()
        if "reason" in value and (value["status"] != "NOT_FOUND" or value["reason"] != "not-found-or-inaccessible"):
            raise ValueError()
        if "delivery_class" in value:
            classification = value["delivery_class"]
            if (type(classification) is not dict or set(classification) != {"status", "value", "pages"}
                    or classification["status"] not in {"known", "unknown"}
                    or type(classification["pages"]) is not int or not 0 <= classification["pages"] <= 10):
                raise ValueError()
            if classification["status"] == "known":
                if (type(classification["value"]) is not str or classification["value"] not in DELIVERY_CLASSES
                        or value["status"] != "OK" or classification["pages"] < 1):
                    raise ValueError()
            elif classification["value"] is not None:
                raise ValueError()
            if value["status"] == "OK" and classification["pages"] < 1:
                raise ValueError()
            if classification["pages"] and (value["issue"] is None or value["pages"] < 1):
                raise ValueError()
        issue = value["issue"]
        if issue is None:
            if value["completeness"] != "unknown" or value["dependencies"] or value["pages"]:
                raise ValueError()
        elif value["completeness"] == "unknown":
            raise ValueError()
        seen_ids, seen_numbers = set(), set()
        for item in ([issue] if issue is not None else []) + value["dependencies"]:
            keys = {"id", "number", "state", "assignees"} if item is issue else {"id", "number", "state"}
            if (type(item) is not dict or set(item) != keys or not _positive(item["id"])
                    or not _positive(item["number"]) or item["state"] not in {"open", "closed"}
                    or item["id"] in seen_ids or item["number"] in seen_numbers):
                raise ValueError()
            seen_ids.add(item["id"])
            seen_numbers.add(item["number"])
        if issue is not None:
            users = issue["assignees"]
            if type(users) is not list or len(users) > 100:
                raise ValueError()
            ids = set()
            for user in users:
                if (type(user) is not dict or set(user) != {"id", "login"} or not _positive(user["id"])
                        or type(user["login"]) is not str or not _LOGIN.fullmatch(user["login"])
                        or user["id"] in ids):
                    raise ValueError()
                ids.add(user["id"])
        return json.loads(json.dumps(value))
    except (ValueError, TypeError, KeyError, RecursionError):
        raise LedgerError("INVALID_PROVIDER_OBSERVATION") from None
