"""Structural validation of one complete proposed Project OKF result.

This is the Library's structural gate seam, not a publisher: it takes an
already authenticated Library scope, admitted settings, the current canonical
bundle tree and the complete proposed tree, and either refuses the whole
proposal with safe code/field evidence or returns the canonical tree to
publish. It opens no clone, writes no file, calls no model and touches no
projection, so a refusal cannot mutate its input, the canonical state or the
last coherent projection a reader still sees.

Structure only: content/link/secret policy (T05) and Git publication (T06)
compose this seam later. Reader tolerance is preserved by refusing only what
the trusted writer itself must not produce: unchanged existing documents keep
their unknown types, keys and unrelated authored material, and broken internal
targets stay readable observations instead of structural rejections.

Paths are required to be canonical rather than rewritten: the trusted writer
emits normalized POSIX paths, so a non-canonical proposal is refused instead
of silently folding two different caller spellings onto one path.
"""
from __future__ import annotations

from dataclasses import dataclass
import posixpath
import re
import unicodedata
from types import MappingProxyType

from . import library as contracts


ROOT_INDEX = "index.md"
LOG = "log.md"
PENDING = "pending"
DIRECTORIES = ("context", "decisions", "research")
DIRECTORY_TYPE = {"context": "context", "decisions": "decision", "research": "research"}
REQUIRED = (ROOT_INDEX, LOG, "context/index.md", "decisions/index.md",
            "research/index.md", "pending/index.md")
OKF_VERSION = "0.2"
STATUSES = ("draft", "stable", "deprecated")
# Supported v1 writer vocabulary. A document may also keep keys and a type it
# already carried, so tolerated existing reader data survives an update.
FIELDS = ("type", "title", "description", "status", "sources")
# YAML literals whose meaning depends on implicit type resolution; canonical
# Library text writes them as explicit strings or not at all. Numeric and
# timestamp-looking text stays a string, so OKF dates and counts round-trip.
UNSAFE_SCALARS = frozenset({"~", "null", "true", "false", "yes", "no", "on", "off"})
KEY = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
HEADING = re.compile(r"#{1,6}[ \t]+\S")
LOG_DATE = re.compile(r"## (\d{4}-\d{2}-\d{2})[ \t]*\Z")


@dataclass(frozen=True)
class Tree:
    """One Git-tree view: regular file bytes plus the symlink paths a Git tree can carry."""

    files: dict
    symlinks: tuple = ()

    def __post_init__(self):
        if type(self.files) is not dict:
            _fail("INVALID_CONTRACT", "tree.files")
        if type(self.symlinks) is not tuple:
            _fail("INVALID_CONTRACT", "tree.symlinks")
        object.__setattr__(self, "files", MappingProxyType(dict(self.files)))


@dataclass(frozen=True)
class Bundle:
    """Canonical accepted result: repository-relative files and bundle-relative changes."""

    prefix: str
    files: dict
    added: tuple
    updated: tuple
    removed: tuple


def _fail(code, field="$"):
    raise contracts.LibraryError(code, field)


# --- Trees, paths and canonical text --------------------------------------

def _tree(value, field):
    if type(value) is not Tree:
        _fail("INVALID_CONTRACT", field)
    for path in value.symlinks:
        _path(path, field)
        _fail("SYMLINK_NOT_ALLOWED", field + "." + path)
    return value


def _path(path, field):
    if type(path) is not str or not path:
        _fail("INVALID_PATH", field)
    if "\\" in path or path.startswith("/"):
        _fail("UNSAFE_PATH", field)
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail("UNSAFE_PATH", field)
    if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in path):
        _fail("UNSAFE_PATH", field)
    if unicodedata.normalize("NFC", path) != path:
        _fail("NON_CANONICAL_PATH", field)
    if posixpath.normpath(path) != path:
        _fail("UNSAFE_PATH", field)
    if ".git" in parts or parts[-1] == ".gitmodules":
        _fail("REPOSITORY_METADATA", field)
    return path


def _prefix(scope):
    """The one Project prefix derived from authenticated authority, never a caller."""
    if type(scope) is not contracts.LibraryScope:
        _fail("LIBRARY_AUTHENTICATION_REQUIRED", "scope")
    if scope.subject not in ("participant", "human"):
        _fail("FORBIDDEN", "scope.project_id")
    if scope.project_path is None or scope.project_identity is None:
        _fail("FORBIDDEN", "scope.project_id")
    return "projects/" + scope.project_path


def _canonical(path, data, field):
    if type(data) is not bytes:
        _fail("INVALID_TEXT", field)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _fail("MALFORMED_UTF8", field)
    if unicodedata.normalize("NFC", text) != text:
        _fail("NON_CANONICAL_TEXT", field)
    for character in text:
        point = ord(character)
        if character == "\r":
            _fail("CR_LINE_ENDING", field)
        if (point < 32 and character not in "\n\t") or 127 <= point < 160:
            _fail("DISALLOWED_CONTROL", field)
    return text


def _canonical_files(tree, prefix, limits, field):
    """Validate this Project's paths and text, then return bundle-relative text."""
    files, seen = {}, {}
    if not tree.files:
        return files
    for path, data in tree.files.items():
        _path(path, field)
        if not path.startswith(prefix + "/"):
            _fail("FOREIGN_PROJECT", field + "." + str(path))
        folded = path.casefold()
        if folded in seen and seen[folded] != path:
            _fail("PATH_COLLISION", field + "." + path)
        seen[folded] = path
        relative = path[len(prefix) + 1:]
        files[relative] = (path, _canonical(path, data, field + "." + path))
    if len(files) > limits["scan_documents"]:
        _fail("TOO_MANY_DOCUMENTS", field)
    total = 0
    for path, text in files.values():
        size = len(text.encode("utf-8"))
        if size > limits["document_bytes"]:
            _fail("DOCUMENT_TOO_LARGE", field + "." + path)
        total += size
    if total > limits["projection_bytes"]:
        _fail("BUNDLE_TOO_LARGE", field)
    return files


# --- YAML frontmatter -----------------------------------------------------

def _quoted(raw, field):
    quote, value, index = raw[0], [], 1
    while index < len(raw):
        character = raw[index]
        if character == quote:
            if quote == "'" and raw[index + 1:index + 2] == "'":
                value.append("'")
                index += 2
                continue
            if raw[index + 1:].strip():
                _fail("INVALID_YAML", field)
            return "".join(value)
        if quote == '"' and character == "\\":
            escape = raw[index + 1:index + 2]
            if escape not in ('"', "\\", "/", "n", "t", "u"):
                _fail("UNSAFE_YAML", field)
            if escape == "u":
                digits = raw[index + 2:index + 6]
                if len(digits) != 4 or not all(c in "0123456789abcdefABCDEF" for c in digits):
                    _fail("INVALID_YAML", field)
                value.append(chr(int(digits, 16)))
                index += 6
                continue
            value.append({"n": "\n", "t": "\t"}.get(escape, escape))
            index += 2
            continue
        value.append(character)
        index += 1
    _fail("INVALID_YAML", field)


def _flow_split(raw, field):
    """Split a flow collection body on top-level commas, honouring quotes and nesting."""
    parts, depth, start, quote = [], 0, 0, None
    for index, character in enumerate(raw):
        if quote:
            if character == quote and not (quote == "'" and raw[index - 1:index] == "'"):
                quote = None
            continue
        if character in "\"'":
            quote = character
        elif character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
        elif character == "," and depth == 0:
            parts.append(raw[start:index])
            start = index + 1
    parts.append(raw[start:])
    return [part for part in parts]


def _flow(raw, field, depth):
    closing = "]" if raw[0] == "[" else "}"
    if not raw.endswith(closing):
        _fail("INVALID_YAML", field)
    body = raw[1:-1].strip()
    items = [item.strip() for item in _flow_split(body, field)] if body else []
    if "" in items:
        _fail("INVALID_YAML", field)
    if closing == "]":
        return [_scalar(item, field, depth + 1) for item in items]
    mapping = {}
    for item in items:
        key, rest = _split_key(item)
        if not rest:
            _fail("UNSAFE_SCALAR", field)
        if key in mapping:
            _fail("DUPLICATE_YAML_KEY", field + "." + key)
        mapping[key] = _scalar(rest, field + "." + key, depth + 1)
    return mapping


def _scalar(raw, field, depth=0):
    if depth > 8:
        _fail("INVALID_YAML", field)
    value = raw.strip()
    if not value:
        _fail("UNSAFE_SCALAR", field)
    if value[0] in "&*!":
        _fail("UNSAFE_YAML", field)
    if value[0] in "|>":
        _fail("UNSAFE_YAML", field)
    if value[0] in "[{":
        return _flow(value, field, depth)
    if value[0] in "\"'":
        return _quoted(value, field)
    if value[0] in "%?@`":
        _fail("UNSAFE_YAML", field)
    if value.lower() in UNSAFE_SCALARS:
        _fail("UNSAFE_SCALAR", field)
    return value


def _split_key(content):
    """Split `key: value` (or `key:`) without treating a URL colon as a key break."""
    if content.endswith(":"):
        return content[:-1].strip(), ""
    index = content.find(": ")
    if index < 0:
        return "", ""
    return content[:index].strip(), content[index + 2:]


def _strip_comment(raw):
    quote = None
    for index, character in enumerate(raw):
        if quote:
            if character == quote:
                quote = None
        elif character in "\"'":
            quote = character
        elif character == "#" and (index == 0 or raw[index - 1] == " "):
            return raw[:index]
    return raw


def _lines(block, field):
    parsed = []
    for raw in block:
        if "\t" in raw:
            _fail("UNSAFE_YAML", field)
        content = _strip_comment(raw).strip()
        if content:
            parsed.append((len(raw) - len(raw.lstrip(" ")), content))
    return parsed


def _mapping(lines, index, indent, field):
    result = {}
    while index < len(lines):
        current, content = lines[index]
        if current < indent:
            break
        if current > indent or content == "-" or content.startswith("- "):
            _fail("INVALID_YAML", field)
        key, rest = _split_key(content)
        if not KEY.fullmatch(key):
            _fail("UNSAFE_YAML", field)
        if key in result:
            _fail("DUPLICATE_YAML_KEY", field + "." + key)
        index += 1
        if rest:
            result[key] = _scalar(rest, field + "." + key)
        elif index < len(lines) and lines[index][0] > indent:
            result[key], index = _block(lines, index, lines[index][0], field + "." + key)
        else:
            _fail("UNSAFE_SCALAR", field + "." + key)
    return result, index


def _block(lines, index, indent, field):
    if lines[index][1] == "-" or lines[index][1].startswith("- "):
        return _sequence(lines, index, indent, field)
    return _mapping(lines, index, indent, field)


def _sequence(lines, index, indent, field):
    items = []
    while index < len(lines):
        current, content = lines[index]
        if current < indent:
            break
        if current > indent or not (content == "-" or content.startswith("- ")):
            _fail("INVALID_YAML", field)
        rest = content[1:].strip()
        entry = field + "[%d]" % len(items)
        key, value = _split_key(rest)
        if rest and rest[0] not in "\"'" and KEY.fullmatch(key) and value:
            sub = [(indent + 2, rest)]
            index += 1
            while index < len(lines) and lines[index][0] > indent:
                sub.append(lines[index])
                index += 1
            item, consumed = _mapping(sub, 0, indent + 2, entry)
            if consumed != len(sub):
                _fail("INVALID_YAML", entry)
            items.append(item)
        else:
            items.append(_scalar(rest, entry))
            index += 1
    return items, index


def _frontmatter(text, field):
    """Split canonical Markdown into (frontmatter mapping, body) with strict YAML."""
    lines = text.split("\n")
    if lines[0] != "---":
        _fail("MISSING_FRONTMATTER", field)
    for index in range(1, len(lines)):
        if lines[index] == "---":
            block = _lines(lines[1:index], field)
            if not block:
                return {}, "\n".join(lines[index + 1:])
            if block[0][0] != 0:
                _fail("INVALID_YAML", field)
            value, consumed = _mapping(block, 0, 0, field)
            if consumed != len(block):
                _fail("INVALID_YAML", field)
            return value, "\n".join(lines[index + 1:])
    _fail("MISSING_FRONTMATTER", field)


def _optional_frontmatter(text, field):
    if text.startswith("---\n"):
        return _frontmatter(text, field)
    return {}, text


# --- Markdown structure ---------------------------------------------------

def _scan(body):
    """Yield inline link targets outside fenced code blocks and code spans."""
    fence = None
    for line in body.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            fence = None if fence == marker else (fence or marker)
            continue
        if fence:
            continue
        index = 0
        while index < len(line):
            character = line[index]
            if character == "`":
                closing = line.find("`", index + 1)
                index = len(line) if closing < 0 else closing + 1
                continue
            if character == "!" and line[index + 1:index + 2] == "[":
                index += 1
                continue
            if character == "]" and line[index + 1:index + 2] == "(":
                closing, depth = index + 2, 1
                while closing < len(line) and depth:
                    depth += {"(": 1, ")": -1}.get(line[closing], 0)
                    closing += 1
                if depth == 0:
                    yield line[index + 2:closing - 1]
                index = closing
                continue
            index += 1


def _target(target, index_relative):
    value = target.strip()
    if not value or value.startswith("#"):
        return None
    if value[:1] in "\"'<":
        value = value[1:]
        if value[-1:] in "\"'>":
            value = value[:-1]
    elif " " in value:
        value = value.split(" ", 1)[0]
    if SCHEME.match(value) or value.startswith("//"):
        return None
    value = value.split("#", 1)[0]
    if not value:
        return None
    if value.startswith("/"):
        candidate = value.lstrip("/")
    else:
        base = posixpath.dirname(index_relative)
        candidate = posixpath.normpath(posixpath.join(base, value))
    if candidate.startswith("..") or candidate.startswith("/"):
        return None
    return candidate


def _links(body, index_relative):
    found = set()
    for target in _scan(body):
        candidate = _target(target, index_relative)
        if candidate is not None:
            found.add(candidate)
    return found


def _headings(body):
    return any(HEADING.match(line) for line in body.split("\n"))


# --- Bundle relationships -------------------------------------------------

def _classify(relative):
    parts = relative.split("/")
    if relative in (ROOT_INDEX, LOG):
        return "reserved", None, None
    if len(parts) != 2 or parts[0] not in DIRECTORIES + (PENDING,):
        return "unknown", None, None
    if parts[1] == "index.md":
        return "index", parts[0], None
    if parts[1].endswith(".md") and len(parts[1]) > 3:
        return "concept", parts[0], parts[1][:-3]
    return "unknown", None, None


def _concept(relative, directory, name, text, previous):
    meta, _body = _frontmatter(text, relative)
    previous_meta = _frontmatter(previous, relative)[0] if previous is not None else {}
    declared = meta.get("type")
    if type(declared) is not str or not declared.strip():
        _fail("MISSING_TYPE", relative + ".type")
    if previous is not None and previous == text:
        return  # tolerated reader data: unknown types, keys and authored material stay readable
    for key in meta:
        if key not in FIELDS and key not in previous_meta:
            _fail("UNSUPPORTED_FIELD", relative + "." + key)
    for key in ("type", "title"):
        if key not in meta:
            _fail("MISSING_FIELD", relative + "." + key)
    title = meta["title"]
    if type(title) is not str or not title.strip() or "\n" in title:
        _fail("INVALID_TEXT", relative + ".title")
    description = meta.get("description")
    if description is not None and (not isinstance(description, str) or "\n" in description):
        _fail("INVALID_TEXT", relative + ".description")
    status = meta.get("status")
    if status is not None and status not in STATUSES:
        _fail("UNSUPPORTED_STATUS", relative + ".status")
    if directory == PENDING:
        if status != "draft":
            _fail("INCOHERENT_STATUS", relative + ".status")
        if not contracts.DIGEST.fullmatch(name):
            _fail("PENDING_PATH_NOT_QUEUE_DERIVED", relative)
        if declared not in contracts.CAPTURE_TYPES and declared != previous_meta.get("type"):
            _fail("UNSUPPORTED_TYPE", relative + ".type")
    else:
        if status == "draft":
            _fail("INCOHERENT_STATUS", relative + ".status")
        if declared != DIRECTORY_TYPE[directory] and declared != previous_meta.get("type"):
            _fail("TYPE_MISMATCH", relative + ".type")
        if not contracts.SLUG.fullmatch(name):
            _fail("UNSAFE_PATH", relative)
    if "sources" in meta:
        sources = meta["sources"]
        if type(sources) is not list or not sources:
            _fail("INVALID_SOURCES", relative + ".sources")
        for index, source in enumerate(sources):
            field = "%s.sources[%d]" % (relative, index)
            if type(source) is not dict or type(source.get("resource")) is not str:
                _fail("INVALID_SOURCES", field + ".resource")
            if not source["resource"].strip() or "\n" in source["resource"]:
                _fail("INVALID_SOURCES", field + ".resource")


def _index(relative, text, empty):
    meta, body = _optional_frontmatter(text, relative)
    if meta:
        _fail("UNEXPECTED_FRONTMATTER", relative)
    if not _headings(body):
        _fail("INVALID_INDEX", relative)
    links = _links(body, relative)
    if empty and links:
        _fail("INITIALIZATION_NOT_EMPTY", relative)
    return links


def _root_index(text, scope):
    meta, body = _frontmatter(text, ROOT_INDEX)
    if set(meta) != {"okf_version"} or meta["okf_version"] != OKF_VERSION:
        _fail("INVALID_OKF_VERSION", ROOT_INDEX + ".okf_version")
    links = _links(body, ROOT_INDEX)
    for required in ("context/index.md", "decisions/index.md", "research/index.md",
                     "pending/index.md"):
        if required not in links:
            _fail("MISSING_INDEX_LINK", ROOT_INDEX + "." + required)
    for value, field in ((scope.project_path, "project_path"),
                         (scope.project_identity, "project_identity")):
        if value not in body:
            _fail("MISSING_SOURCE_IDENTITY", ROOT_INDEX + "." + field)


def _log(text, previous):
    meta, body = _optional_frontmatter(text, LOG)
    if meta:
        _fail("UNEXPECTED_FRONTMATTER", LOG)
    found = [match.group(1) for match in
             (LOG_DATE.match(line) for line in body.split("\n")) if match]
    if not found:
        _fail("MISSING_LOG_ENTRY", LOG)
    for value in found:
        if not _date(value):
            _fail("INVALID_LOG_DATE", LOG)
    if previous is not None:
        old_body = _optional_frontmatter(previous, LOG)[1]
        remaining = iter(body.split("\n"))
        for line in old_body.split("\n"):
            if not line.strip():
                continue
            if not any(line == candidate for candidate in remaining):
                _fail("LOG_HISTORY_REWRITTEN", LOG)


def _date(value):
    year, month, day = (int(part) for part in value.split("-"))
    days = [31, 29 if year % 4 == 0 and (year % 100 or year % 400 == 0) else 28,
            31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return 1 <= month <= 12 and 1 <= day <= days[month - 1]


def _removals(previous, current, selected):
    allowed = set()
    for queue_id in selected:
        if type(queue_id) is not str or not contracts.DIGEST.fullmatch(queue_id):
            _fail("INVALID_DIGEST", "selected")
        allowed.add(PENDING + "/" + queue_id + ".md")
    removed = []
    for relative in previous:
        if relative in current:
            continue
        if _classify(relative)[0] != "concept" or not relative.startswith(PENDING + "/"):
            _fail("EXISTING_DATA_DELETION", relative)
        if relative not in allowed:
            _fail("UNSELECTED_PENDING_REMOVAL", relative)
        removed.append(relative)
    return tuple(sorted(removed))


# --- Public seam ----------------------------------------------------------

def validate(scope, settings, *, proposed, current=None, selected=()):
    """Validate the complete proposed Project result, or refuse all of it.

    ``current`` is the canonical bundle tree or ``None`` before registration,
    ``proposed`` is the complete tree the operation wants published, and
    ``selected`` names the queue identities the operation may integrate out of
    ``pending/``. A refusal raises ``LibraryError`` and mutates nothing.
    """
    limits = contracts.admit_settings_value(settings)["limits"]
    prefix = _prefix(scope)
    if type(selected) is not tuple and type(selected) is not list:
        _fail("INVALID_CONTRACT", "selected")
    if len(selected) > limits["batch_drafts"]:
        _fail("TOO_MANY_SELECTED", "selected")
    previous_tree = None if current is None else _tree(current, "current")
    proposed_tree = _tree(proposed, "proposed")
    previous = ({} if previous_tree is None
                else _canonical_files(previous_tree, prefix, limits, "current"))
    files = _canonical_files(proposed_tree, prefix, limits, "proposed")

    if previous_tree is None:
        extra = set(files) - set(REQUIRED)
        if extra:
            _fail("INITIALIZATION_NOT_EMPTY", sorted(extra)[0])
        for required in REQUIRED:
            if required not in files:
                _fail("MISSING_REQUIRED_FILE", required)
    else:
        for required in REQUIRED:
            if required not in previous:
                _fail("MALFORMED_EXISTING_BUNDLE", required)
            if required not in files:
                _fail("MISSING_REQUIRED_FILE", required)

    removed = _removals(previous, files, selected)
    for relative, (_path_value, text) in files.items():
        kind, directory, name = _classify(relative)
        before = previous.get(relative)
        previous_text = before[1] if before else None
        if kind == "reserved":
            continue
        if kind == "unknown":
            if previous_text is None or previous_text != text:
                _fail("UNSUPPORTED_PATH", relative)
            continue
        if kind == "concept":
            _concept(relative, directory, name, text, previous_text)

    _root_index(files[ROOT_INDEX][1], scope)
    _log(files[LOG][1], previous[LOG][1] if previous else None)
    empty = previous_tree is None
    for directory in DIRECTORIES + (PENDING,):
        relative = directory + "/index.md"
        links = _index(relative, files[relative][1], empty)
        for other in files:
            other_kind, other_directory, _name = _classify(other)
            if other_kind == "concept" and other_directory == directory and other not in links:
                _fail("MISSING_INDEX_ENTRY", relative + "." + other)

    added = tuple(sorted(set(files) - set(previous)))
    updated = tuple(sorted(relative for relative in files
                           if relative in previous and previous[relative][1] != files[relative][1]))
    return Bundle(prefix=prefix,
                  files=MappingProxyType({full: text.encode("utf-8")
                                          for full, text in files.values()}),
                  added=added, updated=updated, removed=removed)
