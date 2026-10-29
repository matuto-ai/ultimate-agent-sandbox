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
# Plain YAML scalars a conforming reader may resolve to a non-string type. The
# gate keeps them as text, so tolerated existing reader data still round-trips,
# and refuses them where the v1 writer owns the value.
UNSAFE_SCALARS = frozenset({"~", "null", "true", "false", "yes", "no", "on", "off", "y", "n",
                            ".nan", ".inf", "-.inf", "+.inf"})
INTEGER = re.compile(r"[-+]?(?:0[box][0-9a-fA-F_]+|[0-9][0-9_]*)\Z")
SEXAGESIMAL = re.compile(r"[-+]?[0-9]+(?::[0-5]?[0-9])+\Z")
FLOAT = re.compile(r"[-+]?(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9][0-9_]*)(?:[eE][-+]?[0-9]+)?\Z"
                   r"|[-+]?[0-9][0-9_]*[eE][-+]?[0-9]+\Z")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ].*)?\Z")
# Service-stamped fidelity fields: the deterministic service owns them, so a
# structural gate neither invents their semantics (T05) nor freezes them. A
# caller- or model-supplied value is refused by proposal/content admission,
# not by re-reading intent from the final tree.
SERVICE_FIELDS = ("verified", "stale_after", "generated")
MAX_EVIDENCE = 200
MAX_PATH = 1024
MAX_COMPONENT = 255
MAX_YAML_DEPTH = 8
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


class Implicit(str):
    """A plain scalar a conforming YAML reader may resolve to a non-string type."""


def _fail(code, field="$"):
    raise contracts.LibraryError(code, str(field)[:MAX_EVIDENCE])


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
    if posixpath.normpath(path) != path or len(path) > MAX_PATH:
        _fail("UNSAFE_PATH", field)
    if any(len(part) > MAX_COMPONENT for part in parts):
        _fail("UNSAFE_PATH", field)
    folded = [part.casefold() for part in parts]
    if ".git" in folded or folded[-1] == ".gitmodules":
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


def _text_check(value, field):
    """Canonical text rules, also applied to scalars decoded from YAML escapes."""
    if unicodedata.normalize("NFC", value) != value:
        _fail("NON_CANONICAL_TEXT", field)
    for character in value:
        point = ord(character)
        if character == "\r":
            _fail("CR_LINE_ENDING", field)
        if character in "\u2028\u2029":
            _fail("DISALLOWED_CONTROL", field)
        if 0xD800 <= point <= 0xDFFF:
            _fail("MALFORMED_UTF8", field)
        if (point < 32 and character not in "\n\t") or 127 <= point < 160:
            _fail("DISALLOWED_CONTROL", field)
    return value


def _canonical(path, data, field):
    if type(data) is not bytes:
        _fail("INVALID_TEXT", field)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _fail("MALFORMED_UTF8", field)
    return _text_check(text, field)


def _canonical_files(tree, prefix, limits, field):
    """Validate this Project's paths and text, then return bundle-relative text."""
    files, seen = {}, {}
    if not tree.files:
        return files
    for path, data in tree.files.items():
        _path(path, field)
        if not path.startswith(prefix + "/"):
            _fail("FOREIGN_PROJECT", field)
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
            return _text_check("".join(value), field)
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
        if not KEY.fullmatch(key):
            _fail("UNSAFE_YAML", field)
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
    if value[0] in "%?@`=":
        _fail("UNSAFE_YAML", field)
    if ": " in value:
        _fail("UNSAFE_YAML", field)
    if value.lower() in UNSAFE_SCALARS:
        return Implicit(value)
    if INTEGER.fullmatch(value) or FLOAT.fullmatch(value) or SEXAGESIMAL.fullmatch(value):
        return Implicit(value)
    if DATE.fullmatch(value):
        return Implicit(value)
    return value


def _same(left, right, depth=0):
    """Deep equality that also keeps an implicit YAML kind distinct from text."""
    if depth > MAX_YAML_DEPTH:
        return False
    if isinstance(left, Implicit) != isinstance(right, Implicit):
        return False
    if type(left) is dict:
        return (type(right) is dict and set(left) == set(right)
                and all(_same(left[key], right[key], depth + 1) for key in left))
    if type(left) is list:
        return (type(right) is list and len(left) == len(right)
                and all(_same(a, b, depth + 1) for a, b in zip(left, right)))
    return left == right


def _implicit(value):
    """True when this parsed value carries an implicit non-string YAML type."""
    if isinstance(value, Implicit):
        return True
    if type(value) is list:
        return any(_implicit(item) for item in value)
    if type(value) is dict:
        return any(_implicit(item) for item in value.values())
    return False


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


def _mapping(lines, index, indent, field, depth):
    if depth > MAX_YAML_DEPTH:
        _fail("INVALID_YAML", field)
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
            result[key], index = _block(lines, index, lines[index][0],
                                        field + "." + key, depth + 1)
        else:
            _fail("UNSAFE_SCALAR", field + "." + key)
    return result, index


def _block(lines, index, indent, field, depth):
    if lines[index][1] == "-" or lines[index][1].startswith("- "):
        return _sequence(lines, index, indent, field, depth)
    return _mapping(lines, index, indent, field, depth)


def _sequence(lines, index, indent, field, depth):
    if depth > MAX_YAML_DEPTH:
        _fail("INVALID_YAML", field)
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
            item, consumed = _mapping(sub, 0, indent + 2, entry, depth + 1)
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
            value, consumed = _mapping(block, 0, 0, field, 0)
            if consumed != len(block):
                _fail("INVALID_YAML", field)
            return value, "\n".join(lines[index + 1:])
    _fail("MISSING_FRONTMATTER", field)


# --- Markdown structure ---------------------------------------------------

def _scan(body):
    """Yield (link text, target) for inline links outside fenced code and code spans.

    The canonical Library writer emits inline links, so reference-style link
    definitions are not resolved here; a reference-style index entry reads as a
    missing index entry instead of being guessed at.
    """
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
                    opening = line.rfind("[", 0, index)
                    yield (line[opening + 1:index] if opening >= 0 else "",
                           line[index + 2:closing - 1])
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
    found = {}
    for text, target in _scan(body):
        candidate = _target(target, index_relative)
        if candidate is not None:
            found[candidate] = text.strip()
    return found


def _headings(body):
    return any(HEADING.match(line) for line in body.split("\n"))


def _entries(body):
    return [line for line in body.split("\n")
            if line.lstrip()[:2] in ("- ", "* ", "+ ")]


def _plain(text, relative):
    """Reserved files (index/log) carry no frontmatter block at all, even an empty one."""
    if text.startswith("---\n"):
        _fail("UNEXPECTED_FRONTMATTER", relative)
    return text


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


def _concept(relative, directory, name, text, previous, selected, limits):
    """Validate one concept document against its directory and its own history."""
    meta, _body = _frontmatter(text, relative)
    previous_meta = _frontmatter(previous, relative)[0] if previous is not None else {}
    declared = meta.get("type")
    if not isinstance(declared, str) or not declared.strip():
        _fail("MISSING_TYPE", relative + ".type")
    status = meta.get("status")
    if status is not None and status not in STATUSES:
        _fail("UNSUPPORTED_STATUS", relative + ".status")
    if directory == PENDING:
        if status != "draft":
            _fail("INCOHERENT_STATUS", relative + ".status")
    else:
        if status == "draft":
            _fail("INCOHERENT_STATUS", relative + ".status")
        # A tolerated unknown existing type stays readable; a supported v1 type
        # never sits in another directory.
        if declared in contracts.CAPTURE_TYPES and declared != DIRECTORY_TYPE[directory]:
            _fail("TYPE_MISMATCH", relative + ".type")
    if declared == "research" and not meta.get("sources"):
        _fail("SOURCE_REQUIRED", relative + ".sources")
    writer = previous is None or previous != text
    _sources(relative, meta.get("sources"), limits, previous_meta, writer)
    if not writer:
        return meta.get("title")
    for key in meta:
        if key not in FIELDS and key not in SERVICE_FIELDS and key not in previous_meta:
            _fail("UNSUPPORTED_FIELD", relative + "." + key)
    for key in ("type", "title"):
        if key not in meta:
            _fail("MISSING_FIELD", relative + "." + key)
    title = meta["title"]
    if not isinstance(title, str) or not title.strip() or "\n" in title:
        _fail("INVALID_TEXT", relative + ".title")
    if len(title) > limits["title_chars"]:
        _fail("TITLE_TOO_LONG", relative + ".title")
    description = meta.get("description")
    if description is not None and (not isinstance(description, str) or "\n" in description):
        _fail("INVALID_TEXT", relative + ".description")
    for key, value in meta.items():
        # Service-stamped fidelity values are the trusted writer's own; every
        # other writer value must be an explicit string.
        if key in SERVICE_FIELDS or (key in previous_meta and key not in FIELDS):
            continue
        if _implicit(value):
            _fail("UNSAFE_SCALAR", relative + "." + key)
    previous_type = previous_meta.get("type")
    if previous_type is not None and previous_type not in contracts.CAPTURE_TYPES:
        if declared != previous_type:
            _fail("TYPE_MISMATCH", relative + ".type")
    elif directory == PENDING:
        if declared not in contracts.CAPTURE_TYPES:
            _fail("UNSUPPORTED_TYPE", relative + ".type")
        if not contracts.DIGEST.fullmatch(name):
            _fail("PENDING_PATH_NOT_QUEUE_DERIVED", relative)
    else:
        if declared != DIRECTORY_TYPE[directory]:
            _fail("TYPE_MISMATCH", relative + ".type")
        if not contracts.SLUG.fullmatch(name):
            _fail("UNSAFE_PATH", relative)
    # Tolerated existing keys stay with their document: an update may not drop,
    # rewrite or retype reader data it did not author here. Document size is
    # bounded by document_bytes; body_bytes bounds one capture/proposal input,
    # which a merged concept may exceed.
    for key, value in previous_meta.items():
        if key in FIELDS or key in SERVICE_FIELDS:
            continue
        if key not in meta or not _same(value, meta[key]):
            _fail("EXISTING_FIELD_CHANGED", relative + "." + key)
    return title


def _sources(relative, sources, limits, previous_meta, writer):
    """Structural provenance: a bounded list of entries, each naming its resource."""
    if sources is None:
        return
    if type(sources) is not list or not sources:
        _fail("INVALID_SOURCES", relative + ".sources")
    if len(sources) > limits["sources"]:
        _fail("TOO_MANY_SOURCES", relative + ".sources")
    previous = [entry for entry in (previous_meta.get("sources") or [])
                if type(entry) is dict]
    allowed = {"resource", "title"}
    for entry in previous:
        allowed.update(entry)
    for index, source in enumerate(sources):
        field = "%s.sources[%d]" % (relative, index)
        if type(source) is not dict or not isinstance(source.get("resource"), str):
            _fail("INVALID_SOURCES", field + ".resource")
        if not source["resource"].strip() or "\n" in source["resource"]:
            _fail("INVALID_SOURCES", field + ".resource")
        if not writer:
            continue
        for key in source:
            if key not in allowed:
                _fail("UNSUPPORTED_FIELD", field + "." + key)
        if "title" in source:
            title = source["title"]
            if not isinstance(title, str) or "\n" in title:
                _fail("INVALID_SOURCES", field + ".title")
            if len(title) > limits["title_chars"]:
                _fail("TITLE_TOO_LONG", field + ".title")
        if _implicit(source):
            _fail("UNSAFE_SCALAR", field)
    if writer:
        _preserved_sources(relative, previous, sources)


def _preserved_sources(relative, previous, sources):
    """Existing source metadata stays with its resource, value and YAML kind."""
    for entry in previous:
        match = next((source for source in sources
                      if type(source) is dict
                      and _same(entry.get("resource"), source.get("resource"))), None)
        if match is None:
            _fail("EXISTING_FIELD_CHANGED", relative + ".sources")
        for key, value in entry.items():
            if key == "resource":
                continue
            if key not in match or not _same(value, match[key]):
                _fail("EXISTING_FIELD_CHANGED", relative + ".sources." + key)


def _index(relative, text, empty):
    body = _plain(text, relative)
    if not _headings(body):
        _fail("INVALID_INDEX", relative)
    links = _links(body, relative)
    if empty and (links or _entries(body)):
        _fail("INITIALIZATION_NOT_EMPTY", relative)
    return links


def _root_index(text, scope):
    meta, body = _frontmatter(text, ROOT_INDEX)
    if (set(meta) != {"okf_version"} or type(meta["okf_version"]) is not str
            or isinstance(meta["okf_version"], Implicit)
            or meta["okf_version"] != OKF_VERSION):
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


def _log(text, previous, initialization):
    body = _plain(text, LOG)
    found = [match.group(1) for match in
             (LOG_DATE.match(line) for line in body.split("\n")) if match]
    if not found:
        _fail("MISSING_LOG_ENTRY", LOG)
    for value in found:
        if not _date(value):
            _fail("INVALID_LOG_DATE", LOG)
    entries = _entries(body)
    if initialization:
        if len(found) != 1 or len(entries) != 1 or "**Initialization**" not in entries[0]:
            _fail("INITIALIZATION_LOG_FORM", LOG)
        return
    # Parked drafts stay in pending/ with draft status and an index entry; the
    # PARKED/DRAFT label itself is writer output and content policy (T05).
    if previous is not None:
        old_body = _plain(previous, LOG)
        remaining = iter(body.split("\n"))
        for line in old_body.split("\n"):
            if not line.strip():
                continue
            if not any(line == candidate for candidate in remaining):
                _fail("LOG_HISTORY_REWRITTEN", LOG)


def _date(value):
    year, month, day = (int(part) for part in value.split("-"))
    if not 1 <= year <= 9999:
        return False
    days = [31, 29 if year % 4 == 0 and (year % 100 or year % 400 == 0) else 28,
            31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return 1 <= month <= 12 and 1 <= day <= days[month - 1]


def _selected(selected, limits):
    """Selected queue identities, turned into the only pending paths they may affect."""
    if type(selected) is not tuple and type(selected) is not list:
        _fail("INVALID_CONTRACT", "selected")
    if len(selected) > limits["batch_drafts"]:
        _fail("TOO_MANY_SELECTED", "selected")
    allowed = set()
    for queue_id in selected:
        if type(queue_id) is not str or not contracts.DIGEST.fullmatch(queue_id):
            _fail("INVALID_DIGEST", "selected")
        allowed.add(PENDING + "/" + queue_id + ".md")
    return allowed


def _removals(previous, current, allowed):
    removed = []
    for relative, (_full, text) in previous.items():
        if relative in current:
            continue
        if _classify(relative)[0] != "concept" or not relative.startswith(PENDING + "/"):
            _fail("EXISTING_DATA_DELETION", relative)
        if relative not in allowed:
            _fail("UNSELECTED_PENDING_REMOVAL", relative)
        meta = _frontmatter(text, relative)[0]
        if meta.get("status") != "draft":
            _fail("NOT_A_PENDING_DRAFT", relative)
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
    allowed = _selected(selected, limits)
    previous_tree = None if current is None else _tree(current, "current")
    proposed_tree = _tree(proposed, "proposed")
    previous = ({} if previous_tree is None
                else _canonical_files(previous_tree, prefix, limits, "current"))
    files = _canonical_files(proposed_tree, prefix, limits, "proposed")

    initialization = previous_tree is None
    # The canonical state must stay coherent too: a conflicting registration or
    # a malformed existing bundle fails closed instead of being overwritten.
    if not initialization:
        _structure(previous, previous, scope, limits, set(), False)
    removed = _structure(files, previous, scope, limits, allowed, initialization)
    added = tuple(sorted(set(files) - set(previous)))
    updated = tuple(sorted(relative for relative in files
                           if relative in previous
                           and previous[relative][1] != files[relative][1]))
    return Bundle(prefix=prefix,
                  files=MappingProxyType({full: text.encode("utf-8")
                                          for full, text in files.values()}),
                  added=added, updated=updated, removed=removed)


def _structure(files, previous, scope, limits, allowed, initialization):
    """Check one complete tree against its predecessor; returns removed drafts."""
    if initialization:
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

    removed = _removals(previous, files, allowed)
    titles = {}
    for relative, (_full, text) in files.items():
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
            if (directory == PENDING and previous_text is not None
                    and previous_text != text and relative not in allowed):
                _fail("UNSELECTED_PENDING_MUTATION", relative)
            titles[relative] = _concept(relative, directory, name, text,
                                        previous_text, allowed, limits)

    _root_index(files[ROOT_INDEX][1], scope)
    _log(files[LOG][1], previous[LOG][1] if previous else None, initialization)
    for directory in DIRECTORIES + (PENDING,):
        relative = directory + "/index.md"
        links = _index(relative, files[relative][1], initialization)
        for other in files:
            other_kind, other_directory, _name = _classify(other)
            if other_kind != "concept" or other_directory != directory:
                continue
            if other not in links:
                _fail("MISSING_INDEX_ENTRY", relative + "." + other)
            title = titles.get(other)
            if title is not None and links[other] != title:
                _fail("INDEX_TITLE_MISMATCH", relative + "." + other)
    return removed
