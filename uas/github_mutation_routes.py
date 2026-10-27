"""One bounded native mutation vocabulary; no endpoints or credentials in argv.

The Supervisor supplies the pinned Project and allowed work labels. A route is
not authority: the Broker still authenticates the Actor and each fact's owner.
Only stdin may supply a body file; no Participant path is opened by this module.
"""
from dataclasses import dataclass
import re
from types import MappingProxyType

from .github_read import GitHubProject
from .ledger import LedgerError

MAX_BODY = 512 * 1024
MAX_ARGV = MAX_BODY + 16384
MAX_ARGUMENTS = 64
MAX_LABELS = 20
_NUMBER = re.compile(r'[1-9][0-9]{0,18}\Z')
_SHA = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
_RESERVED = ('agent:', 'status:', 'run:', 'lifecycle:')
_BOOL = frozenset({'draft', 'approve', 'request-changes', 'comment'})
_LIST = frozenset({'add-assignee', 'remove-assignee', 'add-label', 'remove-label'})
_NORMALIZE = {'assignee': 'add-assignee', 'label': 'add-label'}
_ALIASES = {'-R': 'repo', '-t': 'title', '-b': 'body', '-F': 'body-file',
            '-B': 'base', '-H': 'head', '-d': 'draft'}
_BODY = ('body', 'body-file')


@dataclass(frozen=True)
class MutationSpec:
    kind: str
    words: tuple
    numbered: bool
    flags: tuple
    required: tuple = ()


_ROUTES = (
    MutationSpec('issue-create', ('issue', 'create'), False,
                 ('title', *_BODY, 'assignee', 'label'), ('title', 'body')),
    MutationSpec('issue-edit', ('issue', 'edit'), True,
                 ('title', *_BODY, 'add-assignee', 'remove-assignee', 'add-label', 'remove-label')),
    MutationSpec('issue-close', ('issue', 'close'), True, ('reason',)),
    MutationSpec('issue-reopen', ('issue', 'reopen'), True, ()),
    MutationSpec('issue-comment', ('issue', 'comment'), True, _BODY, ('body',)),
    MutationSpec('pr-create', ('pr', 'create'), False,
                 ('title', *_BODY, 'head', 'base', 'draft', 'assignee', 'label'),
                 ('title', 'body', 'head', 'base')),
    MutationSpec('pr-edit', ('pr', 'edit'), True,
                 ('title', *_BODY, 'base', 'add-assignee', 'remove-assignee', 'add-label', 'remove-label')),
    MutationSpec('pr-close', ('pr', 'close'), True, ()),
    MutationSpec('pr-reopen', ('pr', 'reopen'), True, ()),
    MutationSpec('pr-comment', ('pr', 'comment'), True, _BODY, ('body',)),
    MutationSpec('pr-reply', ('pr', 'reply'), True,
                 ('comment-id', *_BODY), ('comment-id', 'body')),
    MutationSpec('pr-review', ('pr', 'review'), True,
                 ('approve', 'request-changes', 'comment', 'commit', *_BODY), ('commit',)),
    MutationSpec('dependency-add', ('issue', 'dependency', 'add'), True,
                 ('blocked-by',), ('blocked-by',)),
    MutationSpec('dependency-remove', ('issue', 'dependency', 'remove'), True,
                 ('blocked-by',), ('blocked-by',)),
)


def _validate_table():
    kinds, words = set(), set()
    for row in _ROUTES:
        if (row.kind in kinds or row.words in words or type(row.numbered) is not bool
                or len(row.flags) != len(set(row.flags))
                or any(field not in row.flags for field in row.required)
                or any(row.words[:len(previous)] == previous or previous[:len(row.words)] == row.words
                       for previous in words)):
            raise RuntimeError('ambiguous fixed GitHub mutation vocabulary')
        kinds.add(row.kind); words.add(row.words)
_validate_table()
_KNOWN_FLAGS = frozenset({'repo', *(flag for row in _ROUTES for flag in row.flags)})


class MutationRouteError(LedgerError):
    """Safe rejection identifies a location and one correction, never a value."""
    def __init__(self, code, index, token, correction):
        super().__init__(code)
        self.token_index, self.token, self.correction = index, token, correction

    def diagnostic(self):
        return {'code': self.code, 'token_index': self.token_index,
                'token': self.token, 'correction': self.correction}


@dataclass(frozen=True)
class MutationRoute:
    kind: str
    repository: str
    number: int | None
    options: object
    warnings: tuple = ()

    def document(self):
        return {'kind': self.kind, 'repository': self.repository, 'number': self.number,
                'options': {key: list(value) if type(value) is tuple else value
                            for key, value in self.options.items()},
                'warnings': list(self.warnings)}


def help_text():
    lines = ['GitHub mutations (Room Project only; authenticated forge-write owner required):']
    for row in _ROUTES:
        line = 'gh ' + ' '.join(row.words) + (' NUMBER' if row.numbered else '')
        for flag in row.flags:
            if flag == 'body-file':
                continue
            if flag == 'body':
                spelling = '--body TEXT | --body-file -'
                line += ' ' + ('(' + spelling + ')' if 'body' in row.required else '[' + spelling + ']')
                continue
            spelling = '--' + flag + ('' if flag in _BOOL else ' VALUE')
            line += ' ' + (spelling if flag in row.required else '[' + spelling + ']')
        lines.append(line + ' [--repo OWNER/REPO]')
    lines += ['Body: at most 512 KiB; --body-file - reads supplied stdin, never a path.',
              'Review: choose exactly one submitted event and supply --commit FULL_SHA.',
              'Assignments: @me only. Labels: configured work labels only; lifecycle labels are Hub-owned.',
              'No merge, label administration, workflow control, arbitrary API, or binary attachments.']
    return '\n'.join(lines)


def is_mutation_command(argv):
    """Classification only; invalid arguments remain subject to strict parsing."""
    if type(argv) not in (list, tuple): return False
    args = argv[1:] if argv and argv[0] == 'gh' else argv
    return any(tuple(args[:len(row.words)]) == row.words for row in _ROUTES)


def _reject(code, index, token, correction):
    raise MutationRouteError(code, index, token, correction)


def _text(value, index, token, *, body=False, maximum=1024):
    if type(value) is not str:
        _reject('INVALID_MUTATION_INPUT', index, token, 'Supply a UTF-8 text value.')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        _reject('INVALID_MUTATION_INPUT', index, token, 'Supply valid UTF-8 text.')
    if size > maximum:
        _reject('BODY_LIMIT' if body else 'INPUT_LIMIT', index, token,
                'Keep the body within 512 KiB.' if body else 'Shorten this value to its documented bound.')
    if any((ord(c) < 32 and (not body or c not in '\n\r\t')) or ord(c) == 127 for c in value):
        _reject('INVALID_MUTATION_INPUT', index, token, 'Remove unsupported control characters.')
    return value


def _number(value, index, token):
    if type(value) is not str or not _NUMBER.fullmatch(value) or int(value) > 2**63 - 1:
        _reject('INVALID_SELECTOR', index, token, 'Supply one positive decimal object number.')
    return int(value)


def _branch(value, index, token):
    if (not value or value.startswith(('-', '/', '.')) or value.endswith(('/', '.'))
            or '..' in value or '@{' in value or value == '@' or '//' in value
            or any(c in value for c in ' ~^:?*[\\')
            or any(part.startswith('.') or part.endswith('.lock') for part in value.split('/'))):
        _reject('INVALID_SELECTOR', index, token, 'Supply a branch name in the pinned repository.')
    return value


def _work_labels(work_labels):
    if (type(work_labels) not in (tuple, frozenset) or len(work_labels) > 100
            or any(type(label) is not str or not label or label in {'.','..'} or len(label.encode('utf-8', errors='replace')) > 100
                   or ',' in label or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in label)
                   for label in work_labels)):
        raise LedgerError('INVALID_WORK_LABEL_POLICY')
    return frozenset(work_labels)


def parse_mutation_route(argv, project, *, body=None, work_labels=()):
    if type(project) is not GitHubProject:
        raise LedgerError('INVALID_PROJECT')
    allowed_labels = _work_labels(work_labels)
    if type(argv) not in (list, tuple) or not 1 <= len(argv) <= MAX_ARGUMENTS:
        _reject('INPUT_LIMIT', 0, 'command', 'Use one documented bounded mutation command.')
    total = 0
    for index, item in enumerate(argv):
        # Inline bodies are the only potentially large argv value. Further field
        # validation below disallows controls everywhere else.
        _text(item, index, 'value', body=True, maximum=MAX_BODY)
        total += len(item.encode('utf-8'))
    if body is not None:
        _text(body, len(argv), 'stdin', body=True, maximum=MAX_BODY)
        total += len(body.encode('utf-8'))
    if total > MAX_ARGV:
        _reject('INPUT_LIMIT', 0, 'command', 'Keep combined arguments and stdin within the request bound.')
    offset = 1 if argv[0] == 'gh' else 0
    args = list(argv[offset:])
    row = next((row for row in _ROUTES if tuple(args[:len(row.words)]) == row.words), None)
    if row is None:
        _reject('UNSUPPORTED_ROUTE', offset, 'command', 'Choose a documented mutation route from gh --help.')
    cursor = len(row.words)
    number = None
    if row.numbered:
        if cursor >= len(args):
            _reject('INVALID_SELECTOR', offset + cursor, 'NUMBER', 'Supply the pinned repository object number.')
        number = _number(args[cursor], offset + cursor, 'NUMBER')
        cursor += 1
    values, positions, warnings, seen = {}, {}, [], set()
    used_stdin = False
    while cursor < len(args):
        index = offset + cursor
        raw_flag = args[cursor]
        flag = _ALIASES.get(raw_flag, raw_flag[2:] if raw_flag.startswith('--') else '')
        if flag not in ('repo', *row.flags):
            _reject('UNSUPPORTED_ROUTE', index, '--' + flag if flag in _KNOWN_FLAGS else 'option',
                    'Remove this option and use only flags listed for this route.')
        key = _NORMALIZE.get(flag, flag)
        token = '--' + flag
        if key in seen and key not in _LIST:
            _reject('DUPLICATE_OPTION', index, token, 'Supply this option exactly once.')
        seen.add(key); positions[key] = index
        cursor += 1
        if flag in _BOOL:
            values[key] = True
            continue
        if cursor >= len(args):
            _reject('MISSING_VALUE', index, token, 'Supply one value after this option.')
        value = args[cursor]; cursor += 1
        _text(value, index + 1, token, body=flag == 'body', maximum=MAX_BODY if flag == 'body' else 1024)
        if flag == 'repo':
            if value.lower() != project.repository.lower():
                _reject('PROJECT_MISMATCH', index + 1, token, 'Use the Room Project repository.')
            if value != project.repository:
                warnings.append('Repository spelling normalized to the Room Project.')
        elif flag == 'body-file':
            if value != '-' or body is None:
                _reject('BODY_FILE_DENIED', index + 1, token, 'Use --body-file - and provide bounded stdin text.')
            if 'body' in values:
                _reject('CONFLICTING_OPTIONS', index, token, 'Choose either --body or --body-file -, not both.')
            values['body'] = body; positions['body'] = index; used_stdin = True
        elif flag == 'body':
            if used_stdin:
                _reject('CONFLICTING_OPTIONS', index, token, 'Choose either --body or --body-file -, not both.')
            values[key] = value
        elif key in _LIST:
            items = value.split(',')
            if not items or len(items) > MAX_LABELS or any(not item for item in items):
                _reject('INVALID_MUTATION_INPUT', index + 1, token, 'Supply a nonempty bounded comma-separated list.')
            if key.endswith('assignee'):
                if any(item != '@me' for item in items):
                    _reject('OWNER_MISMATCH', index + 1, token, 'Use @me for the authenticated Actor only.')
            elif any(item.lower().startswith(_RESERVED) or item not in allowed_labels for item in items):
                _reject('LABEL_AUTHORITY_DENIED', index + 1, token, 'Use only Supervisor-configured work-type labels.')
            existing = list(values.get(key, ()))
            for item in items:
                if item in existing:
                    warnings.append('Duplicate list entry removed without changing the requested mutation.')
                else:
                    existing.append(item)
            if len(existing) > MAX_LABELS:
                _reject('INPUT_LIMIT', index + 1, token, 'Request at most twenty labels in one field.')
            values[key] = tuple(existing)
        elif flag == 'title':
            _text(value, index + 1, token, maximum=256)
            if not value.strip():
                _reject('INVALID_MUTATION_INPUT', index + 1, token, 'Supply a nonempty title.')
            values[key] = value
        elif flag in {'head', 'base'}:
            values[key] = _branch(value, index + 1, token)
        elif flag == 'reason':
            if value not in {'completed', 'not-planned'}:
                _reject('INVALID_MUTATION_INPUT', index + 1, token, 'Choose completed or not-planned.')
            values[key] = value
        elif flag == 'commit':
            if not _SHA.fullmatch(value):
                _reject('INVALID_SELECTOR', index + 1, token, 'Supply the exact full lowercase candidate commit SHA.')
            values[key] = value
        elif flag in {'blocked-by', 'comment-id'}:
            values[key] = _number(value, index + 1, token)
    if body is not None and not used_stdin:
        _reject('UNUSED_STDIN', len(argv), 'stdin', 'Use --body-file - for the supplied stdin text.')
    for required in row.required:
        if required not in values:
            _reject('MISSING_FIELD', len(argv), '--' + required, 'Supply the required --' + required + ' field.')
    if row.kind.endswith('-edit') and not values:
        _reject('MISSING_FIELD', len(argv), 'option', 'Supply at least one editable field.')
    for noun in ('assignee', 'label'):
        if set(values.get('add-' + noun, ())) & set(values.get('remove-' + noun, ())):
            _reject('CONFLICTING_OPTIONS', positions['remove-' + noun], '--remove-' + noun,
                    'Do not add and remove the same value in one command.')
    if len(values.get('add-label', ())) + len(values.get('remove-label', ())) > MAX_LABELS:
        _reject('INPUT_LIMIT', positions.get('remove-label', positions.get('add-label', len(argv))),
                'labels', 'Request at most twenty total label additions and removals.')
    if row.kind == 'issue-close':
        values.setdefault('reason', 'completed')
    if row.kind in {'dependency-add', 'dependency-remove'} and values['blocked-by'] == number:
        _reject('SELF_DEPENDENCY', positions['blocked-by'], '--blocked-by', 'Select a different issue as the blocker.')
    if row.kind == 'pr-create' and values['head'] == values['base']:
        _reject('INVALID_SELECTOR', positions['head'], '--head', 'Use different head and base branches.')
    if row.kind == 'pr-review':
        events = {'approve': 'APPROVE', 'request-changes': 'REQUEST_CHANGES', 'comment': 'COMMENT'}
        selected = [flag for flag in events if values.pop(flag, False)]
        if len(selected) != 1:
            _reject('REVIEW_EVENT_REQUIRED', len(argv), 'review-event',
                    'Choose exactly one of --approve, --request-changes, or --comment.')
        values['event'] = events[selected[0]]
        if values['event'] != 'APPROVE' and not values.get('body', '').strip():
            _reject('MISSING_FIELD', len(argv), '--body', 'Supply a nonempty submitted review body.')
    if row.kind in {'issue-comment', 'pr-comment', 'pr-reply'} and not values['body'].strip():
        _reject('MISSING_FIELD', positions.get('body', len(argv)), '--body', 'Supply a nonempty comment body.')
    return MutationRoute(row.kind, project.repository, number, MappingProxyType(values),
                         tuple(dict.fromkeys(warnings)))
