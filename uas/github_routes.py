"""Fixed GitHub read vocabulary. Parsing never selects a provider or credential."""
from dataclasses import dataclass
import re
from types import MappingProxyType

from .github_read import GitHubProject
from .ledger import LedgerError

# One table drives discovery, parsing and option enforcement. Mutations remain
# on their separate audited route; no arbitrary API, GraphQL or auth entry exists.
_ROUTES = (
    ('repo-view', ('repo', 'view'), False, ()),
    ('repo-file', ('repo', 'read-file'), True, ('ref',)),
    ('label-list', ('label', 'list'), False, ('limit',)),
    ('issue-list', ('issue', 'list'), False, ('state', 'limit',)),
    ('issue-display', ('issue', 'view'), True, ('comments',)),
    ('issue-status', ('issue', 'status'), False, ()),
    ('issue-dependencies', ('issue', 'dependencies'), True, ('limit',)),
    ('issue-blocks', ('issue', 'blocks'), True, ('limit',)),
    ('pr-list', ('pr', 'list'), False, ('state', 'limit',)),
    ('pr-display', ('pr', 'view'), True, ('comments',)),
    ('pr-status', ('pr', 'status'), False, ()),
    ('pr-diff', ('pr', 'diff'), True, ()),
    ('pr-checks', ('pr', 'checks'), True, ()),
    ('pr-reviews', ('pr', 'reviews'), True, ('limit',)),
    ('pr-review-comments', ('pr', 'review-comments'), True, ('limit',)),
    ('workflow-list', ('workflow', 'list'), False, ('limit',)),
    ('workflow-view', ('workflow', 'view'), True, ()),
    ('run-list', ('run', 'list'), False, ('limit',)),
    ('run-view', ('run', 'view'), False, ('job', 'attempt', 'log',)),
)
_BOOL = {'comments', 'log'}
_NUMERIC = {'limit', 'job', 'attempt'}


@dataclass(frozen=True)
class SurfaceRoute:
    kind: str
    repository: str
    number: int | None
    options: object

    def document(self):
        return {'kind': self.kind, 'repository': self.repository,
                'number': self.number, 'options': dict(self.options)}


def _validate_table():
    kinds, words = set(), set()
    for kind, prefix, positional, flags in _ROUTES:
        if (kind in kinds or prefix in words or len(prefix) != 2
                or len(flags) != len(set(flags)) or type(positional) is not bool):
            raise RuntimeError('ambiguous fixed GitHub read vocabulary')
        kinds.add(kind); words.add(prefix)
_validate_table()


def help_text():
    lines = ['GitHub read routes (same-Forge reads use native Actor access):']
    group = None
    for kind, prefix, positional, flags in _ROUTES:
        if prefix[0] != group:
            group = prefix[0]
            lines.append('\n' + group.upper() + ':')
        line = 'gh ' + ' '.join(prefix)
        if positional:
            line += ' PATH' if kind == 'repo-file' else ' NUMBER'
        elif kind == 'run-view':
            line += ' [RUN_ID]'
        for flag in flags:
            line += ' [--' + flag + (']' if flag in _BOOL else ' VALUE]')
        lines.append(line + ' [--repo OWNER/REPO]')
    lines.append('Logs: completed Project JOB only, --job JOB_ID --log; no whole-run logs.')
    return '\n'.join(lines)


def parse_read_route(argv, project):
    if type(project) is not GitHubProject:
        raise LedgerError('INVALID_PROJECT')
    if (type(argv) not in (list, tuple) or not 1 <= len(argv) <= 20
            or any(type(a) is not str or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in a)
                   or not 0 < len(a.encode('utf-8')) <= 1024 for a in argv)):
        raise LedgerError('UNSUPPORTED_ROUTE')
    args = list(argv)
    if args[0] == 'gh': args.pop(0)
    if args == ['--help']:
        return SurfaceRoute('help', project.repository, None, MappingProxyType({}))
    row = next((r for r in _ROUTES if list(r[1]) == args[:2]), None)
    if row is None: raise LedgerError('UNSUPPORTED_ROUTE')
    kind, prefix, positional, flags = row
    rest, values, selected = args[2:], {}, project.repository
    number = None
    if rest and not rest[0].startswith('-'):
        item = rest.pop(0)
        if kind == 'repo-file':
            if (item.startswith('/') or '\\' in item or any(p in ('', '.', '..') for p in item.split('/'))):
                raise LedgerError('INVALID_READ_PATH')
            values['path'] = item
        elif positional or kind == 'run-view':
            if not re.fullmatch(r'[1-9][0-9]{0,18}', item): raise LedgerError('INVALID_SELECTOR')
            number = int(item)
            if number > 2**63 - 1: raise LedgerError('INVALID_SELECTOR')
        else: raise LedgerError('UNSUPPORTED_ROUTE')
    elif positional: raise LedgerError('INVALID_SELECTOR')
    seen = set()
    while rest:
        flag = rest.pop(0)
        key = 'repo' if flag in ('-R', '--repo') else flag[2:] if flag.startswith('--') else ''
        if key in seen or key not in ('repo', *flags): raise LedgerError('UNSUPPORTED_ROUTE')
        seen.add(key)
        if key in _BOOL:
            values[key] = True; continue
        if not rest: raise LedgerError('UNSUPPORTED_ROUTE')
        value = rest.pop(0)
        if key == 'repo':
            selected = GitHubProject(value).repository
        elif key in _NUMERIC:
            if not re.fullmatch(r'[1-9][0-9]{0,18}', value): raise LedgerError('INVALID_SELECTOR')
            value = int(value)
            if value > (1000 if key == 'limit' else 2**63 - 1): raise LedgerError('INVALID_SELECTOR')
            values[key] = value
        elif key == 'state':
            if value not in {'open', 'closed', 'all', 'merged'} or (kind == 'issue-list' and value == 'merged'):
                raise LedgerError('INVALID_SELECTOR')
            values[key] = value
        elif key == 'ref':
            if (value.startswith('-') or '..' in value or any(c in value for c in '\\~^:?*[ ')):
                raise LedgerError('INVALID_SELECTOR')
            values[key] = value
    if kind == 'run-view':
        if number is None and 'job' not in values: raise LedgerError('INVALID_SELECTOR')
        if values.get('log'):
            if 'job' not in values: raise LedgerError('WHOLE_RUN_LOG_DENIED')
            if selected.lower() != project.repository.lower(): raise LedgerError('PROJECT_MISMATCH')
            kind = 'job-log'
    return SurfaceRoute(kind, selected, number, MappingProxyType(values))
