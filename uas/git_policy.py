"""Pure, closed native-Git vocabulary; never authority or an execution boundary.

The Supervisor supplies the Actor and Room binding. The SSH shim supplies only
an untrusted requested Git service/target, which the external Broker validates.
No parser reads environment, repository configuration, credentials or processes.

The launcher MUST additionally provide its fixed environment, helpers, protocol
policy and sanitized configuration. In particular, accepted argv cannot make
repository filters, hooks, aliases, fsmonitor, diff drivers or URL rewrites safe.
Only one leading absolute ``-C PATH`` is supported; its checkout membership is a
separate Supervisor check. Relative/repeated -C and all general config selectors
are deliberately unavailable. This is a declared subset, not a Git pass-through.
"""
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
import unicodedata

from .forge import ForgeBinding


class GitPolicyError(ValueError):
    """A stable denial code, never caller arguments or provider diagnostics."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _deny(code='UNSUPPORTED_GIT_COMMAND'):
    raise GitPolicyError(code)


def _text(value, maximum=4096):
    return (type(value) is str and 0 < len(value.encode('utf-8', 'surrogatepass')) <= maximum
            and not any(unicodedata.category(c).startswith('C') or c in '\u2028\u2029' for c in value))


_ACTOR = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
_REPOSITORY = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
_OID = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
_REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_./{}^~@:+-]{0,1023}\Z')
_REMOTE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


def _repository(value):
    return (type(value) is str and _REPOSITORY.fullmatch(value) is not None
            and all(part not in ('.', '..') for part in value.split('/')))


@dataclass(frozen=True)
class GitIdentity:
    actor_id: str
    name: str
    email: str

    def __post_init__(self):
        if (type(self.actor_id) is not str or not _ACTOR.fullmatch(self.actor_id)
                or not _text(self.name, 256) or self.name.strip() != self.name
                or '<' in self.name or '>' in self.name
                or not _text(self.email, 254) or not self.email.isascii()
                or not re.fullmatch(r'[^<>\s@]+@[^<>\s@]+', self.email)):
            _deny('INVALID_GIT_IDENTITY')


@dataclass(frozen=True)
class GitTarget:
    host: str
    repository: str
    service: str

    def __post_init__(self):
        if (self.host != 'github.com' or not _repository(self.repository)
                or self.service not in ('git-upload-pack', 'git-receive-pack')):
            _deny('INVALID_GIT_TARGET')


def _arguments(argv, *, maximum=128, size=32768, code='UNSUPPORTED_GIT_COMMAND'):
    if (type(argv) not in (list, tuple) or len(argv) > maximum
            or any(not _text(arg) for arg in argv)
            or sum(len(arg.encode('utf-8')) for arg in argv) > size):
        _deny(code)
    return list(argv)


def parse_ssh(argv, binding):
    """Parse precisely the fixed ssh.variant=ssh Git invocation.

    Reads use any syntactically valid same-Forge repository, with actual Actor
    permission left to GitHub. Receive-pack is pinned to the Room Project.
    No -G probe, arbitrary option, shell parser or alternate host is accepted.
    """
    if (type(binding) is not ForgeBinding or binding.host != 'github.com'
            or not _repository(binding.repository)):
        _deny('INVALID_GIT_BINDING')
    args = _arguments(argv, maximum=4, size=2048, code='UNSUPPORTED_GIT_TRANSPORT')
    if args[:2] == ['-o', 'SendEnv=GIT_PROTOCOL']:
        args = args[2:]
    if len(args) != 2 or args[0] != 'git@github.com':
        _deny('UNSUPPORTED_GIT_TRANSPORT')
    match = re.fullmatch(r"(git-upload-pack|git-receive-pack) '([^']+)\.git'", args[1])
    if match is None or not _repository(match[2]):
        _deny('UNSUPPORTED_GIT_TRANSPORT')
    service, repository = match.groups()
    if service == 'git-receive-pack':
        if repository.casefold() != binding.repository.casefold():
            _deny('GIT_PROJECT_MISMATCH')
        repository = binding.repository  # canonical configured spelling, not caller spelling
    return GitTarget('github.com', repository, service)


@dataclass(frozen=True)
class GitRoute:
    command: str
    kind: str
    usage: str
    flags: tuple = ()
    values: tuple = ()


# This is the complete public vocabulary. The same rows drive help, command
# selection and flag admission. Per-command relationships are checked below.
ROUTES = (
    GitRoute('status', 'local-read', '[--short] [--branch] [-- PATH...]',
             ('-s', '--short', '-b', '--branch', '--porcelain', '--porcelain=v1', '--porcelain=v2',
              '--untracked-files=no', '--untracked-files=normal', '--untracked-files=all', '--ignored')),
    GitRoute('log', 'local-read', '[-n COUNT] [REV...] [-- PATH...]',
             ('--oneline', '--graph', '--decorate', '--no-decorate', '--stat', '--name-only',
              '--name-status', '--all', '--no-patch', '--patch', '--abbrev-commit'), ('-n', '--max-count')),
    GitRoute('show', 'local-read', '[REV...] [-- PATH...]',
             ('--stat', '--name-only', '--name-status', '--no-patch', '--patch', '--oneline')),
    GitRoute('diff', 'local-read', '[REV...] [-- PATH...]',
             ('--cached', '--staged', '--stat', '--name-only', '--name-status', '--check',
              '--no-ext-diff', '--no-textconv', '--color=never')),
    GitRoute('rev-parse', 'local-read', '[--verify] REV',
             ('--verify', '--short', '--show-toplevel', '--git-dir', '--is-inside-work-tree',
              '--show-object-format', '--symbolic-full-name', '--abbrev-ref')),
    GitRoute('ls-files', 'local-read', '[--stage] [-- PATH...]',
             ('--cached', '--others', '--exclude-standard', '--modified', '--deleted', '--stage', '-s')),
    GitRoute('ls-tree', 'local-read', '[-r] REV [-- PATH...]', ('-r', '-d', '--name-only', '--long')),
    GitRoute('cat-file', 'local-read', '(-p|-t|-s) OID', ('-p', '-t', '-s')),
    GitRoute('show-ref', 'local-read', '[--head] [REF...]', ('--head', '--heads', '--tags', '--verify', '--hash')),
    GitRoute('merge-base', 'local-read', '[--is-ancestor] REV REV', ('--is-ancestor', '--all')),
    GitRoute('add', 'local-write', '[-A|-u] [-- PATH...]', ('-A', '--all', '-u', '--update')),
    GitRoute('rm', 'local-write', '[-r] [--cached] -- PATH...', ('-r', '--cached')),
    GitRoute('mv', 'local-write', '-- SOURCE DESTINATION'),
    GitRoute('branch', 'local-write', '[--show-current | --list | -d NAME | NAME [START]]',
             ('--show-current', '--list', '-d', '--delete')),
    GitRoute('switch', 'local-write', '[-c NAME] [START]', (), ('-c',)),
    GitRoute('restore', 'local-write', '[--staged] [--worktree] [--source REV] -- PATH...',
             ('--staged', '--worktree'), ('--source',)),
    GitRoute('commit', 'commit', '[-a] [--amend] (-m MESSAGE | --no-edit)',
             ('-a', '--all', '--amend', '--no-edit', '--allow-empty'), ('-m', '--message')),
    GitRoute('cherry-pick', 'cherry-pick', '(EXACT_OID | --continue | --abort)', ('--continue', '--abort')),
    GitRoute('fetch', 'remote-read', '[--prune] [REMOTE [REFSPEC...]]',
             ('--prune', '--tags', '--no-tags', '--unshallow', '--no-recurse-submodules'), ('--depth',)),
    GitRoute('ls-remote', 'remote-read', '[--heads] [--tags] [REMOTE [REF...]]',
             ('--heads', '--tags', '--refs', '--exit-code', '--symref')),
    # The projected config is immutable. Reject upstream persistence before
    # contacting a provider, not after a successful remote update.
    GitRoute('push', 'remote-write', '[--dry-run] [REMOTE [REFSPEC...]]',
             ('--dry-run', '--tags')),
)
_ROUTES = {route.command: route for route in ROUTES}
if len(_ROUTES) != len(ROUTES) or any(len(set(row.flags + row.values)) != len(row.flags + row.values) for row in ROUTES):
    raise RuntimeError('ambiguous controlled Git vocabulary')


@dataclass(frozen=True)
class GitCommand:
    command: str
    args: tuple
    kind: str
    cwd: str | None = None


def generated_help():
    lines = ['Controlled Git routes (one optional absolute -C PATH):']
    for row in ROUTES:
        lines.append(f'git {row.command} {row.usage}')
        if row.flags or row.values:
            lines.append('  Options: ' + ', '.join((*row.flags, *(name + ' VALUE' for name in row.values))))
    lines.extend(('git --help', 'git --version',
        'Only the fixed SSH Broker transports GitHub reads and Project-pinned pushes.',
        'No git am, arbitrary helper, config/identity override, relative -C, or exec fallback.'))
    return '\n'.join(lines)


def _path(value):
    return value == '.' or (bool(value) and not value.startswith('/') and '\\' not in value
            and all(part not in ('', '.', '..') for part in value.split('/')))


def _reference(value):
    return (_REFERENCE.fullmatch(value) is not None and not value.startswith('-')
            and '\\' not in value and not value.endswith('.lock'))


def _remote(value):
    if _REMOTE.fullmatch(value) and value not in ('.', '..'):
        return True
    prefix = next((p for p in ('git@github.com:', 'ssh://git@github.com/') if value.startswith(p)), None)
    return bool(prefix and value.endswith('.git') and _repository(value[len(prefix):-4]))


def _refspec(value):
    # No deletion, forced update, refspec-file input, protocol selector or option.
    if value.startswith(('-', '+', '^')) or value.count(':') > 1:
        return False
    pieces = value.split(':')
    return all(piece and _reference(piece.replace('*', 'wildcard'))
               and piece.count('*') <= 1 for piece in pieces) and (
                   len(pieces) == 1 or pieces[0].count('*') == pieces[1].count('*'))


def _scan(route, args):
    positional, paths, options = [], [], []
    index = 0
    while index < len(args):
        word = args[index]
        if word == '--':
            paths = args[index + 1:]
            if not paths or any(not _path(path) for path in paths):
                _deny()
            break
        if word in route.flags:
            options.append((word, None))
        elif word in route.values:
            index += 1
            if index >= len(args):
                _deny()
            options.append((word, args[index]))
        elif word.startswith('--') and '=' in word and word.split('=', 1)[0] in route.values:
            key, value = word.split('=', 1)
            if not value:
                _deny()
            options.append((key, value))
        elif word.startswith('-'):
            _deny()
        else:
            positional.append(word)
        index += 1
    # Only commit message is repeatable; repetition is never a hidden override.
    names = [name for name, _ in options if name not in ('-m', '--message')]
    if len(names) != len(set(names)):
        _deny()
    for name, value in options:
        if name in ('-n', '--max-count', '--depth'):
            if not re.fullmatch(r'[1-9][0-9]{0,5}', value) or int(value) > 100000:
                _deny()
        elif name in ('-c', '--source') and not _reference(value):
            _deny()
    return positional, paths, options


def _validate(route, args):
    positional, paths, options = _scan(route, args)
    command = route.command
    flags = {name for name, _ in options}
    if command == 'commit':
        messages = [value for name, value in options if name in ('-m', '--message')]
        if (positional or paths or (not messages and '--no-edit' not in flags)
                or ('--no-edit' in flags and (messages or '--amend' not in flags))):
            _deny()
        return
    if command == 'cherry-pick':
        if paths or not ((len(positional) == 1 and not options and _OID.fullmatch(positional[0]))
                         or (not positional and len(options) == 1)):
            _deny()
        return
    if command in ('fetch', 'ls-remote', 'push'):
        if paths or (positional and not _remote(positional[0])):
            _deny()
        if any(not _refspec(value) for value in positional[1:]):
            _deny()
        if '--tags' in flags and '--no-tags' in flags:
            _deny()
        return
    if command in ('add', 'rm', 'mv', 'restore'):
        if any(not _path(value) or value.startswith('-') for value in positional):
            _deny()
        count = len(positional) + len(paths)
        if command == 'add' and not count and not options:
            _deny()
        if command in ('rm', 'restore') and not count:
            _deny()
        if command == 'mv' and count != 2:
            _deny()
        return
    if paths and command not in ('status', 'log', 'show', 'diff', 'ls-files', 'ls-tree'):
        _deny()
    if any(not _reference(value) for value in positional):
        _deny()
    if command in ('status', 'ls-files'):
        if any(not _path(value) for value in positional):
            _deny()
    elif command == 'cat-file':
        if len(positional) != 1 or len(options) != 1:
            _deny()
    elif command == 'ls-tree':
        if len(positional) != 1:
            _deny()
    elif command == 'merge-base':
        if len(positional) != 2:
            _deny()
    elif command == 'branch':
        if (len(positional) > 2 or len(options) > 1
                or (flags & {'--show-current', '--list'} and positional)
                or (flags & {'-d', '--delete'} and len(positional) != 1)):
            _deny()
    elif command == 'switch':
        if len(positional) > 1 or (not positional and not options):
            _deny()
    elif command == 'rev-parse':
        observers = {'--show-toplevel', '--git-dir', '--is-inside-work-tree', '--show-object-format'}
        if (not positional and not flags & observers) or (flags & observers and (len(options) != 1 or positional)):
            _deny()


def parse_git(invoked_as, argv):
    """Normalize a supported installed Git entry; no external-helper fallback."""
    args = _arguments(argv)
    if not _text(invoked_as, 1024):
        _deny()
    name = PurePosixPath(invoked_as).name
    if name == 'git':
        pass
    elif name.startswith('git-') and name[4:] in _ROUTES:
        args.insert(0, name[4:])
    else:
        _deny()
    cwd = None
    if args[:1] == ['-C']:
        if len(args) < 3:
            _deny()
        cwd = args[1]
        if (not cwd.startswith('/') or '\\' in cwd or str(PurePosixPath(cwd)) != cwd
                or '..' in PurePosixPath(cwd).parts or cwd.startswith('//')):
            _deny('INVALID_GIT_CWD')
        args = args[2:]
    if args in (['--help'], ['--version']):
        return GitCommand(args[0], (), 'help', cwd)
    if not args or args[0] not in _ROUTES:
        _deny()
    route = _ROUTES[args[0]]
    _validate(route, args[1:])
    return GitCommand(route.command, tuple(args[1:]), route.kind, cwd)
