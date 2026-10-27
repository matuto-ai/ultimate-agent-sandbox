"""Fixed account-free Claude recipe; trusted harness paths, not generic spawning."""
from pathlib import Path
import uuid

from .claude_runtime import FixtureClaudeReceiver, ClaudeUnavailable


class FixtureClaudeRecipe:
    def __init__(self, binary, *, sdk_install, node, directory, scope,
                 gateway_url, fixture_key, timeout=8):
        self.binary, self.sdk_install, self.node = map(Path, (binary, sdk_install, node))
        self.directory = Path(directory).resolve()
        self.scope = dict(scope)
        self.gateway_url, self.fixture_key, self.timeout = gateway_url, fixture_key, timeout
        self.workdir = self.directory / 'workspace'
        generation = self.scope.get('context_generation')
        if type(generation) is not int or not 1 <= generation <= 2**53 - 1:
            raise ClaudeUnavailable('invalid context generation')
        self.generation_directory = self.directory / 'contexts' / str(generation)
        self.context_directory = self.home = self.journal = None

    def start(self, incarnation_id, *, resume=False, context_directory=None, defer_ready=False):
        if resume != (context_directory is not None):
            raise ClaudeUnavailable('explicit checkpoint required for restore')
        if resume:
            selected = Path(context_directory)
            if (selected.is_symlink() or selected.resolve() != selected
                    or selected.parent != self.generation_directory
                    or not selected.is_dir()):
                raise ClaudeUnavailable('context directory mismatch')
        else:
            # Failed native attempts are retained, never reused as fresh context.
            self.generation_directory.mkdir(parents=True, exist_ok=True)
            selected = self.generation_directory / ('attempt-' + uuid.uuid4().hex)
            selected.mkdir(mode=0o700)
        self.context_directory = selected
        self.home, self.journal = selected / 'home', selected / 'intent.db'
        if resume:
            if not self.home.is_dir() or not self.journal.is_file():
                raise ClaudeUnavailable('missing current native artifacts')
        else:
            self.home.mkdir(mode=0o700)
        self.workdir.mkdir(parents=True, exist_ok=True)
        return FixtureClaudeReceiver(self.binary, sdk_install=self.sdk_install, node=self.node,
            cwd=self.workdir, home=self.home, gateway_url=self.gateway_url,
            fixture_key=self.fixture_key, journal=self.journal, scope=self.scope,
            resume=resume, timeout=self.timeout, incarnation_id=incarnation_id, defer_ready=defer_ready)
