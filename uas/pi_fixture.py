"""Fixed account-free Pi recipe for the Linux same-UID authority fixture.

This is not arbitrary executable admission, production image qualification,
credential provisioning, or cross-Run reset. Paths are trusted harness inputs;
the fixture does not isolate same-UID filesystem mutation or ptrace.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess

from .pi_runtime import FixturePiRpcReceiver, NativeUnavailable

ROOT = Path(__file__).resolve().parents[1]


class FixturePiRecipe:
    def __init__(self, install, directory, *, scope, session=None, timeout=8):
        self.install = Path(install).resolve()
        self.directory = Path(directory).resolve()
        self.scope = dict(scope)
        self.timeout = timeout
        self.session = str(Path(session).resolve()) if session is not None else None
        self.node = shutil.which('node')
        self.package = self.install / 'node_modules/@earendil-works/pi-coding-agent'
        ai = self.install / 'node_modules/@earendil-works/pi-ai'
        if not self.node or any(json.loads((path / 'package.json').read_text())['version'] != '1.4.0'
                                for path in (self.package, ai)):
            raise NativeUnavailable('locked official Pi 1.4.0 and Node required')
        self.directory.mkdir(parents=True, exist_ok=True)
        self.workdir = self.directory / 'workspace'
        self.workdir.mkdir(exist_ok=True)
        self.home = self.directory / 'home'
        (self.home / 'agent').mkdir(parents=True, exist_ok=True)
        (self.home / 'agent/settings.json').write_text(json.dumps({'compaction': {
            'enabled': False, 'keepRecentTokens': 128, 'reserveTokens': 1024}, 'retry': {'enabled': False}}))
        # Explicit same-Run restore only; no implicit latest-session selection.
        if self.session is not None and not Path(self.session).is_relative_to(self.directory / 'sessions'):
            raise NativeUnavailable('restore session must belong to this fixture directory')

    def spawn(self, child_socket, runtime_directory):
        child_socket.setblocking(False)
        env = {'PATH': str(Path(self.node).parent) + ':/usr/bin:/bin', 'HOME': str(self.home),
               'LANG': 'C.UTF-8', 'PI_CODING_AGENT_DIR': str(self.home / 'agent'), 'PI_OFFLINE': '1',
               'NODE_OPTIONS': '--import=' + str(ROOT / 'tests/pi/network-guard.mjs'),
               'UAS_PI_FAUX_MODULE': str(self.install / 'node_modules/@earendil-works/pi-ai/dist/providers/faux.js'),
               'UAS_PI_PEER_FD': str(child_socket.fileno())}
        argv = [self.node, str(self.package / 'dist/cli.js'), '--mode', 'rpc', '--no-builtin-tools',
                '--no-extensions', '--no-skills', '--no-prompt-templates', '--no-themes',
                '-e', str(ROOT / 'runtime/pi/extension.mjs'), '-e', str(ROOT / 'tests/pi/provider.mjs'),
                '--provider', 'faux', '--model', 'faux-1', '--session-dir', str(self.directory / 'sessions')]
        if self.session is not None:
            argv += ['--session', self.session]
        return subprocess.Popen(argv, cwd=self.workdir, env=env,
                                pass_fds=(child_socket.fileno(),), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

    def attach(self, process, badge):
        if (self.scope.get('room_id') != badge.room_id
                or self.scope.get('participant_id') != badge.participant_id):
            raise NativeUnavailable('recipe does not match Supervisor badge')
        return FixturePiRpcReceiver.attach(process, journal=self.directory / 'intent.db',
            runtime_version='1.4.0', scope=self.scope, incarnation_id=badge.incarnation_id,
            timeout=self.timeout)
