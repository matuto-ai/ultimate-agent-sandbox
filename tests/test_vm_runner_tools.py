"""Offline runner-tool routing contracts; never execute APT locally."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('vm_runner_tools', Path(__file__).parent / 'vm/install_runner_tools.py')
tools = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tools)
STOCK = '''# Ubuntu 24.04 stock deb822 source
Types: deb
URIs: http://azure.archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://azure.archive.ubuntu.com/ubuntu/
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
'''


class VMRunnerToolsTests(unittest.TestCase):
    def test_exact_documented_runner_mirror_indirection_is_replaced_not_followed(self):
        stock = STOCK.replace('http://azure.archive.ubuntu.com/ubuntu/', tools.RUNNER_MIRROR)
        with patch.object(Path, 'read_text', side_effect=AssertionError('must not open mirror file')):
            self.assertEqual(tools.official_sources(STOCK), tools.official_sources(stock))
        for uri in ('mirror+file:///etc/apt/apt-mirrors.txt', 'mirror+file:/tmp/apt-mirrors.txt',
                    tools.RUNNER_MIRROR + '/', tools.RUNNER_MIRROR + '?extra=1',
                    tools.RUNNER_MIRROR + '#fragment', 'file:/etc/apt/apt-mirrors.txt'):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                tools.official_sources(STOCK.replace('http://azure.archive.ubuntu.com/ubuntu/', uri))

    def test_only_uri_fields_change_suites_components_and_signing_stay_exact(self):
        result = tools.official_sources(STOCK)
        untouched = lambda value: [line for line in value.splitlines() if not line.startswith('URIs:')]
        self.assertEqual(untouched(STOCK), untouched(result))
        self.assertIn('URIs: https://archive.ubuntu.com/ubuntu\n', result)
        self.assertIn('URIs: https://security.ubuntu.com/ubuntu\n', result)
        self.assertEqual(result, tools.official_sources(result))

    def test_unknown_source_or_authentication_override_fails_before_apt(self):
        for bad in ('', '# comments only\n', STOCK.replace('noble-updates', 'noble-proposed'),
                    STOCK.replace('azure.archive.ubuntu.com', 'attacker.invalid'),
                    STOCK.replace(tools.KEYRING, '/tmp/untrusted.gpg'),
                    STOCK + 'Trusted: yes\n', STOCK + 'Allow-Insecure: yes\n',
                    STOCK + 'URIs: https://archive.ubuntu.com/ubuntu\n',
                    STOCK.replace('Types: deb', 'Types: deb-src'), STOCK + '\0',
                    STOCK.replace('Components: main', 'Components: foreign'),
                    STOCK.replace('Suites: noble-security', 'Suites:')):
            with self.subTest(source=bad), self.assertRaises(ValueError):
                tools.official_sources(bad)

    def test_no_implicit_host_or_self_hosted_installation(self):
        for environment in ({}, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'}):
            with patch.dict(os.environ, environment, clear=True), patch.object(tools.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError): tools.main(['boundary'])
                run.assert_not_called()

    def test_owned_source_copy_and_bounded_signed_install_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'stock.sources'; source.write_text(STOCK)
            observed = []
            def record(command, **kwargs):
                self.assertTrue(kwargs['check']); self.assertEqual(300, kwargs['timeout'])
                copied = Path(next(value.split('=', 1)[1] for value in command if value.startswith('Dir::Etc::sourcelist=')))
                self.assertNotEqual(source, copied)
                self.assertEqual(tools.official_sources(STOCK), copied.read_text())
                self.assertEqual(0o644, copied.stat().st_mode & 0o777)
                self.assertEqual(0o755, copied.parent.stat().st_mode & 0o777)
                observed.append((command, copied))
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}), patch.object(tools.os, 'geteuid', return_value=1000), patch.object(tools.platform, 'machine', return_value='x86_64'), patch.object(tools.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu', 'VERSION_ID': '24.04'}), patch.object(tools, 'SOURCE', source), patch.object(Path, 'is_file', return_value=True), patch.object(tools.subprocess, 'run', side_effect=record):
                tools.main(['boundary'])
            self.assertEqual(STOCK, source.read_text())
            self.assertEqual(2, len(observed))
            self.assertTrue(all(not copied.exists() for _, copied in observed))
            command = observed[1][0]
            for required in ('Acquire::Retries=0', 'Acquire::https::Timeout=20', 'Dir::Etc::sourceparts=-',
                             'Acquire::AllowInsecureRepositories=false', 'Acquire::Check-Valid-Until=true',
                             'APT::Get::AllowUnauthenticated=false', 'APT::Update::Error-Mode=any', *tools.BASE, *tools.EXTRA):
                self.assertIn(required, command)
            self.assertEqual(['sudo', '-n', 'apt-get'], command[:3])
            self.assertNotIn('APT::Sandbox::User=root', command)

