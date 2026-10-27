"""Pure source checks for the hosted-only endpoint Docker smoke."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name('test_room_fixture_docker.py')


class RoomEndpointDockerSourceTests(unittest.TestCase):
    def test_hosted_guards_precede_any_test_effect(self):
        tree = ast.parse(SOURCE.read_text())
        case = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                    and node.name == 'RoomEndpointDockerSmoke')
        method = next(node for node in case.body if isinstance(node, ast.FunctionDef)
                      and node.name.startswith('test_'))
        body = ast.unparse(method)
        boundary = body.index('with tempfile.TemporaryDirectory(')
        for guard in ("self.assertEqual('true', os.environ.get('GITHUB_ACTIONS'))",
                      "self.assertEqual('Linux', os.environ.get('RUNNER_OS'))", 'self.assertRegex(IMAGE,'):
            self.assertLess(body.index(guard), boundary)
        self.assertEqual(1, len([node for node in case.body if isinstance(node, ast.FunctionDef)
                                and node.name.startswith('test_')]))

    def test_fixture_keeps_exact_narrow_source_and_honest_evidence_scope(self):
        source = SOURCE.read_text()
        self.assertIn("for drift in (None, 'writable', 'source'):", source)
        self.assertIn("expected.removesuffix(',readonly')", source)
        self.assertIn("self.assertEqual(before_starts, backend.start_calls)", source)
        self.assertIn("self.assertEqual('created', actual['State']['Status'])", source)
        self.assertIn("self.assertEqual('EROFS', probe['project_write'])", source)
        self.assertIn("'scope': 'real mount/resource admission only; no Broker, SELinux or network qualification'", source)
        self.assertIn('self.assertLess(seconds, 20,', source)
        for forbidden in ('--privileged', 'docker.sock', 'system prune', 'os.chown', 'subprocess.Popen'):
            self.assertNotIn(forbidden, source)
