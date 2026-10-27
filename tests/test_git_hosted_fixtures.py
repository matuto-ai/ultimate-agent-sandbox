"""Source-only hosted fixture startup contracts; never import/run native seams."""
import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def function(filename, name):
    tree = ast.parse((ROOT / 'tests/linux' / filename).read_text())
    return next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)


class HostedGitStartupSourceTests(unittest.TestCase):
    def test_post_drop_runtime_uses_readonly_staged_source_not_runner_checkout(self):
        provision = ast.unparse(function('git_smoke.py', 'provision'))
        checks = function('git_smoke.py', 'native_checks')
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == 'ROOT' for node in ast.walk(checks)))
        self.assertIn("sources = package / 'fixture-sources'", provision)
        for name in ('launcher.py', 'public-entries.json', 'git_stream_smoke.py'):
            self.assertIn(repr(name), provision)
        self.assertIn('(sources / name).chmod(292)', provision)  # 0444.
        self.assertIn("Path('/opt/uas/fixture-sources')", ast.unparse(checks))
        self.assertIn('os.ST_RDONLY', ast.unparse(checks))

    def test_broker_reexec_uses_fixed_staged_script_after_uid_drop(self):
        namespace = function('git_stream_smoke.py', 'namespace')
        calls = [node for node in ast.walk(namespace) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == 'os.execve']
        self.assertEqual(len(calls), 1)
        argv = calls[0].args[1]
        self.assertIsInstance(argv, ast.List)
        self.assertEqual(ast.literal_eval(argv.elts[1]), '/opt/uas/fixture-sources/git_stream_smoke.py')
        self.assertEqual(ast.literal_eval(argv.elts[2]), '--broker')

    def test_composition_retains_owned_init_parent_and_exact_child_reap(self):
        namespace = ast.unparse(function('git_composition_smoke.py', 'namespace'))
        supervisor = ast.unparse(function('git_composition_smoke.py', 'owned_supervisor'))
        self.assertNotIn('connected_checks(', namespace)
        self.assertIn('owned_supervisor(root, jail, worktree, digest)', namespace)
        self.assertIn('signal.alarm(', namespace)
        self.assertIn('os.getppid() == 1', supervisor)
        self.assertIn('pid = os.fork()', supervisor)
        self.assertIn('child = OwnedChild(pid)', supervisor)
        self.assertIn('while child.observation() is None:', supervisor)
        self.assertIn('child.finish(success=True)', supervisor)
        self.assertIn('finally:\n        child.finish()', supervisor)
