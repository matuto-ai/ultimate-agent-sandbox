"""AST-only staged import inventory; never import or launch staged code."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def source_list(name, variable='SOURCES'):
    tree = ast.parse((ROOT / name).read_bytes())
    node = next(node for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == variable for target in node.targets))
    return set(ast.literal_eval(node.value))


def local_imports(name, include_lazy=False):
    path = ROOT / name
    pending = list(ast.parse(path.read_bytes()).body)
    found = set()
    def resolve(module, directory):
        if not module: return
        relative = Path(*module.split('.'))
        for base in (directory, ROOT, ROOT/'tests/vm', ROOT/'tests/linux'):
            for target in ((base/relative).with_suffix('.py'), base/relative/'__init__.py'):
                if target.is_file():
                    found.add(target.relative_to(ROOT).as_posix())
                    return
    while pending:
        node = pending.pop()
        # These imports do not run on import. Optional branches are not silently
        # staged; called lazy seams must be included explicitly by their fixture.
        if not include_lazy and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)): continue
        pending.extend(ast.iter_child_nodes(node))
        if isinstance(node, ast.Import):
            for alias in node.names: resolve(alias.name, path.parent)
        elif isinstance(node, ast.ImportFrom):
            directory = path.parent if node.level else ROOT
            for _ in range(max(0, node.level-1)): directory = directory.parent
            resolve(node.module, directory)
            for alias in node.names:
                if alias.name != '*': resolve('.'.join(filter(None, (node.module, alias.name))), directory)
    return found


def missing_imports(paths, include_lazy=False):
    pending = [name for name in paths if name.endswith('.py')]
    seen = set(paths)
    while pending:
        for dependency in local_imports(pending.pop(), include_lazy):
            if dependency not in seen:
                seen.add(dependency); pending.append(dependency)
    return sorted(seen - set(paths))


class StagedSourceClosureTests(unittest.TestCase):
    def assert_stage_budget(self, sources):
        tree = ast.parse((ROOT/'tests/linux/diff_smoke.py').read_bytes())
        expressions = {node.targets[0].id: ast.dump(node.value)
                       for node in tree.body if isinstance(node, ast.Assign)
                       and isinstance(node.targets[0], ast.Name)
                       and node.targets[0].id in ('MAX_SOURCE_FILES','MAX_SOURCE_BYTES','MAX_SOURCE_TOTAL')}
        self.assertEqual(expressions, {name: ast.dump(ast.parse(value, mode='eval').body)
            for name,value in {'MAX_SOURCE_FILES':'137','MAX_SOURCE_BYTES':'256<<10','MAX_SOURCE_TOTAL':'3<<20'}.items()})
        limits = {'MAX_SOURCE_FILES':137,'MAX_SOURCE_BYTES':256<<10,'MAX_SOURCE_TOTAL':3<<20}
        sizes = [(ROOT/name).stat().st_size for name in sources]
        self.assertLessEqual(len(sizes),limits['MAX_SOURCE_FILES'])
        self.assertTrue(all(size <= limits['MAX_SOURCE_BYTES'] for size in sizes))
        self.assertLessEqual(sum(sizes),limits['MAX_SOURCE_TOTAL'])

    def test_diff_stage_closes_lazy_owner_imports_too(self):
        # Diff promises full UAS import closure. Other finite native profiles
        # do not call the opt-in Manager action routes and retain eager closure.
        sources = source_list('tests/linux/diff_smoke.py')
        self.assertEqual([], missing_imports(sources, include_lazy=True))
        self.assert_stage_budget(sources)

    def test_fixed_source_manifests_have_eager_import_closure(self):
        for fixture in ('tests/linux/artifact_smoke.py', 'tests/linux/diff_smoke.py',
                        'tests/linux/review_forge_smoke.py',
                        'tests/vm/run_artifacts.py', 'tests/vm/run_boundary.py', 'tests/vm/run_workstation.py'):
            with self.subTest(fixture=fixture):
                sources = source_list(fixture)
                self.assertEqual([], missing_imports(sources))
                if fixture.startswith('tests/vm/'):
                    self.assertLessEqual(len(sources),64)
                    self.assertLessEqual(sum((ROOT/name).stat().st_size for name in sources),4*1024*1024)

    def test_command_and_artifact_profiles_extend_diff_staging(self):
        base = source_list('tests/linux/diff_smoke.py')
        artifact = source_list('tests/linux/artifact_native_smoke.py','EXTRA_SOURCES')
        tree = ast.parse((ROOT/'tests/linux/command_smoke.py').read_bytes())
        command = next(ast.literal_eval(keyword.value) for node in ast.walk(tree)
                       if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                       and node.func.id=='stage_sources' for keyword in node.keywords
                       if keyword.arg=='extra_paths')
        for sources in (base|artifact, base|set(command)):
            self.assertEqual([],missing_imports(sources))
            self.assert_stage_budget(sources)

    def test_optional_identity_route_has_fixed_dependency_files(self):
        # The unchanged native fixture leaves contributions=None. If a trusted
        # host attaches the new route, these three modules are already staged.
        sources = source_list('tests/vm/run_workstation.py')
        self.assertTrue({'uas/gate_identity.py','uas/git_provenance.py','uas/git_policy.py'} <= sources)
        self.assertEqual([],missing_imports(sources))
