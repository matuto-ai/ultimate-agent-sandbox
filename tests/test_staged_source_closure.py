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


# The disposable diff fixture never selects the local command/profile/host.
# These exact lazy boundaries are optional, not an open-ended local_* wildcard.
OPTIONAL_LOCAL_EDGES = {
    # These disposable native profiles never call attach_library. The production
    # Hub image packages every uas module; its explicitly selected Library route
    # is tested separately through real admitted dispatch.
    ('uas/workstation_peer.py', 'uas/library_hub.py'),
    ('uas/lifecycle.py', 'uas/local_native.py'),
    ('uas/__main__.py', 'uas/local_cli.py'),
    ('uas/native_qualification.py', 'uas/local_runtime_plan.py'),
    ('uas/native_run_admission.py', 'uas/local_runtime_plan.py'),
    ('uas/native_run_admission.py', 'uas/local_successor_checkout.py'),
    ('uas/native_run_admission.py', 'uas/local_native_stop.py'),
    ('uas/native_completed_retirement.py', 'uas/local_runtime_plan.py'),
    ('uas/native_completed_retirement.py', 'uas/local_native_stop.py'),
    ('uas/native_completed_retirement.py', 'uas/local_native_terminal.py'),
    ('uas/native_checkout_handoff.py', 'uas/local_native.py'),
    ('uas/native_checkout_handoff.py', 'uas/local_runtime_resources.py'),
    ('uas/native_git_resources.py', 'uas/local_native.py'),
    ('uas/native_session.py', 'uas/local_runtime_plan.py'),
    ('uas/native_session.py', 'uas/local_native_run_session.py'),
    ('uas/native_session.py', 'uas/local_native.py'),
}


def local_imports(name, include_lazy=False, optional_edges=()):
    path = ROOT / name
    pending = list(ast.parse(path.read_bytes()).body)
    found = set()
    def resolve(module, directory):
        if not module: return
        relative = Path(*module.split('.'))
        for base in (directory, ROOT, ROOT/'tests/vm', ROOT/'tests/linux'):
            for target in ((base/relative).with_suffix('.py'), base/relative/'__init__.py'):
                if target.is_file():
                    resolved = target.relative_to(ROOT).as_posix()
                    if (name, resolved) not in optional_edges:
                        found.add(resolved)
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


def missing_imports(paths, include_lazy=False, optional_edges=()):
    pending = [name for name in paths if name.endswith('.py')]
    seen = set(paths)
    while pending:
        for dependency in local_imports(pending.pop(), include_lazy, optional_edges):
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
            for name,value in {'MAX_SOURCE_FILES':'146','MAX_SOURCE_BYTES':'256<<10','MAX_SOURCE_TOTAL':'3<<20'}.items()})
        limits = {'MAX_SOURCE_FILES':146,'MAX_SOURCE_BYTES':256<<10,'MAX_SOURCE_TOTAL':3<<20}
        sizes = [(ROOT/name).stat().st_size for name in sources]
        self.assertLessEqual(len(sizes),limits['MAX_SOURCE_FILES'])
        self.assertTrue(all(size <= limits['MAX_SOURCE_BYTES'] for size in sizes))
        self.assertLessEqual(sum(sizes),limits['MAX_SOURCE_TOTAL'])

    def test_diff_stage_closes_lazy_owner_imports_too(self):
        # Diff promises its qualifier closure, including lazy owner calls.
        # The separately selected local CLI/profile/host is not invoked here. Other profiles
        # do not call the opt-in Manager action routes and retain eager closure.
        sources = source_list('tests/linux/diff_smoke.py')
        # native_human_entry is selected by a fixed -m string, not a Python
        # import: AST reachability alone must not silently omit that entry.
        self.assertTrue({'uas/human_mtls.py','uas/manager_stream.py','uas/manager_transport.py',
            'uas/native_human_control.py','uas/native_human_launch.py','uas/native_human_entry.py'} <= sources)
        self.assertEqual(len(sources),139)
        self.assertIn('uas/local_host_profile.py', sources)
        self.assertEqual(['uas/local_host_profile.py'], missing_imports(
            sources - {'uas/local_host_profile.py'}, include_lazy=True, optional_edges=OPTIONAL_LOCAL_EDGES))
        self.assertEqual([], missing_imports(sources, include_lazy=True, optional_edges=OPTIONAL_LOCAL_EDGES))
        self.assert_stage_budget(sources)

    def test_optional_local_edges_are_lazy_and_do_not_hide_other_dependencies(self):
        sources = source_list('tests/linux/diff_smoke.py')
        for source, dependency in OPTIONAL_LOCAL_EDGES:
            self.assertNotIn(dependency, local_imports(source))
            self.assertIn(dependency, local_imports(source, include_lazy=True))
        self.assertIn('uas/ledger.py', missing_imports(sources - {'uas/ledger.py'},
            include_lazy=True, optional_edges=OPTIONAL_LOCAL_EDGES))
        self.assertTrue(missing_imports(sources, include_lazy=True))

    def test_production_hub_packages_the_explicit_library_route(self):
        from uas.native_hub_image import source_inventory
        sources = source_inventory(ROOT)
        self.assertTrue({'/opt/uas/uas/library.py', '/opt/uas/uas/library_hub.py',
                         '/opt/uas/uas/workstation_peer.py'} <= set(sources))
        # The optional edge is precisely the explicit trusted attachment method,
        # not an unconditional import hidden from the fixed fixture inventory.
        tree = ast.parse((ROOT/'uas/workstation_peer.py').read_bytes())
        methods = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                   and node.name == 'attach_library']
        self.assertEqual(len(methods), 1)
        self.assertTrue(any(isinstance(node, ast.ImportFrom) and node.module == 'library_hub'
                            for node in ast.walk(methods[0])))

    def test_qualifier_policy_checks_do_not_import_optional_local_product(self):
        import builtins
        from types import SimpleNamespace
        from unittest.mock import patch
        from uas.native_qualification import QualificationPlan, is_local_runtime_plan, credential_excluded_roots
        from uas.native_git_resources import local_profile
        original = builtins.__import__
        def qualified_only(name, *args, **kwargs):
            if name.startswith('local_') or name.startswith('uas.local_'):
                raise AssertionError('qualifier imported optional local product: ' + name)
            return original(name, *args, **kwargs)
        plan = object.__new__(QualificationPlan)
        plan.room = {'project': {'roots': {'repo': '/selected/repo'}}, 'state_root': '/selected/state'}
        with patch('builtins.__import__', side_effect=qualified_only):
            self.assertFalse(is_local_runtime_plan(plan))
            self.assertFalse(is_local_runtime_plan(SimpleNamespace()))
            self.assertIsNone(local_profile(plan))
            self.assertEqual(credential_excluded_roots(plan), ['/selected/repo','/selected/state/runtime'])

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
        self.assertEqual((139,143,146),(len(base),len(base|artifact),len(base|set(command))))
        for sources in (base|artifact, base|set(command)):
            self.assertEqual([],missing_imports(sources))
            self.assert_stage_budget(sources)

    def test_exact_file_count_boundary_146_and_147_with_modes_mocked(self):
        # Count/copy behavior only; existing hosted tests prove actual modes.
        import importlib.util
        import tempfile
        from unittest import mock
        spec=importlib.util.spec_from_file_location('finite_stage',ROOT/'tests/linux/diff_smoke.py')
        stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/'input'; source.mkdir()
            accepted=root/'accepted'; accepted.mkdir()
            rejected=root/'rejected'; rejected.mkdir()
            names=tuple('entry-'+str(i) for i in range(146))
            with mock.patch.object(stage,'ROOT',source), mock.patch.object(stage,'SOURCES',names), \
                 mock.patch.object(stage.os,'geteuid',return_value=0), \
                 mock.patch.object(stage,'_source_bytes',return_value=b'fixed'), \
                 mock.patch.object(stage.os,'fchmod'), mock.patch.object(Path,'chmod'):
                destination,hashes=stage.stage_sources(accepted)
                self.assertEqual(set(names),set(hashes))
                self.assertEqual(146,len(list(destination.iterdir())))
                with self.assertRaisesRegex(AssertionError,'file count'):
                    stage.stage_sources(rejected,extra_paths=('entry-146',))
                self.assertFalse((rejected/'source').exists())

    def test_optional_identity_route_has_fixed_dependency_files(self):
        # The unchanged native fixture leaves contributions=None. If a trusted
        # host attaches the new route, these three modules are already staged.
        sources = source_list('tests/vm/run_workstation.py')
        self.assertTrue({'uas/gate_identity.py','uas/git_provenance.py','uas/git_policy.py'} <= sources)
        self.assertEqual([],missing_imports(sources))
