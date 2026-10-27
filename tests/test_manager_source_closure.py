"""Pure AST contracts for passive Manager dependencies in fixed source stages.

Never import a stage runner or launch isolated Python. Include eager and function-local imports in the bounded passive owner closure;
never execute stage runners or their runtime dependencies.
"""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('tests/linux/diff_smoke.py', 'tests/linux/artifact_smoke.py',
          'tests/linux/review_forge_smoke.py', 'tests/vm/run_boundary.py',
          'tests/vm/run_workstation.py', 'tests/vm/run_artifacts.py')
CONSUMERS = {'uas/lifecycle.py', 'uas/participant.py', 'uas/checkouts.py'}


def selected_sources(relative):
    tree = ast.parse((ROOT / relative).read_text())
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'SOURCES'
                           for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError('one literal source allowlist required')
    result = ast.literal_eval(assignments[0].value)
    if type(result) is not tuple or len(set(result)) != len(result):
        raise ValueError('unique literal source tuple required')
    return set(result)


def passive_dependencies():
    pending, seen = ['uas/manager_owner.py'], set()
    owner_profile_imports = set()
    while pending:
        relative = pending.pop()
        if relative in seen:
            continue
        seen.add(relative)
        for node in ast.walk(ast.parse((ROOT / relative).read_text())):
            if isinstance(node, ast.ImportFrom) and node.level:
                if node.level != 1 or not node.module:
                    raise ValueError('explicit local dependency required')
                # Existing Run/Gate captures are owner-profile dependencies,
                # not dependencies of the passive validation/owner stage. Their
                # exercised closures are checked by those profiles separately.
                if (relative == 'uas/manager_projection.py'
                        and node.module in {'run_review', 'gate_evaluation'}):
                    owner_profile_imports.add(node.module)
                    continue
                pending.append('uas/' + node.module.replace('.', '/') + '.py')
    if owner_profile_imports != {'run_review', 'gate_evaluation'}:
        raise ValueError('owner profile import exceptions must remain exact')
    return seen


class ManagerSourceClosureTests(unittest.TestCase):
    def test_every_fixed_owner_stage_contains_exact_passive_dependency_closure(self):
        dependencies = passive_dependencies()
        self.assertEqual(dependencies, {'uas/manager_owner.py', 'uas/manager_projection.py',
                                       'uas/manager_journey.py'})
        for relative in STAGES:
            with self.subTest(stage=relative):
                selected = selected_sources(relative)
                self.assertTrue(CONSUMERS & selected)
                self.assertLessEqual(dependencies, selected)
                self.assertNotIn('uas/manager_stream.py', selected)
                self.assertNotIn('uas/manager_transport.py', selected)
                for path in dependencies:
                    self.assertTrue((ROOT / path).is_file())

    def test_any_missing_dependency_is_detected_without_importing_staged_code(self):
        dependencies = passive_dependencies()
        for relative in STAGES:
            for missing in dependencies:
                with self.subTest(stage=relative, missing=missing):
                    selected = selected_sources(relative) - {missing}
                    self.assertEqual(dependencies - selected, {missing})


if __name__ == '__main__':
    unittest.main()
