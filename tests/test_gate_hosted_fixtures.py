"""Source-only native fixture contracts; never import or execute their entrypoints."""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class GateHostedSourceTests(unittest.TestCase):
    def test_broker_smoke_requires_owned_hosted_root_and_private_staged_sources(self):
        source=(ROOT/'tests/linux/gate_forge_smoke.py').read_text()
        self.assertIn("os.environ.get('GITHUB_ACTIONS') != 'true'",source)
        self.assertIn("os.environ.get('RUNNER_OS') != 'Linux'",source)
        self.assertIn("shutil.copytree(ROOT / 'uas', code / 'uas'",source)
        self.assertIn('secret not in out and secret not in err',source)

    def test_real_broker_guard_is_consumed_in_canonical_ledger_transaction(self):
        tree=ast.parse((ROOT/'tests/linux/gate_forge_smoke.py').read_text())
        script=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
                    and any(isinstance(name,ast.Name) and name.id=='SUPERVISOR' for name in node.targets))
        body=ast.parse(script)
        consumer=next(node for node in body.body if isinstance(node,ast.FunctionDef) and node.name=='consume_guard')
        canonical=ast.unparse(consumer)
        self.assertIn('def accept(state, _):',canonical)
        self.assertIn('require_operation_gates(state, view)',canonical)
        self.assertIn('decide=accept',canonical)
        self.assertIn('fence._is_owned()',canonical)
        self.assertIn("consume_guard(view,'consume-positive')",script)
        self.assertIn("consume_guard(view,'consume-pending')",script)
        self.assertIn("assert ledger.snapshot()==before",script)
        self.assertIn("['status']=='ACTIVE'",script)
