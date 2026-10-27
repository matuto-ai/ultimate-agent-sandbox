"""Pure real-work progress facts, never timer-only guest keepalives."""
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('progress_rootfs', Path(__file__).parent/'vm/native_rootfs.py')
rootfs = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(rootfs)


class RootfsProgressTests(unittest.TestCase):
    def test_fingerprint_progress_advances_only_after_real_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch('builtins.print') as output:
                rootfs.fingerprint(root)
                output.assert_not_called()
            for n in range(5): (root/str(n)).write_bytes(b'x')
            with patch.object(rootfs, 'PROGRESS_FILES', 2), patch('builtins.print') as output:
                rootfs.fingerprint(root)
            facts = [json.loads(call.args[1]) for call in output.call_args_list]
            self.assertEqual(facts, [{'entries':2,'bytes':2},{'entries':4,'bytes':4}])

    def test_extraction_progress_follows_verified_file_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'root'; root.mkdir()
            archive = Path(temporary)/'archive.tar'; files = {}
            with tarfile.open(archive,'w') as target:
                for n in range(3):
                    name = f'opt/uas/{n}'; data = b'abc'
                    entry = tarfile.TarInfo(name); entry.size=3; entry.mode=0o444
                    target.addfile(entry,io.BytesIO(data))
                    files[name]={'bytes':3,'mode':0o444,'sha256':hashlib.sha256(data).hexdigest()}
            with patch.object(rootfs,'PROGRESS_FILES',2), patch('builtins.print') as output:
                rootfs.extract_runtime(archive,files,root)
            self.assertEqual([json.loads(c.args[1]) for c in output.call_args_list],[{'files':2,'bytes':6}])

    def test_failed_rpm_has_start_not_completion_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            def run(*args,**kwargs):
                if args[0]=='rpm': return 'observed tools'
                raise RuntimeError('fixed mock failure')
            with patch.object(rootfs,'guest_guard'),patch.object(rootfs,'verify_runtime',return_value=('archive',{})),patch('builtins.print') as output:
                with self.assertRaises(RuntimeError):
                    rootfs.build_rootfs('a'*32,{'native_runtime':{}},Path(temporary)/'root',run=run)
            phases=[c.args[0] for c in output.call_args_list if c.args[0].startswith('Native rootfs phase:')]
            self.assertEqual(phases,['Native rootfs phase: rpm-transaction start'])

    def test_phase_markers_are_fixed_and_paired_in_source(self):
        tree=ast.parse(Path(rootfs.__file__).read_text())
        markers=[n.args[0].value for n in ast.walk(tree) if isinstance(n,ast.Call)
                 and isinstance(n.func,ast.Name) and n.func.id=='print' and n.args
                 and isinstance(n.args[0],ast.Constant) and isinstance(n.args[0].value,str)
                 and n.args[0].value.startswith('Native rootfs phase:')]
        self.assertEqual(markers,[f'Native rootfs phase: {name} {state}'
            for name in ('rpm-transaction','filesystem-metadata','runtime-extraction','tini-copy',
                         'debug-metadata','fingerprint','manifest-write') for state in ('start','complete')])

if __name__=='__main__': unittest.main()
