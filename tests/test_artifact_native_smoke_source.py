"""Pure source/inert Git-data checks for explicit hosted artifacts fixture."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import zlib

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'tests/linux/artifact_native_smoke.py'


class ArtifactNativeSmokeSourceTests(unittest.TestCase):
    def setUp(self):
        self.source=SOURCE.read_text();self.tree=ast.parse(self.source)
    def constant(self,name):
        return next(ast.literal_eval(node.value) for node in self.tree.body if isinstance(node,ast.Assign)
                    and any(isinstance(target,ast.Name) and target.id==name for target in node.targets))

    def test_explicit_hosted_guard_and_no_import_time_native_effects(self):
        for fragment in ("sys.argv[1:]==['--run']","os.geteuid()==0", "os.environ.get('GITHUB_ACTIONS')=='true'",
                         "os.environ.get('RUNNER_OS')=='Linux'", "if __name__=='__main__':main()"):
            self.assertIn(fragment,self.source)
        self.assertEqual(self.constant('DEADLINE_SECONDS'),40)
        calls=[node.value for node in self.tree.body if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)]
        self.assertEqual(calls,[])
        self.assertLess(self.source.index('sys.dont_write_bytecode=True'),self.source.index('from diff_smoke import'))

    def test_unchanged_exact_test_probe_exit_map_and_distinct_test_payloads(self):
        expected={'N':159,'P':159,'F':159,'E':159,'T':159,'M':159,
                  'R':0,'L':0,'W':0,'C':137,'H':142,'O':126}
        self.assertEqual(self.constant('EXPECTED_EXIT'),expected)
        self.assertEqual(set(self.constant('PROBES')),set(expected))
        self.assertIn("'artifact-test-bootstrap':('runtime/workstation/artifact_bootstrap.c',('-DUAS_ARTIFACT_PROBE',))",self.source)
        self.assertIn("'artifact-confinement-probe':('tests/vm/artifact_confinement_probe.c',())",self.source)
        probe=(ROOT/'tests/vm/artifact_confinement_probe.c').read_text()
        self.assertIn('#include "../../runtime/workstation/artifact_evaluator.c"',probe)
        self.assertIn('setup();filter();',probe)
        original=(ROOT/'tests/vm/artifact_supervisor.py').read_text()
        self.assertIn("expected={'R':0,'L':0,'W':0,'C':137,'H':142,'O':126,'I':0}.get(kind,159)",original)
        self.assertIn("'test_payload':True",self.source)

    def test_actual_target_native_sender_ack_exit_and_postproof_seams(self):
        for fragment in ('ArtifactSourceResolver(supervisor,allocator)', 'targets.prepare(scope,source)',
            'lease.recheck();lease.mark_launch_possible()', 'origin=HeldOrigin(record)',
            "record.credentials[1:]==(HOST_HELPER,HOST_HELPER)",
            'reducer._observations(offer,row,target)', 'offer.acknowledge_final(final);offer.confirm_exit()',
            'lease.mark_exit_confirmed()', 'lease.postverify()==target', 'lease.cleanup()',
            'ArtifactGateHub._checks(row,facts,error)', 'wait_exit(origin,18)'):
            self.assertIn(fragment,self.source)
        self.assertNotIn('patch(',self.source)
        self.assertEqual(self.constant('GATE_CASES'),('positive','missing','mutation','cleanup'))

    def test_staged_source_is_compiled_and_reexecuted_without_runner_traversal(self):
        self.assertIn('payload,hashes=stage_sources(root,extra_paths=EXTRA_SOURCES)',self.source)
        self.assertIn("script=payload/'tests/linux/artifact_native_smoke.py'",self.source)
        self.assertEqual(self.source.count('str(script)'),2)
        self.assertEqual(self.source.count('cwd=payload'),2)
        self.assertIn("str(payload/source)",self.source)
        self.assertNotIn('str(Path(__file__).resolve())',self.source)
        self.assertIn('mapped_popen([',self.source)
        self.assertIn("['0','100000','65536']",self.source)
        self.assertIn("'remount,bind,ro,nodev,nosuid,noexec'",self.source)
        self.assertIn("os.execve(binary,[binary],{})",self.source)

    def test_decisive_probe_status_precedes_assertion_and_cleanup_success_is_last(self):
        self.assertLess(self.source.index('reports.append(result);emit(result)'),self.source.index("expect(result['supervisor_exit']==0"))
        self.assertIn("result['helper_exit']=128-raw if raw<0 else raw",self.source)
        self.assertIn("result['helper_exit']==EXPECTED_EXIT[case]",self.source)
        self.assertIn("result['observed_bytes']==16385 and result['receiver_rejected']",self.source)
        self.assertLess(self.source.index('shutil.rmtree(root)'),self.source.index('summary.update(fixture_cleanup=True'))
        self.assertLess(self.source.index("expect(complete and safe,'fixture cleanup unconfirmed')"),self.source.index('summary.update(fixture_cleanup=True'))
        self.assertIn("'native_qualification':False",self.source)
        self.assertIn('no Room/SELinux/#79/fullVM proof',self.source)

    def test_fixture_head_is_exact_inert_committed_artifacts_not_dirty_worktree(self):
        # Only ordinary temporary files/zlib/SHA are used; no Git process runs.
        location=str(ROOT/'tests/linux');sys.path.insert(0,location)
        self.addCleanup(lambda:sys.path.remove(location))
        spec=importlib.util.spec_from_file_location('artifact_native_data_fixture',SOURCE)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='uas-artifact-data-') as directory:
            _,allocator=module.artifact_source(Path(directory))
            common=allocator.repo/'.git';head=(common/'refs/heads/main').read_text().strip()
            def raw(oid,kind):
                encoded=zlib.decompress((common/'objects'/oid[:2]/oid[2:]).read_bytes())
                self.assertEqual(hashlib.sha1(encoded).hexdigest(),oid)
                header,data=encoded.split(b'\0',1)
                self.assertEqual(header,kind.encode()+b' '+str(len(data)).encode())
                return data
            commit=raw(head,'commit');tree=raw(commit.splitlines()[0].split(b' ')[1].decode(),'tree')
            self.assertTrue(tree.startswith(b'100644 README.md\0'))
            oid=tree[len(b'100644 README.md\0'):len(b'100644 README.md\0')+20].hex()
            self.assertEqual(raw(oid,'blob'),b'committed artifact\n')
            self.assertNotEqual((allocator.repo/'README.md').read_bytes(),raw(oid,'blob'))
