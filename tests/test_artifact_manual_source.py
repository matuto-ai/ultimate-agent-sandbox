"""Pure/build-only manual-profile contracts. No VM/helper/kernel execution."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

VM=Path(__file__).parent/'vm'
ROOT=VM.parent.parent
sys.path.insert(0,str(VM))
try:
    import run_artifacts as run
    import prepare_artifact_payload as stage
    import prepare_payload as payload
    import native_rootfs as rootfs
    import artifact_supervisor as supervisor
finally:sys.path.remove(str(VM))


class ArtifactManualSourceTests(unittest.TestCase):
    def test_explicit_allowlist_is_complete_bounded_and_all_source_files_are_ordinary(self):
        selected=payload.source_files(ROOT,run.SOURCES)
        self.assertEqual(len(selected),len(run.SOURCES));self.assertLessEqual(len(selected),64)
        for needed in ('uas/artifact_target.py','uas/artifact_helper.py','uas/gate_evaluation.py',
                       'tests/vm/artifact_hub.py','tests/vm/artifact_supervisor.py',
                       'runtime/workstation/artifact_protocol.h'):
            self.assertIn(needed,run.SOURCES)
        self.assertNotIn('runtime/pi/extension.mjs',run.SOURCES)
        self.assertEqual(stage.RPM_ROOTS[-2:],('git-core','util-linux'))

    def test_workflow_is_explicit_reviewer_label_or_dispatch_serialized_and_bounded(self):
        value=(ROOT/'.github/workflows/artifacts-native.yml').read_text()
        self.assertIn('workflow_dispatch:',value)
        self.assertIn('  pull_request:\n    types: [labeled]\n',value)
        for trigger in ('pull_request_target:','push:','schedule:','synchronize','opened'):
            self.assertNotIn(trigger,value.split('permissions:')[0])
        guard="${{ github.event_name == 'workflow_dispatch' || (github.event_name == 'pull_request' && github.event.action == 'labeled' && github.event.label.name == 'qualify-native-artifacts' && github.event.sender.login == 'puglab-reviewer' && github.event.pull_request.head.repo.full_name == github.repository) }}"
        self.assertIn('    if: '+guard,value)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha || github.sha }}',value)
        self.assertIn('EXPECTED_HEAD: ${{ github.event.pull_request.head.sha || github.sha }}',value)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_HEAD"',value)
        self.assertLess(value.index('Verify exact reviewed event head'),value.index('Install disposable runner image'))
        self.assertIn('group: artifacts-native-deliberate',value)
        self.assertIn('cancel-in-progress: false',value)
        self.assertIn('timeout-minutes: 45',value)
        self.assertIn('persist-credentials: false',value)
        self.assertNotIn('setup-node',value)

    def test_manual_guard_precedes_download_build_or_boot(self):
        with patch.dict(os.environ,{},clear=True),patch.object(run.feasibility,'fetch_image') as fetch:
            with self.assertRaises(RuntimeError):run.main()
            fetch.assert_not_called()

    def test_report_rejects_missing_failed_pending_wrong_boot_and_production_claims(self):
        nonce='a'*32
        complete={'version':1,'nonce':nonce,'checks':{name:{'status':'passed'} for name in run.REQUIRED},'production_enabled':False}
        def serial(value):return 'UAS_ARTIFACT_REPORT:'+nonce+':'+json.dumps(value)
        self.assertEqual(run.parse_report(serial(complete),nonce),complete)
        for field,value in [('nonce','b'*32),('production_enabled',True),('failure',{})]:
            item=deepcopy(complete);item[field]=value
            with self.assertRaises(RuntimeError):run.parse_report(serial(item),nonce)
        for status in ('not-run','failed','pending'):
            item=deepcopy(complete);item['checks']['native_filter']['status']=status
            with self.assertRaises(RuntimeError):run.parse_report(serial(item),nonce)
        item=deepcopy(complete);del item['checks']['held_identity']
        with self.assertRaises(RuntimeError):run.parse_report(serial(item),nonce)
        with self.assertRaises(RuntimeError):run.parse_report(serial(complete)+'\n'+serial(complete),nonce)

    def test_target_labels_reset_on_body_failure_without_installing_host_policy(self):
        setter=Mock(return_value=0);library=Mock();library.setfscreatecon=setter
        with patch.object(supervisor.ctypes,'CDLL',return_value=library):
            with self.assertRaisesRegex(RuntimeError,'injected'):
                with supervisor.target_labels('s0:c101,c102'):raise RuntimeError('injected')
        self.assertEqual(setter.call_args_list[0].args,(b'system_u:object_r:container_file_t:s0:c101,c102',))
        self.assertEqual(setter.call_args_list[-1].args,(None,))
        source=(VM/'artifact_supervisor.py').read_text()
        self.assertNotIn('setenforce',source);self.assertNotIn('semodule',source)

    def test_denied_label_setup_stops_without_running_body(self):
        library=Mock();library.setfscreatecon=Mock(return_value=-1)
        entered=False
        with patch.object(supervisor.ctypes,'CDLL',return_value=library):
            with self.assertRaises(OSError):
                with supervisor.target_labels('s0:c101,c102'):entered=True
        self.assertFalse(entered)

    def test_capacity_scan_counts_blocks_and_inodes_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'file').write_bytes(b'x'*9000);(root/'child').mkdir()
            used,nodes=supervisor.allocated((root,))
            self.assertGreaterEqual(used,9000);self.assertEqual(nodes,3)
            (root/'link').symlink_to(root/'child',target_is_directory=True)
            with self.assertRaises(RuntimeError):supervisor.allocated((root,))

    def test_journals_are_distinct_private_quota_children_and_probes_not_inside_finish_rpc(self):
        source=(VM/'artifact_supervisor.py').read_text();guest=(VM/'guest_artifacts.py').read_text()
        self.assertIn("journal/'targets'",source);self.assertIn("journal/'launches'",source)
        self.assertIn("journal/'probes'",source);self.assertIn("base/'.supervisor'",guest)
        block=source[source.index('            def finish('):source.index('            launch.finish=finish')]
        self.assertNotIn('probe_task(',block);self.assertNotIn('confinement_probes(',block)
        self.assertIn('1536>8192',source)

    def test_probe_intent_is_durable_before_engine_effects_and_quota_attack_is_fixed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'intent.json'
            supervisor.durable_probe_record(path,{'state':'launch-possible'},create=True)
            self.assertEqual(json.loads(path.read_bytes()),{'state':'launch-possible'})
            with self.assertRaises(FileExistsError):supervisor.durable_probe_record(path,{},create=True)
            supervisor.durable_probe_record(path,{'state':'exited'})
            self.assertEqual(json.loads(path.read_bytes()),{'state':'exited'})
        source=(VM/'artifact_supervisor.py').read_text()
        block=source[source.index('def probe_task('):source.index('def scenario(')]
        self.assertLess(block.index('durable_probe_record('),block.index('engine.create('))
        self.assertIn("'state':'launch-possible'",block)
        quota=(VM/'artifact_quota_probe.py').read_text()
        self.assertIn('denied!=errno.EDQUOT',quota)
        self.assertIn('os.posix_fallocate(descriptor,0,(256<<20)+4096)',quota)
        self.assertIn('(165533,165533)',quota)
        self.assertIn('tests/vm/artifact_quota_probe.py',run.SOURCES)

    def test_root_validates_and_publishes_only_boot_nonce_before_nonroot_children(self):
        source=(VM/'guest_artifacts.py').read_text()
        block=source[source.index('def scenario('):source.index('def main(')]
        self.assertLess(block.index('marker.read_text().strip()==nonce'),block.index('marker.chmod(0o444)'))
        self.assertLess(block.index('marker.chmod(0o444)'),block.index('subprocess.run('))
        self.assertLess(block.index('marker.chmod(0o444)'),block.index('subprocess.Popen('))
        self.assertIn('os.geteuid()==0 and marker.lstat().st_uid==0 and not marker.is_symlink()',block)

    def test_real_listener_uid_is_set_before_listen_not_inferred_from_chown(self):
        source=(VM/'guest_artifacts.py').read_text()
        child=source[source.index('        if child==0:'):source.index('        right.close();right=None')]
        self.assertLess(child.index('os.setuid(165533)'),child.index('listener.listen(4)'))
        self.assertIn('os.setgroups([group]);os.setgid(165533)',child)
        self.assertNotIn('seccomp=unconfined',source)

    def test_fixed_pack_command_disables_unsupported_auxiliaries_and_rejects_shape_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);directory=repo/'.git/objects/pack';directory.mkdir(parents=True)
            base='pack-'+'1'*40
            for extension in ('pack','idx'):(directory/(base+'.'+extension)).write_bytes(b'fixture-shape-only')
            git=Mock();supervisor.pack_fixture_source(git,repo)
            git.assert_called_once_with('-c','pack.writeReverseIndex=false','-c','repack.writeBitmaps=false',
                '-c','gc.writeCommitGraph=false','gc','--prune=now')
            (directory/(base+'.rev')).write_bytes(b'unsupported')
            with self.assertRaisesRegex(RuntimeError,'unsupported generated'):supervisor.pack_fixture_source(Mock(),repo)
            (directory/(base+'.rev')).unlink();(directory/(base+'.idx')).unlink()
            with self.assertRaisesRegex(RuntimeError,'paired actual'):supervisor.pack_fixture_source(Mock(),repo)

    def test_source_config_probe_and_git_materializer_are_not_mocked_in_native_fixture(self):
        source=(VM/'artifact_supervisor.py').read_text()
        self.assertIn('ArtifactSourceResolver(supervisor,allocator)',source)
        self.assertIn('GateSupervisorService(resolver,targets',source)
        self.assertIn('dispatch_gate_control(control,hub,service',source)
        self.assertIn("pack_fixture_source(git,repo)",source)
        self.assertIn("(repo/'.git/config').write_text",source)
        self.assertIn('NativeAdmission(engine,config)',source)
        self.assertIn('confinement_probes(engine,config',source)
        self.assertIn('self.engine._request',source)


class ArtifactProfileBuildTests(unittest.TestCase):
    def test_exact_manifest_bound_static_payload_builds_without_fetch_or_execution(self):
        if shutil.which('cc') is None:self.skipTest('static compiler absent')
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp);directory=work/'payload';source=directory/'repo';source.mkdir(parents=True)
            for relative,path in payload.source_files(ROOT,run.SOURCES):
                target=source/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
            calls=[]
            def compile_only(arguments,timeout):
                self.assertEqual(arguments[0],'cc');self.assertIn('-static',arguments)
                self.assertLessEqual(timeout,60);calls.append(arguments)
                subprocess.run(arguments,check=True,capture_output=True,timeout=20)
            fetch=Mock(side_effect=AssertionError('no artifact runtime fetch'))
            result=stage.stage_native(work,directory,compile_only,fetch)
            self.assertEqual(len(calls),4);fetch.assert_not_called()
            self.assertEqual(result['profile'],'artifacts-v1-source');self.assertFalse(result['production_enabled'])
            archive,files=rootfs.verify_runtime(directory,result)
            self.assertEqual(archive.name,'artifact-runtime.tar')
            self.assertEqual(result['rpm_roots'],list(rootfs.ROOTS))
            for name,digest in result['helper_sha256'].items():
                self.assertEqual(files['opt/uas/bin/'+name]['sha256'],digest)
            bad=deepcopy(result);bad['helper_sha256']['artifact-bootstrap']='0'*64
            with self.assertRaises(ValueError):rootfs.verify_runtime(directory,bad)
            bad=deepcopy(result);bad['helper_sha256']['artifact-bootstrap']=1
            with self.assertRaises(ValueError):rootfs.verify_runtime(directory,bad)
            self.assertNotEqual(result['helper_sha256']['artifact-bootstrap'],result['helper_sha256']['artifact-test-bootstrap'])


if __name__=='__main__':unittest.main()
