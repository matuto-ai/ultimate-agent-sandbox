"""Public build-product retention only; native and Docker effects stay mocked."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_native_image_readback as readback

CHECK = readback.CHECK
ROOT = Path(__file__).resolve().parents[1]


class NativeImageArtifactRetentionTests(unittest.TestCase):
    def test_only_fixed_bounded_products_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = {}
            CHECK.retain_artifact(directory, 'git-backend', b'public ELF', report)
            self.assertEqual(report['retained_artifacts']['git-backend'],
                             {'sha256': hashlib.sha256(b'public ELF').hexdigest(), 'size': 10})
            self.assertEqual((directory / 'git-backend').read_bytes(), b'public ELF')
            with self.assertRaises(FileExistsError):
                CHECK.retain_artifact(directory, 'git-backend', b'replacement', report)
            for name, raw in (('../secret', b'a'), ('docker-config', b'a'),
                              ('pi-payload.json', b''), ('pi-payload.json', b'a' * 65537)):
                with self.assertRaises(ValueError): CHECK.retain_artifact(directory, name, raw, report)
            self.assertEqual(set(report['retained_artifacts']), {'git-backend'})

    def test_main_retains_verified_outputs_and_failed_readback_does_not_export_git(self):
        scenario = readback.NativeImageReadbackTests()
        status, report, _ = scenario.scenario()
        self.assertEqual(status, 0)
        self.assertEqual(set(report['retained_artifacts']), set(CHECK.RETAINED_FILES))
        for failure in ('build', 'export', 'readback', 'git-readback'):
            with self.subTest(failure=failure):
                status, report, _ = scenario.scenario(failure)
                self.assertEqual(status, 1)
                self.assertNotIn('git-backend', report['retained_artifacts'])
                self.assertNotIn('git-payload.json', report['retained_artifacts'])

    def test_retention_failure_keeps_failure_and_container_cleanup(self):
        original = CHECK.retain_artifact
        def fail(directory, name, raw, report):
            if name == 'git-backend': raise OSError('artifact retention failed')
            return original(directory, name, raw, report)
        with patch.object(CHECK, 'retain_artifact', side_effect=fail):
            status, report, _ = readback.NativeImageReadbackTests().scenario()
        self.assertEqual(status, 1)
        self.assertIn('artifact retention failed', report['error'])
        self.assertEqual(report['container_cleanup'], 'complete')

    def test_workflow_upload_is_explicit_allowlist_without_new_permissions(self):
        source = (ROOT / '.github/workflows/native-image-readback.yml').read_text()
        upload = source.split('      - name: Retain only named public build and readback products')[1]
        self.assertIn('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', upload)
        self.assertIn('retention-days: 7', upload)
        self.assertIn('include-hidden-files: false', upload)
        paths = [line.strip() for line in upload.splitlines() if line.strip().startswith('${{ runner.temp }}')]
        self.assertEqual(set(paths), {'${{ runner.temp }}/native-image-readback/report.json',
                          '${{ runner.temp }}/native-image-readback/artifacts/combined-image.tar',
                          '${{ runner.temp }}/native-image-readback/artifacts/combined-image.json'} |
                         {'${{ runner.temp }}/native-image-readback/artifacts/' + name for name in CHECK.RETAINED_FILES} |
                         {'${{ runner.temp }}/native-hub-readback/' + name for name in
                          ('report.json', 'artifacts/hub-image.tar','artifacts/hub-image.json', 'artifacts/selection.json', 'artifacts/Dockerfile.hub-check',
                           'artifacts/hub-payload.json')})
        self.assertNotIn('*', '\n'.join(paths))
        self.assertIn('permissions:\n  contents: read\n', source)
        self.assertNotIn('write', source.split('permissions:', 1)[1].split('concurrency:', 1)[0])
