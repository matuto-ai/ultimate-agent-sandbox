"""Bounded archive transport with mocked Engine, never native execution."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uas import native_image_archive as archive


class NativeImageArchiveTests(unittest.TestCase):
    def saved(self, *, config=None, duplicate=False, unsafe=False, missing_layer=False):
        config = archive.canonical(config or {'os': 'linux', 'architecture': 'amd64'})
        identifier = 'sha256:' + hashlib.sha256(config).hexdigest()
        config_name = 'blobs/sha256/' + identifier.split(':')[1]
        manifest = [{'Config': config_name, 'RepoTags': None, 'Layers': ['blobs/sha256/layer']}]
        values = [('manifest.json', archive.canonical(manifest)), (config_name, config)]
        if not missing_layer: values.append(('blobs/sha256/layer', b'opaque layer bytes'))
        if duplicate: values.append(('manifest.json', b'[]'))
        if unsafe: values.append(('../escape', b'unsafe'))
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as target:
            for name, raw in values:
                member = tarfile.TarInfo(name); member.size = len(raw)
                target.addfile(member, io.BytesIO(raw))
        return identifier, output.getvalue()

    def client(self, raw, status=200, failure=None):
        parent = self
        class Client:
            sock = None
            closed = False
            requests = []
            instances = []
            def __init__(self, *_):
                self.buffer = io.BytesIO(raw)
                self.instances.append(self)
            def request(self, method, path):
                from urllib.parse import parse_qs, urlsplit
                parent.assertEqual(method, 'GET')
                parent.assertEqual(json.loads(parse_qs(urlsplit(path).query)['platform'][0]),
                                   {'os': 'linux', 'architecture': 'amd64'})
                self.requests.append((method, path))
            def getresponse(self): return self
            def read1(self, count):
                parent.assertLessEqual(count, 65536)
                if failure: raise failure
                return self.buffer.read(count)
            def close(self): self.closed = True
        Client.status = status
        return Client

    def run_export(self, directory, identifier, raw, **kwargs):
        client = self.client(raw, kwargs.pop('status', 200), kwargs.pop('failure', None))
        with patch.object(archive, '_UnixHTTP', client), \
             patch.object(archive.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024**3)):
            return archive.export_archive(identifier, directory, artifact_name='hub-image.tar',
                max_bytes=kwargs.pop('max_bytes', 1024**3),
                readback={'image_id': identifier, 'source_revision': 'a'*40, 'payload_sha256': 'b'*64}, **kwargs)

    def test_exact_single_config_binding_and_transport_hash_retained(self):
        identifier, raw = self.saved()
        with tempfile.TemporaryDirectory() as directory:
            record = self.run_export(directory, identifier, raw)
            self.assertEqual(record['image_id'], identifier)
            self.assertEqual(record['archive_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(record['size'], len(raw))
            self.assertEqual(record['restore_verification'], 'required-before-use')
            self.assertIsNone(record['registry_reference'])
            self.assertEqual(set(p.name for p in Path(directory).iterdir()), {'hub-image.tar', 'hub-image.json'})
            self.assertEqual(json.loads((Path(directory)/'hub-image.json').read_bytes()), record)
            self.assertEqual((Path(directory)/'hub-image.tar').read_bytes(), raw)

    def test_rejects_bad_inventory_config_platform_and_missing_layer(self):
        for settings in ({'unsafe': True}, {'duplicate': True}, {'missing_layer': True},
                         {'config': {'os': 'linux', 'architecture': 'arm64'}}):
            with self.subTest(settings=settings), tempfile.TemporaryDirectory() as directory:
                identifier, raw = self.saved(**settings)
                with self.assertRaises(ValueError): self.run_export(directory, identifier, raw)
                self.assertEqual(list(Path(directory).iterdir()), [])
        identifier, raw = self.saved()
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            self.run_export(directory, 'sha256:'+'c'*64, raw)

    def test_stream_failures_and_size_limit_leave_no_artifacts(self):
        identifier, raw = self.saved()
        for changes in ({'failure': TimeoutError('read timeout')}, {'max_bytes': len(raw)-1}, {'status': 500}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises((TimeoutError, ValueError)):
                    self.run_export(directory, identifier, raw, **changes)
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_no_clobber_existing_archive_or_metadata(self):
        identifier, raw = self.saved()
        for name in ('hub-image.tar', 'hub-image.json'):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/name; path.write_bytes(b'existing')
                with self.assertRaises(ValueError): self.run_export(directory, identifier, raw)
                self.assertEqual(path.read_bytes(), b'existing')

    def test_metadata_publication_failure_removes_own_archive_only(self):
        identifier, raw = self.saved()
        real_link = archive.os.link
        def link(source, target):
            if str(target).endswith('.json'): raise OSError('metadata publication failure')
            real_link(source, target)
        with tempfile.TemporaryDirectory() as directory, patch.object(archive.os, 'link', side_effect=link):
            (Path(directory)/'unrelated').write_bytes(b'keep')
            with self.assertRaises(OSError): self.run_export(directory, identifier, raw)
            self.assertEqual([p.name for p in Path(directory).iterdir()], ['unrelated'])

    def test_budget_binding_and_disk_reserve_reject_before_engine(self):
        identifier, _ = self.saved()
        with tempfile.TemporaryDirectory() as directory, patch.object(archive, '_UnixHTTP') as client:
            common = dict(artifact_name='hub-image.tar', max_bytes=1024**3,
                          readback={'image_id': identifier, 'source_revision':'a'*40})
            for changes in ({'artifact_name':'../escape'}, {'max_bytes':1024**3+1},
                            {'timeout':121}, {'readback':{}}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    archive.export_archive(identifier, directory, **{**common, **changes})
            with patch.object(archive.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)), self.assertRaises(ValueError):
                archive.export_archive(identifier, directory, **common)
            client.assert_not_called()

    def test_validation_deadline(self):
        identifier, raw = self.saved()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'archive'; path.write_bytes(raw)
            with self.assertRaises(ValueError): archive.validate_archive(path, identifier, time.monotonic()-1)

    def test_stream_deadline_closes_once_and_does_not_retry(self):
        identifier, raw = self.saved()
        client = self.client(raw)
        with tempfile.TemporaryDirectory() as directory, patch.object(archive, '_UnixHTTP', client), \
             patch.object(archive.shutil, 'disk_usage', return_value=SimpleNamespace(free=10*1024**3)), \
             patch.object(archive.time, 'monotonic', side_effect=[0, 121]):
            with self.assertRaisesRegex(ValueError, 'read deadline'):
                archive.export_archive(identifier, directory, artifact_name='hub-image.tar', max_bytes=1024**3,
                    readback={'image_id':identifier, 'source_revision':'a'*40})
            self.assertEqual(len(client.instances), 1)
            self.assertTrue(client.instances[0].closed)
            self.assertEqual(len(client.requests), 1)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_close_failure_does_not_mask_primary_or_leave_partial(self):
        identifier, raw = self.saved()
        client = self.client(raw, failure=TimeoutError('primary read timeout'))
        def fail_close(_): raise OSError('close failure')
        client.close = fail_close
        with tempfile.TemporaryDirectory() as directory, patch.object(archive, '_UnixHTTP', client), \
             patch.object(archive.shutil, 'disk_usage', return_value=SimpleNamespace(free=10*1024**3)):
            with self.assertRaisesRegex(TimeoutError, 'primary read timeout') as caught:
                archive.export_archive(identifier, directory, artifact_name='hub-image.tar', max_bytes=1024**3,
                    readback={'image_id':identifier, 'source_revision':'a'*40})
            self.assertIn('cleanup incomplete', caught.exception.__notes__[0])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_final_partial_cleanup_failure_rolls_back_published_pair(self):
        identifier, raw = self.saved()
        original = Path.unlink
        failed = False
        def unlink(path, *args, **kwargs):
            nonlocal failed
            if path.name.startswith('.hub-image.tar-') and not failed:
                failed = True
                raise OSError('partial cleanup failed')
            return original(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(Path, 'unlink', side_effect=unlink, autospec=True), self.assertRaisesRegex(OSError, 'partial cleanup failed'):
                self.run_export(directory, identifier, raw)
            self.assertFalse((Path(directory)/'hub-image.tar').exists())
            self.assertFalse((Path(directory)/'hub-image.json').exists())
            # The reported cleanup error honestly leaves its failed partial.
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_metadata_fsync_failure_never_publishes(self):
        identifier, raw = self.saved()
        original = archive.os.fsync
        calls = 0
        def fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('metadata sync failed')
            return original(fd)
        with tempfile.TemporaryDirectory() as directory, patch.object(archive.os, 'fsync', side_effect=fsync):
            with self.assertRaisesRegex(OSError, 'metadata sync failed'): self.run_export(directory, identifier, raw)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_publication_collision_does_not_delete_foreign_target(self):
        identifier, raw = self.saved()
        original = archive.os.link
        def collision(source, target):
            if str(target).endswith('.json'):
                Path(target).write_bytes(b'foreign target')
            return original(source, target)
        with tempfile.TemporaryDirectory() as directory, patch.object(archive.os, 'link', side_effect=collision):
            with self.assertRaises(FileExistsError): self.run_export(directory, identifier, raw)
            self.assertEqual((Path(directory)/'hub-image.json').read_bytes(), b'foreign target')
            self.assertFalse((Path(directory)/'hub-image.tar').exists())

    def test_truncated_layer_payload_is_not_a_complete_transport(self):
        identifier,raw=self.saved()
        # Header claims a larger opaque layer than bytes physically retained.
        data=bytearray(raw)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as source:
            member=source.getmember('blobs/sha256/layer')
        truncated=bytes(data[:member.offset_data+1])
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'truncated.tar';file.write_bytes(truncated)
            with self.assertRaises((ValueError,tarfile.TarError)):
                archive.validate_archive(file,identifier,time.monotonic()+10)

    def test_preexisting_partial_collision_is_not_owned_or_deleted(self):
        identifier,raw=self.saved()
        for suffix in ('hub-image.tar','hub-image.json'):
            with self.subTest(suffix=suffix),tempfile.TemporaryDirectory() as directory:
                foreign=Path(directory)/('.'+suffix+'-'+'a'*32)
                foreign.write_bytes(b'foreign partial')
                with patch.object(archive.uuid,'uuid4',return_value=SimpleNamespace(hex='a'*32)):
                    with self.assertRaises(FileExistsError):self.run_export(directory,identifier,raw)
                self.assertEqual(foreign.read_bytes(),b'foreign partial')
                self.assertEqual(list(Path(directory).iterdir()),[foreign])
